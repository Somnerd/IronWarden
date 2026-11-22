//! SSE streaming proxy with split-token re-hydration buffer.
//!
//! Handles OpenAI (`choices[0].delta.content`) and Anthropic (`delta.text`)
//! SSE streams using a zero-DFA single-pass scanner sorted by placeholder length.

use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use iw_core::TokenMap;
use std::cmp::Reverse;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

/// Buffers streamed delta text and replaces PII placeholders,
/// even when split across chunk boundaries.
pub struct SseRehydrator {
    /// `(placeholder, replacement)` sorted descending by placeholder length
    /// so longer tokens (e.g. `[TOKEN_10]`) match before prefixes (`[TOKEN_1]`).
    entries: Vec<(String, String)>,
    buffer: String,
}

impl SseRehydrator {
    pub fn new(token_map: &TokenMap) -> Self {
        let mut entries: Vec<(String, String)> = token_map
            .iter()
            .filter(|(k, _)| !k.is_empty())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        entries.sort_unstable_by_key(|(k, _)| Reverse(k.len()));
        Self {
            entries,
            buffer: String::new(),
        }
    }

    /// Feeds a new delta string and returns the prefix safe to emit immediately.
    pub fn feed(&mut self, delta: &str) -> String {
        if self.entries.is_empty() {
            return delta.to_string();
        }
        if self.buffer.is_empty() {
            let safe = self.safe_boundary(delta);
            if safe < delta.len() {
                self.buffer.push_str(&delta[safe..]);
            }
            return self.replace_tokens(&delta[..safe]);
        }
        self.buffer.push_str(delta);
        let safe = self.safe_boundary(&self.buffer);
        if safe == 0 {
            return String::new();
        }
        let out = self.replace_tokens(&self.buffer[..safe]);
        self.buffer.drain(..safe);
        out
    }

    /// Flushes and rehydrates everything remaining in the buffer at stream end.
    pub fn flush_all(&mut self) -> String {
        if self.buffer.is_empty() {
            return String::new();
        }
        let out = self.replace_tokens(&self.buffer);
        self.buffer.clear();
        out
    }

    fn safe_boundary(&self, text: &str) -> usize {
        if let Some(pos) = text.rfind('[') {
            let tail = &text[pos..];
            let partial = !tail.contains(']')
                && self
                    .entries
                    .iter()
                    .any(|(k, _)| k.starts_with(tail) && tail.len() < k.len());
            if partial {
                return pos;
            }
        }
        text.len()
    }

    fn replace_tokens(&self, text: &str) -> String {
        let Some(mut pos) = text.find('[') else {
            return text.to_string();
        };
        let mut out = String::with_capacity(text.len() + 32);
        let mut rest = text;
        loop {
            out.push_str(&rest[..pos]);
            rest = &rest[pos..];
            if let Some((k, v)) = self
                .entries
                .iter()
                .find(|(k, _)| rest.starts_with(k.as_str()))
            {
                out.push_str(v);
                rest = &rest[k.len()..];
            } else {
                out.push('[');
                rest = &rest[1..];
            }
            let Some(next) = rest.find('[') else {
                out.push_str(rest);
                return out;
            };
            pos = next;
        }
    }
}

const MAX_SSE_LINE_BYTES: usize = 1024 * 1024;

struct SseState {
    rehydrator: SseRehydrator,
    is_anthropic: bool,
    last_block_idx: u64,
    pending_event: Option<String>,
    suppress_next_empty_line: bool,
    in_overflow_line: bool,
}

impl SseState {
    fn flush_pending(&mut self, out: &mut String) {
        if let Some(prev) = self.pending_event.take() {
            out.push_str(&prev);
            out.push('\n');
        }
    }

    fn push_tail_delta(&mut self, anthropic: bool, idx: u64, out: &mut String) {
        let rem = self.rehydrator.flush_all();
        if rem.is_empty() {
            return;
        }
        if anthropic {
            let v = serde_json::json!({
                "type": "content_block_delta",
                "index": idx,
                "delta": { "type": "text_delta", "text": rem }
            });
            out.push_str(&format!("event: content_block_delta\ndata: {v}\n\n"));
        } else {
            let v = serde_json::json!({
                "choices": [{ "delta": { "content": rem }, "finish_reason": null, "index": 0 }]
            });
            out.push_str(&format!("data: {v}\n\n"));
        }
    }

    fn process_line(&mut self, line: &str, output: &mut String) {
        if self.in_overflow_line {
            self.in_overflow_line = false;
            self.suppress_next_empty_line = false;
            let rehydrated = self.rehydrator.feed(line);
            let flushed = self.rehydrator.flush_all();
            output.push_str(&rehydrated);
            output.push_str(&flushed);
            output.push('\n');
            return;
        }

        if line.is_empty() && self.pending_event.is_none() && self.suppress_next_empty_line {
            self.suppress_next_empty_line = false;
            return;
        }

        if line.starts_with("event:") {
            self.suppress_next_empty_line = false;
            self.flush_pending(output);
            self.pending_event = Some(line.to_string());
            return;
        }
        let Some(raw_data) = line.strip_prefix("data:") else {
            self.suppress_next_empty_line = false;
            self.flush_pending(output);
            output.push_str(line);
            output.push('\n');
            return;
        };
        let data = raw_data.strip_prefix(' ').unwrap_or(raw_data);
        if data.trim() == "[DONE]" {
            self.push_tail_delta(self.is_anthropic, self.last_block_idx, output);
            self.flush_pending(output);
            output.push_str("data: [DONE]\n\n");
            self.suppress_next_empty_line = true;
            return;
        }
        let Ok(mut json) = serde_json::from_str::<serde_json::Value>(data) else {
            self.push_tail_delta(self.is_anthropic, self.last_block_idx, output);
            self.flush_pending(output);
            let rehydrated = self.rehydrator.feed(line);
            let flushed = self.rehydrator.flush_all();
            output.push_str(&rehydrated);
            output.push_str(&flushed);
            output.push_str("\n\n");
            self.suppress_next_empty_line = true;
            return;
        };

        let event_type = json.get("type").and_then(|v| v.as_str());
        self.is_anthropic |= matches!(
            event_type,
            Some(
                "message_start"
                    | "content_block_start"
                    | "content_block_delta"
                    | "content_block_stop"
                    | "message_delta"
                    | "message_stop"
            )
        );
        let is_stop = matches!(event_type, Some("content_block_stop" | "message_stop"));
        if let Some(idx) = json.get("index").and_then(|v| v.as_u64()) {
            self.last_block_idx = idx;
        }

        let mut suppressed_delta = false;
        if let Some(serde_json::Value::String(s)) = json
            .pointer_mut("/choices/0/delta/content")
            .filter(|v| v.is_string())
        {
            let was_non_empty = !s.is_empty();
            *s = self.rehydrator.feed(s);
            if was_non_empty && s.is_empty() {
                suppressed_delta = true;
            }
        } else if let Some(serde_json::Value::String(s)) =
            json.pointer_mut("/delta/text").filter(|v| v.is_string())
        {
            self.is_anthropic = true;
            let was_non_empty = !s.is_empty();
            *s = self.rehydrator.feed(s);
            if was_non_empty && s.is_empty() {
                suppressed_delta = true;
            }
        }

        if is_stop {
            self.push_tail_delta(true, self.last_block_idx, output);
        } else if suppressed_delta {
            self.pending_event = None;
            self.suppress_next_empty_line = true;
            return;
        }
        self.flush_pending(output);
        let rewritten = serde_json::to_string(&json).unwrap_or_else(|_| data.to_string());
        output.push_str(&format!("data: {rewritten}\n\n"));
        self.suppress_next_empty_line = true;
    }
}

fn decode_lossy_with_tail(bytes: &[u8], utf8_tail: &mut Vec<u8>) -> String {
    let start = bytes.len().saturating_sub(3);
    for i in (start..bytes.len()).rev() {
        if let Err(e) = std::str::from_utf8(&bytes[i..]) {
            if e.valid_up_to() == 0 && e.error_len().is_none() {
                utf8_tail.extend_from_slice(&bytes[i..]);
                return String::from_utf8_lossy(&bytes[..i]).into_owned();
            }
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// Processes an arbitrary SSE byte stream, re-hydrating PII placeholders in-flight
/// and flushing any remaining buffered characters on `[DONE]`, Anthropic stop events, or EOF.
pub fn stream_sse_bytes<S, E>(byte_stream: S, token_map: TokenMap) -> Response<Body>
where
    S: futures::Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<Result<Bytes, axum::Error>>(256);
    let mut state = SseState {
        rehydrator: SseRehydrator::new(&token_map),
        is_anthropic: false,
        last_block_idx: 0,
        pending_event: None,
        suppress_next_empty_line: false,
        in_overflow_line: false,
    };

    tokio::spawn(async move {
        futures::pin_mut!(byte_stream);
        let mut line_buffer = String::new();
        let mut utf8_tail = Vec::<u8>::with_capacity(4);

        while let Some(chunk_result) = byte_stream.next().await {
            let chunk = match chunk_result {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("SSE upstream read error: {}", e);
                    break;
                }
            };
            let combined;
            let bytes: &[u8] = if utf8_tail.is_empty() {
                &chunk
            } else {
                utf8_tail.extend_from_slice(&chunk);
                combined = std::mem::take(&mut utf8_tail);
                &combined
            };
            let owned_lossy: String;
            let raw = match std::str::from_utf8(bytes) {
                Ok(s) => s,
                Err(e) if e.error_len().is_none() => {
                    utf8_tail.extend_from_slice(&bytes[e.valid_up_to()..]);
                    std::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or("")
                }
                Err(_) => {
                    owned_lossy = decode_lossy_with_tail(bytes, &mut utf8_tail);
                    &owned_lossy
                }
            };
            line_buffer.push_str(raw);
            let mut output = String::new();
            let mut start = 0;
            while let Some(rel) = line_buffer[start..].find('\n') {
                state.process_line(
                    line_buffer[start..start + rel].trim_end_matches('\r'),
                    &mut output,
                );
                start += rel + 1;
            }
            if start > 0 {
                line_buffer.drain(..start);
            }
            if line_buffer.len() > MAX_SSE_LINE_BYTES {
                let overflow = std::mem::take(&mut line_buffer);
                if !state.in_overflow_line {
                    state.push_tail_delta(state.is_anthropic, state.last_block_idx, &mut output);
                    state.flush_pending(&mut output);
                    state.suppress_next_empty_line = false;
                    state.in_overflow_line = true;
                }
                let rehydrated = state.rehydrator.feed(&overflow);
                output.push_str(&rehydrated);
            }
            if !output.is_empty() && tx.send(Ok(Bytes::from(output))).await.is_err() {
                return;
            }
        }

        if !utf8_tail.is_empty() {
            line_buffer.push_str(&String::from_utf8_lossy(&utf8_tail));
        }
        let mut eof_output = String::new();
        if !line_buffer.is_empty() {
            state.process_line(line_buffer.trim_end_matches('\r'), &mut eof_output);
        }
        state.push_tail_delta(state.is_anthropic, state.last_block_idx, &mut eof_output);
        state.flush_pending(&mut eof_output);
        if !eof_output.is_empty() {
            let _ = tx.send(Ok(Bytes::from(eof_output))).await;
        }
    });

    Response::builder()
        .status(200)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(ReceiverStream::new(rx)))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Proxies an upstream SSE response to the client, re-hydrating PII placeholders in-flight.
/// Supports both OpenAI (`choices[0].delta.content`) and Anthropic (`delta.text`) formats.
pub async fn stream_proxy_response(
    upstream_response: reqwest::Response,
    token_map: TokenMap,
) -> Response<Body> {
    stream_sse_bytes(upstream_response.bytes_stream(), token_map)
}
