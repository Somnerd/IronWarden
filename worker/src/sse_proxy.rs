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

struct SseState {
    rehydrator: SseRehydrator,
    is_anthropic: bool,
    pending_event: Option<String>,
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
        if line.starts_with("event:") {
            self.flush_pending(output);
            self.pending_event = Some(line.to_string());
            return;
        }
        let Some(data) = line.strip_prefix("data: ") else {
            self.flush_pending(output);
            output.push_str(line);
            output.push('\n');
            return;
        };
        if data.trim() == "[DONE]" {
            self.flush_pending(output);
            self.push_tail_delta(false, 0, output);
            output.push_str("data: [DONE]\n\n");
            return;
        }
        let Ok(mut json) = serde_json::from_str::<serde_json::Value>(data) else {
            self.flush_pending(output);
            output.push_str(line);
            output.push_str("\n\n");
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

        if let Some(serde_json::Value::String(s)) = json
            .pointer_mut("/choices/0/delta/content")
            .filter(|v| v.is_string())
        {
            *s = self.rehydrator.feed(s);
        } else if let Some(serde_json::Value::String(s)) =
            json.pointer_mut("/delta/text").filter(|v| v.is_string())
        {
            self.is_anthropic = true;
            *s = self.rehydrator.feed(s);
        }

        if is_stop {
            let idx = json.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
            self.push_tail_delta(true, idx, output);
        }
        self.flush_pending(output);
        let rewritten = serde_json::to_string(&json).unwrap_or_else(|_| data.to_string());
        output.push_str(&format!("data: {rewritten}\n\n"));
    }
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
        pending_event: None,
    };

    tokio::spawn(async move {
        futures::pin_mut!(byte_stream);
        let mut line_buffer = String::new();

        while let Some(chunk_result) = byte_stream.next().await {
            let chunk = match chunk_result {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("SSE upstream read error: {}", e);
                    break;
                }
            };
            let Ok(raw) = std::str::from_utf8(&chunk) else {
                if tx.send(Ok(chunk)).await.is_err() {
                    return;
                }
                continue;
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
            if !output.is_empty() && tx.send(Ok(Bytes::from(output))).await.is_err() {
                return;
            }
        }

        let mut eof_output = String::new();
        if !line_buffer.is_empty() {
            state.process_line(line_buffer.trim_end_matches('\r'), &mut eof_output);
        }
        state.flush_pending(&mut eof_output);
        state.push_tail_delta(state.is_anthropic, 0, &mut eof_output);
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
