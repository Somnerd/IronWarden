//! SSE streaming proxy with split-token re-hydration buffer.
//!
//! Handles both OpenAI format (choices[0].delta.content)
//! and Anthropic format (delta.text) SSE streams using single-pass
//! LeftmostLongest Aho-Corasick token replacement.

use aho_corasick::{AhoCorasick, MatchKind};
use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use iw_core::TokenMap;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

/// Buffers streamed delta text and replaces PII placeholders,
/// even when they are split across chunk boundaries.
pub struct SseRehydrator {
    keys: Vec<String>,
    values: Vec<String>,
    automaton: Option<AhoCorasick>,
    buffer: String,
}

impl SseRehydrator {
    pub fn new(token_map: &TokenMap) -> Self {
        let mut keys = Vec::with_capacity(token_map.len());
        let mut values = Vec::with_capacity(token_map.len());
        for (k, v) in token_map {
            if !k.is_empty() {
                keys.push(k.clone());
                values.push(v.clone());
            }
        }
        let automaton = if keys.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&keys)
                .ok()
        };
        Self {
            keys,
            values,
            automaton,
            buffer: String::new(),
        }
    }

    /// Feed a new delta string. Returns the portion that is safe to emit now.
    pub fn feed(&mut self, delta: &str) -> String {
        self.buffer.push_str(delta);
        self.flush_safe()
    }

    /// Called at stream end — flush everything remaining in the buffer.
    pub fn flush_all(&mut self) -> String {
        let remaining = std::mem::take(&mut self.buffer);
        self.apply_replacements(&remaining)
    }

    /// Emit all content up to the last open bracket that could be a partial token.
    fn flush_safe(&mut self) -> String {
        let safe_boundary = self.find_safe_boundary();
        if safe_boundary == 0 {
            return String::new();
        }
        let safe_chunk = self.buffer[..safe_boundary].to_string();
        self.buffer.drain(..safe_boundary);
        self.apply_replacements(&safe_chunk)
    }

    fn find_safe_boundary(&self) -> usize {
        if let Some(open_bracket) = self.buffer.rfind('[') {
            let potential_token = &self.buffer[open_bracket..];
            let is_partial = self
                .keys
                .iter()
                .any(|k| k.starts_with(potential_token) && potential_token.len() < k.len());
            if is_partial {
                return open_bracket;
            }
        }
        self.buffer.len()
    }

    fn apply_replacements(&self, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        match &self.automaton {
            Some(ac) => ac.replace_all(text, &self.values),
            None => text.to_string(),
        }
    }
}

fn format_tail_event(is_anthropic: bool, block_idx: u64, remaining: &str) -> String {
    if is_anthropic {
        let synthetic = serde_json::json!({
            "type": "content_block_delta",
            "index": block_idx,
            "delta": {
                "type": "text_delta",
                "text": remaining
            }
        });
        format!("event: content_block_delta\ndata: {}\n\n", synthetic)
    } else {
        let synthetic = serde_json::json!({
            "choices": [{
                "delta": {"content": remaining},
                "finish_reason": null,
                "index": 0
            }]
        });
        format!("data: {}\n\n", synthetic)
    }
}

fn process_sse_line(
    line: &str,
    rehydrator: &mut SseRehydrator,
    is_anthropic: &mut bool,
    pending_event_line: &mut Option<String>,
    output: &mut String,
) {
    if line.starts_with("event:") {
        if let Some(prev) = pending_event_line.replace(line.to_string()) {
            output.push_str(&prev);
            output.push('\n');
        }
        return;
    }

    if !line.starts_with("data: ") {
        if let Some(prev) = pending_event_line.take() {
            output.push_str(&prev);
            output.push('\n');
        }
        output.push_str(line);
        output.push('\n');
        return;
    }

    let data = &line["data: ".len()..];

    if data.trim() == "[DONE]" {
        if let Some(prev) = pending_event_line.take() {
            output.push_str(&prev);
            output.push('\n');
        }
        let remaining = rehydrator.flush_all();
        if !remaining.is_empty() {
            output.push_str(&format_tail_event(false, 0, &remaining));
        }
        output.push_str("data: [DONE]\n\n");
        return;
    }

    match serde_json::from_str::<serde_json::Value>(data) {
        Ok(mut json) => {
            let event_type = json
                .get("type")
                .and_then(|v| v.as_str())
                .map(str::to_string);

            if matches!(
                event_type.as_deref(),
                Some(
                    "message_start"
                        | "content_block_start"
                        | "content_block_delta"
                        | "content_block_stop"
                        | "message_delta"
                        | "message_stop"
                )
            ) {
                *is_anthropic = true;
            }

            // OpenAI format: choices[0].delta.content
            if let Some(delta_content) = json
                .pointer("/choices/0/delta/content")
                .and_then(|v| v.as_str())
                .map(str::to_string)
            {
                let restored = rehydrator.feed(&delta_content);
                if let Some(c) = json.pointer_mut("/choices/0/delta/content") {
                    *c = serde_json::Value::String(restored);
                }
            }
            // Anthropic streaming format: delta.text
            else if let Some(delta_text) = json
                .pointer("/delta/text")
                .and_then(|v| v.as_str())
                .map(str::to_string)
            {
                *is_anthropic = true;
                let restored = rehydrator.feed(&delta_text);
                if let Some(c) = json.pointer_mut("/delta/text") {
                    *c = serde_json::Value::String(restored);
                }
            }

            if matches!(
                event_type.as_deref(),
                Some("content_block_stop" | "message_stop")
            ) {
                let remaining = rehydrator.flush_all();
                if !remaining.is_empty() {
                    let block_idx = json.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                    output.push_str(&format_tail_event(true, block_idx, &remaining));
                }
            }

            if let Some(prev) = pending_event_line.take() {
                output.push_str(&prev);
                output.push('\n');
            }
            let rewritten = serde_json::to_string(&json).unwrap_or_else(|_| data.to_string());
            output.push_str(&format!("data: {}\n\n", rewritten));
        }
        Err(_) => {
            if let Some(prev) = pending_event_line.take() {
                output.push_str(&prev);
                output.push('\n');
            }
            // Not valid JSON — forward as-is (handles keep-alive, comments, etc.)
            output.push_str(line);
            output.push_str("\n\n");
        }
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
    let mut rehydrator = SseRehydrator::new(&token_map);

    tokio::spawn(async move {
        futures::pin_mut!(byte_stream);
        let mut is_anthropic = false;
        let mut line_buffer = String::new();
        let mut pending_event_line: Option<String> = None;

        while let Some(chunk_result) = byte_stream.next().await {
            let chunk = match chunk_result {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("SSE upstream read error: {}", e);
                    break;
                }
            };

            let raw = match std::str::from_utf8(&chunk) {
                Ok(s) => s,
                Err(_) => {
                    if tx.send(Ok(chunk)).await.is_err() {
                        return;
                    }
                    continue;
                }
            };

            line_buffer.push_str(raw);
            let mut output = String::new();

            while let Some(nl_pos) = line_buffer.find('\n') {
                let line = line_buffer[..nl_pos].trim_end_matches('\r').to_string();
                line_buffer.drain(..=nl_pos);
                process_sse_line(
                    &line,
                    &mut rehydrator,
                    &mut is_anthropic,
                    &mut pending_event_line,
                    &mut output,
                );
            }

            if !output.is_empty() && tx.send(Ok(Bytes::from(output))).await.is_err() {
                return;
            }
        }

        // Process any remaining line without trailing newline + flush any partial token buffer at EOF
        let mut eof_output = String::new();
        if !line_buffer.is_empty() {
            let line = line_buffer.trim_end_matches('\r').to_string();
            process_sse_line(
                &line,
                &mut rehydrator,
                &mut is_anthropic,
                &mut pending_event_line,
                &mut eof_output,
            );
        }
        if let Some(prev) = pending_event_line.take() {
            eof_output.push_str(&prev);
            eof_output.push('\n');
        }
        let remaining = rehydrator.flush_all();
        if !remaining.is_empty() {
            eof_output.push_str(&format_tail_event(is_anthropic, 0, &remaining));
        }
        if !eof_output.is_empty() {
            let _ = tx.send(Ok(Bytes::from(eof_output))).await;
        }
    });

    let stream = ReceiverStream::new(rx);
    Response::builder()
        .status(200)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(stream))
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
