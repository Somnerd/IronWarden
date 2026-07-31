//! SSE streaming proxy with split-token re-hydration buffer.
//!
//! Handles both OpenAI format (choices[0].delta.content)
//! and Anthropic format (delta.text) SSE streams.

use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use iw_core::TokenMap;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

/// Buffers streamed delta text and replaces PII placeholders,
/// even when they are split across chunk boundaries.
pub struct SseRehydrator {
    token_map: HashMap<String, String>,
    buffer: String,
}

impl SseRehydrator {
    pub fn new(token_map: &TokenMap) -> Self {
        let map = token_map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Self {
            token_map: map,
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
        let result = self.apply_replacements(&self.buffer.clone());
        self.buffer.clear();
        result
    }

    /// Emit all content up to the last open bracket that could be a partial token.
    fn flush_safe(&mut self) -> String {
        let safe_boundary = self.find_safe_boundary();
        if safe_boundary == 0 {
            return String::new();
        }
        let safe_chunk = self.buffer[..safe_boundary].to_string();
        self.buffer = self.buffer[safe_boundary..].to_string();
        self.apply_replacements(&safe_chunk)
    }

    fn find_safe_boundary(&self) -> usize {
        if let Some(open_bracket) = self.buffer.rfind('[') {
            let potential_token = &self.buffer[open_bracket..];
            let is_partial = self
                .token_map
                .keys()
                .any(|k| k.starts_with(potential_token) && potential_token.len() < k.len());
            if is_partial {
                return open_bracket;
            }
        }
        self.buffer.len()
    }

    fn apply_replacements(&self, text: &str) -> String {
        let mut result = text.to_string();
        for (placeholder, original) in &self.token_map {
            result = result.replace(placeholder.as_str(), original.as_str());
        }
        result
    }
}

/// Proxies an upstream SSE response to the client, re-hydrating PII placeholders in-flight.
/// Supports both OpenAI (`choices[0].delta.content`) and Anthropic (`delta.text`) formats.
pub async fn stream_proxy_response(
    upstream_response: reqwest::Response,
    token_map: TokenMap,
) -> Response<Body> {
    let (tx, rx) = mpsc::channel::<Result<Bytes, axum::Error>>(256);
    let mut rehydrator = SseRehydrator::new(&token_map);

    tokio::spawn(async move {
        let mut stream = upstream_response.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            let chunk = match chunk_result {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("SSE upstream read error: {}", e);
                    break;
                }
            };

            // Pass through binary data (e.g. keep-alive pings) as-is
            let raw = match std::str::from_utf8(&chunk) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    let _ = tx.send(Ok(chunk)).await;
                    continue;
                }
            };

            let mut output = String::new();

            for line in raw.lines() {
                if !line.starts_with("data: ") {
                    // Forward comment lines, event: lines, etc. unchanged
                    output.push_str(line);
                    output.push('\n');
                    continue;
                }

                let data = &line["data: ".len()..];

                if data.trim() == "[DONE]" {
                    // Flush anything remaining in the split-token buffer
                    let remaining = rehydrator.flush_all();
                    if !remaining.is_empty() {
                        let synthetic = serde_json::json!({
                            "choices": [{
                                "delta": {"content": remaining},
                                "finish_reason": null,
                                "index": 0
                            }]
                        });
                        output.push_str(&format!("data: {}\n\n", synthetic));
                    }
                    output.push_str("data: [DONE]\n\n");
                    continue;
                }

                match serde_json::from_str::<serde_json::Value>(data) {
                    Ok(mut json) => {
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
                            let restored = rehydrator.feed(&delta_text);
                            if let Some(c) = json.pointer_mut("/delta/text") {
                                *c = serde_json::Value::String(restored);
                            }
                        }

                        let rewritten =
                            serde_json::to_string(&json).unwrap_or_else(|_| data.to_string());
                        output.push_str(&format!("data: {}\n\n", rewritten));
                    }
                    Err(_) => {
                        // Not valid JSON — forward as-is (handles keep-alive, comments, etc.)
                        output.push_str(line);
                        output.push_str("\n\n");
                    }
                }
            }

            if !output.is_empty() {
                if tx.send(Ok(Bytes::from(output))).await.is_err() {
                    break; // Client disconnected
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use iw_core::TokenMap;

    fn map_with(entries: &[(&str, &str)]) -> TokenMap {
        let mut m = TokenMap::new();
        for (k, v) in entries {
            m.insert(k.to_string(), v.to_string());
        }
        m
    }

    #[test]
    fn test_rehydrator_simple() {
        let map = map_with(&[("[PERSON_1]", "John Smith")]);
        let mut r = SseRehydrator::new(&map);
        let out = r.feed("Hello [PERSON_1], how are you?");
        assert_eq!(out, "Hello John Smith, how are you?");
    }

    #[test]
    fn test_rehydrator_split_token() {
        let map = map_with(&[("[PERSON_1]", "John Smith")]);
        let mut r = SseRehydrator::new(&map);
        // Chunk 1 ends mid-placeholder
        let out1 = r.feed("Hello [PER");
        assert_eq!(out1, "Hello "); // holds [PER in buffer
                                    // Chunk 2 completes it
        let out2 = r.feed("SON_1], how are you?");
        assert_eq!(out2, "John Smith, how are you?");
    }

    #[test]
    fn test_rehydrator_flush_all() {
        let map = map_with(&[("[EMAIL_1]", "test@example.com")]);
        let mut r = SseRehydrator::new(&map);
        let _ = r.feed("contact: [EMAIL");
        let flushed = r.flush_all();
        // The partial token is present but no full match → emitted as-is
        assert!(flushed.contains("[EMAIL"));
    }

    #[test]
    fn test_rehydrator_no_placeholders() {
        let map = map_with(&[]);
        let mut r = SseRehydrator::new(&map);
        let out = r.feed("Just a plain message.");
        assert_eq!(out, "Just a plain message.");
    }
}
