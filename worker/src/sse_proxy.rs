//! SSE streaming proxy with split-token re-hydration buffer.
//!
//! Handles OpenAI (`choices[*].delta.{content,reasoning_content,tool_calls}`)
//! and Anthropic (`delta.{text,thinking,partial_json}`) SSE streams using a
//! zero-DFA single-pass scanner sorted by placeholder length.

use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use iw_core::TokenMap;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeMode {
    Plain,
    JsonString,
    SseSingleLine,
}

fn format_replacement(val: &str, mode: EscapeMode) -> std::borrow::Cow<'_, str> {
    match mode {
        EscapeMode::Plain => std::borrow::Cow::Borrowed(val),
        EscapeMode::JsonString => {
            if let Ok(serialized) = serde_json::to_string(val) {
                if serialized.len() >= 2 {
                    return std::borrow::Cow::Owned(
                        serialized[1..serialized.len() - 1].to_string(),
                    );
                }
            }
            std::borrow::Cow::Borrowed(val)
        }
        EscapeMode::SseSingleLine => {
            if val.contains(['\n', '\r']) {
                std::borrow::Cow::Owned(val.replace(['\r', '\n'], " "))
            } else {
                std::borrow::Cow::Borrowed(val)
            }
        }
    }
}

enum Entries {
    Owned(Vec<(String, String)>),
    Shared(Arc<Vec<(String, String)>>),
}

impl Entries {
    #[inline]
    fn as_slice(&self) -> &[(String, String)] {
        match self {
            Self::Owned(v) => v.as_slice(),
            Self::Shared(a) => a.as_slice(),
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

/// Builds a length-sorted placeholder entry table for one or more stream channels.
fn build_sorted_entries(token_map: &TokenMap) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = token_map
        .iter()
        .filter(|(k, _)| !k.is_empty())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    entries.sort_unstable_by_key(|(k, _)| Reverse(k.len()));
    entries
}

/// Buffers streamed delta text and replaces PII placeholders,
/// even when they are split across chunk boundaries.
pub struct SseRehydrator {
    /// `(placeholder, replacement)` sorted descending by placeholder length
    /// so longer tokens (e.g. `[TOKEN_10]`) match before prefixes (`[TOKEN_1]`).
    entries: Entries,
    buffer: String,
}

impl SseRehydrator {
    pub fn new(token_map: &TokenMap) -> Self {
        Self {
            entries: Entries::Owned(build_sorted_entries(token_map)),
            buffer: String::new(),
        }
    }

    fn from_shared(entries: Arc<Vec<(String, String)>>) -> Self {
        Self {
            entries: Entries::Shared(entries),
            buffer: String::new(),
        }
    }

    /// Feeds a new delta string and returns the prefix safe to emit immediately.
    pub fn feed(&mut self, delta: &str) -> String {
        self.feed_with_mode(delta, EscapeMode::Plain)
    }

    fn feed_with_mode(&mut self, delta: &str, mode: EscapeMode) -> String {
        if self.entries.is_empty() {
            return delta.to_string();
        }
        if self.buffer.is_empty() {
            let safe = self.safe_boundary(delta);
            if safe < delta.len() {
                self.buffer.push_str(&delta[safe..]);
            }
            return self.replace_tokens_with_mode(&delta[..safe], mode);
        }
        self.buffer.push_str(delta);
        let safe = self.safe_boundary(&self.buffer);
        if safe == 0 {
            return String::new();
        }
        let out = self.replace_tokens_with_mode(&self.buffer[..safe], mode);
        self.buffer.drain(..safe);
        out
    }

    /// Flushes and rehydrates everything remaining in the buffer at stream end.
    pub fn flush_all(&mut self) -> String {
        self.flush_all_with_mode(EscapeMode::Plain)
    }

    fn flush_all_with_mode(&mut self, mode: EscapeMode) -> String {
        if self.buffer.is_empty() {
            return String::new();
        }
        let out = self.replace_tokens_with_mode(&self.buffer, mode);
        self.buffer.clear();
        out
    }

    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn safe_boundary(&self, text: &str) -> usize {
        if let Some(pos) = text.rfind('[') {
            let tail = &text[pos..];
            let partial = !tail.contains(']')
                && self
                    .entries
                    .as_slice()
                    .iter()
                    .any(|(k, _)| k.starts_with(tail) && tail.len() < k.len());
            if partial {
                return pos;
            }
        }
        text.len()
    }

    fn replace_tokens_with_mode(&self, text: &str, mode: EscapeMode) -> String {
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
                .as_slice()
                .iter()
                .find(|(k, _)| rest.starts_with(k.as_str()))
            {
                if matches!(mode, EscapeMode::Plain) {
                    out.push_str(v);
                } else {
                    out.push_str(&format_replacement(v, mode));
                }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StreamChannel {
    OpenAiContent(usize),
    OpenAiReasoning(usize),
    OpenAiToolArgs(usize, usize),
    AnthropicText(u64),
    AnthropicThinking(u64),
    AnthropicToolJson(u64),
}

impl StreamChannel {
    fn escape_mode(self) -> EscapeMode {
        match self {
            Self::OpenAiToolArgs(_, _) | Self::AnthropicToolJson(_) => EscapeMode::JsonString,
            _ => EscapeMode::Plain,
        }
    }

    fn openai_choice_idx(self) -> Option<usize> {
        match self {
            Self::OpenAiContent(c) | Self::OpenAiReasoning(c) | Self::OpenAiToolArgs(c, _) => {
                Some(c)
            }
            _ => None,
        }
    }

    fn anthropic_block_idx(self) -> Option<u64> {
        match self {
            Self::AnthropicText(b) | Self::AnthropicThinking(b) | Self::AnthropicToolJson(b) => {
                Some(b)
            }
            _ => None,
        }
    }
}

struct SseState {
    entries: Arc<Vec<(String, String)>>,
    channels: BTreeMap<StreamChannel, SseRehydrator>,
    raw_fallback: SseRehydrator,
    last_block_idx: u64,
    pending_lines: Vec<String>,
    suppress_next_empty_line: bool,
    in_overflow_line: bool,
    overflow_is_json: bool,
}

impl SseState {
    fn channel_mut(&mut self, ch: StreamChannel) -> &mut SseRehydrator {
        let entries = &self.entries;
        self.channels
            .entry(ch)
            .or_insert_with(|| SseRehydrator::from_shared(Arc::clone(entries)))
    }

    fn flush_pending(&mut self, out: &mut String) {
        for prev in self.pending_lines.drain(..) {
            out.push_str(&prev);
            out.push('\n');
        }
    }

    fn emit_channel_tail(ch: StreamChannel, rem: String, out: &mut String) {
        if rem.is_empty() {
            return;
        }
        match ch {
            StreamChannel::OpenAiContent(idx) => {
                let v = serde_json::json!({
                    "choices": [{ "delta": { "content": rem }, "finish_reason": null, "index": idx }]
                });
                out.push_str(&format!("data: {v}\n\n"));
            }
            StreamChannel::OpenAiReasoning(idx) => {
                let v = serde_json::json!({
                    "choices": [{ "delta": { "reasoning_content": rem }, "finish_reason": null, "index": idx }]
                });
                out.push_str(&format!("data: {v}\n\n"));
            }
            StreamChannel::OpenAiToolArgs(cidx, tidx) => {
                let v = serde_json::json!({
                    "choices": [{
                        "delta": { "tool_calls": [{ "index": tidx, "function": { "arguments": rem } }] },
                        "finish_reason": null,
                        "index": cidx
                    }]
                });
                out.push_str(&format!("data: {v}\n\n"));
            }
            StreamChannel::AnthropicText(idx) => {
                let v = serde_json::json!({
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": { "type": "text_delta", "text": rem }
                });
                out.push_str(&format!("event: content_block_delta\ndata: {v}\n\n"));
            }
            StreamChannel::AnthropicThinking(idx) => {
                let v = serde_json::json!({
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": { "type": "thinking_delta", "thinking": rem }
                });
                out.push_str(&format!("event: content_block_delta\ndata: {v}\n\n"));
            }
            StreamChannel::AnthropicToolJson(idx) => {
                let v = serde_json::json!({
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": { "type": "input_json_delta", "partial_json": rem }
                });
                out.push_str(&format!("event: content_block_delta\ndata: {v}\n\n"));
            }
        }
    }

    fn flush_matching_channels<F>(&mut self, out: &mut String, pred: F)
    where
        F: Fn(StreamChannel) -> bool,
    {
        let keys: Vec<StreamChannel> = self
            .channels
            .iter()
            .filter(|(&ch, reh)| !reh.is_empty() && pred(ch))
            .map(|(&ch, _)| ch)
            .collect();
        for ch in keys {
            if let Some(reh) = self.channels.get_mut(&ch) {
                let rem = reh.flush_all_with_mode(ch.escape_mode());
                Self::emit_channel_tail(ch, rem, out);
            }
        }
    }

    fn push_all_tail_deltas(&mut self, out: &mut String) {
        self.flush_matching_channels(out, |_| true);
    }

    fn process_line(&mut self, line: &str, output: &mut String) {
        if self.in_overflow_line {
            self.in_overflow_line = false;
            self.suppress_next_empty_line = false;
            let mode = if self.overflow_is_json {
                EscapeMode::JsonString
            } else {
                EscapeMode::SseSingleLine
            };
            self.overflow_is_json = false;
            let rehydrated = self.raw_fallback.feed_with_mode(line, mode);
            let flushed = self.raw_fallback.flush_all_with_mode(mode);
            output.push_str(&rehydrated);
            output.push_str(&flushed);
            output.push('\n');
            return;
        }

        if line.is_empty() {
            if !self.pending_lines.is_empty() {
                self.flush_pending(output);
                output.push('\n');
                self.suppress_next_empty_line = false;
                return;
            }
            if self.suppress_next_empty_line {
                self.suppress_next_empty_line = false;
                return;
            }
            output.push('\n');
            return;
        }

        if line.starts_with("event:")
            || line.starts_with("id:")
            || line.starts_with("retry:")
            || line.starts_with(':')
        {
            self.suppress_next_empty_line = false;
            self.pending_lines.push(line.to_string());
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
            self.push_all_tail_deltas(output);
            self.flush_pending(output);
            output.push_str("data: [DONE]\n\n");
            self.suppress_next_empty_line = true;
            return;
        }
        let Ok(mut json) = serde_json::from_str::<serde_json::Value>(data) else {
            self.push_all_tail_deltas(output);
            self.flush_pending(output);
            let rehydrated = self
                .raw_fallback
                .feed_with_mode(line, EscapeMode::SseSingleLine);
            let flushed = self
                .raw_fallback
                .flush_all_with_mode(EscapeMode::SseSingleLine);
            output.push_str(&rehydrated);
            output.push_str(&flushed);
            output.push_str("\n\n");
            self.suppress_next_empty_line = true;
            return;
        };

        let event_type = json
            .get("type")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let block_idx = json
            .get("index")
            .and_then(|v| v.as_u64())
            .unwrap_or(self.last_block_idx);
        if json.get("index").and_then(|v| v.as_u64()).is_some() {
            self.last_block_idx = block_idx;
        }

        let has_top_metadata = json.get("usage").is_some_and(|v| !v.is_null());
        let mut had_non_empty_delta = false;
        let mut has_non_empty_output = false;
        let mut has_metadata = has_top_metadata;

        if let Some(choices) = json.get_mut("choices").and_then(|v| v.as_array_mut()) {
            let mut finished_choices = Vec::new();
            for (pos, choice) in choices.iter_mut().enumerate() {
                let cidx = choice
                    .get("index")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(pos);
                let choice_finished = choice.get("finish_reason").is_some_and(|fr| !fr.is_null());
                if choice_finished {
                    has_metadata = true;
                    finished_choices.push(cidx);
                }

                if let Some(delta_obj) = choice.get_mut("delta").and_then(|d| d.as_object_mut()) {
                    for (k, v) in delta_obj.iter() {
                        if v.is_null() || k == "content" || k == "reasoning_content" {
                            continue;
                        }
                        if k == "tool_calls" {
                            let tc_has_meta = v.as_array().is_some_and(|arr| {
                                arr.iter().any(|tc| {
                                    tc.as_object().is_some_and(|tobj| {
                                        tobj.iter().any(|(tk, tv)| {
                                            !tv.is_null() && tk != "index" && tk != "function"
                                        }) || tobj
                                            .get("function")
                                            .and_then(|f| f.as_object())
                                            .is_some_and(|fobj| {
                                                fobj.iter().any(|(fk, fv)| {
                                                    fk != "arguments" && !fv.is_null()
                                                })
                                            })
                                    })
                                })
                            });
                            if tc_has_meta {
                                has_metadata = true;
                            }
                        } else {
                            has_metadata = true;
                        }
                    }

                    if let Some(serde_json::Value::String(s)) = delta_obj.get_mut("content") {
                        let ch = StreamChannel::OpenAiContent(cidx);
                        had_non_empty_delta |= !s.is_empty();
                        let mut next = self.channel_mut(ch).feed_with_mode(s, ch.escape_mode());
                        if choice_finished {
                            next.push_str(
                                &self.channel_mut(ch).flush_all_with_mode(ch.escape_mode()),
                            );
                        }
                        if !next.is_empty() {
                            has_non_empty_output = true;
                        }
                        *s = next;
                    }

                    if let Some(serde_json::Value::String(s)) =
                        delta_obj.get_mut("reasoning_content")
                    {
                        let ch = StreamChannel::OpenAiReasoning(cidx);
                        had_non_empty_delta |= !s.is_empty();
                        let mut next = self.channel_mut(ch).feed_with_mode(s, ch.escape_mode());
                        if choice_finished {
                            next.push_str(
                                &self.channel_mut(ch).flush_all_with_mode(ch.escape_mode()),
                            );
                        }
                        if !next.is_empty() {
                            has_non_empty_output = true;
                        }
                        *s = next;
                    }

                    if let Some(tool_calls) = delta_obj
                        .get_mut("tool_calls")
                        .and_then(|v| v.as_array_mut())
                    {
                        for (tc_pos, tc) in tool_calls.iter_mut().enumerate() {
                            let tidx = tc
                                .get("index")
                                .and_then(|v| v.as_u64())
                                .map(|v| v as usize)
                                .unwrap_or(tc_pos);
                            if let Some(serde_json::Value::String(s)) =
                                tc.pointer_mut("/function/arguments")
                            {
                                let ch = StreamChannel::OpenAiToolArgs(cidx, tidx);
                                had_non_empty_delta |= !s.is_empty();
                                let mut next =
                                    self.channel_mut(ch).feed_with_mode(s, ch.escape_mode());
                                if choice_finished {
                                    next.push_str(
                                        &self.channel_mut(ch).flush_all_with_mode(ch.escape_mode()),
                                    );
                                }
                                if !next.is_empty() {
                                    has_non_empty_output = true;
                                }
                                *s = next;
                            }
                        }
                    }
                }
            }

            for cidx in finished_choices {
                self.flush_matching_channels(output, |ch| ch.openai_choice_idx() == Some(cidx));
            }
        } else if let Some(delta_obj) = json.get_mut("delta").and_then(|d| d.as_object_mut()) {
            for (k, v) in delta_obj.iter() {
                if !v.is_null()
                    && k != "type"
                    && k != "text"
                    && k != "thinking"
                    && k != "partial_json"
                {
                    has_metadata = true;
                }
            }
            for (field, ch) in [
                ("text", StreamChannel::AnthropicText(block_idx)),
                ("thinking", StreamChannel::AnthropicThinking(block_idx)),
                ("partial_json", StreamChannel::AnthropicToolJson(block_idx)),
            ] {
                if let Some(serde_json::Value::String(s)) = delta_obj.get_mut(field) {
                    had_non_empty_delta |= !s.is_empty();
                    let next = self.channel_mut(ch).feed_with_mode(s, ch.escape_mode());
                    if !next.is_empty() {
                        has_non_empty_output = true;
                    }
                    *s = next;
                }
            }
        }

        match event_type.as_deref() {
            Some("content_block_stop") => {
                self.flush_matching_channels(output, |ch| {
                    ch.anthropic_block_idx() == Some(block_idx)
                });
            }
            Some("message_stop") => {
                self.push_all_tail_deltas(output);
            }
            _ if had_non_empty_delta && !has_non_empty_output && !has_metadata => {
                self.pending_lines.clear();
                self.suppress_next_empty_line = true;
                return;
            }
            _ => {}
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
    let entries = Arc::new(build_sorted_entries(&token_map));
    let mut state = SseState {
        raw_fallback: SseRehydrator::from_shared(Arc::clone(&entries)),
        entries,
        channels: BTreeMap::new(),
        last_block_idx: 0,
        pending_lines: Vec::new(),
        suppress_next_empty_line: false,
        in_overflow_line: false,
        overflow_is_json: false,
    };

    tokio::spawn(async move {
        futures::pin_mut!(byte_stream);
        let mut line_buffer = String::new();
        let mut utf8_tail = Vec::<u8>::with_capacity(4);

        while let Some(chunk_result) = byte_stream.next().await {
            let chunk = match chunk_result {
                Ok(b) => b,
                Err(e) => {
                    let err_msg = format!("SSE upstream read error: {}", e);
                    tracing::error!("{}", err_msg);
                    let _ = tx
                        .send(Err(axum::Error::new(std::io::Error::other(err_msg))))
                        .await;
                    return;
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
                    state.push_all_tail_deltas(&mut output);
                    state.flush_pending(&mut output);
                    state.suppress_next_empty_line = false;
                    state.in_overflow_line = true;
                    state.overflow_is_json = overflow
                        .trim_start()
                        .strip_prefix("data:")
                        .is_some_and(|d| {
                            let t = d.trim_start();
                            t.starts_with('{') || t.starts_with('[')
                        });
                }
                let mode = if state.overflow_is_json {
                    EscapeMode::JsonString
                } else {
                    EscapeMode::SseSingleLine
                };
                let rehydrated = state.raw_fallback.feed_with_mode(&overflow, mode);
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
        if !line_buffer.is_empty() || state.in_overflow_line {
            state.process_line(line_buffer.trim_end_matches('\r'), &mut eof_output);
        }
        state.push_all_tail_deltas(&mut eof_output);
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
/// Supports both OpenAI (`choices[*].delta.*`) and Anthropic (`delta.*`) formats.
pub async fn stream_proxy_response(
    upstream_response: reqwest::Response,
    token_map: TokenMap,
) -> Response<Body> {
    stream_sse_bytes(upstream_response.bytes_stream(), token_map)
}
