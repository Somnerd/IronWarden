//! SSE streaming proxy with split-token re-hydration buffer.
//!
//! Handles OpenAI (`choices[*].delta.{content,reasoning_content,tool_calls}`)
//! and Anthropic (`delta.{text,thinking,partial_json}`) SSE streams using a
//! zero-DFA length-sorted scanner.

use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use iw_core::TokenMap;
use serde_json::{json, Map, Value};
use std::borrow::Cow;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

const MAX_SSE_LINE_BYTES: usize = 1024 * 1024;
const MAX_PENDING_LINES: usize = 32;
const MAX_PENDING_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeMode {
    Plain,
    JsonString,
    SseSingleLine,
}

fn format_replacement(val: &str, mode: EscapeMode) -> Cow<'_, str> {
    match mode {
        EscapeMode::Plain => Cow::Borrowed(val),
        EscapeMode::JsonString => serde_json::to_string(val)
            .ok()
            .filter(|s| s.len() >= 2)
            .map(|s| Cow::Owned(s[1..s.len() - 1].to_string()))
            .unwrap_or(Cow::Borrowed(val)),
        EscapeMode::SseSingleLine if val.contains(['\n', '\r']) => {
            Cow::Owned(val.replace(['\r', '\n'], " "))
        }
        EscapeMode::SseSingleLine => Cow::Borrowed(val),
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
            Self::Owned(v) => v,
            Self::Shared(a) => a,
        }
    }
}

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
        if self.entries.as_slice().is_empty() {
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

    fn safe_boundary(&self, text: &str) -> usize {
        if let Some(pos) = text.rfind('[') {
            let tail = &text[pos..];
            if !tail.contains(']')
                && self
                    .entries
                    .as_slice()
                    .iter()
                    .any(|(k, _)| k.starts_with(tail) && tail.len() < k.len())
            {
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

fn emit_channel_tail(ch: StreamChannel, rem: String, out: &mut String) {
    if rem.is_empty() {
        return;
    }
    let (prefix, val) = match ch {
        StreamChannel::OpenAiContent(idx) => (
            "data: ",
            json!({"choices": [{"delta": {"content": rem}, "finish_reason": null, "index": idx}]}),
        ),
        StreamChannel::OpenAiReasoning(idx) => (
            "data: ",
            json!({"choices": [{"delta": {"reasoning_content": rem}, "finish_reason": null, "index": idx}]}),
        ),
        StreamChannel::OpenAiToolArgs(cidx, tidx) => (
            "data: ",
            json!({"choices": [{"delta": {"tool_calls": [{"index": tidx, "function": {"arguments": rem}}]}, "finish_reason": null, "index": cidx}]}),
        ),
        StreamChannel::AnthropicText(idx) => (
            "event: content_block_delta\ndata: ",
            json!({"type": "content_block_delta", "index": idx, "delta": {"type": "text_delta", "text": rem}}),
        ),
        StreamChannel::AnthropicThinking(idx) => (
            "event: content_block_delta\ndata: ",
            json!({"type": "content_block_delta", "index": idx, "delta": {"type": "thinking_delta", "thinking": rem}}),
        ),
        StreamChannel::AnthropicToolJson(idx) => (
            "event: content_block_delta\ndata: ",
            json!({"type": "content_block_delta", "index": idx, "delta": {"type": "input_json_delta", "partial_json": rem}}),
        ),
    };
    out.push_str(&format!("{prefix}{val}\n\n"));
}

fn openai_delta_has_metadata(delta_obj: &Map<String, Value>) -> bool {
    delta_obj.iter().any(|(k, v)| {
        if v.is_null() || k == "content" || k == "reasoning_content" {
            return false;
        }
        if k != "tool_calls" {
            return true;
        }
        v.as_array().is_some_and(|arr| {
            arr.iter().any(|tc| {
                tc.as_object().is_some_and(|tobj| {
                    tobj.iter()
                        .any(|(tk, tv)| !tv.is_null() && tk != "index" && tk != "function")
                        || tobj
                            .get("function")
                            .and_then(|f| f.as_object())
                            .is_some_and(|fobj| {
                                fobj.iter()
                                    .any(|(fk, fv)| fk != "arguments" && !fv.is_null())
                            })
                })
            })
        })
    })
}

struct SseState {
    entries: Arc<Vec<(String, String)>>,
    channels: BTreeMap<StreamChannel, SseRehydrator>,
    raw_fallback: SseRehydrator,
    last_block_idx: u64,
    pending_lines: Vec<String>,
    pending_bytes: usize,
    suppress_next_empty_line: bool,
    overflow_mode: Option<EscapeMode>,
}

impl SseState {
    fn feed_channel_slot(
        &mut self,
        ch: StreamChannel,
        slot: &mut String,
        flush_now: bool,
        had_input: &mut bool,
        has_output: &mut bool,
    ) {
        *had_input |= !slot.is_empty();
        let mode = ch.escape_mode();
        let entries = &self.entries;
        let reh = self
            .channels
            .entry(ch)
            .or_insert_with(|| SseRehydrator::from_shared(Arc::clone(entries)));
        let mut next = reh.feed_with_mode(slot, mode);
        if flush_now {
            next.push_str(&reh.flush_all_with_mode(mode));
        }
        *has_output |= !next.is_empty();
        *slot = next;
    }

    fn flush_pending(&mut self, out: &mut String) {
        for prev in self.pending_lines.drain(..) {
            out.push_str(&prev);
            out.push('\n');
        }
        self.pending_bytes = 0;
    }

    fn push_pending(&mut self, line: &str, out: &mut String) {
        if self.pending_lines.len() >= MAX_PENDING_LINES
            || self.pending_bytes + line.len() > MAX_PENDING_BYTES
        {
            self.flush_pending(out);
        }
        self.pending_bytes += line.len();
        self.pending_lines.push(line.to_string());
    }

    fn flush_matching<F>(&mut self, out: &mut String, pred: F)
    where
        F: Fn(StreamChannel) -> bool,
    {
        let keys: Vec<StreamChannel> = self
            .channels
            .iter()
            .filter(|(&ch, reh)| !reh.buffer.is_empty() && pred(ch))
            .map(|(&ch, _)| ch)
            .collect();
        for ch in keys {
            if let Some(reh) = self.channels.get_mut(&ch) {
                emit_channel_tail(ch, reh.flush_all_with_mode(ch.escape_mode()), out);
            }
        }
    }

    fn flush_all_tails(&mut self, out: &mut String) {
        self.flush_matching(out, |_| true);
    }

    fn process_openai_choices(
        &mut self,
        choices: &mut [Value],
        out: &mut String,
        had_input: &mut bool,
        has_output: &mut bool,
        has_metadata: &mut bool,
    ) {
        let mut finished_choices = Vec::new();
        for (pos, choice) in choices.iter_mut().enumerate() {
            let cidx = choice
                .get("index")
                .and_then(Value::as_u64)
                .map(|v| v as usize)
                .unwrap_or(pos);
            let finished = choice.get("finish_reason").is_some_and(|fr| !fr.is_null());
            if finished {
                *has_metadata = true;
                finished_choices.push(cidx);
            }
            let Some(delta_obj) = choice.get_mut("delta").and_then(Value::as_object_mut) else {
                continue;
            };
            *has_metadata |= openai_delta_has_metadata(delta_obj);

            if let Some(Value::String(s)) = delta_obj.get_mut("content") {
                self.feed_channel_slot(
                    StreamChannel::OpenAiContent(cidx),
                    s,
                    finished,
                    had_input,
                    has_output,
                );
            }
            if let Some(Value::String(s)) = delta_obj.get_mut("reasoning_content") {
                self.feed_channel_slot(
                    StreamChannel::OpenAiReasoning(cidx),
                    s,
                    finished,
                    had_input,
                    has_output,
                );
            }
            if let Some(tool_calls) = delta_obj
                .get_mut("tool_calls")
                .and_then(Value::as_array_mut)
            {
                for (tc_pos, tc) in tool_calls.iter_mut().enumerate() {
                    let tidx = tc
                        .get("index")
                        .and_then(Value::as_u64)
                        .map(|v| v as usize)
                        .unwrap_or(tc_pos);
                    if let Some(Value::String(s)) = tc.pointer_mut("/function/arguments") {
                        self.feed_channel_slot(
                            StreamChannel::OpenAiToolArgs(cidx, tidx),
                            s,
                            finished,
                            had_input,
                            has_output,
                        );
                    }
                }
            }
        }
        for cidx in finished_choices {
            self.flush_matching(out, |ch| ch.openai_choice_idx() == Some(cidx));
        }
    }

    fn process_anthropic_delta(
        &mut self,
        delta_obj: &mut Map<String, Value>,
        block_idx: u64,
        had_input: &mut bool,
        has_output: &mut bool,
        has_metadata: &mut bool,
    ) {
        *has_metadata |= delta_obj.iter().any(|(k, v)| {
            !v.is_null() && !matches!(k.as_str(), "type" | "text" | "thinking" | "partial_json")
        });
        for (field, ch) in [
            ("text", StreamChannel::AnthropicText(block_idx)),
            ("thinking", StreamChannel::AnthropicThinking(block_idx)),
            ("partial_json", StreamChannel::AnthropicToolJson(block_idx)),
        ] {
            if let Some(Value::String(s)) = delta_obj.get_mut(field) {
                self.feed_channel_slot(ch, s, false, had_input, has_output);
            }
        }
    }

    fn process_line(&mut self, line: &str, out: &mut String) {
        if let Some(mode) = self.overflow_mode.take() {
            self.suppress_next_empty_line = false;
            out.push_str(&self.raw_fallback.feed_with_mode(line, mode));
            out.push_str(&self.raw_fallback.flush_all_with_mode(mode));
            out.push('\n');
            return;
        }
        if line.is_empty() {
            if !self.pending_lines.is_empty() {
                self.flush_pending(out);
                out.push('\n');
            } else if !std::mem::take(&mut self.suppress_next_empty_line) {
                out.push('\n');
            }
            return;
        }
        if line.starts_with(':') && self.pending_lines.is_empty() {
            self.suppress_next_empty_line = false;
            out.push_str(line);
            out.push('\n');
            return;
        }
        if line.starts_with("event:")
            || line.starts_with("id:")
            || line.starts_with("retry:")
            || line.starts_with(':')
        {
            self.suppress_next_empty_line = false;
            self.push_pending(line, out);
            return;
        }

        let Some(raw_data) = line.strip_prefix("data:") else {
            self.suppress_next_empty_line = false;
            self.flush_pending(out);
            out.push_str(line);
            out.push('\n');
            return;
        };
        let data = raw_data.strip_prefix(' ').unwrap_or(raw_data);
        if data.trim() == "[DONE]" {
            self.flush_all_tails(out);
            self.flush_pending(out);
            out.push_str("data: [DONE]\n\n");
            self.suppress_next_empty_line = true;
            return;
        }
        let Ok(mut json) = serde_json::from_str::<Value>(data) else {
            self.flush_all_tails(out);
            self.flush_pending(out);
            out.push_str(
                &self
                    .raw_fallback
                    .feed_with_mode(line, EscapeMode::SseSingleLine),
            );
            out.push_str(
                &self
                    .raw_fallback
                    .flush_all_with_mode(EscapeMode::SseSingleLine),
            );
            out.push_str("\n\n");
            self.suppress_next_empty_line = true;
            return;
        };

        let event_type = json.get("type").and_then(Value::as_str).map(str::to_string);
        if let Some(idx) = json.get("index").and_then(Value::as_u64) {
            self.last_block_idx = idx;
        }
        let block_idx = self.last_block_idx;

        let mut had_input = false;
        let mut has_output = false;
        let mut has_metadata = json.get("usage").is_some_and(|v| !v.is_null());

        if let Some(choices) = json.get_mut("choices").and_then(Value::as_array_mut) {
            self.process_openai_choices(
                choices,
                out,
                &mut had_input,
                &mut has_output,
                &mut has_metadata,
            );
        } else if let Some(delta_obj) = json.get_mut("delta").and_then(Value::as_object_mut) {
            self.process_anthropic_delta(
                delta_obj,
                block_idx,
                &mut had_input,
                &mut has_output,
                &mut has_metadata,
            );
        }

        match event_type.as_deref() {
            Some("content_block_stop") => {
                self.flush_matching(out, |ch| ch.anthropic_block_idx() == Some(block_idx));
            }
            Some("message_stop") => self.flush_all_tails(out),
            _ if had_input && !has_output && !has_metadata => {
                self.pending_lines.clear();
                self.pending_bytes = 0;
                self.suppress_next_empty_line = true;
                return;
            }
            _ => {}
        }

        self.flush_pending(out);
        let rewritten = serde_json::to_string(&json).unwrap_or_else(|_| data.to_string());
        out.push_str(&format!("data: {rewritten}\n\n"));
        self.suppress_next_empty_line = true;
    }
}

fn decode_utf8_with_tail<'a>(
    bytes: &'a [u8],
    utf8_tail: &mut Vec<u8>,
    scratch: &'a mut String,
) -> &'a str {
    match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) if e.error_len().is_none() => {
            utf8_tail.extend_from_slice(&bytes[e.valid_up_to()..]);
            std::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or("")
        }
        Err(_) => {
            let start = bytes.len().saturating_sub(3);
            for i in (start..bytes.len()).rev() {
                if let Err(e) = std::str::from_utf8(&bytes[i..]) {
                    if e.valid_up_to() == 0 && e.error_len().is_none() {
                        utf8_tail.extend_from_slice(&bytes[i..]);
                        *scratch = String::from_utf8_lossy(&bytes[..i]).into_owned();
                        return scratch.as_str();
                    }
                }
            }
            *scratch = String::from_utf8_lossy(bytes).into_owned();
            scratch.as_str()
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
    let entries = Arc::new(build_sorted_entries(&token_map));
    let mut state = SseState {
        raw_fallback: SseRehydrator::from_shared(Arc::clone(&entries)),
        entries,
        channels: BTreeMap::new(),
        last_block_idx: 0,
        pending_lines: Vec::new(),
        pending_bytes: 0,
        suppress_next_empty_line: false,
        overflow_mode: None,
    };

    tokio::spawn(async move {
        futures::pin_mut!(byte_stream);
        let mut line_buffer = String::new();
        let mut utf8_tail = Vec::<u8>::with_capacity(4);

        while let Some(chunk_result) = byte_stream.next().await {
            let chunk = match chunk_result {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("SSE upstream read error: {e}");
                    tracing::error!("{msg}");
                    let _ = tx
                        .send(Err(axum::Error::new(std::io::Error::other(msg))))
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
            let mut scratch = String::new();
            line_buffer.push_str(decode_utf8_with_tail(bytes, &mut utf8_tail, &mut scratch));

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
                let mode = match state.overflow_mode {
                    Some(m) => m,
                    None => {
                        state.flush_all_tails(&mut output);
                        state.flush_pending(&mut output);
                        state.suppress_next_empty_line = false;
                        let is_json =
                            overflow
                                .trim_start()
                                .strip_prefix("data:")
                                .is_some_and(|d| {
                                    let t = d.trim_start();
                                    t.starts_with('{') || t.starts_with('[')
                                });
                        let m = if is_json {
                            EscapeMode::JsonString
                        } else {
                            EscapeMode::SseSingleLine
                        };
                        state.overflow_mode = Some(m);
                        m
                    }
                };
                output.push_str(&state.raw_fallback.feed_with_mode(&overflow, mode));
            }
            if !output.is_empty() && tx.send(Ok(Bytes::from(output))).await.is_err() {
                return;
            }
        }

        if !utf8_tail.is_empty() {
            line_buffer.push_str(&String::from_utf8_lossy(&utf8_tail));
        }
        let mut eof = String::new();
        if !line_buffer.is_empty() || state.overflow_mode.is_some() {
            state.process_line(line_buffer.trim_end_matches('\r'), &mut eof);
        }
        state.flush_all_tails(&mut eof);
        state.flush_pending(&mut eof);
        if !eof.is_empty() {
            let _ = tx.send(Ok(Bytes::from(eof))).await;
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
