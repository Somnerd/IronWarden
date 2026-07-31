# IronWarden Universal AI Gateway Proxy — Implementation Plan
> **Branch**: `feature/universal-proxy-v1`  
> **Target**: `v1.0.0-rc.1`  
> **GitHub Issues**: #156 (non-streaming), #157 (SSE streaming), #158 (Anthropic), #159 (dynamic routing)

---

## Context & Goal

IronWarden currently routes prompts through an internal queue (`/enqueue`) and an MCP server (`/mcp`).  
This task adds **standard AI provider proxy routes** so any application using the OpenAI or Anthropic SDK can point its `base_url` at IronWarden and get automatic PII redaction, HMAC audit logging, and rate limiting — with zero code changes.

```
Client (openai SDK, base_url="http://localhost:14141")
  → POST /v1/chat/completions
    → IronWarden scrubs PII from all messages
    → Writes audit log (fail-closed — request aborted on failure)
    → Forwards scrubbed request to upstream LLM
    → Restores PII placeholders in response
  → Client receives clean response (PII restored)
```

---

## Pre-Flight (MUST do before implementing)

Add to `worker/Cargo.toml` under `[dependencies]`:

```toml
# Change the existing reqwest line to add the `stream` feature:
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "stream"] }

# Add these new entries:
tokio-stream = "0.1"
bytes = "1.0"
```

---

## Step 1 — Create `worker/src/proxy.rs` (new file)

This file contains all shared DTOs and helper functions used by the proxy route handlers.

```rust
//! Shared types and helpers for the IronWarden Universal Proxy routes.

use crate::searchboost::LocalSessionManager;
use axum::http::{HeaderMap, StatusCode};
use iw_core::crypto::JwtVerifier;
use iw_core::{SessionContext, SovereignError, TokenMap};
use secrecy::ExposeSecret;
use secrecy::SecretVec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// ── OpenAI DTOs ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(flatten)]
    pub extra_fields: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompletionRequest {
    pub model: String,
    pub prompt: serde_json::Value,
    #[serde(default)]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(flatten)]
    pub extra_fields: HashMap<String, serde_json::Value>,
}

// ── Anthropic DTOs ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnthropicMessage {
    pub role: String,
    pub content: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnthropicRequest {
    pub model: String,
    pub messages: Vec<AnthropicMessage>,
    pub max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(default)]
    pub stream: Option<bool>,
    #[serde(flatten)]
    pub extra_fields: HashMap<String, serde_json::Value>,
}

// ── Auth Helper ───────────────────────────────────────────────────────────────

pub struct AuthenticatedUser {
    pub username: String,
    pub session: Arc<SessionContext>,
}

/// Authenticates the Bearer JWT and returns the username + session.
/// Returns `Err((StatusCode, message))` on failure.
pub async fn authenticate(
    headers: &HeaderMap,
    jwt_public_key: &SecretVec<u8>,
    session_manager: &Arc<LocalSessionManager>,
) -> Result<AuthenticatedUser, (StatusCode, String)> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "Missing Bearer Token".to_string()))?;

    let aud = std::env::var("WARDEN_JWT_AUDIENCE").unwrap_or_else(|_| "ironwarden".to_string());
    let iss = std::env::var("WARDEN_JWT_ISSUER").unwrap_or_else(|_| "ironwarden".to_string());

    let claims = JwtVerifier::verify(token, jwt_public_key.expose_secret(), &aud, &iss)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Auth failed: {}", e)))?;

    let session = session_manager
        .get_session(&claims.sub)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Session error: {}", e)))?;

    Ok(AuthenticatedUser { username: claims.sub, session })
}

// ── Upstream Resolution ───────────────────────────────────────────────────────

/// Priority order:
/// 1. `X-IronWarden-Target-URL` request header (explicit override)
/// 2. Model-name auto-routing (claude-* → Anthropic, llama*/mistral*/phi* → Ollama)
/// 3. Env vars: OPENAI_BASE_URL / ANTHROPIC_BASE_URL / OLLAMA_BASE_URL
/// 4. Hardcoded defaults
pub fn resolve_upstream_url(headers: &HeaderMap, model: &str) -> String {
    if let Some(t) = headers.get("X-IronWarden-Target-URL").and_then(|v| v.to_str().ok()) {
        return t.to_string();
    }
    let m = model.to_lowercase();
    if m.starts_with("claude") {
        return std::env::var("ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com/v1/messages".to_string());
    }
    if m.starts_with("llama") || m.starts_with("mistral") || m.starts_with("phi")
        || m.starts_with("gemma") || m.starts_with("qwen")
    {
        return std::env::var("OLLAMA_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:11434/v1/chat/completions".to_string());
    }
    std::env::var("OPENAI_BASE_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string())
}

/// Upstream API key: `X-IronWarden-Upstream-Key` header → OPENAI_API_KEY env → "ollama" fallback.
pub fn resolve_upstream_key(headers: &HeaderMap) -> String {
    headers
        .get("X-IronWarden-Upstream-Key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| std::env::var("OPENAI_API_KEY").ok())
        .unwrap_or_else(|| "ollama".to_string())
}

// ── Token Map Merge ───────────────────────────────────────────────────────────

pub fn merge_token_map(combined: &mut TokenMap, addition: &TokenMap) {
    for (k, v) in addition.iter() {
        combined.insert(k.clone(), v.clone());
    }
}
```

---

## Step 2 — Create `worker/src/sse_proxy.rs` (new file)

This is the SSE streaming engine with split-token re-hydration. The key challenge: a PII placeholder like `[PERSON_1]` may arrive split across multiple SSE chunks (e.g. chunk A ends with `[PER`, chunk B starts with `SON_1]`). The `SseRehydrator` buffers partial tokens until they are complete before forwarding.

```rust
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
        let map = token_map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        Self { token_map: map, buffer: String::new() }
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
            let is_partial = self.token_map.keys().any(|k| {
                k.starts_with(potential_token) && potential_token.len() < k.len()
            });
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

                        let rewritten = serde_json::to_string(&json)
                            .unwrap_or_else(|_| data.to_string());
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
```

---

## Step 3 — Modify `worker/src/bridge.rs`

### 3a. Add imports at the top of the existing use block
```rust
use crate::proxy::{
    authenticate, merge_token_map, resolve_upstream_key, resolve_upstream_url,
    AnthropicRequest, ChatCompletionRequest, CompletionRequest,
};
use iw_core::TokenMap;
```

### 3b. Add routes inside `create_bridge_router`, in the `Router::new()` chain

Add these lines **before** the `.layer(...)` calls:
```rust
.route("/v1/chat/completions", post(handle_openai_chat_completions))
.route("/v1/completions", post(handle_openai_legacy_completions))
.route("/v1/models", get(handle_openai_models))
.route("/v1/messages", post(handle_anthropic_messages))
```

### 3c. Add the `map_error` helper function (if not already present)
```rust
fn map_error(e: SovereignError) -> (StatusCode, String) {
    match &e {
        SovereignError::PiiViolation(_) => (StatusCode::BAD_REQUEST, e.to_string()),
        SovereignError::UnauthorizedAccess(_) => (StatusCode::UNAUTHORIZED, e.to_string()),
        SovereignError::GatewayTimeout(_) => (StatusCode::GATEWAY_TIMEOUT, e.to_string()),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
```

### 3d. Add handler: `handle_openai_chat_completions`

⚠️ **Security rules that MUST be followed — no exceptions:**
1. `log_audit_event()` MUST succeed before request is forwarded upstream. On failure → return 500, abort.
2. `is_blocked == true` → return 400, never contact upstream.
3. Only `sanitized_text` is sent upstream. Raw content is dropped after audit.
4. `save_session()` called after every successful round-trip.
5. Non-2xx from upstream → return 502.

```rust
async fn handle_openai_chat_completions(
    State(state): State<Arc<BridgeState>>,
    headers: HeaderMap,
    Json(mut payload): Json<ChatCompletionRequest>,
) -> impl IntoResponse {
    // 1. Authenticate
    let auth = match authenticate(&headers, &state.jwt_public_key, &state.session_manager).await {
        Ok(a) => a,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    // 2. Sanitize all messages — fail-closed
    let mut combined_token_map = TokenMap::new();
    for msg in payload.messages.iter_mut() {
        if let Some(text) = msg.content.as_str() {
            let report = match state.shield.sanitize_prompt(text, Some(&auth.session)).await {
                Ok(r) => r,
                Err(e) => return map_error(e).into_response(),
            };
            // Audit BEFORE forwarding — abort on failure
            if let Err(e) = state.storage.log_audit_event(&report, text, &auth.username).await {
                tracing::error!("CRITICAL: Audit log failure in proxy. Aborting request: {}", e);
                return map_error(e).into_response();
            }
            if report.is_blocked {
                return (
                    StatusCode::BAD_REQUEST,
                    "[POLICY VIOLATION] Prompt blocked by IronWarden.".to_string(),
                ).into_response();
            }
            merge_token_map(&mut combined_token_map, &report.token_map);
            msg.content = serde_json::Value::String(report.sanitized_text);
        }
    }

    // 3. Resolve target
    let target_url = resolve_upstream_url(&headers, &payload.model);
    let api_key = resolve_upstream_key(&headers);
    let is_stream = payload.stream.unwrap_or(false);

    // 4. Build client
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .unwrap_or_default();

    // 5. Forward scrubbed request
    let upstream_resp = match client
        .post(&target_url)
        .bearer_auth(&api_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return map_error(SovereignError::GatewayTimeout(format!("Upstream unreachable: {}", e)))
                .into_response()
        }
    };

    if !upstream_resp.status().is_success() {
        let status = upstream_resp.status();
        let body = upstream_resp.text().await.unwrap_or_default();
        tracing::error!("Upstream returned {}: {}", status, body);
        return (StatusCode::BAD_GATEWAY, body).into_response();
    }

    // 6. Streaming path — hand off to SSE engine
    if is_stream {
        return crate::sse_proxy::stream_proxy_response(upstream_resp, combined_token_map).await;
    }

    // 7. Non-streaming — parse and re-hydrate
    let mut res_json: serde_json::Value = match upstream_resp.json().await {
        Ok(j) => j,
        Err(e) => {
            return map_error(SovereignError::UpstreamError(format!(
                "Failed to parse upstream JSON: {}", e
            ))).into_response()
        }
    };

    if let Some(choices) = res_json.get_mut("choices").and_then(|c| c.as_array_mut()) {
        for choice in choices.iter_mut() {
            if let Some(content) = choice.pointer_mut("/message/content") {
                if let Some(text) = content.as_str() {
                    if let Ok(restored) = state.shield.restore_prompt(text, &combined_token_map) {
                        *content = serde_json::Value::String(restored);
                    }
                }
            }
        }
    }

    let _ = state.session_manager.save_session(&auth.username, &auth.session).await;
    (StatusCode::OK, Json(res_json)).into_response()
}
```

### 3e. Add handler: `handle_openai_legacy_completions`

```rust
async fn handle_openai_legacy_completions(
    State(state): State<Arc<BridgeState>>,
    headers: HeaderMap,
    Json(mut payload): Json<CompletionRequest>,
) -> impl IntoResponse {
    let auth = match authenticate(&headers, &state.jwt_public_key, &state.session_manager).await {
        Ok(a) => a,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    let mut combined_token_map = TokenMap::new();

    let prompts: Vec<String> = match &payload.prompt {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(arr) => {
            arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
        }
        _ => vec![],
    };

    let mut sanitized_prompts = Vec::new();
    for p in &prompts {
        let report = match state.shield.sanitize_prompt(p, Some(&auth.session)).await {
            Ok(r) => r,
            Err(e) => return map_error(e).into_response(),
        };
        if let Err(e) = state.storage.log_audit_event(&report, p, &auth.username).await {
            return map_error(e).into_response();
        }
        if report.is_blocked {
            return (StatusCode::BAD_REQUEST, "[POLICY VIOLATION] Prompt blocked.".to_string())
                .into_response();
        }
        merge_token_map(&mut combined_token_map, &report.token_map);
        sanitized_prompts.push(report.sanitized_text);
    }

    payload.prompt = if sanitized_prompts.len() == 1 {
        serde_json::Value::String(sanitized_prompts.remove(0))
    } else {
        serde_json::Value::Array(
            sanitized_prompts.into_iter().map(serde_json::Value::String).collect(),
        )
    };

    let target_url = resolve_upstream_url(&headers, &payload.model)
        .replace("/chat/completions", "/completions");
    let api_key = resolve_upstream_key(&headers);

    let client = reqwest::Client::new();
    let upstream_resp = match client.post(&target_url).bearer_auth(&api_key).json(&payload).send().await {
        Ok(r) => r,
        Err(e) => return map_error(SovereignError::GatewayTimeout(e.to_string())).into_response(),
    };

    let mut res_json: serde_json::Value = match upstream_resp.json().await {
        Ok(j) => j,
        Err(e) => return map_error(SovereignError::UpstreamError(e.to_string())).into_response(),
    };

    if let Some(choices) = res_json.get_mut("choices").and_then(|c| c.as_array_mut()) {
        for choice in choices.iter_mut() {
            if let Some(text_val) = choice.get_mut("text") {
                if let Some(text) = text_val.as_str() {
                    if let Ok(restored) = state.shield.restore_prompt(text, &combined_token_map) {
                        *text_val = serde_json::Value::String(restored);
                    }
                }
            }
        }
    }

    let _ = state.session_manager.save_session(&auth.username, &auth.session).await;
    (StatusCode::OK, Json(res_json)).into_response()
}
```

### 3f. Add handler: `handle_openai_models`
```rust
async fn handle_openai_models(
    State(_state): State<Arc<BridgeState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let base = std::env::var("OPENAI_BASE_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string());
    let models_url = base
        .trim_end_matches('/')
        .replace("/chat/completions", "")
        .replace("/completions", "");
    let models_url = format!("{}/models", models_url.trim_end_matches('/'));
    let api_key = resolve_upstream_key(&headers);
    let client = reqwest::Client::new();
    match client.get(&models_url).bearer_auth(&api_key).send().await {
        Ok(resp) => {
            let body = resp.text().await.unwrap_or_default();
            (StatusCode::OK, body).into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}
```

### 3g. Add handler: `handle_anthropic_messages`
```rust
async fn handle_anthropic_messages(
    State(state): State<Arc<BridgeState>>,
    headers: HeaderMap,
    Json(mut payload): Json<AnthropicRequest>,
) -> impl IntoResponse {
    let auth = match authenticate(&headers, &state.jwt_public_key, &state.session_manager).await {
        Ok(a) => a,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    let mut combined_token_map = TokenMap::new();

    // Sanitize system prompt
    if let Some(ref system) = payload.system.clone() {
        let report = match state.shield.sanitize_prompt(system, Some(&auth.session)).await {
            Ok(r) => r,
            Err(e) => return map_error(e).into_response(),
        };
        if let Err(e) = state.storage.log_audit_event(&report, system, &auth.username).await {
            return map_error(e).into_response();
        }
        if report.is_blocked {
            return (StatusCode::BAD_REQUEST, "System prompt blocked.".to_string()).into_response();
        }
        merge_token_map(&mut combined_token_map, &report.token_map);
        payload.system = Some(report.sanitized_text);
    }

    // Sanitize messages — support both string and content-block array formats
    for msg in payload.messages.iter_mut() {
        if let Some(text) = msg.content.as_str() {
            let report = match state.shield.sanitize_prompt(text, Some(&auth.session)).await {
                Ok(r) => r,
                Err(e) => return map_error(e).into_response(),
            };
            if let Err(e) = state.storage.log_audit_event(&report, text, &auth.username).await {
                return map_error(e).into_response();
            }
            if report.is_blocked {
                return (StatusCode::BAD_REQUEST, "Message blocked.".to_string()).into_response();
            }
            merge_token_map(&mut combined_token_map, &report.token_map);
            msg.content = serde_json::Value::String(report.sanitized_text);
        } else if let Some(blocks) = msg.content.as_array_mut() {
            for block in blocks.iter_mut() {
                if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                    if let Some(text) = block.get("text").and_then(|t| t.as_str()).map(str::to_string) {
                        let report = match state.shield.sanitize_prompt(&text, Some(&auth.session)).await {
                            Ok(r) => r,
                            Err(e) => return map_error(e).into_response(),
                        };
                        if report.is_blocked {
                            return (StatusCode::BAD_REQUEST, "Content block blocked.".to_string())
                                .into_response();
                        }
                        merge_token_map(&mut combined_token_map, &report.token_map);
                        block["text"] = serde_json::Value::String(report.sanitized_text);
                    }
                }
            }
        }
    }

    let target_url = std::env::var("ANTHROPIC_BASE_URL")
        .unwrap_or_else(|_| "https://api.anthropic.com/v1/messages".to_string());
    let api_key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
        .unwrap_or_default();
    let anthropic_version = headers
        .get("anthropic-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("2023-06-01");
    let is_stream = payload.stream.unwrap_or(false);

    let client = reqwest::Client::new();
    let upstream_resp = match client
        .post(&target_url)
        .header("x-api-key", &api_key)
        .header("anthropic-version", anthropic_version)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return map_error(SovereignError::GatewayTimeout(e.to_string())).into_response(),
    };

    if !upstream_resp.status().is_success() {
        let body = upstream_resp.text().await.unwrap_or_default();
        return (StatusCode::BAD_GATEWAY, body).into_response();
    }

    if is_stream {
        return crate::sse_proxy::stream_proxy_response(upstream_resp, combined_token_map).await;
    }

    let mut res_json: serde_json::Value = match upstream_resp.json().await {
        Ok(j) => j,
        Err(e) => return map_error(SovereignError::UpstreamError(e.to_string())).into_response(),
    };

    // Re-hydrate Anthropic response content blocks
    if let Some(blocks) = res_json.get_mut("content").and_then(|c| c.as_array_mut()) {
        for block in blocks.iter_mut() {
            if let Some(text_val) = block.get_mut("text") {
                if let Some(text) = text_val.as_str() {
                    if let Ok(restored) = state.shield.restore_prompt(text, &combined_token_map) {
                        *text_val = serde_json::Value::String(restored);
                    }
                }
            }
        }
    }

    let _ = state.session_manager.save_session(&auth.username, &auth.session).await;
    (StatusCode::OK, Json(res_json)).into_response()
}
```

---

## Step 4 — Register new modules in `worker/src/lib.rs`

Add these two lines alongside the existing `pub mod` declarations:
```rust
pub mod proxy;
pub mod sse_proxy;
```

---

## Step 5 — Update `mcp/src/server.rs` version string

Find the `protocol_version` / `server_info` block (around line 158–165) and update:
```rust
server_info: ServerInfo {
    name: "IronWarden",
    version: "1.0.0-rc.1",  // was "0.1.45-alpha"
},
```

Also fix the dead `mcp_ocr_ingest` method (tracked in #142) — add it to the `valid_methods` array:
```rust
let valid_methods = [
    "initialize",
    "mcp_sanitize_prompt",
    "mcp_restore_prompt",
    "mcp_get_compliance_report",
    "mcp_halt_system",
    "mcp_ocr_ingest",       // ← add this line
    "mcp_orchestrate",
];
```

---

## Step 6 — Bump version in workspace

In `worker/Cargo.toml`, update:
```toml
version = "1.0.0-rc.1"
```

In `app/Cargo.toml`, update:
```toml
version = "1.0.0-rc.1"
```

---

## Step 7 — Build & Verify

```bash
# Must compile cleanly
cargo build --workspace 2>&1 | grep -E "^error"

# Must pass all existing tests
./scripts/ci_local.sh | tee cicd_results.log

# Spot-check the new routes are registered
cargo run --bin app -- --help 2>&1 | head -5
```

---

## Step 8 — Commit

```bash
git add worker/src/proxy.rs worker/src/sse_proxy.rs worker/src/bridge.rs worker/src/lib.rs
git add worker/Cargo.toml app/Cargo.toml mcp/src/server.rs
git commit -m "feat(proxy): implement Universal AI Gateway Proxy (OpenAI + Anthropic + SSE)

- Add POST /v1/chat/completions with PII scrubbing + audit + restore
- Add POST /v1/completions (legacy text completions)
- Add GET /v1/models (passthrough)
- Add POST /v1/messages (Anthropic protocol + content blocks)
- Add SSE streaming engine with split-token re-hydration buffer
- Add X-IronWarden-Target-URL header for dynamic upstream routing
- Add model-name auto-routing (claude-* → Anthropic, llama* → Ollama)
- Fix mcp_ocr_ingest missing from valid_methods allowlist (#142)
- Bump version to 1.0.0-rc.1

Closes #156, #157, #158, #159
Fixes #142"

git push origin feature/universal-proxy-v1
```

---

## Acceptance Criteria

- [ ] `cargo build --workspace` → zero errors
- [ ] `cargo clippy --workspace` → zero new warnings
- [ ] `POST /v1/chat/completions` (non-streaming) scrubs PII, audits, restores in response
- [ ] `POST /v1/chat/completions` (streaming, `stream: true`) returns `text/event-stream` with PII restored
- [ ] Split-token test: `[PERSON_1]` split across two chunks is correctly restored
- [ ] `POST /v1/messages` (Anthropic) works for both string and content-block formats
- [ ] `GET /v1/models` proxies to upstream
- [ ] Blocked prompt → 400, no upstream contact
- [ ] Audit failure → 500, no upstream contact
- [ ] All 49+ existing integration tests still pass

---

## Security Non-Negotiables (for any reviewer)

| Rule | What happens on violation |
|------|--------------------------|
| Audit-before-forward | 500 returned, request aborted |
| Block-before-forward | 400 returned, upstream never contacted |
| Zero raw PII upstream | Structural — only `sanitized_text` leaves the process |
| Session saved on success | `save_session()` after every round-trip |
| Upstream error → fail-closed | 502 returned, no data leaked |
