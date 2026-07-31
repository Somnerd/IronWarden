//! Shared types and helpers for the IronWarden Universal Proxy routes.

use crate::searchboost::LocalSessionManager;
use axum::http::{HeaderMap, StatusCode};
use iw_core::crypto::JwtVerifier;
use iw_core::{SessionContext, TokenMap};
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
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Session error: {}", e),
            )
        })?;

    Ok(AuthenticatedUser {
        username: claims.sub,
        session,
    })
}

// ── Upstream Resolution ───────────────────────────────────────────────────────

/// Priority order:
/// 1. `X-IronWarden-Target-URL` request header (explicit override)
/// 2. Model-name auto-routing (claude-* → Anthropic, llama*/mistral*/phi* → Ollama)
/// 3. Env vars: OPENAI_BASE_URL / ANTHROPIC_BASE_URL / OLLAMA_BASE_URL
/// 4. Hardcoded defaults
pub fn resolve_upstream_url(headers: &HeaderMap, model: &str) -> String {
    if let Some(t) = headers
        .get("X-IronWarden-Target-URL")
        .and_then(|v| v.to_str().ok())
    {
        return t.to_string();
    }
    let m = model.to_lowercase();
    if m.starts_with("claude") {
        return std::env::var("ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com/v1/messages".to_string());
    }
    if m.starts_with("llama")
        || m.starts_with("mistral")
        || m.starts_with("phi")
        || m.starts_with("gemma")
        || m.starts_with("qwen")
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
