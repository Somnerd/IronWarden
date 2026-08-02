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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use std::collections::HashMap;

    fn empty_headers() -> HeaderMap {
        HeaderMap::new()
    }

    fn headers_with(key: &str, val: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_bytes(key.as_bytes()).unwrap(),
            HeaderValue::from_str(val).unwrap(),
        );
        h
    }

    #[test]
    fn test_routing_header_override_takes_priority() {
        let h = headers_with(
            "X-IronWarden-Target-URL",
            "http://custom-override.example.com",
        );
        assert_eq!(
            resolve_upstream_url(&h, "claude-3"),
            "http://custom-override.example.com"
        );
    }

    #[test]
    fn test_routing_claude_routes_to_anthropic() {
        std::env::remove_var("ANTHROPIC_BASE_URL");
        let h = empty_headers();
        let url = resolve_upstream_url(&h, "claude-3-5-sonnet-20241022");
        assert!(url.contains("anthropic.com"));
    }

    #[test]
    fn test_routing_llama_routes_to_ollama() {
        std::env::remove_var("OLLAMA_BASE_URL");
        let h = empty_headers();
        let url = resolve_upstream_url(&h, "llama3");
        assert!(url.contains("11434"));
    }

    #[test]
    fn test_routing_mistral_routes_to_ollama() {
        std::env::remove_var("OLLAMA_BASE_URL");
        let h = empty_headers();
        let url = resolve_upstream_url(&h, "mistral-7b");
        assert!(url.contains("11434"));
    }

    #[test]
    fn test_routing_phi_routes_to_ollama() {
        std::env::remove_var("OLLAMA_BASE_URL");
        let h = empty_headers();
        let url = resolve_upstream_url(&h, "phi-3");
        assert!(url.contains("11434"));
    }

    #[test]
    fn test_routing_gemma_routes_to_ollama() {
        std::env::remove_var("OLLAMA_BASE_URL");
        let h = empty_headers();
        let url = resolve_upstream_url(&h, "gemma2");
        assert!(url.contains("11434"));
    }

    #[test]
    fn test_routing_qwen_routes_to_ollama() {
        std::env::remove_var("OLLAMA_BASE_URL");
        let h = empty_headers();
        let url = resolve_upstream_url(&h, "qwen2.5");
        assert!(url.contains("11434"));
    }

    #[test]
    fn test_routing_gpt_routes_to_openai_default() {
        std::env::remove_var("OPENAI_BASE_URL");
        let h = empty_headers();
        let url = resolve_upstream_url(&h, "gpt-4o");
        assert!(url.contains("openai.com"));
    }

    #[test]
    fn test_routing_unknown_model_routes_to_openai() {
        std::env::remove_var("OPENAI_BASE_URL");
        let h = empty_headers();
        let url = resolve_upstream_url(&h, "some-unknown-model");
        assert!(url.contains("openai.com"));
    }

    #[test]
    fn test_upstream_key_header_takes_priority() {
        let h = headers_with("X-IronWarden-Upstream-Key", "sk-from-header");
        assert_eq!(resolve_upstream_key(&h), "sk-from-header");
    }

    #[test]
    fn test_upstream_key_ollama_fallback() {
        std::env::remove_var("OPENAI_API_KEY");
        let h = empty_headers();
        assert_eq!(resolve_upstream_key(&h), "ollama");
    }

    #[test]
    fn test_merge_token_map_basic() {
        let mut combined = HashMap::new();
        combined.insert("a".to_string(), "1".to_string());
        let mut addition = HashMap::new();
        addition.insert("b".to_string(), "2".to_string());

        merge_token_map(&mut combined, &addition);

        assert_eq!(combined.get("a").unwrap(), "1");
        assert_eq!(combined.get("b").unwrap(), "2");
        assert_eq!(combined.len(), 2);
    }

    #[test]
    fn test_merge_token_map_overwrites_same_key() {
        let mut combined = HashMap::new();
        combined.insert("a".to_string(), "1".to_string());
        let mut addition = HashMap::new();
        addition.insert("a".to_string(), "2".to_string());

        merge_token_map(&mut combined, &addition);

        assert_eq!(combined.get("a").unwrap(), "2");
        assert_eq!(combined.len(), 1);
    }

    #[test]
    fn test_merge_token_map_empty_addition() {
        let mut combined = HashMap::new();
        combined.insert("a".to_string(), "1".to_string());
        let addition = HashMap::new();

        merge_token_map(&mut combined, &addition);

        assert_eq!(combined.get("a").unwrap(), "1");
        assert_eq!(combined.len(), 1);
    }
}
