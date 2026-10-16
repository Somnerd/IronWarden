//! Shared types and helpers for the IronWarden Universal Proxy routes.

use crate::grounding::LocalSessionManager;
use axum::http::{HeaderMap, StatusCode};
use iw_core::crypto::JwtVerifier;
use iw_core::{SessionContext, SovereignError, TokenMap};
use secrecy::ExposeSecret;
use secrecy::SecretVec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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

// ── SSRF Validation ──────────────────────────────────────────────────────────

fn is_cloud_metadata_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 169.254.0.0/16 (includes 169.254.169.254)
            octets[0] == 169 && octets[1] == 254
        }
        IpAddr::V6(v6) => {
            // fe80::/10 (prefix 1111 1110 10)
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            if let Some(v4) = v6.to_ipv4() {
                let octets = v4.octets();
                if octets[0] == 169 && octets[1] == 254 {
                    return true;
                }
            }
            false
        }
    }
}

fn is_private_or_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // RFC 1918 & Loopback
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 127.0.0.0/8
            || octets[0] == 127
            // 0.0.0.0/8
            || octets[0] == 0
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            // Unique local address fc00::/7
            if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            if let Some(v4) = v6.to_ipv4() {
                let octets = v4.octets();
                octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
                    || octets[0] == 127
                    || octets[0] == 0
            } else {
                false
            }
        }
    }
}

/// Validates an upstream target URL to defend against Server-Side Request Forgery (SSRF).
///
/// Rules:
/// - Rejects non-HTTP(S) schemes.
/// - Strictly blocks AWS and cloud metadata endpoints (`169.254.169.254`, `169.254.0.0/16`,
///   `fe80::/10`, `instance-data`, `metadata.google.internal`) in all environments.
/// - In production mode (`WARDEN_ENV=production` or `IRONWARDEN_ENV=production`):
///   blocks private/loopback IP ranges (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
///   `127.0.0.0/8`, `::1`, and `localhost`) unless explicitly allowed via
///   `ALLOW_PRIVATE_TARGET_URL=true` or listed in `IRONWARDEN_ALLOWED_TARGET_HOSTS`.
/// - In development/test mode, permits `127.0.0.1` and `localhost` for local services/testing,
///   while keeping metadata IPs strictly blocked.
pub async fn validate_upstream_url(
    raw_url: &str,
) -> Result<(String, Option<SocketAddr>), SovereignError> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err(SovereignError::UnauthorizedAccess(
            "Upstream target URL cannot be empty".to_string(),
        ));
    }

    let parsed = reqwest::Url::parse(trimmed).map_err(|e| {
        SovereignError::UnauthorizedAccess(format!("Invalid upstream URL '{}': {}", trimmed, e))
    })?;

    // 1. Reject non-HTTP(S) schemes
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(SovereignError::UnauthorizedAccess(format!(
            "Forbidden URL scheme '{}': only http and https are permitted",
            scheme
        )));
    }

    // 2. Extract host
    let host_str = parsed.host_str().ok_or_else(|| {
        SovereignError::UnauthorizedAccess(format!("Missing host in upstream URL '{}'", trimmed))
    })?;

    let host_clean = host_str.trim_matches('[').trim_matches(']');
    let host_lower = host_clean.to_lowercase();

    // 3. Strictly block AWS and cloud metadata endpoints (hostnames)
    if host_lower == "instance-data"
        || host_lower.starts_with("instance-data.")
        || host_lower.ends_with(".instance-data")
        || host_lower == "metadata.google.internal"
        || host_lower.ends_with(".metadata.google.internal")
    {
        return Err(SovereignError::UnauthorizedAccess(format!(
            "SSRF protection: access to cloud metadata endpoint '{}' is strictly prohibited",
            host_str
        )));
    }

    // 4. Port parsing
    let port = parsed
        .port_or_known_default()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    // 5. Environment-based checks: Production vs Development/Test
    let (is_allowed_list_set, is_host_allowed) =
        if let Ok(allowed_hosts_val) = std::env::var("IRONWARDEN_ALLOWED_TARGET_HOSTS") {
            let trimmed_allowed = allowed_hosts_val.trim();
            if !trimmed_allowed.is_empty() {
                let host_with_port = match parsed.port() {
                    Some(p) => format!("{}:{}", host_clean, p),
                    None => host_clean.to_string(),
                };
                let allowed = trimmed_allowed.split(',').any(|item| {
                    let trimmed_item = item.trim().trim_matches('[').trim_matches(']');
                    !trimmed_item.is_empty()
                        && (trimmed_item.eq_ignore_ascii_case(host_clean)
                            || trimmed_item.eq_ignore_ascii_case(&host_with_port))
                });
                (true, allowed)
            } else {
                (false, false)
            }
        } else {
            (false, false)
        };

    // If IRONWARDEN_ALLOWED_TARGET_HOSTS is set, strictly enforce the allowlist across all targets.
    if is_allowed_list_set && !is_host_allowed {
        return Err(SovereignError::UnauthorizedAccess(format!(
            "SSRF protection: target host '{}' is not in IRONWARDEN_ALLOWED_TARGET_HOSTS allowlist",
            host_str
        )));
    }

    let is_prod = std::env::var("WARDEN_ENV").unwrap_or_default() == "production"
        || std::env::var("IRONWARDEN_ENV").unwrap_or_default() == "production";

    let allow_private_env = std::env::var("ALLOW_PRIVATE_TARGET_URL")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    let mut pinned_addr: Option<SocketAddr> = None;

    // 6. Check if host parses as literal IP
    if let Ok(ip) = host_clean.parse::<IpAddr>() {
        if is_cloud_metadata_ip(&ip) {
            return Err(SovereignError::UnauthorizedAccess(format!(
                "SSRF protection: access to cloud metadata IP '{}' is strictly prohibited",
                host_str
            )));
        }
        if is_prod && is_private_or_loopback(&ip) && !allow_private_env && !is_host_allowed {
            return Err(SovereignError::UnauthorizedAccess(format!(
                "SSRF protection: private or loopback target '{}' is blocked in production mode",
                host_str
            )));
        }
        pinned_addr = Some(SocketAddr::new(ip, port));
    } else {
        // Hostname (not literal IP)
        let is_localhost = host_lower == "localhost" || host_lower.ends_with(".localhost");
        if is_prod && is_localhost && !allow_private_env && !is_host_allowed {
            return Err(SovereignError::UnauthorizedAccess(format!(
                "SSRF protection: private or loopback target '{}' is blocked in production mode",
                host_str
            )));
        }

        // Perform asynchronous DNS lookup
        match tokio::net::lookup_host((host_clean, port)).await {
            Ok(addrs) => {
                let mut found = false;
                for addr in addrs {
                    if !found {
                        pinned_addr = Some(addr);
                    }
                    found = true;
                    let ip = addr.ip();
                    if is_cloud_metadata_ip(&ip) {
                        return Err(SovereignError::UnauthorizedAccess(format!(
                            "SSRF protection: host '{}' resolves to prohibited cloud metadata IP '{}'",
                            host_str, ip
                        )));
                    }
                    if is_prod
                        && is_private_or_loopback(&ip)
                        && !allow_private_env
                        && !is_host_allowed
                    {
                        return Err(SovereignError::UnauthorizedAccess(format!(
                            "SSRF protection: host '{}' resolves to prohibited private or loopback IP '{}'",
                            host_str, ip
                        )));
                    }
                }
                if !found && is_prod && !is_host_allowed {
                    return Err(SovereignError::UnauthorizedAccess(format!(
                        "SSRF protection: DNS lookup returned no addresses for host '{}'",
                        host_str
                    )));
                }
            }
            Err(e) => {
                if is_prod && !is_host_allowed {
                    return Err(SovereignError::UnauthorizedAccess(format!(
                        "SSRF protection: DNS lookup failed for host '{}': {}",
                        host_str, e
                    )));
                }
                // If in development/test mode or host is allowed: allow proceeding
            }
        }
    }

    Ok((trimmed.to_string(), pinned_addr))
}

// ── Upstream Resolution ───────────────────────────────────────────────────────

/// Priority order:
/// 1. `X-IronWarden-Target-URL` request header (explicit override, SSRF validated)
/// 2. Model-name auto-routing (claude-* → Anthropic, llama*/mistral*/phi* → Ollama)
/// 3. Env vars: OPENAI_BASE_URL / ANTHROPIC_BASE_URL / OLLAMA_BASE_URL
/// 4. Hardcoded defaults
pub async fn resolve_upstream_url(
    headers: &HeaderMap,
    model: &str,
) -> Result<(String, Option<SocketAddr>), SovereignError> {
    if let Some(header_val) = headers
        .get("X-IronWarden-Target-URL")
        .or_else(|| headers.get("x-ironwarden-target-url"))
    {
        let t = header_val.to_str().map_err(|e| {
            SovereignError::UnauthorizedAccess(format!(
                "Invalid UTF-8 in X-IronWarden-Target-URL header: {}",
                e
            ))
        })?;
        return validate_upstream_url(t).await;
    }
    let m = model.to_lowercase();
    if m.starts_with("claude") {
        return Ok((
            std::env::var("ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com/v1/messages".to_string()),
            None,
        ));
    }
    if m.starts_with("llama")
        || m.starts_with("mistral")
        || m.starts_with("phi")
        || m.starts_with("gemma")
        || m.starts_with("qwen")
    {
        return Ok((
            std::env::var("OLLAMA_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:11434/v1/chat/completions".to_string()),
            None,
        ));
    }
    Ok((
        std::env::var("OPENAI_BASE_URL")
            .or_else(|_| std::env::var("UPSTREAM_LLM"))
            .or_else(|_| std::env::var("UPSTREAM_OPENAI_URL"))
            .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string()),
        None,
    ))
}

/// Upstream API key resolution:
/// When routing to a custom target URL, NEVER attach server ambient keys (OPENAI_API_KEY).
/// An explicit `X-IronWarden-Upstream-Key` must be supplied; otherwise, returns empty string.
/// For standard default routing: `X-IronWarden-Upstream-Key` header → OPENAI_API_KEY env → "ollama" fallback.
pub fn resolve_upstream_key(headers: &HeaderMap) -> String {
    let has_custom_target = headers
        .get("X-IronWarden-Target-URL")
        .or_else(|| headers.get("x-ironwarden-target-url"))
        .is_some();

    if has_custom_target {
        headers
            .get("X-IronWarden-Upstream-Key")
            .or_else(|| headers.get("x-ironwarden-upstream-key"))
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .unwrap_or_default()
    } else {
        headers
            .get("X-IronWarden-Upstream-Key")
            .or_else(|| headers.get("x-ironwarden-upstream-key"))
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| std::env::var("OPENAI_API_KEY").ok())
            .unwrap_or_else(|| "ollama".to_string())
    }
}

// ── Token Map Merge ───────────────────────────────────────────────────────────

pub fn merge_token_map(combined: &mut TokenMap, addition: &TokenMap) {
    for (k, v) in addition.iter() {
        combined.insert(k.clone(), v.clone());
    }
}
