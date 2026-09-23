//! Shared types and helpers for the IronWarden Universal Proxy routes.

use crate::grounding::LocalSessionManager;
use axum::http::{HeaderMap, StatusCode};
use iw_core::crypto::JwtVerifier;
use iw_core::{SessionContext, SovereignError, TokenMap};
use secrecy::ExposeSecret;
use secrecy::SecretVec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
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
pub fn validate_upstream_url(raw_url: &str) -> Result<String, SovereignError> {
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

    // Parse host as IP if applicable
    let ip_addr: Option<IpAddr> = host_clean.parse::<IpAddr>().ok();

    // 4. Strictly block AWS and cloud metadata IPs in ALL modes
    if let Some(ref ip) = ip_addr {
        if is_cloud_metadata_ip(ip) {
            return Err(SovereignError::UnauthorizedAccess(format!(
                "SSRF protection: access to cloud metadata IP '{}' is strictly prohibited",
                host_str
            )));
        }
    }

    // 5. Environment-based checks: Production vs Development/Test
    let is_prod = std::env::var("WARDEN_ENV").unwrap_or_default() == "production"
        || std::env::var("IRONWARDEN_ENV").unwrap_or_default() == "production";

    if is_prod {
        let is_localhost = host_lower == "localhost" || host_lower.ends_with(".localhost");
        let is_private = is_localhost
            || ip_addr
                .as_ref()
                .map(is_private_or_loopback)
                .unwrap_or(false);

        if is_private {
            let allow_private_env = std::env::var("ALLOW_PRIVATE_TARGET_URL")
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false);

            let is_host_allowed =
                if let Ok(allowed_hosts_val) = std::env::var("IRONWARDEN_ALLOWED_TARGET_HOSTS") {
                    let host_with_port = match parsed.port() {
                        Some(p) => format!("{}:{}", host_clean, p),
                        None => host_clean.to_string(),
                    };
                    allowed_hosts_val.split(',').any(|item| {
                        let trimmed_item = item.trim().trim_matches('[').trim_matches(']');
                        !trimmed_item.is_empty()
                            && (trimmed_item.eq_ignore_ascii_case(host_clean)
                                || trimmed_item.eq_ignore_ascii_case(&host_with_port))
                    })
                } else {
                    false
                };

            if !allow_private_env && !is_host_allowed {
                return Err(SovereignError::UnauthorizedAccess(format!(
                    "SSRF protection: private or loopback target '{}' is blocked in production mode",
                    host_str
                )));
            }
        }
    }

    Ok(trimmed.to_string())
}

// ── Upstream Resolution ───────────────────────────────────────────────────────

/// Priority order:
/// 1. `X-IronWarden-Target-URL` request header (explicit override, SSRF validated)
/// 2. Model-name auto-routing (claude-* → Anthropic, llama*/mistral*/phi* → Ollama)
/// 3. Env vars: OPENAI_BASE_URL / ANTHROPIC_BASE_URL / OLLAMA_BASE_URL
/// 4. Hardcoded defaults
pub fn resolve_upstream_url(headers: &HeaderMap, model: &str) -> String {
    if let Some(header_val) = headers.get("X-IronWarden-Target-URL") {
        match header_val.to_str() {
            Ok(t) => match validate_upstream_url(t) {
                Ok(valid_url) => return valid_url,
                Err(e) => {
                    tracing::warn!(
                        "SSRF protection rejected X-IronWarden-Target-URL '{}': {}. Falling back to default routing.",
                        t,
                        e
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    "Invalid UTF-8 in X-IronWarden-Target-URL header: {}. Falling back to default routing.",
                    e
                );
            }
        }
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
        .or_else(|_| std::env::var("UPSTREAM_LLM"))
        .or_else(|_| std::env::var("UPSTREAM_OPENAI_URL"))
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

    // ── SSRF Unit Tests ──────────────────────────────────────────────────────────

    use crate::TEST_ENV_MUTEX;

    struct TestEnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl TestEnvGuard {
        fn new(set_vars: &[(&'static str, &str)], remove_vars: &[&'static str]) -> Self {
            let mut saved = Vec::new();
            for &(k, v) in set_vars {
                saved.push((k, std::env::var(k).ok()));
                std::env::set_var(k, v);
            }
            for &k in remove_vars {
                saved.push((k, std::env::var(k).ok()));
                std::env::remove_var(k);
            }
            Self { saved }
        }
    }

    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[tokio::test]
    async fn test_validate_upstream_url_rejects_non_http_schemes() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(&[], &["WARDEN_ENV", "IRONWARDEN_ENV"]);

        assert!(validate_upstream_url("ftp://example.com/api").is_err());
        assert!(validate_upstream_url("file:///etc/passwd").is_err());
        assert!(validate_upstream_url("gopher://127.0.0.1:70/").is_err());
        assert!(validate_upstream_url("javascript:alert(1)").is_err());
        assert!(validate_upstream_url("").is_err());
        assert!(validate_upstream_url("   ").is_err());
    }

    #[tokio::test]
    async fn test_validate_upstream_url_blocks_metadata_always() {
        let _lock = TEST_ENV_MUTEX.lock().await;

        // 1. In dev/test mode (no env vars)
        {
            let _guard = TestEnvGuard::new(
                &[],
                &[
                    "WARDEN_ENV",
                    "IRONWARDEN_ENV",
                    "ALLOW_PRIVATE_TARGET_URL",
                    "IRONWARDEN_ALLOWED_TARGET_HOSTS",
                ],
            );

            // AWS / Cloud metadata IPs
            assert!(validate_upstream_url("http://169.254.169.254/latest/meta-data").is_err());
            assert!(validate_upstream_url("http://169.254.0.1/").is_err());
            assert!(validate_upstream_url("http://169.254.255.254/").is_err());
            assert!(validate_upstream_url("http://[fe80::1]/").is_err());
            assert!(validate_upstream_url("http://[fe80::a00:27ff:fe8e:e912]/").is_err());
            assert!(validate_upstream_url("http://[::ffff:169.254.169.254]/").is_err());

            // Cloud metadata domain names
            assert!(validate_upstream_url("http://instance-data/latest/meta-data").is_err());
            assert!(
                validate_upstream_url("http://metadata.google.internal/computeMetadata/v1/")
                    .is_err()
            );
            assert!(validate_upstream_url("http://api.instance-data/").is_err());
            assert!(validate_upstream_url("http://sub.metadata.google.internal/").is_err());
        }

        // 2. In production mode
        {
            let _guard = TestEnvGuard::new(
                &[("WARDEN_ENV", "production")],
                &[
                    "ALLOW_PRIVATE_TARGET_URL",
                    "IRONWARDEN_ALLOWED_TARGET_HOSTS",
                ],
            );

            assert!(validate_upstream_url("http://169.254.169.254/latest/meta-data").is_err());
            assert!(validate_upstream_url("http://169.254.1.1/").is_err());
            assert!(validate_upstream_url("http://instance-data/").is_err());
            assert!(validate_upstream_url("http://metadata.google.internal/").is_err());
            assert!(validate_upstream_url("http://[fe80::1]/").is_err());
        }

        // 3. In production mode even with ALLOW_PRIVATE_TARGET_URL=true or allowed hosts
        {
            let _guard = TestEnvGuard::new(
                &[
                    ("WARDEN_ENV", "production"),
                    ("ALLOW_PRIVATE_TARGET_URL", "true"),
                    (
                        "IRONWARDEN_ALLOWED_TARGET_HOSTS",
                        "169.254.169.254,metadata.google.internal",
                    ),
                ],
                &[],
            );

            assert!(validate_upstream_url("http://169.254.169.254/latest/meta-data").is_err());
            assert!(validate_upstream_url("http://instance-data/").is_err());
            assert!(validate_upstream_url("http://metadata.google.internal/").is_err());
            assert!(validate_upstream_url("http://[fe80::1]/").is_err());
        }
    }

    #[tokio::test]
    async fn test_validate_upstream_url_production_blocks_private_ips() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(
            &[("WARDEN_ENV", "production")],
            &[
                "IRONWARDEN_ENV",
                "ALLOW_PRIVATE_TARGET_URL",
                "IRONWARDEN_ALLOWED_TARGET_HOSTS",
            ],
        );

        // Loopback
        assert!(validate_upstream_url("http://127.0.0.1:8000/v1").is_err());
        assert!(validate_upstream_url("http://127.0.0.2:8000/").is_err());
        assert!(validate_upstream_url("http://localhost:8000/").is_err());
        assert!(validate_upstream_url("http://api.localhost:8000/").is_err());
        assert!(validate_upstream_url("http://[::1]:8000/").is_err());
        assert!(validate_upstream_url("http://[::ffff:127.0.0.1]:8000/").is_err());
        assert!(validate_upstream_url("http://0.0.0.0:8000/").is_err());

        // RFC 1918 10.0.0.0/8
        assert!(validate_upstream_url("http://10.0.0.1:8000/").is_err());
        assert!(validate_upstream_url("http://10.255.255.254:8000/").is_err());

        // RFC 1918 172.16.0.0/12
        assert!(validate_upstream_url("http://172.16.0.1:8000/").is_err());
        assert!(validate_upstream_url("http://172.31.255.254:8000/").is_err());

        // RFC 1918 192.168.0.0/16
        assert!(validate_upstream_url("http://192.168.1.1:8000/").is_err());
        assert!(validate_upstream_url("http://192.168.254.254:8000/").is_err());

        // Public URLs must succeed in production
        assert!(validate_upstream_url("https://api.openai.com/v1/chat/completions").is_ok());
        assert!(validate_upstream_url("https://api.anthropic.com/v1/messages").is_ok());
        assert!(validate_upstream_url("http://custom-override.example.com").is_ok());
    }

    #[tokio::test]
    async fn test_validate_upstream_url_production_with_allow_private() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(
            &[
                ("IRONWARDEN_ENV", "production"),
                ("ALLOW_PRIVATE_TARGET_URL", "true"),
            ],
            &["WARDEN_ENV", "IRONWARDEN_ALLOWED_TARGET_HOSTS"],
        );

        // Private IPs allowed with ALLOW_PRIVATE_TARGET_URL=true
        assert!(validate_upstream_url("http://127.0.0.1:8000/v1").is_ok());
        assert!(validate_upstream_url("http://localhost:8000/").is_ok());
        assert!(validate_upstream_url("http://10.0.0.1:8000/").is_ok());
        assert!(validate_upstream_url("http://192.168.1.1:8000/").is_ok());

        // Metadata still blocked even with ALLOW_PRIVATE_TARGET_URL=true
        assert!(validate_upstream_url("http://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_upstream_url("http://metadata.google.internal/").is_err());
    }

    #[tokio::test]
    async fn test_validate_upstream_url_production_with_allowed_hosts() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(
            &[
                ("WARDEN_ENV", "production"),
                (
                    "IRONWARDEN_ALLOWED_TARGET_HOSTS",
                    "10.0.0.5,ollama-internal.corp:11434,127.0.0.1",
                ),
            ],
            &["IRONWARDEN_ENV", "ALLOW_PRIVATE_TARGET_URL"],
        );

        // Explicitly allowed hosts
        assert!(validate_upstream_url("http://10.0.0.5:8080/v1").is_ok());
        assert!(validate_upstream_url("http://ollama-internal.corp:11434/v1").is_ok());
        assert!(validate_upstream_url("http://127.0.0.1:9000/v1").is_ok());

        // Non-allowed private hosts blocked
        assert!(validate_upstream_url("http://10.0.0.6:8080/v1").is_err());
        assert!(validate_upstream_url("http://192.168.1.1:8000/").is_err());
    }

    #[tokio::test]
    async fn test_validate_upstream_url_development_permits_localhost_and_loopback() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(
            &[],
            &[
                "WARDEN_ENV",
                "IRONWARDEN_ENV",
                "ALLOW_PRIVATE_TARGET_URL",
                "IRONWARDEN_ALLOWED_TARGET_HOSTS",
            ],
        );

        // Loopback and localhost permitted in development/test
        assert_eq!(
            validate_upstream_url("http://127.0.0.1:11434/v1/chat/completions").unwrap(),
            "http://127.0.0.1:11434/v1/chat/completions"
        );
        assert_eq!(
            validate_upstream_url("http://localhost:11434/v1/chat/completions").unwrap(),
            "http://localhost:11434/v1/chat/completions"
        );
        assert_eq!(
            validate_upstream_url("http://custom-override.example.com").unwrap(),
            "http://custom-override.example.com"
        );

        // Metadata still strictly blocked
        assert!(validate_upstream_url("http://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_upstream_url("http://instance-data/").is_err());
        assert!(validate_upstream_url("http://metadata.google.internal/").is_err());
    }

    #[tokio::test]
    async fn test_resolve_upstream_url_ssrf_rejected_falls_back() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(
            &[],
            &[
                "WARDEN_ENV",
                "IRONWARDEN_ENV",
                "OPENAI_BASE_URL",
                "ANTHROPIC_BASE_URL",
            ],
        );

        // Attempting to route to AWS metadata via X-IronWarden-Target-URL falls back to model default
        let h = headers_with(
            "X-IronWarden-Target-URL",
            "http://169.254.169.254/latest/meta-data",
        );
        let resolved = resolve_upstream_url(&h, "claude-3");
        assert_eq!(resolved, "https://api.anthropic.com/v1/messages");

        let h_openai = headers_with(
            "X-IronWarden-Target-URL",
            "http://169.254.169.254/latest/meta-data",
        );
        let resolved_openai = resolve_upstream_url(&h_openai, "gpt-4o");
        assert_eq!(
            resolved_openai,
            "https://api.openai.com/v1/chat/completions"
        );
    }
}
