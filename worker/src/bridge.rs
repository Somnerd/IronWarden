use crate::grounding::{GroundingQueue, LocalSessionManager};
use crate::proxy::{
    authenticate, merge_token_map, resolve_upstream_key, resolve_upstream_url, AnthropicRequest,
    ChatCompletionRequest, CompletionRequest,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use iw_core::crypto::JwtVerifier;
use iw_core::{PiiShield, SovereignError, StorageProvider, TokenMap};
use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

#[derive(Serialize)]
struct EnqueueResponse<'a> {
    status: &'a str,
    id: String,
    pii_scrubbed: bool,
}

#[derive(Deserialize, Serialize)]
pub struct SearchRequest {
    pub query: String,
    pub thread_id: String,
    pub options: Option<HashMap<String, serde_json::Value>>,
}

pub struct BridgeState {
    pub shield: Arc<dyn PiiShield>,
    pub grounding_shield: Arc<dyn iw_core::GroundingShield>,
    pub queue: Arc<GroundingQueue>,
    pub storage: Arc<dyn StorageProvider>,
    /// Unified Session Manager (Local SQLite-backed)
    pub session_manager: Arc<LocalSessionManager>,
    /// RSA Public Key for identity verification (V1.0 Decoupled Auth Mandate)
    pub jwt_public_key: SecretVec<u8>,
    /// Global Concurrency Semaphore to prevent Tokio executor starvation
    pub ingress_semaphore: Arc<tokio::sync::Semaphore>,
}

async fn concurrency_limiter(
    State(state): State<Arc<BridgeState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let _permit = state
        .ingress_semaphore
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    Ok(next.run(request).await)
}

pub fn create_bridge_router(state: Arc<BridgeState>) -> Router {
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(25)
            .burst_size(100)
            .finish()
            .expect("Failed to initialize Governor Rate Limiter"),
    );

    Router::new()
        .route("/health", get(handle_health))
        .route("/enqueue", post(handle_enqueue))
        .route("/results/:job_id", get(handle_get_result))
        .route("/v1/chat/completions", post(handle_openai_chat_completions))
        .route("/v1/completions", post(handle_openai_legacy_completions))
        .route("/v1/models", get(handle_openai_models))
        .route("/v1/messages", post(handle_anthropic_messages))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            concurrency_limiter,
        ))
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .with_state(state)
}

fn map_error(e: SovereignError) -> impl IntoResponse {
    let status = match e {
        SovereignError::DatabaseBusy(_) => StatusCode::SERVICE_UNAVAILABLE,
        SovereignError::UnauthorizedAccess(_) => StatusCode::FORBIDDEN,
        SovereignError::GatewayTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
        SovereignError::PiiViolation(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, e.to_string())
}

async fn handle_enqueue(
    State(state): State<Arc<BridgeState>>,
    headers: HeaderMap,
    Json(payload): Json<SearchRequest>,
) -> impl IntoResponse {
    // 1. Authenticate & Verify Identity (JWT)
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h: &str| h.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Missing Bearer Token").into_response(),
    };

    // --- SECURITY FIX (Section 3.3 / Finding B.3): RS256 Decoupled Verification ---
    let aud = match std::env::var("WARDEN_JWT_AUDIENCE") {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "WARDEN_JWT_AUDIENCE environment variable is strictly required. Refusing to boot with default fallbacks.").into_response(),
    };
    let iss = match std::env::var("WARDEN_JWT_ISSUER") {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "WARDEN_JWT_ISSUER environment variable is strictly required. Refusing to boot with default fallbacks.").into_response(),
    };

    let token_data =
        match JwtVerifier::verify(token, state.jwt_public_key.expose_secret(), &aud, &iss) {
            Ok(claims) => claims,
            Err(SovereignError::UnauthorizedAccess(msg)) => {
                return (StatusCode::UNAUTHORIZED, msg).into_response()
            }
            Err(e) => return map_error(e).into_response(),
        };

    let has_required_role = token_data.roles.contains(&"admin".to_string())
        || token_data.roles.contains(&"privileged_search".to_string());
    if !has_required_role {
        tracing::error!(
            "RBAC Enforcement Failure: {} lacks required roles",
            token_data.sub
        );
        return (
            StatusCode::FORBIDDEN,
            "Insufficient privileges. Requires 'admin' or 'privileged_search' role.",
        )
            .into_response();
    }

    let username = token_data.sub.clone();

    // 2. Local Session Retrieval
    let user_context = match state.session_manager.get_session(&username).await {
        Ok(ctx) => ctx,
        Err(e) => return map_error(e).into_response(),
    };

    // 3. Scrub PII from the query using the isolated context
    let report_result = state
        .shield
        .sanitize_prompt(&payload.query, Some(&user_context))
        .await;

    let report = match report_result {
        Ok(r) => r,
        Err(e) => return map_error(e).into_response(),
    };

    // --- SECURITY FIX: Log to Audit Ledger ---
    if let Err(e) = state
        .storage
        .log_audit_event(&report, &payload.query, &username)
        .await
    {
        tracing::error!(
            "AUDIT LOG FAILURE: {}. Request aborted to prevent un-audited access!",
            e
        );
        return map_error(e).into_response();
    }

    // --- SECURITY FIX (V-14): Hard-Block Circuit Breaker & Leak Prevention ---
    if report.is_blocked {
        return map_error(iw_core::SovereignError::PiiViolation(
            "[POLICY VIOLATION] Your request was blocked due to sensitive data leakage.".into(),
        ))
        .into_response();
    }

    // 4. Persist updated session state
    if let Err(e) = state
        .session_manager
        .save_session(&username, &user_context)
        .await
    {
        tracing::error!("Failed to save session for {}: {}", username, e);
    }

    // 5. Delegate to Storage & Queue
    tracing::info!(
        "PII Scrubbed for {}: replaced {} terms",
        username,
        report.token_map.len()
    );

    let options = payload.options.unwrap_or_default();

    // --- SECURITY ENFORCEMENT (V-14 / WP-97): Enqueue ONLY sanitized text ---
    // To maintain 100% compliance with the Leak-Proof Routing mandate, raw queries are
    // dropped immediately after auditing. Side-channels for raw query grounding are strictly
    // prohibited as they bypass the core security boundary.
    match state
        .queue
        .enqueue(report.sanitized_text, options, payload.thread_id, username)
        .await
    {
        Ok(job_id) => (
            StatusCode::OK,
            Json(EnqueueResponse {
                status: "queued",
                id: job_id,
                pii_scrubbed: report.token_map.len() > 0,
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to enqueue SearchBoost job: {}", e);
            map_error(e).into_response()
        }
    }
}

async fn handle_get_result(
    State(state): State<Arc<BridgeState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h: &str| h.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Missing Bearer Token").into_response(),
    };

    let aud = match std::env::var("WARDEN_JWT_AUDIENCE") {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "WARDEN_JWT_AUDIENCE environment variable is strictly required.",
            )
                .into_response()
        }
    };
    let iss = match std::env::var("WARDEN_JWT_ISSUER") {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "WARDEN_JWT_ISSUER environment variable is strictly required.",
            )
                .into_response()
        }
    };

    let token_data =
        match JwtVerifier::verify(token, state.jwt_public_key.expose_secret(), &aud, &iss) {
            Ok(claims) => claims,
            Err(SovereignError::UnauthorizedAccess(msg)) => {
                return (StatusCode::UNAUTHORIZED, msg).into_response()
            }
            Err(e) => return map_error(e).into_response(),
        };

    let username = token_data.sub.clone();
    let has_required_role = token_data.roles.contains(&"admin".to_string())
        || token_data.roles.contains(&"privileged_search".to_string());
    let is_admin = token_data.roles.contains(&"admin".to_string());
    if !has_required_role {
        tracing::error!(
            "RBAC Enforcement Failure: {} lacks required roles",
            username
        );
        return (
            StatusCode::FORBIDDEN,
            "Insufficient privileges. Requires 'admin' or 'privileged_search' role.",
        )
            .into_response();
    }

    match state.queue.get_result(&job_id, &username, is_admin).await {
        Ok(Some(res)) => (StatusCode::OK, res).into_response(),
        Ok(None) => (StatusCode::ACCEPTED, "Processing...").into_response(),
        Err(e) => map_error(e).into_response(),
    }
}

async fn handle_health(State(state): State<Arc<BridgeState>>) -> impl IntoResponse {
    match state.storage.check_health().await {
        Ok(_) => (
            StatusCode::OK,
            "IronWarden Bridge: V2.0 Universal AI Gateway Proxy: HEALTHY",
        )
            .into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("IronWarden Bridge: CRITICAL FAILURE: {}", e),
        )
            .into_response(),
    }
}

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
            let report = match state
                .shield
                .sanitize_prompt(text, Some(&auth.session))
                .await
            {
                Ok(r) => r,
                Err(e) => return map_error(e).into_response(),
            };
            // Audit BEFORE forwarding — abort on failure
            if let Err(e) = state
                .storage
                .log_audit_event(&report, text, &auth.username)
                .await
            {
                tracing::error!(
                    "CRITICAL: Audit log failure in proxy. Aborting request: {}",
                    e
                );
                return map_error(e).into_response();
            }
            if report.is_blocked {
                return (
                    StatusCode::BAD_REQUEST,
                    "[POLICY VIOLATION] Prompt blocked by IronWarden.".to_string(),
                )
                    .into_response();
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
            return map_error(SovereignError::GatewayTimeout(format!(
                "Upstream unreachable: {}",
                e
            )))
            .into_response()
        }
    };

    if !upstream_resp.status().is_success() {
        let status = upstream_resp.status();
        let body = upstream_resp.text().await.unwrap_or_default();
        tracing::error!("Upstream returned {}: {}", status, body);
        return (StatusCode::BAD_GATEWAY, body).into_response();
    }

    let mut full_token_map: TokenMap = auth
        .session
        .token_to_pii
        .iter()
        .map(|r| (r.key().clone(), r.value().clone()))
        .collect();
    merge_token_map(&mut full_token_map, &combined_token_map);

    let _ = state
        .session_manager
        .save_session(&auth.username, &auth.session)
        .await;

    // 6. Streaming path — hand off to SSE engine
    if is_stream {
        return crate::sse_proxy::stream_proxy_response(upstream_resp, full_token_map).await;
    }

    // 7. Non-streaming — parse and re-hydrate
    let mut res_json: serde_json::Value = match upstream_resp.json().await {
        Ok(j) => j,
        Err(e) => {
            return map_error(SovereignError::UpstreamError(format!(
                "Failed to parse upstream JSON: {}",
                e
            )))
            .into_response()
        }
    };

    if let Some(choices) = res_json.get_mut("choices").and_then(|c| c.as_array_mut()) {
        for choice in choices.iter_mut() {
            if let Some(content) = choice.pointer_mut("/message/content") {
                if let Some(text) = content.as_str() {
                    if let Ok(restored) = state.shield.restore_prompt(text, &full_token_map) {
                        *content = serde_json::Value::String(restored);
                    }
                }
            }
        }
    }

    let _ = state
        .session_manager
        .save_session(&auth.username, &auth.session)
        .await;
    (StatusCode::OK, Json(res_json)).into_response()
}

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
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => vec![],
    };

    let mut sanitized_prompts = Vec::new();
    for p in &prompts {
        let report = match state.shield.sanitize_prompt(p, Some(&auth.session)).await {
            Ok(r) => r,
            Err(e) => return map_error(e).into_response(),
        };
        if let Err(e) = state
            .storage
            .log_audit_event(&report, p, &auth.username)
            .await
        {
            return map_error(e).into_response();
        }
        if report.is_blocked {
            return (
                StatusCode::BAD_REQUEST,
                "[POLICY VIOLATION] Prompt blocked.".to_string(),
            )
                .into_response();
        }
        merge_token_map(&mut combined_token_map, &report.token_map);
        sanitized_prompts.push(report.sanitized_text);
    }

    payload.prompt = if sanitized_prompts.len() == 1 {
        serde_json::Value::String(sanitized_prompts.remove(0))
    } else {
        serde_json::Value::Array(
            sanitized_prompts
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        )
    };

    let target_url =
        resolve_upstream_url(&headers, &payload.model).replace("/chat/completions", "/completions");
    let api_key = resolve_upstream_key(&headers);

    let client = reqwest::Client::new();
    let upstream_resp = match client
        .post(&target_url)
        .bearer_auth(&api_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return map_error(SovereignError::GatewayTimeout(e.to_string())).into_response(),
    };

    let mut res_json: serde_json::Value = match upstream_resp.json().await {
        Ok(j) => j,
        Err(e) => return map_error(SovereignError::UpstreamError(e.to_string())).into_response(),
    };

    let mut full_token_map: TokenMap = auth
        .session
        .token_to_pii
        .iter()
        .map(|r| (r.key().clone(), r.value().clone()))
        .collect();
    merge_token_map(&mut full_token_map, &combined_token_map);

    if let Some(choices) = res_json.get_mut("choices").and_then(|c| c.as_array_mut()) {
        for choice in choices.iter_mut() {
            if let Some(text_val) = choice.get_mut("text") {
                if let Some(text) = text_val.as_str() {
                    if let Ok(restored) = state.shield.restore_prompt(text, &full_token_map) {
                        *text_val = serde_json::Value::String(restored);
                    }
                }
            }
        }
    }

    let _ = state
        .session_manager
        .save_session(&auth.username, &auth.session)
        .await;
    (StatusCode::OK, Json(res_json)).into_response()
}

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
        let report = match state
            .shield
            .sanitize_prompt(system, Some(&auth.session))
            .await
        {
            Ok(r) => r,
            Err(e) => return map_error(e).into_response(),
        };
        if let Err(e) = state
            .storage
            .log_audit_event(&report, system, &auth.username)
            .await
        {
            return map_error(e).into_response();
        }
        if report.is_blocked {
            return (
                StatusCode::BAD_REQUEST,
                "System prompt blocked.".to_string(),
            )
                .into_response();
        }
        merge_token_map(&mut combined_token_map, &report.token_map);
        payload.system = Some(report.sanitized_text);
    }

    // Sanitize messages — support both string and content-block array formats
    for msg in payload.messages.iter_mut() {
        if let Some(text) = msg.content.as_str() {
            let report = match state
                .shield
                .sanitize_prompt(text, Some(&auth.session))
                .await
            {
                Ok(r) => r,
                Err(e) => return map_error(e).into_response(),
            };
            if let Err(e) = state
                .storage
                .log_audit_event(&report, text, &auth.username)
                .await
            {
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
                    if let Some(text) = block
                        .get("text")
                        .and_then(|t| t.as_str())
                        .map(str::to_string)
                    {
                        let report = match state
                            .shield
                            .sanitize_prompt(&text, Some(&auth.session))
                            .await
                        {
                            Ok(r) => r,
                            Err(e) => return map_error(e).into_response(),
                        };
                        if report.is_blocked {
                            return (
                                StatusCode::BAD_REQUEST,
                                "Content block blocked.".to_string(),
                            )
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

    let mut full_token_map: TokenMap = auth
        .session
        .token_to_pii
        .iter()
        .map(|r| (r.key().clone(), r.value().clone()))
        .collect();
    merge_token_map(&mut full_token_map, &combined_token_map);

    let _ = state
        .session_manager
        .save_session(&auth.username, &auth.session)
        .await;

    if is_stream {
        return crate::sse_proxy::stream_proxy_response(upstream_resp, full_token_map).await;
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
                    if let Ok(restored) = state.shield.restore_prompt(text, &full_token_map) {
                        *text_val = serde_json::Value::String(restored);
                    }
                }
            }
        }
    }

    let _ = state
        .session_manager
        .save_session(&auth.username, &auth.session)
        .await;
    (StatusCode::OK, Json(res_json)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::Request;

    use iw_core::{ComplianceReport, ScrubbingReport, TokenMap};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::sync::Arc;
    use tower::ServiceExt;

    const PRIVATE_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDWKHpjWw901PCx\nDi8HnsbyHY/+xBIpQQ7TpdJ5Kz2jjKoOUXGZbfmKneFXQH8BCCLTR9x7ufhwXI1B\nfn5Hi+7oD1xuAwz+u6gqeLyGbp8om5uoZhvzKnYeLNOC9qTXIzs24y8YWRDniluj\n/yKjyKttbfNzGg5UUlpSkoNmGIvQwzxN0wLLxCJRsJc5JV/AUGngK06p9T/hcu4V\naDW0bEene91pGixp90hDNVwKkDWz1PNU9KOwHuLIJxF+0EFSc3I+PNUqXG6P3In4\nC3JP5xd7ZrGDnNixfus1lXJxe8i/4+kO9Abuedb9BLHETAwHoN/yWy3TC1XLLLWV\n3CBqaumJAgMBAAECggEAFd4Aj+LtQ0TiUMnoeR2Neze+i3Pc1jPg6Nvj5QsfxPKT\ng1kYluM5BEjrs1DlcacG205ZT+mPhHWcLNBW4kUCaiqgtFEBGNpI07wL+qln/Kmq\n7WPZExgbrdLDmXnyyfmRzcsedMd/Z40On20T+JJVwsY5LLW/5HybjBaOw97aGUDu\nVXO8G2RLaDcrGIjydf8iXdKGldeVanFbAEbHuOcJceY3nW6EHawUctI7m22ZCtKu\nSgnA9SYiKamlNmEz223zeQh/K+8UNne3gERuxZ874c8t+Bi3cMInuPhpejl0bdCg\nYaJnL3OdMqnlWXm8mrHS05/XB2PyaFiw9ddtdcS5uwKBgQD04jwJSt3SwLzPRk+i\n5yZIVFoQ8T9O1+cQKQAXSwlN22//tpe44ba2C3FOkYrsU5bapT8VGnc8upQCDAk6\nyY6yeH5T5cFmylinNWFJAqHE2jV+wfbPgUmsRTYytIECq7OTixzLmLmY9vgaySBa\nARv6rGltDor38yxD7vo7sGz1gwKBgQDf4S9OXMB71Xv4xig5J9VjLN8A/u9kPjN/\npnibZF1/kQfpkekqbMveLZbbPKvGrCITiFlUTK9r9p2eBqUYtRyRV/BlKL71oVdB\nZiIivstEpucUhiKJiwrO8oJc/FpA+jRrfT5YBp07ki6jATLyuyVIBO3Rztm6AmXc\nS2EbdNaDAwKBgQCiVOZfcpWhg8qlzII2BuzFvcUGviWtaknt2IAK8N72EaUo6i2h\njV7FRsiRwMFK8A5sWmZ64tRwGW7L/JaRtdM2U9HKY9/U+AXUsfoPoAMEr3IO2R13\naMkhva+z5RwwXQnpoKox/Mfrsqu9dd5QS7P0dB5fAOj2fOi3D9ApiUZxaQKBgGY5\n56Tre0TQPVRh/xniE3C+m3FT9zGZqWA/PlEOKhdGvQstAf/KP+jKfljLQlBsZv7u\nQoPYpD0zFdODiz1V7Z58Phui2FdGfZYyMaIV5rEJWPipKvoNEDlgyJ/25qtG1ErE\nnIQLOR5raHor4Pyu8Z4KCiHERuzFjYdisAuedRjLAoGBAJTkcWpA/SKTkzjFNWfM\nYlzU1vsz9//0EHy//fDWeHqH6dWi1OOP/JnXtlDFHis6M/DvPeXAwjCFfXqnkbwZ\nPNa++c7N0aflBBOWUmo3+333Tqe/HXg/MKiAiIpRXJM2RAGUprL0P3XWXROMCwFQ\nOaWyPS+gFjrX3kXEYT60sBFa\n-----END PRIVATE KEY-----";

    const PUBLIC_KEY_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1ih6Y1sPdNTwsQ4vB57G\n8h2P/sQSKUEO06XSeSs9o4yqDlFxmW35ip3hV0B/AQgi00fce7n4cFyNQX5+R4vu\n6A9cbgMM/ruoKni8hm6fKJubqGYb8yp2HizTgvak1yM7NuMvGFkQ54pbo/8io8ir\nbW3zcxoOVFJaUpKDZhiL0MM8TdMCy8QiUbCXOSVfwFBp4CtOqfU/4XLuFWg1tGxH\np3vdaRosafdIQzVcCpA1s9TzVPSjsB7iyCcRftBBUnNyPjzVKlxuj9yJ+AtyT+cX\ne2axg5zYsX7rNZVycXvIv+PpDvQG7nnW/QSxxEwMB6Df8lst0wtVyyy1ldwgamrp\niQIDAQAB\n-----END PUBLIC KEY-----";

    #[derive(Debug, Serialize, Deserialize)]
    struct CustomClaims {
        sub: String,
        exp: usize,
        iss: String,
        aud: String,
        roles: Vec<String>,
    }

    struct FailingStorage;
    #[async_trait]
    impl StorageProvider for FailingStorage {
        async fn fetch_context(&self, _: &str, _: &str) -> Result<Vec<String>, SovereignError> {
            Ok(vec![])
        }
        async fn log_audit_event(
            &self,
            _: &ScrubbingReport,
            _: &str,
            _: &str,
        ) -> Result<(), SovereignError> {
            Err(SovereignError::InternalError("Audit write failure".into()))
        }
        async fn validate_job_access(&self, _: &str, _: &str) -> Result<bool, SovereignError> {
            Ok(true)
        }
        async fn purge_user_data(&self, _: &str) -> Result<(), SovereignError> {
            Ok(())
        }
        async fn check_health(&self) -> Result<(), SovereignError> {
            Ok(())
        }
        async fn get_compliance_report(&self) -> Result<ComplianceReport, SovereignError> {
            unimplemented!()
        }
    }

    struct MockPiiShield;
    #[async_trait]
    impl PiiShield for MockPiiShield {
        async fn sanitize_prompt(
            &self,
            prompt: &str,
            _: Option<&iw_core::SessionContext>,
        ) -> Result<ScrubbingReport, SovereignError> {
            Ok(ScrubbingReport {
                sanitized_text: prompt.to_string(),
                is_blocked: false,
                redactions: vec![],
                token_map: TokenMap::new(),
                execution_time_ms: 0,
                potential_misses: vec![],
            })
        }
        fn restore_prompt(&self, response: &str, _: &TokenMap) -> Result<String, SovereignError> {
            Ok(response.to_string())
        }
    }

    struct MockGroundingShield;
    impl iw_core::GroundingShield for MockGroundingShield {
        fn seal_query(&self, _: &str, _: &str) -> Result<Vec<u8>, SovereignError> {
            Ok(vec![])
        }
        fn unseal_query(&self, _: &[u8], _: &str) -> Result<String, SovereignError> {
            Ok(String::new())
        }
    }

    #[tokio::test]
    async fn test_audit_failure_circuit_breaker() {
        std::env::set_var("WARDEN_JWT_AUDIENCE", "test_aud");
        std::env::set_var("WARDEN_JWT_ISSUER", "test_iss");

        let claims = CustomClaims {
            sub: "admin_user".to_string(),
            exp: 9999999999,
            iss: "test_iss".to_string(),
            aud: "test_aud".to_string(),
            roles: vec!["admin".to_string()],
        };
        let key = EncodingKey::from_rsa_pem(PRIVATE_KEY_PEM).unwrap();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap();

        let pepper = SecretVec::from(vec![0u8; 32]);
        let queue = GroundingQueue::new(
            "file::memory:?cache=shared".to_string(),
            &pepper,
            None,
            None,
        )
        .unwrap();
        let session_manager =
            LocalSessionManager::new("file::memory:?cache=shared".to_string(), &pepper).unwrap();

        let state = Arc::new(BridgeState {
            shield: Arc::new(MockPiiShield),
            grounding_shield: Arc::new(MockGroundingShield),
            queue: Arc::new(queue),
            storage: Arc::new(FailingStorage),
            session_manager,
            jwt_public_key: SecretVec::from(PUBLIC_KEY_PEM.to_vec()),
            ingress_semaphore: Arc::new(tokio::sync::Semaphore::new(10)),
        });

        let app = create_bridge_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/enqueue")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&SearchRequest {
                    query: "test query".to_string(),
                    thread_id: "thread123".to_string(),
                    options: None,
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();

        // Should return 500 Internal Server Error due to Audit Failure
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
