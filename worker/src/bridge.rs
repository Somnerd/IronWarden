use crate::grounding::{GroundingQueue, LocalSessionManager};
use crate::proxy::{
    authenticate, merge_token_map, resolve_upstream_key, resolve_upstream_url, AnthropicRequest,
    AuthenticatedUser, ChatCompletionRequest, CompletionRequest,
};
use axum::{
    body::Body,
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
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
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
    /// Universal Gateway Prometheus Metrics Collector
    pub metrics: Arc<crate::metrics::GatewayMetrics>,
}

struct PermitStream<S> {
    stream: S,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl<S: futures::Stream<Item = Result<bytes::Bytes, axum::Error>> + Unpin> futures::Stream
    for PermitStream<S>
{
    type Item = Result<bytes::Bytes, axum::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.stream).poll_next(cx)
    }
}

async fn concurrency_limiter(
    State(state): State<Arc<BridgeState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let permit = state
        .ingress_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let stream = body.into_data_stream();
    let tracked_stream = PermitStream {
        stream,
        _permit: permit,
    };
    let tracked_body = Body::from_stream(tracked_stream);
    Ok(axum::response::Response::from_parts(parts, tracked_body))
}

pub fn create_bridge_router(state: Arc<BridgeState>) -> Router {
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(25)
            .burst_size(100)
            .finish()
            .expect("Failed to initialize Governor Rate Limiter"),
    );

    let protected_routes = Router::new()
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
        });

    Router::new()
        .route("/health", get(handle_health))
        .route("/metrics", get(handle_metrics))
        .route("/grafana/dashboard", get(handle_grafana_dashboard))
        .route("/monitoring/dashboard.json", get(handle_grafana_dashboard))
        .merge(protected_routes)
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
    state
        .metrics
        .requests_enqueue
        .fetch_add(1, Ordering::Relaxed);
    if !report.token_map.is_empty() {
        state
            .metrics
            .pii_entities_redacted
            .fetch_add(report.token_map.len() as u64, Ordering::Relaxed);
    }

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
                pii_scrubbed: !report.token_map.is_empty(),
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
    state
        .metrics
        .requests_get_result
        .fetch_add(1, Ordering::Relaxed);
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

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    uptime_seconds: u64,
    concurrency_available: usize,
    subsystems: HealthSubsystems,
}

#[derive(Serialize)]
struct HealthSubsystems {
    storage: &'static str,
    shield: &'static str,
    session_manager: &'static str,
}

async fn handle_health(
    State(state): State<Arc<BridgeState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state
        .metrics
        .requests_health
        .fetch_add(1, Ordering::Relaxed);
    let storage_ok = state.storage.check_health().await.is_ok();
    let status = if storage_ok { "HEALTHY" } else { "DEGRADED" };

    let is_json = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false);

    if is_json {
        let report = HealthResponse {
            status,
            version: env!("CARGO_PKG_VERSION"),
            uptime_seconds: state.metrics.uptime_seconds(),
            concurrency_available: state.ingress_semaphore.available_permits(),
            subsystems: HealthSubsystems {
                storage: if storage_ok { "ok" } else { "unavailable" },
                shield: "ok",
                session_manager: "ok",
            },
        };
        let http_status = if storage_ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        return (http_status, Json(report)).into_response();
    }

    if storage_ok {
        (
            StatusCode::OK,
            "IronWarden Bridge: V2.0 Universal AI Gateway Proxy: HEALTHY",
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "IronWarden Bridge: CRITICAL FAILURE: Storage check failed",
        )
            .into_response()
    }
}

async fn handle_metrics(State(state): State<Arc<BridgeState>>) -> impl IntoResponse {
    let body = state
        .metrics
        .render_prometheus(state.ingress_semaphore.available_permits());
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

const GRAFANA_DASHBOARD_JSON: &str =
    include_str!("../../monitoring/grafana/dashboards/ironwarden_dashboard.json");

async fn handle_grafana_dashboard() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/json; charset=utf-8")],
        GRAFANA_DASHBOARD_JSON,
    )
}

#[doc(hidden)]
pub fn get_proxy_http_client(resolved_addr: Option<(&str, SocketAddr)>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(120));

    if let Some((host, addr)) = resolved_addr {
        builder = builder.resolve(host, addr);
    }

    builder.build().unwrap_or_default()
}

async fn process_and_audit_text(
    state: &Arc<BridgeState>,
    auth: &AuthenticatedUser,
    text: &str,
    combined_token_map: &mut TokenMap,
) -> Result<String, (StatusCode, String)> {
    let report = match state
        .shield
        .sanitize_prompt(text, Some(&auth.session))
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let status = match e {
                SovereignError::PiiViolation(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return Err((status, e.to_string()));
        }
    };

    if let Err(e) = state
        .storage
        .log_audit_event(&report, text, &auth.username)
        .await
    {
        tracing::error!("CRITICAL: Audit log failure. Aborting request: {}", e);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
    }

    if report.is_blocked {
        state
            .metrics
            .injections_blocked
            .fetch_add(1, Ordering::Relaxed);
        return Err((
            StatusCode::BAD_REQUEST,
            "[POLICY VIOLATION] Prompt blocked by IronWarden.".to_string(),
        ));
    }

    if !report.token_map.is_empty() {
        state
            .metrics
            .pii_entities_redacted
            .fetch_add(report.token_map.len() as u64, Ordering::Relaxed);
    }
    merge_token_map(combined_token_map, &report.token_map);
    Ok(report.sanitized_text)
}

type ProcessContentFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), (StatusCode, String)>> + Send + 'a>,
>;

fn process_and_audit_content_value<'a>(
    state: &'a Arc<BridgeState>,
    auth: &'a AuthenticatedUser,
    content: &'a mut serde_json::Value,
    combined_token_map: &'a mut TokenMap,
) -> ProcessContentFuture<'a> {
    Box::pin(async move {
        match content {
            serde_json::Value::String(s) => {
                let sanitized = process_and_audit_text(state, auth, s, combined_token_map).await?;
                *s = sanitized;
            }
            serde_json::Value::Array(items) => {
                for item in items.iter_mut() {
                    process_and_audit_content_value(state, auth, item, combined_token_map).await?;
                }
            }
            serde_json::Value::Object(map) => {
                if let Some(text_val) = map.get_mut("text") {
                    if let serde_json::Value::String(s) = text_val {
                        let sanitized =
                            process_and_audit_text(state, auth, s, combined_token_map).await?;
                        *s = sanitized;
                    } else {
                        process_and_audit_content_value(state, auth, text_val, combined_token_map)
                            .await?;
                    }
                }
                if let Some(content_val) = map.get_mut("content") {
                    process_and_audit_content_value(state, auth, content_val, combined_token_map)
                        .await?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

async fn handle_openai_chat_completions(
    State(state): State<Arc<BridgeState>>,
    headers: HeaderMap,
    Json(mut payload): Json<ChatCompletionRequest>,
) -> impl IntoResponse {
    state
        .metrics
        .requests_chat_completions
        .fetch_add(1, Ordering::Relaxed);

    // 1. Authenticate
    let auth = match authenticate(&headers, &state.jwt_public_key, &state.session_manager).await {
        Ok(a) => a,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    // 2. Pre-flight scrub all messages (both string and structured array content blocks)
    let mut combined_token_map = TokenMap::new();
    for msg in payload.messages.iter_mut() {
        if let Err((status, msg_err)) = process_and_audit_content_value(
            &state,
            &auth,
            &mut msg.content,
            &mut combined_token_map,
        )
        .await
        {
            return (status, msg_err).into_response();
        }
    }

    // 3. Resolve target
    let (target_url, resolved_addr) = match resolve_upstream_url(&headers, &payload.model).await {
        Ok(url) => url,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let api_key = resolve_upstream_key(&headers);
    let is_stream = payload.stream.unwrap_or(false);

    // 4. Build client with SocketAddr pinning (DNS rebinding TOCTOU defense)
    let host_for_pin = reqwest::Url::parse(&target_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()));
    let pin_arg = match (&host_for_pin, resolved_addr) {
        (Some(h), Some(addr)) => Some((h.as_str(), addr)),
        _ => None,
    };
    let client = get_proxy_http_client(pin_arg);

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
    state
        .metrics
        .requests_completions
        .fetch_add(1, Ordering::Relaxed);
    let auth = match authenticate(&headers, &state.jwt_public_key, &state.session_manager).await {
        Ok(a) => a,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    // 2. Pre-flight scrub prompts (string or array)
    let mut combined_token_map = TokenMap::new();
    if let Err((status, msg_err)) =
        process_and_audit_content_value(&state, &auth, &mut payload.prompt, &mut combined_token_map)
            .await
    {
        return (status, msg_err).into_response();
    }

    let (target_url_base, resolved_addr) =
        match resolve_upstream_url(&headers, &payload.model).await {
            Ok(u) => u,
            Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        };
    let target_url = target_url_base.replace("/chat/completions", "/completions");
    let api_key = resolve_upstream_key(&headers);

    let host_for_pin = reqwest::Url::parse(&target_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()));
    let pin_arg = match (&host_for_pin, resolved_addr) {
        (Some(h), Some(addr)) => Some((h.as_str(), addr)),
        _ => None,
    };
    let client = get_proxy_http_client(pin_arg);
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
    State(state): State<Arc<BridgeState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state
        .metrics
        .requests_models
        .fetch_add(1, Ordering::Relaxed);

    // SECURITY: Authenticate request to prevent unauthenticated upstream quota drain
    if let Err((status, msg)) =
        authenticate(&headers, &state.jwt_public_key, &state.session_manager).await
    {
        return (status, msg).into_response();
    }

    let (base, resolved_addr) = match resolve_upstream_url(&headers, "").await {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let models_url = if base.ends_with("/models") {
        base
    } else {
        let trimmed = base
            .trim_end_matches('/')
            .replace("/chat/completions", "")
            .replace("/completions", "");
        format!("{}/models", trimmed.trim_end_matches('/'))
    };
    let api_key = resolve_upstream_key(&headers);
    let host_for_pin = reqwest::Url::parse(&models_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()));
    let pin_arg = match (&host_for_pin, resolved_addr) {
        (Some(h), Some(addr)) => Some((h.as_str(), addr)),
        _ => None,
    };
    let client = get_proxy_http_client(pin_arg);
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
    state
        .metrics
        .requests_messages
        .fetch_add(1, Ordering::Relaxed);
    let auth = match authenticate(&headers, &state.jwt_public_key, &state.session_manager).await {
        Ok(a) => a,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    let mut combined_token_map = TokenMap::new();

    // Sanitize system prompt
    if let Some(ref system) = payload.system.clone() {
        let sanitized =
            match process_and_audit_text(&state, &auth, system, &mut combined_token_map).await {
                Ok(s) => s,
                Err((status, msg_err)) => return (status, msg_err).into_response(),
            };
        payload.system = Some(sanitized);
    }

    // Sanitize messages — support both string and content-block array formats
    for msg in payload.messages.iter_mut() {
        if let Err((status, msg_err)) = process_and_audit_content_value(
            &state,
            &auth,
            &mut msg.content,
            &mut combined_token_map,
        )
        .await
        {
            return (status, msg_err).into_response();
        }
    }

    let (target_url, resolved_addr) = match resolve_upstream_url(&headers, &payload.model).await {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let has_custom_target = headers
        .get("X-IronWarden-Target-URL")
        .or_else(|| headers.get("x-ironwarden-target-url"))
        .is_some();

    let api_key = headers
        .get("x-api-key")
        .or_else(|| headers.get("X-IronWarden-Upstream-Key"))
        .or_else(|| headers.get("x-ironwarden-upstream-key"))
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| {
            if has_custom_target {
                None
            } else {
                std::env::var("ANTHROPIC_API_KEY").ok()
            }
        })
        .unwrap_or_default();
    let anthropic_version = headers
        .get("anthropic-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("2023-06-01");
    let is_stream = payload.stream.unwrap_or(false);

    let host_for_pin = reqwest::Url::parse(&target_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()));
    let pin_arg = match (&host_for_pin, resolved_addr) {
        (Some(h), Some(addr)) => Some((h.as_str(), addr)),
        _ => None,
    };
    let client = get_proxy_http_client(pin_arg);
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
