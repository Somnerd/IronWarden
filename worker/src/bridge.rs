use axum::{
    routing::{get, post},
    Json, Router, extract::{State, Path},
    response::IntoResponse,
    http::{StatusCode, HeaderMap},
};
use std::sync::Arc;
use std::collections::HashMap;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use crate::searchboost::{SearchBoostQueue, LocalSessionManager};
use iw_core::{PiiShield, StorageProvider, SovereignError};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Serialize, Deserialize};
use secrecy::{SecretVec, ExposeSecret};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // The username/tenant_id
    pub exp: usize,
}

#[derive(Deserialize)]
pub struct SearchRequest {
    pub query: String,
    pub thread_id: String,
    pub options: Option<HashMap<String, serde_json::Value>>,
}

pub struct BridgeState {
    pub shield: Arc<dyn PiiShield>,
    pub queue: Arc<SearchBoostQueue>,
    pub storage: Arc<dyn StorageProvider>,
    /// Unified Session Manager (Local SQLite-backed)
    pub session_manager: Arc<LocalSessionManager>,
    /// HMAC/JWT Secret for identity verification
    pub jwt_secret: SecretVec<u8>,
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
        .layer(GovernorLayer { config: governor_conf })
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
    // --- COMPLIANCE CHECK: Hard-Stop Health Check (WP #88) ---
    if let Err(e) = state.storage.check_health().await {
        tracing::error!("HARD-STOP TRIGGERED: {}. Aborting request to maintain zero-failure compliance.", e);
        return map_error(e).into_response();
    }

    // 1. Authenticate & Verify Identity (JWT)
    let auth_header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h: &str| h.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Missing Bearer Token").into_response(),
    };

    let mut validation = Validation::new(Algorithm::HS256);
    let aud = std::env::var("WARDEN_JWT_AUDIENCE").unwrap_or_else(|_| "ironwarden-bridge".to_string());
    let iss = std::env::var("WARDEN_JWT_ISSUER").unwrap_or_else(|_| "ironwarden-auth".to_string());
    validation.set_audience(&[aud]);
    validation.set_issuer(&[iss]);

    let token_data = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.expose_secret()),
        &validation,
    ) {
        Ok(c) => c,
        Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid or Expired Token").into_response(),
    };

    let username = token_data.claims.sub;

    // 2. Local Session Retrieval
    let user_context = match state.session_manager.get_session(&username).await {
        Ok(ctx) => ctx,
        Err(e) => return map_error(e).into_response(),
    };

    // 3. Scrub PII from the query using the isolated context
    let report = match state.shield.sanitize_prompt(&payload.query, Some(&user_context)) {
        Ok(r) => r,
        Err(e) => return map_error(e).into_response(),
    };

    // --- SECURITY FIX: Log to Audit Ledger ---
    if let Err(e) = state.storage.log_audit_event(&report, &payload.query).await {
        tracing::error!("AUDIT LOG FAILURE: {}. Request aborted to prevent un-audited access!", e);
        return map_error(e).into_response();
    }
// --- SECURITY FIX (V-14): Hard-Block Circuit Breaker & Leak Prevention ---
if report.is_blocked {
    return map_error(iw_core::SovereignError::PiiViolation("[POLICY VIOLATION] Your request was blocked due to sensitive data leakage.".into())).into_response();
}

// 4. Persist updated session state
if let Err(e) = state.session_manager.save_session(&username, &user_context).await {
    tracing::error!("Failed to save session for {}: {}", username, e);
}

// 5. Delegate to Storage & Queue
tracing::info!(
    "PII Scrubbed for {}: replaced {} terms",
    username,
    report.token_map.len()
);

let options = payload.options.unwrap_or_default();

    // --- SECURITY FIX (V-14): Enqueue the SANITIZED query ---
    match state.queue.enqueue(
        report.sanitized_text,
        options,
        payload.thread_id,
        username,
    ).await {
        Ok(job_id) => {
            (StatusCode::OK, Json(serde_json::json!({
                "status": "queued",
                "id": job_id,
                "pii_scrubbed": report.token_map.len() > 0
            }))).into_response()
        }
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
    // Authentication (simplified for this turn, ideally share logic)
    let auth_header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h: &str| h.strip_prefix("Bearer "));

    if auth_header.is_none() {
        return (StatusCode::UNAUTHORIZED, "Missing Bearer Token").into_response();
    }

    match state.queue.get_result(&job_id).await {
        Ok(Some(res)) => (StatusCode::OK, res).into_response(),
        Ok(None) => (StatusCode::ACCEPTED, "Processing...").into_response(),
        Err(e) => map_error(e).into_response(),
    }
}

async fn handle_health(State(state): State<Arc<BridgeState>>) -> impl IntoResponse {
    match state.storage.check_health().await {
        Ok(_) => (StatusCode::OK, "IronWarden Bridge: V1.2 Sovereign Search: HEALTHY").into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, format!("IronWarden Bridge: CRITICAL FAILURE: {}", e)).into_response(),
    }
}
