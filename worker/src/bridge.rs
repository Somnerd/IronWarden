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
    // 1. Authenticate & Verify Identity (JWT)
    let auth_header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h: &str| h.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Missing Bearer Token").into_response(),
    };

    let token_data = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.expose_secret()),
        &Validation::new(Algorithm::HS256),
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

    // 4. Persist updated session state (mostly a no-op for Local manager, but keeps trait logic)
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
        },
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
    // 1. Authenticate & Verify Identity (JWT)
    let auth_header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h: &str| h.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Missing Bearer Token").into_response(),
    };

    let token_data = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.expose_secret()),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(c) => c,
        Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid or Expired Token").into_response(),
    };

    let username = token_data.claims.sub;

    // 2. Database IDOR Check
    match state.storage.validate_job_access(&job_id, &username).await {
        Ok(true) => (),
        Ok(false) => return (StatusCode::FORBIDDEN, "Access to result denied").into_response(),
        Err(e) => {
            tracing::error!("Database IDOR check failed: {}", e);
            return map_error(e).into_response();
        }
    }

    // 3. Local Session Retrieval for PII restoration
    let user_context = match state.session_manager.get_session(&username).await {
        Ok(ctx) => ctx,
        Err(e) => return map_error(e).into_response(),
    };

    match state.queue.get_result(&job_id).await {
        Ok(Some(data)) => {
            // Restore PII tokens using the user's private context
            let mut token_map: HashMap<String, String> = HashMap::new();
            for entry in user_context.token_to_pii.iter() {
                // EXPLICIT TYPE ANNOTATION FIX
                let k: String = entry.key().clone();
                let v: String = entry.value().clone();
                token_map.insert(k, v);
            }

            let restored_data = match state.shield.restore_prompt(&data, &token_map) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("PII Restoration failed for {}: {}", username, e);
                    return map_error(e).into_response();
                }
            };
            
            (StatusCode::OK, Json(serde_json::json!({
                "status": "complete",
                "result": restored_data
            }))).into_response()
        },
        Ok(None) => {
            (StatusCode::ACCEPTED, Json(serde_json::json!({"status": "pending"}))).into_response()
        },
        Err(e) => {
            tracing::error!("Failed to fetch result: {}", e);
            map_error(e).into_response()
        }
    }
}

async fn handle_health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "healthy", "service": "ironwarden-bridge"})))
}
