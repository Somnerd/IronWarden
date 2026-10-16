use super::{map_error, BridgeState, SearchRequest};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use iw_core::crypto::JwtVerifier;
use iw_core::SovereignError;
use secrecy::ExposeSecret;
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Serialize)]
pub struct EnqueueResponse<'a> {
    pub status: &'a str,
    pub id: String,
    pub pii_scrubbed: bool,
}

pub async fn handle_enqueue(
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

pub async fn handle_get_result(
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
