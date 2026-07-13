use crate::searchboost::{LocalSessionManager, SearchBoostQueue};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use iw_core::crypto::JwtVerifier;
use iw_core::{PiiShield, SovereignError, StorageProvider};
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

#[derive(Deserialize)]
pub struct SearchRequest {
    pub query: String,
    pub thread_id: String,
    pub options: Option<HashMap<String, serde_json::Value>>,
}

pub struct BridgeState {
    pub shield: Arc<dyn PiiShield>,
    pub grounding_shield: Arc<dyn iw_core::GroundingShield>,
    pub queue: Arc<SearchBoostQueue>,
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
            "IronWarden Bridge: V1.3 Sovereign Search: HEALTHY",
        )
            .into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("IronWarden Bridge: CRITICAL FAILURE: {}", e),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
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
        async fn fetch_context(&self, _: &str, _: &str) -> Result<Vec<String>, SovereignError> { Ok(vec![]) }
        async fn log_audit_event(&self, _: &ScrubbingReport, _: &str, _: &str) -> Result<(), SovereignError> {
            Err(SovereignError::InternalError("Audit write failure".into()))
        }
        async fn validate_job_access(&self, _: &str, _: &str) -> Result<bool, SovereignError> { Ok(true) }
        async fn purge_user_data(&self, _: &str) -> Result<(), SovereignError> { Ok(()) }
        async fn check_health(&self) -> Result<(), SovereignError> { Ok(()) }
        async fn get_compliance_report(&self) -> Result<ComplianceReport, SovereignError> { unimplemented!() }
    }

    struct MockPiiShield;
    #[async_trait]
    impl PiiShield for MockPiiShield {
        async fn sanitize_prompt(&self, prompt: &str, _: Option<&iw_core::SessionContext>) -> Result<ScrubbingReport, SovereignError> {
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
        fn seal_query(&self, _: &str, _: &str) -> Result<Vec<u8>, SovereignError> { Ok(vec![]) }
        fn unseal_query(&self, _: &[u8], _: &str) -> Result<String, SovereignError> { Ok(String::new()) }
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
        let queue = SearchBoostQueue::new("file::memory:?cache=shared".to_string(), &pepper, None, None).unwrap();
        let session_manager = LocalSessionManager::new("file::memory:?cache=shared".to_string(), &pepper).unwrap();

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
            .body(Body::from(serde_json::to_string(&SearchRequest {
                query: "test query".to_string(),
                thread_id: "thread123".to_string(),
                options: None,
            }).unwrap()))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();

        // Should return 500 Internal Server Error due to Audit Failure
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
