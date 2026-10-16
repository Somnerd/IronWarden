pub mod llm_gateway;
pub mod search_handlers;
pub mod telemetry;

pub use llm_gateway::*;
pub use search_handlers::*;
pub use telemetry::*;

use crate::grounding::{GroundingQueue, LocalSessionManager};
use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use iw_core::{PiiShield, SovereignError, StorageProvider};
use secrecy::SecretVec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

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

pub(crate) fn map_error(e: SovereignError) -> impl IntoResponse {
    let status = match e {
        SovereignError::DatabaseBusy(_) => StatusCode::SERVICE_UNAVAILABLE,
        SovereignError::UnauthorizedAccess(_) => StatusCode::FORBIDDEN,
        SovereignError::GatewayTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
        SovereignError::PiiViolation(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, e.to_string())
}
