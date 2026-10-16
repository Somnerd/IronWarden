use super::BridgeState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub concurrency_available: usize,
    pub subsystems: HealthSubsystems,
    pub ner_mode: &'static str,
    pub ner_backend: &'static str,
}

#[derive(Serialize)]
pub struct HealthSubsystems {
    pub storage: &'static str,
    pub shield: &'static str,
    pub session_manager: &'static str,
}

pub async fn handle_health(
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
        let ner_mode = iw_warden::ai::NerMode::from_env()
            .map(|m| m.as_str())
            .unwrap_or("hybrid");
        let ner_backend = if ner_mode != "heuristic"
            && std::env::var("WARDEN_DISABLE_ONNX").is_err()
            && (std::path::Path::new("data/models/distilbert-ner/model_quantized.onnx").exists()
                || std::path::Path::new("../data/models/distilbert-ner/model_quantized.onnx")
                    .exists())
        {
            "onnx"
        } else {
            "heuristic"
        };

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
            ner_mode,
            ner_backend,
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

pub async fn handle_metrics(State(state): State<Arc<BridgeState>>) -> impl IntoResponse {
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
    include_str!("../../../monitoring/grafana/dashboards/ironwarden_dashboard.json");

pub async fn handle_grafana_dashboard() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/json; charset=utf-8")],
        GRAFANA_DASHBOARD_JSON,
    )
}
