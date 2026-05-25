use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use std::sync::Arc;
use iw_core::traits::{PiiShield, EnforcementAction};
use iw_core::{ScrubbingReport, TokenMap, PiiCategory};

// Mock Shield that returns is_blocked = true
struct MockShield;
impl PiiShield for MockShield {
    fn sanitize_prompt(&self, _prompt: &str, _session: Option<&iw_core::SessionContext>) -> Result<ScrubbingReport, iw_core::SovereignError> {
        Ok(ScrubbingReport {
            sanitized_text: "blocked".to_string(),
            token_map: TokenMap::new(),
            is_blocked: true,
            risk_score: 1.0,
            detected_entities: vec![],
        })
    }
    fn restore_prompt(&self, response: &str, _map: &TokenMap) -> Result<String, iw_core::SovereignError> {
        Ok(response.to_string())
    }
}

// I need to be able to run the bridge with this mock.
// Since the bridge is tightly coupled with BridgeState, I might need to look at how to test it.
