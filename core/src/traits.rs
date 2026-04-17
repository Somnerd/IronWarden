use async_trait::async_trait;
use crate::error::SovereignError;
use std::collections::HashMap;

/// A map of pseudonymized tokens to their original values.
pub type TokenMap = HashMap<String, String>;

#[async_trait]
pub trait McpServer: Send + Sync {
    /// Handles an incoming MCP JSON-RPC payload.
    async fn handle_request(&self, request: String) -> Result<String, SovereignError>;
}

pub trait PiiShield: Send + Sync {
    /// Sanitizes a prompt by replacing sensitive terms with deterministic tokens.
    /// Returns the safe prompt and a map to restore the original values later.
    fn sanitize_prompt(&self, prompt: &str) -> Result<(String, TokenMap), SovereignError>;

    /// Restores sensitized tokens in an LLM response with their original values.
    fn restore_prompt(&self, response: &str, map: &TokenMap) -> Result<String, SovereignError>;
}

#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Fetches relevant contextual documents for grounding a prompt.
    async fn fetch_context(&self, query: &str) -> Result<Vec<String>, SovereignError>;

    /// Records a transaction or security event to the audit trail.
    async fn log_audit_event(&self, event: &str) -> Result<(), SovereignError>;
}

#[async_trait]
pub trait InferenceGateway: Send + Sync {
    /// Routes a sanitized prompt to an external LLM and returns the response.
    async fn route_prompt(&self, prompt: &str, context: &[String]) -> Result<String, SovereignError>;
}
