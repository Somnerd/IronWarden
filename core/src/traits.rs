use async_trait::async_trait;
use crate::error::SovereignError;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A map of pseudonymized tokens to their original values.
pub type TokenMap = HashMap<String, String>;

/// Thread-safe in-memory context for maintaining session consistency.
/// Uses DashMap for fine-grained concurrency, allowing multiple threads to scan and update
/// token mappings without a global mutex lock.
#[derive(Debug)]
pub struct SessionContext {
    /// Maps raw PII values (lowercase) to their assigned tokens (e.g. "alice" -> "[PERSON_1]")
    pub pii_to_token: DashMap<String, String>,
    /// Maps tokens back to original values (e.g. "[PERSON_1]" -> "Alice")
    pub token_to_pii: DashMap<String, String>,
    /// History of full-name identities (lowercase full name -> token)
    pub identities: DashMap<String, String>,
    pub next_id: AtomicUsize,
    pub last_accessed: AtomicU64,
}

/// Serializable representation of SessionContext for Redis storage.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionState {
    pub pii_to_token: HashMap<String, String>,
    pub token_to_pii: HashMap<String, String>,
    pub identities: HashMap<String, String>,
    pub next_id: usize,
    pub last_accessed: u64,
}

impl From<&SessionContext> for SessionState {
    fn from(ctx: &SessionContext) -> Self {
        Self {
            pii_to_token: ctx.pii_to_token.iter().map(|kv| (kv.key().clone(), kv.value().clone())).collect(),
            token_to_pii: ctx.token_to_pii.iter().map(|kv| (kv.key().clone(), kv.value().clone())).collect(),
            identities: ctx.identities.iter().map(|kv| (kv.key().clone(), kv.value().clone())).collect(),
            next_id: ctx.next_id.load(Ordering::SeqCst),
            last_accessed: ctx.last_accessed.load(Ordering::SeqCst),
        }
    }
}

impl From<SessionState> for SessionContext {
    fn from(state: SessionState) -> Self {
        let pii_to_token = DashMap::new();
        for (k, v) in state.pii_to_token { pii_to_token.insert(k, v); }
        
        let token_to_pii = DashMap::new();
        for (k, v) in state.token_to_pii { token_to_pii.insert(k, v); }

        let identities = DashMap::new();
        for (k, v) in state.identities { identities.insert(k, v); }

        Self {
            pii_to_token,
            token_to_pii,
            identities,
            next_id: AtomicUsize::new(state.next_id),
            last_accessed: AtomicU64::new(state.last_accessed),
        }
    }
}

impl Default for SessionContext {
    fn default() -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            pii_to_token: DashMap::new(),
            token_to_pii: DashMap::new(),
            identities: DashMap::new(),
            next_id: AtomicUsize::new(1),
            last_accessed: AtomicU64::new(now),
        }
    }
}

impl SessionContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates the last_accessed timestamp to the current time.
    pub fn touch(&self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.last_accessed.store(now, Ordering::SeqCst);
    }

    pub fn last_accessed(&self) -> u64 {
        self.last_accessed.load(Ordering::SeqCst)
    }

    /// Increments and returns the next available token ID.
    pub fn next_id(&self) -> usize {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SanitizationAction {
    Block,        // Stop the entire message
    ReplaceToken, // Replace with unique placeholder (e.g. [PERSON_1])
    Mask,         // Replace with static string (e.g. [REDACTED])
}

// DO NOT REORDER FIELDS: This struct is serialized via `bincode` for the cryptographic audit chain.
// Any field reordering will break historical HMAC validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redaction {
    pub rule_id: String,
    pub action: SanitizationAction,
    pub offset: usize,
    pub length: usize,
    pub placeholder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PotentialMiss {
    pub text: String,
    pub label: String,
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubbingReport {
    pub sanitized_text: String,
    pub is_blocked: bool,
    pub redactions: Vec<Redaction>,
    pub token_map: TokenMap,
    pub execution_time_ms: u64,
    pub potential_misses: Vec<PotentialMiss>,
}

#[async_trait]
pub trait McpServer: Send + Sync {
    /// Handles an incoming MCP JSON-RPC payload.
    async fn handle_request(&self, request: String) -> Result<String, SovereignError>;
}

pub trait PiiShield: Send + Sync {
    /// Sanitizes a prompt using a multi-layer defense pipeline.
    /// Optionally accepts a SessionContext to maintain cross-request token consistency.
    fn sanitize_prompt(
        &self,
        prompt: &str,
        session: Option<&SessionContext>,
    ) -> Result<ScrubbingReport, SovereignError>;

    /// Restores sensitized tokens in an LLM response with their original values.
    fn restore_prompt(&self, response: &str, map: &TokenMap) -> Result<String, SovereignError>;
}

#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Fetches relevant contextual documents for grounding a prompt.
    async fn fetch_context(&self, query: &str) -> Result<Vec<String>, SovereignError>;

    /// Records a transaction or security event to the audit trail.
    async fn log_audit_event(&self, report: &ScrubbingReport, raw_input: &str) -> Result<(), SovereignError>;

    /// Validates that a user has ownership/access to a specific job or result.
    async fn validate_job_access(&self, job_id: &str, username: &str) -> Result<bool, SovereignError>;
}

#[async_trait]
pub trait InferenceGateway: Send + Sync {
    /// Routes a sanitized prompt to an external LLM and returns the response.
    async fn route_prompt(&self, prompt: &str, context: &[String]) -> Result<String, SovereignError>;
}
