use crate::error::SovereignError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
    /// Semantic L1 Cache (text -> (label, score))
    pub semantic_cache: moka::sync::Cache<String, (String, f64)>,
    pub next_id: AtomicUsize,
    pub last_accessed: AtomicU64,
}

/// Serializable representation of SessionContext for Redis storage.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionState {
    pub pii_to_token: HashMap<String, String>,
    pub token_to_pii: HashMap<String, String>,
    pub identities: HashMap<String, String>,
    pub semantic_cache: HashMap<String, (String, f64)>,
    pub next_id: usize,
    pub last_accessed: u64,
}

impl From<&SessionContext> for SessionState {
    fn from(ctx: &SessionContext) -> Self {
        let mut semantic_cache = HashMap::new();
        for (k, v) in ctx.semantic_cache.iter() {
            semantic_cache.insert(k.to_string(), v.clone());
        }

        Self {
            pii_to_token: ctx
                .pii_to_token
                .iter()
                .map(|kv| (kv.key().clone(), kv.value().clone()))
                .collect(),
            token_to_pii: ctx
                .token_to_pii
                .iter()
                .map(|kv| (kv.key().clone(), kv.value().clone()))
                .collect(),
            identities: ctx
                .identities
                .iter()
                .map(|kv| (kv.key().clone(), kv.value().clone()))
                .collect(),
            semantic_cache,
            next_id: ctx.next_id.load(Ordering::SeqCst),
            last_accessed: ctx.last_accessed.load(Ordering::SeqCst),
        }
    }
}

impl From<SessionState> for SessionContext {
    fn from(state: SessionState) -> Self {
        let pii_to_token = DashMap::new();
        for (k, v) in state.pii_to_token {
            pii_to_token.insert(k, v);
        }

        let token_to_pii = DashMap::new();
        for (k, v) in state.token_to_pii {
            token_to_pii.insert(k, v);
        }

        let identities = DashMap::new();
        for (k, v) in state.identities {
            identities.insert(k, v);
        }

        let semantic_cache = moka::sync::Cache::builder()
            .max_capacity(1000)
            .time_to_idle(std::time::Duration::from_secs(3600))
            .build();
        for (k, v) in state.semantic_cache {
            semantic_cache.insert(k, v);
        }

        Self {
            pii_to_token,
            token_to_pii,
            identities,
            semantic_cache,
            next_id: AtomicUsize::new(state.next_id),
            last_accessed: AtomicU64::new(state.last_accessed),
        }
    }
}

impl Default for SessionContext {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            pii_to_token: DashMap::new(),
            token_to_pii: DashMap::new(),
            identities: DashMap::new(),
            semantic_cache: moka::sync::Cache::builder()
                .max_capacity(1000)
                .time_to_idle(std::time::Duration::from_secs(3600))
                .build(),
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
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

#[cfg(test)]
#[path = "traits_tests.rs"]
mod tests;
