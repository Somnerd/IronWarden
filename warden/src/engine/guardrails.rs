use aes_gcm::{
    aead::{Aead, Payload},
    Nonce,
};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use iw_core::{EnforcementAction, GroundingShield, PiiCategory, SovereignError};
use rand::RngCore;
use serde::Serialize;
use std::sync::LazyLock;
use tracing::warn;

use super::WardenEngine;

pub(crate) static INJECTION_BLOCKLIST: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(vec![
            "systemoverride",
            "ignorepreviousinstructions",
            "disregardinstructions",
            "bypassconstraints",
            "systemprompt",
            "youarenow",
            "forgetall",
            "printyour",
        ])
        .unwrap()
});

#[derive(Serialize)]
struct GuardrailPayload<'a> {
    prompt: &'a str,
}

pub(crate) async fn check_ml_sidecar(input: &str) -> Result<bool, SovereignError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let socket_path = std::env::var("WARDEN_ML_SIDECAR_SOCKET")
        .unwrap_or_else(|_| "/tmp/warden_llamaguard.sock".to_string());

    let require_sidecar = std::env::var("WARDEN_REQUIRE_ML_SIDECAR")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if !std::path::Path::new(&socket_path).exists() {
        if require_sidecar {
            warn!(
                socket_path = %socket_path,
                "ML Guardrail Sidecar socket not found. Enforcing fail-closed policy (SEC-01)."
            );
            return Err(SovereignError::UnauthorizedAccess(
                "ML Guardrail Sidecar socket missing — Fail-Closed Policy enforced".into(),
            ));
        }
        return Ok(false);
    }

    let timeout_ms = std::env::var("WARDEN_ML_SIDECAR_TIMEOUT_MS")
        .ok()
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(100);

    let timeout_duration = std::time::Duration::from_millis(timeout_ms);

    match tokio::time::timeout(
        timeout_duration,
        tokio::net::UnixStream::connect(&socket_path),
    )
    .await
    {
        Ok(Ok(mut stream)) => {
            let payload_struct = GuardrailPayload { prompt: input };
            let payload = serde_json::to_string(&payload_struct).map_err(|_| {
                SovereignError::InternalError("Failed to serialize Guardrail payload".into())
            })?;

            if let Err(e) =
                tokio::time::timeout(timeout_duration, stream.write_all(payload.as_bytes())).await
            {
                warn!("ML Guardrail Sidecar write timed out or failed: {}. Enforcing fail-closed policy.", e);
                return Err(SovereignError::UnauthorizedAccess(
                    "ML Guardrail Sidecar write timed out — Fail-Closed Policy enforced".into(),
                ));
            }

            let mut buf = [0u8; 1024];
            let read_res = tokio::time::timeout(timeout_duration, stream.read(&mut buf)).await;
            let n = match read_res {
                Ok(Ok(n)) => n,
                _ => {
                    warn!("ML Guardrail Sidecar read timed out or failed. Enforcing fail-closed policy.");
                    return Err(SovereignError::UnauthorizedAccess(
                        "ML Guardrail Sidecar read timed out — Fail-Closed Policy enforced".into(),
                    ));
                }
            };

            let response = String::from_utf8_lossy(&buf[..n]);
            if response.contains("BLOCKED") {
                return Ok(true);
            }
            Ok(false)
        }
        _ => {
            warn!(
                socket_path = %socket_path,
                "ML Guardrail Sidecar unreachable or timed out. Enforcing fail-closed policy (SEC-01)."
            );
            Err(SovereignError::UnauthorizedAccess(
                "ML Guardrail Sidecar unreachable or timed out — Fail-Closed Policy enforced"
                    .into(),
            ))
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UnifiedMatch {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) text: String,
    pub(crate) rule_id: String,
    #[allow(dead_code)]
    pub(crate) is_confirmed: bool,
    pub(crate) action: EnforcementAction,
    pub(crate) category: PiiCategory,
}

#[doc(hidden)]
pub fn is_standalone_word(text: &str, sub: &str) -> bool {
    if sub.is_empty() {
        return false;
    }
    let mut search_idx = 0;
    while let Some(idx) = text[search_idx..].find(sub) {
        let actual_idx = search_idx + idx;

        let before_ok =
            actual_idx == 0 || !text[..actual_idx].ends_with(|c: char| c.is_alphanumeric());
        let after_idx = actual_idx + sub.len();
        let after_ok = after_idx == text.len()
            || !text[after_idx..].starts_with(|c: char| c.is_alphanumeric());

        if before_ok && after_ok {
            return true;
        }

        let next_char_len = text[actual_idx..]
            .chars()
            .next()
            .map(|c| c.len_utf8())
            .unwrap_or(1);
        search_idx = actual_idx + next_char_len;
    }
    false
}

impl WardenEngine {
    /// Generates a semantic, contextual placeholder token based on the detected PII category and rule (e.g. `[EMAIL_1]`, `[NAME_1]`, `[PHONE_1]`, `[SSN_1]`, `[AFM_1]`).
    pub fn generate_placeholder(category: PiiCategory, rule_id: &str, id: usize) -> String {
        let rule_upper = rule_id.to_ascii_uppercase();
        let prefix = if rule_upper.contains("EMAIL") {
            "EMAIL"
        } else if rule_upper.contains("PERSON") || rule_upper.contains("NAME") {
            "NAME"
        } else if rule_upper.contains("PHONE") {
            "PHONE"
        } else if rule_upper.contains("AFM") {
            "AFM"
        } else if rule_upper.contains("AMKA") {
            "AMKA"
        } else if rule_upper.contains("IBAN") || rule_upper.contains("BANK") {
            "IBAN"
        } else if rule_upper.contains("CREDIT_CARD") || rule_upper.contains("CARD") {
            "CREDIT_CARD"
        } else if rule_upper.contains("SSN") {
            "SSN"
        } else if rule_upper.contains("PASSPORT") {
            "PASSPORT"
        } else if rule_upper.contains("IP_ADDRESS")
            || rule_upper.contains("IPV4")
            || rule_upper.contains("IPV6")
        {
            "IP"
        } else {
            match category {
                PiiCategory::IndividualName => "NAME",
                PiiCategory::IdentificationNumber => "ID",
                PiiCategory::FinancialData => "FINANCIAL",
                PiiCategory::ContactInfo => "CONTACT",
                PiiCategory::InternalAsset => "ASSET",
                PiiCategory::HighConfidenceAi => "AI_REDACTED",
                PiiCategory::PotentialHeuristic => "HEURISTIC",
                PiiCategory::Organization => "ORG",
                PiiCategory::Location => "LOCATION",
                PiiCategory::Other => "TOKEN",
            }
        };
        format!("[{}_{}]", prefix, id)
    }

    #[doc(hidden)]
    pub fn check_shannon_entropy_smuggling(input: &str) -> bool {
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if Self::is_base64_char(bytes[i]) {
                let start = i;
                while i < bytes.len() && Self::is_base64_char(bytes[i]) {
                    i += 1;
                }
                let len = i - start;
                if len > 40 && Self::calculate_entropy(&bytes[start..i]) > 5.8 {
                    return true;
                }
            } else {
                i += 1;
            }
        }
        false
    }

    #[inline(always)]
    fn is_base64_char(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
    }

    fn calculate_entropy(data: &[u8]) -> f64 {
        let mut counts = [0usize; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let mut entropy = 0.0;
        let len = data.len() as f64;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

#[doc(hidden)]
pub fn combine_actions(a: EnforcementAction, b: EnforcementAction) -> EnforcementAction {
    match (a, b) {
        (EnforcementAction::Block, _) | (_, EnforcementAction::Block) => EnforcementAction::Block,
        (EnforcementAction::Redact, _) | (_, EnforcementAction::Redact) => {
            EnforcementAction::Redact
        }
        (EnforcementAction::Mask, _) | (_, EnforcementAction::Mask) => EnforcementAction::Mask,
        (EnforcementAction::AuditOnly, EnforcementAction::AuditOnly) => {
            EnforcementAction::AuditOnly
        }
    }
}

impl GroundingShield for WardenEngine {
    fn seal_query(&self, query: &str, username: &str) -> Result<Vec<u8>, SovereignError> {
        let mut nonce_bytes = [0u8; 12];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut nonce_bytes);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&nonce_bytes);

        // --- SECURITY FIX (V-19): Bind encryption to username via AAD ---
        let payload = Payload {
            msg: query.as_bytes(),
            aad: username.as_bytes(),
        };

        let ciphertext = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|_| SovereignError::InternalError("Query sealing failed".into()))?;

        let mut blob = nonce_bytes.to_vec();
        blob.extend(ciphertext);
        Ok(blob)
    }

    fn unseal_query(&self, blob: &[u8], username: &str) -> Result<String, SovereignError> {
        if blob.len() < 12 {
            return Err(SovereignError::InternalError(
                "Invalid sealed query blob".into(),
            ));
        }

        let (nonce_bytes, ciphertext) = blob.split_at(12);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(nonce_bytes);

        // --- SECURITY FIX (V-19): Bind decryption to username via AAD ---
        let payload = Payload {
            msg: ciphertext,
            aad: username.as_bytes(),
        };

        let plaintext = self.cipher.decrypt(nonce, payload).map_err(|_| {
            SovereignError::UnauthorizedAccess(
                "Query unsealing failed: AAD mismatch or tampering".into(),
            )
        })?;

        String::from_utf8(plaintext)
            .map_err(|_| SovereignError::InternalError("Decrypted query is not valid UTF-8".into()))
    }
}
