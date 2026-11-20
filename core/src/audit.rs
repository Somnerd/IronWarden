use crate::error::SovereignError;
use crate::traits::Redaction;
use hmac::{Hmac, Mac};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Verification summary returned by [`verify_audit_chain`] and [`verify_audit_chain_diagnostic`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditChainSummary {
    pub last_id: i64,
    pub last_hash: Vec<u8>,
    pub verified_count: usize,
    pub archived_count: usize,
    pub gdpr_redacted_count: usize,
    pub failures: Vec<String>,
}

/// Fail-fast HMAC chain and anchor verification used by `AsyncAuditor::init_db`.
pub fn verify_audit_chain(
    conn: &Connection,
    db_path: &str,
    genesis_hash: &[u8; 32],
    hmac_key: &[u8; 32],
) -> Result<AuditChainSummary, String> {
    verify_audit_chain_inner(conn, db_path, genesis_hash, hmac_key, true)
}

/// Full-walk diagnostic verification used by `iw-cli verify` to collect all tampered records
/// and anchor mismatches in one pass.
pub fn verify_audit_chain_diagnostic(
    conn: &Connection,
    db_path: &str,
    genesis_hash: &[u8; 32],
    hmac_key: &[u8; 32],
) -> Result<AuditChainSummary, String> {
    verify_audit_chain_inner(conn, db_path, genesis_hash, hmac_key, false)
}

fn verify_audit_chain_inner(
    conn: &Connection,
    db_path: &str,
    genesis_hash: &[u8; 32],
    hmac_key: &[u8; 32],
    fail_fast: bool,
) -> Result<AuditChainSummary, String> {
    let mut stmt = conn
        .prepare(
            "SELECT ar.id, ar.timestamp, ar.is_blocked, ar.redactions_json, ar.payload_hash, ar.integrity_hash, erl.encrypted_data, erl.nonce, ar.username \
             FROM audit_reports ar \
             LEFT JOIN ephemeral_raw_logs erl ON ar.id = erl.id \
             ORDER BY ar.id ASC",
        )
        .map_err(|e| format!("Failed to prepare audit chain query: {}", e))?;

    let mut rows = stmt
        .query([])
        .map_err(|e| format!("Failed to execute audit chain query: {}", e))?;

    let mut current_hash = genesis_hash.to_vec();
    let mut current_id = 0i64;
    let mut verified_count = 0usize;
    let mut archived_count = 0usize;
    let mut gdpr_redacted_count = 0usize;
    let mut failures = Vec::new();

    while let Some(row) = rows
        .next()
        .map_err(|e| format!("Failed reading audit chain row: {}", e))?
    {
        let id: i64 = row
            .get(0)
            .map_err(|e| format!("Invalid audit row id: {}", e))?;
        let ts: String = row
            .get(1)
            .map_err(|e| format!("Invalid audit timestamp at {}: {}", id, e))?;
        let blocked: bool = row
            .get(2)
            .map_err(|e| format!("Invalid audit is_blocked at {}: {}", id, e))?;
        let redactions: String = row
            .get(3)
            .map_err(|e| format!("Invalid audit redactions_json at {}: {}", id, e))?;
        let payload_hash_str: String = row
            .get(4)
            .map_err(|e| format!("Invalid audit payload_hash at {}: {}", id, e))?;
        let stored_hash: String = row
            .get(5)
            .map_err(|e| format!("Invalid audit integrity_hash at {}: {}", id, e))?;
        let encrypted_data: Option<Vec<u8>> = row
            .get(6)
            .map_err(|e| format!("Invalid ephemeral encrypted_data at {}: {}", id, e))?;
        let nonce: Option<Vec<u8>> = row
            .get(7)
            .map_err(|e| format!("Invalid ephemeral nonce at {}: {}", id, e))?;
        let username: String = row
            .get(8)
            .map_err(|e| format!("Invalid audit username at {}: {}", id, e))?;

        if id != current_id + 1 {
            let msg = format!(
                "Audit sequence break detected at Log ID {}! Expected ID {}.",
                id,
                current_id + 1
            );
            if fail_fast {
                return Err(msg);
            }
            failures.push(msg);
        }

        let redactions_vec: Vec<Redaction> = serde_json::from_str(&redactions).unwrap_or_default();
        let redactions_bin = bincode::serialize(&redactions_vec).unwrap_or_default();
        let payload_hash = hex::decode(&payload_hash_str).unwrap_or_default();
        let stored_bytes = hex::decode(&stored_hash).unwrap_or_default();

        // Cryptographic shredding support: if username was purged/redacted under GDPR,
        // the raw identity is deleted but the proof-of-history hash chain link remains unbroken.
        if username == "[REDACTED]" || username.starts_with("GDPR_") {
            if stored_bytes.is_empty() && !stored_hash.is_empty() {
                let msg = format!("Invalid integrity_hash hex at redacted record {}", id);
                if fail_fast {
                    return Err(msg);
                }
                failures.push(msg);
            }
            current_hash = stored_bytes;
            current_id = id;
            archived_count += 1;
            gdpr_redacted_count += 1;
            continue;
        }

        // Stage 1: Verify HMAC Chain (Metadata + Username + Payload Hash)
        let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
            .map_err(|_| "HMAC key initialization failure".to_string())?;
        mac.update(&current_hash);
        mac.update(ts.as_bytes());
        mac.update(username.as_bytes());
        mac.update(&[blocked as u8]);
        mac.update(&redactions_bin);
        mac.update(&payload_hash);

        let computed_hash = mac.finalize().into_bytes().to_vec();

        if hex::encode(&computed_hash) != stored_hash {
            let msg = format!(
                "CHAIN TAMPER DETECTED at Log ID {}!\n   Expected Hash: {}\n   Stored Hash  : {}",
                id,
                hex::encode(&computed_hash),
                stored_hash
            );
            if fail_fast {
                return Err(format!(
                    "Audit log integrity violation detected at record {}. Chain is broken!",
                    id
                ));
            }
            failures.push(msg);
            current_hash = stored_bytes;
            current_id = id;
            continue;
        }

        // Stage 2: Verify Payload Binding (if ephemeral log still exists)
        match (encrypted_data, nonce) {
            (Some(data), Some(n)) => {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                hasher.update(&n);
                let actual_payload_hash = hasher.finalize();
                if actual_payload_hash[..] != payload_hash[..] {
                    let msg = format!("PAYLOAD TAMPER DETECTED at Log ID {}!", id);
                    if fail_fast {
                        return Err(format!(
                            "Audit payload mismatch at record {}. Raw log has been tampered with!",
                            id
                        ));
                    }
                    failures.push(msg);
                } else {
                    verified_count += 1;
                }
            }
            (None, None) => {
                archived_count += 1;
            }
            _ => {
                let msg = format!(
                    "PAYLOAD TAMPER DETECTED at Log ID {}! Corrupted partial ephemeral binding.",
                    id
                );
                if fail_fast {
                    return Err(msg);
                }
                failures.push(msg);
            }
        }

        current_hash = computed_hash;
        current_id = id;
    }

    if let Err(anchor_err) = check_anchor(db_path, current_id, &current_hash) {
        if fail_fast {
            return Err(anchor_err);
        }
        failures.push(format!("ANCHOR TAMPER DETECTED: {}", anchor_err));
    }

    Ok(AuditChainSummary {
        last_id: current_id,
        last_hash: current_hash,
        verified_count,
        archived_count,
        gdpr_redacted_count,
        failures,
    })
}

/// Atomically persists the latest verified audit record ID and chain hash to `<db_path>.anchor`.
pub fn update_anchor(db_path: &str, last_id: i64, last_hash: &[u8]) -> Result<(), SovereignError> {
    if db_path == ":memory:" || db_path == "file::memory:" || db_path.contains(":memory:") {
        return Ok(());
    }
    let anchor_path = format!("{}.anchor", db_path);
    let tmp_path = format!("{}.tmp.{}", anchor_path, std::process::id());
    let content = format!("{}:{}", last_id, hex::encode(last_hash));
    std::fs::write(&tmp_path, content)
        .map_err(|e| SovereignError::StorageError(format!("Anchor write failure: {}", e)))?;
    std::fs::rename(&tmp_path, &anchor_path)
        .map_err(|e| SovereignError::StorageError(format!("Anchor rename failure: {}", e)))?;
    Ok(())
}

/// Verifies the SQLite chain tail against the external `.anchor` file to catch truncation attacks.
pub fn check_anchor(
    db_path: &str,
    current_last_id: i64,
    current_last_hash: &[u8],
) -> Result<(), String> {
    if db_path == ":memory:" || db_path == "file::memory:" || db_path.contains(":memory:") {
        return Ok(());
    }
    let anchor_path = format!("{}.anchor", db_path);
    match std::fs::read_to_string(&anchor_path) {
        Ok(content) => {
            let parts: Vec<&str> = content.split(':').collect();
            if parts.len() == 2 {
                let expected_id: i64 = parts[0].parse().unwrap_or(0);
                let expected_hash = parts[1];
                if current_last_id < expected_id {
                    return Err(format!(
                        "Audit DB Truncation Detected! Expected last ID >= {}, but found {}",
                        expected_id, current_last_id
                    ));
                }
                if current_last_id > 0
                    && current_last_id == expected_id
                    && hex::encode(current_last_hash) != expected_hash
                {
                    return Err(
                        "Audit DB Integrity Mismatch! Last record does not match stored anchor hash."
                            .into(),
                    );
                }
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if current_last_id > 0 {
                return Err(
                    "Audit DB Anchor missing but database contains records! Potential tampering."
                        .into(),
                );
            }
            Ok(())
        }
        Err(e) => Err(format!("Failed to read anchor file: {}", e)),
    }
}
