use crate::error::SovereignError;
use crate::traits::Redaction;
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

type HmacSha256 = Hmac<Sha256>;

static ANCHOR_TMP_SEQ: AtomicU64 = AtomicU64::new(0);
const GDPR_TOMBSTONE_PREFIX: &str = "GDPR_HMAC:";
const GDPR_TOMBSTONE_DOMAIN: &[u8] = b"GDPR_TOMBSTONE_V1";

fn feed_gdpr_tombstone_fields(
    mac: &mut HmacSha256,
    prev_hash: &[u8],
    id: i64,
    ts: &str,
    is_blocked: bool,
    redactions_bin: &[u8],
    integrity_hash: &[u8],
) -> Result<(), String> {
    if prev_hash.len() != 32 {
        return Err("Invalid predecessor hash length for GDPR tombstone".to_string());
    }
    if integrity_hash.len() != 32 {
        return Err("Invalid integrity hash length for GDPR tombstone".to_string());
    }
    mac.update(GDPR_TOMBSTONE_DOMAIN);
    mac.update(prev_hash);
    mac.update(&id.to_le_bytes());
    mac.update(&(ts.len() as u64).to_le_bytes());
    mac.update(ts.as_bytes());
    mac.update(&[u8::from(is_blocked)]);
    mac.update(&(redactions_bin.len() as u64).to_le_bytes());
    mac.update(redactions_bin);
    mac.update(integrity_hash);
    Ok(())
}

/// Computes a keyed HMAC tombstone tag stored in `payload_hash` when a row's username is
/// shredded under GDPR, binding both row metadata and the predecessor chain hash.
pub fn compute_gdpr_tombstone_mac(
    hmac_key: &[u8],
    prev_hash: &[u8],
    id: i64,
    ts: &str,
    is_blocked: bool,
    redactions_bin: &[u8],
    integrity_hash: &[u8],
) -> Result<String, String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .map_err(|_| "HMAC key initialization failure".to_string())?;
    feed_gdpr_tombstone_fields(
        &mut mac,
        prev_hash,
        id,
        ts,
        is_blocked,
        redactions_bin,
        integrity_hash,
    )?;
    Ok(format!(
        "{}{}",
        GDPR_TOMBSTONE_PREFIX,
        hex::encode(mac.finalize().into_bytes())
    ))
}

#[allow(clippy::too_many_arguments)]
fn verify_gdpr_tombstone_mac(
    hmac_key: &[u8],
    prev_hash: &[u8],
    id: i64,
    ts: &str,
    is_blocked: bool,
    redactions_bin: &[u8],
    integrity_hash: &[u8],
    payload_hash: &str,
) -> Result<(), String> {
    let tag_hex = payload_hash
        .strip_prefix(GDPR_TOMBSTONE_PREFIX)
        .ok_or_else(|| "Missing GDPR_HMAC tombstone tag".to_string())?;
    let tag_bytes = hex::decode(tag_hex).map_err(|_| "Invalid GDPR tombstone hex".to_string())?;
    if tag_bytes.len() != 32 {
        return Err("Invalid GDPR tombstone tag length".to_string());
    }
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .map_err(|_| "HMAC key initialization failure".to_string())?;
    feed_gdpr_tombstone_fields(
        &mut mac,
        prev_hash,
        id,
        ts,
        is_blocked,
        redactions_bin,
        integrity_hash,
    )?;
    mac.verify_slice(&tag_bytes)
        .map_err(|_| "GDPR tombstone HMAC verification failed".to_string())
}

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

        let stored_bytes = match hex::decode(&stored_hash) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                let msg = format!("AUDIT CORRUPTION: Invalid integrity_hash at Log ID {}", id);
                if fail_fast {
                    return Err(msg);
                }
                failures.push(msg);
                current_hash = Vec::new();
                current_id = id;
                continue;
            }
        };

        // Cryptographic shredding support: if username was purged/redacted under GDPR,
        // ephemeral payload must be absent, and we later require a valid keyed tombstone MAC.
        let is_gdpr_redacted = username == "[REDACTED]" || username.starts_with("GDPR_");
        if is_gdpr_redacted && (encrypted_data.is_some() || nonce.is_some()) {
            let msg = format!(
                "GDPR SHREDDING VIOLATION at Log ID {}! Redacted record retains unshredded ephemeral payload.",
                id
            );
            if fail_fast {
                return Err(msg);
            }
            failures.push(msg);
            current_hash = stored_bytes;
            current_id = id;
            continue;
        }

        let redactions_vec: Vec<Redaction> = match serde_json::from_str(&redactions) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!(
                    "AUDIT CORRUPTION: Invalid redactions_json at Log ID {}: {}",
                    id, e
                );
                if fail_fast {
                    return Err(msg);
                }
                failures.push(msg);
                current_hash = stored_bytes;
                current_id = id;
                continue;
            }
        };
        let redactions_bin = match bincode::serialize(&redactions_vec) {
            Ok(b) => b,
            Err(e) => {
                let msg = format!(
                    "AUDIT CORRUPTION: Failed redactions serialization at Log ID {}: {}",
                    id, e
                );
                if fail_fast {
                    return Err(msg);
                }
                failures.push(msg);
                current_hash = stored_bytes;
                current_id = id;
                continue;
            }
        };

        if is_gdpr_redacted {
            match verify_gdpr_tombstone_mac(
                hmac_key,
                &current_hash,
                id,
                &ts,
                blocked,
                &redactions_bin,
                &stored_bytes,
                &payload_hash_str,
            ) {
                Ok(()) => {
                    archived_count += 1;
                    gdpr_redacted_count += 1;
                }
                Err(e) => {
                    let msg = format!(
                        "Record ID {}: Forged or unverified GDPR tombstone MAC ({})",
                        id, e
                    );
                    if fail_fast {
                        return Err(msg);
                    }
                    failures.push(msg);
                }
            }
            current_hash = stored_bytes;
            current_id = id;
            continue;
        }
        let payload_hash = match hex::decode(&payload_hash_str) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                let msg = format!("AUDIT CORRUPTION: Invalid payload_hash at Log ID {}", id);
                if fail_fast {
                    return Err(msg);
                }
                failures.push(msg);
                current_hash = stored_bytes;
                current_id = id;
                continue;
            }
        };

        // Stage 1: Verify HMAC Chain (Metadata + Username + Payload Hash) in constant time
        let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
            .map_err(|_| "HMAC key initialization failure".to_string())?;
        mac.update(&current_hash);
        mac.update(ts.as_bytes());
        mac.update(username.as_bytes());
        mac.update(&[blocked as u8]);
        mac.update(&redactions_bin);
        mac.update(&payload_hash);

        if mac.clone().verify_slice(&stored_bytes).is_err() {
            let computed_hex = hex::encode(mac.finalize().into_bytes());
            let msg = format!(
                "CHAIN TAMPER DETECTED at Log ID {}!\n   Expected Hash: {}\n   Stored Hash  : {}",
                id, computed_hex, stored_hash
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
        let computed_hash = stored_bytes;

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

    if let Err(anchor_err) = check_anchor_with_context(
        db_path,
        Some(conn),
        Some(genesis_hash),
        current_id,
        &current_hash,
    ) {
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
    let seq = ANCHOR_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = format!("{}.tmp.{}.{}", anchor_path, std::process::id(), seq);
    let content = format!("{}:{}", last_id, hex::encode(last_hash));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp_path)
            .map_err(|e| SovereignError::StorageError(format!("Anchor write failure: {}", e)))?;
        if let Err(e) = f.write_all(content.as_bytes()).and_then(|_| f.sync_all()) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(SovereignError::StorageError(format!(
                "Anchor write failure: {}",
                e
            )));
        }
    }
    if let Err(e) = std::fs::rename(&tmp_path, &anchor_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(SovereignError::StorageError(format!(
            "Anchor rename failure: {}",
            e
        )));
    }
    Ok(())
}

/// Verifies the SQLite chain tail against the external `.anchor` file to catch truncation attacks.
pub fn check_anchor(
    db_path: &str,
    current_last_id: i64,
    current_last_hash: &[u8],
) -> Result<(), String> {
    check_anchor_with_context(db_path, None, None, current_last_id, current_last_hash)
}

fn verify_historical_anchor_row(
    conn: &Connection,
    expected_id: i64,
    expected_bytes: &[u8],
) -> Result<(), String> {
    let stored_hex: String = conn
        .query_row(
            "SELECT integrity_hash FROM audit_reports WHERE id = ?1",
            [expected_id],
            |r| r.get(0),
        )
        .map_err(|_| {
            format!(
                "Audit DB Integrity Mismatch! Anchored record ID {} missing from database.",
                expected_id
            )
        })?;
    let stored_bytes = hex::decode(stored_hex.trim()).map_err(|_| {
        "Audit DB Integrity Mismatch! Invalid integrity_hash hex at anchor ID.".to_string()
    })?;
    if stored_bytes.as_slice() != expected_bytes {
        return Err(format!(
            "Audit DB Integrity Mismatch! Historical anchored record ID {} does not match stored anchor hash.",
            expected_id
        ));
    }
    Ok(())
}

fn check_anchor_with_context(
    db_path: &str,
    conn: Option<&Connection>,
    genesis_hash: Option<&[u8; 32]>,
    current_last_id: i64,
    current_last_hash: &[u8],
) -> Result<(), String> {
    if db_path == ":memory:" || db_path == "file::memory:" || db_path.contains(":memory:") {
        return Ok(());
    }
    let anchor_path = format!("{}.anchor", db_path);
    match std::fs::read_to_string(&anchor_path) {
        Ok(content) => {
            let trimmed = content.trim();
            let parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() != 2 {
                return Err("Audit DB Anchor file is malformed!".into());
            }
            let expected_id: i64 = parts[0]
                .parse()
                .map_err(|_| "Audit DB Anchor file has invalid record ID!".to_string())?;
            if expected_id < 0 {
                return Err("Audit DB Anchor file has invalid record ID!".to_string());
            }
            if current_last_id < expected_id {
                return Err(format!(
                    "Audit DB Truncation Detected! Expected last ID >= {}, but found {}",
                    expected_id, current_last_id
                ));
            }
            let expected_bytes = hex::decode(parts[1].trim())
                .map_err(|_| "Audit DB Anchor file has invalid hex hash!".to_string())?;
            if expected_bytes.len() != 32 {
                return Err("Audit DB Anchor file has invalid hash length!".into());
            }

            if expected_id == 0 {
                if let Some(gen) = genesis_hash {
                    if expected_bytes.as_slice() != gen.as_slice() {
                        return Err(
                            "Audit DB Integrity Mismatch! Anchor genesis hash does not match."
                                .into(),
                        );
                    }
                } else if current_last_id == 0
                    && !current_last_hash.is_empty()
                    && current_last_hash != expected_bytes.as_slice()
                {
                    return Err(
                        "Audit DB Integrity Mismatch! Empty DB anchor does not match genesis hash."
                            .into(),
                    );
                }
            } else if current_last_id == expected_id {
                if current_last_hash != expected_bytes.as_slice() {
                    return Err(
                        "Audit DB Integrity Mismatch! Last record does not match stored anchor hash."
                            .into(),
                    );
                }
            } else if let Some(c) = conn {
                verify_historical_anchor_row(c, expected_id, expected_bytes.as_slice())?;
            } else {
                let ro_conn =
                    Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                        .map_err(|e| {
                            format!("Failed to open Audit DB for historical anchor check: {}", e)
                        })?;
                verify_historical_anchor_row(&ro_conn, expected_id, expected_bytes.as_slice())?;
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
