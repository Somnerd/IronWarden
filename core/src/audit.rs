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

/// Current audit ledger schema version stored in SQLite `PRAGMA user_version`.
pub const AUDIT_SCHEMA_VERSION: i64 = 1;

/// Reads SQLite `PRAGMA user_version` for the audit database.
pub fn get_audit_schema_version(conn: &Connection) -> Result<i64, String> {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| format!("Failed to read audit schema user_version: {}", e))
}

/// Sets SQLite `PRAGMA user_version` for the audit database.
pub fn set_audit_schema_version(conn: &Connection, version: i64) -> Result<(), String> {
    conn.execute_batch(&format!("PRAGMA user_version = {};", version))
        .map_err(|e| format!("Failed to update audit schema user_version: {}", e))
}

/// Candidate legacy pre-v1.3 GDPR `[REDACTED]` record without a `GDPR_HMAC:` tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyGdprRow {
    pub id: i64,
    pub timestamp: String,
    pub is_blocked: bool,
    pub redactions_json: String,
}

/// Snapshot of `.anchor` read before SQLite queries to prevent TOCTOU races against live writers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorSnapshot {
    Missing,
    Parsed {
        expected_id: i64,
        hash_result: Result<[u8; 32], String>,
    },
}

/// Returns `true` if `username` is reserved for GDPR-redacted audit tombstones.
pub fn is_reserved_gdpr_username(username: &str) -> bool {
    let trimmed = username.trim();
    trimmed == "[REDACTED]" || trimmed.starts_with("GDPR_")
}

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
    allow_legacy_hint: bool,
) -> Result<(), String> {
    let tag_hex = match payload_hash.strip_prefix(GDPR_TOMBSTONE_PREFIX) {
        Some(h) => h,
        None => {
            if allow_legacy_hint
                && payload_hash.len() == 64
                && hex::decode(payload_hash).is_ok_and(|b| b.len() == 32)
            {
                return Err(
                    "Legacy pre-v1.3 GDPR [REDACTED] record without GDPR_HMAC tag; run 'iw-cli migrate-gdpr --db <path> --confirm' to upgrade tombstones"
                        .to_string(),
                );
            }
            return Err(
                "Missing GDPR_HMAC tombstone tag (forged or tampered GDPR record)".to_string(),
            );
        }
    };
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
    // Read `.anchor` BEFORE taking the SQLite read snapshot so concurrent writers advancing
    // both SQLite and `.anchor` never look like a newer `.anchor` against a stale DB read.
    let anchor_snap_res = read_anchor_snapshot(db_path);
    let expected_anchor_id = match &anchor_snap_res {
        Ok(Some(AnchorSnapshot::Parsed { expected_id, .. })) => Some(*expected_id),
        _ => None,
    };

    let schema_version = get_audit_schema_version(conn)?;
    let has_v13_tombstones: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM audit_reports WHERE payload_hash LIKE 'GDPR_HMAC:%')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| format!("Failed checking GDPR tombstone version markers: {}", e))?;
    let allow_legacy_hint = schema_version == 0 && !has_v13_tombstones;

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
    let mut historical_anchor_hash: Option<Vec<u8>> = None;

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
            Ok(b) if b.len() == 32 => {
                if Some(id) == expected_anchor_id {
                    historical_anchor_hash = Some(b.clone());
                }
                b
            }
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
        let is_gdpr_redacted = is_reserved_gdpr_username(&username);
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
                allow_legacy_hint,
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

    let anchor_check = match anchor_snap_res {
        Ok(snap) => match (&snap, current_id > 0, historical_anchor_hash.as_deref()) {
            (
                Some(AnchorSnapshot::Parsed {
                    expected_id,
                    hash_result: Ok(expected_bytes),
                }),
                true,
                Some(hist),
            ) if *expected_id > 0 && current_id > *expected_id => {
                if hist != expected_bytes.as_slice() {
                    Err(format!(
                        "Audit DB Integrity Mismatch! Historical anchored record ID {} does not match stored anchor hash.",
                        expected_id
                    ))
                } else {
                    Ok(())
                }
            }
            _ => verify_anchor_snapshot(
                snap.as_ref(),
                Some(conn),
                Some(genesis_hash),
                current_id,
                &current_hash,
            ),
        },
        Err(e) => Err(e),
    };
    if let Err(anchor_err) = anchor_check {
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

/// Lists legacy untagged `[REDACTED]` / `GDPR_*` rows on a pre-v1.3 (`user_version == 0`) DB
/// for operator dry-run inspection before running migration with `--confirm`.
pub fn inspect_legacy_gdpr_tombstones(conn: &Connection) -> Result<Vec<LegacyGdprRow>, String> {
    let schema_version = get_audit_schema_version(conn)?;
    if schema_version >= AUDIT_SCHEMA_VERSION {
        return Err(
            "Database is already at v1.3 schema (user_version >= 1); untagged [REDACTED] records indicate tampering — refusing migration"
                .into(),
        );
    }

    let mut stmt = conn
        .prepare(
            "SELECT id, timestamp, is_blocked, redactions_json, payload_hash, username \
             FROM audit_reports ORDER BY id ASC",
        )
        .map_err(|e| format!("Failed to prepare legacy inspection query: {}", e))?;

    let mut rows = stmt
        .query([])
        .map_err(|e| format!("Failed to query audit_reports for legacy inspection: {}", e))?;

    let mut saw_v13_tombstone = false;
    let mut legacy = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|e| format!("Failed reading row during legacy inspection: {}", e))?
    {
        let id: i64 = row.get(0).map_err(|e| format!("Invalid id: {}", e))?;
        let timestamp: String = row
            .get(1)
            .map_err(|e| format!("Invalid timestamp: {}", e))?;
        let is_blocked: bool = row
            .get(2)
            .map_err(|e| format!("Invalid is_blocked: {}", e))?;
        let redactions_json: String = row
            .get(3)
            .map_err(|e| format!("Invalid redactions_json: {}", e))?;
        let payload_hash: String = row
            .get(4)
            .map_err(|e| format!("Invalid payload_hash: {}", e))?;
        let username: String = row.get(5).map_err(|e| format!("Invalid username: {}", e))?;

        if is_reserved_gdpr_username(&username) {
            if payload_hash.starts_with(GDPR_TOMBSTONE_PREFIX) {
                saw_v13_tombstone = true;
            } else {
                legacy.push(LegacyGdprRow {
                    id,
                    timestamp,
                    is_blocked,
                    redactions_json,
                });
            }
        }
    }

    if saw_v13_tombstone && !legacy.is_empty() {
        return Err(
            "Mixed-era audit database detected (both GDPR_HMAC and untagged [REDACTED] rows present) — refusing migration"
                .into(),
        );
    }

    Ok(legacy)
}

/// Upgrades legacy pre-v1.3 `[REDACTED]` / `GDPR_*` rows (which kept a raw 64-char hex
/// `payload_hash` and no `GDPR_HMAC:` tag) inside an atomic transaction after verifying every
/// intact record and anchor in the chain.
pub fn migrate_legacy_gdpr_tombstones(
    conn: &Connection,
    db_path: &str,
    genesis_hash: &[u8; 32],
    hmac_key: &[u8; 32],
) -> Result<usize, String> {
    conn.execute("BEGIN IMMEDIATE TRANSACTION", [])
        .map_err(|e| format!("Failed to begin GDPR tombstone migration: {}", e))?;

    let migration_result: Result<usize, String> = (|| {
        let schema_version = get_audit_schema_version(conn)?;
        if schema_version >= AUDIT_SCHEMA_VERSION {
            return Err(
                "Database is already at v1.3 schema (user_version >= 1); untagged [REDACTED] records indicate tampering — refusing migration"
                    .into(),
            );
        }
        let anchor_snap = read_anchor_snapshot(db_path)?;
        let mut pending_updates: Vec<(i64, String)> = Vec::new();
        let mut saw_v13_tombstone = false;

        {
            let mut stmt = conn
                .prepare(
                    "SELECT ar.id, ar.timestamp, ar.is_blocked, ar.redactions_json, ar.payload_hash, ar.integrity_hash, erl.encrypted_data, erl.nonce, ar.username \
                     FROM audit_reports ar \
                     LEFT JOIN ephemeral_raw_logs erl ON ar.id = erl.id \
                     ORDER BY ar.id ASC",
                )
                .map_err(|e| format!("Failed to prepare migration query: {}", e))?;

            let mut rows = stmt
                .query([])
                .map_err(|e| format!("Failed to execute migration query: {}", e))?;

            let mut current_hash = genesis_hash.to_vec();
            let mut current_id = 0i64;

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
                    return Err(format!(
                        "Audit sequence break detected at Log ID {}! Expected ID {}.",
                        id,
                        current_id + 1
                    ));
                }

                let stored_bytes = match hex::decode(&stored_hash) {
                    Ok(b) if b.len() == 32 => b,
                    _ => {
                        return Err(format!(
                            "AUDIT CORRUPTION: Invalid integrity_hash at Log ID {}",
                            id
                        ))
                    }
                };

                let redactions_vec: Vec<Redaction> =
                    serde_json::from_str(&redactions).map_err(|e| {
                        format!(
                            "AUDIT CORRUPTION: Invalid redactions_json at Log ID {}: {}",
                            id, e
                        )
                    })?;
                let redactions_bin = bincode::serialize(&redactions_vec).map_err(|e| {
                    format!(
                        "AUDIT CORRUPTION: Failed redactions serialization at Log ID {}: {}",
                        id, e
                    )
                })?;

                if is_reserved_gdpr_username(&username) {
                    if encrypted_data.is_some() || nonce.is_some() {
                        return Err(format!(
                            "GDPR SHREDDING VIOLATION at Log ID {}! Redacted record retains unshredded ephemeral payload.",
                            id
                        ));
                    }
                    if payload_hash_str.starts_with(GDPR_TOMBSTONE_PREFIX) {
                        saw_v13_tombstone = true;
                        verify_gdpr_tombstone_mac(
                            hmac_key,
                            &current_hash,
                            id,
                            &ts,
                            blocked,
                            &redactions_bin,
                            &stored_bytes,
                            &payload_hash_str,
                            false,
                        )?;
                    } else {
                        let legacy_ph = hex::decode(payload_hash_str.trim())
                            .map_err(|_| format!("Invalid legacy payload_hash at Log ID {}", id))?;
                        if legacy_ph.len() != 32 {
                            return Err(format!(
                                "Invalid legacy payload_hash length at Log ID {}",
                                id
                            ));
                        }
                        let tombstone = compute_gdpr_tombstone_mac(
                            hmac_key,
                            &current_hash,
                            id,
                            &ts,
                            blocked,
                            &redactions_bin,
                            &stored_bytes,
                        )?;
                        pending_updates.push((id, tombstone));
                    }
                    if saw_v13_tombstone && !pending_updates.is_empty() {
                        return Err(
                            "Mixed-era audit database detected (both GDPR_HMAC and untagged [REDACTED] rows present) — refusing migration"
                                .into(),
                        );
                    }
                    current_hash = stored_bytes;
                    current_id = id;
                    continue;
                }

                let payload_hash = match hex::decode(&payload_hash_str) {
                    Ok(b) if b.len() == 32 => b,
                    _ => {
                        return Err(format!(
                            "AUDIT CORRUPTION: Invalid payload_hash at Log ID {}",
                            id
                        ))
                    }
                };

                let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
                    .map_err(|_| "HMAC key initialization failure".to_string())?;
                mac.update(&current_hash);
                mac.update(ts.as_bytes());
                mac.update(username.as_bytes());
                mac.update(&[blocked as u8]);
                mac.update(&redactions_bin);
                mac.update(&payload_hash);

                if mac.verify_slice(&stored_bytes).is_err() {
                    return Err(format!(
                        "Audit log integrity violation detected at record {}. Refusing GDPR migration.",
                        id
                    ));
                }

                match (encrypted_data, nonce) {
                    (Some(data), Some(n)) => {
                        let mut hasher = Sha256::new();
                        hasher.update(&data);
                        hasher.update(&n);
                        let actual_payload_hash = hasher.finalize();
                        if actual_payload_hash[..] != payload_hash[..] {
                            return Err(format!(
                                "Audit payload mismatch at record {}. Refusing GDPR migration.",
                                id
                            ));
                        }
                    }
                    (None, None) => {}
                    _ => {
                        return Err(format!(
                            "PAYLOAD TAMPER DETECTED at Log ID {}! Corrupted partial ephemeral binding.",
                            id
                        ));
                    }
                }

                current_hash = stored_bytes;
                current_id = id;
            }

            verify_anchor_snapshot(
                anchor_snap.as_ref(),
                Some(conn),
                Some(genesis_hash),
                current_id,
                &current_hash,
            )?;
        }

        let migrated_count = pending_updates.len();
        for (id, tombstone) in pending_updates {
            conn.execute(
                "UPDATE audit_reports SET payload_hash = ?1 WHERE id = ?2",
                (&tombstone, id),
            )
            .map_err(|e| {
                format!(
                    "Failed to update migrated tombstone for Log ID {}: {}",
                    id, e
                )
            })?;
        }
        set_audit_schema_version(conn, AUDIT_SCHEMA_VERSION)?;
        Ok(migrated_count)
    })();

    match migration_result {
        Ok(migrated) => {
            conn.execute("COMMIT", [])
                .map_err(|e| format!("Failed to commit GDPR tombstone migration: {}", e))?;
            Ok(migrated)
        }
        Err(e) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(e)
        }
    }
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
    #[cfg(unix)]
    if let Some(parent) = std::path::Path::new(&anchor_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Reads `<db_path>.anchor` once prior to taking an audit DB read snapshot.
pub fn read_anchor_snapshot(db_path: &str) -> Result<Option<AnchorSnapshot>, String> {
    if db_path == ":memory:" || db_path == "file::memory:" || db_path.contains(":memory:") {
        return Ok(None);
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
            let hash_result = hex::decode(parts[1].trim())
                .map_err(|_| "Audit DB Anchor file has invalid hex hash!".to_string())
                .and_then(|decoded| {
                    decoded
                        .try_into()
                        .map_err(|_| "Audit DB Anchor file has invalid hash length!".to_string())
                });
            Ok(Some(AnchorSnapshot::Parsed {
                expected_id,
                hash_result,
            }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Some(AnchorSnapshot::Missing)),
        Err(e) => Err(format!("Failed to read anchor file: {}", e)),
    }
}

/// Verifies a previously captured [`AnchorSnapshot`] against an observed DB tail state.
pub fn verify_anchor_snapshot(
    snapshot: Option<&AnchorSnapshot>,
    conn: Option<&Connection>,
    genesis_hash: Option<&[u8; 32]>,
    current_last_id: i64,
    current_last_hash: &[u8],
) -> Result<(), String> {
    let Some(snap) = snapshot else {
        return Ok(());
    };
    match snap {
        AnchorSnapshot::Missing => {
            if current_last_id > 0 {
                return Err(
                    "Audit DB Anchor missing but database contains records! Potential tampering."
                        .into(),
                );
            }
            Ok(())
        }
        AnchorSnapshot::Parsed {
            expected_id,
            hash_result,
        } => {
            let expected_id = *expected_id;
            if current_last_id < expected_id {
                return Err(format!(
                    "Audit DB Truncation Detected! Expected last ID >= {}, but found {}",
                    expected_id, current_last_id
                ));
            }
            let expected_bytes = hash_result.as_ref().map_err(Clone::clone)?;
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
                return Err(
                    "Missing SQLite connection to verify historical audit anchor record.".into(),
                );
            }
            Ok(())
        }
    }
}

/// Verifies the SQLite chain tail against the external `.anchor` file to catch truncation attacks.
pub fn check_anchor(
    db_path: &str,
    current_last_id: i64,
    current_last_hash: &[u8],
) -> Result<(), String> {
    let snap = read_anchor_snapshot(db_path)?;
    match &snap {
        Some(AnchorSnapshot::Parsed { expected_id, .. })
            if *expected_id > 0 && current_last_id > *expected_id =>
        {
            let ro_conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| {
                    format!("Failed to open Audit DB for historical anchor check: {}", e)
                })?;
            verify_anchor_snapshot(
                snap.as_ref(),
                Some(&ro_conn),
                None,
                current_last_id,
                current_last_hash,
            )
        }
        _ => verify_anchor_snapshot(
            snap.as_ref(),
            None,
            None,
            current_last_id,
            current_last_hash,
        ),
    }
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
