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
const AUDIT_CHAIN_SQL: &str = "SELECT ar.id, ar.timestamp, ar.is_blocked, ar.redactions_json, ar.payload_hash, ar.integrity_hash, erl.encrypted_data, erl.nonce, ar.username FROM audit_reports ar LEFT JOIN ephemeral_raw_logs erl ON ar.id = erl.id ORDER BY ar.id ASC";
const ALREADY_V13_ERR: &str = "Database is already at v1.3 schema (user_version >= 1); untagged [REDACTED] records indicate tampering — refusing migration";
const MIXED_ERA_ERR: &str = "Mixed-era audit database detected (both GDPR_HMAC and untagged [REDACTED] rows present) — refusing migration";

/// Current audit ledger schema version stored in SQLite `PRAGMA user_version`.
pub const AUDIT_SCHEMA_VERSION: i64 = 1;

/// Reads SQLite `PRAGMA user_version` for the audit database.
pub fn get_audit_schema_version(conn: &Connection) -> Result<i64, String> {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| format!("Failed to read audit schema user_version: {e}"))
}

/// Sets SQLite `PRAGMA user_version` for the audit database.
pub fn set_audit_schema_version(conn: &Connection, version: i64) -> Result<(), String> {
    conn.execute_batch(&format!("PRAGMA user_version = {version};"))
        .map_err(|e| format!("Failed to update audit schema user_version: {e}"))
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

/// Borrowed record fields bound into the Stage-1 audit chain HMAC.
pub struct AuditRowMac<'a> {
    pub ts: &'a str,
    pub username: &'a str,
    pub is_blocked: bool,
    pub redactions_bin: &'a [u8],
    pub payload_hash: &'a [u8],
}

/// Returns `true` if `username` is reserved for GDPR-redacted audit tombstones.
pub fn is_reserved_gdpr_username(username: &str) -> bool {
    let trimmed = username.trim();
    trimmed == "[REDACTED]" || trimmed.starts_with("GDPR_")
}

fn init_row_hmac(
    hmac_key: &[u8],
    prev_hash: &[u8],
    row: &AuditRowMac<'_>,
) -> Result<HmacSha256, String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .map_err(|_| "HMAC key initialization failure".to_string())?;
    mac.update(prev_hash);
    mac.update(row.ts.as_bytes());
    mac.update(row.username.as_bytes());
    mac.update(&[u8::from(row.is_blocked)]);
    mac.update(row.redactions_bin);
    mac.update(row.payload_hash);
    Ok(mac)
}

/// Computes the Stage-1 audit chain HMAC for a live record.
pub fn compute_row_hmac(
    hmac_key: &[u8],
    prev_hash: &[u8],
    row: &AuditRowMac<'_>,
) -> Result<[u8; 32], String> {
    Ok(init_row_hmac(hmac_key, prev_hash, row)?
        .finalize()
        .into_bytes()
        .into())
}

/// Verifies a stored Stage-1 `integrity_hash` in constant time.
pub fn verify_row_hmac(
    hmac_key: &[u8],
    prev_hash: &[u8],
    row: &AuditRowMac<'_>,
    stored_hash: &[u8],
) -> Result<(), String> {
    init_row_hmac(hmac_key, prev_hash, row)?
        .verify_slice(stored_hash)
        .map_err(|_| "HMAC verification failed".to_string())
}

fn init_tombstone_mac(
    hmac_key: &[u8],
    prev_hash: &[u8],
    id: i64,
    ts: &str,
    is_blocked: bool,
    redactions_bin: &[u8],
    integrity_hash: &[u8],
) -> Result<HmacSha256, String> {
    if prev_hash.len() != 32 {
        return Err("Invalid predecessor hash length for GDPR tombstone".to_string());
    }
    if integrity_hash.len() != 32 {
        return Err("Invalid integrity hash length for GDPR tombstone".to_string());
    }
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .map_err(|_| "HMAC key initialization failure".to_string())?;
    mac.update(GDPR_TOMBSTONE_DOMAIN);
    mac.update(prev_hash);
    mac.update(&id.to_le_bytes());
    mac.update(&(ts.len() as u64).to_le_bytes());
    mac.update(ts.as_bytes());
    mac.update(&[u8::from(is_blocked)]);
    mac.update(&(redactions_bin.len() as u64).to_le_bytes());
    mac.update(redactions_bin);
    mac.update(integrity_hash);
    Ok(mac)
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
    let mac = init_tombstone_mac(
        hmac_key,
        prev_hash,
        id,
        ts,
        is_blocked,
        redactions_bin,
        integrity_hash,
    )?;
    Ok(format!(
        "{GDPR_TOMBSTONE_PREFIX}{}",
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
    let Some(tag_hex) = payload_hash.strip_prefix(GDPR_TOMBSTONE_PREFIX) else {
        if allow_legacy_hint
            && payload_hash.len() == 64
            && hex::decode(payload_hash).is_ok_and(|b| b.len() == 32)
        {
            return Err("Legacy pre-v1.3 GDPR [REDACTED] record without GDPR_HMAC tag; run 'iw-cli migrate-gdpr --db <path> --confirm' to upgrade tombstones".into());
        }
        return Err("Missing GDPR_HMAC tombstone tag (forged or tampered GDPR record)".into());
    };
    let tag_bytes = decode_hex32(tag_hex, "GDPR tombstone tag", None)?;
    init_tombstone_mac(
        hmac_key,
        prev_hash,
        id,
        ts,
        is_blocked,
        redactions_bin,
        integrity_hash,
    )?
    .verify_slice(&tag_bytes)
    .map_err(|_| "GDPR tombstone HMAC verification failed".into())
}

struct AuditRow {
    id: i64,
    ts: String,
    blocked: bool,
    redactions: String,
    payload_hash: String,
    stored_hash: String,
    encrypted_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    username: String,
}

impl AuditRow {
    fn from_sql(row: &rusqlite::Row<'_>) -> Result<Self, String> {
        Ok(Self {
            id: row.get(0).map_err(|e| format!("Invalid audit id: {e}"))?,
            ts: row
                .get(1)
                .map_err(|e| format!("Invalid audit timestamp: {e}"))?,
            blocked: row
                .get(2)
                .map_err(|e| format!("Invalid audit is_blocked: {e}"))?,
            redactions: row
                .get(3)
                .map_err(|e| format!("Invalid audit redactions_json: {e}"))?,
            payload_hash: row
                .get(4)
                .map_err(|e| format!("Invalid audit payload_hash: {e}"))?,
            stored_hash: row
                .get(5)
                .map_err(|e| format!("Invalid audit integrity_hash: {e}"))?,
            encrypted_data: row
                .get(6)
                .map_err(|e| format!("Invalid ephemeral encrypted_data: {e}"))?,
            nonce: row
                .get(7)
                .map_err(|e| format!("Invalid ephemeral nonce: {e}"))?,
            username: row
                .get(8)
                .map_err(|e| format!("Invalid audit username: {e}"))?,
        })
    }
}

fn decode_hex32(hex_str: &str, label: &str, id: Option<i64>) -> Result<Vec<u8>, String> {
    match hex::decode(hex_str.trim()) {
        Ok(b) if b.len() == 32 => Ok(b),
        _ => Err(match id {
            Some(row_id) => format!("AUDIT CORRUPTION: Invalid {label} at Log ID {row_id}"),
            None => format!("Invalid {label}"),
        }),
    }
}

fn serialize_redactions(json: &str, id: i64) -> Result<Vec<u8>, String> {
    let vec: Vec<Redaction> = serde_json::from_str(json)
        .map_err(|e| format!("AUDIT CORRUPTION: Invalid redactions_json at Log ID {id}: {e}"))?;
    bincode::serialize(&vec).map_err(|e| {
        format!("AUDIT CORRUPTION: Failed redactions serialization at Log ID {id}: {e}")
    })
}

enum WalkMode<'a> {
    Verify {
        fail_fast: bool,
        allow_legacy_hint: bool,
        expected_anchor_id: Option<i64>,
        historical_anchor_hash: &'a mut Option<Vec<u8>>,
    },
    Migrate {
        pending_updates: &'a mut Vec<(i64, String)>,
        saw_v13_tombstone: &'a mut bool,
    },
}

fn process_gdpr_row(
    row: &AuditRow,
    prev_hash: &[u8],
    redactions_bin: &[u8],
    stored_bytes: &[u8],
    hmac_key: &[u8; 32],
    mode: &mut WalkMode<'_>,
) -> Result<(), String> {
    match mode {
        WalkMode::Verify {
            allow_legacy_hint, ..
        } => verify_gdpr_tombstone_mac(
            hmac_key,
            prev_hash,
            row.id,
            &row.ts,
            row.blocked,
            redactions_bin,
            stored_bytes,
            &row.payload_hash,
            *allow_legacy_hint,
        )
        .map_err(|e| {
            format!(
                "Record ID {}: Forged or unverified GDPR tombstone MAC ({e})",
                row.id
            )
        }),
        WalkMode::Migrate {
            pending_updates,
            saw_v13_tombstone,
        } => {
            if row.payload_hash.starts_with(GDPR_TOMBSTONE_PREFIX) {
                **saw_v13_tombstone = true;
                verify_gdpr_tombstone_mac(
                    hmac_key,
                    prev_hash,
                    row.id,
                    &row.ts,
                    row.blocked,
                    redactions_bin,
                    stored_bytes,
                    &row.payload_hash,
                    false,
                )?;
            } else {
                decode_hex32(&row.payload_hash, "legacy payload_hash", Some(row.id))?;
                let tombstone = compute_gdpr_tombstone_mac(
                    hmac_key,
                    prev_hash,
                    row.id,
                    &row.ts,
                    row.blocked,
                    redactions_bin,
                    stored_bytes,
                )?;
                pending_updates.push((row.id, tombstone));
            }
            if **saw_v13_tombstone && !pending_updates.is_empty() {
                return Err(MIXED_ERA_ERR.into());
            }
            Ok(())
        }
    }
}

fn walk_audit_chain(
    conn: &Connection,
    genesis_hash: &[u8; 32],
    hmac_key: &[u8; 32],
    mut mode: WalkMode<'_>,
) -> Result<AuditChainSummary, String> {
    let mut stmt = conn
        .prepare(AUDIT_CHAIN_SQL)
        .map_err(|e| format!("Failed to prepare audit chain query: {e}"))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| format!("Failed to execute audit chain query: {e}"))?;

    let is_diagnostic = matches!(
        mode,
        WalkMode::Verify {
            fail_fast: false,
            ..
        }
    );
    let is_migrate = matches!(mode, WalkMode::Migrate { .. });
    let mut current_hash = genesis_hash.to_vec();
    let mut current_id = 0i64;
    let (mut verified_count, mut archived_count, mut gdpr_redacted_count) = (0, 0, 0);
    let mut failures = Vec::new();

    macro_rules! record_or_err {
        ($msg:expr, $next_hash:expr, $row_id:expr) => {{
            let msg = $msg;
            if !is_diagnostic {
                return Err(msg);
            }
            failures.push(msg);
            current_hash = $next_hash;
            current_id = $row_id;
            continue;
        }};
    }

    while let Some(sql_row) = rows
        .next()
        .map_err(|e| format!("Failed reading audit chain row: {e}"))?
    {
        let row = AuditRow::from_sql(sql_row)?;
        if row.id != current_id + 1 {
            let msg = format!(
                "Audit sequence break detected at Log ID {}! Expected ID {}.",
                row.id,
                current_id + 1
            );
            if !is_diagnostic {
                return Err(msg);
            }
            failures.push(msg);
        }

        let stored_bytes = match decode_hex32(&row.stored_hash, "integrity_hash", Some(row.id)) {
            Ok(b) => {
                if let WalkMode::Verify {
                    expected_anchor_id: Some(aid),
                    historical_anchor_hash,
                    ..
                } = &mut mode
                {
                    if row.id == *aid {
                        **historical_anchor_hash = Some(b.clone());
                    }
                }
                b
            }
            Err(msg) => record_or_err!(msg, Vec::new(), row.id),
        };

        let is_gdpr = is_reserved_gdpr_username(&row.username);
        if is_gdpr && (row.encrypted_data.is_some() || row.nonce.is_some()) {
            let msg = format!(
                "GDPR SHREDDING VIOLATION at Log ID {}! Redacted record retains unshredded ephemeral payload.",
                row.id
            );
            record_or_err!(msg, stored_bytes, row.id);
        }

        let redactions_bin = match serialize_redactions(&row.redactions, row.id) {
            Ok(b) => b,
            Err(msg) => record_or_err!(msg, stored_bytes, row.id),
        };

        if is_gdpr {
            match process_gdpr_row(
                &row,
                &current_hash,
                &redactions_bin,
                &stored_bytes,
                hmac_key,
                &mut mode,
            ) {
                Ok(()) => {
                    archived_count += 1;
                    gdpr_redacted_count += 1;
                }
                Err(msg) => record_or_err!(msg, stored_bytes, row.id),
            }
            current_hash = stored_bytes;
            current_id = row.id;
            continue;
        }

        let payload_hash = match decode_hex32(&row.payload_hash, "payload_hash", Some(row.id)) {
            Ok(b) => b,
            Err(msg) => record_or_err!(msg, stored_bytes, row.id),
        };

        let mac_fields = AuditRowMac {
            ts: &row.ts,
            username: &row.username,
            is_blocked: row.blocked,
            redactions_bin: &redactions_bin,
            payload_hash: &payload_hash,
        };
        if verify_row_hmac(hmac_key, &current_hash, &mac_fields, &stored_bytes).is_err() {
            let msg = if is_diagnostic {
                let expected = compute_row_hmac(hmac_key, &current_hash, &mac_fields)
                    .map(hex::encode)
                    .unwrap_or_default();
                format!(
                    "CHAIN TAMPER DETECTED at Log ID {}!\n   Expected Hash: {expected}\n   Stored Hash  : {}",
                    row.id, row.stored_hash
                )
            } else if is_migrate {
                format!(
                    "Audit log integrity violation detected at record {}. Refusing GDPR migration.",
                    row.id
                )
            } else {
                format!(
                    "Audit log integrity violation detected at record {}. Chain is broken!",
                    row.id
                )
            };
            record_or_err!(msg, stored_bytes, row.id);
        }

        match (row.encrypted_data.as_deref(), row.nonce.as_deref()) {
            (Some(data), Some(n)) => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.update(n);
                if hasher.finalize()[..] == payload_hash[..] {
                    verified_count += 1;
                } else {
                    let msg = if is_diagnostic {
                        format!("PAYLOAD TAMPER DETECTED at Log ID {}!", row.id)
                    } else if is_migrate {
                        format!(
                            "Audit payload mismatch at record {}. Refusing GDPR migration.",
                            row.id
                        )
                    } else {
                        format!(
                            "Audit payload mismatch at record {}. Raw log has been tampered with!",
                            row.id
                        )
                    };
                    record_or_err!(msg, stored_bytes, row.id);
                }
            }
            (None, None) => archived_count += 1,
            _ => record_or_err!(
                format!(
                    "PAYLOAD TAMPER DETECTED at Log ID {}! Corrupted partial ephemeral binding.",
                    row.id
                ),
                stored_bytes,
                row.id
            ),
        }

        current_hash = stored_bytes;
        current_id = row.id;
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
    // Capture `.anchor` BEFORE querying SQLite so live writers never look like a newer anchor against a stale snapshot.
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
        .map_err(|e| format!("Failed checking GDPR tombstone version markers: {e}"))?;

    let mut historical_anchor_hash = None;
    let mut summary = walk_audit_chain(
        conn,
        genesis_hash,
        hmac_key,
        WalkMode::Verify {
            fail_fast,
            allow_legacy_hint: schema_version == 0 && !has_v13_tombstones,
            expected_anchor_id,
            historical_anchor_hash: &mut historical_anchor_hash,
        },
    )?;

    let anchor_check = match anchor_snap_res {
        Ok(snap) => match (
            &snap,
            summary.last_id > 0,
            historical_anchor_hash.as_deref(),
        ) {
            (
                Some(AnchorSnapshot::Parsed {
                    expected_id,
                    hash_result: Ok(expected_bytes),
                }),
                true,
                Some(hist),
            ) if *expected_id > 0 && summary.last_id > *expected_id => {
                if hist != expected_bytes.as_slice() {
                    Err(format!("Audit DB Integrity Mismatch! Historical anchored record ID {expected_id} does not match stored anchor hash."))
                } else {
                    Ok(())
                }
            }
            _ => verify_anchor_snapshot(
                snap.as_ref(),
                Some(conn),
                Some(genesis_hash),
                summary.last_id,
                &summary.last_hash,
            ),
        },
        Err(e) => Err(e),
    };
    if let Err(anchor_err) = anchor_check {
        if fail_fast {
            return Err(anchor_err);
        }
        summary
            .failures
            .push(format!("ANCHOR TAMPER DETECTED: {anchor_err}"));
    }
    Ok(summary)
}

/// Lists legacy untagged `[REDACTED]` / `GDPR_*` rows on a pre-v1.3 (`user_version == 0`) DB
/// for operator dry-run inspection before running migration with `--confirm`.
pub fn inspect_legacy_gdpr_tombstones(conn: &Connection) -> Result<Vec<LegacyGdprRow>, String> {
    if get_audit_schema_version(conn)? >= AUDIT_SCHEMA_VERSION {
        return Err(ALREADY_V13_ERR.into());
    }
    let mut stmt = conn
        .prepare("SELECT id, timestamp, is_blocked, redactions_json, payload_hash, username FROM audit_reports ORDER BY id ASC")
        .map_err(|e| format!("Failed to prepare legacy inspection query: {e}"))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| format!("Failed to query audit_reports for legacy inspection: {e}"))?;

    let (mut saw_v13_tombstone, mut legacy) = (false, Vec::new());
    while let Some(row) = rows
        .next()
        .map_err(|e| format!("Failed reading row during legacy inspection: {e}"))?
    {
        let (id, timestamp, is_blocked, redactions_json, payload_hash, username): (
            i64,
            String,
            bool,
            String,
            String,
            String,
        ) = (
            row.get(0).map_err(|e| format!("Invalid column: {e}"))?,
            row.get(1).map_err(|e| format!("Invalid column: {e}"))?,
            row.get(2).map_err(|e| format!("Invalid column: {e}"))?,
            row.get(3).map_err(|e| format!("Invalid column: {e}"))?,
            row.get(4).map_err(|e| format!("Invalid column: {e}"))?,
            row.get(5).map_err(|e| format!("Invalid column: {e}"))?,
        );
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
        return Err(MIXED_ERA_ERR.into());
    }
    Ok(legacy)
}

/// Upgrades legacy pre-v1.3 `[REDACTED]` / `GDPR_*` rows inside an atomic transaction after
/// verifying every intact record and anchor in the chain.
pub fn migrate_legacy_gdpr_tombstones(
    conn: &Connection,
    db_path: &str,
    genesis_hash: &[u8; 32],
    hmac_key: &[u8; 32],
) -> Result<usize, String> {
    conn.execute("BEGIN IMMEDIATE TRANSACTION", [])
        .map_err(|e| format!("Failed to begin GDPR tombstone migration: {e}"))?;

    let res = (|| -> Result<usize, String> {
        if get_audit_schema_version(conn)? >= AUDIT_SCHEMA_VERSION {
            return Err(ALREADY_V13_ERR.into());
        }
        let anchor_snap = read_anchor_snapshot(db_path)?;
        let (mut pending_updates, mut saw_v13_tombstone) = (Vec::new(), false);
        let summary = walk_audit_chain(
            conn,
            genesis_hash,
            hmac_key,
            WalkMode::Migrate {
                pending_updates: &mut pending_updates,
                saw_v13_tombstone: &mut saw_v13_tombstone,
            },
        )?;
        verify_anchor_snapshot(
            anchor_snap.as_ref(),
            Some(conn),
            Some(genesis_hash),
            summary.last_id,
            &summary.last_hash,
        )?;
        let count = pending_updates.len();
        for (id, tombstone) in pending_updates {
            conn.execute(
                "UPDATE audit_reports SET payload_hash = ?1 WHERE id = ?2",
                (&tombstone, id),
            )
            .map_err(|e| format!("Failed to update migrated tombstone for Log ID {id}: {e}"))?;
        }
        set_audit_schema_version(conn, AUDIT_SCHEMA_VERSION)?;
        Ok(count)
    })();

    match res {
        Ok(count) => {
            conn.execute("COMMIT", [])
                .map_err(|e| format!("Failed to commit GDPR tombstone migration: {e}"))?;
            Ok(count)
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
    let anchor_path = format!("{db_path}.anchor");
    let seq = ANCHOR_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = format!("{anchor_path}.tmp.{}.{seq}", std::process::id());
    let content = format!("{last_id}:{}", hex::encode(last_hash));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp_path)
            .map_err(|e| SovereignError::StorageError(format!("Anchor write failure: {e}")))?;
        if let Err(e) = f.write_all(content.as_bytes()).and_then(|_| f.sync_all()) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(SovereignError::StorageError(format!(
                "Anchor write failure: {e}"
            )));
        }
    }
    if let Err(e) = std::fs::rename(&tmp_path, &anchor_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(SovereignError::StorageError(format!(
            "Anchor rename failure: {e}"
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
    let anchor_path = format!("{db_path}.anchor");
    match std::fs::read_to_string(&anchor_path) {
        Ok(content) => {
            let parts: Vec<&str> = content.trim().split(':').collect();
            if parts.len() != 2 {
                return Err("Audit DB Anchor file is malformed!".into());
            }
            let expected_id: i64 = parts[0]
                .parse()
                .ok()
                .filter(|&id| id >= 0)
                .ok_or_else(|| "Audit DB Anchor file has invalid record ID!".to_string())?;
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
        Err(e) => Err(format!("Failed to read anchor file: {e}")),
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
                return Err(format!("Audit DB Truncation Detected! Expected last ID >= {expected_id}, but found {current_last_id}"));
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
                    return Err("Audit DB Integrity Mismatch! Last record does not match stored anchor hash.".into());
                }
            } else if let Some(c) = conn {
                let stored_hex: String = c
                    .query_row("SELECT integrity_hash FROM audit_reports WHERE id = ?1", [expected_id], |r| r.get(0))
                    .map_err(|_| format!("Audit DB Integrity Mismatch! Anchored record ID {expected_id} missing from database."))?;
                let stored_bytes =
                    decode_hex32(&stored_hex, "integrity_hash hex at anchor ID", None)?;
                if stored_bytes.as_slice() != expected_bytes.as_slice() {
                    return Err(format!("Audit DB Integrity Mismatch! Historical anchored record ID {expected_id} does not match stored anchor hash."));
                }
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
                .map_err(|e| format!("Failed to open Audit DB for historical anchor check: {e}"))?;
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
