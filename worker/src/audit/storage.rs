use super::{AsyncAuditor, HmacSha256};
use hmac::Mac;
use iw_core::{Redaction, SovereignError};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tracing::{error, info};

impl AsyncAuditor {
    #[doc(hidden)]
    pub fn init_db(
        path: &str,
        genesis_hash: &[u8; 32],
        hmac_key: &[u8; 32],
    ) -> rusqlite::Result<(Connection, Vec<u8>, i64)> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA secure_delete = ON;",
        )?;

        conn.execute("CREATE TABLE IF NOT EXISTS audit_reports (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, username TEXT DEFAULT 'unknown', is_blocked BOOLEAN, redactions_json TEXT, payload_hash TEXT, integrity_hash TEXT)", [])?;
        conn.execute("CREATE TABLE IF NOT EXISTS ephemeral_raw_logs (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, username TEXT DEFAULT 'unknown', encrypted_data BLOB, nonce BLOB, siem_acked BOOLEAN DEFAULT FALSE)", [])?;

        // Ensure username column exists in case of upgrade from older versions
        let _ = conn.execute(
            "ALTER TABLE audit_reports ADD COLUMN username TEXT DEFAULT 'unknown'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE ephemeral_raw_logs ADD COLUMN username TEXT DEFAULT 'unknown'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE ephemeral_raw_logs ADD COLUMN siem_acked BOOLEAN DEFAULT FALSE",
            [],
        );

        info!("Initiating Full-Chain Integrity Walk...");

        let (last_id, last_hash) = {
            let mut stmt = conn.prepare("
                SELECT ar.id, ar.timestamp, ar.is_blocked, ar.redactions_json, ar.payload_hash, ar.integrity_hash, erl.encrypted_data, erl.nonce, ar.username 
                FROM audit_reports ar 
                LEFT JOIN ephemeral_raw_logs erl ON ar.id = erl.id 
                ORDER BY ar.id ASC
            ")?;
            let mut rows = stmt.query([])?;
            let mut current_hash = genesis_hash.to_vec();
            let mut current_id = 0;

            while let Some(row) = rows.next()? {
                let id: i64 = row.get(0)?;
                let ts: String = row.get(1)?;
                let blocked: bool = row.get(2)?;
                let redactions: String = row.get(3)?;
                let payload_hash_str: String = row.get(4)?;
                let stored_hash: String = row.get(5)?;
                let encrypted_data: Option<Vec<u8>> = row.get(6)?;
                let nonce: Option<Vec<u8>> = row.get(7)?;
                let username: String = row.get(8)?;

                if id != current_id + 1 {
                    error!(
                        "CRITICAL: Audit sequence break detected! Expected ID {}, found {}.",
                        current_id + 1,
                        id
                    );
                    return Err(rusqlite::Error::InvalidQuery);
                }

                let redactions_vec: Vec<Redaction> =
                    serde_json::from_str(&redactions).unwrap_or_default();
                let redactions_bin = bincode::serialize(&redactions_vec).unwrap_or_default();
                let payload_hash =
                    hex::decode(&payload_hash_str).map_err(|_| rusqlite::Error::InvalidQuery)?;

                // Cryptographic shredding support: if username was purged/redacted under GDPR,
                // the raw identity is deleted but the proof-of-history hash chain remains unbroken.
                if username == "[REDACTED]" || username.starts_with("GDPR_") {
                    let stored_bytes =
                        hex::decode(&stored_hash).map_err(|_| rusqlite::Error::InvalidQuery)?;
                    current_hash = stored_bytes;
                    current_id = id;
                    continue;
                }

                // Stage 1: Verify HMAC Chain (Metadata + Username + Payload Hash)
                let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                mac.update(&current_hash);
                mac.update(ts.as_bytes());
                mac.update(username.as_bytes());
                mac.update(&[blocked as u8]);
                mac.update(&redactions_bin);
                mac.update(&payload_hash);

                let computed_hash = mac.finalize().into_bytes().to_vec();

                if hex::encode(&computed_hash) != stored_hash {
                    error!("CRITICAL: Audit log integrity violation detected at record {}. Chain is broken!", id);
                    return Err(rusqlite::Error::InvalidQuery);
                }

                // Stage 2: Verify Payload Binding (if ephemeral log still exists)
                if let (Some(data), Some(n)) = (encrypted_data, nonce) {
                    let mut hasher = Sha256::new();
                    hasher.update(&data);
                    hasher.update(&n);
                    let actual_payload_hash = hasher.finalize();
                    if actual_payload_hash[..] != payload_hash[..] {
                        error!("CRITICAL: Audit payload mismatch at record {}. Raw log has been tampered with!", id);
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                }

                current_hash = computed_hash;
                current_id = id;
            }
            (current_id, current_hash)
        };
        info!(
            "Full-Chain Integrity Walk successful. Verified {} records.",
            last_id
        );

        if let Err(e) = Self::check_anchor(path, last_id, &last_hash) {
            error!(
                "CRITICAL INTEGRITY FAILURE: {}. Potential audit tampering or truncation detected!",
                e
            );
            return Err(rusqlite::Error::InvalidQuery);
        }

        let _ = Self::update_anchor(path, last_id, &last_hash);

        Ok((conn, last_hash, last_id))
    }

    #[doc(hidden)]
    pub fn update_anchor(
        db_path: &str,
        last_id: i64,
        last_hash: &[u8],
    ) -> Result<(), SovereignError> {
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

    #[doc(hidden)]
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
                        return Err("Audit DB Integrity Mismatch! Last record does not match stored anchor hash.".into());
                    }
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if current_last_id > 0 {
                    return Err("Audit DB Anchor missing but database contains records! Potential tampering.".into());
                }
                Ok(())
            }
            Err(e) => Err(format!("Failed to read anchor file: {}", e)),
        }
    }
}
