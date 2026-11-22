use super::AsyncAuditor;
use iw_core::SovereignError;
use rusqlite::Connection;
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

        // Ensure columns exist in case of upgrade from older versions
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

        let summary = iw_core::audit::verify_audit_chain(&conn, path, genesis_hash, hmac_key)
            .map_err(|e| {
                error!("CRITICAL INTEGRITY FAILURE: {}", e);
                rusqlite::Error::InvalidQuery
            })?;

        info!(
            "Full-Chain Integrity Walk successful. Verified {} records.",
            summary.last_id
        );

        let current_ver = iw_core::audit::get_audit_schema_version(&conn).map_err(|e| {
            error!("CRITICAL: Failed reading audit schema version: {}", e);
            rusqlite::Error::InvalidQuery
        })?;
        if current_ver < iw_core::audit::AUDIT_SCHEMA_VERSION {
            iw_core::audit::set_audit_schema_version(&conn, iw_core::audit::AUDIT_SCHEMA_VERSION)
                .map_err(|e| {
                error!("CRITICAL: Failed stamping audit schema version: {}", e);
                rusqlite::Error::InvalidQuery
            })?;
        }

        Self::update_anchor(path, summary.last_id, &summary.last_hash).map_err(|e| {
            error!("CRITICAL: Failed to initialize audit anchor: {}", e);
            rusqlite::Error::InvalidQuery
        })?;

        Ok((conn, summary.last_hash, summary.last_id))
    }

    #[doc(hidden)]
    pub fn update_anchor(
        db_path: &str,
        last_id: i64,
        last_hash: &[u8],
    ) -> Result<(), SovereignError> {
        iw_core::audit::update_anchor(db_path, last_id, last_hash)
    }

    #[doc(hidden)]
    pub fn check_anchor(
        db_path: &str,
        current_last_id: i64,
        current_last_hash: &[u8],
    ) -> Result<(), String> {
        iw_core::audit::check_anchor(db_path, current_last_id, current_last_hash)
    }
}
