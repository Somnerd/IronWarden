use iw_core::{ScrubbingReport, SovereignError};
use rusqlite::{Connection, OptionalExtension, ErrorCode};
use tokio::sync::mpsc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hkdf::Hkdf;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use rand::RngCore;
use tracing::{info, error, warn};
use chrono::{Utc, Duration};
use zeroize::Zeroize;
use secrecy::{SecretVec, ExposeSecret};
use iw_core::{Redaction, KDF_SALT_ENCRYPTION, KDF_SALT_INTEGRITY, KDF_SALT_GENESIS};

type HmacSha256 = Hmac<Sha256>;

pub enum AuditMessage {
    LogReport(ScrubbingReport, String, tokio::sync::oneshot::Sender<Result<(), SovereignError>>), // report, raw_input, ack
    Purge,
    Shutdown,
}

#[derive(Clone)]
pub struct AsyncAuditor {
    sender: mpsc::Sender<AuditMessage>,
}

impl AsyncAuditor {
    pub async fn spawn(db_path: &str, pepper: SecretVec<u8>) -> Result<Self, SovereignError> {
        let (tx, mut rx) = mpsc::channel(4096);
        let path = db_path.to_string();
        
        let hk = Hkdf::<Sha256>::new(None, pepper.expose_secret());
        
        let mut encryption_key_bytes = [0u8; 32];
        hk.expand(KDF_SALT_ENCRYPTION, &mut encryption_key_bytes)
            .map_err(|e| SovereignError::InternalError(format!("KDF Expansion Failure: {}", e)))?;
        
        let encryption_key = Key::<Aes256Gcm>::from_slice(&encryption_key_bytes);
        let cipher = Aes256Gcm::new(encryption_key);

        let mut hmac_key_bytes = [0u8; 32];
        hk.expand(KDF_SALT_INTEGRITY, &mut hmac_key_bytes)
            .map_err(|e| SovereignError::InternalError(format!("KDF Expansion Failure: {}", e)))?;
        
        let mut genesis_hash = [0u8; 32];
        hk.expand(KDF_SALT_GENESIS, &mut genesis_hash)
            .map_err(|e| SovereignError::InternalError(format!("KDF Expansion Failure: {}", e)))?;
        
        encryption_key_bytes.zeroize();

        let (init_tx, init_rx) = tokio::sync::oneshot::channel();

        std::thread::spawn(move || {
            info!("Warden Audit Worker (Dedicated Writer Thread) ignited.");
            
            let mut conn: Option<Connection> = None;
            let mut last_hash: Vec<u8> = vec![0u8; 32];

            match Self::init_db(&path, &genesis_hash, &hmac_key_bytes) {
                Ok((c, hash)) => {
                    conn = Some(c);
                    last_hash = hash;
                    info!("Audit database anchored and verified.");
                    let _ = init_tx.send(Ok(()));
                }
                Err(e) => {
                    error!("Audit DB anchoring failure: {}. Aborting startup.", e);
                    let _ = init_tx.send(Err(format!("DB Init Failed: {}", e)));
                    return; // Terminate thread
                }
            }

            while let Some(msg) = rx.blocking_recv() {
                match msg {
                    AuditMessage::LogReport(report, mut raw_input, ack_tx) => {
                        let mut result = Err(SovereignError::InternalError("Auditor not initialized or connection lost".to_string()));
                        if let Some(ref c) = conn {
                            let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            let redactions_json = serde_json::to_string(&report.redactions).unwrap_or_default();
                            let redactions_bin = bincode::serialize(&report.redactions).unwrap_or_default();

                            let mut nonce_bytes = [0u8; 12];
                            rand::thread_rng().fill_bytes(&mut nonce_bytes);
                            let nonce = Nonce::from_slice(&nonce_bytes);

                            let mut mac = match <HmacSha256 as Mac>::new_from_slice(&hmac_key_bytes) {
                                Ok(m) => m,
                                Err(e) => {
                                    let _ = ack_tx.send(Err(SovereignError::InternalError(format!("HMAC Key Failure: {}", e))));
                                    raw_input.zeroize();
                                    nonce_bytes.zeroize();
                                    continue;
                                }
                            };
                            mac.update(&last_hash);
                            mac.update(timestamp.as_bytes());
                            mac.update(&[report.is_blocked as u8]);
                            mac.update(&redactions_bin);
                            let current_hash = mac.finalize().into_bytes().to_vec();

                            let payload = aes_gcm::aead::Payload {
                                msg: raw_input.as_bytes(),
                                aad: &current_hash,
                            };
                            if let Ok(ciphertext) = cipher.encrypt(nonce, payload) {

                                // Fail-Closed: Write to DB, rollback on any error and report to caller
                                let mut write_success = false;
                                
                                let map_err = |e: rusqlite::Error| {
                                    if matches!(e, rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::DatabaseBusy) {
                                        SovereignError::DatabaseBusy("Audit DB busy (timeout)".into())
                                    } else {
                                        SovereignError::StorageError(format!("Audit DB Error: {}", e))
                                    }
                                };

                                let tx_res = c.execute("BEGIN IMMEDIATE TRANSACTION", []);
                                if let Err(e) = tx_res {
                                    result = Err(map_err(e));
                                } else {
                                    let res = c.execute("INSERT INTO ephemeral_raw_logs (encrypted_data, nonce) VALUES (?1, ?2)", (&ciphertext, &nonce_bytes.to_vec()));
                                    if let Err(e) = res {
                                        let _ = c.execute("ROLLBACK", []);
                                        result = Err(map_err(e));
                                    } else {
                                        let res2 = c.execute(
                                            "INSERT INTO audit_reports (timestamp, is_blocked, redactions_json, integrity_hash) VALUES (?1, ?2, ?3, ?4)", 
                                            (&timestamp, report.is_blocked, &redactions_json, hex::encode(&current_hash))
                                        );
                                        if let Err(e) = res2 {
                                            let _ = c.execute("ROLLBACK", []);
                                            result = Err(map_err(e));
                                        } else {
                                            let commit_res = c.execute("COMMIT", []);
                                            if let Err(e) = commit_res {
                                                let _ = c.execute("ROLLBACK", []);
                                                result = Err(map_err(e));
                                            } else {
                                                last_hash = current_hash;
                                                result = Ok(());
                                                write_success = true;
                                            }
                                        }
                                    }
                                }
                                
                                if !write_success {
                                    error!("Audit log failed to persist: {:?}. Sending fail-closed signal.", result);
                                }
                            } else {
                                result = Err(SovereignError::InternalError("Encryption failed".to_string()));
                            }
                            nonce_bytes.zeroize();
                        }
                        let _ = ack_tx.send(result);
                        raw_input.zeroize();
                    }
                    AuditMessage::Purge => {
                        if let Some(ref c) = conn {
                            let cutoff = Utc::now() - Duration::days(30);
                            let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();
                            let _ = c.execute("DELETE FROM ephemeral_raw_logs WHERE timestamp < ?1", [&cutoff_str]);
                        }
                    }
                    AuditMessage::Shutdown => {
                        let mut h = hmac_key_bytes;
                        h.zeroize();
                        break;
                    }
                }
            }
        });

        // Wait for DB initialization to succeed before returning
        init_rx.await
            .map_err(|_| SovereignError::InternalError("Audit worker thread died during init".into()))?
            .map_err(|e| SovereignError::InternalError(e))?;

        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if let Err(_) = tx_clone.send(AuditMessage::Purge).await { break; }
            }
        });

        Ok(Self { sender: tx })
    }

    fn init_db(path: &str, genesis_hash: &[u8; 32], hmac_key: &[u8; 32]) -> rusqlite::Result<(Connection, Vec<u8>)> {
        let conn = Connection::open(path)?;
        // --- RESILIENCE FIX: SQLite Timeout and WAL mode to prevent deadlocks ---
        conn.busy_timeout(std::time::Duration::from_millis(2000))?;
        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
        ")?;
        
        conn.execute("CREATE TABLE IF NOT EXISTS audit_reports (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, is_blocked BOOLEAN, redactions_json TEXT, integrity_hash TEXT)", [])?;
        conn.execute("CREATE TABLE IF NOT EXISTS ephemeral_raw_logs (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, encrypted_data BLOB, nonce BLOB)", [])?;
        conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)", [])?;
        conn.execute("CREATE TABLE IF NOT EXISTS threads (id TEXT PRIMARY KEY, username TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)", [])?;
        conn.execute("CREATE TABLE IF NOT EXISTS search_jobs (id TEXT PRIMARY KEY, username TEXT, thread_id TEXT, query TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)", [])?;
        conn.execute("CREATE TABLE IF NOT EXISTS sessions (username TEXT PRIMARY KEY, session_data TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)", [])?;

        let last_entry: Option<(i64, String, bool, String, String)> = conn.query_row(
            "SELECT id, timestamp, is_blocked, redactions_json, integrity_hash FROM audit_reports ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        ).optional()?;

        if let Some((id, ts, blocked, redactions, stored_hash)) = last_entry {
            let prev_hash: Vec<u8> = if id > 1 {
                conn.query_row(
                    "SELECT integrity_hash FROM audit_reports WHERE id < ?1 ORDER BY id DESC LIMIT 1",
                    [id],
                    |row| {
                        let h: String = row.get(0)?;
                        Ok(hex::decode(h).unwrap_or_default())
                    }
                )?
            } else {
                genesis_hash.to_vec()
            };

            let redactions_vec: Vec<Redaction> = serde_json::from_str(&redactions).unwrap_or_default();
            let redactions_bin = bincode::serialize(&redactions_vec).unwrap_or_default();

            let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key).map_err(|_| rusqlite::Error::InvalidQuery)?;
            mac.update(&prev_hash);
            mac.update(ts.as_bytes());
            mac.update(&[blocked as u8]);
            mac.update(&redactions_bin);
            let computed_hash = mac.finalize().into_bytes().to_vec();

            if hex::encode(&computed_hash) != stored_hash {
                error!("CRITICAL: Audit log integrity violation detected at record {}. Chain is broken!", id);
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok((conn, computed_hash))
        } else {
            Ok((conn, genesis_hash.to_vec()))
        }
    }

    pub async fn log_report(&self, report: ScrubbingReport, raw_input: String) -> Result<(), SovereignError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.sender.send(AuditMessage::LogReport(report, raw_input, tx)).await
            .map_err(|e| SovereignError::InternalError(format!("Audit channel failure: {}", e)))?;
        
        rx.await
            .map_err(|e| SovereignError::InternalError(format!("Audit ack failure: {}", e)))?
    }
}
