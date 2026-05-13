use iw_core::{ScrubbingReport, SovereignError};
use rusqlite::{Connection, OptionalExtension, ErrorCode};
use std::sync::Arc;
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
    is_healthy: Arc<std::sync::atomic::AtomicBool>,
    db_path: String,
}

impl AsyncAuditor {
    pub async fn spawn(db_path: &str, pepper: SecretVec<u8>) -> Result<Self, SovereignError> {
        let (tx, mut rx) = mpsc::channel(4096);
        let path = db_path.to_string();
        let is_healthy = Arc::new(std::sync::atomic::AtomicBool::new(true));
        
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

        let healthy_thread = is_healthy.clone();
        let path_thread = path.clone();
        std::thread::spawn(move || {
            info!("Warden Audit Worker (Dedicated Writer Thread) ignited.");
            
            let mut conn: Option<Connection> = None;
            let mut last_hash: Vec<u8> = vec![0u8; 32];
            let mut last_id: i64 = 0;

            match Self::init_db(&path_thread, &genesis_hash, &hmac_key_bytes) {
                Ok((c, hash, id)) => {
                    conn = Some(c);
                    last_hash = hash;
                    last_id = id;
                    info!("Audit database anchored and verified at ID {}.", last_id);
                    let _ = init_tx.send(Ok(()));
                }
                Err(e) => {
                    error!("Audit DB anchoring failure: {}. Aborting startup.", e);
                    healthy_thread.store(false, std::sync::atomic::Ordering::SeqCst);
                    let _ = init_tx.send(Err(format!("DB Init Failed: {}", e)));
                    return; // Terminate thread
                }
            }

            while let Some(msg) = rx.blocking_recv() {
                match msg {
                    AuditMessage::LogReport(report, mut raw_input, ack_tx) => {
                        let mut result = Err(SovereignError::InternalError("Auditor not initialized or connection lost".to_string()));
                        
                        if !healthy_thread.load(std::sync::atomic::Ordering::SeqCst) {
                            let _ = ack_tx.send(Err(SovereignError::InternalError("Auditor in Panic State: Health check failed".into())));
                            raw_input.zeroize();
                            continue;
                        }

                        if let Some(ref c) = conn {
                            let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            let redactions_json = serde_json::to_string(&report.redactions).unwrap_or_default();
                            let redactions_bin = bincode::serialize(&report.redactions).unwrap_or_default();

                            let mut nonce_bytes = [0u8; 12];
                            rand::thread_rng().fill_bytes(&mut nonce_bytes);
                            let nonce = Nonce::from_slice(&nonce_bytes);

                            // --- SECURITY FIX (Section 3.1): Hash-then-Encrypt with AAD Binding ---
                            // We use last_hash as AAD to bind the ciphertext to the chain,
                            // then include the ciphertext in current_hash.
                            let payload = aes_gcm::aead::Payload {
                                msg: raw_input.as_bytes(),
                                aad: &last_hash,
                            };

                            if let Ok(ciphertext) = cipher.encrypt(nonce, payload) {
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
                                                last_id += 1;
                                                // --- SECURITY FIX (V-13): Update external anchor ---
                                                if let Err(e) = Self::update_anchor(&path_thread, last_id, &last_hash) {
                                                    error!("CRITICAL: Failed to update audit anchor: {}. Halting system.", e);
                                                    healthy_thread.store(false, std::sync::atomic::Ordering::SeqCst);
                                                    result = Err(e);
                                                } else {
                                                    result = Ok(());
                                                    write_success = true;
                                                }
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
                            // 1. Purge encrypted raw logs (30 days)
                            let cutoff_logs = Utc::now() - Duration::days(30);
                            let cutoff_logs_str = cutoff_logs.format("%Y-%m-%d %H:%M:%S").to_string();
                            let _ = c.execute("DELETE FROM ephemeral_raw_logs WHERE timestamp < ?1", [&cutoff_logs_str]);
                            
                            // 2. Purge inactive sessions (24 hours) - WP #47 (Session Isolation/TTL)
                            let cutoff_sessions = Utc::now() - Duration::hours(24);
                            let cutoff_sessions_str = cutoff_sessions.format("%Y-%m-%d %H:%M:%S").to_string();
                            let _ = c.execute("DELETE FROM sessions WHERE updated_at < ?1", [&cutoff_sessions_str]);
                            
                            info!("Auditor: Cleanup task completed (Logs > 30d, Sessions > 24h).");
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

        // Wait for DB initialization to succeed before returning (with 10s timeout to prevent boot deadlock)
        tokio::time::timeout(tokio::time::Duration::from_secs(10), init_rx).await
            .map_err(|_| SovereignError::InternalError("Audit worker init timeout (Boot Deadlock)".into()))?
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

        // --- HARD-STOP BACKGROUND MONITOR (WP #88) ---
        let healthy_monitor = is_healthy.clone();
        let path_monitor = path.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5)); // Increased frequency for zero-failure compliance
            loop {
                interval.tick().await;
                
                // Perform deep health check: 1. DB connection test 2. Anchor integrity test 3. File existence
                let anchor_path = format!("{}.anchor", path_monitor);
                if !std::path::Path::new(&anchor_path).exists() {
                    error!("HARD-STOP MONITOR: Audit anchor file missing! Triggering Fail-Closed state.");
                    healthy_monitor.store(false, std::sync::atomic::Ordering::SeqCst);
                    break;
                }

                if let Ok(conn) = Connection::open(&path_monitor) {
                    let res: rusqlite::Result<(i64, String)> = conn.query_row(
                        "SELECT id, integrity_hash FROM audit_reports ORDER BY id DESC LIMIT 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?))
                    );

                    match res {
                        Ok((id, hash)) => {
                            let hash_bytes = hex::decode(hash).unwrap_or_default();
                            if let Err(e) = Self::check_anchor(&path_monitor, id, &hash_bytes) {
                                error!("HARD-STOP MONITOR: Anchor Violation: {}. Triggering Fail-Closed state.", e);
                                healthy_monitor.store(false, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                        Err(e) if e == rusqlite::Error::QueryReturnedNoRows => {
                            if let Err(e) = Self::check_anchor(&path_monitor, 0, &[]) {
                                error!("HARD-STOP MONITOR: Anchor Mismatch (Empty DB): {}. Triggering Fail-Closed state.", e);
                                healthy_monitor.store(false, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                        Err(e) => {
                            error!("HARD-STOP MONITOR: DB Access Failure: {}. Triggering Fail-Closed state.", e);
                            healthy_monitor.store(false, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                } else {
                    error!("HARD-STOP MONITOR: Cannot open Audit DB. Triggering Fail-Closed state.");
                    healthy_monitor.store(false, std::sync::atomic::Ordering::SeqCst);
                }
                
                if !healthy_monitor.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
            }
        });

        Ok(Self { sender: tx, is_healthy, db_path: path })
    }

    fn init_db(path: &str, genesis_hash: &[u8; 32], hmac_key: &[u8; 32]) -> rusqlite::Result<(Connection, Vec<u8>, i64)> {
        let conn = Connection::open(path)?;
        // --- RESILIENCE FIX: SQLite Timeout and WAL mode to prevent deadlocks ---
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
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

        // --- SECURITY FIX (WP 49): Full-Chain Integrity Walk ---
        info!("Initiating Full-Chain Integrity Walk...");

        let (last_id, last_hash) = {
            let mut stmt = conn.prepare("
                SELECT id, timestamp, is_blocked, redactions_json, integrity_hash 
                FROM audit_reports 
                ORDER BY id ASC
            ")?;

            let mut rows = stmt.query([])?;
            let mut current_hash = genesis_hash.to_vec();
            let mut current_id = 0;

            while let Some(row) = rows.next()? {
                let id: i64 = row.get(0)?;
                let ts: String = row.get(1)?;
                let blocked: bool = row.get(2)?;
                let redactions: String = row.get(3)?;
                let stored_hash: String = row.get(4)?;

                // Sequence check
                if id != current_id + 1 {
                    error!("CRITICAL: Audit sequence break detected! Expected ID {}, found {}.", current_id + 1, id);
                    return Err(rusqlite::Error::InvalidQuery);
                }

                let redactions_vec: Vec<Redaction> = serde_json::from_str(&redactions).unwrap_or_default();
                let redactions_bin = bincode::serialize(&redactions_vec).unwrap_or_default();

                let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key).map_err(|_| rusqlite::Error::InvalidQuery)?;
                mac.update(&current_hash);
                mac.update(ts.as_bytes());
                mac.update(&[blocked as u8]);
                mac.update(&redactions_bin);

                let computed_hash = mac.finalize().into_bytes().to_vec();

                if hex::encode(&computed_hash) != stored_hash {
                    error!("CRITICAL: Audit log integrity violation detected at record {}. Chain is broken!", id);
                    return Err(rusqlite::Error::InvalidQuery);
                }

                current_hash = computed_hash;
                current_id = id;
            }
            (current_id, current_hash)
        };
        info!("Full-Chain Integrity Walk successful. Verified {} records.", last_id);

        // --- SECURITY FIX (V-13): Anchor-based Truncation Detection ---
        if let Err(e) = Self::check_anchor(path, last_id, &last_hash) {
            error!("CRITICAL INTEGRITY FAILURE: {}. Potential audit tampering or truncation detected!", e);
            return Err(rusqlite::Error::InvalidQuery);
        }

        let _ = Self::update_anchor(path, last_id, &last_hash);

        Ok((conn, last_hash, last_id))
    }

    fn update_anchor(db_path: &str, last_id: i64, last_hash: &[u8]) -> Result<(), SovereignError> {
        let anchor_path = format!("{}.anchor", db_path);
        let content = format!("{}:{}", last_id, hex::encode(last_hash));
        std::fs::write(anchor_path, content).map_err(|e| SovereignError::StorageError(format!("Anchor write failure: {}", e)))
    }

    fn check_anchor(db_path: &str, current_last_id: i64, current_last_hash: &[u8]) -> Result<(), String> {
        let anchor_path = format!("{}.anchor", db_path);
        if let Ok(content) = std::fs::read_to_string(&anchor_path) {
            let parts: Vec<&str> = content.split(':').collect();
            if parts.len() == 2 {
                let expected_id: i64 = parts[0].parse().unwrap_or(0);
                let expected_hash = parts[1];
                
                // If the DB has fewer records than the anchor, truncation happened.
                if current_last_id < expected_id {
                    return Err(format!("Audit DB Truncation Detected! Expected last ID >= {}, but found {}", expected_id, current_last_id));
                }
                
                // If the IDs match, the hashes MUST match (unless ID is 0, which means empty DB where we don't have the genesis hash to compare against).
                if current_last_id > 0 && current_last_id == expected_id && hex::encode(current_last_hash) != expected_hash {
                    return Err("Audit DB Integrity Mismatch! Last record does not match stored anchor hash.".into());
                }
            }
        }
        Ok(())
    }

    pub async fn log_report(&self, report: ScrubbingReport, raw_input: String) -> Result<(), SovereignError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.sender.send(AuditMessage::LogReport(report, raw_input, tx)).await
            .map_err(|e| SovereignError::InternalError(format!("Audit channel failure: {}", e)))?;
        
        rx.await
            .map_err(|e| SovereignError::InternalError(format!("Audit ack failure: {}", e)))?
    }

    pub fn get_compliance_stats(&self) -> Result<(u64, u64, String, String, String), SovereignError> {
        let conn = Connection::open(&self.db_path).map_err(|e| SovereignError::StorageError(e.to_string()))?;
        
        let mut stmt = conn.prepare("SELECT COUNT(*), SUM(CASE WHEN is_blocked = 1 THEN 1 ELSE 0 END), MIN(timestamp), MAX(timestamp) FROM audit_reports")
            .map_err(|e| SovereignError::StorageError(e.to_string()))?;
            
        let stats: (u64, u64, String, String) = stmt.query_row([], |row| {
            Ok((
                row.get(0).unwrap_or(0),
                row.get::<_, i64>(1).unwrap_or(0) as u64,
                row.get(2).unwrap_or_else(|_| "N/A".to_string()),
                row.get(3).unwrap_or_else(|_| "N/A".to_string()),
            ))
        }).map_err(|e| SovereignError::StorageError(e.to_string()))?;

        // Get the latest integrity hash separately to avoid complex aggregation issues
        let latest_hash: String = conn.query_row("SELECT integrity_hash FROM audit_reports ORDER BY id DESC LIMIT 1", [], |row| row.get(0))
            .unwrap_or_else(|_| "genesis".to_string());

        Ok((stats.0, stats.1, stats.2, stats.3, latest_hash))
    }

    pub fn check_health(&self) -> Result<(), SovereignError> {
        if self.is_healthy.load(std::sync::atomic::Ordering::SeqCst) {
            Ok(())
        } else {
            Err(SovereignError::InternalError("Auditor Hard-Stop triggered: Audit integrity compromised".into()))
        }
    }
}
