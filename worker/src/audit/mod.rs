pub mod forwarder;
pub mod storage;

pub use forwarder::*;

use chrono::{Duration, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use iw_core::{AadCipher, ScrubbingReport, SovereignError};
use iw_core::{KDF_SALT_ENCRYPTION, KDF_SALT_GENESIS, KDF_SALT_INTEGRITY};
use rusqlite::{Connection, ErrorCode};
use secrecy::{ExposeSecret, SecretVec};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use zeroize::Zeroize;

#[doc(hidden)]
pub type HmacSha256 = Hmac<Sha256>;

pub enum AuditMessage {
    LogReport(
        ScrubbingReport,
        String,
        String,
        tokio::sync::oneshot::Sender<Result<(), SovereignError>>,
    ), // report, raw_input, username, ack
    PurgeUser(
        String,
        tokio::sync::oneshot::Sender<Result<(), SovereignError>>,
    ),
    Purge,
    Shutdown,
    SiemAck(i64),
}

#[derive(Clone)]
pub struct AsyncAuditor {
    sender: mpsc::Sender<AuditMessage>,
    is_healthy: Arc<std::sync::atomic::AtomicBool>,
    db_path: String,
}

impl AsyncAuditor {
    pub async fn spawn(
        db_path: &str,
        pepper: SecretVec<u8>,
        remote_forwarder: Option<Arc<dyn RemoteAuditForwarder>>,
    ) -> Result<Self, SovereignError> {
        let (tx, mut rx) = mpsc::channel(4096);
        let path = db_path.to_string();
        let is_healthy = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let hk = Hkdf::<Sha256>::new(None, pepper.expose_secret());

        let mut hmac_key_bytes = [0u8; 32];
        hk.expand(KDF_SALT_INTEGRITY, &mut hmac_key_bytes)
            .map_err(|e| SovereignError::InternalError(format!("KDF Expansion Failure: {}", e)))?;

        let mut genesis_hash = [0u8; 32];
        hk.expand(KDF_SALT_GENESIS, &mut genesis_hash)
            .map_err(|e| SovereignError::InternalError(format!("KDF Expansion Failure: {}", e)))?;

        let (init_tx, init_rx) = tokio::sync::oneshot::channel();

        let healthy_thread = is_healthy.clone();
        let path_thread = path.clone();
        let tx_for_thread = tx.clone();
        std::thread::spawn(move || {
            info!("Warden Audit Worker (Dedicated Writer Thread) ignited.");

            let conn: Option<Connection>;
            let mut last_hash: Vec<u8> = vec![0u8; 32];
            let mut last_id: i64;

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
                    AuditMessage::LogReport(report, mut raw_input, username, ack_tx) => {
                        let mut result = Err(SovereignError::InternalError(
                            "Auditor not initialized or connection lost".to_string(),
                        ));

                        if !healthy_thread.load(std::sync::atomic::Ordering::SeqCst) {
                            let _ = ack_tx.send(Err(SovereignError::InternalError(
                                "Auditor in Panic State: Health check failed".into(),
                            )));
                            raw_input.zeroize();
                            continue;
                        }

                        if let Some(ref c) = conn {
                            let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            let redactions_json =
                                serde_json::to_string(&report.redactions).unwrap_or_default();
                            let redactions_bin =
                                bincode::serialize(&report.redactions).unwrap_or_default();

                            // --- SECURITY FIX (Section 3.1 & V-19): Hash-then-Encrypt with Composite AAD Binding ---
                            let mut composite_aad = String::new();
                            composite_aad.push_str(&hex::encode(&last_hash));
                            composite_aad.push_str(&username);

                            // Encrypt using centralized AadCipher (WP-98)
                            let encrypted_data = AadCipher::encrypt(
                                raw_input.as_bytes(),
                                &composite_aad,
                                pepper.expose_secret(),
                                KDF_SALT_ENCRYPTION,
                            );

                            match encrypted_data {
                                Ok(combined) => {
                                    // Extract nonce and ciphertext from combined output
                                    let (nonce_bytes, ciphertext) = combined.split_at(12);

                                    // --- SECURITY FIX (WP 55): Hash-then-Encrypt Binding ---
                                    let mut hasher = Sha256::new();
                                    hasher.update(ciphertext);
                                    hasher.update(nonce_bytes);
                                    let payload_hash = hasher.finalize();

                                    let mut mac = match <HmacSha256 as Mac>::new_from_slice(
                                        &hmac_key_bytes,
                                    ) {
                                        Ok(m) => m,
                                        Err(e) => {
                                            let _ =
                                                ack_tx.send(Err(SovereignError::InternalError(
                                                    format!("HMAC Key Failure: {}", e),
                                                )));
                                            raw_input.zeroize();
                                            continue;
                                        }
                                    };

                                    mac.update(&last_hash);
                                    mac.update(timestamp.as_bytes());
                                    mac.update(username.as_bytes()); // Bind username to integrity chain
                                    mac.update(&[report.is_blocked as u8]);
                                    mac.update(&redactions_bin);
                                    mac.update(&payload_hash); // Bind payload to chain

                                    let current_hash = mac.finalize().into_bytes().to_vec();

                                    let mut write_success = false;
                                    let has_forwarder = remote_forwarder.is_some();
                                    let map_err = |e: rusqlite::Error| {
                                        if matches!(e, rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::DatabaseBusy)
                                        {
                                            SovereignError::DatabaseBusy(
                                                "Audit DB busy (timeout)".into(),
                                            )
                                        } else {
                                            SovereignError::StorageError(format!(
                                                "Audit DB Error: {}",
                                                e
                                            ))
                                        }
                                    };

                                    let mut log_id = 0i64;
                                    if let Err(e) = c.execute("BEGIN IMMEDIATE TRANSACTION", []) {
                                        let _ = c.execute("ROLLBACK", []);
                                        result = Err(map_err(e));
                                    } else {
                                        let siem_acked = !has_forwarder;
                                        let res = c.execute("INSERT INTO ephemeral_raw_logs (username, encrypted_data, nonce, siem_acked) VALUES (?1, ?2, ?3, ?4)", (&username, &ciphertext.to_vec(), &nonce_bytes.to_vec(), &siem_acked));
                                        log_id = c.last_insert_rowid();
                                        if let Err(e) = res {
                                            let _ = c.execute("ROLLBACK", []);
                                            result = Err(map_err(e));
                                        } else {
                                            let res2 = c.execute(
                                                "INSERT INTO audit_reports (timestamp, username, is_blocked, redactions_json, payload_hash, integrity_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", 
                                                (&timestamp, &username, report.is_blocked, &redactions_json, hex::encode(payload_hash), hex::encode(&current_hash))
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
                                                    last_hash = current_hash.clone();
                                                    last_id += 1;
                                                    if let Err(e) = Self::update_anchor(
                                                        &path_thread,
                                                        last_id,
                                                        &last_hash,
                                                    ) {
                                                        error!("CRITICAL: Failed to update audit anchor: {}. Halting system.", e);
                                                        healthy_thread.store(
                                                            false,
                                                            std::sync::atomic::Ordering::SeqCst,
                                                        );
                                                        result = Err(e);
                                                    } else {
                                                        result = Ok(());
                                                        write_success = true;
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    if write_success {
                                        if let Some(ref forwarder) = remote_forwarder {
                                            let forward_forwarder = forwarder.clone();
                                            let forward_ciphertext = ciphertext.to_vec();
                                            let forward_nonce = nonce_bytes.to_vec();
                                            let forward_hash = current_hash.clone();
                                            let forward_report = report.clone();
                                            let forward_username = username.clone();
                                            let ack_tx = tx_for_thread.clone();

                                            tokio::runtime::Handle::current().spawn(async move {
                                                if let Err(e) = forward_forwarder.forward_log(&forward_ciphertext, &forward_nonce, &forward_hash, &forward_report, &forward_username).await {
                                                    error!("Remote Audit Forwarding Failed: {}. Audit remains local-only.", e);
                                                } else {
                                                    info!("Audit record successfully streamed to remote endpoint.");
                                                    let _ = ack_tx.send(AuditMessage::SiemAck(log_id)).await;
                                                }
                                            });
                                        }
                                    }

                                    if !write_success {
                                        error!("Audit log failed to persist: {:?}. Sending fail-closed signal.", result);
                                    }
                                }
                                Err(e) => {
                                    result = Err(e);
                                }
                            }
                        }
                        let _ = ack_tx.send(result);
                        raw_input.zeroize();
                    }
                    AuditMessage::PurgeUser(username, ack_tx) => {
                        let res = if let Some(ref c) = conn {
                            let _ = c.execute("BEGIN IMMEDIATE TRANSACTION", []);
                            // Cryptographic shredding under GDPR:
                            // 1. Wipe ephemeral raw logs & encryption keys/nonces
                            let res1 = c.execute(
                                "DELETE FROM ephemeral_raw_logs WHERE username = ?1",
                                [&username],
                            );
                            // 2. Redact username in audit_reports to preserve row IDs and cryptographic chain
                            let res2 = c.execute(
                                "UPDATE audit_reports SET username = '[REDACTED]' WHERE username = ?1",
                                [&username],
                            );

                            if res1.is_err() || res2.is_err() {
                                let _ = c.execute("ROLLBACK", []);
                                Err(SovereignError::StorageError(
                                    "Failed to purge user audit data".into(),
                                ))
                            } else {
                                let _ = c.execute("COMMIT", []);
                                info!(
                                    "GDPR Purge: All audit records for user {} have been cryptographically shredded.",
                                    username
                                );
                                Ok(())
                            }
                        } else {
                            Err(SovereignError::InternalError(
                                "Audit DB not connected".into(),
                            ))
                        };
                        let _ = ack_tx.send(res);
                    }
                    AuditMessage::Purge => {
                        if let Some(ref c) = conn {
                            let cutoff_logs = Utc::now() - Duration::days(30);
                            let cutoff_logs_str =
                                cutoff_logs.format("%Y-%m-%d %H:%M:%S").to_string();
                            let _ = c.execute(
                                "DELETE FROM ephemeral_raw_logs WHERE timestamp < ?1 AND siem_acked = TRUE",
                                [&cutoff_logs_str],
                            );

                            let cutoff_sessions = Utc::now() - Duration::hours(24);
                            let cutoff_sessions_str =
                                cutoff_sessions.format("%Y-%m-%d %H:%M:%S").to_string();
                            let _ = c.execute(
                                "DELETE FROM sessions WHERE updated_at < ?1",
                                [&cutoff_sessions_str],
                            );

                            info!("Auditor: Cleanup task completed (Logs > 30d, Sessions > 24h).");
                        }
                    }
                    AuditMessage::SiemAck(id) => {
                        if let Some(ref c) = conn {
                            let _ = c.execute(
                                "UPDATE ephemeral_raw_logs SET siem_acked = TRUE WHERE id = ?1",
                                [id],
                            );
                            info!("Auditor: SIEM ACK received for log {}.", id);
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

        tokio::time::timeout(tokio::time::Duration::from_secs(10), init_rx)
            .await
            .map_err(|_| {
                SovereignError::InternalError("Audit worker init timeout (Boot Deadlock)".into())
            })?
            .map_err(|_| {
                SovereignError::InternalError("Audit worker thread died during init".into())
            })?
            .map_err(SovereignError::InternalError)?;

        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if tx_clone.send(AuditMessage::Purge).await.is_err() {
                    break;
                }
            }
        });

        // --- HARD-STOP BACKGROUND MONITOR (WP #88) ---
        let healthy_monitor = is_healthy.clone();
        let path_monitor = path.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
            loop {
                interval.tick().await;

                // --- DISK CAPACITY CHECK ---
                unsafe {
                    let mut stat: libc::statvfs = std::mem::zeroed();
                    let check_path = if std::path::Path::new(&path_monitor).exists() {
                        std::ffi::CString::new(path_monitor.as_str()).unwrap_or_default()
                    } else {
                        let parent = std::path::Path::new(&path_monitor)
                            .parent()
                            .filter(|p| !p.as_os_str().is_empty())
                            .unwrap_or_else(|| std::path::Path::new("."));
                        std::ffi::CString::new(parent.to_string_lossy().as_bytes())
                            .unwrap_or_default()
                    };

                    let res = libc::statvfs(check_path.as_ptr(), &mut stat);
                    let res = if res != 0 {
                        libc::statvfs(c".".as_ptr(), &mut stat)
                    } else {
                        res
                    };

                    if res == 0 {
                        let free_space = (stat.f_bavail as u64) * (stat.f_frsize as u64);
                        if free_space < 50_000_000 {
                            // 50MB threshold
                            error!("HARD-STOP MONITOR: Disk exhaustion imminent (Free < 50MB). Triggering Fail-Closed state.");
                            healthy_monitor.store(false, std::sync::atomic::Ordering::SeqCst);
                            break;
                        }
                    } else {
                        warn!("HARD-STOP MONITOR: Cannot read disk capacity, skipping check cycle");
                    }
                }

                if path_monitor.contains(":memory:") {
                    continue;
                }

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
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    );

                    match res {
                        Ok((id, hash)) => {
                            let hash_bytes = hex::decode(hash).unwrap_or_default();
                            if let Err(e) = Self::check_anchor(&path_monitor, id, &hash_bytes) {
                                error!("HARD-STOP MONITOR: Anchor Violation: {}. Triggering Fail-Closed state.", e);
                                healthy_monitor.store(false, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                        Err(rusqlite::Error::QueryReturnedNoRows) => {
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
                    error!(
                        "HARD-STOP MONITOR: Cannot open Audit DB. Triggering Fail-Closed state."
                    );
                    healthy_monitor.store(false, std::sync::atomic::Ordering::SeqCst);
                }

                if !healthy_monitor.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
            }
        });

        Ok(Self {
            sender: tx,
            is_healthy,
            db_path: path,
        })
    }

    pub async fn log_report(
        &self,
        report: ScrubbingReport,
        raw_input: String,
        username: String,
    ) -> Result<(), SovereignError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.sender
            .send(AuditMessage::LogReport(report, raw_input, username, tx))
            .await
            .map_err(|e| SovereignError::InternalError(format!("Audit channel failure: {}", e)))?;
        rx.await
            .map_err(|e| SovereignError::InternalError(format!("Audit ack failure: {}", e)))?
    }

    pub async fn purge_user(&self, username: &str) -> Result<(), SovereignError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.sender
            .send(AuditMessage::PurgeUser(username.to_string(), tx))
            .await
            .map_err(|e| SovereignError::InternalError(format!("Audit channel failure: {}", e)))?;
        rx.await
            .map_err(|e| SovereignError::InternalError(format!("Audit ack failure: {}", e)))?
    }

    pub fn get_compliance_stats(
        &self,
    ) -> Result<(u64, u64, String, String, String), SovereignError> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| SovereignError::StorageError(e.to_string()))?;
        let mut stmt = conn.prepare("SELECT COUNT(*), SUM(CASE WHEN is_blocked = 1 THEN 1 ELSE 0 END), MIN(timestamp), MAX(timestamp) FROM audit_reports")
            .map_err(|e| SovereignError::StorageError(e.to_string()))?;
        let stats: (u64, u64, String, String) = stmt
            .query_row([], |row| {
                Ok((
                    row.get(0).unwrap_or(0),
                    row.get::<_, i64>(1).unwrap_or(0) as u64,
                    row.get(2).unwrap_or_else(|_| "N/A".to_string()),
                    row.get(3).unwrap_or_else(|_| "N/A".to_string()),
                ))
            })
            .map_err(|e| SovereignError::StorageError(e.to_string()))?;
        let latest_hash: String = conn
            .query_row(
                "SELECT integrity_hash FROM audit_reports ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "genesis".to_string());
        Ok((stats.0, stats.1, stats.2, stats.3, latest_hash))
    }

    pub fn check_health(&self) -> Result<(), SovereignError> {
        if self.is_healthy.load(std::sync::atomic::Ordering::SeqCst) {
            Ok(())
        } else {
            Err(SovereignError::InternalError(
                "Auditor Hard-Stop triggered: Audit integrity compromised".into(),
            ))
        }
    }
    #[doc(hidden)]
    pub async fn shutdown(&self) {
        let _ = self.sender.send(AuditMessage::Shutdown).await;
    }
}
