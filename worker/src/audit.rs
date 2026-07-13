use chrono::{Duration, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use iw_core::{AadCipher, ScrubbingReport, SovereignError};
use iw_core::{Redaction, KDF_SALT_ENCRYPTION, KDF_SALT_GENESIS, KDF_SALT_INTEGRITY};
use rusqlite::{Connection, ErrorCode};
use secrecy::{ExposeSecret, SecretVec};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

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
}

/// Trait for off-box audit log streaming.
#[async_trait::async_trait]
pub trait RemoteAuditForwarder: Send + Sync {
    async fn forward_log(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        integrity_hash: &[u8],
        report: &ScrubbingReport,
        username: &str,
    ) -> Result<(), SovereignError>;
}

/// Production-grade HTTP Forwarder for SIEM/Log Aggregator integration.

#[derive(serde::Serialize)]
struct AuditPayload<'a> {
    ciphertext: String,
    nonce: String,
    integrity_hash: String,
    is_blocked: bool,
    redactions_count: usize,
    execution_time_ms: u64,
    timestamp: String,
    username: &'a str,
}

pub struct HttpAuditForwarder {
    client: reqwest::Client,
    endpoint: String,
    token: secrecy::SecretString,
}

impl HttpAuditForwarder {
    pub fn new(endpoint: String, token: secrecy::SecretString) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint,
            token,
        }
    }
}

#[async_trait::async_trait]
impl RemoteAuditForwarder for HttpAuditForwarder {
    async fn forward_log(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        integrity_hash: &[u8],
        report: &ScrubbingReport,
        username: &str,
    ) -> Result<(), SovereignError> {
        use secrecy::ExposeSecret;
        let payload = AuditPayload {
            ciphertext: hex::encode(ciphertext),
            nonce: hex::encode(nonce),
            integrity_hash: hex::encode(integrity_hash),
            is_blocked: report.is_blocked,
            redactions_count: report.redactions.len(),
            execution_time_ms: report.execution_time_ms,
            timestamp: Utc::now().to_rfc3339(),
            username,
        };

        self.client
            .post(&self.endpoint)
            .header(
                "Authorization",
                format!("Bearer {}", self.token.expose_secret()),
            )
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                SovereignError::InternalError(format!("Remote Audit Streaming Failed: {}", e))
            })?;

        Ok(())
    }
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

                                    // --- HA / IMMUTABILITY FIX (WP 92): Real-time Remote Forwarding ---
                                    if let Some(ref forwarder) = remote_forwarder {
                                        let forward_forwarder = forwarder.clone();
                                        let forward_ciphertext = ciphertext.to_vec();
                                        let forward_nonce = nonce_bytes.to_vec();
                                        let forward_hash = current_hash.clone();
                                        let forward_report = report.clone();
                                        let forward_username = username.clone();

                                        let _ = tokio::runtime::Handle::current().spawn(async move {
                                            if let Err(e) = forward_forwarder.forward_log(&forward_ciphertext, &forward_nonce, &forward_hash, &forward_report, &forward_username).await {
                                                error!("Remote Audit Forwarding Failed: {}. Audit remains local-only.", e);
                                            } else {
                                                info!("Audit record successfully streamed to remote endpoint.");
                                            }
                                        });
                                    }

                                    let mut write_success = false;
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

                                    let _ = c.execute("BEGIN IMMEDIATE TRANSACTION", []);
                                    let res = c.execute("INSERT INTO ephemeral_raw_logs (username, encrypted_data, nonce) VALUES (?1, ?2, ?3)", (&username, &ciphertext.to_vec(), &nonce_bytes.to_vec()));
                                    if let Err(e) = res {
                                        let _ = c.execute("ROLLBACK", []);
                                        result = Err(map_err(e));
                                    } else {
                                        let res2 = c.execute(
                                            "INSERT INTO audit_reports (timestamp, username, is_blocked, redactions_json, payload_hash, integrity_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", 
                                            (&timestamp, &username, report.is_blocked, &redactions_json, hex::encode(&payload_hash), hex::encode(&current_hash))
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
                            let res1 = c.execute(
                                "DELETE FROM audit_reports WHERE username = ?1",
                                [&username],
                            );
                            let res2 = c.execute(
                                "DELETE FROM ephemeral_raw_logs WHERE username = ?1",
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
                                    "GDPR Purge: All audit records for user {} have been erased.",
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
                                "DELETE FROM ephemeral_raw_logs WHERE timestamp < ?1",
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
            .map_err(|e| SovereignError::InternalError(e))?;

        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if let Err(_) = tx_clone.send(AuditMessage::Purge).await {
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
                    // We check the parent directory of the DB path, or the current dir as fallback
                    let db_parent = std::path::Path::new(&path_monitor)
                        .parent()
                        .unwrap_or(std::path::Path::new("."));
                    let path_str = db_parent.to_string_lossy().into_owned();
                    let path_to_use = if path_str.is_empty() { "." } else { &path_str };
                    let path_cstr = std::ffi::CString::new(path_to_use).unwrap_or_default();
                    if libc::statvfs(path_cstr.as_ptr(), &mut stat) == 0 {
                        let free_space = (stat.f_bavail as u64) * (stat.f_frsize as u64);
                        if free_space < 50_000_000 {
                            // 50MB threshold
                            error!("HARD-STOP MONITOR: Disk exhaustion imminent (Free < 50MB). Triggering Fail-Closed state.");
                            healthy_monitor.store(false, std::sync::atomic::Ordering::SeqCst);
                            break;
                        }
                    } else {
                        error!("HARD-STOP MONITOR: Cannot read disk capacity. Triggering Fail-Closed state.");
                        healthy_monitor.store(false, std::sync::atomic::Ordering::SeqCst);
                        break;
                    }
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

    fn init_db(
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
        conn.execute("CREATE TABLE IF NOT EXISTS ephemeral_raw_logs (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, username TEXT DEFAULT 'unknown', encrypted_data BLOB, nonce BLOB)", [])?;

        // Ensure username column exists in case of upgrade from older versions
        let _ = conn.execute(
            "ALTER TABLE audit_reports ADD COLUMN username TEXT DEFAULT 'unknown'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE ephemeral_raw_logs ADD COLUMN username TEXT DEFAULT 'unknown'",
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
                    if actual_payload_hash.as_slice() != payload_hash.as_slice() {
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

    fn update_anchor(db_path: &str, last_id: i64, last_hash: &[u8]) -> Result<(), SovereignError> {
        let anchor_path = format!("{}.anchor", db_path);
        let content = format!("{}:{}", last_id, hex::encode(last_hash));
        std::fs::write(anchor_path, content)
            .map_err(|e| SovereignError::StorageError(format!("Anchor write failure: {}", e)))
    }

    fn check_anchor(
        db_path: &str,
        current_last_id: i64,
        current_last_hash: &[u8],
    ) -> Result<(), String> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use iw_core::{ScrubbingReport, TokenMap};
    use secrecy::SecretVec;

    #[tokio::test]
    async fn test_audit_purge_user() {
        let db_path = format!("audit_test_purge_{}.db", uuid::Uuid::new_v4());
        let pepper = SecretVec::from(vec![0u8; 32]);
        let auditor = AsyncAuditor::spawn(&db_path, pepper, None).await.unwrap();

        let report = ScrubbingReport {
            sanitized_text: "test".into(),
            is_blocked: false,
            redactions: vec![],
            token_map: TokenMap::new(),
            execution_time_ms: 1,
            potential_misses: vec![],
        };

        // Log for User A
        auditor.log_report(report.clone(), "rawA".into(), "userA".into()).await.unwrap();
        
        // Log for User B
        auditor.log_report(report.clone(), "rawB".into(), "userB".into()).await.unwrap();

        // Purge User A
        auditor.purge_user("userA").await.unwrap();

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        
        // Check audit_reports
        let count_a: i64 = conn.query_row("SELECT COUNT(*) FROM audit_reports WHERE username = 'userA'", [], |r| r.get(0)).unwrap();
        assert_eq!(count_a, 0, "User A audit_reports should be deleted");

        let count_b: i64 = conn.query_row("SELECT COUNT(*) FROM audit_reports WHERE username = 'userB'", [], |r| r.get(0)).unwrap();
        assert_eq!(count_b, 1, "User B audit_reports should remain");

        // Check ephemeral_raw_logs
        let count_raw_a: i64 = conn.query_row("SELECT COUNT(*) FROM ephemeral_raw_logs WHERE username = 'userA'", [], |r| r.get(0)).unwrap();
        assert_eq!(count_raw_a, 0, "User A ephemeral_raw_logs should be deleted");

        let count_raw_b: i64 = conn.query_row("SELECT COUNT(*) FROM ephemeral_raw_logs WHERE username = 'userB'", [], |r| r.get(0)).unwrap();
        assert_eq!(count_raw_b, 1, "User B ephemeral_raw_logs should remain");

        std::fs::remove_file(&db_path).ok();
        std::fs::remove_file(format!("{}.anchor", db_path)).ok();
    }
}
