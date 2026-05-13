use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{Duration};
use std::sync::Arc;
use uuid::Uuid;
use tracing::{info, error};
use iw_core::{SessionContext, SessionState, SovereignError};
use dashmap::DashMap;
use rusqlite::{Connection, ErrorCode};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use sha2::Sha256;
use hkdf::Hkdf;
use rand::RngCore;
use zeroize::Zeroize;
use secrecy::{SecretVec, ExposeSecret};

/// Represents the job payload for consolidated storage.
#[derive(Serialize, Deserialize, Debug)]
pub struct LocalJob {
    pub id: String,
    pub username: String,
    pub thread_id: String,
    pub query: String,
    pub options: HashMap<String, serde_json::Value>,
    pub created_at: u64,
}

#[derive(Clone)]
pub struct SearchBoostQueue {
    db_path: String,
    cipher: Aes256Gcm,
    conn: Arc<std::sync::Mutex<Connection>>,
    shield: Option<Arc<dyn iw_core::PiiShield + Send + Sync>>,
}

impl SearchBoostQueue {
    pub fn new(db_path: String, pepper: &SecretVec<u8>, shield: Option<Arc<dyn iw_core::PiiShield + Send + Sync>>) -> Self {
        let hk = Hkdf::<Sha256>::new(None, pepper.expose_secret());
        let mut key_bytes = [0u8; 32];
        hk.expand(b"warden-v1-queue-encryption", &mut key_bytes).expect("KDF expansion failed");
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        key_bytes.zeroize();

        let conn = Connection::open(&db_path).expect("Failed to open SearchBoost DB");
        conn.busy_timeout(std::time::Duration::from_millis(5000)).expect("Failed to set busy timeout");
        conn.execute_batch("
            PRAGMA journal_mode = WAL; 
            PRAGMA synchronous = NORMAL;
            CREATE TABLE IF NOT EXISTS search_jobs (
                id TEXT PRIMARY KEY, 
                username TEXT, 
                thread_id TEXT, 
                query BLOB, 
                result BLOB,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        ").expect("Failed to initialize SearchBoost table");

        Self { 
            db_path, 
            cipher,
            conn: Arc::new(std::sync::Mutex::new(conn)),
            shield,
        }
    }

    /// Spawns a background worker to process enqueued search jobs.
    pub fn spawn_worker(&self, librarian: Arc<crate::librarian::LocalLibrarian>) {
        let queue = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                if let Err(e) = queue.process_next_job(librarian.clone()).await {
                    if !matches!(e, SovereignError::DatabaseBusy(_)) {
                        error!("SearchBoost Worker Error: {}", e);
                    }
                }
            }
        });
    }

    async fn process_next_job(&self, librarian: Arc<crate::librarian::LocalLibrarian>) -> Result<(), SovereignError> {
        let conn_arc = self.conn.clone();
        
        let job = tokio::task::spawn_blocking(move || {
            let conn = conn_arc.lock().map_err(|_| SovereignError::InternalError("Mutex poisoned".into()))?;
            let mut stmt = conn.prepare("SELECT id, username, query FROM search_jobs WHERE status = 'pending' ORDER BY created_at ASC LIMIT 1")
                .map_err(|e| SovereignError::StorageError(e.to_string()))?;
            let mut rows = stmt.query([]).map_err(|e| SovereignError::StorageError(e.to_string()))?;
            
            if let Some(row) = rows.next().map_err(|e| SovereignError::StorageError(e.to_string()))? {
                let id: String = row.get(0).map_err(|e| SovereignError::StorageError(e.to_string()))?;
                let username: String = row.get(1).map_err(|e| SovereignError::StorageError(e.to_string()))?;
                let encrypted_query: Vec<u8> = row.get(2).map_err(|e| SovereignError::StorageError(e.to_string()))?;
                Ok::<Option<(String, String, Vec<u8>)>, SovereignError>(Some((id, username, encrypted_query)))
            } else {
                Ok(None)
            }
        }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

        if let Some((id, username, encrypted_query)) = job {
            // 1. Decrypt Query
            if encrypted_query.len() < 12 { return Err(SovereignError::InternalError("Corrupt job data".into())); }
            let (nonce_bytes, ciphertext) = encrypted_query.split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);
            
            // --- SECURITY FIX (V-19): Bind decryption to username via AAD ---
            let payload = aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: username.as_bytes(),
            };
            
            let query_bytes = self.cipher.decrypt(nonce, payload)
                .map_err(|_| SovereignError::InternalError("Job decryption failed (Integrity Mismatch)".into()))?;
            let query = String::from_utf8(query_bytes).map_err(|_| SovereignError::InternalError("Invalid UTF-8".into()))?;

            // 2. Perform Search (RAG)
            info!(job_id = %id, user = %username, "Processing SearchBoost job...");
            let results = librarian.retrieve_policy_context(&query, 3).await
                .map_err(|e| SovereignError::StorageError(e.to_string()))?;
            
            // --- SECURITY FIX (WP 68): Scrub retrieved context ---
            let mut scrubbed_results = Vec::new();
            if let Some(shield) = &self.shield {
                for res in results {
                    // Apply global rules to the retrieved context
                    if let Ok(report) = shield.sanitize_prompt(&res, None) {
                        scrubbed_results.push(report.sanitized_text);
                    } else {
                        scrubbed_results.push("[REDACTION_FAILURE]".to_string());
                    }
                }
            } else {
                scrubbed_results = results;
            }

            let consolidated_result = if scrubbed_results.is_empty() {
                "No relevant local policy context found.".to_string()
            } else {
                scrubbed_results.join("\n---\n")
            };

            // 3. Encrypt Result (Bound to username)
            let mut res_nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut res_nonce_bytes);
            let res_nonce = Nonce::from_slice(&res_nonce_bytes);
            
            let res_payload = aes_gcm::aead::Payload {
                msg: consolidated_result.as_bytes(),
                aad: username.as_bytes(),
            };
            
            let res_ciphertext = self.cipher.encrypt(res_nonce, res_payload)
                .map_err(|_| SovereignError::InternalError("Result encryption failed".into()))?;
            
            let mut encrypted_result = res_nonce_bytes.to_vec();
            encrypted_result.extend(res_ciphertext);

            // 4. Update DB
            let conn_arc = self.conn.clone();
            let id_clone = id.clone();
            tokio::task::spawn_blocking(move || {
                let conn = conn_arc.lock().map_err(|_| SovereignError::InternalError("Mutex poisoned".into()))?;
                conn.execute(
                    "UPDATE search_jobs SET result = ?1, status = 'complete' WHERE id = ?2",
                    (&encrypted_result, &id_clone),
                ).map_err(|e| SovereignError::StorageError(e.to_string()))?;
                Ok::<(), SovereignError>(())
            }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

            info!(job_id = %id, "SearchBoost job completed and encrypted.");

        }

        Ok(())
    }

    /// Enqueues a sanitized query into the local SQLite-backed queue.
    pub async fn enqueue(
        &self,
        query: String,
        _options: HashMap<String, serde_json::Value>,
        thread_id: String,
        username: String,
    ) -> Result<String, SovereignError> {
        let session_id = format!("SB-SESSION:{}:{}", username, thread_id);
        let job_id = format!("{}:{}", session_id, Uuid::new_v4());

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // --- SECURITY FIX (V-19): Bind job to username via AAD ---
        let payload = aes_gcm::aead::Payload {
            msg: query.as_bytes(),
            aad: username.as_bytes(),
        };
        
        let ciphertext = self.cipher.encrypt(nonce, payload)
            .map_err(|_| SovereignError::InternalError("Queue encryption failed".into()))?;
        
        let mut encrypted_query = nonce_bytes.to_vec();
        encrypted_query.extend(ciphertext);

        let username_clone = username.clone();
        let thread_id_clone = thread_id.clone();
        let job_id_clone = job_id.clone();
        let conn_arc = self.conn.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn_arc.lock().map_err(|_| SovereignError::InternalError("Mutex poisoned".into()))?;
            conn.execute(
                "INSERT INTO search_jobs (id, username, thread_id, query) VALUES (?1, ?2, ?3, ?4)",
                (&job_id_clone, &username_clone, &thread_id_clone, &encrypted_query),
            ).map_err(|e| {
                if matches!(e, rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::DatabaseBusy) {
                    SovereignError::DatabaseBusy("SearchBoost Queue busy".into())
                } else {
                    SovereignError::StorageError(format!("Queue persistence failed: {}", e))
                }
            })?;
            Ok::<(), SovereignError>(())
        }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

        info!(job_id = %job_id, "Successfully enqueued encrypted SearchBoost job");

        Ok(job_id)
    }

    pub async fn get_result(&self, job_id: &str) -> Result<Option<String>, SovereignError> {
        let job_id_str = job_id.to_string();
        let conn_arc = self.conn.clone();
        
        let result_data = tokio::task::spawn_blocking(move || {
            let conn = conn_arc.lock().map_err(|_| SovereignError::InternalError("Mutex poisoned".into()))?;
            let mut stmt = conn.prepare("SELECT username, result FROM search_jobs WHERE id = ?1 AND status = 'complete'").map_err(|e| SovereignError::StorageError(e.to_string()))?;
            let mut rows = stmt.query([job_id_str]).map_err(|e| {
                if matches!(e, rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::DatabaseBusy) {
                    SovereignError::DatabaseBusy("SearchBoost Query busy".into())
                } else {
                    SovereignError::StorageError(e.to_string())
                }
            })?;
            if let Some(row) = rows.next().map_err(|e| SovereignError::StorageError(e.to_string()))? {
                let username: String = row.get(0).map_err(|e| SovereignError::StorageError(e.to_string()))?;
                let data: Vec<u8> = row.get(1).map_err(|e| SovereignError::StorageError(e.to_string()))?;
                Ok::<Option<(String, Vec<u8>)>, SovereignError>(Some((username, data)))
            } else {
                Ok(None)
            }
        }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

        match result_data {
            Some((username, data)) => {
                if data.len() < 12 { return Err(SovereignError::InternalError("Invalid result length".into())); }
                let (nonce_bytes, ciphertext) = data.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);
                
                // --- SECURITY FIX (V-19): Bind decryption to username via AAD ---
                let payload = aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: username.as_bytes(),
                };
                
                let decrypted = self.cipher.decrypt(nonce, payload)
                    .map_err(|_| SovereignError::InternalError("Result decryption failed (Integrity Mismatch)".into()))?;
                
                Ok(Some(String::from_utf8(decrypted).map_err(|e| SovereignError::InternalError(e.to_string()))?))
            },
            None => Ok(None)
        }
    }

}

use redis::AsyncCommands;

/// Consolidated Local Session Manager.
pub struct LocalSessionManager {
    sessions: DashMap<String, Arc<SessionContext>>,
    db_path: String,
    cipher: Aes256Gcm,
    conn: Arc<std::sync::Mutex<Connection>>,
    redis_client: Option<redis::Client>,
}

impl LocalSessionManager {
    pub fn new(db_path: String, pepper: &SecretVec<u8>) -> Arc<Self> {
        let hk = Hkdf::<Sha256>::new(None, pepper.expose_secret());
        let mut key_bytes = [0u8; 32];
        hk.expand(b"warden-v1-session-encryption", &mut key_bytes).expect("KDF expansion failed");
        
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        key_bytes.zeroize();

        let conn = Connection::open(&db_path).expect("Failed to open Session DB");
        conn.busy_timeout(std::time::Duration::from_millis(2000)).expect("Failed to set busy timeout");
        conn.execute_batch("
            PRAGMA journal_mode = WAL; 
            PRAGMA synchronous = NORMAL;
            CREATE TABLE IF NOT EXISTS sessions (username TEXT PRIMARY KEY, session_data TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        ").expect("Failed to set PRAGMAs or create sessions table");

        let redis_url = std::env::var("REDIS_URL").ok();
        let redis_client = redis_url.and_then(|url| redis::Client::open(url).ok());
        if redis_client.is_some() {
            info!("Redis HA Backend: ENABLED for Session Management.");
        }

        let manager = Arc::new(Self {
            sessions: DashMap::new(),
            db_path: db_path.clone(),
            cipher,
            conn: Arc::new(std::sync::Mutex::new(conn)),
            redis_client,
        });

        let manager_clone = manager.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = manager_clone.flush_to_db().await {
                    error!("Failed to flush sessions to SQLite: {}", e);
                }
            }
        });

        manager
    }

    pub async fn get_session(&self, username: &str) -> Result<Arc<SessionContext>, SovereignError> {
        if let Some(session) = self.sessions.get(username) {
            session.touch();
            return Ok(session.clone());
        }

        let username_str = username.to_string();
        let conn_arc = self.conn.clone();
        
        let mut encrypted_data = tokio::task::spawn_blocking(move || {
            let conn = conn_arc.lock().map_err(|_| SovereignError::InternalError("Mutex poisoned".into()))?;
            let mut stmt = conn.prepare("SELECT session_data FROM sessions WHERE username = ?1").map_err(|e| SovereignError::StorageError(e.to_string()))?;
            let mut rows = stmt.query([username_str]).map_err(|e| {
                if matches!(e, rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::DatabaseBusy) {
                    SovereignError::DatabaseBusy("Session DB busy".into())
                } else {
                    SovereignError::StorageError(e.to_string())
                }
            })?;
            if let Some(row) = rows.next().map_err(|e| SovereignError::StorageError(e.to_string()))? {
                let data: Vec<u8> = row.get(0).map_err(|e| SovereignError::StorageError(e.to_string()))?;
                Ok::<Option<Vec<u8>>, SovereignError>(Some(data))
            } else {
                Ok(None)
            }
        }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

        // --- HA FIX (WP 90): Check Redis if SQLite is missing ---
        if encrypted_data.is_none() {
            if let Some(ref client) = self.redis_client {
                if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                    let redis_key = format!("iw:session:{}", username);
                    if let Ok(data) = con.get::<_, Vec<u8>>(&redis_key).await {
                        if !data.is_empty() {
                            encrypted_data = Some(data);
                        }
                    }
                }
            }
        }

        let ctx = match encrypted_data {
            Some(data) => {
                if data.len() < 12 { return Err(SovereignError::InternalError("Invalid session data length".into())); }
                let (nonce_bytes, ciphertext) = data.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);
                
                // --- SECURITY FIX (V-19): Bind decryption to username via AAD ---
                let payload = aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: username.as_bytes(),
                };
                
                let decrypted = self.cipher.decrypt(nonce, payload)
                    .map_err(|_| SovereignError::InternalError("Session decryption failed (Integrity Mismatch)".into()))?;
                
                let state: SessionState = serde_json::from_slice(&decrypted)
                    .map_err(|e| SovereignError::InternalError(format!("Session corruption: {}", e)))?;
                Arc::new(SessionContext::from(state))
            },
            None => Arc::new(SessionContext::new()),
        };

        ctx.touch();
        self.sessions.insert(username.to_string(), ctx.clone());
        Ok(ctx)
    }

    pub async fn save_session(&self, username: &str, ctx: &SessionContext) -> Result<(), SovereignError> {
        let state = SessionState::from(ctx);
        let json_bytes = serde_json::to_vec(&state).unwrap_or_default();
        
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // --- SECURITY FIX (V-19): Bind encryption to username via AAD ---
        let payload = aes_gcm::aead::Payload {
            msg: json_bytes.as_slice(),
            aad: username.as_bytes(),
        };
        
        let ciphertext = self.cipher.encrypt(nonce, payload)
            .map_err(|_| SovereignError::InternalError("Session encryption failed".into()))?;
        
        let mut combined = nonce_bytes.to_vec();
        combined.extend(ciphertext);

        // --- HA FIX (WP 90): Write to Redis for HA Clustered Access ---
        if let Some(ref client) = self.redis_client {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let redis_key = format!("iw:session:{}", username);
                let _: Result<(), _> = con.set_ex(&redis_key, &combined, 86400).await; // 24h TTL
            }
        }

        let username_str = username.to_string();
        let conn_arc = self.conn.clone();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn_arc.lock().map_err(|_| SovereignError::InternalError("Mutex poisoned".into()))?;
            conn.execute(
                "INSERT INTO sessions (username, session_data, updated_at) VALUES (?1, ?2, CURRENT_TIMESTAMP)
                 ON CONFLICT(username) DO UPDATE SET session_data = ?2, updated_at = CURRENT_TIMESTAMP",
                (&username_str, &combined),
            ).map_err(|e| {
                if matches!(e, rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::DatabaseBusy) {
                    SovereignError::DatabaseBusy("Session DB busy".into())
                } else {
                    SovereignError::StorageError(format!("Session persistence failed: {}", e))
                }
            })?;
            Ok::<(), SovereignError>(())
        }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

        Ok(())
    }

    async fn flush_to_db(&self) -> Result<(), SovereignError> {
        let mut sessions_to_flush: Vec<(String, Vec<u8>)> = Vec::new();
        
        for item in self.sessions.iter() {
            let username = item.key();
            let state = SessionState::from(item.value().as_ref());
            let json_bytes = serde_json::to_vec(&state).unwrap_or_default();
            
            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            
            // --- SECURITY FIX (V-19): Bind encryption to username via AAD ---
            let payload = aes_gcm::aead::Payload {
                msg: json_bytes.as_slice(),
                aad: username.as_bytes(),
            };
            
            if let Ok(ciphertext) = self.cipher.encrypt(nonce, payload) {
                let mut combined = nonce_bytes.to_vec();
                combined.extend(ciphertext);
                sessions_to_flush.push((username.clone(), combined));
            }
        }

        if sessions_to_flush.is_empty() {
            return Ok(());
        }

        let conn_arc = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = conn_arc.lock().map_err(|_| SovereignError::InternalError("Mutex poisoned".into()))?;
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(|e| {
                if matches!(e, rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::DatabaseBusy) {
                    SovereignError::DatabaseBusy("Session DB busy".into())
                } else {
                    SovereignError::StorageError(e.to_string())
                }
            })?;
            for (username, encrypted_data) in sessions_to_flush {
                tx.execute(
                    "INSERT INTO sessions (username, session_data, updated_at) VALUES (?1, ?2, CURRENT_TIMESTAMP)
                     ON CONFLICT(username) DO UPDATE SET session_data = ?2, updated_at = CURRENT_TIMESTAMP",
                    (&username, &encrypted_data),
                ).map_err(|e| SovereignError::StorageError(e.to_string()))?;
            }
            tx.commit().map_err(|e| SovereignError::StorageError(e.to_string()))?;
            Ok::<(), SovereignError>(())
        }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

        info!("Successfully encrypted and flushed {} sessions to SQLite", self.sessions.len());
        Ok(())
    }
}
