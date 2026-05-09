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
}

impl SearchBoostQueue {
    pub fn new(db_path: String, pepper: &SecretVec<u8>) -> Self {
        let hk = Hkdf::<Sha256>::new(None, pepper.expose_secret());
        let mut key_bytes = [0u8; 32];
        hk.expand(b"warden-v1-queue-encryption", &mut key_bytes).expect("KDF expansion failed");
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        key_bytes.zeroize();

        let conn = Connection::open(&db_path).expect("Failed to open SearchBoost DB");
        conn.busy_timeout(std::time::Duration::from_millis(2000)).expect("Failed to set busy timeout");
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")
            .expect("Failed to set PRAGMAs");

        Self { 
            db_path, 
            cipher,
            conn: Arc::new(std::sync::Mutex::new(conn))
        }
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
        
        let ciphertext = self.cipher.encrypt(nonce, query.as_bytes())
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
                "INSERT INTO search_jobs (id, username, thread_id, query, created_at) VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)",
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
        
        let encrypted_query = tokio::task::spawn_blocking(move || {
            let conn = conn_arc.lock().map_err(|_| SovereignError::InternalError("Mutex poisoned".into()))?;
            let mut stmt = conn.prepare("SELECT query FROM search_jobs WHERE id = ?1").map_err(|e| SovereignError::StorageError(e.to_string()))?;
            let mut rows = stmt.query([job_id_str]).map_err(|e| {
                if matches!(e, rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::DatabaseBusy) {
                    SovereignError::DatabaseBusy("SearchBoost Query busy".into())
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

        match encrypted_query {
            Some(data) => {
                if data.len() < 12 { return Err(SovereignError::InternalError("Invalid job query length".into())); }
                let (nonce_bytes, ciphertext) = data.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);
                let decrypted = self.cipher.decrypt(nonce, ciphertext)
                    .map_err(|_| SovereignError::InternalError("Queue decryption failed".into()))?;
                
                Ok(Some(String::from_utf8(decrypted).map_err(|e| SovereignError::InternalError(e.to_string()))?))
            },
            None => Ok(None)
        }
    }
}

/// Consolidated Local Session Manager.
pub struct LocalSessionManager {
    sessions: DashMap<String, Arc<SessionContext>>,
    db_path: String,
    cipher: Aes256Gcm,
    conn: Arc<std::sync::Mutex<Connection>>,
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
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")
            .expect("Failed to set PRAGMAs");

        let manager = Arc::new(Self {
            sessions: DashMap::new(),
            db_path: db_path.clone(),
            cipher,
            conn: Arc::new(std::sync::Mutex::new(conn)),
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
        
        let encrypted_data_from_db = tokio::task::spawn_blocking(move || {
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

        let ctx = match encrypted_data_from_db {
            Some(data) => {
                if data.len() < 12 { return Err(SovereignError::InternalError("Invalid session data length".into())); }
                let (nonce_bytes, ciphertext) = data.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);
                let decrypted = self.cipher.decrypt(nonce, ciphertext)
                    .map_err(|_| SovereignError::InternalError("Session decryption failed".into()))?;
                
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

    pub async fn save_session(&self, _username: &str, _ctx: &SessionContext) -> Result<(), SovereignError> {
        Ok(())
    }

    async fn flush_to_db(&self) -> Result<(), SovereignError> {
        let mut sessions_to_flush: Vec<(String, Vec<u8>)> = Vec::new();
        
        for item in self.sessions.iter() {
            let state = SessionState::from(item.value().as_ref());
            let json_bytes = serde_json::to_vec(&state).unwrap_or_default();
            
            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            
            if let Ok(ciphertext) = self.cipher.encrypt(nonce, json_bytes.as_slice()) {
                let mut combined = nonce_bytes.to_vec();
                combined.extend(ciphertext);
                sessions_to_flush.push((item.key().clone(), combined));
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
