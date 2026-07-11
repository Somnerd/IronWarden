use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{Duration};
use std::sync::Arc;
use uuid::Uuid;
use tracing::{info, error};
use iw_core::{SessionContext, SessionState, SovereignError, AadCipher};
use dashmap::DashMap;
use rusqlite::{Connection, ErrorCode};
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
    pepper: Arc<SecretVec<u8>>,
    conn: Arc<std::sync::Mutex<Connection>>,
    shield: Option<Arc<dyn iw_core::PiiShield + Send + Sync>>,
    grounding_shield: Option<Arc<dyn iw_core::GroundingShield + Send + Sync>>,
    redis_client: Option<redis::Client>,
    tx: flume::Sender<(String, String, Vec<u8>)>,
    rx: flume::Receiver<(String, String, Vec<u8>)>,
}

impl SearchBoostQueue {
    pub fn new(
        db_path: String, 
        pepper: &SecretVec<u8>, 
        shield: Option<Arc<dyn iw_core::PiiShield + Send + Sync>>,
        grounding_shield: Option<Arc<dyn iw_core::GroundingShield + Send + Sync>>,
    ) -> Result<Self, SovereignError> {
        let conn = Connection::open(&db_path).map_err(|e| SovereignError::StorageError(format!("Failed to open SearchBoost DB: {}", e)))?;
        conn.busy_timeout(std::time::Duration::from_millis(10000)).map_err(|e| SovereignError::StorageError(e.to_string()))?;
        conn.execute_batch("
            PRAGMA journal_mode = WAL; 
            PRAGMA synchronous = NORMAL;
            PRAGMA secure_delete = ON;
            CREATE TABLE IF NOT EXISTS search_jobs (
                id TEXT PRIMARY KEY, 
                username TEXT, 
                thread_id TEXT, 
                query BLOB, 
                sealed_query BLOB, -- DEPRECATED (V-14 Fix): Column remains for schema compatibility but is no longer used.
                result BLOB,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        ").map_err(|e| SovereignError::StorageError(format!("Failed to initialize SearchBoost table: {}", e)))?;

        let redis_url = std::env::var("REDIS_URL").ok();
        let redis_client = redis_url.and_then(|url| redis::Client::open(url).ok());
        if redis_client.is_some() {
            info!("Redis HA Backend: ENABLED for SearchBoost Queue.");
        }

        let (tx, rx) = flume::unbounded();

        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        // Resilience: Recover pending jobs
        let tx_clone = tx.clone();
        let conn_clone = conn_arc.clone();
        if let Ok(conn) = conn_clone.lock() {
            if let Ok(mut stmt) = conn.prepare("SELECT id, username, query FROM search_jobs WHERE status = 'pending' ORDER BY created_at ASC") {
                if let Ok(mut rows) = stmt.query([]) {
                    while let Ok(Some(row)) = rows.next() {
                        if let (Ok(id), Ok(username), Ok(query)) = (row.get::<_, String>(0), row.get::<_, String>(1), row.get::<_, Vec<u8>>(2)) {
                            let _ = tx_clone.send((id, username, query));
                        }
                    }
                }
            }
        }

        let queue = Self {
            db_path, 
            pepper: Arc::new(SecretVec::new(pepper.expose_secret().to_vec())),
            conn: conn_arc,
            shield,
            grounding_shield,
            redis_client,
            tx,
            rx,
        };

        Ok(queue)
    }

    /// Spawns a background worker to process enqueued search jobs.
    pub fn spawn_worker(&self, librarian: Arc<crate::librarian::LocalLibrarian>) {
        let queue = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = queue.process_next_job(librarian.clone()).await {
                    if !matches!(e, SovereignError::DatabaseBusy(_)) {
                        error!("SearchBoost Worker Error: {}", e);
                    }
                }
            }
        });
    }

    /// Processes the next job in the queue (exposed for testing and orchestration).
    pub async fn process_next_job(&self, librarian: Arc<crate::librarian::LocalLibrarian>) -> Result<(), SovereignError> {
        let mut job: Option<(String, String, Vec<u8>)> = None;

        // --- HA FIX (WP 90): Poll Redis first for distributed jobs ---
        if let Some(ref client) = self.redis_client {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                // RPOP from global queue
                if let Ok(Some(job_id)) = con.rpop::<_, Option<String>>("iw:sb:queue", None).await {
                    // Fetch job details from Redis hash (to support cross-node processing)
                    let redis_key = format!("iw:sb:job:{}", job_id);
                    if let Ok(data) = con.hgetall::<_, HashMap<String, Vec<u8>>>(&redis_key).await {
                        if !data.is_empty() {
                            let username = String::from_utf8(data.get("username").cloned().unwrap_or_default()).unwrap_or_default();
                            let encrypted_sanitized = data.get("query").cloned().unwrap_or_default();
                            job = Some((job_id, username, encrypted_sanitized));
                        }
                    }
                }
            }
        }

        if job.is_none() {
            // Use the lock-free ring buffer for local queue
            if self.redis_client.is_some() {
                // If Redis is enabled, don't block forever to allow periodic Redis polling
                if let Ok(local_job) = tokio::time::timeout(Duration::from_secs(2), self.rx.recv_async()).await {
                    if let Ok(j) = local_job {
                        job = Some(j);
                    } else {
                        // Channel is disconnected, wait a bit to avoid hot loops
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            } else {
                // No Redis, block indefinitely until a new local job arrives
                if let Ok(j) = self.rx.recv_async().await {
                    job = Some(j);
                } else {
                    // Channel disconnected
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        if let Some((id, username, encrypted_sanitized)) = job {
            // 1. Decrypt Queries using centralized AadCipher (WP-98)
            let pepper = self.pepper.clone();
            let username_clone = username.clone();
            let decrypted_bytes = tokio::task::spawn_blocking(move || {
                AadCipher::decrypt(
                    &encrypted_sanitized,
                    &username_clone,
                    pepper.expose_secret(),
                    b"warden-v1-queue-encryption"
                )
            }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;
            let sanitized_query = String::from_utf8(decrypted_bytes)
                .map_err(|_| SovereignError::InternalError("Invalid UTF-8 in job data".into()))?;

            // 2. Perform Search (RAG)
            // --- SECURITY FIX (V-14 / WP-97): RAW Query Side-Channel REMOVED ---
            // Grounding now uses exclusively the sanitized query to prevent PII leakage into the RAG pipeline.
            info!(job_id = %id, user = %username, "Processing SearchBoost job (Sanitized Grounding)...");
            let results = librarian.retrieve_policy_context(&sanitized_query, &username, 3).await
                .map_err(|e| SovereignError::StorageError(e.to_string()))?;
            
            // --- SECURITY FIX (WP 68): Scrub retrieved context ---
            let mut scrubbed_results = Vec::new();
            if let Some(shield) = &self.shield {
                for res in results {
                    if let Ok(report) = shield.sanitize_prompt(&res, None).await {
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

            // 3. Encrypt Result using centralized AadCipher (WP-98)
            let pepper_clone = self.pepper.clone();
            let username_clone = username.clone();
            let encrypted_result = tokio::task::spawn_blocking(move || {
                AadCipher::encrypt(
                    consolidated_result.as_bytes(),
                    &username_clone,
                    pepper_clone.expose_secret(),
                    b"warden-v1-queue-encryption"
                )
            }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

            // 4. Update DB (and Redis if HA)
            if let Some(ref client) = self.redis_client {
                if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                    let redis_key = format!("iw:sb:job:{}", id);
                    let _: Result<(), _> = con.hset(&redis_key, "result", &encrypted_result).await;
                    let _: Result<(), _> = con.hset(&redis_key, "status", "complete").await;
                    let _: Result<(), _> = con.expire(&redis_key, 3600).await;
                }
            }

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

    /// Enqueues a job into the local SQLite-backed queue.
    /// --- SECURITY FIX (V-14 / WP-97): Removed sealed_query parameter ---
    pub async fn enqueue(
        &self,
        sanitized_query: String,
        _options: HashMap<String, serde_json::Value>,
        thread_id: String,
        username: String,
    ) -> Result<String, SovereignError> {
        let session_id = format!("SB-SESSION:{}:{}", username, thread_id);
        let job_id = format!("{}:{}", session_id, Uuid::new_v4());

        // Encrypt sanitized query using centralized AadCipher (WP-98)
        let pepper = self.pepper.clone();
        let username_clone = username.clone();
        let sanitized_query_clone = sanitized_query.clone();
        let encrypted_sanitized = tokio::task::spawn_blocking(move || {
            AadCipher::encrypt(
                sanitized_query_clone.as_bytes(),
                &username_clone,
                pepper.expose_secret(),
                b"warden-v1-queue-encryption"
            )
        }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

        // --- HA FIX (WP 90): Push to Redis for distributed processing ---
        if let Some(ref client) = self.redis_client {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let redis_key = format!("iw:sb:job:{}", job_id);
                let fields = vec![
                    ("username", username.as_bytes().to_vec()),
                    ("query", encrypted_sanitized.clone()),
                    ("status", b"pending".to_vec())
                ];
                let _: Result<(), _> = con.hset_multiple(&redis_key, &fields).await;
                let _: Result<(), _> = con.lpush("iw:sb:queue", &job_id).await;
            }
        }

        let username_clone = username.clone();
        let thread_id_clone = thread_id.clone();
        let job_id_clone = job_id.clone();
        let conn_arc = self.conn.clone();

        let encrypted_sanitized_clone = encrypted_sanitized.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn_arc.lock().map_err(|_| SovereignError::InternalError("Mutex poisoned".into()))?;
            conn.execute(
                "INSERT INTO search_jobs (id, username, thread_id, query) VALUES (?1, ?2, ?3, ?4)",
                (&job_id_clone, &username_clone, &thread_id_clone, &encrypted_sanitized_clone),
            ).map_err(|e| {
                if matches!(e, rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::DatabaseBusy) {
                    SovereignError::DatabaseBusy("SearchBoost Queue busy".into())
                } else {
                    SovereignError::StorageError(format!("Queue persistence failed: {}", e))
                }
            })?;
            Ok::<(), SovereignError>(())
        }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

        // Push to local lock-free ring buffer
        if let Err(e) = self.tx.send_async((job_id.clone(), username.clone(), encrypted_sanitized)).await {
            error!("Failed to push job to local channel: {}", e);
        }

        info!(job_id = %job_id, "Successfully enqueued encrypted SearchBoost job (Sanitized)");

        Ok(job_id)
    }

    pub async fn get_result(&self, job_id: &str, requester: &str, is_admin: bool) -> Result<Option<String>, SovereignError> {
        let job_id_str = job_id.to_string();
        
        // --- HA FIX (WP 90): Check Redis first for result ---
        let mut redis_data: Option<(String, Vec<u8>)> = None;
        if let Some(ref client) = self.redis_client {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let redis_key = format!("iw:sb:job:{}", job_id);
                if let Ok(data) = con.hgetall::<_, HashMap<String, Vec<u8>>>(&redis_key).await {
                    if data.get("status").map(|s| s == b"complete").unwrap_or(false) {
                        let username = String::from_utf8(data.get("username").cloned().unwrap_or_default()).unwrap_or_default();
                        let result_data = data.get("result").cloned().unwrap_or_default();
                        redis_data = Some((username, result_data));
                    }
                }
            }
        }

        let result_data = if let Some(d) = redis_data {
            Some(d)
        } else {
            let conn_arc = self.conn.clone();
            tokio::task::spawn_blocking(move || {
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
            }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??
        };

        let pepper = self.pepper.clone();
        match result_data {
            Some((username, data)) => {
                if !is_admin && username != requester {
                    return Err(SovereignError::UnauthorizedAccess("You do not have permission to access this job result".into()));
                }
                if data.is_empty() { return Ok(None); }
                
                let decrypted_string = tokio::task::spawn_blocking(move || {
                    // Decrypt result using centralized AadCipher (WP-98)
                    let decrypted_bytes = AadCipher::decrypt(
                        &data,
                        &username,
                        pepper.expose_secret(),
                        b"warden-v1-queue-encryption"
                    )?;

                    String::from_utf8(decrypted_bytes).map_err(|e| SovereignError::InternalError(e.to_string()))
                }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

                Ok(Some(decrypted_string))
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
    pepper: Arc<SecretVec<u8>>,
    conn: Arc<std::sync::Mutex<Connection>>,
    redis_client: Option<redis::Client>,
}

impl LocalSessionManager {
    pub fn new(db_path: String, pepper: &SecretVec<u8>) -> Result<Arc<Self>, SovereignError> {
        let conn = Connection::open(&db_path).map_err(|e| SovereignError::StorageError(format!("Failed to open Session DB: {}", e)))?;
        conn.busy_timeout(std::time::Duration::from_millis(10000)).map_err(|e| SovereignError::StorageError(e.to_string()))?;
        conn.execute_batch("
            PRAGMA journal_mode = WAL; 
            PRAGMA synchronous = NORMAL;
            PRAGMA secure_delete = ON;
            CREATE TABLE IF NOT EXISTS sessions (username TEXT PRIMARY KEY, session_data TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        ").map_err(|e| SovereignError::StorageError(format!("Failed to set PRAGMAs or create sessions table: {}", e)))?;

        let redis_url = std::env::var("REDIS_URL").ok();
        let redis_client = redis_url.and_then(|url| redis::Client::open(url).ok());
        if redis_client.is_some() {
            info!("Redis HA Backend: ENABLED for Session Management.");
        }

        let manager = Arc::new(Self {
            sessions: DashMap::new(),
            db_path: db_path.clone(),
            pepper: Arc::new(SecretVec::new(pepper.expose_secret().to_vec())),
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

        Ok(manager)
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

        let username_str = username.to_string();
        let pepper = self.pepper.clone();
        let ctx = match encrypted_data {
            Some(data) => {
                let res = tokio::task::spawn_blocking(move || {
                    // Decrypt session using centralized AadCipher (WP-98)
                    let decrypted = AadCipher::decrypt(
                        &data,
                        &username_str,
                        pepper.expose_secret(),
                        b"warden-v1-session-encryption"
                    ).map_err(|e| SovereignError::InternalError(format!("Session decryption failed: {}", e)))?;

                    let state: SessionState = serde_json::from_slice(&decrypted)
                        .map_err(|e| SovereignError::InternalError(format!("Session corruption: {}", e)))?;
                    Ok::<Arc<SessionContext>, SovereignError>(Arc::new(SessionContext::from(state)))
                }).await;
                match res {
                    Ok(Ok(ctx)) => ctx,
                    Ok(Err(e)) => return Err(e),
                    Err(e) => return Err(SovereignError::InternalError(format!("Blocking task failed: {}", e))),
                }
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
        
        let username_str = username.to_string();
        let conn_arc = self.conn.clone();
        let pepper = self.pepper.clone();
        
        let combined = tokio::task::spawn_blocking(move || {
            // Encrypt session using centralized AadCipher (WP-98)
            let combined = AadCipher::encrypt(
                &json_bytes,
                &username_str,
                pepper.expose_secret(),
                b"warden-v1-session-encryption"
            )?;

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
            Ok::<Vec<u8>, SovereignError>(combined)
        }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

        // --- HA FIX (WP 90): Write to Redis for HA Clustered Access ---
        if let Some(ref client) = self.redis_client {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let redis_key = format!("iw:session:{}", username);
                let _: Result<(), _> = con.set_ex(&redis_key, &combined, 86400).await; // 24h TTL
            }
        }

        Ok(())
    }

    async fn flush_to_db(&self) -> Result<(), SovereignError> {
        let mut sessions_to_flush: Vec<(String, Vec<u8>)> = Vec::new();
        
        for item in self.sessions.iter() {
            let username = item.key().clone();
            let state = SessionState::from(item.value().as_ref());
            let json_bytes = serde_json::to_vec(&state).unwrap_or_default();
            let pepper = self.pepper.clone();
            
            // Encrypt session using centralized AadCipher (WP-98)
            let combined_res = tokio::task::spawn_blocking(move || {
                AadCipher::encrypt(
                    &json_bytes,
                    &username,
                    pepper.expose_secret(),
                    b"warden-v1-session-encryption"
                )
            }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))?;

            if let Ok(combined) = combined_res {
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
