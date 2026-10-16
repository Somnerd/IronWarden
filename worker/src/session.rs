use crate::grounding::get_redis_con;
use dashmap::DashMap;
use iw_core::{AadCipher, SessionContext, SessionState, SovereignError};
use r2d2_sqlite::SqliteConnectionManager;
use redis::AsyncCommands;
use rusqlite::ErrorCode;
use secrecy::{ExposeSecret, SecretVec};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{error, info};

pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

/// Consolidated Local Session Manager.
pub struct LocalSessionManager {
    #[doc(hidden)]
    pub sessions: DashMap<String, Arc<SessionContext>>,
    flushed_at: DashMap<String, u64>,
    #[allow(dead_code)]
    db_path: String,
    pepper: Arc<SecretVec<u8>>,
    pool: r2d2::Pool<SqliteConnectionManager>,
    redis_client: Option<redis::Client>,
}

impl LocalSessionManager {
    pub fn new(db_path: String, pepper: &SecretVec<u8>) -> Result<Arc<Self>, SovereignError> {
        let manager = SqliteConnectionManager::file(&db_path).with_init(|c| {
            c.busy_timeout(std::time::Duration::from_millis(10000))?;
            c.execute_batch(
                "
                    PRAGMA journal_mode = WAL; 
                    PRAGMA synchronous = NORMAL;
                    PRAGMA secure_delete = ON;
                ",
            )?;
            Ok(())
        });

        let pool = r2d2::Pool::builder()
            .max_size(15)
            .build(manager)
            .map_err(|e| {
                SovereignError::StorageError(format!("Failed to create connection pool: {}", e))
            })?;

        let conn = pool.get().map_err(|e| {
            SovereignError::StorageError(format!("Failed to get connection from pool: {}", e))
        })?;
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS sessions (username TEXT PRIMARY KEY, session_data TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        ").map_err(|e| SovereignError::StorageError(format!("Failed to create sessions table: {}", e)))?;

        let redis_url = std::env::var("REDIS_URL").ok();
        let redis_client = redis_url.and_then(|url| redis::Client::open(url).ok());
        if redis_client.is_some() {
            info!("Redis HA Backend: ENABLED for Session Management.");
        }

        let manager = Arc::new(Self {
            sessions: DashMap::new(),
            flushed_at: DashMap::new(),
            db_path: db_path.clone(),
            pepper: Arc::new(SecretVec::new(pepper.expose_secret().to_vec())),
            pool,
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
                manager_clone.evict_idle_sessions();
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
        let pool = self.pool.clone();

        let mut encrypted_data = iw_core::executor::BlockingExecutor::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| SovereignError::InternalError(format!("Pool error: {}", e)))?;
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
                if let Some(mut con) = get_redis_con(client).await {
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
                let res = iw_core::executor::BlockingExecutor::spawn_blocking(move || {
                    // Decrypt session using centralized AadCipher (WP-98)
                    let decrypted = AadCipher::decrypt(
                        &data,
                        &username_str,
                        pepper.expose_secret(),
                        b"warden-v1-session-encryption",
                    )
                    .map_err(|e| {
                        SovereignError::InternalError(format!("Session decryption failed: {}", e))
                    })?;

                    let state: SessionState = serde_json::from_slice(&decrypted).map_err(|e| {
                        SovereignError::InternalError(format!("Session corruption: {}", e))
                    })?;
                    Ok::<Arc<SessionContext>, SovereignError>(Arc::new(SessionContext::from(state)))
                })
                .await;
                match res {
                    Ok(Ok(ctx)) => ctx,
                    Ok(Err(e)) => return Err(e),
                    Err(e) => {
                        return Err(SovereignError::InternalError(format!(
                            "Blocking task failed: {}",
                            e
                        )))
                    }
                }
            }
            None => Arc::new(SessionContext::new()),
        };

        ctx.touch();
        self.sessions.insert(username.to_string(), ctx.clone());
        Ok(ctx)
    }

    pub async fn save_session(
        &self,
        username: &str,
        ctx: &SessionContext,
    ) -> Result<(), SovereignError> {
        let state = SessionState::from(ctx);
        let json_bytes = serde_json::to_vec(&state).unwrap_or_default();

        let username_str = username.to_string();
        let pool = self.pool.clone();
        let pepper = self.pepper.clone();

        let combined = iw_core::executor::BlockingExecutor::spawn_blocking(move || {
            // Encrypt session using centralized AadCipher (WP-98)
            let combined = AadCipher::encrypt(
                &json_bytes,
                &username_str,
                pepper.expose_secret(),
                b"warden-v1-session-encryption"
            )?;

            let conn = pool.get().map_err(|e| SovereignError::InternalError(format!("Pool error: {}", e)))?;
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
            if let Some(mut con) = get_redis_con(client).await {
                let redis_key = format!("iw:session:{}", username);
                let _: Result<(), _> = con.set_ex(&redis_key, &combined, 86400).await;
                // 24h TTL
            }
        }

        self.flushed_at
            .insert(username.to_string(), ctx.last_accessed());

        Ok(())
    }

    pub async fn flush_to_db(&self) -> Result<(), SovereignError> {
        let mut sessions_to_flush: Vec<(String, Vec<u8>, u64)> = Vec::new();

        for item in self.sessions.iter() {
            let username = item.key().clone();
            let last_accessed = item.value().last_accessed();
            let last_flushed = self.flushed_at.get(&username).map(|v| *v).unwrap_or(0);

            // Only flush sessions that were modified/active
            if last_accessed <= last_flushed {
                continue;
            }

            let state = SessionState::from(item.value().as_ref());
            let json_bytes = serde_json::to_vec(&state).unwrap_or_default();
            let pepper = self.pepper.clone();
            let username_c = username.clone();

            // Encrypt session using centralized AadCipher (WP-98)
            let combined_res = iw_core::executor::BlockingExecutor::spawn_blocking(move || {
                AadCipher::encrypt(
                    &json_bytes,
                    &username_c,
                    pepper.expose_secret(),
                    b"warden-v1-session-encryption",
                )
            })
            .await
            .map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))?;

            if let Ok(combined) = combined_res {
                sessions_to_flush.push((username, combined, last_accessed));
            }
        }

        if sessions_to_flush.is_empty() {
            return Ok(());
        }

        let db_payload: Vec<(String, Vec<u8>)> = sessions_to_flush
            .iter()
            .map(|(u, d, _)| (u.clone(), d.clone()))
            .collect();
        let num_flushed = db_payload.len();

        let pool = self.pool.clone();
        iw_core::executor::BlockingExecutor::spawn_blocking(move || {
            let mut conn = pool.get().map_err(|e| SovereignError::InternalError(format!("Pool error: {}", e)))?;
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(|e| {
                if matches!(e, rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::DatabaseBusy) {
                    SovereignError::DatabaseBusy("Session DB busy".into())
                } else {
                    SovereignError::StorageError(e.to_string())
                }
            })?;
            for (username, encrypted_data) in db_payload {
                tx.execute(
                    "INSERT INTO sessions (username, session_data, updated_at) VALUES (?1, ?2, CURRENT_TIMESTAMP)
                     ON CONFLICT(username) DO UPDATE SET session_data = ?2, updated_at = CURRENT_TIMESTAMP",
                    (&username, &encrypted_data),
                ).map_err(|e| SovereignError::StorageError(e.to_string()))?;
            }
            tx.commit().map_err(|e| SovereignError::StorageError(e.to_string()))?;
            Ok::<(), SovereignError>(())
        }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

        for (username, _, accessed_at) in sessions_to_flush {
            self.flushed_at
                .entry(username)
                .and_modify(|ts| {
                    if accessed_at > *ts {
                        *ts = accessed_at;
                    }
                })
                .or_insert(accessed_at);
        }

        info!(
            "Successfully encrypted and flushed {} active/modified sessions to SQLite",
            num_flushed
        );
        Ok(())
    }

    pub fn evict_idle_sessions(&self) -> usize {
        self.evict_idle_sessions_older_than(SESSION_IDLE_TIMEOUT)
    }

    pub fn evict_idle_sessions_older_than(&self, timeout: Duration) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let timeout_secs = timeout.as_secs();
        let mut evicted = 0;
        self.sessions.retain(|username, ctx| {
            let last_accessed = ctx.last_accessed();
            if now.saturating_sub(last_accessed) >= timeout_secs {
                self.flushed_at.remove(username);
                evicted += 1;
                false
            } else {
                true
            }
        });
        if evicted > 0 {
            info!("Evicted {} idle sessions from memory cache", evicted);
        }
        evicted
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
