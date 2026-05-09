use async_trait::async_trait;
use iw_core::{SovereignError, StorageProvider, ScrubbingReport};
use crate::audit::AsyncAuditor;
use crate::searchboost::SearchBoostQueue;
use crate::librarian::LocalLibrarian;
use rusqlite::{Connection, ErrorCode};
use std::sync::Arc;
use secrecy::SecretVec;

/// The "Librarian" aggregator that provides the full StorageProvider trait implementation.
pub struct WorkerStorage {
    auditor: AsyncAuditor,
    sb_queue: Option<SearchBoostQueue>,
    librarian: LocalLibrarian,
    db_path: String,
    conn: Arc<std::sync::Mutex<Connection>>,
}

impl WorkerStorage {
    pub async fn new(
        audit_db_path: &str, 
        knowledge_base_path: &str,
        pepper: SecretVec<u8>,
        sb_queue: Option<SearchBoostQueue>,
    ) -> Result<Self, SovereignError> {
        // Await the spawn to ensure DB is writable before boot
        let auditor = AsyncAuditor::spawn(audit_db_path, pepper).await
            .map_err(|e| SovereignError::StorageError(format!("Failed to initialize Async Auditor: {}", e)))?;
        
        let librarian = LocalLibrarian::new(knowledge_base_path).await
            .map_err(|e| SovereignError::StorageError(format!("Failed to initialize Librarian: {}", e)))?;

        let conn = Connection::open(audit_db_path)
            .map_err(|e| SovereignError::StorageError(format!("Failed to open storage DB: {}", e)))?;
        conn.busy_timeout(std::time::Duration::from_millis(2000))
            .map_err(|e| SovereignError::StorageError(format!("Failed to set busy timeout: {}", e)))?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")
            .map_err(|e| SovereignError::StorageError(format!("Failed to set PRAGMAs: {}", e)))?;

        Ok(Self { 
            auditor,
            sb_queue,
            librarian,
            db_path: audit_db_path.to_string(),
            conn: Arc::new(std::sync::Mutex::new(conn)),
        })
    }

    pub async fn validate_thread_access(&self, thread_id: &str, username: &str) -> Result<bool, SovereignError> {
        let thread_id = thread_id.to_string();
        let username = username.to_string();
        let conn_arc = self.conn.clone();

        let exists = tokio::task::spawn_blocking(move || {
            let conn = conn_arc.lock().map_err(|_| SovereignError::InternalError("Mutex poisoned".into()))?;
            let mut stmt = conn.prepare(
                "SELECT EXISTS(SELECT 1 FROM threads WHERE id = ?1 AND username = ?2)"
            ).map_err(|e| SovereignError::StorageError(e.to_string()))?;
            let exists: bool = stmt.query_row([thread_id, username], |row| row.get(0)).map_err(|e| {
                if matches!(e, rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::DatabaseBusy) {
                    SovereignError::DatabaseBusy("Storage DB busy".into())
                } else {
                    SovereignError::StorageError(e.to_string())
                }
            })?;
            Ok::<bool, SovereignError>(exists)
        }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

        Ok(exists)
    }

    pub async fn enqueue_search(
        &self,
        query: String,
        options: std::collections::HashMap<String, serde_json::Value>,
        thread_id: String,
        username: String,
    ) -> Result<String, SovereignError> {
        if !self.validate_thread_access(&thread_id, &username).await? {
            return Err(SovereignError::UnauthorizedAccess(format!("User {} denied access to thread {}", username, thread_id)));
        }

        let queue = self.sb_queue.as_ref()
            .ok_or_else(|| SovereignError::StorageError("SearchBoost Queue not initialized".into()))?;
            
        let job_id = queue.enqueue(query, options, thread_id.clone(), username.clone()).await?;

        Ok(job_id)
    }
}

#[async_trait]
impl StorageProvider for WorkerStorage {
    async fn fetch_context(&self, query: &str) -> Result<Vec<String>, SovereignError> {
        self.librarian.retrieve_policy_context(query, 5).await
            .map_err(|e| SovereignError::StorageError(format!("Retrieval Failure: {}", e)))
    }

    async fn log_audit_event(&self, report: &ScrubbingReport, raw_input: &str) -> Result<(), SovereignError> {
        self.auditor.log_report(report.clone(), raw_input.to_string()).await
    }

    async fn validate_job_access(&self, job_id: &str, username: &str) -> Result<bool, SovereignError> {
        let job_id = job_id.to_string();
        let username = username.to_string();
        let conn_arc = self.conn.clone();

        let exists = tokio::task::spawn_blocking(move || {
            let conn = conn_arc.lock().map_err(|_| SovereignError::InternalError("Mutex poisoned".into()))?;
            let mut stmt = conn.prepare(
                "SELECT EXISTS(SELECT 1 FROM search_jobs WHERE id = ?1 AND username = ?2)"
            ).map_err(|e| SovereignError::StorageError(e.to_string()))?;
            let exists: bool = stmt.query_row([job_id, username], |row| row.get(0)).map_err(|e| {
                if matches!(e, rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::DatabaseBusy) {
                    SovereignError::DatabaseBusy("Storage DB busy".into())
                } else {
                    SovereignError::StorageError(e.to_string())
                }
            })?;
            Ok::<bool, SovereignError>(exists)
        }).await.map_err(|e| SovereignError::InternalError(format!("Blocking task failed: {}", e)))??;

        Ok(exists)
    }
}
