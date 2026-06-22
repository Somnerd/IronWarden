use async_trait::async_trait;
use iw_core::{SovereignError, StorageProvider, ScrubbingReport, ComplianceReport};
use crate::audit::AsyncAuditor;
use crate::searchboost::SearchBoostQueue;
use crate::librarian::LocalLibrarian;
use tokio_rusqlite::Connection;
use rusqlite::ErrorCode;
use std::sync::Arc;
use secrecy::SecretVec;
use tracing::info;

/// The "Librarian" aggregator that provides the full StorageProvider trait implementation.
pub struct WorkerStorage {
    auditor: AsyncAuditor,
    sb_queue: Option<SearchBoostQueue>,
    librarian: Arc<LocalLibrarian>,
    db_path: String,
    conn: Connection,
}

impl WorkerStorage {
    pub async fn new(
        audit_db_path: &str, 
        knowledge_base_path: &str,
        pepper: SecretVec<u8>,
        sb_queue: Option<SearchBoostQueue>,
        remote_forwarder: Option<Arc<dyn crate::audit::RemoteAuditForwarder>>,
    ) -> Result<Self, SovereignError> {
        // Await the spawn to ensure DB is writable before boot
        let auditor = AsyncAuditor::spawn(audit_db_path, pepper, remote_forwarder).await
            .map_err(|e| SovereignError::StorageError(format!("Failed to initialize Async Auditor: {}", e)))?;
        
        let librarian = LocalLibrarian::new(knowledge_base_path).await
            .map_err(|e| SovereignError::StorageError(format!("Failed to initialize Librarian: {}", e)))?;

        let conn = Connection::open(audit_db_path).await
            .map_err(|e| SovereignError::StorageError(format!("Failed to open storage DB: {}", e)))?;
        conn.call(|c| {
            c.busy_timeout(std::time::Duration::from_millis(2000))?;
            c.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA secure_delete = ON;")?;
            Ok::<(), rusqlite::Error>(())
        }).await.map_err(|e| SovereignError::StorageError(format!("Failed to set PRAGMAs: {}", e)))?;

        let storage = Self { 
            auditor,
            sb_queue: sb_queue.clone(),
            librarian: Arc::new(librarian),
            db_path: audit_db_path.to_string(),
            conn: conn.clone(),
        };

        if let Some(queue) = sb_queue {
            queue.spawn_worker(storage.librarian.clone());
            info!("SearchBoost background worker ignited.");
        }

        let db_path_clone = audit_db_path.to_string();
        let conn_clone = storage.conn.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let path_c = std::ffi::CString::new(db_path_clone.clone()).unwrap_or_default();
                if path_c.as_bytes().is_empty() { continue; }
                let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
                if unsafe { libc::statvfs(path_c.as_ptr(), &mut stat) } == 0 {
                    let total = stat.f_blocks.saturating_mul(stat.f_frsize);
                    let avail = stat.f_bavail.saturating_mul(stat.f_frsize);
                    if total > 0 {
                        let percent_avail = (avail as f64 / total as f64) * 100.0;
                        if percent_avail < 10.0 {
                            tracing::warn!("WARNING: Disk space below 10% ({:.1}%). Triggering automatic purge of transient ephemeral logs older than 1 hour to prevent DatabaseFull hard-stops.", percent_avail);
                            let _ = conn_clone.call(|c| {
                                let cutoff = chrono::Utc::now() - chrono::Duration::hours(1);
                                let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();
                                c.execute("DELETE FROM ephemeral_raw_logs WHERE timestamp < ?1", [&cutoff_str])?;
                                Ok::<(), rusqlite::Error>(())
                            }).await;
                        }
                    }
                }
            }
        });

        Ok(storage)
    }

    pub async fn validate_thread_access(&self, thread_id: &str, username: &str) -> Result<bool, SovereignError> {
        let thread_id = thread_id.to_string();
        let username = username.to_string();
        let exists = self.conn.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT EXISTS(SELECT 1 FROM threads WHERE id = ?1 AND username = ?2)"
            )?;
            let exists: bool = stmt.query_row([thread_id, username], |row| row.get(0))?;
            Ok::<bool, rusqlite::Error>(exists)
        }).await.map_err(|e| {
            let err_str = e.to_string().to_lowercase();
            if err_str.contains("busy") || err_str.contains("locked") {
                SovereignError::DatabaseBusy("Storage DB busy".into())
            } else {
                SovereignError::StorageError(e.to_string())
            }
        })?;

        Ok(exists)
    }

    pub async fn enqueue_search(
        &self,
        sanitized_query: String,
        options: std::collections::HashMap<String, serde_json::Value>,
        thread_id: String,
        username: String,
    ) -> Result<String, SovereignError> {
        if !self.validate_thread_access(&thread_id, &username).await? {
            return Err(SovereignError::UnauthorizedAccess(format!("User {} denied access to thread {}", username, thread_id)));
        }

        let queue = self.sb_queue.as_ref()
            .ok_or_else(|| SovereignError::StorageError("SearchBoost Queue not initialized".into()))?;
            
        let job_id = queue.enqueue(sanitized_query, options, thread_id.clone(), username.clone()).await?;

        Ok(job_id)
    }
}

#[async_trait]
impl StorageProvider for WorkerStorage {
    async fn fetch_context(&self, query: &str, username: &str) -> Result<Vec<String>, SovereignError> {
        self.librarian.retrieve_policy_context(query, username, 5).await
            .map_err(|e| SovereignError::StorageError(format!("Retrieval Failure: {}", e)))
    }

    async fn log_audit_event(&self, report: &ScrubbingReport, raw_input: &str, username: &str) -> Result<(), SovereignError> {
        self.auditor.log_report(report.clone(), raw_input.to_string(), username.to_string()).await
    }

    async fn validate_job_access(&self, job_id: &str, username: &str) -> Result<bool, SovereignError> {
        let job_id = job_id.to_string();
        let username = username.to_string();
        let exists = self.conn.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT EXISTS(SELECT 1 FROM search_jobs WHERE id = ?1 AND username = ?2)"
            )?;
            let exists: bool = stmt.query_row([job_id, username], |row| row.get(0))?;
            Ok::<bool, rusqlite::Error>(exists)
        }).await.map_err(|e| {
            let err_str = e.to_string().to_lowercase();
            if err_str.contains("busy") || err_str.contains("locked") {
                SovereignError::DatabaseBusy("Storage DB busy".into())
            } else {
                SovereignError::StorageError(e.to_string())
            }
        })?;

        Ok(exists)
    }

    async fn purge_user_data(&self, username: &str) -> Result<(), SovereignError> {
        let username_str = username.to_string();
        
        // 1. Purge from Audit Ledger (via Auditor)
        self.auditor.purge_user(username).await?;

        // 2. Purge from Vector Store (via Librarian)
        self.librarian.delete_user_documents(username).await
            .map_err(|e| SovereignError::StorageError(format!("Librarian purge failed: {}", e)))?;

        // 3. Purge from Main Storage DB (Threads, Sessions, Jobs)
        let username_str2 = username_str.clone();
        self.conn.call(move |conn| {
            conn.execute("DELETE FROM search_jobs WHERE username = ?1", [&username_str2])?;
            conn.execute("DELETE FROM threads WHERE username = ?1", [&username_str2])?;
            conn.execute("DELETE FROM sessions WHERE username = ?1", [&username_str2])?;
            Ok::<(), rusqlite::Error>(())
        }).await.map_err(|e| SovereignError::StorageError(e.to_string()))?;

        Ok(())
    }

    async fn check_health(&self) -> Result<(), SovereignError> {
        self.auditor.check_health()?;

        self.conn.call(|conn| {
            conn.query_row("SELECT 1", [], |_| Ok(()))
        }).await.map_err(|e| SovereignError::StorageError(e.to_string()))?;

        self.librarian.check_health().await
            .map_err(|e| SovereignError::StorageError(format!("Librarian Unhealthy: {}", e)))?;

        Ok(())
    }

    async fn get_compliance_report(&self) -> Result<ComplianceReport, SovereignError> {
        let stats = self.auditor.get_compliance_stats()?;
        Ok(ComplianceReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            total_redactions: stats.0,
            total_blocks: stats.1,
            period_start: stats.2,
            period_end: stats.3,
            integrity_hash: stats.4,
        })
    }
}
