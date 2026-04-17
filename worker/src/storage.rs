use async_trait::async_trait;
use iw_core::{SovereignError, StorageProvider};
use crate::audit::SqliteAuditor;
use crate::rag::LanceDbProvider;
use rusqlite::params;

/// The "Librarian" aggregator that provides the full StorageProvider trait implementation
/// by delegating to specialized internal modules.
pub struct WorkerStorage {
    auditor: SqliteAuditor,
    rag: LanceDbProvider,
}

impl WorkerStorage {
    /// Creates a new WorkerStorage instance.
    pub fn new(db_path: &str) -> Result<Self, SovereignError> {
        let auditor = SqliteAuditor::new(db_path)
            .map_err(|e| SovereignError::StorageError(format!("Failed to initialize Auditor: {}", e)))?;
        let rag = LanceDbProvider::new();
        
        Ok(Self { auditor, rag })
    }
}

#[async_trait]
impl StorageProvider for WorkerStorage {
    async fn fetch_context(&self, _query: &str) -> Result<Vec<String>, SovereignError> {
        // Delegates to the mocked RAG provider
        Ok(self.rag.fetch_mock_context())
    }

    async fn log_audit_event(&self, event: &str) -> Result<(), SovereignError> {
        let db_path = self.auditor.db_path();
        let event = event.to_string();

        // Safety: bridge synchronous rusqlite to async runtime via spawn_blocking
        tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&*db_path)
                .map_err(|e| SovereignError::StorageError(format!("DB Connection Error: {}", e)))?;
            
            conn.execute(
                "INSERT INTO audit_logs (event_type) VALUES (?1)",
                params![event],
            )
            .map_err(|e| SovereignError::StorageError(format!("DB Write Error: {}", e)))?;
            
            Ok::<(), SovereignError>(())
        })
        .await
        .map_err(|e| SovereignError::StorageError(format!("Async Task Panic: {}", e)))?
    }
}
