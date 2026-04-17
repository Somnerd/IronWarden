use rusqlite::Connection;
use std::sync::Arc;

/// A synchronous auditor that manages a local SQLite database for security logging.
pub struct SqliteAuditor {
    db_path: Arc<String>,
}

impl SqliteAuditor {
    /// Connects to the audit database and ensures the schema is initialized.
    pub fn new(db_path: &str) -> rusqlite::Result<Self> {
        let path = db_path.to_string();
        let conn = Connection::open(&path)?;
        
        // Initialize the audit trail table as per spec
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY,
                event_type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        Ok(Self {
            db_path: Arc::new(path),
        })
    }

    /// Returns the database path for use in blocking task threads.
    pub fn db_path(&self) -> Arc<String> {
        self.db_path.clone()
    }
}
