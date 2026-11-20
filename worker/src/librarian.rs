use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use tokio_rusqlite::Connection;
use tracing::info;

/// The Librarian provides local heuristic grounding for policy enforcement.
/// It uses SQLite FTS5 (`unicode61` tokenizer + BM25 ranking) for high-performance
/// indexed search and local data sovereignty.
pub struct LocalLibrarian {
    db: Connection,
}

static STOP_WORDS: std::sync::LazyLock<std::collections::HashSet<&'static str>> =
    std::sync::LazyLock::new(|| {
        [
            "the", "a", "an", "and", "or", "but", "if", "then", "else", "to", "of", "in", "on",
            "at", "by", "for", "with", "about", "against", "between", "into", "through", "during",
            "before", "after", "above", "below", "from", "up", "down", "out", "over", "under",
            "again", "further", "once", "here", "there", "when", "where", "why", "how", "all",
            "any", "both", "each", "few", "more", "most", "other", "some", "such", "no", "nor",
            "not", "only", "own", "same", "so", "than", "too", "very", "can", "will", "just",
            "should", "now", "me", "tell", "who", "is", "it",
        ]
        .iter()
        .cloned()
        .collect()
    });

impl LocalLibrarian {
    pub async fn new(path: &str) -> Result<Self> {
        let base_path = Path::new(path);
        if !base_path.exists() {
            fs::create_dir_all(base_path).context("Failed to create knowledge base directory")?;
        }

        // --- SECURITY FIX (V-28): Path Traversal Protection ---
        let canonical_path = fs::canonicalize(base_path)?;
        if Path::new(path).is_relative() {
            let current_dir = fs::canonicalize(std::env::current_dir()?)?;
            if !canonical_path.starts_with(&current_dir) {
                return Err(anyhow::anyhow!(
                    "Librarian: Potential Path Traversal attempt: {}",
                    path
                ));
            }
        }

        let db_path = if canonical_path.is_dir() {
            canonical_path.join("librarian.db")
        } else {
            canonical_path
        };

        let db = Connection::open(&db_path)
            .await
            .context("Failed to connect to Librarian SQLite DB")?;

        db.call(|conn| {
            conn.busy_timeout(std::time::Duration::from_millis(5000))?;
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA secure_delete = ON;
                 CREATE TABLE IF NOT EXISTS documents (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     text TEXT NOT NULL,
                     username TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS idx_documents_username ON documents(username);
                 CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
                     text,
                     content='documents',
                     content_rowid='id',
                     tokenize='unicode61'
                 );
                 CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
                     INSERT INTO documents_fts(rowid, text) VALUES (new.id, new.text);
                 END;
                 CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
                     INSERT INTO documents_fts(documents_fts, rowid, text) VALUES('delete', old.id, old.text);
                 END;
                 CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
                     INSERT INTO documents_fts(documents_fts, rowid, text) VALUES('delete', old.id, old.text);
                     INSERT INTO documents_fts(rowid, text) VALUES (new.id, new.text);
                 END;
                 INSERT INTO documents_fts(documents_fts) VALUES('rebuild');",
            )?;
            Ok::<(), rusqlite::Error>(())
        })
        .await
        .context("Failed to initialize Librarian SQLite FTS5 schema")?;

        info!(
            "Librarian: SQLite FTS5 Engine initialized at {}",
            db_path.display()
        );

        Ok(Self { db })
    }

    /// Performs indexed SQLite FTS5 search with BM25 relevance ranking, scoped strictly to `username`.
    pub async fn retrieve_policy_context(
        &self,
        query: &str,
        username: &str,
        limit: usize,
    ) -> Result<Vec<String>> {
        let query_lower = query.to_lowercase();
        let query_terms: Vec<String> = query_lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty() && !STOP_WORDS.contains(s))
            .map(|s| s.to_string())
            .collect();

        let terms_to_use: Vec<String> = if query_terms.is_empty() {
            query_lower
                .split(|c: char| !c.is_alphanumeric())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        } else {
            query_terms
        };

        if terms_to_use.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }

        // Quote every alphanumeric token to isolate FTS5 reserved keywords (AND/OR/NOT/NEAR)
        let fts_query = terms_to_use
            .iter()
            .map(|t| format!("\"{}\"*", t))
            .collect::<Vec<_>>()
            .join(" AND ");

        // --- SECURITY FIX (Section 1.1 / Finding A.4): User-Level Partitioning ---
        let username = username.to_string();
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let results = self
            .db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT d.text \
                     FROM documents_fts f \
                     JOIN documents d ON d.id = f.rowid \
                     WHERE documents_fts MATCH ?1 AND d.username = ?2 \
                     ORDER BY bm25(documents_fts) \
                     LIMIT ?3",
                )?;
                let mut rows = stmt.query((&fts_query, &username, limit_i64))?;
                let mut matched_docs = Vec::new();

                while let Some(row) = rows.next()? {
                    matched_docs.push(row.get::<_, String>(0)?);
                }

                Ok::<Vec<String>, rusqlite::Error>(matched_docs)
            })
            .await
            .context("Failed to retrieve policy context from Librarian SQLite FTS5 DB")?;

        Ok(results)
    }

    /// GDPR Compliance: Purges all documents associated with a user from the store.
    pub async fn delete_user_documents(&self, username: &str) -> Result<()> {
        // --- SECURITY FIX (Section 1.1 / Finding A.3): GDPR Compliance ---
        // Triggers (`documents_ad`) automatically purge matching entries from `documents_fts`.
        let username_owned = username.to_string();
        self.db
            .call(move |conn| {
                conn.execute(
                    "DELETE FROM documents WHERE username = ?1",
                    [&username_owned],
                )?;
                Ok::<(), rusqlite::Error>(())
            })
            .await
            .context("Failed to delete user documents from Librarian SQLite DB")?;

        info!("Librarian: Purged all documents for user {}", username);
        Ok(())
    }

    pub async fn check_health(&self) -> Result<()> {
        self.db
            .call(|conn| {
                conn.execute_batch("SELECT 1;")?;
                Ok::<(), rusqlite::Error>(())
            })
            .await
            .context("Librarian SQLite health check failed")?;
        Ok(())
    }

    /// Helper to add a document (for testing/ingestion)
    pub async fn add_document(&self, text: &str, username: &str) -> Result<()> {
        let text = text.to_string();
        let username = username.to_string();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO documents (text, username) VALUES (?1, ?2)",
                    [&text, &username],
                )?;
                Ok::<(), rusqlite::Error>(())
            })
            .await
            .context("Failed to add document")?;

        Ok(())
    }
}
