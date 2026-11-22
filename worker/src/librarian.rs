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
            "should", "now", "me", "tell", "who", "is", "it", "what", "which", "whom", "whose",
            "this", "that", "these", "those", "am", "are", "was", "were", "be", "been", "being",
            "have", "has", "had", "do", "does", "did", "shall", "would", "could", "may", "might",
            "must", "i", "you", "he", "she", "we", "they", "my", "your", "his", "her", "its",
            "our", "their", "please",
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
                 CREATE INDEX IF NOT EXISTS idx_documents_username ON documents(username);",
            )?;

            // Upgrade any single-column FTS5 table so tenant `username` is indexed directly in FTS5
            let existing_fts_sql: Option<String> = conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='documents_fts'",
                    [],
                    |row| row.get(0),
                )
                .ok();
            if existing_fts_sql
                .as_deref()
                .is_some_and(|sql| !sql.contains("username"))
            {
                conn.execute_batch(
                    "DROP TRIGGER IF EXISTS documents_ai;
                     DROP TRIGGER IF EXISTS documents_ad;
                     DROP TRIGGER IF EXISTS documents_au;
                     DROP TABLE IF EXISTS documents_fts;",
                )?;
            }

            conn.execute_batch(
                "CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
                     username,
                     text,
                     content='documents',
                     content_rowid='id',
                     tokenize='unicode61'
                 );
                 CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
                     INSERT INTO documents_fts(rowid, username, text) VALUES (new.id, new.username, new.text);
                 END;
                 CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
                     INSERT INTO documents_fts(documents_fts, rowid, username, text) VALUES('delete', old.id, old.username, old.text);
                 END;
                 CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
                     INSERT INTO documents_fts(documents_fts, rowid, username, text) VALUES('delete', old.id, old.username, old.text);
                     INSERT INTO documents_fts(rowid, username, text) VALUES (new.id, new.username, new.text);
                 END;",
            )?;
            let needs_rebuild: bool = conn.query_row(
                "SELECT (SELECT COUNT(*) FROM documents) != (SELECT COUNT(*) FROM documents_fts_docsize) \
                 OR COALESCE((SELECT MAX(id) FROM documents), 0) != COALESCE((SELECT MAX(id) FROM documents_fts_docsize), 0)",
                [],
                |row| row.get(0),
            )?;
            if needs_rebuild {
                conn.execute(
                    "INSERT INTO documents_fts(documents_fts) VALUES('rebuild')",
                    [],
                )?;
            }
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
        // and qualify with `text :` so queries never match the `username` column.
        let user_tokens: Vec<&str> = username
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
            .collect();
        let scope_expr = |inner: String| -> String {
            if user_tokens.is_empty() {
                inner
            } else {
                format!("username : \"{}\" AND ({})", user_tokens.join(" "), inner)
            }
        };

        let quoted_terms: Vec<String> = terms_to_use
            .iter()
            .map(|t| format!("text : \"{}\"*", t))
            .collect();
        let and_query = scope_expr(quoted_terms.join(" AND "));
        let or_query = (quoted_terms.len() > 1).then(|| scope_expr(quoted_terms.join(" OR ")));

        // --- SECURITY FIX (Section 1.1 / Finding A.4): User-Level Partitioning ---
        let username = username.to_string();
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let results = self
            .db
            .call(move |conn| {
                // Weight column 0 (username) at 0.0 and column 1 (text) at 1.0 for pure text BM25 ranking
                let sql = "SELECT d.id, d.text \
                           FROM documents_fts f \
                           JOIN documents d ON d.id = f.rowid \
                           WHERE documents_fts MATCH ?1 AND d.username = ?2 \
                           ORDER BY bm25(documents_fts, 0.0, 1.0) \
                           LIMIT ?3";
                let mut stmt = conn.prepare(sql)?;
                let mut matched_docs = Vec::new();

                {
                    let mut rows = stmt.query((&and_query, &username, limit_i64))?;
                    while let Some(row) = rows.next()? {
                        matched_docs.push(row.get::<_, String>(1)?);
                        if matched_docs.len() >= limit {
                            break;
                        }
                    }
                }

                if matched_docs.is_empty() {
                    if let Some(ref oq) = or_query {
                        let or_candidate_limit = limit_i64.saturating_mul(5).max(25);
                        let mut seen_ids = std::collections::HashSet::new();
                        let mut candidates: Vec<(String, usize)> = Vec::new();
                        let mut rows = stmt.query((oq, &username, or_candidate_limit))?;
                        while let Some(row) = rows.next()? {
                            let id: i64 = row.get(0)?;
                            let text: String = row.get(1)?;
                            if !seen_ids.insert(id) {
                                continue;
                            }
                            let lower = text.to_lowercase();
                            let doc_tokens: Vec<&str> = lower
                                .split(|c: char| !c.is_alphanumeric())
                                .filter(|s| !s.is_empty())
                                .collect();
                            let overlap = terms_to_use
                                .iter()
                                .filter(|t| doc_tokens.iter().any(|dt| dt.starts_with(t.as_str())))
                                .count();
                            candidates.push((text, overlap));
                        }
                        let min_overlap = if candidates.iter().any(|(_, c)| *c >= 2) {
                            2
                        } else {
                            1
                        };
                        for (text, overlap) in candidates {
                            if overlap >= min_overlap {
                                matched_docs.push(text);
                                if matched_docs.len() >= limit {
                                    break;
                                }
                            }
                        }
                    }
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
