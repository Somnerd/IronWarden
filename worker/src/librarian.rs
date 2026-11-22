use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tokio_rusqlite::Connection;
use tracing::info;
use unicode_normalization::UnicodeNormalization;

fn normalize_text(s: &str) -> String {
    s.nfd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .flat_map(|c| c.to_lowercase())
        .map(|c| if c == 'ς' { 'σ' } else { c })
        .collect()
}

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
                     search_text TEXT NOT NULL DEFAULT '',
                     username TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS idx_documents_username ON documents(username);",
            )?;
            let has_search_text: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('documents') WHERE name='search_text')",
                [],
                |row| row.get(0),
            )?;
            if !has_search_text {
                conn.execute(
                    "ALTER TABLE documents ADD COLUMN search_text TEXT NOT NULL DEFAULT ''",
                    [],
                )?;
            }

            // Upgrade older FTS5 schemas so tenant `username` and normalized `search_text` are indexed in FTS5
            let existing_fts_sql: Option<String> = conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='documents_fts'",
                    [],
                    |row| row.get(0),
                )
                .ok();
            if existing_fts_sql
                .as_deref()
                .is_some_and(|sql| !sql.contains("username") || !sql.contains("search_text"))
            {
                conn.execute_batch(
                    "DROP TRIGGER IF EXISTS documents_ai;
                     DROP TRIGGER IF EXISTS documents_ad;
                     DROP TRIGGER IF EXISTS documents_au;
                     DROP TABLE IF EXISTS documents_fts;",
                )?;
            }

            // Backfill normalized `search_text` for pre-existing rows before (re)building FTS5
            let rows_to_backfill: Vec<(i64, String)> = {
                let mut stmt = conn.prepare(
                    "SELECT id, text FROM documents WHERE search_text = '' AND text != ''",
                )?;
                let mapped = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
                mapped.collect::<rusqlite::Result<Vec<_>>>()?
            };
            if !rows_to_backfill.is_empty() {
                let mut update_stmt =
                    conn.prepare("UPDATE documents SET search_text = ?1 WHERE id = ?2")?;
                for (id, raw_text) in rows_to_backfill {
                    let norm = normalize_text(&raw_text);
                    update_stmt.execute((&norm, id))?;
                }
            }

            conn.execute_batch(
                "CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
                     username,
                     search_text,
                     content='documents',
                     content_rowid='id',
                     tokenize='unicode61'
                 );
                 CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
                     INSERT INTO documents_fts(rowid, username, search_text) VALUES (new.id, new.username, new.search_text);
                 END;
                 CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
                     INSERT INTO documents_fts(documents_fts, rowid, username, search_text) VALUES('delete', old.id, old.username, old.search_text);
                 END;
                 CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
                     INSERT INTO documents_fts(documents_fts, rowid, username, search_text) VALUES('delete', old.id, old.username, old.search_text);
                     INSERT INTO documents_fts(rowid, username, search_text) VALUES (new.id, new.username, new.search_text);
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
        let query_norm = normalize_text(query);
        let query_terms: Vec<String> = query_norm
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty() && !STOP_WORDS.contains(s))
            .map(|s| s.to_string())
            .collect();

        let terms_to_use: Vec<String> = if query_terms.is_empty() {
            query_norm
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
        // and qualify with `search_text :` so queries never match the `username` column.
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
            .map(|t| format!("search_text : \"{}\"*", t))
            .collect();
        let and_query = scope_expr(quoted_terms.join(" AND "));
        let or_query = (quoted_terms.len() > 1).then(|| scope_expr(quoted_terms.join(" OR ")));

        // --- SECURITY FIX (Section 1.1 / Finding A.4 & BM25 Tenant Isolation): User-Level Partitioning ---
        let norm_terms: Vec<String> = terms_to_use
            .iter()
            .map(|t| normalize_text(t))
            .filter(|t| !t.is_empty())
            .collect();
        let username = username.to_string();
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let candidate_cap = limit_i64.saturating_mul(20).max(200);
        let results = self
            .db
            .call(move |conn| {
                // Use FTS5 strictly as a tenant-scoped inverted-index filter (no global corpus BM25 ORDER BY)
                // so one tenant's document frequencies never leak into or perturb another tenant's ranking.
                let sql = "SELECT d.id, d.text \
                           FROM documents_fts f \
                           JOIN documents d ON d.id = f.rowid \
                           WHERE documents_fts MATCH ?1 AND d.username = ?2 \
                           LIMIT ?3";
                let mut stmt = conn.prepare(sql)?;

                struct Candidate {
                    id: i64,
                    text: String,
                    tokens: Vec<String>,
                    overlap: usize,
                    score: f64,
                }

                let collect_candidates = |fts_q: &str,
                                          s: &mut rusqlite::Statement<'_>|
                 -> rusqlite::Result<Vec<Candidate>> {
                    let mut seen = HashSet::new();
                    let mut out = Vec::new();
                    let mut rows = s.query((fts_q, &username, candidate_cap))?;
                    while let Some(row) = rows.next()? {
                        let id: i64 = row.get(0)?;
                        if !seen.insert(id) {
                            continue;
                        }
                        let text: String = row.get(1)?;
                        let norm_doc = normalize_text(&text);
                        let tokens: Vec<String> = norm_doc
                            .split(|c: char| !c.is_alphanumeric())
                            .filter(|t| !t.is_empty())
                            .map(str::to_string)
                            .collect();
                        let overlap = norm_terms
                            .iter()
                            .filter(|t| tokens.iter().any(|dt| dt.starts_with(t.as_str())))
                            .count();
                        out.push(Candidate {
                            id,
                            text,
                            tokens,
                            overlap,
                            score: 0.0,
                        });
                    }
                    Ok(out)
                };

                let mut candidates = collect_candidates(&and_query, &mut stmt)?;
                if candidates.is_empty() {
                    if let Some(ref oq) = or_query {
                        candidates = collect_candidates(oq, &mut stmt)?;
                        if candidates.iter().any(|c| c.overlap >= 2) {
                            candidates.retain(|c| c.overlap >= 2);
                        }
                    }
                }

                if candidates.is_empty() {
                    return Ok::<Vec<String>, rusqlite::Error>(Vec::new());
                }

                let total_docs_i64: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM documents WHERE username = ?1",
                    [&username],
                    |r| r.get(0),
                )?;
                let n_tenant = (total_docs_i64.max(1)) as f64;
                let avg_dl = (candidates
                    .iter()
                    .map(|c| c.tokens.len().max(1))
                    .sum::<usize>() as f64
                    / candidates.len() as f64)
                    .max(1.0);
                let df_counts: Vec<usize> = norm_terms
                    .iter()
                    .map(|t| {
                        candidates
                            .iter()
                            .filter(|c| c.tokens.iter().any(|dt| dt.starts_with(t.as_str())))
                            .count()
                    })
                    .collect();

                for cand in &mut candidates {
                    let dl = (cand.tokens.len().max(1)) as f64;
                    let mut score = 0.0;
                    for (idx, t) in norm_terms.iter().enumerate() {
                        let tf = cand
                            .tokens
                            .iter()
                            .filter(|dt| dt.starts_with(t.as_str()))
                            .count() as f64;
                        if tf == 0.0 {
                            continue;
                        }
                        let df = (df_counts[idx] as f64).min(n_tenant);
                        let idf = ((n_tenant - df + 0.5) / (df + 0.5) + 1.0).ln().max(0.0);
                        let k1 = 1.2;
                        let b = 0.75;
                        score +=
                            idf * (tf * (k1 + 1.0)) / (tf + k1 * (1.0 - b + b * (dl / avg_dl)));
                    }
                    cand.score = score;
                }

                candidates
                    .sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
                let matched_docs = candidates.into_iter().take(limit).map(|c| c.text).collect();

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
        let search_text = normalize_text(&text);
        let username = username.to_string();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO documents (text, search_text, username) VALUES (?1, ?2, ?3)",
                    [&text, &search_text, &username],
                )?;
                Ok::<(), rusqlite::Error>(())
            })
            .await
            .context("Failed to add document")?;

        Ok(())
    }
}
