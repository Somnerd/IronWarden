use anyhow::{Context, Result};
use rusqlite::TransactionBehavior;
use sha2::{Digest, Sha256};
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

/// Deterministic ASCII alphanumeric tenant token so any username (including punctuation-only
/// or prefix-overlapping names like `alice` vs `alice_2`) maps to an exact single FTS5 token.
fn tenant_key(username: &str) -> String {
    let digest = Sha256::digest(username.as_bytes());
    format!("t{}", &hex::encode(digest)[..32])
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
                 PRAGMA secure_delete = ON;",
            )?;

            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS documents (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     text TEXT NOT NULL,
                     search_text TEXT NOT NULL DEFAULT '',
                     tenant_key TEXT NOT NULL DEFAULT '',
                     username TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS idx_documents_username ON documents(username);",
            )?;
            let has_search_text: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('documents') WHERE name='search_text')",
                [],
                |row| row.get(0),
            )?;
            if !has_search_text {
                tx.execute(
                    "ALTER TABLE documents ADD COLUMN search_text TEXT NOT NULL DEFAULT ''",
                    [],
                )?;
            }
            let has_tenant_key: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('documents') WHERE name='tenant_key')",
                [],
                |row| row.get(0),
            )?;
            if !has_tenant_key {
                tx.execute(
                    "ALTER TABLE documents ADD COLUMN tenant_key TEXT NOT NULL DEFAULT ''",
                    [],
                )?;
            }
            tx.execute(
                "CREATE INDEX IF NOT EXISTS idx_documents_tenant_key ON documents(tenant_key)",
                [],
            )?;

            // Upgrade older FTS5 schemas so hashed `tenant_key` and normalized `search_text` are indexed in FTS5
            let existing_fts_sql: Option<String> = tx
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='documents_fts'",
                    [],
                    |row| row.get(0),
                )
                .ok();
            if existing_fts_sql
                .as_deref()
                .is_some_and(|sql| !sql.contains("tenant_key") || !sql.contains("search_text"))
            {
                tx.execute_batch(
                    "DROP TRIGGER IF EXISTS documents_ai;
                     DROP TRIGGER IF EXISTS documents_ad;
                     DROP TRIGGER IF EXISTS documents_au;
                     DROP TABLE IF EXISTS documents_fts;",
                )?;
            }

            // Backfill normalized `search_text` and `tenant_key` inside the migration transaction
            let rows_to_backfill: Vec<(i64, String, String)> = {
                let mut stmt = tx.prepare(
                    "SELECT id, text, username FROM documents WHERE (search_text = '' AND text != '') OR tenant_key = ''",
                )?;
                let mapped =
                    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
                mapped.collect::<rusqlite::Result<Vec<_>>>()?
            };
            if !rows_to_backfill.is_empty() {
                let mut update_stmt = tx.prepare(
                    "UPDATE documents SET search_text = ?1, tenant_key = ?2 WHERE id = ?3",
                )?;
                for (id, raw_text, uname) in rows_to_backfill {
                    let norm = normalize_text(&raw_text);
                    let tkey = tenant_key(&uname);
                    update_stmt.execute((&norm, &tkey, id))?;
                }
            }

            tx.execute_batch(
                "CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
                     tenant_key,
                     search_text,
                     content='documents',
                     content_rowid='id',
                     tokenize='unicode61'
                 );
                 CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
                     INSERT INTO documents_fts(rowid, tenant_key, search_text) VALUES (new.id, new.tenant_key, new.search_text);
                 END;
                 CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
                     INSERT INTO documents_fts(documents_fts, rowid, tenant_key, search_text) VALUES('delete', old.id, old.tenant_key, old.search_text);
                 END;
                 CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
                     INSERT INTO documents_fts(documents_fts, rowid, tenant_key, search_text) VALUES('delete', old.id, old.tenant_key, old.search_text);
                     INSERT INTO documents_fts(rowid, tenant_key, search_text) VALUES (new.id, new.tenant_key, new.search_text);
                 END;",
            )?;
            let needs_rebuild: bool = tx.query_row(
                "SELECT (SELECT COUNT(*) FROM documents) != (SELECT COUNT(*) FROM documents_fts_docsize) \
                 OR COALESCE((SELECT MAX(id) FROM documents), 0) != COALESCE((SELECT MAX(id) FROM documents_fts_docsize), 0)",
                [],
                |row| row.get(0),
            )?;
            if needs_rebuild {
                tx.execute(
                    "INSERT INTO documents_fts(documents_fts) VALUES('rebuild')",
                    [],
                )?;
            }
            tx.commit()?;
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

        let raw_terms: Vec<String> = if query_terms.is_empty() {
            query_norm
                .split(|c: char| !c.is_alphanumeric())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        } else {
            query_terms
        };

        // Deduplicate query terms preserving order so repeated query words never inflate `overlap`
        // or double-count BM25 weights.
        let mut seen_terms = HashSet::with_capacity(raw_terms.len());
        let mut unique_terms = Vec::with_capacity(raw_terms.len());
        for t in raw_terms {
            if seen_terms.insert(t.clone()) {
                unique_terms.push(t);
            }
        }

        if unique_terms.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }

        // Scope via deterministic ASCII `tenant_key` so punctuation-only or prefix-overlapping
        // usernames always form an exact single-token FTS5 filter, paired with `d.username = ?2`.
        let tkey = tenant_key(username);
        let scope_expr =
            |inner: String| -> String { format!("tenant_key : {} AND ({})", tkey, inner) };

        let quoted_terms: Vec<String> = unique_terms
            .iter()
            .map(|t| format!("search_text : \"{}\"*", t))
            .collect();
        let single_term_queries: Vec<String> = quoted_terms
            .iter()
            .map(|qt| scope_expr(qt.clone()))
            .collect();
        let and_query = scope_expr(quoted_terms.join(" AND "));
        let or_query = (quoted_terms.len() > 1).then(|| scope_expr(quoted_terms.join(" OR ")));

        let username = username.to_string();
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let candidate_cap = limit_i64.saturating_mul(200).max(50_000);
        let results = self
            .db
            .call(move |conn| {
                // Use FTS5 strictly as a tenant-scoped inverted-index filter (no global corpus BM25 ORDER BY)
                // so one tenant's document frequencies never leak into or perturb another tenant's ranking.
                let sql = "SELECT d.id, d.search_text \
                           FROM documents_fts f \
                           JOIN documents d ON d.id = f.rowid \
                           WHERE documents_fts MATCH ?1 AND d.username = ?2 \
                           LIMIT ?3";
                let mut stmt = conn.prepare(sql)?;

                struct ScoredCand {
                    id: i64,
                    dl: usize,
                    tfs: Vec<u32>,
                    overlap: usize,
                    score: f64,
                }

                let term_count = unique_terms.len();
                let collect_candidates = |fts_q: &str,
                                          s: &mut rusqlite::Statement<'_>|
                 -> rusqlite::Result<Vec<ScoredCand>> {
                    let mut seen = HashSet::new();
                    let mut out = Vec::new();
                    let mut rows = s.query((fts_q, &username, candidate_cap))?;
                    while let Some(row) = rows.next()? {
                        let id: i64 = row.get(0)?;
                        if !seen.insert(id) {
                            continue;
                        }
                        let search_text: String = row.get(1)?;
                        let mut dl = 0usize;
                        let mut tfs = vec![0u32; term_count];
                        for tok in search_text
                            .split(|c: char| !c.is_alphanumeric())
                            .filter(|t| !t.is_empty())
                        {
                            dl += 1;
                            for (idx, qterm) in unique_terms.iter().enumerate() {
                                if tok.starts_with(qterm.as_str()) {
                                    tfs[idx] += 1;
                                }
                            }
                        }
                        let overlap = tfs.iter().filter(|&&c| c > 0).count();
                        out.push(ScoredCand {
                            id,
                            dl,
                            tfs,
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
                let avg_dl = (candidates.iter().map(|c| c.dl.max(1)).sum::<usize>() as f64
                    / candidates.len() as f64)
                    .max(1.0);

                // Compute exact tenant-local document frequencies directly via FTS5 so AND queries
                // preserve genuine rarity weighting across the tenant's corpus.
                let mut df_stmt = conn.prepare(
                    "SELECT COUNT(*) FROM documents_fts f \
                     JOIN documents d ON d.id = f.rowid \
                     WHERE documents_fts MATCH ?1 AND d.username = ?2",
                )?;
                let mut df_counts = Vec::with_capacity(term_count);
                for tq in &single_term_queries {
                    let df: i64 = df_stmt.query_row((tq, &username), |r| r.get(0))?;
                    df_counts.push(df.max(0) as usize);
                }

                for cand in &mut candidates {
                    let dl = (cand.dl.max(1)) as f64;
                    let mut score = 0.0;
                    for (idx, &tf_u32) in cand.tfs.iter().enumerate() {
                        if tf_u32 == 0 {
                            continue;
                        }
                        let tf = tf_u32 as f64;
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
                let mut fetch_stmt =
                    conn.prepare("SELECT text FROM documents WHERE id = ?1 AND username = ?2")?;
                let mut matched_docs = Vec::with_capacity(limit.min(candidates.len()));
                for cand in candidates.into_iter().take(limit) {
                    if let Ok(text) = fetch_stmt.query_row((cand.id, &username), |r| r.get(0)) {
                        matched_docs.push(text);
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
        let search_text = normalize_text(&text);
        let tkey = tenant_key(username);
        let username = username.to_string();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO documents (text, search_text, tenant_key, username) VALUES (?1, ?2, ?3, ?4)",
                    [&text, &search_text, &tkey, &username],
                )?;
                Ok::<(), rusqlite::Error>(())
            })
            .await
            .context("Failed to add document")?;

        Ok(())
    }
}
