use anyhow::{Context, Result};
use rusqlite::{Connection as SqliteConn, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tokio_rusqlite::Connection;
use tracing::info;
use unicode_normalization::UnicodeNormalization;

const MAX_QUERY_TERMS: usize = 32;
const SCHEMA_VERSION: i64 = 2;

fn normalize_text(s: &str) -> String {
    s.nfd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .flat_map(|c| c.to_lowercase())
        .map(|c| if c == 'ς' { 'σ' } else { c })
        .collect()
}

/// Deterministic pure-alphanumeric tenant prefix (`t<32hex>z`) kept intact as one atomic token
/// by FTS5 `unicode61` so posting lists are pre-partitioned by tenant with zero cross-tenant scan.
fn tenant_prefix(username: &str) -> String {
    let digest = Sha256::digest(username.as_bytes());
    format!("t{}z", &hex::encode(digest)[..32])
}

fn index_tokens(text: &str, prefix: &str) -> String {
    let norm = normalize_text(text);
    let mut out = String::with_capacity(norm.len() + 64);
    for tok in norm
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
    {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(prefix);
        out.push_str(tok);
    }
    out
}

/// The Librarian provides local heuristic grounding for policy enforcement.
/// It uses SQLite FTS5 (`unicode61` tokenizer + tenant-local BM25 ranking) for fast
/// indexed search and strict multi-tenant data isolation.
pub struct LocalLibrarian {
    db: Connection,
}

static STOP_WORDS: std::sync::LazyLock<HashSet<&'static str>> = std::sync::LazyLock::new(|| {
    HashSet::from([
        "the", "a", "an", "and", "or", "but", "if", "then", "else", "to", "of", "in", "on", "at",
        "by", "for", "with", "about", "against", "between", "into", "through", "during", "before",
        "after", "above", "below", "from", "up", "down", "out", "over", "under", "again",
        "further", "once", "here", "there", "when", "where", "why", "how", "all", "any", "both",
        "each", "few", "more", "most", "other", "some", "such", "no", "nor", "not", "only", "own",
        "same", "so", "than", "too", "very", "can", "will", "just", "should", "now", "me", "tell",
        "who", "is", "it", "what", "which", "whom", "whose", "this", "that", "these", "those",
        "am", "are", "was", "were", "be", "been", "being", "have", "has", "had", "do", "does",
        "did", "shall", "would", "could", "may", "might", "must", "i", "you", "he", "she", "we",
        "they", "my", "your", "his", "her", "its", "our", "their", "please",
    ])
});

struct ScoredCand {
    id: i64,
    text: String,
    dl: usize,
    tfs: Vec<u32>,
    overlap: usize,
    score: f64,
}

fn extract_query_terms(query: &str) -> Vec<String> {
    let norm = normalize_text(query);
    let dedup = |skip_stop: bool| {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for tok in norm
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
        {
            if skip_stop && STOP_WORDS.contains(tok) {
                continue;
            }
            if seen.insert(tok) {
                out.push(tok.to_string());
                if out.len() == MAX_QUERY_TERMS {
                    break;
                }
            }
        }
        out
    };
    let terms = dedup(true);
    if terms.is_empty() {
        dedup(false)
    } else {
        terms
    }
}

fn ensure_column(tx: &Transaction<'_>, col: &str, ddl: &str) -> rusqlite::Result<()> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('documents') WHERE name = ?1)",
        [col],
        |row| row.get(0),
    )?;
    if !exists {
        tx.execute(ddl, [])?;
    }
    Ok(())
}

fn score_bm25(candidates: &mut [ScoredCand], df_counts: &[usize], n_tenant: f64) {
    let avg_dl = (candidates.iter().map(|c| c.dl.max(1)).sum::<usize>() as f64
        / candidates.len() as f64)
        .max(1.0);
    let (k1, b) = (1.2, 0.75);
    for cand in candidates {
        let dl = cand.dl.max(1) as f64;
        let mut score = 0.0;
        for (idx, &tf_u32) in cand.tfs.iter().enumerate() {
            if tf_u32 == 0 {
                continue;
            }
            let tf = tf_u32 as f64;
            let df = (df_counts[idx] as f64).min(n_tenant);
            let idf = ((n_tenant - df + 0.5) / (df + 0.5) + 1.0).ln().max(0.0);
            score += idf * (tf * (k1 + 1.0)) / (tf + k1 * (1.0 - b + b * (dl / avg_dl)));
        }
        cand.score = score;
    }
}

fn migrate_schema_v2(conn: &mut SqliteConn) -> rusqlite::Result<()> {
    let ver: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if ver >= SCHEMA_VERSION {
        return Ok(());
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ver_locked: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if ver_locked < SCHEMA_VERSION {
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS documents (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 text TEXT NOT NULL,
                 search_text TEXT NOT NULL DEFAULT '',
                 username TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_documents_username ON documents(username);
             CREATE TABLE IF NOT EXISTS tenant_stats (
                 username TEXT PRIMARY KEY,
                 doc_count INTEGER NOT NULL DEFAULT 0
             );
             DROP TRIGGER IF EXISTS documents_ai;
             DROP TRIGGER IF EXISTS documents_ad;
             DROP TRIGGER IF EXISTS documents_au;
             DROP TRIGGER IF EXISTS documents_au_tenant;
             DROP TABLE IF EXISTS documents_fts;",
        )?;
        ensure_column(
            &tx,
            "search_text",
            "ALTER TABLE documents ADD COLUMN search_text TEXT NOT NULL DEFAULT ''",
        )?;

        let rows: Vec<(i64, String, String)> = {
            let mut stmt = tx.prepare("SELECT id, text, username FROM documents")?;
            let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()?
        };
        if !rows.is_empty() {
            let mut upd = tx.prepare("UPDATE documents SET search_text = ?1 WHERE id = ?2")?;
            for (id, raw, uname) in rows {
                upd.execute((&index_tokens(&raw, &tenant_prefix(&uname)), id))?;
            }
        }

        tx.execute_batch(
            "CREATE VIRTUAL TABLE documents_fts USING fts5(
                 search_text,
                 content='documents',
                 content_rowid='id',
                 tokenize='unicode61'
             );
             CREATE TRIGGER documents_ai AFTER INSERT ON documents BEGIN
                 INSERT INTO documents_fts(rowid, search_text) VALUES (new.id, new.search_text);
                 INSERT INTO tenant_stats(username, doc_count) VALUES (new.username, 1)
                     ON CONFLICT(username) DO UPDATE SET doc_count = doc_count + 1;
             END;
             CREATE TRIGGER documents_ad AFTER DELETE ON documents BEGIN
                 INSERT INTO documents_fts(documents_fts, rowid, search_text) VALUES('delete', old.id, old.search_text);
                 UPDATE tenant_stats SET doc_count = MAX(0, doc_count - 1) WHERE username = old.username;
             END;
             CREATE TRIGGER documents_au AFTER UPDATE ON documents BEGIN
                 INSERT INTO documents_fts(documents_fts, rowid, search_text) VALUES('delete', old.id, old.search_text);
                 INSERT INTO documents_fts(rowid, search_text) VALUES (new.id, new.search_text);
             END;
             CREATE TRIGGER documents_au_tenant AFTER UPDATE OF username ON documents WHEN old.username != new.username BEGIN
                 UPDATE tenant_stats SET doc_count = MAX(0, doc_count - 1) WHERE username = old.username;
                 INSERT INTO tenant_stats(username, doc_count) VALUES (new.username, 1)
                     ON CONFLICT(username) DO UPDATE SET doc_count = doc_count + 1;
             END;
             INSERT INTO documents_fts(documents_fts) VALUES('rebuild');
             DELETE FROM tenant_stats;
             INSERT INTO tenant_stats(username, doc_count) SELECT username, COUNT(*) FROM documents GROUP BY username;
             PRAGMA user_version = 2;",
        )?;
    }
    tx.commit()
}

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

        db.call(|conn| -> rusqlite::Result<()> {
            conn.busy_timeout(std::time::Duration::from_millis(5000))?;
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA secure_delete = ON;",
            )?;
            migrate_schema_v2(conn)
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
        let unique_terms = extract_query_terms(query);
        if unique_terms.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }

        let prefix = tenant_prefix(username);
        let tagged: Vec<String> = unique_terms
            .iter()
            .map(|t| format!("{prefix}{t}"))
            .collect();
        let exact_terms: Vec<String> = tagged.iter().map(|t| format!("\"{t}\"")).collect();
        let pref_terms: Vec<String> = tagged.iter().map(|t| format!("\"{t}\"*")).collect();

        let and_exact = exact_terms.join(" AND ");
        let and_pref = pref_terms.join(" AND ");
        let or_queries =
            (tagged.len() > 1).then(|| (exact_terms.join(" OR "), pref_terms.join(" OR ")));

        let username = username.to_string();
        let candidate_cap = i64::try_from(limit)
            .unwrap_or(i64::MAX)
            .saturating_mul(200)
            .max(50_000);

        self.db
            .call(move |conn| -> rusqlite::Result<Vec<String>> {
                let collect = |fts_q: &str, is_prefix: bool| -> rusqlite::Result<Vec<ScoredCand>> {
                    // CROSS JOIN forces SQLite to drive from FTS5 before verifying d.username = ?2.
                    let mut stmt = conn.prepare_cached(
                        "SELECT d.id, d.text, d.search_text \
                         FROM documents_fts f \
                         CROSS JOIN documents d ON d.id = f.rowid \
                         WHERE documents_fts MATCH ?1 AND d.username = ?2 \
                         LIMIT ?3",
                    )?;
                    let mut out = Vec::new();
                    let mut rows = stmt.query((fts_q, &username, candidate_cap))?;
                    while let Some(row) = rows.next()? {
                        let id: i64 = row.get(0)?;
                        let text: String = row.get(1)?;
                        let search_text: String = row.get(2)?;
                        let (mut dl, mut tfs) = (0usize, vec![0u32; tagged.len()]);
                        for tok in search_text.split(' ').filter(|t| !t.is_empty()) {
                            dl += 1;
                            for (idx, qterm) in tagged.iter().enumerate() {
                                let matched = if is_prefix {
                                    tok.starts_with(qterm.as_str())
                                } else {
                                    tok == qterm.as_str()
                                };
                                if matched {
                                    tfs[idx] += 1;
                                }
                            }
                        }
                        let overlap = tfs.iter().filter(|&&c| c > 0).count();
                        out.push(ScoredCand {
                            id,
                            text,
                            dl,
                            tfs,
                            overlap,
                            score: 0.0,
                        });
                    }
                    Ok(out)
                };

                let mut used_prefix = false;
                let mut candidates = collect(&and_exact, false)?;
                if candidates.is_empty() {
                    used_prefix = true;
                    candidates = collect(&and_pref, true)?;
                }
                if candidates.is_empty() {
                    if let Some((ref or_exact, ref or_pref)) = or_queries {
                        used_prefix = false;
                        candidates = collect(or_exact, false)?;
                        if candidates.is_empty() {
                            used_prefix = true;
                            candidates = collect(or_pref, true)?;
                        }
                        if candidates.iter().any(|c| c.overlap >= 2) {
                            candidates.retain(|c| c.overlap >= 2);
                        }
                    }
                }
                if candidates.len() <= 1 {
                    return Ok(candidates.into_iter().take(limit).map(|c| c.text).collect());
                }

                if tagged.len() > 1 {
                    let total_docs: i64 = conn
                        .prepare_cached("SELECT doc_count FROM tenant_stats WHERE username = ?1")?
                        .query_row([&username], |r| r.get(0))
                        .unwrap_or(candidates.len() as i64);
                    let mut df_stmt = conn.prepare_cached(
                        "SELECT COUNT(*) FROM documents_fts WHERE documents_fts MATCH ?1",
                    )?;
                    let df_terms = if used_prefix {
                        &pref_terms
                    } else {
                        &exact_terms
                    };
                    let df_counts = df_terms
                        .iter()
                        .map(|tq| {
                            df_stmt
                                .query_row([tq], |r| r.get(0))
                                .map(|d: i64| d.max(0) as usize)
                        })
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    score_bm25(&mut candidates, &df_counts, total_docs.max(1) as f64);
                } else {
                    let n = candidates.len() as f64;
                    score_bm25(&mut candidates, &[0usize], n);
                }

                candidates
                    .sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
                Ok(candidates.into_iter().take(limit).map(|c| c.text).collect())
            })
            .await
            .context("Failed to retrieve policy context from Librarian SQLite FTS5 DB")
    }

    /// GDPR Compliance: Purges all documents associated with a user from the store.
    pub async fn delete_user_documents(&self, username: &str) -> Result<()> {
        let username_owned = username.to_string();
        self.db
            .call(move |conn| -> rusqlite::Result<()> {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                tx.execute(
                    "DELETE FROM documents WHERE username = ?1",
                    [&username_owned],
                )?;
                tx.execute(
                    "DELETE FROM tenant_stats WHERE username = ?1",
                    [&username_owned],
                )?;
                tx.commit()
            })
            .await
            .context("Failed to delete user documents from Librarian SQLite DB")?;

        info!("Librarian: Purged all documents for user {}", username);
        Ok(())
    }

    pub async fn check_health(&self) -> Result<()> {
        self.db
            .call(|conn| -> rusqlite::Result<()> {
                conn.execute_batch("SELECT 1;")?;
                Ok(())
            })
            .await
            .context("Librarian SQLite health check failed")?;
        Ok(())
    }

    /// Helper to add a document (for testing/ingestion)
    pub async fn add_document(&self, text: &str, username: &str) -> Result<()> {
        let search_text = index_tokens(text, &tenant_prefix(username));
        let text = text.to_string();
        let username = username.to_string();
        self.db
            .call(move |conn| -> rusqlite::Result<()> {
                conn.prepare_cached(
                    "INSERT INTO documents (text, search_text, username) VALUES (?1, ?2, ?3)",
                )?
                .execute((&text, &search_text, &username))?;
                Ok(())
            })
            .await
            .context("Failed to add document")?;

        Ok(())
    }
}
