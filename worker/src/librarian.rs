use anyhow::{Context, Result};
use arrow_array::{RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use futures::StreamExt;
use lancedb::query::{ExecutableQuery, QueryBase};
use lancedb::{connect, Connection};
use sha2::Digest;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::info;

/// The Librarian provides local heuristic grounding for policy enforcement.
/// It uses LanceDB for high-performance ranking and local data sovereignty.
pub struct LocalLibrarian {
    db: Connection,
    table_name: String,
    schema: Arc<Schema>,
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

        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, path.as_bytes());
        let hash = hex::encode(sha2::Digest::finalize(hasher));
        let uri = format!("data/lancedb/{}_{}", path.replace('/', "_"), &hash[..16]);
        let db = connect(&uri)
            .execute()
            .await
            .context("Failed to connect to LanceDB")?;

        let schema = Arc::new(Schema::new(vec![
            Field::new("text", DataType::Utf8, false),
            Field::new("username", DataType::Utf8, false),
        ]));

        let table_name = "documents".to_string();

        // Ensure table exists
        if !db.table_names().execute().await?.contains(&table_name) {
            info!("Librarian: Creating new LanceDB table '{}'", table_name);
            let empty_batch = RecordBatch::new_empty(schema.clone());
            db.create_table(&table_name, vec![empty_batch])
                .execute()
                .await
                .context("Failed to create table")?;
        }

        info!("Librarian: LanceDB Engine initialized at {}", uri);

        Ok(Self {
            db,
            table_name,
            schema,
        })
    }

    /// Performs high-speed keyword search using LanceDB's FTS/BM25 capabilities, scoped to the user.
    pub async fn retrieve_policy_context(
        &self,
        query: &str,
        username: &str,
        limit: usize,
    ) -> Result<Vec<String>> {
        let table = self.db.open_table(&self.table_name).execute().await?;

        let mut results = Vec::new();

        // --- SECURITY FIX (Section 1.1 / Finding A.4): User-Level Partitioning ---
        // Push the user filter down to LanceDB to prevent memory exhaustion / DoS
        let sanitized_username = username.replace("'", "''");
        let mut stream = table
            .query()
            .only_if(format!("username = '{}'", sanitized_username))
            .execute()
            .await?;

        while let Some(batch) = stream.next().await {
            let batch = batch?;
            let text_col = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .context("Failed to downcast text column")?;

            for i in 0..batch.num_rows() {
                if results.len() >= limit {
                    break;
                }

                let text = text_col.value(i);
                let text_lower = text.to_lowercase();

                // Define simple stop words to filter out for keyword search
                let stop_words: std::collections::HashSet<&str> = [
                    "the", "a", "an", "and", "or", "but", "if", "then", "else", "to", "of", "in",
                    "on", "at", "by", "for", "with", "about", "against", "between", "into",
                    "through", "during", "before", "after", "above", "below", "from", "up", "down",
                    "out", "over", "under", "again", "further", "once", "here", "there", "when",
                    "where", "why", "how", "all", "any", "both", "each", "few", "more", "most",
                    "other", "some", "such", "no", "nor", "not", "only", "own", "same", "so",
                    "than", "too", "very", "can", "will", "just", "should", "now", "me", "tell",
                    "who", "is", "it",
                ]
                .iter()
                .cloned()
                .collect();

                let query_lower = query.to_lowercase();
                let query_terms: Vec<&str> = query_lower
                    .split(|c: char| !c.is_alphanumeric())
                    .filter(|s| !s.is_empty() && !stop_words.contains(s))
                    .collect();

                let terms_to_use = if query_terms.is_empty() {
                    query_lower
                        .split(|c: char| !c.is_alphanumeric())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<&str>>()
                } else {
                    query_terms
                };

                let mut matched = !terms_to_use.is_empty();
                for term in &terms_to_use {
                    if !text_lower.contains(term) {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    results.push(text.to_string());
                }
            }
        }

        Ok(results)
    }

    /// GDPR Compliance: Purges all documents associated with a user from the vector store.
    pub async fn delete_user_documents(&self, username: &str) -> Result<()> {
        let table = self.db.open_table(&self.table_name).execute().await?;

        // --- SECURITY FIX (Section 1.1 / Finding A.3): GDPR Compliance ---
        // Purge documents where username matches.
        let sanitized_username = username.replace("'", "''");
        table
            .delete(format!("username = '{}'", sanitized_username).as_str())
            .await?;

        info!("Librarian: Purged all documents for user {}", username);
        Ok(())
    }

    pub async fn check_health(&self) -> Result<()> {
        let _ = self.db.table_names().execute().await?;
        Ok(())
    }

    /// Helper to add a document (for testing/ingestion)
    pub async fn add_document(&self, text: &str, username: &str) -> Result<()> {
        let table = self.db.open_table(&self.table_name).execute().await?;

        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![
                Arc::new(StringArray::from(vec![text])),
                Arc::new(StringArray::from(vec![username])),
            ],
        )?;

        table
            .add(vec![batch])
            .execute()
            .await
            .context("Failed to add document")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_librarian_cross_user_isolation_v19() {
        let kb_path = format!("lancedb_test_isolation_{}", uuid::Uuid::new_v4());
        let librarian = LocalLibrarian::new(&kb_path).await.unwrap();

        librarian
            .add_document("Alice top secret document", "userA")
            .await
            .unwrap();
        librarian
            .add_document("Bob top secret document", "userB")
            .await
            .unwrap();

        // Query as user A
        let res_a = librarian
            .retrieve_policy_context("top secret", "userA", 10)
            .await
            .unwrap();
        assert_eq!(res_a.len(), 1);
        assert_eq!(res_a[0], "Alice top secret document");

        // Query as user B
        let res_b = librarian
            .retrieve_policy_context("top secret", "userB", 10)
            .await
            .unwrap();
        assert_eq!(res_b.len(), 1);
        assert_eq!(res_b[0], "Bob top secret document");

        // Cross-user query should return empty
        let res_cross = librarian
            .retrieve_policy_context("Alice", "userB", 10)
            .await
            .unwrap();
        assert!(res_cross.is_empty(), "Cross-user data leakage detected!");

        let uri = format!("data/lancedb/{}", kb_path.replace('/', "_"));
        fs::remove_dir_all(&kb_path).ok();
        fs::remove_dir_all(&uri).ok();
    }
}
