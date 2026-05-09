use anyhow::{Result, Context};
use lancedb::query::{QueryBase, ExecutableQuery};
use futures::StreamExt;
use arrow_array::{StringArray, Array, RecordBatch};
use tracing::{warn, info};

/// The Librarian provides local heuristic grounding for policy enforcement.
/// It uses high-speed keyword filtering within LanceDB to find relevant snippets.
pub struct LocalLibrarian {
    db: lancedb::Connection,
    table_name: String,
}

impl LocalLibrarian {
    pub async fn new(path: &str) -> Result<Self> {
        let db = lancedb::connect(path).execute().await
            .context("Failed to connect to LanceDB")?;
        
        let table_name = "documents".to_string();
        
        if let Err(_e) = db.open_table(&table_name).execute().await {
            warn!("LanceDB: '{}' table not found. Heuristic retrieval will return empty results.", table_name);
        }

        Ok(Self {
            db,
            table_name,
        })
    }

    /// Performs high-speed heuristic keyword search within LanceDB.
    /// This is the primary grounding mechanism for the IronWarden Firewall.
    pub async fn retrieve_policy_context(&self, query: &str, limit: usize) -> Result<Vec<String>> {
        let table = match self.db.open_table(&self.table_name).execute().await {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()),
        };

        // --- HONESTY FIX: Pure Heuristic Keyword Search ---
        // We use a sanitized LIKE filter. This is robust for local policy retrieval
        // and doesn't require complex embedding models within the firewall.
        let sanitized_query = query.replace('\'', "''").replace('%', "");
        let filter = format!("text LIKE '%{}%'", sanitized_query);
        
        info!("Librarian: Retrieving context with heuristic filter: {}", filter);

        let mut results_stream = table.query()
            .only_if(filter)
            .limit(limit)
            .execute()
            .await?;

        let mut contexts = Vec::new();
        while let Some(batch_result) = results_stream.next().await {
            let batch: RecordBatch = batch_result?;
            if let Some(column) = batch.column_by_name("text") {
                let array = column.as_any().downcast_ref::<StringArray>()
                    .context("Failed to downcast 'text' column")?;
                
                for i in 0..array.len() {
                    if !array.is_null(i) {
                        contexts.push(array.value(i).to_string());
                    }
                }
            }
        }

        Ok(contexts)
    }
}
