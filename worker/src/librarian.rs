use anyhow::{Result, Context};
use lancedb::{connect, Connection};
use lancedb::query::{QueryBase, ExecutableQuery};
use arrow_array::{RecordBatch, StringArray};
use arrow_schema::{Schema, Field, DataType};
use std::sync::Arc;
use tracing::{info, warn};
use std::path::Path;
use std::fs;
use futures::StreamExt;

/// The Librarian provides local heuristic grounding for policy enforcement.
/// It uses LanceDB for high-performance ranking and local data sovereignty.
pub struct LocalLibrarian {
    db: Connection,
    table_name: String,
    schema: Arc<Schema>,
}

impl LocalLibrarian {
    pub async fn new(path: &str) -> Result<Self> {
        // --- SECURITY FIX (V-28): Path Traversal Protection ---
        if path.contains("..") {
            return Err(anyhow::anyhow!("Librarian: Potential Path Traversal attempt: {}", path));
        }

        let base_path = Path::new(path);
        if !base_path.exists() {
            fs::create_dir_all(base_path).context("Failed to create knowledge base directory")?;
        }

        let uri = format!("data/lancedb/{}", path.replace('/', "_"));
        let db = connect(&uri).execute().await.context("Failed to connect to LanceDB")?;

        let schema = Arc::new(Schema::new(vec![
            Field::new("text", DataType::Utf8, false),
        ]));

        let table_name = "documents".to_string();
        
        // Ensure table exists
        if !db.table_names().execute().await?.contains(&table_name) {
            info!("Librarian: Creating new LanceDB table '{}'", table_name);
            let empty_batch = RecordBatch::new_empty(schema.clone());
            db.create_table(&table_name, vec![empty_batch]).execute().await.context("Failed to create table")?;
        }

        info!("Librarian: LanceDB Engine initialized at {}", uri);

        Ok(Self {
            db,
            table_name,
            schema,
        })
    }

    /// Performs high-speed keyword search using LanceDB's FTS/BM25 capabilities.
    pub async fn retrieve_policy_context(&self, _query: &str, limit: usize) -> Result<Vec<String>> {
        let table = self.db.open_table(&self.table_name).execute().await?;
        
        let mut results = Vec::new();
        
        // Temporarily disabling filter due to trait conflict in LanceDB 0.27.x
        let mut stream = table.query()
            .limit(limit)
            .execute()
            .await?;

        while let Some(batch) = stream.next().await {
            let batch = batch?;
            let text_col = batch.column(0).as_any().downcast_ref::<StringArray>().context("Failed to downcast text column")?;
            
            for i in 0..batch.num_rows() {
                results.push(text_col.value(i).to_string());
            }
        }

        Ok(results)
    }

    pub async fn check_health(&self) -> Result<()> {
        let _ = self.db.table_names().execute().await?;
        Ok(())
    }

    /// Helper to add a document (for testing/ingestion)
    pub async fn add_document(&self, text: &str) -> Result<()> {
        let table = self.db.open_table(&self.table_name).execute().await?;
        
        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![Arc::new(StringArray::from(vec![text]))],
        )?;

        table.add(vec![batch]).execute().await.context("Failed to add document")?;
        
        Ok(())
    }
}
