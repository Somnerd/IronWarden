// End-to-end integration tests verifying regional legal-compliance rule compilation, document ingestion with Greek PII (AFM), query matching within latency constraints, and correct post-retrieval redaction.
use tempfile::tempdir;
use std::sync::Arc;
use tokio;
use iw_core::{PiiShield, StorageProvider};
use worker::{WorkerStorage, LocalSessionManager, SearchBoostQueue};
use warden::WardenConfig;

#[tokio::test]
async fn test_legal_e2e() {
    let config_dir = "../config/regions";
    let mut config = WardenConfig::from_dir(config_dir).expect("Failed to load config");
    config.ai_enabled = false;
    let secret = secrecy::SecretVec::new(vec![0u8; 32]);
    let engine = config.compile_engine(&secret).expect("Failed to compile engine");
    
    let shield: Arc<dyn PiiShield + Send + Sync> = Arc::new(engine);
    let queue = Arc::new(SearchBoostQueue::new("file::memory:?cache=shared".to_string(), &secret, Some(shield.clone()), None).unwrap());
    
    let temp_dir = tempfile::tempdir().unwrap();
    let kb_path = temp_dir.path().join("knowledge").to_str().unwrap().to_string();

    let librarian = worker::LocalLibrarian::new(&kb_path).await.unwrap();
    let brief = "Ο πελάτης Νικόλαος Αλεξανδράκης με ΑΦΜ 123456789 εμπλέκεται στην υπόθεση.";
    librarian.add_document(brief, "legal_user").await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    let storage = WorkerStorage::new(
        "file::memory:?cache=shared",
        &kb_path,
        secret,
        Some((*queue).clone()),
        None
    ).await.expect("Failed to initialize storage");

    
    let start = std::time::Instant::now();
    // The librarian uses a keyword search with stop word filtering and to_lowercase().
    // "ΑΦΜ" in the query matches the document.
    let contexts = storage.fetch_context("ΑΦΜ 123456789", "legal_user").await.expect("Search failed");
    let elapsed = start.elapsed();
    
    assert!(elapsed.as_millis() < 500, "Latency must be sub-500ms");
    assert!(!contexts.is_empty(), "Should return context");
    
    let report = shield.sanitize_prompt(&contexts[0], None).await.expect("Scrubbing failed");
    assert!(report.sanitized_text.contains("[TOKEN_"), "Should redact AFM");
}
