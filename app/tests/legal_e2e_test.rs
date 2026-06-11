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
    
    let librarian = worker::LocalLibrarian::new("data/knowledge").await.unwrap();
    let brief = std::fs::read_to_string("../data/knowledge/greek_legal_brief.md").unwrap();
    librarian.add_document(&brief, "legal_user").await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    let storage = WorkerStorage::new(
        "file::memory:?cache=shared",
        "data/knowledge",
        secret,
        Some((*queue).clone()),
        None
    ).await.expect("Failed to initialize storage");
    
    let start = std::time::Instant::now();
    let contexts = storage.fetch_context("Nikolas Alexandrakis AFM", "legal_user").await.expect("Search failed");
    let elapsed = start.elapsed();
    
    assert!(elapsed.as_millis() < 500, "Latency must be sub-500ms");
    assert!(!contexts.is_empty(), "Should return context");
    
    let report = shield.sanitize_prompt(&contexts[0], None).expect("Scrubbing failed");
    assert!(report.sanitized_text.contains("[TOKEN_"), "Should redact AFM");
}
