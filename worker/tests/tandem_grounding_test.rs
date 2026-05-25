use worker::{SearchBoostQueue, LocalLibrarian};
use iw_warden::WardenEngine;
use iw_core::{PiiShield, GroundingShield};
use secrecy::SecretVec;
use std::sync::Arc;
use std::collections::HashMap;

#[tokio::test]
async fn test_tandem_grounding_resolution() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let db_path = tmp_dir.path().join("search.db").to_str().unwrap().to_string();
    let knowledge_path = tmp_dir.path().join("knowledge");
    std::fs::create_dir(&knowledge_path).unwrap();
    
    let pepper = SecretVec::new(vec![0u8; 32]);
    
    // 1. Setup Librarian (Tantivy)
    let librarian = Arc::new(LocalLibrarian::new(knowledge_path.to_str().unwrap()).await.unwrap());
    librarian.add_document("The secret project is code-named Project Icarus.", "test_user").await.unwrap();
    
    // Allow Tantivy to commit
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

    // 2. Setup Warden Engine
    let engine = WardenEngine::new(
        vec![("rule1".into(), "Icarus".into(), iw_core::EnforcementAction::Redact, iw_core::PiiCategory::InternalAsset)],
        vec![],
        vec![],
        None,
        0.85,
        &pepper,
    ).unwrap();
    let shield = Arc::new(engine);

    // 3. Setup Queue
    let queue = SearchBoostQueue::new(
        db_path, 
        &pepper, 
        Some(shield.clone()), 
        Some(shield.clone())
    ).unwrap();

    // 4. Test Scenario: RAG Blindness Resolution
    let username = "test_user";
    let raw_query = "Project Icarus";
    
    // Step A: Bridge-side Processing (Scrubbing + Sealing)
    let report = shield.sanitize_prompt(raw_query, None).unwrap();
    assert!(report.sanitized_text.contains("[TOKEN_1]"));
    assert!(!report.sanitized_text.contains("Icarus"));
    println!("Sanitized Query: {}", report.sanitized_text);
    
    let sealed_query = shield.seal_query(raw_query, username).expect("Sealing should succeed");
    
    // Step B: Enqueue (The enqueued query is sanitized, but we include the sealed side-channel)
    let job_id = queue.enqueue(
        report.sanitized_text.clone(),
        HashMap::new(),
        "thread_1".into(),
        username.into(),
        Some(sealed_query)
    ).await.unwrap();

    // Step C: Background Worker Processing (Local Retrieval)
    // This uses the unsealed query internally for accurate search.
    queue.process_next_job(librarian.clone()).await.expect("Worker processing failed");

    // Step D: Verify Result
    let result = queue.get_result(&job_id).await.unwrap().expect("Job should be complete");
    println!("Final Scrubbed Result: {}", result);
    
    // VERIFICATION:
    // 1. The search MUST succeed (meaning it used the unsealed query).
    assert!(result.contains("Project"), "Search should have found the 'Project' context");
    
    // 2. The result MUST be scrubbed (V-14 Mandate).
    assert!(result.contains("[TOKEN_1]"), "Retrieved context must be scrubbed");
    assert!(!result.contains("Icarus"), "Raw PII 'Icarus' must NOT be in the final result");
}

#[tokio::test]
async fn test_blindness_baseline_fails() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let db_path = tmp_dir.path().join("search_blind.db").to_str().unwrap().to_string();
    let knowledge_path = tmp_dir.path().join("knowledge_blind");
    std::fs::create_dir(&knowledge_path).unwrap();
    
    let pepper = SecretVec::new(vec![0u8; 32]);
    let librarian = Arc::new(LocalLibrarian::new(knowledge_path.to_str().unwrap()).await.unwrap());
    librarian.add_document("The secret project is code-named Project Icarus.", "test_user").await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

    let engine = WardenEngine::new(
        vec![("rule1".into(), "Icarus".into(), iw_core::EnforcementAction::Redact, iw_core::PiiCategory::InternalAsset)],
        vec![],
        vec![],
        None,
        0.85,
        &pepper,
    ).unwrap();
    let shield = Arc::new(engine);

    let queue = SearchBoostQueue::new(
        db_path, 
        &pepper, 
        Some(shield.clone()), 
        Some(shield.clone())
    ).unwrap();

    let username = "test_user";
    let raw_query = "Project Icarus";
    let report = shield.sanitize_prompt(raw_query, None).unwrap();

    // Enqueue WITHOUT the sealed query (simulating old behavior)
    let job_id = queue.enqueue(
        report.sanitized_text.clone(),
        HashMap::new(),
        "thread_1".into(),
        username.into(),
        None 
    ).await.unwrap();

    queue.process_next_job(librarian.clone()).await.unwrap();

    let result = queue.get_result(&job_id).await.unwrap().expect("Job should be complete");
    
    // Without the side-channel, searching for "[INTERNALASSET_1]" should return empty results.
    assert!(!result.contains("Project"), "Baseline (blind) search should have missed the context");
}
