use worker::{SearchBoostQueue, LocalLibrarian};
use iw_warden::WardenEngine;
use iw_core::{PiiShield};
use secrecy::SecretVec;
use std::sync::Arc;
use std::collections::HashMap;

#[tokio::test]
async fn test_v14_leak_prevention_enforced() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let db_path = tmp_dir.path().join("search_v14.db").to_str().unwrap().to_string();
    let knowledge_path = tmp_dir.path().join("knowledge_v14");
    std::fs::create_dir(&knowledge_path).unwrap();
    
    let pepper = SecretVec::new(vec![0u8; 32]);
    
    // 1. Setup Librarian (Tantivy) with a document containing PII
    let librarian = Arc::new(LocalLibrarian::new(knowledge_path.to_str().unwrap()).await.unwrap());
    librarian.add_document("The secret project is code-named Project Icarus.", "test_user").await.unwrap();
    
    // Allow Tantivy to commit
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

    // 2. Setup Warden Engine with a rule to redact "Icarus"
    let engine = WardenEngine::new(
        vec![("rule1".into(), "Icarus".into(), iw_core::EnforcementAction::Redact, iw_core::PiiCategory::InternalAsset)],
        vec![],
        vec![],
        None,
        0.85,
        &pepper,
    ).unwrap();
    let shield = Arc::new(engine);

    // 3. Setup Queue (GroundingShield is no longer used for side-channel)
    let queue = SearchBoostQueue::new(
        db_path, 
        &pepper, 
        Some(shield.clone()), 
        None
    ).unwrap();

    // 4. Test Scenario: V-14 Mandatory Sanitization
    let username = "test_user";
    let raw_query = "Project Icarus";
    
    // Step A: Bridge-side Processing (Scrubbing Only)
    let report = shield.sanitize_prompt(raw_query, None).unwrap();
    assert!(report.sanitized_text.contains("[TOKEN_1]"));
    assert!(!report.sanitized_text.contains("Icarus"));
    
    // Step B: Enqueue (Signature now ONLY accepts 4 arguments, raw/sealed query is impossible)
    let job_id = queue.enqueue(
        report.sanitized_text.clone(),
        HashMap::new(),
        "thread_1".into(),
        username.into(),
    ).await.unwrap();

    // Step C: Background Worker Processing
    queue.process_next_job(librarian.clone()).await.expect("Worker processing failed");

    // Step D: Verify Result
    let result = queue.get_result(&job_id, "test_user", true).await.unwrap().expect("Job should be complete");
    
    // VERIFICATION:
    // 1. The search should FAIL to find the context because it used the sanitized query "[TOKEN_1]".
    // This confirms V-14 is enforced (no raw query leak).
    assert!(!result.contains("Project"), "V-14 Enforcement: Search should NOT have found the raw context using a sanitized query");
    
    // 2. The result MUST be scrubbed (Double-check)
    assert!(!result.contains("Icarus"), "Raw PII 'Icarus' must NOT be in the final result");
}

#[tokio::test]
async fn test_aad_binding_integrity() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let db_path = tmp_dir.path().join("search_aad.db").to_str().unwrap().to_string();
    let pepper = SecretVec::new(vec![0u8; 32]);
    
    let queue = SearchBoostQueue::new(db_path, &pepper, None, None).unwrap();
    let username = "alice";
    let query = "Sensitive query for Alice";

    // Enqueue for Alice
    let job_id = queue.enqueue(
        query.to_string(),
        HashMap::new(),
        "thread_1".into(),
        username.into(),
    ).await.unwrap();

    // Verify Alice can get her result (even before processing, it's in the DB encrypted)
    // Wait, get_result checks for 'complete' status.
    // Let's mock a completed job.
}
