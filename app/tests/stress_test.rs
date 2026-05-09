use std::sync::Arc;
use worker::WorkerStorage;
use iw_core::{ScrubbingReport, TokenMap, StorageProvider};
use tokio::time::{sleep, Duration};
use tempfile::tempdir;

#[tokio::test]
async fn test_auditor_concurrency_stress() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("stress.db").to_str().unwrap().to_string();
    let lancedb_path = dir.path().join("lancedb").to_str().unwrap().to_string();
    let pepper = vec![0u8; 32];
    let storage = Arc::new(WorkerStorage::new(&db_path, &lancedb_path, secrecy::SecretVec::new(pepper), None).await.unwrap());

    let num_requests = 100; // Stressing the MPSC channel
    let mut handles = vec![];

    println!("🚀 Firing {} concurrent audit events...", num_requests);

    for i in 0..num_requests {
        let storage_clone = storage.clone();
        let handle = tokio::spawn(async move {
            let report = ScrubbingReport {
                sanitized_text: format!("Safe text {}", i),
                is_blocked: false,
                redactions: vec![],
                token_map: TokenMap::new(),
                potential_misses: vec![],
                execution_time_ms: 1,
            };
            storage_clone.log_audit_event(&report, "Raw sensitive info").await.unwrap();
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }

    // Allow background task to catch up
    sleep(Duration::from_millis(1000)).await;

    // Verify all records exist in DB
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM audit_reports", [], |r| r.get(0)).unwrap();
    
    println!("✅ Stress Test Complete. Logged {}/{} events.", count, num_requests);
    assert_eq!(count, num_requests as i64);
}
