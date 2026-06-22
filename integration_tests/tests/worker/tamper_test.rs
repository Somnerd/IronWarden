// Security integration tests verifying GAP-02 boot/handshake tamper detection, ensuring that the auditor fails to initialize if existing database record integrity has been modified.
use std::time::Duration;
use worker::AsyncAuditor;
use secrecy::SecretVec;
use tempfile::tempdir;

#[tokio::test]
async fn test_gap_02_boot_handshake_tamper_detection() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db");
    let pepper_bytes = vec![0u8; 32];
    
    // 1. Initialize a clean auditor to create the DB and anchor
    {
        let pepper = SecretVec::new(pepper_bytes.clone());
        let auditor = AsyncAuditor::spawn(db_path.to_str().unwrap(), pepper, None).await.unwrap();
        // Log one report to create a record
        let report = iw_core::ScrubbingReport {
            sanitized_text: "test".to_string(),
            redactions: vec![],
            token_map: iw_core::TokenMap::new(),
            is_blocked: false,
            potential_misses: vec![],
            execution_time_ms: 1,
        };
        auditor.log_report(report, "test".to_string(), "user_1".into()).await.unwrap();
        // Wait a bit for the auditor to finish writing
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    
    // 2. Tamper with the DB
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute("UPDATE audit_reports SET integrity_hash = 'TAMPERED' WHERE id = 1", []).unwrap();
    
    // 3. Attempt to respawn the auditor - it should fail the handshake
    let pepper = SecretVec::new(pepper_bytes);
    let result = AsyncAuditor::spawn(db_path.to_str().unwrap(), pepper, None).await;
    
    match result {
        Ok(_) => panic!("Handshake should have failed due to tampering"),
        Err(e) => {
            let err_msg = e.to_string();
            println!("Caught Expected Error: {}", err_msg);
            assert!(err_msg.contains("DB Init Failed"), "Error should indicate DB initialization failure");
        }
    }
}
