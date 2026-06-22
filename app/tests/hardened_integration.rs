// Hardened integration pipeline tests verifying Unicode normalization (homoglyph/zero-width character handling) with offset drift correction, audit persistence, and session tokenization consistency.
use std::sync::Arc;
use warden::{WardenConfig};
use worker::{WorkerStorage};
use iw_core::{PiiShield, StorageProvider};
use tokio::time::{sleep, Duration};
use tempfile::tempdir;
use std::fs;

#[tokio::test]
async fn test_end_to_end_hardened_pipeline() {
    // 1. Setup temporary workspace
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db").to_str().unwrap().to_string();
    let config_path = dir.path().join("rules.yaml");
    
    let rules_yaml = r#"
rules:
  - id: "id_alice"
    pattern: "Alice"
    type: "Dictionary"
  - id: "id_ssn"
    pattern: '\d{3}-\d{2}-\d{4}'
    type: "Regex"
"#;
    fs::write(&config_path, rules_yaml).unwrap();

    // 2. Initialize Components
    let config = WardenConfig::from_file(&config_path).unwrap();
    let pepper = secrecy::SecretVec::new(vec![0u8; 32]);
    let shield = Arc::new(config.compile_engine(&pepper).unwrap());
    
    let pepper = vec![0u8; 32];
    let lancedb_dir = dir.path().join("lancedb");
    let lancedb_path = lancedb_dir.to_str().unwrap();
    let storage = Arc::new(WorkerStorage::new(&db_path, &lancedb_path, secrecy::SecretVec::new(pepper), None, None).await.unwrap());

    // 3. Attack Vector: "Greeting from A[ZERO_WIDTH]lice (Greek Alpha)."
    // Raw length: 30 bytes
    let raw_input = "Greeting from \u{0391}\u{200B}lice."; 
    
    // 4. Process through Shield
    let report = shield.sanitize_prompt(raw_input, None).unwrap();
    
    // VERIFY: Normalization caught the homoglyph and zero-width char
    assert!(report.sanitized_text.contains("[TOKEN_1]"));
    assert!(!report.sanitized_text.contains("Alice"));
    
    // VERIFY: Offset drift corrected. Offset 14 in original is where the 'Α' starts.
    let redaction = &report.redactions[0];
    assert_eq!(redaction.offset, 14);
    assert_eq!(redaction.length, 9); // Greek Α (2) + ZWSP (3) + lice (4) = 9 bytes
    
    // 5. Audit Logging
    storage.log_audit_event(&report, raw_input, "test_user").await.unwrap();
    
    // Give async task time to flush
    sleep(Duration::from_millis(500)).await;

    // 6. Verify Persistence & Integrity
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let mut stmt = conn.prepare("SELECT redactions_json, integrity_hash FROM audit_reports").unwrap();
    let mut rows = stmt.query([]).unwrap();
    
    if let Some(row) = rows.next().unwrap() {
        let json: String = row.get(0).unwrap();
        let hash: String = row.get(1).unwrap();
        
        assert!(json.contains("id_alice")); // Verify real Rule ID preservation
        assert!(!hash.is_empty()); // Verify HMAC chain started
        println!("✅ Audit Entry Verified. Hash: {}", hash);
    } else {
        panic!("No audit entry found!");
    }

    // 7. Verify Encrypted Queue
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM ephemeral_raw_logs", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1);
    println!("✅ Encrypted Ephemeral Log count: {}", count);
}

#[tokio::test]
async fn test_stateful_tokenization_session_consistency() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("rules.yaml");
    let rules_yaml = "rules: [{id: id_name, pattern: Alice, type: Dictionary}]";
    fs::write(&config_path, rules_yaml).unwrap();
    let config = WardenConfig::from_file(&config_path).unwrap();
    let pepper = secrecy::SecretVec::new(vec![0u8; 32]);
    let shield = config.compile_engine(&pepper).unwrap();

    let session = iw_core::SessionContext::new();

    // First call
    let report1 = shield.sanitize_prompt("Hello Alice.", Some(&session)).unwrap();
    let token1 = report1.redactions[0].placeholder.clone();

    // Second call with same session
    let report2 = shield.sanitize_prompt("Alice is here.", Some(&session)).unwrap();
    let token2 = report2.redactions[0].placeholder.clone();

    assert_eq!(token1, token2, "Tokens must be consistent within the same session");
    assert!(report2.sanitized_text.contains(&token1));

    // Third call with NEW session
    let new_session = iw_core::SessionContext::new();
    let report3 = shield.sanitize_prompt("Alice again.", Some(&new_session)).unwrap();
    let token3 = report3.redactions[0].placeholder.clone();

    // Note: Since it's a new session, it starts from TOKEN_1
    assert_eq!(token3, "[TOKEN_1]"); 
}
