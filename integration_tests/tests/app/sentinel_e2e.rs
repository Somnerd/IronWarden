// End-to-end security tests verifying session isolation AAD checks, RAG blindness in output scrubbing (V-14), anchor tampering detection (V-13), engine rule matching, and ephemeral log tampering detection (V-55).
use iw_core::{PiiShield, SovereignError};
use secrecy::SecretVec;
use std::fs;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::time::{sleep, Duration};
use warden::WardenConfig;
use worker::{GroundingQueue, LocalSessionManager, WorkerStorage};

#[tokio::test]
async fn test_v19_session_isolation_aad_adversarial() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db").to_str().unwrap().to_string();
    let pepper = SecretVec::new(vec![0u8; 32]);

    // 1. Create session for User A
    {
        let sm = LocalSessionManager::new(db_path.clone(), &pepper).unwrap();
        let user_a = "alice";
        let ctx_a = sm.get_session(user_a).await.unwrap();
        ctx_a
            .pii_to_token
            .insert("secret_a".to_string(), "[TOKEN_A]".into());
        sm.save_session(user_a, &ctx_a).await.unwrap();
    }

    // 2. Create session for User B
    {
        let sm = LocalSessionManager::new(db_path.clone(), &pepper).unwrap();
        let user_b = "bob";
        let ctx_b = sm.get_session(user_b).await.unwrap();
        ctx_b
            .pii_to_token
            .insert("secret_b".to_string(), "[TOKEN_B]".into());
        sm.save_session(user_b, &ctx_b).await.unwrap();
    }

    // Allow background flusher task's first immediate tick to complete
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 3. ADVERSARIAL MOVE: Manually swap session data in the DB
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let alice_data: Vec<u8> = conn
            .query_row(
                "SELECT session_data FROM sessions WHERE username = 'alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute(
            "UPDATE sessions SET session_data = ?1 WHERE username = 'bob'",
            [alice_data],
        )
        .unwrap();
    }

    // 4. Verification: Bob tries to load his session using a FRESH manager (no cache)
    let sm_new = LocalSessionManager::new(db_path.clone(), &pepper).unwrap();
    let result = sm_new.get_session("bob").await;

    match result {
        Err(SovereignError::InternalError(e)) => {
            assert!(
                e.contains("Decryption failed") || e.contains("Session decryption failed"),
                "Expected decryption failure, got: {}",
                e
            );
            assert!(
                e.contains("Decryption failed"),
                "Expected decryption failure, got: {}",
                e
            );
        }
        _ => panic!(
            "V-19 FAILURE: Swapped session should have failed decryption! Got: {:?}",
            result
        ),
    }
}

#[tokio::test]
async fn test_v14_librarian_output_scrubbing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit_sb.db").to_str().unwrap().to_string();
    let kb_path = dir.path().join("kb_sb").to_str().unwrap().to_string();

    // Setup Engine with a rule
    let rules_yaml = "
rules:
  - id: REDACT_SECRET
    pattern: 'TOP_SECRET_PROJECT'
    type: Dictionary
    action: Redact
    category: Other
";
    let config_path = dir.path().join("rules.yaml");
    fs::write(&config_path, rules_yaml).unwrap();
    let config = WardenConfig::from_file(&config_path.to_str().unwrap()).unwrap();

    let pepper1 = SecretVec::new(vec![0u8; 32]);
    let pepper2 = SecretVec::new(vec![0u8; 32]);
    let shield = Arc::new(config.compile_engine(&pepper1).unwrap());

    // Create queue AND worker properly
    let queue = Arc::new(
        GroundingQueue::new(db_path.clone(), &pepper1, Some(shield.clone()), None).unwrap(),
    );
    let storage = WorkerStorage::new(&db_path, &kb_path, pepper2, Some((*queue).clone()), None)
        .await
        .unwrap();

    // 1. Add sensitive document to Librarian
    let librarian = Arc::new(worker::LocalLibrarian::new(&kb_path).await.unwrap());
    librarian
        .add_document(
            "The document contains TOP_SECRET_PROJECT info.",
            "test_user",
        )
        .await
        .unwrap();

    // Spawn background worker for queue
    queue.spawn_worker(librarian.clone());

    // 2. Enqueue a job with ONLY sanitized text (V-14 Enforced)
    // Query: "tell me about TOP_SECRET_PROJECT" -> sanitized to "tell me about [TOKEN_1]"
    let report = shield
        .sanitize_prompt("tell me about TOP_SECRET_PROJECT", None)
        .await
        .unwrap();
    let job_id = queue
        .enqueue(
            report.sanitized_text,
            std::collections::HashMap::new(),
            "thread_1".to_string(),
            "alice".to_string(),
        )
        .await
        .unwrap();

    // 3. Wait for worker to process
    let mut attempts = 0;
    let mut result = None;
    while attempts < 20 {
        if let Ok(Some(res)) = queue.get_result(&job_id, "sentinel_test", true).await {
            result = Some(res);
            break;
        }
        sleep(Duration::from_millis(500)).await;
        attempts += 1;
    }

    let result = result.expect("Job timed out");

    // 4. Verification: Expect RAG Blindness (Safe Fail-Closed)
    // The librarian has the raw text, but received a sanitized token. It should NOT find a match.
    assert!(!result.contains("TOP_SECRET_PROJECT"), "Librarian leakage!");
    assert!(
        result.contains("No relevant local policy context found."),
        "Expected RAG Blindness result, got: {}",
        result
    );
}

#[tokio::test]
async fn test_v13_anchor_tampering_fail_closed() {
    let dir = tempdir().unwrap();
    let db_path = dir
        .path()
        .join("audit_anchor.db")
        .to_str()
        .unwrap()
        .to_string();
    let anchor_path = dir.path().join("audit_anchor.db.anchor");
    let pepper1 = SecretVec::new(vec![0u8; 32]);
    let pepper2 = SecretVec::new(vec![0u8; 32]);

    // 1. Initialize Auditor
    let auditor = worker::audit::AsyncAuditor::spawn(&db_path, pepper1, None)
        .await
        .unwrap();
    assert!(auditor.check_health().is_ok());

    // 2. Perform a log entry
    let report = iw_core::ScrubbingReport {
        sanitized_text: "test".into(),
        is_blocked: false,
        redactions: vec![],
        token_map: iw_core::TokenMap::new(),
        potential_misses: vec![],
        execution_time_ms: 0,
    };
    auditor
        .log_report(report, "raw input".into(), "test_user".into())
        .await
        .unwrap();

    // 3. Tamper with the anchor file
    fs::write(&anchor_path, "999:badhash").unwrap();

    // 4. Wait for monitor to detect
    let mut attempts = 0;
    let mut failed = false;
    while attempts < 10 {
        if auditor.check_health().is_err() {
            failed = true;
            break;
        }
        sleep(Duration::from_millis(1000)).await;
        attempts += 1;
    }

    assert!(
        failed,
        "Auditor should have entered panic state after anchor tampering"
    );
}

#[tokio::test]
async fn test_engine_rule_matching_diagnostic() {
    let rules_yaml = "
rules:
  - id: REDACT_SECRET
    pattern: 'TOP_SECRET_PROJECT'
    type: Dictionary
    action: Redact
    category: Other
";
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("rules.yaml");
    fs::write(&config_path, rules_yaml).unwrap();
    let config = WardenConfig::from_file(&config_path.to_str().unwrap()).unwrap();
    let pepper = SecretVec::new(vec![0u8; 32]);
    let engine = config.compile_engine(&pepper).unwrap();

    let input = "The document contains TOP_SECRET_PROJECT info.";
    let report = engine.sanitize_prompt(input, None).await.unwrap();

    assert!(
        report.sanitized_text.contains("[TOKEN_1]"),
        "Engine failed to redact TOP_SECRET_PROJECT. Result: {}",
        report.sanitized_text
    );
}

#[tokio::test]
async fn test_v55_ephemeral_tampering_fail_closed() {
    let dir = tempdir().unwrap();
    let db_path = dir
        .path()
        .join("audit_v55.db")
        .to_str()
        .unwrap()
        .to_string();

    // 1. Initialize Auditor and log something
    {
        let pepper = SecretVec::new(vec![0u8; 32]);
        let auditor = worker::audit::AsyncAuditor::spawn(&db_path, pepper, None)
            .await
            .unwrap();
        let report = iw_core::ScrubbingReport {
            sanitized_text: "test".into(),
            is_blocked: false,
            redactions: vec![],
            token_map: iw_core::TokenMap::new(),
            potential_misses: vec![],
            execution_time_ms: 0,
        };
        auditor
            .log_report(report, "sensitive raw data".into(), "user123".into())
            .await
            .unwrap();
    } // Drop auditor to close DB

    // 2. ADVERSARIAL MOVE: Tamper with the raw log ciphertext
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE ephemeral_raw_logs SET encrypted_data = X'DEADBEEF' WHERE id = 1",
            [],
        )
        .unwrap();
    }

    // 3. Verification: freshest boot should fail integrity walk
    let pepper = SecretVec::new(vec![0u8; 32]);
    let result = worker::audit::AsyncAuditor::spawn(&db_path, pepper, None).await;

    match result {
        Err(SovereignError::InternalError(e)) => {
            assert!(
                e.contains("DB Init Failed"),
                "Expected DB initialization failure, got: {}",
                e
            );
        }
        Ok(_) => panic!("V-55 FAILURE: Tampered raw log was not detected!"),
        Err(e) => panic!("V-55 FAILURE: Unexpected error during boot: {}", e),
    }
}
