// Security invariant tests verifying auditor hard-stop functionality when the database anchor file is missing, and verifying V-19 session isolation/AAD binding of encrypted session data.
use worker::WorkerStorage;
use iw_core::{StorageProvider, ScrubbingReport, EnforcementAction, PiiCategory};
use secrecy::SecretVec;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_hard_stop_monitor_anchor_missing() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db");
    let kb_path = dir.path().join("kb");
    std::fs::create_dir_all(&kb_path).unwrap();

    let pepper = SecretVec::new(vec![0u8; 32]);

    let storage = WorkerStorage::new(
        db_path.to_str().unwrap(),
        kb_path.to_str().unwrap(),
        pepper,
        None,
        None,
    ).await.unwrap();

    // Verify healthy state
    assert!(storage.check_health().await.is_ok());

    // 1. Simulate anchor removal
    let anchor_path = dir.path().join("audit.db.anchor");
    assert!(anchor_path.exists());
    std::fs::remove_file(&anchor_path).unwrap();

    // 2. Wait for background monitor (interval is 5s)
    sleep(Duration::from_secs(6)).await;

    // 3. Check health - THIS SHOULD FAIL if the bug is fixed
    let health_res = storage.check_health().await;
    assert!(health_res.is_err(), "Storage health should be ERR after anchor removal, but got OK");
    assert!(health_res.unwrap_err().to_string().contains("Auditor Hard-Stop"));
}

#[tokio::test]
async fn test_v19_session_isolation_aad() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("sessions.db");
    let pepper = SecretVec::new(vec![0u8; 32]);

    let manager = worker::LocalSessionManager::new(db_path.to_str().unwrap().to_string(), &pepper).unwrap();

    let username_a = "user_a";
    let username_b = "user_b";

    // 1. Create session for User A
    let ctx_a = manager.get_session(username_a).await.unwrap();
    ctx_a.pii_to_token.insert("key1".to_string(), "[TOKEN_1]".to_string());
    manager.save_session(username_a, &ctx_a).await.unwrap();

    // 2. Try to manually load User A's data as User B (Simulating session swapping)
    // We need to access the DB directly or simulate a logic error where get_session is called with wrong username for existing data.

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let encrypted_data: Vec<u8> = conn.query_row(
        "SELECT session_data FROM sessions WHERE username = ?1",
        [username_a],
        |row| row.get(0)
    ).unwrap();

    // Inject User A's data into User B's slot
    conn.execute(
        "INSERT INTO sessions (username, session_data) VALUES (?1, ?2)",
        (username_b, &encrypted_data)
    ).unwrap();

    // Clear cache
    // (LocalSessionManager uses DashMap cache, we'd need a fresh manager or clear it)
    let manager_b = worker::LocalSessionManager::new(db_path.to_str().unwrap().to_string(), &pepper).unwrap();

    let res_b = manager_b.get_session(username_b).await;

    // Decryption MUST fail because AAD (username) will be "user_b" but ciphertext was bound to "user_a"
    assert!(res_b.is_err());
    assert!(res_b.unwrap_err().to_string().contains("Decryption failed (Integrity Mismatch or Incorrect AAD)"));
}
