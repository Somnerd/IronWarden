// Security integration tests verifying V-19 session swap protection, ensuring session decryption fails with an integrity mismatch if session data is requested for a different username than it was originally bound to.
use iw_core::SessionContext;
use secrecy::SecretVec;
use worker::grounding::LocalSessionManager;

#[tokio::test]
async fn test_v19_session_swap_integrity() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let db_path = tmp_dir
        .path()
        .join("session.db")
        .to_str()
        .unwrap()
        .to_string();
    let pepper = SecretVec::new(vec![0u8; 32]);

    let manager = LocalSessionManager::new(db_path.clone(), &pepper).unwrap();

    let user_a = "user_a";
    let user_b = "user_b";

    let ctx_a = SessionContext::new();
    ctx_a
        .identities
        .insert("alice".to_string(), "[TOKEN_A]".to_string());

    manager
        .save_session(user_a, &ctx_a)
        .await
        .expect("Failed to save session A");

    // Now try to load session B using A's data (simulating a swap in DB)
    // We can't easily swap it in SQLite from here without more work,
    // but we can verify that if we pass the wrong username to decrypt, it fails.

    // In searchboost.rs:
    // let decrypted = self.cipher.decrypt(nonce, payload)
    // where payload.aad = username.as_bytes()

    // If we try to get_session for user_b, but the DB has been tampered with A's data for user_b's row.

    // Let's manually tamper the DB.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let session_data: Vec<u8> = conn
        .query_row(
            "SELECT session_data FROM sessions WHERE username = 'user_a'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO sessions (username, session_data) VALUES ('user_b', ?1)",
        [session_data],
    )
    .unwrap();

    // Now try to load user_b. It should fail because AAD will be 'user_b' but the ciphertext was bound to 'user_a'.
    let result = manager.get_session(user_b).await;

    match result {
        Err(e) => {
            println!("Got expected error: {}", e);
            assert!(
                format!("{}", e).contains("Integrity Mismatch")
                    || format!("{}", e).contains("decryption failed")
            );
        }
        Ok(_) => panic!("V-19: Session swap succeeded! Identity leak possible."),
    }
}
