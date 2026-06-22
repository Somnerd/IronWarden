// Integration tests verifying auditor database creation, HMAC chain integrity, AES-256-GCM encryption roundtrips, database busy fail-closed behavior, and HMAC chain breakage detection.
use worker::audit::AsyncAuditor;
use iw_core::{ScrubbingReport, Redaction, EnforcementAction};
use tempfile::NamedTempFile;
use std::collections::HashMap;
use rusqlite::Connection;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hkdf::Hkdf;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use secrecy::SecretVec;
use iw_core::{KDF_SALT_ENCRYPTION, KDF_SALT_INTEGRITY, KDF_SALT_GENESIS};

type HmacSha256 = Hmac<Sha256>;

fn derive_keys(pepper: &[u8]) -> (Key<Aes256Gcm>, [u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, pepper);
    let mut enc_key = [0u8; 32];
    hk.expand(KDF_SALT_ENCRYPTION, &mut enc_key).unwrap();
    let mut hmac_key = [0u8; 32];
    hk.expand(KDF_SALT_INTEGRITY, &mut hmac_key).unwrap();
    let mut genesis_hash = [0u8; 32];
    hk.expand(KDF_SALT_GENESIS, &mut genesis_hash).unwrap();
    (Key::<Aes256Gcm>::from_slice(&enc_key).clone(), hmac_key, genesis_hash)
}

#[tokio::test]
async fn test_audit_db_creation() {
    let tmp_file = NamedTempFile::new().unwrap();
    let db_path = tmp_file.path().to_str().unwrap();
    let pepper = vec![0u8; 32];

    let auditor = AsyncAuditor::spawn(db_path, SecretVec::new(pepper), None).await.unwrap();
    
    // Trigger initialization by sending a no-op message
    auditor.log_report(ScrubbingReport {
        sanitized_text: "".into(),
        is_blocked: false,
        redactions: vec![],
        token_map: HashMap::new(),
        potential_misses: vec![],
        execution_time_ms: 0,
    }, "".into(), "test_user".into()).await;
    
    // --- STABILITY FIX: Retry Loop for DB Creation ---
    let mut tables_ready = false;
    for _ in 0..10 {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        if let Ok(conn) = Connection::open(db_path) {
            if let Ok(mut stmt) = conn.prepare("SELECT name FROM sqlite_master WHERE type='table'") {
                let table_names: Vec<String> = stmt.query_map([], |row| row.get(0)).unwrap()
                    .map(|r| r.unwrap()).collect();
                if table_names.contains(&"audit_reports".to_string()) && table_names.contains(&"ephemeral_raw_logs".to_string()) {
                    tables_ready = true;
                    break;
                }
            }
        }
    }

    assert!(tables_ready, "Audit tables were not created within the timeout period.");
}

#[tokio::test]
async fn test_hmac_chain_integrity() {
    let tmp_file = NamedTempFile::new().unwrap();
    let db_path = tmp_file.path().to_str().unwrap();
    let pepper = b"a_very_secret_pepper_32_bytes_long".to_vec();
    let (_, hmac_key, genesis_hash) = derive_keys(&pepper);

    let auditor = AsyncAuditor::spawn(db_path, SecretVec::new(pepper.clone()), None).await.unwrap();
    
    let report = ScrubbingReport {
        sanitized_text: "Hello [TOKEN_1]".to_string(),
        is_blocked: false,
        redactions: vec![Redaction {
            rule_id: "id_alice".to_string(),
            action: EnforcementAction::Redact,
            offset: 0,
            length: 5,
            placeholder: "[TOKEN_1]".to_string(),
            category: iw_core::traits::PiiCategory::Other,
        }],
        token_map: HashMap::new(),
        execution_time_ms: 10,
        potential_misses: vec![],
    };

    auditor.log_report(report.clone(), "Hello Alice".to_string(), "Alice".into()).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;

    let conn = Connection::open(db_path).unwrap();
    let (redactions_json, integrity_hash, timestamp, is_blocked, payload_hash_hex): (String, String, String, bool, String) = conn.query_row(
        "SELECT redactions_json, integrity_hash, timestamp, is_blocked, payload_hash FROM audit_reports ORDER BY id DESC LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
    ).unwrap();

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&hmac_key).unwrap();
    mac.update(&genesis_hash);
    mac.update(timestamp.as_bytes());
    mac.update(b"Alice"); // Bind username to integrity chain
    mac.update(&[is_blocked as u8]);
    
    let redactions_vec: Vec<Redaction> = serde_json::from_str(&redactions_json).unwrap_or_default();
    let redactions_bin = bincode::serialize(&redactions_vec).unwrap_or_default();
    mac.update(&redactions_bin);
    let payload_hash = hex::decode(&payload_hash_hex).unwrap();
    mac.update(&payload_hash);

    let expected_hash = hex::encode(mac.finalize().into_bytes());

    assert_eq!(integrity_hash, expected_hash);
}

#[tokio::test]
async fn test_encryption_roundtrip() {
    let tmp_file = NamedTempFile::new().unwrap();
    let db_path = tmp_file.path().to_str().unwrap();
    let pepper = b"a_very_secret_pepper_32_bytes_long".to_vec();
    let (_, _, genesis_hash) = derive_keys(&pepper);

    let auditor = AsyncAuditor::spawn(db_path, SecretVec::new(pepper.clone()), None).await.unwrap();
    let raw_input = "Extremely Sensitive Data";
    
    let report = ScrubbingReport {
        sanitized_text: "[TOKEN_1]".to_string(),
        is_blocked: false,
        redactions: vec![],
        token_map: HashMap::new(),
        execution_time_ms: 5,
        potential_misses: vec![],
    };

    auditor.log_report(report, raw_input.to_string(), "user_1".into()).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;

    let conn = Connection::open(db_path).unwrap();
    let (encrypted_data, nonce_bytes, _integrity_hash_hex): (Vec<u8>, Vec<u8>, String) = conn.query_row(
        "SELECT e.encrypted_data, e.nonce, a.integrity_hash FROM ephemeral_raw_logs e JOIN audit_reports a ON e.id = a.id ORDER BY e.id DESC LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    ).unwrap();

    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut composite_aad = String::new();
    composite_aad.push_str(&hex::encode(&genesis_hash));
    composite_aad.push_str("user_1");

    let bound_info = iw_core::crypto::build_hkdf_info(KDF_SALT_ENCRYPTION, &composite_aad);

    // Derive key using HKDF to ensure unique keys per context
    let hk = Hkdf::<Sha256>::new(None, &pepper);
    let mut key_bytes = [0u8; 32];
    hk.expand(&bound_info, &mut key_bytes).unwrap();
    let enc_key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(enc_key);

    let payload = aes_gcm::aead::Payload {
        msg: encrypted_data.as_slice(),
        aad: composite_aad.as_bytes(),
    };
    let decrypted = cipher.decrypt(nonce, payload).expect("Decryption failed");
    assert_eq!(String::from_utf8(decrypted).unwrap(), raw_input);
}

#[tokio::test]
async fn test_database_busy_fail_closed() {
    let tmp_file = NamedTempFile::new().unwrap();
    let db_path = tmp_file.path().to_str().unwrap();
    let pepper = b"a_very_secret_pepper_32_bytes_long".to_vec();

    let auditor = AsyncAuditor::spawn(db_path, SecretVec::new(pepper.clone()), None).await.unwrap();

    // Lock the database exclusively from another connection
    let conn = Connection::open(db_path).unwrap();
    conn.execute("BEGIN EXCLUSIVE TRANSACTION", []).unwrap();

    let report = ScrubbingReport {
        sanitized_text: "Test".to_string(),
        is_blocked: false,
        redactions: vec![],
        token_map: HashMap::new(),
        execution_time_ms: 10,
        potential_misses: vec![],
    };

    // The auditor uses a 2000ms busy_timeout. We expect it to fail with DatabaseBusy
    let result = auditor.log_report(report, "Raw".to_string(), "test_user".into()).await;
    
    assert!(result.is_err(), "Expected DatabaseBusy error, but succeeded");
    if let Err(iw_core::SovereignError::DatabaseBusy(_)) = result {
        // Success
    } else {
        panic!("Expected DatabaseBusy error, got: {:?}", result);
    }
    
    conn.execute("ROLLBACK", []).unwrap();
}

#[tokio::test]
async fn test_hmac_chain_breakage() {
    let tmp_file = NamedTempFile::new().unwrap();
    let db_path = tmp_file.path().to_str().unwrap();
    let pepper = b"a_very_secret_pepper_32_bytes_long".to_vec();

    // Spawn first auditor and write a log
    {
        let auditor = AsyncAuditor::spawn(db_path, SecretVec::new(pepper.clone()), None).await.unwrap();
        let report = ScrubbingReport {
            sanitized_text: "Valid".to_string(),
            is_blocked: false,
            redactions: vec![],
            token_map: HashMap::new(),
            execution_time_ms: 10,
            potential_misses: vec![],
        };
        auditor.log_report(report, "Raw".to_string(), "user_1".into()).await.unwrap();
    }
    
    // Give it time to write and shut down
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Tamper with the database
    let conn = Connection::open(db_path).unwrap();
    conn.execute("UPDATE audit_reports SET is_blocked = 1", []).unwrap();
    drop(conn);

    // Attempt to spawn a new auditor on the tampered database
    let result = AsyncAuditor::spawn(db_path, SecretVec::new(pepper.clone()), None).await;
    assert!(result.is_err(), "Auditor spawn should fail due to HMAC chain breakage");
    if let Err(iw_core::SovereignError::InternalError(msg)) = result {
        assert!(msg.contains("DB Init Failed"), "Expected DB Init Failed message");
    } else {
        panic!("Expected InternalError for DB Init Failed");
    }
}
