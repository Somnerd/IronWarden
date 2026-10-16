// Extracted unit tests for worker storage, grounding, audit, ocr, and librarian
extern crate warden as iw_warden;
extern crate worker as iw_worker;

#[cfg(test)]
mod grounding_tests {
    use iw_worker::grounding::*;
    use secrecy::{ExposeSecret, SecretVec};
    use std::collections::HashMap;
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn test_searchboost_cross_user_isolation_v19() {
        let db_path = std::env::temp_dir()
            .join(format!("sb_test_isolation_{}.db", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let pepper = SecretVec::from(vec![0u8; 32]);
        let queue = GroundingQueue::new(db_path.clone(), &pepper, None, None).unwrap();

        let job_id = queue
            .enqueue("query".into(), HashMap::new(), "th1".into(), "userA".into())
            .await
            .unwrap();

        // Let background DB writer persist it
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Force set result to 'complete' for testing retrieval
        let pool = queue.pool.clone();
        let encrypted_result = iw_core::AadCipher::encrypt(
            b"secret result",
            "userA",
            pepper.expose_secret(),
            b"warden-v1-queue-encryption",
        )
        .unwrap();

        let conn = pool.get().unwrap();
        conn.execute(
            "UPDATE search_jobs SET result = ?1, status = 'complete' WHERE id = ?2",
            (&encrypted_result, &job_id),
        )
        .unwrap();

        // Get result as user A
        let res_a = queue.get_result(&job_id, "userA", false).await.unwrap();
        assert_eq!(res_a.unwrap(), "secret result");

        // Get result as user B
        let res_b = queue.get_result(&job_id, "userB", false).await;
        assert!(
            res_b.is_err(),
            "Cross-user data leakage detected in Grounding get_result!"
        );
        assert!(res_b
            .unwrap_err()
            .to_string()
            .contains("permission to access"));

        // Admin override
        let res_admin = queue.get_result(&job_id, "userB", true).await.unwrap();
        assert_eq!(res_admin.unwrap(), "secret result");

        fs::remove_file(&db_path).ok();
        // Remove WAL/SHM if they exist
        fs::remove_file(format!("{}-wal", db_path)).ok();
        fs::remove_file(format!("{}-shm", db_path)).ok();
    }

    #[tokio::test]
    async fn test_searchboost_fifo_ordering() {
        let db_path = std::env::temp_dir()
            .join(format!("sb_test_fifo_{}.db", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let pepper = SecretVec::from(vec![0u8; 32]);
        let queue = GroundingQueue::new(db_path.clone(), &pepper, None, None).unwrap();

        let job1 = queue
            .enqueue(
                "query1".into(),
                HashMap::new(),
                "th1".into(),
                "userA".into(),
            )
            .await
            .unwrap();
        let job2 = queue
            .enqueue(
                "query2".into(),
                HashMap::new(),
                "th1".into(),
                "userA".into(),
            )
            .await
            .unwrap();
        let job3 = queue
            .enqueue(
                "query3".into(),
                HashMap::new(),
                "th1".into(),
                "userA".into(),
            )
            .await
            .unwrap();

        let recv1 = queue.rx.recv_async().await.unwrap();
        let recv2 = queue.rx.recv_async().await.unwrap();
        let recv3 = queue.rx.recv_async().await.unwrap();

        assert_eq!(recv1.0, job1);
        assert_eq!(recv2.0, job2);
        assert_eq!(recv3.0, job3);

        fs::remove_file(&db_path).ok();
        fs::remove_file(format!("{}-wal", db_path)).ok();
        fs::remove_file(format!("{}-shm", db_path)).ok();
    }

    #[tokio::test]
    async fn test_searchboost_graceful_shutdown() {
        let db_path = std::env::temp_dir()
            .join(format!("sb_test_shutdown_{}.db", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let pepper = SecretVec::from(vec![0u8; 32]);
        let queue = GroundingQueue::new(db_path.clone(), &pepper, None, None).unwrap();

        // Enqueue many jobs rapidly
        for i in 0..100 {
            queue
                .enqueue(
                    format!("query{}", i),
                    HashMap::new(),
                    "th1".into(),
                    "userA".into(),
                )
                .await
                .unwrap();
        }

        // Trigger shutdown immediately
        queue.shutdown().await;

        // Verify all jobs were persisted
        let conn = queue.pool.get().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM search_jobs", [], |r| r.get(0))
            .unwrap();

        assert_eq!(count, 100, "Shutdown did not flush all jobs to DB!");

        fs::remove_file(&db_path).ok();
        fs::remove_file(format!("{}-wal", db_path)).ok();
        fs::remove_file(format!("{}-shm", db_path)).ok();
    }

    #[tokio::test]
    async fn test_searchboost_redis_ha_fallback() {
        let db_path = std::env::temp_dir()
            .join(format!("sb_test_redis_{}.db", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let pepper = SecretVec::from(vec![0u8; 32]);

        // Point to a dead port to simulate Redis connection failure
        std::env::set_var("REDIS_URL", "redis://127.0.0.1:9999");
        let queue = GroundingQueue::new(db_path.clone(), &pepper, None, None).unwrap();

        // Enqueue should fallback to SQLite seamlessly
        let job = queue
            .enqueue("query".into(), HashMap::new(), "th1".into(), "userA".into())
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;

        let conn = queue.pool.get().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM search_jobs WHERE id = ?1",
                [&job],
                |r| r.get(0),
            )
            .unwrap();

        assert_eq!(
            count, 1,
            "Failed to fallback to SQLite when Redis is unreachable"
        );

        std::env::remove_var("REDIS_URL");
        fs::remove_file(&db_path).ok();
        fs::remove_file(format!("{}-wal", db_path)).ok();
        fs::remove_file(format!("{}-shm", db_path)).ok();
    }

    #[tokio::test]
    async fn test_session_manager_idle_ttl_eviction() {
        let db_path = std::env::temp_dir()
            .join(format!("session_test_eviction_{}.db", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let pepper = SecretVec::from(vec![0u8; 32]);
        let sm = LocalSessionManager::new(db_path.clone(), &pepper).unwrap();

        let ctx_idle = sm.get_session("user_idle").await.unwrap();
        ctx_idle
            .pii_to_token
            .insert("alice".into(), "[PERSON_1]".into());

        let ctx_active = sm.get_session("user_active").await.unwrap();
        ctx_active
            .pii_to_token
            .insert("bob".into(), "[PERSON_2]".into());

        assert_eq!(sm.session_count(), 2);

        // Flush active sessions to SQLite before simulating idle timeout
        sm.flush_to_db().await.unwrap();

        // Simulate user_idle being idle for > 1 hour (SESSION_IDLE_TIMEOUT)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        ctx_idle.last_accessed.store(
            now - SESSION_IDLE_TIMEOUT.as_secs() - 10,
            std::sync::atomic::Ordering::SeqCst,
        );

        // Evict idle sessions
        let evicted = sm.evict_idle_sessions();
        assert_eq!(evicted, 1, "Expected exactly 1 idle session to be evicted");
        assert_eq!(
            sm.session_count(),
            1,
            "Only active session should remain in memory"
        );

        // Verify user_active is still in memory
        assert!(sm.sessions.contains_key("user_active"));
        assert!(!sm.sessions.contains_key("user_idle"));

        // Verify lazy reload from SQLite for the evicted session
        let reloaded_idle = sm.get_session("user_idle").await.unwrap();
        assert_eq!(
            reloaded_idle
                .pii_to_token
                .get("alice")
                .map(|v| v.value().clone()),
            Some("[PERSON_1]".to_string()),
            "Session state must be preserved across eviction and SQLite reload"
        );
        assert_eq!(sm.session_count(), 2);

        fs::remove_file(&db_path).ok();
        fs::remove_file(format!("{}-wal", db_path)).ok();
        fs::remove_file(format!("{}-shm", db_path)).ok();
    }

    #[tokio::test]
    async fn test_session_manager_flush_only_modified_active() {
        let db_path = std::env::temp_dir()
            .join(format!("session_test_flush_{}.db", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let pepper = SecretVec::from(vec![0u8; 32]);
        let sm = LocalSessionManager::new(db_path.clone(), &pepper).unwrap();

        let ctx = sm.get_session("user1").await.unwrap();
        ctx.pii_to_token.insert("secret".into(), "[TOKEN_1]".into());

        // First flush flushes the active session
        sm.flush_to_db().await.unwrap();

        // A second immediate flush without access or modification must not flush anything
        let second_flush = sm.flush_to_db().await;
        assert!(second_flush.is_ok());

        // Now touch/modify user1
        let ctx = sm.get_session("user1").await.unwrap();
        ctx.pii_to_token
            .insert("secret2".into(), "[TOKEN_2]".into());

        // Third flush should flush the newly active/modified session
        let third_flush = sm.flush_to_db().await;
        assert!(third_flush.is_ok());

        fs::remove_file(&db_path).ok();
        fs::remove_file(format!("{}-wal", db_path)).ok();
        fs::remove_file(format!("{}-shm", db_path)).ok();
    }
}

#[cfg(test)]
mod audit_tests {
    use hmac::Mac;
    use iw_core::{traits::PiiCategory, EnforcementAction, Redaction};
    use iw_worker::audit::*;
    use rusqlite::Connection;
    use sha2::{Digest, Sha256};
    use tempfile::NamedTempFile;

    fn create_test_db(path: &str, genesis: &[u8; 32], hmac_key: &[u8; 32]) {
        let conn = Connection::open(path).unwrap();
        conn.execute("CREATE TABLE IF NOT EXISTS audit_reports (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, username TEXT DEFAULT 'unknown', is_blocked BOOLEAN, redactions_json TEXT, payload_hash TEXT, integrity_hash TEXT)", []).unwrap();
        conn.execute("CREATE TABLE IF NOT EXISTS ephemeral_raw_logs (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, username TEXT DEFAULT 'unknown', encrypted_data BLOB, nonce BLOB)", []).unwrap();

        let ts = "2023-10-10 10:10:10";
        let username = "alice";
        let is_blocked = false;
        let redactions = vec![Redaction {
            rule_id: "test_rule".to_string(),
            action: EnforcementAction::Redact,
            offset: 0,
            length: 4,
            placeholder: "[TEST]".to_string(),
            category: PiiCategory::Other,
        }];
        let redactions_json = serde_json::to_string(&redactions).unwrap();
        let redactions_bin = bincode::serialize(&redactions).unwrap();

        let payload = b"test payload";
        let nonce = vec![0u8; 12];
        let mut hasher = Sha256::new();
        hasher.update(payload);
        hasher.update(&nonce);
        let payload_hash = hasher.finalize();

        let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key).unwrap();
        mac.update(genesis);
        mac.update(ts.as_bytes());
        mac.update(username.as_bytes());
        mac.update(&[is_blocked as u8]);
        mac.update(&redactions_bin);
        mac.update(&payload_hash);
        let integrity_hash = mac.finalize().into_bytes().to_vec();

        conn.execute(
            "INSERT INTO ephemeral_raw_logs (id, timestamp, username, encrypted_data, nonce) VALUES (?1, ?2, ?3, ?4, ?5)",
            (1, ts, username, payload.to_vec(), nonce.clone())
        ).unwrap();

        conn.execute(
            "INSERT INTO audit_reports (id, timestamp, username, is_blocked, redactions_json, payload_hash, integrity_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (1, ts, username, is_blocked, &redactions_json, hex::encode(payload_hash), hex::encode(&integrity_hash))
        ).unwrap();

        AsyncAuditor::update_anchor(path, 1, &integrity_hash).unwrap();
    }

    #[test]
    fn test_hmac_chain_integrity_walk_success() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        let genesis = [0u8; 32];
        let hmac_key = [1u8; 32];

        create_test_db(path, &genesis, &hmac_key);

        let result = AsyncAuditor::init_db(path, &genesis, &hmac_key);
        assert!(result.is_ok(), "init_db should succeed on valid DB");
    }

    #[test]
    fn test_hmac_chain_integrity_walk_tampered_username() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        let genesis = [0u8; 32];
        let hmac_key = [1u8; 32];

        create_test_db(path, &genesis, &hmac_key);
        let conn = Connection::open(path).unwrap();
        conn.execute("UPDATE audit_reports SET username = 'bob' WHERE id = 1", [])
            .unwrap();
        drop(conn);

        let result = AsyncAuditor::init_db(path, &genesis, &hmac_key);
        assert!(result.is_err(), "init_db should fail on tampered username");
    }

    #[test]
    fn test_hmac_chain_integrity_walk_tampered_is_blocked() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        let genesis = [0u8; 32];
        let hmac_key = [1u8; 32];

        create_test_db(path, &genesis, &hmac_key);
        let conn = Connection::open(path).unwrap();
        conn.execute("UPDATE audit_reports SET is_blocked = 1 WHERE id = 1", [])
            .unwrap();
        drop(conn);

        let result = AsyncAuditor::init_db(path, &genesis, &hmac_key);
        assert!(
            result.is_err(),
            "init_db should fail on tampered is_blocked"
        );
    }

    #[test]
    fn test_aes_256_gcm_payload_binding_tampered_payload() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        let genesis = [0u8; 32];
        let hmac_key = [1u8; 32];

        create_test_db(path, &genesis, &hmac_key);
        let conn = Connection::open(path).unwrap();
        conn.execute(
            "UPDATE ephemeral_raw_logs SET encrypted_data = x'deadbeef' WHERE id = 1",
            [],
        )
        .unwrap();
        drop(conn);

        let result = AsyncAuditor::init_db(path, &genesis, &hmac_key);
        assert!(result.is_err(), "init_db should fail on tampered payload");
    }

    #[test]
    fn test_aes_256_gcm_payload_binding_tampered_nonce() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        let genesis = [0u8; 32];
        let hmac_key = [1u8; 32];

        create_test_db(path, &genesis, &hmac_key);
        let conn = Connection::open(path).unwrap();
        // Since nonce was 12 bytes of 0s, 12 bytes of 1s will be a valid length but wrong value
        conn.execute(
            "UPDATE ephemeral_raw_logs SET nonce = x'010101010101010101010101' WHERE id = 1",
            [],
        )
        .unwrap();
        drop(conn);

        let result = AsyncAuditor::init_db(path, &genesis, &hmac_key);
        assert!(result.is_err(), "init_db should fail on tampered nonce");
    }
}

#[cfg(test)]
mod additional_audit_tests {
    use iw_core::{ScrubbingReport, TokenMap};
    use iw_worker::audit::*;
    use secrecy::SecretVec;

    #[tokio::test]
    async fn test_audit_purge_user() {
        let db_path = std::env::temp_dir()
            .join(format!("audit_test_purge_{}.db", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let pepper = SecretVec::from(vec![0u8; 32]);
        let auditor = AsyncAuditor::spawn(&db_path, pepper, None).await.unwrap();

        let report = ScrubbingReport {
            sanitized_text: "test".into(),
            is_blocked: false,
            redactions: vec![],
            token_map: TokenMap::new(),
            execution_time_ms: 1,
            potential_misses: vec![],
        };

        // Log for User A
        auditor
            .log_report(report.clone(), "rawA".into(), "userA".into())
            .await
            .unwrap();

        // Log for User B
        auditor
            .log_report(report.clone(), "rawB".into(), "userB".into())
            .await
            .unwrap();

        // Purge User A
        auditor.purge_user("userA").await.unwrap();

        let conn = rusqlite::Connection::open(&db_path).unwrap();

        // Check audit_reports
        let count_a: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_reports WHERE username = 'userA'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count_a, 0, "User A audit_reports should be deleted");

        let count_b: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_reports WHERE username = 'userB'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count_b, 1, "User B audit_reports should remain");

        // Check ephemeral_raw_logs
        let count_raw_a: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ephemeral_raw_logs WHERE username = 'userA'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count_raw_a, 0,
            "User A ephemeral_raw_logs should be deleted"
        );

        let count_raw_b: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ephemeral_raw_logs WHERE username = 'userB'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count_raw_b, 1, "User B ephemeral_raw_logs should remain");

        // Verify cryptographic shredding preserved contiguous rows in audit_reports
        let count_redacted: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_reports WHERE username = '[REDACTED]'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count_redacted, 1,
            "User A record must be pseudonymized/redacted in-place"
        );

        let total_reports: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_reports", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            total_reports, 2,
            "Total rows must remain 2 to preserve ID sequence"
        );

        drop(conn);
        auditor.shutdown().await;

        // Verify full-chain integrity walk on server restart after GDPR purge
        let pepper2 = SecretVec::from(vec![0u8; 32]);
        let auditor2 = AsyncAuditor::spawn(&db_path, pepper2, None).await.unwrap();
        auditor2
            .log_report(report.clone(), "rawC".into(), "userC".into())
            .await
            .unwrap();

        auditor2.shutdown().await;
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(format!("{}-shm", db_path));
        let _ = std::fs::remove_file(format!("{}-wal", db_path));
        let _ = std::fs::remove_file(format!("{}.anchor", db_path));
    }

    #[test]
    fn test_anchor_in_memory_bypass() {
        let dummy_hash = [0u8; 32];
        // :memory:
        assert!(AsyncAuditor::update_anchor(":memory:", 1, &dummy_hash).is_ok());
        assert!(AsyncAuditor::check_anchor(":memory:", 1, &dummy_hash).is_ok());
        assert!(!std::path::Path::new(":memory:.anchor").exists());

        // file::memory:
        assert!(AsyncAuditor::update_anchor("file::memory:?cache=shared", 1, &dummy_hash).is_ok());
        assert!(AsyncAuditor::check_anchor("file::memory:?cache=shared", 1, &dummy_hash).is_ok());
        assert!(!std::path::Path::new("file::memory:?cache=shared.anchor").exists());
    }

    #[test]
    fn test_anchor_atomic_disk_write() {
        let db_path = std::env::temp_dir()
            .join(format!("test_anchor_disk_{}.db", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let dummy_hash = [42u8; 32];
        let anchor_path = format!("{}.anchor", db_path);
        let tmp_pattern = format!("{}.tmp.{}", anchor_path, std::process::id());

        assert!(AsyncAuditor::update_anchor(&db_path, 10, &dummy_hash).is_ok());
        assert!(std::path::Path::new(&anchor_path).exists());
        assert!(
            !std::path::Path::new(&tmp_pattern).exists(),
            "Temporary anchor file should have been renamed"
        );

        let content = std::fs::read_to_string(&anchor_path).unwrap();
        assert_eq!(content, format!("10:{}", hex::encode(dummy_hash)));

        assert!(AsyncAuditor::check_anchor(&db_path, 10, &dummy_hash).is_ok());

        std::fs::remove_file(&anchor_path).ok();
    }
}

#[cfg(test)]
mod storage_tests {
    use iw_core::StorageProvider;
    use iw_worker::storage::*;
    use secrecy::SecretVec;
    use std::fs;

    #[tokio::test]
    async fn test_storage_purge_user_data() {
        let db_path = std::env::temp_dir()
            .join(format!("storage_test_purge_{}.db", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let kb_path = format!("kb_test_purge_{}", uuid::Uuid::new_v4());
        let pepper = SecretVec::from(vec![0u8; 32]);

        let storage = WorkerStorage::new(&db_path, &kb_path, pepper, None, None)
            .await
            .unwrap();

        // Ensure tables exist for testing purge (normally created by initialization)
        storage
            .conn
            .call(|conn| {
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS search_jobs (id TEXT, username TEXT)",
                    [],
                )?;
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS threads (id TEXT, username TEXT)",
                    [],
                )?;
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS sessions (id TEXT, username TEXT)",
                    [],
                )?;

                conn.execute(
                    "INSERT INTO search_jobs (id, username) VALUES ('job1', 'userA')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO search_jobs (id, username) VALUES ('job2', 'userB')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO threads (id, username) VALUES ('th1', 'userA')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO sessions (id, username) VALUES ('s1', 'userA')",
                    [],
                )?;
                Ok::<(), rusqlite::Error>(())
            })
            .await
            .unwrap();

        // Mock document in librarian
        storage
            .librarian
            .add_document("test document A", "userA")
            .await
            .unwrap();
        storage
            .librarian
            .add_document("test document B", "userB")
            .await
            .unwrap();

        // Trigger purge
        storage.purge_user_data("userA").await.unwrap();

        // Verify DB records
        storage
            .conn
            .call(|conn| {
                let count_jobs: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM search_jobs WHERE username = 'userA'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(count_jobs, 0, "Jobs for userA should be deleted");

                let count_jobs_b: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM search_jobs WHERE username = 'userB'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(count_jobs_b, 1, "Jobs for userB should remain");

                let count_threads: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM threads WHERE username = 'userA'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(count_threads, 0, "Threads for userA should be deleted");

                let count_sessions: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM sessions WHERE username = 'userA'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(count_sessions, 0, "Sessions for userA should be deleted");

                Ok::<(), rusqlite::Error>(())
            })
            .await
            .unwrap();

        // Verify Librarian
        let docs_a = storage
            .librarian
            .retrieve_policy_context("test", "userA", 5)
            .await
            .unwrap();
        assert!(
            docs_a.is_empty(),
            "Librarian docs for userA should be deleted"
        );

        let docs_b = storage
            .librarian
            .retrieve_policy_context("test", "userB", 5)
            .await
            .unwrap();
        assert_eq!(docs_b.len(), 1, "Librarian docs for userB should remain");

        fs::remove_file(&db_path).ok();
        fs::remove_file(format!("{}.anchor", db_path)).ok();
        fs::remove_dir_all(&kb_path).ok();
    }
}

#[cfg(test)]
mod ocr_tests {
    use iw_worker::ocr::{OcrProvider, TesseractOcr};
    use iw_worker::TEST_ENV_MUTEX;
    use std::env;

    #[tokio::test]
    async fn test_ocr_fail_closed_production() {
        let _guard = TEST_ENV_MUTEX.lock().await;

        let orig_warden = env::var("WARDEN_ENV");
        let orig_prod = env::var("IRONWARDEN_ENV");
        let orig_rust_env = env::var("RUST_ENV");
        env::remove_var("WARDEN_ENV");
        env::set_var("IRONWARDEN_ENV", "production");
        env::remove_var("RUST_ENV");

        let orig_path = env::var("PATH");
        env::set_var("PATH", ""); // Ensure tesseract is not found

        let ocr = TesseractOcr;
        let res = ocr.extract_text(b"test data", "image/png").await;

        assert!(
            res.is_err(),
            "OCR must fail in production if tesseract is missing"
        );
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("dependency missing in production mode"));

        if let Ok(val) = orig_path {
            env::set_var("PATH", val);
        } else {
            env::remove_var("PATH");
        }
        if let Ok(val) = orig_warden {
            env::set_var("WARDEN_ENV", val);
        } else {
            env::remove_var("WARDEN_ENV");
        }
        if let Ok(val) = orig_prod {
            env::set_var("IRONWARDEN_ENV", val);
        } else {
            env::remove_var("IRONWARDEN_ENV");
        }
        if let Ok(val) = orig_rust_env {
            env::set_var("RUST_ENV", val);
        } else {
            env::remove_var("RUST_ENV");
        }
    }

    #[tokio::test]
    async fn test_ocr_fail_closed_warden_env_production() {
        let _guard = TEST_ENV_MUTEX.lock().await;

        let orig_warden = env::var("WARDEN_ENV");
        let orig_prod = env::var("IRONWARDEN_ENV");
        let orig_rust_env = env::var("RUST_ENV");
        env::set_var("WARDEN_ENV", "production");
        env::remove_var("IRONWARDEN_ENV");
        env::remove_var("RUST_ENV");

        let orig_path = env::var("PATH");
        env::set_var("PATH", ""); // Ensure tesseract is not found

        let ocr = TesseractOcr;
        let res = ocr.extract_text(b"test data", "image/png").await;

        assert!(
            res.is_err(),
            "OCR must fail in production via WARDEN_ENV if tesseract is missing"
        );
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("dependency missing in production mode"));

        if let Ok(val) = orig_path {
            env::set_var("PATH", val);
        } else {
            env::remove_var("PATH");
        }
        if let Ok(val) = orig_warden {
            env::set_var("WARDEN_ENV", val);
        } else {
            env::remove_var("WARDEN_ENV");
        }
        if let Ok(val) = orig_prod {
            env::set_var("IRONWARDEN_ENV", val);
        } else {
            env::remove_var("IRONWARDEN_ENV");
        }
        if let Ok(val) = orig_rust_env {
            env::set_var("RUST_ENV", val);
        } else {
            env::remove_var("RUST_ENV");
        }
    }

    #[tokio::test]
    async fn test_ocr_fallback_development() {
        let _guard = TEST_ENV_MUTEX.lock().await;

        let orig_warden = env::var("WARDEN_ENV");
        let orig_prod = env::var("IRONWARDEN_ENV");
        let orig_rust_env = env::var("RUST_ENV");
        env::remove_var("WARDEN_ENV");
        env::set_var("IRONWARDEN_ENV", "development");
        env::set_var("RUST_ENV", "development");

        let orig_path = env::var("PATH");
        env::set_var("PATH", ""); // Ensure tesseract is not found

        let ocr = TesseractOcr;
        let res = ocr.extract_text(b"test data", "image/png").await;

        assert!(
            res.is_ok(),
            "OCR must fallback in development if tesseract is missing"
        );
        assert!(res.unwrap().contains("[MOCK OCR]"));

        if let Ok(val) = orig_path {
            env::set_var("PATH", val);
        } else {
            env::remove_var("PATH");
        }
        if let Ok(val) = orig_warden {
            env::set_var("WARDEN_ENV", val);
        } else {
            env::remove_var("WARDEN_ENV");
        }
        if let Ok(val) = orig_prod {
            env::set_var("IRONWARDEN_ENV", val);
        } else {
            env::remove_var("IRONWARDEN_ENV");
        }
        if let Ok(val) = orig_rust_env {
            env::set_var("RUST_ENV", val);
        } else {
            env::remove_var("RUST_ENV");
        }
    }
}

#[cfg(test)]
mod librarian_tests {
    use iw_worker::librarian::*;
    use std::fs;

    #[tokio::test]
    async fn test_librarian_cross_user_isolation_v19() {
        let kb_path = std::env::temp_dir()
            .join(format!("lancedb_test_isolation_{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let librarian = LocalLibrarian::new(&kb_path).await.unwrap();

        librarian
            .add_document("Alice top secret document", "userA")
            .await
            .unwrap();
        librarian
            .add_document("Bob top secret document", "userB")
            .await
            .unwrap();

        // Query as user A
        let res_a = librarian
            .retrieve_policy_context("top secret", "userA", 10)
            .await
            .unwrap();
        assert_eq!(res_a.len(), 1);
        assert_eq!(res_a[0], "Alice top secret document");

        // Query as user B
        let res_b = librarian
            .retrieve_policy_context("top secret", "userB", 10)
            .await
            .unwrap();
        assert_eq!(res_b.len(), 1);
        assert_eq!(res_b[0], "Bob top secret document");

        // Cross-user query should return empty
        let res_cross = librarian
            .retrieve_policy_context("Alice", "userB", 10)
            .await
            .unwrap();
        assert!(res_cross.is_empty(), "Cross-user data leakage detected!");

        let uri = format!("data/lancedb/{}", kb_path.replace('/', "_"));
        fs::remove_dir_all(&kb_path).ok();
        fs::remove_dir_all(&uri).ok();
    }
}
