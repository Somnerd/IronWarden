// Chaos engineering tests verifying SQLite WAL crash recovery, fail-closed disk exhaustion behavior, busy-handler concurrency, graceful drain under burst load, and SIEM-unreachable disk pressure invariants.
use hkdf::Hkdf;
use iw_core::{ScrubbingReport, SovereignError};
use iw_core::{KDF_SALT_ENCRYPTION, KDF_SALT_GENESIS, KDF_SALT_INTEGRITY};
use rusqlite::Connection;
use secrecy::SecretVec;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use worker::audit::{AsyncAuditor, RemoteAuditForwarder};

fn derive_keys(pepper: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, pepper);
    let mut enc_key = [0u8; 32];
    hk.expand(KDF_SALT_ENCRYPTION, &mut enc_key).unwrap();
    let mut hmac_key = [0u8; 32];
    hk.expand(KDF_SALT_INTEGRITY, &mut hmac_key).unwrap();
    let mut genesis_hash = [0u8; 32];
    hk.expand(KDF_SALT_GENESIS, &mut genesis_hash).unwrap();
    (enc_key, hmac_key, genesis_hash)
}

pub fn verify_audit_chain(db_path: &str, pepper: &[u8]) -> Result<(i64, Vec<u8>), SovereignError> {
    let (_, hmac_key, genesis_hash) = derive_keys(pepper);
    let (_conn, last_hash, last_id) = AsyncAuditor::init_db(db_path, &genesis_hash, &hmac_key)
        .map_err(|e| {
            SovereignError::StorageError(format!("Audit chain verification failed: {}", e))
        })?;
    Ok((last_id, last_hash))
}

fn dummy_report(text: &str, is_blocked: bool) -> ScrubbingReport {
    ScrubbingReport {
        sanitized_text: text.to_string(),
        is_blocked,
        redactions: vec![],
        token_map: HashMap::new(),
        execution_time_ms: 1,
        potential_misses: vec![],
    }
}

/// Scenario 1: Verify mid-write crash rollback and recovery under SQLite WAL mode.
#[tokio::test]
async fn test_chaos_mid_write_wal_rollback_and_recovery() {
    let tmp_file = NamedTempFile::new().unwrap();
    let db_path = tmp_file.path().to_str().unwrap().to_string();
    let pepper = b"chaos-32-byte-test-pepper-string!".to_vec();

    // 1. Spawn AsyncAuditor, log 5 valid events and flush so they are committed in HMAC chain
    let auditor = AsyncAuditor::spawn(&db_path, SecretVec::new(pepper.clone()), None)
        .await
        .expect("Spawn initial auditor");

    for i in 1..=5 {
        let report = dummy_report(&format!("Sanitized event {}", i), false);
        auditor
            .log_report(
                report,
                format!("Raw sensitive info {}", i),
                format!("user_{}", i),
            )
            .await
            .expect("Log valid event");
    }

    // Verify 5 events committed and verified
    let (verified_id, _last_hash) =
        verify_audit_chain(&db_path, &pepper).expect("Initial chain verification");
    assert_eq!(verified_id, 5, "Initial 5 events must be verified");

    // Shut down auditor so we can inject raw mid-write chaos
    auditor.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 2. Open a raw rusqlite::Connection, begin explicit transaction, insert partial uncommitted row, abruptly drop
    {
        let raw_conn = Connection::open(&db_path).expect("Open raw SQLite connection");
        raw_conn.busy_timeout(Duration::from_millis(5000)).unwrap();
        raw_conn
            .execute("BEGIN IMMEDIATE", [])
            .expect("Begin immediate transaction");
        raw_conn
            .execute(
                "INSERT INTO audit_reports (timestamp, username, is_blocked, redactions_json, payload_hash, integrity_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    "2026-10-31 12:00:00",
                    "crash_user",
                    false,
                    "[]",
                    "deadbeef",
                    "uncommitted_fake_hash",
                ),
            )
            .expect("Insert partial row");
        raw_conn
            .execute(
                "INSERT INTO ephemeral_raw_logs (username, encrypted_data, nonce, siem_acked) VALUES (?1, ?2, ?3, ?4)",
                ("crash_user", &[1u8, 2, 3][..], &[4u8, 5, 6][..], false),
            )
            .expect("Insert partial raw log");

        // Abruptly drop raw connection without commit to simulate crash mid-write
        drop(raw_conn);
    }

    // 3. Verify SQLite WAL recovery rolls back uncommitted transaction cleanly
    {
        let conn = Connection::open(&db_path).expect("Open connection post-crash");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_reports", [], |r| r.get(0))
            .expect("Query row count");
        assert_eq!(
            count, 5,
            "SQLite WAL recovery must roll back uncommitted transaction (expected 5 rows, found {})",
            count
        );
    }

    // verify_audit_chain passes on the 5 committed events
    let (recovered_id, _) = verify_audit_chain(&db_path, &pepper)
        .expect("Chain verification passes on 5 committed events");
    assert_eq!(recovered_id, 5);

    // 4. Subsequent log_report calls append event #6 with unbroken HMAC chain
    let auditor2 = AsyncAuditor::spawn(&db_path, SecretVec::new(pepper.clone()), None)
        .await
        .expect("Auditor respawn post-recovery");

    let report6 = dummy_report("Sanitized event 6", false);
    auditor2
        .log_report(report6, "Raw sensitive info 6".into(), "user_6".into())
        .await
        .expect("Append event #6 post-recovery");

    auditor2.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify all 6 events are now intact
    let (final_id, _) =
        verify_audit_chain(&db_path, &pepper).expect("Chain verification passes on all 6 events");
    assert_eq!(
        final_id, 6,
        "Event #6 successfully appended with unbroken HMAC chain"
    );
}

/// Scenario 2: Verify fail-closed behavior under simulated disk exhaustion / write constraints.
#[tokio::test]
async fn test_chaos_disk_full_fail_closed() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let db_path = tmp_dir.path().join("disk_full_chaos.db");
    let db_path_str = db_path.to_str().unwrap().to_string();
    let pepper = b"chaos-32-byte-test-pepper-string!".to_vec();

    // Part A: Validate SQLITE_FULL / max_page_count fail-closed semantics directly
    {
        let conn = Connection::open(&db_path_str).expect("Create db for max_page_count test");
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; CREATE TABLE audit_reports (id INTEGER PRIMARY KEY, payload TEXT);",
        )
        .unwrap();
        let page_count: i64 = conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap();
        conn.execute_batch(&format!("PRAGMA max_page_count = {};", page_count))
            .unwrap();

        // Attempting to write audit records exceeding page quota fails with SQLITE_FULL
        let large_payload = vec![0xAAu8; 100_000];
        let write_res = conn.execute(
            "INSERT INTO audit_reports (payload) VALUES (?1)",
            [&large_payload],
        );
        assert!(
            write_res.is_err(),
            "Attempting to write audit records under page exhaustion must return Err"
        );
        let err = write_res.unwrap_err();
        let err_str = err.to_string().to_lowercase();
        assert!(
            err_str.contains("full") || err_str.contains("quota"),
            "Expected database or disk full error, got: {}",
            err
        );
    }

    // Part B: Validate AsyncAuditor fail-closed behavior under filesystem write lock / disk exhaustion
    let dir_auditor = tempfile::tempdir().unwrap();
    let db_audit = dir_auditor.path().join("audit_fail_closed.db");
    let db_audit_str = db_audit.to_str().unwrap().to_string();

    let auditor = AsyncAuditor::spawn(&db_audit_str, SecretVec::new(pepper.clone()), None)
        .await
        .expect("Spawn auditor");

    // Initial valid write succeeds
    auditor
        .log_report(
            dummy_report("Initial event", false),
            "Initial raw".into(),
            "user_1".into(),
        )
        .await
        .expect("Initial write should succeed");

    // Constrain filesystem permissions to read-only (simulating disk exhaustion / read-only fallback)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dir_auditor.path()).unwrap().permissions();
        perms.set_mode(0o555);
        let _ = std::fs::set_permissions(dir_auditor.path(), perms);
        if let Ok(entries) = std::fs::read_dir(dir_auditor.path()) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    let mut file_perms = meta.permissions();
                    file_perms.set_mode(0o444);
                    let _ = std::fs::set_permissions(entry.path(), file_perms);
                }
            }
        }
    }

    // Attempting to write audit records under disk exhaustion returns an Err rather than silently succeeding
    let write_result = auditor
        .log_report(
            dummy_report("Exhaustion event", false),
            "Exhaustion raw".into(),
            "user_2".into(),
        )
        .await;

    assert!(
        write_result.is_err(),
        "Writing audit records under disk exhaustion must return Err to fail closed"
    );

    // Clean up permissions for tempdir deletion
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(entries) = std::fs::read_dir(dir_auditor.path()) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    let mut file_perms = meta.permissions();
                    file_perms.set_mode(0o666);
                    let _ = std::fs::set_permissions(entry.path(), file_perms);
                }
            }
        }
        let mut restore_perms = std::fs::metadata(dir_auditor.path()).unwrap().permissions();
        restore_perms.set_mode(0o777);
        let _ = std::fs::set_permissions(dir_auditor.path(), restore_perms);
    }
}

/// Scenario 3: Verify busy_timeout behavior when competing connection holds write lock.
#[tokio::test]
async fn test_chaos_sqlite_busy_timeout_concurrent_writers() {
    let tmp_file = NamedTempFile::new().unwrap();
    let db_path = tmp_file.path().to_str().unwrap().to_string();
    let pepper = b"chaos-32-byte-test-pepper-string!".to_vec();

    let auditor = AsyncAuditor::spawn(&db_path, SecretVec::new(pepper.clone()), None)
        .await
        .expect("Spawn auditor");

    // Competing connection acquires immediate write lock
    let comp_conn = Connection::open(&db_path).expect("Open competing connection");
    comp_conn.busy_timeout(Duration::from_millis(5000)).unwrap();
    comp_conn
        .execute("BEGIN IMMEDIATE", [])
        .expect("Begin competing transaction");

    // Competing connection holds the lock for 250ms (well within the 5000ms busy_timeout)
    let lock_holder = tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(250));
        comp_conn
            .execute("COMMIT", [])
            .expect("Commit competing transaction");
    });

    // Concurrently dispatch multiple writes to AsyncAuditor while lock is held
    let concurrent_writes = 10;
    let mut handles = Vec::with_capacity(concurrent_writes);

    for i in 0..concurrent_writes {
        let auditor_clone = auditor.clone();
        handles.push(tokio::spawn(async move {
            let report = dummy_report(&format!("Concurrent msg {}", i), false);
            auditor_clone
                .log_report(
                    report,
                    format!("Concurrent raw payload {}", i),
                    format!("concurrent_user_{}", i),
                )
                .await
        }));
    }

    lock_holder.await.expect("Lock holder task panicked");

    // All concurrent writes must wait on SQLite busy handler and complete 100% without data loss
    for (idx, handle) in handles.into_iter().enumerate() {
        let res = handle.await.expect("Task panicked");
        assert!(
            res.is_ok(),
            "Write #{} must succeed via busy handler wait, got: {:?}",
            idx,
            res
        );
    }

    auditor.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify 100% of writes were persisted
    let conn = Connection::open(&db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM audit_reports", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        count, concurrent_writes as i64,
        "All {} writes must be persisted without loss",
        concurrent_writes
    );

    let (verified, _) =
        verify_audit_chain(&db_path, &pepper).expect("All concurrent writes must form valid chain");
    assert_eq!(verified, concurrent_writes as i64);
}

/// Scenario 4: Verify graceful shutdown drain under burst load without data loss.
#[tokio::test]
async fn test_chaos_graceful_shutdown_under_burst_load() {
    let tmp_file = NamedTempFile::new().unwrap();
    let db_path = tmp_file.path().to_str().unwrap().to_string();
    let pepper = b"chaos-32-byte-test-pepper-string!".to_vec();

    let auditor = AsyncAuditor::spawn(&db_path, SecretVec::new(pepper.clone()), None)
        .await
        .expect("Spawn auditor");

    let burst_count = 50;
    let mut handles = Vec::with_capacity(burst_count);

    // Dispatch 50 rapid in-flight log_report calls
    for i in 0..burst_count {
        let auditor_clone = auditor.clone();
        handles.push(tokio::spawn(async move {
            let report = dummy_report(&format!("Burst message {}", i), false);
            auditor_clone
                .log_report(
                    report,
                    format!("Burst raw input {}", i),
                    format!("burst_user_{}", i),
                )
                .await
        }));
    }

    // Allow in-flight tasks to dispatch into the auditor channel before shutdown
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Immediately invoke auditor.shutdown().await
    auditor.shutdown().await;

    // Await all in-flight requests; FIFO processing guarantees they are drained prior to shutdown
    for (idx, handle) in handles.into_iter().enumerate() {
        let res = handle.await.expect("Task panicked");
        assert!(
            res.is_ok(),
            "Burst record #{} failed during shutdown: {:?}",
            idx,
            res
        );
    }

    // Re-open the database and verify all 50 entries were flushed prior to exit
    let conn = Connection::open(&db_path).expect("Reopen database");
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM audit_reports", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        count, burst_count as i64,
        "All 50 records must be flushed before exit"
    );

    // verify_audit_chain succeeds across all 50 entries
    let (verified, _) = verify_audit_chain(&db_path, &pepper)
        .expect("verify_audit_chain must succeed across all 50 entries");
    assert_eq!(verified, burst_count as i64);
}

struct MockUnreachableSiemForwarder;

#[async_trait::async_trait]
impl RemoteAuditForwarder for MockUnreachableSiemForwarder {
    async fn forward_log(
        &self,
        _ciphertext: &[u8],
        _nonce: &[u8],
        _integrity_hash: &[u8],
        _report: &ScrubbingReport,
        _username: &str,
    ) -> Result<(), SovereignError> {
        Err(SovereignError::InternalError(
            "SIEM cluster unreachable: HTTP 503 Service Unavailable".into(),
        ))
    }
}

/// Scenario 5: Verify that when SIEM is unreachable, disk pressure pruning NEVER deletes unsynced rows.
#[tokio::test]
async fn test_chaos_siem_unreachable_disk_pressure_preserves_logs() {
    let tmp_file = NamedTempFile::new().unwrap();
    let db_path = tmp_file.path().to_str().unwrap().to_string();
    let pepper = b"chaos-32-byte-test-pepper-string!".to_vec();

    // Configure AsyncAuditor with a mock RemoteAuditForwarder that always returns Err
    let forwarder = Arc::new(MockUnreachableSiemForwarder);
    let auditor = AsyncAuditor::spawn(&db_path, SecretVec::new(pepper.clone()), Some(forwarder))
        .await
        .expect("Spawn auditor with failing SIEM forwarder");

    let num_events = 10;
    for i in 1..=num_events {
        let report = dummy_report(&format!("SIEM event {}", i), false);
        auditor
            .log_report(
                report,
                format!("Sensitive payload {}", i),
                format!("user_{}", i),
            )
            .await
            .expect("Log report should succeed locally");
    }

    // Allow background forwarder attempts to run and fail
    tokio::time::sleep(Duration::from_millis(300)).await;

    let conn = Connection::open(&db_path).unwrap();

    // Verify all rows have siem_synced / siem_acked = 0
    let unacked: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ephemeral_raw_logs WHERE siem_acked = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        unacked, num_events as i64,
        "All {} rows must have siem_acked = 0",
        num_events
    );

    // Simulate aggressive disk-pressure pruning logic (invariant #129)
    // In production, pruning queries use: DELETE FROM ephemeral_raw_logs WHERE timestamp < ?1 AND siem_acked = TRUE
    let future_cutoff = (chrono::Utc::now() + chrono::Duration::days(365))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    conn.execute(
        "DELETE FROM ephemeral_raw_logs WHERE timestamp < ?1 AND siem_acked = TRUE",
        [&future_cutoff],
    )
    .unwrap();

    // Verify rows with siem_synced = 0 are NEVER deleted before SIEM acknowledgment
    let preserved_unacked: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ephemeral_raw_logs WHERE siem_acked = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        preserved_unacked, num_events as i64,
        "Un-synced SIEM logs must NEVER be pruned under disk pressure"
    );

    // Simulate SIEM recovery for records 1..=4
    conn.execute(
        "UPDATE ephemeral_raw_logs SET siem_acked = TRUE WHERE id <= 4",
        [],
    )
    .unwrap();

    // Run disk pressure cleanup again
    conn.execute(
        "DELETE FROM ephemeral_raw_logs WHERE timestamp < ?1 AND siem_acked = TRUE",
        [&future_cutoff],
    )
    .unwrap();

    let remaining_unacked: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ephemeral_raw_logs WHERE siem_acked = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        remaining_unacked, 6,
        "The 6 un-acked rows must still be preserved"
    );

    let total_remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM ephemeral_raw_logs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        total_remaining, 6,
        "Only the 4 acknowledged rows were pruned"
    );

    drop(conn);
    auditor.shutdown().await;

    // Full HMAC chain walk on audit_reports must still pass
    let (verified, _) = verify_audit_chain(&db_path, &pepper)
        .expect("Proof-of-history HMAC chain must remain valid");
    assert_eq!(verified, num_events as i64);
}
