// Stress tests verifying log purge, HMAC chain integrity, and adversarial database tamper detection using the `iw-cli` tool.
use chrono::{Duration as ChronoDuration, Utc};
use iw_core::{EnforcementAction, Redaction, ScrubbingReport};
use rusqlite::Connection;
use secrecy::SecretVec;
use std::process::Command;
use std::time::Duration;
use worker::audit::AsyncAuditor;

#[tokio::test]
async fn test_time_travel_purge_and_hmac_integrity() {
    let db_path = "audit_stress_test.db";
    let pepper = b"test-pepper-12345678901234567890".to_vec(); // 32 bytes

    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(format!("{}.anchor", db_path));
    let _ = std::fs::remove_file(format!("{}-shm", db_path));
    let _ = std::fs::remove_file(format!("{}-wal", db_path));

    // 1. Initialize Auditor
    let auditor = AsyncAuditor::spawn(db_path, SecretVec::new(pepper.clone()), None)
        .await
        .expect("Failed to spawn auditor");

    // 2. Fuzz with malformed inputs
    let report1 = ScrubbingReport {
        sanitized_text: "Test 1".to_string(),
        is_blocked: false,
        redactions: vec![],
        token_map: Default::default(),
        potential_misses: vec![],
        execution_time_ms: 10,
    };
    // Edge case: Right-to-Left Override character
    let _ = auditor
        .log_report(
            report1.clone(),
            "Malicious prompt with \u{202e} right-to-left override".to_string(),
            "fuzzer_user".into(),
        )
        .await;

    let report2 = ScrubbingReport {
        sanitized_text: "Test 2 [REDACTED]".to_string(),
        is_blocked: true,
        redactions: vec![Redaction {
            rule_id: "test_rule".to_string(),
            action: EnforcementAction::Redact,
            offset: 0,
            length: 5,
            placeholder: "[REDACTED]".to_string(),
            category: iw_core::traits::PiiCategory::Other,
        }],
        token_map: Default::default(),
        potential_misses: vec![],
        execution_time_ms: 20,
    };
    let _ = auditor
        .log_report(
            report2.clone(),
            "Blocked prompt with secret".to_string(),
            "attacker_0".into(),
        )
        .await;

    // Allow worker thread to process the MPSC queue
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // 3. Time-Travel: Backdate the first log by 31 days
    {
        let conn = Connection::open(db_path).unwrap();
        let cutoff = Utc::now() - ChronoDuration::days(31);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();
        conn.execute(
            "UPDATE ephemeral_raw_logs SET timestamp = ?1 WHERE id = 1",
            [&cutoff_str],
        )
        .unwrap();
    }

    // 4. Trigger Purge Simulation
    // (Simulates the 30-day automated worker purge)
    {
        let conn = Connection::open(db_path).unwrap();
        let cutoff = Utc::now() - ChronoDuration::days(30);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();
        conn.execute(
            "DELETE FROM ephemeral_raw_logs WHERE timestamp < ?1",
            [&cutoff_str],
        )
        .unwrap();
    }

    // 5. Build and run the `iw-cli` tool to verify integrity
    let build_status = Command::new("cargo")
        .args(&["build", "-p", "iw-cli"])
        .status()
        .expect("Failed to build iw-cli");
    assert!(build_status.success());

    let output = Command::new("cargo")
        .env("WARDEN_PEPPER", "test-pepper-12345678901234567890")
        .args(&["run", "-p", "iw-cli", "--", "verify", "--db", db_path])
        .output()
        .expect("Failed to run verify");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // We expect: 1 verified (log 2), 1 archived (log 1), 0 tampered.
    assert!(
        stdout.contains("Verified Intact Logs: 1"),
        "Expected 1 verified log"
    );
    assert!(
        stdout.contains("Verified Archived Logs: 1"),
        "Expected 1 archived log"
    );
    assert!(
        stdout.contains("STATUS: CHAIN INTACT"),
        "Expected chain intact status"
    );

    // 6. Adversarial Tamper Test
    // A malicious actor alters the blocked status in the database
    {
        let conn = Connection::open(db_path).unwrap();
        conn.execute("UPDATE audit_reports SET is_blocked = 0 WHERE id = 2", [])
            .unwrap();
    }

    let output_tampered = Command::new("cargo")
        .env("WARDEN_PEPPER", "test-pepper-12345678901234567890")
        .args(&["run", "-p", "iw-cli", "--", "verify", "--db", db_path])
        .output()
        .expect("Failed to run verify");

    let stdout_tampered = String::from_utf8_lossy(&output_tampered.stdout);
    assert!(
        stdout_tampered.contains("TAMPER DETECTED at Log ID 2"),
        "Expected tamper detection on ID 2"
    );
    assert!(
        stdout_tampered.contains("STATUS: CHAIN CORRUPTED (1 records tampered)"),
        "Expected corrupted chain status"
    );

    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(format!("{}.anchor", db_path));
    let _ = std::fs::remove_file(format!("{}-shm", db_path));
    let _ = std::fs::remove_file(format!("{}-wal", db_path));
}
