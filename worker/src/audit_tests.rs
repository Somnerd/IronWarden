use super::*;
    use iw_core::{ScrubbingReport, TokenMap};
    use secrecy::SecretVec;

    #[tokio::test]
    async fn test_audit_purge_user() {
        let db_path = format!("audit_test_purge_{}.db", uuid::Uuid::new_v4());
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

        std::fs::remove_file(&db_path).ok();
        std::fs::remove_file(format!("{}.anchor", db_path)).ok();
    }
