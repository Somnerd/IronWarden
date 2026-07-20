use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_searchboost_cross_user_isolation_v19() {
        let db_path = format!("sb_test_isolation_{}.db", uuid::Uuid::new_v4());
        let pepper = SecretVec::from(vec![0u8; 32]);
        let queue = SearchBoostQueue::new(db_path.clone(), &pepper, None, None).unwrap();

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
            "Cross-user data leakage detected in SearchBoost get_result!"
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
        let db_path = format!("sb_test_fifo_{}.db", uuid::Uuid::new_v4());
        let pepper = SecretVec::from(vec![0u8; 32]);
        let queue = SearchBoostQueue::new(db_path.clone(), &pepper, None, None).unwrap();

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
        let db_path = format!("sb_test_shutdown_{}.db", uuid::Uuid::new_v4());
        let pepper = SecretVec::from(vec![0u8; 32]);
        let queue = SearchBoostQueue::new(db_path.clone(), &pepper, None, None).unwrap();

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
        let db_path = format!("sb_test_redis_{}.db", uuid::Uuid::new_v4());
        let pepper = SecretVec::from(vec![0u8; 32]);

        // Point to a dead port to simulate Redis connection failure
        std::env::set_var("REDIS_URL", "redis://127.0.0.1:9999");
        let queue = SearchBoostQueue::new(db_path.clone(), &pepper, None, None).unwrap();

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
