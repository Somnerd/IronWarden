use super::*;
    use secrecy::SecretVec;
    use std::fs;

    #[tokio::test]
    async fn test_storage_purge_user_data() {
        let db_path = format!("storage_test_purge_{}.db", uuid::Uuid::new_v4());
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
