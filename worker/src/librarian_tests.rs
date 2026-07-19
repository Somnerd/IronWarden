use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_librarian_cross_user_isolation_v19() {
        let kb_path = format!("lancedb_test_isolation_{}", uuid::Uuid::new_v4());
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
