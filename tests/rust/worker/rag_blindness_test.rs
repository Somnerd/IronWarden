// Integration tests verifying LocalLibrarian (SQLite FTS5) search behavior under redacted queries, validating semantic blindness when querying with tokens instead of raw PII.
use tempfile::tempdir;
use worker::LocalLibrarian;

#[tokio::test]
async fn test_librarian_semantic_utility() {
    let dir = tempdir().unwrap();
    let path = dir.path().to_str().unwrap();

    // 1. Setup Librarian (SQLite FTS5)
    let librarian = LocalLibrarian::new(path).await.unwrap();

    // Ingest some "secret" data
    librarian
        .add_document(
            "The project code for the new AI is Project Alpha.",
            "test_user",
        )
        .await
        .unwrap();
    librarian
        .add_document("John Doe is the lead engineer on this task.", "test_user")
        .await
        .unwrap();

    // 2. Test Case: Query with original PII
    let results = librarian
        .retrieve_policy_context("Who is John Doe?", "test_user", 5)
        .await
        .unwrap();
    assert!(!results.is_empty(), "Should find context for 'John Doe'");
    assert!(
        results.iter().any(|r| r.contains("John Doe")),
        "Should find the correct snippet"
    );

    // 3. Test Case: Query with redacted token (Blindness Simulation)
    let results_redacted = librarian
        .retrieve_policy_context("[PERSON_1]", "test_user", 5)
        .await
        .unwrap();
    assert!(
        results_redacted.is_empty(),
        "Redacted query should fail to find context (Semantic Blindness)"
    );
}
