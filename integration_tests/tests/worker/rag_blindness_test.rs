// Integration tests verifying LocalLibrarian (Tantivy) search behavior under redacted queries, validating semantic blindness when querying with tokens instead of raw PII.
#![recursion_limit = "1024"]
use tempfile::tempdir;
use worker::LocalLibrarian;

#[tokio::test]
#[ignore]
async fn test_librarian_semantic_utility() {
    let dir = tempdir().unwrap();
    let path = dir.path().to_str().unwrap();

    // 1. Setup Librarian (Tantivy)
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

    // Allow Tantivy to reload (OnCommitWithDelay)
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

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
