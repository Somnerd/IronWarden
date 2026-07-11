// This file tests prevention of identity ghosting/corruption by verifying Type Isolation (separating names and emails) and Word Boundary Enforcement (preventing substring matches like "Alicia" or "Malice" from matching "Alice").
use iw_core::{PiiShield, SessionContext};
use iw_warden::WardenConfig;
use secrecy::SecretVec;
use std::fs;
use tempfile::tempdir;
#[tokio::test]
async fn test_identity_ghosting_prevention() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("rules.yaml");

    let rules_yaml = r#"
rules:
  - id: "id_person"
    pattern: "Alice"
    type: "Dictionary"
  - id: "id_email"
    pattern: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    type: "Regex"
  - id: "id_person2"
    pattern: "Alicia"
    type: "Dictionary"
"#;
    fs::write(&config_path, rules_yaml).unwrap();

    let config = WardenConfig::from_file(&config_path).unwrap();
    let pepper = SecretVec::new(vec![0u8; 32]);
    let shield = config.compile_engine(&pepper).unwrap();

    let session = SessionContext::new();

    // 1. Establish the "Alice" identity
    let report1 = shield
        .sanitize_prompt("Hello Alice.", Some(&session))
        .await
        .unwrap();
    assert!(report1.sanitized_text.contains("[TOKEN_1]")); // Alice is TOKEN_1

    // 2. Introduce the email containing "alice"
    let report2 = shield
        .sanitize_prompt("Contact alice@example.com.", Some(&session))
        .await
        .unwrap();
    // Prior to Type Isolation, the email would get merged with Alice and corrupted to [TOKEN_1].
    // With Type Isolation, it correctly receives a NEW token for the email.
    assert!(report2.sanitized_text.contains("[TOKEN_2]")); // Email is TOKEN_2

    // 3. Introduce the name "Alicia"
    let report3 = shield
        .sanitize_prompt("Meet Alicia.", Some(&session))
        .await
        .unwrap();
    // Prior to Word Boundary Enforcement, Alicia would get merged into Alice.
    // Now, Alicia correctly receives a NEW token.
    assert!(report3.sanitized_text.contains("[TOKEN_3]")); // Alicia is TOKEN_3

    // 4. Confirm Alice still matches exactly
    let report4 = shield
        .sanitize_prompt("Alice again.", Some(&session))
        .await
        .unwrap();
    assert!(report4.sanitized_text.contains("[TOKEN_1]")); // Reuses Alice token

    // 5. Test Word Boundary Enforcement (Negative case)
    // Alice should NOT be redacted when part of "Malice"
    let report5 = shield
        .sanitize_prompt("Do not match Malice.", Some(&session))
        .await
        .unwrap();
    assert!(!report5.sanitized_text.contains("[TOKEN_1]"));
    assert!(report5.sanitized_text.contains("Malice"));
}
