// This file runs an integration test checking PII sanitization and tokenization for "Alice" (Dictionary) and email patterns (Regex) within a shared SessionContext session.
use iw_core::{SessionContext, PiiShield};
use iw_warden::{WardenConfig};
use std::fs;
use tempfile::tempdir;

#[tokio::main]
async fn main() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("rules.yaml");
    
    let rules_yaml = r#"
rules:
  - id: "PERSON_1"
    pattern: "Alice"
    type: "Dictionary"
  - id: "EMAIL_1"
    pattern: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    type: "Regex"
"#;
    fs::write(&config_path, rules_yaml).unwrap();

    let config = WardenConfig::from_file(&config_path).unwrap();
    let pepper = secrecy::SecretVec::new(vec![0u8; 32]);
    let shield = config.compile_engine(&pepper).unwrap();

    let session = SessionContext::new();

    let report1 = shield.sanitize_prompt("Alice is here.", Some(&session)).await.unwrap();
    println!("Report1: {:?}", report1.sanitized_text);
    println!("Tokens: {:?}", report1.token_map);

    let report2 = shield.sanitize_prompt("Email alice@example.com", Some(&session)).await.unwrap();
    println!("Report2: {:?}", report2.sanitized_text);
    println!("Tokens: {:?}", report2.token_map);
}
