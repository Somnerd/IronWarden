use iw_warden::WardenConfig;
use iw_core::{PiiShield, SessionContext};
use tempfile::tempdir;
use std::fs;

#[test]
fn test_session_token_consistency() {
    let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("rules.yaml");
    
    let rules_yaml = r#"
rules:
  - id: "id_alice"
    pattern: "Alice"
    type: "Dictionary"
  - id: "id_bob"
    pattern: "Bob"
    type: "Dictionary"
"#;
    fs::write(&config_path, rules_yaml).unwrap();

    let config = WardenConfig::from_file(&config_path).unwrap();
    let shield = config.compile_engine(&pepper).unwrap();
    
    // Create a shared session
    let mut session = SessionContext::new();

    // 1. First request: Alice and Bob
    let input1 = "Hello Alice and Bob.";
    let report1 = shield.sanitize_prompt(input1, Some(&mut session)).unwrap();
    
    let alice_token = report1.token_map.iter().find(|(_, v)| *v == "Alice").unwrap().0.clone();
    let bob_token = report1.token_map.iter().find(|(_, v)| *v == "Bob").unwrap().0.clone();
    
    assert_ne!(alice_token, bob_token);
    println!("Initial: Alice -> {}, Bob -> {}", alice_token, bob_token);

    // 2. Second request: Only Alice (should have same token)
    let input2 = "Is Alice there?";
    let report2 = shield.sanitize_prompt(input2, Some(&mut session)).unwrap();
    
    let alice_token_2 = report2.token_map.iter().find(|(_, v)| *v == "Alice").unwrap().0.clone();
    assert_eq!(alice_token, alice_token_2);
    println!("Repeat: Alice -> {} (CONSISTENT)", alice_token_2);

    // 3. Third request: Bob (should have same token)
    let input3 = "Bob left.";
    let report3 = shield.sanitize_prompt(input3, Some(&mut session)).unwrap();
    
    let bob_token_3 = report3.token_map.iter().find(|(_, v)| *v == "Bob").unwrap().0.clone();
    assert_eq!(bob_token, bob_token_3);
    println!("Repeat: Bob -> {} (CONSISTENT)", bob_token_3);
}
