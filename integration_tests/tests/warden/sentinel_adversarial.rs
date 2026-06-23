// This file contains adversarial testing for homoglyph dictionary evasion, Shadow NER with Greek name homoglyphs, and semantic cache lookups with homoglyphs.
use iw_warden::WardenConfig;
use iw_core::{PiiShield};
use secrecy::SecretVec;

#[test]
fn test_v13_homoglyph_dictionary_evasion() {
    // Define a rule with 'Alice' as a blocked entity
    let yaml = r#"
rules:
  - id: "blocked_alice"
    pattern: "Alice"
    type: "Dictionary"
    action: "Block"
"#;
    
    let config: WardenConfig = serde_yaml::from_str(yaml).unwrap();
    let pepper = SecretVec::new(vec![0u8; 32]);
    let engine = config.compile_engine(&pepper).unwrap();
    
    // Test case 1: Standard 'Alice'
    let prompt1 = "Hello Alice";
    let report1 = engine.sanitize_prompt(prompt1, None).unwrap();
    assert!(report1.is_blocked, "Standard Alice should be blocked");

    // Test case 2: 'Alice' with Cyrillic 'A' (U+0410)
    let prompt2 = "Hello \u{0410}lice"; 
    let report2 = engine.sanitize_prompt(prompt2, None).unwrap();
    assert!(report2.is_blocked, "Alice with Cyrillic A should be blocked (V-13 fix)");
}

#[test]
fn test_v15_shadow_ner_greek_homoglyph() {
    let yaml = r#"
rules: []
heuristics:
  - label: "GREEK_AFM"
    pattern: "[0-9]{9}"
    action: "Redact"
"#;
    
    let config: WardenConfig = serde_yaml::from_str(yaml).unwrap();
    let pepper = SecretVec::new(vec![0u8; 32]);
    let engine = config.compile_engine(&pepper).unwrap();
    
    // Greek name: "Νικόλαος Παπαδόπουλος"
    // Using homoglyphs for 'o' (Cyrillic 'о' U+043E)
    let prompt = "Geia sou Nik\u{043E}laos Papadopoulos";
    let report = engine.sanitize_prompt(prompt, None).unwrap();
    
    println!("Redactions: {:?}", report.redactions);
    // Shadow NER should detect "Nikolaos Papadopoulos" even with homoglyphs 
    // because it runs on the ASCII-normalized buffer.
    assert!(report.redactions.iter().any(|r| r.rule_id.contains("POTENTIAL_GLOBAL_NAME")), 
            "Shadow NER failed to detect name with homoglyphs");
}

#[test]
#[ignore]
fn test_semantic_cache_homoglyph_collision() {
    use iw_core::SessionContext;
    use std::sync::Arc;

    let yaml = r#"
rules: []
confidence_threshold: 0.9
"#;
    let config: WardenConfig = serde_yaml::from_str(yaml).unwrap();
    let pepper = SecretVec::new(vec![0u8; 32]);
    let engine = config.compile_engine(&pepper).unwrap();
    
    let session = SessionContext::new();
    
    // Manually prime the cache with "Alice"
    session.semantic_cache.insert("alice".to_string(), ("PERSON".to_string(), 0.99));
    
    // Search for "Alice" (should hit cache)
    // Note: Shadow NER must first identify "Alice" as a potential miss.
    // We need a heuristic that catches "Alice".
    let yaml2 = r#"
heuristics:
  - label: "PERSON"
    pattern: "Alice"
    action: "Redact"
"#;
    let config2: WardenConfig = serde_yaml::from_str(yaml2).unwrap();
    let engine2 = config2.compile_engine(&pepper).unwrap();

    let report1 = engine2.sanitize_prompt("Hello Alice", Some(&session)).unwrap();
    assert!(report1.redactions.iter().any(|r| r.rule_id.contains("ai_cache_PERSON")), 
            "Should have hit the semantic cache for 'Alice'");

    // Search for "Al\u{0456}ce" (Cyrillic 'i' U+0456)
    let prompt2 = "Hello Al\u{0456}ce";
    let report2 = engine2.sanitize_prompt(prompt2, Some(&session)).unwrap();
    
    println!("Report 2 Redactions: {:?}", report2.redactions);
    let cache_hit = report2.redactions.iter().any(|r| r.rule_id.contains("ai_cache_PERSON"));
    println!("Cache hit for homoglyph: {}", cache_hit);
    
    assert!(cache_hit, "Semantic cache should hit even with homoglyphs (V-15 fix correctly applied to cache)");
}
