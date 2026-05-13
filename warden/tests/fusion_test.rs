use iw_warden::WardenConfig;
use iw_core::PiiShield;

#[test]
fn test_papadopoulos_fusion_integrity() {
    let yaml = r#"
rules:
  - id: "gr_afm"
    pattern: '\b[0-9]{9}\b'
    type: "Regex"
heuristics:
  - label: "POTENTIAL_NAME"
    pattern: '\b[A-Z][a-z]+\b'
ai_enabled: true
ai_confidence_threshold: 0.85
"#;
    
    let config: WardenConfig = serde_yaml::from_str(yaml).unwrap();
    let engine = config.compile_engine().unwrap();
    
    // The prompt that failed previously
    let prompt = "Γεια σου, είμαι ο Γεώργιος Παπαδόπουλος και το ΑΦΜ μου είναι 123456789.";
    
    let report = engine.sanitize_prompt(prompt, None).unwrap();
    
    println!("Sanitized: {}", report.sanitized_text);
    println!("Token Map: {:?}", report.token_map);
    
    // ASSERTIONS:
    // 1. Georgios and Papadopoulos must be fused into ONE token.
    assert!(report.sanitized_text.contains("[TOKEN_1]"));
    
    // 2. Papadopoulos must NOT be in the sanitized text.
    assert!(!report.sanitized_text.contains("Papadopoulos"));
    assert!(!report.sanitized_text.contains("Papadopoylos"));
    
    // 3. The token map should contain the full name and the AFM.
    let mut found_name = false;
    let mut found_afm = false;
    for val in report.token_map.values() {
        if val.contains("Γεώργιος") && val.contains("Παπαδόπουλος") {
            found_name = true;
        }
        if val == "123456789" {
            found_afm = true;
        }
    }
    assert!(found_name, "Full name should be in token map");
    assert!(found_afm, "AFM should be in token map");
}
