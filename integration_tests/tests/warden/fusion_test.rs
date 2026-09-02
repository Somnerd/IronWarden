// This file tests the fusion integrity of name heuristics and regex rules (e.g., Greek name components fused into a single token and AFM mapped) during prompt sanitization.
use iw_core::PiiShield;
use iw_warden::WardenConfig;

#[tokio::test]
async fn test_papadopoulos_fusion_integrity() {
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
    let pepper = secrecy::SecretVec::new(vec![0u8; 32]);
    let engine = config.compile_engine(&pepper).unwrap();

    // The prompt that failed previously
    let prompt = "Γεια σου, είμαι ο Γεώργιος Παπαδόπουλος και το ΑΦΜ μου είναι 123456789.";

    let report = engine.sanitize_prompt(prompt, None).await.unwrap();

    println!("Sanitized: {}", report.sanitized_text);
    println!("Token Map: {:?}", report.token_map);

    // ASSERTIONS:
    // 1. Georgios and Papadopoulos must be fused into ONE token.
    assert!(report.sanitized_text.contains("[NAME_") || report.sanitized_text.contains("[TOKEN_"));

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
