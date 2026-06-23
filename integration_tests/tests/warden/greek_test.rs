// This file tests detection of Greek PII (specifically AFM identification numbers) using a custom regex pattern against Greek language prompts.
use iw_warden::WardenConfig;
use iw_core::PiiShield;

#[tokio::test]
async fn test_greek_pii_detection() {
    let yaml = r#"
rules:
  - id: "gr_afm_literal"
    pattern: 'ΑΦΜ\s+[0-9]{9}'
    type: "Regex"
"#;
    
    let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
    let config: WardenConfig = serde_yaml::from_str(yaml).unwrap();
    let engine = config.compile_engine(&pepper).unwrap();
    
    let prompt = "Ο χρήστης Nikolas Papadopoulos με ΑΦΜ 123456789.";
    
    let report = engine.sanitize_prompt(bytes::Bytes::from(prompt.to_string()),  None).await.unwrap();
    
    println!("Sanitized: {:?}", report.sanitized_text);
    
    // If it works, it should have a redaction for ΑΦΜ 123456789
    assert!(!report.redactions.is_empty(), "Expected at least one redaction for Greek AFM");
    assert!(report.redactions.iter().any(|r| r.rule_id == "gr_afm_literal"));
}
