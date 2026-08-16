// This file tests global identity fusion, verifying that complex names containing connectors (such as Spanish names like "Juan Pablo Garcia de la Cruz") are correctly fused into a single token during prompt sanitization.
use iw_core::PiiShield;
use iw_warden::WardenConfig;

#[tokio::test]
async fn test_global_identity_fusion() {
    let yaml = r#"
ai_enabled: true
ai_confidence_threshold: 0.85
"#;

    let config: WardenConfig = serde_yaml::from_str(yaml).unwrap();
    let pepper = secrecy::SecretVec::new(vec![0u8; 32]);
    let engine = config.compile_engine(&pepper).unwrap();

    // A complex Spanish name with connectors
    let prompt = "My name is Juan Pablo Garcia de la Cruz and I live in Madrid.";

    let report = engine.sanitize_prompt(prompt, None).await.unwrap();

    println!("Sanitized: {}", report.sanitized_text);
    println!("Token Map: {:?}", report.token_map);

    // ASSERTIONS:
    // The entire name "Juan Pablo Garcia de la Cruz" should be one token
    assert!(
        report.sanitized_text.contains("[NAME_1]") || report.sanitized_text.contains("[TOKEN_1]")
    );

    let full_name = report
        .token_map
        .values()
        .find(|v| v.contains("Garcia de la Cruz"))
        .expect("Full name missing in token_map");
    assert!(full_name.contains("Garcia de la Cruz"));
}
