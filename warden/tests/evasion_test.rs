use iw_warden::engine::WardenEngine;
use iw_core::traits::{EnforcementAction, PiiShield};
use iw_core::PiiCategory;

#[test]
fn test_v15_homoglyph_evasion() {
    let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
    let rules = vec![
        ("rule1".to_string(), "Alice".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName),
    ];
    let engine = WardenEngine::new(rules, vec![], vec![], None, 0.5, &pepper).expect("Failed to create engine");
    
    // Cyrillic 'A' (U+0410) instead of Latin 'A'
    let input = "Hello \u{0410}lice, how are you?";
    let report = engine.sanitize_prompt(input, None).expect("Sanitization failed");
    
    println!("Sanitized text: {}", report.sanitized_text);
    assert!(report.sanitized_text.contains("[TOKEN_1]"), "V-15: Homoglyph 'Alice' was not redacted!");
}
