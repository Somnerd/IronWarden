use iw_warden::engine::WardenEngine;
use iw_core::traits::EnforcementAction;
use iw_core::PiiCategory;
use iw_core::traits::PiiShield;

#[tokio::test]
async fn test_v12_overlap_bypass() {
    let rules = vec![
        ("rule1".to_string(), "Alice".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName),
        ("rule2".to_string(), "Alice Smith".to_string(), EnforcementAction::Block, PiiCategory::IndividualName),
    ];
    let engine = WardenEngine::new(rules, vec![], vec![], None, 0.5).expect("Failed to create engine");
    
    let input = "Hello Alice Smith, how are you?";
    let report = enginesanitize_prompt(bytes::Bytes::from(input.to_string()),  None).await.expect("Sanitization failed");
    
    println!("Report is_blocked: {}", report.is_blocked);
    println!("Sanitized text: {}", report.sanitized_text);
    
    assert!(report.is_blocked, "V-12: Overlapping 'Block' rule was bypassed by shorter 'Redact' rule!");
}
