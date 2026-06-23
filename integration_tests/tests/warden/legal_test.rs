// This file tests loading of legal configuration rules and verifies the redaction of legal PII (attorney bar numbers, court dockets, confidential markers, and AFM numbers).
use iw_warden::WardenConfig;
use iw_core::PiiShield;

#[tokio::test]
async fn test_legal_rules_loading() {
    let config_dir = "../config/regions";
    let mut config = WardenConfig::from_dir(config_dir).expect("Failed to load config directory");
    config.ai_enabled = false;
    
    // Verify legal rules are loaded
    let bar_rule = config.rules.iter().find(|r| r.id == "attorney_bar_number");
    assert!(bar_rule.is_some(), "Attorney bar number rule should be loaded");
    
    let docket_rule = config.rules.iter().find(|r| r.id == "court_case_docket");
    assert!(docket_rule.is_some(), "Court case docket rule should be loaded");
    
    let marker_rule = config.rules.iter().find(|r| r.id == "confidential_marker");
    assert!(marker_rule.is_some(), "Confidential marker rule should be loaded");
}

#[tokio::test]
async fn test_legal_pii_redaction() {
    let config_dir = "../config/regions";
    let mut config = WardenConfig::from_dir(config_dir).expect("Failed to load config directory");
    config.ai_enabled = false;
    
    let pepper = secrecy::SecretVec::new(vec![0u8; 32]);
    let engine = config.compile_engine(&pepper).expect("Failed to compile engine");
    
    // 1. Attorney Bar Number
    let input_bar = "Counsel: Alice Smith, Bar Number 12345.";
    let report_bar = engine.sanitize_prompt(bytes::Bytes::from(input_bar.to_string()),  None).await.unwrap();
    assert!(String::from_utf8_lossy(&report_bar.sanitized_text).contains("[TOKEN_"), "Attorney bar number should be redacted");
    
    // 2. Court Case Docket
    let input_docket = "Filed under docket 2024-CV-12345.";
    let report_docket = engine.sanitize_prompt(bytes::Bytes::from(input_docket.to_string()),  None).await.unwrap();
    assert!(String::from_utf8_lossy(&report_docket.sanitized_text).contains("[TOKEN_"), "Court case docket should be redacted");
    
    // 3. Confidential Marker
    let input_conf = "This document is ATTORNEY-CLIENT PRIVILEGE and SUBJECT TO NDA.";
    let report_conf = engine.sanitize_prompt(bytes::Bytes::from(input_conf.to_string()),  None).await.unwrap();
    assert!(String::from_utf8_lossy(&report_conf.sanitized_text).contains("[TOKEN_"), "Confidential markers should be redacted");
    
    // 4. Greek AFM
    let input_afm = "My tax identification number (AFM) is 123456789.";
    let report_afm = engine.sanitize_prompt(bytes::Bytes::from(input_afm.to_string()),  None).await.unwrap();
    assert!(String::from_utf8_lossy(&report_afm.sanitized_text).contains("[TOKEN_"), "Greek AFM should be redacted");
}
