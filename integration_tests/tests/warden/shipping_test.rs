// This file tests loading of shipping configuration rules and verifies the redaction of logistics/shipping PII (Bill of Lading, IMO numbers, Container IDs, Air Waybills, HS Codes, invoices, logistics organizations, and vessels).
use iw_warden::WardenConfig;
use iw_core::PiiShield;
use std::sync::Arc;

#[tokio::test]
    async fn test_shipping_rules_loading() {
    let config_dir = "../config";
    let mut config = WardenConfig::from_dir(config_dir).expect("Failed to load config directory");
    config.ai_enabled = false;
    
    // Verify shipping rules are present
    let bol_rule = config.rules.iter().find(|r| r.id == "bill_of_lading");
    assert!(bol_rule.is_some(), "Bill of Lading rule should be loaded");
    
    let pepper = secrecy::SecretVec::new(vec![0u8; 32]);
    let engine = config.compile_engine(&pepper).expect("Failed to compile engine");
    
    // Test Bill of Lading
    let input = "The cargo is under BOL-12345678-NY.";
    let report = engine.sanitize_prompt(input, None).await.unwrap();
    assert!(report.sanitized_text.contains("[TOKEN_"), "BOL should be redacted");
    
    // Test IMO Number
    let input2 = "Ship IMO 1234567 is departing.";
    let report2 = engine.sanitize_prompt(input2, None).await.unwrap();
    assert!(report2.sanitized_text.contains("[TOKEN_"), "IMO should be redacted");

    // Test Container ID
    let input3 = "Container MSKU1234567 is on deck.";
    let report3 = engine.sanitize_prompt(input3, None).await.unwrap();
    assert!(report3.sanitized_text.contains("[TOKEN_"), "Container ID should be redacted");

    // Test Air Waybill
    let input4 = "IATA Air Waybill 020-12345678 loaded.";
    let report4 = engine.sanitize_prompt(input4, None).await.unwrap();
    assert!(report4.sanitized_text.contains("[TOKEN_"), "Air Waybill should be redacted");

    // Test HS Tariff Code
    let input5 = "HS Code is 3926.90.99 for plastic goods.";
    let report5 = engine.sanitize_prompt(input5, None).await.unwrap();
    assert!(report5.sanitized_text.contains("[TOKEN_"), "HS Code should be redacted");

    // Test Commercial Invoice
    let input6 = "Please pay INVOICE-1234567 immediately.";
    let report6 = engine.sanitize_prompt(input6, None).await.unwrap();
    assert!(report6.sanitized_text.contains("[TOKEN_"), "Commercial Invoice should be redacted");
}

#[tokio::test]
    async fn test_logistics_heuristics() {
    let config_dir = "../config";
    let mut config = WardenConfig::from_dir(config_dir).expect("Failed to load config directory");
    config.ai_enabled = false;
    let pepper = secrecy::SecretVec::new(vec![0u8; 32]);
    let engine = config.compile_engine(&pepper).expect("Failed to compile engine");

    // Test Logistics Org Suffix (Heuristic in shadow_ner)
    let input = "Maersk Line is our primary carrier.";
    let report = engine.sanitize_prompt(input, None).await.unwrap();
    assert!(report.sanitized_text.contains("[TOKEN_"), "Logistics Org (Maersk Line) should be redacted");

    // Test Vessel Name (Heuristic in yaml)
    let input2 = "MV Ever Given is stuck again.";
    let report2 = engine.sanitize_prompt(input2, None).await.unwrap();
    assert!(report2.sanitized_text.contains("[TOKEN_"), "Vessel Name (MV Ever Given) should be redacted");
}
