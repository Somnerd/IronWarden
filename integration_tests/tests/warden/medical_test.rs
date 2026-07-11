// This file tests loading of medical configuration rules and verifies the redaction of medical PII (MRN, NPI, MBI, Rx, ICD-10) and audit-only logging behavior for medical heuristics (diseases, drugs).
use iw_core::{EnforcementAction, PiiShield};
use iw_warden::WardenConfig;

#[tokio::test]
async fn test_medical_rules_loading() {
    let config_dir = "../config/regions";
    let mut config = WardenConfig::from_manifest("test_manifest_medical.yaml")
        .expect("Failed to load config manifest")
        .0;
    config.ai_enabled = false;

    // Verify medical rules are loaded
    let mrn_rule = config
        .rules
        .iter()
        .find(|r| r.id == "medical_record_number");
    assert!(
        mrn_rule.is_some(),
        "Medical Record Number rule should be loaded"
    );

    let npi_rule = config
        .rules
        .iter()
        .find(|r| r.id == "national_provider_identifier");
    assert!(
        npi_rule.is_some(),
        "National Provider Identifier rule should be loaded"
    );
}

#[tokio::test]
async fn test_medical_pii_redaction() {
    let config_dir = "../config/regions";
    let mut config = WardenConfig::from_manifest("test_manifest_medical.yaml")
        .expect("Failed to load config manifest")
        .0;
    config.ai_enabled = false;

    let pepper = secrecy::SecretVec::new(vec![0u8; 32]);
    let engine = config
        .compile_engine(&pepper)
        .expect("Failed to compile engine");

    // 1. MRN
    let input_mrn = "Patient's MRN is MRN-12345678.";
    let report_mrn = engine.sanitize_prompt(input_mrn, None).await.unwrap();
    assert!(
        report_mrn.sanitized_text.contains("[TOKEN_"),
        "MRN should be redacted"
    );

    // 2. NPI
    let input_npi = "Provider NPI is 1987654321.";
    let report_npi = engine.sanitize_prompt(input_npi, None).await.unwrap();
    assert!(
        report_npi.sanitized_text.contains("[TOKEN_"),
        "NPI should be redacted"
    );

    // 3. MBI
    let input_mbi = "Medicare MBI is 1EG4TE5MK72.";
    let report_mbi = engine.sanitize_prompt(input_mbi, None).await.unwrap();
    assert!(
        report_mbi.sanitized_text.contains("[TOKEN_"),
        "MBI should be redacted"
    );

    // 4. Prescription Number
    let input_rx = "Refill Rx-98765432.";
    let report_rx = engine.sanitize_prompt(input_rx, None).await.unwrap();
    assert!(
        report_rx.sanitized_text.contains("[TOKEN_"),
        "Prescription number should be redacted"
    );

    // 5. ICD-10
    let input_icd = "Diagnosis code is I10 (Essential hypertension).";
    let report_icd = engine.sanitize_prompt(input_icd, None).await.unwrap();
    assert!(
        report_icd.sanitized_text.contains("[TOKEN_"),
        "ICD-10 code should be redacted"
    );
}

#[tokio::test]
async fn test_medical_heuristics_audit_only() {
    let config_dir = "../config/regions";
    let mut config = WardenConfig::from_manifest("test_manifest_medical.yaml")
        .expect("Failed to load config manifest")
        .0;
    config.ai_enabled = false;

    let pepper = secrecy::SecretVec::new(vec![0u8; 32]);
    let engine = config
        .compile_engine(&pepper)
        .expect("Failed to compile engine");

    // 1. Disease heuristic
    let input_disease = "Patient has history of diabetes.";
    let report_disease = engine.sanitize_prompt(input_disease, None).await.unwrap();

    // It should NOT redact the disease name in sanitized_text (AuditOnly behavior)
    assert!(
        report_disease.sanitized_text.contains("diabetes"),
        "Disease name should remain in the text"
    );

    // But it should log an AuditOnly redaction
    let disease_redaction = report_disease
        .redactions
        .iter()
        .find(|r| r.rule_id == "POTENTIAL_DISEASE");
    assert!(
        disease_redaction.is_some(),
        "Disease should be logged in audit log"
    );
    assert_eq!(
        disease_redaction.unwrap().action,
        EnforcementAction::AuditOnly
    );

    // 2. Drug name heuristic
    let input_drug = "Prescribed Lipitor for cholesterol.";
    let report_drug = engine.sanitize_prompt(input_drug, None).await.unwrap();

    // It should NOT redact the drug name in sanitized_text (AuditOnly behavior)
    assert!(
        report_drug.sanitized_text.contains("Lipitor"),
        "Drug name should remain in the text"
    );

    // But it should log an AuditOnly redaction
    let drug_redaction = report_drug
        .redactions
        .iter()
        .find(|r| r.rule_id == "POTENTIAL_DRUG_NAME");
    assert!(
        drug_redaction.is_some(),
        "Drug name should be logged in audit log"
    );
    assert_eq!(drug_redaction.unwrap().action, EnforcementAction::AuditOnly);
}
