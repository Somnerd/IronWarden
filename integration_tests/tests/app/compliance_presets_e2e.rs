use iw_core::PiiShield;
use iw_warden::WardenConfig;
use secrecy::SecretVec;

#[tokio::test]
async fn test_hipaa_compliance_preset_redaction() {
    let mut config = WardenConfig::from_file("../config/presets/hipaa/rules.yaml")
        .expect("HIPAA preset rules.yaml must load cleanly");
    config.ai_enabled = false;

    let pepper = SecretVec::new(vec![0u8; 32]);
    let engine = config
        .compile_engine(&pepper)
        .expect("Failed to compile HIPAA engine");

    let medical_prompt = "Patient diagnosis: John Doe has acute bronchitis. SSN is 000-12-3456, Medical Record Number MRN-98765432.";
    let report = engine
        .sanitize_prompt(medical_prompt, None)
        .await
        .expect("Sanitization must succeed");

    assert!(!report.is_blocked);
    assert!(
        !report.sanitized_text.contains("000-12-3456"),
        "SSN must be redacted"
    );
    assert!(
        report.sanitized_text.contains('['),
        "Placeholder token must be present"
    );

    // Verify roundtrip restoration
    let restored = engine
        .restore_prompt(&report.sanitized_text, &report.token_map)
        .expect("Restoration must succeed");
    assert!(
        restored.contains("000-12-3456"),
        "Restoration must recover original SSN"
    );
}

#[tokio::test]
async fn test_gdpr_compliance_preset_redaction() {
    let mut config = WardenConfig::from_file("../config/presets/gdpr/rules.yaml")
        .expect("GDPR preset rules.yaml must load cleanly");
    config.ai_enabled = false;

    let pepper = SecretVec::new(vec![0u8; 32]);
    let engine = config
        .compile_engine(&pepper)
        .expect("Failed to compile GDPR engine");

    let citizen_prompt = "EU Citizen contact: citizen.europe@domain.eu, Phone: +30 210 1234567, Tax ID AFM: 123456789.";
    let report = engine
        .sanitize_prompt(citizen_prompt, None)
        .await
        .expect("Sanitization must succeed");

    assert!(!report.is_blocked);
    assert!(
        !report.sanitized_text.contains("citizen.europe@domain.eu"),
        "Email must be redacted"
    );

    let restored = engine
        .restore_prompt(&report.sanitized_text, &report.token_map)
        .expect("Restoration must succeed");
    assert!(
        restored.contains("citizen.europe@domain.eu"),
        "Restoration must recover email"
    );
}

#[tokio::test]
async fn test_pci_dss_compliance_preset_redaction() {
    let mut config = WardenConfig::from_file("../config/presets/pci_dss/rules.yaml")
        .expect("PCI-DSS preset rules.yaml must load cleanly");
    config.ai_enabled = false;

    let pepper = SecretVec::new(vec![0u8; 32]);
    let engine = config
        .compile_engine(&pepper)
        .expect("Failed to compile PCI-DSS engine");

    let payment_prompt =
        "Process transaction for card 4532-1234-5678-9012 with CVV 789 and exp 12/28.";
    let report = engine
        .sanitize_prompt(payment_prompt, None)
        .await
        .expect("Sanitization must succeed");

    assert!(!report.is_blocked);
    assert!(
        !report.sanitized_text.contains("4532-1234-5678-9012"),
        "Payment card must be redacted"
    );

    let restored = engine
        .restore_prompt(&report.sanitized_text, &report.token_map)
        .expect("Restoration must succeed");
    assert!(
        restored.contains("4532-1234-5678-9012"),
        "Restoration must recover card number"
    );
}
