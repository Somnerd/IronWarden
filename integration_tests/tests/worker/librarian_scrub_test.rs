// Integration tests verifying the leak-proof Librarian flow, confirming that sensitive patterns in input context snippets are correctly redacted and replaced by tokens by the WardenEngine.
use iw_core::{PiiShield};
use iw_core::traits::{EnforcementAction, PiiCategory};
use tempfile::tempdir;
use secrecy::SecretVec;

#[tokio::test]
async fn test_leak_proof_librarian_flow() {
    let base_dir = tempdir().unwrap();
    
    // 1. Setup a direct engine with the rule we want
    let dictionary_rules = Vec::new();
    let patterns_rules = vec![("confidential_project".to_string(), "(?i)Project (Alpha|Omega|Zion)".to_string(), EnforcementAction::Redact, PiiCategory::Other)];
    let heuristics = Vec::new();
    
    let pepper = SecretVec::new(vec![0u8; 32]);
    let engine = iw_warden::WardenEngine::new(
        dictionary_rules,
        patterns_rules,
        heuristics,
        None, // No AI needed for regex test
        0.85,
        &pepper,
    ).unwrap();

    // 2. The "Confidential" Data
    let raw_snippet = "This document discusses the acquisition details for Project Omega.";
    
    // 3. THE LEAK PROOF BRIDGE: Scrubbing the Context
    let report = engine.sanitize_prompt(bytes::Bytes::from(raw_snippet.to_string()),  None).await.unwrap();
    
    println!("Raw Snippet: {:?}", raw_snippet);
    println!("Scrubbed Snippet: {:?}", report.sanitized_text);

    // ASSERTION: The secret "Project Omega" must be redacted even in the context
    assert!(String::from_utf8_lossy(&report.sanitized_text).contains("[TOKEN_1]"));
    assert!(!String::from_utf8_lossy(&report.sanitized_text).contains("Project Omega"));
}