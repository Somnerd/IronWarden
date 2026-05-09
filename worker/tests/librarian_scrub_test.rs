use iw_core::{PiiShield};
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_leak_proof_librarian_flow() {
    let base_dir = tempdir().unwrap();
    
    // 1. Setup a direct engine with the rule we want
    let dictionary_rules = Vec::new();
    let patterns_rules = vec![("confidential_project".to_string(), "(?i)Project (Alpha|Omega|Zion)".to_string(), iw_warden::config::SanitizationAction::Redact)];
    let heuristics = Vec::new();
    
    let engine = iw_warden::WardenEngine::new(
        dictionary_rules,
        patterns_rules,
        heuristics,
        None, // No AI needed for regex test
        0.85
    ).unwrap();

    // 2. The "Confidential" Data
    let raw_snippet = "This document discusses the acquisition details for Project Omega.";
    
    // 3. THE LEAK PROOF BRIDGE: Scrubbing the Context
    let report = engine.sanitize_prompt(raw_snippet, None).unwrap();
    
    println!("Raw Snippet: {}", raw_snippet);
    println!("Scrubbed Snippet: {}", report.sanitized_text);

    // ASSERTION: The secret "Project Omega" must be redacted even in the context
    assert!(report.sanitized_text.contains("[TOKEN_1]"));
    assert!(!report.sanitized_text.contains("Project Omega"));
}
