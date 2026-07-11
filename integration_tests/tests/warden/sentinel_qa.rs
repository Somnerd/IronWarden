// This file tests Sentinel QA capabilities, including semantic cache resilience to homoglyphs, Shadow NER heuristic promotion without AI, and Shadow NER homoglyph resilience.
use iw_core::{PiiShield, SessionContext};
use iw_warden::WardenEngine;
use secrecy::SecretVec;

#[tokio::test]
async fn test_semantic_cache_homoglyph_resilience() {
    let pepper = SecretVec::new(vec![0u8; 32]);
    let engine = WardenEngine::new(vec![], vec![], vec![], None, 0.85, &pepper).unwrap();
    let session = SessionContext::new();

    // Prime cache with "Alice Smith" (must match Shadow NER for best testing)
    session
        .semantic_cache
        .insert("alice smith".to_string(), ("PERSON".to_string(), 0.99));

    // Query with homoglyph "Alіce Smith" in a context where "Alice Smith" is the only title-case chain
    let report = engine
        .sanitize_prompt("The name is Al\u{0456}ce Smith.", Some(&session))
        .await
        .unwrap();

    assert_eq!(
        report.redactions.len(),
        1,
        "Homoglyph should hit the ASCII-keyed cache"
    );
    assert_eq!(report.redactions[0].rule_id, "ai_cache_PERSON");
}

#[tokio::test]
async fn test_shadow_ner_promotion_without_ai() {
    // Engine without AI
    let pepper = SecretVec::new(vec![0u8; 32]);
    let engine = WardenEngine::new(vec![], vec![], vec![], None, 0.85, &pepper).unwrap();

    // Greek name should be caught by Shadow NER heuristics and promoted even without AI
    // "Αλέξανδρος" (Alexandros) matches greek_suffix_re
    let report = engine.sanitize_prompt("\u{0391}\u{03BB}\u{03AD}\u{03BE}\u{03B1}\u{03BD}\u{03B4}\u{03C1}\u{03BF}\u{03C2} is here.", None).await.unwrap();

    assert_eq!(
        report.redactions.len(),
        1,
        "Greek name should be promoted without AI"
    );
    assert!(report.redactions[0]
        .rule_id
        .contains("heuristic_promotion_POTENTIAL_GREEK_NAME"));
}

#[tokio::test]
async fn test_shadow_ner_homoglyph_resilience() {
    // Test that Shadow NER itself (not just cache) is homoglyph resilient
    // "Alіce Smith" should be caught as POTENTIAL_GLOBAL_NAME because it becomes "Alice Smith" in ASCII
    let pepper = SecretVec::new(vec![0u8; 32]);
    let engine = WardenEngine::new(vec![], vec![], vec![], None, 0.85, &pepper).unwrap();
    let report = engine
        .sanitize_prompt("Hello Al\u{0456}ce Smith.", None)
        .await
        .unwrap();

    // Without AI and without cache, it should be promoted to a redaction because it's an IndividualName
    assert_eq!(
        report.redactions.len(),
        1,
        "Shadow NER should catch homoglyph input and promote it"
    );
    assert_eq!(
        report.redactions[0].rule_id,
        "heuristic_promotion_POTENTIAL_GLOBAL_NAME"
    );
}
