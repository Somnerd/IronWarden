// This file tests identity linking, verifying that shared components (like the last name "Smith") do not cause separate individuals ("John Smith" and "Alice Smith") to merge or reuse the same token.
#[cfg(test)]
mod tests {
    use iw_core::{PiiShield, SessionContext};
    use iw_warden::engine::WardenEngine;
    use iw_core::traits::{EnforcementAction, PiiCategory};

    #[tokio::test]
    async fn test_identity_linking_john_and_alice_smith() {
        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let session = SessionContext::new();

        let engine = WardenEngine::new(
            vec![("PERSON".to_string(), "John Smith".to_string(), EnforcementAction::Redact, PiiCategory::Other)],
            vec![],
            vec![],
            None,
            0.5,
            &pepper
        ).unwrap();

        let report1 = engine.sanitize_prompt("Hello John Smith.", Some(&session)).await.unwrap();
        let john_token = report1.token_map.iter().find(|(_, v)| *v == "John Smith").map(|(k, _): (&String, &String)| k.clone()).unwrap();

        let engine2 = WardenEngine::new(
            vec![
                ("PERSON".to_string(), "John Smith".to_string(), EnforcementAction::Redact, PiiCategory::Other),
                ("PERSON".to_string(), "Alice Smith".to_string(), EnforcementAction::Redact, PiiCategory::Other)
            ],
            vec![],
            vec![],
            None,
            0.5,
            &pepper
        ).unwrap();

        let report2 = engine2.sanitize_prompt("Hello Alice Smith.", Some(&session)).await.unwrap();
        let alice_token = report2.token_map.iter().find(|(_, v)| *v == "Alice Smith").map(|(k, _): (&String, &String)| k.clone()).unwrap();

        assert_ne!(john_token, alice_token, "John and Alice should have distinct tokens");

        let engine3 = WardenEngine::new(
            vec![
                ("PERSON".to_string(), "John Smith".to_string(), EnforcementAction::Redact, PiiCategory::Other),
                ("PERSON".to_string(), "Alice Smith".to_string(), EnforcementAction::Redact, PiiCategory::Other),
                ("PERSON".to_string(), "Smith".to_string(), EnforcementAction::Redact, PiiCategory::Other)
            ],
            vec![],
            vec![],
            None,
            0.5,
            &pepper
        ).unwrap();

        let report3 = engine3.sanitize_prompt("Smith is here.", Some(&session)).await.unwrap();
        let smith_token = report3.token_map.iter().find(|(_, v)| *v == "Smith").map(|(k, _): (&String, &String)| k.clone()).unwrap();

        assert!(smith_token.starts_with("["), "Smith should be a token");
    }
}
