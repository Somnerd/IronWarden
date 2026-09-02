extern crate warden as iw_warden;

mod core {
    #[path = "session_concurrency.rs"]
    mod session_concurrency;
}

mod warden {
    #[path = "evasion_test.rs"]
    mod evasion_test;
    #[path = "fusion_test.rs"]
    mod fusion_test;
    #[path = "ghosting_test.rs"]
    mod ghosting_test;
    #[path = "global_fusion_test.rs"]
    mod global_fusion_test;
    #[path = "greek_regex_test.rs"]
    mod greek_regex_test;
    #[path = "greek_test.rs"]
    mod greek_test;
    #[path = "identity_ghosting_test.rs"]
    mod identity_ghosting_test;
    #[path = "identity_linking_test.rs"]
    mod identity_linking_test;
    #[path = "legal_test.rs"]
    mod legal_test;
    #[path = "medical_test.rs"]
    mod medical_test;
    #[path = "sentinel_adversarial.rs"]
    mod sentinel_adversarial;
    #[path = "sentinel_qa.rs"]
    mod sentinel_qa;
    #[path = "session_test.rs"]
    mod session_test;
    #[path = "shipping_test.rs"]
    mod shipping_test;
}

mod worker {
    #[path = "adversarial_bridge_stress.rs"]
    mod adversarial_bridge_stress;
    #[path = "audit_integrity.rs"]
    mod audit_integrity;
    #[path = "auditor_concurrency_test.rs"]
    mod auditor_concurrency_test;
    #[path = "ha_verification.rs"]
    mod ha_verification;
    #[path = "librarian_scrub_test.rs"]
    mod librarian_scrub_test;
    #[path = "rag_blindness_test.rs"]
    mod rag_blindness_test;
    #[path = "security_invariant_test.rs"]
    mod security_invariant_test;
    #[path = "session_security_test.rs"]
    mod session_security_test;
    #[path = "streaming_rehydration_fuzz.rs"]
    mod streaming_rehydration_fuzz;
    #[path = "stress_fuzzer.rs"]
    mod stress_fuzzer;
    #[path = "tamper_test.rs"]
    mod tamper_test;
    #[path = "tandem_grounding_test.rs"]
    mod tandem_grounding_test;
}

mod app {
    #[path = "compliance_presets_e2e.rs"]
    mod compliance_presets_e2e;
    #[path = "hardened_integration.rs"]
    mod hardened_integration;
    #[path = "legal_e2e_test.rs"]
    mod legal_e2e_test;
    #[path = "mcp_integration_test.rs"]
    mod mcp_integration_test;
    #[path = "sentinel_e2e.rs"]
    mod sentinel_e2e;
}
