extern crate warden as iw_warden;

mod shadow_ner_tests {
    use iw_warden::shadow_ner::*;

    #[test]
    fn test_track_a_name_initials_and_particles() {
        let ner = ShadowNer::new(vec![]);
        let text =
            "Frederick H. Collier, James W. Hoyt, Ludwig van Beethoven, and B. Young met today.";
        let matches = ner.analyze(text, text);

        let matched_strings: Vec<&str> = matches.iter().map(|m| &text[m.start..m.end]).collect();
        assert!(matched_strings.contains(&"Frederick H. Collier"));
        assert!(matched_strings.contains(&"James W. Hoyt"));
        assert!(matched_strings.contains(&"Ludwig van Beethoven"));
        assert!(matched_strings.contains(&"B. Young"));
    }

    #[test]
    fn test_track_a_honorifics() {
        let ner = ShadowNer::new(vec![]);
        let text = "Dr. Miura and Mr. Hoyt conducted surgery.";
        let matches = ner.analyze(text, text);

        let matched_strings: Vec<&str> = matches.iter().map(|m| &text[m.start..m.end]).collect();
        assert!(matched_strings.contains(&"Dr. Miura"));
        assert!(matched_strings.contains(&"Mr. Hoyt"));
    }

    #[test]
    fn test_negative_controls_and_traps() {
        let ner = ShadowNer::new(vec![]);

        // 1. Literal false friends
        let text_false = "Give Bob A Call and send Mary A Message.";
        let matches_false = ner.analyze(text_false, text_false);
        let names_false: Vec<&str> = matches_false
            .iter()
            .map(|m| &text_false[m.start..m.end])
            .collect();
        assert!(!names_false.contains(&"Bob A Call"));
        assert!(!names_false.contains(&"Mary A Message"));

        // 2. Acronym boundary trap
        let text_acronym = "The U.S. Government announced Plan A. Next, we deploy.";
        let matches_acronym = ner.analyze(text_acronym, text_acronym);
        let names_acronym: Vec<&str> = matches_acronym
            .iter()
            .map(|m| &text_acronym[m.start..m.end])
            .collect();
        assert!(!names_acronym.contains(&"S. Government"));
        assert!(!names_acronym.contains(&"A. Next"));

        // 3. Geographic multi-word cities
        let text_geo = "Refactoring high-availability New York cache.";
        let matches_geo = ner.analyze(text_geo, text_geo);
        let names_geo: Vec<&str> = matches_geo
            .iter()
            .map(|m| &text_geo[m.start..m.end])
            .collect();
        assert!(!names_geo.contains(&"New York"));
    }

    #[test]
    fn test_track_b_ambiguous_role_nouns() {
        let ner = ShadowNer::new(vec![]);

        // Patient Portal, Per Request, Engineer Team should NOT be candidates
        let text_roles = "Log into Patient Portal. As Per Request, contact Engineer Team.";
        let candidates = ner.find_ambiguous_tokens(text_roles, &[]);
        let cand_words: Vec<&str> = candidates.iter().map(|c| c.text.as_str()).collect();

        assert!(!cand_words.contains(&"Portal"));
        assert!(!cand_words.contains(&"Request"));
        assert!(!cand_words.contains(&"Team"));

        // Per Coste, Patient Hoyt SHOULD be candidates
        let text_actual = "Per Coste, delay rollout. Patient Hoyt reported symptoms.";
        let candidates_actual = ner.find_ambiguous_tokens(text_actual, &[]);
        let cand_actual: Vec<&str> = candidates_actual.iter().map(|c| c.text.as_str()).collect();

        assert!(cand_actual.contains(&"Coste"));
        assert!(cand_actual.contains(&"Hoyt"));
    }

    #[test]
    fn test_lowercase_conversational_introducers() {
        let ner = ShadowNer::new(vec![]);

        // 1. "my name is john smith and please ask miura about logs" -> both candidates extracted
        let text_cands = "my name is john smith and please ask miura about logs";
        let cands = ner.find_ambiguous_tokens(text_cands, &[]);
        let cand_words: Vec<&str> = cands.iter().map(|c| c.text.as_str()).collect();

        assert!(
            cand_words.contains(&"john smith"),
            "Expected 'john smith' in {:?}",
            cand_words
        );
        assert!(
            cand_words.contains(&"miura"),
            "Expected 'miura' in {:?}",
            cand_words
        );
        for c in &cands {
            if c.text == "john smith" || c.text == "miura" {
                assert!(c.needs_synthetic_casing);
            }
        }

        // 2. "i am ready to contact support about the patient portal" -> 0 candidates extracted (all stopwords)
        let text_stopwords = "i am ready to contact support about the patient portal";
        let cands_empty = ner.find_ambiguous_tokens(text_stopwords, &[]);
        assert!(
            cands_empty.is_empty(),
            "Expected 0 candidates for stopwords phrase, got {:?}",
            cands_empty
        );

        // 3. Track A lowercase Greek morphological defense
        let text_greek = "please contact nikolas alexandrakis for the database credentials.";
        let matches = ner.analyze(text_greek, text_greek);
        let greek_matches: Vec<&str> = matches
            .iter()
            .map(|m| &text_greek[m.start..m.end])
            .collect();
        assert!(
            greek_matches.contains(&"nikolas alexandrakis")
                || greek_matches.contains(&"alexandrakis")
        );
    }

    #[test]
    fn test_interrogative_and_lowercase_names_comprehensive_suite() {
        let ner = ShadowNer::new(vec![]);

        // 1. Interrogative Pointers: "who is / was / were / who's / tell me about"
        let interrogative_cases = vec![
            ("who is micheal jordan", "micheal jordan"),
            ("who is micheal jordan?", "micheal jordan"),
            ("who was alexander the great", "alexander"),
            ("who was alexander the great?", "alexander"),
            ("who's john doe", "john doe"),
            ("who was napoleon bonaparte", "napoleon bonaparte"),
            ("who were john lennon and paul mccartney", "john lennon"),
            ("tell me about elon musk", "elon musk"),
        ];

        for (prompt, expected_cand) in interrogative_cases {
            let cands = ner.find_ambiguous_tokens(prompt, &[]);
            let cand_texts: Vec<&str> = cands.iter().map(|c| c.text.as_str()).collect();
            assert!(
                cand_texts.contains(&expected_cand),
                "For prompt '{}', expected candidate '{}' in {:?}",
                prompt,
                expected_cand,
                cand_texts
            );
            for c in &cands {
                if c.text == expected_cand {
                    assert!(
                        c.needs_synthetic_casing,
                        "Candidate '{}' in '{}' must have needs_synthetic_casing: true",
                        expected_cand, prompt
                    );
                }
            }
        }

        // 2. Additional Conversational & Relationship Cues
        let conversational_cases = vec![
            ("my name is nikolas alexandrakis", "nikolas alexandrakis"),
            ("contact jane smith", "jane smith"),
            ("email directly to robert frost", "robert frost"),
            ("attn: linus torvalds", "linus torvalds"),
            ("me and my friend john went for coffee", "john"),
            ("me and my friend john smith went for coffee", "john smith"),
            ("my colleague alice went to the meeting", "alice"),
            ("my brother alex went home", "alex"),
        ];

        for (prompt, expected_cand) in conversational_cases {
            let cands = ner.find_ambiguous_tokens(prompt, &[]);
            let cand_texts: Vec<&str> = cands.iter().map(|c| c.text.as_str()).collect();
            assert!(
                cand_texts.contains(&expected_cand),
                "For prompt '{}', expected candidate '{}' in {:?}",
                prompt,
                expected_cand,
                cand_texts
            );
            for c in &cands {
                if c.text == expected_cand {
                    assert!(c.needs_synthetic_casing);
                }
            }
        }

        // 3. Strict Negative Controls: Stopwords, common roles & questions must NOT produce candidates
        let negative_controls = vec![
            "who is the best developer",
            "who was responsible for the delay",
            "who is online",
            "who is offline",
            "who is available",
            "who was in the meeting today",
            "who are they",
            "i am ready to contact support about the patient portal",
        ];

        for negative in negative_controls {
            let cands = ner.find_ambiguous_tokens(negative, &[]);
            assert!(
                cands.is_empty(),
                "Expected 0 candidates for negative control '{}', but got: {:?}",
                negative,
                cands
            );
        }
    }

    #[test]
    fn test_sql_and_tech_stopwords_ignored() {
        let ner = ShadowNer::new(vec![]);
        let sql = "SELECT User, Client FROM Accounts WHERE Status = 'Active'";
        let candidates = ner.find_ambiguous_tokens(sql, &[]);
        assert!(
            candidates.is_empty(),
            "Expected 0 candidates for SQL query, got {:?}",
            candidates
        );
    }
}

mod configurator_tests {
    use iw_warden::configurator::*;
    use std::env;
    use std::fs;
    use std::path::Path;
    use std::sync::LazyLock;
    use std::sync::Mutex;

    static ENV_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    // A helper to run tests sequentially when modifying environment variables
    fn run_with_env<F>(setup: F)
    where
        F: FnOnce(),
    {
        let _guard = match ENV_MUTEX.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // Clear variables that affect `allow_fallback`
        let orig_warden = env::var("WARDEN_ENV");
        let orig_allow = env::var("ALLOW_FALLBACK");
        let orig_pepper = env::var("WARDEN_PEPPER");
        let orig_manifest = env::var("WARDEN_MANIFEST_PATH");
        let orig_key = env::var("OPENAI_API_KEY");

        env::remove_var("WARDEN_ENV");
        env::set_var("ALLOW_FALLBACK", "false");
        env::remove_var("WARDEN_PEPPER");
        env::remove_var("WARDEN_MANIFEST_PATH");
        env::remove_var("OPENAI_API_KEY");

        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(setup));

        // Restore
        if let Ok(val) = orig_warden {
            env::set_var("WARDEN_ENV", val);
        } else {
            env::remove_var("WARDEN_ENV");
        }
        if let Ok(val) = orig_allow {
            env::set_var("ALLOW_FALLBACK", val);
        } else {
            env::remove_var("ALLOW_FALLBACK");
        }
        if let Ok(val) = orig_pepper {
            env::set_var("WARDEN_PEPPER", val);
        } else {
            env::remove_var("WARDEN_PEPPER");
        }
        if let Ok(val) = orig_manifest {
            env::set_var("WARDEN_MANIFEST_PATH", val);
        } else {
            env::remove_var("WARDEN_MANIFEST_PATH");
        }
        if let Ok(val) = orig_key {
            env::set_var("OPENAI_API_KEY", val);
        } else {
            env::remove_var("OPENAI_API_KEY");
        }

        if let Err(e) = res {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    fn test_strict_mode_missing_config_yaml() {
        run_with_env(|| {
            env::set_var("ALLOW_FALLBACK", "false");
            env::set_var(
                "WARDEN_PEPPER",
                "this-is-a-valid-32-byte-test-pepper-string!",
            );

            let res =
                GlobalConfig::resolve_with_path(Some(Path::new("non_existent_path_config.yaml")));
            assert!(
                res.is_err(),
                "Must reject when config/config.yaml is missing in strict mode"
            );
            assert!(res.unwrap_err().to_string().contains("is missing"));
        });
    }

    #[test]
    fn test_strict_mode_pepper_too_short() {
        run_with_env(|| {
            let temp_dir = tempfile::tempdir().unwrap();
            let config_yaml = temp_dir.path().join("config.yaml");
            let manifest_yaml = temp_dir.path().join("manifest.yaml");
            let rules_dir = temp_dir.path().join("rules");

            fs::create_dir(&rules_dir).unwrap();
            fs::write(&config_yaml, "warden_mode: test\nallow_fallback: false\n").unwrap();
            fs::write(
                &manifest_yaml,
                format!(
                    "rules_dir: \"{}\"\nrule_categories: []",
                    rules_dir.display()
                ),
            )
            .unwrap();

            env::set_var("ALLOW_FALLBACK", "false");
            env::set_var("WARDEN_MANIFEST_PATH", manifest_yaml.to_str().unwrap());

            // Pepper < 32 bytes
            env::set_var("WARDEN_PEPPER", "short_pepper");
            let res = GlobalConfig::resolve_with_path(Some(&config_yaml));
            assert!(res.is_err(), "Must reject pepper < 32 bytes in strict mode");
            assert!(res.unwrap_err().to_string().contains("at least 32 bytes"));

            // Pepper >= 32 bytes
            env::set_var("WARDEN_PEPPER", "12345678901234567890123456789012");
            let res_ok = GlobalConfig::resolve_with_path(Some(&config_yaml));
            assert!(
                res_ok.is_ok(),
                "Must accept pepper >= 32 bytes: {:?}",
                res_ok.err()
            );
        });
    }

    #[test]
    fn test_strict_mode_missing_manifest() {
        run_with_env(|| {
            let temp_dir = tempfile::tempdir().unwrap();
            let config_yaml = temp_dir.path().join("config.yaml");
            fs::write(&config_yaml, "warden_mode: test\nallow_fallback: false\n").unwrap();

            env::set_var("ALLOW_FALLBACK", "false");
            env::set_var("WARDEN_PEPPER", "12345678901234567890123456789012");
            env::set_var("WARDEN_MANIFEST_PATH", "non_existent_manifest.yaml");

            let res = GlobalConfig::resolve_with_path(Some(&config_yaml));
            assert!(
                res.is_err(),
                "Must reject missing manifest file in strict mode"
            );
            assert!(res.unwrap_err().to_string().contains("manifest file"));
        });
    }

    #[test]
    fn test_memory_safe_openai_api_key() {
        run_with_env(|| {
            let temp_dir = tempfile::tempdir().unwrap();
            let config_yaml = temp_dir.path().join("config.yaml");
            fs::write(&config_yaml, "warden_mode: hybrid\nallow_fallback: true\n").unwrap();

            env::set_var("ALLOW_FALLBACK", "true");
            env::set_var("OPENAI_API_KEY", "sk-proj-test-secret-key-12345");
            env::set_var("WARDEN_PEPPER", "12345678901234567890123456789012");

            let config = GlobalConfig::resolve_with_path(Some(&config_yaml)).unwrap();

            use secrecy::ExposeSecret;
            assert_eq!(
                config.openai_api_key.expose_secret(),
                "sk-proj-test-secret-key-12345"
            );
        });
    }
}

mod ai_tests {
    use iw_warden::ai::*;
    use std::path::Path;
    use std::sync::Arc;

    #[ignore = "ORT rc.12 global allocator races Tokio multi-thread shutdown (teardown SIGSEGV); concurrency logic covered by pool integration via engine tests"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_ai_pool_concurrent_access() {
        // This test ensures the HybridNerPool can be accessed concurrently without deadlocks
        // We'll initialize a pool with 2 instances and spawn 10 concurrent requests.
        // Note: In an environment without ONNX models, this will fall back to NerBackend::None,
        // which still tests the concurrency logic of the pool itself (channel send/recv).
        let pool = Arc::new(HybridNerPool::new(0.85, 2).unwrap());

        let mut handles = vec![];
        for i in 0..10 {
            let pool_clone = pool.clone();
            handles.push(tokio::spawn(async move {
                // Try to acquire an instance
                if let Some(instance) = pool_clone.get().await {
                    // Simulate work
                    let _ = instance.analyze(&format!("Test input {}", i));
                    // Yield to simulate async delay
                    tokio::task::yield_now().await;
                    // Release instance back to pool
                    pool_clone.release(instance);
                    true
                } else {
                    false
                }
            }));
        }

        let mut success_count = 0;
        for handle in handles {
            if handle.await.unwrap_or(false) {
                success_count += 1;
            }
        }

        // Since we are running concurrently, some might timeout (25ms) if the CI is slow,
        // but we expect at least SOME successes, and crucially: NO deadlocks or panics.
        assert!(
            success_count > 0,
            "Expected at least one successful pool acquisition"
        );
    }

    #[test]
    #[ignore = "requires dedicated ONNX runtime container environment"]
    fn test_onnx_model_load_direct() {
        let model_path = if Path::new("data/models/distilbert-ner/model_quantized.onnx").exists() {
            Path::new("data/models/distilbert-ner/model_quantized.onnx")
        } else {
            Path::new("../data/models/distilbert-ner/model_quantized.onnx")
        };
        let tokenizer_path = if Path::new("data/models/distilbert-ner/tokenizer.json").exists() {
            Path::new("data/models/distilbert-ner/tokenizer.json")
        } else {
            Path::new("../data/models/distilbert-ner/tokenizer.json")
        };
        println!("Testing direct ONNX model load from {:?}...", model_path);
        assert!(model_path.exists(), "Model file must exist");
        assert!(tokenizer_path.exists(), "Tokenizer file must exist");
        let res = OnnxNer::new(model_path, tokenizer_path, 0.85);
        match res {
            Ok(ner) => {
                println!("Model loaded successfully!");
                let entities = ner.predict("John Doe works at Apple in London");
                println!("Predicted {} entities", entities.len());
                assert!(!entities.is_empty(), "Expected entities detected");
            }
            Err(e) => {
                panic!("Direct ONNX load failed: {}", e);
            }
        }
    }

    #[test]
    fn test_ner_mode_heuristic_effective_backend() {
        let dummy_model = Path::new("non_existent/model.onnx");
        let dummy_tok = Path::new("non_existent/tokenizer.json");
        let ner = HybridNer::new_with_paths(0.85, NerMode::Heuristic, dummy_model, dummy_tok)
            .expect("Heuristic mode must succeed");
        assert_eq!(ner.requested_mode(), "heuristic");
        assert_eq!(ner.effective_backend(), "heuristic");
    }

    #[test]
    fn test_ner_mode_hybrid_fallback_on_missing_model() {
        let dummy_model = Path::new("non_existent/model.onnx");
        let dummy_tok = Path::new("non_existent/tokenizer.json");
        let ner = HybridNer::new_with_paths(0.85, NerMode::Hybrid, dummy_model, dummy_tok)
            .expect("Hybrid mode with missing model should fall back to heuristic");
        assert_eq!(ner.requested_mode(), "hybrid");
        assert_eq!(ner.effective_backend(), "heuristic");
    }

    #[test]
    fn test_ner_mode_require_hybrid_err_on_missing_model() {
        let dummy_model = Path::new("non_existent/model.onnx");
        let dummy_tok = Path::new("non_existent/tokenizer.json");
        let res = HybridNer::new_with_paths(0.85, NerMode::RequireHybrid, dummy_model, dummy_tok);
        assert!(
            res.is_err(),
            "RequireHybrid mode must error when model files are missing"
        );
        let err_msg = res.unwrap_err();
        assert!(err_msg.contains("required by WARDEN_NER_MODE=require_hybrid"));
    }
}

mod normalize_tests {
    use iw_warden::normalize::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fuzz_normalization_offset_consistency(s in "\\PC*") {
            Normalizer::with_normalized(&s, |res| {
                // 1. Boundary check: Every normalized byte must map back to a valid original byte index
                for i in 0..res.normalized_ascii.len() {
                    let orig_idx = res.ascii_to_original.get_original_offset(i);
                    prop_assert!(orig_idx < s.len() || (s.is_empty() && orig_idx == 0));
                }

                // 2. Transformation check: The output must be pure ASCII (enforced by any_ascii)
                prop_assert!(res.normalized_ascii.is_ascii());

                // 3. Invisible character check: Output should not contain ZWSP etc.
                for c in res.normalized_ascii.chars() {
                    prop_assert!(!Normalizer::is_invisible(c));
                }
                Ok(())
            })?;
        }
    }

    #[test]
    fn test_specific_edge_cases() {
        let input = "A\u{200B}B"; // Invisible ZWSP (3 bytes: E2 80 8B)
        Normalizer::with_normalized(input, |res| {
            assert_eq!(res.normalized_ascii, "AB");
            assert_eq!(res.ascii_to_original.get_original_offset(0), 0); // A
            assert_eq!(res.ascii_to_original.get_original_offset(1), 4); // B (skips 3-byte ZWSP at indices 1,2,3)
        });
    }

    #[test]
    fn test_whitespace_control_characters_preserved() {
        let input = "User Name:\nAlice\tBob\r\nEmail:\talice@example.com";
        Normalizer::with_normalized(input, |res| {
            assert!(res.normalized_unicode.contains('\n'));
            assert!(res.normalized_unicode.contains('\t'));
            assert!(res.normalized_unicode.contains('\r'));
            assert_eq!(res.normalized_unicode, input);
        });
    }
}

mod config_tests {
    use iw_warden::config::WardenConfig;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_invalid_yaml_fails_gracefully() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "rules: [ invalid yaml \n - ").unwrap();

        let result = WardenConfig::from_file(file.path());
        assert!(result.is_err());
        if let Err(iw_core::SovereignError::ConfigError(msg)) = result {
            assert!(msg.contains("YAML Error"));
        } else {
            panic!("Expected ConfigError");
        }
    }

    #[test]
    fn test_valid_yaml_parses() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            "
rules:
  - id: test_rule
    pattern: 'test'
    type: Dictionary
    action: Redact
ai_enabled: true
ai_confidence_threshold: 0.95
        "
        )
        .unwrap();

        let config = WardenConfig::from_file(file.path()).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "test_rule");
        assert!(config.ai_enabled);
        assert_eq!(config.ai_confidence_threshold, 0.95);
    }
}
