//! Adversarial Torture Integration Test Suite for IronWarden PII Shield
//!
//! Validates:
//! 1. Verb-eater elimination and span boundary integrity (AC1)
//! 2. Greek grammatical case inflections and Greeklish coverage (AC2)
//! 3. Complex name topologies (initials, nobiliary particles, sentence start) (AC3)
//! 4. Dirty enterprise formats, markdown, brackets, and valid JSON (AC3)
//! 5. Adversarial negative controls with zero false positives (AC4)
//! 6. Reversible cryptographic token rehydration roundtrip

extern crate warden as iw_warden;

use iw_core::traits::PiiShield;
use iw_warden::config::WardenConfig;
use iw_warden::engine::WardenEngine;
use secrecy::SecretVec;
use std::path::Path;

struct TestEngines {
    heuristic: WardenEngine,
    hybrid: Option<WardenEngine>,
}

fn is_onnx_model_available() -> bool {
    let model = Path::new("data/models/distilbert-ner/model_quantized.onnx");
    let model_parent = Path::new("../data/models/distilbert-ner/model_quantized.onnx");
    let tok = Path::new("data/models/distilbert-ner/tokenizer.json");
    let tok_parent = Path::new("../data/models/distilbert-ner/tokenizer.json");
    let available =
        (model.exists() || model_parent.exists()) && (tok.exists() || tok_parent.exists());
    if !available && std::env::var("WARDEN_NER_MODE").as_deref() == Ok("require_hybrid") {
        panic!("WARDEN_NER_MODE=require_hybrid is set, but ONNX model weights are missing!");
    }
    available
}

fn init_test_engines() -> TestEngines {
    // If running inside warden/ subdirectory, navigate to repo root
    if !Path::new("config/manifest.yaml").exists() && Path::new("../config/manifest.yaml").exists()
    {
        let _ = std::env::set_current_dir("..");
    }

    let pepper = SecretVec::new(vec![42u8; 32]);
    let manifest_path = if Path::new("config/manifest.yaml").exists() {
        "config/manifest.yaml"
    } else {
        "../config/manifest.yaml"
    };

    let (mut config, _) =
        WardenConfig::from_manifest(manifest_path).expect("Failed to load config/manifest.yaml");

    let gr_path = if Path::new("config/rules/gr.yaml").exists() {
        "config/rules/gr.yaml"
    } else {
        "../config/rules/gr.yaml"
    };
    if let Ok(gr_config) = WardenConfig::from_file(gr_path) {
        config.rules.extend(gr_config.rules);
        config.heuristics.extend(gr_config.heuristics);
    }

    // Heuristic Engine
    let heur_config = WardenConfig {
        rules: config.rules.clone(),
        heuristics: config.heuristics.clone(),
        ai_enabled: false,
        ai_confidence_threshold: 0.85,
    };
    let heuristic = heur_config
        .compile_engine(&pepper)
        .expect("Failed to compile Heuristic engine");

    // Hybrid Engine (Enable ONNX in test only if model files are present on disk)
    let hybrid = if is_onnx_model_available() {
        std::env::set_var("WARDEN_ENABLE_ONNX_TEST", "1");
        let hyb_config = WardenConfig {
            rules: config.rules.clone(),
            heuristics: config.heuristics.clone(),
            ai_enabled: true,
            ai_confidence_threshold: 0.85,
        };
        hyb_config.compile_engine(&pepper).ok()
    } else {
        None
    };

    TestEngines { heuristic, hybrid }
}

static TEST_ENGINES: std::sync::LazyLock<TestEngines> = std::sync::LazyLock::new(init_test_engines);

// =============================================================================
// Module 1: test_verb_eater_and_span_boundaries (AC1)
// =============================================================================

struct SpanCase {
    prompt: &'static str,
    target: &'static str,
    prefix: &'static str,
    suffix: &'static str,
}

#[tokio::test]
async fn test_verb_eater_and_span_boundaries() {
    let engines = &*TEST_ENGINES;
    let cases = [
        SpanCase {
            prompt: "patient hoyt complained yesterday",
            target: "hoyt",
            prefix: "patient ",
            suffix: " complained yesterday",
        },
        SpanCase {
            prompt: "per coste delay the deployment immediately",
            target: "coste",
            prefix: "per ",
            suffix: " delay the deployment immediately",
        },
        SpanCase {
            prompt: "please ask miura urgently about the crash",
            target: "miura",
            prefix: "please ask ",
            suffix: " urgently about the crash",
        },
        SpanCase {
            prompt: "my name is john smith and i approved it",
            target: "john smith",
            prefix: "my name is ",
            suffix: " and i approved it",
        },
        // Protected surnames ending in -ing, -ly, -ed
        SpanCase {
            prompt: "contact alan turing regarding the computation",
            target: "alan turing",
            prefix: "contact ",
            suffix: " regarding the computation",
        },
        SpanCase {
            prompt: "please ping john kelly about the incident",
            target: "john kelly",
            prefix: "please ping ",
            suffix: " about the incident",
        },
        SpanCase {
            prompt: "email tariq ahmed today",
            target: "tariq ahmed",
            prefix: "email ",
            suffix: " today",
        },
        SpanCase {
            prompt: "ask lou reed to review the pr",
            target: "lou reed",
            prefix: "ask ",
            suffix: " to review the pr",
        },
    ];

    let Some(ref hyb) = engines.hybrid else {
        eprintln!(
            "SKIPPING test_verb_eater_and_span_boundaries: ONNX model weights not present on disk"
        );
        return;
    };
    let test_targets: Vec<&WardenEngine> = vec![hyb];

    for engine in test_targets {
        for case in &cases {
            let report = engine
                .sanitize_prompt(case.prompt, None)
                .await
                .expect("sanitize_prompt failed");

            assert!(
                !report.sanitized_text.contains(case.target),
                "Target entity '{}' must be redacted in prompt '{}'. Got: '{}'",
                case.target,
                case.prompt,
                report.sanitized_text
            );
            assert!(
                report.sanitized_text.contains(case.prefix),
                "Prefix '{}' must be preserved in prompt '{}'. Got: '{}'",
                case.prefix,
                case.prompt,
                report.sanitized_text
            );
            assert!(
                report.sanitized_text.contains(case.suffix),
                "Suffix '{}' must be preserved in prompt '{}'. Got: '{}'",
                case.suffix,
                case.prompt,
                report.sanitized_text
            );
            assert!(
                !report.redactions.is_empty(),
                "Expected at least one redaction for prompt '{}'",
                case.prompt
            );
        }
    }
}

// =============================================================================
// Module 2: test_greek_inflections_and_greeklish (AC2)
// =============================================================================

struct GreekCase {
    prompt: &'static str,
    targets: &'static [&'static str],
    prefix: &'static str,
    suffix: &'static str,
    middle: Option<&'static str>,
}

#[tokio::test]
async fn test_greek_inflections_and_greeklish() {
    let engines = &*TEST_ENGINES;
    let cases = [
        // Nominative
        GreekCase {
            prompt: "Ο Νικόλας Αλεξανδράκης ήταν παρών.",
            targets: &["Νικόλας Αλεξανδράκης"],
            prefix: "Ο ",
            suffix: " ήταν παρών.",
            middle: None,
        },
        GreekCase {
            prompt: "Ο Γεώργιος Παπαδόπουλος είναι ο διευθυντής.",
            targets: &["Γεώργιος Παπαδόπουλος"],
            prefix: "Ο ",
            suffix: " είναι ο διευθυντής.",
            middle: None,
        },
        // Accusative
        GreekCase {
            prompt: "Στείλε το έγγραφο στον Νικόλα Αλεξανδράκη.",
            targets: &["Νικόλα Αλεξανδράκη"],
            prefix: "Στείλε το έγγραφο στον ",
            suffix: ".",
            middle: None,
        },
        GreekCase {
            prompt: "Είδα τον Γιώργο Παπαδόπουλο στο γραφείο.",
            targets: &["Γιώργο Παπαδόπουλο"],
            prefix: "Είδα τον ",
            suffix: " στο γραφείο.",
            middle: None,
        },
        GreekCase {
            prompt: "Κάλεσε τον Κώστα Νικολαΐδη.",
            targets: &["Κώστα Νικολαΐδη"],
            prefix: "Κάλεσε τον ",
            suffix: ".",
            middle: None,
        },
        // Genitive
        GreekCase {
            prompt: "Η αναφορά του Γιώργου Παπαδόπουλου και του Κώστα Νικολαΐδη.",
            targets: &["Γιώργου Παπαδόπουλου", "Κώστα Νικολαΐδη"],
            prefix: "Η αναφορά του ",
            suffix: ".",
            middle: Some(" και του "),
        },
        GreekCase {
            prompt: "Το αίτημα του Νικόλα Αλεξανδράκη εγκρίθηκε.",
            targets: &["Νικόλα Αλεξανδράκη"],
            prefix: "Το αίτημα του ",
            suffix: " εγκρίθηκε.",
            middle: None,
        },
        // Lowercase Greek
        GreekCase {
            prompt: "ρώτα τον νικόλα αλεξανδράκη για τον σερβερ",
            targets: &["νικόλα αλεξανδράκη"],
            prefix: "ρώτα τον ",
            suffix: " για τον σερβερ",
            middle: None,
        },
        GreekCase {
            prompt: "επικοινώνησε με τον γιώργο παπαδόπουλο",
            targets: &["γιώργο παπαδόπουλο"],
            prefix: "επικοινώνησε με τον ",
            suffix: "",
            middle: None,
        },
        // Lowercase Greeklish
        GreekCase {
            prompt: "rota ton nikola alexandraki h ton giorgo papadopoulo",
            targets: &["nikola alexandraki", "giorgo papadopoulo"],
            prefix: "rota ton ",
            suffix: "",
            middle: Some(" h ton "),
        },
        GreekCase {
            prompt: "steile email ston kosta nikolaidi",
            targets: &["kosta nikolaidi"],
            prefix: "steile email ston ",
            suffix: "",
            middle: None,
        },
        GreekCase {
            prompt: "per alexandraki delay deployment",
            targets: &["alexandraki"],
            prefix: "per ",
            suffix: " delay deployment",
            middle: None,
        },
    ];

    let mut test_targets: Vec<&WardenEngine> = vec![&engines.heuristic];
    if let Some(ref hyb) = engines.hybrid {
        test_targets.push(hyb);
    }

    for engine in test_targets {
        for case in &cases {
            let report = engine
                .sanitize_prompt(case.prompt, None)
                .await
                .expect("sanitize_prompt failed");

            println!(
                "Greek case '{}' -> '{}' (redactions: {:?})",
                case.prompt, report.sanitized_text, report.redactions
            );

            for target in case.targets {
                assert!(
                    !report.sanitized_text.contains(target),
                    "Target entity '{}' must be redacted in prompt '{}'. Got: '{}'",
                    target,
                    case.prompt,
                    report.sanitized_text
                );
            }
            assert!(
                report.sanitized_text.contains(case.prefix),
                "Prefix '{}' must be preserved in prompt '{}'. Got: '{}'",
                case.prefix,
                case.prompt,
                report.sanitized_text
            );
            assert!(
                report.sanitized_text.contains(case.suffix),
                "Suffix '{}' must be preserved in prompt '{}'. Got: '{}'",
                case.suffix,
                case.prompt,
                report.sanitized_text
            );
            if let Some(mid) = case.middle {
                assert!(
                    report.sanitized_text.contains(mid),
                    "Middle phrase '{}' must be preserved in prompt '{}'. Got: '{}'",
                    mid,
                    case.prompt,
                    report.sanitized_text
                );
            }
            assert!(
                !report.redactions.is_empty(),
                "Expected at least one redaction for prompt '{}'",
                case.prompt
            );
        }
    }
}

// =============================================================================
// Module 3: test_complex_name_topologies (AC3)
// =============================================================================

struct TopologyCase {
    prompt: &'static str,
    targets: &'static [&'static str],
    prefix: &'static str,
    suffix: &'static str,
    middle: Option<&'static str>,
}

#[tokio::test]
async fn test_complex_name_topologies() {
    let engines = &*TEST_ENGINES;
    let cases = [
        // Multiple initials
        TopologyCase {
            prompt: "The novel was written by J. R. R. Tolkien in Oxford.",
            targets: &["J. R. R. Tolkien"],
            prefix: "The novel was written by ",
            suffix: " in Oxford.",
            middle: None,
        },
        TopologyCase {
            prompt: "C. S. Lewis authored Narnia.",
            targets: &["C. S. Lewis"],
            prefix: "",
            suffix: " authored Narnia.",
            middle: None,
        },
        // Single initials
        TopologyCase {
            prompt: "The report was signed by B. Young yesterday.",
            targets: &["B. Young"],
            prefix: "The report was signed by ",
            suffix: " yesterday.",
            middle: None,
        },
        TopologyCase {
            prompt: "Contact H. Wells for system access.",
            targets: &["H. Wells"],
            prefix: "Contact ",
            suffix: " for system access.",
            middle: None,
        },
        // Nobiliary particles
        TopologyCase {
            prompt: "Symphony composed by Ludwig van Beethoven in Vienna.",
            targets: &["Ludwig van Beethoven"],
            prefix: "Symphony composed by ",
            suffix: " in Vienna.",
            middle: None,
        },
        TopologyCase {
            prompt: "Troops led by Tariq ibn Ziyad crossed the strait.",
            targets: &["Tariq ibn Ziyad"],
            prefix: "Troops led by ",
            suffix: " crossed the strait.",
            middle: None,
        },
        TopologyCase {
            prompt: "Masterpiece painted by Leonardo da Vinci.",
            targets: &["Leonardo da Vinci"],
            prefix: "Masterpiece painted by ",
            suffix: ".",
            middle: None,
        },
        // Sentence-start single surnames
        TopologyCase {
            prompt: "Bitar saved well again from Miura.",
            targets: &["Bitar", "Miura"],
            prefix: "",
            suffix: ".",
            middle: Some(" saved well again from "),
        },
        TopologyCase {
            prompt: "Alexandrakis confirmed the database topology.",
            targets: &["Alexandrakis"],
            prefix: "",
            suffix: " confirmed the database topology.",
            middle: None,
        },
    ];

    let Some(ref hyb) = engines.hybrid else {
        eprintln!("SKIPPING test_complex_name_topologies: ONNX model weights not present on disk");
        return;
    };
    let test_targets: Vec<&WardenEngine> = vec![hyb];

    for engine in test_targets {
        for case in &cases {
            let report = engine
                .sanitize_prompt(case.prompt, None)
                .await
                .expect("sanitize_prompt failed");

            for target in case.targets {
                assert!(
                    !report.sanitized_text.contains(target),
                    "Target entity '{}' must be redacted in prompt '{}'. Got: '{}'",
                    target,
                    case.prompt,
                    report.sanitized_text
                );
            }
            assert!(
                report.sanitized_text.contains(case.prefix),
                "Prefix '{}' must be preserved in prompt '{}'. Got: '{}'",
                case.prefix,
                case.prompt,
                report.sanitized_text
            );
            assert!(
                report.sanitized_text.contains(case.suffix),
                "Suffix '{}' must be preserved in prompt '{}'. Got: '{}'",
                case.suffix,
                case.prompt,
                report.sanitized_text
            );
            if let Some(mid) = case.middle {
                assert!(
                    report.sanitized_text.contains(mid),
                    "Middle phrase '{}' must be preserved in prompt '{}'. Got: '{}'",
                    mid,
                    case.prompt,
                    report.sanitized_text
                );
            }
            assert!(
                !report.redactions.is_empty(),
                "Expected at least one redaction for prompt '{}'",
                case.prompt
            );
        }
    }
}

// =============================================================================
// Module 4: test_dirty_enterprise_formats_and_multi_span_offsets (AC3)
// =============================================================================

#[tokio::test]
async fn test_dirty_enterprise_formats_and_multi_span_offsets() {
    let engines = &*TEST_ENGINES;

    let Some(ref hyb) = engines.hybrid else {
        eprintln!("SKIPPING test_dirty_enterprise_formats_and_multi_span_offsets: ONNX model weights not present on disk");
        return;
    };
    let test_targets: Vec<&WardenEngine> = vec![hyb];

    for engine in test_targets {
        // 1. JSON Strings
        let json_prompt = r#"{"user": "Nikolas Alexandrakis", "role": "admin", "active": true}"#;
        let report = engine
            .sanitize_prompt(json_prompt, None)
            .await
            .expect("sanitize_prompt failed");

        assert!(
            !report.sanitized_text.contains("Nikolas Alexandrakis"),
            "Entity must be redacted from JSON"
        );
        let parsed: serde_json::Value = serde_json::from_str(&report.sanitized_text)
            .expect("Sanitized text must remain valid JSON");
        assert_eq!(parsed["role"], "admin");
        assert_eq!(parsed["active"], true);
        assert!(
            parsed["user"].is_string() && parsed["user"].as_str().unwrap().starts_with('['),
            "Expected token placeholder in user field, got: {:?}",
            parsed["user"]
        );

        // 2. Markdown formatting
        let md_prompt = "Please contact **Nikolas Alexandrakis** or _John Kelly_ immediately.";
        let md_report = engine
            .sanitize_prompt(md_prompt, None)
            .await
            .expect("sanitize_prompt failed");
        assert!(!md_report.sanitized_text.contains("Nikolas Alexandrakis"));
        assert!(!md_report.sanitized_text.contains("John Kelly"));
        assert!(
            md_report.sanitized_text.contains("**"),
            "Markdown bold markers must be preserved"
        );
        assert!(
            md_report.sanitized_text.contains('_'),
            "Markdown italic markers must be preserved"
        );
        assert!(
            md_report.sanitized_text.contains("Please contact "),
            "Prefix must be preserved"
        );
        assert!(
            md_report.sanitized_text.contains(" immediately."),
            "Suffix must be preserved"
        );

        // 3. Adjacent comma-separated names
        let list_prompt = "Attendees: Alice Smith, Bob Jones, and Charlie Brown.";
        let list_report = engine
            .sanitize_prompt(list_prompt, None)
            .await
            .expect("sanitize_prompt failed");
        assert!(!list_report.sanitized_text.contains("Alice Smith"));
        assert!(!list_report.sanitized_text.contains("Bob Jones"));
        assert!(!list_report.sanitized_text.contains("Charlie Brown"));
        assert!(list_report.sanitized_text.contains("Attendees: "));
        assert!(list_report.sanitized_text.contains(", "));
        assert!(list_report.sanitized_text.contains(", and "));

        // 4. Brackets and special delimiters
        let brackets_prompt = "Records: [Hoyt, Coste] approved by <Bitar>.";
        let brackets_report = engine
            .sanitize_prompt(brackets_prompt, None)
            .await
            .expect("sanitize_prompt failed");
        assert!(!brackets_report.sanitized_text.contains("Hoyt"));
        assert!(!brackets_report.sanitized_text.contains("Coste"));
        assert!(!brackets_report.sanitized_text.contains("Bitar"));
        assert!(brackets_report.sanitized_text.contains("Records: ["));
        assert!(brackets_report.sanitized_text.contains(", "));
        assert!(brackets_report.sanitized_text.contains("] approved by <"));
        assert!(brackets_report.sanitized_text.contains(">."));
    }
}

// =============================================================================
// Module 5: test_evil_negative_controls_zero_fp (AC4)
// =============================================================================

#[tokio::test]
async fn test_evil_negative_controls_zero_fp() {
    let engines = &*TEST_ENGINES;
    let negative_controls = [
        // Middle-initial traps
        "Give Bob A Call and Send Mary A Message to Plan A Strategy.",
        "Take A Break and Have A Look at Section A Details.",
        // Acronym boundaries & geographic proper nouns
        "The U.S. Government and E.U. Commission met in Hong Kong and New York.",
        "United Nations delegates arrived in San Francisco and Los Angeles.",
        // Role traps
        "Log into the Patient Portal to update Patient Records and Patient Care as Per Request or Billed Per Month.",
        "Customer Portal updates for Customer Service and Client Accounts.",
        // Lowercase non-PII chatter
        "i am ready and i'm looking into why we should contact support or ask billing about the patient portal.",
        "please contact help or ping admin if you need more information about the rollout.",
        // SQL & DevOps keywords
        "SELECT User, Client, Patient FROM Accounts WHERE Status = 'Active' AND Engine = 'Docker' LIMIT 10;",
        "kubectl get pods -n kube-system -l app=ingress-nginx",
    ];

    let mut test_targets: Vec<&WardenEngine> = vec![&engines.heuristic];
    if let Some(ref hyb) = engines.hybrid {
        test_targets.push(hyb);
    }

    for engine in test_targets {
        for control in &negative_controls {
            let report = engine
                .sanitize_prompt(control, None)
                .await
                .expect("sanitize_prompt failed");

            assert!(
                report.redactions.is_empty(),
                "Negative control '{}' produced unexpected redactions: {:?}",
                control,
                report.redactions
            );
            assert_eq!(
                report.sanitized_text, *control,
                "Negative control '{}' must match sanitized text byte-for-byte. Got: '{}'",
                control, report.sanitized_text
            );
        }
    }
}

// =============================================================================
// Module 6: test_token_rehydration_and_roundtrip_integrity
// =============================================================================

#[tokio::test]
async fn test_token_rehydration_and_roundtrip_integrity() {
    let engines = &*TEST_ENGINES;
    let test_prompts = [
        "patient hoyt complained yesterday",
        "per coste delay the deployment immediately",
        "please ask miura urgently about the crash",
        "my name is john smith and i approved it",
        "contact alan turing regarding the computation",
        "please ping john kelly about the incident",
        "email tariq ahmed today",
        "ask lou reed to review the pr",
        "dr. reilly approved the medication",
        "Ο Νικόλας Αλεξανδράκης ήταν παρών.",
        "Ο Γεώργιος Παπαδόπουλος είναι ο διευθυντής.",
        "Στείλε το έγγραφο στον Νικόλα Αλεξανδράκη.",
        "Είδα τον Γιώργο Παπαδόπουλο στο γραφείο.",
        "Κάλεσε τον Κώστα Νικολαΐδη.",
        "Η αναφορά του Γιώργου Παπαδόπουλου και του Κώστα Νικολαΐδη.",
        "Το αίτημα του Νικόλα Αλεξανδράκη εγκρίθηκε.",
        "ρώτα τον νικόλα αλεξανδράκη για τον σερβερ",
        "επικοινώνησε με τον γιώργο παπαδόπουλο",
        "rota ton nikola alexandraki h ton giorgo papadopoulo",
        "steile email ston kosta nikolaidi",
        "per alexandraki delay deployment",
        "The novel was written by J. R. R. Tolkien in Oxford.",
        "C. S. Lewis authored Narnia.",
        "The report was signed by B. Young yesterday.",
        "Contact H. Wells for system access.",
        "Symphony composed by Ludwig van Beethoven in Vienna.",
        "Troops led by Tariq ibn Ziyad crossed the strait.",
        "Masterpiece painted by Leonardo da Vinci.",
        "Bitar saved well again from Miura.",
        "Alexandrakis confirmed the database topology.",
        r#"{"user": "Nikolas Alexandrakis", "role": "admin", "active": true}"#,
        "Please contact **Nikolas Alexandrakis** or _John Kelly_ immediately.",
        "Attendees: Alice Smith, Bob Jones, and Charlie Brown.",
        "Records: [Hoyt, Coste] approved by <Bitar>.",
    ];

    let mut test_targets: Vec<&WardenEngine> = vec![&engines.heuristic];
    if let Some(ref hyb) = engines.hybrid {
        test_targets.push(hyb);
    }

    for engine in test_targets {
        for prompt in &test_prompts {
            let report = engine
                .sanitize_prompt(prompt, None)
                .await
                .expect("sanitize_prompt failed");

            if !report.redactions.is_empty() {
                let restored = engine
                    .restore_prompt(&report.sanitized_text, &report.token_map)
                    .expect("restore_prompt failed");

                assert_eq!(
                    restored, *prompt,
                    "Cryptographic roundtrip failed for prompt '{}'. Restored: '{}'",
                    prompt, restored
                );
            }
        }
    }
}
