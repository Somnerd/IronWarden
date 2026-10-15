//! Challenger 2 Empirical Adversarial Stress Test Suite
//!
//! Independent stress testing covering:
//! 1. Complex name topologies (3-token initials, hyphenated names, noble prefixes, Latin abbr guards)
//! 2. Structural embeddings (Markdown formatting, JSON payloads, CSV lines, roster lists)
//! 3. Negative controls (imperative verbs, geographic proper nouns, role titles, zero false positive rate)
//! 4. Roundtrip cryptographic restoration integrity

use iw_core::traits::PiiShield;
use iw_warden::config::WardenConfig;
use iw_warden::engine::WardenEngine;
use secrecy::SecretVec;
use std::path::Path;

struct TestHarness {
    heuristic: WardenEngine,
    hybrid: WardenEngine,
}

fn init_harness() -> TestHarness {
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

    // Hybrid Engine (ONNX enabled)
    std::env::set_var("WARDEN_ENABLE_ONNX_TEST", "1");
    let hyb_config = WardenConfig {
        rules: config.rules.clone(),
        heuristics: config.heuristics.clone(),
        ai_enabled: true,
        ai_confidence_threshold: 0.85,
    };
    let hybrid = hyb_config
        .compile_engine(&pepper)
        .expect("Failed to compile Hybrid ONNX engine");

    TestHarness { heuristic, hybrid }
}

static HARNESS: std::sync::LazyLock<TestHarness> = std::sync::LazyLock::new(init_harness);

// =============================================================================
// Test 1: Complex Name Topologies (3-token initials, hyphenated, noble prefixes)
// =============================================================================

#[tokio::test]
async fn test_c2_complex_name_topologies() {
    let harness = &*HARNESS;

    struct Case {
        prompt: &'static str,
        expected_redactions: &'static [&'static str],
        expected_preservations: &'static [&'static str],
    }

    let cases = [
        // 3-token and multi-initial names
        Case {
            prompt: "The author J. R. R. Tolkien created Middle-earth.",
            expected_redactions: &["J. R. R. Tolkien"],
            expected_preservations: &["The author ", " created Middle-earth."],
        },
        Case {
            prompt: "Manuscript written by George R. R. Martin in New York.",
            expected_redactions: &["George R. R. Martin"],
            expected_preservations: &["Manuscript written by ", " in New York."],
        },
        Case {
            prompt: "Poems by e. e. cummings were revolutionary.",
            expected_redactions: &["e. e. cummings"],
            expected_preservations: &["Poems by ", " were revolutionary."],
        },
        Case {
            prompt: "Essays by T. S. Eliot and W. H. Auden were discussed.",
            expected_redactions: &["T. S. Eliot", "W. H. Auden"],
            expected_preservations: &["Essays by ", " and ", " were discussed."],
        },
        Case {
            prompt: "Fantasy series by J. K. Rowling published globally.",
            expected_redactions: &["J. K. Rowling"],
            expected_preservations: &["Fantasy series by ", " published globally."],
        },
        Case {
            prompt: "Stories by H. P. Lovecraft remain influential.",
            expected_redactions: &["H. P. Lovecraft"],
            expected_preservations: &["Stories by ", " remain influential."],
        },
        Case {
            prompt: "Fiction edited by F. Scott Fitzgerald and E. B. White.",
            expected_redactions: &["F. Scott Fitzgerald", "E. B. White"],
            expected_preservations: &["Fiction edited by ", " and ", "."],
        },
        Case {
            prompt: "Book written by C. S. Lewis in Oxford.",
            expected_redactions: &["C. S. Lewis"],
            expected_preservations: &["Book written by ", " in Oxford."],
        },
        Case {
            prompt: "Comedy authored by P. G. Wodehouse.",
            expected_redactions: &["P. G. Wodehouse"],
            expected_preservations: &["Comedy authored by ", "."],
        },
        Case {
            prompt: "Novels authored by H. G. Wells.",
            expected_redactions: &["H. G. Wells"],
            expected_preservations: &["Novels authored by ", "."],
        },
        Case {
            prompt: "Children's books by A. A. Milne.",
            expected_redactions: &["A. A. Milne"],
            expected_preservations: &["Children's books by ", "."],
        },
        Case {
            prompt: "Literature penned by D. H. Lawrence.",
            expected_redactions: &["D. H. Lawrence"],
            expected_preservations: &["Literature penned by ", "."],
        },
        // Noble prefixes & nobiliary particles
        Case {
            prompt: "Fables authored by Jean de La Fontaine in Paris.",
            expected_redactions: &["Jean de La Fontaine"],
            expected_preservations: &["Fables authored by ", " in Paris."],
        },
        Case {
            prompt: "Speech delivered by Charles de Gaulle during wartime.",
            expected_redactions: &["Charles de Gaulle"],
            expected_preservations: &["Speech delivered by ", " during wartime."],
        },
        Case {
            prompt: "Symphony premiered by Ludwig van Beethoven in Bonn.",
            expected_redactions: &["Ludwig van Beethoven"],
            expected_preservations: &["Symphony premiered by ", " in Bonn."],
        },
        Case {
            prompt: "Sunflowers painted by Vincent van Gogh in Arles.",
            expected_redactions: &["Vincent van Gogh"],
            expected_preservations: &["Sunflowers painted by ", " in Arles."],
        },
        Case {
            prompt: "Physics formulated by Johannes van der Waals.",
            expected_redactions: &["Johannes van der Waals"],
            expected_preservations: &["Physics formulated by ", "."],
        },
        Case {
            prompt: "Philosophy by Simone de Beauvoir influenced generations.",
            expected_redactions: &["Simone de Beauvoir"],
            expected_preservations: &["Philosophy by ", " influenced generations."],
        },
        Case {
            prompt: "Expedition commanded by Hernan Cortes in the Americas.",
            expected_redactions: &["Hernan Cortes"],
            expected_preservations: &["Expedition commanded by ", " in the Americas."],
        },
        Case {
            prompt: "Monarchy led by Willem van Oranje in the Netherlands.",
            expected_redactions: &["Willem van Oranje"],
            expected_preservations: &["Monarchy led by ", " in the Netherlands."],
        },
        Case {
            prompt: "Army led by Tariq ibn Ziyad crossed into Iberia.",
            expected_redactions: &["Tariq ibn Ziyad"],
            expected_preservations: &["Army led by ", " crossed into Iberia."],
        },
        Case {
            prompt: "Masterpiece created by Leonardo da Vinci in Florence.",
            expected_redactions: &["Leonardo da Vinci"],
            expected_preservations: &["Masterpiece created by ", " in Florence."],
        },
    ];

    for case in &cases {
        let report = harness
            .hybrid
            .sanitize_prompt(case.prompt, None)
            .await
            .expect("Hybrid sanitize failed");

        for ent in case.expected_redactions {
            assert!(
                !report.sanitized_text.contains(ent),
                "Expected entity '{}' to be redacted in prompt '{}'. Got: '{}'",
                ent,
                case.prompt,
                report.sanitized_text
            );
        }

        for pres in case.expected_preservations {
            assert!(
                report.sanitized_text.contains(pres),
                "Expected text '{}' to be preserved in prompt '{}'. Got: '{}'",
                pres,
                case.prompt,
                report.sanitized_text
            );
        }
    }
}

// =============================================================================
// Test 2: Structural Embeddings (Markdown, JSON, CSV, Roster Lists)
// =============================================================================

#[tokio::test]
async fn test_c2_structural_embeddings() {
    let harness = &*HARNESS;

    // 1. Markdown formatting: bold, italic, underscore
    let md_prompt = "Contact _John Smith_ or **Jane Doe** regarding the architecture.";
    let report = harness
        .hybrid
        .sanitize_prompt(md_prompt, None)
        .await
        .unwrap();
    assert!(!report.sanitized_text.contains("John Smith"));
    assert!(!report.sanitized_text.contains("Jane Doe"));
    assert!(
        report.sanitized_text.contains('_'),
        "Underscore markdown marker must be intact"
    );
    assert!(
        report.sanitized_text.contains("**"),
        "Asterisk bold marker must be intact"
    );
    assert!(report.sanitized_text.starts_with("Contact "));
    assert!(report
        .sanitized_text
        .ends_with(" regarding the architecture."));

    // 2. JSON payloads
    let json_prompt = r#"{"user": "Hoyt", "role": "admin", "lead": "Nikolas Alexandrakis"}"#;
    let report_json = harness
        .hybrid
        .sanitize_prompt(json_prompt, None)
        .await
        .unwrap();
    assert!(!report_json.sanitized_text.contains("Hoyt"));
    assert!(!report_json.sanitized_text.contains("Nikolas Alexandrakis"));
    let parsed: serde_json::Value =
        serde_json::from_str(&report_json.sanitized_text).expect("Must remain valid JSON");
    assert_eq!(parsed["role"], "admin");
    assert!(parsed["user"].as_str().unwrap().starts_with('['));
    assert!(parsed["lead"].as_str().unwrap().starts_with('['));

    // 3. Array JSON payload
    let json_arr = r#"{"attendees": ["Hoyt", "Coste", "Miura"]}"#;
    let report_arr = harness
        .hybrid
        .sanitize_prompt(json_arr, None)
        .await
        .unwrap();
    assert!(!report_arr.sanitized_text.contains("Hoyt"));
    assert!(!report_arr.sanitized_text.contains("Coste"));
    assert!(!report_arr.sanitized_text.contains("Miura"));
    let parsed_arr: serde_json::Value =
        serde_json::from_str(&report_arr.sanitized_text).expect("Must remain valid JSON array");
    assert_eq!(parsed_arr["attendees"].as_array().unwrap().len(), 3);

    // 4. Roster lists with commas without list swallowing
    let roster_prompt = "Meeting attendees: Hoyt, Coste, Miura, and Bitar.";
    let report_roster = harness
        .hybrid
        .sanitize_prompt(roster_prompt, None)
        .await
        .unwrap();
    assert!(!report_roster.sanitized_text.contains("Hoyt"));
    assert!(!report_roster.sanitized_text.contains("Coste"));
    assert!(!report_roster.sanitized_text.contains("Miura"));
    assert!(!report_roster.sanitized_text.contains("Bitar"));
    assert!(
        report_roster.sanitized_text.contains(", "),
        "Commas between names must be preserved"
    );
    assert!(
        report_roster.sanitized_text.contains(", and "),
        "Oxford comma and conjunction must be preserved"
    );
    assert!(report_roster
        .sanitized_text
        .starts_with("Meeting attendees: "));

    // 5. CSV lines preservation
    let csv_prompt = "id,name,role\n1,Nikolas Alexandrakis,Admin\n2,John Kelly,Engineer";
    let report_csv = harness
        .hybrid
        .sanitize_prompt(csv_prompt, None)
        .await
        .unwrap();
    assert!(!report_csv.sanitized_text.contains("Nikolas Alexandrakis"));
    assert!(!report_csv.sanitized_text.contains("John Kelly"));
    assert!(report_csv.sanitized_text.contains("id,name,role\n"));
    assert!(report_csv.sanitized_text.contains("1,"));
    assert!(report_csv.sanitized_text.contains(",Admin\n"));
    assert!(report_csv.sanitized_text.contains("2,"));
    assert!(report_csv.sanitized_text.contains(",Engineer"));
}

// =============================================================================
// Test 3: Evil Negative Controls (Zero False Positive Tolerance)
// =============================================================================

#[tokio::test]
async fn test_c2_negative_controls_zero_fp() {
    let harness = &*HARNESS;

    let negative_controls = [
        // Conversational imperative verbs & middle-initial traps
        "Give Bob A Call and Send Mary A Message to Plan A Strategy.",
        "Take A Break and Have A Look at Section A Details.",
        "Make A Choice and Run A Test on Model A Outputs.",
        "Schedule A Meeting and Draft A Proposal for Client A Team.",
        // Latin abbreviation guards (e.g. and i.e. must never be treated as initials)
        "For example, e.g. consult the deployment manual immediately.",
        "Refer to the specifications, i.e. section 4 of the guidelines.",
        // Proper nouns and geographic entities
        "The U.S. Government and E.U. Commission met in Hong Kong and New York.",
        "United Nations delegates arrived in San Francisco and Los Angeles.",
        "Federal Reserve officials gathered in Washington and New Delhi.",
        "NATO headquarters confirmed operations in Great Britain and Czech Republic.",
        "Security protocols established across Saudi Arabia and Costa Rica.",
        "Puerto Rico and Sri Lanka joined the international conference.",
        "Security teams deployed in Las Vegas, San Diego, and San Jose.",
        "North Carolina and South Carolina updated the interstate regulations.",
        // Clinical and enterprise role headers
        "Log into the Patient Portal to update Patient Records and Patient Care as Per Request or Billed Per Month.",
        "Customer Portal maintenance scheduled for Customer Service and Client Accounts.",
        "Attn: Patient Intake forms must follow Patient Protocol and Clinic Policy.",
        "Review Per Order status and calculate Per Item shipping costs.",
        // Lowercase non-PII chatter
        "i am ready and i'm looking into why we should contact support or ask billing about the patient portal.",
        "please contact help or ping admin if you need more information about the rollout.",
        "we should ask operations or check with management before deploying the update.",
        "i am happy to assist and we are looking into the issue with the engineering team.",
        // SQL & DevOps keywords
        "SELECT User, Client, Patient FROM Accounts WHERE Status = 'Active' AND Engine = 'Docker' LIMIT 10;",
        "INSERT INTO Orders (Id, Customer, Date, Status) VALUES (1, 2, '2026-10-14', 'Pending');",
        "kubectl get pods -n kube-system -l app=ingress-nginx",
        "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine:latest",
        "git commit -m 'Fix database connection pooling and client retry logic'",
    ];

    for engine in [&harness.heuristic, &harness.hybrid] {
        for control in &negative_controls {
            let report = engine
                .sanitize_prompt(control, None)
                .await
                .expect("sanitize failed");

            assert!(
                report.redactions.is_empty(),
                "False positive detected on negative control '{}'! Redactions: {:?}",
                control,
                report.redactions
            );
            assert_eq!(
                report.sanitized_text, *control,
                "Sanitized text for negative control '{}' must match input exactly byte-for-byte. Got: '{}'",
                control,
                report.sanitized_text
            );
        }
    }
}

// =============================================================================
// Test 4: Reversible Token Rehydration & Roundtrip Byte-Fidelity
// =============================================================================

#[tokio::test]
async fn test_c2_token_rehydration_roundtrip() {
    let harness = &*HARNESS;

    let prompts = [
        "The author J. R. R. Tolkien created Middle-earth.",
        "Fables authored by Jean de La Fontaine in Paris.",
        "Poems by e. e. cummings were revolutionary.",
        r#"{"user": "Hoyt", "role": "admin", "lead": "Nikolas Alexandrakis"}"#,
        "Contact _John Smith_ or **Jane Doe** regarding the architecture.",
        "Meeting attendees: Hoyt, Coste, Miura, and Bitar.",
        "id,name,role\n1,Nikolas Alexandrakis,Admin\n2,John Kelly,Engineer",
    ];

    for prompt in &prompts {
        let report = harness
            .hybrid
            .sanitize_prompt(prompt, None)
            .await
            .expect("sanitize failed");

        assert!(
            !report.redactions.is_empty(),
            "Expected at least one redaction for '{}'",
            prompt
        );

        let restored = harness
            .hybrid
            .restore_prompt(&report.sanitized_text, &report.token_map)
            .expect("restore_prompt failed");

        assert_eq!(
            restored, *prompt,
            "Rehydration failed! Original: '{}', Restored: '{}'",
            prompt, restored
        );
    }
}
