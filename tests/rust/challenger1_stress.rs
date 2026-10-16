//! Adversarial Stress Test Suite - Challenger 1
//! Empirical testing of R1 (Greek inflections, Greeklish, Tonos/Dialytika, Category)
//! and R2 (Verb eating elimination, Protected surnames, Exact span boundaries).

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

fn init_test_engines() -> TestEngines {
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

    let heur_config = WardenConfig {
        rules: config.rules.clone(),
        heuristics: config.heuristics.clone(),
        ai_enabled: false,
        ai_confidence_threshold: 0.85,
    };
    let heuristic = heur_config
        .compile_engine(&pepper)
        .expect("Failed to compile Heuristic engine");

    std::env::set_var("WARDEN_ENABLE_ONNX_TEST", "1");
    let hyb_config = WardenConfig {
        rules: config.rules.clone(),
        heuristics: config.heuristics.clone(),
        ai_enabled: true,
        ai_confidence_threshold: 0.85,
    };
    let hybrid = hyb_config.compile_engine(&pepper).ok();

    TestEngines { heuristic, hybrid }
}

static ENGINES: std::sync::LazyLock<TestEngines> = std::sync::LazyLock::new(init_test_engines);

#[tokio::test]
async fn test_adversarial_greek_inflections_all_cases() {
    let engines = &*ENGINES;
    let test_targets: Vec<(&str, &WardenEngine)> = if let Some(ref hyb) = engines.hybrid {
        vec![("hybrid", hyb), ("heuristic", &engines.heuristic)]
    } else {
        vec![("heuristic", &engines.heuristic)]
    };

    // Test vectors for R1 Greek Inflections
    // Nominative (-ος/-ης/-ας), Genitive (-ου/-η/-α), Accusative (-ο/-η/-α)
    // Tonos and dialytika combinations
    let cases = vec![
        // Nominative -ος
        (
            "Ο Νικόλαος είναι στο γραφείο.",
            vec!["Νικόλαος"],
            "Ο ",
            " είναι στο γραφείο.",
        ),
        (
            "Ο Παπαδόπουλος είναι ο διευθυντής.",
            vec!["Παπαδόπουλος"],
            "Ο ",
            " είναι ο διευθυντής.",
        ),
        (
            "Ο Αλεξανδράκος έφτασε.",
            vec!["Αλεξανδράκος"],
            "Ο ",
            " έφτασε.",
        ),
        // Genitive -ου
        (
            "Το γραφείο του Νικολάου.",
            vec!["Νικολάου"],
            "Το γραφείο του ",
            ".",
        ),
        (
            "Η αναφορά του Παπαδοπούλου.",
            vec!["Παπαδοπούλου"],
            "Η αναφορά του ",
            ".",
        ),
        (
            "Το αίτημα του Αλεξανδράκου.",
            vec!["Αλεξανδράκου"],
            "Το αίτημα του ",
            ".",
        ),
        // Accusative -ο
        (
            "Είδα τον Νικόλαο χθες.",
            vec!["Νικόλαο"],
            "Είδα τον ",
            " χθες.",
        ),
        (
            "Κάλεσε τον Παπαδόπουλο τώρα.",
            vec!["Παπαδόπουλο"],
            "Κάλεσε τον ",
            " τώρα.",
        ),
        (
            "Ρώτησε τον Αλεξανδράκο.",
            vec!["Αλεξανδράκο"],
            "Ρώτησε τον ",
            ".",
        ),
        // Tonos and dialytika combinations for -ιδης / -ιδη
        (
            "Ο Κώστας Νικολαΐδης ήρθε.",
            vec!["Κώστας Νικολαΐδης"],
            "Ο ",
            " ήρθε.",
        ),
        (
            "Ο Κώστας Νικολαϊδης ήρθε.",
            vec!["Κώστας Νικολαϊδης"],
            "Ο ",
            " ήρθε.",
        ),
        (
            "Ο Κωστας Νικολαιδης ηρθε.",
            vec!["Κωστας Νικολαιδης"],
            "Ο ",
            " ηρθε.",
        ),
        (
            "Κάλεσε τον Κώστα Νικολαΐδη.",
            vec!["Κώστα Νικολαΐδη"],
            "Κάλεσε τον ",
            ".",
        ),
        (
            "Κάλεσε τον Κώστα Νικολαϊδη.",
            vec!["Κώστα Νικολαϊδη"],
            "Κάλεσε τον ",
            ".",
        ),
        (
            "Καλεσε τον Κωστα Νικολαιδη.",
            vec!["Κωστα Νικολαιδη"],
            "Καλεσε τον ",
            ".",
        ),
        // Lowercase Greek variants
        (
            "ρωτα τον νικολαο για το συστημα",
            vec!["νικολαο"],
            "ρωτα τον ",
            " για το συστημα",
        ),
        (
            "ρωτα τον νικολαου για το συστημα",
            vec!["νικολαου"],
            "ρωτα τον ",
            " για το συστημα",
        ),
        (
            "ρωτα τον νικολαος για το συστημα",
            vec!["νικολαος"],
            "ρωτα τον ",
            " για το συστημα",
        ),
        (
            "μιλησε με τον παπαδοπουλο",
            vec!["παπαδοπουλο"],
            "μιλησε με τον ",
            "",
        ),
        (
            "μιλησε με τον παπαδοπουλου",
            vec!["παπαδοπουλου"],
            "μιλησε με τον ",
            "",
        ),
        (
            "μιλησε με τον παπαδοπουλος",
            vec!["παπαδοπουλος"],
            "μιλησε με τον ",
            "",
        ),
    ];

    for (mode, engine) in test_targets {
        println!("=== Testing Greek Inflections in [{}] mode ===", mode);
        for (prompt, targets, prefix, suffix) in &cases {
            let report = engine
                .sanitize_prompt(prompt, None)
                .await
                .expect("sanitize failed");
            println!("Prompt: '{}' -> '{}'", prompt, report.sanitized_text);
            for t in targets {
                let leaked = report.sanitized_text.contains(t);
                if leaked {
                    println!(
                        "FAIL [{}]: Target '{}' leaked in prompt '{}'! Output: '{}'",
                        mode, t, prompt, report.sanitized_text
                    );
                }
            }
            if !report.sanitized_text.contains(prefix) {
                println!(
                    "PREFIX DAMAGED [{}]: Expected '{}' in '{}'",
                    mode, prefix, report.sanitized_text
                );
            }
            if !report.sanitized_text.contains(suffix) {
                println!(
                    "SUFFIX DAMAGED [{}]: Expected '{}' in '{}'",
                    mode, suffix, report.sanitized_text
                );
            }
        }
    }
}

#[tokio::test]
async fn test_adversarial_greeklish_transliteration() {
    let engines = &*ENGINES;
    let test_targets: Vec<(&str, &WardenEngine)> = if let Some(ref hyb) = engines.hybrid {
        vec![("hybrid", hyb), ("heuristic", &engines.heuristic)]
    } else {
        vec![("heuristic", &engines.heuristic)]
    };

    // Greeklish ou vs oy resilience
    let cases = vec![
        ("rota ton nikola papadopoulos", vec!["papadopoulos"]),
        ("rota ton nikola papadopoylos", vec!["papadopoylos"]),
        ("rota ton nikola papadopoulou", vec!["papadopoulou"]),
        ("rota ton nikola papadopoylou", vec!["papadopoylou"]),
        ("rota ton nikola papadopoulo", vec!["papadopoulo"]),
        ("rota ton nikola papadopoylo", vec!["papadopoylo"]),
        ("per papadopoulos delay deployment", vec!["papadopoulos"]),
        ("per papadopoylos delay deployment", vec!["papadopoylos"]),
        ("steile email ston kosta nikolaidis", vec!["nikolaidis"]),
        ("steile email ston kosta nikolaydis", vec!["nikolaydis"]),
        ("steile email ston kosta nikolaidi", vec!["nikolaidi"]),
        ("steile email ston kosta nikolaydi", vec!["nikolaydi"]),
        ("contact giannis nikolaou today", vec!["nikolaou"]),
        ("contact giannis nikolaoy today", vec!["nikolaoy"]),
    ];

    for (mode, engine) in test_targets {
        println!("=== Testing Greeklish 'ou' vs 'oy' in [{}] mode ===", mode);
        for (prompt, targets) in &cases {
            let report = engine
                .sanitize_prompt(prompt, None)
                .await
                .expect("sanitize failed");
            println!(
                "Greeklish prompt: '{}' -> '{}'",
                prompt, report.sanitized_text
            );
            for t in targets {
                if report
                    .sanitized_text
                    .to_lowercase()
                    .contains(&t.to_lowercase())
                {
                    println!(
                        "FAIL [{}]: Greeklish target '{}' leaked in prompt '{}'! Output: '{}'",
                        mode, t, prompt, report.sanitized_text
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn test_adversarial_verb_eating_and_span_boundaries() {
    let engines = &*ENGINES;
    let test_targets: Vec<(&str, &WardenEngine)> = if let Some(ref hyb) = engines.hybrid {
        vec![("hybrid", hyb), ("heuristic", &engines.heuristic)]
    } else {
        vec![("heuristic", &engines.heuristic)]
    };

    let cases = vec![
        // Past tense verbs
        (
            "patient hoyt complained yesterday",
            "hoyt",
            "patient ",
            " complained yesterday",
        ),
        (
            "patient hoyt reported symptoms",
            "hoyt",
            "patient ",
            " reported symptoms",
        ),
        (
            "patient hoyt approved the bill",
            "hoyt",
            "patient ",
            " approved the bill",
        ),
        (
            "patient hoyt rejected the medicine",
            "hoyt",
            "patient ",
            " rejected the medicine",
        ),
        (
            "patient hoyt delayed the visit",
            "hoyt",
            "patient ",
            " delayed the visit",
        ),
        (
            "patient hoyt died yesterday",
            "hoyt",
            "patient ",
            " died yesterday",
        ),
        (
            "patient hoyt walked into the clinic",
            "hoyt",
            "patient ",
            " walked into the clinic",
        ),
        (
            "patient hoyt requested a transfer",
            "hoyt",
            "patient ",
            " requested a transfer",
        ),
        // Adverbs
        (
            "patient hoyt urgently needs a bed",
            "hoyt",
            "patient ",
            " urgently needs a bed",
        ),
        (
            "patient hoyt immediately left",
            "hoyt",
            "patient ",
            " immediately left",
        ),
        // Present participles (-ing verbs)
        (
            "patient hoyt complaining about pain",
            "hoyt",
            "patient ",
            " complaining about pain",
        ),
        (
            "patient hoyt bleeding heavily",
            "hoyt",
            "patient ",
            " bleeding heavily",
        ),
        (
            "patient hoyt recovering well",
            "hoyt",
            "patient ",
            " recovering well",
        ),
        (
            "patient hoyt coughing constantly",
            "hoyt",
            "patient ",
            " coughing constantly",
        ),
        (
            "patient hoyt waiting outside",
            "hoyt",
            "patient ",
            " waiting outside",
        ),
        // Protected surnames
        (
            "alan turing walked to the room",
            "alan turing",
            "",
            " walked to the room",
        ),
        (
            "john kelly complained to the nurse",
            "john kelly",
            "",
            " complained to the nurse",
        ),
        (
            "tariq ahmed reported the anomaly",
            "tariq ahmed",
            "",
            " reported the anomaly",
        ),
        (
            "lou reed approved the track",
            "lou reed",
            "",
            " approved the track",
        ),
        (
            "patient reed complained yesterday",
            "reed",
            "patient ",
            " complained yesterday",
        ),
        (
            "patient kelly complained yesterday",
            "kelly",
            "patient ",
            " complained yesterday",
        ),
        (
            "patient ahmed complained yesterday",
            "ahmed",
            "patient ",
            " complained yesterday",
        ),
        (
            "patient turing complained yesterday",
            "turing",
            "patient ",
            " complained yesterday",
        ),
        // Other surnames ending in -ly / -ed
        (
            "patient connelly complained yesterday",
            "connelly",
            "patient ",
            " complained yesterday",
        ),
        (
            "patient bradley complained yesterday",
            "bradley",
            "patient ",
            " complained yesterday",
        ),
        (
            "patient presley complained yesterday",
            "presley",
            "patient ",
            " complained yesterday",
        ),
        // Conversational triggers with verbs
        (
            "per coste delay the deployment immediately",
            "coste",
            "per ",
            " delay the deployment immediately",
        ),
        (
            "per coste failed the test build",
            "coste",
            "per ",
            " failed the test build",
        ),
        (
            "per coste shipped the binary yesterday",
            "coste",
            "per ",
            " shipped the binary yesterday",
        ),
        (
            "please ask miura urgently about the crash",
            "miura",
            "please ask ",
            " urgently about the crash",
        ),
        (
            "please ask miura reviewed the code",
            "miura",
            "please ask ",
            " reviewed the code",
        ),
        (
            "my name is john smith and i approved it",
            "john smith",
            "my name is ",
            " and i approved it",
        ),
    ];

    for (mode, engine) in test_targets {
        println!(
            "=== Testing Verb Eating & Span Integrity in [{}] mode ===",
            mode
        );
        for (prompt, target, prefix, suffix) in &cases {
            let report = engine
                .sanitize_prompt(prompt, None)
                .await
                .expect("sanitize failed");
            let target_leaked = report
                .sanitized_text
                .to_lowercase()
                .contains(&target.to_lowercase());
            let prefix_preserved = report.sanitized_text.starts_with(prefix);
            let suffix_preserved = report.sanitized_text.ends_with(suffix);

            if target_leaked {
                println!(
                    "FAIL TARGET LEAK [{}]: '{}' leaked in prompt '{}'! Output: '{}'",
                    mode, target, prompt, report.sanitized_text
                );
            }
            if !prefix_preserved {
                println!(
                    "FAIL VERB/PREFIX EATEN [{}]: Expected start '{}', got '{}'",
                    mode, prefix, report.sanitized_text
                );
            }
            if !suffix_preserved {
                println!(
                    "FAIL VERB/SUFFIX EATEN [{}]: Expected end '{}', got '{}'",
                    mode, suffix, report.sanitized_text
                );
            }
        }
    }
}

#[tokio::test]
async fn test_debug_details() {
    let engines = &*ENGINES;
    let engine = engines.hybrid.as_ref().unwrap_or(&engines.heuristic);

    let prompts = vec![
        "Ρώτησε τον Αλεξανδράκο.",
        "steile email ston kosta nikolaydis",
        "patient hoyt complaining about pain",
    ];

    for p in prompts {
        let report = engine.sanitize_prompt(p, None).await.unwrap();
        println!("Prompt: '{}'", p);
        println!("Sanitized: '{}'", report.sanitized_text);
        for r in &report.redactions {
            println!(
                "  Redaction: rule_id='{}', offset={}, len={}, placeholder='{}', category={:?}",
                r.rule_id, r.offset, r.length, r.placeholder, r.category
            );
            println!(
                "  Matched slice in original: '{:?}'",
                &p[r.offset..r.offset + r.length]
            );
        }
    }
}
