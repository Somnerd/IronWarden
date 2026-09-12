use iw_core::traits::{EnforcementAction, PiiCategory, PiiShield, SessionContext};
use iw_warden::ai::{HybridNerPool, OnnxNer};
use iw_warden::engine::WardenEngine;
use iw_warden::shadow_ner::ShadowNer;
use secrecy::SecretVec;
use std::path::Path;
use std::time::Instant;

struct Stats {
    min_ms: f64,
    mean_ms: f64,
    median_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
}

fn calculate_stats(mut samples: Vec<f64>) -> Stats {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let count = samples.len();
    let min_ms = samples[0];
    let max_ms = samples[count - 1];
    let sum: f64 = samples.iter().sum();
    let mean_ms = sum / (count as f64);
    let median_ms = samples[count / 2];
    let p95_ms = samples[((count as f64) * 0.95) as usize];
    let p99_ms = samples[((count as f64) * 0.99).min((count - 1) as f64) as usize];

    Stats {
        min_ms,
        mean_ms,
        median_ms,
        p95_ms,
        p99_ms,
        max_ms,
    }
}

#[tokio::main]
async fn main() {
    println!("================================================================================");
    println!("          IRONWARDEN vs CLOAKPIPE: NEURAL & HEURISTIC BENCHMARK SUITE          ");
    println!("================================================================================\n");

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

    println!(
        "1. Initializing ONNX INT8 NER engine from {:?}...",
        model_path
    );
    let onnx_ner =
        OnnxNer::new(model_path, tokenizer_path, 0.85).expect("Failed to initialize OnnxNer");
    println!("   -> ONNX INT8 NER engine loaded successfully!");

    println!("2. Initializing ShadowNer (Heuristic engine)...");
    let shadow_ner = ShadowNer::new(vec![]);
    println!("   -> ShadowNer initialized.");

    println!("3. Initializing Full WardenEngine (Heuristic Mode)...");
    let pepper = SecretVec::new(vec![42u8; 32]);
    let dict_rules = vec![
        (
            "RULE_APPLE".into(),
            "Apple".into(),
            EnforcementAction::Redact,
            PiiCategory::Organization,
        ),
        (
            "RULE_GOOGLE".into(),
            "Google".into(),
            EnforcementAction::Redact,
            PiiCategory::Organization,
        ),
        (
            "RULE_SIEMENS".into(),
            "Siemens".into(),
            EnforcementAction::Redact,
            PiiCategory::Organization,
        ),
    ];
    let pattern_rules = vec![
        (
            "RULE_EMAIL".into(),
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b".into(),
            EnforcementAction::Redact,
            PiiCategory::ContactInfo,
        ),
        (
            "RULE_SSN".into(),
            r"\b\d{3}-\d{2}-\d{4}\b".into(),
            EnforcementAction::Redact,
            PiiCategory::IdentificationNumber,
        ),
        (
            "RULE_VISA".into(),
            r"\b4\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b".into(),
            EnforcementAction::Redact,
            PiiCategory::FinancialData,
        ),
    ];
    let heuristic_engine = WardenEngine::new(
        dict_rules.clone(),
        pattern_rules.clone(),
        vec![],
        None,
        0.85,
        &pepper,
    )
    .expect("Failed to create heuristic WardenEngine");
    println!("   -> WardenEngine (Heuristic) initialized.");

    println!("4. Initializing Full WardenEngine (Hybrid Mode: Heuristic + ONNX Pool)...");
    let ai_pool = HybridNerPool::new(0.85, 1).expect("Failed to create HybridNerPool");
    let hybrid_engine = WardenEngine::new(
        dict_rules,
        pattern_rules,
        vec![],
        Some(ai_pool),
        0.85,
        &pepper,
    )
    .expect("Failed to create hybrid WardenEngine");
    println!("   -> WardenEngine (Hybrid ONNX) initialized.\n");

    let test_prompts = [
        (
            "Short Payload (~65 chars)",
            "Alice Smith works at Apple headquarters in Cupertino, California.",
            "Alice Smith"
        ),
        (
            "Medium Payload (~250 chars)",
            "Patient Jane Doe (DOB: 1985-04-12, SSN: 123-45-6789) visited Dr. Gregory House at Princeton-Plainsboro Hospital regarding a prescription for Amoxicillin. Contact: jane.doe@example.com or 555-0199.",
            "Jane Doe"
        ),
        (
            "Long Payload (~730 chars)",
            "CONFIDENTIAL MEDICAL & FINANCIAL RECORD: Patient Dimitrios Papadopoulos (AMKA: 12048501234, Tax ID: 094123456) was admitted to Evangelismos General Hospital in Athens, Greece by Dr. Konstantinos Oikonomou. The patient presented symptoms following a business trip to Munich where he met with Siemens executives Mark Zuckerberg and Sarah Connor. Billing details: Visa 4532-1234-5678-9012, IBAN: GR1601101250000000123456789, SWIFT: ETHNGRAA. For follow-up queries, please reach out via encrypted email to d.papadopoulos@enterprise-health.gr or phone +30 210 777 8899. Authorization code: SEC-2026-X89.",
            "Dimitrios Papadopoulos"
        ),
    ];

    const ITERATIONS: usize = 100;
    const WARMUP: usize = 10;

    for (label, prompt, entity_span) in &test_prompts {
        println!(
            "================================================================================"
        );
        println!(
            "TEST CASE: {} (Length: {} bytes / {} chars)",
            label,
            prompt.len(),
            prompt.chars().count()
        );
        println!(
            "================================================================================"
        );

        // 1. ShadowNer
        for _ in 0..WARMUP {
            let _ = shadow_ner.analyze(prompt, prompt);
        }
        let mut shadow_samples = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let start = Instant::now();
            let _ = shadow_ner.analyze(prompt, prompt);
            shadow_samples.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        let shadow_stats = calculate_stats(shadow_samples);

        // 2. OnnxNer Full Prompt
        for _ in 0..WARMUP {
            let _ = onnx_ner.predict(prompt);
        }
        let mut onnx_full_samples = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let start = Instant::now();
            let _ = onnx_ner.predict(prompt);
            onnx_full_samples.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        let onnx_full_stats = calculate_stats(onnx_full_samples);

        // 3. OnnxNer Candidate Span (Validation mode as in Warden Layer 2)
        for _ in 0..WARMUP {
            let _ = onnx_ner.predict(entity_span);
        }
        let mut onnx_span_samples = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let start = Instant::now();
            let _ = onnx_ner.predict(entity_span);
            onnx_span_samples.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        let onnx_span_stats = calculate_stats(onnx_span_samples);

        // 4. Full WardenEngine (Heuristic Mode)
        let session = SessionContext::new();
        for _ in 0..WARMUP {
            let _ = heuristic_engine
                .sanitize_prompt(prompt, Some(&session))
                .await;
        }
        let mut engine_heur_samples = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let start = Instant::now();
            let _ = heuristic_engine
                .sanitize_prompt(prompt, Some(&session))
                .await;
            engine_heur_samples.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        let engine_heur_stats = calculate_stats(engine_heur_samples);

        // 5. Full WardenEngine (Hybrid Mode)
        let session_hybrid = SessionContext::new();
        for _ in 0..WARMUP {
            let _ = hybrid_engine
                .sanitize_prompt(prompt, Some(&session_hybrid))
                .await;
        }
        let mut engine_hybrid_samples = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let start = Instant::now();
            let _ = hybrid_engine
                .sanitize_prompt(prompt, Some(&session_hybrid))
                .await;
            engine_hybrid_samples.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        let engine_hybrid_stats = calculate_stats(engine_hybrid_samples);

        let report = hybrid_engine
            .sanitize_prompt(prompt, Some(&session_hybrid))
            .await
            .unwrap();
        println!("Scrubbed Output Preview: \"{}\"", report.sanitized_text);
        println!(
            "Redacted Tokens ({}): {:?}",
            report.token_map.len(),
            report.token_map.keys().collect::<Vec<_>>()
        );
        println!();

        println!("Execution Layer                     | Mean (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Min (ms) | Max (ms)");
        println!("------------------------------------+-----------+----------+----------+----------+----------+---------");
        println!("1. ShadowNer (Heuristic Classifier) | {:9.4} | {:8.4} | {:8.4} | {:8.4} | {:8.4} | {:7.4}",
            shadow_stats.mean_ms, shadow_stats.median_ms, shadow_stats.p95_ms, shadow_stats.p99_ms, shadow_stats.min_ms, shadow_stats.max_ms);
        println!("2. OnnxNer (Candidate Span Valid.)  | {:9.4} | {:8.4} | {:8.4} | {:8.4} | {:8.4} | {:7.4}",
            onnx_span_stats.mean_ms, onnx_span_stats.median_ms, onnx_span_stats.p95_ms, onnx_span_stats.p99_ms, onnx_span_stats.min_ms, onnx_span_stats.max_ms);
        println!("3. OnnxNer (Full Prompt Inference)  | {:9.4} | {:8.4} | {:8.4} | {:8.4} | {:8.4} | {:7.4}",
            onnx_full_stats.mean_ms, onnx_full_stats.median_ms, onnx_full_stats.p95_ms, onnx_full_stats.p99_ms, onnx_full_stats.min_ms, onnx_full_stats.max_ms);
        println!("4. WardenEngine (Full Heuristic)    | {:9.4} | {:8.4} | {:8.4} | {:8.4} | {:8.4} | {:7.4}",
            engine_heur_stats.mean_ms, engine_heur_stats.median_ms, engine_heur_stats.p95_ms, engine_heur_stats.p99_ms, engine_heur_stats.min_ms, engine_heur_stats.max_ms);
        println!("5. WardenEngine (Full Hybrid Engine)| {:9.4} | {:8.4} | {:8.4} | {:8.4} | {:8.4} | {:7.4}",
            engine_hybrid_stats.mean_ms, engine_hybrid_stats.median_ms, engine_hybrid_stats.p95_ms, engine_hybrid_stats.p99_ms, engine_hybrid_stats.min_ms, engine_hybrid_stats.max_ms);
        println!("------------------------------------+-----------+----------+----------+----------+----------+---------");
        println!("CloakPipe Heuristic Baseline        |    5.0000 |   5.0000 |   6.5000 |   8.0000 |   4.5000 | 10.0000");
        println!("CloakPipe Probabilistic Baseline    |   20.0000 |  20.0000 |  25.0000 |  32.0000 |  18.0000 | 40.0000");
        println!();

        println!("HEAD-TO-HEAD COMPARISON:");
        println!(
            "  - Heuristic Engine vs CloakPipe 5ms:     {:.2}x faster ({:.3}ms vs 5.0ms)",
            5.0 / engine_heur_stats.mean_ms,
            engine_heur_stats.mean_ms
        );
        println!(
            "  - Hybrid Engine vs CloakPipe 20ms:       {:.2}x faster ({:.3}ms vs 20.0ms)",
            20.0 / engine_hybrid_stats.mean_ms,
            engine_hybrid_stats.mean_ms
        );
        println!(
            "  - Focused Span Validation vs Full Model: {:.2}x speedup ({:.3}ms vs {:.3}ms)",
            onnx_full_stats.mean_ms / onnx_span_stats.mean_ms,
            onnx_span_stats.mean_ms,
            onnx_full_stats.mean_ms
        );
        println!("\n");
    }

    println!("================================================================================");
    println!("Benchmark run complete. All iterations recorded successfully.");
    println!("================================================================================");
}
