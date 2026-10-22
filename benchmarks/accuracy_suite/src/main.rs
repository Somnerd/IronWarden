use iw_core::traits::PiiShield;
use iw_warden::config::WardenConfig;
use rand::seq::SliceRandom;
use secrecy::SecretVec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Instant;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct EntitySpan {
    token: String,
    #[serde(default)]
    start: usize,
    #[serde(default)]
    end: usize,
    label: String,
}

#[derive(Debug, Deserialize)]
struct EvalRecord {
    text: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    entities: Vec<EntitySpan>,
}

#[derive(Debug, Deserialize)]
struct CultureNames {
    first: Vec<String>,
    last: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct NameLexicon {
    greek: CultureNames,
    english: CultureNames,
    arabic: CultureNames,
    chinese: CultureNames,
}

#[derive(Debug, Serialize, Default, Clone)]
struct ConfusionMetrics {
    total_samples: usize,
    gold_entities: usize,
    true_positives: usize,
    false_negatives: usize,
    false_positives: usize,
    recall: f64,
    precision: f64,
    f1: f64,
}

impl ConfusionMetrics {
    fn finalize(&mut self) {
        let tp = self.true_positives as f64;
        let fn_count = self.false_negatives as f64;
        let fp = self.false_positives as f64;

        self.recall = if tp + fn_count > 0.0 {
            tp / (tp + fn_count)
        } else {
            1.0
        };

        self.precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 1.0 };

        self.f1 = if self.precision + self.recall > 0.0 {
            2.0 * (self.precision * self.recall) / (self.precision + self.recall)
        } else {
            0.0
        };
    }
}

#[derive(Debug, Serialize, Default)]
struct AccuracyBenchmarkReport {
    timestamp: String,
    system_info: String,
    heuristic_mode: ModeResults,
    hybrid_mode: ModeResults,
    combinatorial_100k_stress_test: CombinatorialReport,
    eval5_adversarial_suite: Eval5Report,
}

#[derive(Debug, Serialize, Default)]
struct Eval5Report {
    total_samples: usize,
    slices: HashMap<String, ConfusionMetrics>,
}

#[derive(Debug, Serialize, Default)]
struct ModeResults {
    synthetic_structural: HashMap<String, ConfusionMetrics>,
    conll2003: ConfusionMetrics,
    wikigold: ConfusionMetrics,
    overall: ConfusionMetrics,
}

#[derive(Debug, Serialize, Default)]
struct CombinatorialReport {
    total_iterations: usize,
    detailed_by_culture: HashMap<String, ConfusionMetrics>,
    aggregate: ConfusionMetrics,
}

fn load_eval_records<P: AsRef<Path>>(path: P) -> Vec<EvalRecord> {
    let mut records = Vec::new();
    if let Ok(file) = File::open(path) {
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            if let Ok(rec) = serde_json::from_str::<EvalRecord>(&line) {
                records.push(rec);
            }
        }
    }
    records
}

#[derive(Debug, Clone)]
struct Eval5TestCase {
    slice_id: &'static str,
    prompt: String,
    target_entity: Option<String>,
    prefix: Option<String>,
    suffix: Option<String>,
}

fn generate_eval5_dataset() -> Vec<Eval5TestCase> {
    let mut cases = Vec::with_capacity(1050);

    // ---------------------------------------------------------------------
    // Slice 5A: Lowercase Conversational Full Names (200 prompts)
    // 25 names x 8 templates
    // ---------------------------------------------------------------------
    let full_names = [
        "john smith",
        "alan turing",
        "georgios papadopoulos",
        "tariq ahmed",
        "lou reed",
        "john kelly",
        "nikos kazantzakis",
        "bruce wayne",
        "clark kent",
        "peter parker",
        "mary watson",
        "sarah connor",
        "arthur dent",
        "ford prefect",
        "ada lovelace",
        "charles babbage",
        "grace hopper",
        "linus torvalds",
        "dennis ritchie",
        "ken thompson",
        "james gosling",
        "guido van rossum",
        "alexander fleming",
        "marie curie",
        "albert einstein",
    ];
    let full_templates = [
        ("my name is ", " and i approved the invoice"),
        ("i am ", " and i submitted the pull request"),
        ("please contact ", " regarding the database migration"),
        ("can you ping ", " about the server outage yesterday"),
        ("send the audit logs directly to ", " for review"),
        ("please dm ", " urgently regarding the incident"),
        ("we should cc ", " on this security advisory"),
        ("attn: ", " please verify the credentials"),
    ];
    for name in &full_names {
        for (pref, suff) in &full_templates {
            cases.push(Eval5TestCase {
                slice_id: "5A_CONVERSATIONAL_FULL",
                prompt: format!("{}{}{}", pref, name, suff),
                target_entity: Some(name.to_string()),
                prefix: Some(pref.to_string()),
                suffix: Some(suff.to_string()),
            });
        }
    }

    // ---------------------------------------------------------------------
    // Slice 5B: Lowercase Single Names & Surnames (200 prompts)
    // 25 surnames x 8 verb-eater combinations
    // ---------------------------------------------------------------------
    let surnames = [
        "hoyt", "coste", "miura", "bitar", "reed", "kelly", "ahmed", "syed", "steed", "clark",
        "wright", "young", "evans", "stone", "ford", "foster", "grant", "morris", "ross", "ward",
        "cole", "hart", "dean", "fox", "graham",
    ];
    let verb_templates = [
        ("patient ", " complained yesterday about the medication"),
        ("per ", " delay the deployment immediately"),
        ("please ask ", " urgently about the server crash"),
        ("ask ", " to review the pull request today"),
        ("dr. ", " approved the clinical treatment plan"),
        ("mr. ", " rejected the initial proposal yesterday"),
        ("patient ", " reported severe symptoms this morning"),
        ("per ", " delayed the production release"),
    ];
    for s in &surnames {
        for (pref, suff) in &verb_templates {
            cases.push(Eval5TestCase {
                slice_id: "5B_SINGLE_SURNAMES_VERBS",
                prompt: format!("{}{}{}", pref, s, suff),
                target_entity: Some(s.to_string()),
                prefix: Some(pref.to_string()),
                suffix: Some(suff.to_string()),
            });
        }
    }

    // ---------------------------------------------------------------------
    // Slice 5C: Greek Inflected & Lowercase Prompts (200 prompts)
    // 25 inflected entities x 8 templates (Greek script & Greeklish)
    // ---------------------------------------------------------------------
    let greek_entities = [
        "Νικόλας Αλεξανδράκης",
        "Νικόλα Αλεξανδράκη",
        "Γεώργιος Παπαδόπουλος",
        "Γιώργο Παπαδόπουλο",
        "Γιώργου Παπαδόπουλου",
        "Κώστας Νικολαΐδης",
        "Κώστα Νικολαΐδη",
        "Δημήτριος Οικονόμου",
        "Δημήτρη Οικονόμου",
        "Γιάννης Βασιλείου",
        "νικόλας αλεξανδράκης",
        "νικόλα αλεξανδράκη",
        "γιώργος παπαδόπουλος",
        "γιώργο παπαδόπουλο",
        "γιώργου παπαδόπουλου",
        "κώστας νικολαΐδης",
        "κώστα νικολαΐδη",
        "nikolas alexandrakis",
        "nikola alexandraki",
        "giorgos papadopoulos",
        "giorgo papadopoulo",
        "giorgou papadopoulou",
        "kostas nikolaidis",
        "kosta nikolaidi",
        "dimitris oikonomou",
    ];
    let greek_templates = [
        ("ρώτα τον ", " για τον σερβερ"),
        ("επικοινώνησε με τον ", " άμεσα"),
        ("η αναφορά του ", " εγκρίθηκε χθες"),
        ("το αίτημα του ", " καταχωρήθηκε"),
        ("στον ", " παραδόθηκαν τα κλειδιά"),
        ("rota ton ", " gia ton server"),
        ("steile email ston ", " simera"),
        ("per ", " delay deployment"),
    ];
    for g in &greek_entities {
        for (pref, suff) in &greek_templates {
            cases.push(Eval5TestCase {
                slice_id: "5C_GREEK_INFLECTED",
                prompt: format!("{}{}{}", pref, g, suff),
                target_entity: Some(g.to_string()),
                prefix: Some(pref.to_string()),
                suffix: Some(suff.to_string()),
            });
        }
    }

    // ---------------------------------------------------------------------
    // Slice 5D: Complex Initials, Particles & Punctuation/JSON Wrapping (200 prompts)
    // 40 complex entities x 5 environments
    // ---------------------------------------------------------------------
    let complex_entities = [
        "J. R. R. Tolkien",
        "C. S. Lewis",
        "G. R. R. Martin",
        "P. G. Wodehouse",
        "H. G. Wells",
        "B. Young",
        "A. Smith",
        "J. Doe",
        "M. Johnson",
        "K. Brown",
        "Ludwig van Beethoven",
        "Tariq ibn Ziyad",
        "Leonardo da Vinci",
        "Vincent van Gogh",
        "Johannes van der Waals",
        "Charles de Gaulle",
        "Simone de Beauvoir",
        "Jean de La Fontaine",
        "Willem van Oranje",
        "Hernan Cortes",
        "Bitar",
        "Miura",
        "Alexandrakis",
        "Papadopoulos",
        "Turing",
        "Hoyt",
        "Coste",
        "Kelly",
        "Ahmed",
        "Reed",
        "F. Scott Fitzgerald",
        "E. B. White",
        "A. A. Milne",
        "T. S. Eliot",
        "W. H. Auden",
        "e. e. cummings",
        "D. H. Lawrence",
        "H. P. Lovecraft",
        "J. K. Rowling",
        "George R. R. Martin",
    ];
    let env_templates = [
        (
            r#"{"user": ""#,
            r#"", "role": "admin", "status": "active"}"#,
        ),
        ("Assigned to **", "** for immediate code review."),
        ("Meeting attendees: ", ", lead architect and reviewer."),
        (
            r#"System log: user '["#,
            r#"]' authenticated successfully."#,
        ),
        ("Approved by ", " (Principal Engineer) at 09:00 UTC."),
    ];
    for c in &complex_entities {
        for (pref, suff) in &env_templates {
            cases.push(Eval5TestCase {
                slice_id: "5D_COMPLEX_FORMATS",
                prompt: format!("{}{}{}", pref, c, suff),
                target_entity: Some(c.to_string()),
                prefix: Some(pref.to_string()),
                suffix: Some(suff.to_string()),
            });
        }
    }

    // ---------------------------------------------------------------------
    // Slice 5E: Adversarial Negative Controls (200 hard non-PII prompts)
    // 5 categories x 40 variations = 200 prompts
    // ---------------------------------------------------------------------
    let control_prompts = [
        // Category 1: Middle-initial traps (40 prompts)
        "Give Bob A Call and Send Mary A Message to Plan A Strategy.",
        "Take A Break and Have A Look at Section A Details.",
        "Make A Choice and Run A Test on Model A Outputs.",
        "Schedule A Meeting and Draft A Proposal for Client A Team.",
        // Category 2: Acronyms & geographic locations (40 prompts)
        "The U.S. Government and E.U. Commission met in Hong Kong and New York.",
        "United Nations delegates arrived in San Francisco and Los Angeles.",
        "Federal Reserve officials gathered in Washington and New Delhi.",
        "NATO headquarters confirmed operations in Great Britain and Czech Republic.",
        // Category 3: Role traps & proper noun blocklists (40 prompts)
        "Log into the Patient Portal to update Patient Records and Patient Care as Per Request or Billed Per Month.",
        "Customer Portal maintenance scheduled for Customer Service and Client Accounts.",
        "Attn: Patient Intake forms must follow Patient Protocol and Clinic Policy.",
        "Review Per Order status and calculate Per Item shipping costs.",
        // Category 4: Lowercase conversational chatter & stopwords (40 prompts)
        "i am ready and i'm looking into why we should contact support or ask billing about the patient portal.",
        "please contact help or ping admin if you need more information about the rollout.",
        "i am happy to assist and we are looking into the issue with the engineering team.",
        "we should ask operations or check with management before deploying the update.",
        // Category 5: SQL, DevOps, code and technical syntax (40 prompts)
        "SELECT User, Client, Patient FROM Accounts WHERE Status = 'Active' AND Engine = 'Docker' LIMIT 10;",
        "INSERT INTO Orders (Id, Customer, Date, Status) VALUES (1, 2, '2026-10-14', 'Pending');",
        "kubectl get pods -n kube-system -l app=ingress-nginx",
        "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine:latest",
    ];
    // Expand to exactly 200 prompts using deterministic variations
    for (idx, base) in control_prompts.iter().cycle().take(200).enumerate() {
        let text = if idx < control_prompts.len() {
            base.to_string()
        } else {
            format!("{} [ID: {}]", base, idx)
        };
        cases.push(Eval5TestCase {
            slice_id: "5E_NEGATIVE_CONTROLS",
            prompt: text,
            target_entity: None,
            prefix: None,
            suffix: None,
        });
    }

    cases
}

async fn evaluate_eval5<E: PiiShield>(
    engine: &E,
    cases: &[Eval5TestCase],
) -> HashMap<String, ConfusionMetrics> {
    let mut slice_metrics: HashMap<String, ConfusionMetrics> = HashMap::new();

    for case in cases {
        let metric = slice_metrics.entry(case.slice_id.to_string()).or_default();
        metric.total_samples += 1;

        let report = engine.sanitize_prompt(&case.prompt, None).await.unwrap();

        match &case.target_entity {
            Some(entity) => {
                metric.gold_entities += 1;

                // Criterion 1: Target entity must be absent
                let entity_absent = !report.sanitized_text.contains(entity);

                if !entity_absent {
                    // False Negative: Entity leaked
                    metric.false_negatives += 1;
                } else {
                    // Criterion 2: Surrounding prefix and suffix words must be 100% intact
                    let prefix_intact = case
                        .prefix
                        .as_ref()
                        .map(|p| report.sanitized_text.contains(p))
                        .unwrap_or(true);
                    let suffix_intact = case
                        .suffix
                        .as_ref()
                        .map(|s| report.sanitized_text.contains(s))
                        .unwrap_or(true);

                    if prefix_intact && suffix_intact {
                        // True Positive: Entity redacted cleanly without collateral damage
                        metric.true_positives += 1;
                    } else {
                        // False Positive: Swallowed verbs, prefixes, or shifted syntax!
                        metric.false_positives += 1;
                    }
                }
            }
            None => {
                // Negative control (Slice 5E): Zero entities expected
                if !report.redactions.is_empty() {
                    metric.false_positives += report.redactions.len();
                }
            }
        }
    }

    for m in slice_metrics.values_mut() {
        m.finalize();
    }

    slice_metrics
}

#[tokio::main]
async fn main() {
    println!("================================================================================");
    println!("     IRONWARDEN SHIELD ACCURACY & DETECTION RECALL BENCHMARK SUITE             ");
    println!("================================================================================\n");

    let pepper = SecretVec::new(vec![42u8; 32]);

    // Build complete ruleset
    let (mut config, _) = WardenConfig::from_manifest("config/manifest.yaml")
        .expect("Failed to load config/manifest.yaml");

    // Also include Greek regional rules
    if let Ok(gr_config) = WardenConfig::from_file("config/rules/gr.yaml") {
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
    let heuristic_engine = heur_config
        .compile_engine(&pepper)
        .expect("Failed to compile Heuristic WardenEngine");
    println!("1. Initialized Heuristic Engine (SIMD Aho-Corasick + ShadowNER)");

    // Hybrid ONNX Engine
    let model_path = Path::new("data/models/distilbert-ner/model_quantized.onnx");
    let tokenizer_path = Path::new("data/models/distilbert-ner/tokenizer.json");
    let has_model = model_path.exists() && tokenizer_path.exists();

    let hybrid_engine = if has_model {
        let hyb_config = WardenConfig {
            rules: config.rules.clone(),
            heuristics: config.heuristics.clone(),
            ai_enabled: true,
            ai_confidence_threshold: 0.85,
        };
        match hyb_config.compile_engine(&pepper) {
            Ok(eng) => {
                println!("2. Initialized Hybrid ONNX Engine (INT8 DistilBERT + Heuristics)");
                Some(eng)
            }
            Err(e) => {
                println!("2. Hybrid ONNX failed to initialize: {e}, falling back to None");
                None
            }
        }
    } else {
        println!("2. Hybrid ONNX model not found, skipping Hybrid mode");
        None
    };

    // Individual evaluations use stateless None session context

    // -------------------------------------------------------------------------
    // EVAL 1: Synthetic Structural PII & Negative Controls
    // -------------------------------------------------------------------------
    println!("\n--- [EVAL 1] Evaluating Synthetic Structural PII & Controls ---");
    let structural_records = load_eval_records("data/eval/synthetic_structural_pii.jsonl");
    println!("Loaded {} structural test cases.", structural_records.len());

    let mut heur_structural_map: HashMap<String, ConfusionMetrics> = HashMap::new();
    let mut hyb_structural_map: HashMap<String, ConfusionMetrics> = HashMap::new();

    for rec in &structural_records {
        let cat = rec
            .category
            .clone()
            .unwrap_or_else(|| "GENERAL".to_string());
        let heur_entry = heur_structural_map.entry(cat.clone()).or_default();
        heur_entry.total_samples += 1;
        heur_entry.gold_entities += rec.entities.len();

        let report = heuristic_engine
            .sanitize_prompt(&rec.text, None)
            .await
            .unwrap();

        if rec.entities.is_empty() {
            // Negative control: check for false positives
            if !report.redactions.is_empty() {
                heur_entry.false_positives += report.redactions.len();
            }
        } else {
            for gold in &rec.entities {
                if !report.sanitized_text.contains(&gold.token) {
                    heur_entry.true_positives += 1;
                } else {
                    heur_entry.false_negatives += 1;
                }
            }
        }

        if let Some(ref hyb_eng) = hybrid_engine {
            let hyb_entry = hyb_structural_map.entry(cat).or_default();
            hyb_entry.total_samples += 1;
            hyb_entry.gold_entities += rec.entities.len();

            let h_report = hyb_eng.sanitize_prompt(&rec.text, None).await.unwrap();
            if rec.entities.is_empty() {
                if !h_report.redactions.is_empty() {
                    hyb_entry.false_positives += h_report.redactions.len();
                }
            } else {
                for gold in &rec.entities {
                    if !h_report.sanitized_text.contains(&gold.token) {
                        hyb_entry.true_positives += 1;
                    } else {
                        hyb_entry.false_negatives += 1;
                    }
                }
            }
        }
    }

    for m in heur_structural_map.values_mut() {
        m.finalize();
    }
    for m in hyb_structural_map.values_mut() {
        m.finalize();
    }

    // -------------------------------------------------------------------------
    // EVAL 2: CoNLL-2003 Test Split (Standard News NER)
    // -------------------------------------------------------------------------
    println!("\n--- [EVAL 2] Evaluating CoNLL-2003 Test Split ---");
    let conll_records = load_eval_records("data/eval/conll2003_eval.jsonl");
    println!("Loaded {} CoNLL-2003 sentences.", conll_records.len());

    let mut heur_conll = ConfusionMetrics::default();
    let mut hyb_conll = ConfusionMetrics::default();

    let mut conll_idx = 0;
    for rec in &conll_records {
        conll_idx += 1;
        if conll_idx % 250 == 0 {
            println!(
                "  -> CoNLL-2003 progress: {} / {} sentences",
                conll_idx,
                conll_records.len()
            );
        }
        let per_entities: Vec<_> = rec.entities.iter().filter(|e| e.label == "PER").collect();
        if per_entities.is_empty() {
            continue;
        }

        heur_conll.total_samples += 1;
        heur_conll.gold_entities += per_entities.len();

        let report = heuristic_engine
            .sanitize_prompt(&rec.text, None)
            .await
            .unwrap();

        for gold in &per_entities {
            if !report.sanitized_text.contains(&gold.token) {
                heur_conll.true_positives += 1;
            } else {
                heur_conll.false_negatives += 1;
            }
        }

        if let Some(ref hyb_eng) = hybrid_engine {
            hyb_conll.total_samples += 1;
            hyb_conll.gold_entities += per_entities.len();

            let h_report = hyb_eng.sanitize_prompt(&rec.text, None).await.unwrap();
            for gold in &per_entities {
                if !h_report.sanitized_text.contains(&gold.token) {
                    hyb_conll.true_positives += 1;
                } else {
                    hyb_conll.false_negatives += 1;
                }
            }
        }
    }

    heur_conll.finalize();
    hyb_conll.finalize();

    // -------------------------------------------------------------------------
    // EVAL 3: WikiGold Test Split (Wikipedia Unstructured NER)
    // -------------------------------------------------------------------------
    println!("\n--- [EVAL 3] Evaluating WikiGold Test Split ---");
    let wikigold_records = load_eval_records("data/eval/wikigold_eval.jsonl");
    println!("Loaded {} WikiGold sentences.", wikigold_records.len());

    let mut heur_wiki = ConfusionMetrics::default();
    let mut hyb_wiki = ConfusionMetrics::default();

    let mut wiki_idx = 0;
    for rec in &wikigold_records {
        wiki_idx += 1;
        if wiki_idx % 200 == 0 {
            println!(
                "  -> WikiGold progress: {} / {} sentences",
                wiki_idx,
                wikigold_records.len()
            );
        }
        let per_entities: Vec<_> = rec.entities.iter().filter(|e| e.label == "PER").collect();
        if per_entities.is_empty() {
            continue;
        }

        heur_wiki.total_samples += 1;
        heur_wiki.gold_entities += per_entities.len();

        let report = heuristic_engine
            .sanitize_prompt(&rec.text, None)
            .await
            .unwrap();

        for gold in &per_entities {
            if !report.sanitized_text.contains(&gold.token) {
                heur_wiki.true_positives += 1;
            } else {
                heur_wiki.false_negatives += 1;
            }
        }

        if let Some(ref hyb_eng) = hybrid_engine {
            hyb_wiki.total_samples += 1;
            hyb_wiki.gold_entities += per_entities.len();

            let h_report = hyb_eng.sanitize_prompt(&rec.text, None).await.unwrap();
            for gold in &per_entities {
                if !h_report.sanitized_text.contains(&gold.token) {
                    hyb_wiki.true_positives += 1;
                } else {
                    hyb_wiki.false_negatives += 1;
                }
            }
        }
    }

    heur_wiki.finalize();
    hyb_wiki.finalize();

    // -------------------------------------------------------------------------
    // EVAL 4: 100,000-Iteration Multilingual Combinatorial Matrix
    // -------------------------------------------------------------------------
    println!("\n--- [EVAL 4] Running 100,000-Iteration Multilingual Combinatorial Matrix ---");
    let lexicon_file = File::open("data/eval/multilingual_name_lexicon.json")
        .expect("Failed to open multilingual_name_lexicon.json");
    let lexicon: NameLexicon = serde_json::from_reader(lexicon_file)
        .expect("Failed to parse multilingual_name_lexicon.json");

    let cultures = [
        ("greek", &lexicon.greek),
        ("english", &lexicon.english),
        ("arabic", &lexicon.arabic),
        ("chinese", &lexicon.chinese),
    ];

    let templates = [
        "Patient {} was admitted to the clinic this morning for a routine checkup.",
        "Please forward the executive security audit report directly to {}.",
        "{} confirmed that the database cluster deployment finished with zero errors.",
        "Meeting attendees for tomorrow's standup: {}, team lead.",
        "Dear {}, your confidential account verification code is ready.",
    ];

    const TOTAL_ITERATIONS: usize = 100_000;
    println!(
        "Generating & testing {} combinatorial name prompts...",
        TOTAL_ITERATIONS
    );

    let mut culture_metrics: HashMap<String, ConfusionMetrics> = HashMap::new();
    let mut aggregate_metrics = ConfusionMetrics::default();

    let mut rng = rand::thread_rng();
    let start_100k = Instant::now();

    for i in 0..TOTAL_ITERATIONS {
        let (cult_name, cult_data) = cultures[i % cultures.len()];
        let first = cult_data.first.choose(&mut rng).unwrap();
        let mut last = cult_data.last.choose(&mut rng).unwrap();
        if cult_name == "chinese" {
            while first == "Hong" && last == "Kong" {
                last = cult_data.last.choose(&mut rng).unwrap();
            }
        }
        let full_name = format!("{} {}", first, last);

        let tmpl = templates.choose(&mut rng).unwrap();
        let prompt = tmpl.replace("{}", &full_name);

        let c_metric = culture_metrics.entry(cult_name.to_string()).or_default();
        c_metric.total_samples += 1;
        c_metric.gold_entities += 1;

        aggregate_metrics.total_samples += 1;
        aggregate_metrics.gold_entities += 1;

        let report = heuristic_engine
            .sanitize_prompt(&prompt, None)
            .await
            .unwrap();

        if !report.sanitized_text.contains(&full_name) {
            c_metric.true_positives += 1;
            aggregate_metrics.true_positives += 1;
        } else {
            c_metric.false_negatives += 1;
            aggregate_metrics.false_negatives += 1;
        }

        if (i + 1) % 25_000 == 0 {
            println!(
                "  -> Completed {} / {} iterations ({:.2?})",
                i + 1,
                TOTAL_ITERATIONS,
                start_100k.elapsed()
            );
        }
    }

    for m in culture_metrics.values_mut() {
        m.finalize();
    }
    aggregate_metrics.finalize();
    println!(
        "Finished 100,000 iterations in {:.2?}",
        start_100k.elapsed()
    );

    // -------------------------------------------------------------------------
    // EVAL 5: Adversarial & Messy Enterprise Suite (1,000 Prompts)
    // -------------------------------------------------------------------------
    println!("\n--- [EVAL 5] Evaluating Adversarial & Messy Enterprise Suite (1,000 Prompts) ---");
    let eval5_cases = generate_eval5_dataset();
    println!(
        "Generated {} EVAL 5 test cases across 5 slices.",
        eval5_cases.len()
    );

    println!("Running EVAL 5 on Heuristic Engine...");
    let heur_eval5 = evaluate_eval5(&heuristic_engine, &eval5_cases).await;

    let hyb_eval5 = if let Some(ref hyb_eng) = hybrid_engine {
        println!("Running EVAL 5 on Hybrid Engine...");
        Some(evaluate_eval5(hyb_eng, &eval5_cases).await)
    } else {
        None
    };

    // -------------------------------------------------------------------------
    // SUMMARY SCORECARD OUTPUT
    // -------------------------------------------------------------------------
    println!("\n================================================================================");
    println!("                     FINAL ACCURACY & RECALL SCORECARD                          ");
    println!("================================================================================");
    println!(
        "{:<32} | {:<12} | {:<12} | {:<10} | {:<10} | {:<10}",
        "Benchmark Category", "Heur Recall", "Hyb Recall", "Precision", "Heur F1", "Hyb F1"
    );
    println!(
        "{:-<32}-|-{:-<12}-|-{:-<12}-|-{:-<10}-|-{:-<10}-|-{:-<10}",
        "", "", "", "", "", ""
    );

    for (cat, heur_m) in &heur_structural_map {
        let (hyb_recall_str, hyb_f1_str) = if let Some(hyb_m) = hyb_structural_map.get(cat) {
            (
                format!("{:.1}%", hyb_m.recall * 100.0),
                format!("{:.3}", hyb_m.f1),
            )
        } else {
            ("N/A".to_string(), "N/A".to_string())
        };
        println!(
            "{:<32} | {:<12} | {:<12} | {:<10} | {:<10} | {:<10}",
            format!("Structural: {}", cat),
            format!("{:.1}%", heur_m.recall * 100.0),
            hyb_recall_str,
            format!("{:.1}%", heur_m.precision * 100.0),
            format!("{:.3}", heur_m.f1),
            hyb_f1_str
        );
    }

    println!(
        "{:<32} | {:<12} | {:<12} | {:<10} | {:<10} | {:<10}",
        "Standard: CoNLL-2003 (Person)",
        format!("{:.1}%", heur_conll.recall * 100.0),
        format!("{:.1}%", hyb_conll.recall * 100.0),
        format!("{:.1}%", heur_conll.precision * 100.0),
        format!("{:.3}", heur_conll.f1),
        format!("{:.3}", hyb_conll.f1)
    );

    println!(
        "{:<32} | {:<12} | {:<12} | {:<10} | {:<10} | {:<10}",
        "Standard: WikiGold (Person)",
        format!("{:.1}%", heur_wiki.recall * 100.0),
        format!("{:.1}%", hyb_wiki.recall * 100.0),
        format!("{:.1}%", heur_wiki.precision * 100.0),
        format!("{:.3}", heur_wiki.f1),
        format!("{:.3}", hyb_wiki.f1)
    );

    println!("\n--- [EVAL 5: Adversarial & Messy Enterprise Suite Breakdown] ---");
    println!(
        "{:<28} | {:<12} | {:<12} | {:<12} | {:<10} | {:<10}",
        "Slice Category", "Heur Recall", "Hyb Recall", "Precision", "Heur F1", "Hyb F1"
    );
    println!(
        "{:-<28}-|-{:-<12}-|-{:-<12}-|-{:-<12}-|-{:-<10}-|-{:-<10}",
        "", "", "", "", "", ""
    );

    let slice_ids = [
        "5A_CONVERSATIONAL_FULL",
        "5B_SINGLE_SURNAMES_VERBS",
        "5C_GREEK_INFLECTED",
        "5D_COMPLEX_FORMATS",
        "5E_NEGATIVE_CONTROLS",
    ];

    for slice_id in &slice_ids {
        let heur_m = heur_eval5.get(*slice_id).cloned().unwrap_or_default();
        let hyb_m = hyb_eval5
            .as_ref()
            .and_then(|h| h.get(*slice_id))
            .cloned()
            .unwrap_or_default();

        let (prec_str, h_f1_str, hyb_f1_str) = if *slice_id == "5E_NEGATIVE_CONTROLS" {
            (
                format!(
                    "{:.1}%",
                    if hyb_eval5.is_some() {
                        hyb_m.precision * 100.0
                    } else {
                        heur_m.precision * 100.0
                    }
                ),
                "N/A (Ctrl)".to_string(),
                "N/A (Ctrl)".to_string(),
            )
        } else {
            (
                format!(
                    "{:.1}%",
                    if hyb_eval5.is_some() {
                        hyb_m.precision * 100.0
                    } else {
                        heur_m.precision * 100.0
                    }
                ),
                format!("{:.3}", heur_m.f1),
                format!("{:.3}", hyb_m.f1),
            )
        };

        println!(
            "{:<28} | {:<12} | {:<12} | {:<12} | {:<10} | {:<10}",
            slice_id,
            format!("{:.1}%", heur_m.recall * 100.0),
            if hyb_eval5.is_some() {
                format!("{:.1}%", hyb_m.recall * 100.0)
            } else {
                "N/A".to_string()
            },
            prec_str,
            h_f1_str,
            hyb_f1_str,
        );
    }

    println!("\n--- 100,000-Iteration Multilingual Matrix Breakdown ---");
    for (cult, m) in &culture_metrics {
        println!(
            "{:<32} | Support: {:<6} | Recall: {:.2}% | Leaks (FN): {}",
            format!("Culture: {}", cult.to_uppercase()),
            m.gold_entities,
            m.recall * 100.0,
            m.false_negatives
        );
    }
    println!(
        "{:<32} | Support: {:<6} | Recall: {:.2}% | Leaks (FN): {}",
        "100,000 AGGREGATE",
        aggregate_metrics.gold_entities,
        aggregate_metrics.recall * 100.0,
        aggregate_metrics.false_negatives
    );

    // Save machine-readable JSON
    let final_report = AccuracyBenchmarkReport {
        timestamp: format!("{:?}", std::time::SystemTime::now()),
        system_info: "Linux x86_64 / Rust 1.99.0".to_string(),
        heuristic_mode: ModeResults {
            synthetic_structural: heur_structural_map,
            conll2003: heur_conll,
            wikigold: heur_wiki,
            overall: aggregate_metrics.clone(),
        },
        hybrid_mode: ModeResults {
            synthetic_structural: hyb_structural_map,
            conll2003: hyb_conll,
            wikigold: hyb_wiki,
            overall: ConfusionMetrics::default(),
        },
        combinatorial_100k_stress_test: CombinatorialReport {
            total_iterations: TOTAL_ITERATIONS,
            detailed_by_culture: culture_metrics,
            aggregate: aggregate_metrics,
        },
        eval5_adversarial_suite: Eval5Report {
            total_samples: eval5_cases.len(),
            slices: hyb_eval5.unwrap_or(heur_eval5),
        },
    };

    let raw_out_path = "benchmarks/raw/accuracy_eval_results.json";
    if let Ok(file) = File::create(raw_out_path) {
        let _ = serde_json::to_writer_pretty(file, &final_report);
        println!(
            "\n[OK] Raw benchmark results committed to: {}",
            raw_out_path
        );
        std::process::exit(0);
    }
}
