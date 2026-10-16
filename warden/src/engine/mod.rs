pub mod guardrails;
mod sanitizer;
pub use guardrails::*;

use crate::normalize::Normalizer;
use crate::shadow_ner::ShadowNer;
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use hkdf::Hkdf;
use iw_core::{EnforcementAction, PiiCategory, SovereignError};
use regex::Regex;
use secrecy::ExposeSecret;
use sha2::Sha256;
use zeroize::Zeroize;

pub struct WardenEngine {
    pub(crate) dictionary_automaton: AhoCorasick,
    pub(crate) individual_regexes: Vec<Regex>,
    pub(crate) rule_ids: Vec<String>,
    pub(crate) rule_actions: Vec<EnforcementAction>,
    pub(crate) rule_categories: Vec<PiiCategory>,
    pub(crate) shadow_ner: ShadowNer,
    pub(crate) dict_pattern_count: usize,
    pub(crate) ai: Option<crate::ai::HybridNerPool>,
    pub(crate) confidence_threshold: f64,
    pub(crate) cipher: Aes256Gcm,
}

impl WardenEngine {
    pub fn new(
        dictionary_rules: Vec<(String, String, EnforcementAction, PiiCategory)>,
        patterns_rules: Vec<(String, String, EnforcementAction, PiiCategory)>,
        heuristics: Vec<crate::config::HeuristicConfig>,
        ai: Option<crate::ai::HybridNerPool>,
        confidence_threshold: f64,
        pepper: &secrecy::SecretVec<u8>,
    ) -> Result<Self, SovereignError> {
        // --- CRYPTOGRAPHIC INITIALIZATION (V-19) ---
        let hk = Hkdf::<Sha256>::new(None, pepper.expose_secret());
        let mut key_bytes = [0u8; 32];
        hk.expand(b"warden-v1-grounding-shield", &mut key_bytes)
            .map_err(|_| SovereignError::InternalError("KDF expansion failed".into()))?;
        #[allow(deprecated)]
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        key_bytes.zeroize();

        let mut dict_patterns = Vec::new();
        let mut dict_ids = Vec::new();
        let mut dict_actions = Vec::new();
        let mut dict_categories = Vec::new();
        for (id, pat, action, category) in dictionary_rules {
            dict_ids.push(id);
            // --- SECURITY FIX (V-13): Normalize dictionary patterns ---
            let norm_ascii =
                Normalizer::with_normalized(&pat, |norm| norm.normalized_ascii.clone());
            dict_patterns.push(norm_ascii);
            dict_actions.push(action);
            dict_categories.push(category);
        }

        let mut individual_regexes = Vec::new();
        let mut regex_ids = Vec::new();
        let mut regex_actions = Vec::new();
        let mut regex_categories = Vec::new();

        let mut all_patterns = patterns_rules;
        // --- CORE GREEK PII PATTERNS NATIVELY EMBEDDED (P0) ---
        all_patterns.push((
            "NATIVE_GR_AMKA".to_string(),
            r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}\d{5}\b".to_string(),
            EnforcementAction::Redact,
            PiiCategory::IdentificationNumber,
        ));
        all_patterns.push((
            "NATIVE_GR_ID".to_string(),
            r"\b[Α-ΩA-Z]{2}[- ]?\d{6}\b".to_string(),
            EnforcementAction::Redact,
            PiiCategory::IdentificationNumber,
        ));
        all_patterns.push((
            "NATIVE_GR_PHONE".to_string(),
            r"\b(?:(?:\+30|0030)[\s\-]?)?(?:2\d{9}|69\d{8})\b".to_string(),
            EnforcementAction::Redact,
            PiiCategory::ContactInfo,
        ));

        for (id, pat, action, category) in all_patterns {
            let re = Regex::new(&pat).map_err(|e| {
                SovereignError::ConfigError(format!(
                    "Failed to compile regex pattern {}: {}",
                    id, e
                ))
            })?;
            individual_regexes.push(re);
            regex_ids.push(id);
            regex_actions.push(action);
            regex_categories.push(category);
        }

        let dict_pattern_count = dict_patterns.len();
        let dictionary_automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(dict_patterns)
            .map_err(|e| {
                SovereignError::ConfigError(format!("Failed to build AC automaton: {}", e))
            })?;

        Ok(Self {
            dictionary_automaton,
            individual_regexes,
            rule_ids: [dict_ids, regex_ids].concat(),
            rule_actions: [dict_actions, regex_actions].concat(),
            rule_categories: [dict_categories, regex_categories].concat(),
            shadow_ner: ShadowNer::new(heuristics),
            dict_pattern_count,
            ai,
            confidence_threshold,
            cipher,
        })
    }
}
