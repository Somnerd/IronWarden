use std::sync::LazyLock;
use iw_core::traits::{PotentialMiss, EnforcementAction};
use iw_core::PiiCategory;
use crate::normalize::OffsetMap;
use regex::Regex;
use tracing::warn;

static GLOBAL_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z\u0386\u0388-\u038A\u038C\u038E\u038F\u0391-\u03A9][\u03B1-\u03C9\u03AC-\u03CEa-z]+(?:\s+(?:[a-z]{1,3}\s+)*[A-Z\u0386\u0388-\u038A\u038C\u038E\u038F\u0391-\u03A9][\u03B1-\u03C9\u03AC-\u03CEa-z]+)+\b").unwrap()
});

static GREEK_SUFFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z\u0386\u0388-\u038A\u038C\u038E\u038F\u0391-\u03A9][\u03B1-\u03C9\u03AC-\u03CE]+(ης|ου|ος|α|ου)\b").unwrap()
});

pub struct ShadowNer {
    patterns: Vec<(Regex, String, bool, EnforcementAction, PiiCategory)>,
    global_name_re: Regex,
    greek_name_re: Regex,
}

#[derive(Debug, Clone)]
pub struct ShadowMatch {
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub action: EnforcementAction,
    pub category: PiiCategory,
    pub is_ascii: bool,
}

impl ShadowNer {
    pub fn new(heuristics: Vec<crate::config::HeuristicConfig>) -> Self {
        let mut compiled = Vec::new();
        for config in heuristics {
            match Regex::new(&config.pattern) {
                Ok(re) => compiled.push((re, config.label, config.skip_sentence_start, config.action, config.category)),
                Err(e) => warn!("ShadowNer: Failed to compile heuristic pattern for {}: {}", config.label, e),
            }
        }
        Self {
            patterns: compiled,
            global_name_re: Regex::new(r"\b[A-Z][a-z]+(?:\s+(?:[a-z]{1,3}\s+)*[A-Z][a-z]+)+\b").unwrap(),
            greek_name_re: Regex::new(r"\b[\u0391-\u03A9][\u03B1-\u03C9\u03AC-\u03CE]+(?:\s+[\u0391-\u03A9][\u03B1-\u03C9\u03AC-\u03CE]+)+\b").unwrap(),
        }
    }

    /// Scans the text and returns matches with normalized offsets.
    /// Incorporates Unicode-aware Greek name heuristics and Multi-word Chain Fusion.
    pub fn analyze(&self, unicode_text: &str, ascii_text: &str) -> Vec<ShadowMatch> {
        let mut matches = Vec::new();

        // 1. Run Configured Heuristics (AFM, AMKA, etc.) on UNICODE
        for (pattern, label, skip_sentence_start, action, category) in &self.patterns {
            for mat in pattern.find_iter(unicode_text) {
                let start = mat.start();
                let end = mat.end();
                
                if *skip_sentence_start && self.is_at_sentence_start(unicode_text, start) {
                    continue;
                }

                matches.push(ShadowMatch {
                    start,
                    end,
                    label: label.clone(),
                    action: *action,
                    category: *category,
                    is_ascii: false,
                });
            }

            // --- SECURITY FIX (V-15): Run heuristics on ASCII for homoglyph resilience ---
            for mat in pattern.find_iter(ascii_text) {
                let start = mat.start();
                let end = mat.end();
                
                if *skip_sentence_start && self.is_at_sentence_start(ascii_text, start) {
                    continue;
                }

                matches.push(ShadowMatch {
                    start,
                    end,
                    label: format!("{}_homoglyph", label),
                    action: *action,
                    category: *category,
                    is_ascii: true,
                });
            }
        }

        // --- GLOBAL IDENTITY FIX: Robust Title-Case Chain Heuristic on ASCII ---
        // This provides homoglyph resilience for Latin-based names.
        for mat in GLOBAL_NAME_RE.find_iter(ascii_text) {
            let matched_text = mat.as_str();
            if matched_text == "My name" || matched_text == "The client" {
                continue;
            }

            matches.push(ShadowMatch {
                start: mat.start(),
                end: mat.end(),
                label: "POTENTIAL_GLOBAL_NAME".to_string(),
                action: EnforcementAction::Redact,
                category: PiiCategory::IndividualName,
                is_ascii: true,
            });
        }

        // --- SECURITY FIX (V-15): Unicode-aware Greek Title-Case Chain Heuristic ---
        // Catching Greek names (e.g., Νίκος Παπαδόπουλος) directly in Unicode.
        for mat in self.greek_name_re.find_iter(unicode_text) {
            matches.push(ShadowMatch {
                start: mat.start(),
                end: mat.end(),
                label: "POTENTIAL_GREEK_NAME_CHAIN".to_string(),
                action: EnforcementAction::Redact,
                category: PiiCategory::IndividualName,
                is_ascii: false,
            });
        }

        // Single Greek names (Fallback) on UNICODE
        for mat in GREEK_SUFFIX_RE.find_iter(unicode_text) {
            matches.push(ShadowMatch {
                start: mat.start(),
                end: mat.end(),
                label: "POTENTIAL_GREEK_NAME".to_string(),
                action: EnforcementAction::Redact,
                category: PiiCategory::IndividualName,
                is_ascii: false,
            });
        }

        matches
    }

    fn is_at_sentence_start(&self, text: &str, offset: usize) -> bool {
        if offset == 0 { return true; }
        
        let before = &text[..offset];
        let trimmed = before.trim_end();
        if trimmed.is_empty() { return true; }
        
        trimmed.ends_with(['.', '!', '?'])
    }
}
