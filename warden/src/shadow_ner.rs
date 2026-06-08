use std::sync::LazyLock;
use iw_core::traits::{PotentialMiss};
use crate::normalize::OffsetMap;
use crate::config::SanitizationAction;
use regex::Regex;
use tracing::warn;

static GLOBAL_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z\u0386\u0388-\u038A\u038C\u038E\u038F\u0391-\u03A9][\u03B1-\u03C9\u03AC-\u03CEa-z]+(?:\s+(?:[a-z]{1,3}\s+)*[A-Z\u0386\u0388-\u038A\u038C\u038E\u038F\u0391-\u03A9][\u03B1-\u03C9\u03AC-\u03CEa-z]+)+\b").unwrap()
});

static GREEK_SUFFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z\u0386\u0388-\u038A\u038C\u038E\u038F\u0391-\u03A9][\u03B1-\u03C9\u03AC-\u03CE]+(ης|ου|ος|α|ου)\b").unwrap()
});

pub struct ShadowNer {
    patterns: Vec<(Regex, String, bool, SanitizationAction)>,
}

pub struct ShadowMatch {
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub action: SanitizationAction,
}

impl ShadowNer {
    pub fn new(heuristics: Vec<crate::config::HeuristicConfig>) -> Self {
        let mut compiled = Vec::new();
        for config in heuristics {
            match Regex::new(&config.pattern) {
                Ok(re) => compiled.push((re, config.label, config.skip_sentence_start, config.action)),
                Err(e) => warn!("ShadowNer: Failed to compile heuristic pattern for {}: {}", config.label, e),
            }
        }
        Self {
            patterns: compiled,
        }
    }

    /// Scans the text and returns matches with normalized offsets.
    /// Incorporates Unicode-aware Greek name heuristics and Multi-word Chain Fusion.
    pub fn analyze(&self, normalized_text: &str) -> Vec<ShadowMatch> {
        let mut matches = Vec::new();

        // 1. Run Configured Heuristics (AFM, AMKA, etc.)
        for (pattern, label, skip_sentence_start, action) in &self.patterns {
            for mat in pattern.find_iter(normalized_text) {
                let start = mat.start();
                let end = mat.end();
                
                if *skip_sentence_start && self.is_at_sentence_start(normalized_text, start) {
                    continue;
                }

                matches.push(ShadowMatch {
                    start,
                    end,
                    label: label.clone(),
                    action: *action,
                });
            }
        }

        // --- GLOBAL IDENTITY FIX: Robust Title-Case Chain Heuristic ---
        // Captures sequences like "Juan Pablo Garcia de la Cruz" or "Mohammad bin Rashid"
        // Capitalized Word followed by any sequence of:
        // (1-3 lowercase words or connectors) + (Capitalized Word)
        // OR simply (Capitalized Word)
        for mat in GLOBAL_NAME_RE.find_iter(normalized_text) {
            // Skip matches that are just "My Name", "The Case", etc.
            let matched_text = mat.as_str();
            if matched_text == "My name" || matched_text == "The client" {
                continue;
            }

            matches.push(ShadowMatch {
                start: mat.start(),
                end: mat.end(),
                label: "POTENTIAL_GLOBAL_NAME".to_string(),
                action: SanitizationAction::Redact,
            });
        }

        // Single Greek names (Fallback)
        for mat in GREEK_SUFFIX_RE.find_iter(normalized_text) {
            matches.push(ShadowMatch {
                start: mat.start(),
                end: mat.end(),
                label: "POTENTIAL_GREEK_NAME".to_string(),
                action: SanitizationAction::Redact,
            });
        }

        matches
    }

    fn is_at_sentence_start(&self, text: &str, offset: usize) -> bool {
        if offset == 0 { return true; }
        
        let before = &text[..offset];
        let trimmed = before.trim_end();
        if trimmed.is_empty() { return true; }
        
        match trimmed.chars().last() {
            Some(last_char) => matches!(last_char, '.' | '!' | '?'),
            None => true,
        }
    }
}
