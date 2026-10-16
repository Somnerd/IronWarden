pub mod patterns;
mod track_a;
mod track_b;

pub use patterns::*;

use iw_core::traits::EnforcementAction;
use iw_core::PiiCategory;
use regex::Regex;
use tracing::warn;

pub struct ShadowNer {
    pub(crate) patterns: Vec<(Regex, String, bool, EnforcementAction, PiiCategory)>,
    pub(crate) greek_name_re: Regex,
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

#[derive(Debug, Clone)]
pub struct AmbiguousCandidate {
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub needs_synthetic_casing: bool,
}

impl ShadowNer {
    pub fn new(heuristics: Vec<crate::config::HeuristicConfig>) -> Self {
        let mut compiled = Vec::new();
        for config in heuristics {
            match Regex::new(&config.pattern) {
                Ok(re) => compiled.push((
                    re,
                    config.label,
                    config.skip_sentence_start,
                    config.action,
                    config.category,
                )),
                Err(e) => warn!(
                    "ShadowNer: Failed to compile heuristic pattern for {}: {}",
                    config.label, e
                ),
            }
        }
        Self {
            patterns: compiled,
            greek_name_re: Regex::new(r"\b[\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03AB}][\u{0386}-\u{03CE}]+(?:[\s\-']+[\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03AB}][\u{0386}-\u{03CE}]+)+\b").unwrap(),
        }
    }

    pub fn is_valid_name_span(text: &str, start: usize, end: usize) -> bool {
        if start >= end || end > text.len() {
            return false;
        }
        let matched = &text[start..end];
        if GEOGRAPHIC_PROPER_NOUNS.contains(matched) {
            return false;
        }

        // Reject if candidate span overlaps with any known geographic proper noun in the source text
        for geo in GEOGRAPHIC_PROPER_NOUNS.iter() {
            let mut search_from = 0;
            while let Some(rel_pos) = text[search_from..].find(geo) {
                let pos = search_from + rel_pos;
                let geo_end = pos + geo.len();
                if start < geo_end && end > pos {
                    return false;
                }
                search_from = pos + geo.len();
            }
        }

        let words: Vec<&str> = matched
            .split(|c: char| c.is_whitespace() || c == '-' || c == '\'')
            .filter(|s| !s.is_empty())
            .collect();

        if words.is_empty() {
            return false;
        }

        // Reject all-caps acronyms (e.g. "NATO", "E.U.", "U.S.")
        for w in &words {
            let clean_w = w.trim_matches('.');
            if clean_w.len() >= 2 && clean_w.chars().all(|c| c.is_ascii_uppercase()) {
                return false;
            }
        }

        // Reject if first word is an imperative verb
        if IMPERATIVE_VERBS.contains(words[0]) {
            return false;
        }

        // If first word is a role prefix (e.g. "Patient", "Per", "Attn", "Client", "Customer") followed by other words, check remaining words
        let candidate_words = if words.len() >= 2
            && matches!(words[0], "Patient" | "Per" | "Attn" | "Client" | "Customer")
        {
            &words[1..]
        } else {
            &words[..]
        };

        // Reject if any token is a role noun, tech stopword, or function stopword
        for w in candidate_words {
            let w_lower = w.to_lowercase();
            if ROLE_NOUN_BLOCKLIST.contains(w)
                || TECH_AND_COMMON_STOPWORDS.contains(w)
                || LOWERCASE_STOPWORDS.contains(w_lower.as_str())
            {
                return false;
            }
        }

        true
    }

    pub fn is_at_sentence_start(&self, text: &str, offset: usize) -> bool {
        if offset == 0 {
            return true;
        }

        let before = &text[..offset];
        let trimmed = before.trim_end();
        if trimmed.is_empty() {
            return true;
        }

        trimmed.ends_with('.')
            || trimmed.ends_with('!')
            || trimmed.ends_with('?')
            || trimmed.ends_with('\n')
    }
}
