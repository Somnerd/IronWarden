use super::patterns::*;
use super::{ShadowMatch, ShadowNer};
use iw_core::traits::EnforcementAction;
use iw_core::PiiCategory;

impl ShadowNer {
    /// Scans the text and returns Track A High-Certainty heuristic matches.
    pub fn analyze(&self, unicode_text: &str, ascii_text: &str) -> Vec<ShadowMatch> {
        let mut matches = Vec::new();

        let clean_ascii = ascii_text.replace('_', " ");
        let clean_unicode = unicode_text.replace('_', " ");

        // 1. Run Configured Heuristics (AFM, AMKA, etc.) on UNICODE
        for (pattern, label, skip_sentence_start, action, category) in &self.patterns {
            for mat in pattern.find_iter(&clean_unicode) {
                let start = mat.start();
                let end = mat.end();

                if *skip_sentence_start && self.is_at_sentence_start(unicode_text, start) {
                    continue;
                }

                if !Self::is_valid_name_span(unicode_text, start, end) {
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
            for mat in pattern.find_iter(&clean_ascii) {
                let start = mat.start();
                let end = mat.end();

                if *skip_sentence_start && self.is_at_sentence_start(ascii_text, start) {
                    continue;
                }

                if !Self::is_valid_name_span(ascii_text, start, end) {
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

        // 2. Track A Branch 1: GLOBAL_NAME_RE on ASCII (Full names, initials, nobiliary particles)
        for mat in GLOBAL_NAME_RE.find_iter(&clean_ascii) {
            let mut start = mat.start();
            let end = mat.end();
            let mut span_text = &clean_ascii[start..end];

            // If the span starts with a greeting or common sentence starter (e.g. "Hello John Doe", "Dear Jane Smith"),
            // trim the leading greeting so the actual name is preserved as a candidate.
            while let Some(first_space) =
                span_text.find(|c: char| c.is_whitespace() || c == '-' || c == '\'')
            {
                let first_word = &span_text[..first_space];
                if COMMON_SENTENCE_STARTERS.contains(first_word)
                    || GREETINGS_BLOCKLIST.contains(first_word)
                {
                    let next_start = start + first_space;
                    let remaining = clean_ascii[next_start..end].trim_start();
                    start = end - remaining.len();
                    span_text = &clean_ascii[start..end];
                } else {
                    break;
                }
            }

            let remaining_words: Vec<&str> = span_text
                .split(|c: char| c.is_whitespace() || c == '-' || c == '\'')
                .filter(|s| !s.is_empty())
                .collect();

            if remaining_words.len() < 2 {
                continue;
            }

            if span_text == "My name"
                || span_text == "The client"
                || !Self::is_valid_name_span(ascii_text, start, end)
            {
                continue;
            }

            matches.push(ShadowMatch {
                start,
                end,
                label: "POTENTIAL_GLOBAL_NAME".to_string(),
                action: EnforcementAction::Redact,
                category: PiiCategory::IndividualName,
                is_ascii: true,
            });
        }

        // 3. Track A Branch 2: INITIAL_NAME_RE on ASCII (Abbreviated first initial + Surname)
        for mat in INITIAL_NAME_RE.find_iter(&clean_ascii) {
            let mat_str = mat.as_str().to_lowercase();
            if mat_str.starts_with("e.g.") || mat_str.starts_with("i.e.") {
                continue;
            }

            // Guard 1: Reject acronym tails like "U.S. Government" or "Plan A. Next"
            if (mat.start() >= 1 && ascii_text.as_bytes()[mat.start() - 1] == b'.')
                || (mat.start() >= 2 && ascii_text.as_bytes()[mat.start() - 2] == b'.')
            {
                continue;
            }

            if !Self::is_valid_name_span(ascii_text, mat.start(), mat.end()) {
                continue;
            }

            // Guard 2: Reject if surname is a known stopword or tech keyword
            let surname = mat.as_str().split_whitespace().last().unwrap_or("");
            if COMMON_SENTENCE_STARTERS.contains(surname)
                || TECH_AND_COMMON_STOPWORDS.contains(surname)
            {
                continue;
            }

            matches.push(ShadowMatch {
                start: mat.start(),
                end: mat.end(),
                label: "POTENTIAL_INITIAL_NAME".to_string(),
                action: EnforcementAction::Redact,
                category: PiiCategory::IndividualName,
                is_ascii: true,
            });
        }

        // 4. Track A Branch 3: HONORIFIC_NAME_RE on ASCII (Strict personal titles)
        for mat in HONORIFIC_NAME_RE.find_iter(&clean_ascii) {
            if !Self::is_valid_name_span(ascii_text, mat.start(), mat.end()) {
                continue;
            }

            matches.push(ShadowMatch {
                start: mat.start(),
                end: mat.end(),
                label: "POTENTIAL_HONORIFIC_NAME".to_string(),
                action: EnforcementAction::Redact,
                category: PiiCategory::IndividualName,
                is_ascii: true,
            });
        }

        // 5. Greek morphological name pairs & distinctive suffixes (Track A)
        for mat in GREEK_NAME_PAIR_RE.find_iter(&clean_ascii) {
            if !Self::is_valid_name_span(ascii_text, mat.start(), mat.end()) {
                continue;
            }

            matches.push(ShadowMatch {
                start: mat.start(),
                end: mat.end(),
                label: "POTENTIAL_GREEK_NAME".to_string(),
                action: EnforcementAction::Redact,
                category: PiiCategory::IndividualName,
                is_ascii: true,
            });
        }
        for mat in GREEK_NAME_PAIR_RE.find_iter(&clean_unicode) {
            if !Self::is_valid_name_span(unicode_text, mat.start(), mat.end()) {
                continue;
            }

            matches.push(ShadowMatch {
                start: mat.start(),
                end: mat.end(),
                label: "POTENTIAL_GREEK_NAME".to_string(),
                action: EnforcementAction::Redact,
                category: PiiCategory::IndividualName,
                is_ascii: false,
            });
        }
        // 5b. Distinctive Greek patronymics in Track A (poulos, akis, idis, etc.)
        for mat in GREEK_PATRONYMIC_RE.find_iter(&clean_ascii) {
            let start = mat.start();
            let end = mat.end();
            if !Self::is_valid_name_span(ascii_text, start, end) {
                continue;
            }
            if !matches.iter().any(|m| start < m.end && end > m.start) {
                matches.push(ShadowMatch {
                    start,
                    end,
                    label: "POTENTIAL_GREEK_NAME".to_string(),
                    action: EnforcementAction::Redact,
                    category: PiiCategory::IndividualName,
                    is_ascii: true,
                });
            }
        }
        for mat in GREEK_PATRONYMIC_RE.find_iter(&clean_unicode) {
            let start = mat.start();
            let end = mat.end();
            if !Self::is_valid_name_span(unicode_text, start, end) {
                continue;
            }
            if !matches.iter().any(|m| start < m.end && end > m.start) {
                matches.push(ShadowMatch {
                    start,
                    end,
                    label: "POTENTIAL_GREEK_NAME".to_string(),
                    action: EnforcementAction::Redact,
                    category: PiiCategory::IndividualName,
                    is_ascii: false,
                });
            }
        }

        // Generic single-word Greek morphological case endings (ης|ου|ος|ας|α|ων|η) are demoted to Track B
        for mat in ARABIC_MORPHOLOGICAL_RE.find_iter(&clean_ascii) {
            let start = mat.start();
            let end = mat.end();
            if !Self::is_valid_name_span(ascii_text, start, end) {
                continue;
            }
            if !matches.iter().any(|m| start < m.end && end > m.start) {
                matches.push(ShadowMatch {
                    start,
                    end,
                    label: "POTENTIAL_ARABIC_NAME".to_string(),
                    action: EnforcementAction::Redact,
                    category: PiiCategory::IndividualName,
                    is_ascii: true,
                });
            }
        }
        for mat in ARABIC_MORPHOLOGICAL_RE.find_iter(&clean_unicode) {
            let start = mat.start();
            let end = mat.end();
            if !Self::is_valid_name_span(unicode_text, start, end) {
                continue;
            }
            if !matches.iter().any(|m| start < m.end && end > m.start) {
                matches.push(ShadowMatch {
                    start,
                    end,
                    label: "POTENTIAL_ARABIC_NAME".to_string(),
                    action: EnforcementAction::Redact,
                    category: PiiCategory::IndividualName,
                    is_ascii: false,
                });
            }
        }

        // 6. Unicode-aware Greek Title-Case Chain Heuristic
        for mat in self.greek_name_re.find_iter(&clean_unicode) {
            let mut start = mat.start();
            let end = mat.end();
            let mut span_text = &clean_unicode[start..end];

            while let Some(first_space) =
                span_text.find(|c: char| c.is_whitespace() || c == '-' || c == '\'')
            {
                let first_word = &span_text[..first_space];
                if COMMON_SENTENCE_STARTERS.contains(first_word)
                    || GREETINGS_BLOCKLIST.contains(first_word)
                {
                    let next_start = start + first_space;
                    let remaining = clean_unicode[next_start..end].trim_start();
                    start = end - remaining.len();
                    span_text = &clean_unicode[start..end];
                } else {
                    break;
                }
            }

            let remaining_words: Vec<&str> = span_text
                .split(|c: char| c.is_whitespace() || c == '-' || c == '\'')
                .filter(|s| !s.is_empty())
                .collect();

            if remaining_words.len() < 2 {
                continue;
            }

            if !Self::is_valid_name_span(unicode_text, start, end) {
                continue;
            }
            matches.push(ShadowMatch {
                start,
                end,
                label: "POTENTIAL_GREEK_NAME_CHAIN".to_string(),
                action: EnforcementAction::Redact,
                category: PiiCategory::IndividualName,
                is_ascii: false,
            });
        }

        matches.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
        });

        matches
    }
}
