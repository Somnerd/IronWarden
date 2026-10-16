use iw_core::traits::EnforcementAction;
use iw_core::PiiCategory;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;
use tracing::warn;

static GLOBAL_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03A9}][\u{03B1}-\u{03C9}\u{03AC}-\u{03CE}a-z]+(?:[\s\-\x27]+(?:(?:(?i:da|de|del|della|der|den|di|du|ter|ten|van|von|ibn|bin|al|el|la|le|des)|[A-Z\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03A9}]\.)[\s\-\x27]+)*[A-Z\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03A9}][\u{03B1}-\u{03C9}\u{03AC}-\u{03CE}a-z]+)+\b").unwrap()
});

static INITIAL_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[A-Za-z\u{0386}-\u{03CE}]\.[\s\-']*){1,3}([A-Za-z\u{0386}-\u{03CE}][\u{03B1}-\u{03C9}\u{03AC}-\u{03CE}a-z]{2,})\b").unwrap()
});

static HONORIFIC_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Rev|Hon)\.?[\s\-']+([A-Z\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03A9}][\u{03B1}-\u{03C9}\u{03AC}-\u{03CE}a-z]{2,})\b").unwrap()
});

static CONTEXT_ROLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Patient|Per|Attn|Client|Customer)[\s\-']+([A-Z\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03A9}][\u{03B1}-\u{03C9}\u{03AC}-\u{03CE}a-z]{2,})\b").unwrap()
});

static CAPITALIZED_WORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03A9}][\u{03B1}-\u{03C9}\u{03AC}-\u{03CE}a-z]{2,}\b").unwrap()
});

static GREEK_NAME_PAIR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z\u{0386}-\u{03CE}]{3,}\s+[a-z\u{0386}-\u{03CE}]{3,}(?:poulos|poulou|poulo|idis|idi|iadis|iadi|akis|aki|oglou|akos|akou|ako|atos|atou|ato|eas|ea|ianni|yianni|omou|ou|πουλος|πουλου|πουλο|ίδης|ίδη|ιάδης|ιάδη|άκης|άκη|όγλου|ογλου|όπουλος|όπουλου|όπουλο|άκος|άκου|άκο|άτος|άτου|άτο|έας|έα|ιδης|ιδη|ιαδης|ιαδη|ακης|ακη|οπουλος|οπουλου|οπουλο|ακος|ακου|ακο|ατος|ατου|ατο|εας|εα|ης|ου|ος|ας|α|ων|η)\b").unwrap()
});

static GREEK_PATRONYMIC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-z]{3,}(?:poulos|poulou|poulo|idis|idi|iadis|iadi|akis|aki|oglou|akos|akou|ako|atos|atou|ato|eas|ea|ianni|yianni)|[\u{0386}-\u{03CE}]{3,}(?:πουλος|πουλου|πουλο|ίδης|ίδη|ιάδης|ιάδη|άκης|άκη|όγλου|ογλου|όπουλος|όπουλου|όπουλο|άκος|άκου|άκο|άτος|άτου|άτο|έας|έα|ιδης|ιδη|ιαδης|ιαδη|ακης|ακη|οπουλος|οπουλου|οπουλο|ακος|ακου|ακο|ατος|ατου|ατο|εας|εα))\b").unwrap()
});

static GREEK_MORPHOLOGICAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[\u{0386}-\u{03CE}]{3,}(?:ης|ου|ος|ας|ων|η)\b").unwrap());

static ARABIC_MORPHOLOGICAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:al-|el-|ibn\s+|bin\s+)[a-z\u{0621}-\u{064A}]{3,}\b").unwrap()
});

static CONVERSATIONAL_INTRO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:my\s+name\s+is|i\s+am|i'm|contact|email|ping|dm|ask|cc|attn[:\.]?|per|patient|client|mr\.?|mrs\.?|ms\.?|dr\.?|directly\s+to|send\s+(?:the\s+[\w\s]+\s+)?(?:directly\s+)?to)\s+|@)(['"]?[a-z\u{0386}-\u{03CE}]{2,}(?:[\s\-']+[a-z\u{0386}-\u{03CE}]{2,}){0,2}['"]?)\b"#).unwrap()
});

static LOWERCASE_STOPWORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../config/dicts/stopwords.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

static PROTECTED_SURNAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../config/dicts/protected_surnames.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

static IMPERATIVE_VERBS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../config/dicts/imperative_verbs.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

static GEOGRAPHIC_PROPER_NOUNS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../config/dicts/geographic_proper_nouns.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

static ROLE_NOUN_BLOCKLIST: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../config/dicts/role_nouns.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

static COMMON_SENTENCE_STARTERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../config/dicts/sentence_starters.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

static GREETINGS_BLOCKLIST: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../config/dicts/greetings.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

static TECH_AND_COMMON_STOPWORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../config/dicts/tech_stopwords.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

pub struct ShadowNer {
    patterns: Vec<(Regex, String, bool, EnforcementAction, PiiCategory)>,
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

    /// Discovers Track B Ambiguous Candidates (Role anchors, mid-sentence capitalized words, OOV sentence starters)
    /// Excludes spans already covered by Track A or Tier 1 matches.
    pub fn find_ambiguous_tokens(
        &self,
        text: &str,
        confirmed_spans: &[(usize, usize)],
    ) -> Vec<AmbiguousCandidate> {
        let mut candidates = Vec::new();

        let is_span_covered = |start: usize, end: usize, list: &[(usize, usize)]| {
            list.iter().any(|(s, e)| start < *e && end > *s)
        };

        // 1. Role Context Anchors (Patient, Per, Attn, Client, Customer)
        for cap in CONTEXT_ROLE_RE.captures_iter(text) {
            if let Some(mat) = cap.get(1) {
                let word = mat.as_str();
                let start = mat.start();
                let end = mat.end();

                if ROLE_NOUN_BLOCKLIST.contains(word)
                    || TECH_AND_COMMON_STOPWORDS.contains(word)
                    || is_span_covered(start, end, confirmed_spans)
                {
                    continue;
                }

                candidates.push(AmbiguousCandidate {
                    start,
                    end,
                    text: word.to_string(),
                    needs_synthetic_casing: false,
                });
            }
        }

        // 2. Capitalized tokens: mid-sentence or OOV sentence starters
        let clean_text = text.replace('_', " ");
        for mat in CAPITALIZED_WORD_RE.find_iter(&clean_text) {
            let word = mat.as_str();
            let start = mat.start();
            let end = mat.end();

            if TECH_AND_COMMON_STOPWORDS.contains(word)
                || ROLE_NOUN_BLOCKLIST.contains(word)
                || is_span_covered(start, end, confirmed_spans)
                || candidates.iter().any(|c| start < c.end && end > c.start)
            {
                continue;
            }

            if self.is_at_sentence_start(text, start) {
                // If at sentence start, only flag if Out-Of-Vocabulary (not a common English sentence starter)
                if !COMMON_SENTENCE_STARTERS.contains(word) {
                    candidates.push(AmbiguousCandidate {
                        start,
                        end,
                        text: word.to_string(),
                        needs_synthetic_casing: false,
                    });
                }
            } else {
                // Mid-sentence capitalized word
                if !COMMON_SENTENCE_STARTERS.contains(word) {
                    candidates.push(AmbiguousCandidate {
                        start,
                        end,
                        text: word.to_string(),
                        needs_synthetic_casing: false,
                    });
                }
            }
        }

        // 3. Conversational Introducer Triggers (Case-Insensitive Lowercase/Mixed)
        for cap in CONVERSATIONAL_INTRO_RE.captures_iter(text) {
            if let Some(mat) = cap.get(1) {
                let mut raw_cand = mat.as_str();
                let mut start = mat.start();
                let mut end = mat.end();

                // Strip optional enclosing quotes from span
                if raw_cand.starts_with('\'') || raw_cand.starts_with('"') {
                    start += 1;
                    raw_cand = &raw_cand[1..];
                }
                if raw_cand.ends_with('\'') || raw_cand.ends_with('"') {
                    end -= 1;
                    raw_cand = &raw_cand[..raw_cand.len() - 1];
                }

                // Split tokens on whitespace and hyphens to prevent verb-eater bypasses
                let words: Vec<&str> = raw_cand
                    .split(|c: char| c.is_whitespace() || c == '-')
                    .filter(|s| !s.is_empty())
                    .collect();
                let mut candidate_text = raw_cand.to_string();

                if words.len() == 3 {
                    let w1 = words[0];
                    let w2 = words[1];
                    let w3 = words[2];
                    let w1_lower = w1.to_lowercase();
                    let w2_lower = w2.to_lowercase();
                    let w3_lower = w3.to_lowercase();

                    if LOWERCASE_STOPWORDS.contains(w1_lower.as_str())
                        || ROLE_NOUN_BLOCKLIST.contains(w1)
                        || TECH_AND_COMMON_STOPWORDS.contains(w1)
                    {
                        continue;
                    }

                    let is_nobiliary_w2 = matches!(
                        w2_lower.as_str(),
                        "van"
                            | "von"
                            | "de"
                            | "da"
                            | "del"
                            | "della"
                            | "der"
                            | "den"
                            | "di"
                            | "du"
                            | "al"
                            | "el"
                            | "ibn"
                            | "bin"
                            | "la"
                    );

                    let is_w2_verb_or_adv = (w2_lower.ends_with("ed")
                        || w2_lower.ends_with("ly")
                        || w2_lower.ends_with("ing")
                        || matches!(
                            w2_lower.as_str(),
                            "delay"
                                | "delayed"
                                | "complained"
                                | "reported"
                                | "approved"
                                | "rejected"
                                | "urgently"
                                | "immediately"
                                | "called"
                                | "sent"
                                | "said"
                                | "tells"
                                | "asks"
                                | "asked"
                        ))
                        && !PROTECTED_SURNAMES.contains(w2_lower.as_str());

                    let is_w2_stopword = (!is_nobiliary_w2
                        && LOWERCASE_STOPWORDS.contains(w2_lower.as_str()))
                        || ROLE_NOUN_BLOCKLIST.contains(w2)
                        || TECH_AND_COMMON_STOPWORDS.contains(w2)
                        || is_w2_verb_or_adv;

                    if is_w2_stopword {
                        // Drop w2 and w3, keep w1
                        end = start + w1.len();
                        candidate_text = w1.to_string();
                    } else {
                        // w2 is part of the name. Now check w3
                        let is_w3_verb_or_adv = (w3_lower.ends_with("ed")
                            || w3_lower.ends_with("ly")
                            || w3_lower.ends_with("ing")
                            || matches!(
                                w3_lower.as_str(),
                                "yesterday"
                                    | "today"
                                    | "tomorrow"
                                    | "now"
                                    | "urgently"
                                    | "immediately"
                                    | "delay"
                                    | "delayed"
                                    | "complained"
                                    | "reported"
                            ))
                            && !PROTECTED_SURNAMES.contains(w3_lower.as_str());

                        let should_drop_w3 = LOWERCASE_STOPWORDS.contains(w3_lower.as_str())
                            || ROLE_NOUN_BLOCKLIST.contains(w3)
                            || TECH_AND_COMMON_STOPWORDS.contains(w3)
                            || is_w3_verb_or_adv;

                        if should_drop_w3 {
                            end = start + w1.len() + 1 + w2.len();
                            candidate_text = format!("{} {}", w1, w2);
                        } else {
                            candidate_text = format!("{} {} {}", w1, w2, w3);
                        }
                    }
                } else if words.len() == 2 {
                    let w1 = words[0];
                    let w2 = words[1];
                    let w1_lower = w1.to_lowercase();
                    let w2_lower = w2.to_lowercase();

                    if LOWERCASE_STOPWORDS.contains(w1_lower.as_str())
                        || ROLE_NOUN_BLOCKLIST.contains(w1)
                        || TECH_AND_COMMON_STOPWORDS.contains(w1)
                    {
                        continue;
                    }

                    let is_nobiliary_w2 = matches!(
                        w2_lower.as_str(),
                        "van"
                            | "von"
                            | "de"
                            | "da"
                            | "del"
                            | "della"
                            | "der"
                            | "den"
                            | "di"
                            | "du"
                            | "al"
                            | "el"
                            | "ibn"
                            | "bin"
                            | "la"
                    );

                    let is_w2_verb_or_adv = (w2_lower.ends_with("ed")
                        || w2_lower.ends_with("ly")
                        || w2_lower.ends_with("ing")
                        || matches!(
                            w2_lower.as_str(),
                            "delay"
                                | "delayed"
                                | "complained"
                                | "reported"
                                | "approved"
                                | "rejected"
                                | "urgently"
                                | "immediately"
                                | "called"
                                | "sent"
                                | "said"
                                | "tells"
                                | "asks"
                                | "asked"
                        ))
                        && !PROTECTED_SURNAMES.contains(w2_lower.as_str());

                    let should_drop_w2 = (!is_nobiliary_w2
                        && LOWERCASE_STOPWORDS.contains(w2_lower.as_str()))
                        || ROLE_NOUN_BLOCKLIST.contains(w2)
                        || TECH_AND_COMMON_STOPWORDS.contains(w2)
                        || is_w2_verb_or_adv;

                    if should_drop_w2 {
                        // Drop w2, keep w1
                        end = start + w1.len();
                        candidate_text = w1.to_string();
                    }
                } else if words.len() == 1 {
                    let w = words[0];
                    let w_lower = w.to_lowercase();
                    if LOWERCASE_STOPWORDS.contains(w_lower.as_str())
                        || ROLE_NOUN_BLOCKLIST.contains(w)
                        || TECH_AND_COMMON_STOPWORDS.contains(w)
                    {
                        continue;
                    }
                } else {
                    continue;
                }

                if is_span_covered(start, end, confirmed_spans)
                    || candidates.iter().any(|c| start < c.end && end > c.start)
                {
                    continue;
                }

                candidates.push(AmbiguousCandidate {
                    start,
                    end,
                    text: candidate_text,
                    needs_synthetic_casing: true,
                });
            }
        }

        // 4. Single-word Greek morphological matches demoted to Track B (requires ONNX confirmation)
        for mat in GREEK_MORPHOLOGICAL_RE.find_iter(text) {
            let start = mat.start();
            let end = mat.end();
            let word = mat.as_str();
            let word_lower = word.to_lowercase();
            if LOWERCASE_STOPWORDS.contains(word_lower.as_str())
                || ROLE_NOUN_BLOCKLIST.contains(word)
                || TECH_AND_COMMON_STOPWORDS.contains(word)
            {
                continue;
            }
            if !is_span_covered(start, end, confirmed_spans)
                && !candidates.iter().any(|c| start < c.end && end > c.start)
            {
                candidates.push(AmbiguousCandidate {
                    start,
                    end,
                    text: word.to_string(),
                    needs_synthetic_casing: word.chars().next().is_some_and(|c| c.is_lowercase()),
                });
            }
        }

        candidates
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
