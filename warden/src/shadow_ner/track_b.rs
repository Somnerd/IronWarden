use super::patterns::*;
use super::{AmbiguousCandidate, ShadowNer};

impl ShadowNer {
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
}
