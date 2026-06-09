use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use iw_core::{PiiShield, SovereignError, TokenMap, ScrubbingReport, Redaction, EnforcementAction, SessionContext, PiiCategory};
use regex::Regex;
use std::collections::HashMap;
use std::time::Instant;

pub struct AhoCorasickShield {
    automaton: AhoCorasick,
    ssn_regex: Regex,
}

impl AhoCorasickShield {
    /// Creates a new AhoCorasickShield with a provided dynamic dictionary of terms and a predefined SSN pattern.
    pub fn new(dictionary: Vec<String>) -> Result<Self, SovereignError> {
        // --- SECURITY FIX (V-11): Robust SSN Pattern ---
        let ssn_regex = Regex::new(r"\d{3}[- ]?\d{2}[- ]?\d{4}")
            .map_err(|e| SovereignError::ConfigError(format!("Failed to build SSN regex: {}", e)))?;
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(dictionary)
            .map_err(|e| SovereignError::ConfigError(format!("Failed to build AC automaton: {}", e)))?;

        Ok(Self {
            automaton,
            ssn_regex,
        })
    }
}

impl PiiShield for AhoCorasickShield {
    fn sanitize_prompt(
        &self,
        prompt: &str,
        _session: Option<&SessionContext>,
    ) -> Result<ScrubbingReport, SovereignError> {
        let start_time = Instant::now();
        
        // --- Stage 0: Normalization (Bypass Protection) ---
        let norm_res = crate::normalize::Normalizer::normalize(prompt);
        // --- SECURITY FIX (V-07): Use ASCII normalization to prevent homoglyph bypasses ---
        let normalized_prompt = &norm_res.normalized_ascii;
        let offset_map = &norm_res.ascii_to_original;

        let mut token_map = TokenMap::new();
        let mut redactions = Vec::new();
        let is_blocked = false;

        // --- Step 1: Scan for SSN Pattern using Regex ---
        let mut ssn_counter = 0;
        let ssn_sanitized = self.ssn_regex.replace_all(&normalized_prompt, |caps: &regex::Captures| {
            ssn_counter += 1;
            let token = format!("[SSN_{}]", ssn_counter);
            let matched_text = caps.get(0).map(|m| m.as_str()).unwrap_or("").to_string();
            
            let m = caps.get(0);
            let start = m.map(|m| m.start()).unwrap_or(0);
            let end = m.map(|m| m.end()).unwrap_or(0);
            let orig_start = offset_map.get_original_offset(start);
            let orig_end = offset_map.get_original_offset(end);

            redactions.push(Redaction {
                rule_id: "regex_ssn".into(),
                action: EnforcementAction::Redact,
                offset: orig_start,
                length: if orig_end >= orig_start { orig_end - orig_start } else { 0 },
                placeholder: token.clone(),
                category: PiiCategory::IdentificationNumber,
            });

            token_map.insert(token.clone(), matched_text);
            token
        });

        // --- Step 2: Scan for Dictionary Terms using Aho-Corasick ---
        let mut term_counter = 0;
        let mut final_result = String::new();
        let mut last_end = 0;
        let mut original_to_token: HashMap<String, String> = HashMap::new();

        for mat in self.automaton.find_iter(&*ssn_sanitized) {
            final_result.push_str(&ssn_sanitized[last_end..mat.start()]);
            let original_text = &ssn_sanitized[mat.start()..mat.end()];
            
            let token = original_to_token.entry(original_text.to_string()).or_insert_with(|| {
                term_counter += 1;
                let t = format!("[TERM_{}]", term_counter);
                token_map.insert(t.clone(), original_text.to_string());
                t
            });

            redactions.push(Redaction {
                rule_id: "dict_match".into(),
                action: EnforcementAction::Redact,
                offset: mat.start(), // Note: These offsets are relative to ssn_sanitized, still drifted
                length: original_text.len(),
                placeholder: token.clone(),
                category: PiiCategory::Other,
            });

            final_result.push_str(token);
            last_end = mat.end();
        }
        
        final_result.push_str(&ssn_sanitized[last_end..]);

        Ok(ScrubbingReport {
            sanitized_text: final_result,
            is_blocked, 
            redactions,
            token_map,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
            potential_misses: Vec::new(),
        })
    }

    fn restore_prompt(&self, response: &str, map: &TokenMap) -> Result<String, SovereignError> {
        if map.is_empty() { return Ok(response.to_string()); }

        let keys: Vec<&String> = map.keys().collect();
        let values: Vec<&String> = map.values().collect();

        let ac = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(&keys)
            .map_err(|e| SovereignError::InternalError(e.to_string()))?;

        let result = ac.replace_all(response, &values);

        Ok(result)
    }
}
