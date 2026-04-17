use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use iw_core::{PiiShield, SovereignError, TokenMap};
use regex::Regex;
use std::collections::HashMap;

pub struct AhoCorasickShield {
    automaton: AhoCorasick,
    ssn_regex: Regex,
}

impl AhoCorasickShield {
    /// Creates a new AhoCorasickShield with a provided dynamic dictionary of terms and a predefined SSN pattern.
    pub fn new(dictionary: Vec<String>) -> Self {
        // Regex for standard US Social Security Number pattern: ###-##-####
        let ssn_regex = Regex::new(r"\d{3}-\d{2}-\d{4}").expect("Critical: Failed to build SSN regex");

        // Building the AhoCorasick automaton from the dynamic dictionary provided by the user
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(dictionary)
            .expect("Critical: Failed to build AhoCorasick automaton from dictionary");

        Self {
            automaton,
            ssn_regex,
        }
    }
}

impl PiiShield for AhoCorasickShield {
    fn sanitize_prompt(&self, prompt: &str) -> Result<(String, TokenMap), SovereignError> {
        let mut token_map = TokenMap::new();

        // --- Step 1: Scan for SSN Pattern using Regex ---
        // This runs first to prioritize patterned identifiers over dictionary terms.
        let mut ssn_counter = 0;
        let ssn_sanitized = self.ssn_regex.replace_all(prompt, |caps: &regex::Captures| {
            ssn_counter += 1;
            let token = format!("[SSN_{}]", ssn_counter);
            token_map.insert(token.clone(), caps[0].to_string());
            token
        });

        // --- Step 2: Scan for Dictionary Terms using Aho-Corasick ---
        // Runs on the output of Step 1.
        let mut term_counter = 0;
        let mut final_result = String::new();
        let mut last_end = 0;
        
        // Tracking to keep token usage consistent for multiple occurrences of the same word
        let mut original_to_token: HashMap<String, String> = HashMap::new();

        for mat in self.automaton.find_iter(&*ssn_sanitized) {
            // Fill in the text between the last match and current match
            final_result.push_str(&ssn_sanitized[last_end..mat.start()]);
            
            let original_text = &ssn_sanitized[mat.start()..mat.end()];
            
            // Map each unique dictionary hit to a generic token [TERM_n]
            let token = original_to_token.entry(original_text.to_string()).or_insert_with(|| {
                term_counter += 1;
                let t = format!("[TERM_{}]", term_counter);
                token_map.insert(t.clone(), original_text.to_string());
                t
            });

            final_result.push_str(token);
            last_end = mat.end();
        }
        
        // Finalize the string
        final_result.push_str(&ssn_sanitized[last_end..]);

        Ok((final_result, token_map))
    }

    fn restore_prompt(&self, response: &str, map: &TokenMap) -> Result<String, SovereignError> {
        let mut restored = response.to_string();
        
        // SAFETY DIRECTIVE: Sort keys by length in descending order.
        // This prevents [TERM_1] from accidentally replacing part of [TERM_10].
        let mut sorted_keys: Vec<&String> = map.keys().collect();
        sorted_keys.sort_by(|a, b| b.len().cmp(&a.len()));

        for token in sorted_keys {
            if let Some(original) = map.get(token) {
                restored = restored.replace(token, original);
            }
        }
        
        Ok(restored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pii_shield_scanning_multimodal() {
        // Provided dictionary from directive
        let dict = vec!["Alice".to_string(), "Project Vault".to_string()];
        let shield = AhoCorasickShield::new(dict);
        
        // Mixed text including SSN and dictionary terms with varied casing
        let prompt = "Greeting from Alice. Her SSN is 111-22-3333. She is assigned to project vault.";
        
        let (sanitized, token_map) = shield.sanitize_prompt(prompt).unwrap();
        
        // Verify tokenization
        // [TERM_1] Alice
        // [SSN_1] 111-22-3333
        // [TERM_2] project vault
        assert!(sanitized.contains("[TERM_1]"));
        assert!(sanitized.contains("[TERM_2]"));
        assert!(sanitized.contains("[SSN_1]"));
        
        // verify no residual sensitivity
        assert!(!sanitized.to_lowercase().contains("alice"));
        assert!(!sanitized.to_lowercase().contains("project vault"));
        assert!(!sanitized.contains("111-22-3333"));
        
        // Verify restoration is perfect
        let restored = shield.restore_prompt(&sanitized, &token_map).unwrap();
        assert_eq!(restored, prompt);
    }
}
