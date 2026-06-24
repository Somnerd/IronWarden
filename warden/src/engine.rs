use iw_core::{ScrubbingReport, Redaction, EnforcementAction, TokenMap, SovereignError, PiiShield, SessionContext, PotentialMiss, PiiCategory, GroundingShield};
use crate::normalize::Normalizer;
use crate::shadow_ner::ShadowNer;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::Regex;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Instant;
use async_trait::async_trait;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::{Aead, Payload}};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;
use rand::RngCore;
use secrecy::ExposeSecret;
use std::sync::LazyLock;

const SEMANTIC_CACHE_THRESHOLD: f64 = 0.95;

static INJECTION_BLOCKLIST: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(vec![
            "systemoverride",
            "ignorepreviousinstructions",
            "disregardinstructions",
            "bypassconstraints",
            "systemprompt",
            "youarenow",
            "forgetall",
            "printyour",
        ])
        .unwrap()
});

use serde::Serialize;

#[derive(Serialize)]
struct GuardrailPayload<'a> {
    prompt: &'a str,
}

async fn check_ml_sidecar(input: &str) -> Result<bool, SovereignError> {
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    let socket_path = "/tmp/warden_llamaguard.sock";
    
    if !std::path::Path::new(socket_path).exists() {
        return Ok(false); 
    }

    match tokio::time::timeout(
        std::time::Duration::from_millis(100),
        tokio::net::UnixStream::connect(socket_path)
    ).await {
        Ok(Ok(mut stream)) => {
            let payload_struct = GuardrailPayload { prompt: input };
            let payload = serde_json::to_string(&payload_struct)
                .map_err(|_| SovereignError::InternalError("Failed to serialize Guardrail payload".into()))?;
            
            if tokio::time::timeout(
                std::time::Duration::from_millis(100),
                stream.write_all(payload.as_bytes())
            ).await.is_ok() {
                let mut buf = [0u8; 1024];
                if let Ok(Ok(n)) = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    stream.read(&mut buf)
                ).await {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    if response.contains("BLOCKED") {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        _ => {
            Err(SovereignError::InternalError("ML Guardrail Sidecar unreachable".into()))
        }
    }
}

pub struct WardenEngine {
    dictionary_automaton: AhoCorasick,
    individual_regexes: Vec<Regex>,
    rule_ids: Vec<String>,
    rule_actions: Vec<EnforcementAction>,
    rule_categories: Vec<PiiCategory>,
    shadow_ner: ShadowNer,
    dict_pattern_count: usize,
    ai: Option<crate::ai::HybridNerPool>,
    confidence_threshold: f64,
    cipher: Aes256Gcm,
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
        let key = Key::<Aes256Gcm>::from(key_bytes);
        let cipher = Aes256Gcm::new(&key);
        key_bytes.zeroize();

        let mut dict_patterns = Vec::new();
        let mut dict_ids = Vec::new();
        let mut dict_actions = Vec::new();
        let mut dict_categories = Vec::new();
        for (id, pat, action, category) in dictionary_rules {
            dict_ids.push(id);
            // --- SECURITY FIX (V-13): Normalize dictionary patterns ---
            let norm_ascii = Normalizer::with_normalized(&pat, |norm| norm.normalized_ascii.clone());
            dict_patterns.push(norm_ascii);
            dict_actions.push(action);
            dict_categories.push(category);
        }

        let mut individual_regexes = Vec::new();
        let mut regex_ids = Vec::new();
        let mut regex_actions = Vec::new();
        let mut regex_categories = Vec::new();
        for (id, pat, action, category) in patterns_rules {
            let re = Regex::new(&pat)
                .map_err(|e| SovereignError::ConfigError(format!("Failed to compile regex pattern {}: {}", id, e)))?;
            individual_regexes.push(re);
            regex_ids.push(id);
            regex_actions.push(action);
            regex_categories.push(category);
        }

        let dict_pattern_count = dict_patterns.len();
        let dictionary_automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(dict_patterns)
            .map_err(|e| SovereignError::ConfigError(format!("Failed to build AC automaton: {}", e)))?;

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

#[derive(Clone, Debug)]
struct UnifiedMatch {
    start: usize,
    end: usize,
    text: bytes::Bytes,
    rule_id: String,
    is_confirmed: bool,
    action: EnforcementAction,
    category: PiiCategory,
}

fn is_standalone_word(text: &str, sub: &str) -> bool {
    if let Some(idx) = text.find(sub) {
        let before_ok = !text[..idx].ends_with(|c: char| c.is_alphanumeric());
        let after_idx = idx + sub.len();
        let after_ok = !text[after_idx..].starts_with(|c: char| c.is_alphanumeric());
        before_ok && after_ok
    } else {
        false
    }
}

#[async_trait]
impl PiiShield for WardenEngine {
    async fn sanitize_prompt(
        &self,
        input_bytes: bytes::Bytes,
        session: Option<&SessionContext>,
    ) -> Result<ScrubbingReport, SovereignError> {
        let input = std::str::from_utf8(&input_bytes).unwrap_or("");
        
        let aggressive_normalized: String = input.chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>()
            .to_lowercase();

        if INJECTION_BLOCKLIST.is_match(&aggressive_normalized) {
            return Err(SovereignError::UnauthorizedAccess("Prompt injection attempt blocked by Layer 1 Heuristic Guardrail".into()));
        }

        if Self::check_shannon_entropy_smuggling(input) {
            return Err(SovereignError::UnauthorizedAccess("Prompt injection attempt blocked by Layer 1.5 Entropy Guardrail (Token Smuggling)".into()));
        }

        if check_ml_sidecar(input).await? {
            return Err(SovereignError::UnauthorizedAccess("Prompt injection attempt blocked by Layer 2 ML Guardrail".into()));
        }

        let start_time = Instant::now();
        
        // --- SYNCHRONOUS PHASE ---
        let (mut final_matches, potential_misses, offset_map) = Normalizer::with_normalized(input, |norm_res| {
            let normalized = &norm_res.normalized_unicode;
            let offset_map = norm_res.unicode_to_original.clone();
            
            let mut matches = Vec::new();

            for mat in self.dictionary_automaton.find_iter(normalized) {
                let pid = mat.pattern().as_usize();
                let is_person = self.rule_categories[pid] == PiiCategory::IndividualName;
                
                let match_str = &normalized[mat.start()..mat.end()];
                let valid = if is_person {
                    is_standalone_word(normalized, match_str)
                } else {
                    true
                };

                if valid {
                    let orig_start = offset_map.get_original_offset(mat.start());
                    let orig_end = offset_map.get_original_offset(mat.end());
                    matches.push(UnifiedMatch {
                        start: mat.start(),
                        end: mat.end(),
                        text: input_bytes.slice(orig_start..orig_end),
                        rule_id: self.rule_ids[pid].clone(),
                        is_confirmed: false,
                        action: self.rule_actions[pid],
                        category: self.rule_categories[pid],
                    });
                }
            }

            for (idx, regex) in self.individual_regexes.iter().enumerate() {
                let actual_pid = self.dict_pattern_count + idx;
                for mat in regex.find_iter(normalized) {
                    let orig_start = offset_map.get_original_offset(mat.start());
                    let orig_end = offset_map.get_original_offset(mat.end());
                    matches.push(UnifiedMatch {
                        start: mat.start(),
                        end: mat.end(),
                        text: input_bytes.slice(orig_start..orig_end),
                        rule_id: self.rule_ids[actual_pid].clone(),
                        is_confirmed: false,
                        action: self.rule_actions[actual_pid],
                        category: self.rule_categories[actual_pid],
                    });
                }
            }

            matches.sort_by(|a, b| {
                match a.start.cmp(&b.start) {
                    std::cmp::Ordering::Equal => b.end.cmp(&a.end),
                    other => other,
                }
            });

            let mut merged_matches: Vec<UnifiedMatch> = Vec::new();
            for mut mat in matches {
                if let Some(last) = merged_matches.last_mut() {
                    if mat.start < last.end {
                        last.action = combine_actions(last.action, mat.action);
                        if !last.rule_id.contains(&mat.rule_id) {
                            last.rule_id.push('|');
                            last.rule_id.push_str(&mat.rule_id);
                        }
                        
                        if mat.end > last.end {
                            last.end = mat.end;
                            let orig_start = offset_map.get_original_offset(last.start);
                            let orig_end = offset_map.get_original_offset(last.end);
                            last.text = input_bytes.slice(orig_start..orig_end);
                        }
                        continue;
                    }
                }
                merged_matches.push(mat);
            }

            let mut final_m = Vec::new();
            let mut potential_m = Vec::new();

            for mat in merged_matches {
                if mat.action == EnforcementAction::Block || mat.action == EnforcementAction::AuditOnly {
                    final_m.push(mat);
                    continue;
                }

                let text_str = std::str::from_utf8(&mat.text).unwrap_or("");
                
                // --- Shadow NER Pass ---
                let shadow_matches = self.shadow_ner.analyze(&norm_res.normalized_unicode, &norm_res.normalized_ascii);
                
                let mut covered_by_shadow = false;
                for shadow in &shadow_matches {
                    let (orig_start, orig_end) = if shadow.is_ascii {
                        (norm_res.ascii_to_original.get_original_offset(shadow.start),
                         norm_res.ascii_to_original.get_original_offset(shadow.end))
                    } else {
                        (norm_res.unicode_to_original.get_original_offset(shadow.start),
                         norm_res.unicode_to_original.get_original_offset(shadow.end))
                    };
                    
                    let unicode_start = norm_res.original_to_unicode[orig_start];
                    let unicode_end = norm_res.original_to_unicode[orig_end];

                    if unicode_start <= mat.end && unicode_end >= mat.start {
                        covered_by_shadow = true;
                        break;
                    }
                }

                if covered_by_shadow {
                    final_m.push(mat);
                } else {
                    potential_m.push(PotentialMiss {
                        text: mat.text.clone(),
                        label: "NER_CANDIDATE".to_string(),
                        offset: mat.start,
                    });
                }
            }

            (final_m, potential_m, offset_map)
        });

        // --- ASYNCHRONOUS PHASE ---
        if let Some(pool) = &self.ai {
            for miss in &potential_misses {
                if let Some(ai_entities) = pool.analyze_async(miss.text.clone()).await {
                    if let Some(ai_entity) = ai_entities.into_iter().max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal)) {
                        if ai_entity.score >= self.confidence_threshold {
                            final_matches.push(UnifiedMatch {
                                start: miss.offset,
                                end: miss.offset + std::str::from_utf8(&miss.text).unwrap_or("").len(),
                                text: miss.text.clone(),
                                rule_id: format!("ai_hybrid_{}", ai_entity.label),
                                is_confirmed: true,
                                action: EnforcementAction::Redact,
                                category: PiiCategory::HighConfidenceAi,
                            });
                        }
                    }
                }
            }
        }

        final_matches.sort_by(|a, b| {
            match a.start.cmp(&b.start) {
                std::cmp::Ordering::Equal => b.end.cmp(&a.end),
                other => other,
            }
        });

        let mut token_map = TokenMap::new();
        let mut redactions = Vec::new();
        let mut is_blocked = false;

        let mut output_bytes = bytes::BytesMut::with_capacity(input_bytes.len());
        let mut last_pos = 0;

        for mat in &final_matches {
            let orig_start = offset_map.get_original_offset(mat.start);
            let orig_end = offset_map.get_original_offset(mat.end);

            if orig_start < last_pos { continue; } 

            if mat.action == EnforcementAction::Block {
                is_blocked = true;
            }

            if mat.action == EnforcementAction::AuditOnly {
                redactions.push(Redaction {
                    rule_id: mat.rule_id.clone(),
                    action: mat.action,
                    offset: orig_start,
                    length: if orig_end >= orig_start { orig_end - orig_start } else { mat.text.len() },
                    placeholder: String::new(),
                    category: mat.category,
                });
                last_pos = orig_end;
                continue;
            }

            let text_str = std::str::from_utf8(&mat.text).unwrap_or("");
            
            let token = if let Some(ctx) = session {
                let text_lower = text_str.to_lowercase();
                
                let mut existing_token = None;
                let is_person_like = mat.category == PiiCategory::IndividualName || mat.category == PiiCategory::HighConfidenceAi;

                if is_person_like {
                    if let Some(t) = ctx.identities.get(&text_lower) {
                        existing_token = Some(t.clone());
                    } else if let Some((cached_label, cached_score)) = ctx.semantic_cache.get(&text_lower) {
                        if cached_score > self.confidence_threshold {
                            existing_token = Some(format!("[{}_1]", cached_label));
                        }
                    }
                } else if let Some(t) = ctx.pii_to_token.get(&text_lower) {
                    existing_token = Some(t.clone());
                }

                if let Some(t) = existing_token {
                    t
                } else {
                    let cat_str = match mat.category {
                        PiiCategory::IndividualName => "NAME",
                        PiiCategory::ContactInfo => "CONTACT",
                        PiiCategory::FinancialData => "FINANCIAL",
                        PiiCategory::IdentificationNumber => "ID",
                        PiiCategory::HighConfidenceAi => "AI_DETECTED",
                        PiiCategory::Location => "LOCATION",
                        PiiCategory::Organization => "ORG",
                        PiiCategory::InternalAsset => "ASSET",
                        PiiCategory::PotentialHeuristic => "HEURISTIC",
                        PiiCategory::Other => "OTHER",
                    };
                    format!("[{}_{}]", cat_str, token_map.len() + 1)
                }
            } else {
                format!("[TOKEN_{}]", token_map.len() + 1)
            };

            token_map.insert(token.clone(), text_str.to_string());
            
            redactions.push(Redaction {
                rule_id: mat.rule_id.clone(),
                action: mat.action,
                offset: orig_start,
                length: if orig_end >= orig_start { orig_end - orig_start } else { mat.text.len() },
                placeholder: token.clone(),
                category: mat.category,
            });

            output_bytes.extend_from_slice(&input_bytes[last_pos..orig_start]);
            output_bytes.extend_from_slice(token.as_bytes());
            
            last_pos = orig_end;
        }

        if last_pos < input_bytes.len() {
            output_bytes.extend_from_slice(&input_bytes[last_pos..]);
        }

        if is_blocked {
            let msg = format!("PROMPT BLOCKED. VIOLATIONS DETECTED: {:?}", redactions.iter().map(|r| &r.rule_id).collect::<Vec<_>>());
            output_bytes.clear();
            output_bytes.extend_from_slice(msg.as_bytes());
            token_map.clear();
        }

        Ok(ScrubbingReport {
            sanitized_text: output_bytes.into(),
            is_blocked,
            redactions,
            token_map,
            potential_misses,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
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

impl WardenEngine {
    fn check_shannon_entropy_smuggling(input: &str) -> bool {
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if Self::is_base64_char(bytes[i]) {
                let start = i;
                while i < bytes.len() && Self::is_base64_char(bytes[i]) {
                    i += 1;
                }
                let len = i - start;
                if len > 40 {
                    if Self::calculate_entropy(&bytes[start..i]) > 5.8 {
                        return true;
                    }
                }
            } else {
                i += 1;
            }
        }
        false
    }

    #[inline(always)]
    fn is_base64_char(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
    }

    fn calculate_entropy(data: &[u8]) -> f64 {
        let mut counts = [0usize; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let mut entropy = 0.0;
        let len = data.len() as f64;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

fn combine_actions(a: EnforcementAction, b: EnforcementAction) -> EnforcementAction {
    match (a, b) {
        (EnforcementAction::Block, _) | (_, EnforcementAction::Block) => EnforcementAction::Block,
        (EnforcementAction::Redact, _) | (_, EnforcementAction::Redact) => EnforcementAction::Redact,
        (EnforcementAction::Mask, _) | (_, EnforcementAction::Mask) => EnforcementAction::Mask,
        (EnforcementAction::AuditOnly, EnforcementAction::AuditOnly) => EnforcementAction::AuditOnly,
    }
}

impl GroundingShield for WardenEngine {
    fn seal_query(&self, query: &str, username: &str) -> Result<Vec<u8>, SovereignError> {
        let mut nonce_bytes = [0u8; 12];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // --- SECURITY FIX (V-19): Bind encryption to username via AAD ---
        let payload = Payload {
            msg: query.as_bytes(),
            aad: username.as_bytes(),
        };

        let ciphertext = self.cipher.encrypt(&nonce, payload)
            .map_err(|_| SovereignError::InternalError("Query sealing failed".into()))?;

        let mut blob = nonce_bytes.to_vec();
        blob.extend(ciphertext);
        Ok(blob)
    }

    fn unseal_query(&self, blob: &[u8], username: &str) -> Result<String, SovereignError> {
        if blob.len() < 12 {
            return Err(SovereignError::InternalError("Invalid sealed query blob".into()));
        }

        let (nonce_bytes, ciphertext) = blob.split_at(12);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(nonce_bytes);

        // --- SECURITY FIX (V-19): Bind decryption to username via AAD ---
        let payload = Payload {
            msg: ciphertext,
            aad: username.as_bytes(),
        };

        let plaintext = self.cipher.decrypt(nonce, payload)
            .map_err(|_| SovereignError::UnauthorizedAccess("Query unsealing failed: AAD mismatch or tampering".into()))?;

        String::from_utf8(plaintext)
            .map_err(|_| SovereignError::InternalError("Decrypted query is not valid UTF-8".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HeuristicConfig;

    #[tokio::test]
    async fn test_overlap_merging_correct_offsets() {
        let dict_rules = vec![
            ("DICT_NAME".to_string(), "John Doe".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName)
        ];
        
        let regex_rules = vec![
            ("REGEX_NAME".to_string(), "ohn".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName)
        ];

        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine = WardenEngine::new(dict_rules, regex_rules, vec![], None, 0.85, &pepper).unwrap();
        
        let report = engine.sanitize_prompt("Hello John Doe.".into(), None).await.unwrap();
        
        assert_eq!(report.redactions.len(), 1, "Should merge overlapping dict and regex matches");
        let red = &report.redactions[0];
        assert_eq!(red.offset, 6);
        assert_eq!(red.length, 8); // "John Doe" is longer and fully encapsulates "ohn"
        assert!(red.rule_id.contains("DICT_NAME")); // Longer match provides the rule ID
    }

    #[tokio::test]
    async fn test_overlap_merging_longest_match_wins() {
        let dict_rules = vec![
            ("DICT_SHORT".to_string(), "John".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName)
        ];
        
        let regex_rules = vec![
            ("REGEX_LONG".to_string(), "John Doe".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName)
        ];

        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine = WardenEngine::new(dict_rules, regex_rules, vec![], None, 0.85, &pepper).unwrap();
        let report = engine.sanitize_prompt("Hello John Doe.".into(), None).await.unwrap();
        
        assert_eq!(report.redactions.len(), 1);
        let red = &report.redactions[0];
        assert_eq!(red.length, 8); // "John Doe"
        assert_eq!(red.rule_id, "REGEX_LONG"); // Longer match wins
    }

    #[tokio::test]
    async fn test_v12_aho_corasick_overlap_bypass_repro() {
        let dict_rules = vec![
            ("REDACT_ALICE".to_string(), "Alice".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName),
            ("BLOCK_ALICE_SMITH".to_string(), "Alice Smith".to_string(), EnforcementAction::Block, PiiCategory::IndividualName)
        ];
        
        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine = WardenEngine::new(dict_rules, vec![], vec![], None, 0.85, &pepper).unwrap();
        let report = engine.sanitize_prompt("Hello Alice Smith.".into(), None).await.unwrap();
        
        // If the bug exists, report.is_blocked will be FALSE because 'Alice Smith' was masked by 'Alice'.
        assert!(report.is_blocked, "Should be blocked because 'Alice Smith' is a blocked entity");
    }

    #[tokio::test]
    async fn test_semantic_cache_bypass() {
        // We use an empty engine (no rules, no AI)
        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine = WardenEngine::new(vec![], vec![], vec![], None, 0.85, &pepper).unwrap();
        let session = SessionContext::new();
        
        // Manually prime the cache with a value that would be caught by ShadowNer (title case)
        session.semantic_cache.insert("alice smith".to_string(), ("PERSON".to_string(), 0.99));
        
        // Use a standalone name to avoid fusion with other words
        let report = engine.sanitize_prompt("Alice Smith is a person.".into(), Some(&session)).await.unwrap();
        
        // Normally, without AI, "Alice Smith" would be a potential miss.
        // With cache hit, it becomes a confirmed redaction.
        assert_eq!(report.redactions.len(), 1, "Should have 1 redaction from cache hit");
        let red = &report.redactions[0];
        assert_eq!(red.rule_id, "ai_cache_PERSON");
        assert_eq!(red.placeholder, "[TOKEN_1]");
        assert!(String::from_utf8_lossy(&report.sanitized_text).contains("[TOKEN_1]"));
        assert_eq!(report.potential_misses.len(), 0, "Should have no potential misses as it was confirmed by cache");
    }

    #[tokio::test]
    async fn test_overlap_merging_action_precedence() {
        let dict_rules = vec![
            ("AUDIT_ALICE".to_string(), "Alice".to_string(), EnforcementAction::AuditOnly, PiiCategory::IndividualName)
        ];
        
        let regex_rules = vec![
            ("REDACT_ALICE_SMITH".to_string(), "Alice Smith".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName)
        ];

        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine = WardenEngine::new(dict_rules, regex_rules, vec![], None, 0.85, &pepper).unwrap();
        let report = engine.sanitize_prompt("Hello Alice Smith.".into(), None).await.unwrap();
        
        assert_eq!(report.redactions.len(), 1);
        let red = &report.redactions[0];
        assert_eq!(red.action, EnforcementAction::Redact, "Redact must override AuditOnly in overlapping match");
        assert!(!String::from_utf8_lossy(&report.sanitized_text).contains("Alice"), "Alice must be redacted");
    }
}
