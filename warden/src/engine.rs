use iw_core::{ScrubbingReport, Redaction, EnforcementAction, TokenMap, SovereignError, PiiShield, SessionContext, PotentialMiss, PiiCategory, GroundingShield};
use crate::normalize::Normalizer;
use crate::shadow_ner::ShadowNer;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::Regex;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Instant;
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

fn check_ml_sidecar(input: &str) -> Result<bool, SovereignError> {
    use std::io::{Write, Read};
    let socket_path = "/tmp/warden_llamaguard.sock";
    
    if !std::path::Path::new(socket_path).exists() {
        return Ok(false); 
    }

    match std::os::unix::net::UnixStream::connect(socket_path) {
        Ok(mut stream) => {
            stream.set_read_timeout(Some(std::time::Duration::from_millis(100))).ok();
            stream.set_write_timeout(Some(std::time::Duration::from_millis(100))).ok();
            
            let payload_struct = GuardrailPayload { prompt: input };
            let payload = serde_json::to_string(&payload_struct)
                .map_err(|_| SovereignError::InternalError("Failed to serialize Guardrail payload".into()))?;

            if stream.write_all(payload.as_bytes()).is_ok() {
                let mut buf = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buf) {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    if response.contains("BLOCKED") {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        Err(_) => {
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
            let norm = Normalizer::normalize(&pat);
            dict_patterns.push(norm.normalized_ascii);
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
    text: String,
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

impl PiiShield for WardenEngine {
    fn sanitize_prompt(
        &self,
        input: &str,
        session: Option<&SessionContext>,
    ) -> Result<ScrubbingReport, SovereignError> {
        // --- SECURITY FIX (Finding 4): Dual-Layer Prompt Injection Guardrails ---
        // Layer 1: Robust Heuristic Tree
        let aggressive_normalized: String = input.chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>()
            .to_lowercase();

        if INJECTION_BLOCKLIST.is_match(&aggressive_normalized) {
            return Err(SovereignError::UnauthorizedAccess("Prompt injection attempt blocked by Layer 1 Heuristic Guardrail".into()));
        }

        // Layer 2: ML Classifier Sidecar
        if check_ml_sidecar(input)? {
            return Err(SovereignError::UnauthorizedAccess("Prompt injection attempt blocked by Layer 2 ML Guardrail".into()));
        }

        let start_time = Instant::now();
        let norm_res = Normalizer::normalize(input);
        
        let normalized = &norm_res.normalized_unicode;
        let offset_map = &norm_res.unicode_to_original;
        
        let mut token_map = TokenMap::new();
        let mut redactions = Vec::new();
        let mut potential_misses = Vec::new();
        let mut is_blocked = false;
        
        let mut all_confirmed: Vec<UnifiedMatch> = Vec::new();
        let mut all_potentials: Vec<UnifiedMatch> = Vec::new();

        // 1. Collect Dictionary Matches (on ASCII for homoglyphs)
        for mat in self.dictionary_automaton.find_overlapping_iter(&norm_res.normalized_ascii) {
            // Word boundary enforcement for dictionary matches
            let before_ok = mat.start() == 0 || !norm_res.normalized_ascii[..mat.start()].ends_with(|c: char| c.is_alphanumeric());
            let after_ok = mat.end() == norm_res.normalized_ascii.len() || !norm_res.normalized_ascii[mat.end()..].starts_with(|c: char| c.is_alphanumeric());
            if !before_ok || !after_ok {
                continue;
            }

            let idx = mat.pattern().as_usize();
            if let (Some(id), Some(action), Some(category)) = (self.rule_ids.get(idx), self.rule_actions.get(idx), self.rule_categories.get(idx)) {
                // Map ASCII offsets to Original, then to Unicode
                let orig_start = norm_res.ascii_to_original.get_original_offset(mat.start());
                let orig_end = norm_res.ascii_to_original.get_original_offset(mat.end());
                
                let unicode_start = norm_res.original_to_unicode[orig_start];
                let unicode_end = norm_res.original_to_unicode[orig_end];

                all_confirmed.push(UnifiedMatch {
                    start: unicode_start,
                    end: unicode_end,
                    text: normalized[unicode_start..unicode_end].to_string(),
                    rule_id: id.clone(),
                    is_confirmed: true,
                    action: *action,
                    category: *category,
                });
            }
        }

        // 1b. Collect Dictionary Matches (on Stripped for flexible separators)
        // --- SECURITY FIX (Section 2.2 / Finding B.2): Flexible Separator Evasion ---
        for mat in self.dictionary_automaton.find_overlapping_iter(&norm_res.stripped) {
            let idx = mat.pattern().as_usize();
            if let (Some(id), Some(action), Some(category)) = (self.rule_ids.get(idx), self.rule_actions.get(idx), self.rule_categories.get(idx)) {
                // Map Stripped offsets to Original, then to Unicode
                let orig_start = norm_res.stripped_to_original.get_original_offset(mat.start());
                let orig_end = if mat.end() > mat.start() {
                    let last_stripped_idx = mat.end() - 1;
                    let orig_last = norm_res.stripped_to_original.get_original_offset(last_stripped_idx);
                    if orig_last < input.len() {
                        let char_len = input[orig_last..].chars().next().map_or(1, |c| c.len_utf8());
                        orig_last + char_len
                    } else {
                        input.len()
                    }
                } else {
                    orig_start
                };
                
                let unicode_start = norm_res.original_to_unicode[orig_start];
                let unicode_end = norm_res.original_to_unicode[orig_end];

                // Enforce word boundaries on the original input for flexible matching
                let has_before = input[..orig_start]
                    .chars()
                    .rev()
                    .take_while(|c| !c.is_whitespace())
                    .any(|c| c.is_alphanumeric());

                let has_after = input[orig_end..]
                    .chars()
                    .take_while(|c| !c.is_whitespace())
                    .any(|c| c.is_alphanumeric());
                if has_before || has_after {
                    continue;
                }

                all_confirmed.push(UnifiedMatch {
                    start: unicode_start,
                    end: unicode_end,
                    text: normalized[unicode_start..unicode_end].to_string(),
                    rule_id: format!("{}_flexible", id),
                    is_confirmed: true,
                    action: *action,
                    category: *category,
                });
            }
        }

        // 2. Collect Regex Pattern Matches (on Unicode for accuracy)
        // --- SECURITY FIX (V-12): Overlapping Regex Scan ---
        for (idx, re) in self.individual_regexes.iter().enumerate() {
            let absolute_idx = self.dict_pattern_count + idx;
            let id = &self.rule_ids[absolute_idx];
            let action = self.rule_actions[absolute_idx];
            let category = self.rule_categories[absolute_idx];

            for mat in re.find_iter(normalized) {
                all_confirmed.push(UnifiedMatch {
                    start: mat.start(),
                    end: mat.end(),
                    text: mat.as_str().to_string(),
                    rule_id: id.clone(),
                    is_confirmed: true,
                    action,
                    category,
                });
            }
        }

        // 2b. Collect Regex Pattern Matches (on ASCII for homoglyph bypasses)
        // --- SECURITY FIX (V-12 & V-15): Overlapping ASCII Regex Scan ---
        for (idx, re) in self.individual_regexes.iter().enumerate() {
            let absolute_idx = self.dict_pattern_count + idx;
            let id = &self.rule_ids[absolute_idx];
            let action = self.rule_actions[absolute_idx];
            let category = self.rule_categories[absolute_idx];

            for mat in re.find_iter(&norm_res.normalized_ascii) {
                // Map ASCII offsets to Original, then to Unicode for consistent internal state
                let orig_start = norm_res.ascii_to_original.get_original_offset(mat.start());
                let orig_end = norm_res.ascii_to_original.get_original_offset(mat.end());
                
                let unicode_start = norm_res.original_to_unicode[orig_start];
                let unicode_end = norm_res.original_to_unicode[orig_end];

                // --- SECURITY FIX: Deduplicate against Unicode pass ---
                let is_duplicate = all_confirmed.iter().any(|m| {
                    m.start == unicode_start && m.end == unicode_end && m.rule_id == *id
                });
                
                if !is_duplicate {
                    all_confirmed.push(UnifiedMatch {
                        start: unicode_start,
                        end: unicode_end,
                        text: normalized[unicode_start..unicode_end].to_string(),
                        rule_id: format!("{}_ascii", id),
                        is_confirmed: true,
                        action,
                        category,
                    });
                }
            }
        }

        // 3. Shadow NER Pass (Dual track: ASCII for homoglyph resilience, Unicode for script awareness)
        let shadow_matches = self.shadow_ner.analyze(&norm_res.normalized_unicode, &norm_res.normalized_ascii);
        
        for shadow in shadow_matches {
            // Map offsets to Original, then to Unicode
            let (orig_start, orig_end) = if shadow.is_ascii {
                (norm_res.ascii_to_original.get_original_offset(shadow.start),
                 norm_res.ascii_to_original.get_original_offset(shadow.end))
            } else {
                (norm_res.unicode_to_original.get_original_offset(shadow.start),
                 norm_res.unicode_to_original.get_original_offset(shadow.end))
            };
            
            let unicode_start = norm_res.original_to_unicode[orig_start];
            let unicode_end = norm_res.original_to_unicode[orig_end];

            let is_covered = all_confirmed.iter().any(|m| {
                unicode_start < m.end && unicode_end > m.start
            });
            if is_covered { continue; }

            // ASCII equivalent for caching
            let ascii_start = norm_res.original_to_ascii[orig_start];
            let ascii_end = norm_res.original_to_ascii[orig_end];
            let ascii_text = norm_res.normalized_ascii[ascii_start..ascii_end].to_string();

            let miss = PotentialMiss {
                text: normalized[unicode_start..unicode_end].to_string(),
                offset: orig_start,
                label: shadow.label.clone(),
            };

            // --- WP #77: SEMANTIC CACHE CHECK (0.1ms bypass) ---
            let mut cache_hit = None;
            if let Some(ctx) = session {
                let cache_key = ascii_text.to_lowercase();
                if let Some((label, score)) = ctx.semantic_cache.get(&cache_key) {
                    if score >= SEMANTIC_CACHE_THRESHOLD {
                        cache_hit = Some((label, score));
                    }
                }
            }

            if let Some((label, _score)) = cache_hit {
                all_confirmed.push(UnifiedMatch {
                    start: unicode_start,
                    end: unicode_end,
                    text: miss.text,
                    rule_id: format!("ai_cache_{}", label),
                    is_confirmed: true,
                    action: shadow.action,
                    category: PiiCategory::HighConfidenceAi,
                });
                continue;
            }
            // --------------------------------------------------

            if shadow.action == EnforcementAction::AuditOnly {
                all_confirmed.push(UnifiedMatch {
                    start: unicode_start,
                    end: unicode_end,
                    text: miss.text,
                    rule_id: shadow.label.clone(),
                    is_confirmed: true,
                    action: shadow.action,
                    category: shadow.category,
                });
                continue;
            }

            let should_force_promote = shadow.category == PiiCategory::IndividualName;

            if let Some(pool) = &self.ai {
                if let Some(ai_instance) = pool.get() {
                    if let Some(ai_entity) = ai_instance.validate_miss(&miss, &normalized, session) {
                        if ai_entity.score >= self.confidence_threshold || should_force_promote {
                            // --- WP #77: SEMANTIC CACHE INSERT ---
                            if let Some(ctx) = session {
                                if ai_entity.score >= SEMANTIC_CACHE_THRESHOLD {
                                    ctx.semantic_cache.insert(ascii_text.to_lowercase(), (ai_entity.label.clone(), ai_entity.score));
                                }
                            }
                            // ------------------------------------
                            all_confirmed.push(UnifiedMatch {
                                start: unicode_start,
                                end: unicode_end,
                                text: miss.text,
                                rule_id: format!("ai_hybrid_{}", shadow.label),
                                is_confirmed: true,
                                action: shadow.action,
                                category: PiiCategory::HighConfidenceAi,
                            });
                        } else {
                            all_potentials.push(UnifiedMatch {
                                start: unicode_start,
                                end: unicode_end,
                                text: miss.text,
                                rule_id: shadow.label.clone(),
                                is_confirmed: false,
                                action: shadow.action,
                                category: shadow.category,
                            });
                        }
                    } else if should_force_promote {
                         all_confirmed.push(UnifiedMatch {
                            start: unicode_start,
                            end: unicode_end,
                            text: miss.text,
                            rule_id: format!("heuristic_promotion_{}", shadow.label),
                            is_confirmed: true,
                            action: shadow.action,
                            category: PiiCategory::IndividualName,
                        });
                    } else {
                        all_potentials.push(UnifiedMatch {
                            start: unicode_start,
                            end: unicode_end,
                            text: miss.text,
                            rule_id: shadow.label.clone(),
                            is_confirmed: false,
                            action: shadow.action,
                            category: shadow.category,
                        });
                    }
                    pool.release(ai_instance);
                } else {
                    // Pool timeout - fall back to force promote if applicable
                    if should_force_promote {
                         all_confirmed.push(UnifiedMatch {
                            start: unicode_start,
                            end: unicode_end,
                            text: miss.text,
                            rule_id: format!("pool_timeout_promotion_{}", shadow.label),
                            is_confirmed: true,
                            action: shadow.action,
                            category: PiiCategory::IndividualName,
                        });
                    }
                }
            } else if should_force_promote {
                all_confirmed.push(UnifiedMatch {
                    start: unicode_start,
                    end: unicode_end,
                    text: miss.text,
                    rule_id: format!("heuristic_promotion_{}", shadow.label),
                    is_confirmed: true,
                    action: shadow.action,
                    category: PiiCategory::IndividualName,
                });
            } else {
                all_potentials.push(UnifiedMatch {
                    start: unicode_start,
                    end: unicode_end,
                    text: miss.text,
                    rule_id: shadow.label.clone(),
                    is_confirmed: false,
                    action: shadow.action,
                    category: shadow.category,
                });
            }
        }

        // 4. Resolve Overlaps & Sort Timeline
        all_confirmed.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)));

        // --- GLOBAL IDENTITY FIX: Aggressive confirmed+potential fusion ---
        let mut final_matches: Vec<UnifiedMatch> = Vec::new();
        for mat in all_confirmed {
            let mut merged = mat;
            
            // Look forward for adjacent potentials
            loop {
                let current_end = merged.end;
                if let Some(pos) = all_potentials.iter().position(|p| {
                    if p.start < current_end { return false; }
                    let gap = &normalized[current_end..p.start];
                    gap.trim().is_empty() || gap == ", " || gap == " bin " || gap == " al " || gap == " da " || gap == " de " || gap == " van " || gap == " von "
                }) {
                    let pot = all_potentials.remove(pos);
                    let gap = &normalized[merged.end..pot.start];
                    merged.end = pot.end;
                    merged.text.push_str(gap);
                    merged.text.push_str(&pot.text);
                    merged.rule_id = format!("{}+fused", merged.rule_id);
                    merged.action = combine_actions(merged.action, pot.action);
                } else {
                    break;
                }
            }
            
            if let Some(last) = final_matches.last_mut() {
                if merged.start >= last.end {
                    let gap = &normalized[last.end..merged.start];
                    if gap.trim().is_empty() || gap == ", " {
                        last.end = merged.end;
                        last.text.push_str(gap);
                        last.text.push_str(&merged.text);
                        last.rule_id = format!("{}+{}", last.rule_id, merged.rule_id);
                        last.action = combine_actions(last.action, merged.action);
                        continue;
                    }
                } else {
                    // It's an overlap. We merge them.
                    let last_len = last.end - last.start;
                    let merged_len = merged.end - merged.start;
                    
                    if merged.end > last.end {
                        let overlap_start = last.end - merged.start;
                        if overlap_start < merged.text.len() {
                            last.text.push_str(&merged.text[overlap_start..]);
                        }
                    }
                    
                    // The rule_id should belong to whichever match was longer (more specific)
                    if merged_len > last_len {
                        last.rule_id = merged.rule_id.clone();
                    } else if merged_len == last_len && !last.rule_id.contains(&merged.rule_id) {
                        last.rule_id = format!("{}+{}", last.rule_id, merged.rule_id);
                    }
                    
                    last.end = std::cmp::max(last.end, merged.end);
                    last.action = combine_actions(last.action, merged.action);
                    continue;
                }
            }
            final_matches.push(merged);
        }

        let mut sanitized_text = String::new();
        let mut last_pos = 0;
        let mut local_unique_tokens: HashMap<String, String> = HashMap::new();

        for mat in final_matches {
            if mat.start < last_pos { continue; }

            if mat.action == EnforcementAction::Block {
                is_blocked = true;
            }

            sanitized_text.push_str(&normalized[last_pos..mat.start]);

            if mat.action == EnforcementAction::AuditOnly {
                sanitized_text.push_str(&normalized[mat.start..mat.end]);
                last_pos = mat.end;
                
                let orig_start = offset_map.get_original_offset(mat.start);
                let orig_end = offset_map.get_original_offset(mat.end);
                redactions.push(Redaction {
                    rule_id: mat.rule_id,
                    action: mat.action,
                    offset: orig_start,
                    length: if orig_end >= orig_start { orig_end - orig_start } else { mat.text.len() },
                    placeholder: String::new(),
                    category: mat.category,
                });
                continue;
            }

            let token = if let Some(ctx) = session {
                let text_lower = mat.text.to_lowercase();
                
                // --- SECURITY FIX (3.1): Category-Aware Identity Linking ---
                // Prevents 'Identity Ghosting' where different PII types share the same token.
                let mut existing_token = None;
                
                let is_person_like = mat.category == PiiCategory::IndividualName || mat.category == PiiCategory::HighConfidenceAi;

                if is_person_like {
                    // 1. Exact Match Check (Category-Bound)
                    if let Some(t) = ctx.identities.get(&text_lower) {
                        existing_token = Some(t.value().clone());
                    }
                    
                    // 2. Fragment Linkage (Child -> Parent)
                    if existing_token.is_none() {
                        for entry in ctx.identities.iter() {
                            let known_id = entry.key();
                            if is_standalone_word(known_id, &text_lower) && text_lower.len() > 3 {
                                existing_token = Some(entry.value().clone());
                                break;
                            }
                        }
                    }
                    
                    // 3. Greedy Expansion (Parent -> Child)
                    if existing_token.is_none() {
                        for entry in ctx.identities.iter() {
                            let known_id = entry.key();
                            if is_standalone_word(&text_lower, known_id) && known_id.len() > 3 {
                                let token = entry.value().clone();
                                existing_token = Some(token.clone());
                                // Upgrade identity storage to the fuller name
                                ctx.identities.insert(text_lower.clone(), token);
                                break;
                            }
                        }
                    }
                }

                let t = if let Some(t) = existing_token {
                    t
                } else {
                    // Use category in key to prevent collision across different PII types (e.g. Name 'Alice' vs Email 'alice@...')
                    let key = format!("{:?}:{}", mat.category, text_lower);
                    ctx.pii_to_token.entry(key).or_insert_with(|| {
                        let id = ctx.next_id.fetch_add(1, Ordering::SeqCst);
                        let t = format!("[TOKEN_{}]", id);
                        ctx.token_to_pii.insert(t.clone(), mat.text.clone());
                        
                        // Register as identity if it's a person or fused name
                        if is_person_like {
                             ctx.identities.insert(text_lower.clone(), t.clone());
                        }
                        t
                    }).value().clone()
                };
                
                token_map.insert(t.clone(), mat.text.clone());
                t
            } else {
                let next_id = local_unique_tokens.len() + 1;
                local_unique_tokens.entry(mat.text.to_lowercase()).or_insert_with(|| {
                    let t = format!("[TOKEN_{}]", next_id);
                    token_map.insert(t.clone(), mat.text.clone());
                    t
                }).clone()
            };

            let orig_start = offset_map.get_original_offset(mat.start);
            let orig_end = offset_map.get_original_offset(mat.end);

            redactions.push(Redaction {
                rule_id: mat.rule_id,
                action: mat.action,
                offset: orig_start,
                length: if orig_end >= orig_start { orig_end - orig_start } else { mat.text.len() },
                placeholder: token.clone(),
                category: mat.category,
            });

            sanitized_text.push_str(&token);
            last_pos = mat.end;
        }
        sanitized_text.push_str(&normalized[last_pos..]);

        // Remaining unmerged potentials go to the report
        for mat in all_potentials {
            let is_covered = redactions.iter().any(|r| {
                let orig_start = offset_map.get_original_offset(mat.start);
                orig_start >= r.offset && orig_start < (r.offset + r.length)
            });
            if !is_covered {
                potential_misses.push(PotentialMiss {
                    text: mat.text,
                    offset: offset_map.get_original_offset(mat.start),
                    label: mat.rule_id,
                });
            }
        }

        Ok(ScrubbingReport {
            sanitized_text,
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
        let nonce = Nonce::from_slice(&nonce_bytes);

        // --- SECURITY FIX (V-19): Bind encryption to username via AAD ---
        let payload = Payload {
            msg: query.as_bytes(),
            aad: username.as_bytes(),
        };

        let ciphertext = self.cipher.encrypt(nonce, payload)
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

    #[test]
    fn test_overlap_merging_correct_offsets() {
        let dict_rules = vec![
            ("DICT_NAME".to_string(), "John Doe".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName)
        ];
        
        let regex_rules = vec![
            ("REGEX_NAME".to_string(), "ohn".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName)
        ];

        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine = WardenEngine::new(dict_rules, regex_rules, vec![], None, 0.85, &pepper).unwrap();
        
        let report = engine.sanitize_prompt("Hello John Doe.", None).unwrap();
        
        assert_eq!(report.redactions.len(), 1, "Should merge overlapping dict and regex matches");
        let red = &report.redactions[0];
        assert_eq!(red.offset, 6);
        assert_eq!(red.length, 8); // "John Doe" is longer and fully encapsulates "ohn"
        assert!(red.rule_id.contains("DICT_NAME")); // Longer match provides the rule ID
    }

    #[test]
    fn test_overlap_merging_longest_match_wins() {
        let dict_rules = vec![
            ("DICT_SHORT".to_string(), "John".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName)
        ];
        
        let regex_rules = vec![
            ("REGEX_LONG".to_string(), "John Doe".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName)
        ];

        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine = WardenEngine::new(dict_rules, regex_rules, vec![], None, 0.85, &pepper).unwrap();
        let report = engine.sanitize_prompt("Hello John Doe.", None).unwrap();
        
        assert_eq!(report.redactions.len(), 1);
        let red = &report.redactions[0];
        assert_eq!(red.length, 8); // "John Doe"
        assert_eq!(red.rule_id, "REGEX_LONG"); // Longer match wins
    }

    #[test]
    fn test_v12_aho_corasick_overlap_bypass_repro() {
        let dict_rules = vec![
            ("REDACT_ALICE".to_string(), "Alice".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName),
            ("BLOCK_ALICE_SMITH".to_string(), "Alice Smith".to_string(), EnforcementAction::Block, PiiCategory::IndividualName)
        ];
        
        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine = WardenEngine::new(dict_rules, vec![], vec![], None, 0.85, &pepper).unwrap();
        let report = engine.sanitize_prompt("Hello Alice Smith.", None).unwrap();
        
        // If the bug exists, report.is_blocked will be FALSE because 'Alice Smith' was masked by 'Alice'.
        assert!(report.is_blocked, "Should be blocked because 'Alice Smith' is a blocked entity");
    }

    #[test]
    fn test_semantic_cache_bypass() {
        // We use an empty engine (no rules, no AI)
        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine = WardenEngine::new(vec![], vec![], vec![], None, 0.85, &pepper).unwrap();
        let session = SessionContext::new();
        
        // Manually prime the cache with a value that would be caught by ShadowNer (title case)
        session.semantic_cache.insert("alice smith".to_string(), ("PERSON".to_string(), 0.99));
        
        // Use a standalone name to avoid fusion with other words
        let report = engine.sanitize_prompt("Alice Smith is a person.", Some(&session)).unwrap();
        
        // Normally, without AI, "Alice Smith" would be a potential miss.
        // With cache hit, it becomes a confirmed redaction.
        assert_eq!(report.redactions.len(), 1, "Should have 1 redaction from cache hit");
        let red = &report.redactions[0];
        assert_eq!(red.rule_id, "ai_cache_PERSON");
        assert_eq!(red.placeholder, "[TOKEN_1]");
        assert!(report.sanitized_text.contains("[TOKEN_1]"));
        assert_eq!(report.potential_misses.len(), 0, "Should have no potential misses as it was confirmed by cache");
    }

    #[test]
    fn test_overlap_merging_action_precedence() {
        let dict_rules = vec![
            ("AUDIT_ALICE".to_string(), "Alice".to_string(), EnforcementAction::AuditOnly, PiiCategory::IndividualName)
        ];
        
        let regex_rules = vec![
            ("REDACT_ALICE_SMITH".to_string(), "Alice Smith".to_string(), EnforcementAction::Redact, PiiCategory::IndividualName)
        ];

        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine = WardenEngine::new(dict_rules, regex_rules, vec![], None, 0.85, &pepper).unwrap();
        let report = engine.sanitize_prompt("Hello Alice Smith.", None).unwrap();
        
        assert_eq!(report.redactions.len(), 1);
        let red = &report.redactions[0];
        assert_eq!(red.action, EnforcementAction::Redact, "Redact must override AuditOnly in overlapping match");
        assert!(!report.sanitized_text.contains("Alice"), "Alice must be redacted");
    }
}
