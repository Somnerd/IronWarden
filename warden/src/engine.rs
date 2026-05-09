use iw_core::{ScrubbingReport, Redaction, SanitizationAction as CoreAction, TokenMap, SovereignError, PiiShield, SessionContext, PotentialMiss};
use crate::normalize::Normalizer;
use crate::shadow_ner::ShadowNer;
use crate::config::SanitizationAction;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::Regex;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Instant;

pub struct WardenEngine {
    dictionary_automaton: AhoCorasick,
    pattern_regex: Regex,
    rule_ids: Vec<String>,
    rule_actions: Vec<SanitizationAction>,
    shadow_ner: ShadowNer,
    dict_pattern_count: usize,
    ai: Option<std::sync::Mutex<crate::ai::HybridNer>>,
    confidence_threshold: f64,
}

impl WardenEngine {
    pub fn new(
        dictionary_rules: Vec<(String, String, SanitizationAction)>, 
        patterns_rules: Vec<(String, String, SanitizationAction)>,
        heuristics: Vec<crate::config::HeuristicConfig>,
        ai: Option<crate::ai::HybridNer>,
        confidence_threshold: f64,
    ) -> Result<Self, SovereignError> {
        let mut dict_patterns = Vec::new();
        let mut dict_ids = Vec::new();
        let mut dict_actions = Vec::new();
        for (id, pat, action) in dictionary_rules {
            dict_ids.push(id);
            dict_patterns.push(pat);
            dict_actions.push(action);
        }

        let mut regex_patterns = Vec::new();
        let mut regex_ids = Vec::new();
        let mut regex_actions = Vec::new();
        for (id, pat, action) in patterns_rules {
            regex_ids.push(id);
            regex_patterns.push(format!("(?P<r_{}>{})", regex_patterns.len(), pat));
            regex_actions.push(action);
        }

        let dict_pattern_count = dict_patterns.len();
        let dictionary_automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(dict_patterns)
            .map_err(|e| SovereignError::ConfigError(format!("Failed to build AC automaton: {}", e)))?;
        
        let combined_pattern = if regex_patterns.is_empty() {
            r"$.^".to_string()
        } else {
            regex_patterns.join("|")
        };
        
        let pattern_regex = Regex::new(&combined_pattern)
            .map_err(|e| SovereignError::ConfigError(format!("Failed to compile pattern union: {}", e)))?;

        Ok(Self {
            dictionary_automaton,
            pattern_regex,
            rule_ids: [dict_ids, regex_ids].concat(),
            rule_actions: [dict_actions, regex_actions].concat(),
            shadow_ner: ShadowNer::new(heuristics),
            dict_pattern_count,
            ai: ai.map(std::sync::Mutex::new),
            confidence_threshold,
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
    action: SanitizationAction,
}

fn is_standalone_word(text: &str, sub: &str) -> bool {
    if let Some(idx) = text.find(sub) {
        let before_ok = idx == 0 || !text[..idx].chars().last().unwrap().is_alphanumeric();
        let after_idx = idx + sub.len();
        let after_ok = after_idx == text.len() || !text[after_idx..].chars().next().unwrap().is_alphanumeric();
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
        for mat in self.dictionary_automaton.find_iter(&norm_res.normalized_ascii) {
            // Word boundary enforcement for dictionary matches
            let before_ok = mat.start() == 0 || !norm_res.normalized_ascii[..mat.start()].chars().last().unwrap().is_alphanumeric();
            let after_ok = mat.end() == norm_res.normalized_ascii.len() || !norm_res.normalized_ascii[mat.end()..].chars().next().unwrap().is_alphanumeric();
            if !before_ok || !after_ok {
                continue;
            }

            let idx = mat.pattern().as_usize();
            if let (Some(id), Some(action)) = (self.rule_ids.get(idx), self.rule_actions.get(idx)) {
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
                });
            }
        }

        // 2. Collect Regex Pattern Matches (on Unicode for accuracy)
        for caps in self.pattern_regex.captures_iter(normalized) {
            if let Some(full_match) = caps.get(0) {
                for (idx, id) in self.rule_ids[self.dict_pattern_count..].iter().enumerate() {
                    if caps.name(&format!("r_{}", idx)).is_some() {
                        let absolute_idx = self.dict_pattern_count + idx;
                        let action = self.rule_actions[absolute_idx];
                        all_confirmed.push(UnifiedMatch {
                            start: full_match.start(),
                            end: full_match.end(),
                            text: full_match.as_str().to_string(),
                            rule_id: id.clone(),
                            is_confirmed: true,
                            action,
                        });
                        break;
                    }
                }
            }
        }

        // 3. Shadow NER Pass
        let shadow_matches = self.shadow_ner.analyze(&normalized);
        
        if let Some(ai_mutex) = &self.ai {
            if let Ok(ai_guard) = ai_mutex.lock() {
                for shadow in shadow_matches {
                    let is_covered = all_confirmed.iter().any(|m| {
                        shadow.start < m.end && shadow.end > m.start
                    });
                    if is_covered { continue; }

                    let miss = PotentialMiss {
                        text: normalized[shadow.start..shadow.end].to_string(),
                        offset: offset_map.get_original_offset(shadow.start),
                        label: shadow.label.clone(),
                    };

                    let should_force_promote = shadow.label == "POTENTIAL_GLOBAL_NAME" || shadow.label == "POTENTIAL_GREEK_NAME";

                    if let Some(ai_entity) = ai_guard.validate_miss(&miss, &normalized, session) {
                        if ai_entity.score >= self.confidence_threshold || should_force_promote {
                            all_confirmed.push(UnifiedMatch {
                                start: shadow.start,
                                end: shadow.end,
                                text: miss.text,
                                rule_id: format!("ai_hybrid_{}", shadow.label),
                                is_confirmed: true,
                                action: shadow.action,
                            });
                        } else {
                            all_potentials.push(UnifiedMatch {
                                start: shadow.start,
                                end: shadow.end,
                                text: miss.text,
                                rule_id: shadow.label.clone(),
                                is_confirmed: false,
                                action: shadow.action,
                            });
                        }
                    } else if should_force_promote {
                         all_confirmed.push(UnifiedMatch {
                            start: shadow.start,
                            end: shadow.end,
                            text: miss.text,
                            rule_id: format!("heuristic_promotion_{}", shadow.label),
                            is_confirmed: true,
                            action: shadow.action,
                        });
                    } else {
                        all_potentials.push(UnifiedMatch {
                            start: shadow.start,
                            end: shadow.end,
                            text: miss.text,
                            rule_id: shadow.label.clone(),
                            is_confirmed: false,
                            action: shadow.action,
                        });
                    }
                }
            }
        } else {
            for shadow in shadow_matches {
                let is_covered = all_confirmed.iter().any(|m| {
                    shadow.start < m.end && shadow.end > m.start
                });
                if !is_covered {
                    all_potentials.push(UnifiedMatch {
                        start: shadow.start,
                        end: shadow.end,
                        text: normalized[shadow.start..shadow.end].to_string(),
                        rule_id: shadow.label.clone(),
                        is_confirmed: false,
                        action: shadow.action,
                    });
                }
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
                    gap.trim().is_empty() || gap == ", " || gap == " bin " || gap == " al "
                }) {
                    let pot = all_potentials.remove(pos);
                    let gap = &normalized[merged.end..pot.start];
                    merged.end = pot.end;
                    merged.text.push_str(gap);
                    merged.text.push_str(&pot.text);
                    merged.rule_id = format!("{}+fused", merged.rule_id);
                    if pot.action == SanitizationAction::Block {
                        merged.action = SanitizationAction::Block;
                    }
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
                        if merged.action == SanitizationAction::Block {
                            last.action = SanitizationAction::Block;
                        }
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
                    if merged.action == SanitizationAction::Block {
                        last.action = SanitizationAction::Block;
                    }
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

            if mat.action == SanitizationAction::Block {
                is_blocked = true;
            }

            sanitized_text.push_str(&normalized[last_pos..mat.start]);

            if mat.action == SanitizationAction::AuditOnly {
                 sanitized_text.push_str(&normalized[mat.start..mat.end]);
                 last_pos = mat.end;
                 continue;
            }

            let token = if let Some(ctx) = session {
                let text_lower = mat.text.to_lowercase();
                
                // --- SUB-PHRASE IDENTITY LINKING ---
                let mut existing_token = None;
                
                let is_person_like = mat.rule_id.contains("PERSON") || mat.rule_id.contains("PER") || mat.rule_id.contains("fused") || mat.rule_id.contains("name");

                if is_person_like {
                    // 1. Exact Match Check
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
                                existing_token = Some(entry.value().clone());
                                // Upgrade identity storage to the fuller name
                                ctx.identities.insert(text_lower.clone(), existing_token.as_ref().unwrap().clone());
                                break;
                            }
                        }
                    }
                }

                let t = if let Some(t) = existing_token {
                    t
                } else {
                    let key = format!("{}:{}", mat.rule_id, text_lower);
                    ctx.pii_to_token.entry(key).or_insert_with(|| {
                        let id = ctx.next_id.fetch_add(1, Ordering::SeqCst);
                        let t = format!("[TOKEN_{}]", id);
                        ctx.token_to_pii.insert(t.clone(), mat.text.clone());
                        
                        // Register as identity if it's a person or fused name
                        if mat.rule_id.contains("PERSON") || mat.rule_id.contains("PER") || mat.rule_id.contains("fused") || mat.rule_id.contains("name") {
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
                action: CoreAction::ReplaceToken,
                offset: orig_start,
                length: if orig_end >= orig_start { orig_end - orig_start } else { mat.text.len() },
                placeholder: token.clone(),
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

        let mut sorted_keys: Vec<&String> = map.keys().collect();
        sorted_keys.sort_by(|a, b| b.len().cmp(&a.len()));
        
        let tokens: Vec<String> = sorted_keys.into_iter().map(|k| regex::escape(k)).collect();
        let pattern = format!("({})", tokens.join("|"));
        let re = Regex::new(&pattern).map_err(|e| SovereignError::InternalError(e.to_string()))?;

        let result = re.replace_all(response, |caps: &regex::Captures| {
            let token = &caps[0];
            map.get(token).cloned().unwrap_or_else(|| token.to_string())
        });

        Ok(result.into_owned())
    }
}
