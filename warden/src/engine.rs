use crate::normalize::Normalizer;
use crate::shadow_ner::ShadowNer;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, Key, KeyInit, Nonce,
};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use async_trait::async_trait;
use hkdf::Hkdf;
use iw_core::{
    EnforcementAction, GroundingShield, PiiCategory, PiiShield, PotentialMiss, Redaction,
    ScrubbingReport, SessionContext, SovereignError, TokenMap,
};
use rand::RngCore;
use regex::Regex;
use secrecy::ExposeSecret;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::LazyLock;
use std::time::Instant;
use zeroize::Zeroize;

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

thread_local! {
    static NORMALIZATION_BUFFER: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

use serde::Serialize;

#[derive(Serialize)]
struct GuardrailPayload<'a> {
    prompt: &'a str,
}

async fn check_ml_sidecar(input: &str) -> Result<bool, SovereignError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let socket_path = "/tmp/warden_llamaguard.sock";

    if !std::path::Path::new(socket_path).exists() {
        return Ok(false);
    }

    match tokio::time::timeout(
        std::time::Duration::from_millis(100),
        tokio::net::UnixStream::connect(socket_path),
    )
    .await
    {
        Ok(Ok(mut stream)) => {
            let payload_struct = GuardrailPayload { prompt: input };
            let payload = serde_json::to_string(&payload_struct).map_err(|_| {
                SovereignError::InternalError("Failed to serialize Guardrail payload".into())
            })?;

            if tokio::time::timeout(
                std::time::Duration::from_millis(100),
                stream.write_all(payload.as_bytes()),
            )
            .await
            .is_ok()
            {
                let mut buf = [0u8; 1024];
                if let Ok(Ok(n)) = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    stream.read(&mut buf),
                )
                .await
                {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    if response.contains("BLOCKED") {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        _ => Err(SovereignError::InternalError(
            "ML Guardrail Sidecar unreachable or timed out".into(),
        )),
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
            let norm_ascii =
                Normalizer::with_normalized(&pat, |norm| norm.normalized_ascii.clone());
            dict_patterns.push(norm_ascii);
            dict_actions.push(action);
            dict_categories.push(category);
        }

        let mut individual_regexes = Vec::new();
        let mut regex_ids = Vec::new();
        let mut regex_actions = Vec::new();
        let mut regex_categories = Vec::new();
        for (id, pat, action, category) in patterns_rules {
            let re = Regex::new(&pat).map_err(|e| {
                SovereignError::ConfigError(format!(
                    "Failed to compile regex pattern {}: {}",
                    id, e
                ))
            })?;
            individual_regexes.push(re);
            regex_ids.push(id);
            regex_actions.push(action);
            regex_categories.push(category);
        }

        let dict_pattern_count = dict_patterns.len();
        let dictionary_automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(dict_patterns)
            .map_err(|e| {
                SovereignError::ConfigError(format!("Failed to build AC automaton: {}", e))
            })?;

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

#[async_trait]
impl PiiShield for WardenEngine {
    async fn sanitize_prompt(
        &self,
        input: &str,
        session: Option<&SessionContext>,
    ) -> Result<ScrubbingReport, SovereignError> {
        // --- SECURITY FIX (Finding 4): Dual-Layer Prompt Injection Guardrails ---
        // Layer 1: Robust Heuristic Tree
        let has_match = NORMALIZATION_BUFFER.with(|buf_cell| {
            let mut buf = buf_cell.borrow_mut();
            buf.clear();
            for c in input.chars() {
                if c.is_alphanumeric() {
                    for lowercase_c in c.to_lowercase() {
                        buf.push(lowercase_c);
                    }
                }
            }
            let input_search = aho_corasick::Input::new(&*buf);
            INJECTION_BLOCKLIST.find(input_search).is_some()
        });

        if has_match {
            return Err(SovereignError::UnauthorizedAccess(
                "Prompt injection attempt blocked by Layer 1 Heuristic Guardrail".into(),
            ));
        }

        // Layer 1.5: Shannon Entropy Analyzer (Base64 Smuggling Detection)
        if Self::check_shannon_entropy_smuggling(input) {
            return Err(SovereignError::UnauthorizedAccess(
                "Prompt injection attempt blocked by Layer 1.5 Entropy Guardrail (Token Smuggling)"
                    .into(),
            ));
        }

        // Layer 2: ML Classifier Sidecar
        if check_ml_sidecar(input).await? {
            return Err(SovereignError::UnauthorizedAccess(
                "Prompt injection attempt blocked by Layer 2 ML Guardrail".into(),
            ));
        }

        let start_time = Instant::now();
        Normalizer::with_normalized(input, |norm_res| {
            let normalized = &norm_res.normalized_unicode;
            let offset_map = &norm_res.unicode_to_original;

            let mut token_map = TokenMap::new();
            let mut redactions = Vec::new();
            let mut potential_misses = Vec::new();
            let mut is_blocked = false;

            let mut all_confirmed: Vec<UnifiedMatch> = Vec::new();
            let mut all_potentials: Vec<UnifiedMatch> = Vec::new();

            // 1. Collect Dictionary Matches (on ASCII for homoglyphs)
            for mat in self
                .dictionary_automaton
                .find_overlapping_iter(&norm_res.normalized_ascii)
            {
                // Word boundary enforcement for dictionary matches
                let before_ok = mat.start() == 0
                    || !norm_res.normalized_ascii[..mat.start()]
                        .ends_with(|c: char| c.is_alphanumeric());
                let after_ok = mat.end() == norm_res.normalized_ascii.len()
                    || !norm_res.normalized_ascii[mat.end()..]
                        .starts_with(|c: char| c.is_alphanumeric());

                if !before_ok || !after_ok {
                    continue;
                }

                let idx = mat.pattern().as_usize();
                if let (Some(id), Some(action), Some(category)) = (
                    self.rule_ids.get(idx),
                    self.rule_actions.get(idx),
                    self.rule_categories.get(idx),
                ) {
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
            for mat in self
                .dictionary_automaton
                .find_overlapping_iter(&norm_res.stripped)
            {
                let idx = mat.pattern().as_usize();
                if let (Some(id), Some(action), Some(category)) = (
                    self.rule_ids.get(idx),
                    self.rule_actions.get(idx),
                    self.rule_categories.get(idx),
                ) {
                    // Map Stripped offsets to Original, then to Unicode
                    let orig_start = norm_res
                        .stripped_to_original
                        .get_original_offset(mat.start());
                    let orig_end = if mat.end() > mat.start() {
                        let last_stripped_idx = mat.end() - 1;
                        let orig_last = norm_res
                            .stripped_to_original
                            .get_original_offset(last_stripped_idx);
                        // find the next character boundary in original to include the last matched char
                        let mut next_orig = orig_last + 1;
                        while next_orig <= input.len() && !input.is_char_boundary(next_orig) {
                            next_orig += 1;
                        }
                        next_orig
                    } else {
                        orig_start
                    };

                    let ascii_start = norm_res.original_to_ascii[orig_start];
                    let ascii_end = norm_res.original_to_ascii[orig_end];

                    let before_ok = ascii_start == 0
                        || !norm_res.normalized_ascii[..ascii_start]
                            .ends_with(|c: char| c.is_alphanumeric());
                    let after_ok = ascii_end == norm_res.normalized_ascii.len()
                        || !norm_res.normalized_ascii[ascii_end..]
                            .starts_with(|c: char| c.is_alphanumeric());
                    if !before_ok || !after_ok {
                        continue;
                    }

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

            // 2. Collect Individual Regex Matches (on Unicode)
            for (i, re) in self.individual_regexes.iter().enumerate() {
                // V-12 Fix applied: 1-character advancement to prevent overlap masking
                let mut search_start = 0;
                while search_start < normalized.len() {
                    if let Some(mat) = re.find_at(normalized, search_start) {
                        let idx = self.dict_pattern_count + i;
                        let id = &self.rule_ids[idx];
                        let action = self.rule_actions[idx];
                        let category = self.rule_categories[idx];

                        all_confirmed.push(UnifiedMatch {
                            start: mat.start(),
                            end: mat.end(),
                            text: mat.as_str().to_string(),
                            rule_id: id.clone(),
                            is_confirmed: true,
                            action,
                            category,
                        });
                        search_start = mat.start() + 1;
                    } else {
                        break;
                    }
                }
            }

            // 3. Shadow NER Pass (Dual track: ASCII for homoglyph resilience, Unicode for script awareness)
            let shadow_matches = self
                .shadow_ner
                .analyze(&norm_res.normalized_unicode, &norm_res.normalized_ascii);

            for shadow in shadow_matches {
                // Map offsets to Original, then to Unicode
                let (orig_start, orig_end) = if shadow.is_ascii {
                    (
                        norm_res.ascii_to_original.get_original_offset(shadow.start),
                        norm_res.ascii_to_original.get_original_offset(shadow.end),
                    )
                } else {
                    (
                        norm_res
                            .unicode_to_original
                            .get_original_offset(shadow.start),
                        norm_res.unicode_to_original.get_original_offset(shadow.end),
                    )
                };

                let unicode_start = norm_res.original_to_unicode[orig_start];
                let unicode_end = norm_res.original_to_unicode[orig_end];

                let is_covered = all_confirmed
                    .iter()
                    .any(|m| unicode_start < m.end && unicode_end > m.start);
                if is_covered {
                    continue;
                }

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
                    if let Some(entry) = ctx.semantic_cache.get(&cache_key) {
                        let (label, score) = entry;
                        if score >= SEMANTIC_CACHE_THRESHOLD {
                            cache_hit = Some((label.clone(), score));
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
                        if let Some(ai_entity) =
                            ai_instance.validate_miss(&miss, &normalized, session)
                        {
                            if ai_entity.score >= self.confidence_threshold || should_force_promote
                            {
                                // --- WP #77: SEMANTIC CACHE INSERT ---
                                if let Some(ctx) = session {
                                    if ai_entity.score >= SEMANTIC_CACHE_THRESHOLD {
                                        ctx.semantic_cache.insert(
                                            ascii_text.to_lowercase(),
                                            (ai_entity.label.clone(), ai_entity.score),
                                        );
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
                        if p.start < current_end {
                            return false;
                        }
                        let gap = &normalized[current_end..p.start];
                        gap.trim().is_empty()
                            || gap == ", "
                            || gap == " bin "
                            || gap == " al "
                            || gap == " da "
                            || gap == " de "
                            || gap == " van "
                            || gap == " von "
                    }) {
                        let pot = all_potentials.remove(pos);
                        let gap = &normalized[merged.end..pot.start];
                        merged.end = pot.end;
                        merged.text.push_str(gap);
                        merged.text.push_str(&pot.text);
                        merged.rule_id.push_str("+fused");
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
                            let merged_rule_str = merged.rule_id.as_str();
                            if !last.rule_id.split('+').any(|id| id == merged_rule_str) {
                                last.rule_id.push('+');
                                last.rule_id.push_str(merged_rule_str);
                            }
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

                        // Resolve action and rule_id using priority rules (Block > Redact > Mask > AuditOnly)

                        // The rule_id should belong to whichever match was longer (more specific)
                        // AND if one match has a stronger action, it should take precedence
                        let get_prio = |a: &EnforcementAction| -> u8 {
                            match a {
                                EnforcementAction::Block => 4,
                                EnforcementAction::Redact => 3,
                                EnforcementAction::Mask => 2,
                                EnforcementAction::AuditOnly => 1,
                            }
                        };
                        let last_prio = get_prio(&last.action);
                        let merged_prio = get_prio(&merged.action);

                        if merged_prio > last_prio {
                            last.rule_id = merged.rule_id.clone();
                            last.action = merged.action;
                        } else if merged_prio == last_prio {
                            if merged_len > last_len {
                                last.rule_id = merged.rule_id.clone();
                                last.action = merged.action;
                            } else if merged_len == last_len {
                                let merged_rule_str = merged.rule_id.as_str();
                                if !last.rule_id.split('+').any(|id| id == merged_rule_str) {
                                    last.rule_id.push('+');
                                    last.rule_id.push_str(merged_rule_str);
                                }
                            }
                        }

                        last.action = combine_actions(last.action, merged.action);
                        last.end = std::cmp::max(last.end, merged.end);
                        continue;
                    }
                }
                final_matches.push(merged);
            }

            // Return original string immediately if no redactions/blocks are required (Zero-Allocation Hot Path)
            if final_matches.is_empty() {
                // Remaining unmerged potentials go to the report
                for mat in all_potentials {
                    potential_misses.push(PotentialMiss {
                        text: mat.text,
                        offset: offset_map.get_original_offset(mat.start),
                        label: mat.rule_id,
                    });
                }

                return Ok(ScrubbingReport {
                    sanitized_text: input.to_string(),
                    is_blocked,
                    redactions,
                    token_map,
                    potential_misses,
                    execution_time_ms: start_time.elapsed().as_millis() as u64,
                });
            }

            let mut generated_tokens: Vec<(
                usize,
                usize,
                String,
                String,
                EnforcementAction,
                PiiCategory,
                String,
            )> = Vec::new();
            let mut local_unique_tokens: HashMap<String, String> = HashMap::new();
            let mut last_pos = 0;

            for mat in &final_matches {
                if mat.start < last_pos {
                    continue;
                }

                if mat.action == EnforcementAction::Block {
                    is_blocked = true;
                }

                let orig_start = offset_map.get_original_offset(mat.start);
                let orig_end = offset_map.get_original_offset(mat.end);

                if mat.action == EnforcementAction::AuditOnly {
                    redactions.push(Redaction {
                        rule_id: mat.rule_id.clone(),
                        action: mat.action,
                        offset: orig_start,
                        length: if orig_end >= orig_start {
                            orig_end - orig_start
                        } else {
                            mat.text.len()
                        },
                        placeholder: String::new(),
                        category: mat.category,
                    });
                    last_pos = mat.end;
                    continue;
                }

                let token = if let Some(ctx) = session {
                    let text_lower = mat.text.to_lowercase();

                    // --- SECURITY FIX (3.1): Category-Aware Identity Linking ---
                    // Prevents 'Identity Ghosting' where different PII types share the same token.
                    let mut existing_token = None;

                    let is_person_like = mat.category == PiiCategory::IndividualName
                        || mat.category == PiiCategory::HighConfidenceAi;

                    if is_person_like {
                        // 1. Exact Match Check (Category-Bound)
                        if let Some(t) = ctx.identities.get(&text_lower) {
                            existing_token = Some(t.value().clone());
                        }

                        // 2. Fragment Linkage (Child -> Parent)
                        if existing_token.is_none() {
                            for entry in ctx.identities.iter() {
                                let known_id = entry.key();
                                if is_standalone_word(known_id, &text_lower) && text_lower.len() > 3
                                {
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
                        ctx.pii_to_token
                            .entry(key)
                            .or_insert_with(|| {
                                let id = ctx.next_id.fetch_add(1, Ordering::SeqCst);
                                let t = format!("[TOKEN_{}]", id);
                                ctx.token_to_pii.insert(t.clone(), mat.text.clone());

                                // Register as identity if it's a person or fused name
                                if is_person_like {
                                    ctx.identities.insert(text_lower.clone(), t.clone());
                                }
                                t
                            })
                            .value()
                            .clone()
                    };

                    token_map.insert(t.clone(), mat.text.clone());
                    t
                } else {
                    let next_id = local_unique_tokens.len() + 1;
                    local_unique_tokens
                        .entry(mat.text.to_lowercase())
                        .or_insert_with(|| {
                            let t = format!("[TOKEN_{}]", next_id);
                            token_map.insert(t.clone(), mat.text.clone());
                            t
                        })
                        .clone()
                };

                token_map.insert(token.clone(), mat.text.clone());
                generated_tokens.push((
                    orig_start,
                    orig_end,
                    token,
                    mat.rule_id.clone(),
                    mat.action,
                    mat.category,
                    mat.text.clone(),
                ));
                last_pos = mat.end;
            }

            // Zero-Copy Slicing Re-hydration
            let mut exact_capacity = input.len();
            for (orig_start, orig_end, token, ..) in &generated_tokens {
                exact_capacity += token.len();
                exact_capacity -= if *orig_end >= *orig_start {
                    *orig_end - *orig_start
                } else {
                    0
                };
            }

            let mut sanitized_text = String::with_capacity(exact_capacity);
            let mut orig_last_pos = 0;
            for (orig_start, orig_end, token, rule_id, action, category, original_text) in
                generated_tokens
            {
                if orig_start > orig_last_pos {
                    sanitized_text.push_str(&input[orig_last_pos..orig_start]);
                }
                sanitized_text.push_str(&token);
                orig_last_pos = orig_end;

                redactions.push(Redaction {
                    rule_id,
                    action,
                    offset: orig_start,
                    length: if orig_end >= orig_start {
                        orig_end - orig_start
                    } else {
                        original_text.len()
                    },
                    placeholder: token,
                    category,
                });
            }
            if orig_last_pos < input.len() {
                sanitized_text.push_str(&input[orig_last_pos..]);
            }

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
        })
    }

    fn restore_prompt(&self, response: &str, map: &TokenMap) -> Result<String, SovereignError> {
        if map.is_empty() {
            return Ok(response.to_string());
        }

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
        (EnforcementAction::Redact, _) | (_, EnforcementAction::Redact) => {
            EnforcementAction::Redact
        }
        (EnforcementAction::Mask, _) | (_, EnforcementAction::Mask) => EnforcementAction::Mask,
        (EnforcementAction::AuditOnly, EnforcementAction::AuditOnly) => {
            EnforcementAction::AuditOnly
        }
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

        let ciphertext = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|_| SovereignError::InternalError("Query sealing failed".into()))?;

        let mut blob = nonce_bytes.to_vec();
        blob.extend(ciphertext);
        Ok(blob)
    }

    fn unseal_query(&self, blob: &[u8], username: &str) -> Result<String, SovereignError> {
        if blob.len() < 12 {
            return Err(SovereignError::InternalError(
                "Invalid sealed query blob".into(),
            ));
        }

        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // --- SECURITY FIX (V-19): Bind decryption to username via AAD ---
        let payload = Payload {
            msg: ciphertext,
            aad: username.as_bytes(),
        };

        let plaintext = self.cipher.decrypt(nonce, payload).map_err(|_| {
            SovereignError::UnauthorizedAccess(
                "Query unsealing failed: AAD mismatch or tampering".into(),
            )
        })?;

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
        let dict_rules = vec![(
            "DICT_NAME".to_string(),
            "John Doe".to_string(),
            EnforcementAction::Redact,
            PiiCategory::IndividualName,
        )];

        let regex_rules = vec![(
            "REGEX_NAME".to_string(),
            "ohn".to_string(),
            EnforcementAction::Redact,
            PiiCategory::IndividualName,
        )];

        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine =
            WardenEngine::new(dict_rules, regex_rules, vec![], None, 0.85, &pepper).unwrap();

        let report = engine
            .sanitize_prompt("Hello John Doe.", None)
            .await
            .unwrap();

        assert_eq!(
            report.redactions.len(),
            1,
            "Should merge overlapping dict and regex matches"
        );
        let red = &report.redactions[0];
        assert_eq!(red.offset, 6);
        assert_eq!(red.length, 8); // "John Doe" is longer and fully encapsulates "ohn"
        assert!(red.rule_id.contains("DICT_NAME")); // Longer match provides the rule ID
    }

    #[tokio::test]
    async fn test_overlap_merging_longest_match_wins() {
        let dict_rules = vec![(
            "DICT_SHORT".to_string(),
            "John".to_string(),
            EnforcementAction::Redact,
            PiiCategory::IndividualName,
        )];

        let regex_rules = vec![(
            "REGEX_LONG".to_string(),
            "John Doe".to_string(),
            EnforcementAction::Redact,
            PiiCategory::IndividualName,
        )];

        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine =
            WardenEngine::new(dict_rules, regex_rules, vec![], None, 0.85, &pepper).unwrap();
        let report = engine
            .sanitize_prompt("Hello John Doe.", None)
            .await
            .unwrap();

        assert_eq!(report.redactions.len(), 1);
        let red = &report.redactions[0];
        assert_eq!(red.length, 8); // "John Doe"
        assert_eq!(red.rule_id, "REGEX_LONG"); // Longer match wins
    }

    #[tokio::test]
    async fn test_v12_aho_corasick_overlap_bypass_repro() {
        let dict_rules = vec![
            (
                "REDACT_ALICE".to_string(),
                "Alice".to_string(),
                EnforcementAction::Redact,
                PiiCategory::IndividualName,
            ),
            (
                "BLOCK_ALICE_SMITH".to_string(),
                "Alice Smith".to_string(),
                EnforcementAction::Block,
                PiiCategory::IndividualName,
            ),
        ];

        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine = WardenEngine::new(dict_rules, vec![], vec![], None, 0.85, &pepper).unwrap();
        let report = engine
            .sanitize_prompt("Hello Alice Smith.", None)
            .await
            .unwrap();

        // If the bug exists, report.is_blocked will be FALSE because 'Alice Smith' was masked by 'Alice'.
        assert!(
            report.is_blocked,
            "Should be blocked because 'Alice Smith' is a blocked entity"
        );
    }

    #[tokio::test]
    async fn test_semantic_cache_bypass() {
        // We use an empty engine (no rules, no AI)
        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine = WardenEngine::new(vec![], vec![], vec![], None, 0.85, &pepper).unwrap();
        let session = SessionContext::new();

        // Manually prime the cache with a value that would be caught by ShadowNer (title case)
        session
            .semantic_cache
            .insert("alice smith".to_string(), ("PERSON".to_string(), 0.99));

        // Use a standalone name to avoid fusion with other words
        let report = engine
            .sanitize_prompt("Alice Smith is a person.", Some(&session))
            .await
            .unwrap();

        // Normally, without AI, "Alice Smith" would be a potential miss.
        // With cache hit, it becomes a confirmed redaction.
        assert_eq!(
            report.redactions.len(),
            1,
            "Should have 1 redaction from cache hit"
        );
        let red = &report.redactions[0];
        assert_eq!(red.rule_id, "ai_cache_PERSON");
        assert_eq!(red.placeholder, "[TOKEN_1]");
        assert!(report.sanitized_text.contains("[TOKEN_1]"));
        assert_eq!(
            report.potential_misses.len(),
            0,
            "Should have no potential misses as it was confirmed by cache"
        );
    }

    #[tokio::test]
    async fn test_overlap_merging_action_precedence() {
        let dict_rules = vec![(
            "AUDIT_ALICE".to_string(),
            "Alice".to_string(),
            EnforcementAction::AuditOnly,
            PiiCategory::IndividualName,
        )];

        let regex_rules = vec![(
            "REDACT_ALICE_SMITH".to_string(),
            "Alice Smith".to_string(),
            EnforcementAction::Redact,
            PiiCategory::IndividualName,
        )];

        let pepper = secrecy::SecretVec::from(vec![0u8; 32]);
        let engine =
            WardenEngine::new(dict_rules, regex_rules, vec![], None, 0.85, &pepper).unwrap();
        let report = engine
            .sanitize_prompt("Hello Alice Smith.", None)
            .await
            .unwrap();

        assert_eq!(report.redactions.len(), 1);
        let red = &report.redactions[0];
        assert_eq!(
            red.action,
            EnforcementAction::Redact,
            "Redact must override AuditOnly in overlapping match"
        );
        assert!(
            !report.sanitized_text.contains("Alice"),
            "Alice must be redacted"
        );
    }
}
