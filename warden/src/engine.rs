use crate::normalize::Normalizer;
use crate::shadow_ner::{AmbiguousCandidate, ShadowNer};
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

use tracing::warn;

async fn check_ml_sidecar(input: &str) -> Result<bool, SovereignError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let socket_path = std::env::var("WARDEN_ML_SIDECAR_SOCKET")
        .unwrap_or_else(|_| "/tmp/warden_llamaguard.sock".to_string());

    let require_sidecar = std::env::var("WARDEN_REQUIRE_ML_SIDECAR")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if !std::path::Path::new(&socket_path).exists() {
        if require_sidecar {
            warn!(
                socket_path = %socket_path,
                "ML Guardrail Sidecar socket not found. Enforcing fail-closed policy (SEC-01)."
            );
            return Err(SovereignError::UnauthorizedAccess(
                "ML Guardrail Sidecar socket missing — Fail-Closed Policy enforced".into(),
            ));
        }
        return Ok(false);
    }

    let timeout_ms = std::env::var("WARDEN_ML_SIDECAR_TIMEOUT_MS")
        .ok()
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(100);

    let timeout_duration = std::time::Duration::from_millis(timeout_ms);

    match tokio::time::timeout(
        timeout_duration,
        tokio::net::UnixStream::connect(&socket_path),
    )
    .await
    {
        Ok(Ok(mut stream)) => {
            let payload_struct = GuardrailPayload { prompt: input };
            let payload = serde_json::to_string(&payload_struct).map_err(|_| {
                SovereignError::InternalError("Failed to serialize Guardrail payload".into())
            })?;

            if let Err(e) =
                tokio::time::timeout(timeout_duration, stream.write_all(payload.as_bytes())).await
            {
                warn!("ML Guardrail Sidecar write timed out or failed: {}. Enforcing fail-closed policy.", e);
                return Err(SovereignError::UnauthorizedAccess(
                    "ML Guardrail Sidecar write timed out — Fail-Closed Policy enforced".into(),
                ));
            }

            let mut buf = [0u8; 1024];
            let read_res = tokio::time::timeout(timeout_duration, stream.read(&mut buf)).await;
            let n = match read_res {
                Ok(Ok(n)) => n,
                _ => {
                    warn!("ML Guardrail Sidecar read timed out or failed. Enforcing fail-closed policy.");
                    return Err(SovereignError::UnauthorizedAccess(
                        "ML Guardrail Sidecar read timed out — Fail-Closed Policy enforced".into(),
                    ));
                }
            };

            let response = String::from_utf8_lossy(&buf[..n]);
            if response.contains("BLOCKED") {
                return Ok(true);
            }
            Ok(false)
        }
        _ => {
            warn!(
                socket_path = %socket_path,
                "ML Guardrail Sidecar unreachable or timed out. Enforcing fail-closed policy (SEC-01)."
            );
            Err(SovereignError::UnauthorizedAccess(
                "ML Guardrail Sidecar unreachable or timed out — Fail-Closed Policy enforced"
                    .into(),
            ))
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
        #[allow(deprecated)]
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

        let mut all_patterns = patterns_rules;
        // --- CORE GREEK PII PATTERNS NATIVELY EMBEDDED (P0) ---
        all_patterns.push((
            "NATIVE_GR_AMKA".to_string(),
            r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}\d{5}\b".to_string(),
            EnforcementAction::Redact,
            PiiCategory::IdentificationNumber,
        ));
        all_patterns.push((
            "NATIVE_GR_ID".to_string(),
            r"\b[Α-ΩA-Z]{2}[- ]?\d{6}\b".to_string(),
            EnforcementAction::Redact,
            PiiCategory::IdentificationNumber,
        ));
        all_patterns.push((
            "NATIVE_GR_PHONE".to_string(),
            r"\b(?:(?:\+30|0030)[\s\-]?)?(?:2\d{9}|69\d{8})\b".to_string(),
            EnforcementAction::Redact,
            PiiCategory::ContactInfo,
        ));

        for (id, pat, action, category) in all_patterns {
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
    #[allow(dead_code)]
    is_confirmed: bool,
    action: EnforcementAction,
    category: PiiCategory,
}

#[doc(hidden)]
pub fn is_standalone_word(text: &str, sub: &str) -> bool {
    if sub.is_empty() {
        return false;
    }
    let mut search_idx = 0;
    while let Some(idx) = text[search_idx..].find(sub) {
        let actual_idx = search_idx + idx;

        let before_ok =
            actual_idx == 0 || !text[..actual_idx].ends_with(|c: char| c.is_alphanumeric());
        let after_idx = actual_idx + sub.len();
        let after_ok = after_idx == text.len()
            || !text[after_idx..].starts_with(|c: char| c.is_alphanumeric());

        if before_ok && after_ok {
            return true;
        }

        let next_char_len = text[actual_idx..]
            .chars()
            .next()
            .map(|c| c.len_utf8())
            .unwrap_or(1);
        search_idx = actual_idx + next_char_len;
    }
    false
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
            // Word boundary enforcement for flexible separators
            let before_ok = mat.start() == 0
                || !norm_res.stripped[..mat.start()].ends_with(|c: char| c.is_alphanumeric());
            let after_ok = mat.end() == norm_res.stripped.len()
                || !norm_res.stripped[mat.end()..].starts_with(|c: char| c.is_alphanumeric());
            if !before_ok || !after_ok {
                continue;
            }

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
                    if mat.start() == mat.end() {
                        if let Some(c) = normalized[search_start..].chars().next() {
                            search_start += c.len_utf8();
                        } else {
                            break;
                        }
                    } else {
                        search_start = mat.start()
                            + normalized[mat.start()..].chars().next().unwrap().len_utf8();
                    }
                } else {
                    break;
                }
            }
        }

        // 3. Shadow NER Pass (Dual track: ASCII for homoglyph resilience, Unicode for script awareness)
        all_confirmed.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)));

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

            if let Some(existing) = all_confirmed
                .iter_mut()
                .find(|m| unicode_start < m.end && unicode_end > m.start)
            {
                if unicode_start < existing.start || unicode_end > existing.end {
                    existing.start = existing.start.min(unicode_start);
                    existing.end = existing.end.max(unicode_end);
                    existing.text = normalized[existing.start..existing.end].to_string();
                }
                existing.action = combine_actions(existing.action, shadow.action);
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
                let ai_instance_opt = pool.get().await;
                if let Some(ai_instance) = ai_instance_opt {
                    if let Some(ai_entity) = ai_instance.validate_miss(&miss, normalized, session) {
                        if ai_entity.score >= self.confidence_threshold || should_force_promote {
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
                            text: miss.text.clone(),
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

        // 3.5. Tier 2 Track B: Ambiguous Candidate Window-Batched ONNX Disambiguation (Hybrid Mode Only)
        if let Some(pool) = &self.ai {
            let confirmed_spans: Vec<(usize, usize)> =
                all_confirmed.iter().map(|m| (m.start, m.end)).collect();

            let ambiguous_candidates = self
                .shadow_ner
                .find_ambiguous_tokens(&norm_res.normalized_unicode, &confirmed_spans);

            if !ambiguous_candidates.is_empty() {
                let text_unicode = &norm_res.normalized_unicode;
                let text_bytes = text_unicode.as_bytes();
                let text_len = text_unicode.len();

                // Group ambiguous candidates by sentence windows
                let mut windows: Vec<(usize, usize)> = Vec::new();

                for cand in &ambiguous_candidates {
                    if text_len <= 512 {
                        if windows.is_empty() {
                            windows.push((0, text_len));
                        }
                    } else {
                        // Find sentence start (last ".", "!", "?", "\n" before cand.start)
                        let mut w_start = text_bytes[..cand.start]
                            .iter()
                            .rposition(|&b| b == b'.' || b == b'!' || b == b'?' || b == b'\n')
                            .map(|pos| pos + 1)
                            .unwrap_or(0);

                        // Find sentence end (next ".", "!", "?", "\n" after cand.end)
                        let mut w_end = text_bytes[cand.end..]
                            .iter()
                            .position(|&b| b == b'.' || b == b'!' || b == b'?' || b == b'\n')
                            .map(|pos| cand.end + pos + 1)
                            .unwrap_or(text_len);
                        // Ensure valid UTF-8 character boundaries
                        while w_start < text_len && !text_unicode.is_char_boundary(w_start) {
                            w_start += 1;
                        }
                        while w_end > 0 && !text_unicode.is_char_boundary(w_end) {
                            w_end -= 1;
                        }
                        if w_start < w_end {
                            let mut merged = false;
                            for w in &mut windows {
                                if w_start <= w.1 && w_end >= w.0 {
                                    w.0 = w.0.min(w_start);
                                    w.1 = w.1.max(w_end);
                                    merged = true;
                                    break;
                                }
                            }
                            if !merged {
                                windows.push((w_start, w_end));
                            }
                        }
                    }
                }

                if let Some(ai_instance) = pool.get().await {
                    for (w_start, w_end) in windows {
                        let original_window_text = &text_unicode[w_start..w_end];

                        // Synthetic casing for lowercase candidates requiring neural probing
                        let cands_requiring_casing: Vec<&AmbiguousCandidate> = ambiguous_candidates
                            .iter()
                            .filter(|c| {
                                c.start >= w_start && c.end <= w_end && c.needs_synthetic_casing
                            })
                            .collect();

                        let synthetic_window_text = {
                            let mut buf = original_window_text.as_bytes().to_vec();

                            // Map delimiter punctuation to standard parens and markdown underscores to spaces
                            for b in buf.iter_mut() {
                                if *b == b'[' || *b == b'<' {
                                    *b = b'(';
                                } else if *b == b']' || *b == b'>' {
                                    *b = b')';
                                } else if *b == b'_' {
                                    *b = b' ';
                                }
                            }

                            // In-place UTF-8 safe synthetic title-casing for candidate words
                            for cand in &cands_requiring_casing {
                                let rel_start = cand.start - w_start;
                                let rel_end = cand.end - w_start;
                                if rel_end <= buf.len()
                                    && original_window_text.is_char_boundary(rel_start)
                                    && original_window_text.is_char_boundary(rel_end)
                                {
                                    // Capitalize preceding honorific if present (e.g. "dr. " -> "Dr. ", "mr. " -> "Mr. ")
                                    if rel_start >= 4 {
                                        let prefix_bytes = &buf[..rel_start];
                                        if prefix_bytes.ends_with(b"dr. ")
                                            || prefix_bytes.ends_with(b"mr. ")
                                            || prefix_bytes.ends_with(b"ms. ")
                                        {
                                            let honorific_pos = rel_start - 4;
                                            buf[honorific_pos] =
                                                buf[honorific_pos].to_ascii_uppercase();
                                        } else if rel_start >= 5 && prefix_bytes.ends_with(b"mrs. ")
                                        {
                                            let honorific_pos = rel_start - 5;
                                            buf[honorific_pos] =
                                                buf[honorific_pos].to_ascii_uppercase();
                                        }
                                    }

                                    let cand_slice = &original_window_text[rel_start..rel_end];
                                    let mut at_word_boundary = true;
                                    for (char_offset, ch) in cand_slice.char_indices() {
                                        if ch == ' ' || ch == '-' || ch == '\'' {
                                            at_word_boundary = true;
                                        } else if at_word_boundary {
                                            if let Some(upper_ch) = ch.to_uppercase().next() {
                                                if upper_ch.len_utf8() == ch.len_utf8() {
                                                    let byte_pos = rel_start + char_offset;
                                                    upper_ch.encode_utf8(
                                                        &mut buf
                                                            [byte_pos..byte_pos + ch.len_utf8()],
                                                    );
                                                }
                                            }
                                            at_word_boundary = false;
                                        }
                                    }
                                }
                            }
                            String::from_utf8(buf)
                                .unwrap_or_else(|_| original_window_text.to_string())
                        };

                        let entities = ai_instance.analyze(&synthetic_window_text);

                        for entity in entities {
                            let global_start = w_start + entity.start;
                            let global_end = w_start + entity.end;

                            if global_start < global_end && global_end <= text_len {
                                if let Some(cand) = ambiguous_candidates
                                    .iter()
                                    .find(|c| global_start < c.end && global_end > c.start)
                                {
                                    let min_thresh = if cand.needs_synthetic_casing {
                                        self.confidence_threshold.min(0.65)
                                    } else {
                                        self.confidence_threshold.min(0.70)
                                    };

                                    let is_valid = ShadowNer::is_valid_name_span(
                                        normalized, cand.start, cand.end,
                                    ) && ShadowNer::is_valid_name_span(
                                        normalized,
                                        global_start,
                                        global_end,
                                    );

                                    let is_agentive_or_starter =
                                        self.shadow_ner
                                            .is_at_sentence_start(normalized, cand.start)
                                            || {
                                                let prefix = normalized[..cand.start]
                                                    .trim_end_matches(|c: char| {
                                                        c == '<'
                                                            || c == '['
                                                            || c == '('
                                                            || c == ' '
                                                            || c == ':'
                                                    });
                                                prefix.ends_with("by")
                                                    || prefix.ends_with("from")
                                                    || prefix.ends_with("for")
                                            };

                                    let label_matches = if entity.label.ends_with("PER") {
                                        is_valid
                                    } else if entity.label.ends_with("ORG") {
                                        is_valid
                                            && (cand.needs_synthetic_casing
                                                || is_agentive_or_starter)
                                    } else {
                                        false
                                    };

                                    if entity.score >= min_thresh && label_matches {
                                        let match_start = global_start.min(cand.start);
                                        let match_end = global_end.max(cand.end);

                                        let already_covered = all_confirmed
                                            .iter()
                                            .any(|m| match_start < m.end && match_end > m.start);

                                        if !already_covered {
                                            if let Some(ctx) = session {
                                                if entity.score >= SEMANTIC_CACHE_THRESHOLD {
                                                    ctx.semantic_cache.insert(
                                                        cand.text.to_lowercase(),
                                                        (entity.label.clone(), entity.score),
                                                    );
                                                }
                                            }

                                            all_confirmed.push(UnifiedMatch {
                                                start: match_start,
                                                end: match_end,
                                                text: normalized[match_start..match_end]
                                                    .to_string(),
                                                rule_id: format!("ai_hybrid_{}", entity.label),
                                                is_confirmed: true,
                                                action: EnforcementAction::Redact,
                                                category: PiiCategory::HighConfidenceAi,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Targeted validation for remaining unconfirmed ambiguous candidates (roster lists & agentive delimiters)
                    for cand in &ambiguous_candidates {
                        let already_covered = all_confirmed
                            .iter()
                            .any(|m| cand.start < m.end && cand.end > m.start);
                        if !already_covered {
                            if !ShadowNer::is_valid_name_span(normalized, cand.start, cand.end) {
                                continue;
                            }

                            // 1. In list coordinate with a confirmed match (e.g. "[Hoyt, Coste]")
                            let is_in_list = all_confirmed.iter().any(|m| {
                                if m.end <= cand.start {
                                    let gap = &normalized[m.end..cand.start];
                                    gap == ", " || gap == ", and " || gap == " and " || gap == " & "
                                } else if cand.end <= m.start {
                                    let gap = &normalized[cand.end..m.start];
                                    gap == ", " || gap == ", and " || gap == " and " || gap == " & "
                                } else {
                                    false
                                }
                            });

                            // 2. Preceded by agentive marker or conversational intro
                            let last_word = normalized[..cand.start]
                                .split(|c: char| {
                                    c.is_whitespace()
                                        || c == '<'
                                        || c == '['
                                        || c == '('
                                        || c == ':'
                                        || c == '"'
                                        || c == '\''
                                        || c == '*'
                                        || c == '`'
                                        || c == '.'
                                        || c == ','
                                        || c == '>'
                                        || c == ']'
                                        || c == ')'
                                })
                                .rfind(|s| !s.is_empty())
                                .unwrap_or("")
                                .to_lowercase();

                            let is_agentive = matches!(
                                last_word.as_str(),
                                "by" | "from"
                                    | "for"
                                    | "to"
                                    | "user"
                                    | "attendees"
                                    | "assigned"
                                    | "lead"
                                    | "patient"
                                    | "per"
                                    | "dr"
                                    | "mr"
                                    | "mrs"
                                    | "ms"
                                    | "ask"
                                    | "ping"
                                    | "contact"
                                    | "email"
                                    | "dm"
                                    | "cc"
                                    | "attn"
                            ) || cand.needs_synthetic_casing;

                            if is_in_list || is_agentive {
                                let capitalized_cand = {
                                    let mut chars = cand.text.chars();
                                    match chars.next() {
                                        None => String::new(),
                                        Some(first) => {
                                            first.to_uppercase().collect::<String>()
                                                + chars.as_str()
                                        }
                                    }
                                };
                                let probe_john = format!("John {}", capitalized_cand);
                                let probe_doc = format!("Doctor {}", capitalized_cand);
                                let matched = {
                                    let p1 = ai_instance.analyze(&probe_john);
                                    let m1 = p1.iter().any(|pe| {
                                        pe.score >= self.confidence_threshold.min(0.70)
                                            && (pe.label.ends_with("PER")
                                                || pe.label.ends_with("ORG"))
                                    });
                                    if m1 {
                                        true
                                    } else {
                                        let p2 = ai_instance.analyze(&probe_doc);
                                        p2.iter().any(|pe| {
                                            pe.score >= self.confidence_threshold.min(0.70)
                                                && (pe.label.ends_with("PER")
                                                    || pe.label.ends_with("ORG"))
                                        })
                                    }
                                };

                                if matched {
                                    all_confirmed.push(UnifiedMatch {
                                        start: cand.start,
                                        end: cand.end,
                                        text: normalized[cand.start..cand.end].to_string(),
                                        rule_id: "ai_hybrid_roster_B-PER".to_string(),
                                        is_confirmed: true,
                                        action: EnforcementAction::Redact,
                                        category: PiiCategory::HighConfidenceAi,
                                    });
                                }
                            }
                        }
                    }

                    pool.release(ai_instance);
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
                    if p.start < current_end {
                        return false;
                    }
                    let gap = &normalized[current_end..p.start];
                    gap.trim().is_empty()
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
                    if gap.trim().is_empty() {
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
                        last.end = merged.end;
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
                            if is_standalone_word(known_id, &text_lower) && text_lower.len() > 3 {
                                existing_token = Some(entry.value().clone());
                                break;
                            }
                        }
                    }

                    // 3. Greedy Expansion (Parent -> Child)
                    if existing_token.is_none() {
                        let mut upgrade_candidate = None;
                        for entry in ctx.identities.iter() {
                            let known_id = entry.key();
                            if is_standalone_word(&text_lower, known_id) && known_id.len() > 3 {
                                let token = entry.value().clone();
                                upgrade_candidate = Some((text_lower.clone(), token));
                                break;
                            }
                        }
                        if let Some((new_key, token)) = upgrade_candidate {
                            existing_token = Some(token.clone());
                            // Drop iterator before inserting to prevent DashMap shard deadlock
                            ctx.identities.insert(new_key, token);
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
                            let t = Self::generate_placeholder(mat.category, &mat.rule_id, id);
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
                        let t = Self::generate_placeholder(mat.category, &mat.rule_id, next_id);
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
            exact_capacity -= (*orig_end).saturating_sub(*orig_start);
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
    }

    fn restore_prompt(&self, response: &str, map: &TokenMap) -> Result<String, SovereignError> {
        if map.is_empty() {
            return Ok(response.to_string());
        }

        let mut keys = Vec::with_capacity(map.len());
        let mut values = Vec::with_capacity(map.len());
        for (k, v) in map {
            keys.push(k);
            values.push(v);
        }

        let ac = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(&keys)
            .map_err(|e| SovereignError::InternalError(e.to_string()))?;

        let result = ac.replace_all(response, &values);

        Ok(result)
    }
}

impl WardenEngine {
    /// Generates a semantic, contextual placeholder token based on the detected PII category and rule (e.g. `[EMAIL_1]`, `[NAME_1]`, `[PHONE_1]`, `[SSN_1]`, `[AFM_1]`).
    pub fn generate_placeholder(category: PiiCategory, rule_id: &str, id: usize) -> String {
        let rule_upper = rule_id.to_ascii_uppercase();
        let prefix = if rule_upper.contains("EMAIL") {
            "EMAIL"
        } else if rule_upper.contains("PERSON") || rule_upper.contains("NAME") {
            "NAME"
        } else if rule_upper.contains("PHONE") {
            "PHONE"
        } else if rule_upper.contains("AFM") {
            "AFM"
        } else if rule_upper.contains("AMKA") {
            "AMKA"
        } else if rule_upper.contains("IBAN") || rule_upper.contains("BANK") {
            "IBAN"
        } else if rule_upper.contains("CREDIT_CARD") || rule_upper.contains("CARD") {
            "CREDIT_CARD"
        } else if rule_upper.contains("SSN") {
            "SSN"
        } else if rule_upper.contains("PASSPORT") {
            "PASSPORT"
        } else if rule_upper.contains("IP_ADDRESS")
            || rule_upper.contains("IPV4")
            || rule_upper.contains("IPV6")
        {
            "IP"
        } else {
            match category {
                PiiCategory::IndividualName => "NAME",
                PiiCategory::IdentificationNumber => "ID",
                PiiCategory::FinancialData => "FINANCIAL",
                PiiCategory::ContactInfo => "CONTACT",
                PiiCategory::InternalAsset => "ASSET",
                PiiCategory::HighConfidenceAi => "AI_REDACTED",
                PiiCategory::PotentialHeuristic => "HEURISTIC",
                PiiCategory::Organization => "ORG",
                PiiCategory::Location => "LOCATION",
                PiiCategory::Other => "TOKEN",
            }
        };
        format!("[{}_{}]", prefix, id)
    }

    #[doc(hidden)]
    pub fn check_shannon_entropy_smuggling(input: &str) -> bool {
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if Self::is_base64_char(bytes[i]) {
                let start = i;
                while i < bytes.len() && Self::is_base64_char(bytes[i]) {
                    i += 1;
                }
                let len = i - start;
                if len > 40 && Self::calculate_entropy(&bytes[start..i]) > 5.8 {
                    return true;
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

#[doc(hidden)]
pub fn combine_actions(a: EnforcementAction, b: EnforcementAction) -> EnforcementAction {
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
        #[allow(deprecated)]
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
        #[allow(deprecated)]
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
