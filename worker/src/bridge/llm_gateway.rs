use super::{map_error, BridgeState};
use crate::proxy::{
    authenticate, merge_token_map, resolve_upstream_key, resolve_upstream_url, AnthropicRequest,
    AuthenticatedUser, ChatCompletionRequest, CompletionRequest,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use iw_core::{SovereignError, TokenMap};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[doc(hidden)]
pub fn get_proxy_http_client(resolved_addr: Option<(&str, SocketAddr)>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(120));

    if let Some((host, addr)) = resolved_addr {
        builder = builder.resolve(host, addr);
    }

    builder.build().unwrap_or_default()
}

pub(crate) async fn process_and_audit_text(
    state: &Arc<BridgeState>,
    auth: &AuthenticatedUser,
    text: &str,
    combined_token_map: &mut TokenMap,
) -> Result<String, (StatusCode, String)> {
    let report = match state
        .shield
        .sanitize_prompt(text, Some(&auth.session))
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let status = match e {
                SovereignError::PiiViolation(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return Err((status, e.to_string()));
        }
    };

    if let Err(e) = state
        .storage
        .log_audit_event(&report, text, &auth.username)
        .await
    {
        tracing::error!("CRITICAL: Audit log failure. Aborting request: {}", e);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
    }

    if report.is_blocked {
        state
            .metrics
            .injections_blocked
            .fetch_add(1, Ordering::Relaxed);
        return Err((
            StatusCode::BAD_REQUEST,
            "[POLICY VIOLATION] Prompt blocked by IronWarden.".to_string(),
        ));
    }

    if !report.token_map.is_empty() {
        state
            .metrics
            .pii_entities_redacted
            .fetch_add(report.token_map.len() as u64, Ordering::Relaxed);
    }
    merge_token_map(combined_token_map, &report.token_map);
    Ok(report.sanitized_text)
}

type ProcessContentFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), (StatusCode, String)>> + Send + 'a>,
>;

pub(crate) fn process_and_audit_content_value<'a>(
    state: &'a Arc<BridgeState>,
    auth: &'a AuthenticatedUser,
    content: &'a mut serde_json::Value,
    combined_token_map: &'a mut TokenMap,
) -> ProcessContentFuture<'a> {
    Box::pin(async move {
        match content {
            serde_json::Value::String(s) => {
                let sanitized = process_and_audit_text(state, auth, s, combined_token_map).await?;
                *s = sanitized;
            }
            serde_json::Value::Array(items) => {
                for item in items.iter_mut() {
                    process_and_audit_content_value(state, auth, item, combined_token_map).await?;
                }
            }
            serde_json::Value::Object(map) => {
                if let Some(text_val) = map.get_mut("text") {
                    if let serde_json::Value::String(s) = text_val {
                        let sanitized =
                            process_and_audit_text(state, auth, s, combined_token_map).await?;
                        *s = sanitized;
                    } else {
                        process_and_audit_content_value(state, auth, text_val, combined_token_map)
                            .await?;
                    }
                }
                if let Some(content_val) = map.get_mut("content") {
                    process_and_audit_content_value(state, auth, content_val, combined_token_map)
                        .await?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

pub async fn handle_openai_chat_completions(
    State(state): State<Arc<BridgeState>>,
    headers: HeaderMap,
    Json(mut payload): Json<ChatCompletionRequest>,
) -> impl IntoResponse {
    state
        .metrics
        .requests_chat_completions
        .fetch_add(1, Ordering::Relaxed);

    // 1. Authenticate
    let auth = match authenticate(&headers, &state.jwt_public_key, &state.session_manager).await {
        Ok(a) => a,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    // 2. Pre-flight scrub all messages (both string and structured array content blocks)
    let mut combined_token_map = TokenMap::new();
    for msg in payload.messages.iter_mut() {
        if let Err((status, msg_err)) = process_and_audit_content_value(
            &state,
            &auth,
            &mut msg.content,
            &mut combined_token_map,
        )
        .await
        {
            return (status, msg_err).into_response();
        }
    }

    // 3. Resolve target
    let (target_url, resolved_addr) = match resolve_upstream_url(&headers, &payload.model).await {
        Ok(url) => url,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let api_key = resolve_upstream_key(&headers);
    let is_stream = payload.stream.unwrap_or(false);

    // 4. Build client with SocketAddr pinning (DNS rebinding TOCTOU defense)
    let host_for_pin = reqwest::Url::parse(&target_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()));
    let pin_arg = match (&host_for_pin, resolved_addr) {
        (Some(h), Some(addr)) => Some((h.as_str(), addr)),
        _ => None,
    };
    let client = get_proxy_http_client(pin_arg);

    // 5. Forward scrubbed request
    let upstream_resp = match client
        .post(&target_url)
        .bearer_auth(&api_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return map_error(SovereignError::GatewayTimeout(format!(
                "Upstream unreachable: {}",
                e
            )))
            .into_response()
        }
    };

    if !upstream_resp.status().is_success() {
        let status = upstream_resp.status();
        let body = upstream_resp.text().await.unwrap_or_default();
        tracing::error!("Upstream returned {}: {}", status, body);
        return (StatusCode::BAD_GATEWAY, body).into_response();
    }

    let mut full_token_map: TokenMap = auth
        .session
        .token_to_pii
        .iter()
        .map(|r| (r.key().clone(), r.value().clone()))
        .collect();
    merge_token_map(&mut full_token_map, &combined_token_map);

    let _ = state
        .session_manager
        .save_session(&auth.username, &auth.session)
        .await;

    // 6. Streaming path — hand off to SSE engine
    if is_stream {
        return crate::sse_proxy::stream_proxy_response(upstream_resp, full_token_map).await;
    }

    // 7. Non-streaming — parse and re-hydrate
    let mut res_json: serde_json::Value = match upstream_resp.json().await {
        Ok(j) => j,
        Err(e) => {
            return map_error(SovereignError::UpstreamError(format!(
                "Failed to parse upstream JSON: {}",
                e
            )))
            .into_response()
        }
    };

    if let Some(choices) = res_json.get_mut("choices").and_then(|c| c.as_array_mut()) {
        for choice in choices.iter_mut() {
            if let Some(content) = choice.pointer_mut("/message/content") {
                if let Some(text) = content.as_str() {
                    if let Ok(restored) = state.shield.restore_prompt(text, &full_token_map) {
                        *content = serde_json::Value::String(restored);
                    }
                }
            }
        }
    }

    let _ = state
        .session_manager
        .save_session(&auth.username, &auth.session)
        .await;
    (StatusCode::OK, Json(res_json)).into_response()
}

pub async fn handle_openai_legacy_completions(
    State(state): State<Arc<BridgeState>>,
    headers: HeaderMap,
    Json(mut payload): Json<CompletionRequest>,
) -> impl IntoResponse {
    state
        .metrics
        .requests_completions
        .fetch_add(1, Ordering::Relaxed);
    let auth = match authenticate(&headers, &state.jwt_public_key, &state.session_manager).await {
        Ok(a) => a,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    // 2. Pre-flight scrub prompts (string or array)
    let mut combined_token_map = TokenMap::new();
    if let Err((status, msg_err)) =
        process_and_audit_content_value(&state, &auth, &mut payload.prompt, &mut combined_token_map)
            .await
    {
        return (status, msg_err).into_response();
    }

    let (target_url_base, resolved_addr) =
        match resolve_upstream_url(&headers, &payload.model).await {
            Ok(u) => u,
            Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        };
    let target_url = target_url_base.replace("/chat/completions", "/completions");
    let api_key = resolve_upstream_key(&headers);

    let host_for_pin = reqwest::Url::parse(&target_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()));
    let pin_arg = match (&host_for_pin, resolved_addr) {
        (Some(h), Some(addr)) => Some((h.as_str(), addr)),
        _ => None,
    };
    let client = get_proxy_http_client(pin_arg);
    let upstream_resp = match client
        .post(&target_url)
        .bearer_auth(&api_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return map_error(SovereignError::GatewayTimeout(e.to_string())).into_response(),
    };

    let mut res_json: serde_json::Value = match upstream_resp.json().await {
        Ok(j) => j,
        Err(e) => return map_error(SovereignError::UpstreamError(e.to_string())).into_response(),
    };

    let mut full_token_map: TokenMap = auth
        .session
        .token_to_pii
        .iter()
        .map(|r| (r.key().clone(), r.value().clone()))
        .collect();
    merge_token_map(&mut full_token_map, &combined_token_map);

    if let Some(choices) = res_json.get_mut("choices").and_then(|c| c.as_array_mut()) {
        for choice in choices.iter_mut() {
            if let Some(text_val) = choice.get_mut("text") {
                if let Some(text) = text_val.as_str() {
                    if let Ok(restored) = state.shield.restore_prompt(text, &full_token_map) {
                        *text_val = serde_json::Value::String(restored);
                    }
                }
            }
        }
    }

    let _ = state
        .session_manager
        .save_session(&auth.username, &auth.session)
        .await;
    (StatusCode::OK, Json(res_json)).into_response()
}

pub async fn handle_openai_models(
    State(state): State<Arc<BridgeState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state
        .metrics
        .requests_models
        .fetch_add(1, Ordering::Relaxed);

    // SECURITY: Authenticate request to prevent unauthenticated upstream quota drain
    if let Err((status, msg)) =
        authenticate(&headers, &state.jwt_public_key, &state.session_manager).await
    {
        return (status, msg).into_response();
    }

    let (base, resolved_addr) = match resolve_upstream_url(&headers, "").await {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let models_url = if base.ends_with("/models") {
        base
    } else {
        let trimmed = base
            .trim_end_matches('/')
            .replace("/chat/completions", "")
            .replace("/completions", "");
        format!("{}/models", trimmed.trim_end_matches('/'))
    };
    let api_key = resolve_upstream_key(&headers);
    let host_for_pin = reqwest::Url::parse(&models_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()));
    let pin_arg = match (&host_for_pin, resolved_addr) {
        (Some(h), Some(addr)) => Some((h.as_str(), addr)),
        _ => None,
    };
    let client = get_proxy_http_client(pin_arg);
    match client.get(&models_url).bearer_auth(&api_key).send().await {
        Ok(resp) => {
            let body = resp.text().await.unwrap_or_default();
            (StatusCode::OK, body).into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

pub async fn handle_anthropic_messages(
    State(state): State<Arc<BridgeState>>,
    headers: HeaderMap,
    Json(mut payload): Json<AnthropicRequest>,
) -> impl IntoResponse {
    state
        .metrics
        .requests_messages
        .fetch_add(1, Ordering::Relaxed);
    let auth = match authenticate(&headers, &state.jwt_public_key, &state.session_manager).await {
        Ok(a) => a,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    let mut combined_token_map = TokenMap::new();

    // Sanitize system prompt
    if let Some(ref system) = payload.system.clone() {
        let sanitized =
            match process_and_audit_text(&state, &auth, system, &mut combined_token_map).await {
                Ok(s) => s,
                Err((status, msg_err)) => return (status, msg_err).into_response(),
            };
        payload.system = Some(sanitized);
    }

    // Sanitize messages — support both string and content-block array formats
    for msg in payload.messages.iter_mut() {
        if let Err((status, msg_err)) = process_and_audit_content_value(
            &state,
            &auth,
            &mut msg.content,
            &mut combined_token_map,
        )
        .await
        {
            return (status, msg_err).into_response();
        }
    }

    let (target_url, resolved_addr) = match resolve_upstream_url(&headers, &payload.model).await {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let has_custom_target = headers
        .get("X-IronWarden-Target-URL")
        .or_else(|| headers.get("x-ironwarden-target-url"))
        .is_some();

    let api_key = headers
        .get("x-api-key")
        .or_else(|| headers.get("X-IronWarden-Upstream-Key"))
        .or_else(|| headers.get("x-ironwarden-upstream-key"))
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| {
            if has_custom_target {
                None
            } else {
                std::env::var("ANTHROPIC_API_KEY").ok()
            }
        })
        .unwrap_or_default();
    let anthropic_version = headers
        .get("anthropic-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("2023-06-01");
    let is_stream = payload.stream.unwrap_or(false);

    let host_for_pin = reqwest::Url::parse(&target_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()));
    let pin_arg = match (&host_for_pin, resolved_addr) {
        (Some(h), Some(addr)) => Some((h.as_str(), addr)),
        _ => None,
    };
    let client = get_proxy_http_client(pin_arg);
    let upstream_resp = match client
        .post(&target_url)
        .header("x-api-key", &api_key)
        .header("anthropic-version", anthropic_version)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return map_error(SovereignError::GatewayTimeout(e.to_string())).into_response(),
    };

    if !upstream_resp.status().is_success() {
        let body = upstream_resp.text().await.unwrap_or_default();
        return (StatusCode::BAD_GATEWAY, body).into_response();
    }

    let mut full_token_map: TokenMap = auth
        .session
        .token_to_pii
        .iter()
        .map(|r| (r.key().clone(), r.value().clone()))
        .collect();
    merge_token_map(&mut full_token_map, &combined_token_map);

    let _ = state
        .session_manager
        .save_session(&auth.username, &auth.session)
        .await;

    if is_stream {
        return crate::sse_proxy::stream_proxy_response(upstream_resp, full_token_map).await;
    }

    let mut res_json: serde_json::Value = match upstream_resp.json().await {
        Ok(j) => j,
        Err(e) => return map_error(SovereignError::UpstreamError(e.to_string())).into_response(),
    };

    // Re-hydrate Anthropic response content blocks
    if let Some(blocks) = res_json.get_mut("content").and_then(|c| c.as_array_mut()) {
        for block in blocks.iter_mut() {
            if let Some(text_val) = block.get_mut("text") {
                if let Some(text) = text_val.as_str() {
                    if let Ok(restored) = state.shield.restore_prompt(text, &full_token_map) {
                        *text_val = serde_json::Value::String(restored);
                    }
                }
            }
        }
    }

    let _ = state
        .session_manager
        .save_session(&auth.username, &auth.session)
        .await;
    (StatusCode::OK, Json(res_json)).into_response()
}
