// Extracted unit tests for worker::proxy and worker::sse_proxy
extern crate warden as iw_warden;
extern crate worker as iw_worker;

#[cfg(test)]
mod proxy_tests {
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use iw_worker::proxy::*;
    use iw_worker::TEST_ENV_MUTEX;
    use std::collections::HashMap;

    fn empty_headers() -> HeaderMap {
        HeaderMap::new()
    }

    fn headers_with(key: &str, val: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_bytes(key.as_bytes()).unwrap(),
            HeaderValue::from_str(val).unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn test_routing_header_override_takes_priority() {
        let h = headers_with(
            "X-IronWarden-Target-URL",
            "http://custom-override.example.com",
        );
        assert_eq!(
            resolve_upstream_url(&h, "claude-3").await.unwrap().0,
            "http://custom-override.example.com"
        );
    }

    #[tokio::test]
    async fn test_routing_claude_routes_to_anthropic() {
        std::env::remove_var("ANTHROPIC_BASE_URL");
        let h = empty_headers();
        let (url, _) = resolve_upstream_url(&h, "claude-3-5-sonnet-20241022")
            .await
            .unwrap();
        assert!(url.contains("anthropic.com"));
    }

    #[tokio::test]
    async fn test_routing_llama_routes_to_ollama() {
        std::env::remove_var("OLLAMA_BASE_URL");
        let h = empty_headers();
        let (url, _) = resolve_upstream_url(&h, "llama3").await.unwrap();
        assert!(url.contains("11434"));
    }

    #[tokio::test]
    async fn test_routing_mistral_routes_to_ollama() {
        std::env::remove_var("OLLAMA_BASE_URL");
        let h = empty_headers();
        let (url, _) = resolve_upstream_url(&h, "mistral-7b").await.unwrap();
        assert!(url.contains("11434"));
    }

    #[tokio::test]
    async fn test_routing_phi_routes_to_ollama() {
        std::env::remove_var("OLLAMA_BASE_URL");
        let h = empty_headers();
        let (url, _) = resolve_upstream_url(&h, "phi-3").await.unwrap();
        assert!(url.contains("11434"));
    }

    #[tokio::test]
    async fn test_routing_gemma_routes_to_ollama() {
        std::env::remove_var("OLLAMA_BASE_URL");
        let h = empty_headers();
        let (url, _) = resolve_upstream_url(&h, "gemma2").await.unwrap();
        assert!(url.contains("11434"));
    }

    #[tokio::test]
    async fn test_routing_qwen_routes_to_ollama() {
        std::env::remove_var("OLLAMA_BASE_URL");
        let h = empty_headers();
        let (url, _) = resolve_upstream_url(&h, "qwen2.5").await.unwrap();
        assert!(url.contains("11434"));
    }

    #[tokio::test]
    async fn test_routing_gpt_routes_to_openai_default() {
        std::env::remove_var("OPENAI_BASE_URL");
        let h = empty_headers();
        let (url, _) = resolve_upstream_url(&h, "gpt-4o").await.unwrap();
        assert!(url.contains("openai.com"));
    }

    #[tokio::test]
    async fn test_routing_unknown_model_routes_to_openai() {
        std::env::remove_var("OPENAI_BASE_URL");
        let h = empty_headers();
        let (url, _) = resolve_upstream_url(&h, "some-unknown-model")
            .await
            .unwrap();
        assert!(url.contains("openai.com"));
    }

    #[test]
    fn test_upstream_key_header_takes_priority() {
        let h = headers_with("X-IronWarden-Upstream-Key", "sk-from-header");
        assert_eq!(resolve_upstream_key(&h), "sk-from-header");
    }

    #[test]
    fn test_upstream_key_ollama_fallback() {
        std::env::remove_var("OPENAI_API_KEY");
        let h = empty_headers();
        assert_eq!(resolve_upstream_key(&h), "ollama");
    }

    #[test]
    fn test_upstream_key_custom_target_never_leaks_ambient_key() {
        std::env::set_var("OPENAI_API_KEY", "sk-production-ambient-secret");
        let h = headers_with(
            "X-IronWarden-Target-URL",
            "http://custom-override.example.com",
        );
        // Must NOT leak OPENAI_API_KEY to custom target URL
        assert_eq!(resolve_upstream_key(&h), "");
        std::env::remove_var("OPENAI_API_KEY");
    }

    #[test]
    fn test_upstream_key_custom_target_with_explicit_key() {
        std::env::set_var("OPENAI_API_KEY", "sk-production-ambient-secret");
        let mut h = headers_with(
            "X-IronWarden-Target-URL",
            "http://custom-override.example.com",
        );
        h.insert(
            HeaderName::from_bytes(b"X-IronWarden-Upstream-Key").unwrap(),
            HeaderValue::from_str("sk-user-custom-key").unwrap(),
        );
        assert_eq!(resolve_upstream_key(&h), "sk-user-custom-key");
        std::env::remove_var("OPENAI_API_KEY");
    }

    #[test]
    fn test_merge_token_map_basic() {
        let mut combined = HashMap::new();
        combined.insert("a".to_string(), "1".to_string());
        let mut addition = HashMap::new();
        addition.insert("b".to_string(), "2".to_string());

        merge_token_map(&mut combined, &addition);

        assert_eq!(combined.get("a").unwrap(), "1");
        assert_eq!(combined.get("b").unwrap(), "2");
        assert_eq!(combined.len(), 2);
    }

    #[test]
    fn test_merge_token_map_overwrites_same_key() {
        let mut combined = HashMap::new();
        combined.insert("a".to_string(), "1".to_string());
        let mut addition = HashMap::new();
        addition.insert("a".to_string(), "2".to_string());

        merge_token_map(&mut combined, &addition);

        assert_eq!(combined.get("a").unwrap(), "2");
        assert_eq!(combined.len(), 1);
    }

    #[test]
    fn test_merge_token_map_empty_addition() {
        let mut combined = HashMap::new();
        combined.insert("a".to_string(), "1".to_string());
        let addition = HashMap::new();

        merge_token_map(&mut combined, &addition);

        assert_eq!(combined.get("a").unwrap(), "1");
        assert_eq!(combined.len(), 1);
    }

    // ── SSRF Unit Tests ──────────────────────────────────────────────────────────

    struct TestEnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl TestEnvGuard {
        fn new(set_vars: &[(&'static str, &str)], remove_vars: &[&'static str]) -> Self {
            let mut saved = Vec::new();
            for &(k, v) in set_vars {
                saved.push((k, std::env::var(k).ok()));
                std::env::set_var(k, v);
            }
            for &k in remove_vars {
                saved.push((k, std::env::var(k).ok()));
                std::env::remove_var(k);
            }
            Self { saved }
        }
    }

    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[tokio::test]
    async fn test_validate_upstream_url_rejects_non_http_schemes() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(&[], &["WARDEN_ENV", "IRONWARDEN_ENV"]);

        assert!(validate_upstream_url("ftp://example.com/api")
            .await
            .is_err());
        assert!(validate_upstream_url("file:///etc/passwd").await.is_err());
        assert!(validate_upstream_url("gopher://127.0.0.1:70/")
            .await
            .is_err());
        assert!(validate_upstream_url("javascript:alert(1)").await.is_err());
        assert!(validate_upstream_url("").await.is_err());
        assert!(validate_upstream_url("   ").await.is_err());
    }

    #[tokio::test]
    async fn test_validate_upstream_url_blocks_metadata_always() {
        let _lock = TEST_ENV_MUTEX.lock().await;

        // 1. In dev/test mode (no env vars)
        {
            let _guard = TestEnvGuard::new(
                &[],
                &[
                    "WARDEN_ENV",
                    "IRONWARDEN_ENV",
                    "ALLOW_PRIVATE_TARGET_URL",
                    "IRONWARDEN_ALLOWED_TARGET_HOSTS",
                ],
            );

            // AWS / Cloud metadata IPs
            assert!(
                validate_upstream_url("http://169.254.169.254/latest/meta-data")
                    .await
                    .is_err()
            );
            assert!(validate_upstream_url("http://169.254.0.1/").await.is_err());
            assert!(validate_upstream_url("http://169.254.255.254/")
                .await
                .is_err());
            assert!(validate_upstream_url("http://[fe80::1]/").await.is_err());
            assert!(validate_upstream_url("http://[fe80::a00:27ff:fe8e:e912]/")
                .await
                .is_err());
            assert!(validate_upstream_url("http://[::ffff:169.254.169.254]/")
                .await
                .is_err());

            // Cloud metadata domain names
            assert!(
                validate_upstream_url("http://instance-data/latest/meta-data")
                    .await
                    .is_err()
            );
            assert!(
                validate_upstream_url("http://metadata.google.internal/computeMetadata/v1/")
                    .await
                    .is_err()
            );
            assert!(validate_upstream_url("http://api.instance-data/")
                .await
                .is_err());
            assert!(
                validate_upstream_url("http://sub.metadata.google.internal/")
                    .await
                    .is_err()
            );
        }

        // 2. In production mode
        {
            let _guard = TestEnvGuard::new(
                &[("WARDEN_ENV", "production")],
                &[
                    "ALLOW_PRIVATE_TARGET_URL",
                    "IRONWARDEN_ALLOWED_TARGET_HOSTS",
                ],
            );

            assert!(
                validate_upstream_url("http://169.254.169.254/latest/meta-data")
                    .await
                    .is_err()
            );
            assert!(validate_upstream_url("http://169.254.1.1/").await.is_err());
            assert!(validate_upstream_url("http://instance-data/")
                .await
                .is_err());
            assert!(validate_upstream_url("http://metadata.google.internal/")
                .await
                .is_err());
            assert!(validate_upstream_url("http://[fe80::1]/").await.is_err());
        }

        // 3. In production mode even with ALLOW_PRIVATE_TARGET_URL=true or allowed hosts
        {
            let _guard = TestEnvGuard::new(
                &[
                    ("WARDEN_ENV", "production"),
                    ("ALLOW_PRIVATE_TARGET_URL", "true"),
                    (
                        "IRONWARDEN_ALLOWED_TARGET_HOSTS",
                        "169.254.169.254,metadata.google.internal",
                    ),
                ],
                &[],
            );

            assert!(
                validate_upstream_url("http://169.254.169.254/latest/meta-data")
                    .await
                    .is_err()
            );
            assert!(validate_upstream_url("http://instance-data/")
                .await
                .is_err());
            assert!(validate_upstream_url("http://metadata.google.internal/")
                .await
                .is_err());
            assert!(validate_upstream_url("http://[fe80::1]/").await.is_err());
        }
    }

    #[tokio::test]
    async fn test_validate_upstream_url_blocks_dns_rebinding_metadata() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(
            &[],
            &[
                "WARDEN_ENV",
                "IRONWARDEN_ENV",
                "ALLOW_PRIVATE_TARGET_URL",
                "IRONWARDEN_ALLOWED_TARGET_HOSTS",
            ],
        );

        // nip.io resolves 169.254.169.254.nip.io to 169.254.169.254
        assert!(
            validate_upstream_url("http://169.254.169.254.nip.io/latest/meta-data")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_validate_upstream_url_production_blocks_private_ips() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(
            &[("WARDEN_ENV", "production")],
            &[
                "IRONWARDEN_ENV",
                "ALLOW_PRIVATE_TARGET_URL",
                "IRONWARDEN_ALLOWED_TARGET_HOSTS",
            ],
        );

        // Loopback
        assert!(validate_upstream_url("http://127.0.0.1:8000/v1")
            .await
            .is_err());
        assert!(validate_upstream_url("http://127.0.0.2:8000/")
            .await
            .is_err());
        assert!(validate_upstream_url("http://localhost:8000/")
            .await
            .is_err());
        assert!(validate_upstream_url("http://api.localhost:8000/")
            .await
            .is_err());
        assert!(validate_upstream_url("http://[::1]:8000/").await.is_err());
        assert!(validate_upstream_url("http://[::ffff:127.0.0.1]:8000/")
            .await
            .is_err());
        assert!(validate_upstream_url("http://0.0.0.0:8000/").await.is_err());

        // RFC 1918 10.0.0.0/8
        assert!(validate_upstream_url("http://10.0.0.1:8000/")
            .await
            .is_err());
        assert!(validate_upstream_url("http://10.255.255.254:8000/")
            .await
            .is_err());

        // RFC 1918 172.16.0.0/12
        assert!(validate_upstream_url("http://172.16.0.1:8000/")
            .await
            .is_err());
        assert!(validate_upstream_url("http://172.31.255.254:8000/")
            .await
            .is_err());

        // RFC 1918 192.168.0.0/16
        assert!(validate_upstream_url("http://192.168.1.1:8000/")
            .await
            .is_err());
        assert!(validate_upstream_url("http://192.168.254.254:8000/")
            .await
            .is_err());

        // Public URLs must succeed in production
        assert!(
            validate_upstream_url("https://api.openai.com/v1/chat/completions")
                .await
                .is_ok()
        );
        assert!(
            validate_upstream_url("https://api.anthropic.com/v1/messages")
                .await
                .is_ok()
        );
        assert!(validate_upstream_url("http://example.com").await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_upstream_url_production_with_allow_private() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(
            &[
                ("IRONWARDEN_ENV", "production"),
                ("ALLOW_PRIVATE_TARGET_URL", "true"),
            ],
            &["WARDEN_ENV", "IRONWARDEN_ALLOWED_TARGET_HOSTS"],
        );

        // Private IPs allowed with ALLOW_PRIVATE_TARGET_URL=true
        assert!(validate_upstream_url("http://127.0.0.1:8000/v1")
            .await
            .is_ok());
        assert!(validate_upstream_url("http://localhost:8000/")
            .await
            .is_ok());
        assert!(validate_upstream_url("http://10.0.0.1:8000/").await.is_ok());
        assert!(validate_upstream_url("http://192.168.1.1:8000/")
            .await
            .is_ok());

        // Metadata still blocked even with ALLOW_PRIVATE_TARGET_URL=true
        assert!(
            validate_upstream_url("http://169.254.169.254/latest/meta-data")
                .await
                .is_err()
        );
        assert!(validate_upstream_url("http://metadata.google.internal/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_upstream_url_production_with_allowed_hosts() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(
            &[
                ("WARDEN_ENV", "production"),
                (
                    "IRONWARDEN_ALLOWED_TARGET_HOSTS",
                    "10.0.0.5,ollama-internal.corp:11434,127.0.0.1",
                ),
            ],
            &["IRONWARDEN_ENV", "ALLOW_PRIVATE_TARGET_URL"],
        );

        // Explicitly allowed hosts
        assert!(validate_upstream_url("http://10.0.0.5:8080/v1")
            .await
            .is_ok());
        assert!(
            validate_upstream_url("http://ollama-internal.corp:11434/v1")
                .await
                .is_ok()
        );
        assert!(validate_upstream_url("http://127.0.0.1:9000/v1")
            .await
            .is_ok());

        // Non-allowed hosts (private and public) blocked
        assert!(validate_upstream_url("http://10.0.0.6:8080/v1")
            .await
            .is_err());
        assert!(validate_upstream_url("http://192.168.1.1:8000/")
            .await
            .is_err());
        assert!(validate_upstream_url("http://attacker.com/v1")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_upstream_url_development_permits_localhost_and_loopback() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(
            &[],
            &[
                "WARDEN_ENV",
                "IRONWARDEN_ENV",
                "ALLOW_PRIVATE_TARGET_URL",
                "IRONWARDEN_ALLOWED_TARGET_HOSTS",
            ],
        );

        // Loopback and localhost permitted in development/test
        let (res1, addr1) = validate_upstream_url("http://127.0.0.1:11434/v1/chat/completions")
            .await
            .unwrap();
        assert_eq!(res1, "http://127.0.0.1:11434/v1/chat/completions");
        assert_eq!(addr1, Some("127.0.0.1:11434".parse().unwrap()));

        let (res2, addr2) = validate_upstream_url("http://localhost:11434/v1/chat/completions")
            .await
            .unwrap();
        assert_eq!(res2, "http://localhost:11434/v1/chat/completions");
        assert!(addr2.is_some());

        let (res3, _) = validate_upstream_url("http://custom-override.example.com")
            .await
            .unwrap();
        assert_eq!(res3, "http://custom-override.example.com");

        // Metadata still strictly blocked
        assert!(
            validate_upstream_url("http://169.254.169.254/latest/meta-data")
                .await
                .is_err()
        );
        assert!(validate_upstream_url("http://instance-data/")
            .await
            .is_err());
        assert!(validate_upstream_url("http://metadata.google.internal/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_resolve_upstream_url_ssrf_rejected_fails_closed() {
        let _lock = TEST_ENV_MUTEX.lock().await;
        let _guard = TestEnvGuard::new(
            &[],
            &[
                "WARDEN_ENV",
                "IRONWARDEN_ENV",
                "OPENAI_BASE_URL",
                "ANTHROPIC_BASE_URL",
            ],
        );

        // Attempting to route to AWS metadata via X-IronWarden-Target-URL must fail closed with Err
        let h = headers_with(
            "X-IronWarden-Target-URL",
            "http://169.254.169.254/latest/meta-data",
        );
        assert!(resolve_upstream_url(&h, "claude-3").await.is_err());

        let h_openai = headers_with(
            "X-IronWarden-Target-URL",
            "http://169.254.169.254/latest/meta-data",
        );
        assert!(resolve_upstream_url(&h_openai, "gpt-4o").await.is_err());
    }
}

#[cfg(test)]
mod sse_proxy_tests {
    use iw_core::TokenMap;
    use iw_worker::sse_proxy::*;

    fn map_with(entries: &[(&str, &str)]) -> TokenMap {
        let mut m = TokenMap::new();
        for (k, v) in entries {
            m.insert(k.to_string(), v.to_string());
        }
        m
    }

    #[test]
    fn test_rehydrator_simple() {
        let map = map_with(&[("[PERSON_1]", "John Smith")]);
        let mut r = SseRehydrator::new(&map);
        let out = r.feed("Hello [PERSON_1], how are you?");
        assert_eq!(out, "Hello John Smith, how are you?");
    }

    #[test]
    fn test_rehydrator_split_token() {
        let map = map_with(&[("[PERSON_1]", "John Smith")]);
        let mut r = SseRehydrator::new(&map);
        // Chunk 1 ends mid-placeholder
        let out1 = r.feed("Hello [PER");
        assert_eq!(out1, "Hello "); // holds [PER in buffer
                                    // Chunk 2 completes it
        let out2 = r.feed("SON_1], how are you?");
        assert_eq!(out2, "John Smith, how are you?");
    }

    #[test]
    fn test_rehydrator_flush_all() {
        let map = map_with(&[("[EMAIL_1]", "test@example.com")]);
        let mut r = SseRehydrator::new(&map);
        let _ = r.feed("contact: [EMAIL");
        let flushed = r.flush_all();
        // The partial token is present but no full match → emitted as-is
        assert!(flushed.contains("[EMAIL"));
    }

    #[test]
    fn test_rehydrator_no_placeholders() {
        let map = map_with(&[]);
        let mut r = SseRehydrator::new(&map);
        let out = r.feed("Just a plain message.");
        assert_eq!(out, "Just a plain message.");
    }

    #[test]
    fn test_rehydrator_single_pass_no_collision() {
        let map = map_with(&[
            ("[TOKEN_1]", "[TOKEN_2]"),
            ("[TOKEN_2]", "COLLIDED"),
            ("[TOKEN_10]", "TEN"),
        ]);
        let mut r = SseRehydrator::new(&map);
        let out = r.feed("[TOKEN_1] and [TOKEN_2]");
        let flushed = r.flush_all();
        assert_eq!(format!("{out}{flushed}"), "[TOKEN_2] and COLLIDED");

        // Prefix disambiguation: [TOKEN_10] must not corrupt into [TOKEN_2]0, even when split
        let mut r_prefix = SseRehydrator::new(&map);
        let p1 = r_prefix.feed("val [TOKEN_1");
        let p2 = r_prefix.feed("0] and [TOKEN_1]");
        let p_flush = r_prefix.flush_all();
        assert_eq!(format!("{p1}{p2}{p_flush}"), "val TEN and [TOKEN_2]");

        // Stray and nested brackets preserve surrounding literal brackets
        let mut r_brackets = SseRehydrator::new(&map);
        let b1 = r_brackets.feed("arr[0] [[TOKEN_1]]");
        let b_flush = r_brackets.flush_all();
        assert_eq!(format!("{b1}{b_flush}"), "arr[0] [[TOKEN_2]]");
    }

    #[tokio::test]
    async fn test_stream_proxy_anthropic_flushes_trailing_partial_bracket() {
        use http_body_util::BodyExt;

        let map = map_with(&[("[PERSON_1]", "Alice")]);

        // 1. Anthropic stream ending with message_stop after a trailing partial `[PER`
        let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from(
                "event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"contact [PER\"}}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            )),
        ];

        let resp = stream_sse_bytes(futures::stream::iter(chunks), map.clone());
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(
            body_str.contains("\"text\":\"[PER\""),
            "Trailing partial bracket was dropped before message_stop: {}",
            body_str
        );
        let delta_flush_pos = body_str.find("\"[PER\"").unwrap();
        let stop_pos = body_str.find("\"type\":\"message_stop\"").unwrap();
        assert!(
            delta_flush_pos < stop_pos,
            "Flushed delta must precede message_stop event: {}",
            body_str
        );

        // 2. Anthropic stream hitting abrupt EOF without message_stop must still flush partial `[PER`
        let eof_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![Ok(
            axum::body::Bytes::from(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ping [PER\"}}\n\n",
            ),
        )];
        let eof_resp = stream_sse_bytes(futures::stream::iter(eof_chunks), map.clone());
        let eof_bytes = eof_resp.into_body().collect().await.unwrap().to_bytes();
        let eof_str = String::from_utf8(eof_bytes.to_vec()).unwrap();

        assert!(
            eof_str.contains("\"type\":\"text_delta\"") && eof_str.contains("\"text\":\"[PER\""),
            "Trailing partial bracket was dropped at EOF: {}",
            eof_str
        );

        // 3. Multi-byte UTF-8 character ("Γεια") split across chunk boundary + no-space data: + index 2 EOF
        let prefix_bytes = b"event: content_block_delta\ndata:{\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"text_delta\",\"text\":\"\xce";
        let suffix_bytes = b"\x93\xce\xb5\xce\xb9\xce\xb1 [PERSON_1] ping [PER\"}}\n\n";
        let utf8_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from_static(prefix_bytes)),
            Ok(axum::body::Bytes::from_static(suffix_bytes)),
        ];
        let utf8_resp = stream_sse_bytes(futures::stream::iter(utf8_chunks), map);
        let utf8_bytes = utf8_resp.into_body().collect().await.unwrap().to_bytes();
        let utf8_str = String::from_utf8(utf8_bytes.to_vec()).unwrap();

        assert!(
            utf8_str.contains("Γεια Alice ping "),
            "Split UTF-8 + no-space data: line failed rehydration: {}",
            utf8_str
        );
        assert!(
            utf8_str.contains("\"index\":2") && utf8_str.contains("\"text\":\"[PER\""),
            "Abrupt EOF tail flush should preserve last content block index 2: {}",
            utf8_str
        );
    }

    #[tokio::test]
    async fn test_stream_proxy_suppresses_empty_delta_and_triple_newlines() {
        use http_body_util::BodyExt;

        let map = map_with(&[("[PERSON_1]", "Alice")]);

        // Chunk 1 holds ONLY "[PER" (100% buffered), chunk 2 holds "SON_1]!"
        let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"[PER\"}}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"SON_1]!\"}}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            )),
        ];

        let resp = stream_sse_bytes(futures::stream::iter(chunks), map.clone());
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(
            !body_str.contains("\"text\":\"\""),
            "Synthetic empty delta frame must be suppressed while token is buffered: {}",
            body_str
        );
        assert!(
            !body_str.contains("\n\n\n"),
            "SSE framing must never contain triple newlines (\\n\\n\\n): {:?}",
            body_str
        );
        assert!(
            body_str.contains("\"text\":\"Alice!\""),
            "Rehydrated text should appear cleanly in second delta: {}",
            body_str
        );

        // OpenAI format with empty-while-buffered delta + [DONE]
        let openai_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from(
                "data: {\"choices\":[{\"delta\":{\"content\":\"[PER\"},\"index\":0}]}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "data: {\"choices\":[{\"delta\":{\"content\":\"SON_1]\"},\"index\":0}]}\n\n",
            )),
            Ok(axum::body::Bytes::from("data: [DONE]\n\n")),
        ];
        let oai_resp = stream_sse_bytes(futures::stream::iter(openai_chunks), map);
        let oai_bytes = oai_resp.into_body().collect().await.unwrap().to_bytes();
        let oai_str = String::from_utf8(oai_bytes.to_vec()).unwrap();

        assert!(
            !oai_str.contains("\"content\":\"\""),
            "OpenAI synthetic empty delta must be suppressed: {}",
            oai_str
        );
        assert!(
            !oai_str.contains("\n\n\n"),
            "OpenAI SSE framing must not contain triple newlines: {:?}",
            oai_str
        );
        assert!(oai_str.contains("\"content\":\"Alice\""));
    }

    #[tokio::test]
    async fn test_stream_proxy_rehydrates_malformed_json_oversized_line_and_invalid_utf8_order() {
        use http_body_util::BodyExt;

        let map = map_with(&[("[PERSON_1]", "Alice")]);

        // 1. Malformed JSON fallback must still rehydrate [PERSON_1]
        let malformed: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![Ok(
            axum::body::Bytes::from("data: {broken_json [PERSON_1]\n\n"),
        )];
        let malformed_resp = stream_sse_bytes(futures::stream::iter(malformed), map.clone());
        let malformed_str = String::from_utf8(
            malformed_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            malformed_str.contains("Alice") && !malformed_str.contains("[PERSON_1]"),
            "Malformed JSON fallback leaked raw placeholder: {}",
            malformed_str
        );

        // 2. Oversized (> 1 MiB) single line split across two TCP chunks must not inject \n\n mid-JSON or leak [PERSON_1]
        let big_pad = "a".repeat(1_050_000);
        let chunk1 = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{} [PER",
            big_pad
        );
        let chunk2 = "SON_1]\"}}]}\n\n".to_string();
        let big_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from(chunk1)),
            Ok(axum::body::Bytes::from(chunk2)),
        ];
        let big_resp = stream_sse_bytes(futures::stream::iter(big_chunks), map.clone());
        let big_str = String::from_utf8(
            big_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            big_str.contains("Alice") && !big_str.contains("[PERSON_1]"),
            "Oversized split line failed to rehydrate token"
        );
        assert!(
            !big_str.contains("Alice\"\n\n") && !big_str.contains("\n\nSON_1"),
            "Oversized split line injected spurious newlines mid-JSON"
        );

        // 3. Invalid UTF-8 byte in chunk 2 must not reorder ahead of incomplete line_buffer from chunk 1
        let inv_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from_static(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"[PERSON_1] ",
            )),
            Ok(axum::body::Bytes::from_static(b"\xff tail\"}}]}\n\n")),
        ];
        let inv_resp = stream_sse_bytes(futures::stream::iter(inv_chunks), map);
        let inv_bytes = inv_resp.into_body().collect().await.unwrap().to_bytes();
        let inv_str = String::from_utf8(inv_bytes.to_vec()).unwrap();
        let alice_pos = inv_str.find("Alice").unwrap();
        let tail_pos = inv_str.find("tail").unwrap();
        assert!(
            alice_pos < tail_pos,
            "Invalid UTF-8 chunk bypassed line_buffer out of order: {}",
            inv_str
        );
    }
}
