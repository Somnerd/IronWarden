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

        // 2. Oversized (> 1 MiB) single line preceded by a normal event holding `[PER` must preserve
        //    event boundaries (\n\n after overflow) and flush `[PER` cleanly before the oversized line
        let big_pad = "a".repeat(1_050_000);
        let prior_event =
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi [PER\"}}]}\n\n".to_string();
        let chunk1 = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{} [PER",
            big_pad
        );
        let chunk2 = "SON_1]\"}}]}\n\ndata: [DONE]\n\n".to_string();
        let big_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from(prior_event)),
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
            !big_str.contains("[PERdata:"),
            "Buffered prior prefix bled into oversized data: line"
        );
        assert!(
            big_str.ends_with("Alice\"}}]}\n\ndata: [DONE]\n\n"),
            "Oversized line must preserve double-newline boundary before next frame"
        );

        // 2b. `event: done\ndata: [DONE]` preceded by partial token `[PER` must flush delta before `event: done`
        let done_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from(
                "data: {\"choices\":[{\"delta\":{\"content\":\"wait [PER\"}}]}\n\n",
            )),
            Ok(axum::body::Bytes::from("event: done\ndata: [DONE]\n\n")),
        ];
        let done_resp = stream_sse_bytes(futures::stream::iter(done_chunks), map.clone());
        let done_str = String::from_utf8(
            done_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let tail_pos = done_str.find("\"[PER\"").unwrap();
        let event_done_pos = done_str.find("event: done\ndata: [DONE]").unwrap();
        assert!(
            tail_pos < event_done_pos,
            "Flushed delta must precede `event: done\\ndata: [DONE]`: {}",
            done_str
        );

        // 2c. Abrupt EOF immediately after >1 MiB overflow chunk ending with `[PER` (no `\n`)
        //     must flush `[PER\n` raw without synthesizing a finish_reason JSON frame mid-line
        let eof_over_chunk = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{} [PER",
            big_pad
        );
        let eof_over_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> =
            vec![Ok(axum::body::Bytes::from(eof_over_chunk))];
        let eof_over_resp = stream_sse_bytes(futures::stream::iter(eof_over_chunks), map.clone());
        let eof_over_str = String::from_utf8(
            eof_over_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            eof_over_str.ends_with(" [PER\n"),
            "Mid-overflow abrupt EOF must flush buffered tail raw without wrapping in synthetic JSON"
        );
        assert!(
            !eof_over_str.contains("finish_reason"),
            "Mid-overflow abrupt EOF must not emit synthetic delta JSON mid-line"
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

    #[tokio::test]
    async fn test_sse_openai_metadata_never_suppressed_and_finish_reason_flushes_tail() {
        use http_body_util::BodyExt;
        use std::collections::HashMap;

        let map = HashMap::from([("[PERSON_1]".to_string(), "Alice".to_string())]);

        // 1. role, tool_calls, and usage chunks whose delta.content is a partial token prefix
        //    must NOT be dropped when SseRehydrator buffers `[PER`.
        let meta_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from_static(
                b"data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"[PER\"},\"finish_reason\":null}]}\n\n",
            )),
            Ok(axum::body::Bytes::from_static(
                b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"SON_1]\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\"}]},\"finish_reason\":null}]}\n\n",
            )),
            Ok(axum::body::Bytes::from_static(
                b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"[PER\"},\"finish_reason\":null}],\"usage\":{\"total_tokens\":42}}\n\n",
            )),
            Ok(axum::body::Bytes::from_static(
                b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"SON_1]\"},\"finish_reason\":\"stop\"}]}\n\n",
            )),
            Ok(axum::body::Bytes::from_static(b"data: [DONE]\n\n")),
        ];
        let meta_resp = stream_sse_bytes(futures::stream::iter(meta_chunks), map.clone());
        let meta_str = String::from_utf8(
            meta_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            meta_str.contains("\"role\":\"assistant\""),
            "delta.role frame was dropped by empty-delta suppression: {}",
            meta_str
        );
        assert!(
            meta_str.contains("\"tool_calls\""),
            "delta.tool_calls frame was dropped: {}",
            meta_str
        );
        assert!(
            meta_str.contains("\"total_tokens\":42"),
            "usage metadata frame was dropped: {}",
            meta_str
        );
        assert!(
            meta_str.contains("\"finish_reason\":\"stop\""),
            "finish_reason frame missing: {}",
            meta_str
        );
        assert_eq!(meta_str.matches("Alice").count(), 2);

        // 2. OpenAI finish_reason chunk with incomplete `[PER` inline in delta.content
        //    must flush `[PER` inside that chunk and keep finish_reason.
        let inline_finish_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from_static(
                b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"[PER\"},\"finish_reason\":\"stop\"}]}\n\n",
            )),
            Ok(axum::body::Bytes::from_static(b"data: [DONE]\n\n")),
        ];
        let inline_resp =
            stream_sse_bytes(futures::stream::iter(inline_finish_chunks), map.clone());
        let inline_str = String::from_utf8(
            inline_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            inline_str.contains("\"content\":\"[PER\"")
                && inline_str.contains("\"finish_reason\":\"stop\""),
            "finish_reason chunk dropped or failed to flush buffered `[PER` inline: {}",
            inline_str
        );

        // 3. OpenAI finish_reason chunk with empty delta `{}` after an earlier buffered `[PER`
        //    chunk must flush `[PER` BEFORE the `finish_reason: stop` frame.
        let split_finish_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from_static(
                b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi [PER\"},\"finish_reason\":null}]}\n\n",
            )),
            Ok(axum::body::Bytes::from_static(
                b"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            )),
            Ok(axum::body::Bytes::from_static(b"data: [DONE]\n\n")),
        ];
        let split_resp = stream_sse_bytes(futures::stream::iter(split_finish_chunks), map);
        let split_str = String::from_utf8(
            split_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let per_pos = split_str.find("[PER").expect("flushed tail [PER missing");
        let stop_pos = split_str
            .find("\"finish_reason\":\"stop\"")
            .expect("finish_reason stop frame missing");
        assert!(
            per_pos < stop_pos,
            "Tail `[PER` must flush BEFORE `finish_reason: stop`: {}",
            split_str
        );
    }

    #[tokio::test]
    async fn test_sse_reasoning_tool_calls_multichoice_escaping_and_upstream_errors() {
        use http_body_util::BodyExt;
        use std::collections::HashMap;

        let map = HashMap::from([("[PERSON_1]".to_string(), "Alice \"Ace\"\nLine2".to_string())]);
        let simple_map = HashMap::from([("[PERSON_1]".to_string(), "Alice".to_string())]);

        // 1. OpenAI reasoning_content + tool_calls.function.arguments split-token rehydration
        //    + JSON-escaped replacement for quotes/newlines inside tool arguments.
        let oai_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"think [PER\"}}]}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"SON_1] done\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\\\"name\\\":\\\"[PER\"}}]}}]}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"SON_1]\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
            )),
            Ok(axum::body::Bytes::from("data: [DONE]\n\n")),
        ];
        let oai_resp = stream_sse_bytes(futures::stream::iter(oai_chunks), map.clone());
        let oai_str = String::from_utf8(
            oai_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(!oai_str.contains("[PERSON_1]"), "Leaked token: {}", oai_str);
        // Reconstruct streamed reasoning_content and tool_calls arguments across frames
        let mut rebuilt_reasoning = String::new();
        let mut rebuilt_args = String::new();
        for line in oai_str.lines() {
            if let Some(d) = line.strip_prefix("data: ") {
                if d != "[DONE]" {
                    let v: serde_json::Value = serde_json::from_str(d).unwrap();
                    if let Some(r) = v
                        .pointer("/choices/0/delta/reasoning_content")
                        .and_then(|s| s.as_str())
                    {
                        rebuilt_reasoning.push_str(r);
                    }
                    if let Some(a) = v
                        .pointer("/choices/0/delta/tool_calls/0/function/arguments")
                        .and_then(|s| s.as_str())
                    {
                        rebuilt_args.push_str(a);
                    }
                }
            }
        }
        assert_eq!(rebuilt_reasoning, "think Alice \"Ace\"\nLine2 done");
        let parsed_args: serde_json::Value = serde_json::from_str(&rebuilt_args).expect(
            "Tool call arguments must remain valid JSON after quote/newline PII replacement",
        );
        assert_eq!(parsed_args["name"], "Alice \"Ace\"\nLine2");

        // 2. Anthropic thinking_delta + input_json_delta split-token + content_block_stop flush
        let anth_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"[PER\"}}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"SON_1] ok\"}}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"u\\\":\\\"[PER\"}}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"SON_1]\\\"}\"}}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"tail [PER\"}}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
            )),
        ];
        let anth_resp = stream_sse_bytes(futures::stream::iter(anth_chunks), simple_map.clone());
        let anth_str = String::from_utf8(
            anth_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            !anth_str.contains("[PERSON_1]"),
            "Anthropic leaked token: {}",
            anth_str
        );
        assert!(
            anth_str.contains("\"thinking\":\"Alice ok\""),
            "Thinking delta not rehydrated: {}",
            anth_str
        );
        assert!(
            anth_str.contains("Alice\\\"}"),
            "partial_json not rehydrated: {}",
            anth_str
        );
        let tail_pos = anth_str.find("tail ").unwrap();
        let block_stop_pos = anth_str.find("\"content_block_stop\"").unwrap();
        assert!(tail_pos < block_stop_pos);

        // 3. Multi-choice isolation: choices[1] finishing early must not flush choices[0]'s buffered `[PER`
        let mc_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi [PER\"}}]}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "data: {\"choices\":[{\"index\":1,\"delta\":{\"content\":\"done\"},\"finish_reason\":\"stop\"}]}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"SON_1]\"}}]}\n\n",
            )),
            Ok(axum::body::Bytes::from("data: [DONE]\n\n")),
        ];
        let mc_resp = stream_sse_bytes(futures::stream::iter(mc_chunks), simple_map.clone());
        let mc_str = String::from_utf8(
            mc_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            mc_str.contains("Alice") && !mc_str.contains("[PER"),
            "Multi-choice premature flush corrupted split token: {}",
            mc_str
        );

        // 4. Orphan `event:` + `id:` headers preceding a suppressed delta must NOT leak onto next event;
        //    and >1 MiB overflow + malformed data lines escape quotes/newlines safely.
        let orphan_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from(
                "event: custom_suppressed\nid: evt-1\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"[PER\"}}]}\n\n",
            )),
            Ok(axum::body::Bytes::from(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"SON_1]\"}}]}\n\n",
            )),
            Ok(axum::body::Bytes::from("data: non_json_[PERSON_1]_tail\n\n")),
            Ok(axum::body::Bytes::from(format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{} [PERSON_1]\"}}}}]}}\n\n",
                "x".repeat(1_050_000)
            ))),
        ];
        let orphan_resp = stream_sse_bytes(futures::stream::iter(orphan_chunks), map);
        let orphan_str = String::from_utf8(
            orphan_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            !orphan_str.contains("custom_suppressed"),
            "Orphan event header leaked: {}",
            orphan_str
        );
        assert!(
            !orphan_str.contains("evt-1"),
            "Orphan id header leaked: {}",
            orphan_str
        );
        assert!(
            orphan_str.contains("non_json_Alice \"Ace\" Line2_tail"),
            "Malformed line injected newline: {}",
            orphan_str
        );
        assert!(
            orphan_str.contains("Alice \\\"Ace\\\"\\nLine2"),
            "Overflow JSON line failed escaping: {}",
            &orphan_str[orphan_str.len().saturating_sub(200)..]
        );

        // 5. Upstream stream error must propagate an HTTP body error rather than clean EOF.
        let err_chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from(
                "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            )),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "boom",
            )),
        ];
        let err_resp = stream_sse_bytes(futures::stream::iter(err_chunks), simple_map);
        let err_collect = err_resp.into_body().collect().await;
        assert!(
            err_collect.is_err(),
            "Upstream read error must abort stream with error rather than clean EOF"
        );
    }

    #[tokio::test]
    async fn test_sse_keepalive_immediate_and_pending_lines_bounded() {
        use futures::SinkExt;
        use http_body_util::BodyExt;
        use std::collections::HashMap;

        let map = HashMap::from([("[PERSON_1]".to_string(), "Alice".to_string())]);
        let (mut tx, rx) =
            futures::channel::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(8);
        let resp = stream_sse_bytes(rx, map);
        let mut body = resp.into_body();

        tx.send(Ok(axum::body::Bytes::from(": keepalive\n")))
            .await
            .unwrap();
        let first = tokio::time::timeout(std::time::Duration::from_secs(2), body.frame())
            .await
            .expect("Keepalive comment must flush immediately without waiting for blank line")
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert_eq!(std::str::from_utf8(&first).unwrap(), ": keepalive\n");

        // Flood 40 id: lines (> MAX_PENDING_LINES=32) and verify stream bounds & delivers final data
        let flood: String = (0..40).map(|i| format!("id: {i}\n")).collect();
        tx.send(Ok(axum::body::Bytes::from(format!(
            "{flood}data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"hi [PERSON_1]\"}}}}]}}\n\n"
        ))))
        .await
        .unwrap();
        drop(tx);

        let mut rest = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(d) = frame.unwrap().into_data() {
                rest.extend_from_slice(&d);
            }
        }
        let rest_str = String::from_utf8(rest).unwrap();
        assert!(
            rest_str.contains("hi Alice"),
            "Missing rehydrated payload: {rest_str}"
        );
        assert!(rest_str.contains("id: 39\n"));
    }
}
