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
}
