use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::Request;

    use iw_core::{ComplianceReport, ScrubbingReport, TokenMap};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::sync::Arc;
    use tower::ServiceExt;

    const PRIVATE_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDWKHpjWw901PCx\nDi8HnsbyHY/+xBIpQQ7TpdJ5Kz2jjKoOUXGZbfmKneFXQH8BCCLTR9x7ufhwXI1B\nfn5Hi+7oD1xuAwz+u6gqeLyGbp8om5uoZhvzKnYeLNOC9qTXIzs24y8YWRDniluj\n/yKjyKttbfNzGg5UUlpSkoNmGIvQwzxN0wLLxCJRsJc5JV/AUGngK06p9T/hcu4V\naDW0bEene91pGixp90hDNVwKkDWz1PNU9KOwHuLIJxF+0EFSc3I+PNUqXG6P3In4\nC3JP5xd7ZrGDnNixfus1lXJxe8i/4+kO9Abuedb9BLHETAwHoN/yWy3TC1XLLLWV\n3CBqaumJAgMBAAECggEAFd4Aj+LtQ0TiUMnoeR2Neze+i3Pc1jPg6Nvj5QsfxPKT\ng1kYluM5BEjrs1DlcacG205ZT+mPhHWcLNBW4kUCaiqgtFEBGNpI07wL+qln/Kmq\n7WPZExgbrdLDmXnyyfmRzcsedMd/Z40On20T+JJVwsY5LLW/5HybjBaOw97aGUDu\nVXO8G2RLaDcrGIjydf8iXdKGldeVanFbAEbHuOcJceY3nW6EHawUctI7m22ZCtKu\nSgnA9SYiKamlNmEz223zeQh/K+8UNne3gERuxZ874c8t+Bi3cMInuPhpejl0bdCg\nYaJnL3OdMqnlWXm8mrHS05/XB2PyaFiw9ddtdcS5uwKBgQD04jwJSt3SwLzPRk+i\n5yZIVFoQ8T9O1+cQKQAXSwlN22//tpe44ba2C3FOkYrsU5bapT8VGnc8upQCDAk6\nyY6yeH5T5cFmylinNWFJAqHE2jV+wfbPgUmsRTYytIECq7OTixzLmLmY9vgaySBa\nARv6rGltDor38yxD7vo7sGz1gwKBgQDf4S9OXMB71Xv4xig5J9VjLN8A/u9kPjN/\npnibZF1/kQfpkekqbMveLZbbPKvGrCITiFlUTK9r9p2eBqUYtRyRV/BlKL71oVdB\nZiIivstEpucUhiKJiwrO8oJc/FpA+jRrfT5YBp07ki6jATLyuyVIBO3Rztm6AmXc\nS2EbdNaDAwKBgQCiVOZfcpWhg8qlzII2BuzFvcUGviWtaknt2IAK8N72EaUo6i2h\njV7FRsiRwMFK8A5sWmZ64tRwGW7L/JaRtdM2U9HKY9/U+AXUsfoPoAMEr3IO2R13\naMkhva+z5RwwXQnpoKox/Mfrsqu9dd5QS7P0dB5fAOj2fOi3D9ApiUZxaQKBgGY5\n56Tre0TQPVRh/xniE3C+m3FT9zGZqWA/PlEOKhdGvQstAf/KP+jKfljLQlBsZv7u\nQoPYpD0zFdODiz1V7Z58Phui2FdGfZYyMaIV5rEJWPipKvoNEDlgyJ/25qtG1ErE\nnIQLOR5raHor4Pyu8Z4KCiHERuzFjYdisAuedRjLAoGBAJTkcWpA/SKTkzjFNWfM\nYlzU1vsz9//0EHy//fDWeHqH6dWi1OOP/JnXtlDFHis6M/DvPeXAwjCFfXqnkbwZ\nPNa++c7N0aflBBOWUmo3+333Tqe/HXg/MKiAiIpRXJM2RAGUprL0P3XWXROMCwFQ\nOaWyPS+gFjrX3kXEYT60sBFa\n-----END PRIVATE KEY-----";

    const PUBLIC_KEY_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1ih6Y1sPdNTwsQ4vB57G\n8h2P/sQSKUEO06XSeSs9o4yqDlFxmW35ip3hV0B/AQgi00fce7n4cFyNQX5+R4vu\n6A9cbgMM/ruoKni8hm6fKJubqGYb8yp2HizTgvak1yM7NuMvGFkQ54pbo/8io8ir\nbW3zcxoOVFJaUpKDZhiL0MM8TdMCy8QiUbCXOSVfwFBp4CtOqfU/4XLuFWg1tGxH\np3vdaRosafdIQzVcCpA1s9TzVPSjsB7iyCcRftBBUnNyPjzVKlxuj9yJ+AtyT+cX\ne2axg5zYsX7rNZVycXvIv+PpDvQG7nnW/QSxxEwMB6Df8lst0wtVyyy1ldwgamrp\niQIDAQAB\n-----END PUBLIC KEY-----";

    #[derive(Debug, Serialize, Deserialize)]
    struct CustomClaims {
        sub: String,
        exp: usize,
        iss: String,
        aud: String,
        roles: Vec<String>,
    }

    struct FailingStorage;
    #[async_trait]
    impl StorageProvider for FailingStorage {
        async fn fetch_context(&self, _: &str, _: &str) -> Result<Vec<String>, SovereignError> {
            Ok(vec![])
        }
        async fn log_audit_event(
            &self,
            _: &ScrubbingReport,
            _: &str,
            _: &str,
        ) -> Result<(), SovereignError> {
            Err(SovereignError::InternalError("Audit write failure".into()))
        }
        async fn validate_job_access(&self, _: &str, _: &str) -> Result<bool, SovereignError> {
            Ok(true)
        }
        async fn purge_user_data(&self, _: &str) -> Result<(), SovereignError> {
            Ok(())
        }
        async fn check_health(&self) -> Result<(), SovereignError> {
            Ok(())
        }
        async fn get_compliance_report(&self) -> Result<ComplianceReport, SovereignError> {
            unimplemented!()
        }
    }

    struct MockPiiShield;
    #[async_trait]
    impl PiiShield for MockPiiShield {
        async fn sanitize_prompt(
            &self,
            prompt: &str,
            _: Option<&iw_core::SessionContext>,
        ) -> Result<ScrubbingReport, SovereignError> {
            Ok(ScrubbingReport {
                sanitized_text: prompt.to_string(),
                is_blocked: false,
                redactions: vec![],
                token_map: TokenMap::new(),
                execution_time_ms: 0,
                potential_misses: vec![],
            })
        }
        fn restore_prompt(&self, response: &str, _: &TokenMap) -> Result<String, SovereignError> {
            Ok(response.to_string())
        }
    }

    struct MockGroundingShield;
    impl iw_core::GroundingShield for MockGroundingShield {
        fn seal_query(&self, _: &str, _: &str) -> Result<Vec<u8>, SovereignError> {
            Ok(vec![])
        }
        fn unseal_query(&self, _: &[u8], _: &str) -> Result<String, SovereignError> {
            Ok(String::new())
        }
    }

    #[tokio::test]
    async fn test_audit_failure_circuit_breaker() {
        std::env::set_var("WARDEN_JWT_AUDIENCE", "test_aud");
        std::env::set_var("WARDEN_JWT_ISSUER", "test_iss");

        let claims = CustomClaims {
            sub: "admin_user".to_string(),
            exp: 9999999999,
            iss: "test_iss".to_string(),
            aud: "test_aud".to_string(),
            roles: vec!["admin".to_string()],
        };
        let key = EncodingKey::from_rsa_pem(PRIVATE_KEY_PEM).unwrap();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap();

        let pepper = SecretVec::from(vec![0u8; 32]);
        let queue = SearchBoostQueue::new(
            "file::memory:?cache=shared".to_string(),
            &pepper,
            None,
            None,
        )
        .unwrap();
        let session_manager =
            LocalSessionManager::new("file::memory:?cache=shared".to_string(), &pepper).unwrap();

        let state = Arc::new(BridgeState {
            shield: Arc::new(MockPiiShield),
            grounding_shield: Arc::new(MockGroundingShield),
            queue: Arc::new(queue),
            storage: Arc::new(FailingStorage),
            session_manager,
            jwt_public_key: SecretVec::from(PUBLIC_KEY_PEM.to_vec()),
            ingress_semaphore: Arc::new(tokio::sync::Semaphore::new(10)),
        });

        let app = create_bridge_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/enqueue")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&SearchRequest {
                    query: "test query".to_string(),
                    thread_id: "thread123".to_string(),
                    options: None,
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();

        // Should return 500 Internal Server Error due to Audit Failure
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
