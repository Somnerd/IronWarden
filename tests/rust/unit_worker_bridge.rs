// Extracted unit tests for worker::bridge
extern crate warden as iw_warden;
extern crate worker as iw_worker;

use axum::http::StatusCode;
use iw_core::{PiiShield, SovereignError, StorageProvider};
use iw_worker::bridge::*;
use iw_worker::grounding::{GroundingQueue, LocalSessionManager};
use iw_worker::metrics::GatewayMetrics;
use secrecy::SecretVec;

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::Request;
    use serde::{Deserialize, Serialize};

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
        let queue = GroundingQueue::new(
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
            metrics: Arc::new(GatewayMetrics::new()),
        });

        let app = create_bridge_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/enqueue")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
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

    #[tokio::test]
    async fn test_metrics_and_health_endpoints() {
        let pepper = SecretVec::from(vec![0u8; 32]);
        let queue = GroundingQueue::new(
            "file::memory:?cache=shared".to_string(),
            &pepper,
            None,
            None,
        )
        .unwrap();
        let session_manager =
            LocalSessionManager::new("file::memory:?cache=shared".to_string(), &pepper).unwrap();

        struct HealthyStorage;
        #[async_trait]
        impl StorageProvider for HealthyStorage {
            async fn fetch_context(&self, _: &str, _: &str) -> Result<Vec<String>, SovereignError> {
                Ok(vec![])
            }
            async fn log_audit_event(
                &self,
                _: &ScrubbingReport,
                _: &str,
                _: &str,
            ) -> Result<(), SovereignError> {
                Ok(())
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

        let state = Arc::new(BridgeState {
            shield: Arc::new(MockPiiShield),
            grounding_shield: Arc::new(MockGroundingShield),
            queue: Arc::new(queue),
            storage: Arc::new(HealthyStorage),
            session_manager,
            jwt_public_key: SecretVec::from(PUBLIC_KEY_PEM.to_vec()),
            ingress_semaphore: Arc::new(tokio::sync::Semaphore::new(100)),
            metrics: Arc::new(GatewayMetrics::new()),
        });

        let app = create_bridge_router(state);

        // 1. Text health check
        let health_req = Request::builder()
            .method("GET")
            .uri("/health")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::empty())
            .unwrap();
        let health_res = app.clone().oneshot(health_req).await.unwrap();
        let status = health_res.status();
        let body = axum::body::to_bytes(health_res.into_body(), 1024)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert_eq!(status, StatusCode::OK, "Body: {}", body_str);
        assert!(body_str.contains("HEALTHY"));

        // 2. JSON health check
        let json_health_req = Request::builder()
            .method("GET")
            .uri("/health")
            .header("Accept", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::empty())
            .unwrap();
        let json_res = app.clone().oneshot(json_health_req).await.unwrap();
        assert_eq!(json_res.status(), StatusCode::OK);
        let json_body = axum::body::to_bytes(json_res.into_body(), 1024)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&json_body).contains("\"status\":\"HEALTHY\""));

        // 3. Prometheus metrics endpoint
        let metrics_req = Request::builder()
            .method("GET")
            .uri("/metrics")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::empty())
            .unwrap();
        let metrics_res = app.clone().oneshot(metrics_req).await.unwrap();
        assert_eq!(metrics_res.status(), StatusCode::OK);
        let metrics_body = axum::body::to_bytes(metrics_res.into_body(), 4096)
            .await
            .unwrap();
        let metrics_str = String::from_utf8_lossy(&metrics_body);
        assert!(metrics_str.contains("ironwarden_uptime_seconds"));
        assert!(metrics_str.contains("ironwarden_requests_total"));
        assert!(metrics_str.contains("ironwarden_injections_blocked_total"));

        // 4. Grafana dashboard JSON endpoint
        let grafana_req = Request::builder()
            .method("GET")
            .uri("/grafana/dashboard")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::empty())
            .unwrap();
        let grafana_res = app.oneshot(grafana_req).await.unwrap();
        assert_eq!(grafana_res.status(), StatusCode::OK);
        let grafana_body = axum::body::to_bytes(grafana_res.into_body(), 16384)
            .await
            .unwrap();
        let grafana_str = String::from_utf8_lossy(&grafana_body);
        assert!(grafana_str.contains("ironwarden-main"));
        assert!(grafana_str.contains("IronWarden Universal Gateway Dashboard"));
    }

    #[tokio::test]
    async fn test_models_endpoint_unauthenticated_rejected() {
        let pepper = SecretVec::from(vec![0u8; 32]);
        let queue = GroundingQueue::new(
            "file::memory:?cache=shared".to_string(),
            &pepper,
            None,
            None,
        )
        .unwrap();
        let session_manager =
            LocalSessionManager::new("file::memory:?cache=shared".to_string(), &pepper).unwrap();

        struct DummyStorage;
        #[async_trait]
        impl StorageProvider for DummyStorage {
            async fn fetch_context(&self, _: &str, _: &str) -> Result<Vec<String>, SovereignError> {
                Ok(vec![])
            }
            async fn log_audit_event(
                &self,
                _: &ScrubbingReport,
                _: &str,
                _: &str,
            ) -> Result<(), SovereignError> {
                Ok(())
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

        let state = Arc::new(BridgeState {
            shield: Arc::new(MockPiiShield),
            grounding_shield: Arc::new(MockGroundingShield),
            queue: Arc::new(queue),
            storage: Arc::new(DummyStorage),
            session_manager,
            jwt_public_key: SecretVec::from(PUBLIC_KEY_PEM.to_vec()),
            ingress_semaphore: Arc::new(tokio::sync::Semaphore::new(10)),
            metrics: Arc::new(GatewayMetrics::new()),
        });

        let app = create_bridge_router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/v1/models")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_health_and_metrics_exempt_when_concurrency_exhausted() {
        let pepper = SecretVec::from(vec![0u8; 32]);
        let queue = GroundingQueue::new(
            "file::memory:?cache=shared".to_string(),
            &pepper,
            None,
            None,
        )
        .unwrap();
        let session_manager =
            LocalSessionManager::new("file::memory:?cache=shared".to_string(), &pepper).unwrap();

        struct DummyStorage;
        #[async_trait]
        impl StorageProvider for DummyStorage {
            async fn fetch_context(&self, _: &str, _: &str) -> Result<Vec<String>, SovereignError> {
                Ok(vec![])
            }
            async fn log_audit_event(
                &self,
                _: &ScrubbingReport,
                _: &str,
                _: &str,
            ) -> Result<(), SovereignError> {
                Ok(())
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

        // Set semaphore to 0 permits (fully exhausted concurrency)
        let state = Arc::new(BridgeState {
            shield: Arc::new(MockPiiShield),
            grounding_shield: Arc::new(MockGroundingShield),
            queue: Arc::new(queue),
            storage: Arc::new(DummyStorage),
            session_manager,
            jwt_public_key: SecretVec::from(PUBLIC_KEY_PEM.to_vec()),
            ingress_semaphore: Arc::new(tokio::sync::Semaphore::new(0)),
            metrics: Arc::new(GatewayMetrics::new()),
        });

        let app = create_bridge_router(state);

        // 1. /health MUST succeed with 200 OK even when concurrency permits are exhausted
        let health_req = Request::builder()
            .method("GET")
            .uri("/health")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::empty())
            .unwrap();
        let health_res = app.clone().oneshot(health_req).await.unwrap();
        assert_eq!(health_res.status(), StatusCode::OK);

        // 2. /metrics MUST succeed with 200 OK even when concurrency permits are exhausted
        let metrics_req = Request::builder()
            .method("GET")
            .uri("/metrics")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::empty())
            .unwrap();
        let metrics_res = app.clone().oneshot(metrics_req).await.unwrap();
        assert_eq!(metrics_res.status(), StatusCode::OK);

        // 3. Protected endpoint MUST return 429 Too Many Requests
        let enqueue_req = Request::builder()
            .method("POST")
            .uri("/enqueue")
            .header("Content-Type", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::from(r#"{"query":"test","thread_id":"t1"}"#))
            .unwrap();
        let enqueue_res = app.oneshot(enqueue_req).await.unwrap();
        assert_eq!(enqueue_res.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_target_url_invalid_fails_closed() {
        let pepper = SecretVec::from(vec![0u8; 32]);
        let queue = GroundingQueue::new(
            "file::memory:?cache=shared".to_string(),
            &pepper,
            None,
            None,
        )
        .unwrap();
        let session_manager =
            LocalSessionManager::new("file::memory:?cache=shared".to_string(), &pepper).unwrap();

        struct DummyStorage;
        #[async_trait]
        impl StorageProvider for DummyStorage {
            async fn fetch_context(&self, _: &str, _: &str) -> Result<Vec<String>, SovereignError> {
                Ok(vec![])
            }
            async fn log_audit_event(
                &self,
                _: &ScrubbingReport,
                _: &str,
                _: &str,
            ) -> Result<(), SovereignError> {
                Ok(())
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

        let state = Arc::new(BridgeState {
            shield: Arc::new(MockPiiShield),
            grounding_shield: Arc::new(MockGroundingShield),
            queue: Arc::new(queue),
            storage: Arc::new(DummyStorage),
            session_manager,
            jwt_public_key: SecretVec::from(PUBLIC_KEY_PEM.to_vec()),
            ingress_semaphore: Arc::new(tokio::sync::Semaphore::new(10)),
            metrics: Arc::new(GatewayMetrics::new()),
        });

        let app = create_bridge_router(state);

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

        // Attempt SSRF via cloud metadata target
        let req = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .header(
                "X-IronWarden-Target-URL",
                "http://169.254.169.254/latest/meta-data",
            )
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::from(
                r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#,
            ))
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        // Must fail closed with 400 Bad Request
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_proxy_http_client_with_pinned_socket_addr() {
        let pinned: std::net::SocketAddr = "127.0.0.1:11434".parse().unwrap();
        let _client = get_proxy_http_client(Some(("localhost", pinned)));
    }
}
