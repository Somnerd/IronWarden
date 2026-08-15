// Stress and concurrency tests for the bridge router verifying high-concurrency request handling, role-based authorization (JWT verification), and security policy blocking behavior.
use axum::http::StatusCode;
use iw_core::crypto::Claims;
use iw_warden::WardenConfig;
use jsonwebtoken::{encode, EncodingKey, Header};
use std::fs;
use std::sync::Arc;
use tempfile::tempdir;
use worker::{create_bridge_router, BridgeState, WorkerStorage};

#[tokio::test]
async fn test_adversarial_bridge_stress_and_blocking() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db").to_str().unwrap().to_string();
    let config_path = dir.path().join("rules.yaml");

    // Define a rule with action: Block
    let rules_yaml = r#"
rules:
  - id: "block_alice"
    pattern: "Alice"
    type: "Dictionary"
    action: "Block"
"#;
    fs::write(&config_path, rules_yaml).unwrap();

    let config = WardenConfig::from_file(&config_path).unwrap();
    let pepper = secrecy::SecretVec::new(vec![1u8; 32]);
    let storage_pepper = secrecy::SecretVec::new(vec![2u8; 32]);

    let private_key_pem = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7IpCkoSDThK2w
Ma6XkCPPvq5CpzIUXLCJ5TzAfvC5hX52/b7ilyBBHuHjQajC0AtsUocHuJoWPOyr
KClkatX4auDZzGwy6D+KIhU0cpH8VlTPJXX5NTx/916AtVjoFeTPk+RBDhTLZ+mR
f408BOvLtgJQUdgKJQZnA4e5Du0BUH87ve9OY7v+tyR0Z/4OIkR5yhnkoohZlKWQ
zaB1Yz+xjly/+zjRC3TPZ7MRB+fcX1cq33K/wuPh/Qo/mPvdLtAqIpYLWqGfA271
I0LvwN02CsEtIjJRGC5AZ+X7Eph1l57qSc0yHTkQVqjXv5KJgcLGvl301jqF/j//
BXLxixZzAgMBAAECggEAFqKEqlUO+mam95Pa0VxO6JbgzxEYHpxjghpnMcVo6pe6
BzyD9TZgYWAR5IIRnpa5ev20dXufr6bo3X77GrlNbkHHNrDiOXocDWI3/GMLQ2FR
2shmL6F/0t6h4KGOwmu7hFwYFMJWQ5ArET1DYQobV0WJnBt6LSfzUUx9AyZKBol3
6a6QvZ3OQbzrInnu8RsOXgNioi2bnrCCbdutJBwkzeIbMIh6mnGNIx0UJ92miXrz
JEPfTd9HUhahuQplsNwIfjEEPYHp0yHJRb1teJeqMV+czl1PSM4ujPrIdIHb5kog
jBh0So3pMxO6UPtRtKQcgNEpnSB+Mi8oyBokLqo6SQKBgQDtmoYmPLXCjj5Gjz4Q
QI1pq0XIZVG40wQPKOGyCEKbXjNzoccn4Q5cq3H/xmdRXcbaCzI7TuQn2C+NrMIL
RydpP/Ggb7j00q8i9u+INr41AMJPdUibTN1DfKFHvLrY6DgjW719y0u9zabjMabq
n2EB1l2CGw/7VYGsyu8v8V9DFQKBgQDJn7eHkc6pIx7l2/UlWUGNKwRQSMMbqrsN
G/5Om1T+jlxDv595UP80/Y3tx2uUS1QJRpdd8cWJ1yqIoU3CuCQZwWs8xLzbPIiZ
5y+GNfyHK1/y7hGqMiNc207StoiQjwTmvFeHNOJY5jqw7M0YsFvQ5RYEoSiKm6EB
KI9sFfT1ZwKBgCyGTWcy7ziTITZlt1KiVh2cG8qOuf6xhEw28/xBsgGdaHTdtw1R
DjjtY8Jzcn773LyVZodYpEaXK2oYGpC0d70wX14aMYWnSWx6664R3BjgmIj9SGrZ
v4ja/PoNctIcyhBOK7c79miN9h0S+91xmmMWwZUU7yzA/DjeGm5Yg+p1AoGAAaPH
5VVdPejoNmxciQo5y0EfTtvYol/4F3ozzkXbIhrcSzzCukTbXn31aoqlqFYYf97Q
GlZ+CcnzMZtGO6AtwvvcuGjNNGdAoSfNLiVAQYUryZkAEcdInFe4Q2RypeJT4uCD
Qbk/YgO1VH0IifvdM0y5qh35a28qlwzSZcmj7V8CgYEAyHgkiGHy6qSbfmudLRZt
SisXN+EVYXy2SlyMWTrO3mwnika7404PzUBv1TB/pXYykhzaQpUzQ3oFs+8M6Dv0
FvgnVB+Fa8ZR88YURVO/mdbgEOnevMlcyo6fihnc9gSxTeVuGVIJOjMdQuMOraZr
LwsIidTKKKmov8GmTX7e0Mc=
-----END PRIVATE KEY-----"#;

    let public_key_pem = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuyKQpKEg04StsDGul5Aj
z76uQqcyFFywieU8wH7wuYV+dv2+4pcgQR7h40GowtALbFKHB7iaFjzsqygpZGrV
+Grg2cxsMug/iiIVNHKR/FZUzyV1+TU8f/degLVY6BXkz5PkQQ4Uy2fpkX+NPATr
y7YCUFHYCiUGZwOHuQ7tAVB/O73vTmO7/rckdGf+DiJEecoZ5KKIWZSlkM2gdWM/
sY5cv/s40Qt0z2ezEQfn3F9XKt9yv8Lj4f0KP5j73S7QKiKWC1qhnwNu9SNC78Dd
NgrBLSIyURguQGfl+xKYdZee6knNMh05EFao17+SiYHCxr5d9NY6hf4//wVy8YsW
cwIDAQAB
-----END PUBLIC KEY-----"#;

    let jwt_public_key = secrecy::SecretVec::new(public_key_pem.as_bytes().to_vec());

    let engine = Arc::new(config.compile_engine(&pepper).unwrap());

    let storage = Arc::new(
        WorkerStorage::new(
            &db_path,
            dir.path().to_str().unwrap(),
            storage_pepper,
            None,
            None,
        )
        .await
        .unwrap(),
    );
    let session_manager = worker::LocalSessionManager::new(db_path.clone(), &pepper).unwrap();

    // Create a user session
    session_manager.get_session("test_user").await.unwrap();

    let state = Arc::new(BridgeState {
        ingress_semaphore: Arc::new(tokio::sync::Semaphore::new(100)),
        shield: engine.clone(),
        grounding_shield: engine.clone(),
        queue: Arc::new(
            worker::GroundingQueue::new(
                db_path.clone(),
                &pepper,
                Some(engine.clone()),
                Some(engine.clone()),
            )
            .unwrap(),
        ),
        storage: storage.clone(),
        session_manager: session_manager.clone(),
        jwt_public_key,
    });

    let router = create_bridge_router(state);

    // Start the server on a random port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    // Generate JWT (RS256) with valid role
    let claims = Claims {
        sub: "test_user".to_string(),
        exp: 10000000000, // far future
        roles: vec!["admin".to_string()],
    };
    let token = encode(
        &Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap();

    // Generate JWT (RS256) with no roles
    let claims_no_roles = Claims {
        sub: "test_user_no_roles".to_string(),
        exp: 10000000000, // far future
        roles: vec![],
    };
    let token_no_roles = encode(
        &Header::new(jsonwebtoken::Algorithm::RS256),
        &claims_no_roles,
        &EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap();

    std::env::set_var("WARDEN_JWT_AUDIENCE", "test_aud");
    std::env::set_var("WARDEN_JWT_ISSUER", "test_iss");

    let client = reqwest::Client::new();
    let url = format!("http://{}/enqueue", addr);

    // Test rejection for low-privileged tokens
    let payload = serde_json::json!({
        "query": "Hello Bob",
        "thread_id": "test_thread"
    });
    let res = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", token_no_roles))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "Unprivileged token should be rejected with 403 Forbidden"
    );

    let num_requests = 100; // Small sample for CI, but enough to test concurrency
    let mut handlers = Vec::new();

    for i in 0..num_requests {
        let client = client.clone();
        let url = url.clone();
        let token = token.clone();

        handlers.push(tokio::spawn(async move {
            let payload = serde_json::json!({
                "query": if i % 2 == 0 { "Hello Alice" } else { "Hello Bob" },
                "thread_id": "test_thread"
            });

            let res = client
                .post(&url)
                .header("Authorization", format!("Bearer {}", token))
                .json(&payload)
                .send()
                .await
                .unwrap();

            let status = res.status();
            if status == StatusCode::INTERNAL_SERVER_ERROR {
                println!("500 Error: {}", res.text().await.unwrap());
            }
            status
        }));
    }

    let mut blocked_count = 0;
    let mut success_count = 0;
    let mut rate_limited_count = 0;

    for h in handlers {
        let status = h.await.unwrap();
        match status {
            StatusCode::BAD_REQUEST => blocked_count += 1,
            StatusCode::OK => success_count += 1,
            StatusCode::TOO_MANY_REQUESTS => rate_limited_count += 1,
            _ => panic!("Unexpected status code: {}", status),
        }
    }

    println!(
        "Results: {} Blocked, {} Success, {} Rate Limited",
        blocked_count, success_count, rate_limited_count
    );

    // Half the requests contained "Alice" and should be blocked (unless rate limited)
    // The other half "Bob" should be successful (unless rate limited)
    assert!(blocked_count > 0, "Should have blocked some requests");
    if rate_limited_count == 0 {
        assert_eq!(blocked_count, num_requests / 2);
        assert_eq!(success_count, num_requests / 2);
    }
}
