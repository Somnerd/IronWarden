// Integration tests verifying the Model Context Protocol (MCP) server pipeline, including StdioMcpServer orchestration, context retrieval via LocalLibrarian (Tantivy), and post-inference token de-redaction.
use async_trait::async_trait;
use iw_core::{InferenceGateway, McpServer, SovereignError};
use mcp::StdioMcpServer;
use secrecy::{ExposeSecret, SecretVec};
use std::sync::Arc;
use tempfile::tempdir;
use worker::{LocalSessionManager, SearchBoostQueue, WorkerStorage};

struct MockRouter;
#[async_trait]
impl InferenceGateway for MockRouter {
    async fn route_prompt(
        &self,
        prompt: &str,
        context: &[String],
    ) -> Result<String, SovereignError> {
        let context_str = context.join(" | ");
        Ok(format!("Prompt: {}, Context: {}", prompt, context_str))
    }
}

#[tokio::test]
async fn test_mcp_full_pipeline_with_tantivy() {
    std::env::set_var("WARDEN_USER", "test_user");
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db").to_str().unwrap().to_string();
    let kb_path = dir.path().join("kb").to_str().unwrap().to_string();
    let pepper = SecretVec::new(vec![0u8; 32]);

    // 1. Setup Components
    let session_manager = LocalSessionManager::new(db_path.clone(), &pepper).unwrap();
    let queue = SearchBoostQueue::new(db_path.clone(), &pepper, None, None).unwrap();

    // Create a new SecretVec for storage as it takes ownership
    let storage_pepper = SecretVec::new(pepper.expose_secret().clone());
    let storage = Arc::new(
        WorkerStorage::new(&db_path, &kb_path, storage_pepper, Some(queue), None)
            .await
            .unwrap(),
    );

    // Ingest some data into Librarian via Storage
    let librarian = worker::LocalLibrarian::new(&kb_path).await.unwrap();
    librarian
        .add_document("The secret project is code-named Project X.", "test_user")
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // 2. Setup Shield (Warden)
    let yaml = r#"
rules:
  - id: "project_names"
    pattern: "Project X"
    type: "Dictionary"
"#;
    let config: warden::WardenConfig = serde_yaml::from_str(yaml).unwrap();
    let shield = Arc::new(config.compile_engine(&pepper).unwrap());

    let router = Arc::new(MockRouter);

    let mcp = StdioMcpServer::new(shield, storage, router, session_manager);

    // 3. Simulate Request with valid _auth signature
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mcp_secret = std::env::var("WARDEN_MCP_SECRET")
        .unwrap_or_else(|_| "dummy_mcp_secret_value_for_testing_purposes".to_string());

    let business_params_string = r#"{"prompt":"Tell me about Project X","username":"test_user"}"#;

    let target_string = format!(
        "mcp_orchestrate:test_user:{}:{}",
        timestamp, business_params_string
    );

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(mcp_secret.as_bytes()).unwrap();
    mac.update(target_string.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "mcp_orchestrate",
        "params": {
            "prompt": "Tell me about Project X",
            "username": "test_user",
            "_auth": {
                "timestamp": timestamp,
                "signature": signature
            }
        },
        "id": "1"
    });

    let response_json = mcp.handle_request(request.to_string()).await.unwrap();
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();

    println!("Response: {}", response);

    let text = response["result"]["text"].as_str().unwrap();

    assert!(
        text.contains("Project X"),
        "Should restore Project X in final output"
    );
    assert!(
        text.contains("Context:"),
        "Should include context from Librarian"
    );
    assert!(
        text.contains("code-named Project X"),
        "Context should be found and restored"
    );
}
