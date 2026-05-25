use std::sync::Arc;
use mcp::StdioMcpServer;
use iw_core::{InferenceGateway, SovereignError, McpServer};
use worker::{LocalSessionManager, WorkerStorage, SearchBoostQueue};
use tempfile::tempdir;
use secrecy::{SecretVec, ExposeSecret};
use async_trait::async_trait;

struct MockRouter;
#[async_trait]
impl InferenceGateway for MockRouter {
    async fn route_prompt(&self, prompt: &str, context: &[String]) -> Result<String, SovereignError> {
        let context_str = context.join(" | ");
        Ok(format!("Prompt: {}, Context: {}", prompt, context_str))
    }
}

#[tokio::test]
async fn test_mcp_full_pipeline_with_tantivy() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db").to_str().unwrap().to_string();
    let kb_path = dir.path().join("kb").to_str().unwrap().to_string();
    let pepper = SecretVec::new(vec![0u8; 32]);
    
    // 1. Setup Components
    let session_manager = LocalSessionManager::new(db_path.clone(), &pepper).unwrap();
    let queue = SearchBoostQueue::new(db_path.clone(), &pepper, None, None).unwrap();
    
    // Create a new SecretVec for storage as it takes ownership
    let storage_pepper = SecretVec::new(pepper.expose_secret().clone());
    let storage = Arc::new(WorkerStorage::new(&db_path, &kb_path, storage_pepper, Some(queue), None).await.unwrap());
    
    // Ingest some data into Librarian via Storage
    let librarian = worker::LocalLibrarian::new(&kb_path).await.unwrap();
    librarian.add_document("The secret project is code-named Project X.", "test_user").await.unwrap();
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
    
    // 3. Simulate Request
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "mcp_orchestrate",
        "params": {
            "prompt": "Tell me about Project X",
            "username": "somnerd"
        },
        "id": "1"
    });
    
    let response_json = mcp.handle_request(request.to_string()).await.unwrap();
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();
    
    println!("Response: {}", response);
    
    let text = response["result"]["text"].as_str().unwrap();
    
    assert!(text.contains("Project X"), "Should restore Project X in final output");
    assert!(text.contains("Context:"), "Should include context from Librarian");
    assert!(text.contains("code-named Project X"), "Context should be found and restored");
}
