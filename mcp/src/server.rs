use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use serde_json::json;
use async_trait::async_trait;
use iw_core::{PiiShield, StorageProvider, InferenceGateway, McpServer, SovereignError};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};

/// A stdio-based MCP server that orchestrates the IronWarden security pipeline.
pub struct StdioMcpServer {
    shield: Arc<dyn PiiShield>,
    storage: Arc<dyn StorageProvider>,
    router: Arc<dyn InferenceGateway>,
}

impl StdioMcpServer {
    /// Creates a new StdioMcpServer with its core dependencies injected.
    pub fn new(
        shield: Arc<dyn PiiShield>,
        storage: Arc<dyn StorageProvider>,
        router: Arc<dyn InferenceGateway>,
    ) -> Self {
        Self {
            shield,
            storage,
            router,
        }
    }

    /// The main event loop that reads JSON lines from stdin and processes them sequentially.
    pub async fn run(&self) -> io::Result<()> {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin).lines();

        // SEQUENTIAL PROCESSING: Architectural ruling to prevent stdout interleaving/corruption.
        while let Some(line) = reader.next_line().await? {
            let response = self.handle_request(line).await;
            
            match response {
                Ok(res_json) => println!("{}", res_json),
                Err(e) => {
                    // Fallback error reporting for orchestration failures
                    let err_resp = JsonRpcResponse::error(None, -32603, format!("Orchestration Failed: {}", e));
                    if let Ok(err_json) = serde_json::to_string(&err_resp) {
                        println!("{}", err_json);
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl McpServer for StdioMcpServer {
    async fn handle_request(&self, request: String) -> Result<String, SovereignError> {
        // Step 1: Ingest (JSON-RPC Parsing)
        let req: JsonRpcRequest = serde_json::from_str(&request)
            .map_err(|e| SovereignError::InternalError(format!("Malformed JSON-RPC request: {}", e)))?;

        let id = req.id.clone();

        // --- CAPABILITY NEGOTIATION (Architectural Ruling) ---
        if req.method == "initialize" {
            let result = json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {
                    "name": "IronWarden",
                    "version": "1.0.0"
                }
            });
            let resp = JsonRpcResponse::success(id, result);
            return serde_json::to_string(&resp)
                .map_err(|e| SovereignError::InternalError(e.to_string()));
        }

        // --- THE 8-STEP PIPELINE ---

        // 1. Extraction (Find the prompt within params)
        let user_prompt = req.params.as_ref()
            .and_then(|p| {
                p.get("prompt").or_else(|| p.get("text"))
            })
            .and_then(|p| p.as_str())
            .ok_or_else(|| SovereignError::InternalError("Method requires a 'prompt' or 'text' parameter in params".into()))?;

        // 2. Audit (Inbound)
        self.storage.log_audit_event("Inbound request received").await?;

        // 3. Shield (Sanitize)
        let (safe_prompt, token_map) = self.shield.sanitize_prompt(user_prompt)?;

        // 4. Ground (RAG)
        // We use the safe_prompt for context retrieval to avoid leaking PII to our own RAG store if it's external
        let context = self.storage.fetch_context(&safe_prompt).await?;

        // 5. Inference (LLM Routing)
        let llm_response = self.router.route_prompt(&safe_prompt, &context).await?;

        // 6. Shield (Restore)
        let clean_response = self.shield.restore_prompt(&llm_response, &token_map)?;

        // 7. Audit (Outbound)
        self.storage.log_audit_event("Response sanitized and returned").await?;

        // 8. Egress (Format response)
        let result = json!({ "text": clean_response });
        let resp = JsonRpcResponse::success(id, result);
        
        serde_json::to_string(&resp)
            .map_err(|e| SovereignError::InternalError(format!("Serialization Error: {}", e)))
    }
}
