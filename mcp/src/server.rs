use std::sync::Arc;
use std::collections::HashMap;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, Semaphore};
use serde_json::json;
use async_trait::async_trait;
use iw_core::{PiiShield, StorageProvider, InferenceGateway, McpServer, SovereignError, SessionContext};
use worker::LocalSessionManager;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use tracing::{info, error};

/// A stdio-based MCP server that orchestrates the IronWarden security pipeline.
pub struct StdioMcpServer {
    shield: Arc<dyn PiiShield>,
    storage: Arc<dyn StorageProvider>,
    router: Arc<dyn InferenceGateway>,
    pub session_manager: Arc<LocalSessionManager>,
    /// --- PERFORMANCE FIX: Concurrency control for AI tasks ---
    ai_semaphore: Arc<Semaphore>,
}

impl StdioMcpServer {
    pub fn new(
        shield: Arc<dyn PiiShield>,
        storage: Arc<dyn StorageProvider>,
        router: Arc<dyn InferenceGateway>,
        session_manager: Arc<LocalSessionManager>,
    ) -> Self {
        Self {
            shield,
            storage,
            router,
            session_manager,
            // Limit to 4 concurrent AI tasks to prevent thread starvation
            ai_semaphore: Arc::new(Semaphore::new(4)),
        }
    }

    pub async fn run(&self) -> io::Result<()> {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin).lines();
        
        let (tx, mut rx) = mpsc::channel::<String>(1024);
        tokio::spawn(async move {
            let mut stdout = io::stdout();
            while let Some(msg) = rx.recv().await {
                let mut out = msg.clone();
                out.push('\n');
                let _ = stdout.write_all(out.as_bytes()).await;
                let _ = stdout.flush().await;
            }
        });

        info!("IronWarden Stdio Server running in Parallel Mode with AI Concurrency Gating.");

        while let Some(line) = reader.next_line().await? {
            let request_id = uuid::Uuid::new_v4().to_string();
            info!(request_id = %request_id, bytes = line.len(), "Processing inbound request");
            
            let shield = self.shield.clone();
            let storage = self.storage.clone();
            let router = self.router.clone();
            let session_manager = self.session_manager.clone();
            let out_tx = tx.clone();
            let semaphore = self.ai_semaphore.clone();

            tokio::spawn(async move {
                let response = handle_request_internal(line, shield, storage, router, session_manager, semaphore).await;
                
                match response {
                    Ok(res_json) => {
                        let _ = out_tx.send(res_json).await;
                        info!(request_id = %request_id, "Request successfully processed");
                    }
                    Err(e) => {
                        error!(request_id = %request_id, "Request handling failed: {}", e);
                        let err_resp = JsonRpcResponse::error(None, -32603, format!("Orchestration Failed: {}", e));
                        if let Ok(err_json) = serde_json::to_string(&err_resp) {
                            let _ = out_tx.send(err_json).await;
                        }
                    }
                }
            });
        }
        Ok(())
    }
}

async fn handle_request_internal(
    request: String,
    shield: Arc<dyn PiiShield>,
    storage: Arc<dyn StorageProvider>,
    router: Arc<dyn InferenceGateway>,
    session_manager: Arc<LocalSessionManager>,
    semaphore: Arc<Semaphore>,
) -> Result<String, SovereignError> {
    let req: JsonRpcRequest = serde_json::from_str(&request)
        .map_err(|e| SovereignError::InternalError(format!("Malformed JSON-RPC request: {}", e)))?;

    let id = req.id.clone();

    if req.method == "initialize" {
        let result = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": { "name": "IronWarden", "version": "1.2.0-STABLE" }
        });
        let resp = JsonRpcResponse::success(id, result);
        return serde_json::to_string(&resp).map_err(|e| SovereignError::InternalError(e.to_string()));
    }

    let params = req.params.as_ref().ok_or_else(|| SovereignError::InternalError("Method requires parameters".into()))?;
    let username = params.get("username").and_then(|u| u.as_str()).unwrap_or("anonymous").to_string();
    
    let user_session: Arc<SessionContext> = session_manager.get_session(&username).await
        .map_err(|e| SovereignError::InternalError(format!("Session Retrieval Failed: {}", e)))?;
    
    // METHOD: Sanitize Only
    if req.method == "mcp_sanitize_prompt" {
        let user_prompt = params.get("prompt").or_else(|| params.get("text"))
            .and_then(|p| p.as_str())
            .ok_or_else(|| SovereignError::InternalError("Method requires a 'prompt' or 'text' parameter".into()))?;
            
        let shield_clone = shield.clone();
        let prompt_clone = user_prompt.to_string();
        let session_clone = user_session.clone();
        
        // --- DEADLOCK FIX: Scope permit to AI block ---
        let report = {
            let _permit = semaphore.acquire().await.map_err(|e| SovereignError::InternalError(e.to_string()))?;
            tokio::task::spawn_blocking(move || {
                shield_clone.sanitize_prompt(&prompt_clone, Some(&session_clone))
            }).await.map_err(|e| SovereignError::InternalError(format!("Task execution failed: {}", e)))??
        };

        storage.log_audit_event(&report, user_prompt).await?;
        let _ = session_manager.save_session(&username, &user_session).await;

        let resp = JsonRpcResponse::success(id, json!(report));
        return serde_json::to_string(&resp).map_err(|e| SovereignError::InternalError(e.to_string()));
    }

    // METHOD: Restore Only
    if req.method == "mcp_restore_prompt" {
        let response_text = params.get("response").or_else(|| params.get("text"))
            .and_then(|p| p.as_str())
            .ok_or_else(|| SovereignError::InternalError("Method requires a 'response' or 'text' parameter".into()))?;
            
        let mut map: HashMap<String, String> = HashMap::new();
        for entry in user_session.token_to_pii.iter() {
            let (k, v): (String, String) = (entry.key().clone(), entry.value().clone());
            map.insert(k, v);
        }
        
        let clean_response = shield.restore_prompt(response_text, &map)?;
        let resp = JsonRpcResponse::success(id, json!(clean_response));
        return serde_json::to_string(&resp).map_err(|e| SovereignError::InternalError(e.to_string()));
    }

    // METHOD: Orchestrate (Full Pipeline)
    let user_prompt = params.get("prompt").or_else(|| params.get("text"))
        .and_then(|p| p.as_str())
        .ok_or_else(|| SovereignError::InternalError("Method requires a 'prompt' or 'text' parameter".into()))?;

    // 1. Shield & Audit (Query)
    let query_report = {
        let shield_clone = shield.clone();
        let prompt_clone = user_prompt.to_string();
        let session_clone = user_session.clone();
        // --- DEADLOCK FIX: Scope permit to AI block ---
        let _permit = semaphore.acquire().await.map_err(|e| SovereignError::InternalError(e.to_string()))?;
        tokio::task::spawn_blocking(move || {
            shield_clone.sanitize_prompt(&prompt_clone, Some(&session_clone))
        }).await.map_err(|e| SovereignError::InternalError(format!("Task execution failed: {}", e)))??
    };
    
    if let Err(e) = storage.log_audit_event(&query_report, user_prompt).await {
        return Err(SovereignError::InternalError(format!("CRITICAL: Audit log failed: {}", e)));
    }

    if query_report.is_blocked {
        let result = json!({ 
            "text": "[POLICY VIOLATION] Your request was blocked due to sensitive data leakage.",
            "policy_report": query_report.redactions 
        });
        let resp = JsonRpcResponse::success(id, result);
        return serde_json::to_string(&resp).map_err(|e| SovereignError::InternalError(e.to_string()));
    }

    // 2. Ground (Sovereign RAG)
    let raw_context = storage.fetch_context(&query_report.sanitized_text).await?;
    
    let mut sanitized_context = Vec::new();
    for snippet in raw_context {
        let shield_inner = shield.clone();
        let snippet_clone = snippet.clone();
        let session_inner = user_session.clone();
        
        // --- DEADLOCK FIX: Inner permit for snippet scrubbing ---
        let snippet_report = {
            let _permit = semaphore.acquire().await.map_err(|e| SovereignError::InternalError(e.to_string()))?;
            tokio::task::spawn_blocking(move || {
                shield_inner.sanitize_prompt(&snippet_clone, Some(&session_inner))
            }).await.map_err(|e| SovereignError::InternalError(format!("Task execution failed: {}", e)))??
        };
        
        // --- INTEGRITY FIX: Fail-Closed on Blocked Context ---
        if snippet_report.is_blocked {
            return Err(SovereignError::InternalError("CRITICAL: Knowledge base snippet triggered a BLOCK policy. Request aborted for safety.".into()));
        }
        
        let _ = storage.log_audit_event(&snippet_report, &snippet).await;
        sanitized_context.push(snippet_report.sanitized_text);
    }

    // 3. Inference
    let llm_response = router.route_prompt(&query_report.sanitized_text, &sanitized_context).await?;

    // 4. Restore & Egress
    let clean_response = shield.restore_prompt(&llm_response, &query_report.token_map)?;
    let result = json!({ "text": clean_response });
    let resp = JsonRpcResponse::success(id, result);
    
    let _ = session_manager.save_session(&username, &user_session).await;

    serde_json::to_string(&resp).map_err(|e| SovereignError::InternalError(e.to_string()))
}

#[async_trait]
impl McpServer for StdioMcpServer {
    async fn handle_request(&self, request: String) -> Result<String, SovereignError> {
        handle_request_internal(
            request, 
            self.shield.clone(), 
            self.storage.clone(), 
            self.router.clone(), 
            self.session_manager.clone(),
            self.ai_semaphore.clone()
        ).await
    }
}
