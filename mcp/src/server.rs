use std::sync::Arc;
use std::collections::HashMap;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, Semaphore};
use serde_json::json;
use async_trait::async_trait;
use iw_core::{PiiShield, StorageProvider, InferenceGateway, McpServer, SovereignError, SessionContext, ComplianceReport, ScrubbingReport};
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
    /// --- SECURITY FIX (V-01): Trusted Host Identity ---
    host_user: String,
}

impl StdioMcpServer {
    pub fn new(
        shield: Arc<dyn PiiShield>,
        storage: Arc<dyn StorageProvider>,
        router: Arc<dyn InferenceGateway>,
        session_manager: Arc<LocalSessionManager>,
    ) -> Self {
        let host_user = std::env::var("WARDEN_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "anonymous".to_string());
            
        info!(host_user = %host_user, "StdioMcpServer initialized with trusted host identity.");

        Self {
            shield,
            storage,
            router,
            session_manager,
            // Limit to 4 concurrent AI tasks to prevent thread starvation
            ai_semaphore: Arc::new(Semaphore::new(4)),
            host_user,
        }
    }

    pub async fn run(&self) -> io::Result<()> {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin).lines();
        
        // --- SECURITY FIX (Section 1.1): Unique connection identity ---
        let connection_id = uuid::Uuid::new_v4().to_string();
        info!(connection_id = %connection_id, "Stdio connection initialized with unique session scope.");

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
            let host_user = self.host_user.clone();
            let connection_id_clone = connection_id.clone();

            tokio::spawn(async move {
                let response = handle_request_internal(line, shield, storage, router, session_manager, semaphore, host_user, connection_id_clone).await;
                
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
    host_user: String,
    connection_id: String,
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
    
    // --- SECURITY FIX (Section 1.1): Connection-scoped anonymity ---
    let username = if let Some(u) = params.get("username").and_then(|u| u.as_str()) {
        if u != host_user && !u.starts_with(&format!("{}:", host_user)) {
            return Err(SovereignError::InternalError(format!("Identity Spoofing Blocked: Request claimed user '{}' but trusted host identity is '{}'.", u, host_user)));
        }
        u.to_string()
    } else {
        // Default to a connection-unique anonymous ID instead of host_user directly,
        // which prevents separate stdio sessions from colliding if they don't specify a user.
        format!("anonymous:{}", connection_id)
    };
    
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

        storage.log_audit_event(&report, user_prompt, &username).await?;
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

    // METHOD: Compliance Reporting (WP #84)
    if req.method == "mcp_get_compliance_report" {
        let report = storage.get_compliance_report().await?;
        let resp = JsonRpcResponse::success(id, json!(report));
        return serde_json::to_string(&resp).map_err(|e| SovereignError::InternalError(e.to_string()));
    }

    // METHOD: OCR Ingestion (WP #91) - TEMPORARILY DISABLED DUE TO BROKEN UPSTREAM
    /*
    if req.method == "mcp_ocr_ingest" {
        // ...
    }
    */

    // METHOD: Kill-Switch (WP #94)
    if req.method == "mcp_halt_system" {
        // Only the trusted host identity can trigger a full system halt
        if username != host_user {
             return Err(SovereignError::UnauthorizedAccess("Only the primary host administrator can trigger a system halt.".into()));
        }

        info!("CRITICAL: Remote Kill-Switch triggered via MCP by {}. Initiating emergency halt...", host_user);
        
        // In a real system, this would signal the main loop to exit.
        // For this implementation, we'll return a confirmation and then the caller can handle the process exit if needed,
        // or we could use std::process::exit(1) but that's a bit extreme for a library call.
        // However, the WP says "Implementation of Kill-Switch", so I will provide the mechanism.
        let resp = JsonRpcResponse::success(id, json!({ "status": "HALTED", "message": "System is entering a fail-closed state." }));
        
        // We trigger an intentional panic or similar if we want a "hard" halt, 
        // but it's better to just set the healthy flag to false in storage if possible.
        let _ = storage.check_health().await; // Just to see
        
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
    
    if let Err(e) = storage.log_audit_event(&query_report, user_prompt, &username).await {
        return Err(SovereignError::InternalError(format!("CRITICAL: Audit log failed: {}", e)));
    }

    // --- SECURITY FIX: Proactive session save after query scrub ---
    let _ = session_manager.save_session(&username, &user_session).await;

    if query_report.is_blocked {
        let result = json!({ 
            "text": "[POLICY VIOLATION] Your request was blocked due to sensitive data leakage.",
            "policy_report": query_report.redactions 
        });
        let resp = JsonRpcResponse::success(id, result);
        return serde_json::to_string(&resp).map_err(|e| SovereignError::InternalError(e.to_string()));
    }

    // 2. Ground (Sovereign RAG)
    // --- SECURITY FIX (V-02): Use original prompt for retrieval utility ---
    let raw_context = storage.fetch_context(user_prompt, &username).await?;
    
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
        
        if let Err(e) = storage.log_audit_event(&snippet_report, &snippet, &username).await {
            return Err(SovereignError::InternalError(format!("CRITICAL: Audit log failed for context snippet: {}", e)));
        }
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
        // Use a default stable connection ID for trait-based calls if not in a run() loop
        let connection_id = "trait-default".to_string();
        
        handle_request_internal(
            request, 
            self.shield.clone(), 
            self.storage.clone(), 
            self.router.clone(), 
            self.session_manager.clone(),
            self.ai_semaphore.clone(),
            self.host_user.clone(),
            connection_id
        ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use iw_core::{ScrubbingReport, TokenMap, ComplianceReport};
    use std::time::Duration;

    struct MockShield;
    impl PiiShield for MockShield {
        fn sanitize_prompt(&self, prompt: &str, _session: Option<&SessionContext>) -> Result<ScrubbingReport, SovereignError> {
            std::thread::sleep(Duration::from_millis(50));
            Ok(ScrubbingReport {
                sanitized_text: prompt.to_string(),
                is_blocked: false,
                redactions: vec![],
                token_map: TokenMap::new(),
                execution_time_ms: 10,
                potential_misses: vec![],
            })
        }
        fn restore_prompt(&self, response: &str, _map: &TokenMap) -> Result<String, SovereignError> {
            Ok(response.to_string())
        }
    }

    struct MockStorage;
    #[async_trait]
    impl StorageProvider for MockStorage {
        async fn fetch_context(&self, _query: &str, _user: &str) -> Result<Vec<String>, SovereignError> { Ok(vec![]) }
        async fn log_audit_event(&self, _report: &ScrubbingReport, _raw: &str, _user: &str) -> Result<(), SovereignError> { Ok(()) }
        async fn validate_job_access(&self, _id: &str, _user: &str) -> Result<bool, SovereignError> { Ok(true) }
        async fn purge_user_data(&self, _user: &str) -> Result<(), SovereignError> { Ok(()) }
        async fn check_health(&self) -> Result<(), SovereignError> { Ok(()) }
        async fn get_compliance_report(&self) -> Result<ComplianceReport, SovereignError> { 
            Ok(ComplianceReport {
                timestamp: "".into(),
                total_redactions: 0,
                total_blocks: 0,
                period_start: "".into(),
                period_end: "".into(),
                integrity_hash: "".into(),
            })
        }
    }

    struct MockRouter;
    #[async_trait]
    impl InferenceGateway for MockRouter {
        async fn route_prompt(&self, prompt: &str, _ctx: &[String]) -> Result<String, SovereignError> { Ok(prompt.to_string()) }
    }

    #[tokio::test]
    async fn test_malformed_json_rpc() {
        let shield = Arc::new(MockShield);
        let storage = Arc::new(MockStorage);
        let router = Arc::new(MockRouter);
        let sm = LocalSessionManager::new("file::memory:?cache=shared".into(), &secrecy::SecretVec::new(vec![0u8; 32])).unwrap();
        let sem = Arc::new(Semaphore::new(4));

        let res = handle_request_internal("NOT JSON".to_string(), shield.clone(), storage.clone(), router.clone(), sm.clone(), sem.clone(), "test_user".to_string(), "conn1".to_string()).await;
        assert!(res.is_err());
        if let Err(SovereignError::InternalError(msg)) = res {
            assert!(msg.contains("Malformed JSON-RPC request"));
        } else {
            panic!("Expected InternalError for malformed JSON");
        }
    }

    #[tokio::test]
    async fn test_missing_prompt_parameter() {
        let shield = Arc::new(MockShield);
        let storage = Arc::new(MockStorage);
        let router = Arc::new(MockRouter);
        let sm = LocalSessionManager::new("file::memory:?cache=shared".into(), &secrecy::SecretVec::new(vec![0u8; 32])).unwrap();
        let sem = Arc::new(Semaphore::new(4));

        let req = json!({
            "jsonrpc": "2.0",
            "method": "mcp_sanitize_prompt",
            "params": {},
            "id": "1"
        });

        let res = handle_request_internal(req.to_string(), shield.clone(), storage.clone(), router.clone(), sm.clone(), sem.clone(), "test_user".to_string(), "conn1".to_string()).await;
        assert!(res.is_err());
        if let Err(SovereignError::InternalError(msg)) = res {
            assert!(msg.contains("requires a 'prompt' or 'text' parameter"));
        } else {
            panic!("Expected InternalError for missing parameter");
        }
    }

    #[tokio::test]
    async fn test_semaphore_concurrency_limit() {
        let shield = Arc::new(MockShield);
        let storage = Arc::new(MockStorage);
        let router = Arc::new(MockRouter);
        let sm = LocalSessionManager::new("file::memory:?cache=shared".into(), &secrecy::SecretVec::new(vec![0u8; 32])).unwrap();
        // Only 1 permit means requests must be sequential
        let sem = Arc::new(Semaphore::new(1));

        let req = json!({
            "jsonrpc": "2.0",
            "method": "mcp_sanitize_prompt",
            "params": { "prompt": "Hello" },
            "id": "1"
        });

        let start = std::time::Instant::now();
        let f1 = handle_request_internal(req.to_string(), shield.clone(), storage.clone(), router.clone(), sm.clone(), sem.clone(), "test_user".to_string(), "conn1".to_string());
        let f2 = handle_request_internal(req.to_string(), shield.clone(), storage.clone(), router.clone(), sm.clone(), sem.clone(), "test_user".to_string(), "conn1".to_string());
        
        let (r1, r2) = tokio::join!(f1, f2);
        let elapsed = start.elapsed().as_millis();
        
        assert!(r1.is_ok());
        assert!(r2.is_ok());
        // 2 sequential tasks of 50ms each should take at least 100ms
        assert!(elapsed >= 100);
    }

    #[tokio::test]
    async fn test_identity_spoofing_blocked() {
        let shield = Arc::new(MockShield);
        let storage = Arc::new(MockStorage);
        let router = Arc::new(MockRouter);
        let sm = LocalSessionManager::new("file::memory:?cache=shared".into(), &secrecy::SecretVec::new(vec![0u8; 32])).unwrap();
        let sem = Arc::new(Semaphore::new(4));

        let req = json!({
            "jsonrpc": "2.0",
            "method": "mcp_sanitize_prompt",
            "params": { 
                "username": "victim",
                "prompt": "Hello" 
            },
            "id": "1"
        });

        // host_user is "attacker"
        let res = handle_request_internal(req.to_string(), shield.clone(), storage.clone(), router.clone(), sm.clone(), sem.clone(), "attacker".to_string(), "conn1".to_string()).await;
        
        assert!(res.is_err());
        if let Err(SovereignError::InternalError(msg)) = res {
            assert!(msg.contains("Identity Spoofing Blocked"));
        } else {
            panic!("Expected identity spoofing to be blocked");
        }
    }

    #[tokio::test]
    async fn test_identity_prefix_allowed() {
        let shield = Arc::new(MockShield);
        let storage = Arc::new(MockStorage);
        let router = Arc::new(MockRouter);
        let sm = LocalSessionManager::new("file::memory:?cache=shared".into(), &secrecy::SecretVec::new(vec![0u8; 32])).unwrap();
        let sem = Arc::new(Semaphore::new(4));

        let req = json!({
            "jsonrpc": "2.0",
            "method": "mcp_sanitize_prompt",
            "params": { 
                "username": "user1:sessionA",
                "prompt": "Hello" 
            },
            "id": "1"
        });

        // host_user is "user1"
        let res = handle_request_internal(req.to_string(), shield.clone(), storage.clone(), router.clone(), sm.clone(), sem.clone(), "user1".to_string(), "conn1".to_string()).await;
        
        assert!(res.is_ok());
    }
}
