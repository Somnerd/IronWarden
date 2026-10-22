pub mod handlers;
pub use handlers::*;

#[doc(hidden)]
pub use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use async_trait::async_trait;
use iw_core::{InferenceGateway, McpServer, PiiShield, SovereignError, StorageProvider};
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, Semaphore};
use tracing::{error, info};
use worker::LocalSessionManager;

/// A stdio-based MCP server that orchestrates the IronWarden security pipeline.
pub struct StdioMcpServer {
    #[doc(hidden)]
    pub shield: Arc<dyn PiiShield>,
    #[doc(hidden)]
    pub storage: Arc<dyn StorageProvider>,
    #[doc(hidden)]
    pub router: Arc<dyn InferenceGateway>,
    pub session_manager: Arc<LocalSessionManager>,
    /// --- PERFORMANCE FIX: Concurrency control for AI tasks ---
    #[doc(hidden)]
    pub ai_semaphore: Arc<Semaphore>,
    /// --- SECURITY FIX (V-01): Trusted Host Identity ---
    #[doc(hidden)]
    pub host_user: String,
    #[doc(hidden)]
    pub mcp_secret: String,
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

        // Enforce the secret presence at boot time
        let mcp_secret = std::env::var("WARDEN_MCP_SECRET").unwrap_or_else(|_| {
            let env = std::env::var("WARDEN_ENV").unwrap_or_default();
            let allow_fallback = std::env::var("ALLOW_FALLBACK")
                .map(|v| v.trim().to_lowercase() == "true")
                .unwrap_or(false);
            if env == "test" || (cfg!(debug_assertions) && !allow_fallback) {
                "dummy_mcp_secret_value_for_testing_purposes".to_string()
            } else if cfg!(debug_assertions)
                || env == "development"
                || env == "demo"
                || allow_fallback
            {
                "default_mcp_secret_change_in_production".to_string()
            } else {
                panic!("CRITICAL: WARDEN_MCP_SECRET must be set in production to secure the MCP Gateway.");
            }
        });

        info!(host_user = %host_user, "StdioMcpServer initialized with trusted host identity.");

        Self {
            shield,
            storage,
            router,
            session_manager,
            // Limit to 4 concurrent AI tasks to prevent thread starvation
            ai_semaphore: Arc::new(Semaphore::new(4)),
            host_user,
            mcp_secret,
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
            let mcp_secret = self.mcp_secret.clone();

            tokio::spawn(async move {
                let response = handle_request_internal(
                    line,
                    shield,
                    storage,
                    router,
                    session_manager,
                    semaphore,
                    host_user,
                    connection_id_clone,
                    mcp_secret,
                )
                .await;

                match response {
                    Ok(res_json) => {
                        let _ = out_tx.send(res_json).await;
                        info!(request_id = %request_id, "Request successfully processed");
                    }
                    Err(e) => {
                        error!(request_id = %request_id, "Request handling failed: {}", e);
                        let err_resp: JsonRpcResponse<serde_json::Value> = JsonRpcResponse::error(
                            None,
                            -32603,
                            format!("Orchestration Failed: {}", e),
                        );
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
            connection_id,
            self.mcp_secret.clone(),
        )
        .await
    }
}
