use std::sync::Arc;
use std::time::Duration;
use warden::WardenConfig;
use mcp::StdioMcpServer;
use iw_core::SovereignError;

use arc_swap::ArcSwap;

// Hot Reload Wrapper
struct DynamicShield {
    engine: ArcSwap<warden::WardenEngine>,
}

impl iw_core::PiiShield for DynamicShield {
    fn sanitize_prompt(
        &self,
        input: &str,
        session: Option<&iw_core::SessionContext>,
    ) -> Result<iw_core::ScrubbingReport, iw_core::SovereignError> {
        let engine = self.engine.load();
        engine.sanitize_prompt(input, session)
    }

    fn restore_prompt(
        &self,
        response: &str,
        map: &iw_core::TokenMap,
    ) -> Result<String, iw_core::SovereignError> {
        let engine = self.engine.load();
        engine.restore_prompt(response, map)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize Tracing (Structured JSON for Production)
    let log_format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "text".to_string());
    if log_format == "json" {
        tracing_subscriber::fmt().json().with_writer(std::io::stderr).init();
    } else {
        tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    }
    tracing::info!("Initializing IronWarden V1.2 - Sovereign Standalone Appliance");

    // 1b. FIPS 140-2/3 Readiness (WP #87)
    iw_core::fips::FipsValidator::verify_readiness()?;

    // 2. Load Configuration
    dotenvy::dotenv().ok();
    let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_else(|_| "ollama".to_string());
    let base_url = std::env::var("OPENAI_BASE_URL").unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string());

    // 3. Security & Rules
    let global_pepper_bytes = std::env::var("WARDEN_PEPPER").map_err(|_| "Missing WARDEN_PEPPER")?.into_bytes();
    if global_pepper_bytes.len() < 32 { return Err("Insecure WARDEN_PEPPER (min 32 bytes)".into()); }
    let global_pepper = secrecy::SecretVec::new(global_pepper_bytes);

    let config_path = std::env::var("WARDEN_CONFIG_PATH").unwrap_or_else(|_| "config/regions".to_string());
    
    // --- PERFORMANCE FIX: Initialize heavy AI engine in a blocking task ---
    let config_path_clone = config_path.clone();
    let initial_engine = tokio::task::spawn_blocking(move || {
        let config = WardenConfig::from_dir(&config_path_clone)?;
        config.compile_engine()
    }).await.map_err(|e| SovereignError::InternalError(format!("Initialization task panicked: {}", e)))??;

    let dynamic_shield = Arc::new(DynamicShield {
        engine: ArcSwap::from_pointee(initial_engine),
    });
    let shield: Arc<dyn iw_core::PiiShield + Send + Sync> = dynamic_shield.clone();

    // 4. Infrastructure Data Paths
    let audit_db_path = std::env::var("AUDIT_DB_PATH").unwrap_or_else(|_| "audit.db".to_string());
    let knowledge_path = std::env::var("KNOWLEDGE_PATH").unwrap_or_else(|_| "data/knowledge".to_string());

    // 5. Instantiate Control Plane Components
    let queue = Arc::new(worker::SearchBoostQueue::new(audit_db_path.clone(), &global_pepper, Some(shield.clone())));
    let session_manager = worker::LocalSessionManager::new(audit_db_path.clone(), &global_pepper);
    
    // Hot-reload background task
    let hot_reload_shield = dynamic_shield.clone();
    let hot_reload_path = config_path.clone();
    tokio::spawn(async move {
        let get_latest_modified = || -> std::time::SystemTime {
            let mut latest = std::time::SystemTime::UNIX_EPOCH;
            if let Ok(entries) = std::fs::read_dir(&hot_reload_path) {
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata() {
                        if let Ok(modified) = metadata.modified() {
                            if modified > latest {
                                latest = modified;
                            }
                        }
                    }
                }
            }
            latest
        };

        let mut last_modified = get_latest_modified();
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let current_modified = get_latest_modified();
            
            if current_modified > last_modified {
                tracing::info!("Detected file modification in config regions directory. Hot-reloading WardenEngine...");
                let hot_reload_path_inner = hot_reload_path.clone();
                let reload_result = tokio::task::spawn_blocking(move || {
                    if let Ok(new_config) = WardenConfig::from_dir(&hot_reload_path_inner) {
                        return new_config.compile_engine();
                    }
                    Err(iw_core::SovereignError::ConfigError("Reload failed".into()))
                }).await;

                if let Ok(Ok(new_engine)) = reload_result {
                    hot_reload_shield.engine.store(Arc::new(new_engine));
                    last_modified = current_modified;
                    tracing::info!("WardenEngine hot-reload complete.");
                }
            }
        }
    });

    let storage = Arc::new(worker::WorkerStorage::new(
        &audit_db_path, 
        &knowledge_path,
        global_pepper, 
        Some((*queue).clone()), 
    ).await?);

    let router = Arc::new(worker::OpenAIGateway::new(api_key, base_url));

    // 6. Initialize Parallel Control Planes (MCP + Bridge)
    let mcp_server = StdioMcpServer::new(
        shield.clone(), 
        storage.clone(), 
        router.clone(),
        session_manager.clone()
    );

    let jwt_secret_bytes = std::env::var("JWT_SECRET").map_err(|_| "Missing JWT_SECRET")?.into_bytes();
    if jwt_secret_bytes.len() < 32 { return Err("Insecure JWT_SECRET (min 32 bytes)".into()); }
    let jwt_secret = secrecy::SecretVec::new(jwt_secret_bytes);

    let bridge_state = Arc::new(worker::BridgeState {
        shield: shield.clone(),
        queue: queue.clone(),
        storage: storage.clone(),
        session_manager,
        jwt_secret,
    });

    let bridge_port = std::env::var("BRIDGE_PORT").unwrap_or_else(|_| "14141".to_string());
    let bridge_bind = std::env::var("BRIDGE_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string());
    let full_addr = format!("{}:{}", bridge_bind, bridge_port);

    let bridge_router = worker::create_bridge_router(bridge_state.clone());

    tracing::info!("IronWarden Forge ignited. Dual Control Planes online.");

    let mcp_handle = tokio::spawn(async move {
        if let Err(e) = mcp_server.run().await {
            tracing::error!("MCP Server Error: {}", e);
        }
    });

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let _bridge_handle = tokio::spawn(async move {
        match tokio::net::TcpListener::bind(&full_addr).await {
            Ok(listener) => {
                let server = axum::serve(
                    listener, 
                    bridge_router.into_make_service_with_connect_info::<std::net::SocketAddr>()
                );
                let _ = server.with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                    tracing::info!("Bridge: Graceful shutdown signal received.");
                }).await;
            },
            Err(e) => {
                tracing::error!("CRITICAL: Bridge failed to bind to {}: {}", full_addr, e);
            }
        }
    });

    // 9. Process Signal Handling
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::warn!("SIGINT received. Initiating graceful shutdown...");
            let _ = shutdown_tx.send(());
        },
        _ = mcp_handle => {
            tracing::error!("MCP Control Plane terminated unexpectedly.");
        },
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    tracing::info!("IronWarden shutting down. Sessions persisted in local SQLite ledger.");
    Ok(())
}
