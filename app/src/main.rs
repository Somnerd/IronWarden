use iw_core::SovereignError;
use mcp::StdioMcpServer;
use std::sync::Arc;
use std::time::Duration;
use warden::WardenConfig;

use arc_swap::ArcSwap;

// Hot Reload Wrapper
struct DynamicShield {
    engine: ArcSwap<warden::WardenEngine>,
}

#[async_trait::async_trait]
impl iw_core::PiiShield for DynamicShield {
    async fn sanitize_prompt(
        &self,
        input: &str,
        session: Option<&iw_core::SessionContext>,
    ) -> Result<iw_core::ScrubbingReport, iw_core::SovereignError> {
        let engine = self.engine.load();
        engine.sanitize_prompt(input, session).await
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

impl iw_core::GroundingShield for DynamicShield {
    fn seal_query(&self, query: &str, username: &str) -> Result<Vec<u8>, iw_core::SovereignError> {
        let engine = self.engine.load();
        engine.seal_query(query, username)
    }

    fn unseal_query(&self, blob: &[u8], username: &str) -> Result<String, iw_core::SovereignError> {
        let engine = self.engine.load();
        engine.unseal_query(blob, username)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env_mode = std::env::var("WARDEN_ENV").unwrap_or_else(|_| "development".to_string());
    let deployment_profile = std::env::var("WARDEN_MODE").unwrap_or_else(|_| "hybrid".to_string());
    let is_ha = deployment_profile == "HA"
        || deployment_profile == "enterprise"
        || deployment_profile == "multi-node"
        || (std::env::var("REDIS_URL").is_ok() && std::env::var("IGNORE_HA_ENFORCEMENT").is_err())
        || (std::env::var("DATABASE_URL").is_ok()
            && std::env::var("IGNORE_HA_ENFORCEMENT").is_err());

    if is_ha && env_mode != "test" {
        match std::env::var("REMOTE_AUDIT_ENDPOINT") {
            Ok(endpoint) if !endpoint.is_empty() => {}
            _ => {
                tracing::error!(
                    "HA deployment profile ({}) enabled but REMOTE_AUDIT_ENDPOINT is not configured. Set REMOTE_AUDIT_ENDPOINT to a highly-available sink or use IGNORE_HA_ENFORCEMENT to override.",
                    deployment_profile
                );
                panic!("FATAL: High Availability (HA) mode is enabled but REMOTE_AUDIT_ENDPOINT is not configured.");
            }
        }
    }

    // 1. Initialize Tracing (Structured JSON for Production)
    let log_format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "text".to_string());
    if log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .init();
    }
    tracing::info!("Initializing IronWarden V1.2 - Sovereign Standalone Appliance");

    // 1b. FIPS 140-2/3 Readiness (WP #87)
    iw_core::fips::FipsValidator::verify_readiness()?;

    // 2. Load Configuration
    dotenvy::dotenv().ok();
    let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_else(|_| "ollama".to_string());
    let base_url = std::env::var("OPENAI_BASE_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string());

    // 3. Security & Rules
    let pepper_raw = std::env::var("WARDEN_PEPPER")
        .map_err(|_| "Missing WARDEN_PEPPER")?
        .into_bytes();
    if pepper_raw.len() < 32 {
        return Err("Insecure WARDEN_PEPPER (min 32 bytes)".into());
    }
    let global_pepper = secrecy::SecretVec::new(pepper_raw.clone());

    let config_path =
        std::env::var("WARDEN_CONFIG_PATH").unwrap_or_else(|_| "config/regions".to_string());

    // --- PERFORMANCE FIX: Initialize heavy AI engine in a blocking task ---
    let config_path_clone = config_path.clone();
    let pepper_init = secrecy::SecretVec::new(pepper_raw.clone());
    let initial_engine = tokio::task::spawn_blocking(move || {
        let config = WardenConfig::from_dir(&config_path_clone)?;
        config.compile_engine(&pepper_init)
    })
    .await
    .map_err(|e| SovereignError::InternalError(format!("Initialization task panicked: {}", e)))??;

    let dynamic_shield = Arc::new(DynamicShield {
        engine: ArcSwap::from_pointee(initial_engine),
    });
    let shield: Arc<dyn iw_core::PiiShield + Send + Sync> = dynamic_shield.clone();
    let grounding_shield: Arc<dyn iw_core::GroundingShield + Send + Sync> = dynamic_shield.clone();

    // 4. Infrastructure Data Paths
    let audit_db_path = std::env::var("AUDIT_DB_PATH").unwrap_or_else(|_| "audit.db".to_string());
    let knowledge_path =
        std::env::var("KNOWLEDGE_PATH").unwrap_or_else(|_| "data/knowledge".to_string());

    // 5. Instantiate Control Plane Components
    let remote_audit_endpoint = std::env::var("REMOTE_AUDIT_ENDPOINT").ok();
    let remote_audit_token = std::env::var("REMOTE_AUDIT_TOKEN").ok();

    let remote_forwarder: Option<Arc<dyn worker::audit::RemoteAuditForwarder>> =
        if let (Some(ep), Some(tk)) = (remote_audit_endpoint, remote_audit_token) {
            tracing::info!("Remote Audit Streaming: ENABLED (Endpoint: {})", ep);
            Some(Arc::new(worker::audit::HttpAuditForwarder::new(
                ep,
                secrecy::SecretString::new(tk.into()),
            )))
        } else {
            tracing::warn!("Remote Audit Streaming: DISABLED. Audit logs are local-only.");
            None
        };

    // Hot-reload background task
    let hot_reload_shield = dynamic_shield.clone();
    let hot_reload_path = config_path.clone();
    let hot_reload_pepper_raw = pepper_raw.clone();
    tokio::spawn(async move {
        let get_latest_modified = |path: String| async move {
            tokio::task::spawn_blocking(move || {
                let mut latest = std::time::SystemTime::UNIX_EPOCH;
                if let Ok(entries) = std::fs::read_dir(&path) {
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
            })
            .await
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        };

        let mut last_modified = get_latest_modified(hot_reload_path.clone()).await;
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let current_modified = get_latest_modified(hot_reload_path.clone()).await;

            if current_modified > last_modified {
                tracing::info!("Detected file modification in config regions directory. Hot-reloading WardenEngine...");
                let hot_reload_path_inner = hot_reload_path.clone();
                let pepper_inner = secrecy::SecretVec::new(hot_reload_pepper_raw.clone());
                let reload_result = tokio::task::spawn_blocking(move || {
                    if let Ok(new_config) = WardenConfig::from_dir(&hot_reload_path_inner) {
                        return new_config.compile_engine(&pepper_inner);
                    }
                    Err(iw_core::SovereignError::ConfigError("Reload failed".into()))
                })
                .await;

                if let Ok(Ok(new_engine)) = reload_result {
                    hot_reload_shield.engine.store(Arc::new(new_engine));
                    last_modified = current_modified;
                    tracing::info!("WardenEngine hot-reload complete.");
                }
            }
        }
    });

    let queue = Arc::new(worker::SearchBoostQueue::new(
        audit_db_path.clone(),
        &global_pepper,
        Some(shield.clone()),
        Some(grounding_shield.clone()),
    )?);
    let session_manager = worker::LocalSessionManager::new(audit_db_path.clone(), &global_pepper)?;

    // ... rest of hot-reload block ...

    let storage = Arc::new(
        worker::WorkerStorage::new(
            &audit_db_path,
            &knowledge_path,
            global_pepper,
            Some((*queue).clone()),
            remote_forwarder,
        )
        .await?,
    );

    let router = Arc::new(worker::OpenAIGateway::new(api_key, base_url));

    // 6. Initialize Parallel Control Planes (MCP + Bridge)
    tracing::info!(
        "IronWarden Deployment Profile: {}",
        deployment_profile.to_uppercase()
    );

    let mcp_handle = if deployment_profile == "hybrid" || deployment_profile == "mcp" {
        let mcp_server = StdioMcpServer::new(
            shield.clone(),
            storage.clone(),
            router.clone(),
            session_manager.clone(),
        );
        Some(tokio::spawn(async move {
            if let Err(e) = mcp_server.run().await {
                tracing::error!("MCP Server Error: {}", e);
            }
        }))
    } else {
        None
    };

    let jwt_public_key_raw = std::env::var("JWT_PUBLIC_KEY")
        .map_err(|_| "Missing JWT_PUBLIC_KEY")?
        .into_bytes();
    let jwt_public_key = secrecy::SecretVec::new(jwt_public_key_raw);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let bridge_handle = if deployment_profile == "hybrid" || deployment_profile == "bridge" {
        let bridge_state = Arc::new(worker::BridgeState {
            shield: shield.clone(),
            grounding_shield: grounding_shield.clone(),
            queue: queue.clone(),
            storage: storage.clone(),
            session_manager,
            jwt_public_key,
            ingress_semaphore: Arc::new(tokio::sync::Semaphore::new(100)),
        });

        let bridge_port = std::env::var("BRIDGE_PORT").unwrap_or_else(|_| "14141".to_string());
        let bridge_bind = std::env::var("BRIDGE_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string());
        let full_addr = format!("{}:{}", bridge_bind, bridge_port);

        let bridge_router = worker::create_bridge_router(bridge_state.clone());

        Some(tokio::spawn(async move {
            match tokio::net::TcpListener::bind(&full_addr).await {
                Ok(listener) => {
                    let server = axum::serve(
                        listener,
                        bridge_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
                    );
                    let _ = server
                        .with_graceful_shutdown(async {
                            let _ = shutdown_rx.await;
                            tracing::info!("Bridge: Graceful shutdown signal received.");
                        })
                        .await;
                }
                Err(e) => {
                    tracing::error!("CRITICAL: Bridge failed to bind to {}: {}", full_addr, e);
                }
            }
        }))
    } else {
        None
    };

    tracing::info!("IronWarden Forge ignited. Active Control Planes ready.");

    // 9. Process Signal Handling
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::warn!("SIGINT received. Initiating graceful shutdown...");
            let _ = shutdown_tx.send(());
        },
        _ = async {
            if let Some(h) = mcp_handle {
                h.await
            } else {
                std::future::pending::<Result<(), tokio::task::JoinError>>().await
            }
        } => {
            tracing::error!("MCP Control Plane terminated unexpectedly.");
        },
        _ = async {
            if let Some(h) = bridge_handle {
                h.await
            } else {
                std::future::pending::<Result<(), tokio::task::JoinError>>().await
            }
        } => {
            tracing::error!("Bridge Control Plane terminated unexpectedly.");
        },
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    tracing::info!("IronWarden shutting down. Sessions persisted in local SQLite ledger.");
    Ok(())
}
