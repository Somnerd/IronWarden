use iw_core::SovereignError;
use mcp::StdioMcpServer;
use secrecy::ExposeSecret;
use std::sync::Arc;
use std::time::Duration;
use warden::{GlobalConfig, WardenConfig};

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
    // 0. Load dotenvy configuration
    dotenvy::dotenv().ok();

    // Resolve global configuration
    let global_config = match GlobalConfig::resolve() {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .init();
            tracing::error!("CRITICAL CONFIGURATION ERROR: {}", e);
            std::process::exit(1);
        }
    };

    let env_mode = std::env::var("WARDEN_ENV").unwrap_or_else(|_| "development".to_string());
    let deployment_profile = global_config.warden_mode.clone();

    // Export resolved JWT values to process env for downstream compat
    if let Some(ref aud) = global_config.warden_jwt_audience {
        std::env::set_var("WARDEN_JWT_AUDIENCE", aud);
    }
    if let Some(ref iss) = global_config.warden_jwt_issuer {
        std::env::set_var("WARDEN_JWT_ISSUER", iss);
    }

    let is_ha = deployment_profile == "HA"
        || deployment_profile == "enterprise"
        || deployment_profile == "multi-node"
        || (std::env::var("REDIS_URL").is_ok() && std::env::var("IGNORE_HA_ENFORCEMENT").is_err())
        || (std::env::var("DATABASE_URL").is_ok()
            && std::env::var("IGNORE_HA_ENFORCEMENT").is_err());

    if is_ha && env_mode != "test" {
        match std::env::var("REMOTE_AUDIT_ENDPOINT")
            .ok()
            .or(global_config.remote_audit_endpoint.clone())
        {
            Some(endpoint) if !endpoint.is_empty() => {}
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
    let api_key = secrecy::SecretString::new(global_config.openai_api_key.clone());
    let base_url = global_config.openai_base_url.clone();

    // 3. Security & Rules
    let global_pepper = match global_config.warden_pepper.clone() {
        Some(p) => secrecy::SecretVec::new(p),
        None => secrecy::SecretVec::new(vec![0u8; 32]),
    };
    let pepper_raw = global_pepper.expose_secret().clone();

    let config_path = global_config.warden_manifest_path.clone();

    // --- PERFORMANCE FIX: Initialize heavy AI engine in a blocking task ---
    let config_path_clone = config_path.clone();
    let pepper_init = secrecy::SecretVec::new(pepper_raw.clone());
    let initial_engine = iw_core::executor::BlockingExecutor::spawn_blocking(
        move || -> Result<_, SovereignError> {
            let (config, warnings) = WardenConfig::from_manifest(&config_path_clone)?;

            if !warnings.is_empty() {
                tracing::warn!("Configuration Warnings:");
                for w in &warnings {
                    tracing::warn!(" - {}", w);
                }
                use std::io::IsTerminal;
                if std::io::stdin().is_terminal() {
                    println!("WARNING: Some rules failed to load. Proceed anyway? [y/N]");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).unwrap();
                    if input.trim().to_lowercase() != "y" {
                        return Err(SovereignError::ConfigError(
                            "Boot aborted by user due to invalid rules.".into(),
                        ));
                    }
                } else {
                    return Err(SovereignError::ConfigError(
                        "Boot aborted due to invalid rules in non-interactive mode.".into(),
                    ));
                }
            }

            config.compile_engine(&pepper_init)
        },
    )
    .await
    .map_err(|e| SovereignError::InternalError(format!("Initialization task panicked: {}", e)))??;

    let dynamic_shield = Arc::new(DynamicShield {
        engine: ArcSwap::from_pointee(initial_engine),
    });
    let shield: Arc<dyn iw_core::PiiShield + Send + Sync> = dynamic_shield.clone();
    let grounding_shield: Arc<dyn iw_core::GroundingShield + Send + Sync> = dynamic_shield.clone();

    // 4. Infrastructure Data Paths
    let audit_db_path = global_config.audit_db_path.clone();
    let knowledge_path = global_config.knowledge_path.clone();

    // 5. Instantiate Control Plane Components
    let remote_audit_endpoint = global_config.remote_audit_endpoint.clone();
    let remote_audit_token = global_config.remote_audit_token.clone();

    let remote_forwarder: Option<Arc<dyn worker::audit::RemoteAuditForwarder>> =
        if let (Some(ep), Some(tk)) = (remote_audit_endpoint, remote_audit_token) {
            tracing::info!("Remote Audit Streaming: ENABLED (Endpoint: {})", ep);
            Some(Arc::new(worker::audit::HttpAuditForwarder::new(
                ep,
                secrecy::SecretString::new(tk),
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
            iw_core::executor::BlockingExecutor::spawn_blocking(move || {
                let mut latest = std::time::SystemTime::UNIX_EPOCH;
                if let Ok(metadata) = std::fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        latest = latest.max(modified);
                    }
                }
                if let Ok(content) = std::fs::read_to_string(&path) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("rules_dir:") {
                            let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                            if parts.len() == 2 {
                                let dir = parts[1].trim().trim_matches('\'').trim_matches('"');
                                if !dir.is_empty() {
                                    if let Ok(metadata) = std::fs::metadata(dir) {
                                        if let Ok(modified) = metadata.modified() {
                                            latest = latest.max(modified);
                                        }
                                    }
                                    let rules_yaml = std::path::Path::new(dir).join("rules.yaml");
                                    if let Ok(metadata) = std::fs::metadata(rules_yaml) {
                                        if let Ok(modified) = metadata.modified() {
                                            latest = latest.max(modified);
                                        }
                                    }
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
                let reload_result =
                    iw_core::executor::BlockingExecutor::spawn_blocking(move || {
                        if let Ok((new_config, warnings)) =
                            WardenConfig::from_manifest(&hot_reload_path_inner)
                        {
                            if !warnings.is_empty() {
                                tracing::warn!("Hot-reload Configuration Warnings:");
                                for w in &warnings {
                                    tracing::warn!(" - {}", w);
                                }
                            }
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

    // Sequential SQLite database initialization to prevent concurrent CREATE TABLE locks
    {
        let conn = rusqlite::Connection::open(&audit_db_path)?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA secure_delete = ON;
            CREATE TABLE IF NOT EXISTS search_jobs (
                id TEXT PRIMARY KEY,
                username TEXT,
                thread_id TEXT,
                query BLOB,
                sealed_query BLOB,
                result BLOB,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sessions (
                username TEXT PRIMARY KEY,
                session_data TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            ",
        )?;
    }

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

    let jwt_public_key = match global_config.jwt_public_key.clone() {
        Some(k) => secrecy::SecretVec::new(k),
        None => {
            if deployment_profile == "hybrid" || deployment_profile == "bridge" {
                if !global_config.allow_fallback {
                    tracing::error!("CRITICAL CONFIGURATION ERROR: Missing JWT_PUBLIC_KEY in bridge/hybrid mode");
                    std::process::exit(1);
                }
            }
            secrecy::SecretVec::new(Vec::new())
        }
    };

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

        let bridge_port = global_config.bridge_port.clone();
        let bridge_bind = global_config.bridge_addr.clone();
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

    queue.shutdown().await;
    tracing::info!("IronWarden shutting down. Sessions persisted in local SQLite ledger.");
    Ok(())
}
