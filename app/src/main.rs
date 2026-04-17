use std::sync::Arc;
use warden::AhoCorasickShield;
use worker::{WorkerStorage, OpenAIGateway};
use mcp::StdioMcpServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize Tracing for system visibility
    tracing_subscriber::fmt::init();
    tracing::info!("Initializing IronWarden V1.0 - The Sovereign AI Gateway");

    // 2. Load Configuration from .env
    dotenvy::dotenv().ok();
    
    let api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| {
            tracing::error!("CRITICAL CONFIGURATION ERROR: OPENAI_API_KEY environment variable is missing.");
            tracing::info!("Please create a .env file with OPENAI_API_KEY=your_key_here");
            "Missing OPENAI_API_KEY"
        })?;
    
    let base_url = std::env::var("OPENAI_BASE_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string());

    // 3. Instantiate the Warden (The Shield)
    // We register high-value sensitive terms for deterministic redaction
    let dictionary = vec![
        "John Doe".to_string(),
        "Internal Project Alpha".to_string(),
        "Acme Corp".to_string(),
    ];
    let shield = Arc::new(AhoCorasickShield::new(dictionary));

    // 4. Instantiate the Worker (The Librarian)
    // This initializes the audit.db and RAG providers
    let storage = Arc::new(WorkerStorage::new("audit.db")?);

    // 5. Instantiate the Router (The Network Layer)
    let router = Arc::new(OpenAIGateway::new(api_key, base_url));

    // 6. Orchestrate: Inject all components into the MCP Server (The Director)
    let server = StdioMcpServer::new(shield, storage, router);

    tracing::info!("IronWarden Forge successfully ignited. System is listening on stdio (JSON-RPC 2.0).");
    
    // 7. Start the main event loop
    server.run().await?;

    Ok(())
}
