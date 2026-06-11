import re
with open("app/src/main.rs", "r") as f:
    content = f.read()

replacement = """#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env_mode = std::env::var("WARDEN_ENV").unwrap_or_else(|_| "development".to_string());
    let deployment_profile = std::env::var("WARDEN_MODE").unwrap_or_else(|_| "hybrid".to_string());
    let is_ha = deployment_profile == "HA" || deployment_profile == "enterprise" || deployment_profile == "multi-node" || (std::env::var("REDIS_URL").is_ok() && std::env::var("IGNORE_HA_ENFORCEMENT").is_err()) || (std::env::var("DATABASE_URL").is_ok() && std::env::var("IGNORE_HA_ENFORCEMENT").is_err());

    if is_ha && env_mode != "test" {
        match std::env::var("REMOTE_AUDIT_ENDPOINT") {
            Ok(endpoint) if !endpoint.is_empty() => {},
            _ => {
                panic!("FATAL: High Availability (HA) mode is enabled but REMOTE_AUDIT_ENDPOINT is not configured.");
            }
        }
    }
"""

content = content.replace("#[tokio::main]\nasync fn main() -> Result<(), Box<dyn std::error::Error>> {", replacement)

content = content.replace('let warden_mode = std::env::var("WARDEN_MODE").unwrap_or_else(|_| "hybrid".to_string());\n    tracing::info!("IronWarden Deployment Profile: {}", warden_mode.to_uppercase());\n\n    let mcp_handle = if warden_mode == "hybrid" || warden_mode == "mcp" {',
                          'tracing::info!("IronWarden Deployment Profile: {}", deployment_profile.to_uppercase());\n\n    let mcp_handle = if deployment_profile == "hybrid" || deployment_profile == "mcp" {')

content = content.replace('let bridge_handle = if warden_mode == "hybrid" || warden_mode == "bridge" {', 'let bridge_handle = if deployment_profile == "hybrid" || deployment_profile == "bridge" {')

with open("app/src/main.rs", "w") as f:
    f.write(content)
