import re

with open("app/src/main.rs", "r") as f:
    content = f.read()

replacement = """#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Early initialization validation for HA Enforcement
    let env_mode = std::env::var("WARDEN_ENV").unwrap_or_else(|_| "development".to_string());
    let is_ha = std::env::var("WARDEN_MODE").unwrap_or_else(|_| "".to_string()) == "HA"
        || std::env::var("WARDEN_MODE").unwrap_or_else(|_| "".to_string()) == "enterprise"
        || std::env::var("WARDEN_MODE").unwrap_or_else(|_| "".to_string()) == "multi-node"
        || std::env::var("REDIS_URL").is_ok()
        || std::env::var("DATABASE_URL").is_ok();

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

with open("app/src/main.rs", "w") as f:
    f.write(content)
