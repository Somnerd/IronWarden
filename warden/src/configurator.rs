use serde::{Deserialize, Serialize};
use secrecy::{SecretString, SecretVec};
use std::path::Path;
use std::fs;
use iw_core::SovereignError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_warden_mode")]
    pub warden_mode: String,

    #[serde(default = "default_openai_api_key")]
    pub openai_api_key: SecretString,

    #[serde(default = "default_openai_base_url")]
    pub openai_base_url: String,

    pub warden_pepper: Option<SecretVec<u8>>,

    #[serde(default = "default_warden_manifest_path")]
    pub warden_manifest_path: String,

    #[serde(default = "default_audit_db_path")]
    pub audit_db_path: String,

    #[serde(default = "default_knowledge_path")]
    pub knowledge_path: String,

    pub remote_audit_endpoint: Option<String>,
    pub remote_audit_token: Option<SecretString>,

    pub jwt_public_key: Option<SecretVec<u8>>,

    #[serde(default = "default_bridge_port")]
    pub bridge_port: String,

    #[serde(default = "default_bridge_addr")]
    pub bridge_addr: String,

    pub warden_jwt_audience: Option<String>,
    pub warden_jwt_issuer: Option<String>,

    #[serde(default)]
    pub allow_fallback: bool,
}

fn default_warden_mode() -> String { "hybrid".to_string() }
fn default_openai_api_key() -> SecretString { SecretString::new("ollama".to_string()) }
fn default_openai_base_url() -> String { "https://api.openai.com/v1/chat/completions".to_string() }
fn default_warden_manifest_path() -> String { "config/manifest.yaml".to_string() }
fn default_audit_db_path() -> String { "audit.db".to_string() }
fn default_knowledge_path() -> String { "data/knowledge".to_string() }
fn default_bridge_port() -> String { "14141".to_string() }
fn default_bridge_addr() -> String { "0.0.0.0".to_string() }

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            warden_mode: default_warden_mode(),
            openai_api_key: default_openai_api_key(),
            openai_base_url: default_openai_base_url(),
            warden_pepper: None,
            warden_manifest_path: default_warden_manifest_path(),
            audit_db_path: default_audit_db_path(),
            knowledge_path: default_knowledge_path(),
            remote_audit_endpoint: None,
            remote_audit_token: None,
            jwt_public_key: None,
            bridge_port: default_bridge_port(),
            bridge_addr: default_bridge_addr(),
            warden_jwt_audience: None,
            warden_jwt_issuer: None,
            allow_fallback: false,
        }
    }
}

impl GlobalConfig {
    pub fn resolve() -> Result<Self, SovereignError> {
        let env_allow_fallback = std::env::var("ALLOW_FALLBACK")
            .map(|v| v.trim().to_lowercase() == "true")
            .unwrap_or(false)
            || std::env::var("WARDEN_ENV").map(|v| v == "test" || v == "ephemeral").unwrap_or(false)
            || std::env::var("CARGO_MANIFEST_DIR").is_ok();

        let mut config: GlobalConfig = if Path::new("config/config.yaml").exists() {
            let content = fs::read_to_string("config/config.yaml")
                .map_err(|e| SovereignError::ConfigError(format!("Failed to read config/config.yaml: {}", e)))?;
            serde_yaml::from_str(&content)
                .map_err(|e| SovereignError::ConfigError(format!("Failed to parse config/config.yaml: {}", e)))?
        } else {
            if !env_allow_fallback {
                return Err(SovereignError::ConfigError(
                    "Strict mode violation: config/config.yaml is missing and fallback is not allowed.".into()
                ));
            }
            GlobalConfig::default()
        };

        if env_allow_fallback {
            config.allow_fallback = true;
        }

        // Environment overrides
        if let Ok(v) = std::env::var("WARDEN_MODE") {
            config.warden_mode = v;
        }
        if let Ok(v) = std::env::var("OPENAI_API_KEY") {
            config.openai_api_key = SecretString::new(v);
        }
        if let Ok(v) = std::env::var("OPENAI_BASE_URL") {
            config.openai_base_url = v;
        }
        if let Ok(v) = std::env::var("WARDEN_PEPPER") {
            config.warden_pepper = Some(SecretVec::new(v.into_bytes()));
        }
        if let Ok(v) = std::env::var("WARDEN_MANIFEST_PATH") {
            config.warden_manifest_path = v;
        }
        if let Ok(v) = std::env::var("AUDIT_DB_PATH") {
            config.audit_db_path = v;
        }
        if let Ok(v) = std::env::var("KNOWLEDGE_PATH") {
            config.knowledge_path = v;
        }
        if let Ok(v) = std::env::var("REMOTE_AUDIT_ENDPOINT") {
            config.remote_audit_endpoint = Some(v);
        }
        if let Ok(v) = std::env::var("REMOTE_AUDIT_TOKEN") {
            config.remote_audit_token = Some(SecretString::new(v));
        }
        if let Ok(v) = std::env::var("JWT_PUBLIC_KEY") {
            config.jwt_public_key = Some(SecretVec::new(v.into_bytes()));
        }
        if let Ok(v) = std::env::var("BRIDGE_PORT") {
            config.bridge_port = v;
        }
        if let Ok(v) = std::env::var("BRIDGE_ADDR") {
            config.bridge_addr = v;
        }
        if let Ok(v) = std::env::var("WARDEN_JWT_AUDIENCE") {
            config.warden_jwt_audience = Some(v);
        }
        if let Ok(v) = std::env::var("WARDEN_JWT_ISSUER") {
            config.warden_jwt_issuer = Some(v);
        }

        // Strict mode validations
        if !config.allow_fallback {
            // Check pepper
            use secrecy::ExposeSecret;
            let pepper_len = config.warden_pepper.as_ref().map(|p| p.expose_secret().len()).unwrap_or(0);
            if pepper_len < 32 {
                return Err(SovereignError::ConfigError(
                    "Strict mode violation: WARDEN_PEPPER must be configured and be at least 32 bytes.".into()
                ));
            }

            // Check manifest path existence
            let manifest_path = Path::new(&config.warden_manifest_path);
            if !manifest_path.exists() {
                return Err(SovereignError::ConfigError(
                    format!("Strict mode violation: manifest file {:?} is missing.", manifest_path)
                ));
            }

            // Check rules directory existence
            let manifest_content = fs::read_to_string(manifest_path)
                .map_err(|e| SovereignError::ConfigError(format!("Failed to read manifest file: {}", e)))?;
            let manifest: crate::config::ManifestConfig = serde_yaml::from_str(&manifest_content)
                .map_err(|e| SovereignError::ConfigError(format!("Failed to parse manifest: {}", e)))?;
            let rules_dir = Path::new(&manifest.rules_dir);
            if !rules_dir.exists() {
                return Err(SovereignError::ConfigError(
                    format!("Strict mode violation: rules directory {:?} is missing.", rules_dir)
                ));
            }
        }

        Ok(config)
    }
}
