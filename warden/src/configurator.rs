use iw_core::SovereignError;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_warden_mode")]
    pub warden_mode: String,

    #[serde(default = "default_openai_api_key", skip_serializing)]
    pub openai_api_key: SecretString,

    #[serde(default = "default_openai_base_url")]
    pub openai_base_url: String,

    pub warden_pepper: Option<Vec<u8>>,

    #[serde(default = "default_warden_manifest_path")]
    pub warden_manifest_path: String,

    #[serde(default = "default_audit_db_path")]
    pub audit_db_path: String,

    #[serde(default = "default_knowledge_path")]
    pub knowledge_path: String,

    pub remote_audit_endpoint: Option<String>,
    pub remote_audit_token: Option<String>,

    pub jwt_public_key: Option<Vec<u8>>,

    #[serde(default = "default_bridge_port")]
    pub bridge_port: String,

    #[serde(default = "default_bridge_addr")]
    pub bridge_addr: String,

    pub warden_jwt_audience: Option<String>,
    pub warden_jwt_issuer: Option<String>,

    #[serde(default)]
    pub allow_fallback: bool,
}

fn default_warden_mode() -> String {
    "hybrid".to_string()
}
fn default_openai_api_key() -> SecretString {
    SecretString::new("ollama".to_string())
}
fn default_openai_base_url() -> String {
    "https://api.openai.com/v1/chat/completions".to_string()
}
fn default_warden_manifest_path() -> String {
    "config/manifest.yaml".to_string()
}
fn default_audit_db_path() -> String {
    "audit.db".to_string()
}
fn default_knowledge_path() -> String {
    "data/knowledge".to_string()
}
fn default_bridge_port() -> String {
    "14141".to_string()
}
fn default_bridge_addr() -> String {
    "0.0.0.0".to_string()
}

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
        Self::resolve_with_path(None)
    }

    pub fn resolve_with_path(custom_config_path: Option<&Path>) -> Result<Self, SovereignError> {
        let env_allow_fallback = std::env::var("ALLOW_FALLBACK")
            .map(|v| v.trim().to_lowercase() == "true")
            .unwrap_or(false)
            || std::env::var("WARDEN_ENV")
                .map(|v| v == "test" || v == "ephemeral")
                .unwrap_or(false);

        let default_path = Path::new("config/config.yaml");
        let config_file = custom_config_path.unwrap_or(default_path);

        let mut config: GlobalConfig = if config_file.exists() {
            let content = fs::read_to_string(config_file).map_err(|e| {
                SovereignError::ConfigError(format!(
                    "Failed to read {}: {}",
                    config_file.display(),
                    e
                ))
            })?;
            serde_yaml::from_str(&content).map_err(|e| {
                SovereignError::ConfigError(format!(
                    "Failed to parse {}: {}",
                    config_file.display(),
                    e
                ))
            })?
        } else {
            if !env_allow_fallback {
                return Err(SovereignError::ConfigError(format!(
                    "Strict mode violation: {} is missing and fallback is not allowed.",
                    config_file.display()
                )));
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
            config.warden_pepper = Some(v.into_bytes());
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
            config.remote_audit_token = Some(v);
        }
        if let Ok(v) = std::env::var("JWT_PUBLIC_KEY") {
            config.jwt_public_key = Some(v.into_bytes());
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

        let pepper_len = config.warden_pepper.as_ref().map(|p| p.len()).unwrap_or(0);
        if pepper_len < 32 {
            return Err(SovereignError::ConfigError(
                "Security violation: WARDEN_PEPPER must be configured and be at least 32 bytes."
                    .into(),
            ));
        }

        // Strict mode validations
        if !config.allow_fallback {
            // Check manifest path existence
            let manifest_path = Path::new(&config.warden_manifest_path);
            if !manifest_path.exists() {
                return Err(SovereignError::ConfigError(format!(
                    "Strict mode violation: manifest file {:?} is missing.",
                    manifest_path
                )));
            }

            // Check rules directory existence
            let manifest_content = fs::read_to_string(manifest_path).map_err(|e| {
                SovereignError::ConfigError(format!("Failed to read manifest file: {}", e))
            })?;
            let manifest: crate::config::ManifestConfig = serde_yaml::from_str(&manifest_content)
                .map_err(|e| {
                SovereignError::ConfigError(format!("Failed to parse manifest: {}", e))
            })?;
            let rules_dir = Path::new(&manifest.rules_dir);
            if !rules_dir.exists() {
                return Err(SovereignError::ConfigError(format!(
                    "Strict mode violation: rules directory {:?} is missing.",
                    rules_dir
                )));
            }
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::LazyLock;
    use std::sync::Mutex;

    static ENV_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    // A helper to run tests sequentially when modifying environment variables
    fn run_with_env<F>(setup: F)
    where
        F: FnOnce(),
    {
        let _guard = match ENV_MUTEX.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // Clear variables that affect `allow_fallback`
        let orig_warden = env::var("WARDEN_ENV");
        let orig_allow = env::var("ALLOW_FALLBACK");
        let orig_pepper = env::var("WARDEN_PEPPER");
        let orig_manifest = env::var("WARDEN_MANIFEST_PATH");

        env::remove_var("WARDEN_ENV");
        env::remove_var("ALLOW_FALLBACK");
        env::remove_var("WARDEN_PEPPER");
        env::remove_var("WARDEN_MANIFEST_PATH");

        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(setup));

        // Restore
        if let Ok(val) = orig_warden {
            env::set_var("WARDEN_ENV", val);
        }
        if let Ok(val) = orig_allow {
            env::set_var("ALLOW_FALLBACK", val);
        }
        if let Ok(val) = orig_pepper {
            env::set_var("WARDEN_PEPPER", val);
        }
        if let Ok(val) = orig_manifest {
            env::set_var("WARDEN_MANIFEST_PATH", val);
        }

        if let Err(e) = res {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    fn test_strict_mode_missing_config_yaml() {
        run_with_env(|| {
            env::set_var(
                "WARDEN_PEPPER",
                "this-is-a-valid-32-byte-test-pepper-string!",
            );

            let res =
                GlobalConfig::resolve_with_path(Some(Path::new("non_existent_path_config.yaml")));
            assert!(
                res.is_err(),
                "Must reject when config/config.yaml is missing in strict mode"
            );
            assert!(res.unwrap_err().to_string().contains("is missing"));
        });
    }

    #[test]
    fn test_strict_mode_pepper_too_short() {
        run_with_env(|| {
            let temp_dir = tempfile::tempdir().unwrap();
            let config_yaml = temp_dir.path().join("config.yaml");
            let manifest_yaml = temp_dir.path().join("manifest.yaml");
            let rules_dir = temp_dir.path().join("rules");

            fs::create_dir(&rules_dir).unwrap();
            fs::write(&config_yaml, "warden_mode: test").unwrap();
            fs::write(
                &manifest_yaml,
                format!(
                    "rules_dir: \"{}\"\nrule_categories: []",
                    rules_dir.display()
                ),
            )
            .unwrap();

            env::set_var("WARDEN_MANIFEST_PATH", manifest_yaml.to_str().unwrap());

            // Pepper < 32 bytes
            env::set_var("WARDEN_PEPPER", "short_pepper");
            let res = GlobalConfig::resolve_with_path(Some(&config_yaml));
            assert!(res.is_err(), "Must reject pepper < 32 bytes in strict mode");
            assert!(res.unwrap_err().to_string().contains("at least 32 bytes"));

            // Pepper >= 32 bytes
            env::set_var("WARDEN_PEPPER", "12345678901234567890123456789012");
            let res_ok = GlobalConfig::resolve_with_path(Some(&config_yaml));
            assert!(
                res_ok.is_ok(),
                "Must accept pepper >= 32 bytes: {:?}",
                res_ok.err()
            );
        });
    }

    #[test]
    fn test_strict_mode_missing_manifest() {
        run_with_env(|| {
            let temp_dir = tempfile::tempdir().unwrap();
            let config_yaml = temp_dir.path().join("config.yaml");
            fs::write(&config_yaml, "warden_mode: test").unwrap();

            env::set_var("WARDEN_PEPPER", "12345678901234567890123456789012");
            env::set_var("WARDEN_MANIFEST_PATH", "non_existent_manifest.yaml");

            let res = GlobalConfig::resolve_with_path(Some(&config_yaml));
            assert!(
                res.is_err(),
                "Must reject missing manifest file in strict mode"
            );
            assert!(res.unwrap_err().to_string().contains("manifest file"));
        });
    }

    #[test]
    fn test_memory_safe_openai_api_key() {
        run_with_env(|| {
            let temp_dir = tempfile::tempdir().unwrap();
            let config_yaml = temp_dir.path().join("config.yaml");
            fs::write(&config_yaml, "warden_mode: hybrid").unwrap();

            env::set_var("ALLOW_FALLBACK", "true");
            env::set_var("OPENAI_API_KEY", "sk-proj-test-secret-key-12345");
            env::set_var("WARDEN_PEPPER", "12345678901234567890123456789012");

            let config = GlobalConfig::resolve_with_path(Some(&config_yaml)).unwrap();

            use secrecy::ExposeSecret;
            assert_eq!(
                config.openai_api_key.expose_secret(),
                "sk-proj-test-secret-key-12345"
            );
        });
    }
}
