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
        let env_allow_fallback = std::env::var("ALLOW_FALLBACK")
            .map(|v| v.trim().to_lowercase() == "true")
            .unwrap_or(false)
            || std::env::var("WARDEN_ENV")
                .map(|v| v == "test" || v == "ephemeral")
                .unwrap_or(false)
            || std::env::var("CARGO_MANIFEST_DIR").is_ok();

        let mut config: GlobalConfig = if Path::new("config/config.yaml").exists() {
            let content = fs::read_to_string("config/config.yaml").map_err(|e| {
                SovereignError::ConfigError(format!("Failed to read config/config.yaml: {}", e))
            })?;
            serde_yaml::from_str(&content).map_err(|e| {
                SovereignError::ConfigError(format!("Failed to parse config/config.yaml: {}", e))
            })?
        } else {
            if !env_allow_fallback {
                return Err(SovereignError::ConfigError(
                    "Strict mode violation: config/config.yaml is missing and fallback is not allowed."
                        .into(),
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

        // Strict mode validations
        if !config.allow_fallback {
            // Check pepper
            let pepper_len = config.warden_pepper.as_ref().map(|p| p.len()).unwrap_or(0);
            if pepper_len < 32 {
                return Err(SovereignError::ConfigError(
                    "Strict mode violation: WARDEN_PEPPER must be configured and be at least 32 bytes."
                        .into(),
                ));
            }

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
        F: FnOnce() -> (),
    {
        let _guard = ENV_MUTEX.lock().unwrap();
        // Clear variables that affect `allow_fallback`
        let orig_cargo = env::var("CARGO_MANIFEST_DIR");
        let orig_warden = env::var("WARDEN_ENV");
        let orig_allow = env::var("ALLOW_FALLBACK");
        let orig_pepper = env::var("WARDEN_PEPPER");
        let orig_manifest = env::var("WARDEN_MANIFEST_PATH");

        env::remove_var("CARGO_MANIFEST_DIR");
        env::remove_var("WARDEN_ENV");
        env::remove_var("ALLOW_FALLBACK");
        env::remove_var("WARDEN_PEPPER");
        env::remove_var("WARDEN_MANIFEST_PATH");

        // We also want to trick the `Path::new("config/config.yaml").exists()` check
        // if we are running in a different dir, but wait: if `config.yaml` doesn't exist,
        // it should error in strict mode! That's exactly what we want to test first.

        setup();

        // Restore
        if let Ok(val) = orig_cargo {
            env::set_var("CARGO_MANIFEST_DIR", val);
        }
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
    }

    #[test]
    fn test_strict_mode_missing_config_yaml() {
        run_with_env(|| {
            // Make sure we are not running from a directory where config/config.yaml exists
            // Or if it does, this test might fail. Assuming we run from workspace root:
            let old_dir = env::current_dir().unwrap();
            env::set_current_dir(env::temp_dir()).unwrap();

            let res = GlobalConfig::resolve();
            assert!(
                res.is_err(),
                "Must reject when config/config.yaml is missing in strict mode"
            );
            assert!(res
                .unwrap_err()
                .to_string()
                .contains("config/config.yaml is missing"));

            env::set_current_dir(old_dir).unwrap();
        });
    }

    #[test]
    fn test_strict_mode_pepper_too_short() {
        run_with_env(|| {
            // To pass the config.yaml check without a real file, we can't easily fake Path::exists.
            // But we can create a temporary file.
            let temp_dir = tempfile::tempdir().unwrap();
            let config_dir = temp_dir.path().join("config");
            fs::create_dir(&config_dir).unwrap();
            fs::write(config_dir.join("config.yaml"), "warden_mode: test").unwrap();
            fs::write(
                config_dir.join("manifest.yaml"),
                "rules_dir: \"rules\"\nrule_categories: []",
            )
            .unwrap();
            fs::create_dir(temp_dir.path().join("rules")).unwrap();

            let old_dir = env::current_dir().unwrap();
            env::set_current_dir(temp_dir.path()).unwrap();

            env::set_var("WARDEN_MANIFEST_PATH", "config/manifest.yaml");

            // Pepper < 32 bytes
            env::set_var("WARDEN_PEPPER", "short_pepper");
            let res = GlobalConfig::resolve();
            assert!(res.is_err(), "Must reject pepper < 32 bytes in strict mode");
            assert!(res.unwrap_err().to_string().contains("at least 32 bytes"));

            // Pepper >= 32 bytes
            env::set_var("WARDEN_PEPPER", "12345678901234567890123456789012");
            let res_ok = GlobalConfig::resolve();
            assert!(
                res_ok.is_ok(),
                "Must accept pepper >= 32 bytes: {:?}",
                res_ok.err()
            );

            env::set_current_dir(old_dir).unwrap();
        });
    }

    #[test]
    fn test_strict_mode_missing_manifest() {
        run_with_env(|| {
            let temp_dir = tempfile::tempdir().unwrap();
            let config_dir = temp_dir.path().join("config");
            fs::create_dir(&config_dir).unwrap();
            fs::write(config_dir.join("config.yaml"), "warden_mode: test").unwrap();

            let old_dir = env::current_dir().unwrap();
            env::set_current_dir(temp_dir.path()).unwrap();

            env::set_var("WARDEN_PEPPER", "12345678901234567890123456789012");
            env::set_var("WARDEN_MANIFEST_PATH", "non_existent_manifest.yaml");

            let res = GlobalConfig::resolve();
            assert!(
                res.is_err(),
                "Must reject missing manifest file in strict mode"
            );
            assert!(res.unwrap_err().to_string().contains("manifest file"));

            env::set_current_dir(old_dir).unwrap();
        });
    }
    #[test]
    fn test_memory_safe_openai_api_key() {
        run_with_env(|| {
            let temp_dir = tempfile::tempdir().unwrap();
            let config_dir = temp_dir.path().join("config");
            fs::create_dir(&config_dir).unwrap();
            fs::write(config_dir.join("config.yaml"), "warden_mode: hybrid").unwrap();

            let old_dir = env::current_dir().unwrap();
            env::set_current_dir(temp_dir.path()).unwrap();

            env::set_var("ALLOW_FALLBACK", "true");
            env::set_var("OPENAI_API_KEY", "sk-proj-test-secret-key-12345");

            let config = GlobalConfig::resolve().unwrap();

            use secrecy::ExposeSecret;
            assert_eq!(
                config.openai_api_key.expose_secret(),
                "sk-proj-test-secret-key-12345"
            );

            env::set_current_dir(old_dir).unwrap();
        });
    }
}
