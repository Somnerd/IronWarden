use serde::{Deserialize, Serialize};
use crate::engine::WardenEngine;
use std::fs;
use std::path::Path;
use tracing::{info, error};
use iw_core::{PiiCategory, EnforcementAction};

#[derive(Debug, Serialize, Deserialize)]
pub enum RuleType {
    Regex,
    Dictionary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    pub pattern: String,
    pub r#type: RuleType,
    #[serde(default = "default_action")]
    pub action: EnforcementAction,
    #[serde(default)]
    pub category: PiiCategory,
}

fn default_action() -> EnforcementAction {
    EnforcementAction::Redact
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicConfig {
    pub label: String,
    pub pattern: String,
    #[serde(default)]
    pub skip_sentence_start: bool,
    #[serde(default = "default_action")]
    pub action: EnforcementAction,
    #[serde(default)]
    pub category: PiiCategory,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WardenConfig {
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub heuristics: Vec<HeuristicConfig>,
    #[serde(default = "default_ai_enabled")]
    pub ai_enabled: bool,
    #[serde(default = "default_ai_threshold")]
    pub ai_confidence_threshold: f64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RulesManifest {
    #[serde(default = "default_rules_dir")]
    pub rules_dir: String,
    #[serde(default)]
    pub active_rules: Vec<String>,
}

fn default_rules_dir() -> String {
    "config/regions".to_string()
}

fn default_ai_enabled() -> bool { false }
fn default_ai_threshold() -> f64 { 0.85 }

impl Default for WardenConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            heuristics: Vec::new(),
            ai_enabled: default_ai_enabled(),
            ai_confidence_threshold: default_ai_threshold(),
        }
    }
}

impl WardenConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, iw_core::SovereignError> {
        let content = fs::read_to_string(path)
            .map_err(|e| iw_core::SovereignError::ConfigError(format!("IO Error: {}", e)))?;
        let config: WardenConfig = serde_yaml::from_str(&content)
            .map_err(|e| iw_core::SovereignError::ConfigError(format!("YAML Error: {}", e)))?;
        Ok(config)
    }

    pub fn from_dir<P: AsRef<Path>>(path: P) -> Result<Self, iw_core::SovereignError> {
        let mut combined_config = WardenConfig::default();
        let entries = fs::read_dir(path)
            .map_err(|e| iw_core::SovereignError::ConfigError(format!("IO Error reading directory: {}", e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| iw_core::SovereignError::ConfigError(format!("IO Error: {}", e)))?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("yaml") {
                let content = fs::read_to_string(&path)
                    .map_err(|e| iw_core::SovereignError::ConfigError(format!("IO Error reading {:?}: {}", path, e)))?;
                let mut config: WardenConfig = serde_yaml::from_str(&content)
                    .map_err(|e| iw_core::SovereignError::ConfigError(format!("YAML Error in {:?}: {}", path, e)))?;
                combined_config.rules.append(&mut config.rules);
                combined_config.heuristics.append(&mut config.heuristics);
                if config.ai_enabled {
                    combined_config.ai_enabled = true;
                    combined_config.ai_confidence_threshold = config.ai_confidence_threshold;
                }
            }
        }
        Ok(combined_config)
    }

    pub fn from_manifest<P: AsRef<Path>>(path: P) -> Result<Self, iw_core::SovereignError> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| iw_core::SovereignError::ConfigError(format!("IO Error reading manifest {:?}: {}", path.as_ref(), e)))?;
        let manifest: RulesManifest = serde_yaml::from_str(&content)
            .map_err(|e| iw_core::SovereignError::ConfigError(format!("YAML Error in manifest {:?}: {}", path.as_ref(), e)))?;

        let rules_dir = Path::new(&manifest.rules_dir);
        let rules_dir_canonical = rules_dir.canonicalize()
            .map_err(|e| iw_core::SovereignError::ConfigError(format!("Invalid rules_dir {:?}: {}", rules_dir, e)))?;

        if manifest.active_rules.is_empty() {
            // Fallback to loading all yaml files in the directory
            return Self::from_dir(rules_dir);
        }

        let mut combined_config = WardenConfig::default();
        for rule_file in &manifest.active_rules {
            let rule_path = rules_dir.join(rule_file);
            let rule_path_canonical = rule_path.canonicalize()
                .map_err(|e| iw_core::SovereignError::ConfigError(format!("Rule file {:?} does not exist or invalid: {}", rule_path, e)))?;

            if !rule_path_canonical.starts_with(&rules_dir_canonical) {
                return Err(iw_core::SovereignError::ConfigError(format!("Path traversal detected! Rule file {:?} is outside rules_dir {:?}", rule_path, rules_dir)));
            }

            let file_content = fs::read_to_string(&rule_path_canonical)
                .map_err(|e| iw_core::SovereignError::ConfigError(format!("IO Error reading rule file {:?}: {}", rule_path_canonical, e)))?;
            let mut config: WardenConfig = serde_yaml::from_str(&file_content)
                .map_err(|e| iw_core::SovereignError::ConfigError(format!("YAML Error in rule file {:?}: {}", rule_path_canonical, e)))?;

            combined_config.rules.append(&mut config.rules);
            combined_config.heuristics.append(&mut config.heuristics);
            if config.ai_enabled {
                combined_config.ai_enabled = true;
                combined_config.ai_confidence_threshold = config.ai_confidence_threshold;
            }
        }
        Ok(combined_config)
    }

    pub fn compile_engine(&self, pepper: &secrecy::SecretVec<u8>) -> Result<WardenEngine, iw_core::SovereignError> {
        let mut dictionary_rules = Vec::new();
        let mut regex_rules = Vec::new();

        for rule in &self.rules {
            match rule.r#type {
                RuleType::Dictionary => dictionary_rules.push((rule.id.clone(), rule.pattern.clone(), rule.action, rule.category)),
                RuleType::Regex => regex_rules.push((rule.id.clone(), rule.pattern.clone(), rule.action, rule.category)),
            }
        }

        let ai = if self.ai_enabled {
            let cpu_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
            let pool_size = std::cmp::min(4, cpu_count); // Cap at 4 instances for memory efficiency
            match crate::ai::HybridNerPool::new(self.ai_confidence_threshold, pool_size) {
                Ok(pool) => {
                    info!("Hybrid Intelligence Pool initialized with {} workers", pool_size);
                    Some(pool)
                },
                Err(e) => {
                    error!("AI Engine Pool failed to initialize: {}", e);
                    None
                }
            }
        } else {
            None
        };

        WardenEngine::new(dictionary_rules, regex_rules, self.heuristics.clone(), ai, self.ai_confidence_threshold, pepper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn test_invalid_yaml_fails_gracefully() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "rules: [ invalid yaml \n - ").unwrap();

        let result = WardenConfig::from_file(file.path());
        assert!(result.is_err());
        if let Err(iw_core::SovereignError::ConfigError(msg)) = result {
            assert!(msg.contains("YAML Error"));
        } else {
            panic!("Expected ConfigError");
        }
    }

    #[test]
    fn test_valid_yaml_parses() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "
rules:
  - id: test_rule
    pattern: 'test'
    type: Dictionary
    action: Redact
ai_enabled: true
ai_confidence_threshold: 0.95
        ").unwrap();

        let config = WardenConfig::from_file(file.path()).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "test_rule");
        assert_eq!(config.ai_enabled, true);
        assert_eq!(config.ai_confidence_threshold, 0.95);
    }

    #[test]
    fn test_manifest_loading() {
        let dir = tempdir().unwrap();
        let rules_dir = dir.path().join("regions");
        fs::create_dir(&rules_dir).unwrap();

        let rule_file_1 = rules_dir.join("rule1.yaml");
        fs::write(&rule_file_1, "rules: [{id: rule1, pattern: test1, type: Dictionary}]").unwrap();

        let rule_file_2 = rules_dir.join("rule2.yaml");
        fs::write(&rule_file_2, "rules: [{id: rule2, pattern: test2, type: Dictionary}]").unwrap();

        // 1. Test specific file loading
        let manifest_path = dir.path().join("manifest.yaml");
        fs::write(&manifest_path, format!("rules_dir: '{}'\nactive_rules:\n  - rule1.yaml", rules_dir.display())).unwrap();

        let config = WardenConfig::from_manifest(&manifest_path).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "rule1");

        // 2. Test fallback (empty active_rules)
        let manifest2_path = dir.path().join("manifest2.yaml");
        fs::write(&manifest2_path, format!("rules_dir: '{}'\nactive_rules: []", rules_dir.display())).unwrap();

        let config2 = WardenConfig::from_manifest(&manifest2_path).unwrap();
        assert_eq!(config2.rules.len(), 2);
    }

    #[test]
    fn test_manifest_path_traversal_blocked() {
        let dir = tempdir().unwrap();
        let rules_dir = dir.path().join("regions");
        fs::create_dir(&rules_dir).unwrap();

        let outside_file = dir.path().join("secret.yaml");
        fs::write(&outside_file, "rules: [{id: secret, pattern: test, type: Dictionary}]").unwrap();

        let manifest_path = dir.path().join("manifest.yaml");
        // Try to traverse outside rules_dir
        fs::write(&manifest_path, format!("rules_dir: '{}'\nactive_rules:\n  - ../secret.yaml", rules_dir.display())).unwrap();

        let result = WardenConfig::from_manifest(&manifest_path);
        assert!(result.is_err());
        if let Err(iw_core::SovereignError::ConfigError(msg)) = result {
            assert!(msg.contains("Path traversal detected") || msg.contains("does not exist or invalid"));
        } else {
            panic!("Expected ConfigError with traversal prevention");
        }
    }
}
