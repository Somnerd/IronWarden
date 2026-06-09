use serde::{Deserialize, Serialize};
use crate::engine::WardenEngine;
use std::fs;
use std::path::Path;
use tracing::{info, error};

#[derive(Debug, Serialize, Deserialize)]
pub enum RuleType {
    Regex,
    Dictionary,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SanitizationAction {
    Block,
    Redact,
    AuditOnly,
}

impl Default for SanitizationAction {
    fn default() -> Self {
        Self::Redact
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    pub pattern: String,
    pub r#type: RuleType,
    #[serde(default)]
    pub action: SanitizationAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicConfig {
    pub label: String,
    pub pattern: String,
    #[serde(default)]
    pub skip_sentence_start: bool,
    #[serde(default)]
    pub action: SanitizationAction,
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

    pub fn compile_engine(&self) -> Result<WardenEngine, iw_core::SovereignError> {
        let mut dictionary_rules = Vec::new();
        let mut regex_rules = Vec::new();

        for rule in &self.rules {
            match rule.r#type {
                RuleType::Dictionary => dictionary_rules.push((rule.id.clone(), rule.pattern.clone(), rule.action)),
                RuleType::Regex => regex_rules.push((rule.id.clone(), rule.pattern.clone(), rule.action)),
            }
        }

        let ai = if self.ai_enabled {
            match crate::ai::HybridNer::new(self.ai_confidence_threshold) {
                Ok(ner) => {
                    // --- HONESTY FIX: Corrected log label ---
                    info!("Hybrid Intelligence (Local BERT) initialized with threshold {}", self.ai_confidence_threshold);
                    Some(ner)
                },
                Err(e) => {
                    error!("AI Engine failed to initialize: {}", e);
                    None
                }
            }
        } else {
            None
        };

        WardenEngine::new(dictionary_rules, regex_rules, self.heuristics.clone(), ai, self.ai_confidence_threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_from_file_malformed_yaml_returns_error() {
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        // Write invalid YAML content
        writeln!(temp_file, "rules:\n  - id: 1\n    pattern: [\n").expect("Failed to write to temp file");

        let result = WardenConfig::from_file(temp_file.path());

        assert!(result.is_err(), "Expected an error for malformed YAML");
        if let Err(iw_core::SovereignError::ConfigError(msg)) = result {
            assert!(msg.contains("YAML Error:"), "Expected error message to contain 'YAML Error:', got: {}", msg);
        } else {
            panic!("Expected ConfigError, got different error type or Ok");
        }
    }

    #[test]
    fn test_from_dir_malformed_yaml_returns_error() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir.path().join("invalid.yaml");
        let mut file = std::fs::File::create(&file_path).expect("Failed to create temp file");
        // Write invalid YAML content
        writeln!(file, "rules:\n  - id: 1\n    pattern: [\n").expect("Failed to write to temp file");

        let result = WardenConfig::from_dir(temp_dir.path());

        assert!(result.is_err(), "Expected an error for malformed YAML in directory");
        if let Err(iw_core::SovereignError::ConfigError(msg)) = result {
            assert!(msg.contains("YAML Error in"), "Expected error message to contain 'YAML Error in', got: {}", msg);
        } else {
            panic!("Expected ConfigError, got different error type or Ok");
        }
    }
}
