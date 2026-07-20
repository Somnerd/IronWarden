use crate::engine::WardenEngine;
use iw_core::{EnforcementAction, PiiCategory};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{error, info};

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

fn default_ai_enabled() -> bool {
    false
}
fn default_ai_threshold() -> f64 {
    0.85
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestConfig {
    pub rules_dir: String,
    #[serde(default)]
    pub active_rules: Vec<String>,
}

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

    pub fn from_manifest<P: AsRef<Path>>(
        manifest_path: P,
    ) -> Result<(Self, Vec<String>), iw_core::SovereignError> {
        let manifest_content = fs::read_to_string(manifest_path.as_ref()).map_err(|e| {
            iw_core::SovereignError::ConfigError(format!(
                "Failed to read manifest file {:?}: {}",
                manifest_path.as_ref(),
                e
            ))
        })?;
        let manifest: ManifestConfig = serde_yaml::from_str(&manifest_content).map_err(|e| {
            iw_core::SovereignError::ConfigError(format!(
                "Failed to parse manifest YAML {:?}: {}",
                manifest_path.as_ref(),
                e
            ))
        })?;

        let mut combined_config = WardenConfig::default();
        let mut warnings = Vec::new();

        let rules_dir_path = Path::new(&manifest.rules_dir);
        let canonical_rules_dir = fs::canonicalize(rules_dir_path).map_err(|e| {
            iw_core::SovereignError::ConfigError(format!(
                "Failed to canonicalize rules_dir {:?}: {}",
                rules_dir_path, e
            ))
        })?;

        for rule_file in &manifest.active_rules {
            let rule_path = rules_dir_path.join(rule_file);

            let canonical_rule_path = match fs::canonicalize(&rule_path) {
                Ok(p) => p,
                Err(e) => {
                    warnings.push(format!(
                        "Failed to canonicalize rule file {:?}: {}",
                        rule_path, e
                    ));
                    continue;
                }
            };

            if !canonical_rule_path.starts_with(&canonical_rules_dir) {
                warnings.push(format!(
                    "Path traversal detected for rule file {:?}",
                    rule_path
                ));
                continue;
            }

            let content = match fs::read_to_string(&canonical_rule_path) {
                Ok(c) => c,
                Err(e) => {
                    warnings.push(format!(
                        "Failed to read rule file {:?}: {}",
                        canonical_rule_path, e
                    ));
                    continue;
                }
            };
            let mut config: WardenConfig = match serde_yaml::from_str(&content) {
                Ok(c) => c,
                Err(e) => {
                    warnings.push(format!(
                        "Failed to parse YAML for rule file {:?}: {}",
                        canonical_rule_path, e
                    ));
                    continue;
                }
            };
            combined_config.rules.append(&mut config.rules);
            combined_config.heuristics.append(&mut config.heuristics);
            if config.ai_enabled {
                combined_config.ai_enabled = true;
                combined_config.ai_confidence_threshold = config.ai_confidence_threshold;
            }
        }
        Ok((combined_config, warnings))
    }

    pub fn compile_engine(
        &self,
        pepper: &secrecy::SecretVec<u8>,
    ) -> Result<WardenEngine, iw_core::SovereignError> {
        let mut dictionary_rules = Vec::new();
        let mut regex_rules = Vec::new();

        for rule in &self.rules {
            match rule.r#type {
                RuleType::Dictionary => dictionary_rules.push((
                    rule.id.clone(),
                    rule.pattern.clone(),
                    rule.action,
                    rule.category,
                )),
                RuleType::Regex => regex_rules.push((
                    rule.id.clone(),
                    rule.pattern.clone(),
                    rule.action,
                    rule.category,
                )),
            }
        }

        let ai = if self.ai_enabled {
            let cpu_count = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);
            let pool_size = std::cmp::min(4, cpu_count); // Cap at 4 instances for memory efficiency
            match crate::ai::HybridNerPool::new(self.ai_confidence_threshold, pool_size) {
                Ok(pool) => {
                    info!(
                        "Hybrid Intelligence Pool initialized with {} workers",
                        pool_size
                    );
                    Some(pool)
                }
                Err(e) => {
                    error!("AI Engine Pool failed to initialize: {}", e);
                    None
                }
            }
        } else {
            None
        };

        WardenEngine::new(
            dictionary_rules,
            regex_rules,
            self.heuristics.clone(),
            ai,
            self.ai_confidence_threshold,
            pepper,
        )
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
