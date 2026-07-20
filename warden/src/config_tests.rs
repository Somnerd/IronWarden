use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

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
        writeln!(
            file,
            "
rules:
  - id: test_rule
    pattern: 'test'
    type: Dictionary
    action: Redact
ai_enabled: true
ai_confidence_threshold: 0.95
        "
        )
        .unwrap();

        let config = WardenConfig::from_file(file.path()).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "test_rule");
        assert_eq!(config.ai_enabled, true);
        assert_eq!(config.ai_confidence_threshold, 0.95);
    }
