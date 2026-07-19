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
