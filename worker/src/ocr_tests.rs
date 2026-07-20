use super::*;
    use std::env;

    // Use a mutex to serialize tests that mutate the global environment
    static ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn test_ocr_fail_closed_production() {
        let _guard = ENV_MUTEX.lock().await;
        
        let orig_prod = env::var("IRONWARDEN_ENV");
        let orig_rust_env = env::var("RUST_ENV");
        env::set_var("IRONWARDEN_ENV", "production");
        env::remove_var("RUST_ENV");
        
        let orig_path = env::var("PATH");
        env::set_var("PATH", ""); // Ensure tesseract is not found
        
        let ocr = TesseractOcr;
        let res = ocr.extract_text(b"test data", "image/png").await;
        
        assert!(res.is_err(), "OCR must fail in production if tesseract is missing");
        assert!(res.unwrap_err().to_string().contains("dependency missing in production mode"));
        
        if let Ok(val) = orig_path { env::set_var("PATH", val); } else { env::remove_var("PATH"); }
        if let Ok(val) = orig_prod { env::set_var("IRONWARDEN_ENV", val); } else { env::remove_var("IRONWARDEN_ENV"); }
        if let Ok(val) = orig_rust_env { env::set_var("RUST_ENV", val); } else { env::remove_var("RUST_ENV"); }
    }

    #[tokio::test]
    async fn test_ocr_fallback_development() {
        let _guard = ENV_MUTEX.lock().await;
        
        let orig_prod = env::var("IRONWARDEN_ENV");
        let orig_rust_env = env::var("RUST_ENV");
        env::set_var("IRONWARDEN_ENV", "development");
        env::set_var("RUST_ENV", "development");
        
        let orig_path = env::var("PATH");
        env::set_var("PATH", ""); // Ensure tesseract is not found
        
        let ocr = TesseractOcr;
        let res = ocr.extract_text(b"test data", "image/png").await;
        
        assert!(res.is_ok(), "OCR must fallback in development if tesseract is missing");
        assert!(res.unwrap().contains("[MOCK OCR]"));
        
        if let Ok(val) = orig_path { env::set_var("PATH", val); } else { env::remove_var("PATH"); }
        if let Ok(val) = orig_prod { env::set_var("IRONWARDEN_ENV", val); } else { env::remove_var("IRONWARDEN_ENV"); }
        if let Ok(val) = orig_rust_env { env::set_var("RUST_ENV", val); } else { env::remove_var("RUST_ENV"); }
    }
