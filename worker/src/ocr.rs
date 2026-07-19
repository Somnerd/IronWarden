use async_trait::async_trait;
use iw_core::SovereignError;
use tracing::{info, error, warn};
use tokio::process::Command;
use std::path::Path;
use tokio::fs;

#[async_trait]
pub trait OcrProvider: Send + Sync {
    /// Extracts text from binary data (PDF, PNG, JPG).
    async fn extract_text(&self, data: &[u8], mime_type: &str) -> Result<String, SovereignError>;
}

pub struct TesseractOcr;

#[async_trait]
impl OcrProvider for TesseractOcr {
    async fn extract_text(&self, data: &[u8], mime_type: &str) -> Result<String, SovereignError> {
        info!("OCR: Processing {} via Tesseract engine...", mime_type);
        
        let temp_dir = std::env::temp_dir();
        let input_uuid = uuid::Uuid::new_v4().to_string();
        let input_path = temp_dir.join(format!("ocr_in_{}", input_uuid));
        let output_base = temp_dir.join(format!("ocr_out_{}", input_uuid));
        let output_path = temp_dir.join(format!("ocr_out_{}.txt", input_uuid));

        fs::write(&input_path, data).await
            .map_err(|e| SovereignError::InternalError(format!("Failed to write OCR temp file: {}", e)))?;

        // Tesseract command: tesseract [input] [output_base] -l eng+grc
        let mut cmd = Command::new("tesseract");
        cmd.arg(&input_path);
        cmd.arg(&output_base);
        cmd.arg("-l").arg("eng+grc"); // Support English and Greek

        match cmd.output().await {
            Ok(output) if output.status.success() => {
                let text = fs::read_to_string(&output_path).await
                    .map_err(|e| SovereignError::InternalError(format!("Failed to read OCR output: {}", e)))?;
                
                // Cleanup
                let _ = fs::remove_file(&input_path).await;
                let _ = fs::remove_file(&output_path).await;
                
                Ok(text)
            }
            Ok(output) => {
                let err = String::from_utf8_lossy(&output.stderr);
                error!("Tesseract execution failed: {}", err);
                let _ = fs::remove_file(&input_path).await;
                Err(SovereignError::InternalError(format!("Tesseract Error: {}", err)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let env_prod = std::env::var("IRONWARDEN_ENV").unwrap_or_default() == "production"
                    || std::env::var("RUST_ENV").unwrap_or_default() == "production";

                if env_prod {
                    error!("CRITICAL: Tesseract binary not found in production environment! Failing closed to prevent data leaks.");
                    let _ = fs::remove_file(&input_path).await;
                    Err(SovereignError::InternalError("Tesseract OCR dependency missing in production mode.".to_string()))
                } else {
                    warn!("SECURITY WARNING: Tesseract binary not found. Falling back to mock OCR for development mode. Do not use in production.");
                    let _ = fs::remove_file(&input_path).await;
                    Ok(format!("[MOCK OCR] This is a simulated extraction for {}. Install Tesseract for real processing.", mime_type))
                }
            }
            Err(e) => {
                error!("OCR Process Error: {}", e);
                let _ = fs::remove_file(&input_path).await;
                Err(SovereignError::InternalError(format!("OCR Process Error: {}", e)))
            }
        }
    }
}

pub struct AwsTextractOcr {
    region: String,
}

#[async_trait]
impl OcrProvider for AwsTextractOcr {
    async fn extract_text(&self, _data: &[u8], _mime_type: &str) -> Result<String, SovereignError> {
        info!("OCR: Routing to AWS Textract in {}...", self.region);
        // Real implementation would use aws-sdk-textract
        Ok("Simulated OCR text from AWS Textract".to_string())
    }
}

pub struct OcrWorker {
    provider: Box<dyn OcrProvider>,
}

impl OcrWorker {
    pub fn new(provider: Box<dyn OcrProvider>) -> Self {
        Self { provider }
    }

    pub async fn process_file(&self, data: &[u8], mime_type: &str) -> Result<String, SovereignError> {
        self.provider.extract_text(data, mime_type).await
    }
}

#[cfg(test)]
mod tests {
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
}
