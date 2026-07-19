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
                warn!("OCR: Tesseract binary not found. Falling back to mock for development.");
                let _ = fs::remove_file(&input_path).await;
                Ok(format!("[MOCK OCR] This is a simulated extraction for {}. Install Tesseract for real processing.", mime_type))
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
