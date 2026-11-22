use async_trait::async_trait;
use iw_core::SovereignError;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::fs;
use tokio::process::Command;
use tokio::time::Instant;
use tracing::{error, info, warn};

const OCR_COMMAND_TIMEOUT_SECS: u64 = 60;
const OCR_PDF_TOTAL_TIMEOUT_SECS: u64 = 180;
const OCR_MAX_PDF_PAGES: usize = 50;

#[async_trait]
pub trait OcrProvider: Send + Sync {
    /// Extracts text from binary data (PDF, PNG, JPG).
    async fn extract_text(&self, data: &[u8], mime_type: &str) -> Result<String, SovereignError>;
}

pub struct TesseractOcr;

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn is_production_env() -> bool {
    ["WARDEN_ENV", "IRONWARDEN_ENV", "RUST_ENV"]
        .iter()
        .any(|k| std::env::var(k).unwrap_or_default() == "production")
}

fn create_and_write_input(
    data: &[u8],
    filename: &str,
) -> Result<(TempDirGuard, PathBuf), SovereignError> {
    let work_dir = std::env::temp_dir().join(format!("iw_ocr_{}", uuid::Uuid::new_v4()));
    let mut dir_builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        dir_builder.mode(0o700);
    }
    dir_builder.create(&work_dir).map_err(|e| {
        SovereignError::InternalError(format!("Failed to create OCR temp directory: {}", e))
    })?;
    let guard = TempDirGuard(work_dir.clone());

    let input_path = work_dir.join(filename);
    let mut file_opts = std::fs::OpenOptions::new();
    file_opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        file_opts.mode(0o600);
    }
    let mut file = file_opts.open(&input_path).map_err(|e| {
        SovereignError::InternalError(format!("Failed to create OCR temp file: {}", e))
    })?;
    use std::io::Write;
    file.write_all(data).map_err(|e| {
        SovereignError::InternalError(format!("Failed to write OCR temp file: {}", e))
    })?;

    Ok((guard, input_path))
}

/// Runs an external OCR tool under both per-invocation and cumulative deadlines.
/// Returns `Ok(None)` on exit 0, `Ok(Some(mock))` when missing in non-production mode.
async fn run_tool(
    bin: &str,
    args: &[&OsStr],
    deadline: Instant,
    label: &str,
    dep_desc: &str,
    mime_type: &str,
) -> Result<Option<String>, SovereignError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(SovereignError::InternalError(format!(
            "{} timed out after {}s cumulative OCR limit",
            label, OCR_PDF_TOTAL_TIMEOUT_SECS
        )));
    }
    let timeout = remaining.min(Duration::from_secs(OCR_COMMAND_TIMEOUT_SECS));

    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if is_production_env() {
                error!(
                    "CRITICAL: {} binary not found in production environment! Failing closed to prevent data leaks.",
                    label
                );
                return Err(SovereignError::InternalError(format!(
                    "{} OCR dependency missing in production mode.",
                    dep_desc
                )));
            }
            warn!(
                "SECURITY WARNING: {} binary not found. Falling back to mock OCR for development mode. Do not use in production.",
                label
            );
            return Ok(Some(format!(
                "[MOCK OCR] This is a simulated extraction for {}. Install {} for real processing.",
                mime_type, dep_desc
            )));
        }
        Err(e) => {
            error!("{} Process Error: {}", label, e);
            return Err(SovereignError::InternalError(format!(
                "OCR Process Error ({}): {}",
                label, e
            )));
        }
    };

    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| {
            error!("{} execution timed out after {}s", label, timeout.as_secs());
            SovereignError::InternalError(format!(
                "{} timed out after {}s",
                label,
                timeout.as_secs()
            ))
        })?
        .map_err(|e| {
            error!("{} wait error: {}", label, e);
            SovereignError::InternalError(format!("OCR Process Error ({}): {}", label, e))
        })?;

    if output.status.success() {
        Ok(None)
    } else {
        let err = String::from_utf8_lossy(&output.stderr);
        error!("{} execution failed: {}", label, err);
        Err(SovereignError::InternalError(format!(
            "{} Error: {}",
            label, err
        )))
    }
}

async fn collect_sorted_page_pngs(work_dir: &Path) -> Result<Vec<PathBuf>, SovereignError> {
    let mut entries = fs::read_dir(work_dir).await.map_err(|e| {
        SovereignError::InternalError(format!("Failed to list OCR page images: {}", e))
    })?;
    let mut pages = Vec::new();
    while let Some(entry) = entries.next_entry().await.map_err(|e| {
        SovereignError::InternalError(format!("Failed to read OCR temp dir entry: {}", e))
    })? {
        let path = entry.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("page-") && n.ends_with(".png"))
        {
            pages.push(path);
        }
    }
    pages.sort_by_key(|p| {
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let num = name
            .strip_prefix("page-")
            .and_then(|s| s.strip_suffix(".png"))
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(usize::MAX);
        (num, name)
    });
    Ok(pages)
}

async fn run_tesseract_page(
    input_path: &Path,
    output_base: &Path,
    mime_type: &str,
    deadline: Instant,
) -> Result<(bool, String), SovereignError> {
    let args = [
        input_path.as_os_str(),
        output_base.as_os_str(),
        OsStr::new("-l"),
        OsStr::new("eng+ell+grc"),
    ];
    if let Some(mock) = run_tool(
        "tesseract",
        &args,
        deadline,
        "Tesseract",
        "Tesseract",
        mime_type,
    )
    .await?
    {
        return Ok((true, mock));
    }
    let output_path = PathBuf::from(format!("{}.txt", output_base.display()));
    let text = fs::read_to_string(&output_path)
        .await
        .map_err(|e| SovereignError::InternalError(format!("Failed to read OCR output: {}", e)))?;
    Ok((false, text))
}

#[async_trait]
impl OcrProvider for TesseractOcr {
    async fn extract_text(&self, data: &[u8], mime_type: &str) -> Result<String, SovereignError> {
        info!("OCR: Processing {} via Tesseract engine...", mime_type);

        let is_pdf = mime_type == "application/pdf";
        let filename = if is_pdf { "input.pdf" } else { "input.img" };
        let data_owned = data.to_vec();
        let (work_guard, input_path) =
            tokio::task::spawn_blocking(move || create_and_write_input(&data_owned, filename))
                .await
                .map_err(|e| {
                    SovereignError::InternalError(format!("OCR task panicked: {}", e))
                })??;

        let work_dir = &work_guard.0;
        let deadline = Instant::now() + Duration::from_secs(OCR_PDF_TOTAL_TIMEOUT_SECS);

        if is_pdf {
            let page_prefix = work_dir.join("page");
            // Request up to OCR_MAX_PDF_PAGES + 1 pages so >50-page PDFs fail closed cleanly.
            let max_probe = (OCR_MAX_PDF_PAGES + 1).to_string();
            let pdf_args = [
                OsStr::new("-png"),
                OsStr::new("-r"),
                OsStr::new("200"),
                OsStr::new("-f"),
                OsStr::new("1"),
                OsStr::new("-l"),
                OsStr::new(&max_probe),
                input_path.as_os_str(),
                page_prefix.as_os_str(),
            ];
            if let Some(mock) = run_tool(
                "pdftoppm",
                &pdf_args,
                deadline,
                "pdftoppm",
                "pdftoppm (poppler-utils)",
                mime_type,
            )
            .await?
            {
                return Ok(mock);
            }

            let pages = collect_sorted_page_pngs(work_dir).await?;
            if pages.is_empty() {
                return Err(SovereignError::InternalError(
                    "pdftoppm produced no page images for PDF".to_string(),
                ));
            }
            if pages.len() > OCR_MAX_PDF_PAGES {
                return Err(SovereignError::InternalError(format!(
                    "PDF exceeds maximum OCR page limit of {} pages",
                    OCR_MAX_PDF_PAGES
                )));
            }

            let mut page_texts = Vec::with_capacity(pages.len());
            for (idx, page_png) in pages.iter().enumerate() {
                let output_base = work_dir.join(format!("ocr_out_{}", idx));
                let (is_mock, text) =
                    run_tesseract_page(page_png, &output_base, mime_type, deadline).await?;
                if is_mock {
                    return Ok(text);
                }
                if !text.trim().is_empty() {
                    page_texts.push(text);
                }
            }
            return Ok(page_texts.join("\n\n"));
        }

        let output_base = work_dir.join("ocr_out");
        let (_, text) = run_tesseract_page(&input_path, &output_base, mime_type, deadline).await?;
        Ok(text)
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

    pub async fn process_file(
        &self,
        data: &[u8],
        mime_type: &str,
    ) -> Result<String, SovereignError> {
        if mime_type == "application/pdf" {
            info!("OCR: Attempting native PDF extraction...");
            let data_clone = data.to_vec();
            let res = tokio::task::spawn_blocking(move || {
                pdf_extract::extract_text_from_mem(&data_clone)
            })
            .await
            .map_err(|e| {
                SovereignError::InternalError(format!("Tokio spawn_blocking error: {}", e))
            })?;

            match res {
                Ok(text) if !text.trim().is_empty() => {
                    info!("OCR: Successfully extracted text natively from PDF.");
                    return Ok(text);
                }
                Ok(_) => {
                    info!("OCR: Native PDF extraction yielded empty text. Falling back to OCR.");
                }
                Err(e) => {
                    warn!(
                        "OCR: Native PDF extraction failed: {}. Falling back to OCR.",
                        e
                    );
                }
            }
        } else if mime_type
            == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            || mime_type == "application/msword"
        {
            info!("OCR: Attempting native DOCX extraction...");
            let data_clone = data.to_vec();
            let res = tokio::task::spawn_blocking(move || {
                let cursor = std::io::Cursor::new(data_clone);
                let mut zip = match zip::ZipArchive::new(cursor) {
                    Ok(z) => z,
                    Err(_) => return String::new(),
                };

                let mut doc = match zip.by_name("word/document.xml") {
                    Ok(d) => d,
                    Err(_) => return String::new(),
                };

                use std::io::Read;
                let mut xml_data = Vec::new();
                if doc.read_to_end(&mut xml_data).is_err() {
                    return String::new();
                }

                let mut reader = quick_xml::Reader::from_reader(xml_data.as_slice());
                let mut text = String::new();
                let mut in_text = false;
                let mut buf = Vec::new();

                loop {
                    match reader.read_event_into(&mut buf) {
                        Ok(quick_xml::events::Event::Start(ref e)) => {
                            if e.name().as_ref() == b"w:t" {
                                in_text = true;
                            }
                        }
                        Ok(quick_xml::events::Event::End(ref e)) => {
                            if e.name().as_ref() == b"w:t" {
                                in_text = false;
                                text.push(' ');
                            }
                        }
                        Ok(quick_xml::events::Event::Text(e)) => {
                            if in_text {
                                if let Ok(s) = std::str::from_utf8(e.as_ref()) {
                                    text.push_str(s);
                                }
                            }
                        }
                        Ok(quick_xml::events::Event::Eof) => break,
                        Err(_) => break,
                        _ => {}
                    }
                    buf.clear();
                }
                text
            })
            .await
            .map_err(|e| {
                SovereignError::InternalError(format!("Tokio spawn_blocking error: {}", e))
            })?;

            if !res.trim().is_empty() {
                info!("OCR: Successfully extracted text natively from DOCX.");
                return Ok(res);
            }
            info!("OCR: Native DOCX extraction yielded empty text. Falling back to OCR.");
        }

        self.provider.extract_text(data, mime_type).await
    }
}
