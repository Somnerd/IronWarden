use async_trait::async_trait;
use iw_core::SovereignError;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::fs;
use tokio::process::Command;
use tracing::{error, info, warn};

const OCR_COMMAND_TIMEOUT_SECS: u64 = 60;

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

enum CmdOutcome {
    Success,
    Failed(String),
    MissingBinary,
}

enum PageOcr {
    Text(String),
    Mock(String),
}

fn is_production_env() -> bool {
    std::env::var("WARDEN_ENV").unwrap_or_default() == "production"
        || std::env::var("IRONWARDEN_ENV").unwrap_or_default() == "production"
        || std::env::var("RUST_ENV").unwrap_or_default() == "production"
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

async fn run_ocr_command(mut cmd: Command, tool_name: &str) -> Result<CmdOutcome, SovereignError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CmdOutcome::MissingBinary);
        }
        Err(e) => {
            error!("{} Process Error: {}", tool_name, e);
            return Err(SovereignError::InternalError(format!(
                "OCR Process Error ({}): {}",
                tool_name, e
            )));
        }
    };

    let output = tokio::time::timeout(
        Duration::from_secs(OCR_COMMAND_TIMEOUT_SECS),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| {
        error!(
            "{} execution timed out after {}s",
            tool_name, OCR_COMMAND_TIMEOUT_SECS
        );
        SovereignError::InternalError(format!(
            "{} timed out after {}s",
            tool_name, OCR_COMMAND_TIMEOUT_SECS
        ))
    })?
    .map_err(|e| {
        error!("{} wait error: {}", tool_name, e);
        SovereignError::InternalError(format!("OCR Process Error ({}): {}", tool_name, e))
    })?;

    if output.status.success() {
        Ok(CmdOutcome::Success)
    } else {
        let err = String::from_utf8_lossy(&output.stderr).into_owned();
        Ok(CmdOutcome::Failed(err))
    }
}

fn handle_missing_binary(
    tool_name: &str,
    dep_desc: &str,
    mime_type: &str,
) -> Result<String, SovereignError> {
    if is_production_env() {
        error!(
            "CRITICAL: {} binary not found in production environment! Failing closed to prevent data leaks.",
            tool_name
        );
        Err(SovereignError::InternalError(format!(
            "{} OCR dependency missing in production mode.",
            dep_desc
        )))
    } else {
        warn!(
            "SECURITY WARNING: {} binary not found. Falling back to mock OCR for development mode. Do not use in production.",
            tool_name
        );
        Ok(format!(
            "[MOCK OCR] This is a simulated extraction for {}. Install {} for real processing.",
            mime_type, dep_desc
        ))
    }
}

fn parse_page_sort_key(path: &Path) -> (usize, String) {
    let name = path
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
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with("page-") && name.ends_with(".png") {
                pages.push(path);
            }
        }
    }
    pages.sort_by_key(|p| parse_page_sort_key(p));
    Ok(pages)
}

async fn run_tesseract_image(
    input_path: &Path,
    output_base: &Path,
    mime_type: &str,
) -> Result<PageOcr, SovereignError> {
    let mut cmd = Command::new("tesseract");
    cmd.arg(input_path);
    cmd.arg(output_base);
    cmd.arg("-l").arg("eng+ell+grc");

    match run_ocr_command(cmd, "Tesseract").await? {
        CmdOutcome::Success => {
            let output_path = PathBuf::from(format!("{}.txt", output_base.display()));
            let text = fs::read_to_string(&output_path).await.map_err(|e| {
                SovereignError::InternalError(format!("Failed to read OCR output: {}", e))
            })?;
            Ok(PageOcr::Text(text))
        }
        CmdOutcome::Failed(err) => {
            error!("Tesseract execution failed: {}", err);
            Err(SovereignError::InternalError(format!(
                "Tesseract Error: {}",
                err
            )))
        }
        CmdOutcome::MissingBinary => {
            let mock = handle_missing_binary("Tesseract", "Tesseract", mime_type)?;
            Ok(PageOcr::Mock(mock))
        }
    }
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

        if is_pdf {
            let page_prefix = work_dir.join("page");
            let mut pdf_cmd = Command::new("pdftoppm");
            pdf_cmd
                .arg("-png")
                .arg("-r")
                .arg("200")
                .arg("-f")
                .arg("1")
                .arg("-l")
                .arg("50")
                .arg(&input_path)
                .arg(&page_prefix);

            match run_ocr_command(pdf_cmd, "pdftoppm").await? {
                CmdOutcome::Success => {}
                CmdOutcome::Failed(err) => {
                    error!("pdftoppm execution failed: {}", err);
                    return Err(SovereignError::InternalError(format!(
                        "pdftoppm Error: {}",
                        err
                    )));
                }
                CmdOutcome::MissingBinary => {
                    return handle_missing_binary(
                        "pdftoppm",
                        "pdftoppm (poppler-utils)",
                        mime_type,
                    );
                }
            }

            let pages = collect_sorted_page_pngs(work_dir).await?;
            if pages.is_empty() {
                return Err(SovereignError::InternalError(
                    "pdftoppm produced no page images for PDF".to_string(),
                ));
            }

            let mut page_texts = Vec::with_capacity(pages.len());
            for (idx, page_png) in pages.iter().enumerate() {
                let output_base = work_dir.join(format!("ocr_out_{}", idx));
                match run_tesseract_image(page_png, &output_base, mime_type).await? {
                    PageOcr::Mock(msg) => return Ok(msg),
                    PageOcr::Text(txt) => {
                        if !txt.trim().is_empty() {
                            page_texts.push(txt);
                        }
                    }
                }
            }
            return Ok(page_texts.join("\n\n"));
        }

        let output_base = work_dir.join("ocr_out");
        match run_tesseract_image(&input_path, &output_base, mime_type).await? {
            PageOcr::Mock(msg) => Ok(msg),
            PageOcr::Text(txt) => Ok(txt),
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
