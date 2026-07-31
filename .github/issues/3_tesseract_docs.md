# Title: [DOCS] Document host system requirements for Tesseract OCR

## Category: Documentation / Developer Experience

## Description
The image/document ingestion pipeline in `worker/src/ocr.rs` attempts to run `tesseract` to extract text from images. If the `tesseract` binary is missing from the system's path, it silently logs a warning and falls back to a development mock:
```rust
warn!("OCR: Tesseract binary not found. Falling back to mock for development.");
```

While this fallback is useful for development setups, users deploying the gateway in production will receive un-redacted documents/images if they do not have `tesseract` installed on their host system, posing a major PII leak risk.

We need to explicitly document the system-level dependency requirements for OCR processing.

## Remediation Plan
1. Add a **"System Dependencies"** section to `README.md` (or the installation docs).
2. Document the installation of Tesseract on common platforms:
   - macOS: `brew install tesseract`
   - Debian/Ubuntu: `sudo apt-get install tesseract-ocr`
   - RedHat/CentOS: `sudo dnf install tesseract`
3. Update the logger in `ocr.rs` to output a clearer warning that OCR functionality is disabled in production mode if the binary is missing, rather than implying it is just a development fallback.
