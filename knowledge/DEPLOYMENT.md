# IronWarden V1.3 Deployment Guide

This guide details how to compile, configure, and deploy the stabilized IronWarden appliance.

## 1. System Requirements
- **OS:** Linux (Ubuntu 22.04 LTS / Debian 12 recommended) or macOS.
- **CPU:** 4+ Cores (Required for smooth concurrent local ONNX inference).
- **RAM:** 4GB+ (LanceDB and the BERT model sit primarily in memory).
- **OCR Engine:** Host-level **Tesseract OCR** is required for document and image parsing.
  * *macOS:* `brew install tesseract`
  * *Ubuntu/Debian:* `sudo apt-get install tesseract-ocr`
  * *RedHat/CentOS:* `sudo dnf install tesseract`

## 2. BERT-NER Model Bootstrap
IronWarden uses local ONNX-based BERT models for its named entity recognition pass, completely eliminating heavy PyTorch/libtorch build dependencies.
Run the bootstrapping script before starting the application:
```bash
./scripts/setup_models.sh
```
This script downloads the quantized DistilBERT model (`model_quantized.onnx`) and its tokenization vocabulary rules, placing them into `data/models/`.

## 3. Configuration & Environment Variables
IronWarden utilizes a unified `GlobalConfig` engine. Configuration values can be set via environment variables, `config/config.yaml`, or fallback defaults:

```yaml
# Example config/config.yaml
allow_fallback: false
warden_mode: "hybrid"
openai_base_url: "https://api.openai.com/v1/chat/completions"
rules_dir: "config/rules"
audit_db_path: "data/audit.db"
knowledge_path: "data/knowledge"
mcp_port: 8080
bridge_port: 3000
```

Key environment variables:
```bash
# Core Cryptographic Pepper (KEEP SECRET - Must be >= 32 bytes)
export WARDEN_PEPPER="your-super-secret-32-byte-pepper-here"

# Sensitive Credentials
export OPENAI_API_KEY="sk-..."
export WARDEN_JWT_PUBLIC_KEY="...base64-encoded..."

# DB connections (HA Backend Mode)
export REDIS_URL="redis://localhost:6379"
export RUST_LOG="info,warden=debug"
```

## 4. Configuration Rules Folder
Place compliance rulesets (e.g. `rules_legal.yaml`, `rules_medical.yaml`) inside:
`config/rules/`

*Note: You can add or modify these rules files while IronWarden is running. The gateway detects the change and hot-reloads the rules automatically using `ArcSwap` in sub-milliseconds without dropping requests.*

## 5. Compilation & Execution
```bash
# Build the project in release mode
cargo build --release

# Run the primary gateway
./target/release/app

# Run the Compliance CLI to verify ledger integrity
./target/release/iw-cli verify --db data/audit.db --pepper $WARDEN_PEPPER
```

## 6. Security & Maintenance
- **Fail-Closed Gateways:** In production, missing Tesseract OCR or configuration dependencies causes the application to immediately fail-closed and log critical errors.
- **Log Purging:** IronWarden operates a background thread that automatically purges ephemeral raw logs older than 30 days to comply with EU Data Minimization standards.
