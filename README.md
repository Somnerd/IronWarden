# 🏰 IronWarden V1.2-FINAL
### Sovereign AI Privacy Firewall & Security Gateway

IronWarden is a high-performance, single-binary security appliance designed to protect sensitive professional data (Legal, Medical, Financial) from leaking into external Large Language Models (LLMs). 

It operates as a **Privacy Proxy** that intercepts, redacts, and audits every AI transaction with "Telco-Grade" reliability and 100% data sovereignty.

---

## 💎 Core Value Proposition: The "Shield & Vault"

### 1. Hybrid Intelligence PII Shield
Unlike basic regex-only redactors, IronWarden uses **Hybrid Intelligence**:
*   **Deterministic Pass:** Lightning-fast pattern matching (Aho-Corasick) for known identifiers like AFM, AMKA, IBANs, and Phone Numbers.
*   **Probabilistic AI Pass:** A real, local **BERT-NER** model that scans for "Unknown Unknowns" (Names, Locations, Organizations) with configurable confidence thresholds.
*   **Unicode Accented Support:** Optimized for the Greek and EU markets with full support for accented characters and regional name heuristics.

### 2. Immutable Cryptographic Audit Vault
IronWarden creates a legally-defensible audit trail:
*   **AES-256-GCM Encryption:** Every prompt and redaction event is encrypted at rest using a 32-byte pepper.
*   **HMAC-SHA256 Hash Chaining:** Every log entry is cryptographically linked to the previous one. If a single byte is modified or a log is deleted, the chain breaks and alerts the administrator.
*   **Fail-Closed Integrity:** The gateway will physically block LLM access if the audit ledger cannot be persisted.

### 3. Sovereign Heuristic Grounding (The Librarian)
Ground your AI prompts in local knowledge without the complexity of external databases:
*   **Local Librarian:** High-speed keyword-based search over local text/markdown files.
*   **Leak-Proof Context:** Every retrieved snippet is automatically scrubbed for PII before being sent to the LLM.
*   **Zero-Ops Search:** No vector database setup required; runs entirely from a local directory.

---

## ⚡ Technical Specifications

*   **Runtime:** Standalone Rust Binary (< 50MB footprint).
*   **Hardware Requirement:** < 1.5GB RAM (Run it on an AWS t3.micro or a Mac Mini).
*   **Latency:** ~45ms - 60ms end-to-end (Synchronous AI protection).
*   **Security:** 100% On-Premise. No data ever leaves your network unredacted.
*   **Persistence:** Unified SQLite ledger for Zero-Ops deployment.

---

## 💻 System Requirements

**Tesseract OCR** is a mandatory host-level dependency for document and image parsing. 

Without Tesseract installed, document OCR falls back to a mock mode which is unsafe for production. In production environments, missing this dependency will cause parsing to fail-closed.

Installation instructions for major platforms:
*   **macOS:** `brew install tesseract`
*   **Ubuntu/Debian:** `sudo apt-get install tesseract-ocr`
*   **RedHat/CentOS:** `sudo dnf install tesseract`

---

## 🚀 Deployment

### Installation & Run

1.  **Model Setup:** Run `./scripts/setup_models.sh` to download ONNX weights. These weights are required for Hybrid NER mode. Note that IronWarden falls back to Heuristic-Only mode if weights are missing.
2.  **Configure:** Set your 32-byte `WARDEN_PEPPER` in the environment.
3.  **Rules:** Drop your regional rules into `config/regions/`.
4.  **Knowledge:** Drop your policy files into `data/knowledge/`.
5.  **Run:** `./ironwarden`

---

## 🏛️ Product Boundary
IronWarden is the **Shield**. It focuses on **Security, Redaction, and Auditing**. 
For advanced semantic search, multi-format PDF ingestion, and high-dimensional vector retrieval, use the **SearchBoost** extension.

---
**Status:** Certified Market-Ready V1.2-FINAL.
**License:** AGPLv3 / Commercial.
