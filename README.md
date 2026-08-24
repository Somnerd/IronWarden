# 🏰 IronWarden v1.0.0-rc.1
### Universal AI Privacy Firewall & Security Gateway

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![CI Status](https://github.com/Somnerd/IronWarden/actions/workflows/rust_ci.yml/badge.svg)](https://github.com/Somnerd/IronWarden/actions)

IronWarden is a high-performance, single-binary **AI security proxy**. Point any OpenAI, Anthropic, or locally hosted LLM (via OpenAI-compatible API) SDK client at it and get automatic PII redaction, cryptographic audit logging, and rate limiting — with **zero code changes** in your application.

---

## 🚀 Universal Proxy Quickstart

> **Designed with EU AI Act alignment principles in mind.** IronWarden acts as a transparent firewall between your app and any LLM provider.

### OpenAI & Locally Hosted LLMs (Python)

```python
# Before: direct OpenAI call
from openai import OpenAI
client = OpenAI(api_key="sk-...")

# After: route through IronWarden — zero other changes (works for OpenAI or local vLLM/Ollama)
client = OpenAI(
    api_key="sk-...",
    base_url="http://localhost:14141/v1",
    default_headers={"Authorization": "Bearer <your-ironwarden-jwt>"}
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "My email is john@example.com — summarize my account."}]
)
# ✅ PII scrubbed before reaching OpenAI / Local LLM
# ✅ HMAC audit log written, fail-closed
# ✅ PII restored in the response you receive
print(response.choices[0].message.content)
```

### Anthropic SDK (Python)

```python
import anthropic

client = anthropic.Anthropic(
    api_key="sk-ant-...",
    base_url="http://localhost:14141",
    default_headers={
        "Authorization": "Bearer <your-ironwarden-jwt>",
        "X-IronWarden-Upstream-Key": "sk-ant-..."
    }
)

message = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    messages=[{"role": "user", "content": "My AMKA is 12345678901. Is this data protected?"}]
)
# ✅ AMKA redacted before Claude sees it
```

### Dynamic Upstream Routing

| Header | Effect |
|--------|--------|
| `X-IronWarden-Target-URL` | Override upstream per-request (Ollama, vLLM, custom local endpoint) |
| `X-IronWarden-Upstream-Key` | Per-request API key for upstream |

**Model-name auto-routing** (no config needed):
- `claude-*` → Anthropic API
- `llama*`, `mistral*`, `phi*`, `gemma*`, `qwen*` → Ollama (`localhost:11434`)
- Everything else → OpenAI API

---

## 💎 Core Value Proposition: The "Shield & Vault"

### 1. Hybrid Intelligence PII Shield
Unlike basic regex-only redactors, IronWarden uses **Hybrid Intelligence**:
*   **Deterministic Pass:** Lightning-fast pattern matching (Aho-Corasick) combined with **heuristic entropy analysis** for known identifiers like Government Identification numbers, IBANs, and Phone Numbers.
*   **Probabilistic AI Pass:** A real, local **BERT-NER** model that scans for "Unknown Unknowns" (Names, Locations, Organizations) with configurable confidence thresholds.
*   **Unicode Accented Support:** Built for international and multilingual data streams (such as Greek or other EU languages) with full support for accented characters and regional name heuristics.

### 2. Immutable Cryptographic Audit Vault
IronWarden creates a legally-defensible audit trail:
*   **AES-256-GCM Encryption:** Every prompt and redaction event is encrypted at rest using a 32-byte pepper (generated via `openssl rand -hex 16`).
*   **HMAC-SHA256 Hash Chaining:** Every log entry is cryptographically linked to the previous one. If a single byte is modified or a log is deleted, the chain breaks and alerts the administrator.
*   **Fail-Closed Integrity:** The gateway will physically block LLM access if the audit ledger cannot be persisted.

### 3. Sovereign Heuristic Grounding (The Librarian)
Ground your AI prompts in local policy knowledge without the complexity of external databases:
*   **Local Librarian:** High-speed keyword-based search over local text/markdown policy files located in `policies/`.
*   **Leak-Proof Context:** Every retrieved snippet is automatically scrubbed for PII before being sent to the LLM.
*   **Policy Structure Example:** Drop markdown files into `policies/` (e.g. `policies/company_guidelines.md`). IronWarden automatically indexes paragraphs and headings for zero-ops grounding.

---

## ⚡ Technical Specifications

*   **Runtime:** Standalone Rust Binary (< 50MB footprint).
*   **Hardware Requirement:** < 1.5GB RAM (Run it on an AWS t3.micro, a Raspberry Pi, or a Mac Mini).
*   **Latency:** ~45ms - 60ms end-to-end (Synchronous AI protection).
*   **Security:** 100% On-Premise. No data ever leaves your network unredacted.
*   **Persistence:** Unified SQLite ledger for Zero-Ops deployment.
*   **Protocols:** OpenAI `/v1/chat/completions`, `/v1/completions`, `/v1/models` + Anthropic `/v1/messages` (streaming & non-streaming).

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
2.  **Configure:** Set your 32-byte `WARDEN_PEPPER` in the environment (`export WARDEN_PEPPER=$(openssl rand -hex 16)`).
3.  **Rules:** Drop your regional rules into `config/rules/`.
4.  **Policies:** Drop your policy files into `policies/`.
5.  **Run:** `./ironwarden`

---

## 🏛️ Product Boundary
IronWarden is the **Shield**. It focuses on **Security, Redaction, and Auditing**.
For advanced semantic search, multi-format PDF ingestion, and high-dimensional vector retrieval, use the **SearchBoost** extension.

## 📜 License

IronWarden is dual-licensed under:
* **Open Source:** [GNU Affero General Public License v3 (AGPLv3)](LICENSE). Free for open source use, research, and non-commercial community projects.
* **Commercial Enterprise:** [Commercial License](LICENSE-COMMERCIAL.md) for organizations requiring proprietary embedding, custom SLAs, FIPS compliance support, or exemption from AGPLv3 copyleft terms.

For commercial inquiries, please see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).
