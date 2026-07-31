# 🏰 IronWarden v1.0.0-rc.1
### Universal AI Privacy Firewall & Security Gateway

IronWarden is a high-performance, single-binary **AI security proxy**. Point any OpenAI or Anthropic SDK client at it and get automatic PII redaction, cryptographic audit logging, and rate limiting — with **zero code changes** in your application.

---

## 🚀 Universal Proxy Quickstart

> **EU AI Act compliant out of the box.** IronWarden acts as a transparent firewall between your app and any LLM provider.

### OpenAI SDK (Python)

```python
# Before: direct OpenAI call
from openai import OpenAI
client = OpenAI(api_key="sk-...")

# After: route through IronWarden — zero other changes
client = OpenAI(
    api_key="sk-...",
    base_url="http://localhost:14141/v1",
    default_headers={"Authorization": "Bearer <your-ironwarden-jwt>"}
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "My email is john@example.com — summarize my account."}]
)
# ✅ PII scrubbed before reaching OpenAI
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
| `X-IronWarden-Target-URL` | Override upstream per-request (Ollama, vLLM, custom endpoint) |
| `X-IronWarden-Upstream-Key` | Per-request API key for upstream |

**Model-name auto-routing** (no config needed):
- `claude-*` → Anthropic API
- `llama*`, `mistral*`, `phi*`, `gemma*`, `qwen*` → Ollama (`localhost:11434`)
- Everything else → OpenAI API

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
2.  **Configure:** Set your 32-byte `WARDEN_PEPPER` in the environment.
3.  **Rules:** Drop your regional rules into `config/rules/`.
4.  **Knowledge:** Drop your policy files into `data/knowledge/`.
5.  **Run:** `./ironwarden`

---

## 🏛️ Product Boundary
IronWarden is the **Shield**. It focuses on **Security, Redaction, and Auditing**.
For advanced semantic search, multi-format PDF ingestion, and high-dimensional vector retrieval, use the **SearchBoost** extension.

---
**Status:** v1.0.0-rc.1 — Universal AI Gateway Proxy.
**License:** AGPLv3 / Commercial.
