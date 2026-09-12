# 🏰 IronWarden
### High-Performance Sovereign AI Reverse Proxy & Privacy Firewall

[![Rust CI](https://github.com/Somnerd/IronWarden/actions/workflows/rust_ci.yml/badge.svg)](https://github.com/Somnerd/IronWarden/actions/workflows/rust_ci.yml)
[![Release](https://img.shields.io/github/v/release/Somnerd/IronWarden?label=Release&color=blue)](https://github.com/Somnerd/IronWarden/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io%2Fsomnerd%2Fironwarden-blue?logo=docker)](https://github.com/Somnerd/IronWarden/pkgs/container/ironwarden)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg?logo=rust)](Cargo.toml)
[![Latency](https://img.shields.io/badge/Overhead-%3C1.8ms%20p95-brightgreen)](BENCHMARKS.md)

**IronWarden** is a sovereign, high-throughput AI security proxy written in safe, high-performance Rust. 

Point any **OpenAI**, **Anthropic**, or **Ollama/vLLM** SDK client at IronWarden to get **real-time PII redaction**, **prompt injection protection**, **streaming SSE token rehydration**, and **cryptographic audit logging** — with **zero code changes** in your application.

---

## 🏗️ Architecture

```
                                 THE IRONWARDEN PROXY PIPELINE
                                 
    ┌──────────────┐                                                     ┌──────────────────┐
    │  Client App  │ ── (1) User Prompt with Sensitive PII ───────────▶ │   IronWarden     │
    │ (OpenAI SDK /│                                                     │ AI Gateway Proxy │
    │  Anthropic)  │ ◀─ (6) Clear Streaming Response with PII Restored ─ │ (Rust, Axum, ML) │
    └──────────────┘                                                     └─────────┬────────┘
                                                                                   │
                 ┌─────────────────────────────────────────────────────────────────┴─┐
                 │  [INGRESS]                                                        │
                 │   • Aho-Corasick & Entropy Smuggling Pattern Normalization        │
                 │   • Local DistilBERT ONNX Hybrid NER Entity Extraction            │
                 │   • PII Tokenization: "John Doe" ➔ "[PII_NAME_1]"                 │
                 │   • Prompt Injection & Jailbreak Firewall                         │
                 │   • AES-256-GCM + HMAC-SHA256 Tamper-Evident Audit Ledger         │
                 └─────────────────────────────────┬─────────────────────────────────┘
                                                   │
                                                   ▼ (2) Scrubbed Anonymized Prompt
                                        ┌──────────────────────┐
                                        │ Upstream LLM Server  │
                                        │ • OpenAI (GPT-4o)    │
                                        │ • Anthropic (Claude) │
                                        │ • Ollama / vLLM      │
                                        └──────────┬───────────┘
                                                   │
                 ┌─────────────────────────────────┴─────────────────────────────────┐
                 │  [EGRESS]                                                         │
                 │   • Real-Time SSE Streaming Chunk Processor                       │
                 │   • Sliding-Window Rehydration Buffer (Zero Partial Chunk Leaks)  │
                 │   • Deterministic Restorer: "[PII_NAME_1]" ➔ "John Doe"           │
                 └───────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Quickstart

### 1. Run with Docker (Recommended)
```bash
docker run -d \
  -p 14141:14141 \
  -e WARDEN_PEPPER="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
  -e OPENAI_API_KEY="sk-..." \
  --name ironwarden \
  ghcr.io/somnerd/ironwarden:latest
```

### 2. Deploy to Kubernetes with Helm
```bash
helm install ironwarden ./deploy/helm/ironwarden \
  --set secrets.wardenPepper="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
  --set secrets.openaiApiKey="sk-..."
```

### 3. Build & Run from Source
```bash
git clone https://github.com/Somnerd/IronWarden.git
cd IronWarden

# Optional: Download ONNX NER weights (falls back to high-speed heuristic mode if omitted)
./scripts/setup_models.sh

# Run the gateway
export WARDEN_PEPPER=$(openssl rand -hex 16)
cargo run --release -p app
```

---

## 🔌 Universal Drop-in SDK Compatibility

### OpenAI Python SDK
Simply set `base_url` to IronWarden's gateway endpoint:

```python
from openai import OpenAI

# Point client to IronWarden — zero code modifications required
client = OpenAI(
    api_key="sk-mock-or-real",
    base_url="http://localhost:14141/v1",
    default_headers={"Authorization": "Bearer <your-jwt-or-key>"}
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": "Patient John Doe (SSN: 123-45-6789) shows elevated blood pressure."}
    ],
    stream=True # Streaming supported natively with real-time SSE token rehydration
)

for chunk in response:
    if chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)

# ✅ PII scrubbed before reaching upstream LLM
# ✅ HMAC-chained tamper-evident audit record logged
# ✅ PII seamlessly restored in the output stream
```

### Anthropic Claude Python SDK
```python
import anthropic

client = anthropic.Anthropic(
    api_key="sk-ant-...",
    base_url="http://localhost:14141",
    default_headers={
        "Authorization": "Bearer <your-jwt-or-key>",
        "X-IronWarden-Upstream-Key": "sk-ant-..."
    }
)

message = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Customer Jane Smith (Email: jane@enterprise.com) requested a refund."}]
)
print(message.content[0].text)
```

### Dynamic Upstream Routing Headers

| Header | Description | Default |
| :--- | :--- | :--- |
| `X-IronWarden-Target-URL` | Explicitly overrides upstream URL per-request (e.g. `http://localhost:11434/v1/chat/completions`) | Inferred from model name |
| `X-IronWarden-Upstream-Key` | Per-request API key for upstream provider | `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` |

**Automatic Model Routing:**
- `claude-*` ➔ Anthropic API (`https://api.anthropic.com/v1/messages`)
- `llama*`, `mistral*`, `phi*`, `gemma*`, `qwen*` ➔ Local Ollama (`http://localhost:11434/v1/chat/completions`)
- All other models ➔ OpenAI API (`https://api.openai.com/v1/chat/completions`)

---

## 🛡️ Core Capabilities & Invariants

### 1. Real-Time Streaming SSE Token Rehydration
Unlike standard proxies that buffer the entire response to replace tokens (introducing massive latency and breaking streaming UI), IronWarden implements an **asynchronous SSE sliding-window state machine** (`SseRehydrator`). It dynamically stitches split tokens across partial HTTP chunks in under **0.04 ms** per chunk.

### 2. Hybrid Intelligence PII Shield
- **Deterministic Layer (Aho-Corasick + Entropy Smuggling Protection)**: Ultra-fast regex and entropy heuristics for Credit Cards, SSNs, Emails, Phone Numbers, IBANs, and International IDs (including Greek AMKA/AFM and EU identifiers).
- **Probabilistic Layer (Local ONNX NER)**: In-process DistilBERT Named Entity Recognition for contextual Names, Organizations, and Locations.

### 3. Cryptographic Audit Vault & Strict Fail-Closed Invariants
- **AES-256-GCM Encryption**: Prompt and redaction records are encrypted at rest using your cryptographic pepper.
- **HMAC-SHA256 Hash Chaining**: Every log entry is cryptographically linked to the previous record with continuous full-chain integrity walk verification.
- **Fail-Closed Security**: If storage fills up or audit logging fails, IronWarden physically halts upstream egress to prevent un-audited data leakage.

### 4. Turnkey Compliance Presets
Pre-configured, zero-touch regulatory rule sets ready to deploy:
- **Middle East & GCC Sovereignty** (`config/rules/me.yaml`): Saudi Arabia PDPL (SDAIA), UAE Federal Decree-Law No. 45/2021, Qatar. Emirates ID, Saudi National ID/Iqama, Saudi & UAE IBANs, GCC mobile numbers, Arabic name heuristics.
- **East Asia Sovereignty** (`config/rules/east_asia.yaml`): China PIPL / CSL, Japan APPI, South Korea PIPA, Singapore PDPA. China Resident ID, USCC, China Mobile, Japan My Number, Korea RRN, Singapore NRIC.
- **India DPDP Act 2023** (`config/rules/in.yaml`): PAN cards, Aadhaar numbers, GSTIN, Voter ID (EPIC), Indian Passports, Indian Mobile.
- **GDPR & European Sovereignty** (`config/rules/eu.yaml`, `config/rules/gr.yaml`): EU & Greek national IDs (AMKA, AFM), EU IBANs, Passports, Driving Licenses.
- **HIPAA** (`config/rules/rules_medical.yaml`): Medical records, Patient IDs, MRNs, SSNs.
- **PCI-DSS** (`config/rules/rules.yaml`): Primary Account Numbers (PANs), CVVs, track data.

### 5. Model Context Protocol (MCP) Server
IronWarden includes a native JSON-RPC 2.0 stdio MCP server for agentic AI architectures (Claude Desktop, Cursor, AI agents) with session isolation and prompt sanitization tools:
- `mcp_sanitize_prompt`
- `mcp_restore_prompt`
- `mcp_get_compliance_report`

---

## 📊 Performance Benchmarks

Measured using [Criterion.rs](https://github.com/bheisler/criterion.rs) with 1,000+ iterations per sample. See [BENCHMARKS.md](BENCHMARKS.md) for full methodology.

| Metric | Measured Value | Real-World Impact |
| :--- | :--- | :--- |
| **Ingress PII Scrubbing + Shield** | **0.38 ms** (p50) / **1.12 ms** (p95) | <0.1% of standard LLM TTFT |
| **Streaming SSE Rehydration (per chunk)** | **0.04 ms** (p50) / **0.12 ms** (p95) | Zero perceived token streaming stutter |
| **AES-256-GCM + HMAC Audit Persistence** | **0.15 ms** (p50) / **0.42 ms** (p95) | Fully offloaded & asynchronous |
| **Total Added Gateway Overhead** | **< 1.8 ms** (p95) | **< 1.2% total added latency** |
| **Throughput (Single Process)** | **14,200+ req/s** | Scales linearly with CPU cores |
| **Base Memory Footprint** | **~28.4 MB RSS** | Ultra-lightweight edge deployment |

---

## 📈 Observability & Grafana Dashboard

IronWarden includes native, production-grade observability:

* **Prometheus Metrics**: `GET /metrics` exposes request counts, blocked prompt injections, redacted PII entities, and available concurrency permits.
* **Turnkey Grafana Dashboard**: `GET /grafana/dashboard` exports the pre-configured Grafana dashboard JSON.
* **Structured Health Inspection**: `GET /health` returns JSON uptime, permit availability, and system status.

### 1-Command Monitoring Stack
Launch IronWarden + Prometheus + Grafana together:
```bash
docker compose -f monitoring/docker-compose.monitoring.yml up -d
```
Visit **`http://localhost:3000`** (admin/admin) to view real-time gateway traffic, blocked prompt injection attacks, and redacted PII statistics.

---

## 🤝 Open Source & Community

* **Contributing:** Please read our [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
* **Security Disclosures:** For vulnerability reporting, please see [SECURITY.md](SECURITY.md).
* **Maintainer Notes:** See [MAINTAINER_NOTES.md](MAINTAINER_NOTES.md).
* **License:** Licensed under the [MIT License](LICENSE). Copyright (c) 2026 IronWarden Maintainers.
