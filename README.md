# 🏰 IronWarden
### High-Performance Sovereign AI Reverse Proxy & Privacy Firewall

[![Rust CI](https://github.com/Somnerd/IronWarden/actions/workflows/rust_ci.yml/badge.svg)](https://github.com/Somnerd/IronWarden/actions/workflows/rust_ci.yml)
[![Release](https://img.shields.io/github/v/release/Somnerd/IronWarden?label=Release&color=blue)](https://github.com/Somnerd/IronWarden/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io%2Fsomnerd%2Fironwarden-blue?logo=docker)](https://github.com/Somnerd/IronWarden/pkgs/container/ironwarden)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg?logo=rust)](Cargo.toml)
[![Criterion Benchmarks](https://img.shields.io/badge/Criterion%20Benchmarks-Statistically%20Verified-brightgreen)](BENCHMARKS.md)
[![SSE Rehydration](https://img.shields.io/badge/SSE%20Rehydration-%3C1%C2%B5s%20per%20chunk-blue)](BENCHMARKS.md)

**IronWarden** is a sovereign, ultra-low-latency AI security reverse proxy and PII firewall written in bare-metal Rust. 

Point any **OpenAI**, **Anthropic**, or **Ollama/vLLM** SDK client at IronWarden to get **real-time streaming PII redaction**, **sliding-window SSE token rehydration**, **prompt injection defense**, and **cryptographic HMAC-SHA256 audit chaining** — with **zero code changes** in your application.

---

## ⚡ Architectural Comparison

| Capability / Dimension | **IronWarden** | **Python Proxies (e.g. LiteLLM)** | **Node.js Gateways (e.g. Portkey)** | **Reverse Proxies (e.g. Kong)** |
| :--- | :---: | :---: | :---: | :---: |
| **Language & Concurrency** | **Safe Rust (Tokio / Axum async)** | Python (FastAPI / Uvicorn) | Node.js (TypeScript / V8) | OpenResty (Nginx / Lua) or Go |
| **Memory Safety & Runtime** | **Zero GC pauses, compile-time borrow checks** | GIL lock, garbage collection overhead | Single-threaded event loop, GC sweeps | Manual memory (C/Lua) or Go GC |
| **Streaming PII Redaction** | **Real-Time Sliding-Window SSE (<1 µs/chunk)** | Buffers stream or high-latency regex | Buffers stream or post-hoc inspection | Plugin-dependent / Lua regex |
| **Audit Log Integrity** | **Cryptographic HMAC-SHA256 Ledger Chaining** | Plaintext JSON files | Cloud SaaS telemetry | Standard web access logs |
| **Base Memory Footprint** | **~28.4 MB RSS (Heuristic) / ~142 MB (Hybrid NER)** | ~140 MB+ baseline | ~110 MB+ baseline | ~85 MB baseline |
| **Data Sovereignty** | **100% Local / Air-Gapped / Private VPC** | Self-hosted or SaaS | SaaS-dependent cloud routing | Self-hosted or Enterprise Cloud |

---

## 🏗️ Architecture

```
       [ Client / Microservices / OpenAI & Anthropic SDKs ]
                   │
                   ▼ (HTTP/2, Streaming SSE, JSON-RPC)
       ┌─────────────────────────────────────────────────────────────┐
       │                   IronWarden Core Gateway                   │
       │                                                             │
       │  ┌──────────────────┐    ┌────────────────────────────────┐ │
       │  │ Token Bucket     │    │ Axum / Hyper High-Concurrency  │ │
       │  │ GCRA Rate Limit  │───▶│ Non-Blocking Connection Pool   │ │
       │  └──────────────────┘    └────────────────────────────────┘ │
       │                                     │                       │
       │                                     ▼                       │
       │  ┌────────────────────────────────────────────────────────┐ │
       │  │ Streaming SSE Rehydration Engine                       │ │
       │  │  • Sliding-window token reassembly across chunk splits │ │
       │  │  • Zero-copy string normalization & homoglyph defense  │ │
       │  └────────────────────────────────────────────────────────┘ │
       │                                     │                       │
       │                                     ▼                       │
       │  ┌────────────────────────────────────────────────────────┐ │
       │  │ Multi-Tier PII & Security Gating                       │ │
       │  │  • Layer 1: SIMD-Accelerated Aho-Corasick Regex Rules  │ │
       │  │  • Layer 2: ShadowNer Named Entity Recognition         │ │
       │  │  • Layer 3: Prompt Injection & Smuggling Guardrail     │ │
       │  └────────────────────────────────────────────────────────┘ │
       │                                     │                       │
       │                                     ▼                       │
       │  ┌────────────────────────────────────────────────────────┐ │
       │  │ Tamper-Proof Audit Chaining (HMAC-SHA256 Merkle Chain) │ │
       │  │  • Verifiable cryptographic audit trail for EU AI Act  │ │
       │  └────────────────────────────────────────────────────────┘ │
       └───────────────────────────────┬─────────────────────────────┘
                                       │ (Redacted Outbound TX)
                                       ▼
                 [ Upstream LLMs: OpenAI / Anthropic / Local Ollama ]
```

---

## ⚡ Zero-Friction Quickstart

### 1. Run with Docker (1-Command Instant Start)
Spin up IronWarden in 5 seconds with zero configuration:
```bash
docker run -d --name ironwarden \
  -p 8080:8080 \
  -e UPSTREAM_LLM="https://api.openai.com" \
  -e WARDEN_MODE="hybrid" \
  ghcr.io/somnerd/ironwarden:latest
```

### 2. Verify with Streaming Curl
Send an LLM prompt containing sensitive PII and observe instant streaming token restoration with zero telemetry leakage:
```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "model": "gpt-4o",
    "messages": [
      {"role": "user", "content": "Process payment for John Doe, SSN 000-12-3456, IBAN GR1201101250000000012345678."}
    ],
    "stream": true
  }'
```

### 3. Deploy with Docker Compose
```bash
docker compose up -d
```

### 4. Deploy to Kubernetes with Helm
```bash
helm install ironwarden ./deploy/helm/ironwarden \
  --set secrets.wardenPepper="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
  --set secrets.openaiApiKey="sk-..."
```

### 5. Build & Run from Source
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
Unlike standard proxies that buffer the entire response to replace tokens (introducing massive latency and breaking streaming UI), IronWarden implements an **asynchronous SSE sliding-window state machine** (`SseRehydrator`). It dynamically stitches split tokens across partial HTTP chunks in under **1 µs** per chunk (503 ns – 822 ns Criterion median on AMD Ryzen 7 5700X3D).

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

Empirically measured using [Criterion.rs](https://github.com/bheisler/criterion.rs) (100 samples, 1,000+ iterations per sample, 95% confidence intervals) on AMD Ryzen 7 5700X3D (8C/16T, 96MB L3 V-Cache), Linux 6.6 WSL2. All raw data committed in [`benchmarks/raw/criterion_estimates.json`](benchmarks/raw/criterion_estimates.json). See [BENCHMARKS.md](BENCHMARKS.md) for full methodology.

| Operation / Micro-Benchmark | Median Latency [95% CI] | Architectural Impact |
| :--- | :---: | :--- |
| **Streaming SSE Rehydration (no tokens)** | **503.2 ns** [502.3 – 503.9 ns] | Zero perceptible streaming stutter (<0.001 ms) |
| **Streaming SSE Rehydration (complete token)** | **579.4 ns** [578.2 – 580.4 ns] | Immediate in-flight substitution |
| **Streaming SSE Rehydration (split token across chunks)** | **821.8 ns** [820.2 – 823.2 ns] | Sub-microsecond multi-chunk state machine |
| **AES-256-GCM Hardware Decryption** | **772.8 ns** [770.9 – 774.7 ns] | Hardware AES-NI accelerated |
| **AES-256-GCM Hardware Encryption** | **807.4 ns** [805.7 – 809.6 ns] | Hardware AES-NI accelerated |
| **Token Restoration (Aho-Corasick SIMD)** | **126.0 µs** [125.6 – 126.5 µs] | 3.4x faster than regex (422.9 µs) |
| **ShadowNER Boundary Token Scan** | **1.01 µs** [1.01 – 1.03 µs] | Sub-microsecond heuristic pre-filter |
| **Lock-Free Atomic Metric Record** | **1.77 ns** [1.76 – 1.77 ns] | Zero lock contention telemetry |
| **Prometheus Exposition Render** | **292.8 ns** [292.2 – 293.7 ns] | Near-zero overhead monitoring |
| **Base Memory Footprint (Heuristic Mode)** | **28.4 MB RSS** | Minimal footprint for micro-containers |
| **Base Memory Footprint (Hybrid ONNX NER Mode)** | **142.0 MB RSS** | Loaded ONNX Runtime engine & tensor buffers |

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

### 🛠️ Need Custom High-Performance Systems or Sovereign AI Infrastructure?
I partner with engineering teams and startups on fractional consulting and dedicated infrastructure sprints:
* **The 1-Week Sovereign AI Gateway Sprint (€4,500 flat fee)**: VPC deployment, custom PII rules, and sub-millisecond gateway processing overhead.
* **Custom Rust Reverse Proxies & Protocol Gateways** (HTTP/2, Tokio, Axum, L2.5–L7 signaling).
* **Backend Performance Audits & Python-to-Rust Migrations**.

👉 **[Contact Nikolas Alexandrakis for Architecture & Consulting Inquiries](mailto:nikolasalexandrakis.work@gmail.com?subject=Consulting%20Inquiry%20-%20Systems%20Architecture)**

---

## 🤝 Open Source & Community

* **Contributing:** Please read our [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
* **Security Disclosures:** For vulnerability reporting, please see [SECURITY.md](SECURITY.md).
* **Maintainer Notes:** See [MAINTAINER_NOTES.md](MAINTAINER_NOTES.md).
* **License:** Licensed under the [MIT License](LICENSE). 100% free and open-source software for commercial and private use.
* **Enterprise Services & Support:** For custom PII rule modeling, compliance readiness, or dedicated architecture sprints, see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).
* **Copyright:** Copyright (c) 2026 IronWarden Maintainers.
