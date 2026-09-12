# 🏰 IronWarden: Master Technical Notes & Architectural Manual

**Project Name:** IronWarden  
**Repository:** `Somnerd/IronWarden`  
**License:** MIT License (*Copyright (c) 2026 IronWarden Maintainers*)  
**Core Technology:** Safe Systems Rust (Edition 2021, Rust 1.80+), Tokio, Axum, LanceDB, ONNX Runtime  
**Target Release:** `v1.0.0-beta.2`  

---

## 1. Executive Summary & Value Proposition

**IronWarden** is a sovereign, high-throughput AI security gateway and privacy firewall engineered in pure Rust. It functions as a transparent reverse proxy positioned between client applications and Large Language Model providers (OpenAI, Anthropic Claude, Ollama, vLLM).

### The Core Problem Solved:
Organizations deploying LLMs face severe regulatory and security risks:
1. **PII/PHI Leakage:** Employees or backend services accidentally transmit confidential customer data, healthcare identifiers, or payment card details to external LLM APIs (violating GDPR, HIPAA, PCI-DSS).
2. **Prompt Injection & Jailbreaks:** Untrusted user inputs hijack LLM system prompts or exfiltrate private corporate data.
3. **Auditability Deficits:** Inability to legally prove what prompts were sent to LLMs, whether they were modified, or if audit logs were altered after the fact.
4. **Streaming Latency Penalty:** Existing redactors buffer the entire LLM response to perform token restoration, introducing massive time-to-first-token (TTFT) delays and breaking streaming interfaces.

### IronWarden's Solution:
- **Zero Application Code Changes:** Point any OpenAI or Anthropic SDK to `http://localhost:14141/v1` or set `base_url`.
- **Microsecond Ingress Sanitization:** Hybrid deterministic pattern matching (Aho-Corasick + Entropy) + in-process DistilBERT ONNX NER.
- **Zero-Copy Streaming SSE Token Rehydration:** State-machine lookahead buffer restores placeholders in real-time (`< 0.04 ms` per chunk).
- **Cryptographic Audit Vault:** AES-256-GCM payload encryption with HMAC-SHA256 tamper-evident hash chaining.
- **Deterministic Fail-Closed Architecture:** Egress traffic is physically blocked if auditing or storage fails.

---

## 2. Workspace Architecture & Crate Hierarchy

The workspace is organized into seven modular, decoupled crates:

```
                                      app (Daemon Binary)
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            ▼                          ▼                          ▼
      worker (Proxy & Storage)    mcp (Stdio JSON-RPC)      cli (Admin Tool)
            │                          │                          │
            └─────────────┬────────────┘                          │
                          ▼                                       │
                    warden (NER & Shield Engine)                  │
                          │                                       │
                          └────────────┬──────────────────────────┘
                                       ▼
                                 core (iw_core)
```

### Detailed Crate Breakdown:

| Crate | Package Name | Primary Responsibilities | Key Modules & Structs |
| :--- | :--- | :--- | :--- |
| **`core`** | `iw_core` | Cryptographic primitives, domain traits, shared data structures, error hierarchies. | `AadCipher`, `JwtVerifier`, `FipsValidator`, `SovereignError`, `PiiShield`, `StorageProvider`, `SessionContext` |
| **`warden`** | `iw-warden` | Text sanitization, dictionary automata, regex normalization, shadow NER, ONNX model pooling. | `WardenEngine`, `Normalizer`, `HybridNerPool`, `WardenConfig`, `RuleConfig`, `RulesConfigurator` |
| **`worker`** | `iw_worker` | Axum HTTP reverse proxy, SSE streaming rehydration, SQLite & Redis session/audit managers, LanceDB Librarian, Prometheus metrics. | `handle_openai_chat_completions`, `handle_anthropic_messages`, `SseRehydrator`, `AsyncAuditor`, `LocalSessionManager`, `LocalLibrarian`, `GatewayMetrics` |
| **`mcp`** | `iw_mcp` | Model Context Protocol stdio server for agentic AI tools (Claude Desktop, Cursor). | `StdioMcpServer`, `mcp_sanitize_prompt`, `mcp_restore_prompt`, `mcp_get_compliance_report` |
| **`app`** | `app` | Main runtime daemon entry point, CLI flag parsing, signal lifecycle (`SIGINT`/`SIGTERM`), hot-reload orchestration (`ArcSwap`). | `main.rs`, `GlobalConfig`, `DynamicShield` |
| **`cli`** | `iw-cli` | Administrative command-line tool for audit verification, chain walking, and compliance reports. | `main.rs`, audit verification commands |
| **`integration_tests`** | `iw-integration-tests` | Comprehensive adversarial, stress, fuzz, and compliance preset integration test suites. | 54 automated e2e integration tests |

---

## 3. Cryptographic Invariants & Security Architecture

```
                    IMMUTABLE HMAC-SHA256 AUDIT LEDGER CHAIN
                    
  [Record n-1] ─── Hash(n-1) ────────┐
                                     ▼
  [Record n]   ─── Inputs: ────────▶ HMAC-SHA256 ──▶ Hash(n) ──▶ Persist to DB & Anchor
                   • Hash(n-1)
                   • Timestamp
                   • Username (Tenant ID)
                   • is_blocked (Boolean)
                   • bincode(Redactions)
                   • SHA256(Ciphertext || Nonce)
```

### 3.1 Centralized `AadCipher` (AES-256-GCM + HKDF)
- **Entropy & Key Derivation:** Keys are derived from the 32-byte master `WARDEN_PEPPER` via HKDF-SHA256. Salts vary per cryptographic subsystem (`KDF_SALT_ENCRYPTION`, `KDF_SALT_INTEGRITY`, `KDF_SALT_GENESIS`).
- **AAD Tenant Isolation (V-19 Invariant):** Every encryption call binds the caller's `username` into the AES-GCM Associated Authenticated Data (`aad`) and HKDF `info`. Even if an attacker manipulates the underlying database directly, cross-tenant ciphertext swapping or injection fails decryption immediately.
- **Memory Zeroization:** All derived cryptographic key buffers implement `zeroize::Zeroize` and are securely erased from memory immediately after cipher construction.

### 3.2 Immutable HMAC-SHA256 Hash Chaining
- Each transaction record is cryptographically bound to its immediate predecessor.
- Any modification, deletion, or out-of-order reinsertion of database records breaks the cryptographic chain and triggers an alert.
- **Anchor File Integrity:** An external filesystem anchor (`.anchor`) records the latest record ID and HMAC signature. On boot and during periodic 5-second background sweeps, any discrepancy triggers an immediate system `HARD-STOP`.

### 3.3 Strict Fail-Closed Invariants
1. **Audit Persistence Failure:** If the audit ledger database is locked (`DatabaseBusy`), disk space drops below 50MB, or writes time out, IronWarden **aborts the request immediately with 503/504**. Un-audited traffic is never forwarded to external LLMs.
2. **Missing Dependencies in Production:** In production environments (`WARDEN_ENV=production`), missing OCR libraries or missing cryptographic peppers cause an immediate startup halt rather than falling back to unsafe mock modes.

---

## 4. Real-Time Streaming SSE Token Rehydration (`SseRehydrator`)

```
Incoming Stream Chunks:
  Chunk 1: '{"choices":[{"delta":{"content":"Hello [PII_"}}]}'
  Chunk 2: '{"choices":[{"delta":{"content":"EMAIL_1], how can I help?"}}]}'

Sliding-Window State Machine (SseRehydrator):
  1. Receives Chunk 1: Detects opening bracket '[' and known token prefix '[PII_'.
     Buffers prefix. Emits: "Hello "
  2. Receives Chunk 2: Detects closing bracket ']' completing '[PII_EMAIL_1]'.
     Looks up token map: '[PII_EMAIL_1]' ➔ 'alice@company.com'.
     Emits: "alice@company.com, how can I help?"
```

### Key Technical Achievements:
- **Zero Full-Response Buffering:** Time-To-First-Token (TTFT) is completely preserved.
- **Boundary-Split Resilient:** Handles arbitrary chunk boundary slicing (e.g. 1 byte at a time) across single or multiple placeholders.
- **Microsecond Execution:** Rehydration executes in **`0.04 ms` (p50) / `0.12 ms` (p95)** per SSE chunk.

---

## 5. Universal Proxy & Model Routing

### Drop-in SDK Compatibility:
1. **OpenAI SDK:** Set `base_url="http://localhost:14141/v1"`. Supports `/v1/chat/completions`, `/v1/completions`, and `/v1/models`.
2. **Anthropic Claude SDK:** Set `base_url="http://localhost:14141"`. Supports `/v1/messages`.
3. **Local LLMs (Ollama / vLLM):** Fully compatible with local OpenAI-compatible runtimes.

### Intelligent Routing Rules:
- Model names starting with `claude-*` automatically route to `https://api.anthropic.com/v1/messages`.
- Model names starting with `llama*`, `mistral*`, `phi*`, `gemma*`, `qwen*` automatically route to local Ollama (`http://localhost:11434/v1/chat/completions`).
- All other models default to OpenAI (`https://api.openai.com/v1/chat/completions`).
- **Dynamic Overrides via Headers:**
  - `X-IronWarden-Target-URL`: Overrides destination endpoint per-request.
  - `X-IronWarden-Upstream-Key`: Provides a per-request API key for the upstream provider.

---

## 6. Observability, Monitoring & Compliance Presets

### Observability Endpoints:
- **`GET /metrics`:** Prometheus-compatible text format exposing:
  - `ironwarden_requests_chat_completions_total`
  - `ironwarden_injections_blocked_total`
  - `ironwarden_pii_entities_redacted_total`
  - `ironwarden_available_permits` (concurrency saturation)
- **`GET /grafana/dashboard`:** Direct export of the pre-configured Grafana dashboard JSON.
- **`GET /health`:** Detailed structured JSON returning uptime, active permits, and subsystem status.
- **Docker Monitoring Stack:** `docker compose -f monitoring/docker-compose.monitoring.yml up -d` launches IronWarden + Prometheus + Grafana together on port 3000.

### Turnkey Regulatory Presets (`config/presets/`):
- **HIPAA:** 18 Safe Harbor PHI identifiers (Medical Record Numbers, NPIs, Medicare MBIs, SSNs, DEA numbers, prescriptions).
- **GDPR:** EU identifiers, IBANs, passports, national tax IDs, emails, phone numbers, and IP addresses.
- **PCI-DSS:** Visa, Mastercard, Amex, Discover, generic 16-digit PANs, CVVs, expiration dates, ABA routing numbers.

---

## 7. Performance Benchmarks Summary

All benchmarks measured on dedicated hardware using Criterion.rs with 1,000+ samples per test (see [`BENCHMARKS.md`](../BENCHMARKS.md)):

| Subsystem / Metric | p50 Latency | p95 Latency | Real-World Impact |
| :--- | :---: | :---: | :--- |
| **Ingress PII Scrubbing + Shield** | **0.38 ms** | **1.12 ms** | <0.1% of standard LLM TTFT |
| **Streaming SSE Rehydration (per chunk)** | **0.04 ms** | **0.12 ms** | Undetectable token streaming latency |
| **AES-256-GCM + HMAC Audit Logging** | **0.15 ms** | **0.42 ms** | Fully asynchronous offload |
| **Total Added Proxy Overhead** | **< 1.8 ms (p95)** | **< 1.8 ms (p95)** | **< 1.2% total added latency** |
| **Throughput (Single Instance)** | **14,200+ req/s** | — | Scales linearly with CPU cores |
| **Base Memory Footprint** | **~28.4 MB RSS** | — | Ultra-lightweight edge deployment |

---

## 8. CI/CD & Automated Distribution

### Automated Workflows (`.github/workflows/`):
1. **`rust_ci.yml`:** Runs on every push and PR:
   - `Lint & Format`: `cargo fmt --check` + `cargo clippy --workspace --all-targets -- -D warnings`.
   - `Unit Tests`: `cargo test --workspace --lib --bins`.
   - `Integration Tests`: Python pytest suite + Rust e2e suite.
   - `Code Coverage`: Automated `cargo-llvm-cov` with Codecov reporting.
   - `Benchmarks`: Verification that Criterion benchmarks compile and execute.
2. **`release.yml`:** Triggers on Git tags (`v*`):
   - Compiles pre-built release binaries for **Linux x86_64** (`ubuntu-latest`) and **macOS Apple Silicon** (`macos-latest` / `aarch64-apple-darwin`).
   - Packages `ironwarden`, `iw-cli`, configuration files, and licenses into `.tar.gz` archives.
   - Generates aggregate `SHA256SUMS.txt`.
   - Automatically creates GitHub Releases with release notes and downloadable assets.
3. **`docker_publish.yml`:** Triggers on pushes to `main` and Git tags:
   - Builds multi-arch Docker images using QEMU and Buildx.
   - Automatically pushes images to GitHub Container Registry:
     - `ghcr.io/somnerd/ironwarden:latest`
     - `ghcr.io/somnerd/ironwarden:<version>`

---

## 9. Interface & Integration with Sister Project: SearchBoost

### SearchBoost's Role:
While IronWarden is the **Shield** (Security, PII Scrubbing, Audit, and Reverse Proxy), **SearchBoost** is the **Cognitive Research & Vector Grounding Engine** (Multi-engine web search, large-scale multi-format document vectorization, and contextual grounding).

### The Integration Contract:
IronWarden exposes dedicated async grounding interfaces designed specifically for SearchBoost:
1. **`POST /enqueue`:**
   - Ingests a search or document grounding query from a user session.
   - Automatically scrubs all PII from the query before persisting.
   - Encrypts the query using `AadCipher` bound to the user's tenant ID.
   - Enqueues into an encrypted SQLite ring-buffer queue (with Redis HA cluster replication).
2. **`GET /results/:job_id`:**
   - Authenticated endpoint allowing clients or SearchBoost workers to retrieve completed grounding responses.
   - Decrypts payloads in-memory, verifies AAD identity, and restores token placeholders.
3. **Decoupled LanceDB Vector Storage:**
   - IronWarden's `LocalLibrarian` interacts with LanceDB for local semantic lookup while preserving strict multi-user document isolation and GDPR deletion compliance.

---

## 10. Summary Checklist for Moving to SearchBoost

- [x] Workspace license transitioned to **MIT**.
- [x] Full `README.md` and documentation suite published with badges and quickstart.
- [x] All 137 unit and integration tests passing 100% locally and on GitHub CI.
- [x] 29 stale remote branches and local branches pruned.
- [x] Docker build and container distribution pipeline verified with tracked `Cargo.lock`.
- [x] Release packaging pipeline verified with Linux x86_64 and Apple Silicon targets.
- [x] Release tag `v1.0.0-beta.2` pushed and running.

IronWarden is fully documented, tested, and production-ready. We are ready to transition focus to **SearchBoost**!
