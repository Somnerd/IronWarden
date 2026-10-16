# 🏛️ IronWarden Architecture & System Design

IronWarden is a sovereign, low-latency AI security reverse proxy and PII firewall written in safe Rust. It intercepts incoming LLM prompt traffic and outgoing streaming Server-Sent Events (SSE) to scrub sensitive personal data, enforce prompt safety guardrails, log tamper-evident cryptographic audit records, and seamlessly restore scrubbed tokens in real time before delivering responses to clients.

---

## 🗺️ High-Level System Architecture

```
                    [ Upstream Client Application / SDK ]
                        (OpenAI, Anthropic, Ollama, MCP)
                                      │
                                      ▼ HTTP/2 / JSON-RPC / SSE
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                IRONWARDEN GATEWAY                                      │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 1. Axum Bridge & Network Gateway (worker/src/bridge/)                            │  │
│  │    • Concurrency Semaphore & Rate Limiting                                       │  │
│  │    • SSRF Defense, Private CIDR Filter & DNS Pinning (worker/src/proxy.rs)        │  │
│  │    • JWT RS256/HS256 Auth & Tenant Identity Extraction (core/src/crypto.rs)     │  │
│  └──────────────────────────────────────────┬───────────────────────────────────────┘  │
│                                             │ Ingress Prompt                           │
│                                             ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 2. Ingress Normalization & Safety Pipeline (warden/src/)                         │  │
│  │    • Unicode NFKD & Zero-Width Stripping (warden/src/normalize.rs)                │  │
│  │    • Prompt Injection Blocklist & Sidecar (warden/src/engine/guardrails.rs)      │  │
│  │    • Entropy Smuggling Guardrail (warden/src/engine/mod.rs)                       │  │
│  └──────────────────────────────────────────┬───────────────────────────────────────┘  │
│                                             │ Normalized Prompt                        │
│                                             ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 3. Dual-Track PII Scrubbing Engine (warden/src/engine/sanitizer.rs)              │  │
│  │    • Track A: High-speed Heuristic Scan & Dictionaries (config/dicts/)           │  │
│  │    • Track B: Ambiguous Span Extraction & Context Gating                         │  │
│  │    • Neural Disambiguation: INT8 ONNX DistilBERT-NER (warden/src/ai.rs)          │  │
│  │    • V-12 Overlap Resolution & Checksum Validation (Luhn, IBAN, AFM)             │  │
│  └──────────────────────────────────────────┬───────────────────────────────────────┘  │
│                                             │ Sanitized Prompt + TokenMap              │
│                                             ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 4. Cryptographic Vault & Audit Ledger (worker/src/audit/, core/src/crypto.rs)   │  │
│  │    • AES-256-GCM AAD Payload Encryption (AadCipher bound to tenant identity)     │  │
│  │    • Append-only SQLite WAL Ledger with HMAC-SHA256 Hash Chaining               │  │
│  │    • Fail-Closed Circuit Breaker (halts egress if ledger write fails)           │  │
│  └──────────────────────────────────────────┬───────────────────────────────────────┘  │
│                                             │ Scrubbed Request                         │
└─────────────────────────────────────────────┼──────────────────────────────────────────┘
                                              │ (Redacted Outbound TX)
                                              ▼
                    [ Upstream LLM: OpenAI / Anthropic / Ollama ]
                                              │
                                              ▼ (Raw SSE Response Stream)
┌─────────────────────────────────────────────┼──────────────────────────────────────────┐
│  ┌──────────────────────────────────────────┴───────────────────────────────────────┐  │
│  │ 5. Streaming Token Rehydrator (worker/src/sse_proxy.rs)                          │  │
│  │    • Zero-Buffering Sliding-Window Ring Buffer                                   │  │
│  │    • Cross-Chunk Placeholder Stitching (<1 µs/chunk)                             │  │
│  │    • Real-Time Token Map Restoration                                             │  │
│  └──────────────────────────────────────────┬───────────────────────────────────────┘  │
└─────────────────────────────────────────────┼──────────────────────────────────────────┘
                                              │ Restored Cleartext Stream
                                              ▼
                             [ Client Application / SDK ]
```

---

## 📦 Workspace Crates & Exact File Paths

IronWarden is structured as a Cargo workspace with strict crate separation and defense-in-depth boundaries:

### 1. `core/` (`iw_core`)
Foundation types, security traits, cryptographic primitives, and error models. Contains zero business-logic dependencies on HTTP or runtime frameworks.
- [`core/src/lib.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/core/src/lib.rs): Crate root and re-exports.
- [`core/src/traits.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/core/src/traits.rs): Core domain traits:
  - `PiiShield`: Abstraction for prompt sanitization (`sanitize_prompt`) and restoration (`restore_prompt`).
  - `VisionShield`: Abstraction for OCR bounding-box redaction.
  - `GroundingShield`: Abstraction for grounding context scrubbing.
  - `StorageProvider`: Asynchronous audit event persistence and context retrieval.
  - `McpServer`: Protocol interface for Model Context Protocol dispatch.
- [`core/src/crypto.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/core/src/crypto.rs):
  - `AadCipher`: AES-256-GCM encryption/decryption with HKDF-derived context binding using Associated Authenticated Data (AAD) for strict tenant isolation.
  - `JwtVerifier`: RS256/HS256 JWT validation, audience/issuer enforcement, and FIPS-readiness verifier.
- [`core/src/error.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/core/src/error.rs): `SovereignError` enumeration covering cryptographic, validation, storage, and upstream errors.
- [`core/src/fips.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/core/src/fips.rs): `FipsValidator` verifying runtime environment FIPS flags and cipher suite policies when `WARDEN_FIPS_MODE` is activated.
- [`core/src/executor.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/core/src/executor.rs): Thread-safe asynchronous executor wrappers.
- [`core/src/constants.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/core/src/constants.rs): System-wide default limits, header definitions, and placeholder format templates.

### 2. `warden/` (`iw-warden`)
The core PII detection, redaction, normalization, and safety analysis engine.
- [`warden/src/engine/mod.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/engine/mod.rs): `WardenEngine` implementation orchestrating sanitization passes, token map tracking, and entropy smuggling detection.
- [`warden/src/engine/sanitizer.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/engine/sanitizer.rs): Dual-track candidate evaluation and V-12 interval overlap resolution resolving nested and conflicting entity spans.
- [`warden/src/engine/guardrails.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/engine/guardrails.rs): Prompt injection detection via regex blocklists and sidecar guardrail hooks.
- [`warden/src/shadow_ner/mod.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/shadow_ner/mod.rs): ShadowNER subsystem coordinator.
- [`warden/src/shadow_ner/track_a.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/shadow_ner/track_a.rs): Track A high-certainty heuristic scanner (honorifics, initials, multi-word names, nobiliary particles).
- [`warden/src/shadow_ner/track_b.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/shadow_ner/track_b.rs): Track B ambiguous candidate extractor gating spans against externalized stopword and entity dictionaries in `config/dicts/`.
- [`warden/src/shadow_ner/patterns.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/shadow_ner/patterns.rs): Static pattern matchers and regex tables.
- [`warden/src/ai.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/ai.rs): Neural inference integrating ONNX Runtime INT8 DistilBERT-NER (`OnnxNer`, `HybridNer`, `HybridNerPool`, controlled via `WARDEN_NER_MODE`).
- [`warden/src/vision.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/vision.rs): `VisionWarden` applying geometric coordinate-box redaction over OCR bounding box outputs.
- [`warden/src/normalize.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/normalize.rs): Zero-width character stripping, homoglyph replacement, and Unicode NFKD canonical normalization.
- [`warden/src/pii.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/pii.rs): Mathematical and algorithmic checksum validators (Luhn algorithm for credit cards, IBAN mod-97 validation, Greek AFM/AMKA validators).
- [`warden/src/config.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/config.rs) & [`warden/src/configurator.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/warden/src/configurator.rs): Rule manifest parsers supporting dynamically composable YAML policies in `config/rules/`.

### 3. `worker/` (`iw_worker`)
High-performance network edge proxy, reverse proxy routing, streaming token rehydration, audit logging, and grounding.
- [`worker/src/bridge/mod.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/bridge/mod.rs): Axum HTTP router binding endpoints:
  - `/v1/chat/completions` & `/v1/completions`: OpenAI-compatible drop-in proxy.
  - `/v1/messages`: Anthropic-compatible drop-in proxy.
  - `/v1/models`: Upstream model catalog with JWT auth gating.
  - `/enqueue` & `/result/{id}`: Asynchronous document grounding pipeline.
  - `/health`: Liveness and concurrency permit status probe.
  - `/metrics`: Prometheus telemetry exposition.
- [`worker/src/bridge/llm_gateway.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/bridge/llm_gateway.rs): Ingress request parsing, tenant extraction, and outbound proxying.
- [`worker/src/bridge/telemetry.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/bridge/telemetry.rs): Atomic lock-free Prometheus metrics recorders.
- [`worker/src/bridge/search_handlers.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/bridge/search_handlers.rs): Policy and context retrieval handlers.
- [`worker/src/proxy.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/proxy.rs): SSRF-hardened upstream URL resolution, private CIDR filtering, and DNS pinning.
- [`worker/src/sse_proxy.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/sse_proxy.rs): Zero-buffering `SseRehydrator` sliding window ring-buffer restoring tokens across fragmented SSE delta chunks in sub-microsecond latency.
- [`worker/src/router.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/router.rs): Dynamic upstream model-based and header-based request router (`X-IronWarden-Target-URL`, `X-IronWarden-Upstream-Key`).
- [`worker/src/audit/mod.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/audit/mod.rs) & [`worker/src/audit/storage.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/audit/storage.rs): `AsyncAuditor` append-only SQLite WAL ledger with HMAC-SHA256 sequential hash chaining, atomic `.anchor` state file verification, and fail-closed circuit breaker.
- [`worker/src/audit/forwarder.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/audit/forwarder.rs): Background SIEM HTTP forwarder for remote enterprise logging.
- [`worker/src/session.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/session.rs): `LocalSessionManager` maintaining bounded-TTL session state and cryptographic shredding.
- [`worker/src/grounding.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/grounding.rs): `GroundingQueue` backed by Redis or SQLite.
- [`worker/src/librarian.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/librarian.rs): `LocalLibrarian` implementing LanceDB vector and BM25 hybrid policy retrieval.
- [`worker/src/ocr.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/worker/src/ocr.rs): Document processing pipeline integrating `TesseractOcr`, `AwsTextractOcr`, and `OcrWorker`.

### 4. `mcp/` (`iw_mcp`)
Native Model Context Protocol (MCP) JSON-RPC 2.0 server for agentic AI frameworks.
- [`mcp/src/protocol.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/mcp/src/protocol.rs): JSON-RPC 2.0 protocol envelopes, error definitions, and MCP parameter data structures.
- [`mcp/src/server/mod.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/mcp/src/server/mod.rs): Stdio transport event loop with concurrency semaphores.
- [`mcp/src/server/handlers.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/mcp/src/server/handlers.rs): RPC tool dispatch handlers:
  - `initialize`: Protocol capability negotiation.
  - `mcp_sanitize_prompt`: Standalone prompt scrubbing.
  - `mcp_restore_prompt`: Outbound token restoration.
  - `mcp_get_compliance_report`: Rule match inspection and statistics.
  - `mcp_ocr_ingest`: Multimodal document ingestion.
  - `mcp_orchestrate`: Agentic prompt sanitization and guarded execution.
  - `mcp_halt_system`: Administrative emergency kill switch.

### 5. `cli/` (`iw-cli`)
Operational command-line utility for offline ledger verification and GDPR compliance audits.
- [`cli/src/main.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/cli/src/main.rs): Verifies SQLite WAL hash-chain integrity, detects ledger tampering, and performs cryptographic shredding validation.

### 6. `app/`
Application binary packaging and bootstrapping.
- [`app/src/main.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/app/src/main.rs): Initializes configuration, opens the encrypted SQLite audit vault, instantiates the dual-track `WardenEngine`, sets up signal handling, and starts the Axum server.

### 7. `benchmarks/accuracy_suite/` (`iw-accuracy-suite`)
Empirical precision, recall, and adversarial evaluation harness.
- [`benchmarks/accuracy_suite/src/main.rs`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/benchmarks/accuracy_suite/src/main.rs): Evaluates Heuristic and Hybrid NER pipelines across 100,000 multilingual prompts, CoNLL-2003, WikiGold, and adversarial torture tests, emitting results to [`benchmarks/raw/accuracy_eval_results.json`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/benchmarks/raw/accuracy_eval_results.json).

### 8. `tests/` (`iw-integration-tests`)
Comprehensive integration, unit, adversarial, stress, and end-to-end test suites.
- Documented in detail in [`tests/README.md`](file:///home/somnerd/Documents/Projects/IronWarden-worktrees/pr5-safety-ci-and-docs/tests/README.md).

---

## 🔄 End-to-End Request Data Flow

### 1. Ingress Flow (Prompt Scrubbing & Guardrails)
1. **Request Ingestion**: The client issues an HTTP `POST` to `/v1/chat/completions` (OpenAI format) or `/v1/messages` (Anthropic format).
2. **Authentication & Identity**: The Axum bridge extracts the JWT Bearer token or API key. The tenant identifier is bound to the request's `SessionContext`.
3. **SSRF Validation**: If dynamic routing headers (`X-IronWarden-Target-URL`) are present, `worker/src/proxy.rs` resolves the hostname, blocks loopback/link-local/private RFC1918 IPs, and pins the socket to the validated IP.
4. **Text Normalization**: `warden/src/normalize.rs` strips zero-width non-printing characters and normalizes Unicode homoglyphs via NFKD to prevent bypass attacks.
5. **Prompt Injection & Smuggling Guard**: `warden/src/engine/guardrails.rs` checks for prompt injection patterns and Shannon entropy anomalies. If an attack is detected, the request is immediately rejected or flagged.
6. **Dual-Track PII Scrubbing**:
   - **Track A**: SIMD Aho-Corasick matches high-certainty structural patterns (credit cards, IBANs, national IDs, emails, API keys) and high-confidence names from `config/dicts/`.
   - **Track B**: Ambiguous capitalized tokens are evaluated against stopword dictionaries. In Hybrid mode (`WARDEN_NER_MODE=hybrid`), remaining ambiguous candidates are dispatched to the INT8 ONNX DistilBERT model.
7. **Interval Overlap Resolution (V-12)**: Overlapping or nested entity spans are resolved using an interval tree to ensure deterministic, longest-match token substitution (e.g., preserving full card numbers over partial sub-matches).
8. **Token Map Creation & Vaulting**: Replaced entities are assigned deterministic surrogates (e.g., `{{PERSON_1}}`, `{{CREDIT_CARD_1}}`). The surrogate-to-cleartext mapping is encrypted with AES-256-GCM via `AadCipher` and stored in the session state.
9. **HMAC-SHA256 Audit Chaining**: An audit record containing the timestamp, tenant ID, and redaction metadata is cryptographically chained to the previous record's hash and committed to SQLite WAL storage.
10. **Fail-Closed Gate**: If the audit write fails or the disk is full, the request is aborted immediately before any outbound traffic leaves the network boundary.
11. **Upstream Forwarding**: The sanitized prompt containing only surrogate tokens is dispatched to the upstream LLM provider.

### 2. Egress Flow (Real-Time Streaming SSE Token Restoration)
1. **Upstream SSE Streaming**: The upstream LLM begins streaming `text/event-stream` chunks back to IronWarden.
2. **Sliding-Window Token Rehydration**:
   - HTTP chunks stream into `SseRehydrator` (`worker/src/sse_proxy.rs`) without buffering the full response into memory.
   - If a surrogate token like `{{PERSON_1}}` arrives split across chunk boundaries (e.g., chunk 1 ends with `{{PER` and chunk 2 begins with `SON_1}}`), the sliding window state machine retains only the partial boundary bytes, stitches the surrogate, and restores the original cleartext value.
   - Chunks without surrogates pass through at line rate (<1 µs latency overhead).
3. **Client Delivery**: The reconstructed delta chunk is flushed immediately to the downstream client application.

---

## 🛡️ Security, Cryptography & Isolation Invariants

| Principle | Architectural Implementation | Verification & Testing |
| :--- | :--- | :--- |
| **Strict Fail-Closed** | If audit logging fails or storage is unavailable, upstream egress is aborted immediately. Un-audited traffic never leaves the proxy. | Verified in `tests/rust/unit_worker_bridge.rs` and `tests/rust/worker/security_invariant_test.rs`. |
| **Tenant AAD Cryptographic Binding** | Payloads encrypted via `AadCipher` bind the tenant ID in the HKDF context and AAD buffer. Encrypted tokens cannot be decrypted under another tenant's session. | Verified in `tests/rust/unit_core.rs` and `tests/rust/core/session_concurrency.rs`. |
| **Cryptographic Shredding** | GDPR right-to-erasure is enforced by zeroizing the session encryption key. Encrypted ledger records become mathematically undecryptable without rewriting historical chain hashes. | Verified in `tests/rust/unit_worker_storage.rs` and CLI verification in `cli/src/main.rs`. |
| **SSRF Defense with DNS Pinning** | Hostnames in target URLs are resolved via OS DNS, verified against RFC 1918, RFC 3927, and loopback blacklists, and pinned to the verified IP for HTTP connection establishment. | Verified in `tests/rust/unit_worker_proxy.rs`. |
| **Zero Stream Buffering** | Response streaming uses a fixed-size ring buffer rather than accumulating complete HTTP responses, ensuring sub-microsecond latency and immune to memory exhaustion attacks. | Verified via Criterion benchmarks in `benchmarks/raw/criterion_estimates.json`. |

---

## 📜 Rule Presets & Compliance Configuration

IronWarden includes modular YAML rule manifests in `config/rules/` targeting identifiers commonly referenced across international privacy frameworks:

- **`config/rules/core.yaml`**: Standard universal identifiers (emails, phone numbers, IP addresses, secrets, AWS keys).
- **`config/rules/eu.yaml` & `config/rules/gr.yaml`**: European and Greek identifiers (Greek AFM tax numbers, AMKA social security numbers, EU IBANs, passports).
- **`config/rules/me.yaml`**: Middle East and GCC identifiers (Emirates ID, Saudi National ID/Iqama, GCC mobile numbers, Saudi/UAE IBANs).
- **`config/rules/east_asia.yaml`**: East Asian identifiers (China Resident ID, Japan My Number, South Korea RRN, Singapore NRIC).
- **`config/rules/in.yaml`**: Indian sovereign identifiers (PAN, Aadhaar, GSTIN, Indian EPIC Voter ID).
- **`config/rules/rules_medical.yaml`**: Protected Health Information (PHI) identifiers (Patient IDs, MRNs, Medical Record numbers).
- **`config/rules/rules_legal.yaml`**: Legal proceeding identifiers (Case numbers, Court filings, Attorney identifiers).

> [!NOTE]
> **Regulatory Notice**: IronWarden's rule manifests and cryptographic audit ledgers provide pattern-based redaction and verifiable audit records targeting identifiers referenced in frameworks such as HIPAA, GDPR, PDPL, and PCI-DSS. Deploying IronWarden does not constitute a formal regulatory certification or legal compliance endorsement by any supervisory authority.
