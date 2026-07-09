# 🛡️ IronWarden V1.1 Master QA Test Plan
**Classification:** Internal / Engineering / QA
**Version:** 1.1
**Date:** 2026-05-02

## 1. Objective
To comprehensively validate the IronWarden Sovereign Standalone Appliance for V1.1 release. The goal is to ensure 100% functional reliability, robust security isolation, and acceptable high-concurrency performance prior to commercial deployment.

## 2. Test Environment & Scope
- **Appliance Architecture:** Standalone (SQLite + Local DashMap memory).
- **Core Components Tested:**
  - `mcp::server` (JSON-RPC 2.0 interface for LLMs)
  - `worker::bridge` (High-throughput REST API for bulk ingestion)
  - `warden::engine` (Aho-Corasick + Heuristic + Hybrid AI scrubbing)
  - `worker::audit` (Tamper-evident cryptographic ledger)
- **Framework:** `pytest` (Python 3.14+) with concurrent load generators (`concurrent.futures`).

## 3. Test Suites & Procedures

### Suite 1: Protocol & Functional Validation (`test_mcp.py`, `test_generalized.py`)
**Procedure:** Inject structured and unstructured data streams to verify PII detection.
- **TC-FUNC-01 (Initialization):** Verify JSON-RPC 2.0 handshake and capability broadcast.
- **TC-FUNC-02 (Sanitization):** Inject PII (Emails, SSNs) and verify deterministic token replacement (`[TOKEN_1]`).
- **TC-FUNC-03 (Restoration):** Submit tokens in an LLM response; verify exact rehydration of original PII.
- **TC-FUNC-04 (Multi-Line & Nested):** Verify PII embedded in JSON payloads and multi-line strings is caught without breaking syntax.
- **TC-FUNC-05 (Hot-Reloading):** Dynamically alter `rules.yaml` while the server runs; assert new rules apply within 5 seconds without restarting the gateway.

### Suite 2: Security & Adversarial Attacks (`test_security.py`, `test_adversarial.py`)
**Procedure:** Emulate threat actors attempting to bypass the scrubbing engine or breach isolation.
- **TC-SEC-01 (Invisible Injection):** Inject Zero-Width Spaces (`\u200B`) inside sensitive names. *Expected: Stripped and redacted.*
- **TC-SEC-02 (Homoglyph Bypass):** Substitute Latin characters with Cyrillic/Greek lookalikes (e.g., Greek `Α`). *Expected: Normalized and redacted.*
- **TC-SEC-03 (Session Isolation):** User B attempts to restore User A's token ID. *Expected: Restoration fails; Zero cross-tenant leakage.*
- **TC-SEC-04 (JWT Spoofing):** Submit REST requests with invalid or improperly signed JWTs. *Expected: 401 Unauthorized.*
- **TC-SEC-05 (Payload Overflow):** Submit a 2MB request payload. *Expected: 413 Payload Too Large (Buffer limit protection).*

### Suite 3: Resilience & Fault Injection (`test_fault_injection.py`)
**Procedure:** Sabotage the underlying host environment to ensure safe-failure modes.
- **TC-RES-01 (DB Read-Only):** Make `audit.db` read-only via OS permissions. *Expected: Service degradation, critical logging.*
- **TC-RES-02 (DB Lock Contention):** Hold an exclusive OS lock on the SQLite file. *Expected: 500 Internal Server Error (Fail-Closed to prevent unaudited data processing).*
- **TC-RES-03 (State Corruption):** Inject malformed JSON directly into the persistent session store. *Expected: Graceful error parsing, no panic/crash.*

### Suite 4: High-Concurrency Scaling (`test_scaling.py`)
**Procedure:** Flood the REST API to measure throughput, latency, and rate-limiting limits.
- **TC-SCALE-01 (Sustained Burst):** 50 concurrent users firing 10 requests each. *Expected: Peak >400 RPS, Latency <50ms.*
- **TC-SCALE-02 (Heavy Scrubbing):** Submit a 3.5KB payload containing 200+ PII hits. *Expected: Processing <100ms.*
- **TC-SCALE-03 (Rate Limit Enforcement):** Exceed the 100-request burst / 25 RPS sustained limit. *Expected: 429 Too Many Requests.*

### Suite 5: Greek Market Localization (`test_localization_gr.py`)
**Procedure:** Verify localized regex and heuristics for the Hellenic market.
- **TC-LOC-01 (AFM):** 9-digit Tax ID detection.
- **TC-LOC-02 (AMKA):** 11-digit Social Security Number boundary checking.
- **TC-LOC-03 (Name Heuristics):** Verify detection of Greek surnames (e.g., Παπαδόπουλος) using AI fallback.

## 4. Verification Requirements
- All 29 tests must execute successfully in a CI/CD environment using **Ephemeral Mode** (Mock DB/Redis).
- Any failing tests must be documented as "Known Limitations" in the V1.1 Release Notes.
