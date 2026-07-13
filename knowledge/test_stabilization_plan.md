# 🏰 IronWarden V1.3 Test Stabilization Plan

This document outlines the testing gaps identified across the codebase and specifies the implementation plans for both unit and integration tests, prioritizing Critical Security Invariant (Code Red) gaps.

---

## 🚨 PART 1: Critical Security Gaps (V-Series Invariants)

These are Code Red gaps that threaten the security invariants from the GEMINI.md mandate and must be written immediately.

### 🎯 1. Isolation via AAD (V-19) - Cipher & GroundingShield
* **Crate:** `iw-core`, `iw-warden`
* **Files:** `core/src/crypto.rs`, `warden/src/engine.rs`
* **Objective:** Ensure AAD mismatch fails decryption and Job/Session swapping is impossible.
* **Implementation Plan (Jules):**
  * `core/crypto.rs`: Unit tests for `AadCipher::encrypt/decrypt`. Test roundtrip, wrong-key rejection, wrong AAD rejection (V-19), tampered ciphertext, empty payload.
  * `warden/engine.rs`: Test `GroundingShield::seal_query` and `unseal_query` round-trip. Test that unseal with a wrong username fails due to AAD mismatch.

### 🎯 2. Overlap Integrity (V-12) - PII Restoration
* **Crate:** `iw-warden`
* **File:** `warden/src/engine.rs`
* **Objective:** Validate that the inverse operation of `sanitize_prompt` (`restore_prompt`) never leaks raw PII to the user.
* **Implementation Plan (Jules):**
  * Test `PiiShield::restore_prompt` round-trip: sanitize → restore original. Test with empty map and overlapping token strings.

### 🎯 3. Leak-Proof Routing (V-14) - Prompt Injection Guardrails
* **Crate:** `iw-warden`, `iw-worker`
* **Files:** `warden/src/engine.rs`, `worker/src/bridge.rs`
* **Objective:** Ensure Layer 1/1.5/2 guardrails prevent raw queries from reaching the LLM and audit failures abort requests.
* **Implementation Plan (Jules):**
  * `warden/engine.rs`: Unit tests for `INJECTION_BLOCKLIST` (test "ignore previous instructions", mixed case) triggering `UnauthorizedAccess`.
  * `warden/engine.rs`: Unit test for `check_shannon_entropy_smuggling` (base64 payload >40 chars & entropy >5.8 triggering block).
  * `warden/engine.rs`: Unit test for `check_ml_sidecar` fallback.
  * `worker/bridge.rs`: Integration test verifying that an audit log failure aborts the request (circuit breaker).

### 🎯 4. Strict Mode Configurations (V-Series)
* **Crate:** `iw-warden`, `iw-core`
* **Files:** `warden/src/configurator.rs`, `core/src/crypto.rs`
* **Objective:** Prevent weak encryption keys and unauthorized access.
* **Implementation Plan (Jules):**
  * `warden/configurator.rs`: Test `GlobalConfig::resolve()` strict mode: missing config.yaml rejection, pepper <32 bytes rejection (Critical), missing manifest path.
  * `core/crypto.rs`: Unit tests for `JwtVerifier::verify`. Test valid token, expired token, wrong audience, wrong issuer, invalid PEM, tampered signature.

### 🎯 5. GDPR Purge Pipeline (Hard Requirement)
* **Crate:** `iw-core`, `iw-worker`
* **Files:** `core/src/traits.rs`, `worker/src/audit.rs`, `worker/src/storage.rs`
* **Objective:** Verify all user data across all tables and systems is deleted.
* **Implementation Plan (Jules):**
  * `worker/audit.rs`: Test `purge_user` handler deletes from `audit_reports` and `ephemeral_raw_logs`.
  * `worker/storage.rs`: Test `purge_user_data` full pipeline across audit, librarian, sessions, threads, jobs.

### 🎯 6. Cross-User Data Isolation (V-19)
* **Crate:** `iw-worker`
* **Files:** `worker/src/searchboost.rs`, `worker/src/librarian.rs`
* **Objective:** Ensure users cannot access other users' jobs or documents.
* **Implementation Plan (Jules):**
  * `worker/searchboost.rs`: Test `get_result()` access denial. Enqueue as user A, request as user B, verify `UnauthorizedAccess`.
  * `worker/librarian.rs`: Test cross-user document isolation. Add docs for user A, query as user B, verify empty results.

### 🎯 7. OCR Fail-Closed Safety
* **Crate:** `iw-worker`
* **File:** `worker/src/ocr.rs`
* **Objective:** Verify OCR module fails closed in production without Tesseract.
* **Implementation Plan (Jules):**
  * `worker/ocr.rs`: Test `IRONWARDEN_ENV=production` missing binary triggers `SovereignError::InternalError`. Test Dev fallback mode.

---

## 🏗️ PART 2: System Architecture & Stabilization (High Priority)

### 🎯 8. SearchBoost FIFO, Shutdown, & Redis HA
* **Crate:** `iw-worker`
* **File:** `worker/src/searchboost.rs`
* **Implementation Plan (Jules):**
  * Test graceful flush: Enqueue 100 jobs, call `shutdown().await`, verify flume channel is empty and DB has 100 jobs.
  * (Optional) Test Redis HA paths for enqueue, process, and session management if a mock is available.

### 🎯 9. Thread-Local Normalization & Concurrent ONNX
* **Crate:** `iw-warden`
* **Files:** `warden/src/engine.rs`, `warden/src/ai.rs`
* **Implementation Plan (Jules):**
  * `engine.rs`: Verify `thread_local!` string buffers isolate states and reuse capacity correctly without data corruption.
  * `ai.rs`: Verify ONNX Mutex prevents deadlocks and panics under concurrent multi-threaded inference.

---

## 🚀 PART 3: CI/CD Pipeline Restructuring

### 🎯 10. Parallel Split for CI/CD Workflow
* **File:** `.github/workflows/rust_ci.yml`
* **Objective:** Split the monolithic CI job into parallel, fast-failing jobs to improve developer velocity.
* **Implementation Plan (Jules):**
  * Break current monolithic job into 4 parallel jobs:
    1. **`lint`**: `cargo fmt --check` + `cargo clippy` + auto-format commit (~2 min)
    2. **`unit-tests`**: `cargo test --workspace --lib --bins` (crate-level unit tests) (~5 min)
    3. **`integration-tests`**: `cargo test -p iw-integration-tests` + `pytest test_suites/` (Depends on `lint`) (~8 min)
    4. **`benchmarks`**: `cargo bench --workspace` (Run actual Criterion benchmarks for perf regression tracking) (~3 min)
