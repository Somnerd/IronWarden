# 🏰 IronWarden V1.3 Test Stabilization Plan

This document outlines the testing gaps identified across the codebase and specifies the implementation plans for both unit and integration tests.

---

## 🎯 1. Phase 2: Safe ONNX Mutex Concurrency
* **Crate:** `iw-warden`
* **File:** [warden/src/ai.rs](file:///Users/nikolasalexandrakis/Documents/IronWarden/warden/src/ai.rs)
* **Objective:** Verify that wrapping the ONNX session inside a `Mutex` prevents data corruption, data races, and deadlocks under concurrent multi-threaded inference.

### 📋 Implementation Plan (Jules)
* Create `integration_tests/tests/warden/onnx_concurrency.rs`.
* Spawn 10 parallel threads, each feeding distinct sentences to the `WardenEngine::classify_ner` concurrently.
* Assert that:
  1. No deadlocks occur.
  2. All classifications return the correct respective redacted labels.
  3. No threads panic due to poison locks or internal cell mutability violations.

---

## 🎯 2. Phase 3: FIFO SQLite Queue Writer & Graceful Shutdown
* **Crate:** `iw-worker`
* **File:** [worker/src/searchboost.rs](file:///Users/nikolasalexandrakis/Documents/IronWarden/worker/src/searchboost.rs)
* **Objective:** Ensure sequential execution consistency of DB commands (Insert ➔ Update) and verify zero-loss graceful shutdown flushes.

### 📋 Implementation Plan (Jules)
* Create `integration_tests/tests/worker/searchboost_fifo_shutdown.rs`.
* **Test Case 1 (FIFO Consistency):** Enqueue 50 sequential jobs with immediate results update. Spin up multiple concurrent workers and ensure that every job successfully transitions to `status = 'complete'` without any SQL sequence issues.
* **Test Case 2 (Graceful Flush):** Enqueue 100 jobs in the background SQLite queue, then immediately execute `queue.shutdown().await`. Assert that:
  1. The flume channel length drops to 0.
  2. The SQLite database contains exactly 100 completed/inserted jobs (proving zero log losses).

---

## 🎯 3. Phase 4: Thread-Local Normalization Buffer Isolation
* **Crate:** `iw-warden`
* **File:** [warden/src/engine.rs](file:///Users/nikolasalexandrakis/Documents/IronWarden/warden/src/engine.rs)
* **Objective:** Verify that `thread_local!` string buffers isolate states correctly between threads and do not corrupt data when reusing capacity.

### 📋 Implementation Plan (Jules)
* Create `integration_tests/tests/warden/thread_local_normalization.rs`.
* **Test Case 1 (Isolation):** Spin up Thread A and Thread B. Pass a very large string to Thread A and a small string to Thread B simultaneously. Verify that Thread B's output is not contaminated by Thread A's data.
* **Test Case 2 (Capacity Reuse):** Call the normalizer on the same thread sequentially with:
  1. A very long string.
  2. A tiny string.
  3. A string containing special Unicode characters.
  Verify that the buffer does not truncate or leak remnants of the long string into the subsequent short strings.

---

## 🎯 4. Configuration Prioritization & Strict Cryptographical Keys
* **Crate:** `iw-warden`
* **File:** [warden/src/configurator.rs](file:///Users/nikolasalexandrakis/Documents/IronWarden/warden/src/configurator.rs)
* **Objective:** Test that env variables take priority over files, and that weak/short keys cause the application to fail-closed during startup.

### 📋 Implementation Plan (Jules)
* Create `integration_tests/tests/warden/configurator_rules.rs`.
* **Test Case 1 (Priorities):** Set `PORT` via env, set a different port in config YAML. Assert that the parsed config uses the env port.
* **Test Case 2 (Strict Keys):** Attempt to initialize `GlobalConfig` with a pepper key shorter than 32 bytes. Assert that the configuration engine throws a validation error and refuses to load.

---

## 🎯 5. OCR Pipeline Fallbacks & Fail-Closed Guardrails
* **Crate:** `iw-worker`
* **File:** [worker/src/ocr.rs](file:///Users/nikolasalexandrakis/Documents/IronWarden/worker/src/ocr.rs)
* **Objective:** Verify mock OCR fallbacks in development mode, fail-closed safety in production mode when dependencies are missing, and actual Greek/English parsing when Tesseract is available.

### 📋 Implementation Plan (Jules)
* Create `integration_tests/tests/worker/ocr_pipeline.rs`.
* **Test Case 1 (Dev Fallback):** Unset `IRONWARDEN_ENV` and `RUST_ENV`. Mock a missing `tesseract` binary call. Assert that the provider returns the `[MOCK OCR]` prefix fallback.
* **Test Case 2 (Production Fail-Closed):** Set `IRONWARDEN_ENV=production`. Mock a missing `tesseract` binary. Assert that the provider returns a hard `SovereignError::InternalError` stating the dependency is missing.

---

## 🎯 6. Bridge API Rate Limiting & Concurrency Semaphore
* **Crate:** `iw-worker`
* **File:** [worker/src/bridge.rs](file:///Users/nikolasalexandrakis/Documents/IronWarden/worker/src/bridge.rs)
* **Objective:** Stress test the Axum bridge to verify that rate limiting (Governor layer) and the global concurrency semaphore drop excess requests with expected status codes.

### 📋 Implementation Plan (Jules)
* Create `integration_tests/tests/worker/bridge_limits.rs`.
* **Test Case 1 (Concurrency Semaphore):** Set the concurrency semaphore limit to 2. Send 10 concurrent requests and verify that the bridge returns `429 Too Many Requests` (or drops requests) when limits are exceeded.
* **Test Case 2 (Rate Limiter):** Send high-frequency requests exceeding the burst size (100) or per-second limits. Verify that the client receives rate-limiting headers and `429 Too Many Requests`.
