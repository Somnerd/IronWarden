# 📋 Reconstructed Work Packages: Phase 3 Stabilization

This document reconstructs the detailed requirements and technical specifications for the pending Phase 3 stabilization tasks (`WP-99` through `WP-102`) that were previously stored on the lost OpenProject dashboard.

---

## 💾 WP-99: [SQLite Silo] Unified Connection Pooling (SqlitePool)
*   **Priority:** High
*   **Target Files:** `worker/src/storage.rs`, `worker/src/audit.rs`, `worker/src/searchboost.rs`
*   **The Problem:**
    Currently, separate database connections are opened individually across the storage manager, the audit logging worker, and SearchBoost queue, leading to connection overhead and SQLite lock starvation.
*   **Requirements:**
    1.  **Introduce Connection Pool:** Integrate `r2d2` with `r2d2_sqlite` (or `sqlx` if migrated) in `core` or `worker`.
    2.  **Shared Pool Instance:** Initialize a single `Pool<SqliteConnectionManager>` at startup in `app/src/main.rs`.
    3.  **Thread-Safe Sharing:** Share the pool across all storage, search, and audit workers using thread-safe reference counting (`Arc<SqlitePool>`).
    4.  **Database Performance Tuning:** Ensure all pooled connections automatically execute:
        *   `PRAGMA journal_mode = WAL;` (Write-Ahead Logging to allow concurrent reads and writes).
        *   `PRAGMA synchronous = NORMAL;`
        *   `PRAGMA busy_timeout = 5000;` (Replaces local ad-hoc timeouts).

---

## ⚡ WP-100: [Boilerplate] Standardized Blocking Executor
*   **Priority:** Medium
*   **Target Files:** `core/src/executor.rs` (New), `warden/src/ai.rs`, `worker/src/audit.rs`
*   **The Problem:**
    Heavy blocking operations (ONNX model inference, cryptographic key derivation, local disk I/O) are called using ad-hoc `tokio::task::block_in_place` or verbose `tokio::task::spawn_blocking` statements spread throughout the codebase, making code maintenance and testing difficult.
*   **Requirements:**
    1.  **Implement BlockingExecutor:** Create a standardized wrapper in `core` that exposes:
        ```rust
        pub async fn run_blocking<F, R, E>(f: F) -> Result<R, SovereignError>
        where
            F: FnOnce() -> Result<R, E> + Send + 'static,
            R: Send + 'static,
            E: std::error::Error + 'static;
        ```
    2.  **Panic Handling:** Wrap the task execution to catch thread panics inside the blocking thread pool and map them gracefully to `SovereignError::ExecutionError`.
    3.  **Refactor Occurrences:** Migrate all LibTorch/ONNX inference pools and cryptographic hash computations to run through the new `BlockingExecutor`.

---

## ⚙️ WP-101: [Config/Errors] Unified Configurator & Error Mapping
*   **Priority:** Medium (Staged next)
*   **Target Files:** `warden/src/configurator.rs` (New), `warden/src/config.rs`, `app/src/main.rs`
*   **The Problem:**
    Config files are parsed in different places, rules directory scans have crash-on-boot risks, and folder/file paths are hardcoded.
*   **Requirements:**
    1.  **Design GlobalConfig:** Resolve configurations from environment variables, `config/config.yaml`, or defaults.
    2.  **Enforce Strict Mode by Default:** The gateway must abort boot (`exit(1)`) if config folders/files are missing, unless `allow_fallback` is explicitly enabled.
    3.  **Directory Renaming:** Rename the default rules folder from `config/regions/` to `config/rules/`.
    4.  **Standardize Errors:** Convert parsing failures into clear `SovereignError::ConfigError` variants with line and file details.

---

## 🔑 WP-102: [JWT] Reusable JWT Verification Component
*   **Priority:** Medium
*   **Target Files:** `core/src/auth.rs` (New), `worker/src/bridge.rs`, `app/src/main.rs`
*   **The Problem:**
    JWT authentication validation, signature checking, and claims extractions are hardcoded directly into HTTP endpoints, leading to code duplication and potential validation gaps.
*   **Requirements:**
    1.  **Implement JwtVerifier:** Create a reusable component using the `jsonwebtoken` or `jwt` crate:
        ```rust
        pub struct JwtVerifier {
            decoding_key: jsonwebtoken::DecodingKey,
            validation: jsonwebtoken::Validation,
        }
        ```
    2.  **Standardized Verification:** Expose a method to validate tokens and extract the `username` (from `sub` claim) bound by security policy.
    3.  **Bridge Integration:** Replace the ad-hoc validation blocks in the bridge server routes with the new verifier middleware.
