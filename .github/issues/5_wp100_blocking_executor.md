# Title: [REFACTOR] Standardize spawn_blocking via BlockingExecutor (WP-100)

## Category: Code Health / Concurrency Refactoring

## Description
Heavy CPU-bound and synchronous blocking operations (ONNX model inference, cryptographic key derivation, local disk writes) are currently called using ad-hoc `tokio::task::block_in_place` or verbose `tokio::task::spawn_blocking` statements spread throughout the codebase. This increases boilerplate code and makes error and panic handling inconsistent.

We need to implement a centralized `BlockingExecutor` wrapper inside `core/src/executor.rs` to standardize task execution.

## Technical Specifications
1.  **Create BlockingExecutor:** Implement a generic wrapper in `core` that exposes:
    ```rust
    pub async fn run_blocking<F, R, E>(f: F) -> Result<R, SovereignError>
    where
        F: FnOnce() -> Result<R, E> + Send + 'static,
        R: Send + 'static,
        E: std::error::Error + 'static;
    ```
2.  **Panic Safety:** Wrap the thread task to catch panics gracefully and map them to `SovereignError::ExecutionError`.
3.  **Refactor Occurrences:** Migrate all LibTorch/ONNX inference pools and cryptographic hash computations to run through the new executor.
