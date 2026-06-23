## 2024-06-10 - `any` over loop for has_before/has_after
**Learning:** Found an opportunity to replace `while let Some(c) = chars.next()` loops with `any` for `has_before` and `has_after` checking. `any` provides early returns naturally.
**Action:** Replace `while let` with iterators for performance gains.
## 2024-06-11 - `starts_with` and `ends_with` over `chars().next()` and `chars().last()`
**Learning:** Found an opportunity to replace `text.chars().last().map_or(...)` and `text.chars().next().map_or(...)` with `text.ends_with(...)` and `text.starts_with(...)` for performance gains. `ends_with` and `starts_with` are much faster because they operate on bytes/slices rather than creating a full character iterator.
**Action:** Replace `chars().last()` and `chars().next()` with `ends_with` and `starts_with` for boundary checks.

## 2024-11-23 - Async Cryptography Bottlenecks
**Learning:** CPU-bound cryptographic operations, particularly `AadCipher::encrypt` and `AadCipher::decrypt`, will block the Tokio event loop if executed directly within async functions, leading to executor starvation and latency spikes.
**Action:** Always offload these operations by wrapping them in `tokio::task::spawn_blocking`.
## 2024-06-15 - DoubleEndedIterator and slice bound limits
**Learning:** `chars().last()` is actually an O(1) operation because `Chars` implements `DoubleEndedIterator` which delegates to `.next_back()`. It does not iterate the full string. However, `.ends_with(char)` is still technically faster as it is a direct byte/pattern comparison instead of creating the iterator struct. Also, passing `[char; N]` to `ends_with` only stabilized in Rust 1.80.0; for wider compatibility, chained `ends_with(char) || ends_with(char)` is safer.
**Action:** When replacing `chars().last()` checks for simple punctuation or ASCII, use chained `ends_with` calls or character match closures, avoiding array patterns if compatibility with older compilers is required.

## 2026-06-16 - json! Macro Overhead in High-Throughput Paths
**Learning:** Using the `json!` macro for payload construction in hot paths (like `route_prompt`) introduces performance overhead by creating intermediate DOM tree allocations (`serde_json::Value`).
**Action:** Achieve zero-copy serialization by defining strictly typed structs with borrowed lifetimes (e.g., `#[derive(Serialize)] struct Payload<'a>`) and serializing them directly.
## 2024-11-23 - json! Macro Overhead in High-Throughput Paths
**Learning:** Using the `json!` macro for payload construction in hot paths introduces performance overhead by creating intermediate DOM tree allocations (`serde_json::Value`).
**Action:** Achieve zero-copy serialization by defining strictly typed structs with borrowed lifetimes (e.g., `#[derive(Serialize)] struct Payload<'a>`) and serializing them directly.
## 2024-11-23 - json! Macro Overhead in High-Throughput Paths
**Learning:** Using the `json!` macro for payload construction in hot paths introduces performance overhead by creating intermediate DOM tree allocations (`serde_json::Value`). This applies even to HTTP response serialization and formatting.
**Action:** Achieve zero-copy serialization by defining strictly typed structs with borrowed lifetimes (e.g., `#[derive(Serialize)] struct Payload<'a>`) and serializing them directly.
