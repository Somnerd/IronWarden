## 2024-06-10 - `any` over loop for has_before/has_after
**Learning:** Found an opportunity to replace `while let Some(c) = chars.next()` loops with `any` for `has_before` and `has_after` checking. `any` provides early returns naturally.
**Action:** Replace `while let` with iterators for performance gains.

## 2024-11-23 - Async Cryptography Bottlenecks
**Learning:** CPU-bound cryptographic operations, particularly `AadCipher::encrypt` and `AadCipher::decrypt`, will block the Tokio event loop if executed directly within async functions, leading to executor starvation and latency spikes.
**Action:** Always offload these operations by wrapping them in `tokio::task::spawn_blocking`.
