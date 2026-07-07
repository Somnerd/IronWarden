# Remediation Plan for V1.3 Differential Security Audit

This plan outlines the steps to resolve the critical vulnerabilities identified in the IronWarden V1.3 Security Audit, ensuring the system remains fail-closed and robust under adversarial attack.

## User Review Required
> [!IMPORTANT]
> **Architectural Change (Finding 3)**: Isolating the LibTorch/ONNX AI engine into a separate sidecar process is a significant architectural pivot. This will require establishing an IPC mechanism (e.g., local Unix Domain Sockets or HTTP/gRPC) and introducing a new binary or spawn model for the worker. I recommend we start by separating it logically and communicating over a lightweight local HTTP server, or keeping it as a spawned thread but using cross-process boundaries if possible. Please review the proposed approach below.

## Open Questions
> [!WARNING]
> 1. **Prompt Injection Guardrails (Finding 4)**: Do you have a preferred ONNX model (e.g., a quantized Llama Guard or similar) to use for prompt injection classification? If not, I can implement a heuristic/regex-based stub for now and lay the groundwork for an ONNX model.
> 2. **AI Sidecar (Finding 3)**: Would you prefer the sidecar to communicate via local HTTP API, gRPC, or direct UDS (Unix Domain Sockets)? I will default to a local HTTP microservice within the workspace for simplicity unless specified.

## Proposed Changes

---

### Security / Cryptography Layer

#### [MODIFY] [audit.rs](file:///home/somnerd/Projects/IronWarden/worker/src/audit.rs)
- Remove `Aes256Gcm` instance from the `AsyncAuditor` state and closure.
- Derive the encryption key locally inside the thread loop right before `aes_gcm::Aes256Gcm::new(...)` using the stored `pepper`, perform the encryption, and rely on standard Rust drop/zeroize to clear the stack (Finding 1).

#### [MODIFY] [searchboost.rs](file:///home/somnerd/Projects/IronWarden/worker/src/searchboost.rs)
- Remove `cipher: Aes256Gcm` from `SearchBoostQueue` and `LocalSessionManager`.
- Store the `pepper` (wrapped in `SecretVec`) within the structs instead.
- Refactor the encryption and decryption blocks to instantiate `Aes256Gcm` dynamically using HKDF, execute the operation, and drop the key buffers to ensure true transient key usage (Finding 1).

---

### Storage / Grounding Layer

#### [MODIFY] [librarian.rs](file:///home/somnerd/Projects/IronWarden/worker/src/librarian.rs)
- Update `delete_user_documents` to sanitize the `username` string before inserting it into the LanceDB predicate.
- Replace single quotes (`'`) with double single quotes (`''`) to neutralize SQL injection attempts that could bypass the right-to-erasure filters (Finding 2).

#### [MODIFY] [storage.rs](file:///home/somnerd/Projects/IronWarden/worker/src/storage.rs)
- Implement a disk space monitoring thread in `WorkerStorage::new()`.
- Use `std::fs::metadata` or a lightweight `statvfs` wrapper to check the available space on the partition hosting `audit.db`.
- Trigger automatic cleanup of the `ephemeral_raw_logs` table and log `WARN` messages if disk space drops below a 10% threshold to prevent `DatabaseFull` hard-stops (Finding 5).

---

### AI Inference / Pipeline Layer

#### [MODIFY] [ai.rs](file:///home/somnerd/Projects/IronWarden/warden/src/ai.rs)
- Isolate the `HybridNer` logic.
- We will refactor `HybridNerPool` to proxy requests to an external local microservice/sidecar instead of running `rust-bert` directly in the main thread. This prevents C++ LibTorch crashes from bringing down the gateway (Finding 3).

#### [MODIFY] [engine.rs](file:///home/somnerd/Projects/IronWarden/warden/src/engine.rs)
- Introduce a new Pre-Flight check in `sanitize_prompt`.
- Add a lightweight heuristic-based prompt injection detection mechanism (or hook it to the new AI sidecar) to reject commands like "System Override" or "Ignore previous instructions" (Finding 4).

## Verification Plan

### Automated Tests
- `cargo test` across all crates to ensure no regressions in existing PII identification or session handling.
- Add a test in `librarian_scrub_test.rs` to verify that injecting `' OR '1'='1` does not delete other users' documents.
- Add a test in `searchboost.rs` tests to verify that keys are derived accurately on the fly and decryptions succeed with the transient method.

### Manual Verification
- Review the `ironwarden_security_audit_v1.3.md` artifact to confirm findings align with the remediation strategy.
