## 2025-06-16 - [Secure Deletion in SQLite]
**Vulnerability:** The application was using `DELETE FROM` to remove sensitive user data and raw PII logs without securely erasing the deleted content, potentially leaving data physically intact on disk.
**Learning:** In SQLite, `DELETE` only marks space as free. Using `VACUUM` after every deletion causes severe performance issues and database locks. The performant standard is setting `PRAGMA secure_delete = ON;`, which overwrites deleted content with zeros immediately.
**Prevention:** Enable `PRAGMA secure_delete = ON;` on database connections to ensure physical destruction of deleted data from the filesystem, complying with GDPR/Sovereign standards.
## 2024-05-18 - [Missing RBAC on API endpoints]
**Vulnerability:** RBAC (Role-Based Access Control) was missing on `results` endpoint. Any user with a valid JWT token was authorized.
**Learning:** Some API endpoints may not perform enough security checks on their own, allowing any user with any JWT role to succeed.
**Prevention:** Check roles on all API endpoints individually.
## 2026-06-16 - JSON Injection in IPC Payload
**Vulnerability:** The Layer 2 ML Guardrail payload in `check_ml_sidecar` used manual string formatting (`format!(r#"{{"prompt":"{}"}}"#)`), making it vulnerable to JSON injection.
**Learning:** Manual escaping of user input for serialization often misses edge cases. String interpolation should never be used for JSON construction.
**Prevention:** Rely on established serialization libraries like `serde_json` (`serde_json::json!`) to safely handle escaping and formatting.

## 2026-06-17 - Insecure Data Deletion in SQLite
**Vulnerability:** SQLite `DELETE FROM` statements only mark rows as free space without wiping the underlying disk data, allowing recovery of sensitive data like deleted audit logs and sessions from the `.db` or `.db-wal` files. Using `VACUUM` to wipe data causes severe performance degradation.
**Learning:** For privacy compliance and secure data deletion, overwriting the disk is necessary, but full-table rebuilds (`VACUUM`) are too slow for high-throughput gateways. `PRAGMA secure_delete = ON;` provides immediate, localized zeroing of deleted content without full-table locks.
**Prevention:** Always initialize SQLite connections handling sensitive data with `PRAGMA secure_delete = ON;` to ensure physical disk wipe of deleted rows.

## 2026-06-22 - [Critical] Undefined Behavior via `unsafe impl Sync` on UnsafeCell
**Vulnerability:** The `OnnxNer` struct in `warden/src/ai.rs` wraps `ort::Session` in an `UnsafeCell` (necessary to bypass `&mut self` requirements in `Session::run()`), but explicitly implemented `unsafe impl Sync`. If an instance was ever shared across threads (e.g., via `Arc<OnnxNer>`), multiple threads could simultaneously mutate the inner session via `&self` -> `UnsafeCell::get()`, causing mutable aliasing and Undefined Behavior (data races).
**Learning:** Never implement `Sync` on types containing `UnsafeCell` if the inner data is accessed mutably through shared (`&`) references without interior mutability primitives (like `Mutex` or `RwLock`).
**Prevention:** Removed `unsafe impl Sync` from `OnnxNer`. In our architecture (`HybridNerPool`), instances are passed by value over bounded channels to achieve exclusive access, so `Send` is sufficient and safe, but `Sync` is unnecessary and fundamentally unsound.
