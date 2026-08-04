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

## 2026-06-21 - [DoS Vulnerability via Brittle Hard-Stops]
**Vulnerability:** The worker storage initialized a disk space monitoring thread that deliberately called `std::process::exit(1)` when disk space dropped below 10%, ostensibly to preserve "Zero-Failure compliance." This created a Denial of Service (DoS) vulnerability under resource exhaustion conditions.
**Learning:** Brittle hard-stops on resource thresholds (like disk space) allow an attacker or normal workload to completely halt the system by filling up the disk. Resilience is preferred over crashing.
**Prevention:** Instead of crashing, gracefully degrade functionality or proactively mitigate resource exhaustion (e.g., purging old transient logs like `ephemeral_raw_logs`) when approaching critical thresholds.
