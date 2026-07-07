# Architecture Spec: 30-Day Automated Purge Task (IronWarden V1.0)

## 1. Objective
Ensure that all raw PII data (stored in `ephemeral_raw_logs`) is physically and logically destroyed after 30 days to comply with GDPR/Sovereign privacy standards. Maintain auditability by preserving the non-PII metadata and integrity hash-chains.

## 2. Targeted Components
- **Database:** `audit.db` (SQLite).
- **Worker:** `worker/src/audit.rs`.
- **In-Memory State:** Ensure no stale log buffers persist in RAM.

## 3. Technical Requirements

### 3.1 Dual-Stage Cleanup
- **Physical Destruction (Raw Logs):**
    - The task must target the `ephemeral_raw_logs` table.
    - Rows with `timestamp < (now - 30 days)` must be deleted.
    - **Physical Wipe:** After deletion, the worker should trigger an `incremental_vacuum` or `VACUUM` to ensure the data is removed from the filesystem, not just marked as free in the DB.

- **Logical Preservation (Audit Ledger):**
    - The `audit_reports` table **must not** be deleted. Deleting rows would break the HMAC-SHA256 hash-chain continuity.
    - Instead, add a `purged` boolean column (or check the missing link to `ephemeral_raw_logs`) to indicate the raw data is no longer available.

### 3.2 Hash-Chain Continuity
- The `integrity_hash` of each record is built using the hash of the *previous* record. 
- Even when the raw data is purged, the `integrity_hash` in `audit_reports` remains valid as a "proof of history."
- The `Tamper-Check Tool` must be able to verify the chain even if `ephemeral_raw_logs` is empty.

### 3.3 Zeroization & RAM Safety
- During the encryption/decryption process, any temporary `Vec<u8>` or `String` containing raw PII must be zeroed out before being dropped.
- *Implementation Hint:* Use the `zeroize` crate for sensitive buffers.

### 3.4 Operational Constraints
- **Frequency:** The purge check should run every 24 hours (configurable).
- **Concurrency:** Use `tokio::spawn` to run the timer, but the actual SQL execution should occur on the dedicated writer thread in `worker/src/audit.rs` to avoid locking issues.
- **Logging:** Log the number of records purged and the resulting database file size.

## 4. Acceptance Criteria
1.  **Privacy:** After 30 days, `SELECT * FROM ephemeral_raw_logs` returns zero rows for that period.
2.  **Integrity:** The hash-chain in `audit_reports` remains 100% verifiable.
3.  **Performance:** The purge task does not block the main AI prompt/response loop.
4.  **Verification:** The `Tester` agent can prove the purge happened by artificially advancing the system clock in a simulated environment.
