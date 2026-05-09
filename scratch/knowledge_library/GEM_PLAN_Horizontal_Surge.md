# GEM_PLAN: Phase 12 - Horizontal Surge Hardening

**Objective:** Transform IronWarden from a stateful "pet" into a resilient, scalable security relay by optimizing I/O handles and hardening background workers.

---

## 1. Performance: LanceDB Table Caching (`worker/src/storage.rs`)
- **Action:** Add `documents_table: Option<lancedb::Table>` to `WorkerStorage`.
- **Optimization:** Open the "documents" table once during `new()` and reuse the handle in `fetch_context`. This removes O(Disk I/O) table-opening overhead from every request path.
- **Improvement:** Implement a basic vector search using the query string instead of a blind `limit(5)`.

## 2. Stability: Resilient Auditor (`worker/src/audit.rs`)
- **Action:** Purge all `.expect()` and `.unwrap()` calls in the background writer thread.
- **Resilience:** Implement a retry loop for SQLite connection and schema initialization.
- **Optimization:** Cache the `last_hash` in a local variable within the worker loop to eliminate redundant database reads before every write.
- **Safety:** Ensure the worker thread continues to consume the `mpsc` channel even during transient database failures to prevent head-of-line blocking on the primary request pipeline.

## 3. Configurability: Externalized Networking (`app/src/main.rs`)
- **Action:** Replace hardcoded `0.0.0.0:14141` with `BRIDGE_BIND_ADDR` and `BRIDGE_PORT` environment variables.

---
**Status:** IN_PROGRESS
**Owner:** GeminiCLI
**Subagents:** executor (Implementation), security-reviewer (Final Verification)
