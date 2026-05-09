# GEM_PLAN: Phase 12 - Final Hardening & Distributed Resilience

**Objective:** Finalize the "Horizontal Surge" by hardening the startup sequence and unifying the distributed session persistence.

## 1. Resilient Startup (`app/src/main.rs`)
- **Problem:** Multiple `.expect()` calls on database and Redis connections can cause unnecessary CrashLoopBackOffs in containerized environments.
- **Action:** Replace `.expect()` with a retry loop (using `tokio_retry` or simple loop with sleep) for critical infra.
- **Goal:** Allow the relay to wait for its dependencies to become ready before giving up.

## 2. Distributed Session Unification
- **Problem:** Redis-backed session logic is currently embedded directly in `bridge.rs` handlers. The MCP server still uses a local `DashMap`, breaking horizontal scaling for stdio-based clients.
- **Action:** Move the Redis session persistence into a dedicated helper (e.g., `worker/src/sessions.rs`) or integrate it into `SearchBoostQueue`.
- **Goal:** Enable both MCP and HTTP Control Planes to share the same distributed state seamlessly.

## 3. Proper Graceful Shutdown
- **Action:** Refactor `main.rs` to use `axum::serve(...).with_graceful_shutdown(...)`.
- **Action:** Update `StdioMcpServer::run` to accept a shutdown signal.

---
**Status:** PROPOSED
**Owner:** GeminiCLI
