# GEM_PLAN: Phase 10 - Production Hardening Validation

**Objective:** Conduct a comprehensive security and performance audit of the Phase 10 implementation to ensure zero-trust compliance and system stability.

## 1. Security Audit (security-reviewer)
- **JWT Integrity:** Verify HS256 key management and claim validation (sub, exp, iat). Ensure the `username` is no longer sourced from unverified query params.
- **HMAC Metadata Chain:** Audit `audit.rs` to ensure the extended metadata (id, timestamp, is_blocked) is correctly incorporated into the hash calculation.
- **IDOR Check:** Verify that the `claims.sub` from the JWT correctly isolates the `SessionContext`.

## 2. Performance Audit (performance-reviewer)
- **Session Eviction:** Analyze the background sweeper task for potential locking contention on the `sessions` DashMap. 
- **Resource Usage:** Check the memory overhead of the `last_accessed` timestamp in `SessionContext`.
- **Database Pooling:** Ensure `PgPool` configuration is optimal for the relay load.

## 3. Full Integration Validation (executor)
- Run `app/tests/hardened_integration.rs` and `worker/tests/searchboost_tests.rs`.
- Execute a manual JWT-based probe to verify cross-user isolation.

---
**Status:** IN_PROGRESS
**Assigned Subagents:** security-reviewer, performance-reviewer, executor
