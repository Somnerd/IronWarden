# Phase 9: Security & Isolation Validation Plan

This document outlines the test suites required to validate the Phase 9 "Sovereign Hardening" refactor. These tests must be implemented and pass before the system is considered production-ready.

## 1. Multi-Tenant Isolation (The "Chinese Wall" Test)
**Goal**: Verify that PII tokens and session state are strictly isolated between users.

### [Test] Cross-User Token Collision
- **Scenario**: 
    1. User `Alice` sends: "My secret is PASSWORD123". 
    2. User `Bob` sends: "My secret is PASSWORD123".
- **Expectation**: 
    - Both users may receive `[TOKEN_1]`, but their internal `SessionContext` maps must be independent.
    - `Context_Alice` must NOT contain any metadata or references to `Bob`'s request.
    - Modifying `Context_Alice` must have zero effect on `Context_Bob`.

### [Test] Session Leakage Probe
- **Scenario**: 
    1. User `Alice` sends a prompt. 
    2. User `Bob` attempts to use `[TOKEN_1]` in a restoration request.
- **Expectation**: 
    - The system must fail to restore the token for `Bob` because `[TOKEN_1]` does not exist in `Bob`'s isolated context.

## 2. IDOR Attack Prevention (The "Identity" Test)
**Goal**: Ensure that result-fetching and session-management are protected against identity spoofing.

### [Test] Unauthorized Result Fetch
- **Scenario**: 
    1. `Alice` enqueues a SearchBoost job and receives `JOB_ID_A`.
    2. `Bob` attempts to GET `/results/JOB_ID_A?username=Bob`.
- **Expectation**: 
    - `403 Forbidden` or `404 Not Found`. The system must verify that the requester is the owner of the job.

### [Test] Username Spoofing
- **Scenario**: 
    1. `Bob` attempts to GET `/results/JOB_ID_A?username=Alice`.
- **Expectation**: 
    - `401 Unauthorized`. (Requires future JWT integration, but for now, must fail if no valid session exists for Alice on the current connection).

## 3. Atomic Token Consistency (The "Race" Test)
**Goal**: Eliminate the token-bloat race condition identified in the Phase 8 audit.

### [Test] High-Concurrency Duplicate PII
- **Scenario**: 
    - Send 100 concurrent requests to the *same* session containing the string "SovereignAI".
- **Expectation**: 
    - The `SessionContext` for that user must contain exactly **ONE** token mapping for "sovereignai".
    - `next_id` should have incremented exactly once for that string.

## 4. Resource Pressure (The "Hardening" Test)
**Goal**: Ensure memory and CPU stability during peak loads.

### [Test] Large Payload OOM Probe
- **Scenario**: 
    - Send a 5MB prompt with dense PII patterns.
- **Expectation**: 
    - Memory usage must remain stable. `OffsetMap` must not cause a linear memory explosion (targeting <10x overhead).

---
**Status**: DRAFT - Ready for Implementation by GemCLI. 🛡️🛰️
