# 🗺️ IronWarden V1.2: Remediation Master Plan
**Version:** 1.0 (Draft)
**Objective:** Transition IronWarden from a "Stable Prototype" to a "Certified Security Appliance."
**Priority:** High-Integrity Fixes over Feature Expansion.

---

## 🛑 Phase 1: Critical Security Hardening (Immediate)

### 1.1 The "Fail-Closed" Audit Mandate
*   **Problem:** `AsyncAuditor` spawns in the background. If initialization fails (e.g., read-only DB), the gateway continues to scrub and route PII without a forensic trail.
*   **Impact:** **CRITICAL COMPLIANCE BREACH.** Total loss of forensic accountability.
*   **Ideal Solution:** Implement a synchronous handshake during startup. `main.rs` must wait for a "READY" signal from the Auditor task before initializing the MCP or Bridge servers.
*   **Target:** `app/src/main.rs`, `worker/src/audit.rs`.

### 1.2 Enum-Based Policy Enforcement
*   **Problem:** The engine determines whether to "Block" a request based on whether the `rule_id` string contains the word "block".
*   **Impact:** **HIGH RISK.** Prone to administrative typos and developer errors.
*   **Ideal Solution:** Refactor the `RuleConfig` and `Redaction` structures to include an explicit `Action` field (e.g., `Redact`, `Block`, `Flag`). The `engine.rs` must switch on this enum, not a string match.
*   **Target:** `warden/src/config.rs`, `warden/src/engine.rs`, `core/src/traits.rs`.

---

## 🧱 Phase 2: Operational Resilience (Stability)

### 2.1 SQLite Deadlock Prevention
*   **Problem:** Lack of connection timeouts/retries in `rusqlite` causing the gateway to hang indefinitely if an OS-level lock is held on `audit.db`.
*   **Impact:** **HIGH RISK (DoS).** Single point of failure that freezes the gateway.
*   **Ideal Solution:** 
    1. Implement `busy_timeout` on all SQLite connections.
    2. Use a dedicated `blocking` pool with a fixed size and timeout for DB operations to prevent resource exhaustion.
*   **Target:** `worker/src/storage.rs`, `worker/src/searchboost.rs`.

### 2.2 Token Coalescing (Identity Fusion)
*   **Problem:** Long names (e.g., "Ezio Auditore") are fragmented into multiple tokens, causing context loss and restoration failures.
*   **Impact:** **MEDIUM RISK.** Degrades LLM performance and risks "token collision" across different names.
*   **Ideal Solution:** Implement a "Post-Scrub Fusion" pass in `engine.rs` that merges contiguous or adjacent redaction spans of the same category into a single atomic token (e.g., `[PERSON_1]`).
*   **Target:** `warden/src/engine.rs`.

---

## 🌍 Phase 3: Global Market Readiness (Localization)

### 3.1 Transliteration-Aware Heuristics
*   **Problem:** `Normalizer` converts Greek/Cyrillic to Latin *before* the heuristic engine runs, causing localized name patterns (regexes) to fail.
*   **Impact:** **MEDIUM RISK.** Significant leakage of non-Latin PII.
*   **Ideal Solution:** 
    1. Pass both the *Raw* and *Normalized* strings to the heuristic engine.
    2. Add "transliterated suffixes" to `gr.yaml` (e.g., `-opoulos` in addition to `-όπουλος`).
*   **Target:** `warden/src/shadow_ner.rs`, `config/regions/gr.yaml`.

### 3.2 AMKA/AFM Precision Hardening
*   **Problem:** AMKA regex is too broad, catching non-existent dates (e.g., Month 13).
*   **Impact:** **LOW RISK.** Occasional False Positives.
*   **Ideal Solution:** Implement a two-pass validator for Greek IDs. Pass 1: Regex match. Pass 2: A small Rust helper function that validates the date logic and checksum.
*   **Target:** `warden/src/engine.rs` (Post-processor).

---

## ⚙️ Phase 4: Protocol & State (Distributed)

### 4.1 JSON-RPC 2.0 Compliance
*   **Problem:** Unknown methods return `-32603` (Internal Error) instead of the standard `-32601` (Method not found).
*   **Impact:** **LOW RISK.** Incompatibility with standard MCP clients.
*   **Ideal Solution:** Update the request dispatcher in `mcp/src/server.rs` to catch unknown methods and return the correct error code.
*   **Target:** `mcp/src/server.rs`.

### 4.2 Re-Enabling Distributed State (Horizontal Scaling)
*   **Problem:** Current architecture is Standalone-only. Multi-instance deployments suffer from session loss and DB contention.
*   **Impact:** **BLOCKER FOR HA.**
*   **Ideal Solution:** Restore the `DistributedSessionManager` trait implementation using Redis for session state and Postgres/External-DB for the shared Audit trail.
*   **Target:** `worker/Cargo.toml`, `worker/src/searchboost.rs`.

---

## ✅ Verification Criteria for V1.2
1.  **`test_fault_audit_db_readonly`** must result in an immediate service stop (Fail-Closed).
2.  **`test_security_policy_bypass_naming`** must be impossible (Blocked by types).
3.  **`test_mcp_multi_token_restoration`** must return the full name, not fragments.
4.  **`test_localization_gr_mixed_greek_latin`** must catch "Giorgos" via transliterated heuristics.
