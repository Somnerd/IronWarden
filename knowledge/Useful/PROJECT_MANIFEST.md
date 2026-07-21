# 🏰 IronWarden: V1.3-STABILIZATION Master Manifest
**Product Status:** V1.3-RC1 (RELEASE CANDIDATE 1) - SHADOW LAUNCH READY
**Lead Developer:** Nikolas
**Engineering Orchestrator:** GemCLI (Gemini CLI)

---

## 🎯 Project Identity
IronWarden is a **Sovereign AI Privacy Firewall** built to protect legal and medical professionals. It is designed as a zero-ops, single-binary appliance that ensures 100% data sovereignty by running all PII detection, redaction, and auditing locally.

---

## 🛡️ Code Red: Security Invariants (May 2026 Mandate)
IronWarden operates under a **Zero-Failure / Fail-Closed** mandate. The following invariants are codified and verified:

1.  **Overlap Integrity (V-12):** The engine MUST perform overlapping PII scans. A 'Redact' match must never mask a 'Block' match.
2.  **Leak-Proof Routing (V-14):** The bridge MUST ONLY enqueue sanitized text. RAW queries are strictly prohibited in the LLM/grounding pipeline. (REMEDIATED & VERIFIED)
3.  **Dual-Track NER (V-15):** Named Entity Recognition MUST maintain parity between ASCII (homoglyph-resilient) and Unicode (script-aware) buffers.
4.  **Isolation via AAD (V-19):** All session and job data MUST be bound to the 'username' using Associated Authenticated Data (AAD) during encryption. (CENTRALIZED & VERIFIED)

---

## 🛠️ Technical Milestones (The "Truth-First" Gates)

| Milestone | Status | Description |
| :--- | :--- | :--- |
| **1. Structured Policy** | ✅ PASS | Purged all fragile string-based blocking. Security actions are now enforced via a physical `SanitizationAction` enum (Block, Redact, AuditOnly). |
| **2. Concurrency Resilience** | ✅ PASS | SQLite connection pooling via `r2d2`, lock-free FIFO command-driven batch writer, WAL mode, and 10,000ms busy_timeout. |
| **3. Identity Persistence** | ✅ PASS | Fixed "PII Fragmentation." Identities are fused into atomic tokens, preventing reconstruction. (Verified via AAD Binding). |
| **4. Unicode Preservation** | ✅ PASS | Refactored the `Normalizer` to use a **Dual-Buffer System** (Unicode/ASCII parity). |
| **5. 3rd-Party Audit** | 🔄 PENDING | Mandatory gate for lifting the feature freeze. Verification of cryptographic and logical invariants. |

---

## 🔍 Audit Trail & Remediation History

*   **V1.0 - V1.1:** Proved concept, but identified critical "Fail-Open" and "Deadlock" vulnerabilities.
*   **V1.2 Internal:** Infrastructure stabilized. Transitioned to Enum-based logic and WAL mode.
*   **V1.3 DEFINITIVE:** Codified the V-series Security Invariants. Codebase reorganized to a "Crate-First" testing standard.
*   **V1.3 Hotfix (2026-05-30):** Remediated V-14 raw query leak and centralized V-19 AAD-bound cryptography.
*   **V1.3 Performance & Safety Patch (2026-07-13):** Eliminated ONNX soundness holes, implemented lock-free SQLite Write Batching (Phase 3), and allocation-free thread-local search buffers (Phase 4).

---

## 🏗️ Deployment Tiers (WP-92)
*   **Sovereign ($500/mo):** Standalone SQLite-based appliance for small firms.
*   **Enterprise ($4,000/mo):** Clustered HA version (Redis/Postgres) with remote audit streaming.

---

## 🏁 Verification Proof
Verified via full integration suite (`cargo test`) on 2026-07-13.
- All 49 Integration/Unit Tests: **PASSED (Run #58 & #60)**
- V-19 AAD Binding: **VERIFIED & CENTRALIZED**
- Fail-Closed Bridge: **VERIFIED (V-14 Fixed)**
- Concurrency & Write safety: **VERIFIED (FIFO sqlite batch writer & Mutex ONNX)**

**Current Posture: RELEASE CANDIDATE 1. Ready for production shadow launch deployment.**
