# 🏰 IronWarden: V1.3-STABILIZATION Master Manifest
**Product Status:** CODE RED / AUDIT READY
**Lead Developer:** Nikolas
**Engineering Orchestrator:** GemCLI (Gemini CLI)

---

## 🎯 Project Identity
IronWarden is a **Sovereign AI Privacy Firewall** built to protect legal and medical professionals. It is designed as a zero-ops, single-binary appliance that ensures 100% data sovereignty by running all PII detection, redaction, and auditing locally.

---

## 🛡️ Code Red: Security Invariants (May 2026 Mandate)
IronWarden operates under a **Zero-Failure / Fail-Closed** mandate. The following invariants are codified and currently under 3rd-party audit (#86):

1.  **Overlap Integrity (V-12):** The engine MUST perform overlapping PII scans. A 'Redact' match must never mask a 'Block' match.
2.  **Leak-Proof Routing (V-14):** The bridge MUST ONLY enqueue sanitized text. RAW queries are strictly prohibited in the LLM/grounding pipeline.
3.  **Dual-Track NER (V-15):** Named Entity Recognition MUST maintain parity between ASCII (homoglyph-resilient) and Unicode (script-aware) buffers.
4.  **Isolation via AAD (V-19):** All session and job data MUST be bound to the 'username' using Associated Authenticated Data (AAD) during encryption.

---

## 🛠️ Technical Milestones (The "Truth-First" Gates)

| Milestone | Status | Description |
| :--- | :--- | :--- |
| **1. Structured Policy** | ✅ PASS | Purged all fragile string-based blocking. Security actions are now enforced via a physical `SanitizationAction` enum (Block, Redact, AuditOnly). |
| **2. Concurrency Resilience** | ✅ PASS | SQLite implementation upgraded with **WAL (Write-Ahead Logging)** mode and a **5000ms busy_timeout**. |
| **3. Identity Persistence** | ✅ PASS | Fixed "PII Fragmentation." Identities are fused into atomic tokens, preventing reconstruction. |
| **4. Unicode Preservation** | ✅ PASS | Refactored the `Normalizer` to use a **Dual-Buffer System** (Unicode/ASCII parity). |
| **5. 3rd-Party Audit** | 🔄 PENDING | Mandatory gate for lifting the feature freeze. Verification of cryptographic and logical invariants. |

---

## 🔍 Audit Trail & Remediation History

*   **V1.0 - V1.1:** Proved concept, but identified critical "Fail-Open" and "Deadlock" vulnerabilities.
*   **V1.2 Internal:** Infrastructure stabilized. Transitioned to Enum-based logic and WAL mode.
*   **V1.3 DEFINITIVE:** Codified the V-series Security Invariants. Codebase reorganized to a "Crate-First" testing standard.

---

## 🏗️ Deployment Tiers (WP-92)
*   **Sovereign ($500/mo):** Standalone SQLite-based appliance for small firms.
*   **Enterprise ($4,000/mo):** Clustered HA version (Redis/Postgres) with remote audit streaming.

---

## 🏁 Verification Proof
Verified via full integration suite (`cargo test`) on 2026-05-20.
- All 15+ Integration Tests: **PASSED**
- V-19 AAD Binding: **VERIFIED**
- Fail-Closed Bridge: **VERIFIED**

**Current Posture: AUDIT READY. Feature freeze remains in effect for non-critical components.**
