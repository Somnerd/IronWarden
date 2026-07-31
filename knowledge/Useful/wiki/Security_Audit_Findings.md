# Security Audit Findings

This document summarizes critical remediation steps and current vulnerabilities across IronWarden releases.

## 🔴 V1.3-STABILIZATION: Audit Ready (Current)
The V1.3 release codifies the **Code Red** security invariants required for the 3rd-party cryptographic audit (#86). It remediates the "Security Theater" found in previous internal versions.

### Current Mandatory Invariants
*   **[V-12] Overlap Integrity**: The engine now performs overlapping scans (`find_overlapping_iter`). A 'Redact' match is physically incapable of masking a 'Block' match.
*   **[V-14] Leak-Proof Bridge**: The bridge in `bridge.rs` is now a strict **Fail-Closed** circuit. It refuses to enqueue any text if the PII shield flags a violation.
*   **[V-15] Dual-Track NER**: Parity maintained between ASCII (homoglyph-resilient) and Unicode (script-aware) buffers to close the "Hellenic detection hole."
*   **[V-19] Session Isolation**: AAD-bound encryption (AES-GCM-256) ensures that session data is cryptographically tied to the authenticated `username`.

## 🟡 V1.2: Internal Infrastructure Milestone (2026-05-12)
V1.2 addressed foundational infrastructure gaps but left several logical invariants unverified, leading to the "Code Red" mandate.

### Remediation History
*   **Fail-Open Audit Logic**: Fixed by implementing a synchronous handshake for database writes.
*   **SQLite Deadlock Risk**: Resolved by enabling WAL mode and a 5000ms `busy_timeout`.
*   **PII Fragmentation**: Initial "Identity Persistence" logic was introduced, later refined in V1.3 to prevent token collisions.

## 🏁 Audit Posture (WP-86)
We are currently awaiting certification from a 3rd-party auditor. Until this audit returns a "Clean" report, the following features are on **Feature Freeze**:
*   Model Distillation (#74)
*   Advanced Sector Expansion (#82)
*   Native Kubernetes Operator (#96)

---
**Last Updated:** 2026-05-20
**Custodian:** Warden (Security Ops)

