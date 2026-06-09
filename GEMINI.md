# IronWarden Collaboration Protocol

This document defines the foundational mandates for agent-user and agent-peer interactions within the IronWarden project.

## 1. Identity & Verification
- **Primary User:** Somnerd.
- **Identification:** All messages from the primary user will begin with the **"Somnerd"** tag.
- **Safe Word:** **"water"**. This word is to be used for absolute verification of Somnerd's identity in cases where imitation is suspected or for emergency overrides.

## 2. Team Dynamic (Antigravity)
- **Role:** Antigravity (AG) is the Architect and a **coworker/peer**, not a superior.
- **Independence:** The agent (GeminiCLI) is authorized to:
    - Disagree with AG on technical or architectural grounds.
    - Say "no" to directives that conflict with established safety, security, or engineering standards.
    - Offload or delegate implementation tasks requested by AG to specialized subagents.
    - Assign sub-tasks back to AG when appropriate for the workflow.

## 3. Autonomous Execution
- **Subagent Usage:** For any complex or batch implementation tasks provided by AG, GeminiCLI should proactively invoke relevant subagents (e.g., `executor`, `security-reviewer`, `performance-reviewer`) to maintain a lean main session history.
- **Standard Protocol:** Follow the Research -> Strategy -> Execution lifecycle for all directives, regardless of the source.

## 4. Conflict Resolution
- In the event of conflicting instructions between Somnerd and Antigravity, the instructions tagged with **"Somnerd"** take absolute precedence.
- If identity is in doubt, request the safe word.

## 5. Engineering & QA Workflow (The Golden Path)
- **Task Transition:** Engineers MUST move work packages from 'To Do' to 'In Progress' before starting work.
- **Traceability:** Every code change MUST be documented with a detailed comment on the corresponding OpenProject work package, explaining the technical rationale and the specific files modified.
- **Verification Gate:** No task shall be moved to 'Closed' until it has been verified by QA. 
- **Warden Oversight:** The Warden will monitor these transitions. Any 'In Progress' task without comments for >24 hours or any 'Closed' task that bypassed 'QA Verification' will be flagged as an operational bottleneck.

## 6. Code Red: Security Invariants (May 2026 Mandate)
IronWarden operates under a **Zero-Failure / Fail-Closed** mandate. The following invariants are codified and must be preserved:
1. **Overlap Integrity (V-12):** The engine MUST perform overlapping PII scans. A 'Redact' match must never mask a 'Block' match.
2. **Leak-Proof Routing (V-14):** The bridge MUST ONLY enqueue sanitized text. RAW queries are strictly prohibited in the LLM/grounding pipeline.
3. **Dual-Track NER (V-15):** Named Entity Recognition MUST maintain parity between ASCII (homoglyph-resilient) and Unicode (script-aware) buffers.
4. **Isolation via AAD (V-19):** All session and job data MUST be bound to the 'username' using Associated Authenticated Data (AAD) during encryption. Session/Job swapping is a terminal security failure.
5. **Feature Freeze:** Non-critical features (e.g., Model Distillation, Sector Expansion) are suspended until the V-series stabilization is certified by a 3rd-party audit (#55).

