# 🚀 Plan: IronWarden V1.0 Commercial Launch (Law Firm Edition)

## Objective
Transition the codebase from a "Hardened Engine" to a "Client-Ready Product" for a boutique law firm demo tomorrow.

---

### Phase 1: Real-World Grounding (The RAG Bridge)
*Goal: Remove the [MOCK] context and actually search local case files.*
- [ ] **Implementation:** Refactor `worker/src/rag.rs` to implement a high-performance, keyword-based searcher.
- [ ] **Data Source:** It will index a local `/data/knowledge` directory containing text/markdown files.
- [ ] **Logic:** Use a simple BM25-lite or TF-IDF heuristic to find relevant context for the AI prompt.
- [ ] **Acceptance Criteria:** A user query like "What is our policy on data retention?" returns a real snippet from a local file, not a mock string.

### Phase 2: Legal Sector Localization
*Goal: Prove the engine understands the specifics of Greek and EU legal practice.*
- [ ] **`rules_legal.yaml`:** Create a specialized ruleset containing:
    - **Greek AFM:** (9-digit Tax ID) Regex.
    - **Greek AMKA:** (11-digit Social Security) Regex.
    - **EU IBAN:** Pattern matching for banking identifiers.
    - **Case/Folder IDs:** Pattern for typical legal file references (e.g., `LAW-2026-X`).
- [ ] **Integration:** Update `app/src/main.rs` to load this legal ruleset by default.

### Phase 3: Performance & Polish (The 50ms Gate)
*Goal: Ensure the "Warden Loop" feels instantaneous.*
- [ ] **Latency Audit:** Use `Instant::now()` to log a detailed breakdown of (Normalization + Deterministic + AI) times.
- [ ] **Sanity Check:** Remove all remaining "TODO" and "MOCK" comments from the source code.
- [ ] **Compliance PDF:** Create a sample "Safe-Usage Certificate" based on the `audit.db` to show the client's managing partner.

---

## 🛠️ Verification & Testing
1.  **Functional Test:** Drop a real Greek legal brief into `/data/knowledge` and ask the gateway to summarize it.
2.  **Safety Test:** Ensure the AFM and client names in that brief are correctly replaced with `[TOKEN_N]`.
3.  **Audit Test:** Verify the encrypted raw data and HMAC chain are present for this specific transaction.
