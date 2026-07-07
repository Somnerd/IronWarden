# 🏰 IronWarden Work Board

## ✅ Phase 1: Security & Compliance Hardening (V-series)

*Goal: Address critical security vulnerabilities and establish baseline compliance.*

* [x] **WP-47: Session Isolation**: Enforce Unique UUID Sessions.
* [x] **WP-48: PII Shield Hardening**: Broaden Normalization & Homoglyph Pass.
* [x] **WP-49: Audit Trail Integrity**: Hash Ciphertext & Full-Chain Validation.
* [x] **WP-65: Sector Localization**: Expand regional compliance rules.
* [x] **WP-68: [V-02] RAG Semantic Blindness**: Fix via Pre-Redaction Search.
* [x] **WP-69: [V-19] Session Swap Attack**: Fix via AAD Binding.
* [x] **WP-70: [V-12] Aho-Corasick Bypass**: Fix Overlapping Match Masking.
* [x] **WP-71: [V-13] Rule Evasion**: Fix Normalization Mismatch.
* [x] **WP-72: [V-14] Hard-Block Bypass**: Fix in Bridge API.
* [x] **WP-73: [V-15] Shadow NER Homoglyph Bypass**: Implementation verified.
* [x] **WP-81: Legal Sector Localization**: Finalize `rules_legal.yaml` & Default Loading.
* [x] **WP-88: Hard-Stop Fail-Closed Logic**: Implementation of strict enforcement.
* [x] **WP-89: Policy Engine Refactor**: Transition to Strongly Typed Policy Engine (GAP-01).
* [x] **WP-87: FIPS Compliance**: Enable FIPS 140-2/3 Compliance Mode.

---

## ✅ Phase 2: Infrastructure & Resilience

*Goal: Stabilize the system and prepare for enterprise workloads.*

* [x] **WP-76: Performance**: Abolish Global AI Mutex & Implement Decoupled Thread Pool.
* [x] **WP-77: Caching**: Implement Semantic L1 Caching (Session LRU Cache).
* [x] **WP-80: Cleanup**: Purge all [TODO] and [MOCK] interfaces from source.
* [x] **WP-90: HA Backend**: Implement Redis/Postgres HA Backend (Remediate GAP-04).
* [x] **WP-91: OCR**: Integration of OCR Pipeline (Tesseract/AWS Textract).
* [x] **WP-94: Audit Streaming**: Implementation of Remote Audit Streaming.
* [x] **WP-95: Multi-Modal**: Multi-Modal Vision Shield Foundation (VisionWarden).
* [x] **WP-82: Logistics**: Advanced Sector Expansion: Shipping & Logistics PII Rulesets.

---

## 🏗️ Phase 3: Stabilization & Audit (Code Red)

*Goal: Finalize documentation and pass 3rd-party security audit.*

* [/] **WP-46: Documentation**: Initial Documentation Ingestion. (In Progress)
* [/] **WP-53: QA Strategy**: [Wiki] V1.1 QA Test Strategy & Plan. (In Progress)
* [/] **WP-54: Identity**: [Wiki] Project Overview & Identity. (In Progress)
* [/] **WP-58: Architecture**: [Wiki] Architecture & Design. (In Progress)
* [/] **WP-64: Audit Findings**: [Wiki] Security Audit Findings. (In Progress)
* [/] **WP-55: Pen-Test**: [Task] Final Hardening: Third-party penetration test. (In Progress)
* [/] **WP-86: Master Audit**: [Security] Third-Party Penetration Test & Cryptographic Audit (V1.0 Readiness). (In Progress)
* [ ] **WP-93: Verification**: [QA] Regression Stress Test for Phase 3 Stability Gaps (V1.3 Verification). (New)
* [x] **WP-97: [V-14 Violation]**: Fix RAW unsanitized query leak in `bridge.rs`. (Verified)
* [x] **WP-98: [V-19 Fragility]**: Centralize AAD-bound encryption logic in `iw-core`. (Verified)
* [ ] **WP-99: [SQLite Silo]**: Implement unified connection pooling (SqlitePool). (High)
* [ ] **WP-100: [Boilerplate]**: Standardize `spawn_blocking` via `BlockingExecutor`. (Medium)
* [ ] **WP-101: [Config/Errors]**: Unify YAML configuration loading and standardize error mapping. (Medium)
* [ ] **WP-102: [JWT]**: Refactor JWT verification into a reusable component. (Medium)

---

## 🚀 Phase 4: Scaling & Enterprise Readiness

*Goal: Prepare for high-availability and multi-tenant deployments.*

* [ ] **WP-92: Tiered Models**: [Architecture] Define Tiered Deployment Models (Sovereign vs. Enterprise). (New)
* [ ] **WP-96: K8s Operator**: [Scaling] Native Kubernetes Operator for Auto-Scaling. (On Hold)

---

## 🔮 Phase 5: Advanced Features & Expansion (Post-MVP)

*Goal: Broaden the PII detection capabilities.*

* [ ] **WP-67: Evasion Defense**: [V-11] PII Pattern Evasion via Flexible Separators. (On Hold)
* [ ] **WP-85: Retrieval**: [Feature] Retrieval Upgrade: Migrate Librarian to LanceDB. (On Hold)

---

### 💡 Current Status

* **Status**: **CODE RED / AUDIT READY**.
* **Blocker**: **WP-86** (3rd Party Audit).
* **Next Major Milestone**: V1.3 Certification.

### ❌ Rejected/Archived
* **WP-74**: Model Distillation & Quantization (ONNX) - *Suspended for security reliability.*
* **WP-75**: Aggressive Bloom Filtering via Shadow NER - *Deemed redundant.*
* **WP-78**: [V-16] Shadow NER Promotion Bypass - *Not reproducible.*
* **WP-79**: [V-17] Semantic Cache Homoglyph Collision - *Mitigated via V-15.*
* **WP-83**: [QA] Commercial Readiness Validation - *Folded into WP-93.*
* **WP-84**: [Feature] Compliance Reporting - *Deferred.*
