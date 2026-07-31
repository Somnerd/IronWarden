# Execution Plan: Dynamic Rule Provider Implementation

**Objective:** Implement a high-performance, secure, and configurable PII scrubbing engine in the `iw-warden` crate based on `docs/DESIGN_RULES.md`.

## Metadata
- **Crate:** `iw-warden` (located at `warden/`)
- **Primary Owners:** 
  - **Architect:** Lead implementation of core logic.
  - **Security Reviewer:** Audit session isolation and logging security.
  - **Performance Reviewer:** Validate latency and memory targets.

---

## Phase 1: Foundation (Data Modeling & Configuration)
**Goal:** Define the core data structures and enable YAML-based rule configuration.
**Owner:** Architect

### Steps:
1.  **Define Core Types:** Create `warden/src/rules.rs` with `Rule`, `RuleType`, `RuleAction`, and `RuleSet` structs/enums as specified in `docs/DESIGN_RULES.md`.
2.  **YAML Integration:** Add `serde` and `serde_yaml` dependencies to `warden/Cargo.toml`.
3.  **Rule Loader:** Implement `RuleLoader` to deserialize `rules.yaml` into a `RuleSet`.
4.  **Initial Config:** Create a default `config/rules.yaml` with baseline patterns (SSN, Email, etc.).

### Acceptance Criteria:
- [ ] `RuleSet` successfully deserializes from a sample YAML file.
- [ ] Unit tests verify that all `RuleAction` variants are correctly parsed.
- [ ] `warden/src/lib.rs` exports the `rules` module.

**Risk:** Low. Standard data modeling and serialization.

---

## Phase 2: Engine (Matching & Stateful Tokenization)
**Goal:** Implement the high-speed scrubbing logic using Aho-Corasick and Regex.
**Owner:** Architect / Performance Reviewer

### Steps:
1.  **Automaton Compilation:** Implement logic to compile `Dictionary` rules into an `aho_corasick::AhoCorasick` instance and `Regex` rules into a `regex::RegexSet`.
2.  **Scrubbing Logic:** Create `warden/src/engine.rs` implementing `WardenEngine`.
3.  **Stateful Tokenization:** 
    - Implement a `SessionContext` struct to hold the `HashMap<RawValue, TokenID>`.
    - **Address Session Bleeding:** Ensure `SessionContext` is passed as a mutable reference to the `scrub` method, preventing state from persisting across unrelated requests.
4.  **Action Enforcement:** Implement logic for `Block`, `ReplaceToken`, and `Mask`.

### Acceptance Criteria:
- [ ] Dictionary matching uses Aho-Corasick for O(n) performance.
- [ ] Stateful tokenization correctly reuses tokens (e.g., "John Doe" -> `[PERSON_1]` consistently within a session).
- [ ] **Verification:** Test that two different `SessionContext` instances do not share token mappings (No Session Bleeding).

**Risk:** Medium. Requires careful handling of session state and efficient string manipulation.

---

## Phase 3: Audit (Security & Tamper-Evident Logging)
**Goal:** Implement secure logging and audit trails for compliance.
**Owner:** Security Reviewer

### Steps:
1.  **Salted Hashing:** Implement permanent logging of scrubbed entities using salted hashes (to prevent reverse-lookup of PII).
2.  **Ephemeral Storage:** Implement a 30-day raw log retention policy (logical implementation/metadata).
3.  **Tamper-Evident Strategy:**
    - Implement a Hash-Chaining mechanism for logs.
    - Each log entry includes `H_n = Hash(Content | Timestamp | H_{n-1})`.
4.  **Security Audit:** Review the `WardenEngine` for potential bypasses or state leaks.

### Acceptance Criteria:
- [ ] Permanent logs contain no raw PII, only salted hashes.
- [ ] Log entries are linked via a hash chain, making deletions or modifications detectable.
- [ ] Security Reviewer signs off on session isolation logic.

**Risk:** High. Logging PII incorrectly can lead to compliance violations.

---

## Phase 4: Bridge (Integration & Performance)
**Goal:** Integrate the engine into the main workflow and verify performance.
**Owner:** Architect / Performance Reviewer

### Steps:
1.  **Crate Integration:** Update `warden/src/lib.rs` to expose the `WardenEngine`.
2.  **Worker Integration:** Integrate `WardenEngine` into the `worker` crate's prompt processing pipeline.
3.  **Benchmarking:** Measure scrubbing latency for large prompts (1,000+ words) and high rule counts.
4.  **Final Validation:** End-to-end test with a sample YAML config and real-world PII samples.

### Acceptance Criteria:
- [ ] E2E tests show successful blocking/masking in the worker pipeline.
- [ ] Performance target met: < 5ms latency for 1,000 words.
- [ ] Memory usage remains under 10MB for standard rule sets.

**Risk:** Medium. Integration might reveal performance bottlenecks in the worker pipeline.

---

## Verification Plan

### Automated Tests
- `cargo test --package warden` (Unit tests for rules and engine)
- `cargo bench --package warden` (Performance benchmarks)

### Security Checks
- Manual verification of "Session Bleeding": Run concurrent requests with same PII but different session IDs; verify token IDs are independent.
- Log integrity check: Manually alter a log entry and verify the hash chain fails validation.
