# Module Specification: Warden Crate (`warden/`)

**Objective:** Implement the `PiiShield` trait defined in the `core` crate to perform deterministic, memory-safe text sanitization.

**Strict Constraints:**
1. **NO Network or Database:** This module operates entirely in-memory. Do not import or use any I/O crates.
2. **Deterministic Only:** You must use the `aho-corasick` crate. Do not attempt to use LLMs, regex, or probabilistic models for PII detection.
3. **Zero-Panic Rule:** Use `.map_err()` to convert any internal errors to `SovereignError`. Absolutely no `.unwrap()` or `panic!`.

**Required Deliverables:**
1. `warden/src/pii.rs`: A struct `AhoCorasickShield` that implements the `PiiShield` trait.
2. **Pseudonymization Logic:** The `sanitize_prompt` method must replace sensitive terms with tokens (e.g., `[PERSON_1]`) and return the safe string alongside an in-memory `HashMap` mapping tokens back to the original terms.
3. **Restoration Logic:** The `restore_prompt` method must take the LLM's response and swap the tokens back to the real text using the provided `HashMap`.