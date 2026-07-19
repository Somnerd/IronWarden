# 🛠️ Design Specification: Hardened Dynamic Rule Provider
**Crate:** `iw-warden`
**Status:** Hardened / Phase 1 implementation

## 1. Overview
The Hardened Dynamic Rule Provider implements a multi-stage defense pipeline designed to prevent PII leakage while resisting obfuscation attacks. It utilizes an asynchronous, out-of-band auditing system to maintain high performance.

## 2. The Defensive Pipeline (The "Warden Path")

### Stage 0: Normalization & De-obfuscation
Before any matching occurs, the input text is normalized to prevent "Bypass Attacks."
*   **NFKC Normalization:** Convert homoglyphs (e.g., Greek 'ο' to Latin 'o').
*   **Char Stripping:** Remove zero-width spaces, hidden control characters, and non-printable markers.
*   **De-obfuscation:** Detect and decode common encoding patterns (Base64, Hex) used to hide PII.

### Stage 1: Deterministic Redaction (Active)
*   **Aho-Corasick:** $O(n)$ matching for high-volume dictionaries (Client lists, Projects).
*   **RegexSet:** Parallel pattern matching for standard identifiers (SSN, IBAN, API Keys).
*   **Stateful Tokenization:** Per-session entity mapping (e.g., `John Doe` -> `[PERSON_1]`).

### Stage 2: Shadow NER (Passive Audit)
*   Probabilistic check for contextual PII. Flags detected anomalies for human review without modifying the text.

## 3. High-Performance Auditing

### A. Asynchronous Ledger
To meet the **<5ms latency** target, all logging operations are handled by a dedicated background task.
*   **The Channel:** The engine sends a `ScrubbingReport` to an async MPSC channel.
*   **The Writer:** A background worker in the `worker` crate batched-writes to SQLite.

### B. Defensive Hashing
*   **Per-Session Salting:** Prevents frequency analysis attacks by using a unique salt for every conversation session.
*   **Hash-Chain Integrity:** Each log entry contains a hash of its content + the previous entry's hash to ensure tamper-evidence.

## 4. Configuration Governance
*   **Config Auditing:** Every change to `rules.yaml` is logged with a timestamp and reason.
*   **Hot-Reloading:** Securely reload rules in memory without interrupting the gateway flow.

## 5. Performance Targets
*   **Normalization Latency:** < 1ms.
*   **Overall Scrubbing Latency:** < 5ms (enabled by async logging).
*   **Memory Efficiency:** < 15MB for all automata and regex sets.
