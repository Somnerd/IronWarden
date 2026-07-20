# 🛠️ Design Specification: Hardened Dynamic Rule Provider
**Crate:** `iw-warden`
**Status:** Stabilized V1.3 (Definitive)

## 1. Overview
The Hardened Dynamic Rule Provider implements a multi-stage defense pipeline designed to prevent PII leakage while resisting obfuscation attacks. It utilizes an asynchronous, out-of-band auditing system to maintain high performance.

## 2. The Defensive Pipeline (The "Warden Path")

### Stage 0: Normalization & De-obfuscation
Before any matching occurs, the input text is normalized to prevent "Bypass Attacks."
*   **NFKC Normalization:** Convert homoglyphs (e.g., Greek 'ο' to Latin 'o').
*   **Char Stripping:** Remove zero-width spaces, hidden control characters, and non-printable markers.
*   **Dual-Buffer Matching (V-15):** The engine maintains parity between an ASCII-normalized buffer (homoglyph-resilient) and the original Unicode buffer (script-aware) to preserve precise character offsets during replacement.
*   **De-obfuscation:** Detect and decode common encoding patterns (Base64, Hex, Shannon Entropy smuggling) used to hide PII.

### Stage 1: Deterministic Redaction (Active)
*   **Aho-Corasick:** $O(n)$ matching for high-volume dictionaries (Client lists, Projects). Reuses `thread_local!` string buffers to run allocation-free on the hot path.
*   **RegexSet:** Parallel pattern matching for standard identifiers (SSN, IBAN, API Keys).
*   **Stateful Tokenization:** Per-session entity mapping (e.g., `John Doe` -> `[PERSON_1]`).

### Stage 2: Shadow NER (Passive Audit)
*   Probabilistic check for contextual PII. Flags detected anomalies for human review without modifying the text. Powered by local ONNX DistilBERT-NER inference, secured via Mutex wrapper.

## 3. High-Performance Auditing

### A. Asynchronous Ledger
To meet the **<5ms latency** target, all logging operations are handled by a dedicated background task.
*   **The Channel:** Senders dispatch `DbCommand` (Insert/Update) variants to a FIFO Flume channel.
*   **The Writer:** A background writer task in `worker` processes the queue in transactions (up to 50 items or every 100ms), eliminating database commit locking.

### B. Defensive Hashing & AAD Binding (V-19)
*   **Associated Authenticated Data (AAD):** Cryptographic binding of session data and username prevents session swapping attacks.
*   **Hash-Chain Integrity:** Each log entry contains a hash of its content + the previous entry's hash to ensure tamper-evidence.

## 4. Configuration Governance
*   **Strict Mode Configurability (WP-101):** Validates config files and environment variables, failing closed with a hard exit if critical secrets (such as the 32-byte pepper key) are missing.
*   **Hot-Reloading:** Securely reload rules in memory via `ArcSwap` without interrupting the gateway flow.

## 5. Performance Targets
*   **Normalization Latency:** < 1ms.
*   **Overall Scrubbing Latency:** < 5ms (enabled by async logging).
*   **Memory Efficiency:** < 15MB for all automata and regex sets.
