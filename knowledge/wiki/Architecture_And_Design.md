# Architecture & Design

## The "Shield & Vault" Modular Workspace

IronWarden is organized around a dual-component philosophy: the **Shield** (real-time defense) and the **Vault** (immutable auditing).

### 1. The Shield (`iw-warden`)
A multi-stage sanitization pipeline designed for <50ms end-to-end overhead.

- **Deterministic Pass**: Utilizes Aho-Corasick automata and optimized Regex unions for fast, $O(n)$ pattern matching.
- **Dual-Track Scanning (V-15)**: The engine maintains parity between two distinct buffers:
    - **Unicode Buffer**: Preserves raw characters (e.g., Greek, Cyrillic) for script-aware regex and regional compliance.
    - **ASCII-Normalized Buffer**: Strips visual homoglyphs and accents to catch spoofing attempts.
- **Parallel Probabilistic Pass**: Powered by a pool of local **BERT-NER** models.
- **Shadow NER & Semantic Cache**: Heuristic detection for potential identities promoted via a sub-0.1ms semantic L1 cache.
- **Identity Linking (V-12)**: Prevents "Identity Ghosting" by ensuring substrings share parent tokens across a session.

### 2. The Bridge (`iw-worker::bridge`)
A high-integrity routing layer that connects the local firewall to the LLM/grounding pipeline.

- **Fail-Closed Circuit (V-14)**: The bridge physically refuses to route any traffic if the Shield returns an `is_blocked` status. It is architecturally impossible for a "Blocked" prompt to reach the external API.
- **Sanitized Enqueuing**: Only text processed by the `Redactor` is allowed into the grounding stream. RAW queries are strictly prohibited.

### 2. The Vault (`worker::audit`)
A legally-defensible, tamper-proof audit trail for compliance and security oversight.

- **Cryptographic Hash Chain**: Every log entry is linked to the previous entry via HMAC-SHA256. Manual alteration of the underlying SQLite database automatically breaks the chain, rendering the tampering evident.
- **AAD-Bound Encryption at Rest**: Raw, unsanitized prompts are encrypted using AES-256-GCM with the `username` bound as Additional Authenticated Data (AAD), preventing cross-user session injection.
- **Full-Chain Integrity Walk**: Validates the entire audit history on startup to detect truncation or modification.

### 3. Grounding & Knowledge (`worker::librarian` & SearchBoost)
- **Local Librarian**: Performs high-speed keyword-based document retrieval from local text/markdown assets leveraging **Tantivy**.
- **Sovereign Search Fix (V-02)**: Passing original prompts to the Librarian ensures retrieval accuracy, while all results are scrubbed by the Shield before being consolidated into the system prompt.

### 4. Dynamic Configuration
- **Hot-Reload**: A background file watcher actively monitors the `config/regions/*.yaml` policies. This allows administrators to enforce or relax localization rules (e.g., swapping to EU or US strict modes) without dropping active TCP connections or restarting the daemon.
