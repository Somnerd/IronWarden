# IronWarden V1.0 Architecture

IronWarden is an advanced, standalone AI Security Gateway specifically designed to act as an impenetrable middle-tier between Enterprise environments and Large Language Models (LLMs). It intercepts, sanitizes, audits, and grounds prompts before they ever reach an external API.

## Core Architectural Pillars

### 1. Hybrid Intelligence Engine
IronWarden utilizes a two-stage analysis pipeline to maximize performance while ensuring uncompromising security:

*   **Deterministic First (Zero-Latency):** 
    The engine immediately runs the prompt through an Aho-Corasick automaton and union-compiled Regular Expressions (spanning IBANs, Tax IDs, SSNs, etc.). This executes in `O(n)` time, taking ~2ms.
*   **Probabilistic Secondary (High Accuracy):**
    A heuristic `ShadowNer` scans for linguistic patterns (like Greek `-ης` suffixes or capitalization chains). If flagged, the `HybridNer` (powered by Hugging Face's `rust-bert`) fires up. If the neural network validates the entity with a confidence > `0.85`, it is fully redacted.

### 2. The Sovereign Hash-Chain (Tamper-Proof Ledger)
Audit logging in IronWarden goes far beyond simple database inserts. It utilizes Cryptographic Ledgers for mathematical non-repudiation.
*   **Dedicated Worker:** `AsyncAuditor` runs on a non-blocking MPSC channel to avoid slowing down HTTP response times.
*   **AES-256-GCM:** Raw prompts are encrypted instantly with a random nonce.
*   **HMAC-SHA256 Hash-Chain:** Each log calculates `current_hash = HMAC(last_hash + timestamp + redactions + nonce + ciphertext)`. If an attacker directly alters the SQLite file, the cryptographic chain is broken, and the `iw-cli verify` tool instantly flags the tampering.

### 3. Edge Grounding (LanceDB + SearchBoost)
IronWarden intercepts requests and can augment them securely:
*   Instead of making remote API calls for RAG (Retrieval-Augmented Generation), IronWarden connects to a local, in-process LanceDB instance to fetch vectorized corporate data.
*   The `SearchBoost` queue intelligently batches retrieval requests to minimize database load during traffic spikes.

### 4. Configuration Hot-Reload
IronWarden is a "Zero-Ops" environment. Policies are stored in `config/regions/*.yaml`. An async file watcher continually monitors this directory. If a new rule is added, the gateway compiles a new `WardenEngine` and hot-swaps it via an `RwLock` in sub-milliseconds without dropping a single HTTP request.
