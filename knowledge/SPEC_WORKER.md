# Module Specification: Worker Crate (`worker/`)

**Objective:** Core infrastructure and orchestration for IronWarden and SearchBoost.

## Primary Responsibilities
1. **Audit Ledger (`audit.rs`):** Implements the High-Integrity HMAC-SHA256 hash-chain audit ledger.
2. **Session Management (`searchboost.rs`):** Manages user sessions and identities, ensuring AAD isolation for encrypted data.
3. **Storage Abstraction (`storage.rs`):** Aggregates audit logs, session state, and knowledge base access.
4. **Search Orchestration (`searchboost.rs`, `librarian.rs`):** Manages background search jobs for SearchBoost, including the "Decoupled Tandem" grounding protocol.
5. **LLM Gateway (`router.rs`):** Provides a standardized interface for interacting with LLM providers (e.g., OpenAI, Ollama).

## Security Constraints
- **Zero-Panic Rule:** All background tasks must use proper error propagation. Panics in worker threads must be caught or prevented to ensure the system fails closed.
- **Fail-Closed Audit:** If the `AsyncAuditor` fails or detects tampering, all routing through the `WorkerStorage` must halt.
- **AAD Isolation:** Every encryption operation (Sessions, Audit Logs, Sealed Queries) MUST use the user identity (username) or the preceding chain hash as Associated Authenticated Data.

## Key Components
- `AsyncAuditor`: Dedicated background thread for high-throughput audit logging.
- `SearchBoostQueue`: SQLite-backed job queue for asynchronous grounding.
- `LocalLibrarian`: LanceDB-backed local knowledge base management.
