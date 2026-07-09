# Module Specification: Core Crate (`core/`)

**Objective:** Define the shared vocabulary (Errors) and contracts (Traits) for the IronWarden workspace.

**Strict Constraints:**
1. **NO Business Logic:** Do not write any structs, implementations, or logic functions.
2. **NO External I/O:** Do not import `reqwest`, `lancedb`, `rusqlite`, or any file system modules.
3. **Allowed Dependencies:** Only `thiserror` and `async-trait` are permitted in `Cargo.toml`.

**Required Deliverables:**
1. `core/src/error.rs`: Define the `SovereignError` enum using `thiserror`. It must cover PiiViolations, GatewayTimeouts, UpstreamErrors, StorageErrors, and UnauthorizedAccess.
2. `core/src/traits.rs`: Define exactly four traits:
   - `McpServer` (async handle_request)
   - `PiiShield` (sanitize_prompt, restore_prompt)
   - `StorageProvider` (async fetch_context, async log_audit_event)
   - `InferenceGateway` (async route_prompt)