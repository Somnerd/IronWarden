***

# 🏰 IronWarden: Master Design & Sprint Document
**Version:** 1.0 (The Workspace Monolith)
**Mission:** Build a stateless, memory-safe, zero-ops Enterprise AI Gateway in 6 days. It must intercept prompts via MCP, ground them in local data, scrub PII deterministically, and route them to external LLMs without ever panicking.

---

## 1. Clean Order of Responsibilities (The Cargo Workspace)
To guarantee zero circular dependencies and maximum compile speed, the system is strictly divided into five distinct crates. 

### 🧱 `core` (The Dictionary)
* **Responsibility:** Defines the vocabulary and interfaces of the system. Contains zero business logic, zero network calls, and zero database connections.
* **Key Components:**
    * `error.rs`: The central `SovereignError` enum (`thiserror`).
    * `traits.rs`: `McpServer`, `PiiShield`, `StorageProvider`, `InferenceGateway`.

### 🛡️ `warden` (The Policy Engine)
* **Responsibility:** The high-margin intellectual property. It enforces rules and sanitizes data in-memory before it leaves the server.
* **Key Components:**
    * **PII Scanner:** Uses `aho-corasick` for lightning-fast deterministic matching.
    * **Pseudonymization:** Swaps sensitive terms for safe tokens (e.g., `[PERSON_1]`) and reverses them on the way back out.

### ⚙️ `worker` (The Infrastructure Layer)
* **Responsibility:** All heavy Input/Output (Disk and Network). If it touches the outside world, it lives here.
* **Key Components:**
    * **RAG Engine:** Uses `lancedb` to fetch relevant contextual documents.
    * **Audit Logger:** Uses `rusqlite` to asynchronously record transactions.
    * **LLM Router:** Uses `reqwest` to stream safe prompts to Azure/vLLM.

### 🚪 `mcp` (The Front Door)
* **Responsibility:** Translates the outside world into Rust structs.
* **Key Components:**
    * Handles Model Context Protocol JSON-RPC payloads over `stdio` or Server-Sent Events (SSE).

### 🚀 `app` (The Integrator)
* **Responsibility:** The final executable.
* **Key Components:**
    * Reads the `.env` file.
    * Initializes `tracing` for terminal logging.
    * Wires the `warden`, `worker`, and `mcp` implementations together and starts the async runtime.

---

## 2. Goalposts (The 6-Day Sprint Plan)
We cannot slip. Each day has a singular focus.

* **Day 1: The Foundation.** Initialize the Workspace. Write `core/src/error.rs` and `core/src/traits.rs`. Ensure `cargo check` passes on the workspace.
* **Day 2: The Shield.** Build the `warden` crate. Implement the `aho-corasick` PII scanner and the pseudonymization logic. Write unit tests to prove it catches secrets.
* **Day 3: The Librarian.** Build the `worker` storage layer. Connect `lancedb` for document grounding and `rusqlite` for the audit trail.
* **Day 4: The Router.** Build the `worker` network layer. Implement the `reqwest` client to stream data to a mock LLM endpoint.
* **Day 5: The Ingress.** Build the `mcp` crate. Set up the JSON-RPC listener to accept incoming requests and route them to the `warden`.
* **Day 6: The Forge.** Write `app/main.rs`. Wire the traits together, load the environment variables, and run the first end-to-end prompt through the system. 

---

## 3. Immediate To-Dos (Day 1 Execution)

Your mission right now is purely structural. Do not write any PII or database logic yet.

1. **Burn the Ships:** Move the old legacy `searchboost` repository to an archive folder.
2. **Initialize the Workspace:** Run the `cargo new` commands to create `ironwarden` and its 5 sub-crates (`core`, `warden`, `worker`, `mcp`, `app`).
3. **Configure `Cargo.toml`:** Set up the root `Cargo.toml` to link the members of the workspace.
4. **Draft the Core:** Open `core/src/error.rs` and build out the `SovereignError` enum using the `thiserror` crate.
5. **Verify:** Run `cargo check` at the root level.

***