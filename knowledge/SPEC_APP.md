
# Module Specification: App Crate (`app/`)

**Objective:** The final executable. Wire all the modules together and start the system.

**Strict Constraints:**
1. **Minimal Code:** This file (`main.rs`) should be as short as possible. No actual processing happens here.
2. **Initialization Only:** This crate is responsible for reading `.env` variables and starting the `tokio` runtime.

**Required Deliverables:**
1. `app/src/main.rs`: 
   - Initialize `tracing` for terminal logging.
   - Instantiate `AhoCorasickShield` (from `warden`).
   - Instantiate the Database and Router (from `worker`).
   - Pass them into the `McpServer` (from `mcp`).
   - Start the async event loop.