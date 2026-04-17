# Module Specification: MCP Crate (`mcp/`)

**Objective:** Handle the ingestion and translation of Model Context Protocol (MCP) JSON-RPC payloads.

**Strict Constraints:**
1. **NO Business Logic:** Do not validate user identity, do not scrub PII, and do not route to LLMs. This crate is strictly a translator.
2. **Communication Only:** It only knows how to parse JSON from `stdio` and pass it to the traits defined in `core`.

**Required Deliverables:**
1. `mcp/src/server.rs`: A struct that implements the `McpServer` trait. 
2. It must listen for standard MCP Initialization requests, parse the capabilities, and respond with the correct JSON-RPC success payload.