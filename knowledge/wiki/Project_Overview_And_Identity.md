# Project Overview & Identity

## Mission Statement
IronWarden is a Sovereign AI Privacy Firewall. Its mission is to enable high-performance, local-first AI privacy protection, ensuring that no sensitive PII (Personally Identifiable Information) ever leaves the on-premise environment.

## Core Philosophy: Local-First
In an era of ubiquitous cloud AI APIs, IronWarden stands as an unyielding proxy layer. The foundational rule is strict sovereignty: **no PII is sent to external APIs for detection, vectorization, or processing.** 

All analysis, sanitization, and context scrubbing is performed completely offline, ensuring total data privacy for the enterprise, while still facilitating interaction with modern LLMs safely.

## Key Capabilities
- **Real-Time PII Sanitization**: Millisecond latency masking of known identity formats (SSN, IBAN, etc.) and unknown unknowns (Names, Organizations).
- **Identity Ghosting**: Linking fragments (e.g., "Alice" and "Alice Smith") to consistent opaque tokens (`[TOKEN_N]`).
- **Cryptographic Audit Log**: A legally defensible, hash-chained ledger of every prompt sent to AI endpoints, ensuring that attempts to bypass or tamper with logs are permanently recorded.
- **Fail-Closed Guarantee**: The gateway strictly blocks communication if any step of the sanitization or audit process fails.
