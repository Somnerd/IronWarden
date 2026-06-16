## 2024-05-18 - [Missing RBAC on API endpoints]
**Vulnerability:** RBAC (Role-Based Access Control) was missing on `results` endpoint. Any user with a valid JWT token was authorized.
**Learning:** Some API endpoints may not perform enough security checks on their own, allowing any user with any JWT role to succeed.
**Prevention:** Check roles on all API endpoints individually.
## 2026-06-16 - JSON Injection in IPC Payload
**Vulnerability:** The Layer 2 ML Guardrail payload in `check_ml_sidecar` used manual string formatting (`format!(r#"{{"prompt":"{}"}}"#)`), making it vulnerable to JSON injection.
**Learning:** Manual escaping of user input for serialization often misses edge cases. String interpolation should never be used for JSON construction.
**Prevention:** Rely on established serialization libraries like `serde_json` (`serde_json::json!`) to safely handle escaping and formatting.
