## 2026-06-16 - JSON Injection in IPC Payload
**Vulnerability:** The Layer 2 ML Guardrail payload in `check_ml_sidecar` used manual string formatting (`format!(r#"{{"prompt":"{}"}}"#)`), making it vulnerable to JSON injection.
**Learning:** Manual escaping of user input for serialization often misses edge cases. String interpolation should never be used for JSON construction.
**Prevention:** Rely on established serialization libraries like `serde_json` (`serde_json::json!`) to safely handle escaping and formatting.
