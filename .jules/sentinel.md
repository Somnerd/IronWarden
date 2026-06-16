## 2024-05-18 - [Missing RBAC on API endpoints]
**Vulnerability:** RBAC (Role-Based Access Control) was missing on `results` endpoint. Any user with a valid JWT token was authorized.
**Learning:** Some API endpoints may not perform enough security checks on their own, allowing any user with any JWT role to succeed.
**Prevention:** Check roles on all API endpoints individually.
