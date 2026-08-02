# Security Policy & Vulnerability Disclosure — IronWarden

IronWarden operates under a **Zero-Failure / Fail-Closed** security mandate. We take the security of our sovereign AI gateway, PII redaction pipeline, and cryptographic isolation mechanisms extremely seriously.

---

## 🛡️ Supported Versions

We provide security updates and patches for the following releases:

| Version | Supported | Security Maintenance |
| :--- | :---: | :--- |
| `1.0.x` / `v1.0.0-rc.1` | ✅ | Full Security Patch Support |
| `0.1.x` | ❌ | End of Life (Upgrade to v1.0.0-rc.1) |

---

## 🔒 Reporting a Vulnerability

If you discover a security vulnerability or security invariant breach in IronWarden, **please do NOT open a public GitHub issue**, it should be contacted through private channels. For any other type of issue (e.g., Performance, User Experience, etc.), please go through GitHub Issues so the community can check if someone else has already opened the same issue.

### How to Privately Disclose:
1. **GitHub Private Advisory (Preferred)**: Submit a report via [GitHub Security Advisories](https://github.com/Somnerd/IronWarden/security/advisories/new).
2. **Direct Email**: Send a report to **nikolasalexandrakis.work@gmail.com** or contact **Somnerd**.

### What to Include in Your Report:
* Description of the vulnerability or security invariant failure (e.g. PII leak, side-channel, MAC forgery).
* Steps to reproduce, proof-of-concept (PoC) script, or HTTP payload.
* Impact assessment on data confidentiality or system availability.

---

## ⏱️ Response SLA

We adhere to no strict timeline for security reports since this is a free, unpaid side project, and the maintainer has a life and a family. However, I will try to the best of my abilities to handle security reports and issues as quickly and efficiently as I can.

---

## 🎯 Scope

### In-Scope:
* **IronWarden Core Engine (`warden`)**: PII redaction accuracy, homoglyph normalization, regex bounds, ML sidecar circuit breaker.
* **Bridge & Universal Proxy (`worker`)**: Token re-hydration security, raw context leakage into LLM prompts (V-14), SSE buffer isolation.
* **Cryptographic Layer (`iw_core`)**: HKDF key derivation, AES-256-GCM context encryption with AAD isolation (V-19), HMAC audit log tampering.
* **Control Plane (`mcp`)**: Connection MAC validation, identity spoofing, authentication bypass.

### Out-of-Scope:
* Vulnerabilities in 3rd-party upstream LLM APIs (OpenAI, Anthropic).
* Social engineering or physical access to host infrastructure.
* Denial of Service (DoS) attacks on un-authenticated public rate-limiters.

---

## 🤝 Coordinated Disclosure & Credit

* We request an **embargo window of up to 30 days** from initial report before public disclosure to allow downstream users time to update.
* Security researchers who responsibly report valid vulnerabilities will be recognized in our release notes and Hall of Fame.
