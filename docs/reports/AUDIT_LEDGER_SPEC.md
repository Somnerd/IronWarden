# Cryptographic Specification: Two-Stage Hash-Binding HMAC-SHA256 Audit Ledger

## Overview
IronWarden utilizes a high-integrity, tamper-evident audit ledger to maintain forensic accountability while preserving data sovereignty. The ledger ensures that any modification to the audit logs, whether by an external attacker or a malicious administrator, is mathematically detectable.

## Cryptographic Design

### 1. Key Derivation (HKDF)
All cryptographic keys are derived from a single `WARDEN_PEPPER` (minimum 32 bytes) using HKDF-SHA256.
- **Encryption Key:** `HKDF-Expand(pepper, "encryption-v1")`
- **Integrity (HMAC) Key:** `HKDF-Expand(pepper, "integrity-v1")`
- **Genesis Hash:** `HKDF-Expand(pepper, "genesis-v1")`

### 2. The Hash Chain
The ledger is organized as a cryptographic hash chain. Each record $R_i$ contains an `integrity_hash` $H_i$ that binds it to the previous record $R_{i-1}$.

$$H_i = \text{HMAC-SHA256}(K_{int}, H_{i-1} \parallel \text{Metadata}_i \parallel \text{PayloadHash}_i)$$

Where:
- $H_{i-1}$ is the hash of the previous record (or the Genesis Hash for $R_1$).
- $\text{Metadata}_i$ includes the timestamp, `is_blocked` status, and the serialized JSON of redactions.
- $\text{PayloadHash}_i$ is the SHA256 hash of the encrypted raw input and its nonce.

### 3. Two-Stage Binding
The ledger employs "Two-Stage Binding" to protect against both metadata tampering and raw log substitution:
1.  **Stage 1 (Chain Binding):** The `integrity_hash` binds the current record's metadata and the payload's hash to the preceding chain.
2.  **Stage 2 (Payload Binding):** The `payload_hash` itself is a SHA256 digest of the `ciphertext` and `nonce`. This ensures that even if the raw log is stored separately (e.g., in an ephemeral table), it cannot be swapped for another encrypted blob.

### 4. Authenticated Encryption (AES-256-GCM)
Raw inputs are encrypted using AES-256-GCM. To prevent "Session Swapping" attacks, the `last_hash` ($H_{i-1}$) is used as **Associated Authenticated Data (AAD)**.
- If an attacker moves an encrypted log from one position in the chain to another, decryption will fail because the AAD (the previous record's hash) will not match.

## Operational Invariants

### Fail-Closed (Zero-Panic)
If the `AsyncAuditor` detects an integrity violation during its 5-second background health check or during the "Full-Chain Integrity Walk" at startup, it triggers a **Hard-Stop**. The system will refuse to process further requests, ensuring no un-audited data can flow through the gateway.

### Retention & Purging
- **Audit Metadata (`audit_reports`):** Persistent. Maintains the chain integrity even if raw logs are purged.
- **Raw Logs (`ephemeral_raw_logs`):** Purged after 30 days. Once purged, the `PayloadHash` remains in the metadata, allowing auditors to verify that a log *existed* and has not been tampered with, even if the content is gone.

## Verification Tooling
The `iw-cli verify` tool performs a complete re-calculation of the HMAC chain from the Genesis Hash. It flags:
- **Chain Corruption:** Mismatch in `integrity_hash`.
- **Payload Tampering:** Mismatch between `payload_hash` and the actual encrypted data/nonce.
- **Database Truncation:** Missing records at the end of the chain compared to the signed `.anchor` file.
