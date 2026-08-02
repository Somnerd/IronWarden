# 🛠️ Contributing to IronWarden

Thank you for your interest in contributing to **IronWarden**! IronWarden is a high-performance, security-focused Sovereign AI Data Protection Gateway written in Rust.

By contributing to this project, you agree that your contributions will be licensed under the project's AGPLv3 license (the "inbound=outbound" principle). You retain copyright to your own contributions, but grant the project the right to use and distribute them under these terms.

We welcome community contributions, bug fixes, documentation improvements, and security enhancements.

---

## 💻 Local Development Setup

### 1. Prerequisites
* **Rust Toolchain**: 1.80+ (`rustup update stable`)
* **System Libraries**:
  * macOS: `brew install tesseract openssl pkg-config`
  * Debian/Ubuntu: `sudo apt-get install tesseract-ocr libtesseract-dev libssl-dev pkg-config`
* **Python**: 3.10+ (for integration test suites)

### 2. Clone & Build
```bash
git clone https://github.com/Somnerd/IronWarden.git
cd IronWarden

# Download local BERT-NER ONNX model weights
./scripts/setup_models.sh

# Build all workspace crates
cargo build --workspace
```

### 3. Environment Setup
Before running the application or test suites, set the required cryptographic environment variables:

```bash
export WARDEN_PEPPER="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
export WARDEN_MCP_SECRET="test_secret"
export WARDEN_ENV="development"
```

---

## 🧪 Running Tests & Quality Checks

All pull requests must pass local verification before submission:

### Run Workspace Unit & Integration Tests
```bash
cargo test --workspace
```

### Run Proxy Route Integration Tests
```bash
cargo test --test proxy_tests
```

### Code Formatting & Linting
```bash
# Enforce Rust formatting
cargo fmt --all -- --check

# Enforce zero Clippy warnings
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 🔐 The Golden Path & Security Invariants

IronWarden operates under strict **Zero-Failure / Fail-Closed** security mandates:

1. **Overlap Integrity (V-12)**: A `Redact` match must never mask a `Block` match.
2. **Leak-Proof Routing (V-14)**: The bridge MUST ONLY enqueue sanitized text. RAW queries are strictly prohibited in the LLM/grounding pipeline.
3. **Dual-Track NER (V-15)**: NER must maintain parity between ASCII (homoglyph-resilient) and Unicode (script-aware) buffers.
4. **Isolation via AAD (V-19)**: All session and job data MUST be bound to the `username` using Associated Authenticated Data (AAD) during encryption.
5. **No Panic Policy**: Avoid `unwrap()` on untrusted input. Return explicit `SovereignError` variants instead.

---

## 🔀 Pull Request Protocol

1. **Branch Naming**:
   * Feature: `feature/your-feature-name`
   * Fix: `fix/issue-number-description`
2. **PR Base Branch**: Always target `dev` or `release-v0.2.0` (never push directly to `main`).
3. **Commit Messages**: Follow standard commit conventions:
   * `feat(proxy): add Anthropic /v1/messages streaming handler`
   * `fix(warden): enforce fail-closed on ML sidecar timeout`
   * `test(audit): add HMAC chain validation test`
4. **CI Verification**: All GitHub Actions workflows (tests, linters, and security scanners) must complete cleanly before merge.

---

## 💡 Good First Issues

Looking for a good place to start? Check our issue tracker for issues labeled [`good first issue`](https://github.com/Somnerd/IronWarden/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).
