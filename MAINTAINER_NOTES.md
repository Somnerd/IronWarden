# 📋 Maintainer Action Items & Release Checklist

This document tracks all manual tasks, security procedures, and pre-launch steps that require direct maintainer action before the public release of **IronWarden v1.0.0**.

---

## 🔴 1. Security & Credentials (Immediate Actions)

- [ ] **Revoke Leaked GitHub PAT**:
  - **Action**: Go to GitHub **Settings** $\rightarrow$ **Developer settings** $\rightarrow$ **Personal access tokens** and revoke the personal access token ending in `...124RNZ`.
  - **Status**: Token removed from working tree and replaced with environment variable enforcement (`GITHUB_TOKEN`).

- [ ] **Purge Token from Historical Commits (Before Public Launch)**:
  - **Action**: Historical commit `098eccb` contained the token string. Use `git-filter-repo` on a bare/mirror clone to scrub it across all branches and tags before making the repository public:
    ```bash
    cd /tmp
    git clone --mirror git@github.com:Somnerd/IronWarden.git ironwarden-clean
    cd ironwarden-clean
    echo "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==>REDACTED_GITHUB_TOKEN" > replacements.txt
    git filter-repo --replace-text replacements.txt
    git push --force --all
    git push --force --tags
    ```

---

## 🟡 2. GitHub Governance & Pull Request Workflow

- [ ] **Review & Merge PR #182 (`fix/docker-compose-setup` ➔ `dev`)**:
  - Contains Dockerfile protobuf fixes, Debian trixie runtime image update, and standalone configuration mapping.

- [ ] **Open Pull Request for `chore/oss-standards` (➔ `dev`)**:
  - Target branch: `dev`
  - URL: [https://github.com/Somnerd/IronWarden/pull/new/chore/oss-standards](https://github.com/Somnerd/IronWarden/pull/new/chore/oss-standards)
  - Contains OSS licensing (`LICENSE`, `LICENSE-COMMERCIAL.md`), `.env.example`, TruffleHog CI scanning, cargo-audit, and token security removal.

- [ ] **OpenProject / Task Tracking**:
  - Add documentation comment on the corresponding work package explaining files modified (`LICENSE`, `LICENSE-COMMERCIAL.md`, `example.env`, `.env.example`, `.gitignore`, `scripts/`, `.github/workflows/rust_ci.yml`).

---

## 🟢 3. Pre-Launch Configuration & Sanity Checks

- [ ] **Verify `example.env` Out-of-the-Box Flow**:
  - Ensure new users can run:
    ```bash
    cp example.env .env
    docker-compose up -d
    curl -i http://localhost:8080/health
    ```
- [ ] **Review Issue #140 (Kill Switch Implementation)**:
  - Verify emergency halt implementation in `mcp/src/server.rs` before enterprise certification.

- [ ] **Review Issue #183 (Anthropic Target URL Header)**:
  - Verify `/v1/messages` header routing overrides for local proxy tests.

- [ ] **Review Issue #133 (ONNX AI Pool Mutex Poison Recovery)**:
  - Ensure worker pool uses `.unwrap_or_else(|e| e.into_inner())` to prevent threadpool poisoning.

---

## 🚀 4. Final v1.0.0 Release Tagging

- [ ] Merge `dev` $\rightarrow$ `main` via Pull Request (direct merges strictly forbidden per `GEMINI.md`).
- [ ] Create signed GitHub Release `v1.0.0` with release notes and attach standalone binary artifacts if needed.

---

## 🛠️ 5. CI / Quality Gate Verification

- **Automated Workflow**: `.github/workflows/rust_ci.yml`
- **Jobs Executed**:
  1. `secret-scan`: TruffleHog automated credential scanner.
  2. `security-audit`: `cargo-audit` dependency vulnerability verification.
  3. `lint-and-format`: `cargo fmt --all -- --check` & `cargo clippy --workspace --all-targets -- -D warnings`.
  4. `unit-tests`: Full workspace lib/binary test suite.
  5. `integration-tests`: Rust integration suite (`iw-integration-tests`) + Python end-to-end pytest suite (`test_suites/`).
  6. `benchmarks`: Performance regression benchmarking.
- **Local Pre-Commit Hook**: `.pre-commit-config.yaml`
  - Integrated with `detect-private-key`, `detect-secrets`, `trufflehog`, and standard file format validators to block unencrypted secrets at commit time.
- **Local Validation Status**: Verified clean workspace compile, zero clippy warnings (`-D warnings`), and 100% formatted.

