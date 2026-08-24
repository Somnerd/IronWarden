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

- [ ] **Open Pull Request for `chore/oss-standards`**:
  - Target branch: `dev`
  - URL: [https://github.com/Somnerd/IronWarden/pull/new/chore/oss-standards](https://github.com/Somnerd/IronWarden/pull/new/chore/oss-standards)
  - Verify that all CI pipelines (formatting, clippy, unit tests, integration tests, TruffleHog secret scan) pass with green checks.

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

---

## 🚀 4. Final v1.0.0 Release Tagging

- [ ] Merge `dev` $\rightarrow$ `main` via Pull Request (direct merges strictly forbidden per `GEMINI.md`).
- [ ] Create signed GitHub Release `v1.0.0` with release notes and attach standalone binary artifacts if needed.
