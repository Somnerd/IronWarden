# 📦 IronWarden Binary Release & Verification Guide

This document outlines how official IronWarden standalone binaries are packaged, signed, and verified by end users and administrators.

---

## 🚀 Downloading Official Binaries

Official binary releases are published automatically on GitHub Releases:
* **Release Page:** [https://github.com/Somnerd/IronWarden/releases](https://github.com/Somnerd/IronWarden/releases)

### Available Target Platforms:
* **Linux x86_64:** `ironwarden-x86_64-unknown-linux-gnu.tar.gz` (Debian, Ubuntu, RedHat, Alpine)
* **macOS Apple Silicon (ARM64):** `ironwarden-aarch64-apple-darwin.tar.gz` (M1/M2/M3/M4)
* **macOS Intel (x86_64):** `ironwarden-x86_64-apple-darwin.tar.gz`

---

## 🔒 Cryptographic Integrity Verification

Every release contains an aggregated `SHA256SUMS.txt` file computed during the isolated CI build environment.

### Verification Steps:

1. **Download the archive and checksum file:**
   ```bash
   # Example for Linux x86_64:
   curl -LO https://github.com/Somnerd/IronWarden/releases/download/v1.0.0/ironwarden-x86_64-unknown-linux-gnu.tar.gz
   curl -LO https://github.com/Somnerd/IronWarden/releases/download/v1.0.0/SHA256SUMS.txt
   ```

2. **Verify SHA-256 Checksum:**
   ```bash
   # On Linux:
   sha256sum --ignore-missing -c SHA256SUMS.txt

   # On macOS:
   shasum -a 256 --check SHA256SUMS.txt 2>/dev/null || grep -E "ironwarden" SHA256SUMS.txt | shasum -a 256 -c
   ```

   **Expected Output:**
   ```text
   ironwarden-x86_64-unknown-linux-gnu.tar.gz: OK
   ```

3. **Extract & Run:**
   ```bash
   tar -xzf ironwarden-x86_64-unknown-linux-gnu.tar.gz
   cd ironwarden-x86_64-unknown-linux-gnu

   # Start the gateway
   cp example.env .env
   ./ironwarden
   ```

---

## 🛠️ Maintainer Release Protocol

To cut a new official release:
1. Ensure all changes are merged into `main` via Pull Request after full CI verification.
2. Tag the commit with the semantic version tag:
   ```bash
   git tag -s v1.0.0 -m "Release v1.0.0 — Universal AI Privacy Firewall"
   git push origin v1.0.0
   ```
3. The `.github/workflows/release.yml` GitHub Action will automatically:
   - Compile optimized release binaries across Linux and macOS.
   - Bundle `ironwarden`, `iw-cli`, `example.env`, and `LICENSE`.
   - Calculate cryptographic SHA-256 hashes.
   - Publish the GitHub Release with downloadable tarballs.
