# IronWarden V1.0 Deployment Guide

This guide details how to compile, configure, and deploy IronWarden into an enterprise environment.

## 1. System Requirements
- **OS:** Linux (Ubuntu 22.04 LTS / Debian 12 recommended)
- **CPU:** 4+ Cores (Required for smooth Hybrid ML execution)
- **RAM:** 4GB+ (LanceDB and the BERT model sit primarily in memory)
- **Dependencies:** `libtorch` (~1GB). The build script automatically downloads the PyTorch C++ bindings during `cargo build` thanks to the `download-libtorch` feature in `rust-bert`.

## 2. Environment Variables
You must set the following environment variables before running IronWarden:

```bash
# Core Cryptographic Material (KEEP SECRET)
export WARDEN_PEPPER="your-super-secret-32-byte-pepper-here"

# Database Connections
export DATABASE_URL="postgres://user:pass@localhost:5432/ironwarden"
export REDIS_URL="redis://localhost:6379"
export OPENAI_API_KEY="sk-..."

# Server Config
export RUST_LOG="info,warden=debug"
```

## 3. Configuration Directory
IronWarden reads policies directly from the filesystem. Ensure your rules are placed in the `config/regions/` folder.
*   **core.yaml**: Global rules (SSNs, UUIDs, AI enablement).
*   **gr.yaml**, **us.yaml**: Region-specific regulations.

*Note: You can add or modify these YAML files while IronWarden is running. The gateway will detect the change and hot-reload the rules automatically.*

## 4. Compilation & Execution
```bash
# Build the project in release mode (Highly recommended for ML inference speed)
cargo build --release

# Run the primary gateway
./target/release/app

# Run the Compliance CLI to generate a report
./target/release/iw-cli report --db audit.db

# Verify ledger integrity
./target/release/iw-cli verify --db audit.db --pepper $WARDEN_PEPPER
```

## 5. Security & Maintenance
- IronWarden operates a background thread that automatically purges `ephemeral_raw_logs` older than 30 days to comply with EU Data Minimization standards.
- You must regularly run `./target/release/iw-cli verify` and export the output for external compliance audits. Older logs will be marked as `[Archived/Purged]` as their raw inputs are mathematically irrecoverable.
