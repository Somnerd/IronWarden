# IronWarden Scripts

This directory organizes automation, CI, benchmarking, setup, and development scripts for IronWarden into domain-specific subdirectories.

All scripts automatically resolve the repository root via `$(dirname "${BASH_SOURCE[0]}")/../..` and can be safely executed from any working directory.

---

## Directory Layout

```
scripts/
├── bench/
│   ├── bench.sh            # Criterion.rs latency and throughput benchmarks
│   └── eval_accuracy.sh    # Accuracy & recall evaluation harness across benchmark datasets
├── ci/
│   └── ci_local.sh         # Complete local CI runner mirroring GitHub Actions
├── dev/
│   └── demo.sh             # Zero-dependency interactive gateway demo (Heuristic mode)
└── setup/
    └── setup_models.sh     # ONNX model and tokenizer downloader with SHA-256 verification
```

---

## Script Reference

### `scripts/ci/`

#### `ci_local.sh`
Local runner that mirrors `.github/workflows/rust_ci.yml` directly on your workstation. It auto-provisions a Python virtual environment (`.venv`), downloads ONNX Runtime dynamic libraries if missing, and executes five pipeline jobs:
1. **Code Quality**: `cargo fmt` formatting checks and `cargo clippy` with memory-throttled worker jobs.
2. **Security & Crypto**: Unit tests for core cryptographic and security invariants (`iw_core`).
3. **Warden Shield**: PII redaction, tokenization, and pattern evaluation tests (`iw-warden`).
4. **Worker Core**: Storage, proxy, and message routing tests (`iw_worker`).
5. **Integration**: App binary verification and end-to-end Python test suite (`pytest tests/e2e/`).

**Usage:**
```bash
./scripts/ci/ci_local.sh [flags]
```

**Common Flags:**
- `--only-quality`: Run only formatting and clippy checks.
- `--only-security`: Run only `iw_core` cryptography tests.
- `--only-warden`: Run only `iw-warden` shield tests.
- `--only-worker`: Run only `iw_worker` pipeline tests.
- `--only-integration`: Run only the end-to-end integration test suite.
- `--skip-integration`: Run all Rust compilation/unit test jobs, skipping Python tests.
- `--skip-quality`: Skip clippy and fmt checks for rapid iteration.

---

### `scripts/setup/`

#### `setup_models.sh`
Downloads INT8-quantized DistilBERT Named Entity Recognition (NER) model weights and tokenizer from Hugging Face into `data/models/distilbert-ner/`. Cryptographic SHA-256 hashes are verified after download:
- `model_quantized.onnx` (SHA-256: `9419a876387ff2bbe5f21ab7429c7bef93eac86c50353390d4d8fca6e4a210d8`)
- `tokenizer.json` (SHA-256: `cb26b43c98e8266ae3e99c2a583cf8315d73b33a17e6b20b4df7ff1f22392d34`)

Without these assets, IronWarden automatically operates in lightweight Heuristic-Only mode.

**Usage:**
```bash
./scripts/setup/setup_models.sh
```

---

### `scripts/bench/`

#### `bench.sh`
Executes statistical microbenchmarks across all workspace crates using Criterion.rs:
- Measures proxy latency overhead (p50, p95, p99).
- Benchmarks SSE token rehydration throughput.
- Tracks AES-256-GCM session vault encryption/decryption overhead.

Detailed HTML performance reports are written to `target/criterion/`.

**Usage:**
```bash
./scripts/bench/bench.sh
```

#### `eval_accuracy.sh`
Runs the comprehensive statistical evaluation harness (`iw-accuracy-suite`) to measure PII Shield precision, recall, and F1 scores against standardized and adversarial datasets:
- CoNLL-2003 Test Split (Standard News NER)
- WikiGold Test Split (Wikipedia Unstructured NER)
- 100,000-Iteration Multilingual Combinatorial Matrix (GR/EN/AR/ZH)
- Adversarial and messy enterprise slices

Raw JSON benchmark outputs are stored in `benchmarks/raw/accuracy_eval_results.json`.

**Usage:**
```bash
./scripts/bench/eval_accuracy.sh
```

---

### `scripts/dev/`

#### `demo.sh`
Launches an instant, interactive IronWarden demonstration in Heuristic-Only mode with zero external dependencies (no Docker daemon, no Tesseract OCR, no model downloads).
- Generates ephemeral RSA-2048 keys and an RS256 JWT token for authentication.
- Boots the gateway on `http://127.0.0.1:8080`.
- Sends sample prompts containing SSNs, emails, IBANs, and phone numbers, displaying real-time redaction, tokenization, and audit ledger logging.

**Usage:**
```bash
./scripts/dev/demo.sh
```
