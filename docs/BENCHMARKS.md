# ⚡ IronWarden Performance Benchmarks & Methodology

IronWarden is engineered in **safe, high-performance Rust** with zero-copy deserialization, lock-free atomic telemetry, and pre-allocated sliding window state machines. 

This document outlines the performance benchmarks, latency overhead, memory footprint, and reproducibility methodology for the IronWarden Universal AI Gateway.

All benchmarks in this document were empirically executed on the hardware environment specified below, using [Criterion.rs](https://github.com/bheisler/criterion.rs) with 100 samples (1,000+ iterations per sample) and 95% confidence intervals. The raw benchmark data is committed in [`benchmarks/raw/criterion_estimates.json`](../benchmarks/raw/criterion_estimates.json).

---

## 📊 Executive Summary

| Metric / Operation | Median Latency [95% CI] | Architectural Impact |
| :--- | :---: | :--- |
| **Streaming SSE Rehydration (per chunk)** | **503.2 ns – 821.8 ns** | Sub-microsecond sliding window; zero stream buffering |
| **AES-256-GCM Hardware Crypto (1 KB)** | **807.4 ns** [805.7 – 809.6 ns] | Hardware AES-NI accelerated payload encryption |
| **Token Restoration (Aho-Corasick SIMD)** | **126.0 µs** [125.6 – 126.5 µs] | 3.4x faster than standard regex (422.9 µs) |
| **Single-Token Fast Replacement** | **7.59 µs** [7.54 – 7.63 µs] | Microsecond hot-path placeholder substitution |
| **ShadowNER Boundary Token Scan** | **1.01 µs** [1.01 – 1.03 µs] | Sub-microsecond pre-filter before neural NER |
| **Lock-Free Atomic Metric Record** | **1.77 ns** [1.76 – 1.77 ns] | Single-cycle atomic increment |
| **Prometheus Metrics Exposition Render** | **292.8 ns** [292.2 – 293.7 ns] | Near-zero overhead monitoring endpoint |

---

## ⏱️ Detailed Latency Measurements (Criterion.rs)

All micro-benchmarks report statistical **Median**, **Mean**, and **95% Confidence Intervals** computed by Criterion.rs.

### 1. Ingress & Egress Token Restoration (`iw-warden`)
Evaluates placeholder re-insertion and token restoration comparing regex against Aho-Corasick SIMD pattern matching (`engine_benchmark.rs`).

| Benchmark Scenario | Median [95% Confidence Interval] | Mean [95% Confidence Interval] |
| :--- | :---: | :---: |
| **Aho-Corasick Multi-Token Restore** | **126.04 µs** [125.61 – 126.50 µs] | **127.37 µs** [126.44 – 128.66 µs] |
| **Regex Multi-Token Restore (Baseline)** | **422.86 µs** [421.62 – 423.98 µs] | **424.06 µs** [422.84 – 425.29 µs] |
| **Single-Token Direct Replace** | **7.59 µs** [7.54 – 7.63 µs] | **7.67 µs** [7.62 – 7.73 µs] |
| **Fast-Path Multi-Token Replace** | **20.53 µs** [20.47 – 20.67 µs] | **20.65 µs** [20.56 – 20.74 µs] |

### 2. Streaming SSE Token Rehydration (`iw_worker`)
Measures the sliding window state machine (`SseRehydrator`) processing Server-Sent Events (SSE) deltas and stitching split token placeholders across chunk boundaries (`proxy_benchmark.rs`).

| Streaming Scenario | Median [95% Confidence Interval] | Mean [95% Confidence Interval] |
| :--- | :---: | :---: |
| **Delta Chunk without Placeholders** | **503.17 ns** [502.27 – 503.94 ns] | **504.78 ns** [503.32 – 506.91 ns] |
| **Delta Chunk with Complete Token** | **579.44 ns** [578.20 – 580.44 ns] | **582.38 ns** [579.57 – 586.26 ns] |
| **Token Split Across Chunk Boundary** | **821.81 ns** [820.16 – 823.15 ns] | **823.25 ns** [821.53 – 825.12 ns] |

### 3. Cryptographic Storage & Telemetry (`iw_worker`)
Measures AES-256-GCM authenticated payload encryption/decryption (`grounding_benchmark.rs`) and lock-free atomic telemetry exposition (`proxy_benchmark.rs`).

| Operation | Median [95% Confidence Interval] | Mean [95% Confidence Interval] |
| :--- | :---: | :---: |
| **AES-256-GCM Payload Decryption** | **772.81 ns** [770.94 – 774.70 ns] | **775.37 ns** [773.47 – 777.61 ns] |
| **AES-256-GCM Payload Encryption** | **807.37 ns** [805.73 – 809.59 ns] | **810.76 ns** [808.25 – 814.18 ns] |
| **Atomic Gateway Metric Record** | **1.77 ns** [1.76 – 1.77 ns] | **1.77 ns** [1.76 – 1.77 ns] |
| **Prometheus Exposition Render** | **292.78 ns** [292.17 – 293.68 ns] | **296.48 ns** [294.27 – 299.23 ns] |

### 4. Named Entity Recognition Boundary Detection (`iw-warden`)
Measures heuristic token boundary classification prior to neural ONNX model invocation (`ner_benchmark.rs`).

| Operation | Median [95% Confidence Interval] | Mean [95% Confidence Interval] |
| :--- | :---: | :---: |
| **ShadowNER Boundary Token Scan** | **1.01 µs** [1.01 – 1.03 µs] | **1.05 µs** [1.03 – 1.07 µs] |

---


---

## 🎯 PII Shield Detection Accuracy, Recall & Precision Scorecard

In addition to latency and throughput, IronWarden's PII Shield was empirically evaluated across **four comprehensive benchmark suites**:

1. **Multilingual Combinatorial Stress Matrix**: 100,000 randomized prompt iterations generated from a combinatorial dictionary of the top 100 first names and 100 surnames across 4 cultures (**Greek**, **English**, **Arabic**, and **Chinese**; 40,000 unique name combinations), embedded into varied real-world prompt templates.
2. **Synthetic Sovereign Structural PII & Negative Controls**: 400 test cases covering API keys/secrets, national IDs (US SSN, Greek AFM, Greek AMKA), financial records (Luhn-checked credit cards, European IBANs), and technical false-positive controls (PostgreSQL, Docker, Kubernetes, Axum).
3. **CoNLL-2003 Test Split**: 2,756 standard news wire sentences (1,025 sentences containing 1,617 gold Person entity annotations).
4. **WikiGold Test Split**: 1,341 unstructured Wikipedia sentences (541 sentences containing 934 gold Person entity annotations).

All raw results are reproducible via `./scripts/bench/eval_accuracy.sh` and committed to [`benchmarks/raw/accuracy_eval_results.json`](../benchmarks/raw/accuracy_eval_results.json).

### 🏆 Empirical Detection Scorecard

| Evaluation Suite | Sample Size | Mode | Heur Recall | Hybrid Recall | Precision | F1 Score (Heur / Hyb) | Leaks / False Negatives |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **100,000 Multilingual Matrix (Overall)** | **100,000** | Heuristic (SIMD) | **98.13%** | **98.13%** | **100.0%** | **0.991 / 0.991** | **1,873 / 100,000** |
| ↳ English Combinatorial Names | 25,000 | Heuristic (SIMD) | 100.00% | 100.00% | 100.0% | 1.000 / 1.000 | 0 / 25,000 |
| ↳ Greek Combinatorial Names | 25,000 | Heuristic (SIMD) | 100.00% | 100.00% | 100.0% | 1.000 / 1.000 | 0 / 25,000 |
| ↳ Arabic Combinatorial Names | 25,000 | Heuristic (SIMD) | 99.24% | 99.24% | 100.0% | 0.996 / 0.996 | 189 / 25,000 |
| ↳ Chinese Combinatorial Names | 25,000 | Heuristic (SIMD) | 93.26% | 93.26% | 100.0% | 0.965 / 0.965 | 1,684 / 25,000 |
| **Structural Secrets (API Keys, JWTs, AWS)** | **100** | Heuristic / Hybrid | **100.0%** | **100.0%** | **100.0%** | **1.000 / 1.000** | **0 / 100** |
| **National IDs (US SSN, Greek AFM, AMKA)** | **100** | Heuristic / Hybrid | **100.0%** | **100.0%** | **100.0%** | **1.000 / 1.000** | **0 / 100** |
| **Financial (Luhn Cards, EU IBANs)** | **100** | Heuristic / Hybrid | **100.0%** | **100.0%** | **100.0%** | **1.000 / 1.000** | **0 / 100** |
| **Negative Controls (SQL, Code, Geographies)** | **100** | Heuristic / Hybrid | **100.0%** | **100.0%** | **100.0%** | **1.000 / 1.000** | **0 / 100 (0 FP)** |
| **CoNLL-2003 Test Split (Gold Person NER)** | **1,617 gold entities** | Dual-Track Hybrid | **66.54%** | **94.62%** | **100.0%** | **0.799 / 0.972** | **541 (Heur) / 87 (Hyb)** |
| **WikiGold Test Split (Gold Person NER)** | **934 gold entities** | Dual-Track Hybrid | **56.21%** | **92.18%** | **100.0%** | **0.720 / 0.959** | **409 (Heur) / 73 (Hyb)** |
| **Adversarial Torture Suite (Eval 5)** | **1,000** | Dual-Track Hybrid | **100.0%** | **100.0%** | **99.80%** | **0.999 / 0.999** | **0 / 1,000 (2 FP in inflected Greek)** |

### ⚡ Evaluation Throughput & Performance
- **100,000 Prompts Execution Time**: **3.50 seconds** on AMD Ryzen 7 5700X3D (~**28,571 prompts/second** on a single CPU thread with 98.13% overall recall across 4 languages and zero false positives).
- **Zero Heap Thrashing**: Zero memory leaks observed across the 100,000-iteration stress test.

### 🛡️ Dual-Track ShadowNER & Window-Batched ONNX Architecture

To eliminate the classic trade-off between recall and latency, IronWarden implements a **Dual-Track Candidate Pipeline with Window-Batched Disambiguation**:

1. **Track A (High-Certainty Heuristics — Zero Latency Overhead)**:
   - Full names (`FirstName LastName`), multiple initials (`J. R. R. Tolkien`, `B. Young`), and nobiliary particles (`da`, `de`, `del`, `van`, `von`, `bin`, `ibn`, `al-`).
   - Strict personal honorifics (`Mr.`, `Mrs.`, `Dr.`, `Prof.`) with byte-boundary and acronym-tail guards to reject patterns like `U.S. Government`.
   - Structural secrets, Luhn-validated credit cards, and national IDs via SIMD Aho-Corasick.
   - Immediate redaction in both Heuristic and Hybrid modes at line rate (>28,000 prompts/sec).

2. **Track B (Ambiguous Candidates — Window-Batched Hybrid Mode)**:
   - Evaluates context role anchors (`Patient Hoyt`, `Per Coste`) and isolated mid-sentence capitalized tokens.
   - Filtered against common English stop words, programming keywords, SQL reserved words, and geographic proper nouns to prevent false positives.
   - In **Pure Heuristic Mode** (`ai_enabled: false`), Track B candidates are discarded to guarantee 100.0% precision on business code, SQL, and technical text.
   - In **Hybrid Mode** (`ai_enabled: true`), candidates are grouped by unique sentence windows and evaluated in a single batched pass with INT8 quantized DistilBERT. This completely prevents N+1 ONNX inference spikes while rescuing ambiguous entities, elevating CoNLL-2003 recall from 66.54% to **94.62%** and WikiGold recall from 56.21% to **92.18%** with **zero false positives**.

## 📈 Concurrency & Architectural Scalability

IronWarden is built on the Tokio multi-threaded asynchronous runtime and Axum/Hyper HTTP stack:
- **Zero-Allocation Streaming Path**: HTTP response chunks pass through the `SseRehydrator` ring buffer without buffering the entire upstream payload into memory.
- **Backpressure & Concurrency Control**: Upstream streaming requests acquire permits from an atomic concurrency semaphore (`DEFAULT_CONCURRENCY_PERMITS`), preventing upstream connection flooding or thread pool exhaustion.
- **Rate Limiting**: Implements GCRA (Generic Cell Rate Algorithm / leaky bucket) per IP and per API key in constant memory.
- **Observability Isolation**: Health probes (`/health`) and metrics scraping (`/metrics`) bypass proxy concurrency queues to guarantee uninterrupted cluster liveness telemetry even under peak load.

---

## 💾 Memory Architecture & Resource Management

IronWarden avoids garbage collection overhead and dynamic heap allocations in its streaming hot paths:
- **Zero Stream Buffering**: Fixed-size sliding-window ring buffers (`SseRehydrator`) stream upstream tokens without buffering complete responses.
- **Heuristic Engine Allocation**: Pre-compiled Aho-Corasick automata and regex sets are initialized once during startup and shared across threads via read-only memory references.
- **Hybrid ONNX Runtime Memory**: When `WARDEN_NER_MODE=hybrid` is enabled, the in-process ONNX Runtime manages INT8 tensor memory and session allocations.
- **Production RSS Sizing**: Process memory varies by platform libc and allocator configuration. In production environments, monitor process memory via Prometheus `/metrics` (`process_resident_memory_bytes`) or container metrics (`cgroups`).

---

## 🔬 Benchmark Methodology & Environment

### Hardware Specifications
- **Machine**: Dedicated Test Rig
- **CPU**: AMD Ryzen 7 5700X3D (8 Cores, 16 Threads, 3.0 GHz base / 4.1 GHz boost, 96 MB L3 3D V-Cache)
- **RAM**: 16 GB DDR4-3200
- **OS**: Ubuntu 24.04 LTS (Linux kernel 6.6 WSL2)
- **Rust Toolchain**: `stable-x86_64-unknown-linux-gnu` (`rustc 1.84.0+`)
- **Criterion.rs Version**: `0.5.1`

### Methodology Principles
1. **Isolated Micro-benchmarking**: Criterion.rs configured with 3.0s warm-up cycles and 5.0s measurement phases (100 statistical samples per benchmark target).
2. **Compiler Optimization Safeguards**: All inputs and outputs wrapped in `criterion::black_box` to prevent LLVM dead-code elimination.
3. **Statistical Verification**: Results report bootstrap-estimated medians, means, and 95% confidence intervals directly from Criterion output.

---

## 🚀 How to Reproduce Benchmarks Locally

### 1. Run All Criterion Benchmarks
```bash
./scripts/bench/bench.sh
```

Or execute crate benchmarks individually:
```bash
# Benchmark Warden Engine & Token Restoration
cargo bench --package iw-warden --bench engine_benchmark

# Benchmark NER Entity Extraction
cargo bench --package iw-warden --bench ner_benchmark

# Benchmark Streaming SSE Token Rehydration & Metrics
cargo bench --package iw_worker --bench proxy_benchmark

# Benchmark Grounding & Cryptographic Storage
cargo bench --package iw_worker --bench grounding_benchmark
```

### 2. Run Accuracy & Detection Evaluation
```bash
./scripts/bench/eval_accuracy.sh
```
Raw empirical accuracy data is committed in `benchmarks/raw/accuracy_eval_results.json`.

### 2. View Raw Criterion Outputs
All raw statistical estimates are stored in:
```bash
cat benchmarks/raw/criterion_estimates.json
```
Criterion also generates interactive HTML charts in `target/criterion/report/index.html`.
