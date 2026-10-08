# ⚡ IronWarden Performance Benchmarks & Methodology

IronWarden is engineered in **safe, high-performance Rust** with zero-copy deserialization, lock-free atomic telemetry, and pre-allocated sliding window state machines. 

This document outlines the performance benchmarks, latency overhead, memory footprint, and reproducibility methodology for the IronWarden Universal AI Gateway.

All benchmarks in this document were empirically executed on the hardware environment specified below, using [Criterion.rs](https://github.com/bheisler/criterion.rs) with 100 samples (1,000+ iterations per sample) and 95% confidence intervals. The raw benchmark data is committed in [`benchmarks/raw/criterion_estimates.json`](benchmarks/raw/criterion_estimates.json).

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
| **Base Memory Footprint (Heuristic Mode)** | **28.4 MB RSS** | Lightweight edge deployment |
| **Base Memory Footprint (Hybrid ONNX NER Mode)** | **142.0 MB RSS** | Includes active ONNX Runtime engine & tensor buffers |

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

## 📈 Concurrency & Architectural Scalability

IronWarden is built on the Tokio multi-threaded asynchronous runtime and Axum/Hyper HTTP stack:
- **Zero-Allocation Streaming Path**: HTTP response chunks pass through the `SseRehydrator` ring buffer without buffering the entire upstream payload into memory.
- **Backpressure & Concurrency Control**: Upstream streaming requests acquire permits from an atomic concurrency semaphore (`DEFAULT_CONCURRENCY_PERMITS`), preventing upstream connection flooding or thread pool exhaustion.
- **Rate Limiting**: Implements GCRA (Generic Cell Rate Algorithm / leaky bucket) per IP and per API key in constant memory.
- **Observability Isolation**: Health probes (`/health`) and metrics scraping (`/metrics`) bypass proxy concurrency queues to guarantee uninterrupted cluster liveness telemetry even under peak load.

---

## 💾 Memory Footprint

- **Idle Baseline (Heuristic Mode)**: `28.4 MB RSS` (compiled regexes, Aho-Corasick automatons, token tables).
- **Idle Baseline (Hybrid ONNX NER Mode)**: `142.0 MB RSS` (active ONNX Runtime C++ engine, BERT model weights, and tensor scratch buffers).
- **Zero Heap Thrashing**: Fixed-size sliding-window buffers and zero-copy JSON parsing avoid frequent heap re-allocations during streaming.

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
./scripts/bench.sh
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

### 2. View Raw Criterion Outputs
All raw statistical estimates are stored in:
```bash
cat benchmarks/raw/criterion_estimates.json
```
Criterion also generates interactive HTML charts in `target/criterion/report/index.html`.
