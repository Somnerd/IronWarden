# 🧪 IronWarden Unified Test Suite

IronWarden maintains a comprehensive, defense-in-depth test suite covering unit correctness, cross-crate integration, deterministic adversarial attacks, black-box end-to-end proxy behavior, and high-concurrency stress/chaos resilience.

All tests are centralized in the `tests/` workspace package (`iw-integration-tests`) and supporting Python/bash test harnesses.

---

## 🏗️ Test Directory Structure

```
tests/
├── Cargo.toml                     # Defines [[test]] binaries for iw-integration-tests
├── fixtures/
│   └── manifests/                 # Domain-specific YAML test rule manifests
│       ├── test_manifest_legal.yaml
│       ├── test_manifest_medical.yaml
│       └── test_manifest_shipping.yaml
├── rust/                          # Rust unit, integration, and adversarial suites
│   ├── unit_core.rs               # Unit tests for iw_core primitives
│   ├── unit_warden_engine.rs      # Unit tests for WardenEngine sanitization & restoration
│   ├── unit_warden_subsystems.rs  # Unit tests for ShadowNER, ONNX NER, Normalizer, Config
│   ├── unit_worker_bridge.rs      # Unit tests for Axum bridge HTTP endpoints & circuit breaker
│   ├── unit_worker_proxy.rs       # Unit tests for SSRF DNS pinning & SSE rehydration
│   ├── unit_worker_storage.rs     # Unit tests for HMAC audit chain, GDPR shredding, Grounding
│   ├── unit_mcp.rs                # Unit tests for MCP stdio JSON-RPC server & kill switch
│   ├── integration_tests.rs       # Multi-crate integration driver uniting core/warden/worker/app
│   ├── adversarial_torture_suite.rs # Deterministic adversarial NER torture suite
│   ├── challenger1_stress.rs      # High-load concurrent stress tests
│   ├── challenger_2_adversarial_suite.rs # Advanced obfuscation & unicode adversarial tests
│   ├── app/                       # E2E app module tests (presets, sentinel, legal, mcp)
│   ├── core/                      # Multi-tenant session concurrency tests
│   ├── warden/                    # Evasion, ghosting, fusion, and multilingual Greek tests
│   └── worker/                    # Audit integrity, fail-closed invariant, SSE fuzzing
├── e2e/                           # Black-box Python end-to-end integration suite
│   ├── conftest.py                # Pytest fixtures and mock LLM upstreams
│   ├── test_adversarial.py        # Obfuscation and prompt injection black-box tests
│   ├── test_bridge.py             # Axum bridge HTTP API integration
│   ├── test_complex_naming.py     # Multilingual and multi-word name recognition
│   ├── test_distributed_isolation.py # Multi-tenant session boundary tests
│   ├── test_fault_injection.py    # Fail-closed storage and network fault tests
│   ├── test_generalized.py        # Generic prompt scrubbing end-to-end
│   ├── test_generalized_edge_cases.py # Boundary conditions and split chunk tests
│   ├── test_localization_gr.py    # Greek legal and sovereign PII tests
│   ├── test_localization_in.py    # Indian DPDP identifier tests
│   ├── test_localization_me_east_asia.py # GCC and East Asian compliance preset tests
│   ├── test_mcp.py                # MCP JSON-RPC protocol e2e tests
│   ├── test_proxy.py              # Streaming SSE proxy rehydration tests
│   ├── test_proxy_routing.py      # Upstream routing header tests
│   ├── test_scaling.py            # Throughput and connection pool scaling
│   └── test_security.py           # SSRF defense, token theft, and injection guards
└── stress/                        # Concurrency load, chaos, and security penetration scripts
    ├── bridge_stress.sh           # Shell driver for concurrent HTTP load
    ├── bridge_stress_test.py      # Python asyncio multi-worker load tester
    ├── isolation_attack.py        # Cross-tenant data leak penetration script
    ├── security_audit.py          # Automated security and header penetration check
    └── docker-compose.test.yml    # Isolated multi-container integration environment
```

---

## 🚀 Running Rust Test Targets

The Rust integration test crate `iw-integration-tests` contains modular binary targets designed for fast individual execution or comprehensive suite runs.

### Run All Integration Tests
```bash
cargo test -p iw-integration-tests
```

### Run Specific Test Targets

#### 1. Core Cryptography & Primitives (`unit_core`)
Tests AES-256-GCM `AadCipher` context binding, `JwtVerifier` RS256 token verification, FIPS mode flags, and session context serialization:
```bash
cargo test -p iw-integration-tests --test unit_core
```

#### 2. Warden Engine & Overlap Resolution (`unit_warden_engine`)
Tests `WardenEngine::sanitize_prompt`, `restore_prompt`, entropy smuggling detection, and the V-12 interval tree algorithm for nested/overlapping entities:
```bash
cargo test -p iw-integration-tests --test unit_warden_engine
```

#### 3. Warden Subsystems & Normalization (`unit_warden_subsystems`)
Tests `ShadowNer` heuristic token classification, `OnnxNer` / `HybridNer` / `NerMode` fallback behaviors, Unicode NFKD normalizer, zero-width character stripping, and YAML manifest parsing:
```bash
cargo test -p iw-integration-tests --test unit_warden_subsystems
```

#### 4. Worker HTTP Bridge & Fail-Closed Gate (`unit_worker_bridge`)
Tests Axum route handlers (`/health`, `/metrics`, `/v1/models`), authentication enforcement, concurrency semaphores, and the fail-closed circuit breaker halting traffic on storage unavailability:
```bash
cargo test -p iw-integration-tests --test unit_worker_bridge
```

#### 5. Worker Network Proxy & Streaming Rehydration (`unit_worker_proxy`)
Tests SSRF private CIDR rejection, DNS pinning, upstream provider routing (`X-IronWarden-Target-URL`), and `SseRehydrator` split-token rehydration across chunk boundaries:
```bash
cargo test -p iw-integration-tests --test unit_worker_proxy
```

#### 6. Worker Storage, Audit & Grounding (`unit_worker_storage`)
Tests `AsyncAuditor` sequential HMAC-SHA256 hash chaining, `.anchor` state file verification, GDPR cryptographic key shredding, `GroundingQueue` (Redis/SQLite), and `LocalLibrarian` LanceDB BM25 search:
```bash
cargo test -p iw-integration-tests --test unit_worker_storage
```

#### 7. Model Context Protocol Server (`unit_mcp`)
Tests `StdioMcpServer` JSON-RPC 2.0 handlers (`initialize`, `mcp_sanitize_prompt`, `mcp_restore_prompt`, `mcp_get_compliance_report`, `mcp_ocr_ingest`, `mcp_halt_system`), tenant identity spoofing defenses, and concurrency controls:
```bash
cargo test -p iw-integration-tests --test unit_mcp
```

#### 8. Multi-Crate Integration Driver (`integration_tests`)
Executes cross-crate integration scenarios spanning `core`, `warden`, `worker`, and `app`:
```bash
cargo test -p iw-integration-tests --test integration_tests
```

#### 9. Deterministic Adversarial & Torture Suites
Stress-tests NER boundary conditions, verb-eater ambiguities, inflected Greek names, and zero-false-positive guarantees on code/SQL:
```bash
cargo test -p iw-integration-tests --test adversarial_torture_suite
cargo test -p iw-integration-tests --test challenger1_stress
cargo test -p iw-integration-tests --test challenger_2_adversarial_suite
```

---

## 🐍 Running Python E2E Suite

The Python test suite provides black-box functional testing of the running IronWarden gateway against mock upstream LLMs.

### Prerequisites
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r tests/requirements.txt  # pytest, httpx, sseclient-py, cryptography
```

### Execution
Run all end-to-end tests:
```bash
pytest tests/e2e/ -v
```

Run localized compliance and boundary tests:
```bash
pytest tests/e2e/test_localization_gr.py -v
pytest tests/e2e/test_localization_in.py -v
pytest tests/e2e/test_localization_me_east_asia.py -v
```

Run security and fault injection suites:
```bash
pytest tests/e2e/test_security.py -v
pytest tests/e2e/test_fault_injection.py -v
```

---

## ⚡ Stress, Chaos & Penetration Suite

High-concurrency load and adversarial isolation attack scripts are located in `tests/stress/`.

### Run Concurrency Load Test
```bash
bash tests/stress/bridge_stress.sh
```
Or execute the asynchronous Python load generator:
```bash
python3 tests/stress/bridge_stress_test.py --concurrency 50 --requests 1000
```

### Run Cross-Tenant Isolation Attack Verification
```bash
python3 tests/stress/isolation_attack.py
```

### Run Automated Security & Header Audit
```bash
python3 tests/stress/security_audit.py --target http://localhost:8080
```
