# IronWarden Repository Cleanup & Safety Audit (Phase 0)

**Date**: October 15, 2026  
**Auditor**: Senior Rust Engineer / Antigravity Investigation Agent  
**Branch**: `audit/repo-cleanup-phase0`  
**Base Commit**: `c0ca50e` (origin/dev)  
**Status**: COMPLETED — Awaiting Maintainer Approval (Phase 0 Hard Rule: Zero Code Changes)

---

## 1. Executive Summary

This audit establishes the baseline evidence and remediation plan for the IronWarden repository across 5 critical dimensions:
1. **Safety & Security**: Discovered a critical CI vulnerability where `pull_request` workflows run arbitrary fork code on a `self-hosted` runner (`somnerd`), alongside a silent fallback mechanism where missing ONNX NER model weights quietly degrade to `NerBackend::None` while the system reports healthy hybrid execution.
2. **Truthfulness & Evidence**: Identified unsubstantiated competitor performance metrics (LiteLLM, Portkey, Kong) and unmeasured memory footprint figures (~28.4 MB / ~142 MB RSS) in `README.md` and `BENCHMARKS.md`, as well as compliance marketing claims (FIPS 140-2/3, EU AI Act, HIPAA) backed only by simple regex patterns and mock environment variable checks.
3. **Repository Architecture**: Identified 46 internal planning/wiki documents in `knowledge/`, 3 byte-for-byte duplicate policy files in `policies/`, 2 duplicate environment templates (`.env.example` vs `example.env`), and 3 duplicated test manifests across `app/`, `warden/`, and `integration_tests/`.
4. **Dead Code & Dependencies**: Uncovered 18+ unused workspace dependencies across crates (including `serde-pickle`, `tantivy`, `docx-rs`, `dashmap`, `crossbeam-channel`, and `once_cell`).
5. **Swallowed Failures**: Documented 10+ instances of `2>/dev/null` and `|| true` in CI workflows and maintenance scripts, along with unhandled `let _ = save_session(...)` operations in gateway proxy routes.

Baseline verification check results:
- `cargo fmt --all -- --check`: **FAILED** (formatting diffs in `warden/src/shadow_ner.rs:356` and line 659).
- `cargo clippy --workspace --all-targets -- -D warnings`: **PASSED** (0 warnings).
- `cargo test --workspace`: **PASSED** (88 unit and integration tests passed).
- `pytest test_suites/ -k "not stress and not benchmark"`: **PASSED** (106 passed, 21 deselected in 40.50s).

---

## 2. Baseline Verification Commands & Outputs

### 2.1 Code Formatting (`cargo fmt --all -- --check`)
```
Diff in /home/somnerd/Documents/Projects/IronWarden/warden/src/shadow_ner.rs:356:
     let mut filtered: Vec<Span> = Vec::new();
     for span in sorted {
         if let Some(last) = filtered.last() {
-            if span.start < last.end {
-                continue;
-            }
+            if span.start < last.end {
+                continue;
+            }
         }
         filtered.push(span);
     }
Diff in /home/somnerd/Documents/Projects/IronWarden/warden/src/shadow_ner.rs:659:
                         }
-                        continue;
+                        continue;
                     }
-                }
+                }
                 _ => {}
FMT_CHECK_FAILED: 1
```

### 2.2 Linter (`cargo clippy --workspace --all-targets -- -D warnings`)
```
    Checking iw_core v1.1.0 (/home/somnerd/Documents/Projects/IronWarden/core)
    Checking iw-warden v1.1.0 (/home/somnerd/Documents/Projects/IronWarden/warden)
    Checking iw-accuracy-suite v1.1.0 (/home/somnerd/Documents/Projects/IronWarden/benchmarks/accuracy_suite)
    Checking iw-cli v1.1.0 (/home/somnerd/Documents/Projects/IronWarden/cli)
    Checking iw_worker v1.1.0 (/home/somnerd/Documents/Projects/IronWarden/worker)
    Checking iw_mcp v1.1.0 (/home/somnerd/Documents/Projects/IronWarden/mcp)
    Checking iw-integration-tests v1.1.0 (/home/somnerd/Documents/Projects/IronWarden/integration_tests)
    Checking app v1.1.0 (/home/somnerd/Documents/Projects/IronWarden/app)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 53s
```
*Result: Clean pass, 0 warnings.*

### 2.3 Workspace Rust Test Suite (`cargo test --workspace`)
```
     Running unittests src/lib.rs (core): ok. 0 passed
     Running unittests src/lib.rs (warden): ok. 28 passed (0.04s)
     Running tests/adversarial_torture_suite.rs: ok. 15 passed (0.01s)
     Running tests/challenger1_stress.rs: ok. 24 passed (0.02s)
     Running tests/challenger_2_adversarial_suite.rs: ok. 13 passed (0.02s)
     Running unittests src/lib.rs (mcp): ok. 0 passed
     Running unittests src/lib.rs (worker): ok. 8 passed (0.05s)
     Running tests/sentinel_qa.rs (integration_tests): ok. 15 passed (0.01s)
     Running unittests src/main.rs (benchmarks/accuracy_suite): ok. 0 passed
     Doc-tests core, ironwarden, mcp, worker: ok. 0 passed
Total: 103 passed; 0 failed; 0 ignored
```

### 2.4 Python End-to-End Test Suite (`pytest test_suites/`)
```
============================= test session starts ==============================
platform linux -- Python 3.10.12, pytest-9.1.1, pluggy-1.6.0
rootdir: /home/somnerd/Documents/Projects/IronWarden, configfile: pytest.ini
collected 127 items / 21 deselected / 106 selected

test_suites/isolation_attack.py PASSED (3/3)
test_suites/security_audit.py PASSED (4/4)
test_suites/test_adversarial.py PASSED (14/14)
test_suites/test_bridge.py PASSED (6/6)
test_suites/test_complex_naming.py PASSED (7/7)
test_suites/test_distributed_isolation.py PASSED (6/6)
test_suites/test_fault_injection.py PASSED (6/6)
test_suites/test_generalized.py PASSED (6/6)
test_suites/test_generalized_edge_cases.py PASSED (7/7)
test_suites/test_localization_gr.py PASSED (6/6)
test_suites/test_localization_in.py PASSED (6/6)
test_suites/test_localization_me_east_asia.py PASSED (8/8)
test_suites/test_mcp.py PASSED (5/5)
test_suites/test_proxy.py PASSED (10/10)
test_suites/test_proxy_routing.py PASSED (6/6)
test_suites/test_security.py PASSED (6/6)

====================== 106 passed, 21 deselected in 40.50s ======================
```

---

## 3. Silent Fallbacks & Swallowed Failures

### 3.1 The Silent NER Degradation Pattern
In `warden/src/ai.rs` (lines 283–323), `HybridNer::new` attempts to locate the ONNX model and tokenizer:
```rust
// warden/src/ai.rs:294-323
if model_path.exists() && tokenizer_path.exists() {
    match OnnxNer::new(model_path, tokenizer_path, threshold) {
        Ok(onnx) => {
            info!("ONNX Runtime Inference Engine: ONLINE (DistilBERT-INT8)");
            return Ok(Self {
                backend: NerBackend::Onnx(Box::new(onnx)),
                threshold,
            });
        }
        Err(e) => {
            error!("ONNX Initialization Failed: {}. Falling back to Heuristic-Only mode.", e);
        }
    }
} else {
    warn!("ONNX model files not found at {:?} / {:?}. Running in Heuristic-Only mode.", model_path, tokenizer_path);
}
Ok(Self {
    backend: NerBackend::None,
    threshold,
})
```
**Impact Chain**:
1. When `ai_enabled: true` is configured in `warden_manifest.yaml`, `HybridNerPool::new(...)` is called in `warden/src/config.rs:203`.
2. Each worker initializes with `backend: NerBackend::None` and returns `Ok(instance)`.
3. `warden/src/config.rs:205` logs: `info!("Hybrid Intelligence Pool initialized with {} workers", pool_size);`.
4. In `warden/src/engine.rs:672`, ambiguous candidates (Track B) are passed to `worker.analyze(...)`. Under `NerBackend::None`, this immediately returns empty (`Vec::new()`), silently dropping disambiguation.
5. In `worker/src/bridge.rs:390-394`, the `/health` endpoint responds with:
   ```json
   "subsystems": {
       "storage": "ok",
       "shield": "ok",
       "session_manager": "ok"
   }
   ```
   The health check has zero visibility into whether the active NER backend is `Onnx` or `None`.

### 3.2 Swallowed Failures in CI & Shell Scripts (`|| true` and `2>/dev/null`)
| File | Line | Command / Pattern | Impact |
| :--- | :---: | :--- | :--- |
| `.github/workflows/rust_ci.yml` | 62 | `cp warden/test_manifest_*.yaml integration_tests/ 2>/dev/null \|\| true` | Masks missing test manifests in CI setup |
| `.github/workflows/rust_ci.yml` | 63 | `cp app/test_manifest_legal.yaml /tmp/manifest_legal.yaml 2>/dev/null \|\| true` | Masks missing manifest file copy to `/tmp` |
| `.github/workflows/rust_ci.yml` | 65 | `cp -r /home/somnerd/.../distilbert-ner/* data/models/distilbert-ner/ 2>/dev/null \|\| true` | Silently swallows failure to seed local model weights |
| `scripts/ci_local.sh` | 210 | `cp warden/test_manifest_*.yaml integration_tests/ 2>/dev/null \|\| true` | Mirrors CI silent copy failure |
| `scripts/ci_local.sh` | 211 | `cp app/test_manifest_legal.yaml /tmp/manifest_legal.yaml 2>/dev/null \|\| true` | Mirrors CI silent copy failure |
| `scripts/ci_local.sh` | 218 | `cargo test --benches --no-run 2>/dev/null` | Silently suppresses benchmark compilation errors |
| `scripts/demo.sh` | 32–33 | `kill "$PID" 2>/dev/null \|\| true`, `wait "$PID" 2>/dev/null \|\| true` | Suppresses process cleanup errors |
| `scripts/demo.sh` | 137 | `-d "$TEST_PAYLOAD" \|\| true` | Ignores curl request failure in quickstart demo |
| `examples/curl_recipes.sh` | 26, 52 | `curl ... \| jq . \|\| true` | Ignores curl pipe failures |

### 3.3 Swallowed Failures in Rust Code (`let _ = `)
| File | Line Range | Expression | Risk / Analysis |
| :--- | :---: | :--- | :--- |
| `worker/src/bridge.rs` | 630, 664, 746, 903, 930 | `let _ = state.session_manager.save_session(&auth.username, &auth.session).await;` | **High**: Session state updates, token mappings, and counters are dropped without error handling or logging if SQLite is busy or errors |
| `worker/src/audit.rs` | 411, 418, 426, 431, 505 | `let _ = c.execute("ROLLBACK", []);` | **Medium**: Rollback failures are completely unmonitored during database transaction aborts |
| `worker/src/audit.rs` | 807 | `let _ = Self::update_anchor(path, last_id, &last_hash);` | **High**: Merkle anchor file update failures are silently dropped, risking anchor desynchronization |
| `mcp/src/server.rs` | 332, 478, 545 | `let _ = session_manager.save_session(&username, &user_session).await;` | **High**: MCP session updates are discarded without logging errors |

---

## 4. Hardcoded Absolute Paths

| Location | Path Detected | Purpose / Context | Remediation |
| :--- | :--- | :--- | :--- |
| `.github/workflows/rust_ci.yml:64-65` | `/home/somnerd/Documents/Projects/IronWarden/data/models/distilbert-ner` | Host machine model cache copy in CI | Replace with proper runner cache or `./scripts/setup_models.sh` |
| `scripts/eval_accuracy.sh:13` | `/home/somnerd/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin` | Hardcoded toolchain PATH | Prepend `$HOME/.cargo/bin` or use `rustup which cargo` |
| `test_suites/docker-compose.test.yml:6, 11` | `somnerd` (PostgreSQL user) | Database container user | Parameterize via `${POSTGRES_USER:-postgres}` |
| `test_suites/bridge_stress_test.py:21` | `USERNAME = "somnerd"` | Hardcoded test username | Parameterize via environment or random string |
| `test_suites/bridge_stress.sh:5` | `USERNAME="somnerd"` | Hardcoded test script user | Parameterize via `${TEST_USER:-test_user}` |
| `warden/src/engine.rs:58` | `/tmp/warden_llamaguard.sock` | Unix domain socket path | Parameterize via `WARDEN_LLAMAGUARD_SOCKET` env var with portable fallback |
| `.github/workflows/rust_ci.yml:63` | `/tmp/manifest_legal.yaml` | Hardcoded manifest temp path | Use repo-relative fixture path |

---

## 5. CI / CD Security Audit & Runner Assessment

### 5.1 Workflow Runner Matrix
| Workflow File | Trigger Events | Job Name | Runner Label | Untrusted PR Risk? |
| :--- | :--- | :--- | :--- | :---: |
| `.github/workflows/rust_ci.yml` | `pull_request` (branches: dev, main), `push`, `workflow_dispatch` | `lint` | `[self-hosted, linux]` | **CRITICAL** |
| `.github/workflows/rust_ci.yml` | `pull_request` (branches: dev, main), `push`, `workflow_dispatch` | `test` | `[self-hosted, linux]` | **CRITICAL** |
| `.github/workflows/benchmarks.yml` | `workflow_dispatch` | `benchmarks` | `[self-hosted, linux]` | Low (Manual maintainer trigger) |
| `.github/workflows/benchmarks.yml` | `workflow_dispatch` | `coverage` | `[self-hosted, linux]` | Low (Manual maintainer trigger) |
| `.github/workflows/docker_publish.yml` | `push` (main, v*.*.*), `workflow_dispatch` | `build-and-push` | `[self-hosted, linux]` | Low (Protected branch push) |
| `.github/workflows/release.yml` | `push` (v*.*.*), `workflow_dispatch` | `build-and-package` | `[self-hosted, linux]` | Low (Protected tag push) |
| `.github/workflows/release.yml` | `push` (v*.*.*), `workflow_dispatch` | `publish-release` | `[self-hosted, linux]` | Low (Protected tag push) |

### 5.2 Critical Vulnerability: Self-Hosted Runner on Fork Pull Requests
- **Vulnerability**: In `.github/workflows/rust_ci.yml`, the `pull_request` trigger runs on `[self-hosted, linux]`. When an external contributor opens a pull request against `dev` or `main`, GitHub Actions provisions the job on Nikolas's workstation (`somnerd`).
- **Exploitation**: The workflow executes `cargo test` and `pytest`. Any PR author can submit modified build scripts (`build.rs`), Rust unit tests, or Python test files containing arbitrary shell execution payloads (e.g., extracting SSH keys, inspecting local `/home/somnerd/` files, or pivoting onto the local private network).
- **Mandatory Remediation**:
  1. Change `pull_request` workflows to `runs-on: ubuntu-latest` (GitHub-hosted runners).
  2. Restrict `self-hosted` runners exclusively to trusted push events on protected branches (`refs/heads/main`, `refs/heads/dev`) or manual `workflow_dispatch` requiring maintainer review.

---

## 6. Truthfulness Audit: Docs & README Claims

### 6.1 Unsubstantiated Competitor Claims (`README.md` Architectural Comparison)
| Competitor | Claimed Memory | Claimed Concurrency / Limitations | Committed Evidence | Audit Finding |
| :--- | :---: | :--- | :---: | :--- |
| **Python Proxies (LiteLLM)** | `~140 MB+ baseline` | "GIL lock, garbage collection overhead", "Buffers stream or high-latency regex", "Plaintext JSON files" | None | **UNVERIFIED**: No benchmark scripts or comparative test results exist in repo |
| **Node.js Gateways (Portkey)** | `~110 MB+ baseline` | "Single-threaded event loop, GC sweeps", "Buffers stream or post-hoc inspection", "Cloud SaaS telemetry" | None | **UNVERIFIED**: No comparative test harness exists in repo |
| **Reverse Proxies (Kong)** | `~85 MB baseline` | "Manual memory (C/Lua) or Go GC", "Plugin-dependent / Lua regex", "Standard web access logs" | None | **UNVERIFIED**: No comparative test harness exists in repo |

*Remediation*: Remove unverified competitor memory numbers and assertions or explicitly label them as qualitative industry estimates.

### 6.2 Unverified Memory Footprint Numbers
- Claim: `~28.4 MB RSS (Heuristic Mode)` and `~142.0 MB RSS (Hybrid ONNX NER Mode)` in `README.md` (lines 26, 240, 241) and `BENCHMARKS.md` (lines 22, 23, 131, 132).
- Committed Source: Grep across the repository reveals no raw heap profiling output, memory test script, or `/proc/$PID/status` log backing up these exact figures.
- *Status*: **UNVERIFIED**. Must be labeled as estimates or validated with a committed memory benchmark script.

### 6.3 Compliance & Certification Claims
- `core/src/fips.rs`:
  ```rust
  pub fn verify_readiness() -> Result<(), SovereignError> {
      if !Self::is_fips_enabled() { return Ok(()); }
      info!("FIPS Compliance Mode: ENABLED. Verifying cryptographic environment...");
      let openssl_fips = std::env::var("OPENSSL_FIPS").unwrap_or_default();
      if openssl_fips != "1" && openssl_fips != "yes" {
          warn!("FIPS: OPENSSL_FIPS is not set to 1. External dependencies might not be in FIPS mode.");
      }
      info!("FIPS: Restricting TLS to version 1.2+ with approved ciphers...");
      Ok(())
  }
  ```
- *Audit Finding*: Claiming "FIPS 140-2/3 Readiness" or "Verifiable cryptographic audit trail for EU AI Act" or "HIPAA / PCI-DSS Turnkey Compliance" implies formal regulatory certification. In reality, IronWarden provides configurable regex and dictionary filters for PII categories (such as credit card numbers and medical keywords) and an env check for OpenSSL.
- *Remediation*: Rephrase as "Configurable PII Rule Sets for Healthcare (HIPAA-aligned) and Payment Data (PCI-aligned)" and clarify that FIPS mode requires an underlying FIPS-validated OS crypto provider.

---

## 7. Dead Code, Unused Dependencies & Oversized Modules

### 7.1 Unused Workspace Dependencies
The following dependencies are declared in crate manifests but have zero references in source code:
| Crate | Unused Dependency | Manifest Location | Remediation |
| :--- | :--- | :--- | :--- |
| `cli` | `aes-gcm` | `cli/Cargo.toml:16` | Remove from `dependencies` |
| `cli` | `chrono` | `cli/Cargo.toml:15` | Remove from `dependencies` |
| `cli` | `rand` | `cli/Cargo.toml:17` | Remove from `dependencies` |
| `app` | `dashmap` | `app/Cargo.toml:15` | Remove from `dependencies` |
| `app` | `serde_json`, `serde_yaml`, `tempfile` | `app/Cargo.toml:22-25` | Remove unused dev-dependencies |
| `core` | `secrecy` | `core/Cargo.toml:12` | Remove from `dependencies` |
| `mcp` | `dashmap` | `mcp/Cargo.toml:16` | Remove from `dependencies` |
| `warden` | `console` | `warden/Cargo.toml:25` | Remove from `dependencies` |
| `warden` | `crossbeam-channel` | `warden/Cargo.toml:14` | Remove from `dependencies` |
| `warden` | `futures` | `warden/Cargo.toml:24` | Remove from `dependencies` |
| `warden` | `once_cell` | `warden/Cargo.toml:12` | Remove (superseded by `std::sync::LazyLock`) |
| `worker` | `serde-pickle` | `worker/Cargo.toml:34` | Remove legacy pickle dependency |
| `worker` | `tantivy` | `worker/Cargo.toml:40` | Remove unused full-text search dependency |
| `worker` | `docx-rs` | `worker/Cargo.toml:53` | Remove unused docx parsing dependency |
| `worker` | `crossbeam-channel` | `worker/Cargo.toml:38` | Remove from `dependencies` |
| `worker` | `aead` | `worker/Cargo.toml:24` | Remove from `dependencies` |
| `worker` | `aes-gcm` | `worker/Cargo.toml:23` | Remove from `dependencies` |
| `worker` | `rand` | `worker/Cargo.toml:25` | Remove from `dependencies` |

### 7.2 Stale Scripts
- `scripts/create_github_issues.py`: One-off script for batch-creating issues via GitHub REST API.
- `scripts/compare_issues.py`: Stale issue state diffing tool.

### 7.3 Oversized Modules (> 400 lines)
| File | Lines | Primary Responsibilities | Refactoring Target |
| :--- | :---: | :--- | :--- |
| `warden/src/engine.rs` | 2,134 | Engine lifecycle, rule dispatch, entropy calc, canary injection, testing | Split into `engine/builder.rs`, `engine/executor.rs`, `engine/entropy.rs` |
| `worker/src/bridge.rs` | 1,477 | HTTP router, Auth/JWT handlers, health, OpenAI proxy, Anthropic proxy | Split into `bridge/handlers/openai.rs`, `handlers/anthropic.rs`, `handlers/health.rs` |
| `worker/src/grounding.rs` | 1,135 | Background queue, Redis fallback, vector indexing, query sealing | Split into `grounding/queue.rs`, `grounding/ha.rs` |
| `worker/src/audit.rs` | 1,078 | SQLite ledger, HMAC hash chaining, Merkle walk, background flusher | Split into `audit/ledger.rs`, `audit/chain.rs` |
| `worker/src/proxy.rs` | 1,015 | Reverse proxy forwarding, header filtering, upstream resolution | Extract routing logic into `proxy/router.rs` |
| `warden/src/shadow_ner.rs` | 1,013 | Heuristic regex engine, dictionary loaders, span deduplication | Split into `shadow_ner/rules.rs`, `shadow_ner/filter.rs` |
| `mcp/src/server.rs` | 998 | JSON-RPC 2.0 stdio server, tool dispatch, session management | Split into `server/dispatch.rs`, `server/tools.rs` |
| `benchmarks/accuracy_suite/src/main.rs` | 986 | Accuracy evaluation CLI and synthetic test harness | Modularize dataset generators |

---

## 8. Complete File Inventory

Every top-level file and folder is classified below:
- **(a) Code**: Application, libraries, CLI, SDK, and container definitions.
- **(b) Tests**: Test suites, test harnesses, and fixtures.
- **(c) Scripts**: Operational and CI automation scripts.
- **(d) Benchmarks**: Benchmark suites and committed raw results.
- **(e) User-Facing Docs**: Documentation intended for end users and open-source contributors.
- **(f) Internal Docs / Notes**: Maintainer notes, planning boards, and wiki archives (candidates for Notion).
- **(g) Config**: Runtime configurations, rule dictionaries, presets, and manifests.
- **(h) Generated / Junk**: Untracked build outputs, test databases, and redundant files.

### 8.1 Root Inventory
| Path | Classification | Description / Notes |
| :--- | :---: | :--- |
| `.env.example` | (g) Config | Template environment file |
| `example.env` | (g) Config / (h) Junk | Duplicate of `.env.example` (differ by only 1 comment character) |
| `.gitignore` | (g) Config | Standard gitignore configuration |
| `.pre-commit-config.yaml` | (g) Config | Pre-commit hook configuration |
| `.github/` | (g) Config / (c) Scripts | GitHub workflows, issue templates, PR template |
| `.jules/` | (f) Internal Docs/Notes | Maintainer persona prompt guidelines (`bolt.md`, `sentinel.md`) |
| `AGENTS.md` | (f) Internal Docs/Notes | Internal prompt engineering guidelines for AI coding agents |
| `BENCHMARKS.md` | (d) Benchmarks / (e) Docs | User-facing benchmark methodology and empirical results |
| `CODE_OF_CONDUCT.md` | (e) User-Facing Docs | Contributor Covenant Code of Conduct |
| `CONTRIBUTING.md` | (e) User-Facing Docs | Contributor guidelines |
| `Cargo.lock` | (g) Config | Workspace dependency lockfile |
| `Cargo.toml` | (g) Config | Workspace root configuration |
| `Dockerfile` | (a) Code / (g) Config | Multi-stage Docker packaging specification |
| `GEMINI.md` | (f) Internal Docs/Notes | Maintainer system prompt instructions |
| `LICENSE` | (e) User-Facing Docs | MIT open-source license |
| `LICENSE-COMMERCIAL.md` | (e) User-Facing Docs | Commercial dual-licensing terms |
| `MAINTAINER_NOTES.md` | (f) Internal Docs/Notes | Maintainer log, architectural roadmap, and work packages |
| `MODELS.md` | (e) User-Facing Docs | Model weights acquisition and license documentation |
| `PROXY_IMPLEMENTATION.md` | (f) Internal Docs/Notes | 35 KB deep implementation notes for proxy engine |
| `QUICKSTART.md` | (e) User-Facing Docs | Standalone quickstart guide (partially redundant with README) |
| `README.md` | (e) User-Facing Docs | Primary repository landing page |
| `RELEASE.md` | (f) Internal Docs/Notes | Maintainer release procedure checklist |
| `SECURITY.md` | (e) User-Facing Docs | Security vulnerability reporting policy |
| `docker-compose.yml` | (g) Config | Standard local container orchestration |
| `vscode_mcp_config.json` | (g) Config | VSCode MCP editor configuration |
| `app/` | (a) Code | Gateway daemon binary crate (`app`) |
| `benchmarks/` | (d) Benchmarks | Benchmark harness crate & raw result data |
| `cli/` | (a) Code | Admin CLI crate (`iw-cli`) |
| `config/` | (g) Config | Dictionaries (`dicts/`), rule presets (`rules/`), and config manifests |
| `core/` | (a) Code | Common library crate (`iw_core`) |
| `data/` | (g) Config / (d) Benchmarks | Sample documents (`data/knowledge/`), eval datasets (`data/eval/`) |
| `deploy/` | (g) Config | Helm Kubernetes deployment charts |
| `docs/` | (f) Internal Docs / (e) Docs | Repo documentation (`MASTER_NOTES.md`) |
| `examples/` | (a) Code / (e) Docs | Client integration examples (Python, LangChain, MCP) |
| `integration_tests/` | (b) Tests | Rust integration test crate (`iw-integration-tests`) |
| `knowledge/` | (f) Internal Docs/Notes | 46 internal design, architecture, and planning documents |
| `mcp/` | (a) Code | Model Context Protocol server crate (`iw_mcp`) |
| `monitoring/` | (g) Config | Prometheus & Grafana monitoring stack configs |
| `policies/` | (g) Config / (h) Junk | 3 duplicate files identical to `data/knowledge/` |
| `scripts/` | (c) Scripts | Build, CI, test, and evaluation scripts |
| `sdk/` | (a) Code | Official Python client library (`sdk/python/`) |
| `test_suites/` | (b) Tests | Python integration and end-to-end test suite |
| `warden/` | (a) Code / (b) Tests | PII engine crate (`iw-warden`) |
| `worker/` | (a) Code / (b) Tests | Gateway proxy crate (`iw_worker`) |
| `.pytest_cache/` | (h) Generated / Junk | Pytest execution cache (ignored) |
| `.venv/` | (h) Generated / Junk | Python virtual environment (ignored) |
| `.agents/` | (h) Generated / Junk | Agent dispatch logs and work state (ignored) |
| `worker/audit_test_purge_*` | (h) Generated / Junk | Leftover SQLite test artifacts (ignored) |
| `target/` | (h) Generated / Junk | Cargo build target directory (ignored) |

---

## 9. Proposed Move Map

*Note: Per Phase 0 rules, NO files are moved in this phase. The table below represents the proposed plan for Phase 2 execution following maintainer approval.*

### 9.1 File Move Table
| Old Path | Proposed New Path | Reason | Affected References to Update |
| :--- | :--- | :--- | :--- |
| `scripts/ci_local.sh` | `scripts/ci/ci_local.sh` | Group scripts by purpose | `README.md`, `CONTRIBUTING.md` |
| `scripts/setup_models.sh` | `scripts/setup/setup_models.sh` | Group scripts by purpose | `.github/workflows/rust_ci.yml`, `README.md`, `MODELS.md`, `Dockerfile` |
| `scripts/bench.sh` | `scripts/bench/bench.sh` | Group scripts by purpose | `BENCHMARKS.md` |
| `scripts/eval_accuracy.sh` | `scripts/bench/eval_accuracy.sh` | Group scripts by purpose | `BENCHMARKS.md`, `README.md` |
| `scripts/demo.sh` | `scripts/dev/demo.sh` | Group scripts by purpose | `README.md`, `QUICKSTART.md` |
| `scripts/compare_issues.py` | `scripts/dev/compare_issues.py` | Group scripts by purpose | None |
| `scripts/create_github_issues.py` | `scripts/dev/create_github_issues.py` | Group scripts by purpose | None |
| `test_suites/` (entire dir) | `tests/` | Standardize end-to-end Python test root | `.github/workflows/rust_ci.yml`, `scripts/ci_local.sh`, `.gitignore` |
| `test_suites/bridge_stress.sh` | `tests/stress/bridge_stress.sh` | Group stress tests in dedicated folder | `tests/stress/bridge_stress_test.py` |
| `test_suites/bridge_stress_test.py` | `tests/stress/bridge_stress_test.py` | Group stress tests in dedicated folder | None |
| `test_suites/docker-compose.test.yml` | `tests/docker-compose.test.yml` | Keep test infra alongside tests | `tests/conftest.py` |
| `test_suites/test_*.py` | `tests/<category>/test_*.py` | Group by integration, security, localization | `tests/conftest.py` |
| `BENCHMARKS.md` | `docs/BENCHMARKS.md` | Versioned docs directory | `README.md`, `Cargo.toml` |
| `MODELS.md` | `docs/MODELS.md` | Versioned docs directory | `README.md` |
| `QUICKSTART.md` | `docs/QUICKSTART.md` | Versioned docs directory | `README.md` |
| `.env.example` | *Delete (redundant)* | `example.env` is the canonical template | `README.md`, `docker-compose.yml` |
| `policies/` (3 files) | *Delete (redundant)* | Exact duplicate of `data/knowledge/` | None (zero references in codebase) |
| `app/test_manifest_legal.yaml` | `tests/fixtures/manifests/test_manifest_legal.yaml` | Eliminate cross-crate manifest duplication | `app/src/main.rs`, CI workflows |
| `warden/test_manifest_medical.yaml` | `tests/fixtures/manifests/test_manifest_medical.yaml` | Eliminate cross-crate manifest duplication | `warden/tests/`, CI workflows |
| `warden/test_manifest_shipping.yaml` | `tests/fixtures/manifests/test_manifest_shipping.yaml` | Eliminate cross-crate manifest duplication | `warden/tests/`, CI workflows |

### 9.2 Internal Docs Migration to Notion (Docs Policy)
Per repository guidelines, internal maintainer notes, planning artifacts, and work boards must be moved to Nikolas's Notion workspace under the IronWarden section, verified, and removed from git tracking in a dedicated PR:
1. `MAINTAINER_NOTES.md` (170 lines): Maintainer backlog, work packages, roadmap.
2. `PROXY_IMPLEMENTATION.md` (896 lines): Deep proxy architecture and implementation notes.
3. `RELEASE.md` (93 lines): Internal release SOP and checklist.
4. `AGENTS.md` (27 lines): Internal AI coding agent guidelines.
5. `GEMINI.md` (85 lines): Internal prompt instructions.
6. `.jules/bolt.md` & `.jules/sentinel.md`: Persona prompt instructions.
7. `docs/MASTER_NOTES.md`: Maintainer notes.
8. `knowledge/` (46 files): Entire historical wiki, deprecated design briefs, QA reports, and architectural specifications.

---

## 10. Ranked Proposed Changes

Ranked by security impact, engineering risk, and test coverage:

| Rank | Change Topic | Risk | Size | Test Coverage | Rationale |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **1** | **CI Security Remediation**: Move PR workflows to `ubuntu-latest` | Medium | Small | CI workflow tests | **Critical**: Eliminates arbitrary remote code execution on the maintainer's host machine via fork PRs. |
| **2** | **Explicit NER Mode & Health Inspection**: Fail hard in `require_hybrid` mode; expose active mode in `/health` | Low | Small | 28 unit tests, Python health test | **High**: Eliminates silent degradation to `NerBackend::None`; makes operational security state transparent. |
| **3** | **Eliminate Swallowed Failures**: Replace `\|\| true` and `2>/dev/null` in scripts; handle `save_session` errors | Low | Small | Full workspace test suite | **High**: Ensures failures are loudly surfaced instead of quietly corrupting state. |
| **4** | **Consolidate Test Manifests & Remove Hardcoded Paths**: Unify manifests into `tests/fixtures/`; eliminate `/home/somnerd/` references | Low | Small | Full workspace test suite | **Medium**: Restores hermetic test portability across different developer machines and standard CI runners. |
| **5** | **Docs Truthfulness & Claim Moderation**: Remove unverified competitor figures and soften compliance language | Zero | Small | Documentation | **Medium**: Eliminates unbacked claims; protects maintainer credibility. |
| **6** | **Unused Dependencies Cleanup**: Remove unused crates from workspace `Cargo.toml` manifests | Low | Small | `cargo check --workspace --all-targets` | **Low**: Reduces compile footprint and eliminates dependency bloat. |
| **7** | **Directory Structure Move (Phase 2)**: Reorganize `scripts/`, `tests/`, and `docs/` | Medium | Medium | Full Python + Rust test suite | **Medium**: Clean, maintainable layout matching engineering standards. |
| **8** | **Internal Docs Notion Migration**: Move 50+ internal docs to Notion; remove in dedicated PR | Zero | Large | Verification check | **Low**: Declutters repository root; preserves internal notes in private knowledge base. |
| **9** | **Module Decomposition (Future)**: Refactor `engine.rs` (2.1k lines), `bridge.rs` (1.4k lines), `audit.rs` (1.0k lines) | High | Large | Unit + Integration suites | **Architectural**: Improves maintainability and compiler compilation times. |

---

## 11. Remaining Questions & Decisions for Nikolas

1. **GitHub Actions Runners for Push vs PR**:
   - Proposal: Run all `pull_request` triggers on `ubuntu-latest` (GitHub-hosted). Run `push` to `main`/`dev` and `release` packaging on `[self-hosted, linux]` to maintain native hardware performance and build speed. Does this match your security boundary?
2. **Explicit NER Mode Configuration**:
   - In Phase 1, we propose three explicit modes: `heuristic`, `hybrid` (opportunistic: uses ONNX if model files exist, logs warning and falls back if missing), and `require_hybrid` (hard error: gateway refuses to start if model weights or tokenizer fail SHA-256 validation). Should `require_hybrid` be the default in `production`?
3. **Notion Migration Destination**:
   - Do you want the 46 `knowledge/` files and maintainer notes exported into a specific Notion page or database under IronWarden before opening the removal PR?
4. **Duplicate Policies**:
   - Confirm deletion of `policies/` (identical duplicate of `data/knowledge/`).
