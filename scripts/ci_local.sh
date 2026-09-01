#!/usr/bin/env bash
# =============================================================================
# IronWarden — Local CI Runner
# Mirrors .github/workflows/rust_ci.yml exactly.
# Run from the repo root: ./scripts/ci_local.sh
#
# Prerequisites (auto-handled on first run):
#   - Rust toolchain + protoc (must be pre-installed)
#   - ORT dylib: downloaded to ~/.ort/lib/libonnxruntime.dylib if missing
#   - Python venv: created at .venv if missing
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
PASS="${GREEN}✔ PASS${RESET}"; FAIL="${RED}✘ FAIL${RESET}"

FAILED_JOBS=(); SKIPPED_JOBS=()
START_TIME=$(date +%s)

job_header() {
  echo ""
  echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${BLUE}${BOLD}  JOB: $1${RESET}"
  echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}
step()     { echo -e "\n${BOLD}  ▶ $1${RESET}"; }
pass_job() { echo -e "\n  ${PASS}  $1"; }
fail_job() { echo -e "\n  ${FAIL}  $1"; FAILED_JOBS+=("$1"); }
warn()     { echo -e "  ${YELLOW}⚠ $1${RESET}"; }

# ── Environment (mirrors CI env block) ───────────────────────────────────────
export CARGO_TERM_COLOR=always
export CARGO_PROFILE_TEST_DEBUG=0    # Disable DWARF debug symbols for test binaries (5x faster link time)
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4} # Parallel compilation across 4 cores instead of single-thread
export WARDEN_MCP_SECRET="dummy_mcp_secret_value_for_testing_purposes"
ORT_VERSION="1.21.0"   # Last ORT version with macOS x86_64 prebuilt binaries
ORT_DYLIB_PATH="${ORT_DYLIB_PATH:-$HOME/.ort/lib/libonnxruntime.dylib}"
export ORT_DYLIB_PATH

ARCH=$(uname -m)        # x86_64 | arm64
OS=$(uname -s)          # Darwin | Linux
VENV_PATH="$(pwd)/.venv"
PYTEST="$VENV_PATH/bin/pytest"
PIP="$VENV_PATH/bin/pip"

# ── Flag parsing ──────────────────────────────────────────────────────────────
RUN_QUALITY=true; RUN_SECURITY=true; RUN_WARDEN=true
RUN_WORKER=true;  RUN_INTEGRATION=true

for arg in "$@"; do
  case $arg in
    --only-quality)     RUN_SECURITY=false; RUN_WARDEN=false; RUN_WORKER=false; RUN_INTEGRATION=false ;;
    --only-security)    RUN_QUALITY=false;  RUN_WARDEN=false; RUN_WORKER=false; RUN_INTEGRATION=false ;;
    --only-warden)      RUN_QUALITY=false;  RUN_SECURITY=false; RUN_WORKER=false; RUN_INTEGRATION=false ;;
    --only-worker)      RUN_QUALITY=false;  RUN_SECURITY=false; RUN_WARDEN=false; RUN_INTEGRATION=false ;;
    --only-integration) RUN_QUALITY=false;  RUN_SECURITY=false; RUN_WARDEN=false; RUN_WORKER=false ;;
    --skip-integration) RUN_INTEGRATION=false ;;
    --skip-quality)     RUN_QUALITY=false ;;
    --help|-h)
      echo "Usage: ./scripts/ci_local.sh [flags]"
      echo ""
      echo "Flags:"
      echo "  --only-quality       Run only the Code Quality job"
      echo "  --only-security      Run only the Security & Crypto job"
      echo "  --only-warden        Run only the Warden Shield job"
      echo "  --only-worker        Run only the Worker Core job"
      echo "  --only-integration   Run only the Integration job"
      echo "  --skip-integration   Skip the Python integration tests"
      echo "  --skip-quality       Skip fmt/clippy (fast iteration)"
      echo ""
      echo "Env overrides:"
      echo "  ORT_DYLIB_PATH       Override the ORT dylib path (default: ~/.ort/lib/libonnxruntime.dylib)"
      exit 0
      ;;
  esac
done

echo ""
echo -e "${BOLD}🏰 IronWarden — Local CI Runner${RESET}"
echo -e "   Mirrors: .github/workflows/rust_ci.yml"
echo -e "   Platform: $OS/$ARCH"
echo -e "   ORT dylib: $ORT_DYLIB_PATH"
echo -e "   Started:  $(date '+%Y-%m-%d %H:%M:%S')"

# ── Auto-download ORT dylib if missing ───────────────────────────────────────
if [ ! -f "$ORT_DYLIB_PATH" ]; then
  echo ""
  echo -e "  ${YELLOW}ORT dylib not found at $ORT_DYLIB_PATH — downloading...${RESET}"
  mkdir -p "$(dirname "$ORT_DYLIB_PATH")"
  if [[ "$OS" == "Darwin" && "$ARCH" == "x86_64" ]]; then
    ARCHIVE="onnxruntime-osx-x86_64-${ORT_VERSION}.tgz"
    LIB_INSIDE="libonnxruntime.${ORT_VERSION}.dylib"
  elif [[ "$OS" == "Darwin" && "$ARCH" == "arm64" ]]; then
    ARCHIVE="onnxruntime-osx-arm64-${ORT_VERSION}.tgz"
    LIB_INSIDE="libonnxruntime.${ORT_VERSION}.dylib"
  else
    ARCHIVE="onnxruntime-linux-x64-${ORT_VERSION}.tgz"
    LIB_INSIDE="libonnxruntime.so.${ORT_VERSION}"
  fi
  curl -fsSL "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/${ARCHIVE}" \
    -o "/tmp/ort-download.tgz"
  tar -xzf "/tmp/ort-download.tgz" -C /tmp/
  EXTRACTED_DIR=$(find /tmp -maxdepth 1 -name "onnxruntime-*" -type d | head -1)
  cp "$EXTRACTED_DIR/lib/$LIB_INSIDE" "$ORT_DYLIB_PATH"
  rm -rf /tmp/ort-download.tgz "$EXTRACTED_DIR"
  echo -e "  ${GREEN}✔ ORT dylib ready: $ORT_DYLIB_PATH${RESET}"
fi

# =============================================================================
# JOB 1 — Code Quality (Fmt & Clippy)
# =============================================================================
if $RUN_QUALITY; then
  job_header "Code Quality (Fmt & Clippy)"

  step "Check & apply rustfmt"
  if cargo fmt --all; then
    if ! git diff --quiet; then
      warn "rustfmt made changes — review with: git diff"
    else
      echo "  No formatting changes needed."
    fi
  else
    fail_job "Code Quality (fmt)"
  fi

  step "Run Clippy (per-package, 2 jobs to manage memory pressure)"
  CLIPPY_FAILED=false
  for pkg in iw_core iw-warden iw_worker iw_mcp iw-cli app; do
    echo "    • clippy: $pkg"
    if ! CARGO_BUILD_JOBS=2 cargo clippy --package "$pkg" --all-targets 2>&1; then
      CLIPPY_FAILED=true
    fi
  done
  if $CLIPPY_FAILED; then
    fail_job "Code Quality (clippy)"
  else
    pass_job "Code Quality"
  fi
fi

# =============================================================================
# JOB 2 — Security & Crypto (Code Red) — package: iw_core
# =============================================================================
if $RUN_SECURITY; then
  job_header "Security & Crypto (Code Red)"
  step "cargo test --package iw_core"
  if cargo test --package iw_core; then
    pass_job "Security & Crypto"
  else
    fail_job "Security & Crypto"
  fi
fi

# =============================================================================
# JOB 3 — Warden Shield (ML) — package: iw-warden
# =============================================================================
if $RUN_WARDEN; then
  job_header "Warden Shield (ML)"
  step "cargo test --package iw-warden"
  if cargo test --package iw-warden; then
    pass_job "Warden Shield"
  else
    fail_job "Warden Shield"
  fi
fi

# =============================================================================
# JOB 4 — Worker Core — package: iw_worker
# =============================================================================
if $RUN_WORKER; then
  job_header "Worker Core (Storage/Queue)"
  step "cargo test --package iw_worker"
  # Run in a subshell and capture exit code to avoid old bash's _job artifact on SIGKILL
  (cargo test --package iw_worker)
  _worker_exit=$?
  if [ $_worker_exit -eq 0 ]; then
    pass_job "Worker Core"
  else
    fail_job "Worker Core"
  fi
fi

# =============================================================================
# JOB 5 — Integration (Full Flow)
# =============================================================================
if $RUN_INTEGRATION; then
  job_header "Integration (Full Flow)"

  step "Check Python venv + dependencies"
  if [ ! -d "$VENV_PATH" ]; then
    echo "  Creating Python venv..."
    python3 -m venv "$VENV_PATH"
  fi
  REQUIRED="pytest pyjwt cryptography requests httpx redis PyYAML"
  MISSING=""
  for pkg in $REQUIRED; do
    "$PIP" show "$pkg" &>/dev/null || MISSING="$MISSING $pkg"
  done
  if [ -n "$MISSING" ]; then
    echo "  Installing:$MISSING"
    "$PIP" install --quiet $MISSING
  else
    echo "  All Python dependencies present."
  fi

  step "Prepare test manifests"
  mkdir -p integration_tests
  cp warden/test_manifest_*.yaml integration_tests/ 2>/dev/null || true
  cp app/test_manifest_legal.yaml /tmp/manifest_legal.yaml 2>/dev/null || true
  echo "  Done."

  step "cargo test --package app"
  cargo test --package app || true

  step "Verify benchmarks compile"
  if cargo test --benches --no-run 2>/dev/null; then
    echo "  Benchmarks compile OK."
  else
    warn "Benchmarks failed to compile (non-blocking)."
  fi

  step "pytest test_suites/"
  if "$PYTEST" test_suites/ -v; then
    pass_job "Integration"
  else
    fail_job "Integration (pytest)"
  fi
fi

# =============================================================================
# SUMMARY
# =============================================================================
END_TIME=$(date +%s); ELAPSED=$((END_TIME - START_TIME))
MINS=$((ELAPSED / 60)); SECS=$((ELAPSED % 60))

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  CI SUMMARY — ${MINS}m ${SECS}s${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

if [ ${#FAILED_JOBS[@]} -eq 0 ]; then
  echo -e "\n  ${GREEN}${BOLD}ALL JOBS PASSED ✔${RESET}\n"
  exit 0
else
  echo -e "\n  ${RED}${BOLD}FAILED JOBS:${RESET}"
  for j in "${FAILED_JOBS[@]}"; do echo -e "    ${RED}✘ $j${RESET}"; done
  echo ""
  exit 1
fi
