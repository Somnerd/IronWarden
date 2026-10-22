#!/usr/bin/env bash
# ==============================================================================
# IronWarden — Benchmark & Test Longitudinal Tracker
# Executes tests, microbenchmarks, and accuracy suites, appending date/time
# indexed metrics to `benchmarks/history/benchmark_history.csv`.
# ==============================================================================

set -euo pipefail

export PATH="/home/somnerd/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$HOME/.cargo/bin:$PATH"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Ensure Python 3 is available
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 is required to run the historical benchmark tracker." >&2
    exit 1
fi

python3 scripts/bench/track_history.py "$@"
