#!/usr/bin/env bash
# =============================================================================
# IronWarden — Performance Benchmark Runner
# Measures latency overhead, token rehydration throughput, and memory footprint.
# =============================================================================

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo ""
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BLUE}${BOLD}  🏰 IronWarden Benchmark Suite (Criterion.rs)${RESET}"
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# Ensure release build for accurate measurements
echo -e "${BOLD}▶ Running Criterion Benchmarks across all crates...${RESET}\n"

cargo bench --workspace -- --verbose

echo ""
echo -e "${GREEN}${BOLD}✔ Benchmark execution complete!${RESET}"
echo -e "  Detailed HTML reports available in: ${BOLD}target/criterion/${RESET}"
