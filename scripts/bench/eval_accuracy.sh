#!/usr/bin/env bash
# ==============================================================================
# IronWarden Shield Accuracy & Recall Evaluation Harness
# Evaluates PII Shield detection accuracy across:
#   1. Synthetic Sovereign Structural PII & Zero-Tolerance Negative Controls
#   2. CoNLL-2003 Test Split (Standard News NER)
#   3. WikiGold Test Split (Wikipedia Unstructured NER)
#   4. 100,000-Iteration Multilingual Combinatorial Matrix (GR/EN/AR/ZH)
#   5. EVAL 5: Adversarial & Messy Enterprise Slice Suite (1,000 Prompts: 5A-5E)
# ==============================================================================
set -euo pipefail

export PATH="/home/somnerd/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$HOME/.cargo/bin:$PATH"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "=== IronWarden Accuracy Evaluation Harness ==="
echo "Working directory: $REPO_ROOT"

# Ensure eval datasets exist
if [ ! -f "data/eval/conll2003_eval.jsonl" ] || \
   [ ! -f "data/eval/wikigold_eval.jsonl" ] || \
   [ ! -f "data/eval/multilingual_name_lexicon.json" ] || \
   [ ! -f "data/eval/synthetic_structural_pii.jsonl" ]; then
    echo "ERROR: Evaluation datasets not found in data/eval/" >&2
    exit 1
fi

mkdir -p benchmarks/raw

echo "Running full release evaluation suite..."
cargo run --release -p iw-accuracy-suite

echo ""
echo "=== Accuracy Evaluation Complete ==="
echo "Raw results stored in: benchmarks/raw/accuracy_eval_results.json"
