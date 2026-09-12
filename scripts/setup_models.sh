#!/usr/bin/env bash
# ==============================================================================
# setup_models.sh — IronWarden ONNX Model Downloader
# ==============================================================================
# Downloads the INT8 quantized DistilBERT NER model weights and tokenizer.
#
# UPSTREAM ASSETS & LICENSES:
# - Model: optimum/distilbert-base-uncased-finetuned-ner (ONNX INT8 Quantized)
#   Source: https://huggingface.co/optimum/distilbert-base-uncased-finetuned-ner
#   License: Apache 2.0 (Hugging Face / Optimum)
#
# - Tokenizer: distilbert-base-uncased/tokenizer.json
#   Source: https://huggingface.co/distilbert-base-uncased
#   License: Apache 2.0 (Hugging Face)
#
# NOTE: IronWarden does NOT bundle model weights directly in repository releases.
# If these files are omitted, IronWarden automatically falls back to Heuristic-Only
# mode (deterministic pattern matching & regex rules) for lightweight execution.
# ==============================================================================

set -euo pipefail

MODEL_DIR="data/models/distilbert-ner"
MODEL_URL="https://huggingface.co/onnx-community/distilbert-NER-ONNX/resolve/main/onnx/model_quantized.onnx"
TOKENIZER_URL="https://huggingface.co/onnx-community/distilbert-NER-ONNX/resolve/main/tokenizer.json"

MODEL_FILE="$MODEL_DIR/model_quantized.onnx"
TOKENIZER_FILE="$MODEL_DIR/tokenizer.json"

MODEL_SHA256="9419a876387ff2bbe5f21ab7429c7bef93eac86c50353390d4d8fca6e4a210d8"
TOKENIZER_SHA256="cb26b43c98e8266ae3e99c2a583cf8315d73b33a17e6b20b4df7ff1f22392d34"

echo "=========================================================="
echo "🏰 IronWarden Model Setup (DistilBERT-NER INT8 Quantized)"
echo "License: Apache 2.0 (Hugging Face / Optimum)"
echo "=========================================================="

mkdir -p "$MODEL_DIR"

verify_checksum() {
    local file=$1
    local expected=$2

    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        echo "⚠️ Warning: Neither sha256sum nor shasum found. Skipping integrity check."
        return 0
    fi

    if [ "$actual" != "$expected" ]; then
        echo "❌ Checksum mismatch for $file!"
        echo "   Expected: $expected"
        echo "   Actual:   $actual"
        return 1
    fi
    echo "✅ Verified SHA-256 for $(basename "$file")"
}

download_file() {
    local url=$1
    local dest=$2
    local expected_hash=$3

    if [ -f "$dest" ]; then
        echo "📁 File $dest already exists. Verifying checksum..."
        if verify_checksum "$dest" "$expected_hash"; then
            return 0
        fi
        echo "Re-downloading $dest due to checksum mismatch..."
    fi

    echo "⬇️ Downloading $(basename "$dest") from $url..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url"
    else
        echo "❌ Error: Neither curl nor wget is installed."
        exit 1
    fi

    verify_checksum "$dest" "$expected_hash"
}

download_file "$MODEL_URL" "$MODEL_FILE" "$MODEL_SHA256"
download_file "$TOKENIZER_URL" "$TOKENIZER_FILE" "$TOKENIZER_SHA256"

echo "=========================================================="
echo "✅ Setup complete! Models ready for Hybrid NER mode."
echo "💡 Tip: Without these weights, IronWarden runs in Heuristic-Only demo mode."
echo "=========================================================="
