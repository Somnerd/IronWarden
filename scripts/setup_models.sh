#!/bin/bash

# setup_models.sh
# Downloads the BERT-NER ONNX model weights and tokenizer for IronWarden's Hybrid NER mode.

set -e

MODEL_DIR="data/models/distilbert-ner"
MODEL_URL="https://huggingface.co/optimum/distilbert-base-uncased-finetuned-ner/resolve/main/model_quantized.onnx"
TOKENIZER_URL="https://huggingface.co/distilbert-base-uncased/resolve/main/tokenizer.json"

MODEL_FILE="$MODEL_DIR/model_quantized.onnx"
TOKENIZER_FILE="$MODEL_DIR/tokenizer.json"

echo "Checking for BERT-NER ONNX weights in $MODEL_DIR..."

if [ ! -d "$MODEL_DIR" ]; then
    echo "Directory $MODEL_DIR does not exist. Creating it..."
    mkdir -p "$MODEL_DIR"
fi

download_file() {
    local url=$1
    local dest=$2

    if [ -f "$dest" ]; then
        echo "File $dest already exists. Skipping download."
    else
        echo "Downloading $url to $dest..."
        if command -v curl >/dev/null 2>&1; then
            curl -L -o "$dest" "$url"
        elif command -v wget >/dev/null 2>&1; then
            wget -O "$dest" "$url"
        else
            echo "Error: Neither curl nor wget is installed."
            exit 1
        fi

        # Verify file size > 0
        if [ ! -s "$dest" ]; then
            echo "Error: Downloaded file $dest is empty or failed."
            rm -f "$dest"
            exit 1
        fi
        echo "Successfully downloaded $(basename "$dest")."
    fi
}

download_file "$MODEL_URL" "$MODEL_FILE"
download_file "$TOKENIZER_URL" "$TOKENIZER_FILE"

echo "Setup complete! Models are ready for Hybrid NER mode."
