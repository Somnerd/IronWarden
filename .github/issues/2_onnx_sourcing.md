# Title: [DX] Implement automated bootstrap/setup script for BERT-NER ONNX weights

## Category: Developer Experience (DX) / Setup

## Description
To perform Hybrid NER scanning, IronWarden relies on local ONNX model weights (`model.onnx` and `tokenizer.json`).

Committing binary model files (often 100MB+ in size) directly to a git repository is a major anti-pattern:
1. It bloats the git history and makes repository cloning extremely slow for developers and CI/CD pipelines.
2. Binary files cannot be diffed cleanly by git, leading to repository bloating over time.

We need a dedicated initialization script (`setup.sh` or `setup.py`) or a Cargo build script task that automatically downloads the required BERT-NER ONNX weights from a public model repository (like Hugging Face) and maps them to the local `data/models/` path.

## Remediation Plan
1. Create a script `scripts/setup_models.sh` or python equivalent that checks for the existence of `data/models/model.onnx` and `data/models/tokenizer.json`.
2. If missing, automatically download them (e.g. from `https://huggingface.co/optimum/distilbert-base-uncased-NER/resolve/main/model.onnx`).
3. Document this setup step in `README.md` under the "Installation" section so new users can get started with a single command.
