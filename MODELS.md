# 🧠 IronWarden AI Models & Asset Licensing

IronWarden uses a **Hybrid Intelligence Architecture** combining fast deterministic pattern heuristics with local ONNX transformer models.

This document details the lifecycle, upstream sources, licenses, and fallback modes for all machine learning assets used by IronWarden.

---

## 📦 Upstream Models & Licenses

IronWarden does **NOT** bundle proprietary or copyleft model binaries in repository releases. All optional ONNX models are permissively licensed open-source models fetched directly from their official upstream repositories.

| Model / Asset | Architecture | Purpose | Upstream Source & Card | Upstream License |
| :--- | :--- | :--- | :--- | :--- |
| **DistilBERT NER (Quantized)** | INT8 Quantized DistilBERT | Probabilistic Named Entity Recognition (Persons, Organizations, Locations) | [optimum/distilbert-base-uncased-finetuned-ner](https://huggingface.co/optimum/distilbert-base-uncased-finetuned-ner) | **Apache 2.0** |
| **WordPiece Tokenizer** | DistilBERT Tokenizer JSON | Text Tokenization & Subword Mapping | [distilbert-base-uncased](https://huggingface.co/distilbert-base-uncased) | **Apache 2.0** |

---

## 🔒 Integrity Verification (SHA-256 Checksums)

When running `./scripts/setup_models.sh`, files are downloaded over HTTPS and verified against cryptographic SHA-256 checksums:

```text
data/models/distilbert-ner/model_quantized.onnx
SHA-256: 2ff638639abe90e83ea079443393df9d2d2e1e04b0904946c4578c0cabd0f7c4

data/models/distilbert-ner/tokenizer.json
SHA-256: 343989712a36cd8b253efeaf8baf6a08b9d2583f78e395e83832e8ee9f8d8ee1
```

---

## ⚡ Zero-Dependency / Heuristic-Only Demo Mode

If model weights are not downloaded, IronWarden **automatically runs in Heuristic-Only mode**:

* **Zero Download Requirement**: You can clone the repository, run `cargo run --bin app`, and start intercepting traffic immediately.
* **Coverage in Heuristic Mode**:
  - Deterministic PII redaction (SSN, credit cards, emails, phone numbers, IBANs, AMKA, government IDs).
  - Aho-Corasick dictionary lookups and multi-lingual homoglyph normalization.
  - Immutable HMAC-SHA256 audit chaining and AES-256-GCM context encryption.
* **When to enable Hybrid NER mode**:
  - Run `./scripts/setup_models.sh` when you want contextual entity recognition for arbitrary personal names, organizations, and location entities that cannot be matched by static regex rules alone.
