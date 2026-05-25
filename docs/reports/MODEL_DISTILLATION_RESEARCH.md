# Research Report: Model Distillation & Quantization for IronWarden V1.2
**Status:** In Progress (WP #74)
**Target:** 440+ RPS on 16GB RAM Standalone Appliance

## 1. Objective
Reduce the memory footprint and inference latency of the current BERT-NER model (`dbmdz/bert-large-cased-finetuned-conll03-english`) to support the high-throughput requirements of the IronWarden Sovereign stack.

## 2. Proposed Strategy: Knowledge Distillation
Transition from a "Large" Teacher model to a "Tiny" Student model:
- **Teacher:** BERT-Large (24 layers, 1024 hidden, 340M parameters)
- **Student:** DistilBERT or TinyBERT (4-6 layers, 312-768 hidden, 14M-66M parameters)
- **Method:** Use the Teacher model to generate "soft targets" for the student during training on private domain-specific data (unredacted logs, legal documents).

## 3. Optimization: 8-bit Quantization (INT8)
Using the `ort` (ONNX Runtime) backend, we can apply static or dynamic quantization:
- **Current:** FP32 (Full Precision)
- **Target:** INT8 (8-bit Integer)
- **Benefit:** ~4x reduction in model size (~400MB -> ~100MB) and 2-3x speedup on CPU-only hardware.

## 4. Performance Projection
| Metric | Current (BERT-Large) | Target (DistilBERT-INT8) |
| :--- | :--- | :--- |
| Model Size | 1.3 GB | ~60 MB |
| Latency (128 seq) | ~150ms | ~15ms |
| Max Throughput | ~6 RPS/core | ~60+ RPS/core |

## 5. Next Steps
1. Export DistilBERT-NER to ONNX format.
2. Apply quantization using `onnxruntime` tools.
3. Integrate the quantized model into the `warden` AI pool.
4. Benchmark against the 440 RPS target.
