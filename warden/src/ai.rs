use ort::session::Session;
use ort::value::Tensor;
use std::path::Path;
use std::sync::Mutex;
use tokenizers::Tokenizer;
use tracing::{error, info, warn};

/// NER label set for DistilBERT-NER (CoNLL-2003 standard).
/// Index 0 = O (outside), then B-/I- pairs for PER, ORG, LOC, MISC.
const NER_LABELS: &[&str] = &[
    "O", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC", "B-MISC", "I-MISC",
];

pub struct Entity {
    pub word: String,
    pub score: f64,
    pub label: String,
}

pub enum NerBackend {
    Onnx(Box<OnnxNer>),
    None,
}

pub struct OnnxNer {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    threshold: f64,
}

impl OnnxNer {
    pub fn new(model_path: &Path, tokenizer_path: &Path, threshold: f64) -> Result<Self, String> {
        info!("Loading ONNX NER Model from {:?}...", model_path);

        let session = Session::builder()
            .map_err(|e| format!("Failed to create ONNX builder: {}", e))?
            .with_intra_threads(2)
            .map_err(|e| format!("Failed to set threads: {}", e))?
            .commit_from_file(model_path)
            .map_err(|e| format!("Failed to load ONNX model: {}", e))?;

        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| format!("Failed to load tokenizer: {}", e))?;

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            threshold,
        })
    }

    pub fn predict(&self, text: &str) -> Vec<Entity> {
        let encoding = match self.tokenizer.encode(text, true) {
            Ok(e) => e,
            Err(e) => {
                warn!("Tokenization failed: {}. Returning empty entities.", e);
                return Vec::new();
            }
        };

        let ids = encoding.get_ids();
        let attention = encoding.get_attention_mask();
        let tokens = encoding.get_tokens();
        let offsets = encoding.get_offsets();
        let seq_len = ids.len();

        // Build input tensors using ort's native (shape, Vec) API — no ndarray needed.
        let shape = vec![1i64, seq_len as i64];
        let ids_data: Vec<i64> = ids.iter().map(|&id| id as i64).collect();
        let mask_data: Vec<i64> = attention.iter().map(|&m| m as i64).collect();

        let input_ids_tensor = match Tensor::from_array((shape.clone(), ids_data)) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to create input_ids tensor: {}", e);
                return Vec::new();
            }
        };

        let attention_mask_tensor = match Tensor::from_array((shape, mask_data)) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to create attention_mask tensor: {}", e);
                return Vec::new();
            }
        };

        // Run ONNX inference via named inputs.
        let mut session = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let outputs = match session.run(ort::inputs! {
            "input_ids" => input_ids_tensor,
            "attention_mask" => attention_mask_tensor
        }) {
            Ok(o) => o,
            Err(e) => {
                // --- SECURITY FIX (Finding 3): OOM returns an error instead of abort() ---
                error!(
                    "ONNX inference failed (possible OOM): {}. Failing closed.",
                    e
                );
                return Vec::new();
            }
        };

        // Extract logits from the first output.
        // SessionOutputs implements Index<usize>, returning a DynValue.
        let logits_value = &outputs[0usize];

        let (logits_shape, logits_data) = match logits_value.try_extract_tensor::<f32>() {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to extract logits tensor: {}", e);
                return Vec::new();
            }
        };

        // Expected shape: [1, seq_len, num_labels]
        if logits_shape.len() != 3 || logits_shape[0] != 1 {
            error!("Unexpected logits shape: {:?}", logits_shape);
            return Vec::new();
        }
        let num_labels = logits_shape[2] as usize;

        // Process each token (skip [CLS] at 0 and [SEP] at end)
        let mut entities: Vec<Entity> = Vec::new();
        for i in 1..(seq_len.saturating_sub(1)) {
            // Logits for token i are at offset: i * num_labels
            let base = i * num_labels;

            // Find argmax
            let mut max_idx = 0usize;
            let mut max_val = f32::NEG_INFINITY;
            for j in 0..num_labels {
                let val = logits_data[base + j];
                if val > max_val {
                    max_val = val;
                    max_idx = j;
                }
            }

            // Compute softmax score for the winning label
            let mut sum_exp = 0.0f64;
            for j in 0..num_labels {
                sum_exp += ((logits_data[base + j] - max_val) as f64).exp();
            }
            let score = 1.0 / sum_exp;

            // Skip "O" (outside) labels and low-confidence predictions
            if max_idx == 0 || score < self.threshold {
                continue;
            }

            let label = NER_LABELS.get(max_idx).unwrap_or(&"O");
            if *label == "O" {
                continue;
            }

            let token_text = &tokens[i];
            let (start, end) = offsets[i];

            // Extract the original text span
            let word = if start < text.len() && end <= text.len() && start < end {
                text[start..end].to_string()
            } else {
                token_text.replace("##", "")
            };

            // Merge with previous entity if this is an I- continuation
            if label.starts_with("I-") && !entities.is_empty() {
                let last = entities.last_mut().unwrap();
                let base_label = &label[2..];
                if last.label.ends_with(base_label) {
                    // Merge: extend the word
                    if token_text.starts_with("##") {
                        last.word.push_str(&word);
                    } else {
                        last.word.push(' ');
                        last.word.push_str(&word);
                    }
                    // Keep the higher score
                    if score > last.score {
                        last.score = score;
                    }
                    continue;
                }
            }

            entities.push(Entity {
                word,
                score,
                label: label.to_string(),
            });
        }

        entities
    }
}

pub struct HybridNer {
    backend: NerBackend,
    #[allow(dead_code)]
    threshold: f64,
}

impl HybridNer {
    pub fn new(threshold: f64) -> Result<Self, String> {
        // Attempt ONNX (the only supported path post-V1.3)
        let model_path = Path::new("data/models/distilbert-ner/model_quantized.onnx");
        let tokenizer_path = Path::new("data/models/distilbert-ner/tokenizer.json");

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
                    error!(
                        "ONNX Initialization Failed: {}. Falling back to Heuristic-Only mode.",
                        e
                    );
                }
            }
        } else {
            warn!(
                "ONNX model files not found at {:?} / {:?}. Running in Heuristic-Only mode.",
                model_path, tokenizer_path
            );
        }

        // --- SECURITY FIX (Finding 3): LibTorch removed entirely ---
        // No LibTorch fallback. If ONNX fails, we run heuristic-only.
        // This prevents C++ abort() from crashing the gateway on VRAM OOM.
        Ok(Self {
            backend: NerBackend::None,
            threshold,
        })
    }

    pub fn analyze(&self, text: &str) -> Vec<Entity> {
        match &self.backend {
            NerBackend::Onnx(onnx) => onnx.predict(text),
            NerBackend::None => Vec::new(),
        }
    }

    pub fn validate_miss(
        &self,
        miss: &iw_core::traits::PotentialMiss,
        _text: &str,
        _session: Option<&iw_core::SessionContext>,
    ) -> Option<Entity> {
        match &self.backend {
            NerBackend::Onnx(onnx) => {
                let entities = onnx.predict(&miss.text);
                entities.into_iter().max_by(|a, b| {
                    a.score
                        .partial_cmp(&b.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
            }
            NerBackend::None => None,
        }
    }
}

/// A thread-safe pool for managing multiple AI model instances.
/// This abolishes the global AI mutex (WP #76).
pub struct HybridNerPool {
    sender: flume::Sender<HybridNer>,
    receiver: flume::Receiver<HybridNer>,
}

impl HybridNerPool {
    pub fn new(threshold: f64, count: usize) -> Result<Self, String> {
        info!("Initializing AI Worker Pool with {} instances...", count);
        let (tx, rx) = flume::bounded(count);

        for i in 0..count {
            let instance = HybridNer::new(threshold)?;
            info!("AI Worker #{} initialized.", i);
            tx.send(instance).map_err(|e| e.to_string())?;
        }

        Ok(Self {
            sender: tx,
            receiver: rx,
        })
    }

    pub async fn get(&self) -> Option<HybridNer> {
        // --- SECURITY FIX (Section 4): Decoupled AI Circuit Breaker ---
        // Uses tokio::time::timeout on the receiver side rather than blocking a worker thread.
        // Falls back to Aho-Corasick immediately on 25ms timeout.
        tokio::time::timeout(
            std::time::Duration::from_millis(25),
            self.receiver.recv_async(),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
    }

    pub fn release(&self, instance: HybridNer) {
        let _ = self.sender.send(instance);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_ai_pool_concurrent_access() {
        // This test ensures the HybridNerPool can be accessed concurrently without deadlocks
        // We'll initialize a pool with 2 instances and spawn 10 concurrent requests.
        // Note: In an environment without ONNX models, this will fall back to NerBackend::None,
        // which still tests the concurrency logic of the pool itself (channel send/recv).
        let pool = Arc::new(HybridNerPool::new(0.85, 2).unwrap());

        let mut handles = vec![];
        for i in 0..10 {
            let pool_clone = pool.clone();
            handles.push(tokio::spawn(async move {
                // Try to acquire an instance
                if let Some(instance) = pool_clone.get().await {
                    // Simulate work
                    let _ = instance.analyze(&format!("Test input {}", i));
                    // Yield to simulate async delay
                    tokio::task::yield_now().await;
                    // Release instance back to pool
                    pool_clone.release(instance);
                    true
                } else {
                    false
                }
            }));
        }

        let mut success_count = 0;
        for handle in handles {
            if handle.await.unwrap_or(false) {
                success_count += 1;
            }
        }

        // Since we are running concurrently, some might timeout (25ms) if the CI is slow,
        // but we expect at least SOME successes, and crucially: NO deadlocks or panics.
        assert!(
            success_count > 0,
            "Expected at least one successful pool acquisition"
        );
    }
}
