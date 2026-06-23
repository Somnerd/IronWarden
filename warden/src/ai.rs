use tracing::{info, error, warn};
use ort::session::Session;
use ort::value::Tensor;
use tokenizers::Tokenizer;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

const NER_LABELS: &[&str] = &[
    "O",
    "B-PER", "I-PER",
    "B-ORG", "I-ORG",
    "B-LOC", "I-LOC",
    "B-MISC", "I-MISC",
];

pub struct Entity {
    pub word: String,
    pub score: f64,
    pub label: String,
}

pub struct NerRequest {
    pub text: bytes::Bytes,
    pub reply_to: oneshot::Sender<Vec<Entity>>,
}

struct OnnxNerActor {
    session: Session,
    tokenizer: Tokenizer,
    threshold: f64,
    receiver: mpsc::Receiver<NerRequest>,
}

impl OnnxNerActor {
    fn new(model_path: &Path, tokenizer_path: &Path, threshold: f64, receiver: mpsc::Receiver<NerRequest>) -> Result<Self, String> {
        info!("Loading ONNX NER Model from {:?}...", model_path);
        let session = Session::builder()
            .map_err(|e| format!("Failed to create ONNX builder: {}", e))?
            .with_intra_threads(1)
            .map_err(|e| format!("Failed to set threads: {}", e))?
            .commit_from_file(model_path)
            .map_err(|e| format!("Failed to load ONNX model: {}", e))?;

        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| format!("Failed to load tokenizer: {}", e))?;

        Ok(Self {
            session,
            tokenizer,
            threshold,
            receiver,
        })
    }

    fn run(mut self) {
        while let Some(req) = self.receiver.blocking_recv() {
            let text_str = match std::str::from_utf8(&req.text) {
                Ok(s) => s,
                Err(_) => {
                    let _ = req.reply_to.send(Vec::new());
                    continue;
                }
            };
            let entities = self.predict(text_str);
            let _ = req.reply_to.send(entities);
        }
    }

    fn predict(&mut self, text: &str) -> Vec<Entity> {
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

        let shape = vec![1i64, seq_len as i64];
        let ids_data: Vec<i64> = ids.iter().map(|&id| id as i64).collect();
        let mask_data: Vec<i64> = attention.iter().map(|&m| m as i64).collect();

        let input_ids_tensor = match Tensor::from_array((shape.clone(), ids_data)) {
            Ok(t) => t,
            Err(e) => return Vec::new(),
        };

        let attention_mask_tensor = match Tensor::from_array((shape, mask_data)) {
            Ok(t) => t,
            Err(e) => return Vec::new(),
        };

        let outputs = match self.session.run(ort::inputs! {
            "input_ids" => input_ids_tensor,
            "attention_mask" => attention_mask_tensor
        }) {
            Ok(o) => o,
            Err(e) => {
                error!("ONNX inference failed (possible OOM): {}. Failing closed.", e);
                return Vec::new();
            }
        };

        let logits_value = &outputs[0usize];
        let (logits_shape, logits_data) = match logits_value.try_extract_tensor::<f32>() {
            Ok(result) => result,
            Err(e) => return Vec::new(),
        };

        if logits_shape.len() != 3 || logits_shape[0] != 1 {
            return Vec::new();
        }
        let num_labels = logits_shape[2] as usize;

        let mut entities: Vec<Entity> = Vec::new();
        for i in 1..(seq_len.saturating_sub(1)) {
            let base = i * num_labels;
            let mut max_idx = 0usize;
            let mut max_val = f32::NEG_INFINITY;
            for j in 0..num_labels {
                let val = logits_data[base + j];
                if val > max_val {
                    max_val = val;
                    max_idx = j;
                }
            }

            let mut sum_exp = 0.0f64;
            for j in 0..num_labels {
                sum_exp += ((logits_data[base + j] - max_val) as f64).exp();
            }
            let score = 1.0 / sum_exp;

            if max_idx == 0 || score < self.threshold {
                continue;
            }

            let label = NER_LABELS.get(max_idx).unwrap_or(&"O");
            if *label == "O" {
                continue;
            }

            let token_text = &tokens[i];
            let (start, end) = offsets[i];
            let word = if start < text.len() && end <= text.len() && start < end {
                text[start..end].to_string()
            } else {
                token_text.replace("##", "")
            };

            if label.starts_with("I-") && !entities.is_empty() {
                let last = entities.last_mut().unwrap();
                let base_label = &label[2..];
                if last.label.ends_with(base_label) {
                    if token_text.starts_with("##") {
                        last.word.push_str(&word);
                    } else {
                        last.word.push(' ');
                        last.word.push_str(&word);
                    }
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

pub struct HybridNerPool {
    senders: Vec<mpsc::Sender<NerRequest>>,
    next_idx: AtomicUsize,
    threshold: f64,
}

impl HybridNerPool {
    pub fn new(threshold: f64, count: usize) -> Result<Self, String> {
        let model_path = Path::new("data/models/distilbert-ner/model_quantized.onnx");
        let tokenizer_path = Path::new("data/models/distilbert-ner/tokenizer.json");

        if !model_path.exists() || !tokenizer_path.exists() {
            warn!("ONNX model files not found. Running in Heuristic-Only mode.");
            return Ok(Self {
                senders: Vec::new(),
                next_idx: AtomicUsize::new(0),
                threshold,
            });
        }

        info!("Initializing AI Actor Pool with {} instances...", count);
        let mut senders = Vec::with_capacity(count);

        for i in 0..count {
            let (tx, rx) = mpsc::channel(100);
            let actor = OnnxNerActor::new(model_path, tokenizer_path, threshold, rx)?;
            std::thread::Builder::new()
                .name(format!("ml-actor-{}", i))
                .spawn(move || actor.run())
                .map_err(|e| e.to_string())?;
            senders.push(tx);
        }

        Ok(Self {
            senders,
            next_idx: AtomicUsize::new(0),
            threshold,
        })
    }

    pub async fn analyze_async(&self, text: bytes::Bytes) -> Option<Vec<Entity>> {
        if self.senders.is_empty() {
            return None;
        }

        let idx = self.next_idx.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        let (reply_tx, reply_rx) = oneshot::channel();
        
        let req = NerRequest {
            text,
            reply_to: reply_tx,
        };

        if self.senders[idx].send(req).await.is_err() {
            return None;
        }

        // Circuit breaker: 25ms timeout
        tokio::time::timeout(std::time::Duration::from_millis(25), reply_rx)
            .await
            .ok()
            .and_then(|r| r.ok())
    }
}
