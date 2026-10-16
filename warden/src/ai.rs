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

#[derive(Debug, Clone)]
pub struct Entity {
    pub word: String,
    pub score: f64,
    pub label: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NerMode {
    Heuristic,
    Hybrid,
    RequireHybrid,
}

impl NerMode {
    pub fn from_env() -> Result<Self, String> {
        match std::env::var("WARDEN_NER_MODE").as_deref() {
            Ok("heuristic") => Ok(Self::Heuristic),
            Ok("hybrid") | Ok("") | Err(_) => Ok(Self::Hybrid),
            Ok("require_hybrid") => Ok(Self::RequireHybrid),
            Ok(other) => Err(format!(
                "Invalid WARDEN_NER_MODE '{}': expected 'heuristic', 'hybrid', or 'require_hybrid'",
                other
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Heuristic => "heuristic",
            Self::Hybrid => "hybrid",
            Self::RequireHybrid => "require_hybrid",
        }
    }
}

pub enum NerBackend {
    Onnx(Box<OnnxNer>),
    None,
}

impl std::fmt::Debug for NerBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Onnx(_) => write!(f, "NerBackend::Onnx"),
            Self::None => write!(f, "NerBackend::None"),
        }
    }
}

static ORT_INIT: std::sync::Once = std::sync::Once::new();

#[repr(C)]
struct OrtApiBase {
    get_api: unsafe extern "C" fn(u32) -> *const ort_sys::OrtApi,
    get_version_string: unsafe extern "C" fn() -> *const std::ffi::c_char,
}

fn ensure_ort_initialized() {
    ORT_INIT.call_once(|| {
        let home_lib = std::env::var("HOME")
            .map(|h| format!("{}/lib/libonnxruntime.so", h))
            .unwrap_or_default();
        let candidates = [
            std::env::var("ORT_DYLIB_PATH").unwrap_or_default(),
            home_lib,
            "/usr/lib/libonnxruntime.so".to_string(),
            "/usr/local/lib/libonnxruntime.so".to_string(),
            "libonnxruntime.so".to_string(),
        ];
        for cand in &candidates {
            if !cand.is_empty() && (Path::new(cand).exists() || cand == "libonnxruntime.so") {
                if let Ok(c_path) = std::ffi::CString::new(cand.as_str()) {
                    let handle = unsafe {
                        libc::dlopen(
                            c_path.as_ptr(),
                            libc::RTLD_NOW | libc::RTLD_GLOBAL | libc::RTLD_NODELETE,
                        )
                    };
                    if !handle.is_null() {
                        let sym = unsafe { libc::dlsym(handle, c"OrtGetApiBase".as_ptr()) };
                        if !sym.is_null() {
                            let get_api_base: unsafe extern "C" fn() -> *const OrtApiBase =
                                unsafe { std::mem::transmute(sym) };
                            let base = unsafe { &*get_api_base() };
                            let api = unsafe { &*(base.get_api)(20) };
                            let _ = ort::set_api(api.clone());
                            return;
                        }
                    }
                }
            }
        }
        let _ = ort::init().commit();
    });
}

pub struct OnnxNer {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    threshold: f64,
}
impl OnnxNer {
    pub fn new(model_path: &Path, tokenizer_path: &Path, threshold: f64) -> Result<Self, String> {
        ensure_ort_initialized();

        let builder =
            Session::builder().map_err(|e| format!("Failed to create ONNX builder: {}", e))?;
        let mut builder = builder
            .with_intra_threads(1)
            .map_err(|e| format!("Failed to set intra_threads: {}", e))?
            .with_inter_threads(1)
            .map_err(|e| format!("Failed to set inter_threads: {}", e))?
            .with_intra_op_spinning(false)
            .map_err(|e| format!("Failed to disable intra_op_spinning: {}", e))?
            .with_inter_op_spinning(false)
            .map_err(|e| format!("Failed to disable inter_op_spinning: {}", e))?;

        let session = builder
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
                    if end > last.end {
                        last.end = end;
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
                start,
                end,
            });
        }

        entities
    }
}

#[derive(Debug)]
pub struct HybridNer {
    backend: NerBackend,
    #[allow(dead_code)]
    threshold: f64,
    mode: NerMode,
}

impl HybridNer {
    pub fn requested_mode(&self) -> &'static str {
        self.mode.as_str()
    }

    pub fn effective_backend(&self) -> &'static str {
        match self.backend {
            NerBackend::Onnx(_) => "onnx",
            NerBackend::None => "heuristic",
        }
    }

    pub fn new(threshold: f64) -> Result<Self, String> {
        let mode = NerMode::from_env()?;
        let disable_onnx = std::env::var("WARDEN_DISABLE_ONNX").is_ok()
            || (std::env::var("WARDEN_ENV").as_deref() == Ok("test")
                && std::env::var("WARDEN_ENABLE_ONNX_TEST").is_err()
                && mode != NerMode::RequireHybrid);

        if mode == NerMode::RequireHybrid && std::env::var("WARDEN_DISABLE_ONNX").is_ok() {
            return Err(
                "WARDEN_NER_MODE=require_hybrid conflicts with WARDEN_DISABLE_ONNX".to_string(),
            );
        }

        if mode == NerMode::Heuristic || disable_onnx {
            info!("NER Mode: requested={}, effective=heuristic", mode.as_str());
            return Ok(Self {
                backend: NerBackend::None,
                threshold,
                mode,
            });
        }

        // Attempt ONNX (the only supported path post-V1.3)
        let model_path = if Path::new("data/models/distilbert-ner/model_quantized.onnx").exists() {
            Path::new("data/models/distilbert-ner/model_quantized.onnx")
        } else {
            Path::new("../data/models/distilbert-ner/model_quantized.onnx")
        };
        let tokenizer_path = if Path::new("data/models/distilbert-ner/tokenizer.json").exists() {
            Path::new("data/models/distilbert-ner/tokenizer.json")
        } else {
            Path::new("../data/models/distilbert-ner/tokenizer.json")
        };

        Self::new_with_paths(threshold, mode, model_path, tokenizer_path)
    }

    pub fn new_with_paths(
        threshold: f64,
        mode: NerMode,
        model_path: &Path,
        tokenizer_path: &Path,
    ) -> Result<Self, String> {
        if mode == NerMode::Heuristic {
            return Ok(Self {
                backend: NerBackend::None,
                threshold,
                mode,
            });
        }

        if model_path.exists() && tokenizer_path.exists() {
            match OnnxNer::new(model_path, tokenizer_path, threshold) {
                Ok(onnx) => {
                    info!(
                        "ONNX Runtime Inference Engine: ONLINE (requested_mode={}, effective_backend=onnx)",
                        mode.as_str()
                    );
                    Ok(Self {
                        backend: NerBackend::Onnx(Box::new(onnx)),
                        threshold,
                        mode,
                    })
                }
                Err(e) => {
                    if mode == NerMode::RequireHybrid {
                        Err(format!(
                            "ONNX Initialization Failed in require_hybrid mode: {}",
                            e
                        ))
                    } else {
                        error!(
                            "ONNX Initialization Failed: {}. Falling back to Heuristic-Only mode.",
                            e
                        );
                        Ok(Self {
                            backend: NerBackend::None,
                            threshold,
                            mode,
                        })
                    }
                }
            }
        } else if mode == NerMode::RequireHybrid {
            Err(format!(
                "ONNX model files required by WARDEN_NER_MODE=require_hybrid but missing at {:?} / {:?}",
                model_path, tokenizer_path
            ))
        } else {
            warn!(
                "ONNX model files not found at {:?} / {:?}. Running in Heuristic-Only mode.",
                model_path, tokenizer_path
            );
            Ok(Self {
                backend: NerBackend::None,
                threshold,
                mode,
            })
        }
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
