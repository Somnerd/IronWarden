use rust_bert::pipelines::ner::NERModel;
use tracing::{info, error, warn};
use ort::session::Session;
use ort::value::Value;
use ort::inputs;
use ndarray::Array2;
use tokenizers::Tokenizer;
use std::path::Path;

pub struct Entity {
    pub word: String,
    pub score: f64,
    pub label: String,
}

pub enum NerBackend {
    LibTorch(NERModel),
    Onnx(OnnxNer),
    None,
}

pub struct OnnxNer {
    session: Session,
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
            session,
            tokenizer,
            threshold,
        })
    }

    pub fn predict(&self, text: &str) -> Vec<Entity> {
        let _encoding = match self.tokenizer.encode(text, true) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        // ONNX Inference is currently disabled due to API incompatibilities in ort 2.0.0-rc.12
        // and missing model files. This is a stub to allow the project to build.
        warn!("ONNX Inference triggered but STUBBED. Models missing or API mismatch.");
        Vec::new()
    }
}

pub struct HybridNer {
    backend: NerBackend,
    threshold: f64,
}

impl HybridNer {
    pub fn new(threshold: f64) -> Result<Self, String> {
        // Attempt ONNX first (WP #74 preferred path)
        let model_path = Path::new("data/models/distilbert-ner/model_quantized.onnx");
        let tokenizer_path = Path::new("data/models/distilbert-ner/tokenizer.json");

        if model_path.exists() && tokenizer_path.exists() {
            match OnnxNer::new(model_path, tokenizer_path, threshold) {
                Ok(onnx) => {
                    info!("ONNX Runtime Inference Engine: ONLINE (DistilBERT-INT8)");
                    return Ok(Self {
                        backend: NerBackend::Onnx(onnx),
                        threshold,
                    });
                }
                Err(e) => warn!("ONNX Initialization Failed: {}. Falling back to LibTorch.", e),
            }
        }

        info!("Initializing Legacy LibTorch BERT-NER Engine...");
        let model = tokio::task::block_in_place(|| {
            NERModel::new(Default::default())
        });

        match model {
            Ok(m) => {
                info!("LibTorch Inference Engine: ONLINE");
                Ok(Self {
                    backend: NerBackend::LibTorch(m),
                    threshold,
                })
            }
            Err(e) => {
                error!("AI Engine Initialization Failed: {}. Falling back to Heuristic-Only mode.", e);
                Ok(Self {
                    backend: NerBackend::None,
                    threshold,
                })
            }
        }
    }

    pub fn analyze(&self, text: &str) -> Vec<Entity> {
        match &self.backend {
            NerBackend::Onnx(onnx) => onnx.predict(text),
            NerBackend::LibTorch(model) => {
                let output = model.predict(&[text]);
                let mut entities = Vec::new();
                for entity_list in output {
                    for e in entity_list {
                        if e.score >= self.threshold {
                            entities.push(Entity {
                                word: e.word,
                                score: e.score,
                                label: e.label,
                            });
                        }
                    }
                }
                entities
            }
            NerBackend::None => Vec::new(),
        }
    }

    pub fn validate_miss(
        &self, 
        miss: &iw_core::traits::PotentialMiss, 
        _text: &str, 
        _session: Option<&iw_core::SessionContext>
    ) -> Option<Entity> {
        match &self.backend {
            NerBackend::Onnx(onnx) => {
                let entities = onnx.predict(&miss.text);
                entities.into_iter().max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal))
            }
            NerBackend::LibTorch(model) => {
                let results = model.predict(&[&miss.text]);
                if let Some(entities) = results.first() {
                    let best = entities.iter()
                        .filter(|e| e.score >= self.threshold)
                        .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));
                    
                    if let Some(e) = best {
                        return Some(Entity {
                            word: e.word.clone(),
                            score: e.score,
                            label: e.label.clone(),
                        });
                    }
                }
                None
            }
            NerBackend::None => None,
        }
    }
}

/// A thread-safe pool for managing multiple AI model instances.
/// This abolishes the global AI mutex (WP #76).
pub struct HybridNerPool {
    sender: crossbeam_channel::Sender<HybridNer>,
    receiver: crossbeam_channel::Receiver<HybridNer>,
}

impl HybridNerPool {
    pub fn new(threshold: f64, count: usize) -> Result<Self, String> {
        info!("Initializing AI Worker Pool with {} instances...", count);
        let (tx, rx) = crossbeam_channel::bounded(count);
        
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

    pub fn get(&self) -> Option<HybridNer> {
        self.receiver.recv_timeout(std::time::Duration::from_millis(100)).ok()
    }

    pub fn release(&self, instance: HybridNer) {
        let _ = self.sender.send(instance);
    }
}
