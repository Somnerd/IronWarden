use rust_bert::pipelines::ner::NERModel;
use tracing::{info, error};

pub struct Entity {
    pub word: String,
    pub score: f64,
    pub label: String,
}

pub struct HybridNer {
    model: Option<NERModel>,
    threshold: f64,
}

impl HybridNer {
    pub fn new(threshold: f64) -> Result<Self, String> {
        info!("Initializing Local BERT-NER Engine (Fail-Soft Mode)...");

        // Use a standard pre-trained model for NER (English)
        let model = tokio::task::block_in_place(|| {
            NERModel::new(Default::default())
        });

        match model {
            Ok(m) => {
                info!("BERT-NER Physical Inference Engine: ONLINE");
                Ok(Self {
                    model: Some(m),
                    threshold,
                })
            }
            Err(e) => {
                error!("BERT-NER Initialization Failed: {}. Falling back to Heuristic-Only mode.", e);
                Ok(Self {
                    model: None,
                    threshold,
                })
            }
        }
    }

    pub fn analyze(&self, text: &str) -> Vec<Entity> {
        let model = match &self.model {
            Some(m) => m,
            None => return Vec::new(),
        };

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

    pub fn validate_miss(
        &self, 
        miss: &iw_core::traits::PotentialMiss, 
        _text: &str, 
        _session: Option<&iw_core::SessionContext>
    ) -> Option<Entity> {
        let model = match &self.model {
            Some(m) => m,
            None => return None,
        };

        let results = model.predict(&[&miss.text]);
        
        if let Some(entities) = results.first() {
            let best = entities.iter()
                .filter(|e| e.score >= self.threshold)
                .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap());
            
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
            if instance.model.is_some() {
                info!("AI Worker #{} initialized.", i);
            }
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
