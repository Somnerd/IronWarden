pub struct Entity { pub word: String, pub score: f64, pub label: String }
pub struct HybridNer { _c: f64 }
impl HybridNer {
    pub fn new(c: f64) -> Result<Self, String> { Ok(Self { _c: c }) }
    pub fn analyze(&self, _t: &str) -> Vec<Entity> { Vec::new() }
    pub fn validate_miss(&self, m: &iw_core::traits::PotentialMiss, _t: &str, _s: Option<&iw_core::traits::SessionContext>) -> Option<Entity> { None }
}
