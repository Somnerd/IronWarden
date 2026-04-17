/// A mock implementation of the LanceDB grounding provider for the current sprint.
pub struct LanceDbProvider;

impl LanceDbProvider {
    pub fn new() -> Self {
        Self
    }

    /// Mock method to fetch grounding context.
    pub fn fetch_mock_context(&self) -> Vec<String> {
        vec!["Company Policy: Do not share passwords".to_string()]
    }
}

impl Default for LanceDbProvider {
    fn default() -> Self {
        Self::new()
    }
}
