use async_trait::async_trait;
use iw_core::{InferenceGateway, SovereignError};
use reqwest::Client;
use serde_json::json;

/// An InferenceGateway implementation for interacting with OpenAI-compatible APIs.
pub struct OpenAIGateway {
    client: Client,
    api_key: String,
    base_url: String,
}

impl OpenAIGateway {
    /// Creates a new OpenAIGateway instance.
    pub fn new(api_key: String, base_url: String) -> Self {
        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to build reqwest client");

        Self {
            client,
            api_key,
            base_url,
        }
    }
}

#[async_trait]
impl InferenceGateway for OpenAIGateway {
    async fn route_prompt(&self, prompt: &str, context: &[String]) -> Result<String, SovereignError> {
        // --- INTEGRITY FIX: Removed IRONWARDEN_MOCK simulation path ---

        // Construct the grounding instruction from the provided context strings
        let system_context = context.join("\n");
        
        // Build the OpenAI-compatible JSON payload dynamically using the json! macro
        let payload = json!({
            "model": "gpt-4",
            "messages": [
                {
                    "role": "system",
                    "content": format!("You are a secure assistant. Use the following context to provide factual answers: \n\n{}", system_context)
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        });

        // Execute the POST request with the required Authorization header
        let response = self.client
            .post(&self.base_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&payload)
            .send()
            .await
            .map_err(|e| SovereignError::GatewayTimeout(format!("Network Failure: {}", e)))?;

        // Catch non-success status codes and convert to UpstreamError
        if !response.status().is_success() {
            let status = response.status();
            return Err(SovereignError::UpstreamError(format!("Upstream API returned HTTP {}", status)));
        }

        // Parse the JSON response body safely
        let response_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| SovereignError::UpstreamError(format!("Failed to parse JSON response: {}", e)))?;

        // Extract choices[0].message.content deterministically
        response_body["choices"][0]["message"]["content"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| SovereignError::UpstreamError("Incompatible response format: choices[0].message.content not found".to_string()))
    }
}
