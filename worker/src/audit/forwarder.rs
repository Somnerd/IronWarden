use chrono::Utc;
use iw_core::{ScrubbingReport, SovereignError};

/// Trait for off-box audit log streaming.
#[async_trait::async_trait]
pub trait RemoteAuditForwarder: Send + Sync {
    async fn forward_log(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        integrity_hash: &[u8],
        report: &ScrubbingReport,
        username: &str,
    ) -> Result<(), SovereignError>;
}

/// Production-grade HTTP Forwarder for SIEM/Log Aggregator integration.

#[derive(serde::Serialize)]
pub struct AuditPayload<'a> {
    ciphertext: String,
    nonce: String,
    integrity_hash: String,
    is_blocked: bool,
    redactions_count: usize,
    execution_time_ms: u64,
    timestamp: String,
    username: &'a str,
}

pub struct HttpAuditForwarder {
    client: reqwest::Client,
    endpoint: String,
    token: secrecy::SecretString,
}

impl HttpAuditForwarder {
    pub fn new(endpoint: String, token: secrecy::SecretString) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint,
            token,
        }
    }
}

#[async_trait::async_trait]
impl RemoteAuditForwarder for HttpAuditForwarder {
    async fn forward_log(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        integrity_hash: &[u8],
        report: &ScrubbingReport,
        username: &str,
    ) -> Result<(), SovereignError> {
        use secrecy::ExposeSecret;
        let payload = AuditPayload {
            ciphertext: hex::encode(ciphertext),
            nonce: hex::encode(nonce),
            integrity_hash: hex::encode(integrity_hash),
            is_blocked: report.is_blocked,
            redactions_count: report.redactions.len(),
            execution_time_ms: report.execution_time_ms,
            timestamp: Utc::now().to_rfc3339(),
            username,
        };

        let res = self
            .client
            .post(&self.endpoint)
            .header(
                "Authorization",
                format!("Bearer {}", self.token.expose_secret()),
            )
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                SovereignError::InternalError(format!("Remote Audit Streaming Failed: {}", e))
            })?;

        if !res.status().is_success() {
            return Err(SovereignError::InternalError(format!(
                "Remote Audit Endpoint returned error status: {}",
                res.status()
            )));
        }

        Ok(())
    }
}
