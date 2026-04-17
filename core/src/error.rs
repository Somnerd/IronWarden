use thiserror::Error;

#[derive(Error, Debug)]
pub enum SovereignError {
    #[error("PII Violation: {0}")]
    PiiViolation(String),

    #[error("Gateway Timeout: {0}")]
    GatewayTimeout(String),

    #[error("Upstream Error: {0}")]
    UpstreamError(String),

    #[error("Storage Error: {0}")]
    StorageError(String),

    #[error("Unauthorized Access: {0}")]
    UnauthorizedAccess(String),

    #[error("Internal Error: {0}")]
    InternalError(String),
}
