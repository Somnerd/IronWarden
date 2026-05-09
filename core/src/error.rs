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

    #[error("Database Busy: {0}")]
    DatabaseBusy(String),

    #[error("Unauthorized Access: {0}")]
    UnauthorizedAccess(String),

    #[error("Configuration Error: {0}")]
    ConfigError(String),

    #[error("Audit Integrity Failure: {0}")]
    AuditError(String),

    #[error("Normalization Failure: {0}")]
    NormalizationError(String),

    #[error("Internal Error: {0}")]
    InternalError(String),
}
