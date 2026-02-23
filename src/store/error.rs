// Keystone — Store error types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Credential not found: {0}")]
    NotFound(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Credential expired")]
    Expired,

    #[error("Approval required for request ID: {0}")]
    ApprovalRequired(uuid::Uuid),

    #[error("Database not initialized — run `keystone init` first")]
    NotInitialized,

    #[error("Invalid database key — database may be corrupted or key is wrong")]
    InvalidKey,

    #[error("{0}")]
    Other(String),
}
