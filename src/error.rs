// Keystone — Top-level error types
//
// Aggregates errors from the enclave and store modules into a single
// error enum for the application boundary.

use thiserror::Error;

/// Top-level error type for all Keystone operations.
#[derive(Debug, Error)]
pub enum KeystoneError {
    #[error("Enclave error: {0}")]
    Enclave(#[from] crate::enclave::EnclaveError),

    #[error("Store error: {0}")]
    Store(#[from] crate::store::StoreError),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, KeystoneError>;
