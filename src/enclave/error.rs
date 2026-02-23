// Keystone — Enclave error types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnclaveError {
    #[error("Keyring error: {0}")]
    Keyring(String),

    #[error("Key derivation error: {0}")]
    Derivation(String),

    #[error("Master secret not found — run `keystone init` first")]
    MasterSecretNotFound,

    #[error("Entropy error: generated secret has insufficient entropy ({0} bytes, expected {1})")]
    InsufficientEntropy(usize, usize),
}
