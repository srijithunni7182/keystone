// Keystone — Enclave Module
//
// Handles platform-native master key storage and Argon2id key derivation.
// The master secret is stored in the OS keyring (Keychain/DPAPI/libsecret)
// and never leaves kernel-protected memory in plaintext.

mod error;
mod provider;

pub use error::EnclaveError;
pub use provider::{KeyringProvider, MasterKeyProvider};
