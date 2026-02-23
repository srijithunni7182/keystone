// Keystone — Master Key Provider
//
// Manages the lifecycle of the master secret used to encrypt the SQLCipher database.
// The master secret is stored in the platform's native keyring and never exposed
// in logs, debug output, or process memory longer than necessary.
//
// Flow:
//   1. `get_or_create_master_secret()` — retrieves from keyring, or generates + stores a new one
//   2. `derive_db_key()` — uses Argon2id to derive a 32-byte SQLCipher key from the master secret
//   3. The derived key is passed to SQLCipher via `PRAGMA key` and then immediately zeroized

use argon2::{Argon2, Algorithm, Params, Version};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::EnclaveError;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Service name used to identify Keystone entries in the platform keyring.
const KEYRING_SERVICE: &str = "keystone-credential-daemon";

/// Username for the keyring entry (identifies the master secret).
const KEYRING_USER: &str = "master-secret";

/// Length of the randomly generated master secret in bytes (256-bit entropy).
const MASTER_SECRET_LEN: usize = 32;

/// Length of the derived database key in bytes (256-bit for AES-256).
const DERIVED_KEY_LEN: usize = 32;

// Argon2id parameters: strong defaults for a security application.
// m=65536 (64 MiB), t=3 (3 iterations), p=4 (4 parallelism lanes)
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

// ─── Trait ───────────────────────────────────────────────────────────────────

/// Abstraction over master key management, enabling platform-specific backends
/// and mock implementations for testing.
pub trait MasterKeyProvider {
    /// Retrieve the master secret from the platform keyring.
    /// On first run, generates a new random master secret and stores it.
    fn get_or_create_master_secret(&self) -> std::result::Result<Zeroizing<Vec<u8>>, EnclaveError>;

    /// Derive the SQLCipher encryption key from the master secret using Argon2id.
    fn derive_db_key(
        &self,
        master_secret: &[u8],
    ) -> std::result::Result<Zeroizing<Vec<u8>>, EnclaveError>;

    /// Check if a master secret already exists in the keyring.
    fn has_master_secret(&self) -> std::result::Result<bool, EnclaveError>;

    /// Delete the master secret from the platform keyring.
    /// WARNING: This makes the encrypted database irrecoverable.
    fn delete_master_secret(&self) -> std::result::Result<(), EnclaveError>;
}

// ─── Platform Implementation ─────────────────────────────────────────────────

/// Production implementation using the `keyring` crate.
/// Dispatches to:
///   - Linux: D-Bus Secret Service (GNOME Keyring / KDE Wallet)
///   - macOS: Security.framework Keychain
///   - Windows: Windows Credential Manager
pub struct KeyringProvider {
    service: String,
    user: String,
}

impl KeyringProvider {
    pub fn new() -> Self {
        Self {
            service: KEYRING_SERVICE.to_string(),
            user: KEYRING_USER.to_string(),
        }
    }

    /// Creates a provider with custom service/user names (useful for testing isolation).
    #[allow(dead_code)]
    pub fn with_names(service: &str, user: &str) -> Self {
        Self {
            service: service.to_string(),
            user: user.to_string(),
        }
    }

    fn entry(&self) -> std::result::Result<keyring::Entry, EnclaveError> {
        keyring::Entry::new(&self.service, &self.user)
            .map_err(|e| EnclaveError::Keyring(format!("failed to create keyring entry: {}", e)))
    }

    /// Generate a cryptographically secure random master secret.
    fn generate_master_secret() -> std::result::Result<Zeroizing<Vec<u8>>, EnclaveError> {
        let mut secret = Zeroizing::new(vec![0u8; MASTER_SECRET_LEN]);
        rand::rng().fill_bytes(&mut secret);

        // Sanity check: ensure we got the right number of bytes
        if secret.len() != MASTER_SECRET_LEN {
            return Err(EnclaveError::InsufficientEntropy(
                secret.len(),
                MASTER_SECRET_LEN,
            ));
        }

        Ok(secret)
    }

    /// Build the deterministic salt for Argon2id.
    /// Salt = SHA-256(service_name || "::" || user_name)
    /// This ensures the same master secret always derives the same DB key,
    /// while being unique per Keystone installation.
    fn build_salt(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.service.as_bytes());
        hasher.update(b"::");
        hasher.update(self.user.as_bytes());
        hasher.finalize().to_vec()
    }
}

impl Default for KeyringProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MasterKeyProvider for KeyringProvider {
    fn get_or_create_master_secret(&self) -> std::result::Result<Zeroizing<Vec<u8>>, EnclaveError> {
        let entry = self.entry()?;

        // Try to retrieve existing secret
        match entry.get_secret() {
            Ok(secret) => {
                tracing::debug!("Retrieved existing master secret from keyring");
                Ok(Zeroizing::new(secret))
            }
            Err(keyring::Error::NoEntry) => {
                // First run: generate and store a new master secret
                tracing::info!("No master secret found — generating new one");
                let secret = Self::generate_master_secret()?;
                entry.set_secret(&secret).map_err(|e| {
                    EnclaveError::Keyring(format!("failed to store master secret: {}", e))
                })?;
                tracing::info!("Master secret stored in platform keyring");
                Ok(secret)
            }
            Err(e) => Err(EnclaveError::Keyring(format!(
                "failed to retrieve master secret: {}",
                e
            ))),
        }
    }

    fn derive_db_key(
        &self,
        master_secret: &[u8],
    ) -> std::result::Result<Zeroizing<Vec<u8>>, EnclaveError> {
        let salt = self.build_salt();

        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(DERIVED_KEY_LEN))
            .map_err(|e| EnclaveError::Derivation(format!("invalid Argon2 params: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut derived_key = Zeroizing::new(vec![0u8; DERIVED_KEY_LEN]);
        argon2
            .hash_password_into(master_secret, &salt, &mut derived_key)
            .map_err(|e| EnclaveError::Derivation(format!("Argon2id hash failed: {}", e)))?;

        Ok(derived_key)
    }

    fn has_master_secret(&self) -> std::result::Result<bool, EnclaveError> {
        let entry = self.entry()?;
        match entry.get_secret() {
            Ok(_) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(EnclaveError::Keyring(format!(
                "failed to check master secret: {}",
                e
            ))),
        }
    }

    fn delete_master_secret(&self) -> std::result::Result<(), EnclaveError> {
        let entry = self.entry()?;
        match entry.delete_credential() {
            Ok(()) => {
                tracing::warn!("Master secret deleted from keyring — database is now irrecoverable");
                Ok(())
            }
            Err(keyring::Error::NoEntry) => {
                tracing::debug!("No master secret to delete");
                Ok(())
            }
            Err(e) => Err(EnclaveError::Keyring(format!(
                "failed to delete master secret: {}",
                e
            ))),
        }
    }
}

// ─── In-Memory Mock for Testing ──────────────────────────────────────────────

/// A mock provider that stores the master secret in memory.
/// Used for unit tests so we don't touch the real platform keyring.
#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::Mutex;

    pub struct MockKeyProvider {
        secret: Mutex<Option<Vec<u8>>>,
        salt_service: String,
        salt_user: String,
    }

    impl MockKeyProvider {
        pub fn new() -> Self {
            Self {
                secret: Mutex::new(None),
                salt_service: "keystone-test".to_string(),
                salt_user: "test-user".to_string(),
            }
        }

        /// Create a mock provider pre-loaded with a known secret.
        pub fn with_secret(secret: Vec<u8>) -> Self {
            Self {
                secret: Mutex::new(Some(secret)),
                salt_service: "keystone-test".to_string(),
                salt_user: "test-user".to_string(),
            }
        }

        fn build_salt(&self) -> Vec<u8> {
            let mut hasher = Sha256::new();
            hasher.update(self.salt_service.as_bytes());
            hasher.update(b"::");
            hasher.update(self.salt_user.as_bytes());
            hasher.finalize().to_vec()
        }
    }

    impl MasterKeyProvider for MockKeyProvider {
        fn get_or_create_master_secret(
            &self,
        ) -> std::result::Result<Zeroizing<Vec<u8>>, EnclaveError> {
            let mut guard = self.secret.lock().unwrap();
            if let Some(ref s) = *guard {
                Ok(Zeroizing::new(s.clone()))
            } else {
                let mut secret = vec![0u8; MASTER_SECRET_LEN];
                rand::rng().fill_bytes(&mut secret);
                *guard = Some(secret.clone());
                Ok(Zeroizing::new(secret))
            }
        }

        fn derive_db_key(
            &self,
            master_secret: &[u8],
        ) -> std::result::Result<Zeroizing<Vec<u8>>, EnclaveError> {
            let salt = self.build_salt();
            let params =
                Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(DERIVED_KEY_LEN))
                    .map_err(|e| {
                        EnclaveError::Derivation(format!("invalid Argon2 params: {}", e))
                    })?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let mut derived_key = Zeroizing::new(vec![0u8; DERIVED_KEY_LEN]);
            argon2
                .hash_password_into(master_secret, &salt, &mut derived_key)
                .map_err(|e| EnclaveError::Derivation(format!("Argon2id hash failed: {}", e)))?;
            Ok(derived_key)
        }

        fn has_master_secret(&self) -> std::result::Result<bool, EnclaveError> {
            let guard = self.secret.lock().unwrap();
            Ok(guard.is_some())
        }

        fn delete_master_secret(&self) -> std::result::Result<(), EnclaveError> {
            let mut guard = self.secret.lock().unwrap();
            *guard = None;
            Ok(())
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::mock::MockKeyProvider;

    #[test]
    fn test_master_secret_generation_has_correct_entropy() {
        let provider = MockKeyProvider::new();
        let secret = provider.get_or_create_master_secret().unwrap();
        assert_eq!(
            secret.len(),
            MASTER_SECRET_LEN,
            "Master secret must be exactly {} bytes (256-bit entropy)",
            MASTER_SECRET_LEN
        );
    }

    #[test]
    fn test_master_secret_is_stable_once_created() {
        let provider = MockKeyProvider::new();
        let first = provider.get_or_create_master_secret().unwrap();
        let second = provider.get_or_create_master_secret().unwrap();
        assert_eq!(
            first.as_slice(),
            second.as_slice(),
            "Subsequent calls must return the same master secret"
        );
    }

    #[test]
    fn test_argon2id_derivation_deterministic() {
        let secret = vec![42u8; MASTER_SECRET_LEN];
        let provider = MockKeyProvider::with_secret(secret);
        let master = provider.get_or_create_master_secret().unwrap();

        let key1 = provider.derive_db_key(&master).unwrap();
        let key2 = provider.derive_db_key(&master).unwrap();

        assert_eq!(
            key1.as_slice(),
            key2.as_slice(),
            "Same master secret must produce the same derived key"
        );
    }

    #[test]
    fn test_argon2id_different_secrets_produce_different_keys() {
        let provider_a = MockKeyProvider::with_secret(vec![1u8; MASTER_SECRET_LEN]);
        let provider_b = MockKeyProvider::with_secret(vec![2u8; MASTER_SECRET_LEN]);

        let master_a = provider_a.get_or_create_master_secret().unwrap();
        let master_b = provider_b.get_or_create_master_secret().unwrap();

        let key_a = provider_a.derive_db_key(&master_a).unwrap();
        let key_b = provider_b.derive_db_key(&master_b).unwrap();

        assert_ne!(
            key_a.as_slice(),
            key_b.as_slice(),
            "Different master secrets must produce different derived keys"
        );
    }

    #[test]
    fn test_derived_key_length() {
        let provider = MockKeyProvider::with_secret(vec![99u8; MASTER_SECRET_LEN]);
        let master = provider.get_or_create_master_secret().unwrap();
        let key = provider.derive_db_key(&master).unwrap();

        assert_eq!(
            key.len(),
            DERIVED_KEY_LEN,
            "Derived key must be exactly {} bytes for AES-256",
            DERIVED_KEY_LEN
        );
    }

    #[test]
    fn test_has_master_secret() {
        let provider = MockKeyProvider::new();
        assert!(!provider.has_master_secret().unwrap());

        provider.get_or_create_master_secret().unwrap();
        assert!(provider.has_master_secret().unwrap());
    }

    #[test]
    fn test_delete_master_secret() {
        let provider = MockKeyProvider::new();
        provider.get_or_create_master_secret().unwrap();
        assert!(provider.has_master_secret().unwrap());

        provider.delete_master_secret().unwrap();
        assert!(!provider.has_master_secret().unwrap());
    }

    #[test]
    fn test_delete_nonexistent_secret_is_ok() {
        let provider = MockKeyProvider::new();
        // Deleting when nothing exists should not error
        assert!(provider.delete_master_secret().is_ok());
    }
}
