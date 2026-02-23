// Keystone — Store Module
//
// Encrypted credential storage using SQLCipher. All secrets are encrypted at rest
// via AES-256-GCM and every access is audit-logged.

mod db;
mod error;
mod models;
mod repository;

pub use db::Database;
pub use error::StoreError;
pub use models::{Credential, CredentialSummary, NewCredential, Policy};
pub use repository::{CredentialStore, SqliteCredentialStore};
