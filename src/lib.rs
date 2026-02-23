// Keystone — Library root
//
// Re-exports the enclave, store, CLI, MCP, and gateway modules.

pub mod cli;
pub mod enclave;
pub mod error;
pub mod gateway;
pub mod mcp;
pub mod store;
pub mod intelligence;

pub use error::{KeystoneError, Result};
