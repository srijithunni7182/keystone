// Keystone — CLI Module
//
// Command-line interface using clap derive macros.
// Subcommands: init, add, list, get, delete.

mod commands;

use clap::{Parser, Subcommand};

pub use commands::execute;

/// Keystone — The intelligent credential librarian for AI agents.
#[derive(Parser, Debug)]
#[command(name = "keystone")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize Keystone: create the master key and encrypted database.
    Init,

    /// Add a new credential to the store.
    Add {
        /// The service provider (e.g., "github", "openai", "slack").
        #[arg(long)]
        provider: String,

        /// The deployment environment (e.g., "production", "staging", "development").
        #[arg(long, default_value = "development")]
        environment: String,

        /// Comma-separated scope tags (e.g., "repo:read,repo:write").
        #[arg(long, default_value = "")]
        scope_tags: String,

        /// A natural-language description of what this credential is used for.
        #[arg(long)]
        intent: String,

        /// The secret value (API key, token, etc.).
        /// For production use, prefer interactive entry to avoid shell history exposure.
        #[arg(long)]
        secret: String,

        /// Require human approval before releasing this credential.
        #[arg(long, default_value = "false")]
        require_approval: bool,

        /// Maximum time-to-live for JIT tokens (e.g., "1h", "30m").
        #[arg(long)]
        max_ttl: Option<String>,
    },

    /// List all stored credentials (metadata only, no secrets).
    List,

    /// Search credentials semantically by intent.
    Search {
        /// The search query (describe the intent or what the credential is for)
        intent: String,

        /// Maximum number of results to return (default: 5)
        #[arg(long, default_value = "5")]
        limit: usize,
    },

    /// Get the details of a specific credential by ID.
    Get {
        /// The UUID of the credential to retrieve.
        id: String,
    },

    /// Delete a credential by ID.
    Delete {
        /// The UUID of the credential to delete.
        id: String,
    },

    /// Approve a pending credential access request.
    Approve {
        /// The UUID of the approval request to authorize.
        request_id: String,
    },

    /// Reject a pending credential access request.
    Reject {
        /// The UUID of the approval request to deny.
        request_id: String,
    },

    /// View the audit log for a specific credential.
    Audit {
        /// The UUID of the credential to investigate.
        id: String,
    },

    /// Start the Keystone daemon (MCP or UDS server).
    Serve {
        /// Transport mode: "stdio" for MCP over stdin/stdout, "uds" for Unix Domain Socket.
        #[arg(long, default_value = "stdio")]
        transport: String,
    },
}
