// Keystone — Application Entry Point
//
// Parses CLI arguments, initializes structured logging (with a filter that
// never emits secret values), and dispatches to the command handler.
// Uses tokio async runtime for MCP/UDS server support.

use clap::Parser;
use tracing_subscriber::EnvFilter;

use keystone::cli::{Cli, execute};

#[tokio::main]
async fn main() {
    // Initialize tracing with env filter (RUST_LOG=keystone=debug for verbose output).
    // The default level is `info`, which never includes secret values.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("keystone=info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    if let Err(e) = execute(cli.command).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
