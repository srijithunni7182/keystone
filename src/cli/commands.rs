// Keystone — CLI Command Handlers
//
// Each function handles one CLI subcommand. They coordinate between the
// enclave (master key) and store (credentials) modules. The `serve`
// command starts either the MCP stdio server or the UDS server.

use std::path::PathBuf;

use uuid::Uuid;

use crate::enclave::{KeyringProvider, MasterKeyProvider};
use crate::gateway::UdsServer;
use crate::mcp::KeystoneServer;
use crate::store::{CredentialStore, Database, NewCredential, Policy, SqliteCredentialStore};
use crate::error::KeystoneError;

use super::Commands;

/// Default directory for Keystone data files.
fn data_dir() -> PathBuf {
    let base = dirs_next::data_dir()
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("keystone")
}

/// Path to the encrypted database file.
fn db_path() -> PathBuf {
    data_dir().join("keystone.db")
}

/// Convert the master key bytes to the hex string format SQLCipher expects.
fn key_to_hex(key: &[u8]) -> String {
    key.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Execute the parsed CLI command.
pub async fn execute(command: Commands) -> Result<(), KeystoneError> {
    match command {
        Commands::Init => cmd_init(),
        Commands::Add {
            provider,
            environment,
            scope_tags,
            intent,
            secret,
            require_approval,
            max_ttl,
        } => cmd_add(
            provider,
            environment,
            scope_tags,
            intent,
            secret,
            require_approval,
            max_ttl,
        ).await,
        Commands::List => cmd_list(),
        Commands::Search { intent, limit } => cmd_search(intent, limit).await,
        Commands::Get { id } => cmd_get(id),
        Commands::Delete { id } => cmd_delete(id),
        Commands::Approve { request_id } => cmd_approve(request_id),
        Commands::Reject { request_id } => cmd_reject(request_id),
        Commands::Audit { id } => cmd_audit(id),
        Commands::Serve { transport } => cmd_serve(transport).await,
    }
}

// ─── Guardrails (Approve, Reject, Audit) ─────────────────────────────────────

fn cmd_approve(request_id: String) -> Result<(), KeystoneError> {
    let req_uuid = uuid::Uuid::parse_str(&request_id).map_err(|e| {
        KeystoneError::Other(format!("Invalid request UUID: {}", e))
    })?;

    let (db, _provider) = open_db()?;
    let store = SqliteCredentialStore::new(&db);

    if store.approve_request(&req_uuid)? {
        println!("✓ Request {} approved", req_uuid);
    } else {
        println!("Request not found or not pending: {}", req_uuid);
    }

    Ok(())
}

fn cmd_reject(request_id: String) -> Result<(), KeystoneError> {
    let req_uuid = uuid::Uuid::parse_str(&request_id).map_err(|e| {
        KeystoneError::Other(format!("Invalid request UUID: {}", e))
    })?;

    let (db, _provider) = open_db()?;
    let store = SqliteCredentialStore::new(&db);

    if store.reject_request(&req_uuid)? {
        println!("✓ Request {} rejected", req_uuid);
    } else {
        println!("Request not found or not pending: {}", req_uuid);
    }

    Ok(())
}

fn cmd_audit(id: String) -> Result<(), KeystoneError> {
    let cred_uuid = uuid::Uuid::parse_str(&id).map_err(|e| {
        KeystoneError::Other(format!("Invalid credential UUID: {}", e))
    })?;

    let (db, _provider) = open_db()?;
    let store = SqliteCredentialStore::new(&db);

    let logs = store.get_audit_logs(&cred_uuid)?;

    if logs.is_empty() {
        println!("No audit logs found for credential: {}", id);
        return Ok(());
    }

    println!("Audit Log for Credential: {}", id);
    println!("{:-<80}", "");
    for log in logs {
        println!("{}", log);
    }
    println!("{:-<80}", "");

    Ok(())
}

// ─── Search ──────────────────────────────────────────────────────────────────

async fn cmd_search(intent: String, limit: usize) -> Result<(), KeystoneError> {
    let semantic = crate::intelligence::embeddings::SemanticService::get_or_init().await?;
    
    let all_embeddings = {
        let (db, _provider) = open_db()?;
        let store = SqliteCredentialStore::new(&db);
        store.get_all_embeddings()?
    };

    let best_matches = semantic.search_best_matches(&intent, &all_embeddings, limit).await?;

    if best_matches.is_empty() {
        println!("No credentials found matching your intent.");
        return Ok(());
    }

    println!("Top semantic matches for intent: '{}'", intent);
    println!("{:-<80}", "");

    let (db, _provider) = open_db()?;
    let store = SqliteCredentialStore::new(&db);
    
    for (id, score) in best_matches {
        if let Ok(Some(cred)) = store.get(&id) {
            println!("Score:       {:.3}", score);
            println!("ID:          {}", id);
            println!("Provider:    {}", cred.provider);
            println!("Environment: {}", cred.environment);
            println!("Intent:      {}", cred.intent_description);
            println!("{:-<80}", "");
        }
    }

    Ok(())
}

// ─── Init ────────────────────────────────────────────────────────────────────

fn cmd_init() -> Result<(), KeystoneError> {
    let provider = KeyringProvider::new();

    // Create data directory if it doesn't exist
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;

    // Generate or retrieve the master secret
    let master_secret = provider.get_or_create_master_secret()?;
    let db_key = provider.derive_db_key(&master_secret)?;
    let hex_key = key_to_hex(&db_key);

    // Open (and create) the encrypted database
    let path = db_path();
    let _db = Database::open(&path, &hex_key)
        .map_err(|e| KeystoneError::Other(format!("Failed to initialize database: {}", e)))?;

    println!("✓ Keystone initialized successfully");
    println!("  Database: {}", path.display());
    println!("  Master key stored in platform keyring");
    println!();
    println!("Next: add a credential with `keystone add --provider <name> --intent <description> --secret <value>`");

    Ok(())
}

// ─── Add ─────────────────────────────────────────────────────────────────────

async fn cmd_add(
    provider: String,
    environment: String,
    scope_tags: String,
    intent: String,
    secret: String,
    require_approval: bool,
    max_ttl: Option<String>,
) -> Result<(), KeystoneError> {
    let (db, _provider) = open_db()?;
    let store = SqliteCredentialStore::new(&db);

    let tags: Vec<String> = scope_tags
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Generate embedding from intent and provider/tags for better search
    let embedding_text = format!("{} {} {}", provider, tags.join(" "), intent);
    let semantic = crate::intelligence::embeddings::SemanticService::get_or_init().await?;
    let embedding = semantic.embed_text(&embedding_text).await?;

    let new_cred = NewCredential {
        provider: provider.clone(),
        scope_tags: tags,
        environment,
        intent_description: intent,
        secret_value: secret,
        policy: Policy {
            require_approval,
            max_ttl,
            allowed_agent_hashes: vec![],
        },
    };

    let id = store.add(new_cred, Some(&embedding))?;
    println!("✓ Credential stored");
    println!("  ID:       {}", id);
    println!("  Provider: {}", provider);

    Ok(())
}

// ─── List ────────────────────────────────────────────────────────────────────

fn cmd_list() -> Result<(), KeystoneError> {
    let (db, _provider) = open_db()?;
    let store = SqliteCredentialStore::new(&db);

    let summaries = store.list()?;

    if summaries.is_empty() {
        println!("No credentials stored yet.");
        println!("Add one with: keystone add --provider <name> --intent <description> --secret <value>");
        return Ok(());
    }

    println!("Stored credentials ({}):\n", summaries.len());
    for summary in &summaries {
        println!("  {} │ {:12} │ {:12} │ {}",
            summary.id,
            summary.provider,
            summary.environment,
            summary.intent_description,
        );
    }

    Ok(())
}

// ─── Get ─────────────────────────────────────────────────────────────────────

fn cmd_get(id_str: String) -> Result<(), KeystoneError> {
    let id = Uuid::parse_str(&id_str)
        .map_err(|e| KeystoneError::Other(format!("Invalid UUID: {}", e)))?;

    let (db, _provider) = open_db()?;
    let store = SqliteCredentialStore::new(&db);

    match store.get(&id)? {
        Some(cred) => {
            println!("Credential details:\n");
            println!("  ID:          {}", cred.id);
            println!("  Provider:    {}", cred.provider);
            println!("  Environment: {}", cred.environment);
            println!("  Scopes:      {}", cred.scope_tags.join(", "));
            println!("  Intent:      {}", cred.intent_description);
            println!("  Secret:      [REDACTED]"); // Never print the secret!
            println!("  Policy:");
            println!("    Approval:  {}", cred.policy.require_approval);
            if let Some(ref ttl) = cred.policy.max_ttl {
                println!("    Max TTL:   {}", ttl);
            }
            println!("  Created:     {}", cred.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("  Updated:     {}", cred.updated_at.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        None => {
            println!("Credential not found: {}", id);
        }
    }

    Ok(())
}

// ─── Delete ──────────────────────────────────────────────────────────────────

fn cmd_delete(id_str: String) -> Result<(), KeystoneError> {
    let id = Uuid::parse_str(&id_str)
        .map_err(|e| KeystoneError::Other(format!("Invalid UUID: {}", e)))?;

    let (db, _provider) = open_db()?;
    let store = SqliteCredentialStore::new(&db);

    if store.delete(&id)? {
        println!("✓ Credential {} deleted", id);
    } else {
        println!("Credential not found: {}", id);
    }

    Ok(())
}

// ─── Serve ───────────────────────────────────────────────────────────────────

async fn cmd_serve(transport: String) -> Result<(), KeystoneError> {
    let (_, provider) = open_db()?;

    // Get the database key for the server
    let master_secret = provider.get_or_create_master_secret()?;
    let db_key = provider.derive_db_key(&master_secret)?;
    let hex_key = key_to_hex(&db_key);
    let path = db_path();

    match transport.as_str() {
        "stdio" => {
            println!("Starting Keystone MCP server (stdio transport)...");
            let server = KeystoneServer::new(path, hex_key);

            use rmcp::ServiceExt;
            let service = server
                .serve(rmcp::transport::stdio())
                .await
                .map_err(|e| KeystoneError::Other(format!("MCP server error: {}", e)))?;

            service
                .waiting()
                .await
                .map_err(|e| KeystoneError::Other(format!("MCP server error: {}", e)))?;
        }
        "uds" => {
            let socket_path = UdsServer::default_socket_path();
            println!("Starting Keystone UDS server at {}...", socket_path.display());

            let server = UdsServer::new(path, hex_key, socket_path);
            server
                .run()
                .await
                .map_err(|e| KeystoneError::Other(format!("UDS server error: {}", e)))?;
        }
        other => {
            return Err(KeystoneError::Other(format!(
                "Unknown transport '{}'. Use 'stdio' or 'uds'.",
                other
            )));
        }
    }

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Open the encrypted database using the platform keyring.
fn open_db() -> Result<(Database, KeyringProvider), KeystoneError> {
    let provider = KeyringProvider::new();

    if !provider.has_master_secret()? {
        return Err(KeystoneError::Other(
            "Keystone is not initialized. Run `keystone init` first.".to_string(),
        ));
    }

    let master_secret = provider.get_or_create_master_secret()?;
    let db_key = provider.derive_db_key(&master_secret)?;
    let hex_key = key_to_hex(&db_key);

    let path = db_path();
    if !path.exists() {
        return Err(KeystoneError::Other(format!(
            "Database not found at {}. Run `keystone init` first.",
            path.display()
        )));
    }

    let db = Database::open(&path, &hex_key)
        .map_err(|e| KeystoneError::Other(format!("Failed to open database: {}", e)))?;

    Ok((db, provider))
}
