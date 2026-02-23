// Keystone — MCP Server Implementation
//
// Uses the rmcp crate (official Rust MCP SDK) to expose credential
// operations as discoverable tools. Each tool maps to a CredentialStore
// operation. Secrets returned via get_secret are audit-logged.

use std::path::PathBuf;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router};
use rmcp::{ErrorData as McpError, ServerHandler};
use serde::{Deserialize, Serialize};

use crate::store::{CredentialStore, Database, NewCredential, Policy, SqliteCredentialStore};

// ─── Tool Parameter Types ────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CredentialIdParam {
    /// The UUID of the credential
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AddCredentialParams {
    /// The service provider name (e.g., "github", "openai", "aws")
    pub provider: String,
    /// Human-readable description of what this credential is for
    pub intent_description: String,
    /// The secret value (API key, token, etc.)
    pub secret_value: String,
    /// Deployment environment (default: "development")
    #[serde(default = "default_environment")]
    pub environment: String,
    /// Comma-separated scope tags (e.g., "repo:read,repo:write")
    #[serde(default)]
    pub scope_tags: String,
    /// Whether human approval is required before use
    #[serde(default)]
    pub require_approval: bool,
    /// Maximum time-to-live for JIT tokens (e.g., "1h", "24h")
    #[serde(default)]
    pub max_ttl: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SearchCredentialsParams {
    /// The search query (describe the intent or what the credential is for)
    pub intent: String,
    /// Maximum number of results to return (default: 5)
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    5
}

fn default_environment() -> String {
    "development".to_string()
}

// ─── Server State ────────────────────────────────────────────────────────────

/// The MCP server that exposes Keystone credential tools.
///
/// Opens a database connection per-request to avoid `Sync` issues
/// with rusqlite::Connection across async boundaries.
#[derive(Clone)]
pub struct KeystoneServer {
    db_path: PathBuf,
    hex_key: String,
    tool_router: ToolRouter<Self>,
}

impl KeystoneServer {
    /// Create a new MCP server connected to the given encrypted database.
    pub fn new(db_path: PathBuf, hex_key: String) -> Self {
        Self {
            db_path,
            hex_key,
            tool_router: Self::tool_router(),
        }
    }

    /// Open a fresh database connection for the current operation.
    fn open_db(&self) -> Result<Database, McpError> {
        Database::open(&self.db_path, &self.hex_key).map_err(|e| {
            McpError::internal_error(format!("Failed to open database: {}", e), None)
        })
    }
}

// ─── Tool Definitions ────────────────────────────────────────────────────────

#[tool_router]
impl KeystoneServer {
    /// List all stored credentials. Returns metadata only — never secrets.
    #[tool(description = "List all stored credentials (metadata only, no secrets)")]
    async fn list_credentials(&self) -> Result<CallToolResult, McpError> {
        let db = self.open_db()?;
        let store = SqliteCredentialStore::new(&db);

        let summaries = store.list().map_err(|e| {
            McpError::internal_error(format!("Failed to list credentials: {}", e), None)
        })?;

        let json = serde_json::to_string_pretty(&summaries).map_err(|e| {
            McpError::internal_error(format!("Serialization error: {}", e), None)
        })?;

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Get metadata for a single credential by ID. Secret is redacted.
    #[tool(description = "Get metadata for a credential by ID (secret is redacted)")]
    async fn get_credential(
        &self,
        params: Parameters<CredentialIdParam>,
    ) -> Result<CallToolResult, McpError> {
        let uuid = uuid::Uuid::parse_str(&params.0.id).map_err(|e| {
            McpError::invalid_params(format!("Invalid UUID: {}", e), None)
        })?;

        let db = self.open_db()?;
        let store = SqliteCredentialStore::new(&db);

        match store.get(&uuid) {
            Ok(Some(cred)) => {
                let output = format!("{:#?}", cred);
                Ok(CallToolResult::success(vec![Content::text(output)]))
            }
            Ok(None) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Credential not found: {}",
                params.0.id
            ))])),
            Err(e) => Err(McpError::internal_error(
                format!("Failed to get credential: {}", e),
                None,
            )),
        }
    }

    /// Retrieve the raw secret value. This operation is audit-logged.
    #[tool(
        description = "Retrieve a secret value (API key/token). This access is audit-logged."
    )]
    async fn get_secret(
        &self,
        params: Parameters<CredentialIdParam>,
    ) -> Result<CallToolResult, McpError> {
        let uuid = uuid::Uuid::parse_str(&params.0.id).map_err(|e| {
            McpError::invalid_params(format!("Invalid UUID: {}", e), None)
        })?;

        let db = self.open_db()?;
        let store = SqliteCredentialStore::new(&db);

        match store.get_secret(&uuid, "mcp-client") {
            Ok(Some(secret)) => Ok(CallToolResult::success(vec![Content::text(
                secret.as_str().to_string(),
            )])),
            Ok(None) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Credential not found: {}",
                params.0.id
            ))])),
            Err(crate::store::StoreError::ApprovalRequired(req_id)) => Ok(CallToolResult::success(vec![Content::text(
                format!("Approval required. Ask the human operator to run: `keystone approve {}`", req_id)
            )])),
            Err(crate::store::StoreError::Expired) => Ok(CallToolResult::success(vec![Content::text(
                "Credential has expired max TTL and was automatically deleted.".to_string()
            )])),
            Err(e) => Err(McpError::internal_error(
                format!("Failed to get secret: {}", e),
                None,
            )),
        }
    }

    /// Store a new credential and return its generated UUID.
    #[tool(description = "Store a new credential (API key, token, etc.)")]
    async fn add_credential(
        &self,
        params: Parameters<AddCredentialParams>,
    ) -> Result<CallToolResult, McpError> {
        let tags: Vec<String> = params.0.scope_tags
            .split(',')
            .map(|s: &str| s.trim().to_string())
            .filter(|s: &String| !s.is_empty())
            .collect();

        let new_cred = NewCredential {
            provider: params.0.provider.clone(),
            scope_tags: tags.clone(),
            environment: params.0.environment.clone(),
            intent_description: params.0.intent_description.clone(),
            secret_value: params.0.secret_value.clone(),
            policy: Policy {
                require_approval: params.0.require_approval,
                max_ttl: params.0.max_ttl.clone(),
                allowed_agent_hashes: vec![],
            },
        };

        // Generate embedding from intent and tags
        let embedding_text = format!("{} {} {}", params.0.provider, tags.join(" "), params.0.intent_description);
        let semantic = crate::intelligence::embeddings::SemanticService::get_or_init()
            .await
            .map_err(|e| McpError::internal_error(format!("Failed to initialize semantic service: {}", e), None))?;
        
        // This is synchronous, but fast enough for MCP inside tokio worker
        let embedding = semantic.embed_text(&embedding_text).await
            .map_err(|e| McpError::internal_error(format!("Failed to generate embedding: {}", e), None))?;

        let db = self.open_db()?;
        let store = SqliteCredentialStore::new(&db);

        let id = store.add(new_cred, Some(&embedding)).map_err(|e| {
            McpError::internal_error(format!("Failed to store credential: {}", e), None)
        })?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Credential stored successfully.\nID: {}\nProvider: {}",
            id, params.0.provider
        ))]))
    }

    /// Delete a credential by ID.
    #[tool(description = "Delete a credential by its UUID")]
    async fn delete_credential(
        &self,
        params: Parameters<CredentialIdParam>,
    ) -> Result<CallToolResult, McpError> {
        let uuid = uuid::Uuid::parse_str(&params.0.id).map_err(|e| {
            McpError::invalid_params(format!("Invalid UUID: {}", e), None)
        })?;

        let db = self.open_db()?;
        let store = SqliteCredentialStore::new(&db);

        match store.delete(&uuid) {
            Ok(true) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Credential {} deleted successfully",
                params.0.id
            ))])),
            Ok(false) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Credential not found: {}",
                params.0.id
            ))])),
            Err(e) => Err(McpError::internal_error(
                format!("Failed to delete credential: {}", e),
                None,
            )),
        }
    }

    /// Search credentials by intent/description using semantic similarity.
    #[tool(description = "Search credentials semantically by intent or description")]
    async fn search_credentials(
        &self,
        params: Parameters<SearchCredentialsParams>,
    ) -> Result<CallToolResult, McpError> {
        let semantic = crate::intelligence::embeddings::SemanticService::get_or_init()
            .await
            .map_err(|e| McpError::internal_error(format!("Failed to init semantic service: {}", e), None))?;

        let all_embeddings = {
            let db = self.open_db()?;
            let store = SqliteCredentialStore::new(&db);
            store.get_all_embeddings().map_err(|e| {
                McpError::internal_error(format!("Failed to fetch embeddings: {}", e), None)
            })?
        };

        let best_matches = semantic.search_best_matches(&params.0.intent, &all_embeddings, params.0.limit)
            .await
            .map_err(|e| McpError::internal_error(format!("Semantic search failed: {}", e), None))?;

        if best_matches.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text("No relevant credentials found.".to_string())]));
        }

        let mut results = Vec::new();
        {
            let db = self.open_db()?;
            let store = SqliteCredentialStore::new(&db);
            
            for (id, score) in best_matches {
                if let Ok(Some(cred)) = store.get(&id) {
                    results.push(format!("Score: {:.2} | ID: {} | Provider: {} | Environment: {}\nIntent: {}",
                        score, id, cred.provider, cred.environment, cred.intent_description));
                }
            }
        }

        let text = if results.is_empty() {
            "No matching credentials found.".to_string()
        } else {
            results.join("\n\n")
        };

        Ok(CallToolResult::success(vec![Content::text(text)]))
    }
}

// ─── ServerHandler ───────────────────────────────────────────────────────────

#[tool_handler]
impl ServerHandler for KeystoneServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Keystone — Secure credential manager for AI agents. \
                 Store, retrieve, and manage API keys and tokens with \
                 audit logging and encrypted storage."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn setup_server() -> KeystoneServer {
        let dir = tempdir().unwrap();
        let db_path = dir.into_path().join("test.db");
        let hex_key =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();

        // Create the database so it exists for the server
        let _db = Database::open(&db_path, &hex_key).unwrap();

        KeystoneServer::new(db_path, hex_key)
    }

    #[tokio::test]
    async fn test_list_credentials_empty() {
        let server = setup_server();
        let result = server.list_credentials().await.unwrap();
        assert!(!result.is_error.unwrap_or(false));
    }

    #[tokio::test]
    async fn test_add_and_list_credential() {
        let server = setup_server();

        let params = Parameters(AddCredentialParams {
            provider: "github".to_string(),
            intent_description: "CI/CD token".to_string(),
            secret_value: "ghp_test123".to_string(),
            environment: "production".to_string(),
            scope_tags: "repo:read".to_string(),
            require_approval: false,
            max_ttl: None,
        });

        let add_result = server.add_credential(params).await.unwrap();
        assert!(!add_result.is_error.unwrap_or(false));

        let list_result = server.list_credentials().await.unwrap();
        let text = content_text(&list_result);
        assert!(
            text.contains("github"),
            "Listed credentials should contain 'github'"
        );
    }

    #[tokio::test]
    async fn test_get_credential_not_found() {
        let server = setup_server();
        let params = Parameters(CredentialIdParam {
            id: "00000000-0000-0000-0000-000000000000".to_string(),
        });
        let result = server.get_credential(params).await.unwrap();
        let text = content_text(&result);
        assert!(text.contains("not found"));
    }

    #[tokio::test]
    async fn test_get_credential_invalid_uuid() {
        let server = setup_server();
        let params = Parameters(CredentialIdParam {
            id: "not-a-uuid".to_string(),
        });
        let result = server.get_credential(params).await;
        assert!(result.is_err(), "Invalid UUID should return an error");
    }

    #[tokio::test]
    async fn test_get_secret_audit_logged() {
        let server = setup_server();

        // Add a credential first
        let add_params = Parameters(AddCredentialParams {
            provider: "openai".to_string(),
            intent_description: "GPT-4 API key".to_string(),
            secret_value: "sk-test-secret-key".to_string(),
            environment: "development".to_string(),
            scope_tags: "".to_string(),
            require_approval: false,
            max_ttl: None,
        });

        let add_result = server.add_credential(add_params).await.unwrap();
        let add_text = content_text(&add_result);
        let id = extract_id_from_response(&add_text);

        // Get the secret
        let secret_params = Parameters(CredentialIdParam { id: id.clone() });
        let secret_result = server.get_secret(secret_params).await.unwrap();
        let secret_text = content_text(&secret_result);
        assert_eq!(secret_text, "sk-test-secret-key");

        // Verify audit log entry was created
        let db = server.open_db().unwrap();
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM audit_log WHERE action = 'secret_accessed' AND actor = 'mcp-client'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "get_secret via MCP should create an audit log entry"
        );
    }

    #[tokio::test]
    async fn test_delete_credential() {
        let server = setup_server();

        let add_params = Parameters(AddCredentialParams {
            provider: "slack".to_string(),
            intent_description: "Bot token".to_string(),
            secret_value: "xoxb-test".to_string(),
            environment: "development".to_string(),
            scope_tags: "".to_string(),
            require_approval: false,
            max_ttl: None,
        });

        let add_result = server.add_credential(add_params).await.unwrap();
        let id = extract_id_from_response(&content_text(&add_result));

        let del_params = Parameters(CredentialIdParam { id: id.clone() });
        let delete_result = server.delete_credential(del_params).await.unwrap();
        let text = content_text(&delete_result);
        assert!(text.contains("deleted successfully"));

        // Verify it's gone
        let get_params = Parameters(CredentialIdParam { id });
        let get_result = server.get_credential(get_params).await.unwrap();
        let text = content_text(&get_result);
        assert!(text.contains("not found"));
    }

    #[tokio::test]
    async fn test_server_info() {
        let server = setup_server();
        let info = server.get_info();
        assert!(info.instructions.is_some());
        assert!(info
            .instructions
            .unwrap()
            .contains("credential manager"));
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    fn content_text(result: &CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|c| match &c.raw {
                RawContent::Text(t) => Some(t.text.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("")
    }

    fn extract_id_from_response(text: &str) -> String {
        text.lines()
            .find(|line| line.starts_with("ID: "))
            .map(|line| line.trim_start_matches("ID: ").trim().to_string())
            .expect("Response should contain 'ID: <uuid>'")
    }
}
