// Keystone — Unix Domain Socket Server
//
// Listens on a Unix domain socket for JSON-RPC 2.0 requests from agents
// and scripts. Each connection is handled in a spawned tokio task with
// optional caller verification via /proc/<pid>/exe.

use std::path::{Path, PathBuf};

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::store::{CredentialStore, Database, NewCredential, Policy, SqliteCredentialStore};

use super::caller::CallerInfo;
use super::protocol::{
    JsonRpcRequest, JsonRpcResponse, INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND,
};

/// Unix Domain Socket server for Keystone.
pub struct UdsServer {
    db_path: PathBuf,
    hex_key: String,
    socket_path: PathBuf,
}

impl UdsServer {
    /// Create a new UDS server.
    pub fn new(db_path: PathBuf, hex_key: String, socket_path: PathBuf) -> Self {
        Self {
            db_path,
            hex_key,
            socket_path,
        }
    }

    /// Default socket path: `$XDG_RUNTIME_DIR/keystone/keystone.sock`
    /// Falls back to `/tmp/keystone/keystone.sock`.
    pub fn default_socket_path() -> PathBuf {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        runtime_dir.join("keystone").join("keystone.sock")
    }

    /// Start the UDS server. This runs until the process is terminated.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Ensure the socket directory exists
        if let Some(parent) = self.socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Remove stale socket file if it exists
        if self.socket_path.exists() {
            tokio::fs::remove_file(&self.socket_path).await?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        tracing::info!(
            socket = %self.socket_path.display(),
            "Keystone UDS server listening"
        );

        // Set restrictive permissions on the socket (owner-only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.socket_path, perms)?;
        }

        loop {
            let (stream, _addr) = listener.accept().await?;
            let db_path = self.db_path.clone();
            let hex_key = self.hex_key.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, &db_path, &hex_key).await {
                    tracing::error!("Connection handler error: {}", e);
                }
            });
        }
    }
}

/// Handle a single client connection.
/// Reads newline-delimited JSON-RPC requests and writes responses.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    db_path: &Path,
    hex_key: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Try to get caller info from peer credentials
    let caller_info = {
        #[cfg(target_os = "linux")]
        {
            // Get peer credentials via SO_PEERCRED
            let cred = stream.peer_cred()?;
            let pid = cred.pid().unwrap_or(0) as u32;
            CallerInfo::from_pid(pid).ok()
        }
        #[cfg(not(target_os = "linux"))]
        {
            None::<CallerInfo>
        }
    };

    let actor = caller_info
        .as_ref()
        .map(|c| c.actor_string())
        .unwrap_or_else(|| "uds-client".to_string());

    if let Some(ref info) = caller_info {
        tracing::info!(%info, "Client connected");
    }

    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let response = process_request(&line, db_path, hex_key, &actor);
        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Parse and dispatch a single JSON-RPC request.
fn process_request(
    raw: &str,
    db_path: &Path,
    hex_key: &str,
    actor: &str,
) -> JsonRpcResponse {
    // Parse the JSON
    let request: JsonRpcRequest = match serde_json::from_str(raw) {
        Ok(req) => req,
        Err(e) => return JsonRpcResponse::parse_error(format!("Parse error: {}", e)),
    };

    // Validate JSON-RPC 2.0
    if let Err(e) = request.validate() {
        return JsonRpcResponse::error(request.id, -32600, e);
    }

    // Open the database
    let db = match Database::open(std::path::Path::new(db_path), hex_key) {
        Ok(db) => db,
        Err(e) => {
            return JsonRpcResponse::error(
                request.id,
                INTERNAL_ERROR,
                format!("Database error: {}", e),
            )
        }
    };
    let store = SqliteCredentialStore::new(&db);

    // Dispatch by method
    match request.method.as_str() {
        "list" => handle_list(&store, request.id),
        "get" => handle_get(&store, request.id, &request.params),
        "get_secret" => handle_get_secret(&store, request.id, &request.params, actor),
        "add" => handle_add(&store, request.id, &request.params),
        "delete" => handle_delete(&store, request.id, &request.params),
        _ => JsonRpcResponse::error(
            request.id,
            METHOD_NOT_FOUND,
            format!("Unknown method: {}", request.method),
        ),
    }
}

// ─── Method Handlers ─────────────────────────────────────────────────────────

fn handle_list(store: &SqliteCredentialStore<'_>, id: Value) -> JsonRpcResponse {
    match store.list() {
        Ok(summaries) => {
            let json = serde_json::to_value(&summaries).unwrap_or(Value::Null);
            JsonRpcResponse::success(id, json)
        }
        Err(e) => JsonRpcResponse::error(id, INTERNAL_ERROR, format!("{}", e)),
    }
}

fn handle_get(
    store: &SqliteCredentialStore<'_>,
    id: Value,
    params: &Value,
) -> JsonRpcResponse {
    let cred_id = match extract_uuid(params) {
        Ok(uuid) => uuid,
        Err(resp) => return resp.with_id(id),
    };

    match store.get(&cred_id) {
        Ok(Some(cred)) => {
            // Return metadata with redacted secret
            let result = serde_json::json!({
                "id": cred.id.to_string(),
                "provider": cred.provider,
                "environment": cred.environment,
                "scope_tags": cred.scope_tags,
                "intent_description": cred.intent_description,
                "secret": "[REDACTED]",
                "policy": {
                    "require_approval": cred.policy.require_approval,
                    "max_ttl": cred.policy.max_ttl,
                },
                "created_at": cred.created_at.to_rfc3339(),
                "updated_at": cred.updated_at.to_rfc3339(),
            });
            JsonRpcResponse::success(id, result)
        }
        Ok(None) => JsonRpcResponse::error(id, INVALID_PARAMS, "Credential not found"),
        Err(e) => JsonRpcResponse::error(id, INTERNAL_ERROR, format!("{}", e)),
    }
}

fn handle_get_secret(
    store: &SqliteCredentialStore<'_>,
    id: Value,
    params: &Value,
    actor: &str,
) -> JsonRpcResponse {
    let cred_id = match extract_uuid(params) {
        Ok(uuid) => uuid,
        Err(resp) => return resp.with_id(id),
    };

    match store.get_secret(&cred_id, actor) {
        Ok(Some(secret)) => {
            let result = serde_json::json!({ "secret": secret.as_str() });
            JsonRpcResponse::success(id, result)
        }
        Ok(None) => JsonRpcResponse::error(id, INVALID_PARAMS, "Credential not found"),
        Err(crate::store::StoreError::ApprovalRequired(req_id)) => JsonRpcResponse::error(
            id,
            -32001, // Custom app error code for "Approval Required"
            format!("Approval required. Run: keystone approve {}", req_id),
        ),
        Err(crate::store::StoreError::Expired) => JsonRpcResponse::error(
            id,
            -32002, // Custom app error code for "Expired"
            "Credential has expired its max TTL and was securely deleted",
        ),
        Err(e) => JsonRpcResponse::error(id, INTERNAL_ERROR, format!("{}", e)),
    }
}

fn handle_add(
    store: &SqliteCredentialStore<'_>,
    id: Value,
    params: &Value,
) -> JsonRpcResponse {
    let provider = match params.get("provider").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing 'provider'"),
    };
    let intent = match params.get("intent_description").and_then(|v| v.as_str()) {
        Some(i) => i.to_string(),
        None => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing 'intent_description'")
        }
    };
    let secret = match params.get("secret_value").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing 'secret_value'"),
    };

    let environment = params
        .get("environment")
        .and_then(|v| v.as_str())
        .unwrap_or("development")
        .to_string();

    let scope_tags_str = params
        .get("scope_tags")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let scope_tags: Vec<String> = scope_tags_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let require_approval = params
        .get("require_approval")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let max_ttl = params
        .get("max_ttl")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let new_cred = NewCredential {
        provider: provider.clone(),
        scope_tags,
        environment,
        intent_description: intent,
        secret_value: secret,
        policy: Policy {
            require_approval,
            max_ttl,
            allowed_agent_hashes: vec![],
        },
    };

    match store.add(new_cred, None) {
        Ok(uuid) => {
            let result = serde_json::json!({
                "id": uuid.to_string(),
                "provider": provider,
            });
            JsonRpcResponse::success(id, result)
        }
        Err(e) => JsonRpcResponse::error(id, INTERNAL_ERROR, format!("{}", e)),
    }
}

fn handle_delete(
    store: &SqliteCredentialStore<'_>,
    id: Value,
    params: &Value,
) -> JsonRpcResponse {
    let cred_id = match extract_uuid(params) {
        Ok(uuid) => uuid,
        Err(resp) => return resp.with_id(id),
    };

    match store.delete(&cred_id) {
        Ok(true) => {
            let result =
                serde_json::json!({ "deleted": true, "id": cred_id.to_string() });
            JsonRpcResponse::success(id, result)
        }
        Ok(false) => JsonRpcResponse::error(id, INVALID_PARAMS, "Credential not found"),
        Err(e) => JsonRpcResponse::error(id, INTERNAL_ERROR, format!("{}", e)),
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn extract_uuid(params: &Value) -> Result<uuid::Uuid, JsonRpcResponse> {
    let id_str = params
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            JsonRpcResponse::error(Value::Null, INVALID_PARAMS, "Missing 'id' parameter")
        })?;

    uuid::Uuid::parse_str(id_str).map_err(|e| {
        JsonRpcResponse::error(
            Value::Null,
            INVALID_PARAMS,
            format!("Invalid UUID: {}", e),
        )
    })
}

impl JsonRpcResponse {
    /// Replace the id field (used when we parsed the request but had a param error).
    fn with_id(mut self, id: Value) -> Self {
        self.id = id;
        self
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_db() -> (PathBuf, String) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.into_path().join("test.db");
        let hex_key =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        let _db = Database::open(&db_path, &hex_key).unwrap();
        (db_path, hex_key)
    }

    #[test]
    fn test_process_list_request() {
        let (db_path, hex_key) = setup_db();
        let req = r#"{"jsonrpc":"2.0","method":"list","params":{},"id":1}"#;
        let resp = process_request(req, &db_path, &hex_key, "test");
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_process_add_request() {
        let (db_path, hex_key) = setup_db();
        let req = r#"{"jsonrpc":"2.0","method":"add","params":{"provider":"github","intent_description":"CI token","secret_value":"ghp_123"},"id":2}"#;
        let resp = process_request(req, &db_path, &hex_key, "test");
        assert!(resp.error.is_none(), "Add should succeed: {:?}", resp.error);
        let result = resp.result.unwrap();
        assert_eq!(result["provider"], "github");
        assert!(result["id"].is_string());
    }

    #[test]
    fn test_process_add_missing_params() {
        let (db_path, hex_key) = setup_db();
        let req = r#"{"jsonrpc":"2.0","method":"add","params":{"provider":"github"},"id":3}"#;
        let resp = process_request(req, &db_path, &hex_key, "test");
        assert!(resp.error.is_some(), "Missing intent_description should fail");
    }

    #[test]
    fn test_process_crud_lifecycle() {
        let (db_path, hex_key) = setup_db();

        // Add
        let add_req = r#"{"jsonrpc":"2.0","method":"add","params":{"provider":"openai","intent_description":"API key","secret_value":"sk-test"},"id":1}"#;
        let add_resp = process_request(add_req, &db_path, &hex_key, "test");
        let added_id = add_resp.result.unwrap()["id"].as_str().unwrap().to_string();

        // List
        let list_req = r#"{"jsonrpc":"2.0","method":"list","params":{},"id":2}"#;
        let list_resp = process_request(list_req, &db_path, &hex_key, "test");
        let list_result = list_resp.result.unwrap();
        assert!(list_result.as_array().unwrap().len() == 1);

        // Get
        let get_req = format!(
            r#"{{"jsonrpc":"2.0","method":"get","params":{{"id":"{}"}},"id":3}}"#,
            added_id
        );
        let get_resp = process_request(&get_req, &db_path, &hex_key, "test");
        let get_result = get_resp.result.unwrap();
        assert_eq!(get_result["provider"], "openai");
        assert_eq!(get_result["secret"], "[REDACTED]");

        // Get secret
        let secret_req = format!(
            r#"{{"jsonrpc":"2.0","method":"get_secret","params":{{"id":"{}"}},"id":4}}"#,
            added_id
        );
        let secret_resp = process_request(&secret_req, &db_path, &hex_key, "test");
        let secret_result = secret_resp.result.unwrap();
        assert_eq!(secret_result["secret"], "sk-test");

        // Delete
        let delete_req = format!(
            r#"{{"jsonrpc":"2.0","method":"delete","params":{{"id":"{}"}},"id":5}}"#,
            added_id
        );
        let delete_resp = process_request(&delete_req, &db_path, &hex_key, "test");
        assert!(delete_resp.result.unwrap()["deleted"].as_bool().unwrap());

        // Verify gone
        let list2_req = r#"{"jsonrpc":"2.0","method":"list","params":{},"id":6}"#;
        let list2_resp = process_request(list2_req, &db_path, &hex_key, "test");
        assert!(list2_resp.result.unwrap().as_array().unwrap().is_empty());
    }

    #[test]
    fn test_unknown_method() {
        let (db_path, hex_key) = setup_db();
        let req = r#"{"jsonrpc":"2.0","method":"unknown_method","params":{},"id":1}"#;
        let resp = process_request(req, &db_path, &hex_key, "test");
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[test]
    fn test_invalid_json() {
        let (db_path, hex_key) = setup_db();
        let resp = process_request("not json at all", &db_path, &hex_key, "test");
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32700); // PARSE_ERROR
    }

    #[test]
    fn test_default_socket_path() {
        let path = UdsServer::default_socket_path();
        assert!(path.to_string_lossy().contains("keystone"));
        assert!(path.to_string_lossy().ends_with("keystone.sock"));
    }
}
