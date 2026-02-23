// Keystone — JSON-RPC 2.0 Protocol Types
//
// Minimal JSON-RPC 2.0 implementation for the UDS gateway.
// We implement this directly rather than pulling in a crate,
// since we only need a handful of types.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A JSON-RPC 2.0 request.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    pub id: Value,
}

/// A JSON-RPC 2.0 success/error response.
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// Standard JSON-RPC 2.0 error codes
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

impl JsonRpcResponse {
    /// Create a success response.
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Create an error response.
    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }

    /// Create a parse error response (id is null because we couldn't parse it).
    pub fn parse_error(message: impl Into<String>) -> Self {
        Self::error(Value::Null, PARSE_ERROR, message)
    }
}

impl JsonRpcRequest {
    /// Validate that this is a proper JSON-RPC 2.0 request.
    pub fn validate(&self) -> Result<(), String> {
        if self.jsonrpc != "2.0" {
            return Err("jsonrpc must be \"2.0\"".to_string());
        }
        if self.method.is_empty() {
            return Err("method must not be empty".to_string());
        }
        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_request() {
        let json = r#"{"jsonrpc":"2.0","method":"list","params":{},"id":1}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "list");
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_parse_request_without_params() {
        let json = r#"{"jsonrpc":"2.0","method":"list","id":1}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.params, Value::Null);
    }

    #[test]
    fn test_invalid_jsonrpc_version() {
        let json = r#"{"jsonrpc":"1.0","method":"list","params":{},"id":1}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(req.validate().is_err());
    }

    #[test]
    fn test_success_response_serialization() {
        let resp = JsonRpcResponse::success(
            Value::Number(1.into()),
            serde_json::json!({"count": 5}),
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_error_response_serialization() {
        let resp = JsonRpcResponse::error(
            Value::Number(1.into()),
            METHOD_NOT_FOUND,
            "Method not found",
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("\"result\""));
        assert!(json.contains("\"error\""));
        assert!(json.contains("-32601"));
    }

    #[test]
    fn test_parse_error_has_null_id() {
        let resp = JsonRpcResponse::parse_error("bad json");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"id\":null"));
        assert!(json.contains("-32700"));
    }
}
