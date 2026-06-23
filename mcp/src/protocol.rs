use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A standard JSON-RPC 2.0 Request object.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
    pub id: Option<Value>,
}

/// A standard JSON-RPC 2.0 Response object.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse<T = Value> {
    pub jsonrpc: String,
    pub result: Option<T>,
    pub error: Option<JsonRpcErrorObject>,
    pub id: Option<Value>,
}

/// A standard JSON-RPC 2.0 Error object.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcErrorObject {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

impl<T> JsonRpcResponse<T> {
    /// Creates a successful response.
    pub fn success(id: Option<Value>, result: T) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Creates an error response.
    pub fn error(id: Option<Value>, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcErrorObject {
                code,
                message,
                data: None,
            }),
            id,
        }
    }
}
