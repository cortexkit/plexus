//! Shared MCP request and result handling for every MCP transport.
//!
//! Both remote HTTP and route-plane adapters speak MCP tool semantics. Keeping
//! the wire shapes here prevents the two transports from drifting on envelopes
//! such as JSON serialized inside a text content block.

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpPayloadError {
    InvalidResponse,
}

pub(crate) fn json_rpc_request(id: u64, method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
}

pub(crate) fn tools_list_params() -> Value {
    json!({})
}

pub(crate) fn tools_call_params(name: String, arguments: Value) -> Value {
    json!({"name": name, "arguments": arguments})
}

pub(crate) fn tools_from_response(response: &Value) -> Result<Vec<Value>, McpPayloadError> {
    response
        .get("result")
        .and_then(Value::as_object)
        .and_then(|result| result.get("tools"))
        .and_then(Value::as_array)
        .cloned()
        .ok_or(McpPayloadError::InvalidResponse)
}

pub(crate) fn tool_result_from_response(response: Value) -> Result<Value, McpPayloadError> {
    response
        .get("result")
        .cloned()
        .ok_or(McpPayloadError::InvalidResponse)
}

/// Decode an MCP `tools/call` result into the payload its consumers need.
///
/// MCP does not return a tool's output as a bare object. Every result is a list
/// of content blocks, and a vendor returning JSON puts it in a text block as a
/// serialized string. Centralizing this keeps the route-plane transport aligned
/// with the remote transport when a server uses that common response shape.
pub(crate) fn decode_tool_result(result: Value) -> Value {
    if let Some(structured) = result.get("structuredContent") {
        if !structured.is_null() {
            return structured.clone();
        }
    }
    let Some(blocks) = result.get("content").and_then(Value::as_array) else {
        return result;
    };
    let [block] = blocks.as_slice() else {
        return result;
    };
    if block.get("type").and_then(Value::as_str) != Some("text") {
        return result;
    }
    let Some(text) = block.get("text").and_then(Value::as_str) else {
        return result;
    };
    match serde_json::from_str::<Value>(text) {
        Ok(value) if value.is_object() || value.is_array() => value,
        _ => result,
    }
}
