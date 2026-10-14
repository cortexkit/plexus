//! In-process MCP streamable-HTTP stub server for conformance fixtures.
//!
//! Promoted from the slice-3 test pattern into a reusable, long-lived fixture
//! that does not depend on test-only cfg. The server presents a configured
//! action set and answers tools/call with deterministic JSON.

use serde_json::{json, Value};

use crate::http_wire::{http_empty, http_json};

/// One tool the stub MCP server advertises via `tools/list`.
#[derive(Debug, Clone)]
pub struct StubTool {
    pub name: String,
    pub input_schema: Value,
}

impl StubTool {
    pub fn new(name: impl Into<String>, input_schema: Value) -> Self {
        Self {
            name: name.into(),
            input_schema,
        }
    }

    pub fn simple(name: impl Into<String>) -> Self {
        Self::new(
            name,
            json!({
                "type": "object",
                "properties": {
                    "q": {"type": "string"},
                    "team": {"type": "string"},
                    "title": {"type": "string"},
                    "workspace": {"type": "string"}
                }
            }),
        )
    }
}

/// Long-lived local MCP stub with a fixed HTTP worker pool.
pub struct StubMcpServer {
    server: crate::http_wire::StubHttpServer,
}

impl StubMcpServer {
    pub fn start(tools: Vec<StubTool>) -> Result<Self, String> {
        let server = crate::http_wire::StubHttpServer::start("/mcp", move |request| {
            response_for_request(request, &tools)
        })?;
        Ok(Self { server })
    }

    pub fn endpoint(&self) -> &str {
        self.server.endpoint()
    }
}

/// Answer one JSON-RPC request. The method and id are read from the parsed
/// body, never by searching the raw request text: a `tools/call` whose
/// arguments carry their own `"method":"initialize"` field is still a
/// `tools/call`, and a client that formats `"method": "initialize"` with a
/// space is still initializing. Each response carries the id of the request
/// it answers, so a client that checks the pairing sees a correct one.
fn response_for_request(request: &str, tools: &[StubTool]) -> String {
    let body = request
        .find("\r\n\r\n")
        .map(|index| &request[index + 4..])
        .unwrap_or("");
    let Ok(message) = serde_json::from_str::<Value>(body) else {
        return http_json(
            400,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}"#,
        );
    };
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    match message.get("method").and_then(Value::as_str) {
        Some("initialize") => rpc_result(
            id,
            json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "serverInfo": {"name": "plexus-stub", "version": "0.1.0"}
            }),
        ),
        Some("notifications/initialized") => http_empty(202),
        Some("tools/list") => {
            let listed = tools
                .iter()
                .map(|tool| {
                    json!({
                        "name": tool.name,
                        "description": format!("stub tool {}", tool.name),
                        "inputSchema": tool.input_schema,
                    })
                })
                .collect::<Vec<_>>();
            rpc_result(id, json!({ "tools": listed }))
        }
        Some("tools/call") => {
            let action = message
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            rpc_result(
                id,
                json!({
                    "content": [{"type": "text", "text": format!("stub-ok:{action}")}],
                    "isError": false
                }),
            )
        }
        _ => http_json(
            400,
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": "method not found"}
            })
            .to_string(),
        ),
    }
}

fn rpc_result(id: Value, result: Value) -> String {
    http_json(
        200,
        &json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(body: &str) -> String {
        format!(
            "POST /mcp HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn response_body(response: &str) -> Value {
        let body = &response[response.find("\r\n\r\n").expect("terminator") + 4..];
        serde_json::from_str(body).expect("JSON response")
    }

    #[test]
    fn the_method_is_read_from_the_body_not_searched_for_in_its_text() {
        let tools = vec![StubTool::simple("search")];
        let call = post(
            r#"{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"search","arguments":{"method":"initialize"}}}"#,
        );
        let reply = response_body(&response_for_request(&call, &tools));
        assert_eq!(
            reply["result"]["content"][0]["text"], "stub-ok:search",
            "{reply}"
        );
        assert_eq!(reply["id"], 41, "the reply must carry the request's id");

        let spaced = post(r#"{"jsonrpc": "2.0", "id": "a", "method": "initialize"}"#);
        let reply = response_body(&response_for_request(&spaced, &tools));
        assert_eq!(
            reply["result"]["serverInfo"]["name"], "plexus-stub",
            "{reply}"
        );
        assert_eq!(reply["id"], "a");

        let notification = post(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        assert!(response_for_request(&notification, &tools).starts_with("HTTP/1.1 202"));
    }
}
