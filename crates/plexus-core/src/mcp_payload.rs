//! Shared MCP request and result handling for every MCP transport.
//!
//! Both remote HTTP and route-plane adapters speak MCP tool semantics. Keeping
//! the wire shapes here prevents the two transports from drifting on envelopes
//! such as JSON serialized inside a text content block.

use std::collections::HashSet;

use serde_json::{json, Value};

use crate::mcp_remote::{
    next_tool_cursor, DiscoveredAction, McpRemoteError, MAX_DISCOVERED_TOOLS, MAX_TOOL_PAGES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpPayloadError {
    InvalidResponse,
}

/// Why a `tools/list` walk ended without a complete catalog. Each transport
/// maps these onto its own error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToolPagesError<E> {
    /// Fetching a page failed with the transport's own error.
    Fetch(E),
    /// The pages together exceeded the response-size limit, or held more tools
    /// than the tool-count limit allows.
    TooLarge,
    /// A page was malformed, repeated a tool name or cursor, or the walk
    /// reached the page limit.
    Protocol,
    /// A tool entry could not be read as an action.
    Action(McpRemoteError),
}

/// Walk `tools/list` pages through `fetch`, which sends one request with the
/// given params and returns the JSON-RPC response, until a page has no next
/// cursor. The size, tool-count and page limits and the duplicate checks are
/// the same for every MCP transport.
pub(crate) fn collect_tool_pages<E>(
    mut fetch: impl FnMut(Value) -> Result<Value, E>,
) -> Result<Vec<DiscoveredAction>, ToolPagesError<E>> {
    let mut actions = Vec::new();
    let mut params = tools_list_params();
    let mut cursors = HashSet::new();
    let mut names = HashSet::new();
    let mut bytes = 0usize;
    for _ in 0..MAX_TOOL_PAGES {
        let page = fetch(params).map_err(ToolPagesError::Fetch)?;
        bytes = bytes.saturating_add(
            serde_json::to_vec(&page)
                .map_err(|_| ToolPagesError::Protocol)?
                .len(),
        );
        if bytes > crate::http_support::MAX_RESPONSE_BODY_BYTES {
            return Err(ToolPagesError::TooLarge);
        }
        for tool in tools_from_response(&page).map_err(|_| ToolPagesError::Protocol)? {
            let action = DiscoveredAction::from_value(tool).map_err(ToolPagesError::Action)?;
            if !names.insert(action.name.clone()) {
                return Err(ToolPagesError::Protocol);
            }
            if actions.len() >= MAX_DISCOVERED_TOOLS {
                return Err(ToolPagesError::TooLarge);
            }
            actions.push(action);
        }
        match next_tool_cursor(&page, &mut cursors).map_err(|_| ToolPagesError::Protocol)? {
            None => return Ok(actions),
            Some(cursor) => params = json!({"cursor": cursor}),
        }
    }
    Err(ToolPagesError::Protocol)
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

pub(crate) fn tools_from_response(response: &Value) -> Result<&[Value], McpPayloadError> {
    response
        .get("result")
        .and_then(Value::as_object)
        .and_then(|result| result.get("tools"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(McpPayloadError::InvalidResponse)
}

pub(crate) fn tool_result_from_response(mut response: Value) -> Result<Value, McpPayloadError> {
    if !response.get("result").is_some_and(Value::is_object) {
        return Err(McpPayloadError::InvalidResponse);
    }
    response
        .get_mut("result")
        .map(Value::take)
        .ok_or(McpPayloadError::InvalidResponse)
}

/// Decode an MCP `tools/call` result into the payload its consumers need.
///
/// MCP does not return a tool's output as a bare object. Every result is a list
/// of content blocks, and a vendor returning JSON puts it in a text block as a
/// serialized string. Centralizing this keeps the route-plane transport aligned
/// with the remote transport when a server uses that common response shape.
pub(crate) fn decode_tool_result(mut result: Value) -> Value {
    if let Some(structured) = result.get_mut("structuredContent") {
        if !structured.is_null() {
            return structured.take();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> Value {
        json!({"name": name, "inputSchema": {"type": "object"}})
    }

    fn page(tools: Vec<Value>, cursor: Option<&str>) -> Value {
        let mut result = json!({"tools": tools});
        if let Some(cursor) = cursor {
            result["nextCursor"] = json!(cursor);
        }
        json!({"jsonrpc": "2.0", "id": 1, "result": result})
    }

    /// Runs the walk over fixed pages, recording the params each fetch got.
    fn walk(
        pages: Vec<Value>,
    ) -> (
        Result<Vec<String>, ToolPagesError<&'static str>>,
        Vec<Value>,
    ) {
        let mut sent = Vec::new();
        let mut pages = pages.into_iter();
        let result = collect_tool_pages(|params| {
            sent.push(params);
            pages.next().ok_or("no more pages")
        })
        .map(|actions| actions.into_iter().map(|action| action.name).collect());
        (result, sent)
    }

    #[test]
    fn tool_pages_follow_cursors_until_a_page_has_none() {
        let (result, sent) = walk(vec![
            page(vec![tool("a"), tool("b")], Some("c1")),
            page(vec![tool("c")], Some("c2")),
            page(vec![], None),
        ]);
        assert_eq!(result, Ok(vec!["a".into(), "b".into(), "c".into()]));
        assert_eq!(
            sent,
            [json!({}), json!({"cursor": "c1"}), json!({"cursor": "c2"})]
        );
        // A null cursor ends the walk like an absent one.
        let mut last = page(vec![tool("a")], None);
        last["result"]["nextCursor"] = Value::Null;
        assert_eq!(walk(vec![last]).0, Ok(vec!["a".into()]));
    }

    #[test]
    fn tool_pages_refuse_what_both_transports_refused() {
        let protocol = Err(ToolPagesError::Protocol);
        assert_eq!(
            walk(vec![
                page(vec![tool("a")], Some("c1")),
                page(vec![tool("b")], Some("c1"))
            ])
            .0,
            protocol,
            "a repeated cursor"
        );
        assert_eq!(
            walk(vec![page(vec![tool("a")], Some(""))]).0,
            protocol,
            "an empty cursor"
        );
        assert_eq!(
            walk(vec![
                page(vec![tool("a")], Some("c1")),
                page(vec![tool("a")], None)
            ])
            .0,
            protocol,
            "a tool name seen on an earlier page"
        );
        assert_eq!(
            walk(vec![json!({"result": {"tools": {}}})]).0,
            protocol,
            "tools that are not a list"
        );
        assert_eq!(
            walk(vec![json!({"result": [{"tools": []}]})]).0,
            protocol,
            "a result that is not an object"
        );
        assert_eq!(
            walk(vec![page(vec![json!({"name": "a"})], None)]).0,
            Err(ToolPagesError::Action(McpRemoteError::Protocol)),
            "a tool without a schema"
        );
        assert_eq!(walk(vec![]).0, Err(ToolPagesError::Fetch("no more pages")));

        let endless: Vec<Value> = (0..=MAX_TOOL_PAGES)
            .map(|n| page(vec![], Some(&format!("c{n}"))))
            .collect();
        let (result, sent) = walk(endless);
        assert_eq!(result, protocol, "the page limit");
        assert_eq!(sent.len(), MAX_TOOL_PAGES);
    }

    #[test]
    fn tool_pages_stop_at_the_size_and_tool_count_limits() {
        let tools: Vec<Value> = (0..MAX_DISCOVERED_TOOLS)
            .map(|n| tool(&format!("t{n}")))
            .collect();
        assert_eq!(
            walk(vec![page(tools.clone(), None)])
                .0
                .map(|names| names.len()),
            Ok(MAX_DISCOVERED_TOOLS),
            "tool-count limit"
        );
        assert_eq!(
            walk(vec![
                page(tools, Some("more")),
                page(vec![tool("one-more")], None)
            ])
            .0,
            Err(ToolPagesError::TooLarge),
            "tool-count limit"
        );
        let mut oversized = page(vec![], None);
        oversized["result"]["padding"] =
            json!("x".repeat(crate::http_support::MAX_RESPONSE_BODY_BYTES));
        assert_eq!(walk(vec![oversized]).0, Err(ToolPagesError::TooLarge));
    }
}
