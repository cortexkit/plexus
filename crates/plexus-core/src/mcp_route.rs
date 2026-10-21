//! MCP tool transport carried over a route-plane adapter.
//!
//! The adapter owns local child processes. Plexus only sends MCP `tools/list`
//! and `tools/call` operations to its configured module id, so unreviewed npm
//! code never receives Plexus's resolved vendor credentials.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::mcp_payload::{
    decode_tool_result, tool_result_from_response, tools_call_params, tools_from_response,
    tools_list_params,
};
use crate::mcp_remote::DiscoveredAction;
use crate::transport::{
    Retryability, TransmissionState, Transport, TransportRequest, TransportResponse,
    OPERATOR_DIAGNOSTIC_MESSAGE,
};
use crate::ResolvedCredential;

/// Errors while sending an MCP request to the route-plane adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpRouteError {
    NotSent,
    OutcomeUnknown,
    Transport,
}

/// Source used by the adapter to serve a successful route response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpRouteServedFrom {
    Live,
    Cache,
}

impl McpRouteServedFrom {
    fn from_wire(value: &str) -> Option<Self> {
        match value {
            "live" => Some(Self::Live),
            "cache" => Some(Self::Cache),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Cache => "cache",
        }
    }
}

/// A route-plane frame returned by the local-MCP adapter.
///
/// Successful frames carry the adapter's provenance envelope. Refusals are
/// route-plane ERROR frames, represented by [`Self::Error`] rather than a
/// field embedded in a successful payload.
#[derive(Debug, Clone, PartialEq)]
pub enum McpRouteFrame {
    Success {
        served_from: McpRouteServedFrom,
        observed_at_ms: u64,
        /// The child's MCP JSON-RPC response, without the adapter envelope.
        payload: Value,
    },
    Error {
        code: String,
        message: String,
        detail: Option<Value>,
    },
}

/// Narrow route seam for the local-MCP adapter. Requests and replies retain the
/// route-plane frame type so callers can distinguish a successful envelope from
/// an adapter refusal without inspecting child payload fields.
pub trait McpRoutePeer: Send + Sync {
    fn call(&self, request: Value) -> Result<McpRouteFrame, McpRouteError>;
}

/// A local MCP server selected for one Plexus connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRouteConnection {
    pub connection_id: String,
    pub server: String,
}

impl McpRouteConnection {
    pub fn new(connection_id: impl Into<String>, server: impl Into<String>) -> Self {
        Self {
            connection_id: connection_id.into(),
            server: server.into(),
        }
    }
}

/// Route-plane transport for MCP servers whose processes belong to an adapter.
pub struct McpRouteTransport<P> {
    peer: Arc<P>,
    connections: Mutex<HashMap<String, String>>,
}

impl<P> McpRouteTransport<P> {
    pub fn new(peer: Arc<P>) -> Self {
        Self {
            peer,
            connections: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_connection(&self, connection: McpRouteConnection) {
        if let Ok(mut connections) = self.connections.lock() {
            connections.insert(connection.connection_id, connection.server);
        }
    }

    pub fn has_connection(&self, connection_id: &str) -> bool {
        self.connections
            .lock()
            .map(|connections| connections.contains_key(connection_id))
            .unwrap_or(false)
    }

    pub fn peer(&self) -> &Arc<P> {
        &self.peer
    }
}

impl<P: McpRoutePeer> McpRouteTransport<P> {
    /// Discover actions from the adapter-managed server assigned to `connection_id`.
    pub fn discover(&self, connection_id: &str) -> Result<Vec<DiscoveredAction>, McpRouteError> {
        let server = self.server_for(connection_id)?;
        let mut actions = Vec::new();
        let mut params = tools_list_params();
        let mut cursors = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        let mut bytes = 0usize;
        for _ in 0..crate::mcp_remote::MAX_TOOL_PAGES {
            let frame = self
                .peer
                .call(adapter_request(server.clone(), "tools/list", params))?;
            let McpRouteFrame::Success { payload, .. } = frame else {
                return Err(McpRouteError::Transport);
            };
            bytes = bytes.saturating_add(
                serde_json::to_vec(&payload)
                    .map_err(|_| McpRouteError::Transport)?
                    .len(),
            );
            if bytes > crate::http_support::MAX_RESPONSE_BODY_BYTES {
                return Err(McpRouteError::Transport);
            }
            for tool in tools_from_response(&payload).map_err(|_| McpRouteError::Transport)? {
                let action =
                    DiscoveredAction::from_value(tool).map_err(|_| McpRouteError::Transport)?;
                if !names.insert(action.name.clone())
                    || actions.len() >= crate::mcp_remote::MAX_DISCOVERED_TOOLS
                {
                    return Err(McpRouteError::Transport);
                }
                actions.push(action);
            }
            match crate::mcp_remote::next_tool_cursor(&payload, &mut cursors)
                .map_err(|_| McpRouteError::Transport)?
            {
                None => return Ok(actions),
                Some(cursor) => params = serde_json::json!({"cursor": cursor}),
            }
        }
        Err(McpRouteError::Transport)
    }

    fn server_for(&self, connection_id: &str) -> Result<String, McpRouteError> {
        self.connections
            .lock()
            .map_err(|_| McpRouteError::Transport)?
            .get(connection_id)
            .filter(|server| !server.trim().is_empty())
            .cloned()
            .ok_or(McpRouteError::Transport)
    }

    fn dispatch_for_server(&self, request: TransportRequest, server: String) -> TransportResponse {
        let frame = adapter_request(
            server,
            "tools/call",
            tools_call_params(request.action, request.args),
        );
        match self.peer.call(frame) {
            Ok(response) => adapter_response(response),
            Err(McpRouteError::NotSent) => TransportResponse::transient_not_sent(),
            Err(McpRouteError::OutcomeUnknown) => TransportResponse::unknown(),
            Err(McpRouteError::Transport) => {
                eprintln!(warn transport: "local MCP adapter request failed");
                TransportResponse::unknown_with_error("mcp_route_transport_error")
            }
        }
    }
}

impl<P: McpRoutePeer> Transport for McpRouteTransport<P> {
    fn dispatch(
        &self,
        request: TransportRequest,
        _credential: &ResolvedCredential,
    ) -> TransportResponse {
        let Ok(server) = self.server_for(&request.connection_id) else {
            eprintln!(warn transport: "local MCP adapter connection is not configured");
            return TransportResponse::vendor_error("mcp_route_transport_error").not_sent();
        };
        self.dispatch_for_server(request, server)
    }
}

fn adapter_request(server: String, op: &str, params: Value) -> Value {
    json!({
        "server": server,
        "op": op,
        "payload": {"method": op, "params": params},
    })
}

fn adapter_response(frame: McpRouteFrame) -> TransportResponse {
    match frame {
        // Do not sniff child payloads for refusal fields. The provenance fields
        // are present only in success envelopes, so a body-sniffing consumer
        // would read fields that are absent by design on the refusal path it is
        // trying to detect. The route frame type is the discriminator.
        McpRouteFrame::Error {
            code,
            message,
            detail,
        } => adapter_refusal_response(code, message, detail),
        McpRouteFrame::Success {
            served_from,
            observed_at_ms,
            payload,
        } => {
            let Ok(result) = tool_result_from_response(payload) else {
                eprintln!(warn transport: "local MCP adapter returned an invalid tool response");
                return with_provenance(
                    TransportResponse::unknown_with_error("mcp_protocol_error"),
                    served_from,
                    observed_at_ms,
                );
            };
            if result
                .get("isError")
                .is_some_and(|value| !value.is_boolean())
            {
                return with_provenance(
                    TransportResponse::unknown_with_error("mcp_protocol_error"),
                    served_from,
                    observed_at_ms,
                );
            }
            if result
                .get("isError")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let detail = crate::http_support::bounded_json_for_log(&result, 4096);
                eprintln!(warn transport: "local MCP adapter vendor tool error: {}", detail);
                return with_provenance(
                    TransportResponse::vendor_error("mcp_tool_error"),
                    served_from,
                    observed_at_ms,
                );
            }
            with_provenance(
                TransportResponse::success(decode_tool_result(result)),
                served_from,
                observed_at_ms,
            )
        }
    }
}

fn with_provenance(
    mut response: TransportResponse,
    served_from: McpRouteServedFrom,
    observed_at_ms: u64,
) -> TransportResponse {
    response.served_from = Some(served_from.as_str().to_string());
    response.observed_at_ms = Some(observed_at_ms);
    response
}

/// Format the operator log line for an adapter refusal code this transport
/// does not recognize (one outside the fixed list matched in
/// `adapter_refusal_response`).
///
/// Kept apart from the `eprintln!` so a test can check the line's content: the
/// point is that the line NAMES the offending code, and a print alone cannot
/// be asserted. `rest_api::vendor_error_log_line` is split out the same way.
fn unknown_code_log_line(code: &str, message: &str) -> String {
    format!("local MCP adapter sent unknown refusal code '{code}': {message}")
}

fn adapter_refusal_response(
    code: String,
    message: String,
    detail: Option<Value>,
) -> TransportResponse {
    let (transmission, retryability) = match code.as_str() {
        "bad_request" | "server_unknown" | "server_disabled" | "initialize_failed" => {
            (TransmissionState::NotSent, Retryability::Terminal)
        }
        // A spawn failure means no child accepted the request, so the call stays
        // not-sent even though retrying after the cooldown may succeed.
        "spawn_failed" => (TransmissionState::NotSent, Retryability::Terminal),
        "child_framing_error" => (TransmissionState::OutcomeUnknown, Retryability::Terminal),
        "call_outcome_unknown" | "child_unresponsive" => {
            (TransmissionState::OutcomeUnknown, Retryability::Terminal)
        }
        "child_capacity" => (TransmissionState::NotSent, Retryability::AutoRetryable),
        // The route vocabulary is closed. A code outside it is an adapter
        // protocol violation, not a new refusal posture for this transport.
        //
        // LOGGED RATHER THAN RETURNED. The caller-facing message is replaced by a
        // fixed phrase (see `sanitize_message`), so naming the offending code in
        // the reply would reach nobody. This arm fires on VERSION SKEW between two
        // independently deployed modules, where the first question is always
        // "which code" — and without it, answering means instrumenting the
        // adapter. The adapter's own message rides along, since a violating
        // adapter may still explain itself.
        _ => {
            eprintln!(warn transport: "{}", unknown_code_log_line(&code, &message));
            return TransportResponse::unknown_with_error("mcp_route_protocol_error");
        }
    };
    let retry_after_ms = (code == "spawn_failed")
        .then(|| {
            detail
                .as_ref()
                .and_then(|detail| detail.get("retry_after_ms"))
                .and_then(Value::as_u64)
        })
        .flatten();
    // The adapter's message can carry a child's stderr, file paths or vendor
    // text, and this reply crosses the facade to an agent. It goes to the
    // operator log; the agent gets the fixed phrase every other vendor
    // failure gets, while the closed refusal code still says what happened.
    eprintln!(warn transport: "{}", refusal_log_line(&code, &message));
    TransportResponse {
        transmission,
        retryability,
        response: None,
        error_code: Some(code),
        error_message: Some(OPERATOR_DIAGNOSTIC_MESSAGE.to_string()),
        vendor_request_id: None,
        served_from: None,
        observed_at_ms: None,
        retry_after_ms,
        error_signal: None,
    }
}

/// Longest adapter refusal message one log line carries.
const REFUSAL_MESSAGE_LOG_LIMIT: usize = 4096;

/// Format the operator diagnostic for an adapter refusal in the closed route
/// vocabulary, with the adapter's message bounded so a child's full stderr
/// cannot flood the log.
fn refusal_log_line(code: &str, message: &str) -> String {
    format!(
        "local MCP adapter refused '{code}': {}",
        crate::http_support::truncate_utf8(message, REFUSAL_MESSAGE_LOG_LIMIT)
    )
}

/// Production route peer backed by the shared subc Rust client. The connection
/// owns a long-lived runtime; synchronous calls wait for tasks on its worker so
/// async module handlers never have to nest runtimes or spawn per-call threads.
pub struct SubcMcpRoutePeer {
    consumer: Arc<subc_client_rs::SubcConsumer>,
    target: subc_protocol::RouteTarget,
    identity: subc_protocol::BindIdentity,
    runtime: Option<Arc<tokio::runtime::Runtime>>,
}

impl Drop for SubcMcpRoutePeer {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            if let Some(owned) = Arc::into_inner(runtime) {
                owned.shutdown_background();
            }
        }
    }
}

impl SubcMcpRoutePeer {
    pub fn connect(
        connection_file: &std::path::Path,
        module_id: impl Into<String>,
        identity: subc_protocol::BindIdentity,
    ) -> Result<Self, McpRouteError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map(Arc::new)
            .map_err(|_| McpRouteError::Transport)?;
        let connection_file = connection_file.to_path_buf();
        let connected = run_on(&runtime, async move {
            subc_client_rs::SubcConsumer::connect(
                &connection_file,
                subc_client_rs::ConsumerOptions::default(),
            )
            .await
            .map_err(|_| McpRouteError::NotSent)
        });
        let consumer = match connected {
            Ok(consumer) => consumer,
            Err(error) => {
                if let Some(owned) = Arc::into_inner(runtime) {
                    owned.shutdown_background();
                }
                return Err(error);
            }
        };
        Ok(Self {
            consumer: Arc::new(consumer),
            target: subc_protocol::RouteTarget::ManagementSurface {
                module_id: module_id.into(),
            },
            identity,
            runtime: Some(runtime),
        })
    }
}

impl McpRoutePeer for SubcMcpRoutePeer {
    fn call(&self, request: Value) -> Result<McpRouteFrame, McpRouteError> {
        let body = serde_json::to_vec(&request).map_err(|_| McpRouteError::NotSent)?;
        let consumer = Arc::clone(&self.consumer);
        let target = self.target.clone();
        let identity = self.identity.clone();
        let Some(runtime) = self.runtime.as_ref() else {
            return Err(McpRouteError::NotSent);
        };
        run_on(runtime, async move {
            match consumer
                .call(
                    target,
                    identity,
                    body,
                    subc_client_rs::CallOptions::default(),
                )
                .await
            {
                Ok(bytes) => decode_success_frame(&bytes),
                Err(subc_client_rs::CallError::NotSent(_)) => Err(McpRouteError::NotSent),
                Err(subc_client_rs::CallError::Module(error)) => Ok(McpRouteFrame::Error {
                    code: error.code,
                    message: error.message,
                    detail: error.detail,
                }),
                Err(_) => Err(McpRouteError::OutcomeUnknown),
            }
        })
    }
}

fn decode_success_frame(bytes: &[u8]) -> Result<McpRouteFrame, McpRouteError> {
    let response = serde_json::from_slice::<Value>(bytes).map_err(|_| McpRouteError::Transport)?;
    let served_from = response
        .get("served_from")
        .and_then(Value::as_str)
        .and_then(McpRouteServedFrom::from_wire)
        .ok_or(McpRouteError::Transport)?;
    let observed_at_ms = response
        .get("observed_at_ms")
        .and_then(Value::as_u64)
        .ok_or(McpRouteError::Transport)?;
    let payload = response
        .get("payload")
        .cloned()
        .ok_or(McpRouteError::Transport)?;
    Ok(McpRouteFrame::Success {
        served_from,
        observed_at_ms,
        payload,
    })
}

fn run_on<F, T>(runtime: &Arc<tokio::runtime::Runtime>, future: F) -> Result<T, McpRouteError>
where
    F: std::future::Future<Output = Result<T, McpRouteError>> + Send + 'static,
    T: Send + 'static,
{
    crate::transport::wait_on_runtime(runtime, future).map_err(|_| McpRouteError::OutcomeUnknown)?
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

    use crate::test_scratch::Scratch;

    use super::*;

    #[test]
    fn route_call_bridge_reuses_the_runtime_worker() {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap(),
        );
        let start = std::time::Instant::now();
        let mut threads = std::collections::HashSet::new();
        for _ in 0..20 {
            threads.insert(run_on(&runtime, async { Ok(std::thread::current().id()) }).unwrap());
        }
        println!(
            "20 route calls: elapsed_us={} execution_threads={}",
            start.elapsed().as_micros(),
            threads.len()
        );
        let count = threads.len();
        Arc::into_inner(runtime).unwrap().shutdown_background();
        assert_eq!(
            count, 1,
            "route calls must reuse the runtime worker, not spawn one OS thread per call"
        );
    }

    #[test]
    #[ignore = "diagnostic allocation measurement"]
    fn measure_route_error_diagnostic_serialization() {
        let value = json!({"isError":true, "content":[{"text":"x".repeat(1024 * 1024)}]});
        let start = std::time::Instant::now();
        let serialized = value.to_string();
        println!(
            "full_error_serialization_bytes={} elapsed_us={}",
            serialized.len(),
            start.elapsed().as_micros()
        );
        let start = std::time::Instant::now();
        let bounded = crate::http_support::bounded_json_for_log(&value, 4096);
        println!(
            "bounded_error_serialization_bytes={} elapsed_us={}",
            bounded.len(),
            start.elapsed().as_micros()
        );
        assert!(bounded.len() <= 4096);
    }
    use crate::{
        ingest_value, jcs_sha256, CatalogActionInput, GovernanceEngine, GrantInput, PlexusStore,
        PollCycle, Poller, StubCredentialSource, TriggerSubscription, AUTHORITY_POLL,
        CATALOG_PRINCIPAL,
    };

    type RoutePoller = Poller<StubCredentialSource, McpRouteTransport<StubAdapter>>;
    type RouteEngine = GovernanceEngine<StubCredentialSource, McpRouteTransport<StubAdapter>>;
    type RoutePollerFixture = (RoutePoller, RouteEngine, Scratch, String, Arc<StubAdapter>);

    #[derive(Default)]
    struct StubAdapter {
        responses: Mutex<VecDeque<Result<McpRouteFrame, McpRouteError>>>,
        calls: Mutex<Vec<Value>>,
    }

    impl StubAdapter {
        fn push_success(
            &self,
            served_from: McpRouteServedFrom,
            observed_at_ms: u64,
            payload: Value,
        ) {
            self.responses
                .lock()
                .expect("stub response queue")
                .push_back(Ok(McpRouteFrame::Success {
                    served_from,
                    observed_at_ms,
                    payload,
                }));
        }

        fn push_error(&self, code: &str) {
            self.responses
                .lock()
                .expect("stub response queue")
                .push_back(Ok(error_frame(code, None)));
        }
    }

    impl McpRoutePeer for StubAdapter {
        fn call(&self, request: Value) -> Result<McpRouteFrame, McpRouteError> {
            self.calls.lock().expect("stub call log").push(request);
            self.responses
                .lock()
                .expect("stub response queue")
                .pop_front()
                .unwrap_or(Err(McpRouteError::Transport))
        }
    }

    fn error_frame(code: &str, detail: Option<Value>) -> McpRouteFrame {
        McpRouteFrame::Error {
            code: code.to_string(),
            message: format!("adapter refused {code}"),
            detail,
        }
    }

    fn transport() -> (McpRouteTransport<StubAdapter>, Arc<StubAdapter>) {
        let peer = Arc::new(StubAdapter::default());
        let transport = McpRouteTransport::new(Arc::clone(&peer));
        transport.register_connection(McpRouteConnection::new("local", "fixture-server"));
        (transport, peer)
    }

    #[test]
    fn missing_adapter_is_terminal_not_sent() {
        let peer = Arc::new(StubAdapter::default());
        let transport = McpRouteTransport::new(Arc::clone(&peer));
        let result = transport.dispatch(request(), &ResolvedCredential::anonymous());
        assert_eq!(result.transmission, TransmissionState::NotSent);
        assert_eq!(result.retryability, Retryability::Terminal);
        assert!(peer.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn route_discovery_reads_all_pages_and_rejects_cursor_cycles() {
        for repeat in [false, true] {
            let (transport, peer) = transport();
            peer.push_success(McpRouteServedFrom::Live, 1, json!({"result":{"tools":[{"name":"first", "inputSchema":{}}], "nextCursor":"next"}}));
            let mut page = json!({"tools":[{"name":"second", "inputSchema":{}}]});
            if repeat {
                page["nextCursor"] = json!("next");
            }
            peer.push_success(McpRouteServedFrom::Live, 1, json!({"result":page}));
            let actions = transport.discover("local");
            if repeat {
                assert_eq!(actions.unwrap_err(), McpRouteError::Transport);
            } else {
                assert_eq!(
                    actions.unwrap().len(),
                    2,
                    "every tool page must be discovered"
                );
            }
            assert_eq!(
                peer.calls.lock().unwrap()[1]["payload"]["params"]["cursor"],
                "next"
            );
            assert_eq!(
                peer.calls.lock().unwrap().len(),
                2,
                "a cursor cycle must stop before another vendor call"
            );
        }
    }

    #[test]
    fn tool_discovery_stops_after_one_hundred_unique_cursor_pages() {
        let (transport, peer) = transport();
        for page in 0..101 {
            peer.push_success(
                McpRouteServedFrom::Live,
                1,
                json!({"result":{"tools":[],"nextCursor":format!("page-{page}")}}),
            );
        }
        assert_eq!(
            transport.discover("local").unwrap_err(),
            McpRouteError::Transport
        );
        assert_eq!(
            peer.calls.lock().unwrap().len(),
            100,
            "discovery must stop at the independent 100-page bound"
        );
    }

    fn request() -> TransportRequest {
        TransportRequest {
            request_id: "request".to_string(),
            connection_id: "local".to_string(),
            action: "list_issues".to_string(),
            args: json!({"owner": "cortexkit"}),
            credential_fingerprint: "unused".to_string(),
        }
    }

    #[test]
    fn vendor_tool_error_points_to_operator_log_without_echoing_payload() {
        let (transport, peer) = transport();
        peer.push_success(
            McpRouteServedFrom::Live,
            1_710_000_000_000,
            json!({"result": {"isError": true, "content": [{
                "type": "text", "text": "ghs_SECRET123 https://example.test/?token=abc"
            }]}}),
        );
        let response = transport.dispatch(
            request(),
            &ResolvedCredential::new(b"credential".to_vec(), None, 1),
        );
        assert_eq!(response.error_code.as_deref(), Some("mcp_tool_error"));
        let message = response.error_message.as_deref().expect("agent error text");
        assert!(message.contains("ck module logs plexus"), "{message}");
        assert!(!message.contains("ghs_SECRET123"), "{message}");
        assert!(!message.contains("?token=abc"), "{message}");
        for flag in [json!("true"), json!(1), Value::Null] {
            peer.push_success(
                McpRouteServedFrom::Live,
                1_710_000_000_000,
                json!({"result":{"isError":flag,"content":[]}}),
            );
            let malformed = transport.dispatch(request(), &ResolvedCredential::anonymous());
            assert_eq!(
                malformed.transmission,
                TransmissionState::OutcomeUnknown,
                "invalid isError must not become a successful route result"
            );
            assert_eq!(malformed.error_code.as_deref(), Some("mcp_protocol_error"));
        }
    }

    #[test]
    fn route_adapter_uses_the_settled_envelopes_and_surfaces_provenance() {
        let (transport, peer) = transport();
        peer.push_success(
            McpRouteServedFrom::Live,
            1_710_000_000_000,
            json!({
                "result": {"tools": [{
                    "name": "list_issues", "inputSchema": {"type": "object"}
                }]}
            }),
        );
        let actions = transport.discover("local").expect("adapter tools/list");
        assert_eq!(actions[0].name, "list_issues");

        // This is a successful MCP payload whose content happens to contain an
        // error-shaped field. It must remain success because its ROUTE FRAME is
        // successful; only ERROR frames represent adapter refusals.
        peer.push_success(
            McpRouteServedFrom::Cache,
            1_710_000_000_123,
            json!({
                "result": {
                    "content": [{"type": "text", "text": "{\"issues\":[{\"number\":4}]}"}],
                    "error": {"code": "child_capacity"}
                }
            }),
        );
        let response = transport.dispatch(request(), &ResolvedCredential::anonymous());
        assert_eq!(
            response.response.expect("successful call")["issues"][0]["number"],
            4
        );
        assert_eq!(response.served_from.as_deref(), Some("cache"));
        assert_eq!(response.observed_at_ms, Some(1_710_000_000_123));

        let calls = peer.calls.lock().expect("stub call log");
        assert_eq!(
            calls[0],
            json!({
                "server": "fixture-server",
                "op": "tools/list",
                "payload": {"method": "tools/list", "params": {}}
            })
        );
        assert_eq!(
            calls[1],
            json!({
                "server": "fixture-server",
                "op": "tools/call",
                "payload": {
                    "method": "tools/call",
                    "params": {"name": "list_issues", "arguments": {"owner": "cortexkit"}}
                }
            })
        );
    }

    #[test]
    fn success_envelope_parses_optional_spawn_elapsed_ms() {
        for metadata in [
            None,
            Some(json!(4_000)),
            Some(json!(0)),
            Some(json!("not a number")),
            Some(json!({"unexpected": true})),
        ] {
            let mut response = json!({
                "served_from": "live", "observed_at_ms": 1_710_000_000_000u64,
                "payload": {"result": {"content": []}}
            });
            if let Some(metadata) = metadata {
                response["spawn_elapsed_ms"] = metadata;
            }
            assert!(
                matches!(
                    decode_success_frame(&serde_json::to_vec(&response).unwrap()),
                    Ok(McpRouteFrame::Success { .. })
                ),
                "unused spawn metadata must not refuse success"
            );
        }
    }

    fn assert_refusal_posture(
        code: &str,
        transmission: TransmissionState,
        retryability: Retryability,
    ) {
        let response = adapter_response(error_frame(code, None));
        assert_eq!(response.error_code.as_deref(), Some(code));
        assert_eq!(response.transmission, transmission);
        assert_eq!(response.retryability, retryability);
    }

    #[test]
    fn bad_request_error_frame_is_not_sent_and_terminal() {
        assert_refusal_posture(
            "bad_request",
            TransmissionState::NotSent,
            Retryability::Terminal,
        );
    }

    /// An adapter refusal never relays the adapter's own message to the agent.
    ///
    /// The message can quote a child process's stderr or a local path, and the
    /// reply crosses the facade to an agent. Every refusal code in the closed
    /// vocabulary is checked, since each one builds its reply on the same
    /// path; the operator log line keeps the text, bounded.
    #[test]
    fn adapter_refusal_text_reaches_the_operator_log_not_the_agent() {
        let leaked = "spawn: /Users/someone/.npm/_npx/9f/node_modules/.bin/server: ghs_CANARY";
        for code in [
            "bad_request",
            "server_unknown",
            "server_disabled",
            "initialize_failed",
            "spawn_failed",
            "child_framing_error",
            "call_outcome_unknown",
            "child_unresponsive",
            "child_capacity",
        ] {
            let response = adapter_response(McpRouteFrame::Error {
                code: code.to_string(),
                message: leaked.to_string(),
                detail: None,
            });
            assert_eq!(response.error_code.as_deref(), Some(code));
            assert_eq!(
                response.error_message.as_deref(),
                Some(OPERATOR_DIAGNOSTIC_MESSAGE),
                "{code} relayed adapter text to the agent: {response:?}"
            );
        }
        let line = refusal_log_line("spawn_failed", leaked);
        assert!(
            line.contains("spawn_failed") && line.contains(leaked),
            "{line}"
        );
        let long = "é".repeat(REFUSAL_MESSAGE_LOG_LIMIT);
        assert!(refusal_log_line("bad_request", &long).len() < long.len());
    }

    #[test]
    fn server_unknown_error_frame_is_not_sent_and_terminal() {
        assert_refusal_posture(
            "server_unknown",
            TransmissionState::NotSent,
            Retryability::Terminal,
        );
    }

    #[test]
    fn server_disabled_error_frame_is_not_sent_and_terminal() {
        assert_refusal_posture(
            "server_disabled",
            TransmissionState::NotSent,
            Retryability::Terminal,
        );
    }

    #[test]
    fn spawn_failed_error_frame_is_not_sent_and_terminal() {
        let response = adapter_response(error_frame(
            "spawn_failed",
            Some(json!({"cause": "exec", "retry_after_ms": 60_000})),
        ));
        assert_eq!(response.error_code.as_deref(), Some("spawn_failed"));
        assert_eq!(response.transmission, TransmissionState::NotSent);
        assert_eq!(response.retryability, Retryability::Terminal);
        assert_eq!(response.retry_after_ms, Some(60_000));
    }

    #[test]
    fn spawn_failed_without_a_cooldown_detail_leaves_retry_after_absent() {
        let response = adapter_response(error_frame("spawn_failed", None));
        assert_eq!(response.transmission, TransmissionState::NotSent);
        assert_eq!(response.retry_after_ms, None);
    }

    #[test]
    fn initialize_failed_error_frame_is_provably_not_sent_and_terminal() {
        assert_refusal_posture(
            "initialize_failed",
            TransmissionState::NotSent,
            Retryability::Terminal,
        );
    }

    #[test]
    fn child_framing_error_frame_keeps_the_write_outcome_unknown() {
        assert_refusal_posture(
            "child_framing_error",
            TransmissionState::OutcomeUnknown,
            Retryability::Terminal,
        );
    }

    /// A call written to a child that dies before replying may have produced a
    /// side effect. Treating it as a plain failure would make a caller retry a
    /// request whose outcome is unknowable.
    ///
    /// Mutation-proved: changing this mapping to `TransmissionState::Sent`
    /// fails the transmission assertion below.
    #[test]
    fn call_outcome_unknown_error_frame_stays_outcome_unknown() {
        assert_refusal_posture(
            "call_outcome_unknown",
            TransmissionState::OutcomeUnknown,
            Retryability::Terminal,
        );
    }

    #[test]
    fn child_unresponsive_error_frame_stays_outcome_unknown() {
        assert_refusal_posture(
            "child_unresponsive",
            TransmissionState::OutcomeUnknown,
            Retryability::Terminal,
        );
    }

    /// Capacity is the sole retryable refusal: no child accepted the request,
    /// and the next capacity slot can serve it without any repair.
    ///
    /// Mutation-proved: changing the retryability to terminal fails the
    /// assertion below, which would otherwise suspend a watch on a passing load
    /// spike.
    #[test]
    fn child_capacity_error_frame_is_not_sent_and_retryable() {
        assert_refusal_posture(
            "child_capacity",
            TransmissionState::NotSent,
            Retryability::AutoRetryable,
        );
    }

    /// An unknown refusal code is a protocol failure, AND the refusal names which
    /// code it was.
    ///
    /// The posture assertions below say the transport handled it safely; they say
    /// nothing about whether an operator can act on it. This arm fires on VERSION
    /// SKEW between two independently deployed modules, so "which code" is always
    /// the first question, and reporting only the category leaves answering it to
    /// instrumenting the adapter.
    ///
    /// Mutation-proved: reverting the message to the constant "local MCP adapter
    /// sent an unknown refusal code" fails the naming assertions while every
    /// posture assertion here stays green — which is exactly how the gap survived.
    #[test]
    fn unknown_error_frame_code_is_a_protocol_failure() {
        let response = adapter_response(error_frame("unrecognized_code", None));
        assert_eq!(
            response.error_code.as_deref(),
            Some("mcp_route_protocol_error")
        );
        assert_eq!(response.transmission, TransmissionState::OutcomeUnknown);
        assert_eq!(response.retryability, Retryability::Terminal);

        // The caller-facing message is a fixed phrase by design, so the naming
        // lives on the OPERATOR path. Asserting the log line rather than the
        // reply is the difference between testing what an agent sees and testing
        // what a person diagnosing a version skew can act on.
        let line = unknown_code_log_line("unrecognized_code", "adapter said why");
        assert!(
            line.contains("unrecognized_code"),
            "the diagnostic must name the code the adapter sent, or diagnosing a \
             version skew means instrumenting the adapter: {line}"
        );
        assert!(
            line.contains("adapter said why"),
            "a violating adapter may still explain itself, and that explanation \
             is the other half of the diagnosis: {line}"
        );
    }

    fn route_poller_fixture(label: &str) -> RoutePollerFixture {
        // The macOS clock ticks in microseconds, so the counter prevents same-tick test nonce collisions.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = format!(
            "{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let path = Scratch::database(&format!("mcp-route-poller-{label}"));
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("{label}-{unique}"),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        };
        let store = PlexusStore::open(&descriptor).expect("open test store");
        let principal = "direct";
        let connection_id = "route-connection";
        let action = "read_feed";
        let binding_handle = b"test:route-poller-binding";
        store
            .insert_connection(principal, connection_id, "mock", "pending", &json!({}))
            .expect("insert connection");
        let ticket = store
            .create_binding_ticket(principal, connection_id, binding_handle)
            .expect("issue binding ticket");
        store
            .connect_with_ticket(principal, &ticket.ticket_id)
            .expect("consume binding ticket")
            .expect("connection activates");
        store
            .upsert_manifest(
                CATALOG_PRINCIPAL,
                &ingest_value(json!({
                    "schema_version": 1,
                    "key": "mock",
                    "name": "Mock",
                    "description": "route poller test vendor",
                    "reuse_path": "mcp_direct",
                    "reuse_rationale": "in-process tests",
                    "tier": "S2",
                    "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
                    "auth": {"mode": "api_key"},
                    "credential_bindings": [{
                        "ref_role": "api_key",
                        "placement": "header",
                        "key": "Authorization",
                        "prefix": "Bearer ",
                        "required": true
                    }],
                    "resource_filters": {"required": [], "optional": [], "write_enabling": []},
                    "actions_baseline": [{
                        "name": action,
                        "risk": "read",
                        "poll": {"item_kind": "issue", "cursor_kind": "sync_token"}
                    }],
                    "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 30}},
                    "availability": "ga"
                }))
                .expect("manifest"),
            )
            .expect("store manifest");
        let peer = Arc::new(StubAdapter::default());
        let transport = Arc::new(McpRouteTransport::new(Arc::clone(&peer)));
        transport.register_connection(McpRouteConnection::new(connection_id, "fixture-server"));
        let credentials = Arc::new(StubCredentialSource::default());
        credentials.set_success(binding_handle, b"vendor-token".to_vec(), None, 1);
        let engine = GovernanceEngine::new(Arc::new(store), credentials, transport);
        let schema = json!({"type": "object"});
        engine
            .store()
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: connection_id.to_string(),
                principal: principal.to_string(),
                name: action.to_string(),
                title: Some(action.to_string()),
                schema: schema.clone(),
                schema_hash: jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
                risk: "read".to_string(),
                severity: "S2".to_string(),
                ask_first: false,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("upsert catalog action");
        let expiry = crate::now_ms() + 3_600_000;
        engine
            .store()
            .insert_grant(&GrantInput {
                grant_id: "route-poll-grant".to_string(),
                principal: principal.to_string(),
                connection_id: connection_id.to_string(),
                grantee_principal: principal.to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec![action.to_string()],
                authority_kind: AUTHORITY_POLL.to_string(),
                expires_at: Some(expiry),
            })
            .expect("insert poll grant");
        let subscription = engine
            .store()
            .subscribe(principal, connection_id, action, 30)
            .expect("subscribe store")
            .expect("subscription accepted");
        (
            Poller::new(engine.clone()),
            engine,
            path,
            subscription.subscription_id,
            peer,
        )
    }

    /// A `spawn_failed` refusal means the local MCP adapter could not start
    /// the server process and is waiting out a cooldown; it recovers without
    /// an operator. Five such refusals driven through the real poller must
    /// not count as vendor failures, so the stored failure count stays at
    /// zero and the scheduler's circuit breaker, which suspends a watch after
    /// repeated vendor failures, leaves the watch active.
    #[test]
    fn repeated_spawn_failed_error_frames_leave_the_watch_active() {
        let (poller, engine, path, subscription_id, peer) = route_poller_fixture("spawn-failed");
        for _ in 0..5 {
            peer.push_error("spawn_failed");
        }

        for _ in 0..5 {
            assert_eq!(
                poller.poll_once("direct", &subscription_id),
                PollCycle::Inconclusive {
                    code: "spawn_failed".to_string()
                }
            );
        }

        let stored: TriggerSubscription = engine
            .store()
            .subscription("direct", &subscription_id)
            .expect("read subscription")
            .expect("subscription exists");
        assert_eq!(stored.status, "active");
        assert_eq!(stored.consecutive_vendor_failures, 0);
        let _ = std::fs::remove_file(path);
    }

    /// A successful live reply cannot increase the scheduler's vendor-failure
    /// streak; only a failure is evidence that the vendor is unhealthy.
    ///
    #[test]
    fn live_success_leaves_the_vendor_failure_streak_at_zero() {
        let (poller, engine, path, subscription_id, peer) = route_poller_fixture("slow-spawn");
        peer.push_success(
            McpRouteServedFrom::Live,
            1_710_000_000_000,
            json!({
                "result": {
                    "structuredContent": {"items": [], "next_cursor": "after-shed"}
                }
            }),
        );

        assert_eq!(
            poller.poll_once("direct", &subscription_id),
            PollCycle::Completed {
                inserted: 0,
                duplicates: 0
            }
        );
        let stored: TriggerSubscription = engine
            .store()
            .subscription("direct", &subscription_id)
            .expect("read subscription")
            .expect("subscription exists");
        assert_eq!(stored.status, "active");
        assert_eq!(stored.consecutive_vendor_failures, 0);
        let _ = std::fs::remove_file(path);
    }
}
