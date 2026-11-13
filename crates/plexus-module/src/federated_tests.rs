use super::*;
use subc_protocol::{
    manifest::ProviderRole,
    scope::{
        FederatedAttributes, FederatedPeerClass, ParentState, RemoteClaim, ScopeAttributes,
        ScopeKind, ScopeStamp,
    },
    BindIdentity, RouteTarget,
};

fn reserved(module_id: &str) -> Principal {
    Principal::Reserved {
        module_id: module_id.into(),
    }
}

fn stamp() -> ScopeStamp {
    ScopeStamp::new(
        reserved("callosum"),
        "fed-base:peer:pairing",
        1,
        ScopeKind::Federated,
    )
    .with_attributes(
        ScopeAttributes::new().with_federated(Some(FederatedAttributes::new(
            FederatedPeerClass::Computer,
            "a".repeat(32),
            "pairing".into(),
            "Peer".into(),
        ))),
    )
}

fn state(enabled: bool) -> Arc<ModuleState> {
    let store = Arc::new(test_support::open_memory_store("federated-admission"));
    let mut runtime = runtime_for_test(store);
    runtime.set_federated_callers_enabled_for_test(enabled);
    Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    })
}

fn bind_body(principal: Principal, scope: Option<ScopeStamp>, mode: CallMode) -> Value {
    serde_json::to_value(ModuleControlRequest::RouteBind {
        route_channel: 17,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: DEFAULT_MODULE_ID.into(),
        },
        identity: BindIdentity::new("federated-test", "session"),
        principal: Some(principal),
        scope,
        call_mode: Some(mode),
        role_versions: None,
        consumer_capabilities: None,
        admission_facts: None,
    })
    .unwrap()
}

async fn bind(state: &Arc<ModuleState>, routes: &Arc<RouteBindings>, body: Value) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        wire::control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let (writer, mut responses) = mpsc::channel(1);
    handle_control_request(frame, &writer, state, routes)
        .await
        .unwrap();
    bounded::recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "federated bind reply",
    )
    .await
}

async fn bind_accepted(
    state: &Arc<ModuleState>,
    scope: ScopeStamp,
    mode: CallMode,
) -> Arc<RouteBindings> {
    let routes = Arc::new(RouteBindings::new());
    let reply = bind(
        state,
        &routes,
        bind_body(reserved("callosum"), Some(scope), mode),
    )
    .await;
    assert_eq!(reply.header.ty, FrameType::Response, "{:?}", reply.body);
    assert!(routes.binding(17, 3).unwrap().is_some());
    routes
}

async fn assert_bind_denied(body: Value, enabled: bool) {
    let state = state(enabled);
    let routes = Arc::new(RouteBindings::new());
    let principal: Option<Principal> = serde_json::from_value(body["principal"].clone()).unwrap();
    let reply = bind(&state, &routes, body).await;
    // Compare against the unchanged wire refusal, including its frame kind.
    let (writer, mut responses) = mpsc::channel(1);
    send_principal_denied(&writer, reply.header.ver, reply.header.corr, &principal)
        .await
        .unwrap();
    let expected = bounded::recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "expected bind denial",
    )
    .await;
    assert_eq!(reply.header.ty, FrameType::Error);
    let actual: Value = serde_json::from_slice(&reply.body).unwrap();
    let expected: Value = serde_json::from_slice(&expected.body).unwrap();
    assert_eq!(actual["code"], "principal_denied");
    assert_eq!(actual, expected);
    assert!(routes.binding(17, 3).unwrap().is_none());
}

async fn call(state: &Arc<ModuleState>, routes: &Arc<RouteBindings>, body: Value) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        17,
        3,
        2,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let (writer, mut responses) = mpsc::channel(1);
    assert!(handle_frame(frame, &writer, state, routes).await.unwrap());
    bounded::recv_within(
        responses.recv(),
        std::time::Duration::from_secs(10),
        "federated frame reply",
    )
    .await
}

fn reply(frame: Frame) -> Value {
    serde_json::from_slice(&frame.body).unwrap()
}

#[tokio::test]
async fn fully_stamped_callosum_is_refused_with_hook_off_even_after_declaration() {
    assert_bind_denied(
        bind_body(reserved("callosum"), Some(stamp()), CallMode::Classic),
        false,
    )
    .await;
}

#[test]
fn dormant_manifest_does_not_declare_federated_scopes() {
    let manifest = manifest::build(DEFAULT_MODULE_ID);
    assert!(!manifest
        .capabilities
        .unwrap()
        .provides
        .iter()
        .any(|cap| cap == "scope-federated/v1"));
}

#[tokio::test]
async fn unstamped_callosum_is_refused() {
    assert_bind_denied(
        bind_body(reserved("callosum"), None, CallMode::Classic),
        true,
    )
    .await;
}

macro_rules! local_stamp_refused {
    ($test:ident, $kind:ident) => {
        #[tokio::test]
        async fn $test() {
            let mut scope = stamp();
            scope.kind = ScopeKind::$kind;
            assert_bind_denied(
                bind_body(reserved("callosum"), Some(scope), CallMode::Classic),
                true,
            )
            .await;
        }
    };
}
local_stamp_refused!(callosum_head_is_refused, Head);
local_stamp_refused!(callosum_worker_is_refused, Worker);
local_stamp_refused!(callosum_ephemeral_is_refused, Ephemeral);

#[tokio::test]
async fn first_party_principal_on_callosum_federated_stamp_is_refused() {
    for principal in [
        Principal::Direct,
        reserved("prefrontal-core"),
        reserved("basal"),
    ] {
        assert_bind_denied(bind_body(principal, Some(stamp()), CallMode::Classic), true).await;
    }
}

#[tokio::test]
async fn federated_stamp_with_another_owner_is_refused() {
    let mut scope = stamp();
    scope.owner = reserved("prefrontal-core");
    assert_bind_denied(
        bind_body(reserved("callosum"), Some(scope), CallMode::Classic),
        true,
    )
    .await;
}

#[tokio::test]
async fn federated_stamp_without_attributes_is_refused() {
    let mut scope = stamp();
    scope.attributes.federated = None;
    assert_bind_denied(
        bind_body(reserved("callosum"), Some(scope), CallMode::Classic),
        true,
    )
    .await;
}

#[tokio::test]
async fn nonlinked_parent_is_refused() {
    for parent in [ParentState::Pending, ParentState::Ended] {
        assert_bind_denied(
            bind_body(
                reserved("callosum"),
                Some(stamp().with_parent_state(Some(parent))),
                CallMode::Classic,
            ),
            true,
        )
        .await;
    }
}

#[tokio::test]
async fn noncomputer_peer_is_refused() {
    for class in [
        FederatedPeerClass::Phone,
        FederatedPeerClass::Sim,
        FederatedPeerClass::Unknown,
    ] {
        let mut scope = stamp();
        scope.attributes.federated.as_mut().unwrap().peer_class = class;
        assert_bind_denied(
            bind_body(reserved("callosum"), Some(scope), CallMode::Classic),
            true,
        )
        .await;
    }
}

#[tokio::test]
async fn unknown_remote_claim_is_denied_at_bind_never_claimless() {
    let mut body = bind_body(reserved("callosum"), Some(stamp()), CallMode::Classic);
    body["scope"]["attributes"]["federated"]["remote_claim"] =
        json!({"kind":"future_claim", "agent_id":"local-agent"});
    assert_bind_denied(body, true).await;
}

#[tokio::test]
async fn enabled_admission_accepts_only_federated_identity_not_first_party_standing() {
    assert!(!principal::trust_for_principal(&Some(reserved("callosum"))).is_first_party());
    for claim in [
        None,
        Some(RemoteClaim::agent("agent")),
        Some(RemoteClaim::worker("owner", "b".repeat(64), None)),
        Some(RemoteClaim::flow("flow", 1, "install", "c".repeat(64))),
        Some(RemoteClaim::run("agent")),
    ] {
        for parent in [None, Some(ParentState::Linked)] {
            let mut scope = stamp().with_parent_state(parent);
            scope.attributes.federated.as_mut().unwrap().remote_claim = claim.clone();
            bind_accepted(&state(true), scope, CallMode::Classic).await;
        }
    }
}

fn served_frames() -> Vec<Value> {
    vec![
        json!({"name":"invoke", "arguments":{"op":"call", "connection":"github-handle-app-x", "action":"github.pulls.open", "args":{}}}),
        json!({"name":"web_search", "arguments":{"query":"test"}}),
        json!({"name":"code_search", "arguments":{"query":"test"}}),
        json!({"name":"connections", "arguments":{"op":"list"}}),
        json!({"name":"catalog", "arguments":{"op":"apps"}}),
        json!({"name":"catalog", "arguments":{"op":"list", "connection":"github-handle-app-x"}}),
        json!({"name":"catalog", "arguments":{"op":"inspect", "connection":"github-handle-app-x"}}),
    ]
}

fn assert_frame_denied(body: &Value, frame: Frame) {
    assert_eq!(frame.header.ty, FrameType::Response, "{body}");
    let actual = reply(frame);
    assert_eq!(
        actual["error"]["code"], "caller_not_allowed",
        "{body}: {actual}"
    );
    assert_eq!(
        actual["error"]["transmission"], "not_sent",
        "{body}: {actual}"
    );
    assert!(actual["error"]["message"].is_string());
    assert_eq!(actual.as_object().unwrap().len(), 1, "{body}: {actual}");
    assert_eq!(
        actual["error"].as_object().unwrap().len(),
        3,
        "{body}: {actual}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn frame_gate_walks_every_advertised_tool_and_management_operation_by_name() {
    let state = state(true);
    let routes = bind_accepted(&state, stamp(), CallMode::Classic).await;
    let mut denied = Vec::new();
    for role in manifest::build(DEFAULT_MODULE_ID).provides {
        match role {
            ProviderRole::ToolProvider { tools, .. } => {
                for tool in tools {
                    let operations = tool.schema["properties"]["op"]["enum"]
                        .as_array()
                        .cloned()
                        .unwrap_or_else(|| vec![Value::Null]);
                    for op in operations {
                        // This literal list is independent of the admission
                        // classifier; new advertised tools must start denied.
                        let served = match tool.name.as_str() {
                            "invoke" | "web_search" | "code_search" => true,
                            "connections" => op == "list",
                            "catalog" => matches!(op.as_str(), Some("apps" | "list" | "inspect")),
                            _ => false,
                        };
                        if !served {
                            denied.push(json!({"name":tool.name, "arguments":{"op":op}}));
                        }
                        denied.push(json!({"method":tool.name, "params":{"op":op}}));
                    }
                }
            }
            ProviderRole::ManagementSurface { operations, .. } => {
                for operation in operations {
                    denied.push(json!({"method":operation.name, "params":{}}));
                    denied.push(json!({"name":operation.name, "arguments":{}}));
                }
            }
            _ => {}
        }
    }
    for name in [
        "github",
        "github_read",
        "github_react",
        "events",
        "events_get",
        "requests",
        "tool.withdraw",
        "github.read.bulk",
        "grants.would_ask",
        "permissions.list",
        "permissions.revoke",
        "unknown.operation",
    ] {
        denied.push(json!({"name":name, "arguments":{}}));
        denied.push(json!({"method":name, "params":{}}));
    }
    for name in ["connections", "catalog"] {
        for op in [Value::Null, json!(17), json!("future_op"), json!({})] {
            denied.push(json!({"name":name,"arguments":{"op":op}}));
        }
        denied.push(json!({"name":name,"arguments":{}}));
    }
    for method in ["tool.catalog", "role.describe"] {
        denied.push(json!({"method":method,"params":{}}));
    }
    for body in denied {
        assert_frame_denied(&body, call(&state, &routes, body.clone()).await);
    }
    assert!(state
        .store()
        .list_audit("reserved:callosum")
        .unwrap()
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn method_refusal_precedes_retired_identity_validation_in_both_fields() {
    let state = state(true);
    let routes = bind_accepted(&state, stamp(), CallMode::Classic).await;
    for method in [
        "permissions.revoke",
        "admin.delete_connection",
        "github.read.bulk",
        "unknown.method",
    ] {
        for field in ["assertion", "agent_assertion"] {
            let body = json!({"method":method,"params":{field:"retired"}});
            assert_frame_denied(&body, call(&state, &routes, body.clone()).await);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_and_nonobject_frames_are_denied_by_entry_gate() {
    let state = state(true);
    let routes = bind_accepted(&state, stamp(), CallMode::Classic).await;
    for body in [
        Value::Null,
        json!([]),
        json!(false),
        json!({"method":"permissions.revoke", "params":{"padding":"x".repeat(MAX_REQUEST_BYTES)}}),
    ] {
        let actual = reply(call(&state, &routes, body).await);
        assert_eq!(actual["error"]["code"], "caller_not_allowed");
        assert_eq!(actual["error"]["transmission"], "not_sent");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_method_of_any_type_with_allowed_name_reaches_no_handler() {
    let state = state(true);
    let routes = bind_accepted(&state, stamp(), CallMode::Classic).await;
    for method in [
        json!("permissions.revoke"),
        json!("unknown.method"),
        Value::Null,
        json!(17),
        json!(false),
        json!([]),
        json!({}),
    ] {
        for name in ["invoke", "tool.catalog", "role.describe"] {
            let body = json!({"method":method,"name":name,"params":{"agent_assertion":"retired"},"arguments":{}});
            assert_frame_denied(&body, call(&state, &routes, body.clone()).await);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn served_tools_fail_closed_before_any_namespace_or_grant_read_or_dispatch() {
    let (mut state, _store, transport, scratch) =
        super::github_read_frame_tests::imported_runtime();
    Arc::get_mut(&mut state)
        .unwrap()
        .runtime
        .set_federated_callers_enabled_for_test(true);
    // Any accidental connection or local grant lookup now fails independently
    // of its authority decision, even if it selects Callosum's namespace.
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    db.execute_batch("DROP TABLE grants; DROP TABLE connections;")
        .unwrap();
    let routes = bind_accepted(&state, stamp(), CallMode::Classic).await;
    for body in served_frames() {
        let actual = reply(call(&state, &routes, body.clone()).await);
        assert_eq!(
            actual["error"]["code"], "consent_unavailable",
            "{body}: {actual}"
        );
        assert_eq!(
            actual["error"]["transmission"], "not_sent",
            "{body}: {actual}"
        );
    }
    assert!(transport.requests().is_empty());
    assert!(state
        .store()
        .list_audit("reserved:callosum")
        .unwrap()
        .is_empty());
    assert!(state.store().list_audit("direct").unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federated_flow_skips_local_carrier_and_scope_checks_but_keeps_modes() {
    let state = state(true);
    for top_level_flow in [None, Some("remote-flow".to_string())] {
        let mut scope = stamp();
        scope.attributes.flow_id = top_level_flow;
        let routes = bind_accepted(&state, scope, CallMode::Flow).await;
        for body in served_frames() {
            let actual = reply(call(&state, &routes, body.clone()).await);
            let name = body["name"].as_str().unwrap();
            let expected = if tool_provider::mode_refusal(name, &CallMode::Flow).is_some() {
                "call_mode_unsupported"
            } else {
                "consent_unavailable"
            };
            assert_eq!(actual["error"]["code"], expected, "{body}: {actual}");
        }
    }
    let routes = bind_accepted(&state, stamp(), CallMode::Codemode).await;
    let body = served_frames().remove(0);
    let actual = reply(call(&state, &routes, body).await);
    let expected = tool_provider::mode_refusal("invoke", &CallMode::Codemode).unwrap();
    assert_eq!(actual["error"], serde_json::to_value(expected).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn role_metadata_returns_identical_bytes_to_local_including_federated_flow() {
    let state = state(true);
    let local = Arc::new(RouteBindings::new());
    assert_eq!(
        bind(
            &state,
            &local,
            bind_body(Principal::Direct, None, CallMode::Classic)
        )
        .await
        .header
        .ty,
        FrameType::Response
    );
    for mode in [CallMode::Classic, CallMode::Flow] {
        let scope =
            stamp().with_attributes(stamp().attributes.with_flow_id(Some("remote-flow".into())));
        let routes = bind_accepted(&state, scope, mode).await;
        for name in ["tool.catalog", "role.describe"] {
            let body = json!({"name":name,"arguments":{}});
            let expected = call(&state, &local, body.clone()).await;
            let actual = call(&state, &routes, body).await;
            assert_eq!(expected.header.ty, FrameType::Response, "{name}");
            assert_eq!(actual.header.ty, expected.header.ty, "{name}");
            assert_eq!(actual.body, expected.body, "{name}");
        }
    }
}
