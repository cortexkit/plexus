use super::*;
use subc_protocol::{
    scope::{ScopeAttributes, ScopeKind, ScopeStamp},
    BindIdentity, RouteTarget,
};

fn reserved(id: &str) -> Principal {
    Principal::Reserved {
        module_id: id.into(),
    }
}

fn stamp(mode: &CallMode) -> Option<ScopeStamp> {
    let attributes = match mode {
        CallMode::Codemode => ScopeAttributes::new().with_run_id(Some("run-1".into())),
        CallMode::Flow => ScopeAttributes::new().with_flow_id(Some("flow-1".into())),
        _ => return None,
    };
    Some(
        ScopeStamp::new(reserved("prefrontal-core"), "scope-1", 1, ScopeKind::Worker)
            .with_attributes(
                attributes
                    .with_agent_id(Some("agent-1".into()))
                    .with_delegates(true),
            )
            .with_owner_authorized(true),
    )
}

async fn bind_route(
    state: &Arc<ModuleState>,
    routes: &Arc<RouteBindings>,
    principal: Principal,
    scope: Option<ScopeStamp>,
    mode: Option<CallMode>,
) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        wire::control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&ModuleControlRequest::RouteBind {
            route_channel: 17,
            epoch: 3,
            target: RouteTarget::ToolProvider {
                module_id: DEFAULT_MODULE_ID.into(),
            },
            identity: BindIdentity::new("/tmp", "mode-test", "session"),
            principal: Some(principal),
            scope,
            call_mode: mode,
            role_versions: None,
            consumer_capabilities: None,
            admission_facts: None,
        })
        .unwrap(),
    )
    .unwrap();
    let (writer, mut responses) = mpsc::channel(1);
    handle_control_request(frame, &writer, state, routes)
        .await
        .unwrap();
    crate::bounded::recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "route.bind reply",
    )
    .await
}

async fn call(
    state: &Arc<ModuleState>,
    routes: &Arc<RouteBindings>,
    name: &str,
    args: Value,
) -> Value {
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        17,
        3,
        2,
        serde_json::to_vec(&json!({"name": name, "arguments": args})).unwrap(),
    )
    .unwrap();
    let (writer, mut responses) = mpsc::channel(1);
    handle_tool_request(frame, &writer, state, routes)
        .await
        .unwrap();
    let frame = crate::bounded::recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "tool call reply",
    )
    .await;
    serde_json::from_slice(&frame.body).unwrap()
}

pub(super) async fn bound_call(
    runtime: ModuleRuntime,
    principal: Principal,
    scope: Option<ScopeStamp>,
    mode: Option<CallMode>,
    name: &str,
    args: Value,
) -> Value {
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    });
    bound_state_call(state, principal, scope, mode, name, args).await
}

pub(super) async fn bound_state_call(
    state: Arc<ModuleState>,
    principal: Principal,
    scope: Option<ScopeStamp>,
    mode: Option<CallMode>,
    name: &str,
    args: Value,
) -> Value {
    let routes = Arc::new(RouteBindings::new());
    assert_eq!(
        bind_route(&state, &routes, principal, scope, mode)
            .await
            .header
            .ty,
        FrameType::Response,
        "known-mode bind must be accepted"
    );
    call(&state, &routes, name, args).await
}

fn state() -> (Arc<ModuleState>, Scratch) {
    let scratch = Scratch::database("call-modes");
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.into(),
            storage_namespace: "test".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    (
        Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(store),
        }),
        scratch,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_tool_checks_the_bound_mode_with_standard_refusals() {
    let (state, _scratch) = state();
    for (mode, allowed) in [
        (
            CallMode::Classic,
            vec![
                "connections",
                "catalog",
                "invoke",
                "requests",
                "github",
                "github_read",
                "events_get",
                "events",
                "web_search",
                "code_search",
            ],
        ),
        (
            CallMode::Codemode,
            vec![
                "catalog",
                "github_read",
                "events_get",
                "web_search",
                "code_search",
            ],
        ),
        (
            CallMode::Flow,
            vec![
                "catalog",
                "invoke",
                "github",
                "github_read",
                "events_get",
                "web_search",
                "code_search",
            ],
        ),
    ] {
        let routes = Arc::new(RouteBindings::new());
        let principal = reserved(if mode == CallMode::Flow {
            "basal"
        } else {
            "prefrontal-core"
        });
        assert_eq!(
            bind_route(&state, &routes, principal, stamp(&mode), Some(mode.clone()))
                .await
                .header
                .ty,
            FrameType::Response
        );
        for name in [
            "connections",
            "catalog",
            "invoke",
            "requests",
            "github",
            "github_read",
            "events_get",
            "events",
            "web_search",
            "code_search",
        ] {
            let reply = call(&state, &routes, name, json!({})).await;
            if allowed.contains(&name) {
                assert_ne!(
                    reply["error"]["code"], "call_mode_unsupported",
                    "{name} in {mode:?}: {reply}"
                );
            } else {
                assert_eq!(
                    reply["error"]["code"], "call_mode_unsupported",
                    "tool mode admission must match the contract: {name} in {mode:?}: {reply}"
                );
                assert_eq!(
                    reply["error"]["detail"],
                    json!({"tool": name, "mode": mode})
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_mode_bind_is_refused_and_never_installed() {
    let (state, _scratch) = state();
    let routes = Arc::new(RouteBindings::new());
    let mode = CallMode::Unknown("future-mode".into());
    let reply = bind_route(
        &state,
        &routes,
        reserved("prefrontal-core"),
        None,
        Some(mode),
    )
    .await;
    assert_eq!(
        reply.header.ty,
        FrameType::Error,
        "unknown bind mode must be refused"
    );
    let error: ErrorBody = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(error.code, "call_mode_unsupported");
    assert_eq!(
        error.detail.unwrap(),
        json!({"tool": "route.bind", "mode": "future-mode"})
    );
    assert!(routes.get(17, 3).unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_bind_mode_is_derived_from_scope_and_explicit_mode_is_not_from_body() {
    let (state, _scratch) = state();
    for mode in [CallMode::Classic, CallMode::Codemode, CallMode::Flow] {
        let routes = Arc::new(RouteBindings::new());
        bind_route(
            &state,
            &routes,
            reserved("prefrontal-core"),
            stamp(&mode),
            None,
        )
        .await;
        assert_eq!(
            routes.binding(17, 3).unwrap().map(|binding| binding.mode),
            Some(mode)
        );
    }
    let routes = Arc::new(RouteBindings::new());
    bind_route(
        &state,
        &routes,
        reserved("prefrontal-core"),
        None,
        Some(CallMode::Codemode),
    )
    .await;
    let reply = call(
        &state,
        &routes,
        "github",
        json!({"op": "bindings.read", "connection_id": "missing", "call_mode": "classic"}),
    )
    .await;
    assert_eq!(reply["error"]["code"], "call_mode_unsupported");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn codemode_github_is_refused_before_grant_lookup_or_dispatch() {
    let (state, _store, transport, scratch) = super::github_read_frame_tests::imported_runtime();
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    // Make any grant lookup fail independently of its decision. The mode
    // refusal must be returned before reaching even this broken authority store.
    db.execute_batch("DROP TABLE grants").unwrap();
    let routes = Arc::new(RouteBindings::new());
    bind_route(
        &state,
        &routes,
        reserved("prefrontal-core"),
        stamp(&CallMode::Codemode),
        Some(CallMode::Codemode),
    )
    .await;
    for args in [
        json!({"op":"bindings.read","connection_id":"github-handle-app-x"}),
        json!({"op":"bot_request","request":{},"request_nonce":"nonce"}),
    ] {
        let reply = call(&state, &routes, "github", args).await;
        assert_eq!(
            reply["error"]["code"], "call_mode_unsupported",
            "codemode github must refuse before authority or dispatch: {reply}"
        );
        assert_eq!(
            reply["error"]["detail"],
            json!({"tool":"github","mode":"codemode"})
        );
    }
    assert!(state.store().list_audit("direct").unwrap().is_empty());
    assert!(transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grants_would_ask_still_works_on_the_flows_bound_route() {
    let (state, _scratch) = state();
    let routes = Arc::new(RouteBindings::new());
    bind_route(
        &state,
        &routes,
        reserved("basal"),
        stamp(&CallMode::Flow),
        Some(CallMode::Flow),
    )
    .await;
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        17,
        3,
        2,
        serde_json::to_vec(&json!({"method":"grants.would_ask",
            "params":{"agent_id":"agent-1","flow_id":"flow-1","items":[]}}))
        .unwrap(),
    )
    .unwrap();
    let (writer, mut responses) = mpsc::channel(1);
    handle_tool_request(frame, &writer, &state, &routes)
        .await
        .unwrap();
    let frame = crate::bounded::recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "grants.would_ask reply",
    )
    .await;
    let reply: Value = serde_json::from_slice(&frame.body).unwrap();
    assert_eq!(
        reply["result"]["items"],
        json!([]),
        "the flow restore-check route op must not encounter tool mode admission: {reply}"
    );
    assert!(reply.get("error").is_none());
}
