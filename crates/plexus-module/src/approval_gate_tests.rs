use super::*;
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{BindIdentity, RouteTarget};

/// Approve and deny reach the engine with the request the CALLER named.
///
/// These are the highest-stakes ops on the facade: an ask-first write waits
/// as a pending request, and these two decide whether it executes. Both
/// were unproven at the handler — measured, passing an id the caller never
/// sent (so the engine is asked about a request that does not exist) left
/// the whole module suite green for each of them.
///
/// The two failure directions are not symmetric. A broken APPROVE reports
/// success while the write never happens, which an operator eventually
/// notices because the effect is missing. A broken DENY reports success
/// while the request stays pending and approvable, so an operator who
/// believes they refused an action has not refused it — a decision to
/// withhold authority that silently did not take.
///
/// Asserted on STORE STATE and on the TRANSPORT, never on the response
/// alone: reporting success while doing nothing is precisely the mutation
/// being caught.
// Multi-threaded, because the invoke and approve paths reach a real
// transport call wrapped in `blocking_section` (tokio::task::block_in_place),
// which panics on the single-threaded runtime the default #[tokio::test]
// provides. The same wrapper is what production uses on every connector
// call, so a test driving these paths has to run where it is legal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approve_and_deny_act_on_the_request_the_caller_named() {
    let (writer, mut responses) = mpsc::channel(8);
    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "approval-gate-{}",
        std::process::id()
    )));
    // The approved write is checked for freshness before it is sent, which
    // loads the connection's manifest; its catalog row is fresh, so no
    // vendor is contacted. The manifest declares `held_write` on an S1
    // app, so the write is S2 and an ordinary grant admits it.
    store
        .upsert_manifest(
            "system",
            &crate::test_write_manifest("mock", "https://vendor.invalid/mcp"),
        )
        .expect("mock manifest");
    store
        .insert_connection(
            "direct",
            "conn-approval",
            "mock",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": ["team"]}),
        )
        .expect("seed connection");
    // Activated through the real ticket ceremony rather than by writing an
    // `active` row directly, because dispatch resolves a credential from
    // the binding a ticket installs — a connection marked active with no
    // binding stops at the credential gate, which would leave the approval
    // assertions unreachable.
    let ticket = store
        .create_binding_ticket("direct", "conn-approval", b"test:canary-binding-handle")
        .expect("issue binding ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume binding ticket")
        .expect("connection activates");

    // An ask-first WRITE, so `authorize` parks it as a pending request
    // rather than dispatching — which is the only way to get a row for
    // approve/deny to act on.
    let schema = json!({"type": "object"});
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: "conn-approval".to_string(),
            principal: "direct".to_string(),
            name: "held_write".to_string(),
            title: None,
            schema: schema.clone(),
            schema_hash: plexus_core::jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
            risk: "write".to_string(),
            // The column holds the app's tier, as the catalog seed writes
            // it. Freshness judges the write from it; a value that is not
            // a tier reads as S4, whose staleness bound is zero, so every
            // dispatch would first refresh from the (unreachable) vendor
            // and be refused as a stale write.
            severity: "S1".to_string(),
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
            ask_first: true,
        })
        .expect("seed catalog action");
    for (grant_id, authority_kind) in [
        ("grant-approval-invoke", "invoke"),
        // approve/deny both require connection-admin authority, so the
        // decision itself is gated rather than available to any caller who
        // can invoke.
        ("grant-approval-admin", "connection_admin"),
    ] {
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: grant_id.to_string(),
                principal: "direct".to_string(),
                connection_id: "conn-approval".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "write".to_string(),
                action_selectors: vec!["held_write".to_string()],
                authority_kind: authority_kind.to_string(),
                expires_at: None,
            })
            .expect("seed grant");
    }

    let transport = Arc::new(MockTransport::default());
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: ModuleRuntime::with_stub_credentials_and_mock_transport(
            Arc::clone(&store),
            Arc::new(StubCredentialSource::with_default_success(
                b"mock-credential".to_vec(),
            )),
            transport.clone(),
        ),
    });
    let bindings = Arc::new(RouteBindings::new());
    handle_control_request(
        Frame::build(
            FrameType::Request,
            wire::control_flags(),
            0,
            0,
            7,
            serde_json::to_vec(&ModuleControlRequest::RouteBind {
                scope: None,
                call_mode: None,
                role_versions: None,
                route_channel: 4,
                epoch: 2,
                target: RouteTarget::ToolProvider {
                    module_id: DEFAULT_MODULE_ID.to_string(),
                },
                identity: BindIdentity::new(
                    "/tmp/project",
                    "test".to_string(),
                    "session".to_string(),
                ),
                principal: Some(Principal::Direct),
                consumer_capabilities: None,
                admission_facts: None,
            })
            .expect("serialize bind"),
        )
        .expect("build bind frame"),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("bind succeeds");
    let _bind_ack = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "bind response",
    )
    .await;
    assert_bind_ack(&_bind_ack);

    let tool_frame = |correlation: u64, name: &str, arguments: Value| {
        Frame::build(
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
            4,
            2,
            correlation,
            serde_json::to_vec(&json!({"name": name, "arguments": arguments}))
                .expect("serialize tool request"),
        )
        .expect("build tool frame")
    };

    // Park two requests: one to deny, one to approve. They are separate
    // rows so neither decision can be satisfied by the other's effect.
    let mut request_ids = Vec::new();
    for (correlation, team) in [(30u64, "alpha"), (31, "beta")] {
        handle_tool_request(
            tool_frame(
                correlation,
                manifest::INVOKE_TOOL,
                json!({
                    "op": "call",
                    "connection": "conn-approval",
                    "action": "held_write",
                    "args": {"team": team}
                }),
            ),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("invoke request succeeds");
        let response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "invoke response",
        )
        .await;
        let body: Value = serde_json::from_slice(&response.body).expect("invoke body");
        assert_eq!(
            body["error"]["code"], "consent_unavailable",
            "an unscoped call cannot park a card: {body}"
        );
        // The operator can still approve or deny a held request through
        // the `requests` tool, without any card. An unscoped call can't
        // create one (asserted above), so hold it through internal
        // authorization, then exercise the admin tool and listing below.
        let created_id = match state.runtime.engine.authorize(AuthorizationRequest::new(
            "direct",
            "conn-approval",
            "held_write",
            json!({"team":team}),
        )) {
            Err(plexus_core::Denial::ActionRequestCreated { request_id }) => request_id,
            other => panic!("operator approval was not parked: {other:?}"),
        };
        let denial_body = denial_response(&plexus_core::Denial::ActionRequestCreated {
            request_id: created_id.clone(),
        });
        assert_eq!(
            denial_body["error"]["request_id"],
            json!(created_id),
            "the denial must name the parked request"
        );
        let request_id = store
            .list_action_requests("direct")
            .expect("read requests")
            .into_iter()
            .find(|request| request.args_snapshot["team"] == json!(team))
            .map(|request| request.request_id)
            .unwrap_or_else(|| panic!("the parked request for {team} is not listed"));
        assert_eq!(
            created_id, request_id,
            "the operator's request must be listed"
        );
        request_ids.push(request_id);
    }

    // DENY the first. The request must stop being actionable, and nothing
    // may reach the vendor.
    handle_tool_request(
        tool_frame(
            32,
            manifest::REQUESTS_TOOL,
            json!({"op": "deny", "request_id": request_ids[0]}),
        ),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("deny request succeeds");
    let deny_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "deny response",
    )
    .await;
    let deny_body: Value = serde_json::from_slice(&deny_response.body).expect("deny body");
    assert_eq!(
        deny_body["result"]["denied"],
        json!(true),
        "deny did not report success: {deny_body}"
    );
    let denied = store
        .list_action_requests("direct")
        .expect("read requests")
        .into_iter()
        .find(|request| request.request_id == request_ids[0])
        .expect("the request row survives the decision");
    assert_eq!(
        denied.status, "denied",
        "the denied request is still actionable: {denied:?}"
    );

    // APPROVE the second, and require the vendor call to actually happen.
    // Approving is the only path here that can produce one, so a transport
    // request is unambiguous evidence the engine acted on THIS row.
    let pending = store
        .list_action_requests("direct")
        .expect("read requests")
        .into_iter()
        .find(|request| request.request_id == request_ids[1])
        .expect("the second request is present");
    assert_eq!(
        pending.status, "pending",
        "the second request must still be awaiting a decision: {pending:?}"
    );
    handle_tool_request(
        tool_frame(
            33,
            manifest::REQUESTS_TOOL,
            json!({"op": "approve", "request_id": request_ids[1]}),
        ),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("approve request succeeds");
    let approve_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "approve response",
    )
    .await;
    let approve_body: Value = serde_json::from_slice(&approve_response.body).expect("approve body");
    assert!(
        approve_body["error"].is_null(),
        "approve failed: {approve_body}"
    );

    assert_eq!(
        transport.requests().len(),
        1,
        "approve must contact the vendor exactly once"
    );
    assert_eq!(
        transport.requests()[0].args["team"],
        "beta",
        "approve must dispatch the named request's arguments"
    );

    // A consumed row also proves the approval cannot be used twice.
    let decided = store
        .list_action_requests("direct")
        .expect("read requests")
        .into_iter()
        .find(|request| request.request_id == request_ids[1])
        .expect("the approved request survives the decision");
    assert_eq!(
        decided.status, "consumed",
        "the approved request was not dispatched: {decided:?}"
    );

    // Approving it again must name the used approval, not a lapsed window.
    handle_tool_request(
        tool_frame(
            34,
            manifest::REQUESTS_TOOL,
            json!({"op": "approve", "request_id": request_ids[1]}),
        ),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("second approve request succeeds");
    let again_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "second approve response",
    )
    .await;
    let again_body: Value =
        serde_json::from_slice(&again_response.body).expect("second approve body");
    assert_eq!(
        again_body["error"]["code"],
        json!("approval_consumed"),
        "a second approve must be refused as consumed: {again_body}"
    );

    // The denied request must NOT have moved with it: each decision acts on
    // the row the caller named, not on whatever is pending.
    let untouched = store
        .list_action_requests("direct")
        .expect("read requests")
        .into_iter()
        .find(|request| request.request_id == request_ids[0])
        .expect("the denied request is still present");
    assert_eq!(
        untouched.status, "denied",
        "approving one request changed another: {untouched:?}"
    );
}
