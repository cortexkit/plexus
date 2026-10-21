use super::*;
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{BindIdentity, RouteTarget};

/// Configure and revoke take effect on the connection the caller named.
///
/// Revoke matters most here, and not because it is destructive — because it
/// WITHDRAWS authority. An operator who suspects a credential is compromised
/// and hits revoke must actually lose the connection; a revoke that reports
/// success while the connection stays active is worse than no button at
/// all, because it ends the operator's search for a problem that is still
/// live. Without this test, pointing the handler's store call at a
/// different connection id left the whole module suite green.
///
/// Configure carries the write-enabling filters. A connection starts with
/// empty filters and writes require a non-empty `write_enabling` set, so a
/// handler that drops the caller's filters leaves every write permanently
/// refused — a capability that reads as configured and is not.
///
/// Both assertions inspect STORED STATE rather than the response, so a
/// handler that answers successfully while writing nothing still fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configure_and_revoke_take_effect_on_the_named_connection() {
    let (writer, mut responses) = mpsc::channel(8);
    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "conn-admin-{}",
        std::process::id()
    )));

    // Configure validates the requested filters against the vendor's
    // declared selectors, so the manifest has to be in the catalog or the
    // op refuses before reaching the store write under test.
    let ingested = test_write_manifest("configure_fixture", "https://example.invalid/mcp");
    store
        .upsert_manifest("system", &ingested)
        .expect("seed manifest");
    let app_key = ingested.manifest.key.clone();

    // Two connections, so a handler acting on "the only one there is"
    // cannot pass: each decision must land on the id the caller named.
    for connection_id in ["conn-target", "conn-bystander"] {
        store
            .insert_connection(
                "direct",
                connection_id,
                &app_key,
                "active",
                &json!({"required": [], "optional": ["team"], "write_enabling": []}),
            )
            .expect("seed connection");
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: format!("grant-admin-{connection_id}"),
                principal: "direct".to_string(),
                connection_id: connection_id.to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "write".to_string(),
                action_selectors: vec!["*".to_string()],
                authority_kind: "connection_admin".to_string(),
                expires_at: None,
            })
            .expect("seed admin grant");
    }

    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    state
        .runtime
        .mcp_transport
        .register_connection(plexus_core::McpConnection::new(
            "conn-target",
            "http://127.0.0.1:1",
        ));
    state
        .runtime
        .rest_transport
        .register_connection(plexus_core::RestConnection::new(
            "conn-target",
            "http://127.0.0.1:1",
        ));
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

    let tool_frame = |correlation: u64, arguments: Value| {
        Frame::build(
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
            4,
            2,
            correlation,
            serde_json::to_vec(&json!({
                "name": manifest::CONNECTIONS_TOOL,
                "arguments": arguments
            }))
            .expect("serialize tool request"),
        )
        .expect("build tool frame")
    };
    // `connection()` rather than the list projection, because the list
    // deliberately omits resource filters and this test's whole subject is
    // whether the caller's filters landed.
    let connection_of = |store: &PlexusStore, id: &str| {
        store
            .connection("direct", id)
            .expect("read connection")
            .unwrap_or_else(|| panic!("connection {id} is missing"))
    };

    handle_tool_request(
        tool_frame(
            40,
            json!({
                "op": "configure",
                "connection": "conn-target",
                "resource_filters": {"write_enabling": ["team"]}
            }),
        ),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("configure request succeeds");
    let configure_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "configure response",
    )
    .await;
    let configure_body: Value =
        serde_json::from_slice(&configure_response.body).expect("configure body");
    assert!(
        configure_body["error"].is_null(),
        "configure failed: {configure_body}"
    );
    assert_eq!(
        connection_of(&store, "conn-target").resource_filters["write_enabling"],
        json!(["team"]),
        "the caller's write-enabling filters did not reach the store"
    );
    assert_eq!(
        connection_of(&store, "conn-bystander").resource_filters["write_enabling"],
        json!([]),
        "configuring one connection changed another"
    );

    handle_tool_request(
        tool_frame(41, json!({"op": "revoke", "connection": "conn-target"})),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("revoke request succeeds");
    let revoke_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "revoke response",
    )
    .await;
    let revoke_body: Value = serde_json::from_slice(&revoke_response.body).expect("revoke body");
    assert!(
        revoke_body["error"].is_null(),
        "revoke failed: {revoke_body}"
    );
    assert_eq!(
        connection_of(&store, "conn-target").status,
        "revoked",
        "the connection survived its own revocation"
    );
    assert!(
        !state.runtime.mcp_transport.has_connection("conn-target"),
        "revocation must unregister MCP configuration"
    );
    assert!(
        !state.runtime.rest_transport.has_connection("conn-target"),
        "revocation must unregister REST configuration"
    );
    assert_eq!(
        connection_of(&store, "conn-bystander").status,
        "active",
        "revoking one connection revoked another"
    );
}
