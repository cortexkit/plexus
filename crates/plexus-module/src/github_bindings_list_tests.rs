use super::*;
use plexus_core::{storage::github_store::GithubImportRow, test_scratch::Scratch, MockTransport};
use std::time::Duration;

fn fixture() -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    let (mut state, store, transport, scratch) = crate::github_read_frame_tests::imported_runtime();
    Arc::get_mut(&mut state).unwrap().runtime.connector_home =
        Arc::new(connector_home::ConnectorHome::unavailable());
    let prototype = store.github_handle_for_repo("o/x").unwrap().unwrap();
    for (id, repositories, status) in [
        ("y", vec!["O/Z", "O/A"], "enabled"),
        ("disabled", vec!["o/disabled"], "disabled"),
        ("missing", vec!["o/missing"], "enabled"),
        ("expired", vec!["o/expired"], "enabled"),
    ] {
        let mut handle = prototype.clone();
        handle.app_handle_id = format!("app-{id}");
        handle.agent_id = format!("agent-{id}");
        handle.credential_reference = format!("github_app:app-{id}");
        handle.connection_id = format!("github-handle-app-{id}");
        handle.status = status.into();
        store
            .import_github_handles(&[GithubImportRow {
                handle,
                repositories: repositories.into_iter().map(str::to_owned).collect(),
                grants: vec![],
                module_actions: vec![],
                policies: vec![],
            }])
            .unwrap();
    }
    for caller in ["bindings-reader", "basal"] {
        for id in ["x", "y", "disabled", "expired"] {
            store
                .insert_grant(&plexus_core::GrantInput {
                    grant_id: format!("list-{caller}-{id}"),
                    principal: "direct".into(),
                    connection_id: format!("github-handle-app-{id}"),
                    grantee_principal: format!("reserved:{caller}"),
                    risk_ceiling: "read".into(),
                    action_selectors: vec![],
                    authority_kind: "invoke".into(),
                    expires_at: (id == "expired").then_some(1),
                })
                .unwrap();
        }
    }
    assert_eq!(store.github_repo_binding_generation().unwrap(), 6);
    (state, store, transport, scratch)
}

fn scope(agent: Option<&str>) -> CallScope {
    CallScope {
        owner: "reserved:prefrontal-core".into(),
        scope_ref: "flow-a".into(),
        scope_epoch: 1,
        kind: Some("head".into()),
        parent: None,
        parent_state: None,
        agent_id: agent.map(str::to_owned),
        flow_id: Some("flow-a".into()),
        delegates: agent.is_some(),
        owner_authorized: true,
    }
}

async fn call(
    state: &Arc<ModuleState>,
    caller: &str,
    scope: Option<CallScope>,
    args: Value,
) -> Value {
    crate::test_support::send_tool_call(
        state,
        Principal::Reserved {
            module_id: caller.into(),
        },
        scope,
        None,
        manifest::GITHUB_READ_TOOL,
        args,
    )
    .await
}

fn assert_audit(scratch: &Scratch, agent: Option<&str>, reason: &str) {
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_journal WHERE gate='github_control'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "exactly one audit row per call");
    let row: (String, Option<String>, String, String) = db.query_row(
        "SELECT action,agent_id,decision,reason_code FROM audit_journal WHERE gate='github_control'",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).unwrap();
    assert_eq!(
        row,
        (
            "github.bindings.list".into(),
            agent.map(str::to_owned),
            if reason == "allowed" { "allow" } else { "deny" }.into(),
            reason.into()
        )
    );
    for table in ["github_bot_read_ledger", "reservations"] {
        let count: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "store read must not charge or reserve: {table}");
    }
}

fn expected() -> Value {
    json!({"generation":6,"bindings":[
        {"repository":"o/a","agent_id":"agent-y","app_handle_id":"app-y"},
        {"repository":"o/x","agent_id":"agent-x","app_handle_id":"app-x"},
        {"repository":"o/z","agent_id":"agent-y","app_handle_id":"app-y"}
    ]})
}

#[tokio::test]
async fn lists_sorted_enabled_granted_bindings_without_home_vendor_or_budget() {
    let (state, _store, transport, scratch) = fixture();
    assert!(!connector_home::tool_effect(
        "github_read",
        Some("github.bindings.list")
    ));
    assert!(connector_home::tool_effect(
        "github_read",
        Some("github.issue.get")
    ));
    assert!(connector_home::tool_effect("github_read", None));
    let reply = call(
        &state,
        "bindings-reader",
        None,
        json!({"action":"github.bindings.list"}),
    )
    .await;
    // github_read replies carry the facade object once, with no MCP mirrors.
    assert_eq!(reply, json!({"result":expected()}));
    assert!(transport.requests().is_empty());
    assert_audit(&scratch, None, "allowed");
}

#[tokio::test]
async fn refuses_every_extra_field_by_name_and_audits_once() {
    for field in ["repository", "args", "agent_id", "op", "token", "unknown"] {
        let (state, _, transport, scratch) = fixture();
        let mut args = json!({"action":"github.bindings.list"});
        args[field] = json!("not accepted");
        let reply = call(&state, "bindings-reader", None, args).await;
        assert_eq!(
            reply["error"],
            json!({"code":"invalid_request","field":field})
        );
        assert!(transport.requests().is_empty());
        assert_audit(&scratch, None, "invalid_request");
    }
}

#[tokio::test]
async fn flow_lists_intersect_agent_or_workspace_visibility_with_module_grants() {
    for (agent, audience, repositories) in [
        (
            Some("agent-x"),
            flow_audience::Audience::Global,
            vec!["o/x"],
        ),
        (
            Some("agent-missing"),
            flow_audience::Audience::Global,
            vec![],
        ),
        (
            None,
            flow_audience::Audience::Global,
            vec!["o/a", "o/x", "o/z"],
        ),
        (
            None,
            flow_audience::Audience::Workspace {
                workspace_id: "ws-a".into(),
                project_ids: vec!["pj-a".into()],
            },
            vec!["o/x"],
        ),
    ] {
        let (mut state, _store, transport, scratch) = fixture();
        Arc::get_mut(&mut state).unwrap().runtime.flow_audiences =
            flow_audience::FlowAudiences::fixture("flow-a", audience);
        let db = rusqlite::Connection::open(scratch.path()).unwrap();
        db.execute("INSERT INTO trigger_subscriptions (subscription_id,principal,connection_id,action,cadence_s,cursor_kind,cursor_state,fixed_args,schema_hash,status,created_at_ms,project_id,project_source)
            VALUES ('watch','direct','github-handle-app-x','list_issues',300,'ordered_timestamp','{}','{\"owner\":\"o\",\"repo\":\"x\"}','hash','active',1,'pj-a','entorhinal')", []).unwrap();
        let reply = call(
            &state,
            "basal",
            Some(scope(agent)),
            json!({"action":"github.bindings.list"}),
        )
        .await;
        assert_eq!(reply["result"]["generation"], 6, "{reply}");
        assert_eq!(
            reply["result"]["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["repository"].as_str().unwrap())
                .collect::<Vec<_>>(),
            repositories
        );
        assert!(reply.get("structuredContent").is_none(), "{reply}");
        assert!(transport.requests().is_empty());
        assert_audit(&scratch, agent, "allowed");
    }
}

#[tokio::test]
async fn example_replays_exact_request_and_reply_bytes() {
    let request = include_bytes!("../tests/fixtures/github-read-bindings/list.request.json");
    let expected = include_bytes!("../tests/fixtures/github-read-bindings/list.reply.json");
    let (state, _, transport, scratch) = fixture();
    let routes = Arc::new(RouteBindings::new());
    routes
        .insert_mode(
            73,
            1,
            Principal::Reserved {
                module_id: "basal".into(),
            },
            Some(scope(None)),
            CallMode::Flow,
        )
        .unwrap();
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        wire::control_flags(),
        73,
        1,
        702,
        request.to_vec(),
    )
    .unwrap();
    let (writer, mut responses) = mpsc::channel(1);
    handle_tool_request(frame, &writer, &state, &routes)
        .await
        .unwrap();
    let reply = recv_within(
        responses.recv(),
        Duration::from_secs(5),
        "binding list example",
    )
    .await;
    assert_eq!(reply.body.as_slice(), expected.as_slice());
    assert!(transport.requests().is_empty());
    assert_audit(&scratch, None, "allowed");
}
