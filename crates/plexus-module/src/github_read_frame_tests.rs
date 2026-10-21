#[path = "artifact_file_read_tests.rs"]
mod artifact_file_tests;
#[path = "bot_read_tests.rs"]
mod bot_read_tests;
#[path = "bot_read_vector_tests.rs"]
mod bot_read_vector_tests;
#[path = "ci_read_tests.rs"]
mod ci_read_tests;
#[path = "issue_flow_read_tests.rs"]
mod issue_flow_tests;
#[path = "job_log_read_tests.rs"]
mod job_log_tests;
#[path = "review_threads_read_tests.rs"]
mod review_threads_tests;
use super::*;
use plexus_core::github::credential::HandleCredentialProvider;
use plexus_core::storage::github_store::{GithubGovernanceSeams, GithubHandle, GithubImportRow};
use plexus_core::{ingest_value, MockResponse, CATALOG_PRINCIPAL};

pub(super) fn github_manifest() -> plexus_core::IngestedManifest {
    let source = include_str!("../../../catalog/github_rest.jsonc");
    ingest_value(serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap())
        .unwrap()
}

pub(super) fn imported_runtime() -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    imported_runtime_with_actions(&[
        "github.issue.get",
        "github.issue_comments.list",
        "github.issue.search",
    ])
}

fn imported_runtime_with_actions(
    actions: &[&str],
) -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    imported_runtime_with_provider(
        actions,
        crate::consent_test_support::anonymous_handle_credentials(),
    )
}

/// [`imported_runtime_with_actions`] whose bot tokens come from `provider`,
/// so a test can see what the vault is told about a vendor reply.
fn imported_runtime_with_provider(
    actions: &[&str],
    provider: Arc<dyn HandleCredentialProvider>,
) -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    let scratch = Scratch::database("github-read-frame");
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: scratch.to_string_lossy().into_owned(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &github_manifest())
        .unwrap();
    store
        .import_github_handles(&[GithubImportRow {
            handle: GithubHandle {
                app_handle_id: "app-x".into(),
                agent_id: "agent-x".into(),
                app_id: 1,
                installation_id: None,
                credential_reference: "github_app:app-x".into(),
                credential_generation: 0,
                status: "enabled".into(),
                proven_at: None,
                connection_principal: "direct".into(),
                connection_id: "github-handle-app-x".into(),
            },
            repositories: vec!["o/x".into()],
            grants: vec![],
            module_actions: actions.iter().map(|action| (*action).to_owned()).collect(),
            policies: vec![],
        }])
        .unwrap();
    let transport = Arc::new(MockTransport::default());
    transport.set_response(MockResponse::Success(json!({"items":[
        {"repository":{"full_name":"o/x"}},
        {"repository":{"full_name":"o/unbound"}}
    ]})));
    let mut runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
        store.clone(),
        Arc::new(StubCredentialSource::default()),
        transport.clone(),
    );
    runtime.engine = runtime
        .engine
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: Some(provider),
        }));
    (
        Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        }),
        store,
        transport,
        scratch,
    )
}

async fn send_github_read_frame(runtime: Arc<ModuleState>, action: &str) -> Value {
    send_facade_frame(
        runtime,
        manifest::GITHUB_READ_TOOL,
        json!({"repository":["o/x"], "action":action, "args":{"terms":"bug"}}),
        "prefrontal-core",
        None,
    )
    .await
}

async fn send_facade_frame(
    runtime: Arc<ModuleState>,
    name: &str,
    arguments: Value,
    module_id: &str,
    scope: Option<subc_protocol::scope::ScopeStamp>,
) -> Value {
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        72,
        1,
        701,
        serde_json::to_vec(&json!({
            "name": name,
            "arguments": arguments
        }))
        .unwrap(),
    )
    .unwrap();
    let (writer, mut responses) = mpsc::channel(1);
    let routes = Arc::new(RouteBindings::new());
    routes
        .insert_mode(
            frame.header.channel,
            frame.header.epoch,
            Principal::Reserved {
                module_id: module_id.into(),
            },
            scope.as_ref().map(CallScope::from_stamp),
            derive_call_mode(scope.as_ref()),
        )
        .unwrap();
    handle_tool_request(frame, &writer, &runtime, &routes)
        .await
        .unwrap();
    serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "expected reply",
        )
        .await
        .body,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_read_returns_the_governed_envelope_for_all_three_actions() {
    for (action, repository, args, vendor_reply, expected) in [
        (
            "github.issue.get",
            json!("o/x"),
            json!({"issue_number":42}),
            json!({"number":42,"title":"a bug"}),
            json!({"number":42,"title":"a bug"}),
        ),
        (
            "github.issue_comments.list",
            json!("o/x"),
            json!({"issue_number":42,"since":"2026-01-01T00:00:00Z"}),
            json!([{ "id": 123, "body": "hello" }]),
            json!([{ "id": 123, "body": "hello" }]),
        ),
        (
            "github.issue.search",
            json!(["o/x"]),
            json!({"terms":"bug"}),
            json!({"items":[{"repository":{"full_name":"o/x"}},{"repository":{"full_name":"o/unbound"}}]}),
            json!({"items":[{"repository":{"full_name":"o/x"}}],"total_count":1,"incomplete":true,"incomplete_results":true}),
        ),
    ] {
        let (runtime, _store, transport, _scratch) = imported_runtime();
        transport.set_response(MockResponse::Success(vendor_reply));
        let arguments = json!({"action":action,"repository":repository,"args":args});
        let reply = send_facade_frame(
            runtime.clone(),
            manifest::GITHUB_READ_TOOL,
            arguments.clone(),
            "prefrontal-core",
            None,
        )
        .await;
        assert_eq!(reply["result"], expected, "{action}: {reply}");
        assert_eq!(reply["isError"], false);
        assert_eq!(reply["content"][0]["type"], "text");
        let text: Value =
            serde_json::from_str(reply["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, json!({"result":expected}));
        if expected.is_object() {
            assert_eq!(reply["structuredContent"], expected);
        } else {
            assert!(reply.get("structuredContent").is_none());
        }
        let requests = transport.requests();
        assert_eq!(
            requests.len(),
            1,
            "{action}: github_read must dispatch exactly once"
        );
        assert_eq!(requests[0].action, action);
        assert_eq!(requests[0].connection_id, "github-handle-app-x");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_facade_refuses_removed_read_op_by_name_and_keeps_bindings_read() {
    let (runtime, store, transport, _scratch) = imported_runtime();
    let refused = send_facade_frame(
            runtime.clone(),
            manifest::GITHUB_TOOL,
            json!({"op":"read","action":"github.issue.get","repository":"o/x","args":{"issue_number":42}}),
            "prefrontal-core",
            None,
        )
        .await;
    assert_eq!(refused["error"]["code"], "invalid_operation", "{refused}");
    assert_eq!(refused["error"]["op"], "read", "{refused}");
    assert!(transport.requests().is_empty());

    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "prefrontal-bindings-read".into(),
            principal: "direct".into(),
            connection_id: "github-handle-app-x".into(),
            grantee_principal: "reserved:prefrontal-core".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec![],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    let bindings = send_facade_frame(
        runtime,
        manifest::GITHUB_TOOL,
        json!({"op":"bindings.read","connection_id":"github-handle-app-x"}),
        "prefrontal-core",
        None,
    )
    .await;
    assert_eq!(bindings["isError"], false, "{bindings}");
    assert_eq!(bindings["result"]["bindings"][0]["repository"], "o/x");
    assert_eq!(bindings["result"]["bindings"][0]["app_handle_id"], "app-x");
    assert!(transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_read_refuses_write_and_unknown_actions_by_name_before_other_inputs() {
    let (runtime, store, transport, _scratch) = imported_runtime();
    for action in ["add_issue_comment", "unknown_action"] {
        // The action check runs first. A malformed repository and a
        // credential-like argument must not change the refusal to some other
        // error, and nothing may be looked up or written to the audit
        // journal for an action github_read never serves.
        let reply = send_facade_frame(
            runtime.clone(),
            manifest::GITHUB_READ_TOOL,
            json!({"action":action,"repository":null,"args":{"api_token":"ckh_secret"}}),
            "prefrontal-core",
            None,
        )
        .await;
        assert_eq!(reply["error"]["code"], "read_action_unsupported", "{reply}");
        assert_eq!(
            reply["error"]["action"], action,
            "unsupported reads must be refused by action name: {reply}"
        );
        assert!(reply["error"]["message"].as_str().unwrap().contains(action));
        assert_eq!(reply["isError"], true, "a refusal must set isError");
        assert!(!reply.to_string().contains("ckh_secret"));
    }
    assert!(transport.requests().is_empty());
    assert!(store.list_audit("direct").unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_read_rejects_extra_or_missing_fields_without_dispatch() {
    let (runtime, store, transport, _scratch) = imported_runtime();
    let valid = json!({"action":"github.issue.get","repository":"o/x","args":{"issue_number":42}});
    for field in ["action", "repository", "args", "op", "request"] {
        let mut arguments = valid.clone();
        if matches!(field, "op" | "request") {
            arguments[field] = json!("bot_request");
        } else {
            arguments.as_object_mut().unwrap().remove(field);
        }
        let reply = send_facade_frame(
            runtime.clone(),
            manifest::GITHUB_READ_TOOL,
            arguments,
            "prefrontal-core",
            None,
        )
        .await;
        assert_eq!(
            reply["error"]["code"],
            if field == "action" {
                "read_action_unsupported"
            } else {
                "invalid_request"
            },
            "{field}: {reply}"
        );
    }
    assert!(transport.requests().is_empty());
    assert!(store.list_audit("direct").unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_read_requires_the_calling_modules_grant() {
    let (runtime, store, transport, _scratch) = imported_runtime();
    let arguments =
        json!({"action":"github.issue.get","repository":"o/x","args":{"issue_number":42}});
    let refused = send_facade_frame(
        runtime.clone(),
        manifest::GITHUB_READ_TOOL,
        arguments.clone(),
        "ungranted-reader",
        None,
    )
    .await;
    // The fixture grants prefrontal-core read access on this bot's
    // connection. A different module with no grant of its own must not
    // borrow that one: it cannot even see the connection.
    assert_eq!(
        refused["error"]["code"], "connection_not_found",
        "{refused}"
    );
    assert!(transport.requests().is_empty());
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "reader-grant".into(),
            principal: "direct".into(),
            connection_id: "github-handle-app-x".into(),
            grantee_principal: "reserved:ungranted-reader".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["github.issue.get".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    let allowed = send_facade_frame(
        runtime,
        manifest::GITHUB_READ_TOOL,
        arguments,
        "ungranted-reader",
        None,
    )
    .await;
    assert!(allowed.get("result").is_some(), "{allowed}");
    assert_eq!(transport.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delegated_codemode_github_read_keeps_only_module_authority() {
    let (runtime, store, transport, _scratch) = imported_runtime();
    let scope = subc_protocol::scope::ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        "run-read",
        1,
        subc_protocol::scope::ScopeKind::Worker,
    )
    .with_attributes(
        subc_protocol::scope::ScopeAttributes::new()
            .with_agent_id(Some("agent-x".into()))
            .with_run_id(Some("run-read".into()))
            .with_delegates(true),
    )
    .with_owner_authorized(true);
    let args = json!({"action":"github.issue.get","repository":"o/x","args":{"issue_number":42}});
    let reply = crate::call_mode_tests::bound_state_call(
        runtime.clone(),
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        Some(scope.clone()),
        Some(CallMode::Codemode),
        manifest::GITHUB_READ_TOOL,
        args.clone(),
    )
    .await;
    assert!(
        reply.get("result").is_some(),
        "run reads need only module grants: {reply}"
    );
    assert_eq!(transport.requests().len(), 1);
    let rows = store.list_audit("direct").unwrap();
    let rows: Vec<_> = rows
        .iter()
        .filter(|row| {
            row.scope
                .as_ref()
                .is_some_and(|scope| scope.scope_ref == "run-read")
        })
        .collect();
    assert_eq!(
        rows.len(),
        2,
        "authorization and dispatch retain run attribution"
    );
    assert!(rows
        .iter()
        .all(|row| row.agent_id.as_deref() == Some("agent-x")));
    let denied = crate::call_mode_tests::bound_state_call(
        runtime.clone(),
        Principal::Reserved {
            module_id: "broca".into(),
        },
        Some(scope),
        Some(CallMode::Codemode),
        manifest::GITHUB_READ_TOOL,
        args,
    )
    .await;
    assert_eq!(
        denied["error"]["code"], "connection_not_found",
        "delegation cannot replace module grants: {denied}"
    );
    assert_eq!(transport.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unscoped_basal_can_read_tool_metadata_but_no_real_tool() {
    let (runtime, _store, transport, _scratch) = imported_runtime();
    let described = send_facade_frame(
        runtime.clone(),
        cortexkit_role_tool_provider::ops::ROLE_DESCRIBE,
        json!({}),
        "basal",
        None,
    )
    .await;
    // Role metadata replies are the bare answer, and a refusal is a bare
    // error body, so check for the answer's own fields, not an "error" key.
    assert!(
        described.get("code").is_none() && described.get("tool_capabilities").is_some(),
        "basal installs read role.describe before any flow scope exists: {described}"
    );
    let catalog = send_facade_frame(
        runtime.clone(),
        cortexkit_role_tool_provider::ops::TOOL_CATALOG,
        json!({"params": {"capabilities": ["plexus:github.react/v1"]}}),
        "basal",
        None,
    )
    .await;
    assert!(
        catalog.get("code").is_none()
            && catalog["tools"]
                .as_array()
                .is_some_and(|tools| tools.iter().any(|tool| tool["name"] == "github_react")),
        "basal installs read tool.catalog before any flow scope exists: {catalog}"
    );
    let refused = send_facade_frame(
        runtime,
        manifest::GITHUB_READ_TOOL,
        json!({"action":"github.issue.get","repository":"o/x","args":{"issue_number":42}}),
        "basal",
        None,
    )
    .await;
    assert_eq!(
        refused["error"]["code"], "flow_scope_required",
        "the metadata exemption must not reach real tools: {refused}"
    );
    assert!(transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_read_requires_flow_scoped_basal_and_dispatches_with_its_grant() {
    let (runtime, store, transport, scratch) = imported_runtime();
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "basal-read".into(),
            principal: "direct".into(),
            connection_id: "github-handle-app-x".into(),
            grantee_principal: "reserved:basal".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["github.issue.get".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    let arguments =
        json!({"action":"github.issue.get","repository":"o/x","args":{"issue_number":42}});
    let refused = send_facade_frame(
        runtime.clone(),
        manifest::GITHUB_READ_TOOL,
        arguments.clone(),
        "basal",
        None,
    )
    .await;
    assert_eq!(
        refused["error"]["code"], "flow_scope_required",
        "github_read cannot bypass the common flow check: {refused}"
    );
    assert_eq!(refused["error"]["transmission"], "not_sent");
    assert!(transport.requests().is_empty());
    assert!(store.list_audit("direct").unwrap().is_empty());
    let scope = subc_protocol::scope::ScopeStamp::new(
        Principal::Reserved {
            module_id: "basal".into(),
        },
        "read-flow",
        1,
        subc_protocol::scope::ScopeKind::Head,
    )
    .with_attributes(
        subc_protocol::scope::ScopeAttributes::new()
            .with_agent_id(Some("agent-x".into()))
            .with_flow_id(Some("github-read-flow".into())),
    )
    .with_owner_authorized(true);
    let impostor = send_facade_frame(
        runtime.clone(),
        manifest::GITHUB_READ_TOOL,
        arguments.clone(),
        "basal-impostor",
        Some(scope.clone()),
    )
    .await;
    assert_eq!(
        impostor["error"]["code"], "flow_carrier_not_admitted",
        "{impostor}"
    );
    assert!(transport.requests().is_empty());
    let allowed = send_facade_frame(
        runtime,
        manifest::GITHUB_READ_TOOL,
        arguments,
        "basal",
        Some(scope),
    )
    .await;
    assert!(allowed.get("result").is_some(), "{allowed}");
    assert_eq!(allowed["isError"], false);
    assert_eq!(transport.requests().len(), 1);
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    let attributed: i64 = db.query_row(
            "SELECT count(*) FROM audit_journal WHERE scope_flow_id = 'github-read-flow' AND acting_principal = 'reserved:basal'",
            [], |row| row.get(0)).unwrap();
    assert_eq!(
        attributed, 2,
        "authorization and dispatch must attribute the flow"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prefrontal_read_frame_returns_only_bound_search_hits() {
    let (runtime, store, transport, _scratch) = imported_runtime();
    let reply = send_github_read_frame(runtime, "github.issue.search").await;
    assert_eq!(
        reply["result"]["items"],
        json!([{"repository":{"full_name":"o/x"}}]),
        "{reply}"
    );
    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].connection_id, "github-handle-app-x");
    assert_eq!(requests[0].args["q"], "bug repo:o/x");
    let rows = store.list_audit("direct").unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].request_id, rows[1].request_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prefrontal_read_frame_refuses_unsupported_action_by_name() {
    let (runtime, store, transport, _scratch) = imported_runtime();
    let reply = send_github_read_frame(runtime, "add_issue_comment").await;
    assert_eq!(reply["error"]["code"], "read_action_unsupported", "{reply}");
    assert!(transport.requests().is_empty());
    assert!(store.list_audit("direct").unwrap().is_empty());
}
