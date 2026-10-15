use super::*;

const CONNECTION: &str = "conn-github-actions";

pub(super) fn actions_runtime() -> (Arc<ModuleState>, Arc<PlexusStore>, Arc<MockTransport>, Scratch) {
    let (mut runtime, store, transport, scratch) = imported_runtime();
    let source = include_str!("../../../catalog/github_actions.jsonc");
    let manifest = ingest_value(serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap()).unwrap();
    store.upsert_manifest(CATALOG_PRINCIPAL, &manifest).unwrap();
    store.insert_connection("direct", CONNECTION, "github_actions", "pending", &json!({"required":[],"optional":["owner","repo"],"write_enabling":[]})).unwrap();
    let ticket = store.create_binding_ticket("direct", CONNECTION, b"test:actions").unwrap();
    store.connect_with_ticket("direct", &ticket.ticket_id).unwrap().unwrap();
    for action in &manifest.manifest.actions_baseline {
        let schema = action.http.as_ref().unwrap().args_schema.clone();
        store.upsert_catalog_action(&plexus_core::CatalogActionInput {
            principal: "direct".into(), connection_id: CONNECTION.into(), name: action.name.clone(), title: None,
            schema_hash: plexus_core::jcs_sha256(&schema).unwrap(), schema, risk: "read".into(), severity: "read".into(),
            status: "active".into(), quarantine_reason: None, reconciliation: None, ask_first: false,
        }).unwrap();
    }
    store.insert_grant(&plexus_core::GrantInput {
        grant_id: "basal-actions".into(), principal: "direct".into(), connection_id: CONNECTION.into(),
        grantee_principal: "reserved:basal".into(), risk_ceiling: "read".into(),
        action_selectors: vec!["get_job".into(), "github.actions.job_log".into(), "list_workflow_run_artifacts".into(), "github.actions.artifact_file".into(), "get_workflow_run_metadata".into(), "list_workflow_runs_for_workflow".into()], authority_kind: "invoke".into(), expires_at: None,
    }).unwrap();
    transport.set_response_for_method("get_job", "", MockResponse::Success(json!({"status":"completed"})));
    transport.set_response_for_method("github.actions.job_log", "", MockResponse::Success(json!({"total_bytes":17,"truncated":false,"text":"test NAME FAILED\n"})));
    Arc::get_mut(&mut runtime).unwrap().runtime.engine = plexus_core::GovernanceEngine::new(
        Arc::clone(&store), Arc::new(StubCredentialSource::with_default_success(b"test".to_vec())) as Arc<dyn plexus_core::CredentialSource>,
        transport.clone() as Arc<dyn plexus_core::Transport>);
    (runtime, store, transport, scratch)
}

pub(super) fn flow(agent: Option<&str>) -> subc_protocol::scope::ScopeStamp {
    subc_protocol::scope::ScopeStamp::new(Principal::Reserved { module_id: "basal".into() }, "ci-watch", 1, subc_protocol::scope::ScopeKind::Head)
        .with_attributes(subc_protocol::scope::ScopeAttributes::new().with_agent_id(agent.map(str::to_owned)).with_flow_id(Some("ci-watch".into())))
        .with_owner_authorized(true)
}

async fn read(runtime: Arc<ModuleState>, repository: &str, args: Value, agent: Option<&str>) -> Value {
    send_facade_frame(runtime, manifest::GITHUB_READ_TOOL,
        json!({"action":"github.actions.job_log","repository":repository,"args":args}), "basal", Some(flow(agent))).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn job_log_flow_visibility_uses_the_agents_bot_bindings() {
    let (runtime, _, transport, _scratch) = actions_runtime();
    let reply = read(runtime.clone(), "o/unbound", json!({"job_id":42}), Some("agent-x")).await;
    assert_eq!(reply["error"]["code"], "repository_not_visible", "{reply}");
    assert!(transport.requests().is_empty());
    let reply = read(runtime.clone(), "o/x", json!({"job_id":42}), Some("agent-other")).await;
    assert_eq!(reply["error"]["code"], "repository_not_visible", "{reply}");
    assert!(transport.requests().is_empty());
    let allowed = read(runtime, "O/X", json!({"job_id":42}), Some("agent-x")).await;
    assert_eq!(allowed["result"]["repository"], "o/x", "{allowed}");
    assert_eq!(allowed["result"]["job_id"], 42);
    let requests = transport.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| request.connection_id == CONNECTION));
    assert_eq!(requests[1].args["max_bytes"], 65536);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agentless_job_log_flow_uses_only_basals_grant() {
    let (runtime, store, transport, _scratch) = actions_runtime();
    let allowed = read(runtime.clone(), "o/unbound", json!({"job_id":42}), None).await;
    assert!(allowed.get("result").is_some(), "{allowed}");
    assert_eq!(transport.requests().len(), 2);
    store.revoke_grant("direct", "basal-actions").unwrap();
    let denied = read(runtime, "o/unbound", json!({"job_id":42}), None).await;
    assert!(denied.get("error").is_some(), "{denied}");
    assert_eq!(transport.requests().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn running_job_has_a_named_refusal_and_no_log_request() {
    let (mut runtime, store, _, _scratch) = actions_runtime();
    let (url, server) = crate::test_http::FixedRequestServer::start(1, "job status", |_, request| {
        assert!(request.starts_with("GET /repos/o/x/actions/jobs/42 "));
        let body = r#"{"status":"in_progress"}"#;
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let source = include_str!("../../../catalog/github_actions.jsonc");
    let manifest = ingest_value(serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap()).unwrap();
    let config = plexus_core::RestConfig::new(url)
        .with_bindings(manifest.manifest.credential_bindings.clone())
        .with_actions(plexus_core::rest_api::actions_from_manifest(&manifest.manifest));
    Arc::get_mut(&mut runtime).unwrap().runtime.engine = plexus_core::GovernanceEngine::new(store,
        Arc::new(StubCredentialSource::with_default_success(b"test".to_vec())) as Arc<dyn plexus_core::CredentialSource>,
        Arc::new(plexus_core::RestTransport::new(config)) as Arc<dyn plexus_core::Transport>);
    let refused = read(runtime, "o/x", json!({"job_id":42}), Some("agent-x")).await;
    server.join().unwrap();
    assert_eq!(refused["error"]["code"], "job_not_finished", "{refused}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn job_log_arguments_are_bounded_before_dispatch() {
    let (runtime, _, transport, _scratch) = actions_runtime();
    for args in [json!({"job_id":42,"max_bytes":262145}), json!({"job_id":42,"max_bytes":0}), json!({"job_id":-1}), json!({"job_id":42,"owner":"other"})] {
        let denied = read(runtime.clone(), "o/x", args, Some("agent-x")).await;
        assert_eq!(denied["error"]["code"], "job_log_arguments_invalid", "{denied}");
    }
    assert!(transport.requests().is_empty());
}
