use super::*;
use plexus_core::{jcs_sha256, CatalogActionInput, GrantInput};

fn seeded_runtime(label: &str) -> (ModuleRuntime, Arc<PlexusStore>, Arc<MockTransport>, Scratch) {
    let path = Scratch::database(&format!("stamp-{label}"));
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: label.to_string(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        })
        .expect("open stamp facade store"),
    );
    store
        .insert_connection(
            "direct",
            "conn-github",
            "github_rest",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("insert stamp connection");
    let handle = b"test:stamp-test-handle";
    let ticket = store
        .create_binding_ticket("direct", "conn-github", handle)
        .expect("create binding ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume binding ticket")
        .expect("activate connection");
    let schema = json!({"type": "object"});
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "conn-github".to_string(),
            principal: "direct".to_string(),
            name: "read_item".to_string(),
            title: Some("Read item".to_string()),
            schema: schema.clone(),
            schema_hash: jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
            risk: "read".to_string(),
            severity: "S1".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("insert stamp action");
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-stamp".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-github".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["read_item".to_string()],
            authority_kind: "invoke".to_string(),
            expires_at: None,
        })
        .expect("insert stamp grant");
    let credentials = Arc::new(StubCredentialSource::default());
    credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
    let transport = Arc::new(MockTransport::default());
    let runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
        Arc::clone(&store),
        credentials,
        Arc::clone(&transport),
    );
    (runtime, store, transport, path)
}

fn invoke_frame(correlation: u64) -> Frame {
    let arguments = json!({
        "op": "call",
        "connection": "conn-github",
        "action": "read_item",
        "args": {"query": "safe"}
    });
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        41,
        1,
        correlation,
        serde_json::to_vec(&json!({
            "name": manifest::INVOKE_TOOL,
            "arguments": arguments
        }))
        .expect("serialize stamp invoke"),
    )
    .expect("build stamp invoke")
}

async fn invoke(
    runtime: ModuleRuntime,
    frame: Frame,
    scope: Option<subc_protocol::scope::ScopeStamp>,
) -> Value {
    let (writer, mut responses) = mpsc::channel(1);
    handle_scoped_tool_request_for_test(frame, &writer, runtime, Principal::Direct, scope)
        .await
        .expect("handle stamp invoke");
    serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "stamp response",
        )
        .await
        .body,
    )
    .expect("stamp response JSON")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_request_module_entry_dispatches_through_governed_transport() {
    use plexus_core::credentials::CredentialSource;
    use plexus_core::governance::GovernanceEngine;
    use plexus_core::storage::github_store::{GithubGovernanceSeams, GithubHandle};
    use plexus_core::transport::Transport;
    use rusqlite::{params, Connection};
    let path = Scratch::database("module-facade-dispatch");
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "module-facade-dispatch".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    store
        .insert_connection(
            "operator",
            "conn-facade",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    store
        .put_github_handle(&GithubHandle {
            app_handle_id: "app-fixture".into(),
            agent_id: "agent-fixture".into(),
            app_id: 1,
            installation_id: None,
            credential_reference: "github_app:app-fixture".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: Some(1),
            connection_principal: "operator".into(),
            connection_id: "conn-facade".into(),
        })
        .unwrap();
    store.bind_github_repo("org/repo", "app-fixture").unwrap();
    let db = Connection::open(path.as_ref()).unwrap();
    db.execute("INSERT INTO catalog_actions (connection_id,principal,name,schema_json,schema_hash,risk,severity,status,first_seen_at_ms,last_seen_at_ms,ask_first)
            VALUES ('conn-facade','operator','add_reaction','{}','schema','write','S1','active',1,1,0)", []).unwrap();
    // The facade sends each call only the arguments the reviewed manifest
    // declares for its action, so the shipped GitHub REST manifest must be
    // stored. Stored directly, so no other catalog row is seeded from it.
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github_rest.jsonc"),
    )
    .unwrap();
    let ingested = plexus_core::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap(),
    )
    .unwrap();
    db.execute(
            "INSERT INTO app_manifests (principal,key,schema_version,content_hash,manifest_json,ingested_at_ms)
             VALUES ('system','github_rest',1,'fixture',?1,1)",
            params![serde_json::to_string(&ingested.manifest).unwrap()],
        )
        .unwrap();
    for (id, agent) in [("module", None), ("agent", Some("agent-fixture"))] {
        db.execute("INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,authority_kind,created_at_ms,action_selectors,agent_id)
                VALUES (?1,'operator','conn-facade','reserved:aft','write','invoke',1,'[\"add_reaction\"]',?2)", params![id, agent]).unwrap();
    }
    let transport = Arc::new(MockTransport::default());
    let mut runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
        store.clone(),
        Arc::new(StubCredentialSource::default()),
        transport.clone(),
    );
    runtime.engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(StubCredentialSource::default()) as Arc<dyn CredentialSource>,
        transport.clone() as Arc<dyn Transport>,
    )
    .with_governance_seams(Arc::new(GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(crate::consent_test_support::anonymous_handle_credentials()),
    }));
    let stamp = subc_protocol::scope::ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        "bot-session",
        1,
        subc_protocol::scope::ScopeKind::Head,
    )
    .with_attributes(
        subc_protocol::scope::ScopeAttributes::new()
            .with_agent_id(Some("agent-fixture".into()))
            .with_delegates(true),
    )
    .with_owner_authorized(true);
    runtime.engine = runtime
        .engine
        .with_scope_reader(crate::consent_test_support::live_reader(
            CallScope::from_stamp(&stamp),
        ));
    let frame = Frame::build_with_version(PROTOCOL_VERSION, FrameType::Request,
            Flags::new(false, Priority::Interactive, false), 41, 1, 99,
            serde_json::to_vec(&json!({"name":manifest::GITHUB_TOOL,"arguments":{
                "op":"bot_request","request_nonce":"module-nonce",
                "request":{"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}}
            }})).unwrap()).unwrap();
    let (writer, mut response) = mpsc::channel(1);
    handle_scoped_tool_request_for_test(
        frame,
        &writer,
        runtime,
        Principal::Reserved {
            module_id: "aft".into(),
        },
        Some(stamp),
    )
    .await
    .unwrap();
    let reply: Value = serde_json::from_slice(
        &recv_within(
            response.recv(),
            std::time::Duration::from_secs(5),
            "expected reply",
        )
        .await
        .body,
    )
    .unwrap();
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(transport.requests()[0].action, "add_reaction");
    for (op, nested, secret) in [
        (
            "bot_request",
            json!({"request":{"body":{"api_token":"ckh_pretend_secret"}}}),
            "ckh_pretend_secret",
        ),
        (
            "bindings.read",
            json!({"api_token":"ckh_pretend_secret"}),
            "ckh_pretend_secret",
        ),
    ] {
        let mut arguments = json!({"op":op});
        for (key, value) in nested.as_object().unwrap() {
            arguments[key] = value.clone();
        }
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            41,
            1,
            100,
            serde_json::to_vec(&json!({"name":manifest::GITHUB_TOOL,"arguments":arguments}))
                .unwrap(),
        )
        .unwrap();
        let (writer, mut response) = mpsc::channel(1);
        handle_tool_request_for_test(
            frame,
            &writer,
            runtime_for_test(store.clone()),
            Principal::Reserved {
                module_id: "aft".into(),
            },
        )
        .await
        .unwrap();
        let response = String::from_utf8(
            recv_within(
                response.recv(),
                std::time::Duration::from_secs(5),
                "expected reply",
            )
            .await
            .body
            .to_vec(),
        )
        .unwrap();
        let decoded: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(
            decoded["error"]["code"], "secret_input_rejected",
            "{response}"
        );
        assert!(
            !response.contains(secret),
            "secret appeared in refusal response"
        );
    }
    assert_eq!(
        transport.requests().len(),
        1,
        "refused calls never reach transport"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stamped_invoke_sends_only_vendor_args_and_audits_agent() {
    let (runtime, store, transport, _path) = seeded_runtime("stamped");
    let stamp = subc_protocol::scope::ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        "head-fixture",
        1,
        subc_protocol::scope::ScopeKind::Head,
    )
    .with_attributes(
        subc_protocol::scope::ScopeAttributes::new().with_agent_id(Some("agent_wire".into())),
    )
    .with_owner_authorized(true);
    let response = invoke(runtime, invoke_frame(1), Some(stamp)).await;
    assert_eq!(
        response["result"]["transmission"], "completed",
        "{response}"
    );
    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].args, json!({"query": "safe"}));
    assert!(store
        .list_audit("direct")
        .expect("audit rows")
        .iter()
        .any(|row| {
            row.agent_id.as_deref() == Some("agent_wire") && row.agent_handle.is_none()
        }));
    drop(store);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unscoped_invoke_preserves_the_module_principal_path() {
    let (runtime, store, transport, _path) = seeded_runtime("absent");
    let response = invoke(runtime, invoke_frame(3), None).await;
    assert_eq!(
        response["result"]["transmission"], "completed",
        "{response}"
    );
    assert_eq!(transport.requests().len(), 1);
    assert!(store
        .list_audit("direct")
        .expect("audit rows")
        .iter()
        .all(|row| row.agent_id.is_none() && row.agent_handle.is_none()));
    drop(store);
}

#[test]
fn an_absent_audit_retention_window_defaults_to_30_days() {
    let window = audit_retention_window_ms(None).expect("default retention window");
    assert_eq!(window, DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY);
    assert_eq!(DEFAULT_AUDIT_RETENTION_DAYS, 30);
}

#[test]
fn an_unparseable_audit_retention_window_refuses_startup() {
    let error = audit_retention_window_ms(Some(OsString::from("thirty")))
        .expect_err("a stated but unparseable policy must refuse");
    let ModuleError::Message(message) = error else {
        panic!("unexpected error shape");
    };
    assert!(
        message.contains(AUDIT_RETENTION_DAYS_ENV) && message.contains("thirty"),
        "the refusal must name the variable and rejected value: {message}"
    );
}

#[test]
fn an_audit_retention_window_not_greater_than_the_floor_refuses_startup() {
    let configured = AUDIT_DELETE_FLOOR_DAYS.to_string();
    let error = audit_retention_window_ms(Some(OsString::from(configured)))
        .expect_err("a window at the delete floor disables retention");
    let ModuleError::Message(message) = error else {
        panic!("unexpected error shape");
    };
    assert!(
        message.contains(&format!(
            "configured window: {AUDIT_DELETE_FLOOR_DAYS} days"
        )),
        "the refusal must name the configured window: {message}"
    );
    assert!(
        message.contains(&format!("floor: {AUDIT_DELETE_FLOOR_DAYS} days")),
        "the refusal must name the delete floor: {message}"
    );
}

// Mutations proved by hand against these three: swapping the release arm
// to return the dev fallback (the pre-fix behavior) reddens the refusal
// test; dropping the configured-wins arm reddens the explicit test in
// both build kinds.
#[test]
fn a_configured_catalog_dir_wins_in_both_build_kinds() {
    for dev_fallback_allowed in [true, false] {
        let resolved = catalog_directory(
            Some(std::ffi::OsString::from("/staged/catalog")),
            dev_fallback_allowed,
        )
        .expect("configured directory resolves");
        assert_eq!(resolved, PathBuf::from("/staged/catalog"));
    }
}

#[test]
fn a_dev_build_without_config_falls_back_to_the_repo_tree() {
    let resolved = catalog_directory(None, true).expect("dev fallback resolves");
    assert!(
        resolved.ends_with("catalog"),
        "dev fallback must point at the repository catalog: {resolved:?}"
    );
}

#[test]
fn a_release_build_without_config_refuses_by_name() {
    let error = catalog_directory(None, false).expect_err("release build must refuse");
    let ModuleError::Message(message) = &error else {
        panic!("unexpected error shape: {error:?}");
    };
    assert!(
        message.contains("PLEXUS_CATALOG_DIR"),
        "the refusal must name the missing variable: {message}"
    );
    assert!(
        !message.contains(env!("CARGO_MANIFEST_DIR")),
        "the refusal must not leak the compile-time path as advice"
    );
}
