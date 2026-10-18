use super::*;
use plexus_core::{
    consent_card::{ElicitationCallError, ElicitationRoute},
    storage::GrantInput,
};
use std::sync::Mutex;

#[derive(Default)]
struct Cards(Mutex<Vec<Value>>);

fn recipient_worker_scope() -> CallScope {
    CallScope {
        owner: "reserved:prefrontal-core".into(),
        scope_ref: "recipient-worker".into(),
        scope_epoch: 1,
        kind: Some("worker".into()),
        parent: Some("reserved:prefrontal-core/head@1".into()),
        parent_state: Some("linked".into()),
        agent_id: None,
        flow_id: None,
        delegates: false,
        owner_authorized: true,
    }
}

struct RecipientScopes;
impl plexus_core::scope::ScopeReader for RecipientScopes {
    fn describe(
        &self,
        _: &str,
        _: &str,
    ) -> Result<plexus_core::scope::ScopeDescription, plexus_core::scope::ScopeReadError> {
        Ok(plexus_core::scope::ScopeDescription {
            status: plexus_core::scope::ScopeStatus::Live,
            owner_synced: true,
            owner_configured: true,
            live: Some(recipient_worker_scope()),
        })
    }
}
impl ElicitationRoute for Cards {
    fn call_scoped(
        &self,
        _: &CallScope,
        operation: &str,
        params: Value,
        _: std::time::Duration,
    ) -> Result<Value, ElicitationCallError> {
        if operation == "consent.request" {
            self.0.lock().unwrap().push(params);
            Ok(json!({"elicitation_id":"recipient-card"}))
        } else if operation == "consent.await" {
            Err(ElicitationCallError::NotSent)
        } else {
            let mut record = self.0.lock().unwrap().last().cloned().unwrap();
            record["state"] = json!("pending");
            record["elicitation_id"] = json!("recipient-card");
            Ok(record)
        }
    }
}

fn manifest_value(declared: bool) -> Value {
    let mut manifest = json!({
        "schema_version":1,"key":"messaging_fixture","name":"Messaging fixture",
        "description":"service-independent send fixture","reuse_path":"openapi_shim","reuse_rationale":"fixture",
        "tier":"S1","transport":{"kind":"rest_api","url":"http://127.0.0.1:0"},
        "auth":{"mode":"none"},"credential_bindings":[],
        "resource_filters":{"required":[],"optional":[],"write_enabling":["to"]},
        "actions_baseline":[{"name":"send","risk":"write","http":{"method":"POST","path":"/send","args_schema":{
            "type":"object","properties":{"to":{"type":"string"},"cc":{"type":"array","items":{"type":"string"}},"text":{"type":"string"}},"additionalProperties":false
        }}}],
        "defaults":{"ask_first_risk":["write"],"rate_limit":{"calls_per_min":60}},"availability":"ga"
    });
    if declared {
        manifest["actions_baseline"][0]["recipients"] = json!(["/to", "/cc"]);
    }
    manifest
}

struct Fixture {
    scratch: Scratch,
    state: Arc<ModuleState>,
    routes: Arc<RouteBindings>,
    transport: Arc<plexus_core::MockTransport>,
    cards: Arc<Cards>,
}
impl Fixture {
    fn new(declared: bool) -> Self {
        let scratch = Scratch::database("recipient-gate");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "recipients".into(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: scratch.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        let manifest = plexus_core::manifest::ingest_value(manifest_value(declared)).unwrap();
        store
            .upsert_manifest(plexus_core::storage::CATALOG_PRINCIPAL, &manifest)
            .unwrap();
        store
            .insert_connection(
                "direct",
                "mail",
                "messaging_fixture",
                "active",
                &json!({"required":[],"optional":[],"write_enabling":["to"]}),
            )
            .unwrap();
        store
            .seed_catalog_from_manifest("direct", "mail", "messaging_fixture")
            .unwrap();
        for (id, kind, grantee) in [
            ("invoke", "invoke", "direct"),
            ("admin", "connection_admin", "direct"),
            ("basal", "invoke", "reserved:basal"),
        ] {
            store
                .insert_grant(&GrantInput {
                    grant_id: id.into(),
                    principal: "direct".into(),
                    connection_id: "mail".into(),
                    grantee_principal: grantee.into(),
                    risk_ceiling: "write".into(),
                    action_selectors: vec!["send".into()],
                    authority_kind: kind.into(),
                    expires_at: None,
                })
                .unwrap();
        }
        let credentials = Arc::new(plexus_core::StubCredentialSource::default());
        let transport = Arc::new(plexus_core::MockTransport::default());
        let mut runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
            store,
            credentials,
            transport.clone(),
        );
        let cards = Arc::new(Cards::default());
        runtime.engine = runtime
            .engine
            .with_scope_reader(Arc::new(RecipientScopes))
            .with_consent_cards(Arc::new(plexus_core::ConsentCards::new(cards.clone())));
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        });
        let routes = Arc::new(RouteBindings::new());
        routes
            .insert_scoped(2, 1, Principal::Direct, Some(recipient_worker_scope()))
            .unwrap();
        routes.insert(3, 1, Principal::Direct).unwrap();
        let fixture = Self {
            scratch,
            state,
            routes,
            transport,
            cards,
        };
        fixture.policy("allow");
        fixture
    }
    fn store(&self) -> &PlexusStore {
        self.state.store()
    }
    fn policy(&self, effect: &str) {
        self.store()
            .set_policy("direct", "mail", "send", effect, None)
            .unwrap();
    }
    fn count(&self, table: &str) -> i64 {
        rusqlite::Connection::open(self.scratch.path())
            .unwrap()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }
    async fn call(&self, body: Value) -> Value {
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            wire::control_flags(),
            if body.get("method").is_some() { 3 } else { 2 },
            1,
            8,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        let (writer, mut replies) = mpsc::channel(1);
        handle_tool_request(frame, &writer, &self.state, &self.routes)
            .await
            .unwrap();
        serde_json::from_slice(
            &recv_within(
                replies.recv(),
                std::time::Duration::from_secs(5),
                "expected reply",
            )
            .await
            .body,
        )
        .unwrap()
    }
    async fn send(&self, args: Value) -> Value {
        self.call(json!({"name":"invoke","arguments":{"op":"call","connection":"mail","action":"send","args":args}})).await
    }
    async fn manage(&self, method: &str, params: Value) -> Value {
        self.call(json!({"method":method,"params":params})).await
    }
    fn list(&self, agent: Option<&str>, recipient: &str) {
        self.store()
            .change_recipient("direct", "mail", agent, recipient, true, true)
            .unwrap();
    }
    fn request_id(&self, reply: &Value) -> String {
        assert_eq!(
            reply["structuredContent"]["code"], "access_pending",
            "{reply}"
        );
        rusqlite::Connection::open(self.scratch.path())
            .unwrap()
            .query_row(
                "SELECT request_id FROM action_requests ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }
}
fn args() -> Value {
    json!({"to":" Alice@Example.COM ","cc":["bob@example.com"],"text":"Message from the operator"})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listed_recipients_under_allow_dispatch_and_audit_normalized_identities() {
    let f = Fixture::new(true);
    f.list(None, "alice@example.com");
    f.list(None, " BOB@EXAMPLE.COM ");
    let reply = f.send(args()).await;
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(f.transport.requests().len(), 1);
    let conn = rusqlite::Connection::open(f.scratch.path()).unwrap();
    let summaries = conn
        .prepare("SELECT args_redaction_summary FROM audit_journal WHERE action='send'")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(summaries.len(), 2);
    for summary in summaries {
        assert!(
            summary.contains(r#"recipients:["alice@example.com","bob@example.com"]"#),
            "{summary}"
        );
        assert!(!summary.contains("Message from the operator"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_unlisted_recipient_overrides_allow_and_files_complete_preview() {
    let f = Fixture::new(true);
    f.list(None, "alice@example.com");
    let mut args = args();
    args["text"] = json!(format!("{} exact ending", "Long message ".repeat(150)));
    let reply = f.send(args.clone()).await;
    assert!(!f.request_id(&reply).is_empty());
    assert_eq!(f.count("action_requests"), 1);
    assert_eq!(f.count("reservations"), 0);
    assert!(f.transport.requests().is_empty());
    let cards = f.cards.0.lock().unwrap();
    assert_eq!(cards.len(), 1);
    let preview = cards[0]["preview"]["text"].as_str().unwrap();
    assert!(preview.contains("bob@example.com"), "{preview}");
    assert!(preview.contains(args["text"].as_str().unwrap()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approving_unlisted_send_is_once_and_does_not_grow_allowlist() {
    let f = Fixture::new(true);
    let held = f.send(args()).await;
    let id = f.request_id(&held);
    let approved = f
        .call(json!({"name":"requests","arguments":{"op":"approve","request_id":id}}))
        .await;
    assert!(approved.get("error").is_none(), "{approved}");
    assert_eq!(f.transport.requests().len(), 1);
    assert_eq!(f.count("recipient_allowlist"), 0);
    let retry = f
        .call(json!({"name":"requests","arguments":{"op":"approve","request_id":id}}))
        .await;
    assert_eq!(retry["error"]["code"], "approval_consumed");
    assert_eq!(f.transport.requests().len(), 1);
    let second = f.send(args()).await;
    assert_eq!(second["error"]["code"], "approval_consumed");
    let mut changed = args();
    changed["text"] = json!("A separate message needs its own approval");
    let second = f.send(changed).await;
    assert_ne!(f.request_id(&second), id);
    assert_eq!(f.count("action_requests"), 2);
    assert_eq!(f.transport.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_unlisted_recipient_refuses_consent_without_reservation() {
    let f = Fixture::new(true);
    f.routes
        .insert_scoped(
            2,
            1,
            Principal::Reserved {
                module_id: "basal".into(),
            },
            Some(CallScope {
                owner: "reserved:prefrontal-core".into(),
                scope_ref: "flow".into(),
                scope_epoch: 1,
                kind: Some("head".into()),
                parent: None,
                parent_state: None,
                agent_id: None,
                flow_id: Some("flow-one".into()),
                delegates: false,
                owner_authorized: true,
            }),
        )
        .unwrap();
    let reply = f.send(args()).await;
    assert_eq!(reply["error"]["code"], "consent_unavailable", "{reply}");
    assert_eq!(reply["error"]["action"], "send");
    assert_eq!(f.count("reservations"), 0);
    assert_eq!(f.count("action_requests"), 0);
    assert!(f.transport.requests().is_empty());
    assert!(f.cards.0.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_recipient_arguments_fail_closed_even_under_allow() {
    let f = Fixture::new(true);
    for invalid in [
        json!({"text":"hello"}),
        json!({"to":3,"cc":["bob@example.com"]}),
        json!({"to":"alice@example.com","cc":["bob@example.com",false]}),
        json!({"to":[],"cc":[]}),
        json!({"to":" ","cc":["bob@example.com"]}),
    ] {
        let reply = f.send(invalid).await;
        assert_eq!(
            reply["error"]["code"], "recipient_argument_invalid",
            "{reply}"
        );
    }
    assert_eq!(f.count("reservations"), 0);
    assert_eq!(f.count("action_requests"), 0);
    assert!(f.transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undeclared_action_keeps_allow_behavior() {
    let f = Fixture::new(false);
    let reply = f.send(args()).await;
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(f.transport.requests().len(), 1);
    assert_eq!(f.count("action_requests"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recipients_management_preview_apply_remove_and_direct_boundary() {
    let f = Fixture::new(true);
    let params = json!({"connection":"mail","recipient":" ALICE@EXAMPLE.COM "});
    let preview = f
        .manage(manifest::ADMIN_RECIPIENTS_ADD_OP, params.clone())
        .await;
    assert_eq!(preview["result"]["outcome"], "would_add");
    assert_eq!(preview["result"]["widening"], true);
    assert_eq!(f.count("recipient_allowlist"), 0);
    for recipient in ["alice@example.com", "bob@example.com"] {
        let applied = f
            .manage(
                manifest::ADMIN_RECIPIENTS_ADD_OP,
                json!({"connection":"mail","recipient":recipient,"dry_run":false}),
            )
            .await;
        assert_eq!(applied["result"]["outcome"], "added", "{applied}");
    }
    let reply = f.send(args()).await;
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(f.transport.requests().len(), 1);
    let listed = f
        .manage(
            manifest::ADMIN_RECIPIENTS_LIST_OP,
            json!({"connection":"mail"}),
        )
        .await;
    assert_eq!(
        listed["result"]["recipients"],
        json!(["alice@example.com", "bob@example.com"])
    );
    let before = f.count("audit_journal");
    f.manage(
        manifest::ADMIN_RECIPIENTS_LIST_OP,
        json!({"connection":"mail"}),
    )
    .await;
    assert_eq!(f.count("audit_journal"), before);
    let removed = f
        .manage(manifest::ADMIN_RECIPIENTS_REMOVE_OP, params.clone())
        .await;
    assert_eq!(removed["result"]["outcome"], "would_remove");
    assert_eq!(f.count("recipient_allowlist"), 2);
    f.manage(
        manifest::ADMIN_RECIPIENTS_REMOVE_OP,
        json!({"connection":"mail","recipient":"alice@example.com","dry_run":false}),
    )
    .await;
    let held = f.send(args()).await;
    assert!(!f.request_id(&held).is_empty());
    assert_eq!(f.transport.requests().len(), 1);
    f.routes
        .insert(
            3,
            1,
            Principal::Reserved {
                module_id: "aft".into(),
            },
        )
        .unwrap();
    for method in [
        manifest::ADMIN_RECIPIENTS_ADD_OP,
        manifest::ADMIN_RECIPIENTS_REMOVE_OP,
        manifest::ADMIN_RECIPIENTS_LIST_OP,
    ] {
        let reply = f.manage(method, params.clone()).await;
        assert_eq!(
            reply["error"]["code"], "operator_authority_required",
            "{reply}"
        );
    }
    let conn = rusqlite::Connection::open(f.scratch.path()).unwrap();
    let audits:i64 = conn.query_row("SELECT COUNT(*) FROM audit_journal WHERE action IN ('recipients_add','recipients_remove')",[],|r|r.get(0)).unwrap();
    assert_eq!(audits, 5);
}

#[test]
fn manifest_unresolvable_recipient_pointer_refuses_ingest_by_action_and_pointer() {
    for pointer in ["/missing", "/text/invalid", "/cc/01", "/to~3", "to"] {
        let mut value = manifest_value(true);
        value["actions_baseline"][0]["recipients"] = json!([pointer]);
        let error = plexus_core::manifest::ingest_value(value)
            .unwrap_err()
            .to_string();
        assert!(error.contains("send") && error.contains(pointer), "{error}");
    }
}

#[test]
fn non_rest_declaration_requires_and_accepts_its_reviewed_input_schema() {
    let mut value = manifest_value(true);
    let schema = value["actions_baseline"][0]["http"]["args_schema"].clone();
    value["transport"]["kind"] = json!("mcp_remote");
    value["actions_baseline"][0]
        .as_object_mut()
        .unwrap()
        .remove("http");
    assert!(plexus_core::manifest::ingest_value(value.clone()).is_err());
    value["actions_baseline"][0]["input_schema"] = schema;
    assert!(plexus_core::manifest::ingest_value(value).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listed_recipients_keep_default_ask_first_until_policy_allows() {
    let f = Fixture::new(true);
    f.list(None, "alice@example.com");
    f.list(None, "bob@example.com");
    let policy = f
        .store()
        .list_policies("direct", Some("mail"))
        .unwrap()
        .pop()
        .unwrap();
    f.store()
        .remove_policy("direct", &policy.policy_id)
        .unwrap();
    let reply = f.send(args()).await;
    assert!(!f.request_id(&reply).is_empty());
    assert!(f.transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_overrides_stored_approval_without_consuming_or_sending() {
    // A current block refuses even a call approved earlier, for every action;
    // an earlier approval must not bypass the operator's later restriction.
    for declared in [false, true] {
        let f = Fixture::new(declared);
        f.policy("ask_first");
        let held = f.send(args()).await;
        let id = f.request_id(&held);
        assert!(f
            .store()
            .decide_action_request("direct", &id, true, "direct")
            .unwrap());
        f.policy("block");
        let authorization =
            plexus_core::AuthorizationRequest::new("direct", "mail", "send", args())
                .approved_from(&id);
        let denial = f.state.runtime.engine.authorize(authorization).unwrap_err();
        assert_eq!(denial.reason_code(), "policy_blocked");
        let status: String = rusqlite::Connection::open(f.scratch.path())
            .unwrap()
            .query_row(
                "SELECT status FROM action_requests WHERE request_id=?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "approved");
        assert!(f.transport.requests().is_empty());
        assert_eq!(f.count("reservations"), 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recipient_keys_separate_agents_connections_and_module_only_calls() {
    let f = Fixture::new(true);
    f.list(Some("agent-one"), "alice@example.com");
    f.list(Some("agent-one"), "bob@example.com");
    let held = f.send(args()).await;
    assert!(!f.request_id(&held).is_empty());
    // A scope identifying an agent without delegating its authority still makes
    // a module-only call, so it cannot use that agent's recipient list.
    f.routes
        .insert_scoped(
            2,
            1,
            Principal::Direct,
            Some(CallScope {
                owner: "reserved:prefrontal-core".into(),
                scope_ref: "session".into(),
                scope_epoch: 1,
                kind: Some("head".into()),
                parent: None,
                parent_state: None,
                agent_id: Some("agent-one".into()),
                flow_id: None,
                delegates: false,
                owner_authorized: true,
            }),
        )
        .unwrap();
    let held = f.send(args()).await;
    assert_eq!(held["error"]["code"], "consent_unavailable");
    f.store()
        .insert_grant(&GrantInput {
            grant_id: "agent".into(),
            principal: "direct".into(),
            connection_id: "mail".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "write".into(),
            action_selectors: vec!["send".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    rusqlite::Connection::open(f.scratch.path())
        .unwrap()
        .execute(
            "UPDATE grants SET agent_id='agent-one' WHERE grant_id='agent'",
            [],
        )
        .unwrap();
    f.routes
        .insert_scoped(
            2,
            1,
            Principal::Direct,
            Some(CallScope {
                owner: "reserved:prefrontal-core".into(),
                scope_ref: "session".into(),
                scope_epoch: 1,
                kind: Some("head".into()),
                parent: None,
                parent_state: None,
                agent_id: Some("agent-one".into()),
                flow_id: None,
                delegates: true,
                owner_authorized: true,
            }),
        )
        .unwrap();
    let reply = f.send(args()).await;
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(f.transport.requests().len(), 1);
    assert!(f
        .store()
        .list_recipients("direct", "other-connection", Some("agent-one"))
        .unwrap()
        .is_empty());
    assert!(f
        .store()
        .list_recipients("direct", "mail", Some("agent-two"))
        .unwrap()
        .is_empty());
}

#[test]
fn removed_recipient_invalidates_an_outstanding_reservation() {
    let f = Fixture::new(true);
    f.list(None, "alice@example.com");
    f.list(None, "bob@example.com");
    let reservation = f
        .state
        .runtime
        .engine
        .authorize(plexus_core::AuthorizationRequest::new(
            "direct",
            "mail",
            "send",
            args(),
        ))
        .unwrap();
    f.store()
        .change_recipient("direct", "mail", None, "bob@example.com", false, true)
        .unwrap();
    let outcome = f.state.runtime.engine.revalidate_and_dispatch(&reservation);
    assert_eq!(
        outcome.transmission,
        plexus_core::TransmissionState::NotSent
    );
    assert!(f.transport.requests().is_empty());
}

#[test]
fn oversized_complete_preview_refuses_before_parking_or_filing_a_card() {
    let f = Fixture::new(true);
    let mut arguments = args();
    // Call the engine directly because the transport rejects this oversized
    // body before it reaches authorization. The authorization size check is
    // still needed for smaller incoming requests: serializing their arguments
    // into a preview string adds JSON escaping that can push the card request
    // past the daemon's maximum frame-body size.
    arguments["text"] = json!("x".repeat(subc_protocol::MAX_FRAME_BODY_LEN as usize));
    let denial = f
        .state
        .runtime
        .engine
        .authorize(
            plexus_core::AuthorizationRequest::new("direct", "mail", "send", arguments)
                .with_scope(recipient_worker_scope()),
        )
        .unwrap_err();
    match denial {
        plexus_core::Denial::ApprovalPreviewTooLong {
            action,
            length,
            limit,
        } => {
            assert_eq!(action, "send");
            assert!(length > limit);
            assert_eq!(limit, subc_protocol::MAX_FRAME_BODY_LEN as usize);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(f.count("action_requests"), 0);
    assert_eq!(f.count("reservations"), 0);
    assert!(f.cards.0.lock().unwrap().is_empty());
    assert!(f.transport.requests().is_empty());
}
