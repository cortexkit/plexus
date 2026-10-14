use super::*;
use plexus_core::{CatalogActionInput, GrantInput, MockResponse};

struct Fixture {
    cards: Option<Arc<plexus_core::ConsentCards>>,
    store: Arc<PlexusStore>,
    transport: Arc<MockTransport>,
    path: Scratch,
}

impl Fixture {
    fn new() -> Self {
        let path = Scratch::database("code-search-wire");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "code-search-wire".into(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        let source =
            subc_jsonc::jsonc_to_json(include_str!("../../../catalog/grep_app.jsonc")).unwrap();
        store
            .upsert_manifest(
                plexus_core::storage::CATALOG_PRINCIPAL,
                &plexus_core::ingest_value(serde_json::from_str(&source).unwrap()).unwrap(),
            )
            .unwrap();
        store
            .insert_connection(
                "direct",
                "grep",
                "grep_app",
                "pending",
                &json!({"required":[],"optional":[],"write_enabling":[]}),
            )
            .unwrap();
        let ticket = store
            .create_binding_ticket_with_role("direct", "grep", "none", b"")
            .unwrap();
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .unwrap()
            .unwrap();
        let schema = json!({"type":"object"});
        store
            .upsert_catalog_action(&CatalogActionInput {
                principal: "direct".into(),
                connection_id: "grep".into(),
                name: "searchGitHub".into(),
                title: None,
                schema: schema.clone(),
                schema_hash: plexus_core::jcs_sha256(&schema).unwrap(),
                risk: "read".into(),
                severity: "S1".into(),
                ask_first: false,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
        for caller in ["direct", "reserved:basal"] {
            store
                .insert_grant(&GrantInput {
                    principal: "direct".into(),
                    connection_id: "grep".into(),
                    grant_id: caller.into(),
                    grantee_principal: caller.into(),
                    risk_ceiling: "read".into(),
                    action_selectors: vec!["searchGitHub".into()],
                    authority_kind: "invoke".into(),
                    expires_at: None,
                })
                .unwrap();
        }
        let data = include_str!("../../plexus-core/tests/fixtures/grep_app/search.sse")
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .unwrap();
        let transport = Arc::new(MockTransport::default());
        transport.set_response(MockResponse::Success(
            serde_json::from_str::<Value>(data).unwrap()["result"].clone(),
        ));
        Self {
            cards: None,
            store,
            transport,
            path,
        }
    }

    async fn call(
        &self,
        principal: Principal,
        scope: Option<subc_protocol::scope::ScopeStamp>,
        args: Value,
    ) -> Value {
        let mut runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
            self.store.clone(),
            Arc::new(StubCredentialSource::default()),
            self.transport.clone(),
        );
        if let Some(cards) = &self.cards {
            runtime.engine = runtime.engine.with_consent_cards(cards.clone());
        }
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            41,
            1,
            7,
            serde_json::to_vec(&json!({"name":manifest::CODE_SEARCH_TOOL,"arguments":args}))
                .unwrap(),
        )
        .unwrap();
        let (writer, mut responses) = mpsc::channel(1);
        handle_scoped_tool_request_for_test(frame, &writer, runtime, principal, scope)
            .await
            .unwrap();
        let reply: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "code search reply",
            )
            .await
            .body,
        )
        .unwrap();
        let result: cortexkit_role_tool_provider::result::ToolResult =
            serde_json::from_value(reply.clone()).unwrap();
        cortexkit_role_tool_provider::result::validate(&result).unwrap();
        assert!(reply.get("result").is_none());
        assert!(reply.get("error").is_none());
        reply
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn facade_maps_arguments_and_emits_readable_and_structured_matches() {
    let f = Fixture::new();
    let reply = f.call(Principal::Direct,None,json!({"query":"pub fn with_capacity", "regex":true, "match_case":true,"whole_words":true,"repo":"rust-lang/rust","path":"library/","language":["Rust"]})).await;
    assert_eq!(reply["isError"], false, "{reply}");
    let structured = &reply["structuredContent"];
    assert!(reply.get("result").is_none());
    assert!(reply.get("error").is_none());
    assert_eq!(structured["matches"].as_array().unwrap().len(), 10);
    let text = reply["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("rust-lang/rust library/std/src/collections/hash/set.rs"));
    assert!(text.contains("169:     pub fn with_capacity"));
    assert!(text.len() <= plexus_core::code_search::reply::MAX_TEXT_BYTES);
    assert_eq!(
        f.transport.requests()[0].args,
        json!({"query":"pub fn with_capacity","useRegexp":true,"matchCase":true,"matchWholeWords":true,"repo":"rust-lang/rust","path":"library/","language":["Rust"]})
    );
    let invalid = f
        .call(Principal::Direct, None, json!({"query":"x","unknown":true}))
        .await;
    assert_eq!(invalid["errorCode"], "invalid_query");
    assert_eq!(f.transport.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn repo_filtered_zero_matches_explain_that_the_filter_may_be_too_narrow() {
    let f = Fixture::new();
    let data = include_str!("../../plexus-core/tests/fixtures/grep_app/empty.sse")
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap();
    f.transport.set_response(MockResponse::Success(
        serde_json::from_str::<Value>(data).unwrap()["result"].clone(),
    ));

    let filtered = f
        .call(
            Principal::Direct,
            None,
            json!({"query":"func NewReader(", "repo":"golang/go"}),
        )
        .await;
    assert_eq!(filtered["isError"], false);
    assert_eq!(
        filtered["structuredContent"]["matches"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let text = filtered["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("A repository filter may match no indexed repository."));
    assert!(text.contains("Check the owner/name or retry without the filter."));
    assert!(text.contains("Zero matches do not prove the code does not exist."));

    let unfiltered = f
        .call(Principal::Direct, None, json!({"query":"func NewReader("}))
        .await;
    assert_eq!(unfiltered["isError"], false);
    assert!(!unfiltered["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("A repository filter may match no indexed repository."));
}

#[tokio::test(flavor = "multi_thread")]
async fn basal_flow_is_admitted_and_unscoped_basal_is_refused() {
    let f = Fixture::new();
    let basal = Principal::Reserved {
        module_id: "basal".into(),
    };
    let unscoped = f.call(basal.clone(), None, json!({"query":"x"})).await;
    assert_eq!(unscoped["errorCode"], "flow_scope_required");
    assert!(f.transport.requests().is_empty());
    let scope = subc_protocol::scope::ScopeStamp::new(
        basal.clone(),
        "flow-search",
        1,
        subc_protocol::scope::ScopeKind::Worker,
    )
    .with_attributes(
        subc_protocol::scope::ScopeAttributes::new()
            .with_agent_id(Some("reader-agent".into()))
            .with_flow_id(Some("flow-search".into()))
            .with_delegates(true),
    )
    .with_owner_authorized(true);
    let reply = f
        .call(basal, Some(scope), json!({"query":"pub fn with_capacity"}))
        .await;
    assert_eq!(reply["isError"], false, "{reply}");
    assert_eq!(f.transport.requests().len(), 1);
    let db = rusqlite::Connection::open(f.path.path()).unwrap();
    let rows:i64 = db.query_row("SELECT count(*) FROM audit_journal WHERE gate='code_search' AND agent_id='reader-agent' AND scope_flow_id='flow-search'",[],|r| r.get(0)).unwrap();
    assert_eq!(rows, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_assertion_is_refused_without_dispatch() {
    let f = Fixture::new();
    let reply = f
        .call(
            Principal::Direct,
            None,
            json!({
                "query": "pub fn with_capacity", "agent_assertion": {}
            }),
        )
        .await;
    assert_eq!(
        reply["errorCode"], "argument_undeclared",
        "code_search must reject agent_assertion as an undeclared argument"
    );
    assert!(reply["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("field: agent_assertion"));
    assert_eq!(reply["isError"], true);
    assert!(
        f.transport.requests().is_empty(),
        "an assertion must never enable dispatch"
    );

    let secret = f
        .call(
            Principal::Direct,
            None,
            json!({
                "query": "pub fn with_capacity", "agent_assertion": {"token": "not-a-token"}
            }),
        )
        .await;
    assert_eq!(
        secret["errorCode"], "argument_undeclared",
        "retired identity fields are refused before the secret screen"
    );
    assert!(!secret.to_string().contains("not-a-token"));
    assert!(f.transport.requests().is_empty());

    let valid = f
        .call(
            Principal::Direct,
            None,
            json!({"query":"pub fn with_capacity"}),
        )
        .await;
    assert_eq!(valid["isError"], false);
    assert_eq!(f.transport.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delegated_codemode_code_search_uses_only_module_rights() {
    let f = Fixture::new();
    let scope = subc_protocol::scope::ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        "run-code",
        1,
        subc_protocol::scope::ScopeKind::Worker,
    )
    .with_attributes(
        subc_protocol::scope::ScopeAttributes::new()
            .with_run_id(Some("run-code".into()))
            .with_agent_id(Some("reader-agent".into()))
            .with_delegates(true),
    )
    .with_owner_authorized(true);
    let reply = f
        .call(
            Principal::Direct,
            Some(scope.clone()),
            json!({"query":"codemode code"}),
        )
        .await;
    assert!(
        reply.get("structuredContent").is_some(),
        "a run needs no agent grant for code search: {reply}"
    );
    assert_eq!(f.transport.requests().len(), 1);
    let denied = f
        .call(
            Principal::Reserved {
                module_id: "broca".into(),
            },
            Some(scope),
            json!({"query":"codemode code"}),
        )
        .await;
    assert_eq!(
        denied["errorCode"], "code_search_not_granted",
        "run delegation cannot replace module authority: {denied}"
    );
    assert_eq!(f.transport.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ask_first_search_refuses_without_card_or_vendor_contact() {
    let mut f = Fixture::new();
    let spy = Arc::new(crate::consent_test_support::SearchCardSpy::default());
    f.cards = Some(spy.cards());
    f.store
        .set_policy("direct", "grep", "searchGitHub", "ask_first", None)
        .unwrap();
    let reply = f
        .call(
            Principal::Direct,
            Some(crate::consent_test_support::worker_stamp(
                "search-worker",
                1,
            )),
            json!({"query":"scoped authorization"}),
        )
        .await;
    assert_eq!(spy.calls(), 0, "search must never contact Cingulate");
    assert!(
        f.store.list_action_requests("direct").unwrap().is_empty(),
        "search must never file an approval row"
    );
    assert!(f.transport.requests().is_empty());
    assert_eq!(reply["errorCode"], "policy_ask_first");
    let text = reply["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("cannot be approved per call"), "{reply}");
    assert!(text.contains("allow or block"), "{reply}");
}
