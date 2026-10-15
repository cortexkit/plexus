//! The `web_search` tool end to end: a real store, the module's tool handler,
//! and the mock transport standing in for Exa.

use super::*;
use chrono::TimeZone;
use plexus_core::storage::web_search_store::WebSearchLimits;
use plexus_core::web_search::{ExaRestBackend, WebSearchService};
use plexus_core::{jcs_sha256, CatalogActionInput, GrantInput, MockResponse};
use rusqlite::{params, Connection};

/// An Exa `/search` reply built from Exa's published API example; see the
/// README beside it for exactly what is documentation and what is shaped.
const REPLY: &str = include_str!("../tests/fixtures/web_search/exa_search_reply.json");
const CONNECTION: &str = "conn-exa";
const HANDLE: &[u8] = b"test:exa-test-handle";
const AGENT: &str = "agent_ws";
/// The service clock is held here, so a test can spend a whole per-minute
/// allowance without the bucket refilling underneath it.
const NOW_MS: i64 = 1_790_000_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn code_lookup_refusals_are_audited_without_spending_rate_budget() {
    let fixture = Fixture::new("code-lookup-budget");
    fixture
        .store
        .set_web_search_limits(
            "exa",
            WebSearchLimits {
                per_caller_per_minute: 1,
                per_backend_per_minute: 1,
            },
        )
        .unwrap();
    for arguments in [
        json!({"query": "site:github.com/owner/repo/blob/main/lib.rs"}),
        json!({"query": "dependency API", "include_domains": ["docs.rs"]}),
        json!({"query": "a".repeat(64)}),
    ] {
        let query = arguments["query"].as_str().unwrap().to_string();
        let reply = fixture.search(Principal::Direct, arguments).await;
        assert_eq!(reply["error"]["code"], "web_search_code_lookup");
        assert_eq!(reply["isError"], true);
        assert_eq!(fixture.requests(), 0);
        assert_eq!(fixture.reservations(), 0);
        let rows = fixture.web_search_rows();
        let row = rows.last().unwrap();
        assert_eq!(row.query_text.as_deref(), Some(query.as_str()));
        assert_eq!(row.reason_code, "web_search_code_lookup");
        assert_eq!(row.outcome.as_deref(), Some("not_sent"));
        assert_eq!(row.result_count, None);
    }
    let reply = fixture
        .search(Principal::Direct, json!({"query": "rust async book"}))
        .await;
    assert!(
        reply.get("result").is_some(),
        "refusals must leave the entire caller and backend allowance unspent: {reply}"
    );
    assert_eq!(fixture.requests(), 1);
    let reply = fixture
        .search(Principal::Direct, json!({"query": "site:docs.rs tokio"}))
        .await;
    assert_eq!(
        reply["error"]["code"], "web_search_code_lookup",
        "source refusal must precede an exhausted limiter"
    );
    let reply = fixture
        .search(Principal::Direct, json!({"query": "release notes"}))
        .await;
    assert_eq!(reply["error"]["code"], "rate_limited");
    assert_eq!(fixture.requests(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn code_lookup_guard_preserves_argument_validation() {
    let fixture = Fixture::new("code-lookup-invalid");
    let reply = fixture
        .search(
            Principal::Direct,
            json!({
                "query": "site:docs.rs tokio", "max_results": 0
            }),
        )
        .await;
    assert_eq!(reply["error"]["code"], "invalid_query");
    assert_eq!(reply["error"]["field"], "max_results");
    assert_eq!(fixture.requests(), 0);
}

fn aft() -> Principal {
    Principal::Reserved {
        module_id: "aft".to_string(),
    }
}

fn basal() -> Principal {
    Principal::Reserved {
        module_id: "basal".to_string(),
    }
}

#[derive(Debug)]
struct AuditColumns {
    gate: Option<String>,
    reason_code: String,
    outcome: Option<String>,
    agent_id: Option<String>,
    query_text: Option<String>,
    result_count: Option<i64>,
}

struct Fixture {
    consent: Option<(
        Arc<plexus_core::ConsentCards>,
        plexus_core::scope::CallScope,
    )>,
    store: Arc<PlexusStore>,
    transport: Arc<MockTransport>,
    credentials: Arc<StubCredentialSource>,
    web_search: Arc<WebSearchService>,
    path: Scratch,
}

impl Fixture {
    /// One active Exa REST connection owned by `direct`, its `search` action,
    /// and a module grant for `direct` and for `reserved:aft`.
    fn new(label: &str) -> Self {
        let path = Scratch::database(&format!("web-search-{label}"));
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".to_string(),
                storage_namespace: format!("web-search-{label}"),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .expect("open web_search store"),
        );
        let credentials = Arc::new(StubCredentialSource::default());
        credentials.set_success(HANDLE, b"exa-key".to_vec(), None, 1);
        let transport = Arc::new(MockTransport::default());
        transport.set_response(MockResponse::Success(
            serde_json::from_str(REPLY).expect("fixture reply is JSON"),
        ));
        let fixture = Self {
            consent: None,
            store,
            transport,
            credentials,
            web_search: Arc::new(WebSearchService::with_clock(
                Arc::new(ExaRestBackend),
                Arc::new(|| NOW_MS),
            )),
            path,
        };
        fixture.add_connection(CONNECTION);
        fixture.grant("grant-direct", CONNECTION, &Principal::Direct);
        fixture.grant("grant-aft", CONNECTION, &aft());
        fixture.grant("grant-basal", CONNECTION, &basal());
        fixture
    }

    fn add_connection(&self, connection_id: &str) {
        self.store
            .insert_connection(
                "direct",
                connection_id,
                "exa_rest",
                "pending",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("insert exa connection");
        let ticket = self
            .store
            .create_binding_ticket("direct", connection_id, HANDLE)
            .expect("create binding ticket");
        self.store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("consume binding ticket")
            .expect("activate connection");
        let schema = json!({"type": "object"});
        self.store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: connection_id.to_string(),
                principal: "direct".to_string(),
                name: "search".to_string(),
                title: Some("Search".to_string()),
                schema: schema.clone(),
                schema_hash: jcs_sha256(&schema).expect("schema is JCS-compatible"),
                risk: "read".to_string(),
                severity: "S1".to_string(),
                ask_first: false,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("insert search action");
    }

    fn grant(&self, grant_id: &str, connection_id: &str, grantee: &Principal) {
        self.store
            .insert_grant(&GrantInput {
                grant_id: grant_id.to_string(),
                principal: "direct".to_string(),
                connection_id: connection_id.to_string(),
                grantee_principal: principal::principal_key(grantee),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["search".to_string()],
                authority_kind: "invoke".to_string(),
                expires_at: None,
            })
            .expect("insert module grant");
    }

    /// An agent's own grant, written the way the handle ceremony writes one:
    /// the carrying module as grantee, the agent in `agent_id`.
    fn agent_grant(&self, grantee: &Principal, agent_id: &str) {
        let db = Connection::open(self.path.as_ref() as &Path).expect("open store file");
        db.execute(
            "INSERT INTO grants (grant_id, principal, connection_id, grantee_principal,
                risk_ceiling, authority_kind, created_at_ms, action_selectors, agent_id)
             VALUES ('grant-agent', 'direct', ?1, ?2, 'read', 'invoke', 1, '[\"search\"]', ?3)",
            params![CONNECTION, principal::principal_key(grantee), agent_id],
        )
        .expect("insert agent grant");
    }

    fn runtime(&self) -> ModuleRuntime {
        let mut runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
            Arc::clone(&self.store),
            Arc::clone(&self.credentials),
            Arc::clone(&self.transport),
        );
        if plexus_core::github::facade::gates::GateStore::handle_for_agent(
            self.store.as_ref(),
            AGENT,
        )
        .unwrap()
        .is_some()
        {
            runtime.engine = runtime.engine.with_governance_seams(Arc::new(
                plexus_core::storage::github_store::GithubGovernanceSeams {
                    store: Arc::clone(&self.store),
                    credential_provider: None,
                },
            ));
        }
        if let Some((cards, scope)) = &self.consent {
            runtime.engine = runtime
                .engine
                .with_consent_cards(cards.clone())
                .with_scope_reader(crate::consent_test_support::live_reader(scope.clone()));
        }
        runtime.web_search = Arc::clone(&self.web_search);
        runtime
    }

    async fn send(&self, principal: Principal, body: Value) -> Value {
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            41,
            1,
            7,
            serde_json::to_vec(&body).expect("serialize request"),
        )
        .expect("build request frame");
        let (writer, mut responses) = mpsc::channel(1);
        handle_tool_request_for_test(frame, &writer, self.runtime(), principal)
            .await
            .expect("handle request");
        serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "response frame",
            )
            .await
            .body,
        )
        .expect("response JSON")
    }

    async fn search(&self, principal: Principal, arguments: Value) -> Value {
        let reply = self
            .send(
                principal,
                json!({"name": manifest::WEB_SEARCH_TOOL, "arguments": arguments}),
            )
            .await;
        let result: cortexkit_role_tool_provider::result::ToolResult =
            serde_json::from_value(reply.clone()).unwrap();
        cortexkit_role_tool_provider::result::validate(&result).unwrap();
        if let Some(error) = reply.get("error") {
            assert_eq!(
                reply["errorCode"], error["code"],
                "each web-search refusal keeps its code"
            );
        }
        reply
    }

    fn requests(&self) -> usize {
        self.transport.requests().len()
    }

    fn audit(&self) -> Vec<AuditColumns> {
        let db = Connection::open(self.path.as_ref() as &Path).expect("open store file");
        let mut statement = db
            .prepare(
                "SELECT gate, reason_code, outcome, agent_id, query_text, result_count
                 FROM audit_journal ORDER BY journal_id",
            )
            .expect("prepare audit read");
        let rows = statement
            .query_map([], |row| {
                Ok(AuditColumns {
                    gate: row.get(0)?,
                    reason_code: row.get(1)?,
                    outcome: row.get(2)?,
                    agent_id: row.get(3)?,
                    query_text: row.get(4)?,
                    result_count: row.get(5)?,
                })
            })
            .expect("read audit");
        rows.collect::<Result<_, _>>().expect("audit rows")
    }

    /// Pin the connection's `search` action to the shipped reviewed schema from
    /// `catalog/exa_rest.jsonc`, which closes its top level, instead of the
    /// open `{"type": "object"}` the fixture starts with.
    fn pin_shipped_search_schema(&self) {
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/exa_rest.jsonc"),
        )
        .expect("read shipped exa_rest catalog");
        let manifest: Value =
            serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).expect("catalog is JSONC"))
                .expect("catalog is JSON");
        let schema = manifest["actions_baseline"]
            .as_array()
            .expect("actions")
            .iter()
            .find(|action| action["name"] == "search")
            .expect("search is declared")["http"]["args_schema"]
            .clone();
        assert!(schema["properties"].is_object(), "{schema}");
        let db = Connection::open(self.path.as_ref() as &Path).expect("open store file");
        let updated = db
            .execute(
                "UPDATE catalog_actions SET schema_json = ?1, schema_hash = ?2
                 WHERE connection_id = ?3 AND name = 'search'",
                params![
                    schema.to_string(),
                    jcs_sha256(&schema).expect("schema is JCS-compatible"),
                    CONNECTION
                ],
            )
            .expect("pin search schema");
        assert_eq!(updated, 1);
    }

    async fn invoke_search(&self, args: Value) -> Value {
        self.send(
            Principal::Direct,
            json!({"name": manifest::INVOKE_TOOL, "arguments": {
                "op": "call", "connection": CONNECTION, "action": "search", "args": args
            }}),
        )
        .await
    }

    fn reservations(&self) -> i64 {
        Connection::open(self.path.as_ref() as &Path)
            .expect("open store file")
            .query_row("SELECT COUNT(*) FROM reservations", [], |row| row.get(0))
            .expect("count reservations")
    }

    fn web_search_rows(&self) -> Vec<AuditColumns> {
        self.audit()
            .into_iter()
            .filter(|row| row.gate.as_deref() == Some("web_search"))
            .collect()
    }
}

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or("")
}

#[test]
fn different_connection_facade_calls_progress_during_a_rest_pool_sweep() {
    use plexus_core::{CredentialSource, GovernanceEngine, RestConfig, RestTransport, Transport};
    use std::time::Duration;

    // reqwest's blocking client panics if it's dropped inside a Tokio runtime,
    // so the transport owning the clients lives outside block_on and outlasts it,
    // including when an assertion fails.
    let rest = Arc::new(RestTransport::default());
    let executor = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    executor.block_on(async {
    let fixture = Fixture::new("concurrent-rest-sweep");
    let (first_arrived, mut first_requests) = mpsc::channel(1);
    let (second_arrived, mut second_requests) = mpsc::channel(1);
    let (release_first, first_release) = std::sync::mpsc::channel();
    let (release_second, second_release) = std::sync::mpsc::channel();
    let response = || {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{REPLY}",
            REPLY.len()
        )
    };
    let (first_url, first_server) = test_http::FixedRequestServer::start_with_deadline(1, "first vendor", Duration::from_secs(20), move |_, _| {
        first_arrived.blocking_send(()).unwrap();
        first_release.recv_timeout(Duration::from_secs(60)).expect("release first vendor");
        response()
    });
    let configure = |connection, url| {
        let mut config = RestConfig::new(url).with_actions(HashMap::from([(
            "search".into(), plexus_core::manifest::HttpOperation {
                method: plexus_core::manifest::HttpMethod::Post,
                path: "/search".into(),
                args_schema: json!({"type": "object"}),
                request_constants: None,
                credentialless_tail: None,
            },
        )]));
        // Vendor expiry must not release the busy entry during the progress
        // check: only the explicit release messages may open these gates.
        config.request_timeout = Duration::from_secs(60);
        rest.register_config(connection, config);
    };
    configure(CONNECTION, first_url);
    let mut runtime = fixture.runtime();
    runtime.engine = GovernanceEngine::new(
        Arc::clone(&fixture.store),
        Arc::clone(&fixture.credentials) as Arc<dyn CredentialSource>,
        Arc::clone(&rest) as Arc<dyn Transport>,
    );
    runtime.rest_transport = Arc::clone(&rest);
    let state = Arc::new(ModuleState { health: Arc::new(health::HealthState::new()), runtime });
    let routes = Arc::new(RouteBindings::new());
    routes.insert(41, 1, aft()).unwrap();
    let frame = |correlation, body| Frame::build_with_version(
        PROTOCOL_VERSION, FrameType::Request, Flags::new(false, Priority::Interactive, false),
        41, 1, correlation, serde_json::to_vec(&body).unwrap(),
    ).unwrap();
    let (writer, mut responses) = mpsc::channel(2);
    handle_frame(frame(1, json!({"name": "web_search", "arguments": {"query": "slow vendor"}})),
        &writer, &state, &routes).await.unwrap();
    recv_within(first_requests.recv(), Duration::from_secs(5), "first vendor request").await;

    // web_search refuses a search when the caller can reach more than one search
    // connection (backend_ambiguous). So the second connection is added only
    // after the search has picked the first and is in flight. Both connections
    // still share the one REST pool, which is what this test exercises.
    let fixture = tokio::task::spawn_blocking(move || {
        fixture.add_connection("conn-other");
        fixture.grant("grant-other", "conn-other", &aft());
        fixture
    }).await.unwrap();
    let sweep_rest = Arc::clone(&rest);
    // Start the sweep on its own thread so a queued blocking-pool dispatch is
    // not mistaken for waiting on the vendor's pooled entry.
    let (swept, mut sweep) = tokio::sync::oneshot::channel();
    let sweep_worker = std::thread::spawn(move || {
        let _ = swept.send(sweep_rest.sweep_idle());
    });
    let sweep_result = tokio::time::timeout(Duration::from_secs(5), &mut sweep).await;
    let (second_url, second_server) = test_http::FixedRequestServer::start_with_deadline(1, "second vendor", Duration::from_secs(20), move |_, _| {
        second_arrived.blocking_send(()).unwrap();
        second_release.recv_timeout(Duration::from_secs(60)).expect("release second vendor");
        response()
    });
    configure("conn-other", second_url);
    handle_frame(frame(2, json!({"name": "invoke", "arguments": {
        "op": "call", "connection": "conn-other", "action": "search", "args": {"query": "other vendor"}
    }})), &writer, &state, &routes).await.unwrap();
    // The first vendor stays gated throughout this wait. Extra headroom for the
    // second call's durable governance writes cannot hide pool serialization.
    let second_started = tokio::time::timeout(Duration::from_secs(20), second_requests.recv()).await;

    // Both calls should be at their vendors at once. If they were serialized,
    // the second would never start while the first is held, and joining with the
    // first still held would hang the test. So release both vendors and join
    // every worker before checking, so a regression fails instead of hanging.
    let _ = release_first.send(());
    let _ = release_second.send(());
    let mut valid_replies = true;
    for _ in 0..2 {
        let reply = recv_within(responses.recv(), Duration::from_secs(20), "facade response").await;
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        valid_replies &= body.get("result").is_some();
    }
    if sweep_result.is_err() {
        recv_within(async { Some(sweep.await.unwrap()) }, Duration::from_secs(5), "pool sweep").await;
    }
    let (first_joined, second_joined) = blocking_section(|| {
        sweep_worker.join().unwrap();
        (first_server.join(), second_server.join())
    });
    assert!(sweep_result.is_ok(), "REST sweep must not wait for an in-flight facade call");
    assert!(matches!(second_started, Ok(Some(()))),
        "second facade call must reach its vendor before the first is released");
    first_joined.unwrap();
    second_joined.unwrap();
    assert!(valid_replies, "facade call refused");
    assert_eq!(rest.connection_count(), 2, "an in-flight client must remain pooled");
    drop(fixture);
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exa_reply_maps_onto_every_neutral_field() {
    let fixture = Fixture::new("mapping");
    let before = chrono::Utc
        .timestamp_millis_opt(plexus_core::storage::now_ms())
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let reply = fixture
        .search(
            Principal::Direct,
            json!({"query": "  Latest LLM developments ", "max_results": 5}),
        )
        .await;
    let after = chrono::Utc
        .timestamp_millis_opt(plexus_core::storage::now_ms())
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let result = &reply["result"];
    assert_eq!(result["backend"], "exa", "{reply}");
    assert_eq!(result["cached"], false);
    let results = result["results"].as_array().expect("results array");
    assert_eq!(results.len(), 2);
    let fetched_at = results[0]["fetched_at"].as_str().expect("fetched_at");
    assert!(
        before.as_str() <= fetched_at && fetched_at <= after.as_str(),
        "fetched_at {fetched_at} is the receipt time, between {before} and {after}"
    );
    assert_eq!(
        results[0],
        json!({
            "url": "https://arxiv.org/pdf/2307.06435.pdf",
            "title": "A Comprehensive Overview of Large Language Models",
            "excerpt": "Such requirements have limited their adoption...",
            "published_at": "2023-11-16T01:36:32.547Z",
            "fetched_at": fetched_at,
        }),
        "highlights, not text or summary, become the excerpt"
    );
    assert_eq!(
        results[1],
        json!({
            "url": "https://exa.ai/docs/reference/search",
            "title": "Search",
            "excerpt": "Perform a search with an Exa prompt-engineered query and retrieve a list of relevant results. Optionally get contents.",
            "fetched_at": fetched_at,
        }),
        "without highlights the excerpt is the text, and no publishedDate means no published_at"
    );
    assert!(results[1].get("published_at").is_none());

    let requests = fixture.transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].action, "search");
    assert_eq!(requests[0].connection_id, CONNECTION);
    assert_eq!(
        requests[0].args,
        json!({
            "query": "Latest LLM developments",
            "numResults": 5,
            "contents": {
                "highlights": {"maxCharacters": 600},
                "text": {"maxCharacters": 600}
            }
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caller_without_a_grant_is_refused_before_the_vendor() {
    let fixture = Fixture::new("no-grant");
    let stranger = Principal::Reserved {
        module_id: "prefrontal-core".to_string(),
    };
    let reply = fixture.search(stranger, json!({"query": "anything"})).await;
    assert_eq!(code(&reply), "web_search_not_granted", "{reply}");
    assert_eq!(fixture.requests(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stamped_agent_cannot_replace_the_carriers_module_grant() {
    let fixture = Fixture::new("stamped-no-module-grant");
    let stranger = Principal::Reserved {
        module_id: "prefrontal-core".to_string(),
    };
    fixture.agent_grant(&stranger, AGENT);
    let reply = fixture
        .send_scoped(
            stranger,
            stamp(Some(AGENT), false, true),
            json!({"name":manifest::WEB_SEARCH_TOOL,"arguments":{"query":"anything"}}),
        )
        .await;
    assert_eq!(code(&reply), "web_search_not_granted", "{reply}");
    assert_eq!(fixture.requests(), 0);
    let rows = fixture.web_search_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].agent_id.as_deref(), Some(AGENT));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unscoped_module_grant_is_enough() {
    let fixture = Fixture::new("module-only");
    let reply = fixture.search(aft(), json!({"query": "module only"})).await;
    assert_eq!(reply["result"]["cached"], false, "{reply}");
    assert_eq!(fixture.requests(), 1);
    assert!(fixture.audit().iter().all(|row| row.agent_id.is_none()));
}

/// A live search from a session's primary agent, relayed by Prefrontal, was
/// refused despite the carrier's module grant because no search agent grants
/// were minted. Prefrontal's per-session `websearch: off | plexus` setting
/// already controls tool access; search uses the carrier's module grant and the
/// stamped agent only for attribution and the caller's rate bucket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stamped_agent_without_its_own_grant_searches_attributed() {
    let fixture = Fixture::new("agent-module-granted");
    let reply = fixture
        .send_scoped(
            aft(),
            stamp(Some(AGENT), false, true),
            json!({"name":manifest::WEB_SEARCH_TOOL,"arguments":{"query":"agent search"}}),
        )
        .await;
    assert_eq!(reply["result"]["cached"], false, "{reply}");
    assert_eq!(fixture.requests(), 1);
    let rows = fixture.web_search_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].agent_id.as_deref(), Some(AGENT));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stamped_agent_with_both_grants_searches_attributed() {
    let fixture = Fixture::new("agent-granted");
    fixture.agent_grant(&aft(), AGENT);
    let reply = fixture
        .send_scoped(
            aft(),
            stamp(Some(AGENT), false, true),
            json!({"name":manifest::WEB_SEARCH_TOOL,"arguments":{"query":"agent search"}}),
        )
        .await;
    assert_eq!(reply["result"]["cached"], false, "{reply}");
    assert_eq!(fixture.requests(), 1);
    let audit = fixture.audit();
    assert!(
        audit
            .iter()
            .any(|row| row.gate.as_deref() != Some("web_search")
                && row.agent_id.as_deref() == Some(AGENT)),
        "the governance rows carry the agent: {audit:?}"
    );
    assert_eq!(
        fixture.web_search_rows()[0].agent_id.as_deref(),
        Some(AGENT)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_policy_refuses_a_cached_query() {
    let fixture = Fixture::new("cached-block");
    let first = fixture
        .search(Principal::Direct, json!({"query": "policy me"}))
        .await;
    assert_eq!(first["result"]["cached"], false, "{first}");
    fixture
        .store
        .insert_policy(&plexus_core::PolicyInput {
            policy_id: "block-search".to_string(),
            principal: "direct".to_string(),
            connection_id: CONNECTION.to_string(),
            action_selector: "search".to_string(),
            effect: "block".to_string(),
            expires_at: None,
        })
        .expect("insert block policy");
    let second = fixture
        .search(Principal::Direct, json!({"query": "policy me"}))
        .await;
    assert_eq!(code(&second), "web_search_not_granted", "{second}");
    assert_eq!(fixture.requests(), 1, "the refused hit sent nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ask_first_policy_refuses_a_cached_query_without_parking_a_request() {
    let fixture = Fixture::new("cached-ask-first");
    fixture
        .search(Principal::Direct, json!({"query": "ask me"}))
        .await;
    fixture
        .store
        .insert_policy(&plexus_core::PolicyInput {
            policy_id: "ask-search".to_string(),
            principal: "direct".to_string(),
            connection_id: CONNECTION.to_string(),
            action_selector: "*".to_string(),
            effect: "ask_first".to_string(),
            expires_at: None,
        })
        .expect("insert ask_first policy");
    let second = fixture
        .search(Principal::Direct, json!({"query": "ask me"}))
        .await;
    assert_eq!(code(&second), "policy_ask_first", "{second}");
    assert_eq!(fixture.requests(), 1);
    assert!(fixture
        .store
        .list_action_requests("direct")
        .expect("action requests")
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_31st_call_in_a_minute_is_limited_for_that_caller_only() {
    let fixture = Fixture::new("per-caller");
    for call in 1..=30 {
        let reply = fixture
            .search(Principal::Direct, json!({"query": "limits"}))
            .await;
        assert!(reply.get("result").is_some(), "call {call}: {reply}");
    }
    let refused = fixture
        .search(Principal::Direct, json!({"query": "limits"}))
        .await;
    assert_eq!(code(&refused), "rate_limited", "{refused}");
    let retry_after = refused["error"]["retry_after_ms"]
        .as_u64()
        .expect("retry_after_ms");
    assert!(retry_after > 0);
    let second_caller = fixture.search(aft(), json!({"query": "limits"})).await;
    assert!(
        second_caller.get("result").is_some(),
        "another caller keeps its own allowance: {second_caller}"
    );
    assert_eq!(fixture.requests(), 1, "every repeat was a cache hit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_backend_cap_applies_across_callers() {
    let fixture = Fixture::new("per-backend");
    fixture
        .store
        .set_web_search_limits(
            "exa",
            WebSearchLimits {
                per_caller_per_minute: 30,
                per_backend_per_minute: 3,
            },
        )
        .expect("set limits");
    for principal in [Principal::Direct, Principal::Direct, aft()] {
        let reply = fixture
            .search(principal, json!({"query": "shared cap"}))
            .await;
        assert!(reply.get("result").is_some(), "{reply}");
    }
    for principal in [aft(), Principal::Direct] {
        let refused = fixture
            .search(principal, json!({"query": "shared cap"}))
            .await;
        assert_eq!(code(&refused), "rate_limited", "{refused}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cache_hit_skips_the_vendor_and_is_audited() {
    let fixture = Fixture::new("cache-hit");
    let first = fixture
        .search(Principal::Direct, json!({"query": "Cache Me"}))
        .await;
    let second = fixture
        .search(Principal::Direct, json!({"query": "  cache me  "}))
        .await;
    assert_eq!(first["result"]["cached"], false, "{first}");
    assert_eq!(second["result"]["cached"], true, "{second}");
    assert_eq!(
        second["result"]["results"], first["result"]["results"],
        "a hit returns the stored results, fetched_at included"
    );
    assert_eq!(fixture.requests(), 1);
    let rows = fixture.web_search_rows();
    let hit = rows.last().expect("cache hit row");
    assert_eq!(hit.reason_code, "web_search_cache_hit");
    assert_eq!(hit.outcome.as_deref(), Some("cached"));
    assert_eq!(hit.query_text.as_deref(), Some("cache me"));
    assert_eq!(hit.result_count, Some(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_grant_refuses_the_cached_query() {
    let fixture = Fixture::new("revoked");
    let first = fixture
        .search(Principal::Direct, json!({"query": "revoke me"}))
        .await;
    assert_eq!(first["result"]["cached"], false, "{first}");
    assert!(fixture
        .store
        .revoke_grant("direct", "grant-direct")
        .expect("revoke grant"));
    let second = fixture
        .search(Principal::Direct, json!({"query": "revoke me"}))
        .await;
    assert_eq!(code(&second), "web_search_not_granted", "{second}");
    assert_eq!(fixture.requests(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_different_max_results_is_a_cache_miss() {
    let fixture = Fixture::new("cache-miss");
    fixture
        .search(Principal::Direct, json!({"query": "count"}))
        .await;
    let three = fixture
        .search(
            Principal::Direct,
            json!({"query": "count", "max_results": 3}),
        )
        .await;
    assert_eq!(three["result"]["cached"], false, "{three}");
    assert_eq!(fixture.requests(), 2);
    let default_spelled_out = fixture
        .search(
            Principal::Direct,
            json!({"query": "count", "max_results": 8}),
        )
        .await;
    assert_eq!(
        default_spelled_out["result"]["cached"], true,
        "the default and an explicit 8 are one query"
    );
    assert_eq!(fixture.requests(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_quarantined_search_action_refuses_by_name() {
    let fixture = Fixture::new("quarantined");
    fixture
        .store
        .quarantine_action("direct", CONNECTION, "search", "schema drift")
        .expect("quarantine");
    let reply = fixture
        .search(Principal::Direct, json!({"query": "quarantine"}))
        .await;
    assert_eq!(code(&reply), "backend_quarantined", "{reply}");
    assert_eq!(reply["error"]["backend"], "exa");
    assert_eq!(fixture.requests(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_vendor_5xx_is_unavailable_and_keeps_vendor_text_out_of_the_reply() {
    let fixture = Fixture::new("vendor-5xx");
    fixture.transport.set_response(MockResponse::VendorError {
        code: "http_503".to_string(),
        message: "ghs_SECRET123 https://example.test/?token=abc".to_string(),
    });
    let reply = fixture
        .search(Principal::Direct, json!({"query": "outage"}))
        .await;
    assert_eq!(code(&reply), "backend_unavailable", "{reply}");
    assert_eq!(reply["error"]["backend"], "exa");
    let rendered = reply.to_string();
    assert!(rendered.contains("ck module logs plexus"), "{rendered}");
    for vendor_text in ["ghs_SECRET123", "?token=abc", "http_503"] {
        assert!(!rendered.contains(vendor_text), "{rendered}");
    }
    assert_eq!(fixture.requests(), 1);
    let row = fixture.web_search_rows().pop().expect("web_search row");
    assert_eq!(row.outcome.as_deref(), Some("failed"));
    assert_eq!(row.result_count, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_eligible_connections_are_ambiguous() {
    let fixture = Fixture::new("ambiguous");
    fixture.add_connection("conn-exa-second");
    fixture.grant("grant-direct-second", "conn-exa-second", &Principal::Direct);
    let reply = fixture
        .search(Principal::Direct, json!({"query": "which one"}))
        .await;
    assert_eq!(code(&reply), "backend_ambiguous", "{reply}");
    assert_eq!(fixture.requests(), 0);
    let single = fixture.search(aft(), json!({"query": "which one"})).await;
    assert!(
        single.get("result").is_some(),
        "a caller granted only one connection is not ambiguous: {single}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_argument_is_refused_by_field_before_the_vendor() {
    let fixture = Fixture::new("invalid");
    for (arguments, field) in [
        (json!({"query": ""}), "query"),
        (json!({"query": "q", "max_results": 21}), "max_results"),
        (
            json!({"query": "q", "include_domains": ["https://docs.rs"]}),
            "include_domains",
        ),
        (json!({"query": "q", "recency": "hour"}), "recency"),
        (json!({"query": "q", "numResults": 3}), "numResults"),
    ] {
        let reply = fixture.search(Principal::Direct, arguments).await;
        assert_eq!(code(&reply), "invalid_query", "{reply}");
        assert_eq!(reply["error"]["field"], field, "{reply}");
    }
    assert_eq!(fixture.requests(), 0);
}

/// An invoke carrying a top-level argument the reviewed schema does not declare
/// is refused by the argument's name before anything is reserved or sent, and
/// the refusal is audited without the argument's value. `aaa_extra` sorts
/// before `zzz_extra`, so it is the one named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invoke_refuses_an_undeclared_top_level_argument_by_name() {
    let fixture = Fixture::new("undeclared-argument");
    fixture.pin_shipped_search_schema();
    let reply = fixture
        .invoke_search(json!({
            "query": "q",
            "zzz_extra": 1,
            "aaa_extra": "undeclared-secret-value"
        }))
        .await;
    assert_eq!(code(&reply), "argument_undeclared", "{reply}");
    assert_eq!(reply["error"]["field"], "aaa_extra", "{reply}");
    assert!(
        !reply.to_string().contains("undeclared-secret-value"),
        "the refusal echoed an argument value: {reply}"
    );
    assert_eq!(fixture.requests(), 0, "nothing was dispatched");
    assert_eq!(fixture.reservations(), 0, "nothing was reserved");
    let audit = fixture.audit();
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].reason_code, "argument_undeclared");
    assert_eq!(audit[0].gate.as_deref(), Some("catalog"));
    assert_eq!(audit[0].outcome, None, "{audit:?}");
}

/// The same call without the undeclared argument dispatches, so the refusal
/// above is about the argument and not the schema or the fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invoke_with_only_declared_arguments_dispatches() {
    let fixture = Fixture::new("declared-arguments");
    fixture.pin_shipped_search_schema();
    let reply = fixture
        .invoke_search(json!({"query": "q", "numResults": 3}))
        .await;
    assert_eq!(reply["result"]["transmission"], "completed", "{reply}");
    assert_eq!(fixture.requests(), 1);
}

/// Only the top level is checked: an unknown key inside a declared object
/// argument is the vendor's schema to judge, not this one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_key_nested_in_a_declared_argument_is_not_refused() {
    let fixture = Fixture::new("nested-unknown");
    fixture.pin_shipped_search_schema();
    let reply = fixture
        .invoke_search(json!({"query": "q", "contents": {"notAnExaOption": true}}))
        .await;
    assert_eq!(reply["result"]["transmission"], "completed", "{reply}");
    assert_eq!(fixture.requests(), 1);
}

/// A schema with no `properties` object declares no argument list, so it does
/// not close the top level and nothing is refused. The fixture's own
/// `{"type": "object"}` is that shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_schema_without_properties_does_not_refuse_arguments() {
    let fixture = Fixture::new("no-properties");
    let reply = fixture
        .invoke_search(json!({"query": "q", "anything": 1}))
        .await;
    assert_eq!(reply["result"]["transmission"], "completed", "{reply}");
    assert_eq!(fixture.requests(), 1);
}

/// web_search's own backend arguments, including the `startPublishedDate` a
/// recency filter adds, are all declared by the shipped `search` schema, so a
/// search still dispatches with the check on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn web_search_with_recency_dispatches_against_the_shipped_schema() {
    let fixture = Fixture::new("recency-declared");
    fixture.pin_shipped_search_schema();
    let reply = fixture
        .search(
            Principal::Direct,
            json!({"query": "recent news", "recency": "week", "include_domains": ["docs.python.org"]}),
        )
        .await;
    assert!(reply.get("result").is_some(), "{reply}");
    let requests = fixture.transport.requests();
    assert_eq!(requests.len(), 1);
    for key in [
        "query",
        "numResults",
        "contents",
        "includeDomains",
        "startPublishedDate",
    ] {
        assert!(
            requests[0].args.get(key).is_some(),
            "{key}: {:?}",
            requests[0].args
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_web_search_rows_carry_query_text_and_result_count() {
    let fixture = Fixture::new("audit-columns");
    let searched = fixture
        .search(Principal::Direct, json!({"query": "audited query"}))
        .await;
    assert!(searched.get("result").is_some(), "{searched}");
    let refused = fixture
        .search(
            Principal::Reserved {
                module_id: "prefrontal-core".to_string(),
            },
            json!({"query": "ungranted query"}),
        )
        .await;
    assert_eq!(code(&refused), "web_search_not_granted");
    let invoked = fixture
        .send(
            Principal::Direct,
            json!({"name": manifest::INVOKE_TOOL, "arguments": {
                "op": "call", "connection": CONNECTION, "action": "search",
                "args": {"query": "via invoke"}
            }}),
        )
        .await;
    assert_eq!(invoked["result"]["transmission"], "completed", "{invoked}");

    let audit = fixture.audit();
    let (web_search, other): (Vec<_>, Vec<_>) = audit
        .iter()
        .partition(|row| row.gate.as_deref() == Some("web_search"));
    assert_eq!(web_search.len(), 2, "{audit:?}");
    assert_eq!(web_search[0].query_text.as_deref(), Some("audited query"));
    assert_eq!(web_search[0].result_count, Some(2));
    assert_eq!(web_search[1].query_text.as_deref(), Some("ungranted query"));
    assert_eq!(
        web_search[1].result_count, None,
        "a refusal returned nothing"
    );
    assert!(
        other.len() >= 4,
        "the engine's decision and dispatch rows for both calls: {audit:?}"
    );
    for row in other {
        assert_eq!(row.query_text, None, "{row:?}");
        assert_eq!(row.result_count, None, "{row:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_limit_admin_op_dry_runs_then_applies_with_one_audit_row() {
    let fixture = Fixture::new("admin-limit");
    let params = json!({
        "backend": "exa",
        "per_caller_per_minute": 2,
        "per_backend_per_minute": 9,
    });
    let ceremony_rows = |fixture: &Fixture| {
        fixture
            .audit()
            .iter()
            .filter(|row| row.reason_code == "ceremony_set_web_search_limit")
            .count()
    };
    let op = manifest::ADMIN_SET_WEB_SEARCH_LIMIT_OP;

    let dry = fixture
        .send(Principal::Direct, json!({"method": op, "params": params}))
        .await;
    assert_eq!(dry["result"]["outcome"], "would_set", "{dry}");
    assert_eq!(dry["result"]["current_source"], "default");
    assert_eq!(
        dry["result"]["current"],
        json!({"per_caller_per_minute": 30, "per_backend_per_minute": 120})
    );
    assert_eq!(fixture.store.web_search_limits("exa").unwrap(), None);
    assert_eq!(ceremony_rows(&fixture), 0);

    let mut apply = params.clone();
    apply["dry_run"] = json!(false);
    let applied = fixture
        .send(Principal::Direct, json!({"method": op, "params": apply}))
        .await;
    assert_eq!(applied["result"]["outcome"], "set", "{applied}");
    assert_eq!(
        fixture.store.web_search_limits("exa").unwrap(),
        Some(WebSearchLimits {
            per_caller_per_minute: 2,
            per_backend_per_minute: 9,
        })
    );
    assert_eq!(ceremony_rows(&fixture), 1);

    for _ in 0..2 {
        let reply = fixture
            .search(Principal::Direct, json!({"query": "tight"}))
            .await;
        assert!(reply.get("result").is_some(), "{reply}");
    }
    let limited = fixture
        .search(Principal::Direct, json!({"query": "tight"}))
        .await;
    assert_eq!(
        code(&limited),
        "rate_limited",
        "the stored limit applies at once"
    );

    let module = fixture
        .send(aft(), json!({"method": op, "params": apply}))
        .await;
    assert_eq!(code(&module), "operator_authority_required", "{module}");
    let mut unknown = apply.clone();
    unknown["backend"] = json!("bing");
    let unknown = fixture
        .send(Principal::Direct, json!({"method": op, "params": unknown}))
        .await;
    assert_eq!(code(&unknown), "unknown_backend", "{unknown}");
    assert_eq!(ceremony_rows(&fixture), 1);
}

// `call_key` is checked by the generic tool-request decode, before any tool's
// handler. It is exercised through `web_search` because this fixture can tell
// whether a call was dispatched: every dispatched search reaches the mock
// transport and writes a web_search audit row.

/// A call whose `call_key` fails the protocol's shape check is refused as
/// `invalid_request` naming the field, and never reaches the tool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_call_key_is_refused_by_field_before_dispatch() {
    let fixture = Fixture::new("call-key-malformed");
    for (label, key) in [
        ("contains a space", json!("run-7 call-3")),
        ("257 characters", json!("k".repeat(257))),
        ("non-ASCII", json!("run-7:cäll")),
        ("empty", json!("")),
        ("not a string", json!(7)),
    ] {
        let reply = fixture
            .send(
                Principal::Direct,
                json!({
                    "name": manifest::WEB_SEARCH_TOOL,
                    "arguments": {"query": "keyed"},
                    "call_key": key,
                }),
            )
            .await;
        assert_eq!(code(&reply), "invalid_request", "{label}: {reply}");
        assert_eq!(reply["error"]["field"], "call_key", "{label}: {reply}");
    }
    assert_eq!(
        fixture.requests(),
        0,
        "a refused call must not be dispatched"
    );
    assert!(fixture.web_search_rows().is_empty());
}

/// A well-formed key, including one of exactly 256 characters, is accepted
/// and the call runs as it would without one; so does a call with no key or
/// an explicit `null`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_valid_or_absent_call_key_dispatches_as_before() {
    let fixture = Fixture::new("call-key-valid");
    let mut dispatched = 0;
    for key in [
        Some(json!("run-7:call-3")),
        Some(json!("k".repeat(256))),
        Some(Value::Null),
        None,
    ] {
        // A distinct query each time, so no reply can come from the cache.
        let mut request = json!({
            "name": manifest::WEB_SEARCH_TOOL,
            "arguments": {"query": format!("keyed {dispatched}")},
        });
        if let Some(key) = &key {
            request["call_key"] = key.clone();
        }
        let reply = fixture.send(Principal::Direct, request).await;
        assert!(reply.get("result").is_some(), "{key:?}: {reply}");
        dispatched += 1;
        assert_eq!(fixture.requests(), dispatched, "{key:?}");
    }
}

// ---------------------------------------------------------------------------
// Routes bound under a daemon scope. The in-process subc-daemon the
// conformance harness runs cannot open a scoped route: `scope.sync` is taken
// only from a module whose launch nonce is the supervisor's recorded spawn
// nonce, and the harness supervises no scope owner. So these tests hand the
// tool handler a route whose bind carried a constructed stamp, exactly what a
// scoped `route.bind` records.
// ---------------------------------------------------------------------------

/// A stamp for a head scope owned by Prefrontal, naming `agent`.
fn stamp(
    agent: Option<&str>,
    delegates: bool,
    owner_authorized: bool,
) -> subc_protocol::scope::ScopeStamp {
    subc_protocol::scope::ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".to_string(),
        },
        "head-7",
        4,
        subc_protocol::scope::ScopeKind::Head,
    )
    .with_attributes(
        subc_protocol::scope::ScopeAttributes::new()
            .with_agent_id(agent.map(str::to_owned))
            .with_delegates(delegates),
    )
    .with_owner_authorized(owner_authorized)
}

/// The scope columns of every audit row, in journal order.
#[derive(Debug, PartialEq)]
struct ScopeColumns {
    gate: Option<String>,
    agent_id: Option<String>,
    scope_owner: Option<String>,
    scope_ref: Option<String>,
    scope_epoch: Option<i64>,
    scope_kind: Option<String>,
    scope_delegates: Option<bool>,
    scope_owner_authorized: Option<bool>,
    scope_flow_id: Option<String>,
}

impl Fixture {
    async fn send_scoped(
        &self,
        principal: Principal,
        scope: subc_protocol::scope::ScopeStamp,
        body: Value,
    ) -> Value {
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            41,
            1,
            7,
            serde_json::to_vec(&body).expect("serialize request"),
        )
        .expect("build request frame");
        let (writer, mut responses) = mpsc::channel(1);
        handle_scoped_tool_request_for_test(frame, &writer, self.runtime(), principal, Some(scope))
            .await
            .expect("handle request");
        serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "response frame",
            )
            .await
            .body,
        )
        .expect("response JSON")
    }

    async fn invoke_search_scoped(
        &self,
        scope: subc_protocol::scope::ScopeStamp,
        extra: Value,
    ) -> Value {
        self.invoke_search_scoped_as(aft(), scope, extra).await
    }

    async fn invoke_search_scoped_as(
        &self,
        carrier: Principal,
        scope: subc_protocol::scope::ScopeStamp,
        extra: Value,
    ) -> Value {
        let mut arguments = json!({
            "op": "call", "connection": CONNECTION, "action": "search", "args": {"query": "q"}
        });
        if let Value::Object(extra) = extra {
            arguments.as_object_mut().expect("object").extend(extra);
        }
        self.send_scoped(
            carrier,
            scope,
            json!({"name": manifest::INVOKE_TOOL, "arguments": arguments}),
        )
        .await
    }

    fn scope_columns(&self) -> Vec<ScopeColumns> {
        let db = Connection::open(self.path.as_ref() as &Path).expect("open store file");
        let mut statement = db
            .prepare(
                "SELECT gate, agent_id, scope_owner, scope_ref, scope_epoch, scope_kind,
                        scope_delegates, scope_owner_authorized, scope_flow_id
                 FROM audit_journal ORDER BY journal_id",
            )
            .expect("prepare audit read");
        let rows = statement
            .query_map([], |row| {
                Ok(ScopeColumns {
                    gate: row.get(0)?,
                    agent_id: row.get(1)?,
                    scope_owner: row.get(2)?,
                    scope_ref: row.get(3)?,
                    scope_epoch: row.get(4)?,
                    scope_kind: row.get(5)?,
                    scope_delegates: row.get(6)?,
                    scope_owner_authorized: row.get(7)?,
                    scope_flow_id: row.get(8)?,
                })
            })
            .expect("read audit");
        rows.collect::<Result<_, _>>().expect("audit rows")
    }
}

/// Under a delegating scope whose owner is authorized, an ordinary invoke is
/// judged as the scope's agent: the carrier's module grant alone is refused
/// `agent_grant_absent` before anything is sent, and the agent's own grant
/// lets the same call through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delegating_stamp_needs_the_agents_grant_to_invoke() {
    let fixture = Fixture::new("scope-delegating");
    let refused = fixture
        .invoke_search_scoped(stamp(Some(AGENT), true, true), json!({}))
        .await;
    assert_eq!(code(&refused), "agent_grant_absent", "{refused}");
    assert_eq!(
        fixture.requests(),
        0,
        "nothing was sent without the agent grant"
    );

    fixture.agent_grant(&aft(), AGENT);
    let allowed = fixture
        .invoke_search_scoped(stamp(Some(AGENT), true, true), json!({}))
        .await;
    assert_eq!(allowed["result"]["transmission"], "completed", "{allowed}");
    assert_eq!(fixture.requests(), 1);
}

/// A delegating stamp whose carrier holds no module grant is refused on the
/// module layer by name, even when the agent's own grant exists: an agent
/// grant never substitutes for the module grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delegating_stamp_without_the_module_grant_refuses_module_grant_absent() {
    let fixture = Fixture::new("scope-no-module-grant");
    fixture.agent_grant(&aft(), AGENT);
    let db = Connection::open(fixture.path.as_ref() as &Path).expect("open store file");
    db.execute("DELETE FROM grants WHERE grant_id = 'grant-aft'", [])
        .expect("drop the carrier's module grant");
    let refused = fixture
        .invoke_search_scoped(stamp(Some(AGENT), true, true), json!({}))
        .await;
    assert_eq!(code(&refused), "module_grant_absent", "{refused}");
    assert_eq!(fixture.requests(), 0);
}

/// A stamp that does not delegate, or whose owner is not authorized to set
/// agent attributes, gives module-level authority only: the call runs on the
/// carrier's module grant with no agent grant, and the stamp's agent is
/// recorded on the audit rows for attribution.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_delegating_stamp_invokes_on_the_module_grant_with_its_agent_attributed() {
    for (label, scope) in [
        ("not-delegating", stamp(Some(AGENT), false, true)),
        ("owner-unauthorized", stamp(Some(AGENT), true, false)),
    ] {
        let fixture = Fixture::new(&format!("scope-{label}"));
        let reply = fixture.invoke_search_scoped(scope, json!({})).await;
        assert_eq!(
            reply["result"]["transmission"], "completed",
            "{label}: {reply}"
        );
        assert_eq!(fixture.requests(), 1, "{label}");
        let rows = fixture.scope_columns();
        assert!(!rows.is_empty(), "{label}");
        assert!(
            rows.iter()
                .all(|row| row.agent_id.as_deref() == Some(AGENT)),
            "{label}: every row attributes the stamp's agent: {rows:?}"
        );
    }
}

fn flow_stamp() -> subc_protocol::scope::ScopeStamp {
    let mut scope = stamp(Some(AGENT), false, true);
    scope.attributes.flow_id = Some("flow-governance".into());
    scope
}

fn carrier_calls() -> [Value; 2] {
    [
        json!({"name": manifest::WEB_SEARCH_TOOL, "arguments": {"query": "q"}}),
        json!({"name": manifest::INVOKE_TOOL, "arguments": {
            "op": "call", "connection": CONNECTION, "action": "search", "args": {"query": "q"}
        }}),
    ]
}

async fn assert_flow_carrier_refused(module_id: &str) {
    for body in carrier_calls() {
        let fixture = Fixture::new(&format!("flow-carrier-{module_id}"));
        let carrier = Principal::Reserved {
            module_id: module_id.into(),
        };
        // Grant access so this refusal proves the carrier gate blocks even a
        // module that would otherwise be authorized to dispatch.
        fixture.grant("grant-carrier", CONNECTION, &carrier);
        let reply = fixture.send_scoped(carrier, flow_stamp(), body).await;
        assert_eq!(code(&reply), "flow_carrier_not_admitted", "{reply}");
        assert_eq!(reply["error"]["carrier"], format!("reserved:{module_id}"));
        assert_eq!(reply["error"]["transmission"], "not_sent");
        assert_eq!(fixture.requests(), 0);
        assert_eq!(fixture.reservations(), 0);
        assert!(fixture
            .store
            .list_action_requests("direct")
            .unwrap()
            .is_empty());
        // The shared pre-handler gate refuses before dispatch without writing
        // an audit row, matching the facade's unsupported-preset gate.
        assert!(fixture.audit().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_carrier_non_basal_refuses_before_dispatch_or_parking() {
    assert_flow_carrier_refused("prefrontal-core").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_carrier_resemblances_are_not_admitted() {
    for module_id in ["basal-x", "basalx"] {
        assert_flow_carrier_refused(module_id).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_carrier_basal_proceeds_to_governance() {
    for body in carrier_calls() {
        let fixture = Fixture::new("flow-carrier-basal");
        let reply = fixture.send_scoped(basal(), flow_stamp(), body).await;
        assert_ne!(code(&reply), "flow_carrier_not_admitted", "{reply}");
        assert!(reply.get("result").is_some(), "{reply}");
        assert_eq!(fixture.requests(), 1);
    }
}

/// Basal's module grants exist for flows. A Basal call with no flow stamp,
/// whether unscoped or on a session scope without `flow_id`, would use them
/// outside the flow rules, so it is refused before anything is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_carrier_without_a_flow_scope_is_refused() {
    for body in carrier_calls() {
        let fixture = Fixture::new("flow-carrier-unscoped");
        let unscoped = fixture.send(basal(), body.clone()).await;
        let scoped = fixture
            .send_scoped(basal(), stamp(Some(AGENT), true, true), body)
            .await;
        for reply in [&unscoped, &scoped] {
            assert_eq!(code(reply), "flow_scope_required", "{reply}");
            assert_eq!(reply["error"]["carrier"], "reserved:basal");
            assert_eq!(reply["error"]["transmission"], "not_sent");
        }
        assert_eq!(fixture.requests(), 0);
        assert_eq!(fixture.reservations(), 0);
        assert!(fixture.audit().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_carrier_gate_does_not_affect_non_flow_calls() {
    let carrier = Principal::Reserved {
        module_id: "prefrontal-core".into(),
    };
    for body in carrier_calls() {
        let fixture = Fixture::new("flow-carrier-non-flow");
        fixture.grant("grant-carrier", CONNECTION, &carrier);
        fixture.agent_grant(&carrier, AGENT);
        let scoped = fixture
            .send_scoped(
                carrier.clone(),
                stamp(Some(AGENT), true, true),
                body.clone(),
            )
            .await;
        assert_ne!(code(&scoped), "flow_carrier_not_admitted", "{scoped}");
        assert!(scoped.get("result").is_some(), "{scoped}");
        let unscoped = fixture.send(carrier.clone(), body).await;
        assert_ne!(code(&unscoped), "flow_carrier_not_admitted", "{unscoped}");
        assert!(unscoped.get("result").is_some(), "{unscoped}");
        assert!(fixture.requests() > 0);
    }
}

fn flow_policy(fixture: &Fixture, effect: &str) {
    fixture
        .store
        .insert_policy(&plexus_core::PolicyInput {
            policy_id: "flow-policy".into(),
            principal: "direct".into(),
            connection_id: CONNECTION.into(),
            action_selector: "search".into(),
            effect: effect.into(),
            expires_at: None,
        })
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_ask_first_refuses_consent_without_parking_an_approval() {
    let fixture = Fixture::new("flow-ask");
    flow_policy(&fixture, "ask_first");
    let reply = fixture
        .invoke_search_scoped_as(basal(), flow_stamp(), json!({}))
        .await;
    assert_eq!(code(&reply), "consent_unavailable", "{reply}");
    assert_eq!(reply["error"]["action"], "search");
    assert_eq!(reply["error"]["transmission"], "not_sent");
    assert!(
        fixture
            .store
            .list_action_requests("direct")
            .unwrap()
            .is_empty(),
        "consent_unavailable must precede parking: {reply}"
    );
    assert_eq!(fixture.requests(), 0);
    let audit = fixture.store.list_audit("direct").unwrap();
    assert_eq!(audit.last().unwrap().reason_code, "consent_unavailable");
    assert_eq!(
        audit
            .last()
            .unwrap()
            .scope
            .as_ref()
            .unwrap()
            .flow_id
            .as_deref(),
        Some("flow-governance")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_consent_refusal_creates_no_reservation_row() {
    let fixture = Fixture::new("flow-no-reservation");
    flow_policy(&fixture, "ask_first");
    let _reply = fixture
        .invoke_search_scoped_as(basal(), flow_stamp(), json!({}))
        .await;
    assert_eq!(
        fixture.reservations(),
        0,
        "consent refusal must precede reservation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_allow_still_dispatches_and_block_still_blocks() {
    let fixture = Fixture::new("flow-allow");
    flow_policy(&fixture, "allow");
    let reply = fixture
        .invoke_search_scoped_as(basal(), flow_stamp(), json!({}))
        .await;
    assert_eq!(reply["result"]["transmission"], "completed", "{reply}");
    assert_eq!(fixture.requests(), 1);
    let blocked = Fixture::new("flow-block");
    flow_policy(&blocked, "block");
    let reply = blocked
        .invoke_search_scoped_as(basal(), flow_stamp(), json!({}))
        .await;
    assert_eq!(code(&reply), "policy_blocked", "{reply}");
    assert_eq!(blocked.requests(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_web_search_ask_first_refuses_cache_hits_and_misses_without_parking() {
    for cached in [false, true] {
        let fixture = Fixture::new(if cached { "flow-cache" } else { "flow-miss" });
        let body = json!({"name": manifest::WEB_SEARCH_TOOL, "arguments":{"query":"q"}});
        if cached {
            let reply = fixture
                .send_scoped(basal(), flow_stamp(), body.clone())
                .await;
            assert!(reply.get("result").is_some(), "{reply}");
        }
        flow_policy(&fixture, "ask_first");
        let reply = fixture.send_scoped(basal(), flow_stamp(), body).await;
        assert_eq!(code(&reply), "policy_ask_first", "{reply}");
        assert!(
            reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains("cannot be approved per call"),
            "{reply}"
        );
        assert!(fixture
            .store
            .list_action_requests("direct")
            .unwrap()
            .is_empty());
        assert_eq!(fixture.requests(), usize::from(cached));
    }
}

/// Both rows of a governed call made under a scope (the authorization
/// decision and the dispatch result) carry the scope, with the stamp's own
/// values; a call on an unscoped route leaves every scope column NULL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_audit_rows_of_a_stamped_call_carry_its_scope() {
    let fixture = Fixture::new("scope-audit");
    let mut scope = stamp(Some(AGENT), false, true);
    scope.attributes.flow_id = Some("flow-audit".into());
    let reply = fixture
        .invoke_search_scoped_as(basal(), scope, json!({}))
        .await;
    assert_eq!(reply["result"]["transmission"], "completed", "{reply}");
    let rows = fixture.scope_columns();
    let gates: Vec<_> = rows.iter().map(|row| row.gate.clone()).collect();
    assert_eq!(
        gates,
        vec![Some("credential".to_string()), Some("dispatch".to_string())],
        "one authorization row and one dispatch row: {rows:?}"
    );
    for row in &rows {
        assert_eq!(row.scope_flow_id.as_deref(), Some("flow-audit"));
        assert_eq!(
            (
                row.scope_owner.as_deref(),
                row.scope_ref.as_deref(),
                row.scope_epoch,
                row.scope_kind.as_deref(),
                row.scope_delegates,
                row.scope_owner_authorized,
            ),
            (
                Some("reserved:prefrontal-core"),
                Some("head-7"),
                Some(4),
                Some("head"),
                Some(false),
                Some(true)
            ),
            "{row:?}"
        );
    }

    let unscoped = Fixture::new("scope-audit-unscoped");
    let reply = unscoped.invoke_search(json!({"query": "q"})).await;
    assert_eq!(reply["result"]["transmission"], "completed", "{reply}");
    assert!(unscoped
        .scope_columns()
        .iter()
        .all(|row| row.scope_owner.is_none()
            && row.scope_ref.is_none()
            && row.scope_epoch.is_none()
            && row.scope_delegates.is_none()
            && row.scope_flow_id.is_none()));
}

/// Removed identity fields must never be ignored or reach a vendor, even on
/// a stamped route and even when their value is null or secret-shaped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_token_arguments_are_undeclared_before_dispatch() {
    let fixture = Fixture::new("retired-identity-fields");
    let invoke_args = json!({"op":"call", "connection":CONNECTION, "action":"search",
        "args":{"query":"stamp only"}});
    for (tool, arguments) in [
        (manifest::INVOKE_TOOL, invoke_args.clone()),
        (
            manifest::GITHUB_TOOL,
            json!({"op":"bot_request", "request_nonce":"old-client",
            "request":{"action":"issue comment", "repository":"org/repo",
                "target":{"number":"42"}, "body":{"body":"hello"}}}),
        ),
        (manifest::WEB_SEARCH_TOOL, json!({"query":"stamp only"})),
        (manifest::CODE_SEARCH_TOOL, json!({"query":"stamp only"})),
        (manifest::CONNECTIONS_TOOL, json!({"op":"list"})),
    ] {
        for field in ["assertion", "agent_assertion"] {
            for value in [
                Value::Null,
                json!({}),
                json!({"token":{"signature_hex":"retired"}}),
                json!({"api_key":"do-not-send"}),
            ] {
                let mut arguments = arguments.clone();
                arguments[field] = value;
                let reply = fixture
                    .send_scoped(
                        aft(),
                        stamp(Some(AGENT), false, true),
                        json!({"name":tool, "arguments":arguments}),
                    )
                    .await;
                assert_eq!(
                    reply["errorCode"]
                        .as_str()
                        .or_else(|| reply["error"]["code"].as_str())
                        .unwrap_or(""),
                    "argument_undeclared",
                    "retired token argument must be refused: {tool}/{field}: {reply}"
                );
                if tool == manifest::CODE_SEARCH_TOOL {
                    assert!(
                        reply["content"][0]["text"]
                            .as_str()
                            .unwrap()
                            .contains(&format!("field: {field}")),
                        "{reply}"
                    );
                } else {
                    assert_eq!(reply["error"]["field"], field);
                    assert_eq!(reply["error"]["transmission"], "not_sent");
                }
                assert_eq!(fixture.requests(), 0);
                assert_eq!(fixture.reservations(), 0);
            }
        }
    }
    assert!(
        fixture.audit().is_empty(),
        "no handler ran for a retired argument"
    );
    let control = fixture
        .send_scoped(
            aft(),
            stamp(Some(AGENT), false, true),
            json!({"name":manifest::INVOKE_TOOL, "arguments":invoke_args}),
        )
        .await;
    assert_eq!(control["result"]["transmission"], "completed", "{control}");
    assert_eq!(fixture.requests(), 1, "the token-free control dispatches");
}

/// Search is not an action taken as the agent, so a delegating stamp adds no
/// agent-grant requirement: the carrier's module grant alone authorizes it,
/// and the stamp's agent is attribution (and the rate key) on the rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delegating_stamp_adds_no_agent_grant_requirement_to_web_search() {
    let fixture = Fixture::new("scope-web-search");
    let reply = fixture
        .send_scoped(
            aft(),
            stamp(Some(AGENT), true, true),
            json!({"name": manifest::WEB_SEARCH_TOOL, "arguments": {"query": "scoped search"}}),
        )
        .await;
    assert_eq!(reply["result"]["cached"], false, "{reply}");
    assert_eq!(fixture.requests(), 1);
    let rows = fixture.scope_columns();
    let search_row = rows
        .iter()
        .find(|row| row.gate.as_deref() == Some("web_search"))
        .expect("the web_search row");
    assert_eq!(search_row.agent_id.as_deref(), Some(AGENT));
    assert_eq!(search_row.scope_ref.as_deref(), Some("head-7"));
    assert!(
        rows.iter()
            .all(|row| row.scope_ref.as_deref() == Some("head-7")),
        "every row of the search carries the scope: {rows:?}"
    );
}

// Every facade tool reply also carries the MCP `CallToolResult` fields
// (`content`, `isError`, `structuredContent`) beside its unchanged `result` or
// `error` member, because model-facing callers read only those fields. These
// tests live here because `Fixture::send` drives any request body, a
// `web_search` call, another facade tool or a management operation, through
// the module's own `handle_tool_request`, against a store holding a live Exa
// connection.

/// The keys a facade reply adds, which management replies must not carry.
const CALL_TOOL_RESULT_KEYS: [&str; 3] = ["content", "isError", "structuredContent"];

/// The reply's single `content` text block.
fn content_text(reply: &Value) -> &str {
    let content = reply["content"].as_array().expect("content array");
    assert_eq!(content.len(), 1, "{reply}");
    assert_eq!(content[0]["type"], "text", "{reply}");
    content[0]["text"].as_str().expect("content text")
}

/// The reply's top-level keys, sorted.
fn keys(reply: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = reply
        .as_object()
        .expect("reply object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_web_search_success_carries_a_listing_and_its_result_as_structured_content() {
    let fixture = Fixture::new("mcp-search");
    let reply = fixture
        .search(Principal::Direct, json!({"query": "mcp listing"}))
        .await;
    assert_eq!(
        keys(&reply),
        ["content", "isError", "result", "structuredContent"],
        "{reply}"
    );
    assert_eq!(reply["isError"], false, "{reply}");
    assert_eq!(reply["structuredContent"], reply["result"]);
    let text = content_text(&reply);
    let results = reply["result"]["results"].as_array().expect("results");
    assert_eq!(results.len(), 2, "{reply}");
    for item in results {
        for field in ["title", "url"] {
            let value = item[field].as_str().expect(field);
            assert!(text.contains(value), "{field} {value} missing from {text}");
        }
    }
    assert!(
        text.contains("Published 2023-11-16") && !text.contains("T01:36:32.547Z"),
        "{text}"
    );
    assert!(
        text.contains("Such requirements have limited their adoption..."),
        "{text}"
    );
    assert!(
        !text.contains("cache"),
        "a fresh search is not cached: {text}"
    );

    let hit = fixture
        .search(Principal::Direct, json!({"query": "mcp listing"}))
        .await;
    assert_eq!(hit["result"]["cached"], true, "{hit}");
    assert!(
        content_text(&hit).starts_with("2 web results (cached):"),
        "{hit}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rate_limited_web_search_is_an_error_naming_the_code_and_the_retry_delay() {
    let fixture = Fixture::new("mcp-limited");
    fixture
        .store
        .set_web_search_limits(
            "exa",
            WebSearchLimits {
                per_caller_per_minute: 1,
                per_backend_per_minute: 120,
            },
        )
        .expect("set limits");
    let first = fixture
        .search(Principal::Direct, json!({"query": "once"}))
        .await;
    assert_eq!(first["isError"], false, "{first}");
    let refused = fixture
        .search(Principal::Direct, json!({"query": "once"}))
        .await;
    assert_eq!(code(&refused), "rate_limited", "{refused}");
    assert_eq!(
        keys(&refused),
        ["content", "error", "errorCode", "isError"],
        "{refused}"
    );
    assert_eq!(refused["errorCode"], "rate_limited");
    assert_eq!(refused["isError"], true, "{refused}");
    let retry_after_ms = refused["error"]["retry_after_ms"]
        .as_u64()
        .expect("retry_after_ms");
    assert!(retry_after_ms > 0);
    let wait = crate::web_search_wait_words(retry_after_ms);
    assert_eq!(
        content_text(&refused),
        format!("web_search was refused (rate_limited): the web search rate limit is reached. Retry in {wait} (retry_after_ms {retry_after_ms}).")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_naming_a_field_says_which_in_its_text() {
    let fixture = Fixture::new("mcp-field");
    let refused = fixture
        .search(Principal::Direct, json!({"query": ""}))
        .await;
    assert_eq!(code(&refused), "invalid_query", "{refused}");
    assert_eq!(refused["isError"], true, "{refused}");
    let field = refused["error"]["field"].as_str().expect("field");
    assert_eq!(
        content_text(&refused),
        format!("web_search was refused (invalid_query): the `{field}` argument is not valid. Correct it and search again.")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_facade_tool_success_carries_its_whole_reply_as_pretty_json() {
    let fixture = Fixture::new("mcp-catalog");
    let reply = fixture
        .send(
            Principal::Direct,
            json!({"name": manifest::CATALOG_TOOL, "arguments": {"op": "list", "connection": CONNECTION}}),
        )
        .await;
    assert!(reply["result"]["actions"].is_array(), "{reply}");
    assert_eq!(
        keys(&reply),
        ["content", "isError", "result", "structuredContent"],
        "{reply}"
    );
    assert_eq!(reply["isError"], false, "{reply}");
    assert_eq!(reply["structuredContent"], reply["result"]);
    assert_eq!(
        content_text(&reply),
        serde_json::to_string_pretty(&json!({"result": reply["result"]})).expect("render reply")
    );
}

/// AFT's gh-shim relay (`facade_reply` in aft's gh_shim_relay/mod.rs) unwraps
/// a JSON `content[0].text` as the complete facade reply and then reads
/// `result.status` and `repo_binding_generation` from it. When this text held
/// only `result`, the shim found no `result.status` and reported a failure for
/// a bot comment that had posted. This decodes a bot_request-shaped reply the
/// same way and requires the unwrapped value to equal the original reply.
#[test]
fn a_relay_that_unwraps_the_text_block_gets_the_original_reply_back() {
    let original = json!({
        "result": {"status": "completed", "result": {"url": "https://github.com/o/r/issues/1#c1", "id": 7}},
        "repo_binding_generation": 42
    });
    let reply = crate::with_call_tool_result(Some(manifest::GITHUB_TOOL), original.clone());
    let unwrapped = reply["content"]
        .as_array()
        .and_then(|blocks| blocks.iter().find_map(|block| block["text"].as_str()))
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .expect("the text block is JSON");
    assert_eq!(unwrapped, original);
    assert_eq!(unwrapped["result"]["status"], "completed");
    assert_eq!(unwrapped["repo_binding_generation"], 42);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_replies_carry_no_call_tool_result_fields() {
    let fixture = Fixture::new("mcp-management");
    let op = manifest::ADMIN_SET_WEB_SEARCH_LIMIT_OP;
    let params = json!({"backend": "exa", "per_caller_per_minute": 2, "per_backend_per_minute": 9});
    let dry = fixture
        .send(Principal::Direct, json!({"method": op, "params": params}))
        .await;
    assert_eq!(dry["result"]["outcome"], "would_set", "{dry}");
    assert_eq!(keys(&dry), ["result"], "{dry}");
    let refused = fixture
        .send(aft(), json!({"method": op, "params": params}))
        .await;
    assert_eq!(code(&refused), "operator_authority_required", "{refused}");
    assert_eq!(keys(&refused), ["error"], "{refused}");
    for key in CALL_TOOL_RESULT_KEYS {
        assert!(dry.get(key).is_none() && refused.get(key).is_none());
    }
}

/// Removing the added keys gives back exactly the body the handler built, so
/// `result` and `error` reach existing readers unchanged in value.
#[test]
fn the_added_fields_leave_result_and_error_unchanged() {
    let bodies = [
        (
            Some(manifest::WEB_SEARCH_TOOL),
            json!({"result": {"results": [], "backend": "exa", "cached": false}}),
        ),
        (
            Some(manifest::CONNECTIONS_TOOL),
            json!({"result": {"connections": [{"connection_id": "c", "status": "active"}]}}),
        ),
        (
            Some(manifest::EVENTS_GET_TOOL),
            json!({"result": {"body": "{}", "digest": "d", "event_key": "0".repeat(64), "event_name": "github_issue_changed", "repo": "owner/repo", "published_at": 1}}),
        ),
        (
            Some(manifest::GITHUB_TOOL),
            json!({"result": ["an", "array", "result"]}),
        ),
        (
            Some(manifest::INVOKE_TOOL),
            json!({"error": {"code": "invalid_operation", "message": "m", "example": {"op": "call"}}}),
        ),
        (
            None,
            json!({"error": {"code": "invalid_request", "message": "tool request requires a string name"}}),
        ),
    ];
    for (tool, body) in bodies {
        let mut reply = with_call_tool_result(tool, body.clone());
        let fields = reply.as_object_mut().expect("reply object");
        assert!(fields.contains_key("content") && fields.contains_key("isError"));
        for key in CALL_TOOL_RESULT_KEYS {
            fields.remove(key);
        }
        assert_eq!(reply, body);
    }
    let array = with_call_tool_result(
        Some(manifest::GITHUB_TOOL),
        json!({"result": ["an", "array"]}),
    );
    assert!(
        array.get("structuredContent").is_none(),
        "MCP structured content is an object, so a non-object result is text only: {array}"
    );
    assert_eq!(
        content_text(&with_call_tool_result(
            None,
            json!({"error": {"code": "invalid_request"}})
        )),
        "invalid_request"
    );
}

// A relayed call's top-level `origin` names the call it came from. It is
// checked beside `call_key`, before any tool's handler, and recorded for
// attribution only. The pinned vectors are in `tests/fixtures/fetch-plan-v1/`;
// see the README there for why the recording calls swap the tool and why the
// `web_search` vector's own assertion is refused.

/// A well-formed origin carried by `reserved:broca`, with a valid key.
fn broca_origin() -> Value {
    json!({"carrier": {"kind": "reserved", "module_id": "broca"}, "call_key": "lin_7f3a9c2e:42"})
}

impl Fixture {
    /// `(gate, origin_carrier, origin_call_key)` of every audit row, oldest
    /// first.
    #[allow(clippy::type_complexity)]
    fn origin_rows(&self) -> Vec<(Option<String>, Option<String>, Option<String>)> {
        let db = Connection::open(self.path.as_ref() as &Path).expect("open store file");
        let mut statement = db
            .prepare(
                "SELECT gate, origin_carrier, origin_call_key
                 FROM audit_journal ORDER BY journal_id",
            )
            .expect("prepare audit read");
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("read audit");
        rows.collect::<Result<_, _>>().expect("audit rows")
    }

    /// Assert `body` is refused as `invalid_request` naming `field`, that the
    /// reply never repeats `hidden`, and that nothing was sent or audited.
    async fn assert_refused(&self, label: &str, body: Value, field: &str, hidden: &str) {
        let reply = self.send(aft(), body).await;
        assert_eq!(code(&reply), "invalid_request", "{label}: {reply}");
        assert_eq!(reply["error"]["field"], field, "{label}: {reply}");
        assert!(
            hidden.is_empty() || !reply.to_string().contains(hidden),
            "{label}: the refusal must not echo the value: {reply}"
        );
        assert_eq!(self.requests(), 0, "{label}: a refused call is not sent");
        assert!(
            self.audit().is_empty(),
            "{label}: a refused call is not audited"
        );
    }
}

/// Every relayed-call vector, with its envelope kept and the tool swapped for
/// Plexus tools, records the vector's origin verbatim on every audit row the
/// call writes: the `web_search` rows, both rows of an `invoke`, and the rows
/// of a held `invoke` and of its later approved send. The OpenCode plugin
/// vector states no origin and records NULL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relayed_calls_record_their_origin_on_every_audit_row() {
    for (label, vector) in crate::relay_vectors::RELAYED {
        let vector = crate::relay_vectors::parse(vector);
        let expected = crate::relay_vectors::recorded_origin(&vector);
        assert_eq!(expected.is_some(), label != "opencode-plugin", "{label}");
        let mut fixture = Fixture::new(&format!("relayed-audit-{label}"));
        let scope = crate::consent_test_support::worker_stamp("relay-worker", 1);
        fixture.consent = Some((
            crate::consent_test_support::pending_cards(),
            plexus_core::scope::CallScope::from_stamp(&scope),
        ));
        let invoke = |query: &str| {
            crate::relay_vectors::relayed_as(
                &vector,
                manifest::INVOKE_TOOL,
                json!({"op": "call", "connection": CONNECTION, "action": "search",
                       "args": {"query": query}}),
            )
        };

        let searched = fixture
            .send(
                aft(),
                crate::relay_vectors::relayed_as(
                    &vector,
                    manifest::WEB_SEARCH_TOOL,
                    json!({"query": "relayed"}),
                ),
            )
            .await;
        assert_eq!(searched["result"]["cached"], false, "{label}: {searched}");

        let invoked = fixture.send(aft(), invoke("open")).await;
        assert_eq!(
            invoked["result"]["transmission"], "completed",
            "{label}: {invoked}"
        );

        // Hold the next call for approval, then approve it as the owner.
        Connection::open(fixture.path.as_ref() as &Path)
            .expect("open store file")
            .execute(
                "UPDATE catalog_actions SET ask_first = 1 WHERE connection_id = ?1",
                [CONNECTION],
            )
            .expect("make search ask first");
        let held = fixture.send_scoped(aft(), scope, invoke("held")).await;
        assert_eq!(
            held["structuredContent"]["code"], "access_pending",
            "{label}: {held}"
        );
        let request_id = fixture
            .store
            .list_action_requests("direct")
            .expect("list requests")
            .into_iter()
            .next()
            .expect("the call parked a request")
            .request_id;
        fixture
            .store
            .insert_grant(&GrantInput {
                grant_id: "grant-admin".to_string(),
                principal: "direct".to_string(),
                connection_id: CONNECTION.to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["*".to_string()],
                authority_kind: "connection_admin".to_string(),
                expires_at: None,
            })
            .expect("insert admin grant");
        let approved = fixture
            .send(
                Principal::Direct,
                json!({"name": manifest::REQUESTS_TOOL, "arguments": {
                    "op": "approve", "request_id": request_id
                }}),
            )
            .await;
        assert_eq!(
            approved["result"]["transmission"], "completed",
            "{label}: {approved}"
        );

        let rows = fixture.origin_rows();
        let gates: Vec<_> = rows.iter().map(|row| row.0.as_deref()).collect();
        assert_eq!(
            gates
                .iter()
                .filter(|gate| **gate == Some("dispatch"))
                .count(),
            3,
            "{label}: the search, the open invoke and the approved send each dispatched: {gates:?}"
        );
        assert!(gates.contains(&Some("web_search")), "{label}: {gates:?}");
        assert!(rows.len() >= 7, "{label}: {gates:?}");
        for (gate, carrier, call_key) in &rows {
            assert_eq!(
                carrier.clone().zip(call_key.clone()),
                expected,
                "{label}: audit row {gate:?}"
            );
            assert_eq!(carrier.is_some(), call_key.is_some(), "{label}: {gate:?}");
        }
    }
}

/// Sent verbatim, every vector that names a tool Plexus does not serve ends at
/// the unknown-tool check as `unknown_method`. That check comes after `origin`
/// is validated, so for the vectors that state an origin, whose carrier is a
/// principal object, reaching it proves the origin was accepted as written.
/// Nothing is sent or audited.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_verbatim_relayed_vector_passes_its_origin_and_reaches_the_tool_check() {
    let fixture = Fixture::new("relayed-verbatim");
    let mut with_origin = 0;
    for (label, source) in crate::relay_vectors::RELAYED {
        let vector = crate::relay_vectors::parse(source);
        if vector.get("origin").is_some() {
            assert!(
                vector["origin"]["carrier"].is_object(),
                "{label}: the vector writes its carrier as a principal object"
            );
            with_origin += 1;
        }
        let reply = fixture.send(aft(), vector).await;
        assert_eq!(code(&reply), "unknown_method", "{label}: {reply}");
    }
    assert_eq!(
        with_origin, 2,
        "the Broca and bridge vectors state an origin"
    );
    assert_eq!(fixture.requests(), 0);
    assert!(fixture.audit().is_empty());
}

/// The principal Plexus sees as the caller (the carrier) when Prefrontal core
/// relays a call to it.
fn prefrontal_core() -> Principal {
    Principal::Reserved {
        module_id: "prefrontal-core".to_string(),
    }
}

/// The relayed web-search vector is accepted from Prefrontal core under its
/// daemon stamp. Forwarded arguments are unchanged and no origin is invented.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relayed_web_search_vector_is_searched_under_its_stamp_without_origin() {
    let fixture = Fixture::new("relayed-web-search-signed");
    fixture.grant("grant-core", CONNECTION, &prefrontal_core());
    let vector = crate::relay_vectors::parse(crate::relay_vectors::WEB_SEARCH_FROM_OPENCODE_PLUGIN);

    let reply = fixture
        .send_scoped(prefrontal_core(), stamp(Some(AGENT), false, true), vector)
        .await;
    assert_eq!(reply["result"]["cached"], false, "{reply}");
    let requests = fixture.transport.requests();
    assert_eq!(requests.len(), 1);
    let sent = &requests[0].args;
    assert_eq!(sent["query"], "RFC 8785 canonical JSON", "{sent}");
    assert_eq!(sent["numResults"], 5, "{sent}");
    assert_eq!(sent["includeDomains"], json!(["rfc-editor.org"]), "{sent}");
    assert!(
        sent["startPublishedDate"].is_string(),
        "recency sets a start date: {sent}"
    );

    let rows = fixture.origin_rows();
    assert!(
        rows.iter().any(|row| row.0.as_deref() == Some("dispatch")),
        "the search dispatched: {rows:?}"
    );
    assert!(
        rows.iter()
            .any(|row| row.0.as_deref() == Some("web_search")),
        "{rows:?}"
    );
    for (gate, carrier, call_key) in &rows {
        assert_eq!(
            (carrier, call_key),
            (&None, &None),
            "audit row {gate:?} records no origin"
        );
    }
    assert_eq!(
        fixture.web_search_rows()[0].agent_id.as_deref(),
        Some(AGENT)
    );
}

/// An `origin` that is not an object of exactly a principal `carrier` and a
/// `call_key` is refused as `invalid_request` naming the faulty field, without
/// repeating the value, and never reaches the tool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_origin_is_refused_by_field_before_dispatch() {
    let fixture = Fixture::new("origin-malformed");
    let reserved = |module_id: String| json!({"kind": "reserved", "module_id": module_id});
    for (label, origin, field) in [
        ("a string", json!("SENTINEL"), "origin"),
        ("an array", json!(["SENTINEL"]), "origin"),
        (
            "an extra member",
            json!({"carrier": reserved("broca".into()), "call_key": "k", "SENTINEL": 1}),
            "origin",
        ),
        ("no carrier", json!({"call_key": "k"}), "origin.carrier"),
        (
            "a display-string carrier",
            json!({"carrier": "reserved:SENTINEL", "call_key": "k"}),
            "origin.carrier",
        ),
        (
            "an unknown principal kind",
            json!({"carrier": {"kind": "SENTINEL"}, "call_key": "k"}),
            "origin.carrier",
        ),
        (
            "a carrier with a space",
            json!({"carrier": reserved("SENTINEL x".into()), "call_key": "k"}),
            "origin.carrier",
        ),
        (
            "a carrier over 256 bytes",
            json!({"carrier": reserved(format!("SENTINEL{}", "m".repeat(250))), "call_key": "k"}),
            "origin.carrier",
        ),
        (
            "a message position that is not an object",
            json!({"carrier": reserved("broca".into()), "call_key": "k", "message_position": "SENTINEL"}),
            "origin.message_position.message_id",
        ),
        (
            "a message position with a bad message id",
            json!({"carrier": reserved("broca".into()), "call_key": "k",
                "message_position": {"message_id": "SENTINEL x", "index": 0}}),
            "origin.message_position.message_id",
        ),
        (
            "a message position with a negative index",
            json!({"carrier": reserved("broca".into()), "call_key": "k",
                "message_position": {"message_id": "msg_SENTINEL", "index": -1}}),
            "origin.message_position.message_id",
        ),
    ] {
        fixture
            .assert_refused(
                label,
                json!({
                    "name": manifest::WEB_SEARCH_TOOL,
                    "arguments": {"query": "relayed"},
                    "call_key": "pf:1",
                    "origin": origin,
                }),
                field,
                "SENTINEL",
            )
            .await;
    }
}

/// The protocol's optional `origin.message_position` is accepted and ignored,
/// so a forwarder can send one origin shape to every module: the call runs and
/// its audit rows record the same carrier and key as without it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_origin_message_position_is_accepted_and_ignored() {
    let fixture = Fixture::new("origin-message-position");
    let reply = fixture
        .send(
            aft(),
            json!({
                "name": manifest::WEB_SEARCH_TOOL,
                "arguments": {"query": "relayed"},
                "call_key": "pf:1",
                "origin": {
                    "carrier": {"kind": "reserved", "module_id": "broca"},
                    "call_key": "lin_7f3a9c2e",
                    "message_position": {"message_id": "msg_01AbC", "index": 2},
                },
            }),
        )
        .await;
    assert!(
        reply.get("error").is_none(),
        "a message position must not refuse the call: {reply}"
    );
    assert_eq!(fixture.requests(), 1, "{reply}");
    assert!(
        fixture
            .origin_rows()
            .iter()
            .any(
                |(_, carrier, key)| carrier.as_deref() == Some("reserved:broca")
                    && key.as_deref() == Some("lin_7f3a9c2e")
            ),
        "origin is still recorded: {:?}",
        fixture.origin_rows()
    );
}

/// `origin.call_key` must pass the protocol's call-key validator: each key
/// the pinned vectors say `validate_call_key` refuses, and any non-string or
/// missing key, is refused naming `origin.call_key`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_origin_call_key_is_refused_by_field() {
    let fixture = Fixture::new("origin-call-key-malformed");
    let keys = crate::relay_vectors::parse(crate::relay_vectors::PF_CALL_KEYS);
    let mut cases: Vec<(String, Option<Value>)> = keys["invalid"]
        .as_array()
        .expect("invalid keys")
        .iter()
        .filter(|case| case["refused_by"] == "validate_call_key")
        .map(|case| {
            (
                case["name"].as_str().expect("name").to_string(),
                Some(case["call_key"].clone()),
            )
        })
        .collect();
    assert_eq!(cases.len(), 3, "the vectors pin three validator refusals");
    cases.extend([
        ("empty".to_string(), Some(json!(""))),
        ("non-ASCII".to_string(), Some(json!("lin:cäll"))),
        ("not a string".to_string(), Some(json!(7))),
        ("missing".to_string(), None),
    ]);
    for (label, call_key) in cases {
        let mut origin = json!({"carrier": {"kind": "reserved", "module_id": "broca"}});
        if let Some(call_key) = &call_key {
            origin["call_key"] = call_key.clone();
        }
        let hidden = call_key
            .as_ref()
            .and_then(Value::as_str)
            .filter(|key| key.len() > 4)
            .unwrap_or("");
        fixture
            .assert_refused(
                &label,
                json!({
                    "name": manifest::WEB_SEARCH_TOOL,
                    "arguments": {"query": "relayed"},
                    "call_key": "pf:1",
                    "origin": origin,
                }),
                "origin.call_key",
                hidden,
            )
            .await;
    }
}

/// Every `valid` key in `pf-call-keys.json`, plus its empty record id `pf:`,
/// is accepted as `origin.call_key` under each principal kind as the carrier
/// (reserved, direct, unverified). `pf:` belongs here because only
/// Prefrontal's own record-id rule refuses it; the protocol's
/// `validate_call_key`, which is the check Plexus applies, accepts it. Each
/// call names `browser_use`, which Plexus does not serve, so an accepted call
/// ends at the unknown-tool check as `unknown_method`. That check comes after
/// `origin` is validated, so reaching it proves `origin` was accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_valid_call_keys_are_accepted_as_origin_call_key() {
    let fixture = Fixture::new("origin-call-key-valid");
    let keys = crate::relay_vectors::parse(crate::relay_vectors::PF_CALL_KEYS);
    let accepted = keys["valid"]
        .as_array()
        .expect("valid keys")
        .iter()
        .chain(
            keys["invalid"]
                .as_array()
                .expect("invalid keys")
                .iter()
                .filter(|case| case["refused_by"] == "record_id_rule"),
        )
        .map(|case| case["call_key"].clone());
    let carriers = [
        json!({"kind": "reserved", "module_id": "broca"}),
        json!({"kind": "direct"}),
        json!({"kind": "unverified"}),
    ];
    for call_key in accepted {
        for carrier in &carriers {
            let reply = fixture
                .send(
                    aft(),
                    json!({
                        "name": "browser_use",
                        "arguments": {},
                        "call_key": "pf:1",
                        "origin": {"carrier": carrier, "call_key": call_key},
                    }),
                )
                .await;
            assert_eq!(
                code(&reply),
                "unknown_method",
                "{carrier} {call_key}: {reply}"
            );
        }
    }
}

/// An `origin` on a call with no top-level `call_key` (absent or `null`) is
/// refused as `invalid_request` naming `origin`, without echoing the origin's
/// key, and the tool never runs. A relay always sends the calls it relays
/// under its own top-level `call_key`, so an `origin` without one cannot have
/// come from a relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_origin_without_a_top_level_call_key_is_refused() {
    let fixture = Fixture::new("origin-unkeyed");
    let mut absent = json!({
        "name": manifest::WEB_SEARCH_TOOL,
        "arguments": {"query": "relayed"},
        "origin": broca_origin(),
    });
    fixture
        .assert_refused("absent call_key", absent.clone(), "origin", "lin_7f3a9c2e")
        .await;
    absent[CALL_KEY_FIELD] = Value::Null;
    fixture
        .assert_refused("null call_key", absent, "origin", "lin_7f3a9c2e")
        .await;
}

/// `origin` is read only as a top-level member of a call, never as a tool
/// argument. The `search` action's schema that `invoke` checks `args` against
/// (pinned here to the schema shipped in `catalog/exa_rest.jsonc`, whose top
/// level is closed) declares no `origin`, so `origin` inside `args` is refused
/// as `argument_undeclared`. `web_search`'s arguments
/// have no `origin` field either, so `origin` there is refused naming
/// `origin`. Either way no request is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_origin_inside_arguments_is_still_an_undeclared_argument() {
    let fixture = Fixture::new("origin-in-arguments");
    fixture.pin_shipped_search_schema();
    let invoked = fixture
        .send(
            aft(),
            json!({"name": manifest::INVOKE_TOOL, "arguments": {
                "op": "call", "connection": CONNECTION, "action": "search",
                "args": {"query": "relayed", "origin": broca_origin()}
            }, "call_key": "pf:1"}),
        )
        .await;
    assert_eq!(code(&invoked), "argument_undeclared", "{invoked}");
    assert_eq!(invoked["error"]["field"], "origin", "{invoked}");
    let searched = fixture
        .send(
            aft(),
            json!({"name": manifest::WEB_SEARCH_TOOL, "arguments": {
                "query": "relayed", "origin": broca_origin()
            }, "call_key": "pf:1"}),
        )
        .await;
    assert_eq!(searched["error"]["field"], "origin", "{searched}");
    assert_eq!(fixture.requests(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unserved_presets_refuse_by_name_before_dispatch_or_audit() {
    for preset in [
        json!("mason"),
        json!("work"),
        json!("a0_-z9"),
        json!("a".repeat(64)),
        json!(""),
        json!("a".repeat(65)),
        json!("Upper"),
        json!("bad.name"),
        json!(7),
        Value::Null,
    ] {
        let fixture = Fixture::new("preset-refusal");
        let reply = fixture
            .send(
                aft(),
                json!({"name":manifest::INVOKE_TOOL,
            "preset":preset, "arguments":{"op":"call", "connection":CONNECTION,
                "action":"search", "args":{"query":"q"}}}),
            )
            .await;
        assert_eq!(code(&reply), "invalid_request", "{preset}: {reply}");
        assert_eq!(reply["error"]["field"], "preset");
        assert_eq!(reply["error"]["preset"], preset);
        assert!(reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown or malformed plexus preset"));
        assert_eq!(fixture.requests(), 0);
        assert_eq!(fixture.reservations(), 0);
        assert!(fixture.store.list_audit("direct").unwrap().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_preset_explicitly_selects_the_existing_facade() {
    let fixture = Fixture::new("preset-absent");
    let reply = fixture.invoke_search(json!({"query":"q"})).await;
    assert_eq!(reply["result"]["transmission"], "completed", "{reply}");
    assert_eq!(fixture.requests(), 1);
}

fn owned_flow_stamp() -> subc_protocol::scope::ScopeStamp {
    let mut scope = flow_stamp();
    scope.attributes.delegates = true;
    scope
}
fn query_params(items: Value) -> Value {
    json!({"method":"grants.would_ask","params":{"agent_id":AGENT,"flow_id":"flow-governance","items":items}})
}
fn check_detail(detail: &Value, layer: &str, connection: Value, action: &str, cause: &str) {
    assert!(
        detail["grant"].as_str().unwrap().starts_with("g1."),
        "{detail}"
    );
    assert!(!detail["grant_label"].as_str().unwrap().is_empty());
    assert_eq!(detail["layer"], layer);
    assert_eq!(detail["connection"], connection);
    assert_eq!(detail["action"], action);
    assert_eq!(detail["cause"], cause);
}
impl Fixture {
    fn sql(&self, sql: &str) {
        Connection::open(self.path.as_ref() as &Path)
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
    async fn flow_query(&self, items: Value) -> Value {
        self.send_scoped(basal(), owned_flow_stamp(), query_params(items))
            .await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_flow_invoke_module_refusal_restores_end_to_end() {
    let fixture = Fixture::new("typed-invoke-module");
    fixture.agent_grant(&basal(), AGENT);
    fixture.sql("DELETE FROM grants WHERE grant_id='grant-basal'");
    let first = fixture
        .invoke_search_scoped_as(basal(), owned_flow_stamp(), json!({}))
        .await;
    let second = fixture
        .invoke_search_scoped_as(basal(), owned_flow_stamp(), json!({}))
        .await;
    assert_eq!(code(&first), "module_grant_absent", "{first}");
    check_detail(
        &first["error"]["detail"],
        "module",
        json!(CONNECTION),
        "search",
        "missing",
    );
    assert_eq!(
        first["error"]["detail"]["grant"],
        second["error"]["detail"]["grant"]
    );
    let text: Value = serde_json::from_str(first["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text["error"]["detail"], first["error"]["detail"]);
    assert_eq!(first["isError"], true, "a refusal must set isError");
    let item = json!({"grant":first["error"]["detail"]["grant"]});
    let before = fixture.flow_query(json!([item])).await;
    assert_eq!(before["result"]["items"][0]["verdict"], "no", "{before}");
    assert_eq!(
        before["result"]["items"][0]["detail"],
        first["error"]["detail"]
    );
    fixture.grant("restored-basal", CONNECTION, &basal());
    let after = fixture.flow_query(json!([item])).await;
    assert_eq!(after["result"]["items"][0]["verdict"], "yes", "{after}");
    assert_eq!(after["result"]["items"][0]["grant"], item["grant"]);
    assert_eq!(fixture.requests(), 0);
    assert_eq!(fixture.reservations(), 0);
    assert!(fixture
        .store
        .list_action_requests("direct")
        .unwrap()
        .is_empty());
    let dispatched = fixture
        .invoke_search_scoped_as(basal(), owned_flow_stamp(), json!({}))
        .await;
    assert_eq!(
        dispatched["result"]["transmission"], "completed",
        "{dispatched}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_flow_invoke_agent_refusal_and_query_agree() {
    let fixture = Fixture::new("typed-invoke-agent");
    let denied = fixture
        .invoke_search_scoped_as(basal(), owned_flow_stamp(), json!({}))
        .await;
    assert_eq!(code(&denied), "agent_grant_absent", "{denied}");
    check_detail(
        &denied["error"]["detail"],
        "agent",
        json!(CONNECTION),
        "search",
        "missing",
    );
    let query = fixture
        .flow_query(json!([{"grant":denied["error"]["detail"]["grant"]}]))
        .await;
    assert_eq!(
        query["result"]["items"][0]["detail"],
        denied["error"]["detail"]
    );
    fixture.agent_grant(&basal(), AGENT);
    let query = fixture
        .flow_query(json!([{"tool":"invoke","connection":CONNECTION,"action":"search"}]))
        .await;
    assert_eq!(query["result"]["items"][0]["verdict"], "yes", "{query}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_flow_invoke_invisible_existing_connection_differs_from_absent() {
    let fixture = Fixture::new("typed-invisible");
    fixture.sql("DELETE FROM grants WHERE grant_id='grant-basal'");
    let existing = fixture
        .invoke_search_scoped_as(basal(), owned_flow_stamp(), json!({}))
        .await;
    assert_eq!(code(&existing), "module_grant_absent", "{existing}");
    check_detail(
        &existing["error"]["detail"],
        "module",
        json!(CONNECTION),
        "search",
        "missing",
    );
    let absent = fixture
        .invoke_search_scoped_as(
            basal(),
            owned_flow_stamp(),
            json!({"connection":"does-not-exist"}),
        )
        .await;
    assert_eq!(code(&absent), "connection_not_found", "{absent}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_non_flow_invoke_keeps_grant_missing() {
    let fixture = Fixture::new("typed-legacy");
    fixture.sql("DELETE FROM grants WHERE grant_id='grant-direct'");
    let denied = fixture
        .send(Principal::Direct, carrier_calls()[1].clone())
        .await;
    assert_eq!(code(&denied), "grant_missing", "{denied}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_flow_web_search_capability_ref_restores_without_agent_grant() {
    let fixture = Fixture::new("typed-search");
    fixture.sql("DELETE FROM grants WHERE grant_id='grant-basal'");
    let denied = fixture
        .send_scoped(basal(), owned_flow_stamp(), carrier_calls()[0].clone())
        .await;
    assert_eq!(code(&denied), "module_grant_absent", "{denied}");
    check_detail(
        &denied["error"]["detail"],
        "module",
        Value::Null,
        "search",
        "missing",
    );
    assert_eq!(
        denied["error"]["detail"]["grant_label"],
        "web search (module grant for reserved:basal)"
    );
    let item = json!({"grant":denied["error"]["detail"]["grant"]});
    let before = fixture.flow_query(json!([item])).await;
    assert_eq!(
        before["result"]["items"][0]["detail"],
        denied["error"]["detail"]
    );
    fixture.grant("restored-basal", CONNECTION, &basal());
    let after = fixture.flow_query(json!([item])).await;
    assert_eq!(after["result"]["items"][0]["verdict"], "yes", "{after}");
    assert_eq!(fixture.requests(), 0);
    assert_eq!(fixture.reservations(), 0);
    for _ in 0..2 {
        let allowed = fixture
            .send_scoped(basal(), owned_flow_stamp(), carrier_calls()[0].clone())
            .await;
        assert!(allowed.get("result").is_some(), "{allowed}");
    }
    assert_eq!(
        fixture.requests(),
        1,
        "the cache remains usable with no agent search grant"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_would_ask_policy_projection_matches_flow_without_reservations() {
    let fixture = Fixture::new("typed-policy");
    fixture.agent_grant(&basal(), AGENT);
    let item = json!({"tool":"invoke","connection":CONNECTION,"action":"search"});
    for (effect, verdict, reason, call_code) in [
        (
            "ask_first",
            "would_ask",
            "consent_unavailable",
            "consent_unavailable",
        ),
        ("block", "no", "policy_blocked", "policy_blocked"),
    ] {
        fixture.sql("DELETE FROM policies WHERE policy_id='flow-policy'");
        flow_policy(&fixture, effect);
        let before_rows = fixture.audit().len();
        let reply = fixture.flow_query(json!([item])).await;
        assert_eq!(reply["result"]["items"][0]["verdict"], verdict, "{reply}");
        assert_eq!(reply["result"]["items"][0]["reason"], reason);
        assert_eq!(
            fixture.audit().len(),
            before_rows + 1,
            "one audit row per query"
        );
        let denied = fixture
            .invoke_search_scoped_as(basal(), owned_flow_stamp(), json!({}))
            .await;
        assert_eq!(code(&denied), call_code, "{denied}");
        assert_eq!(fixture.reservations(), 0);
        assert_eq!(fixture.requests(), 0);
        assert!(fixture
            .store
            .list_action_requests("direct")
            .unwrap()
            .is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_would_ask_admission_scope_and_unknown_fields() {
    let fixture = Fixture::new("typed-admission");
    let request = query_params(json!([]));
    for principal in [
        Principal::Direct,
        aft(),
        Principal::Reserved {
            module_id: "basal-x".into(),
        },
    ] {
        let refused = fixture.send(principal, request.clone()).await;
        assert_eq!(code(&refused), "principal_denied", "{refused}");
    }
    let unscoped = fixture.send(basal(), request.clone()).await;
    assert_eq!(code(&unscoped), "flow_scope_required");
    let mut wrong = request.clone();
    wrong["params"]["agent_id"] = json!("agent-other");
    let reply = fixture
        .send_scoped(basal(), owned_flow_stamp(), wrong)
        .await;
    assert_eq!(code(&reply), "agent_identity_conflict");
    let mut wrong = request.clone();
    wrong["params"]["flow_id"] = json!("flow-other");
    let reply = fixture
        .send_scoped(basal(), owned_flow_stamp(), wrong)
        .await;
    assert_eq!(code(&reply), "flow_identity_conflict");
    for (location, field) in [
        ("top", "extra_top"),
        ("params", "extra_param"),
        ("item", "extra_item"),
    ] {
        let mut wrong = request.clone();
        match location {
            "top" => wrong[field] = json!(1),
            "params" => wrong["params"][field] = json!(1),
            _ => wrong["params"]["items"] = json!([{"grant":"invalid","extra_item":1}]),
        }
        let reply = fixture
            .send_scoped(basal(), owned_flow_stamp(), wrong)
            .await;
        assert_eq!(code(&reply), "invalid_request", "{reply}");
        assert_eq!(reply["error"]["field"], field);
        assert_eq!(reply["error"]["reason"], "unknown_field");
    }
    let other_method = fixture
        .send_scoped(
            basal(),
            owned_flow_stamp(),
            json!({"method":manifest::ADMIN_LIST_GRANTS_OP,"params":{}}),
        )
        .await;
    assert_eq!(code(&other_method), "operator_authority_required");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_would_ask_foreign_and_malformed_refs_are_invalid_targets() {
    use plexus_core::grant_refusal::{GrantTarget, Layer};
    let fixture = Fixture::new("typed-ref-targets");
    let foreign = GrantTarget::new(
        Layer::Agent,
        "agent-other",
        "invoke",
        Some(CONNECTION),
        "search",
    )
    .reference();
    let reply = fixture.flow_query(json!([{"grant":foreign},{"grant":"not-a-ref"},{"tool":"not-a-tool","action":"search"}])).await;
    for item in reply["result"]["items"].as_array().unwrap() {
        assert_eq!(item["verdict"], "no");
        assert_eq!(item["reason"], "invalid_target");
    }
}

/// A store failure while deciding an item is reported as store_failure, not
/// as an invalid target: the target is fine, the read failed. The verdict
/// stays a fail-closed "no".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_would_ask_reports_a_store_failure_by_name() {
    let fixture = Fixture::new("typed-store-failure");
    // Remove the agent identity so the flow needs only the module's grant.
    // The fixture's `grant-basal` permits `basal` to invoke `search` on this
    // connection. That grant lets the query reach the policy read, which fails
    // because the test renames the policies table.
    let mut scope = flow_stamp();
    scope.attributes.agent_id = None;
    fixture.sql("ALTER TABLE policies RENAME TO policies_unavailable;");
    let body = json!({"method":"grants.would_ask","params":{"flow_id":"flow-governance",
        "items":[{"tool":"invoke","connection":CONNECTION,"action":"search"}]}});
    let reply = fixture.send_scoped(basal(), scope, body).await;
    let item = &reply["result"]["items"][0];
    assert_eq!(item["verdict"], "no", "{reply}");
    assert_eq!(
        item["reason"], "store_failure",
        "a store failure must be named: {reply}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_would_ask_global_flow_matches_module_only_call() {
    let fixture = Fixture::new("typed-global");
    let mut scope = flow_stamp();
    scope.attributes.agent_id = None;
    let body = json!({"method":"grants.would_ask","params":{"flow_id":"flow-governance","items":[{"tool":"invoke","connection":CONNECTION,"action":"search"}]}});
    let query = fixture
        .send_scoped(basal(), scope.clone(), body.clone())
        .await;
    assert_eq!(query["result"]["items"][0]["verdict"], "yes", "{query}");
    let query = fixture
        .send(
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            body,
        )
        .await;
    assert_eq!(query["result"]["items"][0]["verdict"], "yes", "{query}");
    let allowed = fixture
        .invoke_search_scoped_as(basal(), scope, json!({}))
        .await;
    assert_eq!(allowed["result"]["transmission"], "completed", "{allowed}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_flow_grant_causes_keep_the_failed_layer() {
    for (change, layer, cause) in [("UPDATE grants SET expires_at=1 WHERE grant_id='grant-basal'", "module", "expired"), ("UPDATE grants SET action_selectors='[\"other\"]' WHERE grant_id='grant-basal'", "module", "action_selector"), ("UPDATE grants SET risk_ceiling='read' WHERE grant_id='grant-agent'; UPDATE catalog_actions SET risk='write'", "agent", "risk_ceiling")] {
        let fixture = Fixture::new(&format!("typed-cause-{layer}-{cause}")); fixture.agent_grant(&basal(), AGENT);
        if cause == "risk_ceiling" { fixture.sql("UPDATE grants SET risk_ceiling='write' WHERE grant_id='grant-basal'"); }
        fixture.sql(change);
        let denied = fixture.invoke_search_scoped_as(basal(), owned_flow_stamp(), json!({})).await;
        assert_eq!(code(&denied), format!("{layer}_grant_absent"), "{denied}");
        check_detail(&denied["error"]["detail"], layer, json!(CONNECTION), "search", cause);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_flow_github_bot_write_missing_layers_have_full_detail() {
    let fixture = Fixture::new("typed-github");
    fixture.sql("INSERT INTO github_app_handle(app_handle_id,agent_id,app_id,credential_reference,status,proven_at,connection_principal,connection_id) VALUES ('test-bot','agent_ws',1,'github_app:test-bot','enabled',1,'direct','conn-exa'); INSERT INTO github_repo_binding(repository,app_handle_id) VALUES ('cortexkit/basal','test-bot'); UPDATE catalog_actions SET name='create_issue'; UPDATE grants SET action_selectors='[\"create_issue\"]',risk_ceiling='write'; DELETE FROM grants WHERE grant_id='grant-basal';");
    let body = json!({"name":"github","arguments":{"op":"bot_request","request_nonce":"typed-bot","request":{"action":"issue create","repository":"cortexkit/basal","title":"hello","body":{"body":"body"}}}});
    let denied = fixture
        .send_scoped(basal(), owned_flow_stamp(), body.clone())
        .await;
    assert_eq!(
        denied["result"]["refusal_code"], "module_grant_absent",
        "{denied}"
    );
    check_detail(
        &denied["result"]["detail"],
        "module",
        json!(CONNECTION),
        "create_issue",
        "missing",
    );
    let envelope: Value =
        serde_json::from_str(denied["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["result"]["detail"], denied["result"]["detail"]);
    fixture.sql("INSERT INTO grants(grant_id,principal,connection_id,grantee_principal,risk_ceiling,authority_kind,created_at_ms,action_selectors) VALUES ('bot-basal','direct','conn-exa','reserved:basal','write','invoke',1,'[\"create_issue\"]');");
    let denied = fixture.send_scoped(basal(), owned_flow_stamp(), body).await;
    assert_eq!(
        denied["result"]["refusal_code"], "agent_grant_absent",
        "{denied}"
    );
    check_detail(
        &denied["result"]["detail"],
        "agent",
        json!(CONNECTION),
        "create_issue",
        "missing",
    );
    let before = fixture
        .flow_query(json!([{"grant":denied["result"]["detail"]["grant"]}]))
        .await;
    assert_eq!(
        before["result"]["items"][0]["detail"],
        denied["result"]["detail"]
    );
    fixture.agent_grant(&basal(), AGENT);
    fixture.sql("UPDATE grants SET action_selectors='[\"create_issue\"]',risk_ceiling='write' WHERE grant_id='grant-agent'");
    let after = fixture
        .flow_query(json!([{"grant":denied["result"]["detail"]["grant"]}]))
        .await;
    assert_eq!(after["result"]["items"][0]["verdict"], "yes", "{after}");
    assert_eq!(fixture.requests(), 0);
    assert_eq!(fixture.reservations(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_flow_cannot_decide_approvals_even_with_admin_grant() {
    let fixture = Fixture::new("typed-approval");
    fixture.sql("INSERT INTO grants(grant_id,principal,connection_id,grantee_principal,risk_ceiling,authority_kind,created_at_ms,action_selectors) VALUES ('basal-admin','direct','conn-exa','reserved:basal','write','connection_admin',1,'[\"*\"]');");
    for op in ["approve", "deny"] {
        let reply = fixture
            .send_scoped(
                basal(),
                owned_flow_stamp(),
                json!({"name":"requests","arguments":{"op":op,"request_id":"anything"}}),
            )
            .await;
        assert_eq!(code(&reply), "call_mode_unsupported", "{reply}");
        assert_eq!(
            reply["error"]["detail"],
            json!({"tool":"requests","mode":"flow"})
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_bind_preserves_carrier_scope_consent_and_both_grant_layers() {
    let args = json!({"op":"call","connection":CONNECTION,"action":"search","args":{"query":"q"}});
    for (label, carrier, scope, module_grant, agent_grant, policy, expected) in [
        (
            "carrier",
            aft(),
            Some(flow_stamp()),
            true,
            true,
            "allow",
            "flow_carrier_not_admitted",
        ),
        (
            "scope",
            basal(),
            None,
            true,
            true,
            "allow",
            "flow_scope_required",
        ),
        (
            "module",
            basal(),
            Some(stamp(Some(AGENT), true, true)),
            false,
            true,
            "allow",
            "module_grant_absent",
        ),
        (
            "agent",
            basal(),
            Some(stamp(Some(AGENT), true, true)),
            true,
            false,
            "allow",
            "agent_grant_absent",
        ),
        (
            "consent",
            basal(),
            Some(flow_stamp()),
            true,
            false,
            "ask_first",
            "consent_unavailable",
        ),
        (
            "allowed",
            basal(),
            Some(stamp(Some(AGENT), true, true)),
            true,
            true,
            "allow",
            "",
        ),
    ] {
        let fixture = Fixture::new(&format!("flow-bind-{label}"));
        if !module_grant {
            fixture.sql("DELETE FROM grants WHERE grant_id='grant-basal'");
        }
        if agent_grant {
            fixture.agent_grant(&basal(), AGENT);
        }
        flow_policy(&fixture, policy);
        let scope = scope.map(|mut scope| {
            scope.attributes.flow_id = Some("flow-bind".into());
            scope
        });
        let reply = crate::call_mode_tests::bound_call(
            fixture.runtime(),
            carrier,
            scope,
            Some(CallMode::Flow),
            manifest::INVOKE_TOOL,
            args.clone(),
        )
        .await;
        if expected.is_empty() {
            assert!(reply.get("result").is_some(), "{label}: {reply}");
            assert_eq!(fixture.requests(), 1);
        } else {
            assert_eq!(code(&reply), expected, "{label}: {reply}");
            assert_eq!(fixture.requests(), 0);
            assert_eq!(fixture.reservations(), 0);
        }
        assert!(fixture
            .store
            .list_action_requests("direct")
            .unwrap()
            .is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delegated_codemode_search_uses_only_module_rights_and_keeps_agent_attribution() {
    let fixture = Fixture::new("codemode-search");
    let mut scope = stamp(Some(AGENT), true, true);
    scope.attributes.run_id = Some("run-search".into());
    let args = json!({"query":"codemode attribution"});
    let reply = crate::call_mode_tests::bound_call(
        fixture.runtime(),
        aft(),
        Some(scope.clone()),
        Some(CallMode::Codemode),
        manifest::WEB_SEARCH_TOOL,
        args.clone(),
    )
    .await;
    assert!(
        reply.get("result").is_some(),
        "a run needs no agent grant for search: {reply}"
    );
    assert_eq!(fixture.requests(), 1);
    let rows = fixture.audit();
    assert!(rows
        .iter()
        .all(|row| row.agent_id.as_deref() == Some(AGENT)));
    assert!(fixture.store.revoke_grant("direct", "grant-aft").unwrap());
    fixture.agent_grant(&aft(), AGENT);
    let denied = crate::call_mode_tests::bound_call(
        fixture.runtime(),
        aft(),
        Some(scope),
        Some(CallMode::Codemode),
        manifest::WEB_SEARCH_TOOL,
        args,
    )
    .await;
    assert_eq!(
        code(&denied),
        "web_search_not_granted",
        "run delegation cannot replace module authority: {denied}"
    );
    assert_eq!(fixture.requests(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ask_first_search_refuses_without_card_or_vendor_contact() {
    let mut f = Fixture::new("ask-first-no-card");
    let spy = Arc::new(crate::consent_test_support::SearchCardSpy::default());
    let scope = crate::consent_test_support::worker_stamp("search-worker", 1);
    f.consent = Some((
        spy.cards(),
        plexus_core::scope::CallScope::from_stamp(&scope),
    ));
    let cached_query =
        json!({"name":manifest::WEB_SEARCH_TOOL,"arguments":{"query":"hiking trails in France"}});
    let warm = f
        .send_scoped(aft(), scope.clone(), cached_query.clone())
        .await;
    assert_eq!(warm["isError"], false, "{warm}");
    let sent = f.requests();
    f.store
        .set_policy("direct", CONNECTION, "search", "ask_first", None)
        .unwrap();
    let cold = f.send_scoped(aft(), scope.clone(), json!({"name":manifest::WEB_SEARCH_TOOL,"arguments":{"query":"a different hiking question"}})).await;
    assert_eq!(spy.calls(), 0, "search must never contact Cingulate");
    assert!(
        f.store.list_action_requests("direct").unwrap().is_empty(),
        "search must never file an approval row"
    );
    assert_eq!(f.requests(), sent);
    assert_eq!(code(&cold), "policy_ask_first", "{cold}");
    let text = cold["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("cannot be approved per call"), "{cold}");
    assert!(text.contains("allow or block"), "{cold}");
    let cached = f.send_scoped(aft(), scope, cached_query).await;
    assert_eq!(code(&cached), "policy_ask_first", "{cached}");
    assert_eq!(spy.calls(), 0);
    assert_eq!(f.requests(), sent);
}
