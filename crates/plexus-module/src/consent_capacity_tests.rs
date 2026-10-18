//! Held consent calls retain admission while yielding scarce execution slots.
use super::*;
use plexus_core::consent_card::{
    ConsentCards, ElicitationCallError, ElicitationRoute, CONSENT_AWAIT, CONSENT_DETACH,
    CONSENT_GET, CONSENT_REPORT_EXECUTION, CONSENT_REQUEST,
};
use plexus_core::scope::{ScopeDescription, ScopeReadError, ScopeReader, ScopeStatus};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Condvar, Mutex,
};
use std::time::Duration;

#[derive(Default)]
struct Cards {
    records: Mutex<HashMap<String, Value>>,
    parking: AtomicBool,
    waiting: AtomicUsize,
    released: Mutex<bool>,
    answer: Condvar,
}
impl Cards {
    fn approve_all(&self) {
        *self.released.lock().unwrap() = true;
        self.answer.notify_all();
    }
}
impl ElicitationRoute for Cards {
    fn call_scoped(
        &self,
        _: &CallScope,
        operation: &str,
        params: Value,
        _: Duration,
    ) -> Result<Value, ElicitationCallError> {
        if operation == CONSENT_REQUEST {
            let id = format!("el_{}", params["requester_ref"].as_str().unwrap());
            let mut record = params;
            record["elicitation_id"] = json!(id);
            record["state"] = json!("pending");
            self.records.lock().unwrap().insert(id.clone(), record);
            return Ok(json!({"elicitation_id":id}));
        }
        let id = params["elicitation_id"].as_str().unwrap();
        if operation == CONSENT_AWAIT {
            if !self.parking.load(Ordering::SeqCst) {
                return Err(ElicitationCallError::NotSent);
            }
            self.waiting.fetch_add(1, Ordering::SeqCst);
            let released = self.released.lock().unwrap();
            let (released, timed) = self
                .answer
                // Only the test releases approval. The timeout is a deadlock
                // guard, not an automatic answer while fixture writes finish.
                .wait_timeout_while(released, Duration::from_secs(120), |done| !*done)
                .unwrap();
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            if timed.timed_out() && !*released {
                return Err(ElicitationCallError::NotSent);
            }
            let mut records = self.records.lock().unwrap();
            let record = records.get_mut(id).unwrap();
            record["state"] = json!("answered");
            record["answered_choice_id"] = json!(plexus_core::consent_card::OPTION_APPROVE);
            return Ok(record.clone());
        }
        let mut records = self.records.lock().unwrap();
        let record = records.get_mut(id).unwrap();
        match operation {
            CONSENT_GET | CONSENT_DETACH => Ok(record.clone()),
            CONSENT_REPORT_EXECUTION => {
                record["execution"] = params["execution"].clone();
                Ok(record.clone())
            }
            _ => Err(ElicitationCallError::Transport),
        }
    }
}
struct ReleaseOnDrop(Arc<Cards>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.approve_all();
    }
}

struct LiveScopes {
    held: CallScope,
    bot: CallScope,
    cards: Arc<Cards>,
    rechecks_after_answer: AtomicUsize,
}
impl ScopeReader for LiveScopes {
    fn describe(&self, _: &str, scope_ref: &str) -> Result<ScopeDescription, ScopeReadError> {
        if *self.cards.released.lock().unwrap() {
            self.rechecks_after_answer.fetch_add(1, Ordering::SeqCst);
        }
        let scope = if scope_ref == self.bot.scope_ref {
            &self.bot
        } else {
            &self.held
        };
        Ok(ScopeDescription {
            status: ScopeStatus::Live,
            owner_synced: true,
            owner_configured: true,
            live: Some(scope.clone()),
        })
    }
}
fn request(channel: u16, corr: u64, body: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        1,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}
fn held_body(index: usize) -> Value {
    json!({"name":"invoke", "call_key":format!("held-{index}"), "arguments":{
        "op":"call", "connection":"conn-held", "action":"search", "args":{"query":format!("held query {index}")}
    }})
}
async fn wait_until(label: &str, mut ready: impl FnMut() -> bool) {
    // Filling 32 consent slots includes serialized durable writes. This is a
    // fixture rendezvous, not the execution-capacity property checked below.
    tokio::time::timeout(Duration::from_secs(60), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{label}"));
}

fn seed_bot(fixture: &crate::withdraw_tests::Fixture) {
    use plexus_core::storage::github_store::GithubHandle;
    let store = &fixture.store;
    store
        .insert_connection("operator", "conn-bot", "github_rest", "active", &json!({}))
        .unwrap();
    store
        .put_github_handle(&GithubHandle {
            app_handle_id: "app-bot".into(),
            agent_id: "agent-bot".into(),
            app_id: 1,
            installation_id: None,
            credential_reference: "github_app:app-bot".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: Some(1),
            connection_principal: "operator".into(),
            connection_id: "conn-bot".into(),
        })
        .unwrap();
    store.bind_github_repo("org/repo", "app-bot").unwrap();
    let db = rusqlite::Connection::open(fixture.path.path()).unwrap();
    db.execute("INSERT INTO catalog_actions (connection_id,principal,name,schema_json,schema_hash,risk,severity,status,first_seen_at_ms,last_seen_at_ms,ask_first)
        VALUES ('conn-bot','operator','add_reaction','{}','schema','write','S1','active',1,1,0)", []).unwrap();
    let manifest = crate::github_read_frame_tests::github_manifest();
    db.execute("INSERT INTO app_manifests (principal,key,schema_version,content_hash,manifest_json,ingested_at_ms)
        VALUES ('system','github_rest',1,'fixture',?1,1)", [serde_json::to_string(&manifest.manifest).unwrap()]).unwrap();
    for (id, agent) in [("bot-module", None), ("bot-agent", Some("agent-bot"))] {
        db.execute("INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,authority_kind,created_at_ms,action_selectors,agent_id)
            VALUES (?1,'operator','conn-bot','reserved:aft','write','invoke',1,'[\"add_reaction\"]',?2)", rusqlite::params![id, agent]).unwrap();
    }
}
struct BotToken;
impl plexus_core::github::credential::HandleCredentialProvider for BotToken {
    fn prepare(
        &self,
        _: &str,
        _: i64,
        _: &str,
    ) -> Result<plexus_core::ResolvedCredential, &'static str> {
        Ok(plexus_core::ResolvedCredential::anonymous())
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

async fn parked_calls_do_not_starve_work(recalled: bool) {
    use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
    let mut fixture = crate::withdraw_tests::Fixture::new(if recalled {
        "capacity-recalled"
    } else {
        "capacity-new"
    });
    let cards = Arc::new(Cards::default());
    let _release = ReleaseOnDrop(cards.clone());
    fixture.cards = Arc::new(ConsentCards::new(cards.clone()));
    // Keep the parked connector separate from the web-search backend so search
    // selects the immediate, granted Exa connection rather than asking again.
    let db = rusqlite::Connection::open(fixture.path.path()).unwrap();
    assert_eq!(
        db.execute(
            "UPDATE connections SET app_key='held_service' WHERE connection_id='conn-held'",
            []
        )
        .unwrap(),
        1
    );
    for key in ["exa_rest", "held_service"] {
        let source =
            subc_jsonc::jsonc_to_json(include_str!("../../../catalog/exa_rest.jsonc")).unwrap();
        let mut value: Value = serde_json::from_str(&source).unwrap();
        value["key"] = json!(key);
        let manifest = plexus_core::ingest_value(value).unwrap();
        db.execute("INSERT INTO app_manifests (principal,key,schema_version,content_hash,manifest_json,ingested_at_ms) VALUES ('system',?1,1,'fixture',?2,1)",
            rusqlite::params![key, serde_json::to_string(&manifest.manifest).unwrap()]).unwrap();
    }
    seed_bot(&fixture);
    let held_stamp = crate::consent_test_support::worker_stamp("worker-7", 4);
    let bot_stamp = ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        "bot-session",
        1,
        ScopeKind::Head,
    )
    .with_attributes(
        ScopeAttributes::new()
            .with_agent_id(Some("agent-bot".into()))
            .with_delegates(true),
    )
    .with_owner_authorized(true);
    let scopes = Arc::new(LiveScopes {
        held: CallScope::from_stamp(&held_stamp),
        bot: CallScope::from_stamp(&bot_stamp),
        cards: cards.clone(),
        rechecks_after_answer: AtomicUsize::new(0),
    });
    let mut runtime = fixture.runtime();
    runtime.engine = runtime
        .engine
        .with_scope_reader(scopes.clone())
        .with_governance_seams(Arc::new(
            plexus_core::storage::github_store::GithubGovernanceSeams {
                store: fixture.store.clone(),
                credential_provider: Some(Arc::new(BotToken)),
            },
        ));
    runtime.web_search = Arc::new(plexus_core::web_search::WebSearchService::exa());
    fixture
        .transport
        .set_response(plexus_core::MockResponse::Success(json!({"results":[]})));
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    });
    let routes = Arc::new(RouteBindings::new());
    routes
        .insert_scoped(
            1,
            1,
            Principal::Reserved {
                module_id: "aft".into(),
            },
            Some(scopes.held.clone()),
        )
        .unwrap();
    routes
        .insert(
            2,
            1,
            Principal::Reserved {
                module_id: "aft".into(),
            },
        )
        .unwrap();
    routes
        .insert_scoped(
            3,
            1,
            Principal::Reserved {
                module_id: "aft".into(),
            },
            Some(scopes.bot.clone()),
        )
        .unwrap();
    let (writer, mut replies) = mpsc::channel(64);
    if recalled {
        for index in 0..32 {
            handle_tool_request(
                request(1, index, held_body(index as usize)),
                &writer,
                &state,
                &routes,
            )
            .await
            .unwrap();
            let reply =
                recv_within(replies.recv(), Duration::from_secs(20), "seed pending card").await;
            let body: Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(
                body["structuredContent"]["code"], "access_pending",
                "{body}"
            );
        }
        assert_eq!(cards.records.lock().unwrap().len(), 32);
    }
    cards.parking.store(true, Ordering::SeqCst);
    for index in 0..32 {
        handle_frame(
            request(1, index, held_body(index as usize)),
            &writer,
            &state,
            &routes,
        )
        .await
        .unwrap();
    }
    wait_until("32 calls must reach the consent wait", || {
        cards.waiting.load(Ordering::SeqCst) == 32
    })
    .await;
    assert_eq!(
        routes.in_flight.available_permits(),
        224,
        "parked consent retains admission"
    );
    assert_eq!(
        cards.records.lock().unwrap().len(),
        32,
        "recalling must not file duplicate cards"
    );
    handle_frame(
        request(
            2,
            100,
            json!({"name":"web_search","arguments":{"query":"rust async guide"}}),
        ),
        &writer,
        &state,
        &routes,
    )
    .await
    .unwrap();
    handle_frame(request(3, 101, json!({"name":"github","arguments":{"op":"bot_request","request_nonce":"capacity-bot-write",
        "request":{"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}}
    }})), &writer, &state, &routes).await.unwrap();
    for _ in 0..2 {
        let reply = recv_within(
            replies.recv(),
            Duration::from_secs(20),
            "unrelated work must complete while 32 approvals wait",
        )
        .await;
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert!(body["error"].is_null(), "{body}");
        match reply.header.corr {
            100 => assert_eq!(body["isError"], false, "search must succeed: {body}"),
            101 => assert_eq!(
                body["result"]["status"], "completed",
                "bot write must succeed: {body}"
            ),
            other => panic!("parked request {other} answered before the user"),
        }
    }
    assert_eq!(cards.waiting.load(Ordering::SeqCst), 32);
    assert_eq!(
        fixture.transport.requests().len(),
        2,
        "only search and bot write may contact transport before consent"
    );
    wait_until("completed work releases admission", || {
        routes.in_flight.available_permits() == 224
    })
    .await;
    let blocked = tokio::time::timeout(
        Duration::from_secs(3),
        routes.blocking.clone().acquire_many_owned(32),
    )
    .await
    .expect("parked approvals must release all blocking slots")
    .unwrap();
    cards.approve_all();
    wait_until("consent answers return", || {
        cards.waiting.load(Ordering::SeqCst) == 0
    })
    .await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        scopes.rechecks_after_answer.load(Ordering::SeqCst),
        0,
        "recheck must reacquire execution capacity"
    );
    assert_eq!(
        fixture.transport.requests().len(),
        2,
        "dispatch must reacquire execution capacity"
    );
    assert!(matches!(
        replies.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    drop(blocked);
    for _ in 0..32 {
        let reply = recv_within(
            replies.recv(),
            Duration::from_secs(20),
            "approved request reply",
        )
        .await;
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["result"]["transmission"], "completed", "{body}");
    }
    wait_until("all requests release admission", || {
        routes.in_flight.available_permits() == 256
    })
    .await;
    assert_eq!(fixture.transport.requests().len(), 34);
    assert!(scopes.rechecks_after_answer.load(Ordering::SeqCst) >= 32);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn newly_filed_consent_waits_yield_slots_for_search_and_bot_write() {
    parked_calls_do_not_starve_work(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recalled_consent_waits_yield_slots_for_search_and_bot_write() {
    parked_calls_do_not_starve_work(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_consent_request_keeps_approval_without_dispatching() {
    let mut fixture = crate::withdraw_tests::Fixture::new("expired-capacity");
    let source =
        subc_jsonc::jsonc_to_json(include_str!("../../../catalog/exa_rest.jsonc")).unwrap();
    let manifest = plexus_core::ingest_value(serde_json::from_str(&source).unwrap()).unwrap();
    let db = rusqlite::Connection::open(fixture.path.path()).unwrap();
    db.execute("INSERT INTO app_manifests (principal,key,schema_version,content_hash,manifest_json,ingested_at_ms) VALUES ('system','exa_rest',1,'fixture',?1,1)", [serde_json::to_string(&manifest.manifest).unwrap()]).unwrap();
    let cards = Arc::new(Cards::default());
    cards.parking.store(true, Ordering::SeqCst);
    let _release = ReleaseOnDrop(cards.clone());
    fixture.cards = Arc::new(ConsentCards::new(cards.clone()));
    let scope = CallScope::from_stamp(&crate::consent_test_support::worker_stamp("worker-7", 4));
    let mut runtime = fixture.runtime();
    runtime.engine = runtime.engine.with_scope_reader(Arc::new(LiveScopes {
        held: scope.clone(),
        bot: scope.clone(),
        cards: cards.clone(),
        rechecks_after_answer: AtomicUsize::new(0),
    }));
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    });
    let routes = Arc::new(RouteBindings::new());
    routes
        .insert_scoped(
            1,
            1,
            Principal::Reserved {
                module_id: "aft".into(),
            },
            Some(scope),
        )
        .unwrap();
    let budget =
        request_execution::RequestBudget::until(std::time::Instant::now() + Duration::from_secs(7));
    let deadline = budget.deadline;
    let permit = routes.blocking.clone().acquire_owned().await.unwrap();
    let (writer, mut rx) = mpsc::channel(1);
    let state_worker = state.clone();
    let routes_worker = routes.clone();
    let handle = tokio::runtime::Handle::current();
    let task = tokio::task::spawn_blocking(move || {
        let _slot = request_execution::RequestSlot::enter(
            routes_worker.blocking.clone(),
            permit,
            budget.clone(),
        );
        handle
            .block_on(handle_tool_request_with_budget(
                request(1, 1, held_body(999)),
                &writer,
                &state_worker,
                &routes_worker,
                budget,
            ))
            .unwrap();
    });
    wait_until("consent call parked", || {
        if let Ok(reply) = rx.try_recv() {
            panic!(
                "request returned before consent wait: {}",
                String::from_utf8_lossy(&reply.body)
            );
        }
        cards.waiting.load(Ordering::SeqCst) == 1
    })
    .await;
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
    cards.approve_all();
    let reply =
        crate::bounded::recv_within(rx.recv(), Duration::from_secs(5), "expired consent reply")
            .await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["error"]["code"], "request_deadline_exceeded", "{body}");
    assert_eq!(body["error"]["transmission"], "not_sent");
    task.await.unwrap();
    assert!(fixture.transport.requests().is_empty());
    let rows = fixture.store.list_action_requests("direct").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "approved");
    let (writer, mut rx) = mpsc::channel(1);
    handle_tool_request(request(1, 2, held_body(999)), &writer, &state, &routes)
        .await
        .unwrap();
    let reply =
        crate::bounded::recv_within(rx.recv(), Duration::from_secs(5), "recalled approved reply")
            .await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["result"]["transmission"], "completed", "{body}");
    assert_eq!(fixture.transport.requests().len(), 1);
}
