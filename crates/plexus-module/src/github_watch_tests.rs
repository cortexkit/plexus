use super::*;
use plexus_core::{CatalogActionInput, GrantInput};

const TOOL: &str = "github_watch";
const DAY: i64 = 86_400_000;
const ACTIONS: &str = "conn-github-actions";
const ISSUES: &str = "conn-github";
const OWNER: &str = "direct";
const BASAL: &str = "reserved:basal";

struct Fixture {
    runtime: Arc<ModuleState>,
    store: Arc<PlexusStore>,
    mock: Arc<MockTransport>,
    scratch: Scratch,
}

impl Fixture {
    fn new() -> Self {
        let (runtime, store, mock, scratch) = job_log_tests::actions_runtime();
        let source =
            subc_jsonc::jsonc_to_json(include_str!("../../../catalog/github.jsonc")).unwrap();
        let github = ingest_value(serde_json::from_str(&source).unwrap()).unwrap();
        store.upsert_manifest(CATALOG_PRINCIPAL, &github).unwrap();
        fixture_connection(&store, ISSUES, &["list_issues", "issue_read"]);
        fixture_connection(
            &store,
            "conn-github-prs",
            &["list_pull_requests", "pull_request_read"],
        );
        fixture_connection(&store, "conn-github-releases", &["get_latest_release"]);
        for principal in [OWNER, BASAL] {
            fixture_grant(&store, ACTIONS, principal, &["get_repository"]);
        }
        mock.set_response_for_method(
            "get_repository",
            "",
            MockResponse::Success(json!({"private":false,"id":101})),
        );
        mock.set_response_for_method(
            "issue_read",
            "get",
            MockResponse::Success(json!({"number":7})),
        );
        mock.set_response_for_method(
            "get_latest_release",
            "",
            MockResponse::Success(json!({"tag_name":"v1","id":19})),
        );
        Self {
            runtime,
            store,
            mock,
            scratch,
        }
    }

    async fn call(&self, name: &str, args: Value, flow: &str, agent: Option<&str>) -> Value {
        let stamp = subc_protocol::scope::ScopeStamp::new(
            Principal::Reserved {
                module_id: "basal".into(),
            },
            flow,
            1,
            subc_protocol::scope::ScopeKind::Head,
        )
        .with_attributes(
            subc_protocol::scope::ScopeAttributes::new()
                .with_agent_id(agent.map(str::to_owned))
                .with_flow_id(Some(flow.into())),
        )
        .with_owner_authorized(true);
        send_facade_frame(self.runtime.clone(), name, args, "basal", Some(stamp)).await
    }

    async fn watch(&self, args: Value, flow: &str, agent: Option<&str>) -> Value {
        self.call(TOOL, args, flow, agent).await
    }

    fn set_watch_created_at(&self, flow: &str, at_ms: i64) {
        let db = rusqlite::Connection::open(self.scratch.as_ref() as &Path).unwrap();
        assert_eq!(
            db.execute(
                "UPDATE github_outside_watches SET created_at_ms=?1 WHERE flow_id=?2",
                rusqlite::params![at_ms, flow],
            )
            .unwrap(),
            1
        );
    }
}

fn fixture_connection(store: &PlexusStore, connection: &str, actions: &[&str]) {
    store
        .insert_connection(OWNER, connection, "github", "pending", &json!({}))
        .unwrap();
    let ticket = store
        .create_binding_ticket(OWNER, connection, b"test:github")
        .unwrap();
    store
        .connect_with_ticket(OWNER, &ticket.ticket_id)
        .unwrap()
        .unwrap();
    for action in actions {
        let schema = json!({"type":"object","properties":{
            "owner":{"type":"string"},"repo":{"type":"string"},"since":{"type":"string"},
            "orderBy":{"type":"string"},"direction":{"type":"string"},"perPage":{"type":"integer"},
            "after":{"type":"string"},"sort":{"type":"string"},"state":{"type":"string"},
            "method":{"type":"string"},"issue_number":{"type":"integer"},"pullNumber":{"type":"integer"}
        },"required":["owner","repo"]});
        store
            .upsert_catalog_action(&CatalogActionInput {
                principal: OWNER.into(),
                connection_id: connection.into(),
                name: (*action).into(),
                title: None,
                schema_hash: plexus_core::jcs_sha256(&schema).unwrap(),
                schema,
                risk: "read".into(),
                severity: "S1".into(),
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
                ask_first: false,
            })
            .unwrap();
    }
    for principal in [OWNER, BASAL] {
        fixture_grant(store, connection, principal, actions);
    }
}

fn fixture_grant(store: &PlexusStore, connection: &str, grantee: &str, actions: &[&str]) {
    store
        .insert_grant(&GrantInput {
            grant_id: format!("{connection}-{grantee}"),
            principal: OWNER.into(),
            connection_id: connection.into(),
            grantee_principal: grantee.into(),
            risk_ceiling: "read".into(),
            action_selectors: actions.iter().map(|s| (*s).into()).collect(),
            authority_kind: "poll".into(),
            expires_at: None,
        })
        .unwrap();
}

fn ensure(repository: &str, number: i64, expires_at_ms: i64) -> Value {
    json!({"action":"ensure","repository":repository,"kind":"issue","number":number,"expires_at_ms":expires_at_ms})
}

fn iso_time(millis: i64) -> String {
    chrono::DateTime::from_timestamp_millis(millis)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn refused(reply: &Value, code: &str) {
    assert_eq!(reply["error"]["code"], code, "{reply}");
    assert_eq!(reply["error"]["transmission"], "not_sent", "{reply}");
    assert_eq!(reply["error"]["retryable"], false, "{reply}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_repo_is_refused_before_item_read() {
    let f = Fixture::new();
    f.mock.set_response_for_method(
        "get_repository",
        "",
        MockResponse::Success(json!({"private":true,"id":101})),
    );
    let reply = f
        .watch(
            ensure("outside/repo", 7, plexus_core::now_ms() + DAY),
            "flow-a",
            Some("agent-x"),
        )
        .await;
    refused(&reply, "repository_not_public");
    let sent = f.mock.requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].action, "get_repository");
    assert!(f
        .store
        .list_subscriptions(OWNER, None, None)
        .unwrap()
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_cap_applies_only_without_active_watch_of_same_kind() {
    let f = Fixture::new();
    f.store
        .subscribe_with_cursor_state(
            OWNER,
            ISSUES,
            "list_issues",
            300,
            &json!({}),
            &json!({"owner":"outside","repo":"repo"}),
        )
        .unwrap()
        .unwrap();
    let expiry = plexus_core::now_ms() + 90 * DAY;
    let reply = f
        .watch(ensure("Outside/Repo", 7, expiry), "flow-a", Some("agent-x"))
        .await;
    assert_eq!(
        reply,
        json!({"result":{"watch":"existing","repository":"outside/repo","kind":"issue","number":7,"expires_at_ms":null}})
    );
    let mut release = json!({"action":"ensure","repository":"outside/repo","kind":"release","expires_at_ms":expiry});
    refused(
        &f.watch(release.clone(), "flow-a", Some("agent-x")).await,
        "invalid_request",
    );
    assert!(f.mock.requests().is_empty());
    release["expires_at_ms"] = json!(plexus_core::now_ms() + 30 * DAY);
    assert_eq!(
        f.watch(release, "flow-a", Some("agent-x")).await["result"]["watch"],
        "outside"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caps_count_active_rows_per_agent_and_globally() {
    let f = Fixture::new();
    let expiry = plexus_core::now_ms() + DAY;
    for agent in 0..5 {
        for n in 0..5 {
            let reply = f
                .watch(
                    ensure("outside/repo", 7, expiry),
                    &format!("flow-{agent}-{n}"),
                    Some(&format!("agent-{agent}")),
                )
                .await;
            assert_eq!(reply["result"]["watch"], "outside", "{reply}");
        }
        refused(
            &f.watch(
                ensure("outside/repo", 7, expiry),
                "extra",
                Some(&format!("agent-{agent}")),
            )
            .await,
            "outside_watch_limit",
        );
    }
    refused(
        &f.watch(
            ensure("outside/repo", 7, expiry),
            "extra",
            Some("agent-other"),
        )
        .await,
        "outside_watch_limit",
    );
    assert_eq!(
        f.store.list_subscriptions(OWNER, None, None).unwrap().len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ensures_are_idempotent_and_end_retires_only_the_last_subscription() {
    let f = Fixture::new();
    let expiry = plexus_core::now_ms() + DAY;
    let first = f
        .watch(ensure("Outside/Repo", 7, expiry), "flow-a", Some("agent-x"))
        .await;
    assert_eq!(
        first,
        json!({"result":{"watch":"outside","repository":"outside/repo","kind":"issue","number":7,"expires_at_ms":expiry}})
    );
    let retry = f
        .watch(
            ensure("outside/repo", 7, expiry + DAY),
            "flow-a",
            Some("agent-x"),
        )
        .await;
    assert_eq!(first, retry);
    assert_eq!(
        f.watch(ensure("outside/repo", 7, expiry), "flow-b", Some("agent-x"))
            .await,
        first
    );
    let subs = f.store.list_subscriptions(OWNER, None, None).unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].cadence_s, 900);
    assert_eq!(subs[0].cursor_kind, "ordered_timestamp");
    assert!(subs[0].project_id.is_none());
    let end = json!({"action":"end","repository":"outside/repo","kind":"issue","number":7});
    assert_eq!(
        f.watch(end.clone(), "flow-a", Some("agent-x")).await,
        json!({"result":{"ended":true}})
    );
    assert_eq!(
        f.watch(end.clone(), "flow-a", Some("agent-x")).await,
        json!({"result":{"ended":false}})
    );
    assert_eq!(
        f.store
            .subscription(OWNER, &subs[0].subscription_id)
            .unwrap()
            .unwrap()
            .status,
        "active"
    );
    assert_eq!(
        f.watch(end, "flow-b", Some("agent-x")).await,
        json!({"result":{"ended":true}})
    );
    assert_eq!(
        f.store
            .subscription(OWNER, &subs[0].subscription_id)
            .unwrap()
            .unwrap()
            .status,
        "retired"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_and_events_get_reach_only_the_watched_item_for_the_same_flow() {
    let f = Fixture::new();
    let before_watch = plexus_core::now_ms();
    let expiry = before_watch + DAY;
    let watch = f
        .watch(ensure("outside/repo", 7, expiry), "flow-a", Some("agent-x"))
        .await;
    assert_eq!(watch["result"]["watch"], "outside", "{watch}");
    let sub = f
        .store
        .list_subscriptions(OWNER, None, None)
        .unwrap()
        .pop()
        .unwrap();
    let created = iso_time(before_watch - DAY);
    let old = iso_time(before_watch - 1_000);
    f.mock.set_response_for_method(
        "list_issues",
        "",
        MockResponse::Success(json!({"issues":[
            {"number":7,"updated_at":old,"created_at":created,"title":"watched"}
        ]})),
    );
    let poller = plexus_core::Poller::new(f.runtime.runtime.engine.clone());
    let first = poller.poll_once(OWNER, &sub.subscription_id);
    assert!(
        matches!(first, plexus_core::PollCycle::Completed { inserted: 0, .. }),
        "the first poll must not publish pre-existing issue activity: {first:?}"
    );
    assert!(f.store.drain_event_outbox(10).unwrap().is_empty());
    let updated = iso_time(plexus_core::now_ms() + 1_000);
    f.mock.set_response_for_method(
        "list_issues",
        "",
        MockResponse::Success(json!({"issues":[
            {"number":7,"updated_at":updated,"created_at":created,"title":"watched"},
            {"number":8,"updated_at":updated,"created_at":created,"title":"unwatched"}
        ]})),
    );
    assert!(matches!(
        poller.poll_once(OWNER, &sub.subscription_id),
        plexus_core::PollCycle::Completed { inserted: 1, .. }
    ));
    let events = f.store.drain_event_outbox(10).unwrap();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(
        serde_json::from_str::<Value>(&event.body).unwrap()["number"],
        7
    );
    for version in [1, 2] {
        let args = json!({"event_key":event.event_key,"event_name":"github_issue_changed","version":version});
        let visible = f
            .call(
                manifest::EVENTS_GET_TOOL,
                args.clone(),
                "flow-a",
                Some("agent-x"),
            )
            .await;
        assert!(visible.get("result").is_some(), "{visible}");
        let not_visible = f
            .call(manifest::EVENTS_GET_TOOL, args, "flow-b", Some("agent-x"))
            .await;
        assert_eq!(
            not_visible["error"]["code"], "event_not_visible",
            "{not_visible}"
        );
    }
    f.watch(
        json!({"action":"end","repository":"outside/repo","kind":"issue","number":7}),
        "flow-a",
        Some("agent-x"),
    )
    .await;
    let args = json!({"event_key":event.event_key,"event_name":"github_issue_changed","version":2});
    let ended = f
        .call(manifest::EVENTS_GET_TOOL, args, "flow-a", Some("agent-x"))
        .await;
    assert_eq!(ended["error"]["code"], "event_not_visible", "{ended}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joining_watch_ignores_activity_before_its_own_creation() {
    let f = Fixture::new();
    let before_join = plexus_core::now_ms();
    let expiry = before_join + DAY;
    let first = f
        .watch(ensure("outside/repo", 7, expiry), "flow-a", Some("agent-x"))
        .await;
    assert_eq!(first["result"]["watch"], "outside", "{first}");
    f.set_watch_created_at("flow-a", before_join - 60_000);
    let sub = f
        .store
        .list_subscriptions(OWNER, None, None)
        .unwrap()
        .pop()
        .unwrap();
    f.mock.set_response_for_method(
        "issue_read",
        "get",
        MockResponse::Success(json!({"number":8})),
    );
    let other = f
        .watch(ensure("outside/repo", 8, expiry), "flow-b", Some("agent-x"))
        .await;
    assert_eq!(other["result"]["watch"], "outside", "{other}");
    assert_eq!(
        f.store.list_subscriptions(OWNER, None, None).unwrap().len(),
        1
    );
    let created = iso_time(before_join - DAY);
    f.mock.set_response_for_method(
        "list_issues",
        "",
        MockResponse::Success(json!({"issues":[
            {"number":8,"updated_at":iso_time(before_join - 30_000),"created_at":created}
        ]})),
    );
    let poller = plexus_core::Poller::new(f.runtime.runtime.engine.clone());
    let first = poller.poll_once(OWNER, &sub.subscription_id);
    assert!(
        matches!(first, plexus_core::PollCycle::Completed { inserted: 0, .. }),
        "activity after the first watch but before the joining watch must not publish: {first:?}"
    );
    assert!(f.store.drain_event_outbox(10).unwrap().is_empty());
    f.mock.set_response_for_method(
        "list_issues",
        "",
        MockResponse::Success(json!({"issues":[
            {"number":8,"updated_at":iso_time(plexus_core::now_ms() + 1_000),"created_at":created}
        ]})),
    );
    assert!(matches!(
        poller.poll_once(OWNER, &sub.subscription_id),
        plexus_core::PollCycle::Completed { inserted: 1, .. }
    ));
    let events = f.store.drain_event_outbox(10).unwrap();
    assert_eq!(events.len(), 1);
    let other_event = &events[0];
    let args =
        json!({"event_key":other_event.event_key,"event_name":"github_issue_changed","version":2});
    let refusal = f
        .call(
            manifest::EVENTS_GET_TOOL,
            args.clone(),
            "flow-a",
            Some("agent-x"),
        )
        .await;
    assert_eq!(refusal["error"]["code"], "event_not_visible", "{refusal}");
    let allowed = f
        .call(manifest::EVENTS_GET_TOOL, args, "flow-b", Some("agent-x"))
        .await;
    assert!(allowed.get("result").is_some(), "{allowed}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_item_watch_reads_only_activity_after_its_own_creation() {
    let f = Fixture::new();
    let before_join = plexus_core::now_ms();
    let expiry = before_join + DAY;
    for flow in ["flow-a", "flow-b"] {
        let reply = f
            .watch(ensure("outside/repo", 7, expiry), flow, Some("agent-x"))
            .await;
        assert_eq!(reply["result"]["watch"], "outside", "{reply}");
    }
    f.set_watch_created_at("flow-a", before_join - 60_000);
    let subs = f.store.list_subscriptions(OWNER, None, None).unwrap();
    assert_eq!(1, subs.len());
    let poller = plexus_core::Poller::new(f.runtime.runtime.engine.clone());
    for (activity, new_watch_visible) in [
        (before_join - 30_000, false),
        (plexus_core::now_ms() + 1_000, true),
    ] {
        f.mock.set_response_for_method(
            "list_issues",
            "",
            MockResponse::Success(json!({"issues":[
                {"number":7,"updated_at":iso_time(activity),"created_at":iso_time(before_join-DAY)}
            ]})),
        );
        let cycle = poller.poll_once(OWNER, &subs[0].subscription_id);
        assert!(
            matches!(cycle, plexus_core::PollCycle::Completed { inserted: 1, .. }),
            "the older watch is owed both changes: {cycle:?}"
        );
        let events = f.store.drain_event_outbox_version(10, 2).unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        let args = json!({"event_key":event.event_key,"event_name":event.event_name,"version":2});
        for (flow, visible) in [("flow-a", true), ("flow-b", new_watch_visible)] {
            let reply = f
                .call(
                    manifest::EVENTS_GET_TOOL,
                    args.clone(),
                    flow,
                    Some("agent-x"),
                )
                .await;
            if visible {
                assert!(reply.get("result").is_some(), "{flow}: {reply}");
            } else {
                assert_eq!(
                    reply["error"]["code"], "event_not_visible",
                    "{flow}: {reply}"
                );
            }
        }
        assert!(f
            .store
            .mark_event_version_published(&event.event_key, 2, plexus_core::now_ms())
            .unwrap());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn release_watch_ignores_tags_published_before_creation() {
    let f = Fixture::new();
    let before_watch = plexus_core::now_ms();
    let release = |tag, id, at_ms| {
        f.mock.set_response_for_method(
            "get_latest_release",
            "",
            MockResponse::Success(json!({"tag_name":tag,"id":id,"published_at":iso_time(at_ms)})),
        );
    };
    release("v2", 20, before_watch - DAY);
    let watch = f
        .watch(
            json!({"action":"ensure","repository":"outside/repo","kind":"release","expires_at_ms":before_watch+DAY}),
            "flow-a",
            Some("agent-x"),
        )
        .await;
    assert_eq!(watch["result"]["watch"], "outside", "{watch}");
    let sub = f
        .store
        .list_subscriptions(OWNER, None, None)
        .unwrap()
        .pop()
        .unwrap();
    let poller = plexus_core::Poller::new(f.runtime.runtime.engine.clone());
    // GitHub can fall back to an older release when the latest is removed.
    release("v1", 19, before_watch - 2 * DAY);
    let first = poller.poll_once(OWNER, &sub.subscription_id);
    assert!(
        matches!(first, plexus_core::PollCycle::Completed { inserted: 0, .. }),
        "a change in the latest tag is not a new publication: {first:?}"
    );
    assert!(f.store.drain_event_outbox(10).unwrap().is_empty());
    release("v3", 21, plexus_core::now_ms() + 1_000);
    let later = poller.poll_once(OWNER, &sub.subscription_id);
    assert!(
        matches!(later, plexus_core::PollCycle::Completed { inserted: 1, .. }),
        "{later:?}"
    );
    let events = f.store.drain_event_outbox(10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_name, "github_release_published");
    assert_eq!(
        serde_json::from_str::<Value>(&events[0].body).unwrap()["tag_name"],
        "v3"
    );
    let event = &events[0];
    let reply = f
        .call(
            manifest::EVENTS_GET_TOOL,
            json!({"event_key":event.event_key,"event_name":event.event_name,"version":2}),
            "flow-a",
            Some("agent-x"),
        )
        .await;
    assert!(reply.get("result").is_some(), "{reply}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inconclusive_public_check_pauses_then_resumes_or_retires() {
    let f = Fixture::new();
    let now = plexus_core::now_ms();
    let reply = f
        .watch(
            ensure("outside/repo", 7, now + 2 * DAY),
            "flow-a",
            Some("agent-x"),
        )
        .await;
    assert_eq!(reply["result"]["watch"], "outside", "{reply}");
    let db = rusqlite::Connection::open(f.scratch.as_ref() as &Path).unwrap();
    let hour = DAY / 24;
    let set_public_check = |when| {
        db.execute("UPDATE github_outside_watches SET last_public_check_at_ms=?1,last_public_attempt_at_ms=?1", [when]).unwrap()
    };
    set_public_check(now - 2 * hour);
    let housekeep = |at| {
        plexus_core::github_watch::housekeeping_at_for_test(&f.runtime.runtime.engine, at).unwrap()
    };
    f.mock.set_response_for_method(
        "get_repository",
        "",
        MockResponse::VendorError {
            code: "http_503".into(),
            message: "transient".into(),
        },
    );
    housekeep(now);
    let requests = f.mock.requests().len();
    housekeep(now + hour / 2);
    assert_eq!(
        requests,
        f.mock.requests().len(),
        "re-checks are at most hourly per repo"
    );
    let sub = f
        .store
        .list_subscriptions(OWNER, None, None)
        .unwrap()
        .pop()
        .unwrap();
    let poller = plexus_core::Poller::new(f.runtime.runtime.engine.clone());
    assert_eq!(sub.status, "active");
    assert!(matches!(
        poller.poll_once(OWNER, &sub.subscription_id),
        plexus_core::PollCycle::NotEligible { .. }
    ));
    assert_eq!(
        requests,
        f.mock.requests().len(),
        "a stale proof must prevent even a vendor poll"
    );
    f.mock.set_response_for_method(
        "get_repository",
        "",
        MockResponse::Success(json!({"private":false,"id":101})),
    );
    f.mock.set_response_for_method(
        "list_issues",
        "",
        MockResponse::Success(json!({"issues":[]})),
    );
    housekeep(now + hour);
    assert!(matches!(
        poller.poll_once(OWNER, &sub.subscription_id),
        plexus_core::PollCycle::Completed { .. }
    ));
    set_public_check(now - DAY + 10 * hour);
    f.mock.set_response_for_method(
        "get_repository",
        "",
        MockResponse::VendorError {
            code: "http_503".into(),
            message: "transient".into(),
        },
    );
    housekeep(now + 9 * hour);
    assert_eq!(
        f.store
            .subscription(OWNER, &sub.subscription_id)
            .unwrap()
            .unwrap()
            .status,
        "active"
    );
    housekeep(now + 10 * hour);
    assert_eq!(
        f.store
            .subscription(OWNER, &sub.subscription_id)
            .unwrap()
            .unwrap()
            .status,
        "retired"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_basal_selector_refuses_before_any_vendor_read() {
    let f = Fixture::new();
    f.store
        .revoke_grant(OWNER, &format!("{ISSUES}-{BASAL}"))
        .unwrap();
    fixture_grant(&f.store, ISSUES, BASAL, &["list_issues"]);
    let reply = f
        .watch(
            ensure("outside/repo", 7, plexus_core::now_ms() + DAY),
            "flow-a",
            Some("agent-x"),
        )
        .await;
    refused(&reply, "grant_missing");
    assert!(f.mock.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_vectors_match_the_flow_handler() {
    use std::fmt::Write as _;

    let f = Fixture::new();
    let expiry = plexus_core::now_ms() + DAY;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/github-watch-v1");
    let regenerate = std::env::var("PLEXUS_REGENERATE_GITHUB_WATCH_FIXTURES").as_deref() == Ok("1");
    let pinned: Option<Vec<Value>> = (!regenerate).then(|| {
        serde_json::from_slice(&std::fs::read(directory.join("vectors.json")).unwrap()).unwrap()
    });
    let mut vectors = Vec::new();
    async fn capture(
        vectors: &mut Vec<Value>,
        f: &Fixture,
        case: &str,
        args: Value,
        agent: Option<&str>,
    ) {
        let reply = f.watch(args.clone(), "flow-a", agent).await;
        vectors.push(json!({"case":case,"request":{"name":TOOL,"arguments":args},"reply":reply}));
    }
    let outside = ensure("Outside/Repo", 7, expiry);
    capture(
        &mut vectors,
        &f,
        "ensure_outside",
        outside.clone(),
        Some("agent-x"),
    )
    .await;
    assert_eq!(
        vectors[0]["reply"]["result"]["watch"], "outside",
        "{}",
        vectors[0]
    );
    let sub = f
        .store
        .list_subscriptions(OWNER, None, None)
        .unwrap()
        .pop()
        .unwrap();
    // Replay the sample's update relative to its recorded expiry so that the
    // timestamp and derived event key stay stable. The live call still requires
    // a future expiry; move the stored watch start to before the sample update.
    let sample_expiry = pinned.as_ref().map_or(expiry, |vectors| {
        vectors[0]["reply"]["result"]["expires_at_ms"]
            .as_i64()
            .unwrap()
    });
    let update_at = sample_expiry - DAY;
    f.set_watch_created_at("flow-a", update_at - 1_000);
    f.mock.set_response_for_method("list_issues", "", MockResponse::Success(json!({"issues":[
        {"number":7,"created_at":iso_time(update_at - 2 * DAY),"updated_at":iso_time(update_at),"title":"watched","state":"open"}
    ]})));
    let poller = plexus_core::Poller::new(f.runtime.runtime.engine.clone());
    assert!(matches!(
        poller.poll_once(OWNER, &sub.subscription_id),
        plexus_core::PollCycle::Completed { inserted: 1, .. }
    ));
    let event = f
        .store
        .drain_event_outbox_version(10, 2)
        .unwrap()
        .pop()
        .unwrap();
    assert!(f
        .store
        .mark_event_version_published(&event.event_key, 2, plexus_core::now_ms())
        .unwrap());
    let mut body: Value = serde_json::from_str(event.envelope_v2.as_deref().unwrap()).unwrap();
    assert!(body["observed_at"].is_string());
    capture(
        &mut vectors,
        &f,
        "end",
        json!({"action":"end","repository":"outside/repo","kind":"issue","number":7}),
        Some("agent-x"),
    )
    .await;

    f.store
        .subscribe_with_cursor_state(
            OWNER,
            ISSUES,
            "list_issues",
            300,
            &json!({}),
            &json!({"owner":"fleet","repo":"repo"}),
        )
        .unwrap()
        .unwrap();
    capture(
        &mut vectors,
        &f,
        "ensure_existing",
        ensure("fleet/repo", 7, expiry),
        Some("agent-x"),
    )
    .await;
    capture(
        &mut vectors,
        &f,
        "invalid_request",
        ensure("outside/repo", 7, expiry + 31 * DAY),
        Some("agent-x"),
    )
    .await;
    capture(
        &mut vectors,
        &f,
        "agent_identity_required",
        outside.clone(),
        None,
    )
    .await;
    f.mock.set_response_for_method(
        "get_repository",
        "",
        MockResponse::Success(json!({"private":true,"id":101})),
    );
    capture(
        &mut vectors,
        &f,
        "repository_not_public",
        outside.clone(),
        Some("agent-x"),
    )
    .await;
    f.mock.set_response_for_method(
        "get_repository",
        "",
        MockResponse::Success(json!({"private":false,"id":101})),
    );
    for code in ["http_404", "mcp_tool_error"] {
        f.mock.set_response_for_method(
            "issue_read",
            "get",
            MockResponse::VendorError {
                code: code.into(),
                message: "mock vendor failure".into(),
            },
        );
        let case = if code == "http_404" {
            "item_not_found"
        } else {
            "read_dispatch_failed"
        };
        capture(&mut vectors, &f, case, outside.clone(), Some("agent-x")).await;
    }
    f.mock.set_response_for_method(
        "issue_read",
        "get",
        MockResponse::Success(json!({"number":7})),
    );
    for n in 0..5 {
        assert_eq!(
            f.watch(outside.clone(), &format!("cap-{n}"), Some("agent-x"))
                .await["result"]["watch"],
            "outside"
        );
    }
    capture(
        &mut vectors,
        &f,
        "outside_watch_limit",
        outside.clone(),
        Some("agent-x"),
    )
    .await;
    f.store
        .revoke_grant(OWNER, &format!("{ISSUES}-{BASAL}"))
        .unwrap();
    capture(
        &mut vectors,
        &f,
        "grant_missing",
        outside.clone(),
        Some("agent-x"),
    )
    .await;
    let mut f = f;
    Arc::get_mut(&mut f.runtime).unwrap().runtime.connector_home =
        crate::connector_home::ConnectorHome::unavailable().into();
    capture(
        &mut vectors,
        &f,
        "connector_home_not_held",
        outside,
        Some("agent-x"),
    )
    .await;
    for vector in &vectors {
        if vector["reply"].get("error").is_some() {
            assert_eq!(vector["reply"]["error"]["code"], vector["case"], "{vector}");
            assert_eq!(
                vector["reply"]["error"]["transmission"], "not_sent",
                "{vector}"
            );
        }
    }
    if let Some(pinned) = pinned {
        // Real calls require a future expiry. Compare the live value to the
        // request, then substitute the recorded clock for the byte comparison.
        assert_eq!(vectors[0]["reply"]["result"]["expires_at_ms"], expiry);
        for (sample, pin) in vectors.iter_mut().zip(&pinned) {
            if sample["request"]["arguments"]
                .get("expires_at_ms")
                .is_some()
            {
                sample["request"]["arguments"]["expires_at_ms"] =
                    pin["request"]["arguments"]["expires_at_ms"].clone();
            }
        }
        vectors[0]["reply"]["result"]["expires_at_ms"] =
            pinned[0]["reply"]["result"]["expires_at_ms"].clone();
        let pinned_body: Value =
            serde_json::from_slice(&std::fs::read(directory.join("event-v2.json")).unwrap())
                .unwrap();
        body["observed_at"] = pinned_body["observed_at"].clone();
    }
    let mut sums = String::new();
    for (name, value) in [("event-v2.json", body), ("vectors.json", json!(vectors))] {
        let bytes = format!("{}\n", serde_json::to_string_pretty(&value).unwrap());
        writeln!(
            sums,
            "{}  {name}",
            plexus_core::jcs::sha256_hex(bytes.as_bytes())
        )
        .unwrap();
        if regenerate {
            std::fs::write(directory.join(name), bytes).unwrap();
        } else {
            assert_eq!(
                std::fs::read_to_string(directory.join(name)).unwrap(),
                bytes,
                "{name}"
            );
        }
    }
    if regenerate {
        std::fs::write(directory.join("SHA256SUMS"), sums).unwrap();
    } else {
        assert_eq!(
            std::fs::read_to_string(directory.join("SHA256SUMS")).unwrap(),
            sums
        );
    }
}
