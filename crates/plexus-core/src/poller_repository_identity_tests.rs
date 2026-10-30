use super::*;
use crate::credentials::{ResolvedCredential, StubCredentialSource};
use crate::storage::{CatalogActionInput, Ceiling, GrantInput, PlexusStore};
use crate::test_scratch::Scratch;
use crate::transport::{MockResponse, MockTransport, TransportRequest, TransportResponse};
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

const PRINCIPAL: &str = "watch-owner";
const GITHUB: &str = "conn-github";
const ACTIONS: &str = "conn-github-actions";

// Inspect the database through a separate reader while dispatch is running:
// an in-memory promise or a reservation committed after HTTP cannot pass.
struct CheckedTransport {
    mock: MockTransport,
    path: std::path::PathBuf,
}
impl Transport for CheckedTransport {
    fn dispatch(
        &self,
        request: TransportRequest,
        credential: &ResolvedCredential,
    ) -> TransportResponse {
        if request.connection_id == ACTIONS {
            let conn = rusqlite::Connection::open(&self.path).unwrap();
            let units: i64 = conn.query_row("SELECT COALESCE(SUM(requests),0) FROM github_actions_quota WHERE reserved_at_ms >= ?1", [now_ms() - 3_600_000], |row| row.get(0)).unwrap();
            assert!(
                units > 0 && units <= 600,
                "identity HTTP must have a committed quota reservation"
            );
            let claimed: i64 = conn.query_row("SELECT COUNT(*) FROM github_repo_id_cache WHERE repo = lower(?1) AND last_attempt_at_ms > 0", [format!("{}/{}", request.args["owner"].as_str().unwrap(), request.args["repo"].as_str().unwrap())], |row| row.get(0)).unwrap();
            assert_eq!(claimed, 1, "the shared name claim must commit before HTTP");
        }
        self.mock.dispatch(request, credential)
    }
}

type Engine = GovernanceEngine<StubCredentialSource, CheckedTransport>;
struct Fixture {
    store: Arc<PlexusStore>,
    credentials: Arc<StubCredentialSource>,
    engine: Engine,
    poller: Poller<StubCredentialSource, CheckedTransport>,
    mock: MockTransport,
    path: Scratch,
}
impl Fixture {
    fn new(actions: bool) -> Self {
        let path = Scratch::database("poll-repository-identity");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: path.to_string_lossy().into_owned(),
                isolation: Isolation::Module,
                backend: StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        for source in [
            include_str!("../../../catalog/github.jsonc"),
            include_str!("../../../catalog/github_actions.jsonc"),
        ] {
            let source = subc_jsonc::jsonc_to_json(source).expect("shipped catalog is valid JSONC");
            let manifest =
                crate::manifest::ingest_value(serde_json::from_str(&source).unwrap()).unwrap();
            store
                .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &manifest)
                .unwrap();
        }
        let credentials = Arc::new(StubCredentialSource::default());
        let mock = MockTransport::default();
        let engine = GovernanceEngine::new(
            store.clone(),
            credentials.clone(),
            Arc::new(CheckedTransport {
                mock: mock.clone(),
                path: path.to_path_buf(),
            }),
        );
        let fixture = Self {
            store,
            credentials,
            poller: Poller::new(engine.clone()),
            engine,
            mock,
            path,
        };
        fixture.connect(
            GITHUB,
            "github",
            &["list_issues", "list_pull_requests", "get_latest_release"],
        );
        if actions {
            fixture.connect_actions();
        }
        fixture.mock.set_response_for_method(
            "get_repository",
            "",
            MockResponse::Success(json!({"id":101})),
        );
        fixture.mock.set_response_for_method(
            "list_issues",
            "",
            MockResponse::Success(json!({"issues":[issue(7, "2026-10-07T00:00:00Z")]})),
        );
        fixture.mock.set_response_for_method("list_pull_requests", "", MockResponse::Success(json!([{"number":8, "updated_at":"2026-10-07T00:00:00Z", "created_at":"2026-10-07T00:00:00Z", "head":{"ref":"must-not-be-a-header"}}])));
        fixture.mock.set_response_for_method("get_latest_release", "", MockResponse::Success(json!({"id":9,"tag_name":"v1","created_at":"2026-10-07T00:00:00Z","updated_at":"2026-10-07T00:00:00Z"})));
        fixture
    }
    fn connect_actions(&self) {
        self.connect(
            ACTIONS,
            "github_actions",
            &["get_repository", "list_workflow_runs"],
        );
    }
    fn connect(&self, connection: &str, app: &str, actions: &[&str]) {
        self.store
            .insert_connection(PRINCIPAL, connection, app, "pending", &json!({}))
            .unwrap();
        for action in actions {
            self.store.upsert_catalog_action(&CatalogActionInput {
                    connection_id: connection.into(), principal: PRINCIPAL.into(), name: (*action).into(), title: None,
                    schema: json!({"type":"object","properties":{
                        "owner":{"type":"string"},"repo":{"type":"string"},"since":{"type":"string"},
                        "orderBy":{"type":"string"},"direction":{"type":"string"},"perPage":{"type":"integer"},
                        "after":{"type":"string"},"sort":{"type":"string"},"state":{"type":"string"}},"required":["owner","repo"]}),
                    schema_hash: format!("current-{action}"), risk: "read".into(), severity: "S2".into(), ask_first: false,
                    status: "active".into(), quarantine_reason: None, reconciliation: None,
                }).unwrap();
        }
        let handle = format!("test:{connection}").into_bytes();
        let ticket = self
            .store
            .create_binding_ticket_bounded(
                PRINCIPAL,
                connection,
                "credential_reference",
                &handle,
                &Ceiling::unrestricted_for_tests(),
            )
            .unwrap();
        self.store
            .connect_with_ticket(PRINCIPAL, &ticket.ticket_id)
            .unwrap()
            .unwrap();
        self.credentials
            .set_success(&handle, b"vendor-token".to_vec(), None, 1);
        self.grant(connection, actions);
    }
    fn grant(&self, connection: &str, actions: &[&str]) {
        self.store
            .insert_grant(&GrantInput {
                grant_id: format!("poll-{connection}"),
                principal: PRINCIPAL.into(),
                connection_id: connection.into(),
                grantee_principal: PRINCIPAL.into(),
                risk_ceiling: "read".into(),
                action_selectors: actions.iter().map(|s| (*s).into()).collect(),
                authority_kind: crate::governance::AUTHORITY_POLL.into(),
                expires_at: Some(now_ms() + 3_600_000),
            })
            .unwrap();
    }
    fn watch(&self, action: &str) -> TriggerSubscription {
        self.watch_repo(action, "OWNER", "Repo")
    }
    fn watch_repo(&self, action: &str, owner: &str, repo: &str) -> TriggerSubscription {
        let cursor = if action == "get_latest_release" {
            json!({"scalar":"v0"})
        } else {
            json!({})
        };
        self.store
            .subscribe_with_cursor_state(
                PRINCIPAL,
                if action == "list_workflow_runs" {
                    ACTIONS
                } else {
                    GITHUB
                },
                action,
                300,
                &cursor,
                &json!({"owner":owner,"repo":repo}),
            )
            .unwrap()
            .unwrap()
    }
    fn sql(&self, sql: &str) {
        let conn = rusqlite::Connection::open(&*self.path).unwrap();
        conn.execute_batch(sql).unwrap();
    }
    fn count(&self, table: &str) -> i64 {
        rusqlite::Connection::open(&*self.path)
            .unwrap()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }
    fn refresh_due(&self) {
        self.sql(&format!(
            "UPDATE github_repo_id_cache SET resolved_at_ms = {}, last_attempt_at_ms = {}",
            now_ms() - 86_400_001,
            now_ms() - 3_600_001
        ));
    }
    fn poll(&self, watch: &TriggerSubscription) -> PollCycle {
        self.poller.poll_once(PRINCIPAL, &watch.subscription_id)
    }
    fn counter(&self, name: &str) -> u64 {
        self.poller.repo_identity_counts.snapshot()[name]
            .as_u64()
            .unwrap()
    }
}
fn issue(number: i64, updated: &str) -> Value {
    json!({"number":number,"title":"vendor body","created_at":"2026-10-07T00:00:00Z","updated_at":updated})
}

#[test]
fn identity_read_is_shared_authorized_audited_and_reserved_before_the_vendor_read() {
    let f = Fixture::new(true);
    for action in ["list_issues", "list_pull_requests", "get_latest_release"] {
        let watch = f.watch(action);
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 0
            }
        );
    }
    let requests = f.mock.requests();
    assert_eq!(
        requests
            .iter()
            .map(|r| r.action.as_str())
            .collect::<Vec<_>>(),
        vec![
            "get_repository",
            "list_issues",
            "list_pull_requests",
            "get_latest_release"
        ]
    );
    assert_eq!(requests[0].connection_id, ACTIONS);
    assert_eq!(f.count("github_actions_quota"), 1);
    let audit = f.store.list_audit(PRINCIPAL).unwrap();
    let identity_dispatch = audit
        .iter()
        .find(|row| row.action.as_deref() == Some("get_repository") && row.outcome.is_some())
        .expect("own dispatch audit for repository read");
    assert_eq!(identity_dispatch.principal, PRINCIPAL);
    assert!(identity_dispatch.actor.starts_with("trigger:"));
    let list_dispatch = audit
        .iter()
        .find(|row| row.action.as_deref() == Some("list_issues") && row.outcome.is_some())
        .unwrap();
    assert!(identity_dispatch.journal_id < list_dispatch.journal_id);
    assert_eq!(
        f.store
            .repo_id_cache("owner/repo")
            .unwrap()
            .unwrap()
            .repo_id,
        Some(101)
    );
    assert_eq!(
        f.count("event_outbox"),
        3,
        "current identity schema hash must authorize, not the issue watch's pin"
    );
}

#[test]
fn keyed_poll_markers_keep_change_out_of_bodies_and_pr_branch_out_of_headers() {
    let f = Fixture::new(true);
    let watch = f.watch("list_issues");
    f.sql(
        "UPDATE trigger_subscriptions SET project_id = 'project-p', project_source = 'entorhinal'",
    );
    f.mock.set_response_for_method(
        "list_issues",
        "",
        MockResponse::Success(json!({"issues":[
            issue(7,"2026-10-07T00:00:00Z"), issue(8,"2026-10-07T00:00:01Z"),
            {"number":9,"updated_at":"2026-10-07T00:00:02Z"}
        ]})),
    );
    assert_eq!(
        f.poll(&watch),
        PollCycle::Completed {
            inserted: 3,
            duplicates: 0
        }
    );
    for (number, updated, change) in [
        (7, "2026-10-07T00:00:00Z", Some("opened")),
        (8, "2026-10-07T00:00:01Z", Some("updated")),
        (9, "2026-10-07T00:00:02Z", None),
    ] {
        let key = crate::event_key::derive_event_key(
            "github_issue_changed",
            &json!({"repo_id":101,"number":number,"updated_at":updated}),
        )
        .unwrap();
        let marker = f.store.canonical_event_by_key(&key).unwrap().unwrap();
        assert_eq!(marker.change.as_deref(), change);
        assert_eq!(marker.headers.repo, "owner/repo");
        assert_eq!(marker.event_name, "github_issue_changed");
        assert_eq!(marker.headers.project.as_deref(), Some("project-p"));
        assert!(serde_json::from_str::<Value>(&marker.body)
            .unwrap()
            .get("change")
            .is_none());
    }
    let before = f.count("event_outbox");
    assert!(matches!(
        f.poll(&watch),
        PollCycle::Completed { inserted: 0, .. }
    ));
    assert_eq!(f.count("event_outbox"), before);
    for action in ["list_pull_requests", "get_latest_release"] {
        assert_eq!(
            f.poll(&f.watch(action)),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 0
            }
        );
    }
    let markers = f.store.drain_event_outbox(10).unwrap();
    let pr = markers
        .iter()
        .find(|m| m.event_name == "github_pr_changed")
        .unwrap();
    assert_eq!(pr.headers.pr.as_deref(), Some("8"));
    assert_eq!(pr.headers.branch, None);
    assert_eq!(pr.change, None);
    let release = markers
        .iter()
        .find(|m| m.event_name == "github_release_published")
        .unwrap();
    assert_eq!(release.change, None);
    assert_eq!(release.headers.pr, None);
}

#[test]
fn unchanged_legacy_issue_is_duplicate_on_real_poll_with_no_marker() {
    let f = Fixture::new(true);
    let watch = f.watch("list_issues");
    let payload = issue(7, "2026-10-07T00:00:00Z");
    let outcomes = f
        .store
        .commit_poll_success(
            PRINCIPAL,
            GITHUB,
            &watch.subscription_id,
            &json!({}),
            &[PollEventInput {
                vendor_event_id: "7",
                payload: &payload,
                observed_at_ms: now_ms(),
                item_kind: Some("issue"),
                activity_at_ms: Some(now_ms()),
                actor: &ActorAttribution::NotEnriched,
            }],
            now_ms(),
            None,
        )
        .unwrap();
    assert!(matches!(
        outcomes[0],
        TriggerEventInsertOutcome::Inserted { .. }
    ));
    assert_eq!(
        f.poll(&watch),
        PollCycle::Completed {
            inserted: 0,
            duplicates: 1
        }
    );
    assert_eq!(f.count("trigger_events"), 1);
    assert_eq!(f.count("event_outbox"), 0);
    assert!(f.store.list_events(PRINCIPAL, None, None).unwrap()[0]
        .payload
        .get("change")
        .is_none());
    assert_eq!(
        f.poll(&watch),
        PollCycle::Completed {
            inserted: 0,
            duplicates: 1
        }
    );
    assert_eq!(f.count("event_outbox"), 0);
}

#[test]
fn relay_stored_revisions_skip_actor_reads_before_poll_dedup() {
    use crate::storage::relay::{Event, Hello};

    for (action, event_name, item_kind) in [
        ("list_issues", "issues", "issue"),
        ("list_pull_requests", "pull_request", "pull_request"),
    ] {
        let f = Fixture::new(true);
        let issue_watch = f.watch("list_issues");
        let pr_watch = f.watch("list_pull_requests");
        let watch = if action == "list_issues" {
            issue_watch
        } else {
            pr_watch
        };
        f.connect("actors", "github", &["issue_read"]);
        f.sql("UPDATE catalog_actions SET schema_json = '{\"type\":\"object\",\"additionalProperties\":true}' WHERE connection_id = 'actors'");
        f.store
            .set_subscription_actor_source(
                PRINCIPAL,
                &watch.subscription_id,
                Some(&ActorSource {
                    connection_id: "actors".into(),
                    action: "issue_read".into(),
                    methods: if item_kind == "issue" {
                        vec!["get_comments".into()]
                    } else {
                        vec!["get_comments".into(), "get_review_comments".into()]
                    },
                }),
            )
            .unwrap();
        f.mock.set_response_for_method(
            "issue_read",
            "get_comments",
            MockResponse::Success(json!({"unrecognized":true})),
        );
        let timestamp = iso8601::format_millis(now_ms().div_euclid(1_000) * 1_000);
        let items = [issue(1, &timestamp), issue(3, &timestamp)];
        let hello = Hello {
            v: 1,
            source: "github".into(),
            stream_id: "actor-dedup".into(),
            next_seq: 1,
            oldest_seq: 1,
            last_acked_seq: 0,
        };
        f.store.relay_hello("github", &hello).unwrap();
        for (i, payload) in items.iter().enumerate() {
            let event = Event {
                seq: i as u64 + 1,
                delivery_id: format!("webhook-delivery-{i}"),
                event: event_name.into(),
                action: Some("edited".into()),
                installation_id: 1,
                received_at: iso8601::format_millis(now_ms()),
                stub: None,
                body: json!({"repository":{"id":101,"full_name":"owner/repo"},
                    "sender":{"login":"relay-bot"}, item_kind: payload}),
            };
            f.store
                .commit_relay_event("github", "actor-dedup", &event)
                .unwrap();
        }
        assert_eq!(
            f.count("trigger_events"),
            2,
            "the relay must store both deliveries"
        );
        let before = f
            .store
            .list_events(PRINCIPAL, None, Some(&watch.subscription_id))
            .unwrap();
        assert!(before.iter().all(|event| event
            .vendor_event_id
            .as_deref()
            .unwrap()
            .starts_with("webhook-delivery-")));
        let markers = f.store.drain_event_outbox(10).unwrap();
        let reply = |items: Vec<Value>| {
            if item_kind == "issue" {
                json!({"issues":items})
            } else {
                json!(items)
            }
        };
        f.mock
            .set_response_for_method(action, "", MockResponse::Success(reply(items.to_vec())));
        let actor_reads = || {
            f.mock
                .requests()
                .iter()
                .filter(|request| request.connection_id == "actors")
                .count()
        };
        for _ in 0..2 {
            assert_eq!(
                f.poll(&watch),
                PollCycle::Completed {
                    inserted: 0,
                    duplicates: 2
                }
            );
            assert_eq!(
                actor_reads(),
                0,
                "a relay-stored revision must not spend actor reads"
            );
        }
        assert_eq!(f.count("trigger_events"), 2);
        assert_eq!(
            f.store.drain_event_outbox(10).unwrap(),
            markers,
            "dedup must not rewrite canonical bytes or actors"
        );

        // A new item between two duplicates must keep its own identity and
        // remain deliverable even when actor attribution fails.
        f.mock.set_response_for_method(
            action,
            "",
            MockResponse::Success(reply(vec![
                items[0].clone(),
                issue(2, &timestamp),
                items[1].clone(),
            ])),
        );
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 2
            }
        );
        let stored = f
            .store
            .list_events(PRINCIPAL, None, Some(&watch.subscription_id))
            .unwrap();
        let new = stored
            .iter()
            .find(|event| event.vendor_event_id.as_deref() == Some("2"))
            .unwrap();
        assert_eq!(
            actor_reads(),
            1,
            "new event attribution: {:?}",
            new.actor_unknown
        );
        assert_eq!(new.payload["number"], 2);
        assert!(
            new.actor_logins.is_none(),
            "failed enrichment must not suppress delivery"
        );
        let expected = crate::event_key::derive_event_key(
            if item_kind == "issue" {
                crate::event_key::GITHUB_ISSUE_CHANGED
            } else {
                crate::event_key::GITHUB_PR_CHANGED
            },
            &json!({"repo_id":101,"number":2,"updated_at":timestamp}),
        )
        .unwrap();
        assert_eq!(
            f.store
                .canonical_event_by_key(&expected)
                .unwrap()
                .unwrap()
                .event_id,
            new.event_id
        );
        assert_eq!(f.count("event_outbox"), 3);
        assert_eq!(
            f.store
                .stored_event_keys("another-subscription", &[Some(&expected), None])
                .unwrap(),
            vec![false, false]
        );
    }
}

#[test]
fn keyed_prefilter_retains_uncertain_and_unkeyed_candidates() {
    let event = |id: &str| DerivedEvent {
        vendor_event_id: id.into(),
        payload: json!({}),
        activity_at_ms: None,
        replay_candidate: false,
    };
    let identity = || {
        Some(PollEventIdentity {
            key: "stored-key".into(),
            change: None,
            headers: EventHeaders::default(),
        })
    };
    let mut events = vec![event("1"), event("2")];
    let mut identities = vec![identity(), None];
    let mut dropped = vec![];
    assert_eq!(
        retain_unstored_keyed_events(&mut events, &mut identities, &mut dropped, |_| Err::<
            Vec<bool>,
            _,
        >(
            "unreadable"
        )),
        0
    );
    assert_eq!(events.len(), 2);
    assert_eq!(identities.len(), 2);
    assert!(dropped.is_empty());
    assert_eq!(
        retain_unstored_keyed_events(&mut events, &mut identities, &mut dropped, |_| Ok::<_, ()>(
            vec![true]
        )),
        1
    );
    assert_eq!(
        events[0].vendor_event_id, "2",
        "a short lookup result is not proof of a duplicate"
    );
    assert!(identities[0].is_none());
    assert_eq!(dropped, vec![("1".into(), DropReason::AlreadyDelivered)]);
}

#[test]
fn actor_unknown_warns_once_per_subscription_item_then_debugs() {
    const TEST: &str = "poller::repository_identity_tests::actor_unknown_warns_once_per_subscription_item_then_debugs";
    if std::env::var_os("PLEXUS_ACTOR_UNKNOWN_LOG_CHILD").is_some() {
        let mut config =
            cortexkit_log::Config::in_dir("plexus", std::env::current_exe().unwrap().join("logs"));
        config.spec = Some("debug".into());
        assert!(cortexkit_log::init(config).unwrap().fallback_active());
        let f = Fixture::new(false);
        let mut watch = f.watch("list_issues");
        watch.subscription_id = "warn-once-watch".into();
        let mut event = DerivedEvent {
            vendor_event_id: "808".into(),
            payload: json!({}),
            activity_at_ms: None,
            replay_candidate: false,
        };
        log_actor_unknown(
            &watch,
            &event,
            "same_second_ambiguity method=get_comments count=1",
        );
        log_actor_unknown(&watch, &event, "call_cap_exhausted count=1");
        event.vendor_event_id = "818".into();
        log_actor_unknown(&watch, &event, "empty_actor_window count=1");
        watch.subscription_id = "another-watch".into();
        event.vendor_event_id = "808".into();
        log_actor_unknown(&watch, &event, "transport_failure count=1");
        return;
    }
    let output = crate::test_http::bounded::child_test_output(
        TEST,
        &[("PLEXUS_ACTOR_UNKNOWN_LOG_CHILD", "1")],
        Duration::from_secs(30),
        "actor unknown diagnostic child",
    );
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    let log = String::from_utf8(output.stderr).unwrap();
    let lines: Vec<_> = log
        .lines()
        .filter(|line| line.contains("actor_enrichment_unknown"))
        .collect();
    assert_eq!(lines.len(), 4, "{log}");
    for (line, level) in lines.iter().zip([
        cortexkit_log::ParsedLevel::Warn,
        cortexkit_log::ParsedLevel::Debug,
        cortexkit_log::ParsedLevel::Warn,
        cortexkit_log::ParsedLevel::Warn,
    ]) {
        let parsed = cortexkit_log::parse_line(line).unwrap();
        assert_eq!(parsed.level, level, "{line}");
        assert_eq!(parsed.logger, "plexus.poller");
    }
    assert!(lines[0].contains("reason=same_second_ambiguity method=get_comments count=1"));
    assert!(lines[1].contains("reason=call_cap_exhausted count=1"));
}

#[test]
fn absent_actions_connection_survives_twenty_ticks_and_recovery_does_not_publish_old_state() {
    let f = Fixture::new(false);
    let watch = f.watch("list_issues");
    for second in 0..20 {
        f.mock.set_response_for_method(
            "list_issues",
            "",
            MockResponse::Success(
                json!({"issues":[issue(7,&format!("2026-10-07T00:00:{second:02}Z"))]}),
            ),
        );
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 0
            }
        );
        let stored = f
            .store
            .subscription(PRINCIPAL, &watch.subscription_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, "active");
        assert_eq!(stored.consecutive_vendor_failures, 0);
    }
    assert_eq!(f.counter("repo_id_unresolved"), 20);
    assert_eq!(f.count("trigger_events"), 20);
    assert_eq!(f.count("event_outbox"), 0);
    assert_eq!(f.mock.requests().len(), 20);
    assert_eq!(
        f.count("github_actions_quota"),
        0,
        "absent connection must not consume a vendor quota reservation"
    );
    let scheduler = crate::scheduler::Scheduler::new(f.engine.clone(), 604_800_000);
    let pass = scheduler.run_pass(&[PRINCIPAL.to_string()], now_ms() + 300_001);
    assert_eq!(pass.len(), 1);
    assert_eq!(
        pass[0].cycle,
        PollCycle::Completed {
            inserted: 0,
            duplicates: 1
        },
        "the scheduler must not trip its breaker after degraded identity ticks"
    );
    f.connect_actions();
    f.sql("UPDATE github_repo_id_cache SET last_attempt_at_ms = 0");
    assert_eq!(
        f.poll(&watch),
        PollCycle::Completed {
            inserted: 0,
            duplicates: 1
        }
    );
    assert_eq!(
        f.count("event_outbox"),
        0,
        "unchanged unkeyed state stays unpublished"
    );
    f.mock.set_response_for_method(
        "list_issues",
        "",
        MockResponse::Success(json!({"issues":[issue(7,"2026-10-07T00:00:20Z")]})),
    );
    assert_eq!(
        f.poll(&watch),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    assert_eq!(f.count("event_outbox"), 1);
}

/// A store failure while preparing the `get_repository` read, before the
/// shared owner/name claim is taken, is neither a failed resolution nor a
/// failure of the watched read. The cycle publishes without the repository
/// id but records and counts nothing: the repository name is not blocked
/// for an hour, no quota is reserved, and the next poll resolves the id and
/// keys its events.
#[test]
fn a_store_failure_claiming_identity_is_not_a_failed_resolution() {
    let f = Fixture::new(true);
    let watch = f.watch("list_issues");
    f.sql("UPDATE catalog_actions SET schema_json = 'unreadable' WHERE name = 'get_repository'");
    assert_eq!(
        f.poll(&watch),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    assert!(
        f.store.repo_id_cache("owner/repo").unwrap().is_none(),
        "a store failure throttled the name as a failed resolution"
    );
    assert_eq!(f.count("github_actions_quota"), 0);
    assert_eq!(f.counter("repo_id_refresh_failed"), 0);
    assert!(f
        .mock
        .requests()
        .iter()
        .all(|r| r.action != "get_repository"));

    f.sql(&format!(
        "UPDATE catalog_actions SET schema_json = '{}' WHERE name = 'get_repository'",
        json!({"type": "object"})
    ));
    f.poll(&watch);
    assert_eq!(
        f.store
            .repo_id_cache("owner/repo")
            .unwrap()
            .and_then(|entry| entry.repo_id),
        Some(101),
        "the next poll must resolve the name"
    );
}

#[test]
fn missing_identity_grant_is_not_a_vendor_failure_or_a_watch_suspension() {
    let f = Fixture::new(true);
    f.sql("DELETE FROM grants WHERE connection_id = 'conn-github-actions'");
    let watch = f.watch("list_issues");
    assert_eq!(
        f.poll(&watch),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    assert_eq!(f.counter("repo_id_grant_missing"), 1);
    assert_eq!(f.counter("repo_id_unresolved"), 1);
    assert_eq!(
        f.mock
            .requests()
            .iter()
            .filter(|r| r.action == "get_repository")
            .count(),
        0
    );
    assert_eq!(
        f.store
            .subscription(PRINCIPAL, &watch.subscription_id)
            .unwrap()
            .unwrap()
            .consecutive_vendor_failures,
        0
    );
    assert_eq!(f.count("event_outbox"), 0);
}

#[test]
fn failed_resolution_is_shared_for_an_hour_and_failed_refresh_keeps_cached_id() {
    let f = Fixture::new(true);
    f.mock.set_response_for_method(
        "get_repository",
        "",
        MockResponse::VendorError {
            code: "http_404".into(),
            message: "missing".into(),
        },
    );
    for action in ["list_issues", "list_pull_requests", "get_latest_release"] {
        assert_eq!(
            f.poll(&f.watch(action)),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 0
            }
        );
    }
    assert_eq!(
        f.mock
            .requests()
            .iter()
            .filter(|r| r.action == "get_repository")
            .count(),
        1
    );
    assert_eq!(f.count("event_outbox"), 0);
    f.sql("UPDATE github_repo_id_cache SET last_attempt_at_ms = 0");
    let watch = f
        .store
        .list_subscriptions(PRINCIPAL, None, None)
        .unwrap()
        .into_iter()
        .find(|s| s.action == "list_issues")
        .unwrap();
    f.mock.set_response_for_method(
        "get_repository",
        "",
        MockResponse::Success(json!({"id":101})),
    );
    assert!(matches!(f.poll(&watch), PollCycle::Completed { .. }));
    assert_eq!(
        f.mock
            .requests()
            .iter()
            .filter(|r| r.action == "get_repository")
            .count(),
        2
    );
    f.refresh_due();
    f.mock.set_response_for_method(
        "get_repository",
        "",
        MockResponse::VendorError {
            code: "http_503".into(),
            message: "retry later".into(),
        },
    );
    f.mock.set_response_for_method(
        "list_issues",
        "",
        MockResponse::Success(json!({"issues":[issue(7,"2026-10-07T00:00:01Z")]})),
    );
    assert_eq!(
        f.poll(&watch),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    assert_eq!(f.counter("repo_id_refresh_failed"), 1);
    assert_eq!(
        f.store
            .repo_id_cache("owner/repo")
            .unwrap()
            .unwrap()
            .repo_id,
        Some(101)
    );
    assert_eq!(f.store.drain_event_outbox(10).unwrap()[0].repo_id, 101);
}

#[test]
fn identity_quota_deferral_polls_unkeyed_or_keeps_cached_id_and_retries_next_cycle() {
    for cached in [false, true] {
        let f = Fixture::new(true);
        let watch = f.watch("list_issues");
        if cached {
            f.store
                .record_repo_id_resolution("owner/repo", Some(101), now_ms() - 86_400_001)
                .unwrap();
        }
        f.sql(&format!(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<300)
                INSERT INTO github_actions_quota SELECT 'full-' || i, {}, 8 FROM n",
            now_ms()
        ));
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 0
            }
        );
        assert_eq!(
            f.counter(if cached {
                "repo_id_refresh_deferred"
            } else {
                "repo_id_deferred"
            }),
            1
        );
        assert_eq!(f.counter("repo_id_unresolved"), u64::from(!cached));
        assert_eq!(
            f.mock
                .requests()
                .iter()
                .filter(|r| r.action == "get_repository")
                .count(),
            0
        );
        assert_eq!(f.count("event_outbox"), i64::from(cached));
        f.sql("DELETE FROM github_actions_quota");
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 0,
                duplicates: 1
            }
        );
        assert_eq!(
            f.mock
                .requests()
                .iter()
                .filter(|r| r.action == "get_repository")
                .count(),
            1,
            "deferred resolution retries next cycle, not an hour later"
        );
    }
}

#[test]
fn changed_repository_identity_suspends_all_four_watches_before_listing_or_inserting() {
    let f = Fixture::new(true);
    let watches = [
        "list_issues",
        "list_pull_requests",
        "get_latest_release",
        "list_workflow_runs",
    ]
    .map(|action| f.watch(action));
    let unrelated = f.watch_repo("list_issues", "other", "repo");
    assert_eq!(
        f.poll(&watches[0]),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    let old_marker = f.store.drain_event_outbox(10).unwrap()[0].clone();
    let generations: Vec<_> = watches
        .iter()
        .map(|s| {
            f.store
                .subscription(PRINCIPAL, &s.subscription_id)
                .unwrap()
                .unwrap()
                .generation
        })
        .collect();
    f.refresh_due();
    f.mock.set_response_for_method(
        "get_repository",
        "",
        MockResponse::Success(json!({"id":202})),
    );
    let requests_before = f.mock.requests().len();
    assert_eq!(
        f.poll(&watches[0]),
        PollCycle::Suspended {
            reason: "repository_identity_changed".into()
        }
    );
    let requests = f.mock.requests();
    assert_eq!(requests.len(), requests_before + 1);
    assert_eq!(
        requests.last().unwrap().action,
        "get_repository",
        "identity change must not dispatch a list read"
    );
    assert_eq!(f.count("trigger_events"), 1);
    assert_eq!(f.count("event_outbox"), 1);
    assert_eq!(f.counter("repository_identity_changed"), 1);
    assert_eq!(
        f.store
            .repo_id_cache("owner/repo")
            .unwrap()
            .unwrap()
            .repo_id,
        Some(202)
    );
    for (watch, generation) in watches.iter().zip(generations) {
        let stored = f
            .store
            .subscription(PRINCIPAL, &watch.subscription_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, "suspended");
        assert_eq!(
            stored.suspended_reason.as_deref(),
            Some("repository_identity_changed")
        );
        assert_eq!(stored.generation, generation + 1);
    }
    assert_eq!(
        f.store
            .subscription(PRINCIPAL, &unrelated.subscription_id)
            .unwrap()
            .unwrap()
            .status,
        "active"
    );
    assert_eq!(
        f.store
            .canonical_event_by_key(&old_marker.event_key)
            .unwrap()
            .unwrap(),
        old_marker
    );
}
