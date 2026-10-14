use super::*;
use crate::credentials::{ResolvedCredential, StubCredentialSource};
use crate::governance::{GovernanceEngine, AUTHORITY_POLL};
use crate::poller::{iso8601, PollCycle, Poller};
use crate::storage::{CatalogActionInput, GrantInput, TriggerSubscription};
use crate::transport::{Transport, TransportRequest, TransportResponse};
use crate::Ceiling;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

#[derive(Default)]
struct Registry {
    replies: Mutex<BTreeMap<(String, String), RemoteResolution>>,
    calls: Mutex<Vec<(String, String)>>,
    projects: Mutex<Value>,
}
impl Registry {
    fn empty() -> Self {
        Self {
            projects: Mutex::new(json!({"projects":[]})),
            ..Default::default()
        }
    }
    fn answer(&self, owner: &str, repo: &str, reply: RemoteResolution) {
        self.replies
            .lock()
            .unwrap()
            .insert((owner.into(), repo.into()), reply);
    }
    fn own(&self, owner: &str, repo: &str) {
        self.answer(
            &owner.to_ascii_lowercase(),
            &repo.to_ascii_lowercase(),
            RemoteResolution::Found("project".into()),
        );
        *self.projects.lock().unwrap() = json!({"projects":[{"projectId":"project","rootRecords":[
            {"root":"/test","remotes":[{"name":"origin","owner":owner,"repo":repo,"owned":true},
            {"name":"upstream","owner":"other","repo":"not-owned","owned":false}]}]}]});
    }
}
impl RepositoryRegistry for Registry {
    fn resolve_remote(&self, owner: &str, repo: &str) -> RemoteResolution {
        self.calls.lock().unwrap().push((owner.into(), repo.into()));
        self.replies
            .lock()
            .unwrap()
            .get(&(owner.into(), repo.into()))
            .cloned()
            .unwrap_or(RemoteResolution::Unavailable)
    }
    fn enumerate(&self) -> Option<Value> {
        Some(self.projects.lock().unwrap().clone())
    }
}

#[derive(Default)]
struct Github {
    items: Mutex<Vec<Value>>,
    requests: Mutex<Vec<TransportRequest>>,
}
impl Transport for Github {
    fn dispatch(&self, request: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
        let response = match request.action.as_str() {
            "list_issues" => {
                // Model GitHub's server-side since filter independently of the
                // cursor seed. Old items still exist, but are not on this page.
                let since = request
                    .args
                    .get("since")
                    .and_then(Value::as_str)
                    .and_then(iso8601::parse_to_millis);
                let items: Vec<_> = self
                    .items
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|item| {
                        since.is_none_or(|since| {
                            iso8601::parse_to_millis(item["updated_at"].as_str().unwrap()).unwrap()
                                >= since
                        })
                    })
                    .cloned()
                    .collect();
                json!({"issues":items,"pageInfo":{"hasNextPage":false}})
            }
            "list_pull_requests" => json!(self.items.lock().unwrap().clone()),
            "issue_read" | "pull_request_read" => json!([]),
            _ => json!({}),
        };
        self.requests.lock().unwrap().push(request);
        TransportResponse::success(response)
    }
}

type Engine = GovernanceEngine<StubCredentialSource, Github>;
fn fixture() -> (Arc<PlexusStore>, Engine, Arc<Github>) {
    static ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: format!(
                "ownership-tests-{}",
                ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap(),
    );
    let source = include_str!("../../../catalog/github.jsonc")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let manifest = crate::manifest::ingest_value(serde_json::from_str(&source).unwrap()).unwrap();
    store
        .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &manifest)
        .unwrap();
    let credentials = Arc::new(StubCredentialSource::default());
    for (connection, action) in [
        ("conn-github", "list_issues"),
        ("conn-github-prs", "list_pull_requests"),
        ("conn-github-comments", "issue_read"),
        ("conn-github-pr-comments", "pull_request_read"),
    ] {
        store
            .insert_connection("direct", connection, "github", "pending", &json!({}))
            .unwrap();
        store.upsert_catalog_action(&CatalogActionInput {
            connection_id: connection.into(), principal: "direct".into(), name: action.into(), title: None,
            schema: json!({"type":"object","properties":{
                "owner":{"type":"string"},"repo":{"type":"string"},"since":{"type":"string"},
                "orderBy":{"type":"string"},"direction":{"type":"string"},"perPage":{"type":"integer"},
                "after":{"type":"string"},"sort":{"type":"string"},"state":{"type":"string"},
                "method":{"type":"string"},"issue_number":{"type":"integer"},"pullNumber":{"type":"integer"}},
                "required":["owner","repo"]}),
            schema_hash: format!("hash-{action}"), risk: "read".into(), severity: "S2".into(),
            ask_first: false, status: "active".into(), quarantine_reason: None, reconciliation: None,
        }).unwrap();
        let handle = format!("test:{connection}").into_bytes();
        let ticket = store
            .create_binding_ticket_bounded(
                "direct",
                connection,
                "credential_reference",
                &handle,
                &Ceiling::unrestricted_for_tests(),
            )
            .unwrap();
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .unwrap()
            .unwrap();
        credentials.set_success(&handle, b"vendor-token".to_vec(), None, 1);
        store
            .insert_grant(&GrantInput {
                grant_id: format!("poll-{connection}"),
                principal: "direct".into(),
                connection_id: connection.into(),
                grantee_principal: "direct".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["*".into()],
                authority_kind: AUTHORITY_POLL.into(),
                expires_at: None,
            })
            .unwrap();
    }
    let github = Arc::new(Github::default());
    let engine = GovernanceEngine::new(store.clone(), credentials, github.clone());
    (store, engine, github)
}
fn bind(store: &PlexusStore, repository: &str) {
    store
        .insert_connection("direct", "bot", "github_rest", "pending", &json!({}))
        .unwrap();
    store
        .put_github_handle(&crate::storage::github_store::GithubHandle {
            app_handle_id: "handle".into(),
            agent_id: "agent".into(),
            app_id: 1,
            installation_id: None,
            credential_reference: "github_app:test".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: None,
            connection_principal: "direct".into(),
            connection_id: "bot".into(),
        })
        .unwrap();
    store.bind_github_repo(repository, "handle").unwrap();
}

fn watch(store: &PlexusStore, owner: &str, repo: &str) -> TriggerSubscription {
    store
        .subscribe_with_cursor_state(
            "direct",
            "conn-github",
            "list_issues",
            300,
            &json!({}),
            &json!({"owner":owner,"repo":repo}),
        )
        .unwrap()
        .unwrap()
}
fn stamps(store: &PlexusStore) -> Vec<(String, Option<String>, Option<String>)> {
    store
        .repository_watches()
        .unwrap()
        .into_iter()
        .map(|w| (w.id, w.project_id, w.source))
        .collect()
}
fn audit_count(store: &PlexusStore) -> usize {
    store
        .list_audit("direct")
        .unwrap()
        .iter()
        .filter(|row| row.reason_code == "repository_ownership")
        .count()
}

#[test]
fn found_converts_even_equal_hand_stamp_and_audits_once() {
    let (store, _, _) = fixture();
    let watch = watch(&store, "Owner", "Repo");
    store
        .set_subscription_project("direct", &watch.subscription_id, Some("project"))
        .unwrap();
    let registry = Registry::empty();
    registry.answer("owner", "repo", RemoteResolution::Found("project".into()));
    assert_eq!(
        reconcile(&store, &registry, crate::now_ms())
            .unwrap()
            .changed,
        1
    );
    assert_eq!(stamps(&store)[0].2.as_deref(), Some("entorhinal"));
    assert_eq!(
        reconcile(&store, &registry, crate::now_ms())
            .unwrap()
            .changed,
        0
    );
    assert_eq!(audit_count(&store), 1);
}

#[test]
fn none_clears_only_entorhinal_and_reports_hand() {
    let (store, _, _) = fixture();
    let ento = watch(&store, "owner", "ento");
    let hand = watch(&store, "owner", "hand");
    store
        .set_subscription_project("direct", &hand.subscription_id, Some("manual"))
        .unwrap();
    let registry = Registry::empty();
    registry.answer("owner", "ento", RemoteResolution::Found("project".into()));
    registry.answer("owner", "hand", RemoteResolution::None);
    reconcile(&store, &registry, crate::now_ms()).unwrap();
    registry.answer("owner", "ento", RemoteResolution::None);
    let report = reconcile(&store, &registry, crate::now_ms()).unwrap();
    let rows = stamps(&store);
    assert!(rows
        .iter()
        .any(|(id, p, s)| id == &ento.subscription_id && p.is_none() && s.is_none()));
    assert!(rows.iter().any(|(id, p, s)| id == &hand.subscription_id
        && p.as_deref() == Some("manual")
        && s.as_deref() == Some("hand")));
    assert_eq!(report.unconfirmed_hand, vec![hand.subscription_id]);
    assert_eq!(audit_count(&store), 2);
}

#[test]
fn ambiguous_and_no_answer_leave_every_stamp_unchanged() {
    let (store, _, _) = fixture();
    let w = watch(&store, "owner", "repo");
    store
        .set_subscription_project("direct", &w.subscription_id, Some("manual"))
        .unwrap();
    let before = stamps(&store);
    let registry = Registry::empty();
    registry.answer("owner", "repo", RemoteResolution::Ambiguous);
    reconcile(&store, &registry, crate::now_ms()).unwrap();
    assert_eq!(stamps(&store), before);
    registry.answer("owner", "repo", RemoteResolution::Unavailable);
    assert!(
        reconcile(&store, &registry, crate::now_ms())
            .unwrap()
            .unanswered
    );
    assert_eq!(stamps(&store), before);
    assert_eq!(audit_count(&store), 0);
}

#[test]
fn deliver_to_and_existing_cursor_and_connection_are_untouched() {
    let (store, _, _) = fixture();
    let w = watch(&store, "owner", "repo");
    store
        .set_subscription_deliver_to("direct", &w.subscription_id, Some("agent-override"))
        .unwrap();
    let registry = Registry::empty();
    registry.answer("owner", "repo", RemoteResolution::Found("project".into()));
    reconcile(&store, &registry, crate::now_ms()).unwrap();
    let after = store
        .subscription("direct", &w.subscription_id)
        .unwrap()
        .unwrap();
    assert_eq!(after.deliver_to.as_deref(), Some("agent-override"));
    assert_eq!(after.cursor_state, w.cursor_state);
    assert_eq!(after.connection_id, w.connection_id);
}

#[test]
fn case_insensitive_watches_resolve_once_per_remote() {
    let (store, _, _) = fixture();
    watch(&store, "Owner", "Repo");
    watch(&store, "OWNER", "REPO");
    let registry = Registry::empty();
    registry.answer("owner", "repo", RemoteResolution::Found("project".into()));
    assert_eq!(
        reconcile(&store, &registry, crate::now_ms())
            .unwrap()
            .changed,
        2
    );
    assert_eq!(
        *registry.calls.lock().unwrap(),
        vec![("owner".into(), "repo".into())]
    );
}

#[test]
fn hourly_throttle_runs_on_scheduler_pass_and_defers_unanswered() {
    let (store, engine, _) = fixture();
    watch(&store, "owner", "repo");
    let registry = Arc::new(Registry::empty());
    let scheduler = crate::scheduler::Scheduler::new(engine, 604_800_000)
        .with_repository_registry(registry.clone());
    for now in [100, 101, RECONCILE_INTERVAL_MS + 99] {
        scheduler.run_pass(&[], now);
    }
    assert_eq!(registry.calls.lock().unwrap().len(), 1);
    scheduler.run_pass(&[], RECONCILE_INTERVAL_MS + 100);
    assert_eq!(registry.calls.lock().unwrap().len(), 2);
}

#[test]
fn stop_at_first_unanswered_defers_remaining_and_enumeration() {
    let (store, _, _) = fixture();
    watch(&store, "owner", "a");
    watch(&store, "owner", "b");
    let registry = Registry::empty();
    registry.own("owner", "new");
    registry.answer("owner", "b", RemoteResolution::Found("project".into()));
    assert!(
        reconcile(&store, &registry, crate::now_ms())
            .unwrap()
            .unanswered
    );
    assert_eq!(
        *registry.calls.lock().unwrap(),
        vec![("owner".into(), "a".into())]
    );
    assert_eq!(stamps(&store).len(), 2);
    assert!(stamps(&store)
        .iter()
        .all(|(_, p, s)| p.is_none() && s.is_none()));
}

#[test]
fn creates_missing_pair_with_reviewed_shape_and_no_duplicate_after_restart() {
    let (store, _, _) = fixture();
    bind(&store, "owner/repo");
    let registry = Registry::empty();
    registry.own("OWNER", "REPO");
    let now = crate::now_ms();
    assert_eq!(reconcile(&store, &registry, now).unwrap().created, 2);
    let rows = store.list_subscriptions("direct", None, None).unwrap();
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.principal, "direct");
        assert_eq!(row.cadence_s, 300);
        assert_eq!(row.fixed_args, json!({"owner":"owner","repo":"repo"}));
        assert_eq!(row.cursor_state, json!({"watermark_ms":now}));
        assert_eq!(row.project_id.as_deref(), Some("project"));
        assert!(row.deliver_to.is_none());
        let actor = row.actor_source.as_ref().unwrap();
        if row.action == "list_issues" {
            assert_eq!(row.connection_id, "conn-github");
            assert_eq!(row.cursor_kind, "ordered_timestamp");
            assert_eq!(actor.connection_id, "conn-github-comments");
            assert_eq!(actor.action, "issue_read");
            assert_eq!(actor.methods, vec!["get_comments"]);
        } else {
            assert_eq!(row.action, "list_pull_requests");
            assert_eq!(row.connection_id, "conn-github-prs");
            assert_eq!(row.cursor_kind, "sorted_head");
            assert_eq!(actor.connection_id, "conn-github-pr-comments");
            assert_eq!(actor.action, "pull_request_read");
            assert_eq!(actor.methods, vec!["get_comments", "get_review_comments"]);
        }
    }
    assert!(stamps(&store)
        .iter()
        .all(|(_, _, s)| s.as_deref() == Some("entorhinal")));
    // A fresh throttle simulates a process restart. The watches already stored must stop the second pass from creating duplicates.
    assert_eq!(
        reconcile(&store, &registry, now + RECONCILE_INTERVAL_MS)
            .unwrap()
            .created,
        0
    );
    assert_eq!(
        store
            .list_subscriptions("direct", None, None)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(audit_count(&store), 2);
}

#[test]
fn missing_prerequisite_never_mints_half_a_pair() {
    let (store, _, _) = fixture();
    bind(&store, "owner/repo");
    store
        .revoke_grant("direct", "poll-conn-github-prs")
        .unwrap();
    let registry = Registry::empty();
    registry.own("owner", "repo");
    assert_eq!(
        reconcile(&store, &registry, crate::now_ms())
            .unwrap()
            .created,
        0
    );
    assert!(stamps(&store).is_empty());
    assert_eq!(audit_count(&store), 0);
}

#[test]
fn existing_issue_is_not_duplicated_when_only_pr_is_missing() {
    let (store, _, _) = fixture();
    bind(&store, "owner/repo");
    watch(&store, "OWNER", "REPO");
    let registry = Registry::empty();
    registry.own("owner", "repo");
    assert_eq!(
        reconcile(&store, &registry, crate::now_ms())
            .unwrap()
            .created,
        1
    );
    assert_eq!(stamps(&store).len(), 2);
}

fn item(number: i64, at: i64) -> Value {
    json!({"number":number,"updated_at":iso8601::format_millis(at),"user":{"login":"author"}})
}
#[test]
fn seeded_pair_real_poller_excludes_history_then_emits_later_activity() {
    let (store, engine, github) = fixture();
    bind(&store, "owner/repo");
    let registry = Registry::empty();
    registry.own("owner", "repo");
    let now = crate::now_ms();
    reconcile(&store, &registry, now).unwrap();
    let rows = store.list_subscriptions("direct", None, None).unwrap();
    let poller = Poller::new(engine);
    *github.items.lock().unwrap() = vec![item(1, now - 86_400_000)];
    for row in &rows {
        for _ in 0..2 {
            let cycle = poller.poll_once("direct", &row.subscription_id);
            assert!(matches!(cycle, PollCycle::Completed { .. }), "{cycle:?}");
            assert!(
                store
                    .list_events("direct", None, Some(&row.subscription_id))
                    .unwrap()
                    .is_empty(),
                "{} backfilled",
                row.action
            );
        }
    }
    *github.items.lock().unwrap() = vec![item(2, now + 60_000), item(1, now - 86_400_000)];
    for row in &rows {
        let cycle = poller.poll_once("direct", &row.subscription_id);
        assert!(matches!(cycle, PollCycle::Completed { .. }), "{cycle:?}");
        let events = store
            .list_events("direct", None, Some(&row.subscription_id))
            .unwrap();
        assert_eq!(events.len(), 1, "{}: {events:?}", row.action);
        assert_eq!(events[0].vendor_event_id.as_deref(), Some("2"));
    }
    let requests = github.requests.lock().unwrap();
    assert!(requests
        .iter()
        .any(|r| r.action == "list_issues" && r.args.get("since").is_some()));
}

#[test]
fn entorhinal_adapter_uses_management_ops_and_result_envelope() {
    struct Peer {
        calls: Mutex<Vec<(String, Value)>>,
        reply: Mutex<Result<Value, crate::github_identity::PrefrontalRouteError>>,
    }
    impl PrefrontalRoutePeer for Peer {
        fn call(
            &self,
            op: &str,
            params: Value,
        ) -> Result<Value, crate::github_identity::PrefrontalRouteError> {
            self.calls.lock().unwrap().push((op.into(), params));
            self.reply.lock().unwrap().clone()
        }
    }
    let peer = Arc::new(Peer {
        calls: Mutex::new(vec![]),
        reply: Mutex::new(Ok(json!({"result":{
        "status":"found","projectId":"project","root":"/root","generation":2,"incarnation":"one"}}))),
    });
    let adapter = EntorhinalRepositoryRegistry::new(peer.clone());
    assert_eq!(
        adapter.resolve_remote("Owner", "Repo"),
        RemoteResolution::Found("project".into())
    );
    assert_eq!(
        peer.calls.lock().unwrap()[0],
        (
            "resolve_remote".into(),
            json!({"owner":"Owner","repo":"Repo"})
        )
    );
    for (status, expected) in [
        ("none", RemoteResolution::None),
        ("ambiguous", RemoteResolution::Ambiguous),
        ("unknown", RemoteResolution::Unavailable),
    ] {
        *peer.reply.lock().unwrap() =
            Ok(json!({"result":{"status":status,"generation":3,"incarnation":"one"}}));
        assert_eq!(adapter.resolve_remote("Owner", "Repo"), expected);
    }
    *peer.reply.lock().unwrap() = Err(crate::github_identity::PrefrontalRouteError::Transport);
    assert_eq!(
        adapter.resolve_remote("Owner", "Repo"),
        RemoteResolution::Unavailable
    );
    *peer.reply.lock().unwrap() =
        Ok(json!({"result":{"projects":[],"generation":3,"incarnation":"one"}}));
    assert_eq!(adapter.enumerate().unwrap()["projects"], json!([]));
    assert_eq!(
        peer.calls.lock().unwrap().last().unwrap(),
        &("enumerate".into(), json!({}))
    );
}

#[test]
fn owned_but_unbound_remote_creates_nothing_and_is_summarized_once() {
    let (store, _, _) = fixture();
    let registry = Registry::empty();
    registry.own("OWNER", "REPO");
    // Duplicate roots for the same remote must not duplicate the summary.
    let root = registry.projects.lock().unwrap()["projects"][0]["rootRecords"][0].clone();
    registry.projects.lock().unwrap()["projects"][0]["rootRecords"]
        .as_array_mut()
        .unwrap()
        .push(root);
    let report = reconcile(&store, &registry, crate::now_ms()).unwrap();
    assert_eq!(report.created, 0);
    assert_eq!(report.unbound_owned_remotes, vec!["owner/repo"]);
    assert!(stamps(&store).is_empty());
    assert_eq!(audit_count(&store), 0);
}

#[test]
fn case_only_bot_binding_match_creates_owned_pair() {
    let (store, _, _) = fixture();
    bind(&store, "OwNeR/RePo");
    let registry = Registry::empty();
    registry.own("OWNER", "REPO");
    let report = reconcile(&store, &registry, crate::now_ms()).unwrap();
    assert_eq!(report.created, 2);
    assert!(report.unbound_owned_remotes.is_empty());
    assert_eq!(stamps(&store).len(), 2);
}

#[test]
fn unconfirmed_hand_watches_exclude_unanswered_and_unqueried_watches() {
    let (store, _, _) = fixture();
    let mut watches = Vec::new();
    for repo in ["a", "b", "c", "d"] {
        let row = watch(&store, "owner", repo);
        store
            .set_subscription_project("direct", &row.subscription_id, Some("manual"))
            .unwrap();
        watches.push(row);
    }
    let before = stamps(&store);
    let registry = Registry::empty();
    registry.answer("owner", "a", RemoteResolution::None);
    registry.answer("owner", "b", RemoteResolution::Ambiguous);
    registry.answer("owner", "c", RemoteResolution::Unavailable);
    registry.answer("owner", "d", RemoteResolution::Found("not-queried".into()));
    let report = reconcile(&store, &registry, crate::now_ms()).unwrap();
    let mut unconfirmed = vec![
        watches[0].subscription_id.clone(),
        watches[1].subscription_id.clone(),
    ];
    unconfirmed.sort();
    let mut deferred = vec![
        watches[2].subscription_id.clone(),
        watches[3].subscription_id.clone(),
    ];
    deferred.sort();
    assert_eq!(
        report.unconfirmed_hand, unconfirmed,
        "only answered non-Found watches are unconfirmed"
    );
    assert_eq!(report.deferred_hand, deferred);
    assert!(report.unanswered);
    assert_eq!(report.stopped_at, Some(("owner".into(), "c".into())));
    assert_eq!(registry.calls.lock().unwrap().len(), 3);
    assert_eq!(stamps(&store), before);
}
