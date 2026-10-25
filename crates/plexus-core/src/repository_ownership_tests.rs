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
            projects: Mutex::new(
                json!({"projects":[],"workspaces":[],"generation":0,"incarnation":"test"}),
            ),
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
        *self.projects.lock().unwrap() = owned_enumeration(owner, repo);
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
    fn enumerate(&self) -> Option<EnumerateReply> {
        Some(serde_json::from_value(self.projects.lock().unwrap().clone()).unwrap())
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
    let source = subc_jsonc::jsonc_to_json(include_str!("../../../catalog/github.jsonc"))
        .expect("shipped catalog is valid JSONC");
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
fn ambiguous_owner_clears_only_automatically_sourced_project_labels() {
    let (store, _, _) = fixture();
    watch(&store, "owner", "repo");
    let registry = Registry::empty();
    registry.answer("owner", "repo", RemoteResolution::Found("project".into()));
    reconcile(&store, &registry, crate::now_ms()).unwrap();
    registry.answer("owner", "repo", RemoteResolution::Ambiguous);
    reconcile(&store, &registry, crate::now_ms()).unwrap();
    assert_eq!(stamps(&store)[0].1, None);
    assert_eq!(stamps(&store)[0].2, None);
}

#[test]
fn owned_remote_uses_the_watch_resolution_once_per_pass() {
    let (store, _, _) = fixture();
    bind(&store, "owner/repo");
    watch(&store, "owner", "repo");
    let registry = Registry::empty();
    registry.own("owner", "repo");
    reconcile(&store, &registry, crate::now_ms()).unwrap();
    assert_eq!(registry.calls.lock().unwrap().len(), 1);
}

#[test]
fn ownership_pass_budget_resumes_after_the_last_processed_remote() {
    let (store, _, _) = fixture();
    watch(&store, "owner", "a");
    watch(&store, "owner", "z");
    let registry = Registry::empty();
    registry.answer("owner", "a", RemoteResolution::None);
    registry.answer("owner", "z", RemoteResolution::None);
    let first = reconcile_with_budget(&store, &registry, 1, None, || {
        std::time::Duration::from_secs(2)
    })
    .unwrap();
    assert_eq!(first.stopped_at, Some(("owner".into(), "a".into())));
    assert_eq!(registry.calls.lock().unwrap().len(), 1);
    reconcile_with_budget(&store, &registry, 2, first.stopped_at.as_ref(), || {
        std::time::Duration::from_secs(2)
    })
    .unwrap();
    assert_eq!(
        registry.calls.lock().unwrap()[1],
        ("owner".into(), "z".into())
    );
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

type WireReply = Result<Value, crate::github_identity::PrefrontalRouteError>;

struct EntorhinalPeer {
    calls: Mutex<Vec<(String, Value)>>,
    remote: WireReply,
    enumeration: WireReply,
}
impl PrefrontalRoutePeer for EntorhinalPeer {
    fn call(&self, op: &str, params: Value) -> WireReply {
        self.calls.lock().unwrap().push((op.into(), params));
        match op {
            "resolve_remote" => self.remote.clone(),
            "enumerate" => self.enumeration.clone(),
            _ => panic!("unexpected management operation: {op}"),
        }
    }
}

fn wire_registry(
    remote: WireReply,
    enumeration: WireReply,
) -> (EntorhinalRepositoryRegistry, Arc<EntorhinalPeer>) {
    let peer = Arc::new(EntorhinalPeer {
        calls: Mutex::new(vec![]),
        remote,
        enumeration,
    });
    (EntorhinalRepositoryRegistry::new(peer.clone()), peer)
}

fn found_reply(project: &str) -> Value {
    json!({"result":{"status":"found","projectId":project,"root":"/root",
        "generation":2,"incarnation":"one"}})
}

fn owned_enumeration(owner: &str, repo: &str) -> Value {
    json!({"projects":[{"projectId":"project","name":"test","roots":["/test"],
        "implicit":false,"refKind":"local","rootRecords":[{"root":"/test",
        "identity":"unbound","approval":{"state":"unapproved"},
        "remotes":[{"name":"origin","owner":owner,"repo":repo,"owned":true},
            {"name":"upstream","owner":"other","repo":"not-owned","owned":false}]}]}],
        "workspaces":[],"generation":0,"incarnation":"test"})
}

fn assert_wire_resolution(reply: WireReply, expected: RemoteResolution, message: &str) {
    let mut enumeration = owned_enumeration("owner", "repo");
    if let RemoteResolution::Found(project) = &expected {
        enumeration["projects"][0]["projectId"] = json!(project);
    }
    let (adapter, _) = wire_registry(reply, Ok(json!({"result":enumeration})));
    assert_eq!(
        adapter.resolve_remote("owner", "repo"),
        expected,
        "{message}"
    );

    let (store, _, _) = fixture();
    let watch = watch(&store, "owner", "repo");
    let seed = Registry::empty();
    seed.answer("owner", "repo", RemoteResolution::Found("old".into()));
    reconcile(&store, &seed, crate::now_ms()).unwrap();
    let report = reconcile(&store, &adapter, crate::now_ms()).unwrap();
    let (project, source) = match &expected {
        RemoteResolution::Found(project) => (Some(project.clone()), Some("entorhinal".into())),
        RemoteResolution::None | RemoteResolution::Ambiguous => (None, None),
        RemoteResolution::Unavailable => (Some("old".into()), Some("entorhinal".into())),
    };
    assert_eq!(
        stamps(&store),
        vec![(watch.subscription_id, project, source)],
        "{message}"
    );
    assert_eq!(
        report.unanswered,
        expected == RemoteResolution::Unavailable,
        "{message}"
    );

    let (store, _, _) = fixture();
    bind(&store, "owner/repo");
    let report = reconcile(&store, &adapter, crate::now_ms()).unwrap();
    let creates_pair = matches!(expected, RemoteResolution::Found(_));
    assert_eq!(
        report.created,
        if creates_pair { 2 } else { 0 },
        "{message}"
    );
    assert_eq!(
        stamps(&store).len(),
        if creates_pair { 2 } else { 0 },
        "{message}"
    );
    assert_eq!(
        report.unanswered,
        expected == RemoteResolution::Unavailable,
        "{message}"
    );
}

#[test]
fn entorhinal_requests_keep_exact_management_params() {
    let (adapter, peer) = wire_registry(
        Ok(found_reply("project")),
        Ok(json!({"result":owned_enumeration("owner", "repo")})),
    );
    adapter.resolve_remote(" Owner/\"雪 ", "Repo\\Name");
    adapter.enumerate().unwrap();
    let calls = peer.calls.lock().unwrap();
    assert_eq!(calls[0].0, "resolve_remote");
    assert_eq!(
        serde_json::to_vec(&calls[0].1).unwrap(),
        r#"{"owner":" Owner/\"雪 ","repo":"Repo\\Name"}"#.as_bytes()
    );
    assert_eq!(calls[1].0, "enumerate");
    assert_eq!(serde_json::to_vec(&calls[1].1).unwrap(), b"{}");
}

#[test]
fn entorhinal_found_confirms_project_and_creates_watches() {
    assert_wire_resolution(
        Ok(found_reply("project")),
        RemoteResolution::Found("project".into()),
        "found must confirm ownership",
    );
}

#[test]
fn entorhinal_none_clears_automatic_project_without_creating_watches() {
    assert_wire_resolution(
        Ok(json!({"result":{"status":"none","generation":2,"incarnation":"one"}})),
        RemoteResolution::None,
        "none must not confirm ownership",
    );
}

#[test]
fn entorhinal_ambiguous_does_not_confirm_ownership() {
    assert_wire_resolution(
        Ok(
            json!({"result":{"status":"ambiguous","projectIds":["project","other"],"generation":2,"incarnation":"one"}}),
        ),
        RemoteResolution::Ambiguous,
        "ambiguous status must not confirm ownership",
    );
}

#[test]
fn entorhinal_other_status_is_unanswered() {
    assert_wire_resolution(
        Ok(
            json!({"result":{"status":"future_value","projectId":"project","root":"/root","generation":2,"incarnation":"one"}}),
        ),
        RemoteResolution::Unavailable,
        "future status must remain unanswered",
    );
}

#[test]
fn entorhinal_refusals_are_unanswered() {
    for code in [
        "invalid_request",
        "invalid_params",
        "storage_unavailable",
        "store_unavailable",
        "storage_error",
        "encode_failed",
        "module_draining",
        "unknown_method",
    ] {
        assert_wire_resolution(
            Ok(json!({"code":code,"message":"refused","detail":{"reason":"test"}})),
            RemoteResolution::Unavailable,
            code,
        );
    }
}

#[test]
fn entorhinal_unknown_refusal_is_unanswered() {
    assert_wire_resolution(
        Ok(json!({"code":"future_value","message":"refused"})),
        RemoteResolution::Unavailable,
        "unknown refusal must remain unanswered",
    );
}

#[test]
fn entorhinal_remote_decode_failures_are_unanswered() {
    for reply in [
        json!({}),
        json!({"result":null}),
        json!({"status":"found","projectId":"project"}),
        json!({"result":{"status":true}}),
    ] {
        assert_wire_resolution(
            Ok(reply),
            RemoteResolution::Unavailable,
            "malformed reply must remain unanswered",
        );
    }
    for field in ["projectId", "root", "generation", "incarnation"] {
        for replacement in [None, Some(Value::Null), Some(json!([]))] {
            let mut reply = found_reply("project");
            if let Some(value) = replacement {
                reply["result"][field] = value;
            } else {
                reply["result"].as_object_mut().unwrap().remove(field);
            }
            assert_wire_resolution(Ok(reply), RemoteResolution::Unavailable, field);
        }
    }
    assert_wire_resolution(
        Ok(json!({"result":{"status":"ambiguous","generation":2,"incarnation":"one"}})),
        RemoteResolution::Unavailable,
        "ambiguous requires projectIds",
    );
    for project in ["", " \t\n"] {
        assert_wire_resolution(
            Ok(found_reply(project)),
            RemoteResolution::Unavailable,
            "blank project must remain unanswered",
        );
    }
}

#[test]
fn entorhinal_remote_transport_error_is_unanswered() {
    assert_wire_resolution(
        Err(crate::github_identity::PrefrontalRouteError::Transport),
        RemoteResolution::Unavailable,
        "transport error must remain unanswered",
    );
}

#[test]
fn entorhinal_unknown_extra_members_do_not_change_found() {
    let mut reply = found_reply("project");
    reply["future_member"] = json!({"status":"future_value"});
    reply["result"]["future_member"] = json!([1, 2]);
    assert_wire_resolution(
        Ok(reply),
        RemoteResolution::Found("project".into()),
        "extra members must be ignored",
    );
}

fn assert_enumeration_unanswered(reply: WireReply) {
    let (adapter, _) = wire_registry(Ok(found_reply("project")), reply);
    let (store, _, _) = fixture();
    bind(&store, "owner/repo");
    let report = reconcile(&store, &adapter, crate::now_ms()).unwrap();
    assert!(
        report.unanswered,
        "unsafe enumeration must remain unanswered"
    );
    assert_eq!(report.created, 0);
    assert!(stamps(&store).is_empty());
}

#[test]
fn entorhinal_enumeration_ignores_unknown_extra_members() {
    let mut reply = owned_enumeration("OWNER", "REPO");
    reply["future_member"] = json!("future_value");
    reply["projects"][0]["future_member"] = json!({});
    reply["projects"][0]["rootRecords"][0]["future_member"] = json!(false);
    reply["projects"][0]["rootRecords"][0]["remotes"][0]["future_member"] = json!([]);
    let (adapter, _) = wire_registry(
        Ok(found_reply("project")),
        Ok(json!({"result":reply,"future_member":null})),
    );
    let (store, _, _) = fixture();
    bind(&store, "owner/repo");
    let report = reconcile(&store, &adapter, crate::now_ms()).unwrap();
    assert!(!report.unanswered);
    assert_eq!(report.created, 2);
    assert_eq!(stamps(&store).len(), 2);
}

#[test]
fn entorhinal_enumeration_refusal_is_unanswered() {
    for code in ["invalid_params", "future_value"] {
        assert_enumeration_unanswered(Ok(json!({"code":code,"message":"refused","detail":null})));
    }
}

#[test]
fn entorhinal_enumeration_transport_error_is_unanswered() {
    assert_enumeration_unanswered(Err(crate::github_identity::PrefrontalRouteError::Transport));
}

#[test]
fn entorhinal_enumeration_decode_failure_rejects_the_whole_snapshot() {
    for pointer in [
        "/workspaces",
        "/projects",
        "/generation",
        "/incarnation",
        "/projects/0/projectId",
        "/projects/0/name",
        "/projects/0/roots",
        "/projects/0/implicit",
        "/projects/0/refKind",
        "/projects/0/rootRecords",
        "/projects/0/rootRecords/0/root",
        "/projects/0/rootRecords/0/remotes",
        "/projects/0/rootRecords/0/identity",
        "/projects/0/rootRecords/0/approval",
        "/projects/0/rootRecords/0/remotes/0/name",
        "/projects/0/rootRecords/0/remotes/0/owner",
        "/projects/0/rootRecords/0/remotes/0/repo",
        "/projects/0/rootRecords/0/remotes/0/owned",
    ] {
        let mut reply = owned_enumeration("owner", "repo");
        *reply.pointer_mut(pointer).unwrap() = json!({});
        assert_enumeration_unanswered(Ok(json!({"result":reply})));
    }
    let mut reply = owned_enumeration("owner", "repo");
    reply["projects"]
        .as_array_mut()
        .unwrap()
        .push(json!({"projectId":"malformed"}));
    assert_enumeration_unanswered(Ok(json!({"result":reply})));
    for reply in [
        json!({}),
        json!({"result":null}),
        json!({"result":{"projects":[]}}),
    ] {
        assert_enumeration_unanswered(Ok(reply));
    }
}

#[test]
fn entorhinal_enumeration_ignores_unknown_vocabulary() {
    let mut baseline = owned_enumeration("OWNER", "REPO");
    baseline["projects"][0]["rootRecords"][0]["rootKey"] = json!({"kind":"remote","rootKey":"key"});
    baseline["projects"][0]["rootRecords"][0]["incarnation"] =
        json!({"kind":"token","value":"token"});
    let fields = [
        "/projects/0/refKind",
        "/projects/0/rootRecords/0/identity",
        "/projects/0/rootRecords/0/approval/state",
        "/projects/0/rootRecords/0/rootKey/kind",
        "/projects/0/rootRecords/0/incarnation/kind",
    ];
    let expected = BTreeMap::from([(
        ("owner".into(), "repo".into()),
        BTreeSet::from(["project".into()]),
    )]);
    // Check known values, each unknown value independently, then all unknown values together.
    for changed in std::iter::once(vec![])
        .chain(fields.iter().map(|field| vec![*field]))
        .chain(std::iter::once(fields.to_vec()))
    {
        let mut reply = baseline.clone();
        for field in &changed {
            *reply.pointer_mut(field).unwrap() = json!("future_value");
        }
        let (adapter, _) = wire_registry(Ok(found_reply("project")), Ok(json!({"result":reply})));
        let ownership = adapter.enumerate().and_then(owned_repositories);
        assert_eq!(
            ownership,
            Some(expected.clone()),
            "ignored enumeration vocabulary must not change ownership: {changed:?}"
        );
        let (store, _, _) = fixture();
        bind(&store, "owner/repo");
        let report = reconcile(&store, &adapter, crate::now_ms()).unwrap();
        assert!(
            !report.unanswered,
            "ignored metadata must remain answered: {changed:?}"
        );
        assert_eq!(report.created, 2);
        assert!(stamps(&store)
            .iter()
            .all(|(_, project, source)| project.as_deref() == Some("project")
                && source.as_deref() == Some("entorhinal")));
    }
}

#[test]
fn entorhinal_enumeration_skips_projects_without_root_records() {
    for roots in [None, Some(Value::Null)] {
        let mut reply = owned_enumeration("owner", "repo");
        let mut project = reply["projects"][0].clone();
        project["projectId"] = json!("without-roots");
        if let Some(roots) = roots {
            project["rootRecords"] = roots;
        } else {
            project.as_object_mut().unwrap().remove("rootRecords");
        }
        reply["projects"].as_array_mut().unwrap().insert(0, project);
        let (adapter, _) = wire_registry(Ok(found_reply("project")), Ok(json!({"result":reply})));
        assert_eq!(
            adapter.enumerate().and_then(owned_repositories),
            Some(BTreeMap::from([(
                ("owner".into(), "repo".into()),
                BTreeSet::from(["project".into()]),
            )]))
        );
    }
}

#[test]
fn entorhinal_enumeration_keeps_empty_components_unowned() {
    for pointer in [
        "/projects/0/projectId",
        "/projects/0/rootRecords/0/remotes/0/owner",
        "/projects/0/rootRecords/0/remotes/0/repo",
    ] {
        let mut reply = owned_enumeration("owner", "repo");
        *reply.pointer_mut(pointer).unwrap() = json!("");
        let (adapter, _) = wire_registry(Ok(found_reply("project")), Ok(json!({"result":reply})));
        assert!(owned_repositories(adapter.enumerate().unwrap())
            .unwrap()
            .is_empty());
    }
}

#[test]
fn entorhinal_vendored_samples_replay_through_the_registry() {
    use sha2::{Digest, Sha256};
    let remote_bytes = include_bytes!("../tests/fixtures/project-resolve-v1/resolve-remote.json");
    let enumerate_bytes = include_bytes!("../tests/fixtures/project-resolve-v1/enumerate.json");
    assert_eq!(
        hex::encode(Sha256::digest(remote_bytes)),
        "e0504720dc0f4a81b532fbe4e0cfa4a43d0fa1b218f703cbc3efca5387e17cba"
    );
    assert_eq!(
        hex::encode(Sha256::digest(enumerate_bytes)),
        "89afedb88fa4ddec219f4932df22f26ca8395022c5c1dd399e3e50c9d50b94dd"
    );
    let samples: Vec<Value> = serde_json::from_slice(remote_bytes).unwrap();
    let expected = [
        (
            json!({"owner":"example-org","repo":"widgets"}),
            RemoteResolution::Found("pj-widgets".into()),
        ),
        (
            json!({"owner":"example-org","repo":"missing"}),
            RemoteResolution::None,
        ),
        (
            json!({"owner":"example-org","repo":"shared"}),
            RemoteResolution::Ambiguous,
        ),
        (
            json!({"owner":"EXAMPLE-ORG","repo":"WiDgEtS"}),
            RemoteResolution::Found("pj-widgets".into()),
        ),
        (
            json!({"owner":"example-org","repo":"hidden"}),
            RemoteResolution::Found("pj-unreadable".into()),
        ),
        (
            json!({"owner":"example-org","repo":"hidden"}),
            RemoteResolution::None,
        ),
        (
            json!({"owner":"example-org","repo":"widgets"}),
            RemoteResolution::Found("pj-widgets".into()),
        ),
        (json!({}), RemoteResolution::Unavailable),
    ];
    assert_eq!(
        samples.len(),
        expected.len(),
        "unrecognised resolve_remote sample"
    );
    for (sample, (params, decision)) in samples.iter().zip(expected) {
        assert_eq!(
            sample["request"],
            json!({"method":"resolve_remote","params":params}),
            "unrecognised resolve_remote sample"
        );
        let (adapter, peer) = wire_registry(
            Ok(sample["reply"].clone()),
            Ok(json!({"result":owned_enumeration("owner", "repo")})),
        );
        // The malformed-request vector supplies a refusal; Plexus always sends both params.
        let owner = params["owner"].as_str().unwrap_or("");
        let repo = params["repo"].as_str().unwrap_or("");
        assert_eq!(adapter.resolve_remote(owner, repo), decision);
        if params.get("owner").is_some() {
            assert_eq!(peer.calls.lock().unwrap()[0].1, params);
        }
        assert_wire_resolution(
            Ok(sample["reply"].clone()),
            decision,
            "vendored resolve_remote decision",
        );
    }
    let samples: Vec<Value> = serde_json::from_slice(enumerate_bytes).unwrap();
    assert_eq!(samples.len(), 1, "unrecognised enumerate sample");
    assert_eq!(
        samples[0]["request"],
        json!({"method":"enumerate","params":{}})
    );
    let (adapter, _) = wire_registry(Ok(found_reply("project")), Ok(samples[0]["reply"].clone()));
    let snapshot = adapter.enumerate().unwrap();
    assert_eq!(
        snapshot
            .projects
            .iter()
            .map(|p| p.project_id.as_str())
            .collect::<Vec<_>>(),
        vec!["pj-dashboard-editor", "pj-dashboard-terminal"]
    );
    assert!(owned_repositories(snapshot).unwrap().is_empty());
    let (store, _, _) = fixture();
    bind(&store, "owner/repo");
    let report = reconcile(&store, &adapter, crate::now_ms()).unwrap();
    assert!(!report.unanswered);
    assert_eq!(report.created, 0);
    assert!(stamps(&store).is_empty());
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
