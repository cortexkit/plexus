use super::*;
use plexus_core::agent_registry::{AgentLookup, StubAgentRegistry};
use plexus_core::credentials::ResolvedCredential;
use plexus_core::github::{
    agent_policy::{check_github, ActivePolicy},
    control::{self, InstallationReader, Inventory, InventoryHandle},
    credential::HandleCredentialProvider,
};

const SLUG: &str = "attested-vector";
const RECORD: &str = "github_app:attested-vector";
const AGENT: &str = "agent_0123456789abcdef";
const APP_ID: i64 = 9_007_199_254_740_993;
const CONNECTION: &str = "github-handle-attested-vector";

#[derive(Default)]
struct OwnToken(AtomicUsize);

impl HandleCredentialProvider for OwnToken {
    fn prepare(
        &self,
        handle: &str,
        generation: i64,
        reference: &str,
    ) -> Result<ResolvedCredential, &'static str> {
        assert_eq!((handle, generation, reference), (SLUG, 0, RECORD));
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(ResolvedCredential::new(
            b"installation-token".to_vec(),
            None,
            1,
        ))
    }

    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

struct Installation(bool);

impl InstallationReader for Installation {
    fn repositories_page(
        &self,
        token: &ResolvedCredential,
        _: usize,
        _: usize,
    ) -> Result<Value, String> {
        assert_eq!(token.payload(), b"installation-token");
        if !self.0 {
            return Err("test: connection failed".into());
        }
        Ok(
            json!({"total_count":2, "repository_selection":"selected", "repositories":[
                {"full_name":"org/one"}, {"full_name":"org/two"}
            ]}),
        )
    }
}

struct Fixture {
    state: Arc<ModuleState>,
    registry: Arc<StubAgentRegistry>,
    token: Arc<OwnToken>,
    watcher: Reconciler,
}

impl Fixture {
    fn new(lookup: AgentLookup, prove: bool) -> Self {
        let store = Arc::new(crate::test_support::open_memory_store("vault-app-import"));
        let catalog = include_str!("../../../catalog/github_rest.jsonc");
        let manifest = plexus_core::ingest_value(
            serde_json::from_str(&subc_jsonc::jsonc_to_json(catalog).unwrap()).unwrap(),
        )
        .unwrap();
        store.upsert_manifest("system", &manifest).unwrap();
        let mut runtime = crate::runtime_for_test(store);
        let registry = Arc::new(StubAgentRegistry::with_default_response(lookup));
        let token = Arc::new(OwnToken::default());
        runtime.agent_registry = registry.clone();
        runtime.github_handle_credentials = Some(token.clone());
        runtime.github_control_reader = Some(Arc::new(Installation(prove)));
        Self {
            state: Arc::new(ModuleState {
                health: Arc::new(crate::health::HealthState::new()),
                runtime,
            }),
            registry,
            token,
            watcher: Reconciler::default(),
        }
    }

    fn reconcile(&mut self, reply: &Value) {
        self.watcher
            .reconcile(&self.state, reply, 17, true)
            .unwrap();
    }

    fn attest(&mut self) {
        self.reconcile(&vault_case("github_app_attestation"));
    }

    fn handle(
        &self,
    ) -> Option<(
        plexus_core::storage::github_store::GithubHandle,
        Vec<String>,
    )> {
        self.state.store().github_handle_and_bindings(SLUG).unwrap()
    }

    fn imports(&self) -> Value {
        match self.state.health.report() {
            subc_protocol::session::ModuleControlResponse::HealthCheck {
                metrics: Some(metrics),
                ..
            } => metrics["agentPolicy"]["imports"].clone(),
            other => panic!("expected health metrics: {other:?}"),
        }
    }
}

#[test]
fn attested_app_imports_only_the_reviewed_module_grants_and_registers_transport() {
    let mut f = Fixture::new(AgentLookup::Known, true);
    f.attest();
    let (handle, bindings) = f.handle().expect("attested vault App should import");
    let store = f.state.store();
    assert_eq!(store.github_handles_for_agent(AGENT).unwrap().len(), 1);
    assert_eq!(handle.agent_id, AGENT);
    assert_eq!(handle.app_id, APP_ID);
    assert_eq!(handle.credential_reference, RECORD);
    assert_eq!(handle.connection_id, CONNECTION);
    assert_eq!(handle.status, "enabled");
    assert!(handle.proven_at.is_some());
    assert!(bindings.is_empty());
    assert_eq!(f.token.0.load(Ordering::SeqCst), 1);
    assert!(f.state.runtime.rest_transport.has_connection(CONNECTION));
    assert!(store.grants_held_by_agent(AGENT).unwrap().is_empty());
    let grants = store.list_all_grants(OWNER).unwrap();
    let expected: &[(&str, &str, &str, &[&str])] = &[
        (
            "reserved:aft",
            "invoke",
            "write",
            &[
                "github.actions.job.get",
                "github.actions.job_log",
                "github.issue.get",
                "github.issue.search",
                "github.issue_comment.get",
                "github.issue_comments.list",
                "github.pr.review_threads",
                "github.pull_request.get",
                "github.pull_request.queue_state.get",
                "github.pulls.open",
                "github.repo.get",
                "github.search.code",
                "github.search.issues",
                "github.review_thread.get",
                "github.stack.get",
                "add_issue_assignees",
                "add_issue_comment",
                "add_issue_labels",
                "add_pr_review",
                "add_reaction",
                "add_to_pull_request_stack",
                "close_issue",
                "convert_pull_request_to_draft",
                "create_issue",
                "create_pull_request",
                "create_pull_request_stack",
                "edit_issue",
                "edit_pull_request",
                "mark_pull_request_ready",
                "remove_issue_assignees",
                "remove_issue_label",
                "reopen_issue",
                "reply_to_review_comment",
                "resolve_review_thread",
                "unresolve_review_thread",
                "unstack_pull_requests",
                "update_issue_comment",
                "dequeue_pull_request",
                "enqueue_pull_request",
            ],
        ),
        (
            "reserved:prefrontal",
            "invoke",
            "write",
            &[
                "github.issue.get",
                "github.issue_comments.list",
                "github.issue.search",
                "github.pr.review_threads",
                "add_reaction",
            ],
        ),
        (
            "reserved:basal",
            "invoke",
            "write",
            &[
                "add_issue_assignees",
                "add_issue_comment",
                "add_issue_labels",
                "add_pr_review",
                "add_reaction",
                "close_issue",
                "create_issue",
                "create_pull_request",
                "edit_issue",
                "github.issue.get",
                "github.issue_comment.get",
                "github.issue_comments.list",
                "remove_issue_assignees",
                "remove_issue_label",
                "reopen_issue",
                "update_issue_comment",
            ],
        ),
        ("direct", "poll", "read", &["github.issue_timeline.list"]),
    ];
    assert_eq!(grants.len(), expected.len());
    let selectors = |actions: &[String]| actions.iter().cloned().collect::<BTreeSet<_>>();
    for (module, kind, risk, actions) in expected {
        let grant = grants
            .iter()
            .find(|grant| grant.grantee_principal == *module)
            .unwrap();
        assert_eq!(
            (
                &*grant.connection_id,
                &*grant.authority_kind,
                &*grant.risk_ceiling
            ),
            (CONNECTION, *kind, *risk)
        );
        assert_eq!(
            selectors(&grant.action_selectors),
            actions.iter().map(|s| (*s).to_owned()).collect()
        );
    }
    let ceiling = store
        .connection_ceiling(OWNER, CONNECTION)
        .unwrap()
        .unwrap();
    assert_eq!(ceiling.risk, plexus_core::manifest::Risk::Write);
    assert_eq!(
        selectors(&ceiling.action_selectors),
        expected
            .iter()
            .flat_map(|(_, _, _, actions)| *actions)
            .map(|s| (*s).to_owned())
            .collect()
    );
    assert_eq!(
        f.imports(),
        json!({"imported":[SLUG], "pending":[], "conflicts":[]})
    );
}

#[test]
fn hand_added_and_invalid_apps_do_not_reach_the_registry_or_import() {
    let mut f = Fixture::new(AgentLookup::Known, true);
    f.reconcile(&vault_case("github_app_identity"));
    assert!(f
        .state
        .store()
        .connection(OWNER, "github-handle-listing-vector")
        .unwrap()
        .is_none());
    for (field, value) in [
        ("slug", json!("not-attested-vector")),
        ("app_id", json!("042")),
        ("agent", json!("agent_0123456789ABCDEF")),
    ] {
        let mut reply = vault_case("github_app_attestation");
        reply["result"]["credentials"][0]["github_app"][field] = value;
        f.reconcile(&reply);
        assert!(f.handle().is_none(), "imported invalid {field}");
    }
    assert!(f.registry.requests().is_empty());
    assert_eq!(f.token.0.load(Ordering::SeqCst), 0);
}

#[test]
fn agent_must_be_live_and_next_listing_rechecks_liveness() {
    for lookup in [
        AgentLookup::Retired,
        AgentLookup::Unknown,
        AgentLookup::Unavailable,
    ] {
        let mut f = Fixture::new(lookup, true);
        f.attest();
        assert!(f.handle().is_none());
        assert_eq!(f.registry.requests(), [AGENT]);
        assert_eq!(f.imports()["pending"][0]["slug"], SLUG);
        assert_eq!(f.token.0.load(Ordering::SeqCst), 0);
        f.registry.set_response(AGENT, AgentLookup::Known);
        f.attest();
        assert!(f.handle().is_some());
        assert_eq!(f.registry.requests(), [AGENT, AGENT]);
        assert_eq!(f.imports()["pending"], json!([]));
    }
}

#[test]
fn existing_app_id_or_agent_conflict_replaces_nothing() {
    for (app_id, agent) in [(42, AGENT), (APP_ID, "agent_0123456789abcdee")] {
        let mut f = Fixture::new(AgentLookup::Known, true);
        control::import_listed(
            f.state.store(),
            OWNER,
            &Inventory {
                version: "github-grant-import.v1".into(),
                handles: vec![InventoryHandle {
                    app_handle_id: SLUG.into(),
                    agent_id: agent.into(),
                    app_id,
                    installation_id: None,
                    credential_id: RECORD.into(),
                    status: "enabled".into(),
                    grants: vec![],
                }],
            },
            &BTreeMap::from([(SLUG.into(), vec![])]),
            false,
        )
        .unwrap();
        let grants_before = f.state.store().list_all_grants(OWNER).unwrap().len();
        f.attest();
        f.attest();
        let (handle, bindings) = f.handle().unwrap();
        assert_eq!((handle.app_id, &*handle.agent_id), (app_id, agent));
        assert!(handle.proven_at.is_none());
        assert!(bindings.is_empty());
        assert_eq!(
            f.state.store().list_all_grants(OWNER).unwrap().len(),
            grants_before
        );
        assert_eq!(f.token.0.load(Ordering::SeqCst), 0);
        assert_eq!(f.imports()["conflicts"].as_array().unwrap().len(), 1);
        assert_eq!(f.imports()["conflicts"][0]["slug"], SLUG);
    }
}

#[test]
fn identical_listing_does_not_probe_or_write_again() {
    let mut f = Fixture::new(AgentLookup::Known, true);
    f.attest();
    let before = f.handle().unwrap().0;
    let health = f.imports();
    let grants_before = f.state.store().list_all_grants(OWNER).unwrap().len();
    f.watcher
        .reconcile(&f.state, &vault_case("github_app_attestation"), 200, true)
        .unwrap();
    assert_eq!(f.registry.requests(), [AGENT]);
    assert_eq!(f.token.0.load(Ordering::SeqCst), 1);
    assert_eq!(f.handle().unwrap().0.proven_at, before.proven_at);
    assert_eq!(
        f.state.store().list_all_grants(OWNER).unwrap().len(),
        grants_before
    );
    assert_eq!(f.imports(), health);
}

#[test]
fn failed_own_token_probe_leaves_handle_disabled() {
    let mut f = Fixture::new(AgentLookup::Known, false);
    f.attest();
    let (handle, bindings) = f
        .handle()
        .expect("a failed proof must not lose the imported handle");
    assert_eq!(handle.status, "disabled");
    assert!(handle.proven_at.is_none());
    assert!(bindings.is_empty());
    assert_eq!(f.token.0.load(Ordering::SeqCst), 1);
    assert!(f.state.runtime.rest_transport.has_connection(CONNECTION));
    assert_eq!(f.imports()["pending"][0]["slug"], SLUG);
}

#[test]
fn listings_cannot_import_without_connector_home() {
    let mut f = Fixture::new(AgentLookup::Known, true);
    Arc::get_mut(&mut f.state).unwrap().runtime.connector_home =
        Arc::new(crate::connector_home::ConnectorHome::unavailable());
    f.attest();
    assert!(f.handle().is_none());
    assert!(f.registry.requests().is_empty());
    assert_eq!(f.token.0.load(Ordering::SeqCst), 0);
}

#[test]
fn an_imported_app_is_bound_only_when_policy_apply_is_enabled() {
    let mut f = Fixture::new(AgentLookup::Known, true);
    let mut seed: Value = serde_json::from_str(include_str!(
        "../../plexus-core/tests/fixtures/vault-wire/agent-policy-v1/github.json"
    ))
    .unwrap();
    seed["source"] = json!({"release":"cortexkit-defaults-2026.11", "sha256":"0".repeat(64)});
    let text = json!({
        "schema":"ck-agent-policy/v1", "version":1, "issued_at_unix_secs":1,
        "root_key_id":"56fae12f77164627", "rule_sets":{"github":seed},
        "bindings":[{"agent":AGENT,"identity":RECORD,"resources":["org/one", "org/two"],"service":"github"}]
    });
    let active = ActivePolicy {
        policy: serde_json::from_value(text).unwrap(),
        policy_sha256: "0".repeat(64),
        manifest_version: 1,
    };
    f.attest();
    let store = f.state.store();
    let manifest = store.cached_manifest("github_rest").unwrap();
    let checked = check_github(&active.policy, &manifest.actions_baseline);
    store
        .apply_github_policy((&active, &checked), || true)
        .unwrap();
    assert!(f
        .handle()
        .expect("policy target must be imported first")
        .1
        .is_empty());
    assert!(store.grants_held_by_agent(AGENT).unwrap().is_empty());
    store.set_github_policy_apply(true).unwrap();
    store
        .apply_github_policy((&active, &checked), || true)
        .unwrap();
    assert_eq!(f.handle().unwrap().1, ["org/one", "org/two"]);
    assert!(!store.grants_held_by_agent(AGENT).unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_watch_wake_retries_a_pending_app_on_a_fresh_listing() {
    let mut f = Fixture::new(AgentLookup::Unknown, true);
    let vault = Arc::new(MockVault {
        reply: Mutex::new(vault_case("github_app_attestation")),
        calls: AtomicUsize::new(0),
        watches: Mutex::default(),
    });
    Arc::get_mut(&mut f.state).unwrap().runtime.vault_peer = Some(vault.clone());
    let (stop, receiver) = mpsc::channel(1);
    let task = spawn(f.state.clone(), receiver);
    until(|| !vault.watches.lock().unwrap().is_empty()).await;
    let watch = vault.watches.lock().unwrap()[0].clone();
    watch.send(vault_case("watch_opening")).await.unwrap();
    until(|| f.imports()["pending"][0]["reason"] == "agent_unknown").await;
    assert!(f.handle().is_none());

    f.registry.set_response(AGENT, AgentLookup::Known);
    watch
        .send(vault_case("watch_category_changed"))
        .await
        .unwrap();
    until(|| f.imports()["imported"] == json!([SLUG])).await;
    stop.send(()).await.unwrap();
    task.await.unwrap();
    assert_eq!(vault.calls.load(Ordering::SeqCst), 2);
    assert_eq!(f.token.0.load(Ordering::SeqCst), 1);
}
