use super::*;
use plexus_core::credentials::CkcredRouteError;
use plexus_core::{test_scratch::Scratch, PlexusStore};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use subc_protocol::session::ModuleControlResponse;

const SEED: &str =
    include_str!("../../../plexus-core/tests/fixtures/vault-wire/agent-policy-v1/github.json");

fn ready(version: i64) -> Value {
    let mut seed: Value = serde_json::from_str(SEED).unwrap();
    seed["source"] = json!({
        "release":"cortexkit-defaults-2026.11",
        "sha256":"aca7b285dce9d1ebff602aae291d0205779a932fc47cf2afd380b3ee5d91f1a7"
    });
    let text = json!({
        "schema":"ck-agent-policy/v1", "version":version, "issued_at_unix_secs":1,
        "root_key_id":"56fae12f77164627", "rule_sets":{"github":seed},
        "bindings":[{"agent":"other-agent","identity":"github_app:other-app","resources":["o/x"],"service":"github"}]
    }).to_string();
    json!({"result":{
        "version":version,
        "policy_sha256":format!("{:x}", Sha256::digest(&text)),
        "manifest_version":41,
        "policy_text":text,
    }})
}

fn no_policy() -> Value {
    json!({"result":{"version":null,"policy_sha256":null,"manifest_version":null,"policy_text":null}})
}

struct Vault {
    reply: Mutex<Result<Value, CkcredRouteError>>,
    calls: AtomicUsize,
    watches: Mutex<Vec<mpsc::Sender<Value>>>,
}

impl Vault {
    fn new(reply: Value) -> Self {
        Self {
            reply: Mutex::new(Ok(reply)),
            calls: AtomicUsize::new(0),
            watches: Mutex::default(),
        }
    }

    fn reply(&self, reply: Value) {
        *self.reply.lock().unwrap() = Ok(reply);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CkcredRoutePeer for Vault {
    fn call(&self, method: &str, params: Value) -> Result<Value, CkcredRouteError> {
        assert_eq!(method, "policy.active");
        assert_eq!(params, json!({}));
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.reply.lock().unwrap().clone()
    }

    fn watch_policy(&self) -> Result<CkcredWatch, CkcredRouteError> {
        let (tx, rx) = mpsc::channel(16);
        self.watches.lock().unwrap().push(tx);
        Ok(CkcredWatch::from_events(rx))
    }
}

fn health(state: &ModuleState) -> Value {
    match state.health.report() {
        ModuleControlResponse::HealthCheck {
            metrics: Some(metrics),
            ..
        } => metrics["agentPolicy"].clone(),
        other => panic!("expected health metrics: {other:?}"),
    }
}

fn runtime(store: Arc<PlexusStore>) -> ModuleState {
    ingest_shipped_catalog(&store);
    ModuleState {
        runtime: crate::runtime_for_test(store),
        health: Arc::new(crate::health::HealthState::new()),
    }
}

fn shipped_catalog() -> Scratch {
    let directory = Scratch::directory("agent-policy-catalog");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github_rest.jsonc");
    std::fs::copy(path, directory.join("github_rest.jsonc")).unwrap();
    directory
}

fn ingest_shipped_catalog(store: &PlexusStore) {
    crate::catalog_loader::ingest_catalog_from(store, &shipped_catalog()).unwrap();
}

fn assert_loaded(state: &ModuleState, version: i64, reply: &Value) -> Value {
    let health = health(state);
    assert_eq!(health["state"], "loaded");
    assert_eq!(health["version"], version);
    assert_eq!(health["policy_sha256"], reply["result"]["policy_sha256"]);
    assert_eq!(
        health["served"],
        json!([
            "close",
            "comment",
            "comment_edit",
            "comment_edit_last",
            "issue_create",
            "issue_edit",
            "pr_create",
            "pr_dequeue",
            "pr_draft",
            "pr_edit",
            "pr_enqueue",
            "pr_ready",
            "pr_review",
            "reaction",
            "reopen",
            "resolve_thread",
            "review_reply",
            "stack_add",
            "stack_create",
            "stack_unstack",
            "unresolve_thread"
        ])
    );
    assert_eq!(
        health["unserved"],
        json!([
            {"name":"node_repository","reason":"policy_kind_not_catalogued"}
        ])
    );
    health
}

#[test]
fn null_policy_reads_as_none_and_unknown_method_reads_as_absent() {
    let state = runtime(Arc::new(crate::test_support::open_memory_store(
        "policy-none",
    )));
    let vault = Vault::new(no_policy());
    assert!(refresh(&state, &vault));
    assert_eq!(
        health(&state),
        json!({"state":"none","version":null,"policy_sha256":null,"served":[],"unserved":[]})
    );
    vault.reply(json!({"code":"unknown_method"}));
    assert!(!refresh(&state, &vault));
    assert_eq!(
        health(&state),
        json!({"state":"absent","version":null,"policy_sha256":null,"served":[],"unserved":[]})
    );
}

#[test]
fn older_or_null_policy_cannot_replace_a_checked_version() {
    let state = runtime(Arc::new(crate::test_support::open_memory_store(
        "policy-rollback",
    )));
    let current = ready(8);
    let vault = Vault::new(current.clone());
    refresh(&state, &vault);
    let loaded = assert_loaded(&state, 8, &current);
    for reply in [ready(7), no_policy(), no_policy()] {
        vault.reply(reply);
        refresh(&state, &vault);
        assert_eq!(health(&state), loaded);
    }
}

#[test]
fn a_transport_error_keeps_the_checked_policy_and_same_version_recovers() {
    let state = runtime(Arc::new(crate::test_support::open_memory_store(
        "policy-transport",
    )));
    let current = ready(2);
    let vault = Vault::new(current.clone());
    refresh(&state, &vault);
    let loaded = assert_loaded(&state, 2, &current);
    *vault.reply.lock().unwrap() = Err(CkcredRouteError::OutcomeUnknown);
    refresh(&state, &vault);
    let mut unreadable = loaded.clone();
    unreadable["state"] = json!("unreadable");
    assert_eq!(health(&state), unreadable);
    vault.reply(current);
    refresh(&state, &vault);
    assert_eq!(health(&state), loaded);
}

#[test]
fn seeded_policy_follows_deployed_catalog_hash_without_a_vault_read() {
    let store = Arc::new(crate::test_support::open_memory_store(
        "policy-deployed-catalog",
    ));
    let state = runtime(store.clone());
    let current = ready(1);
    let vault = Vault::new(current.clone());
    refresh(&state, &vault);
    let loaded = assert_loaded(&state, 1, &current);

    *vault.reply.lock().unwrap() = Err(CkcredRouteError::OutcomeUnknown);
    refresh(&state, &vault);
    let mut unreadable = loaded;
    unreadable["state"] = json!("unreadable");
    assert_eq!(health(&state), unreadable);

    let directory = shipped_catalog();
    let path = directory.join("github_rest.jsonc");
    let source = std::fs::read_to_string(&path).unwrap();
    let mut deployed: Value =
        serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap();
    let comment = deployed["actions_baseline"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["name"] == "add_issue_comment")
        .unwrap();
    comment["http"]["path"] = json!("/repos/{owner}/{repo}/issues/{issue_number}/other-comments");
    std::fs::write(&path, deployed.to_string()).unwrap();
    crate::catalog_loader::ingest_catalog_from(&store, &directory).unwrap();

    assert!(
        !recheck_catalog(&state),
        "a changed but readable catalog is not a recovery"
    );
    let checked = health(&state);
    assert_eq!(
        checked["state"], "unreadable",
        "the vault is still unreadable"
    );
    assert_eq!(checked["policy_sha256"], unreadable["policy_sha256"]);
    assert_eq!(checked["version"], 1);
    assert_eq!(
        checked["unserved"],
        json!([
            {"name":"add_issue_comment","reason":"policy_rest_mismatch"},
            {"name":"close","reason":"policy_leg_unserved"},
            {"name":"comment","reason":"policy_leg_unserved"},
            {"name":"node_repository","reason":"policy_kind_not_catalogued"},
            {"name":"reopen","reason":"policy_leg_unserved"}
        ]),
        "the retained policy must follow the deployed shape"
    );
    assert_eq!(
        vault.calls(),
        2,
        "a changed catalog does not require a vault read"
    );
}

struct Claim(AtomicBool);

impl crate::connector_home::RolePeer for Claim {
    fn call(&self, _: &str, _: Value) -> Result<Value, subc_protocol::ErrorBody> {
        Ok(json!({
            "role":crate::connector_home::ROLE, "epoch":1, "known":true,
            "held_here":self.0.load(Ordering::SeqCst), "stale":false,
            "holder":null, "holder_name":null, "source":null,
        }))
    }
}

async fn until(predicate: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker did not reach expected state");
}

fn table_counts(db: &rusqlite::Connection) -> BTreeMap<String, i64> {
    let mut tables = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table'")
        .unwrap();
    tables
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(|table| {
            let table = table.unwrap();
            let query = format!("SELECT count(*) FROM \"{}\"", table.replace('"', "\"\""));
            let count = db.query_row(&query, [], |row| row.get(0)).unwrap();
            (table, count)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_watch_and_backstop_reads_keep_store_rows_and_last_checked_policy() {
    let (mut state, store, _, scratch) = crate::github_read_frame_tests::imported_runtime();
    ingest_shipped_catalog(&store);
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    let before = table_counts(&db);
    let binding_generation = store.github_repo_binding_generation().unwrap();
    assert!(before["github_repo_binding"] > 0);
    assert!(before["github_app_handle"] > 0);
    assert!(before["grants"] > 0);

    let initial = ready(1);
    let vault = Arc::new(Vault::new(initial.clone()));
    let claim = Arc::new(Claim(AtomicBool::new(false)));
    let runtime = &mut Arc::get_mut(&mut state).unwrap().runtime;
    runtime.vault_peer = Some(vault.clone());
    runtime.connector_home = Arc::new(crate::connector_home::ConnectorHome::new(claim.clone()));
    runtime.connector_home.refresh().unwrap();

    let (stop, rx) = mpsc::channel(1);
    let wakes = Arc::new(Wakes::default());
    let worker = spawn(state.clone(), rx, wakes.clone());
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(vault.calls(), 0, "no read before connector home is held");
    assert!(vault.watches.lock().unwrap().is_empty());

    claim.0.store(true, Ordering::SeqCst);
    state.runtime.connector_home.refresh().unwrap();
    until(|| !vault.watches.lock().unwrap().is_empty()).await;
    assert_eq!(
        vault.calls(),
        1,
        "boot read precedes the watch opening notice"
    );
    let loaded = assert_loaded(&state, 1, &initial);
    let watch = vault.watches.lock().unwrap()[0].clone();

    vault.reply(json!({"result":{"error":{"code":"store_error","class":"transient"}}}));
    // The opening notice carries no policy. It must still cause an active read.
    let notice = json!({"kind":"changed","epoch":"00112233445566778899aabbccddeeff","seq":1,"version":null,"policy_sha256":null});
    watch.send(notice.clone()).await.unwrap();
    until(|| health(&state)["state"] == "unreadable").await;
    let mut unreadable = loaded;
    unreadable["state"] = json!("unreadable");
    assert_eq!(
        health(&state),
        unreadable,
        "refusal did not clear the checked version or its report"
    );

    let next = ready(2);
    vault.reply(next.clone());
    let mut changed = notice;
    changed["seq"] = json!(2);
    watch.send(changed).await.unwrap();
    until(|| health(&state)["version"] == 2).await;
    assert_loaded(&state, 2, &next);

    let newest = ready(3);
    vault.reply(newest.clone());
    wakes.read.notify_one();
    until(|| health(&state)["version"] == 3).await;
    assert_loaded(&state, 3, &newest);
    assert_eq!(vault.calls(), 4);

    claim.0.store(false, Ordering::SeqCst);
    state.runtime.connector_home.refresh().unwrap();
    until(|| watch.is_closed()).await;
    wakes.read.notify_one();
    wakes.catalog.notify_one();
    stop.send(()).await.unwrap();
    worker.await.unwrap();
    assert_eq!(vault.calls(), 4, "home loss stops reads and the watch");
    assert_eq!(table_counts(&db), before);
    assert_eq!(
        store.github_repo_binding_generation().unwrap(),
        binding_generation
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_recovery_reads_policy_again_without_promoting_the_unchecked_candidate() {
    let (mut state, store, _, scratch) = crate::github_read_frame_tests::imported_runtime();
    ingest_shipped_catalog(&store);
    let original = ready(1);
    let vault = Arc::new(Vault::new(original.clone()));
    Arc::get_mut(&mut state).unwrap().runtime.vault_peer = Some(vault.clone());
    let (stop, rx) = mpsc::channel(1);
    let wakes = Arc::new(Wakes::default());
    let worker = spawn(state.clone(), rx, wakes.clone());
    until(|| health(&state)["state"] == "loaded").await;
    let mut retained = assert_loaded(&state, 1, &original);

    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    assert_eq!(
        db.execute(
            "UPDATE app_manifests SET content_hash=?1, manifest_json=?2 WHERE key=?3",
            ["invalid-content-hash", "{", GITHUB_CATALOG],
        )
        .unwrap(),
        1
    );
    vault.reply(ready(2));
    wakes.read.notify_one();
    until(|| health(&state)["state"] == "unreadable").await;
    retained["state"] = json!("unreadable");
    assert_eq!(
        health(&state),
        retained,
        "do not promote a version without a readable catalog"
    );

    let current = ready(3);
    vault.reply(current.clone());
    ingest_shipped_catalog(&store);
    wakes.catalog.notify_one();
    until(|| health(&state)["version"] == 3).await;
    assert_loaded(&state, 3, &current);
    stop.send(()).await.unwrap();
    worker.await.unwrap();
    assert_eq!(vault.calls(), 3, "catalog recovery triggers one fresh read");
}
