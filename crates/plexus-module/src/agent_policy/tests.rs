use super::*;
use plexus_core::credentials::CkcredRouteError;
use plexus_core::PlexusStore;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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
    ModuleState {
        runtime: crate::runtime_for_test(store),
        health: Arc::new(crate::health::HealthState::new()),
    }
}

fn assert_loaded(state: &ModuleState, version: i64, reply: &Value) -> Value {
    let health = health(state);
    assert_eq!(health["state"], "loaded");
    assert_eq!(health["version"], version);
    assert_eq!(health["policy_sha256"], reply["result"]["policy_sha256"]);
    assert_eq!(health["served"].as_array().unwrap().len(), 21);
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
    let catalog = checked_catalog().unwrap();
    assert!(refresh(&state, &vault, &catalog.actions_baseline));
    assert_eq!(
        health(&state),
        json!({"state":"none","version":null,"policy_sha256":null,"served":[],"unserved":[]})
    );
    vault.reply(json!({"code":"unknown_method"}));
    assert!(!refresh(&state, &vault, &catalog.actions_baseline));
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
    let catalog = checked_catalog().unwrap();
    refresh(&state, &vault, &catalog.actions_baseline);
    let loaded = assert_loaded(&state, 8, &current);
    for reply in [ready(7), no_policy(), no_policy()] {
        vault.reply(reply);
        refresh(&state, &vault, &catalog.actions_baseline);
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
    let catalog = checked_catalog().unwrap();
    refresh(&state, &vault, &catalog.actions_baseline);
    let loaded = assert_loaded(&state, 2, &current);
    *vault.reply.lock().unwrap() = Err(CkcredRouteError::OutcomeUnknown);
    refresh(&state, &vault, &catalog.actions_baseline);
    let mut unreadable = loaded.clone();
    unreadable["state"] = json!("unreadable");
    assert_eq!(health(&state), unreadable);
    vault.reply(current);
    refresh(&state, &vault, &catalog.actions_baseline);
    assert_eq!(health(&state), loaded);
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
    let wake = Arc::new(Notify::new());
    let worker = spawn(state.clone(), rx, wake.clone());
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
    wake.notify_one();
    until(|| health(&state)["version"] == 3).await;
    assert_loaded(&state, 3, &newest);
    assert_eq!(vault.calls(), 4);

    claim.0.store(false, Ordering::SeqCst);
    state.runtime.connector_home.refresh().unwrap();
    until(|| watch.is_closed()).await;
    wake.notify_one();
    stop.send(()).await.unwrap();
    worker.await.unwrap();
    assert_eq!(vault.calls(), 4, "home loss stops reads and the watch");
    assert_eq!(table_counts(&db), before);
    assert_eq!(
        store.github_repo_binding_generation().unwrap(),
        binding_generation
    );
}
