use super::*;
use base64::Engine;
use plexus_core::credentials::{CkcredRouteError, CkcredWatch};
use plexus_core::{GrantMintRequest, PlexusStore};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

fn vault_case(name: &str) -> Value {
    let bytes = include_bytes!("../../plexus-core/tests/fixtures/vault-wire/list-scoped-v2.json");
    assert_eq!(
        format!("{:x}", Sha256::digest(bytes)),
        "e9dfb2140ff4d92ece55de09da5987b27d8ca1a2023f0f9c50439499c3c3d603"
    );
    let vectors: Value = serde_json::from_slice(bytes).unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["case"] == name)
        .unwrap();
    let reply = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(case["reply_b64url"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&reply)),
        case["reply_sha256"]
    );
    serde_json::from_slice(&reply).unwrap()
}

fn catalog() -> Value {
    vault_case("catalog_and_lifecycle")
}

fn only(provider: &str) -> Value {
    let mut reply = catalog();
    reply["result"]["credentials"]
        .as_array_mut()
        .unwrap()
        .retain(|row| row["provider"] == provider);
    reply
}

fn fixture(seed_callers: bool) -> Arc<ModuleState> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "search-auto-{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    for provider in plexus_core::web_search::providers::PROVIDER_NAMES {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(provider.manifest);
        let source = std::fs::read_to_string(path).unwrap();
        let manifest = plexus_core::ingest_value(
            serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap(),
        )
        .unwrap();
        store.upsert_manifest("system", &manifest).unwrap();
    }
    let state = Arc::new(ModuleState {
        health: Arc::new(crate::health::HealthState::new()),
        runtime: crate::runtime_for_test(store.clone()),
    });
    if seed_callers {
        let provider = plexus_core::web_search::providers::provider_named("tavily").unwrap();
        let (_, reply) = web_search_provider_admin::auto_plan_and_apply(
            &state,
            OWNER,
            provider,
            "apikey:tavily",
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(reply["result"]["applied"], true, "{reply}");
        store
            .mint_grant_bounded(&GrantMintRequest {
                principal: OWNER,
                connection_id: provider.connection_id,
                grantee_principal: "reserved:broca",
                authority_kind: "invoke",
                requested_risk: "read",
                requested_selectors: &["search".into()],
                expires_at: None,
            })
            .unwrap()
            .unwrap();
        store.set_web_search_order(&["tavily".into()]).unwrap();
    }
    state
}

fn connections(store: &PlexusStore, app: &str) -> Vec<plexus_core::storage::ConnectionSummary> {
    store
        .list_connections(OWNER)
        .unwrap()
        .into_iter()
        .filter(|connection| connection.app_key == app)
        .collect()
}

fn grant_count(store: &PlexusStore, id: &str) -> usize {
    store
        .list_all_grants(OWNER)
        .unwrap()
        .iter()
        .filter(|grant| grant.connection_id == id)
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_exa_connects_once_with_grants_order_and_no_confirmation() {
    let state = fixture(true);
    let mut reconciler = Reconciler::default();
    let before = crate::operator_confirmation::test_confirmation_calls();
    reconciler.reconcile(&state, &only("exa"), 0, true).unwrap();
    assert_eq!(
        crate::operator_confirmation::test_confirmation_calls(),
        before,
        "auto-connect must not call confirm_operator"
    );
    let store = state.store();
    assert_eq!(connections(store, "exa_rest").len(), 1);
    assert_eq!(connections(store, "exa_rest")[0].status, "active");
    assert_eq!(
        store
            .connection_credential_reference(OWNER, "conn-exa-rest")
            .unwrap()
            .as_deref(),
        Some("apikey:exa")
    );
    assert_eq!(grant_count(store, "conn-exa-rest"), 1);
    let grant = store
        .list_all_grants(OWNER)
        .unwrap()
        .into_iter()
        .find(|grant| grant.connection_id == "conn-exa-rest")
        .unwrap();
    assert_eq!(
        (
            grant.grantee_principal.as_str(),
            grant.authority_kind.as_str(),
            grant.risk_ceiling.as_str()
        ),
        ("reserved:broca", "invoke", "read")
    );
    assert_eq!(grant.action_selectors, ["search"]);
    assert_eq!(
        store.web_search_order().unwrap().unwrap(),
        ["tavily", "exa"]
    );
    let audit = store.list_audit(OWNER).unwrap();
    for action in ["issue_ticket", "grant", "auto_connected"] {
        assert!(
            audit
                .iter()
                .any(|row| row.connection_id.as_deref() == Some("conn-exa-rest")
                    && row.action.as_deref() == Some(action)),
            "missing {action}: {audit:?}"
        );
    }
    let source = audit
        .iter()
        .find(|row| row.action.as_deref() == Some("auto_connected"))
        .unwrap();
    let source: Value =
        serde_json::from_str(source.args_redaction_summary.as_deref().unwrap()).unwrap();
    assert_eq!(
        (
            source["credential_id"].as_str(),
            source["incarnation"].as_str(),
            source["record_version"].as_u64()
        ),
        (
            Some("apikey:exa"),
            Some("00000000000000000000000000000001"),
            Some(1)
        )
    );
    reconciler.reconcile(&state, &only("exa"), 1, true).unwrap();
    assert_eq!(
        store.list_audit(OWNER).unwrap().len(),
        audit.len(),
        "repeat notice must write nothing"
    );
    assert_eq!(grant_count(store, "conn-exa-rest"), 1);
    assert_eq!(connections(store, "exa_rest").len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_maps_kimi_and_ignores_nonactive_unmapped_and_searxng() {
    let state = fixture(true);
    let mut reply = catalog();
    for service in ["searxng", "unknown", "moonshot"] {
        let mut row = only("exa")["result"]["credentials"][0].clone();
        row["provider"] = json!(service);
        row["id"] = json!(format!("apikey:{service}"));
        row["provider_ids"] = json!(["exa"]);
        reply["result"]["credentials"]
            .as_array_mut()
            .unwrap()
            .push(row);
    }
    Reconciler::default()
        .reconcile(&state, &reply, 0, true)
        .unwrap();
    let store = state.store();
    assert_eq!(connections(store, "kimi_rest").len(), 1);
    assert_eq!(
        store
            .connection_credential_reference(OWNER, "conn-web-search-kimi")
            .unwrap()
            .as_deref(),
        Some("apikey:kimi-for-coding")
    );
    for app in ["brave_rest", "searxng_rest", "ollama_rest"] {
        assert!(connections(store, app).is_empty(), "{app}");
    }
    assert_eq!(
        connections(store, "tavily_rest").len(),
        1,
        "retired key must not create another connection"
    );
    assert_eq!(store.auto_search_connections(OWNER).unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_metadata_selects_vendor_but_ticket_binds_exact_record_name() {
    let state = fixture(false);
    let mut reply = only("exa");
    reply["result"]["credentials"][0]["id"] = json!("apikey:search-account");
    reply["result"]["credentials"][0]["provider_ids"] = json!(["brave"]);
    Reconciler::default()
        .reconcile(&state, &reply, 0, true)
        .unwrap();
    assert_eq!(
        state
            .store()
            .connection_credential_reference(OWNER, "conn-exa-rest")
            .unwrap()
            .as_deref(),
        Some("apikey:search-account")
    );
    assert!(connections(state.store(), "brave_rest").is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn older_or_incomplete_vault_never_guesses_names_or_provider_ids() {
    let state = fixture(false);
    let mut reconciler = Reconciler::default();
    let mut mixed = catalog();
    mixed["result"]["credentials"][2]
        .as_object_mut()
        .unwrap()
        .remove("incarnation");
    for reply in [
        mixed,
        vault_case("older_vault_unknown_method"),
        {
            let mut reply = only("exa");
            reply["result"]["credentials"][0]
                .as_object_mut()
                .unwrap()
                .remove("provider");
            reply["result"]["credentials"][0]["provider_ids"] = json!(["exa"]);
            reply
        },
        {
            let mut reply = only("exa");
            reply["result"]["credentials"][0]
                .as_object_mut()
                .unwrap()
                .remove("incarnation");
            reply
        },
    ] {
        reconciler.reconcile(&state, &reply, 0, true).unwrap();
        assert!(state.store().list_connections(OWNER).unwrap().is_empty());
        assert!(state
            .store()
            .auto_search_connections(OWNER)
            .unwrap()
            .is_empty());
    }
    assert!(reconciler.warned_unsupported);
    assert!(unknown_method(&vault_case("older_vault_unknown_method")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaving_active_revokes_normally_and_keeps_order_and_same_consent_revoked() {
    for state_name in [
        "needs_reauth",
        "retired",
        "corrupt",
        "future_state",
        "missing",
    ] {
        let state = fixture(true);
        let mut reconciler = Reconciler::default();
        let active = only("exa");
        reconciler.reconcile(&state, &active, 0, true).unwrap();
        let mut inactive = active.clone();
        if state_name == "missing" {
            inactive["result"]["credentials"] = json!([]);
        } else {
            inactive["result"]["credentials"][0]["state"] = json!(state_name);
        }
        reconciler.reconcile(&state, &inactive, 1, true).unwrap();
        assert_eq!(
            connections(state.store(), "exa_rest")[0].status,
            "revoked",
            "{state_name}"
        );
        assert!(!state.runtime.rest_transport.has_connection("conn-exa-rest"));
        assert_eq!(
            state.store().web_search_order().unwrap().unwrap(),
            ["tavily", "exa"]
        );
        assert!(state.store().auto_search_connections(OWNER).unwrap()[0]
            .revoked_at_ms
            .is_some());
        assert!(state
            .store()
            .list_audit(OWNER)
            .unwrap()
            .iter()
            .any(|row| row.action.as_deref() == Some("auto_key_removed")));
        reconciler.reconcile(&state, &active, 2, true).unwrap();
        assert_eq!(
            connections(state.store(), "exa_rest").len(),
            1,
            "same consent must not recreate a revoked connection"
        );
        assert_eq!(connections(state.store(), "exa_rest")[0].status, "revoked");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn person_revoke_is_sticky_across_restart_but_new_incarnation_or_version_connects_new_id() {
    let state = fixture(true);
    Reconciler::default()
        .reconcile(&state, &only("exa"), 0, true)
        .unwrap();
    state
        .store()
        .revoke_connection(OWNER, "conn-exa-rest")
        .unwrap();
    let mut reconciler = Reconciler::default();
    reconciler.reconcile(&state, &only("exa"), 1, true).unwrap();
    assert_eq!(connections(state.store(), "exa_rest").len(), 1);
    assert_eq!(connections(state.store(), "exa_rest")[0].status, "revoked");
    assert!(state
        .store()
        .list_audit(OWNER)
        .unwrap()
        .iter()
        .any(|row| row.action.as_deref() == Some("auto_person_revoked")));
    let mut new = only("exa");
    new["result"]["credentials"][0]["incarnation"] = json!("new-incarnation");
    reconciler.reconcile(&state, &new, 2, true).unwrap();
    assert_eq!(connections(state.store(), "exa_rest").len(), 2);
    assert_eq!(
        state
            .store()
            .connection(OWNER, "conn-exa-rest")
            .unwrap()
            .unwrap()
            .status,
        "revoked"
    );
    assert_eq!(
        state
            .store()
            .connection(OWNER, "conn-web-search-exa-1")
            .unwrap()
            .unwrap()
            .status,
        "active"
    );
    assert_eq!(grant_count(state.store(), "conn-web-search-exa-1"), 1);
    assert_eq!(
        state
            .store()
            .web_search_candidate_connection_ids(
                "reserved:broca",
                "exa_rest",
                plexus_core::storage::now_ms()
            )
            .unwrap(),
        ["conn-web-search-exa-1"]
    );
    new["result"]["credentials"][0]["record_version"] = json!(2);
    reconciler.reconcile(&state, &new, 3, true).unwrap();
    assert_eq!(
        state
            .store()
            .connection(OWNER, "conn-web-search-exa-1")
            .unwrap()
            .unwrap()
            .status,
        "revoked"
    );
    assert_eq!(
        state
            .store()
            .connection(OWNER, "conn-web-search-exa-2")
            .unwrap()
            .unwrap()
            .status,
        "active"
    );
    assert_eq!(
        state.store().web_search_order().unwrap().unwrap(),
        ["tavily", "exa"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_order_entry_stays_dropped_until_a_new_key() {
    let state = fixture(true);
    let active = only("exa");
    Reconciler::default()
        .reconcile(&state, &active, 0, true)
        .unwrap();
    state
        .store()
        .set_web_search_order(&["tavily".into()])
        .unwrap();
    let mut restarted = Reconciler::default();
    restarted.reconcile(&state, &active, 1, true).unwrap();
    assert_eq!(
        state.store().web_search_order().unwrap().unwrap(),
        ["tavily"]
    );
    let mut new = active;
    new["result"]["credentials"][0]["record_version"] = json!(2);
    restarted.reconcile(&state, &new, 2, true).unwrap();
    assert_eq!(
        state.store().web_search_order().unwrap().unwrap(),
        ["tavily", "exa"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_connection_is_reused_without_duplicate_grants() {
    let state = fixture(true);
    let provider = plexus_core::web_search::providers::provider_named("exa").unwrap();
    let (_, reply) = web_search_provider_admin::auto_plan_and_apply(
        &state,
        OWNER,
        provider,
        "apikey:exa",
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(reply["result"]["applied"], true);
    let before = grant_count(state.store(), "conn-exa-rest");
    assert_eq!(before, 1);
    Reconciler::default()
        .reconcile(&state, &only("exa"), 0, true)
        .unwrap();
    assert_eq!(grant_count(state.store(), "conn-exa-rest"), before);
    assert_eq!(connections(state.store(), "exa_rest").len(), 1);
    let tickets = state
        .store()
        .list_audit(OWNER)
        .unwrap()
        .into_iter()
        .filter(|row| {
            row.connection_id.as_deref() == Some("conn-exa-rest")
                && row.action.as_deref() == Some("issue_ticket")
        })
        .count();
    assert_eq!(tickets, 1, "reuse must not issue another ticket");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_connect_with_zero_default_callers_is_allowed() {
    let state = fixture(false);
    Reconciler::default()
        .reconcile(&state, &only("exa"), 0, true)
        .unwrap();
    assert_eq!(connections(state.store(), "exa_rest")[0].status, "active");
    assert_eq!(grant_count(state.store(), "conn-exa-rest"), 0);
    assert_eq!(state.store().web_search_order().unwrap().unwrap(), ["exa"]);
    state
        .store()
        .revoke_connection(OWNER, "conn-exa-rest")
        .unwrap();
    let mut new = only("exa");
    new["result"]["credentials"][0]["incarnation"] = json!("replacement");
    Reconciler::default()
        .reconcile(&state, &new, 1, true)
        .unwrap();
    assert_eq!(
        state
            .store()
            .connection(OWNER, "conn-web-search-exa-1")
            .unwrap()
            .unwrap()
            .status,
        "active"
    );
    assert_eq!(grant_count(state.store(), "conn-web-search-exa-1"), 0);
}

struct RejectingVendor {
    url: String,
    running: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RejectingVendor {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let active = running.clone();
        let thread = std::thread::spawn(move || {
            while active.load(Ordering::Acquire) {
                if let Ok((stream, _)) = listener.accept() {
                    drop(stream);
                } else {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        });
        Self {
            url,
            running,
            thread: Some(thread),
        }
    }
}

impl Drop for RejectingVendor {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn with_endpoint(state: &Arc<ModuleState>, endpoint: &str) -> Arc<ModuleState> {
    let mut runtime = crate::runtime_for_test(state.runtime.store.clone());
    runtime.endpoint_override = Some(endpoint.into());
    Arc::new(ModuleState {
        health: state.health.clone(),
        runtime,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_failure_keeps_connection_inert_then_next_notice_completes_it() {
    let state = fixture(true);
    let mut reply = only("exa");
    reply["result"]["credentials"][0]["provider"] = json!("zai");
    reply["result"]["credentials"][0]["id"] = json!("apikey:zai");
    let key = active_keys(&reply).unwrap().into_iter().next().unwrap();
    let vendor = RejectingVendor::start();
    let failing = with_endpoint(&state, &vendor.url);
    let mut reconciler = Reconciler::default();
    reconciler.reconcile(&failing, &reply, 0, true).unwrap();
    assert_eq!(
        connections(state.store(), "zai").len(),
        1,
        "manual connect semantics keep an inert connection"
    );
    assert_eq!(grant_count(state.store(), "conn-web-search-zai"), 0);
    assert_eq!(
        state.store().web_search_order().unwrap().unwrap(),
        ["tavily"]
    );
    assert!(state.store().auto_search_connections(OWNER).unwrap()[0]
        .appended_at_ms
        .is_none());
    assert_eq!(reconciler.retries[&key], (60_000, 60_000));
    let before = state.store().list_audit(OWNER).unwrap().len();
    reconciler
        .reconcile(&failing, &reply, 59_999, false)
        .unwrap();
    assert_eq!(
        state.store().list_audit(OWNER).unwrap().len(),
        before,
        "timer must honor backoff"
    );
    reconciler
        .reconcile(&failing, &reply, 60_000, false)
        .unwrap();
    assert_eq!(reconciler.retries[&key], (180_000, 120_000));
    reconciler.retries.insert(key.clone(), (0, MAX_RETRY_MS));
    reconciler
        .reconcile(&failing, &reply, 60_001, true)
        .unwrap();
    assert_eq!(
        reconciler.retries[&key],
        (60_001 + MAX_RETRY_MS, MAX_RETRY_MS)
    );
    let vendor = plexus_conformance::stub_server::StubMcpServer::start(vec![
        plexus_conformance::stub_server::StubTool::simple("web_search_prime"),
    ])
    .unwrap();
    let working = with_endpoint(&state, vendor.endpoint());
    reconciler
        .reconcile(&working, &reply, 60_002, true)
        .unwrap();
    assert_eq!(
        grant_count(state.store(), "conn-web-search-zai"),
        1,
        "notice bypasses remaining backoff"
    );
    assert_eq!(
        state.store().web_search_order().unwrap().unwrap(),
        ["tavily", "zai"]
    );
    assert_eq!(connections(state.store(), "zai").len(), 1);
    assert!(reconciler.retries.is_empty());
}

struct MockVault {
    reply: Mutex<Value>,
    calls: AtomicUsize,
    watches: Mutex<Vec<mpsc::Sender<Value>>>,
}

impl CkcredRoutePeer for MockVault {
    fn call(&self, method: &str, params: Value) -> Result<Value, CkcredRouteError> {
        assert_eq!(method, "credential.list_scoped");
        assert_eq!(params, json!({}));
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.reply.lock().unwrap().clone())
    }
    fn watch_scoped(&self) -> Result<CkcredWatch, CkcredRouteError> {
        let (sender, receiver) = mpsc::channel(16);
        self.watches.lock().unwrap().push(sender);
        Ok(CkcredWatch::from_events(receiver))
    }
}

async fn until(predicate: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("search watch condition deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_watch_lists_on_opening_changed_and_reconnect_and_cancels_on_shutdown() {
    let state = fixture(true);
    let peer = Arc::new(MockVault {
        reply: Mutex::new(only("exa")),
        calls: AtomicUsize::new(0),
        watches: Mutex::new(Vec::new()),
    });
    let mut runtime = crate::runtime_for_test(state.runtime.store.clone());
    runtime.vault_peer = Some(peer.clone());
    let state = Arc::new(ModuleState {
        health: state.health.clone(),
        runtime,
    });
    let (stop, receiver) = mpsc::channel(1);
    let task = spawn_with_reconnect_delay(state.clone(), receiver, Duration::from_millis(1));
    until(|| !peer.watches.lock().unwrap().is_empty()).await;
    let sender = peer.watches.lock().unwrap()[0].clone();
    assert_eq!(
        peer.calls.load(Ordering::SeqCst),
        0,
        "must wait for a scoped opening snapshot"
    );
    sender.send(vault_case("watch_opening")).await.unwrap();
    until(|| {
        state
            .store()
            .auto_search_connections(OWNER)
            .unwrap()
            .iter()
            .any(|row| row.appended_at_ms.is_some())
    })
    .await;
    assert_eq!(peer.calls.load(Ordering::SeqCst), 1);
    let before = state.store().list_audit(OWNER).unwrap().len();
    sender
        .send(vault_case("watch_category_changed"))
        .await
        .unwrap();
    until(|| peer.calls.load(Ordering::SeqCst) == 2).await;
    peer.watches.lock().unwrap().clear();
    drop(sender);
    until(|| !peer.watches.lock().unwrap().is_empty()).await;
    let sender = peer.watches.lock().unwrap()[0].clone();
    sender.send(vault_case("watch_opening")).await.unwrap();
    until(|| peer.calls.load(Ordering::SeqCst) == 3).await;
    assert_eq!(
        state.store().list_audit(OWNER).unwrap().len(),
        before,
        "reconnect opening must diff without duplicate writes"
    );
    sender.send(vault_case("watch_revoked")).await.unwrap();
    until(|| sender.is_closed()).await;
    assert_eq!(
        peer.calls.load(Ordering::SeqCst),
        3,
        "terminal not_found must not be interpreted as a removal snapshot"
    );
    stop.send(()).await.unwrap();
    task.await.unwrap();
    assert!(peer
        .watches
        .lock()
        .unwrap()
        .iter()
        .all(mpsc::Sender::is_closed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn older_vault_watch_error_connects_nothing_and_never_lists() {
    let state = fixture(false);
    let peer = Arc::new(MockVault {
        reply: Mutex::new(catalog()),
        calls: AtomicUsize::new(0),
        watches: Mutex::new(Vec::new()),
    });
    let mut runtime = crate::runtime_for_test(state.runtime.store.clone());
    runtime.vault_peer = Some(peer.clone());
    let state = Arc::new(ModuleState {
        health: state.health.clone(),
        runtime,
    });
    let (stop, receiver) = mpsc::channel(1);
    let task = spawn(state.clone(), receiver);
    until(|| !peer.watches.lock().unwrap().is_empty()).await;
    let sender = peer.watches.lock().unwrap()[0].clone();
    sender
        .send(vault_case("older_vault_unknown_method"))
        .await
        .unwrap();
    until(|| sender.is_closed()).await;
    stop.send(()).await.unwrap();
    task.await.unwrap();
    assert_eq!(peer.calls.load(Ordering::SeqCst), 0);
    assert!(state.store().list_connections(OWNER).unwrap().is_empty());
    assert!(state
        .store()
        .auto_search_connections(OWNER)
        .unwrap()
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_connector_home_no_connection_revoke_or_order_write_occurs() {
    let state = fixture(true);
    Reconciler::default()
        .reconcile(&state, &only("exa"), 0, true)
        .unwrap();
    let mut runtime = crate::runtime_for_test(state.runtime.store.clone());
    runtime.connector_home = Arc::new(crate::connector_home::ConnectorHome::unavailable());
    let unheld = Arc::new(ModuleState {
        health: state.health.clone(),
        runtime,
    });
    let before = state.store().list_audit(OWNER).unwrap();
    let mut reconciler = Reconciler::default();
    reconciler
        .reconcile(&unheld, &json!({"result":{"credentials":[]}}), 1, true)
        .unwrap();
    reconciler
        .reconcile(&unheld, &only("kimi-for-coding"), 2, true)
        .unwrap();
    assert_eq!(state.store().list_audit(OWNER).unwrap(), before);
    assert_eq!(connections(state.store(), "exa_rest")[0].status, "active");
    assert!(connections(state.store(), "kimi_rest").is_empty());
    assert_eq!(
        state.store().web_search_order().unwrap().unwrap(),
        ["tavily", "exa"]
    );
}
