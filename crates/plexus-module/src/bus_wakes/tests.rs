use super::*;
use cortexkit_bus_inmemory::{InMemoryBus, InMemoryConfig};
use plexus_core::PlexusStore;
use plexus_core::{
    agent_registry::EntorhinalAgentRegistry,
    github_identity::{PrefrontalRouteError, PrefrontalRoutePeer},
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

fn fixture() -> (plexus_core::test_scratch::Scratch, Arc<ModuleState>) {
    let scratch = plexus_core::test_scratch::Scratch::database("bus-wakes");
    let store = Arc::new(
        PlexusStore::open(&cortexkit_store::StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "bus-wakes".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    let runtime = crate::runtime_for_test(store);
    (
        scratch,
        Arc::new(ModuleState {
            runtime,
            health: Arc::new(crate::health::HealthState::new()),
        }),
    )
}

struct Peer {
    calls: Mutex<Vec<(String, Value)>>,
    reply: Mutex<Result<Value, PrefrontalRouteError>>,
}
impl Peer {
    fn new(reply: Result<Value, PrefrontalRouteError>) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(vec![]),
            reply: Mutex::new(reply),
        })
    }
}
impl PrefrontalRoutePeer for Peer {
    fn call(&self, op: &str, params: Value) -> Result<Value, PrefrontalRouteError> {
        self.calls.lock().unwrap().push((op.into(), params));
        self.reply.lock().unwrap().clone()
    }
}

struct MemoryReader {
    item: Option<ModuleEventItem>,
    acks: usize,
}
#[async_trait]
impl ModuleEventReader for MemoryReader {
    async fn next(&mut self) -> Result<Option<ModuleEventItem>, String> {
        Ok(self.item.take())
    }
    async fn ack(&mut self) -> Result<(), String> {
        self.acks += 1;
        Ok(())
    }
}

#[tokio::test]
async fn handled_ignored_and_malformed_deliveries_ack() {
    for item in [
        ModuleEventItem::Handled,
        ModuleEventItem::Ignored,
        ModuleEventItem::Malformed,
    ] {
        let mut reader = MemoryReader {
            acks: 0,
            item: Some(item),
        };
        assert!(read_module_event_once(&mut reader).await.unwrap());
        assert_eq!(reader.acks, 1);
    }
}

async fn until(predicate: impl Fn() -> bool) {
    let start = std::time::Instant::now();
    while !predicate() {
        assert!(start.elapsed() < Duration::from_secs(3), "wake did not run");
        tokio::task::yield_now().await;
    }
}

fn plant_agent_grant(store: &PlexusStore, id: &str) {
    store
        .insert_agent_grant_for_test(
            &plexus_core::GrantInput {
                grant_id: format!("grant-{id}"),
                principal: "direct".into(),
                connection_id: "conn".into(),
                grantee_principal: "reserved:aft".into(),
                risk_ceiling: "write".into(),
                action_selectors: vec!["github.issue.comment".into()],
                authority_kind: "invoke".into(),
                expires_at: None,
            },
            id,
        )
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn agents_snapshot_and_bursts_run_one_full_sweep_per_sixty_seconds() {
    let (_scratch, state) = fixture();
    for id in ["agent-a", "agent-z"] {
        plant_agent_grant(state.store(), id);
    }
    let registry = Arc::new(
        plexus_core::agent_registry::StubAgentRegistry::with_default_response(
            plexus_core::AgentLookup::Known,
        ),
    );
    let mut runtime = crate::runtime_for_test(state.store().clone());
    runtime.agent_registry = registry.clone();
    let state = Arc::new(ModuleState {
        runtime,
        health: Arc::new(crate::health::HealthState::new()),
    });
    let bus = InMemoryBus::new(InMemoryConfig::default());
    bus.put(
        "agents",
        br#"{"generation":1,"incarnation":"first"}"#.to_vec(),
    )
    .await
    .unwrap();
    let mut watch = bus.watch("").await.unwrap();
    let task = tokio::spawn(async move {
        consume_changes(
            &mut watch,
            &state,
            &mut OwnershipWake::default(),
            &mut AgentWake::default(),
        )
        .await
    });
    until(|| registry.requests().len() == 2).await;
    assert_eq!(registry.requests(), ["agent-a", "agent-z"]);
    for generation in 2..20 {
        bus.put(
            "agents",
            json!({"generation":generation,"incarnation":"first"})
                .to_string()
                .into_bytes(),
        )
        .await
        .unwrap();
    }
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(59)).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(registry.requests().len(), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    until(|| registry.requests().len() == 4).await;
    assert_eq!(
        registry.requests(),
        ["agent-a", "agent-z", "agent-a", "agent-z"]
    );
    task.abort();
    let _ = task.await;
}

#[tokio::test(start_paused = true)]
async fn agents_reconnect_snapshot_keeps_runtime_throttle() {
    let (_scratch, state) = fixture();
    plant_agent_grant(state.store(), "agent");
    let registry = Arc::new(
        plexus_core::agent_registry::StubAgentRegistry::with_default_response(
            plexus_core::AgentLookup::Known,
        ),
    );
    let mut runtime = crate::runtime_for_test(state.store().clone());
    runtime.agent_registry = registry.clone();
    let state = Arc::new(ModuleState {
        runtime,
        health: Arc::new(crate::health::HealthState::new()),
    });
    let bus = InMemoryBus::new(InMemoryConfig::default());
    bus.put(
        "agents",
        br#"{"generation":1,"incarnation":"first"}"#.to_vec(),
    )
    .await
    .unwrap();
    let start_watch = || {
        let bus = bus.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let mut watch = bus.watch("").await.unwrap();
            consume_changes(
                &mut watch,
                &state,
                &mut OwnershipWake::default(),
                &mut AgentWake::default(),
            )
            .await
        })
    };
    let first = start_watch();
    until(|| registry.requests().len() == 1).await;
    first.abort();
    let _ = first.await;
    let reconnected = start_watch();
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(59)).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        registry.requests().len(),
        1,
        "a reconnect snapshot bypassed the runtime's throttle"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    until(|| registry.requests().len() == 2).await;
    reconnected.abort();
    let _ = reconnected.await;
}

#[tokio::test(start_paused = true)]
async fn agents_wake_and_scheduler_share_one_retirement_resume_point() {
    let (_scratch, state) = fixture();
    for id in ["agent-a", "agent-z"] {
        plant_agent_grant(state.store(), id);
    }
    let peer = Peer::new(Err(PrefrontalRouteError::Transport));
    let mut runtime = crate::runtime_for_test(state.store().clone());
    runtime.agent_registry = Arc::new(EntorhinalAgentRegistry::new(peer.clone()));
    let state = Arc::new(ModuleState {
        runtime,
        health: Arc::new(crate::health::HealthState::new()),
    });
    let bus = InMemoryBus::new(InMemoryConfig::default());
    let mut watch = bus.watch("").await.unwrap();
    let wake_state = state.clone();
    let task = tokio::spawn(async move {
        consume_changes(
            &mut watch,
            &wake_state,
            &mut OwnershipWake::default(),
            &mut AgentWake::default(),
        )
        .await
    });
    bus.put("agents", vec![]).await.unwrap();
    until(|| peer.calls.lock().unwrap().len() == 1).await;
    let (stop, receiver) = tokio::sync::mpsc::channel(1);
    let scheduler = crate::spawn_trigger_scheduler(state, receiver, 604_800_000);
    until(|| peer.calls.lock().unwrap().len() == 2).await;
    stop.send(()).await.unwrap();
    scheduler.await.unwrap();
    assert_eq!(
        *peer.calls.lock().unwrap(),
        [
            ("agent.resolve".into(), json!({"agent_id":"agent-a"})),
            ("agent.resolve".into(), json!({"agent_id":"agent-z"})),
        ]
    );
    bus.put("agents", vec![]).await.unwrap();
    tokio::time::advance(Duration::from_secs(60)).await;
    until(|| peer.calls.lock().unwrap().len() == 3).await;
    assert_eq!(
        peer.calls.lock().unwrap()[2].1,
        json!({"agent_id":"agent-a"})
    );
    task.abort();
    let _ = task.await;
}

struct RolePeer {
    calls: AtomicUsize,
    reply: Mutex<Result<Value, subc_protocol::ErrorBody>>,
}
impl crate::connector_home::RolePeer for RolePeer {
    fn call(&self, method: &str, params: Value) -> Result<Value, subc_protocol::ErrorBody> {
        assert_eq!(method, "role.read");
        assert_eq!(params, json!({"role":"connector_home"}));
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.reply.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn connector_home_put_reads_role_and_never_trusts_marker_state() {
    let (_scratch, state) = fixture();
    let peer = Arc::new(RolePeer {
        calls: AtomicUsize::new(0),
        reply: Mutex::new(Ok(json!({
            "role":"connector_home", "epoch":1, "holder":null, "holder_name":null, "source":null,
            "known":true, "held_here":true, "stale":false
        }))),
    });
    let mut runtime = crate::runtime_for_test(state.store().clone());
    let home = Arc::new(crate::connector_home::ConnectorHome::new(peer.clone()));
    runtime.connector_home = home.clone();
    home.refresh().unwrap();
    *peer.reply.lock().unwrap() = Err(subc_protocol::ErrorBody {
        code: "unavailable".into(),
        message: "offline".into(),
        detail: None,
    });
    let state = Arc::new(ModuleState {
        runtime,
        health: Arc::new(crate::health::HealthState::new()),
    });
    let bus = InMemoryBus::new(InMemoryConfig::default());
    bus.put(
        "role.connector_home",
        br#"{"epoch":998,"held_here":false}"#.to_vec(),
    )
    .await
    .unwrap();
    let mut watch = bus.watch("").await.unwrap();
    let task = tokio::spawn(async move {
        consume_changes(
            &mut watch,
            &state,
            &mut OwnershipWake::default(),
            &mut AgentWake::default(),
        )
        .await
    });
    until(|| peer.calls.load(Ordering::SeqCst) == 2).await;
    bus.put(
        "role.connector_home",
        br#"{"epoch":999,"held_here":false,"state":"not_held"}"#.to_vec(),
    )
    .await
    .unwrap();
    until(|| peer.calls.load(Ordering::SeqCst) == 3).await;
    assert!(
        home.held(),
        "a KV value changed holding without an authoritative answer"
    );
    bus.put("unrelated", vec![]).await.unwrap();
    bus.delete("role.connector_home").await.unwrap();
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(peer.calls.load(Ordering::SeqCst), 3);
    task.abort();
    let _ = task.await;
}

#[tokio::test(start_paused = true)]
async fn registry_snapshot_and_bursts_schedule_at_most_one_pass_per_ten_seconds() {
    let (_scratch, state) = fixture();
    let peer = Peer::new(Err(PrefrontalRouteError::Transport));
    let mut runtime = crate::runtime_for_test(state.store().clone());
    runtime.repository_registry = Some(Arc::new(
        plexus_core::repository_ownership::EntorhinalRepositoryRegistry::new(peer.clone()),
    ));
    let state = Arc::new(ModuleState {
        runtime,
        health: Arc::new(crate::health::HealthState::new()),
    });
    let bus = InMemoryBus::new(InMemoryConfig::default());
    bus.put(
        "registry",
        br#"{"generation":1,"incarnation":"first"}"#.to_vec(),
    )
    .await
    .unwrap();
    let mut watch = bus.watch("").await.unwrap();
    let task = tokio::spawn(async move {
        consume_changes(
            &mut watch,
            &state,
            &mut OwnershipWake::default(),
            &mut AgentWake::default(),
        )
        .await
    });
    until(|| peer.calls.lock().unwrap().len() == 1).await;
    assert_eq!(peer.calls.lock().unwrap()[0].0, "enumerate");
    for generation in 2..20 {
        bus.put(
            "registry",
            json!({"generation":generation,"incarnation":"first"})
                .to_string()
                .into_bytes(),
        )
        .await
        .unwrap();
    }
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(peer.calls.lock().unwrap().len(), 1);
    tokio::time::advance(Duration::from_secs(10)).await;
    until(|| peer.calls.lock().unwrap().len() == 2).await;
    task.abort();
    let _ = task.await;
}

struct InitiallyMissingBucket {
    bus: InMemoryBus,
    attempts: Arc<AtomicUsize>,
}

#[tokio::test(start_paused = true)]
async fn registry_wake_and_scheduler_share_one_ownership_resume_point() {
    let (_scratch, state) = fixture();
    let store = state.store().clone();
    let source =
        subc_jsonc::jsonc_to_json(include_str!("../../../../catalog/github.jsonc")).unwrap();
    let manifest = plexus_core::ingest_value(serde_json::from_str(&source).unwrap()).unwrap();
    store.upsert_manifest("system", &manifest).unwrap();
    store
        .insert_connection("direct", "ownership", "github", "active", &json!({}))
        .unwrap();
    store.upsert_catalog_action(&plexus_core::CatalogActionInput {
        connection_id: "ownership".into(), principal: "direct".into(),
        name: "list_issues".into(), title: None,
        schema: json!({"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"}}}),
        schema_hash: "ownership-schema".into(), risk: "read".into(), severity: "S2".into(),
        status: "active".into(), quarantine_reason: None, reconciliation: None, ask_first: false,
    }).unwrap();
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "ownership-poll".into(),
            principal: "direct".into(),
            connection_id: "ownership".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["list_issues".into()],
            authority_kind: "poll".into(),
            expires_at: None,
        })
        .unwrap();
    for repo in ["a", "b"] {
        store
            .subscribe_with_cursor_state(
                "direct",
                "ownership",
                "list_issues",
                300,
                &json!({}),
                &json!({"owner":"owner","repo":repo}),
            )
            .unwrap()
            .unwrap();
    }
    let peer = Peer::new(Err(PrefrontalRouteError::Transport));
    let mut runtime = crate::runtime_for_test(store);
    runtime.repository_registry = Some(Arc::new(
        plexus_core::repository_ownership::EntorhinalRepositoryRegistry::new(peer.clone()),
    ));
    let state = Arc::new(ModuleState {
        runtime,
        health: Arc::new(crate::health::HealthState::new()),
    });
    let bus = InMemoryBus::new(InMemoryConfig::default());
    let mut watch = bus.watch("").await.unwrap();
    let wake_state = state.clone();
    let wake = tokio::spawn(async move {
        consume_changes(
            &mut watch,
            &wake_state,
            &mut OwnershipWake::default(),
            &mut AgentWake::default(),
        )
        .await
    });
    bus.put("registry", vec![]).await.unwrap();
    until(|| peer.calls.lock().unwrap().len() == 1).await;

    let (stop, receiver) = tokio::sync::mpsc::channel(1);
    let scheduler = crate::spawn_trigger_scheduler(state, receiver, 604_800_000);
    until(|| peer.calls.lock().unwrap().len() >= 2).await;
    stop.send(()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), scheduler)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        *peer.calls.lock().unwrap(),
        [
            ("resolve_remote".into(), json!({"owner":"owner","repo":"a"})),
            ("resolve_remote".into(), json!({"owner":"owner","repo":"b"})),
        ],
        "the scheduler must start after the unanswered repository from the wake"
    );

    bus.put("registry", vec![]).await.unwrap();
    tokio::time::advance(Duration::from_secs(10)).await;
    until(|| peer.calls.lock().unwrap().len() == 3).await;
    assert_eq!(
        peer.calls.lock().unwrap()[2],
        ("resolve_remote".into(), json!({"owner":"owner","repo":"a"})),
        "the next wake must resume after the scheduler's unanswered repository"
    );
    wake.abort();
    let _ = wake.await;
}
#[async_trait]
impl ChangesSource for InitiallyMissingBucket {
    async fn watch(&self) -> BusResult<Box<dyn RegisterWatch>> {
        if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(cortexkit_bus_trait::BusError::absent("missing bucket"));
        }
        Ok(Box::new(self.bus.watch("").await?))
    }
}

#[tokio::test(start_paused = true)]
async fn missing_bucket_keeps_task_alive_and_retries_with_bounded_backoff() {
    let (_scratch, state) = fixture();
    let held_before = state.runtime.connector_home.held();
    let attempts = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(run_change_watch(
        state.clone(),
        InitiallyMissingBucket {
            bus: InMemoryBus::new(InMemoryConfig::default()),
            attempts: attempts.clone(),
        },
    ));
    until(|| attempts.load(Ordering::SeqCst) == 1).await;
    assert!(!task.is_finished());
    assert_eq!(state.runtime.connector_home.held(), held_before);
    tokio::time::advance(Duration::from_secs(2)).await;
    until(|| attempts.load(Ordering::SeqCst) == 2).await;
    assert!(!task.is_finished());
    for failures in 0..100 {
        assert!(retry_delay(failures) <= Duration::from_secs(300));
    }
    task.abort();
    let _ = task.await;
}

struct MissingDurable(Arc<AtomicUsize>);
#[async_trait]
impl ModuleEventReader for MissingDurable {
    async fn next(&mut self) -> Result<Option<ModuleEventItem>, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err("missing durable m_plexus".into())
    }
    async fn ack(&mut self) -> Result<(), String> {
        panic!("missing durable cannot be acked")
    }
}

#[tokio::test(start_paused = true)]
async fn missing_durable_retries_without_stopping_or_acking() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let (stop, receiver) = tokio::sync::mpsc::channel(1);
    let count = attempts.clone();
    let task = tokio::spawn(async move {
        run_module_event_reader(&mut MissingDurable(count), receiver).await;
    });
    until(|| attempts.load(Ordering::SeqCst) == 1).await;
    assert!(!task.is_finished());
    tokio::time::advance(Duration::from_secs(2)).await;
    until(|| attempts.load(Ordering::SeqCst) == 2).await;
    stop.send(()).await.unwrap();
    task.await.unwrap();
}
