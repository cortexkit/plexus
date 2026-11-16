use super::*;
use cortexkit_bus_inmemory::{InMemoryBus, InMemoryConfig};
use plexus_core::{
    agent_registry::PrefrontalAgentRegistry,
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
    item: Option<AgentChangedItem>,
    acks: usize,
}
#[async_trait]
impl AgentChangedReader for MemoryReader {
    async fn next(&mut self) -> Result<Option<AgentChangedItem>, String> {
        Ok(self.item.take())
    }
    async fn ack(&mut self) -> Result<(), String> {
        self.acks += 1;
        Ok(())
    }
    async fn nak(&mut self, _: Duration) -> Result<(), String> {
        Ok(())
    }
}
fn reader(body: Value) -> MemoryReader {
    MemoryReader {
        acks: 0,
        item: Some(AgentChangedItem::Delivery(AgentChangedDelivery {
            subject: AccountNames::derive("box_test")
                .unwrap()
                .event_subject("prefrontal-core", "agent_changed", 1)
                .unwrap(),
            msg_id: "fact".into(),
            body: serde_json::to_vec(&body).unwrap(),
            headers: BTreeMap::new(),
            sequence: 1,
        })),
    }
}

#[tokio::test]
async fn retired_event_resolves_once_and_only_well_formed_gone_revokes() {
    for (reply, revoked, acked) in [
        (json!({"gone":{"at":1,"reason":"deleted"}}), true, true),
        (json!({"agent":{"agent_id":"agent"}}), false, true),
        (json!({"error":{"code":"unknown_agent"}}), false, true),
        (json!({"gone":{"reason":"deleted"}}), false, false),
    ] {
        let (_scratch, state) = fixture();
        state
            .store()
            .insert_agent_grant_for_test(
                &plexus_core::GrantInput {
                    grant_id: "grant".into(),
                    principal: "direct".into(),
                    connection_id: "conn".into(),
                    grantee_principal: "reserved:aft".into(),
                    risk_ceiling: "write".into(),
                    action_selectors: vec!["github.issue.comment".into()],
                    authority_kind: "invoke".into(),
                    expires_at: None,
                },
                "agent",
            )
            .unwrap();
        let peer = Peer::new(Ok(reply));
        let registry = Arc::new(PrefrontalAgentRegistry::new(peer.clone()));
        let mut reader = reader(json!({"agent_id":"agent", "change":"retired", "seq":1}));
        let complete = read_agent_changed_once(
            &mut reader,
            state.store().clone(),
            registry,
            &AccountNames::derive("box_test").unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(complete, acked);
        assert_eq!(reader.acks, usize::from(acked));
        assert_eq!(
            *peer.calls.lock().unwrap(),
            [("agent.resolve".into(), json!({"agent_id":"agent"}))]
        );
        assert_eq!(
            state
                .store()
                .grants_held_by_agent("agent")
                .unwrap()
                .is_empty(),
            revoked
        );
    }
}

#[tokio::test]
async fn non_retired_unknown_and_malformed_events_ack_without_resolving() {
    let (_scratch, state) = fixture();
    let peer = Peer::new(Ok(json!({})));
    let registry = Arc::new(PrefrontalAgentRegistry::new(peer.clone()));
    for body in [
        json!({"agent_id":"agent","change":"created","seq":1}),
        json!({"agent_id":"agent","change":"merged","seq":1}),
        json!({"agent_id":"agent","change":"residence_moved","seq":1}),
        json!({"agent_id":"agent","change":"future","seq":1}),
        json!({"change":"retired"}),
    ] {
        let mut reader = reader(body);
        assert!(read_agent_changed_once(
            &mut reader,
            state.store().clone(),
            registry.clone(),
            &AccountNames::derive("box_test").unwrap()
        )
        .await
        .unwrap());
        assert_eq!(reader.acks, 1);
    }
    let mut reader = MemoryReader {
        acks: 0,
        item: Some(AgentChangedItem::Malformed),
    };
    read_agent_changed_once(
        &mut reader,
        state.store().clone(),
        registry,
        &AccountNames::derive("box_test").unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(reader.acks, 1);
    assert!(peer.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unreachable_registry_leaves_delivery_unacked() {
    let (_scratch, state) = fixture();
    let peer = Peer::new(Err(PrefrontalRouteError::Transport));
    let mut reader = reader(json!({"agent_id":"agent","change":"retired","seq":1}));
    assert!(!read_agent_changed_once(
        &mut reader,
        state.store().clone(),
        Arc::new(PrefrontalAgentRegistry::new(peer)),
        &AccountNames::derive("box_test").unwrap()
    )
    .await
    .unwrap());
    assert_eq!(reader.acks, 0);
}

async fn until(predicate: impl Fn() -> bool) {
    let start = std::time::Instant::now();
    while !predicate() {
        assert!(start.elapsed() < Duration::from_secs(3), "wake did not run");
        tokio::task::yield_now().await;
    }
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
        consume_changes(&mut watch, &state, &mut OwnershipWake::default()).await
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
        consume_changes(&mut watch, &state, &mut OwnershipWake::default()).await
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
impl AgentChangedReader for MissingDurable {
    async fn next(&mut self) -> Result<Option<AgentChangedItem>, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err("missing durable m_plexus".into())
    }
    async fn ack(&mut self) -> Result<(), String> {
        panic!("missing durable cannot be acked")
    }
    async fn nak(&mut self, _: Duration) -> Result<(), String> {
        panic!("missing durable cannot be nacked")
    }
}

#[tokio::test(start_paused = true)]
async fn missing_durable_retries_without_stopping_or_acking() {
    let (_scratch, state) = fixture();
    let attempts = Arc::new(AtomicUsize::new(0));
    let (stop, receiver) = tokio::sync::mpsc::channel(1);
    let count = attempts.clone();
    let task = tokio::spawn(async move {
        run_agent_changed_reader(
            &mut MissingDurable(count),
            state.store().clone(),
            state.runtime.agent_registry.clone(),
            &AccountNames::derive("box_test").unwrap(),
            receiver,
        )
        .await;
    });
    until(|| attempts.load(Ordering::SeqCst) == 1).await;
    assert!(!task.is_finished());
    tokio::time::advance(Duration::from_secs(2)).await;
    until(|| attempts.load(Ordering::SeqCst) == 2).await;
    stop.send(()).await.unwrap();
    task.await.unwrap();
}
