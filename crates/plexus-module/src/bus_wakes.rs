//! Bus messages only wake authoritative reads. No body or key-value marker grants authority.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use cortexkit_bus_client::{BusClient, EventItem, EventReader};
use cortexkit_bus_naming::AccountNames;
use cortexkit_bus_nats::NatsConnection;
use cortexkit_bus_trait::{BusResult, Register, RegisterUpdate, RegisterWatch, WatchEvent};
use plexus_core::diag;
use serde::Deserialize;

use crate::ModuleState;

pub enum ModuleEventItem {
    Ignored,
    Malformed,
    Handled,
}

/// The reader attaches only to an existing durable subscription. The bus
/// service creates and configures that subscription.
#[async_trait]
pub trait ModuleEventReader: Send {
    async fn next(&mut self) -> Result<Option<ModuleEventItem>, String>;
    async fn ack(&mut self) -> Result<(), String>;
}

struct SessionEvents {
    client: Arc<BusClient>,
    state: Arc<ModuleState>,
    reader: Option<EventReader>,
    pending: Option<EventItem>,
}

#[cfg(test)]
pub(crate) fn session_reader(
    client: Arc<BusClient>,
    state: Arc<ModuleState>,
) -> Box<dyn ModuleEventReader> {
    Box::new(SessionEvents {
        client,
        state,
        reader: None,
        pending: None,
    })
}

#[async_trait]
impl ModuleEventReader for SessionEvents {
    async fn next(&mut self) -> Result<Option<ModuleEventItem>, String> {
        if self.reader.is_none() {
            let durable =
                AccountNames::module_consumer_name("plexus").map_err(|error| error.to_string())?;
            self.reader = Some(
                self.client
                    .event_reader(&durable)
                    .await
                    .map_err(|_| "event_reader_bind_failed")?,
            );
        }
        let item = match self.reader.as_mut().expect("attached reader").next().await {
            Ok(item) => item,
            Err(_) => {
                self.reader = None;
                return Err("event_reader_failed".into());
            }
        };
        let result = match &item {
            EventItem::Delivery(delivery)
                if delivery.subject.module == "cingulate"
                    && delivery.subject.event == "card_settled"
                    && delivery.subject.version == 1
                    && delivery.subject.reader.as_deref() == Some("plexus") =>
            {
                schedule_card_settled(&self.state, &delivery.body).await?;
                ModuleEventItem::Handled
            }
            EventItem::Delivery(_) => ModuleEventItem::Ignored,
            EventItem::Malformed(_) => {
                diag!(debug bus: "malformed event received");
                ModuleEventItem::Malformed
            }
            _ => return Err("unknown_event_item".into()),
        };
        self.pending = Some(item);
        Ok(Some(result))
    }

    async fn ack(&mut self) -> Result<(), String> {
        match self.pending.take() {
            Some(EventItem::Delivery(delivery)) => delivery.ack().await,
            Some(EventItem::Malformed(delivery)) => delivery.term().await,
            None => return Ok(()),
            _ => return Err("unknown_event_item".into()),
        }
        .map_err(|_| "event_ack_failed".into())
    }
}

#[derive(Deserialize)]
struct CardSettled {
    elicitation_id: String,
    feed: String,
    seq: u64,
}

async fn schedule_card_settled(state: &Arc<ModuleState>, body: &[u8]) -> Result<(), String> {
    let Some(pointer) = serde_json::from_slice::<CardSettled>(body)
        .ok()
        .filter(|pointer| pointer.feed == "answers" && !pointer.elicitation_id.is_empty())
    else {
        diag!(debug bus: "malformed card settlement ignored");
        return Ok(());
    };
    let store = state.store().clone();
    let _sequence = pointer.seq;
    let pending = tokio::task::spawn_blocking(move || {
        store.github_manifest_bindings().map(|rows| {
            rows.into_iter().any(|row| {
                row.present
                    && row.state == "pending"
                    && row.card_id.as_deref() == Some(pointer.elicitation_id.as_str())
            })
        })
    })
    .await
    .map_err(|_| "manifest_card_lookup_join_failed")?
    .map_err(|_| "manifest_card_lookup_failed")?;
    if pending {
        state.runtime.manifest_binding_wake.notify_one();
    } else {
        diag!(debug bus: "card settlement is not a pending manifest binding");
    }
    Ok(())
}

pub(crate) fn spawn_session_watches(
    state: Arc<ModuleState>,
    client: Arc<BusClient>,
    account: &AccountNames,
) -> Result<WakeTask, String> {
    let account = account.clone();
    let mut changes = client.connection_changes();
    let mut watch = spawn_change_watch(state.clone(), client.connection(), &account)?;
    let events = WakeTask(tokio::spawn({
        let client = client.clone();
        let state = state.clone();
        async move {
            let mut reader = SessionEvents {
                client,
                state: state.clone(),
                reader: None,
                pending: None,
            };
            let (_stop, rx) = tokio::sync::mpsc::channel(1);
            run_module_event_reader(&mut reader, rx).await;
        }
    }));
    Ok(WakeTask(tokio::spawn(async move {
        let _events = events;
        loop {
            if changes.changed().await.is_err() {
                return;
            }
            drop(watch);
            watch = match spawn_change_watch(state.clone(), client.connection(), &account) {
                Ok(watch) => watch,
                Err(_) => return,
            };
        }
    })))
}

/// A missing durable is a retryable reader failure, never module startup failure.
pub async fn run_module_event_reader(
    reader: &mut dyn ModuleEventReader,
    mut stop: tokio::sync::mpsc::Receiver<()>,
) {
    let mut failures = 0u32;
    let mut logged = false;
    loop {
        let result = tokio::select! {
            _ = stop.recv() => return,
            result = read_module_event_once(reader) => result,
        };
        match result {
            Ok(true) => {
                failures = 0;
            }
            _ => {
                if !logged {
                    diag!(info bus: "module event reader deferred");
                    logged = true;
                }
                failures = failures.saturating_add(1);
                let delay = retry_delay(failures);
                tokio::select! {
                    _ = stop.recv() => return,
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

/// Process one durable delivery, acknowledging it only after its wake succeeds.
pub async fn read_module_event_once(reader: &mut dyn ModuleEventReader) -> Result<bool, String> {
    if reader.next().await?.is_none() {
        return Err("module_event_reader_ended".into());
    }
    reader.ack().await?;
    Ok(true)
}

fn retry_delay(failures: u32) -> Duration {
    Duration::from_secs(1u64.checked_shl(failures.min(9)).unwrap_or(300).min(300))
}

pub(crate) struct WakeTask(tokio::task::JoinHandle<()>);
impl Drop for WakeTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) fn spawn_change_watch(
    state: Arc<ModuleState>,
    connection: NatsConnection,
    account: &AccountNames,
) -> Result<WakeTask, String> {
    let bucket = account
        .module_bucket_name("entorhinal", "changes")
        .map_err(|error| error.to_string())?;
    Ok(WakeTask(tokio::spawn(run_change_watch(
        state,
        NatsChanges { connection, bucket },
    ))))
}

#[async_trait]
trait ChangesSource: Send + Sync {
    async fn watch(&self) -> BusResult<Box<dyn RegisterWatch>>;
}

struct NatsChanges {
    connection: NatsConnection,
    bucket: String,
}
#[async_trait]
impl ChangesSource for NatsChanges {
    async fn watch(&self) -> BusResult<Box<dyn RegisterWatch>> {
        let register = self.connection.register(&self.bucket).await?;
        Ok(Box::new(register.watch("").await?))
    }
}

async fn run_change_watch(state: Arc<ModuleState>, source: impl ChangesSource) {
    let mut failures = 0;
    let mut logged = false;
    let mut ownership = OwnershipWake::default();
    let mut agents = AgentWake::default();
    loop {
        let result = async {
            let mut watch = source.watch().await?;
            failures = 0;
            consume_changes(watch.as_mut(), &state, &mut ownership, &mut agents).await
        }
        .await;
        if let Err(error) = result {
            if !logged {
                diag!(info bus: "entorhinal changes unavailable; timers remain active: {error}");
                logged = true;
            }
            failures += 1;
            tokio::time::sleep(retry_delay(failures)).await;
        }
    }
}

#[derive(Default)]
struct OwnershipWake {
    pending: bool,
    last: Option<tokio::time::Instant>,
}

impl OwnershipWake {
    fn delay(&self) -> Duration {
        self.last
            .map(|last| {
                (last + Duration::from_secs(10))
                    .saturating_duration_since(tokio::time::Instant::now())
            })
            .unwrap_or(Duration::ZERO)
    }
}

#[derive(Default)]
struct AgentWake {
    pending: bool,
}

/// A reconnect republishes Entorhinal's `changes` bucket snapshot, including
/// `agents`. Keep the throttle outside the watcher task so reconnects cannot
/// start extra retirement sweeps.
#[derive(Default)]
pub(crate) struct AgentSweepThrottle(Mutex<Option<tokio::time::Instant>>);

impl AgentSweepThrottle {
    fn delay(&self) -> Duration {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .map(|last| {
                (last + Duration::from_secs(60))
                    .saturating_duration_since(tokio::time::Instant::now())
            })
            .unwrap_or(Duration::ZERO)
    }

    fn claim(&self) -> bool {
        let mut last = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = tokio::time::Instant::now();
        if last.is_some_and(|last| now.duration_since(last) < Duration::from_secs(60)) {
            return false;
        }
        *last = Some(now);
        true
    }
}

async fn consume_changes<W: RegisterWatch + ?Sized>(
    watch: &mut W,
    state: &Arc<ModuleState>,
    ownership: &mut OwnershipWake,
    agents: &mut AgentWake,
) -> BusResult<()> {
    let throttle = state.runtime.agent_sweep_throttle.clone();
    loop {
        tokio::select! {
            result = watch.next() => {
                let keys: Vec<String> = match result? {
                    WatchEvent::Snapshot { entries, .. } => entries.into_iter().map(|entry| entry.key).collect(),
                    WatchEvent::Update(RegisterUpdate::Put(entry)) => vec![entry.key],
                    _ => Vec::new(),
                };
                for key in keys {
                    match key.as_str() {
                        "role.connector_home" => refresh_home(state).await,
                        "registry" => ownership.pending = true,
                        "agents" => agents.pending = true,
                        _ => {}
                    }
                }
            }
            _ = tokio::time::sleep(throttle.delay()), if agents.pending => {
                if !throttle.claim() { continue; }
                agents.pending = false;
                let state = state.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    plexus_core::agent_retirement::run_and_report(state.store(), state.runtime.agent_registry.as_ref(), &state.runtime.agent_sweep_resume);
                }).await;
            }
            _ = tokio::time::sleep(ownership.delay()), if ownership.pending => {
                ownership.pending = false;
                ownership.last = Some(tokio::time::Instant::now());
                if let Some(registry) = state.runtime.repository_registry.clone() {
                    let state = state.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        plexus_core::repository_ownership::run_and_report(state.store(), registry.as_ref(), plexus_core::storage::now_ms(), &state.runtime.ownership_resume);
                    }).await;
                }
            }
        }
    }
}

async fn refresh_home(state: &Arc<ModuleState>) {
    let state = state.clone();
    let _ = tokio::task::spawn_blocking(move || state.runtime.connector_home.refresh()).await;
}

#[cfg(test)]
mod tests;
