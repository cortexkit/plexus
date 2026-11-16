//! Bus messages only wake authoritative reads. No body or key-value marker grants authority.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use cortexkit_bus_naming::AccountNames;
use cortexkit_bus_nats::NatsConnection;
use cortexkit_bus_trait::{BusResult, Register, RegisterUpdate, RegisterWatch, WatchEvent};
use plexus_core::{agent_registry::AgentRegistry, diag, PlexusStore};
use serde::Deserialize;

use crate::ModuleState;

pub struct AgentChangedDelivery {
    pub subject: String,
    pub msg_id: String,
    pub body: Vec<u8>,
    pub headers: BTreeMap<String, String>,
    pub sequence: u64,
}

pub enum AgentChangedItem {
    Delivery(AgentChangedDelivery),
    Malformed,
}

/// cortexkit-bus-client's body-capable EventReader will supply this bind-only seam.
/// It must bind `m_plexus`, never create a durable or fetch another credential.
#[async_trait]
pub trait AgentChangedReader: Send {
    async fn next(&mut self) -> Result<Option<AgentChangedItem>, String>;
    async fn ack(&mut self) -> Result<(), String>;
    async fn nak(&mut self, delay: Duration) -> Result<(), String>;
}

/// A missing durable is a retryable reader failure, never module startup failure.
pub async fn run_agent_changed_reader(
    reader: &mut dyn AgentChangedReader,
    store: Arc<PlexusStore>,
    registry: Arc<dyn AgentRegistry>,
    account: &AccountNames,
    mut stop: tokio::sync::mpsc::Receiver<()>,
) {
    let mut failures = 0u32;
    let mut logged = false;
    loop {
        let result = tokio::select! {
            _ = stop.recv() => return,
            result = read_agent_changed_once(reader, store.clone(), registry.clone(), account) => result,
        };
        match result {
            Ok(true) => {
                failures = 0;
            }
            result => {
                if !logged {
                    diag!(info bus: "agent change reader deferred; hourly sweep remains active");
                    logged = true;
                }
                failures = failures.saturating_add(1);
                let delay = retry_delay(failures);
                if matches!(result, Ok(false)) {
                    let _ = reader.nak(delay).await;
                }
                tokio::select! {
                    _ = stop.recv() => return,
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

#[derive(Deserialize)]
struct AgentChanged {
    agent_id: String,
    change: String,
    seq: u64,
}

/// False leaves the current delivery unacked so the durable can retry it.
pub async fn read_agent_changed_once(
    reader: &mut dyn AgentChangedReader,
    store: Arc<PlexusStore>,
    registry: Arc<dyn AgentRegistry>,
    account: &AccountNames,
) -> Result<bool, String> {
    let Some(item) = reader.next().await? else {
        return Err("agent_changed_reader_ended".into());
    };
    let expected = account
        .event_subject("prefrontal-core", "agent_changed", 1)
        .map_err(|error| error.to_string())?;
    let agent = match item {
        AgentChangedItem::Delivery(delivery) if delivery.subject == expected => {
            serde_json::from_slice::<AgentChanged>(&delivery.body)
                .ok()
                .filter(|event| !event.agent_id.is_empty())
        }
        _ => None,
    };
    if let Some(event) = agent.filter(|event| event.change == "retired") {
        let _sequence = event.seq;
        let complete = tokio::task::spawn_blocking(move || {
            plexus_core::agent_retirement::check_retired_agent(
                &store,
                registry.as_ref(),
                &event.agent_id,
            )
        })
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
        if !complete {
            return Ok(false);
        }
    } else {
        diag!(debug bus: "agent change ignored: non-retired, unknown, or malformed delivery");
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
    loop {
        let result = async {
            let mut watch = source.watch().await?;
            failures = 0;
            consume_changes(watch.as_mut(), &state, &mut ownership).await
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
    resume: plexus_core::repository_ownership::OwnershipResume,
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

async fn consume_changes<W: RegisterWatch + ?Sized>(
    watch: &mut W,
    state: &Arc<ModuleState>,
    ownership: &mut OwnershipWake,
) -> BusResult<()> {
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
                        _ => {}
                    }
                }
            }
            _ = tokio::time::sleep(ownership.delay()), if ownership.pending => {
                ownership.pending = false;
                ownership.last = Some(tokio::time::Instant::now());
                if let Some(registry) = state.runtime.repository_registry.clone() {
                    let state = state.clone();
                    let resume = std::mem::take(&mut ownership.resume);
                    if let Ok(resume) = tokio::task::spawn_blocking(move || {
                        plexus_core::repository_ownership::run_and_report(state.store(), registry.as_ref(), plexus_core::storage::now_ms(), &resume);
                        resume
                    }).await { ownership.resume = resume; }
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
