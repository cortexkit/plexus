//! Authenticated NATS bus connection and outbox drain for plexus notices.
//! Obtains credentials from ck-bus, the NATS credential module, over subc,
//! the module supervisor. Never logs credential material and drains the store's
//! outbox markers to JetStream.
//! Connector home is the claim in engram that this machine may contact outside
//! services; Plexus blocks outward effects unless it holds the claim.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use cortexkit_bus_client::{BusClient, BusClientOptions};
use cortexkit_bus_naming::AccountNames;
use cortexkit_bus_nats::NatsConnection;
use cortexkit_bus_trait::{BusError, ContentDigest, Headers, PublishReceipt, Stream};
use plexus_core::storage::event_outbox::{OutboxCursor, OutboxVersion};
use plexus_core::{event_key::PUBLISHED_EVENTS, storage::now_ms, EventHeaders, PlexusStore};
use subc_client_rs::{ConsumerOptions, SubcConsumer};
use tokio::sync::mpsc;

use tracing_subscriber::layer::SubscriberExt;

use crate::ModuleState;

const OUTBOX_BATCH: usize = 50;
const OUTBOX_IDLE: Duration = Duration::from_secs(30);

fn session_reusable(error: &str) -> bool {
    matches!(
        error,
        "nats_publish_refused" | "nats_publish_clamped" | "nats_publish_capacity"
    )
}

const OWN_CRATE_NAMES: &[&str] = &[
    "plexus_core",
    "plexus_module",
    "plexus_probe",
    "plexus_conformance",
    "ck_plexus",
    "ck_plexus_admin",
];

pub(crate) fn safe_log_layer(
    config: cortexkit_log::Config,
) -> Result<(cortexkit_log::LogLayer, cortexkit_log::Handle), cortexkit_log::InitError> {
    // The logger gives every dependency a separate namespace and default WARN
    // cap. Only these compiled Plexus crates keep the module's own namespaces.
    let crates = cortexkit_log::Crates::new()
        .own(OWN_CRATE_NAMES.iter().copied())
        .ceiling("tungstenite", cortexkit_log::LevelFilter::OFF)
        .ceiling("tokio_tungstenite", cortexkit_log::LevelFilter::OFF)
        .ceiling("async_nats", cortexkit_log::LevelFilter::INFO);
    let (layer, handle) = cortexkit_log::layer(config)?;
    Ok((layer.with_crates(crates), handle))
}

pub(crate) fn init_logger_from_env() -> Result<cortexkit_log::Handle, cortexkit_log::InitError> {
    let (layer, handle) = safe_log_layer(cortexkit_log::Config::from_env()?)?;
    tracing::subscriber::set_global_default(tracing_subscriber::Registry::default().with(layer))
        .map_err(|_| cortexkit_log::InitError::GlobalSubscriberAlreadySet)?;
    handle.install_panic_hook();
    Ok(handle)
}

/// Abstract publisher for event notices.
#[async_trait]
#[allow(clippy::double_must_use)]
pub trait EventPublisher: Send + Sync {
    fn connection(&self) -> Option<NatsConnection> {
        None
    }
    async fn publish(
        &self,
        subject: &str,
        id: &str,
        digest: ContentDigest,
        headers: Headers,
    ) -> Result<PublishReceipt, String>;
}

/// Real NATS JetStream publisher using `cortexkit-bus-nats`.
pub struct NatsEventPublisher {
    pub connection: NatsConnection,
    pub stream_name: String,
}

/// Read the current NATS connection for each notice after a credential re-issue.
/// The raw stream publisher preserves GitHub's empty payload and digest header;
/// readers retrieve the stored event body from Plexus rather than from the bus.
struct ClientEventPublisher(Arc<BusClient>);

#[async_trait]
impl EventPublisher for ClientEventPublisher {
    async fn publish(
        &self,
        subject: &str,
        id: &str,
        digest: ContentDigest,
        headers: Headers,
    ) -> Result<PublishReceipt, String> {
        let account = AccountNames::derive(self.0.acct()).map_err(|_| "ckbus_invalid_account")?;
        NatsEventPublisher {
            connection: self.0.connection(),
            stream_name: account.streams().event.clone(),
        }
        .publish(subject, id, digest, headers)
        .await
    }
}

/// Searches only enqueue. The outbox task supplies a weak reference to its
/// connector-home session so searches cannot keep it alive after claim loss.
#[derive(Default)]
pub(crate) struct RouteFactBus {
    binding: Mutex<Option<RouteFactBinding>>,
}

struct RouteFactBinding {
    client: std::sync::Weak<BusClient>,
    home: std::sync::Weak<crate::connector_home::ConnectorHome>,
}

impl RouteFactBus {
    fn bind(&self, client: &Arc<BusClient>, home: &Arc<crate::connector_home::ConnectorHome>) {
        *self.binding.lock().unwrap_or_else(|p| p.into_inner()) = Some(RouteFactBinding {
            client: Arc::downgrade(client),
            home: Arc::downgrade(home),
        });
    }
}

impl plexus_core::web_search::routing::RouteFactPublisher for RouteFactBus {
    fn publish_event<'a>(
        &'a self,
        event: &'a str,
        version: u32,
        reader: Option<&'a str>,
        msg_id: &'a str,
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let (client, home) = self
                .binding
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .and_then(|binding| Some((binding.client.upgrade()?, binding.home.upgrade()?)))
                .ok_or("route_fact_session_absent")?;
            if !home.held() {
                return Err("connector_home_not_held".into());
            }
            let receipt = client
                .publish_event(event, version, reader, msg_id, body.to_vec())
                .await
                .map_err(|_| "route_fact_publish_failed")?;
            if receipt.duplicate() {
                plexus_core::diag!(debug bus: "route fact retry acknowledged: id={msg_id}");
            }
            Ok(())
        })
    }
}

#[async_trait]
impl EventPublisher for NatsEventPublisher {
    fn connection(&self) -> Option<NatsConnection> {
        Some(self.connection.clone())
    }
    async fn publish(
        &self,
        subject: &str,
        id: &str,
        digest: ContentDigest,
        headers: Headers,
    ) -> Result<PublishReceipt, String> {
        let stream = self.connection.stream(&self.stream_name);
        stream
            .publish(subject, id, digest, headers)
            .await
            .map_err(|error| {
                match error {
                    BusError::Denied { .. } | BusError::Absent { .. } => "nats_publish_refused",
                    BusError::Clamped { .. } => "nats_publish_clamped",
                    BusError::Unavailable {
                        exhausted_limit: Some(_),
                        ..
                    } => "nats_publish_capacity",
                    _ => "nats_publish_failed",
                }
                .into()
            })
    }
}

/// Build filter headers from the event's declaration so a notice cannot gain
/// labels the manifest does not promise.
///
/// An event with no published declaration (a stored row whose declaration was
/// later removed) is an error for that row, not a panic: the outbox holds rows
/// written by older builds, and one such row must not kill the drain task.
pub(crate) fn notice_headers(
    event_name: &str,
    event: &EventHeaders,
) -> Result<BTreeMap<String, String>, String> {
    let declaration = PUBLISHED_EVENTS
        .iter()
        .find(|declaration| declaration.name == event_name)
        .ok_or_else(|| format!("event_undeclared: {event_name} has no published declaration"))?;
    let mut headers = BTreeMap::new();
    headers.insert("kind".to_string(), event_name.to_string());
    // A producer that fills a label this event doesn't declare is a drift between
    // the producers and the declaration. The label is withheld either way, so say
    // so instead of dropping it silently.
    let undeclared: Vec<&str> = [
        ("pr", event.pr.is_some()),
        ("branch", event.branch.is_some()),
        ("conclusion", event.conclusion.is_some()),
    ]
    .into_iter()
    .filter(|(name, set)| *set && !declaration.headers.contains(name))
    .map(|(name, _)| name)
    .collect();
    if !undeclared.is_empty() {
        eprintln!(warn bus: "{event_name} notice withheld undeclared labels {undeclared:?}");
    }
    for name in declaration.headers {
        let value = match *name {
            "repo" => Some(event.repo.to_ascii_lowercase()),
            "project" => event.project.clone(),
            "pr" => event.pr.clone(),
            "branch" => event.branch.clone(),
            "conclusion" => event.conclusion.clone(),
            other => {
                return Err(format!(
                    "event_header_unmapped: {event_name} declares header {other} with no publisher mapping"
                ))
            }
        };
        if let Some(value) = value {
            if value.chars().any(char::is_control) {
                return Err("header_invalid".into());
            }
            headers.insert((*name).to_string(), value);
        }
    }
    Ok(headers)
}

/// Rows that cannot form a notice, plus a per-version keyset walk. Rebuild
/// remembered poison keys at the end of each complete sweep so deleted rows
/// cannot accumulate in process memory forever.
#[derive(Default)]
pub(crate) struct UnpublishableRows(Mutex<DrainCursorState>);

#[derive(Default)]
struct DrainCursorState {
    known: BTreeSet<(u8, String)>,
    seen: BTreeSet<(u8, String)>,
    after: BTreeMap<u8, OutboxCursor>,
    refused_passes: BTreeMap<(u8, String), u32>,
}

impl UnpublishableRows {
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).known.len()
    }
    fn cursor(&self, version: u8) -> Option<OutboxCursor> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .after
            .get(&version)
            .cloned()
    }
    fn pending_more(&self) -> bool {
        !self
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .after
            .is_empty()
    }
    fn advance(&self, version: u8, cursor: OutboxCursor) {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .after
            .insert(version, cursor);
    }
    fn contains(&self, version: u8, key: &str) -> bool {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let key = (version, key.to_owned());
        if state.known.contains(&key) {
            state.seen.insert(key);
            true
        } else {
            false
        }
    }
    fn insert(&self, version: u8, key: &str) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let key = (version, key.to_owned());
        state.known.insert(key.clone());
        state.seen.insert(key);
    }
    fn complete_sweep(&self, version: u8) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let seen = std::mem::take(&mut state.seen);
        state
            .known
            .retain(|key| key.0 != version || seen.contains(key));
        state.seen = seen.into_iter().filter(|key| key.0 != version).collect();
        state.after.remove(&version);
    }

    fn isolated_refusals(
        &self,
        version: u8,
        refused: &[String],
        made_progress: bool,
    ) -> Vec<String> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        state
            .refused_passes
            .retain(|(v, key), _| *v != version || (made_progress && refused.contains(key)));
        if !made_progress {
            return vec![];
        }
        refused
            .iter()
            .filter_map(|key| {
                let count = state
                    .refused_passes
                    .entry((version, key.clone()))
                    .or_default();
                *count += 1;
                (*count >= 3).then(|| key.clone())
            })
            .collect()
    }
}

fn outbox_version(version: u8) -> OutboxVersion {
    if version == 2 {
        OutboxVersion::V2
    } else {
        OutboxVersion::V1
    }
}

async fn mark_unpublishable(
    store: &Arc<PlexusStore>,
    key: &str,
    version: u8,
    reason: &'static str,
) -> Result<(), String> {
    let db = store.clone();
    let key = key.to_owned();
    tokio::task::spawn_blocking(move || {
        db.mark_outbox_unpublishable(&key, outbox_version(version), reason, now_ms())
    })
    .await
    .map_err(|_| "outbox_dead_letter_join_failed")?
    .map_err(|_| "outbox_dead_letter_failed".into())
}

async fn refresh_unpublishable_count(state: &ModuleState) -> Result<(), String> {
    let db = state.store().clone();
    let count = tokio::task::spawn_blocking(move || db.unpublishable_outbox_count())
        .await
        .map_err(|_| "outbox_count_join_failed")?
        .map_err(|_| "outbox_count_failed")?;
    state.health.stamp_outbox_unpublishable(count);
    Ok(())
}

async fn outbox_has_pending(store: &Arc<PlexusStore>) -> Result<bool, String> {
    let db = store.clone();
    tokio::task::spawn_blocking(move || {
        for &version in plexus_core::event_key::PUBLISHED_EVENT_VERSIONS {
            if !db
                .drain_event_outbox_version_after(1, version, None)?
                .is_empty()
            {
                return Ok(true);
            }
        }
        Ok::<_, cortexkit_store::StoreError>(!db.pending_route_facts(1)?.is_empty())
    })
    .await
    .map_err(|_| "outbox_read_join_failed")?
    .map_err(|_| "outbox_read_failed".into())
}

/// Drain one batch of pending outbox events and publish them.
/// Mark each event published only after the JetStream ack: the server's
/// confirmation that the message is stored.
#[cfg(test)]
pub async fn drain_pass(
    store: &Arc<PlexusStore>,
    account: &AccountNames,
    publisher: &(impl EventPublisher + ?Sized),
    batch_size: usize,
    held: &(impl Fn() -> bool + Sync),
) -> Result<usize, String> {
    drain_pass_skipping(
        store,
        account,
        publisher,
        batch_size,
        held,
        &UnpublishableRows::default(),
    )
    .await
}

/// Run a pass like [`drain_pass`], using the publisher's record of rows that
/// cannot produce notices so later passes can read past those rows.
pub(crate) async fn drain_pass_skipping(
    store: &Arc<PlexusStore>,
    account: &AccountNames,
    publisher: &(impl EventPublisher + ?Sized),
    batch_size: usize,
    held: &(impl Fn() -> bool + Sync),
    unpublishable: &UnpublishableRows,
) -> Result<usize, String> {
    let mut published = 0;
    let mut first_error = None;
    for &version in plexus_core::event_key::PUBLISHED_EVENT_VERSIONS {
        match drain_version_pass(
            store,
            account,
            publisher,
            batch_size,
            held,
            version,
            unpublishable,
        )
        .await
        {
            Ok(count) => published += count,
            Err(error) => {
                if first_error.as_deref().is_none_or(session_reusable) {
                    first_error = Some(error);
                }
            }
        }
    }
    first_error.map_or(Ok(published), Err)
}

/// Prepare an event notice's subject, digest, and headers. Return an error
/// if the event cannot supply those parts.
fn prepare_notice(
    account: &AccountNames,
    event: &plexus_core::CanonicalEvent,
    version: u8,
) -> Result<(String, ContentDigest, BTreeMap<String, String>), String> {
    let subject = account
        .event_subject("plexus", &event.event_name, version.into())
        .map_err(|e| format!("event_subject: {e}"))?;
    let digest = if version == 2 {
        event.digest_v2.as_ref().ok_or("missing_v2_digest")?
    } else {
        &event.digest
    };
    let digest = digest
        .parse::<ContentDigest>()
        .map_err(|e| format!("digest_unparsable: {e}"))?;
    let headers = notice_headers(&event.event_name, &event.headers)?;
    Ok((subject, digest, headers))
}

async fn drain_version_pass(
    store: &Arc<PlexusStore>,
    account: &AccountNames,
    publisher: &(impl EventPublisher + ?Sized),
    batch_size: usize,
    held: &(impl Fn() -> bool + Sync),
    version: u8,
    unpublishable: &UnpublishableRows,
) -> Result<usize, String> {
    let db = store.clone();
    let after = unpublishable.cursor(version);
    let events = tokio::task::spawn_blocking(move || {
        db.drain_event_outbox_version_after(batch_size, version, after.as_ref())
    })
    .await
    .map_err(|_| "outbox_read_join_failed")?
    .map_err(|e| e.to_string())?;
    let mut published = 0;
    let mut acknowledged = Vec::new();
    let mut refused = Vec::new();
    let mut first_error = None;
    for (event, cursor) in &events {
        if unpublishable.contains(version, &event.event_key) {
            unpublishable.advance(version, cursor.clone());
            continue;
        }
        let (subject, digest, mut headers) = match prepare_notice(account, event, version) {
            Ok(notice) => notice,
            Err(reason) => {
                eprintln!(error bus:
                    "outbox event {} (v{version}, {}) cannot be published and is skipped: {reason}",
                    event.event_key, event.event_name
                );
                mark_unpublishable(
                    store,
                    &event.event_key,
                    version,
                    if reason == "header_invalid" {
                        "header_invalid"
                    } else {
                        "notice_invalid"
                    },
                )
                .await?;
                unpublishable.insert(version, &event.event_key);
                unpublishable.advance(version, cursor.clone());
                continue;
            }
        };
        // JetStream deduplicates ids across the whole stream, not per subject.
        // Keep v1's wire id intact and carry v2's fetch key separately.
        let notice_id = if version == 2 {
            format!("{}.v2", event.event_key)
        } else {
            event.event_key.clone()
        };
        if version == 2 {
            headers.insert(
                plexus_core::event_key::V2_EVENT_KEY_HEADER.into(),
                event.event_key.clone(),
            );
        }

        // Re-check that this machine still holds connector home before publishing:
        // it may have lost the claim during awaited work, including session setup
        // or the previous publish's ack.
        if !held() {
            first_error = Some("connector_home_not_held".to_owned());
            break;
        }
        let receipt = match publisher
            .publish(&subject, &notice_id, digest, headers)
            .await
        {
            Ok(receipt) => receipt,
            Err(error) if error == "nats_publish_refused" => {
                eprintln!(warn bus: "outbox publish refused: event_key={} version={version} code=nats_publish_refused", event.event_key);
                refused.push(event.event_key.clone());
                unpublishable.advance(version, cursor.clone());
                first_error.get_or_insert(error);
                continue;
            }
            Err(error) => {
                first_error = Some(error);
                break;
            }
        };
        if receipt.duplicate() {
            // A stored event has one immutable notice id per version. A duplicate
            // acknowledges that same notice after a publish-before-stamp crash.
            eprintln!(debug bus:
                "outbox notice retry acknowledged: subject={subject} id={notice_id} event_key={} stream_sequence={}",
                event.event_key, receipt.stream_sequence()
            );
        }

        acknowledged.push(event.event_key.clone());
        unpublishable.advance(version, cursor.clone());
        published += 1;
    }
    // Stamp acknowledgements even if a later publish failed. A cancelled batch
    // can replay its immutable notice IDs safely through JetStream deduplication.
    if !acknowledged.is_empty() {
        let db = store.clone();
        tokio::task::spawn_blocking(move || {
            let keys: Vec<_> = acknowledged.iter().map(String::as_str).collect();
            db.mark_events_published(&keys, outbox_version(version), now_ms())
        })
        .await
        .map_err(|_| "outbox_stamp_join_failed")?
        .map_err(|e| e.to_string())?;
    }
    // A whole-account refusal is a bus outage, not evidence of corrupt rows.
    // Require successful peers in three consecutive passes before quarantining.
    for key in unpublishable.isolated_refusals(version, &refused, published > 0) {
        mark_unpublishable(store, &key, version, "publish_refused").await?;
    }
    if events.len() < batch_size {
        unpublishable.complete_sweep(version);
    }
    first_error.map_or(Ok(published), Err)
}

// async-nats exposes graceful drain but no abortive close. Give each session
// its own small runtime so revocation can destroy every transport task and its
// buffered commands, rather than draining them after authority has been lost.
struct SessionRuntime(Option<tokio::runtime::Runtime>);
impl Drop for SessionRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

pub(crate) struct BusSession {
    client: Option<Arc<BusClient>>,
    account: AccountNames,
    publisher: Box<dyn EventPublisher>,
    _transport: Option<SessionRuntime>,
    wakes: Option<crate::bus_wakes::WakeTask>,
}

impl Drop for BusSession {
    fn drop(&mut self) {
        drop(self.wakes.take());
        // Stop the transport before dropping the last client sender: sender
        // closure must not give the library a chance to flush queued commands.
        drop(self._transport.take());
    }
}

#[async_trait]
#[allow(clippy::double_must_use)]
pub(crate) trait SessionFactory: Send + Sync {
    #[cfg(test)]
    fn observe_pass(&self) {}
    fn needs_idle_session(&self) -> bool {
        false
    }
    async fn open(&self) -> Result<BusSession, String>;
}

struct ProductionSessions {
    path: Option<PathBuf>,
}
pub(crate) fn session_factory(path: Option<PathBuf>) -> Arc<dyn SessionFactory> {
    Arc::new(ProductionSessions { path })
}

async fn build_session(path: PathBuf) -> Result<BusSession, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(|_| "bus_runtime_failed")?;
    let transport = SessionRuntime(Some(runtime));
    let client = transport
        .0
        .as_ref()
        .unwrap()
        .spawn(async move {
            let consumer = Arc::new(
                SubcConsumer::connect(&path, ConsumerOptions::default())
                    .await
                    .map_err(|_| "ckbus_route_connect_failed")?,
            );
            BusClient::connect(
                consumer,
                BusClientOptions::new("plexus").map_err(|_| "ckbus_options_failed")?,
            )
            .await
            .map(Arc::new)
            .map_err(|_| "ckbus_connect_failed")
        })
        .await
        .map_err(|_| "bus_connect_join_failed")??;
    let account = AccountNames::derive(client.acct()).map_err(|_| "ckbus_invalid_account")?;
    Ok(BusSession {
        client: Some(client.clone()),
        account,
        publisher: Box::new(ClientEventPublisher(client)),
        _transport: Some(transport),
        wakes: None,
    })
}

#[async_trait]
impl SessionFactory for ProductionSessions {
    fn needs_idle_session(&self) -> bool {
        true
    }
    async fn open(&self) -> Result<BusSession, String> {
        let path = self.path.as_ref().ok_or("ckbus_connection_file_absent")?;
        build_session(path.clone()).await
    }
}

async fn wait_for_claim_loss(state: &ModuleState) {
    let mut claim = state.runtime.connector_home.decisions();
    let _ = claim.wait_for(|held| !*held).await;
}

// A full batch can have more rows behind it; otherwise a notification or the
// fallback timer starts the next pass.
fn reconnect_backoff(failures: u32) -> Duration {
    Duration::from_millis(plexus_core::backoff::doubling_ms(
        1_000, failures, 9, 300_000,
    ))
}

async fn wait_for_outbox(store: &PlexusStore, delay: Duration, failures: u32) {
    tokio::select! {
        // A wake must not defeat transport failure backoff.
        _ = store.outbox_committed(), if failures == 0 => {},
        _ = tokio::time::sleep(delay) => {},
    }
}

/// Run the publisher until shutdown, cancelling in-flight work on claim loss.
pub(crate) fn spawn_outbox_drain(
    state: Arc<ModuleState>,
    mut stop: mpsc::Receiver<()>,
    factory: Arc<dyn SessionFactory>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Marks the drain dead in health however the task ends, a panic
        // included, so a stopped drain cannot keep reporting ok.
        let _liveness = crate::health::OutboxDrainLiveness::new(Arc::clone(&state.health));
        let unpublishable = UnpublishableRows::default();
        let mut session: Option<BusSession> = None;
        let mut delay = Duration::ZERO;
        let mut failures = 0u32;
        let mut wake_setup_logged = false;
        let mut claim = state.runtime.connector_home.decisions();
        loop {
            tokio::select! {
                biased;
                _ = stop.recv() => break,
                _ = claim.changed() => {},
                _ = wait_for_outbox(state.store(), delay, failures) => {}
            }
            delay = OUTBOX_IDLE;
            if let Err(error) = refresh_unpublishable_count(&state).await {
                state.health.record_publish_error(error);
            }
            if !state.runtime.connector_home.held() {
                session = None;
                continue;
            }
            let work = async {
                let pending = outbox_has_pending(state.store()).await?;
                if !pending && !factory.needs_idle_session() {
                    return Ok(0);
                }
                #[cfg(test)]
                factory.observe_pass();
                if session.is_none() {
                    session = Some(factory.open().await.map_err(|error| {
                        if pending {
                            error
                        } else {
                            "wake_only_bus_unavailable".into()
                        }
                    })?);
                }
                let active = session.as_mut().expect("opened session");
                if active
                    .client
                    .as_ref()
                    .is_some_and(|client| client.connection_changes().has_changed().is_err())
                {
                    return Err("ckbus_maintenance_stopped".into());
                }
                if active.wakes.is_none() {
                    // Share the held session and its claim-loss teardown. Loss wakes
                    // refresh promptly; acquisition still uses connector-home's 30 s role.read tick.
                    if let Some(client) = &active.client {
                        state
                            .runtime
                            .route_facts
                            .bind(client, &state.runtime.connector_home);
                        active.wakes = Some(crate::bus_wakes::spawn_session_watches(
                            state.clone(),
                            client.clone(),
                            &active.account,
                        )?);
                    }
                }
                let result = drain_pass_skipping(
                    state.store(),
                    &active.account,
                    active.publisher.as_ref(),
                    OUTBOX_BATCH,
                    &|| state.runtime.connector_home.held(),
                    &unpublishable,
                )
                .await;
                let route_result = state
                    .runtime
                    .web_search
                    .drain_route_facts(state.store(), OUTBOX_BATCH)
                    .await;
                refresh_unpublishable_count(&state).await?;
                result.and_then(|count| route_result.map(|routes| count + routes))
            };
            let result = tokio::select! {
                biased;
                _ = stop.recv() => break,
                _ = wait_for_claim_loss(&state) => Err("connector_home_not_held".into()),
                result = work => result,
            };
            match result {
                Ok(published) => {
                    if published > 0 || !outbox_has_pending(state.store()).await.unwrap_or(true) {
                        state.health.clear_publish_error();
                    }
                    failures = 0;
                    delay = if unpublishable.pending_more()
                        || outbox_has_pending(state.store()).await.unwrap_or(false)
                    {
                        Duration::ZERO
                    } else {
                        OUTBOX_IDLE
                    };
                }
                Err(error) => {
                    // Dropping a session terminates its transport tasks without
                    // flushing queued messages. Timeouts and auth errors also
                    // require a fresh gated session, not an autonomous retry.
                    if !session_reusable(&error) {
                        session = None;
                    }
                    if error != "connector_home_not_held" {
                        if error == "wake_only_bus_unavailable" {
                            // Optional wakes cannot degrade an idle publisher's health.
                            state.health.clear_publish_error();
                            if !wake_setup_logged {
                                plexus_core::diag!(info bus: "change watch setup unavailable; timers remain active");
                                wake_setup_logged = true;
                            }
                        } else {
                            state.health.record_publish_error(error);
                        }
                        failures = failures.saturating_add(1);
                        delay = reconnect_backoff(failures);
                    }
                }
            }
        }
        drop(session);
    })
}

#[cfg(test)]
#[path = "bus_tests.rs"]
pub mod tests;

#[cfg(test)]
#[path = "bus_live_tests.rs"]
mod live_tests;
