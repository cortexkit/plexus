//! GitHub's hosted webhook stream. Polling remains the reconciliation mechanism.
use crate::{connector_home::ConnectorHome, ModuleState};
use futures_util::{SinkExt, StreamExt};
use plexus_core::{
    storage::relay::{
        canonical_app_id, AppRelayMetadata, CommitOutcome, CoverageReset, Event, Hello, Stub,
        GITHUB_APPS_SOURCE,
    },
    CredentialSource, PlexusStore,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::mpsc,
};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{
        self,
        client::IntoClientRequest,
        http::{HeaderValue, StatusCode},
        protocol::{frame::coding::CloseCode, CloseFrame},
        Message,
    },
    MaybeTlsStream, WebSocketStream,
};
use zeroize::Zeroizing;

pub const URL: &str = "wss://hooks.cortexkit.io/v1/relay/github/ws";
pub const STATUS_OP: &str = "relay.status";
const SOURCE: &str = "github";
const CREDENTIAL: &str = "relay:github";
const APPS_URL: &str = "wss://hooks.cortexkit.io/v1/relay/github-apps/ws";
const APPS_CREDENTIAL: &str = "relay:github-apps";
const CREDENTIAL_RECHECK: Duration = Duration::from_secs(300);
/// How soon to try again after the connector home was not held. The home is
/// re-read every 30 seconds by the module's claim task (and again by `dial`),
/// so waiting the full credential recheck would leave the relay down for up
/// to five minutes after this machine regains the claim.
const NOT_HOME_RECHECK: Duration = Duration::from_secs(30);
const INITIAL_CREDENTIAL_RECHECK: Duration = Duration::from_secs(5);
const HEALTHY_RELAY_WINDOW: Duration = Duration::from_secs(3600);
// Require deliveries throughout the healthy hour, not just one event followed
// by a live socket. Quiet installations safely keep normal polling; even an
// established relay loses slow polling after fifteen minutes without a delivery.
const DELIVERY_SILENCE_LIMIT: Duration = Duration::from_secs(900);
const CLEAN_RECONNECT_WINDOW: Duration = Duration::from_secs(300);
const PING_PERIOD: Duration = Duration::from_secs(30);
const RECEIVE_DEADLINE: Duration = Duration::from_secs(60);
const CONNECT_BOUND: Duration = Duration::from_secs(30);
// Two minutes before the poll START leaves room for the relay's 60-second
// receive watchdog plus a 30-second vendor request and 30-second vault read.
// Pings are not deliveries, and the hosted service promises no delivery SLA:
// this is a conservative fallback threshold, not proof an event is lost forever.
const POLL_MISS_GRACE_MS: i64 = 120_000;
const SUMMARY_PERIOD: Duration = Duration::from_secs(3600);
const SUPERSEDED_MESSAGE: &str =
    "The relay was superseded by another machine also acting as connector home.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Connected,
    Reconnecting,
    NotHome,
    NoCredential,
    CredentialRejected,
    SourceNotServed,
}
impl State {
    fn name(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Reconnecting => "reconnecting",
            Self::NotHome => "not_home",
            Self::NoCredential => "no_credential",
            Self::CredentialRejected => "credential_rejected",
            Self::SourceNotServed => "source_not_served",
        }
    }
    fn message(self) -> Option<&'static str> {
        match self {
            Self::Connected => None,
            Self::Reconnecting => {
                Some("Plexus lost its connection to the relay and is reconnecting.")
            }
            Self::NotHome => {
                Some("Plexus is not the connector home; the relay is deliberately stopped.")
            }
            Self::NoCredential => {
                Some("Plexus has no relay credential for GitHub. Use Connect GitHub.")
            }
            Self::CredentialRejected => {
                Some("The relay refused Plexus's credential. Use Connect GitHub again.")
            }
            Self::SourceNotServed => {
                Some("The relay doesn't serve GitHub events for this account.")
            }
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Github,
    Apps,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Self::Github => SOURCE,
            Self::Apps => GITHUB_APPS_SOURCE,
        }
    }

    fn credential(self) -> &'static str {
        match self {
            Self::Github => CREDENTIAL,
            Self::Apps => APPS_CREDENTIAL,
        }
    }
}

struct SourceSnapshot {
    state: State,
    last_event_at: Option<String>,
    superseded: bool,
    connected_since: Option<Instant>,
    stream_id: Option<String>,
    disconnected_at: Option<Instant>,
}

impl Default for SourceSnapshot {
    fn default() -> Self {
        Self {
            state: State::NoCredential,
            last_event_at: None,
            superseded: false,
            connected_since: None,
            stream_id: None,
            disconnected_at: None,
        }
    }
}

struct Snapshot {
    github: SourceSnapshot,
    apps: SourceSnapshot,
    healthy_since: Option<Instant>,
    last_delivery: Option<Instant>,
    missed_events: u64,
    last_clock_reset: &'static str,
    logged_slow: bool,
    reconcile_pending: bool,
    activity: Activity,
    #[cfg(test)]
    after_event_commit: Option<Box<dyn FnOnce() + Send>>,
}

impl Snapshot {
    fn source(&self, source: Source) -> &SourceSnapshot {
        match source {
            Source::Github => &self.github,
            Source::Apps => &self.apps,
        }
    }

    fn source_mut(&mut self, source: Source) -> &mut SourceSnapshot {
        match source {
            Source::Github => &mut self.github,
            Source::Apps => &mut self.apps,
        }
    }

    fn sources(&self) -> [&SourceSnapshot; 2] {
        [&self.github, &self.apps]
    }

    fn connected_since(&self) -> Option<Instant> {
        self.sources()
            .into_iter()
            .filter_map(|source| source.connected_since)
            .max()
    }
}

// The single-source polling tests exercise the GitHub socket directly.
#[cfg(test)]
impl std::ops::Deref for Snapshot {
    type Target = SourceSnapshot;

    fn deref(&self) -> &Self::Target {
        &self.github
    }
}

#[cfg(test)]
impl std::ops::DerefMut for Snapshot {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.github
    }
}

#[derive(Default)]
struct Activity {
    stored: u64,
    dropped: BTreeMap<(String, String), u64>,
}
pub struct Status(Mutex<Snapshot>, tokio::sync::Notify, Arc<AppRelayMetadata>);
impl Default for Status {
    fn default() -> Self {
        Self(
            Mutex::new(Snapshot {
                github: SourceSnapshot::default(),
                apps: SourceSnapshot::default(),
                healthy_since: None,
                last_delivery: None,
                missed_events: 0,
                last_clock_reset: "process_started",
                logged_slow: false,
                reconcile_pending: false,
                activity: Activity::default(),
                #[cfg(test)]
                after_event_commit: None,
            }),
            tokio::sync::Notify::new(),
            Arc::default(),
        )
    }
}
impl Status {
    #[cfg(test)]
    fn committed(&self, outcome: CommitOutcome, event: String) {
        self.source_committed(Source::Github, outcome, event);
    }

    fn source_committed(&self, source: Source, outcome: CommitOutcome, event: String) {
        let mut status = self.0.lock().unwrap();
        Self::source_delivered_at(&mut status, source, Instant::now());
        match outcome {
            CommitOutcome::Stored => status.activity.stored += 1,
            CommitOutcome::Dropped(reason) => {
                *status
                    .activity
                    .dropped
                    .entry((format!("{reason:?}"), event))
                    .or_default() += 1;
            }
            CommitOutcome::CursorOnly => {}
        }
        self.1.notify_one();
    }

    #[cfg(test)]
    fn delivered_at(status: &mut Snapshot, now: Instant) {
        Self::source_delivered_at(status, Source::Github, now);
    }

    fn source_delivered_at(status: &mut Snapshot, source: Source, now: Instant) {
        Self::observe(status, now);
        // Dropped and cursor-only frames prove the delivery pipe works too.
        if status.source(source).state == State::Connected {
            if Self::covers_polling(status, now) {
                status.healthy_since.get_or_insert(now);
            }
            status.last_delivery = Some(now);
        }
        Self::observe(status, now);
    }

    fn log_summary(&self) {
        let activity = std::mem::take(&mut self.0.lock().unwrap().activity);
        if activity.stored == 0 && activity.dropped.is_empty() {
            return;
        }
        let dropped: Vec<_> = activity
            .dropped
            .into_iter()
            .map(|((reason, event), count)| json!({"reason": reason, "event": event, "count": count}))
            .collect();
        eprintln!(info relay: "relay activity summary: stored={} dropped={}", activity.stored, json!(dropped));
    }

    #[cfg(test)]
    fn set(&self, state: State) {
        self.transition(Source::Github, state, None);
    }
    #[cfg(test)]
    fn rejected(&self, cause: RejectionCause) {
        self.transition(Source::Github, State::CredentialRejected, Some(cause));
    }
    fn transition(&self, source: Source, state: State, cause: Option<RejectionCause>) {
        let changed = {
            let mut status = self.0.lock().unwrap();
            let now = Instant::now();
            Self::observe(&mut status, now);
            let changed = status.source(source).state != state;
            if changed {
                if state == State::Connected {
                    status.source_mut(source).connected_since = Some(now);
                    status.source_mut(source).disconnected_at = None;
                } else if state == State::Reconnecting
                    && status.source(source).state == State::Connected
                    && Self::slow_at(&status, now)
                {
                    // Cursor replay can bridge a short transport outage without a full poll.
                    status.source_mut(source).disconnected_at = Some(now);
                    status.source_mut(source).connected_since = None;
                } else {
                    let prior = status.source(source);
                    let reconcile =
                        prior.state == State::Connected || prior.disconnected_at.is_some();
                    Self::fall_back(&mut status, state.name(), reconcile);
                    status.source_mut(source).connected_since = None;
                }
            }
            let current = status.source_mut(source);
            current.state = state;
            if state != State::Reconnecting {
                current.superseded = false;
            }
            Self::observe(&mut status, now);
            changed
        };
        self.1.notify_one();
        if changed {
            log_transition(source, state, cause);
        }
    }
    #[cfg(test)]
    fn superseded(&self) {
        self.source_superseded(Source::Github);
    }
    fn source_superseded(&self, source: Source) {
        let changed = {
            let mut status = self.0.lock().unwrap();
            Self::observe(&mut status, Instant::now());
            let prior = status.source(source);
            let changed = prior.state != State::Reconnecting;
            let reconcile = prior.state == State::Connected || prior.disconnected_at.is_some();
            Self::fall_back(&mut status, "superseded", reconcile);
            let current = status.source_mut(source);
            current.state = State::Reconnecting;
            current.superseded = true;
            current.connected_since = None;
            Self::observe(&mut status, Instant::now());
            changed
        };
        self.1.notify_one();
        if changed {
            log_transition(source, State::Reconnecting, None);
        }
    }
    fn event(&self, source: Source, received: String) {
        self.0.lock().unwrap().source_mut(source).last_event_at = Some(received);
    }
    #[cfg(test)]
    fn reset_clock(&self, reason: &'static str) {
        self.reset_source_clock(Source::Github, reason);
    }
    fn reset_source_clock(&self, source: Source, reason: &'static str) {
        let mut status = self.0.lock().unwrap();
        Self::observe(&mut status, Instant::now());
        status.healthy_since = None;
        status.last_clock_reset = reason;
        // A relay overflow marker (events lost on this source) triggers a catch-up for this
        // source's coverage only; it doesn't clear an outage still open on the other source.
        status.source_mut(source).disconnected_at = None;
        Self::observe(&mut status, Instant::now());
        self.1.notify_one();
    }
    #[cfg(test)]
    fn connected(&self, stream: String, reset: Option<CoverageReset>) {
        self.connected_at(stream, reset, Instant::now());
    }
    #[cfg(test)]
    fn connected_at(&self, stream: String, reset: Option<CoverageReset>, now: Instant) {
        self.source_connected_at(Source::Github, stream, reset, now);
    }
    fn source_connected_at(
        &self,
        source: Source,
        stream: String,
        reset: Option<CoverageReset>,
        now: Instant,
    ) {
        let mut status = self.0.lock().unwrap();
        Self::observe(&mut status, now);
        let prior = status.source(source);
        let disconnected = prior.disconnected_at;
        let clean_resume = disconnected
            .is_some_and(|since| now.saturating_duration_since(since) <= CLEAN_RECONNECT_WINDOW)
            && prior.stream_id.as_ref() == Some(&stream)
            && reset.is_none();
        if clean_resume {
            eprintln!(info relay: "GitHub polling kept relay_slow: reason=clean_resume disconnect_ms={} stream_unchanged=true reset=none", now.saturating_duration_since(disconnected.unwrap()).as_millis());
        } else if disconnected.is_some() || reset.is_some() {
            let reason = reset.map_or("stream_changed", |reset| reset.name());
            // A reset hello already queued reconciliation in its store transaction.
            Self::fall_back(&mut status, reason, reset.is_none());
            if reset.is_some() {
                status.reconcile_pending = false;
            }
        }
        let current = status.source_mut(source);
        let changed = current.state != State::Connected;
        current.connected_since = if changed {
            Some(now)
        } else {
            current.connected_since
        };
        current.state = State::Connected;
        current.stream_id = Some(stream);
        current.disconnected_at = None;
        current.superseded = false;
        Self::observe(&mut status, now);
        drop(status);
        self.1.notify_one();
        if changed {
            log_transition(source, State::Connected, None);
        }
    }
    fn fall_back(status: &mut Snapshot, reason: &'static str, reconcile: bool) {
        status.healthy_since = None;
        status.github.disconnected_at = None;
        status.apps.disconnected_at = None;
        status.last_clock_reset = reason;
        status.reconcile_pending |= reconcile;
    }
    fn observe(status: &mut Snapshot, now: Instant) -> bool {
        if status.sources().into_iter().any(|source| {
            source
                .disconnected_at
                .is_some_and(|since| now.saturating_duration_since(since) > CLEAN_RECONNECT_WINDOW)
        }) {
            Self::fall_back(status, "reconnect_timeout", true);
        }
        if status.healthy_since.is_some()
            && status
                .last_delivery
                .is_some_and(|last| now.saturating_duration_since(last) >= DELIVERY_SILENCE_LIMIT)
        {
            Self::fall_back(status, "relay_delivery_stale", true);
        }
        let slow = Self::slow_at(status, now);
        if slow != status.logged_slow {
            eprintln!(info relay: "GitHub polling mode changed: mode={} reason={}", if slow { "relay_slow" } else { "normal" }, if slow { "healthy_relay_window_elapsed" } else { status.last_clock_reset });
            status.logged_slow = slow;
        }
        slow
    }
    fn polling_deadline(&self) -> Option<Instant> {
        let status = self.0.lock().unwrap();
        let reconnect = status
            .sources()
            .into_iter()
            .filter_map(|source| source.disconnected_at)
            .min()
            .map(|since| since + CLEAN_RECONNECT_WINDOW + Duration::from_nanos(1));
        let delivery = status
            .healthy_since
            .zip(status.last_delivery)
            .map(|(since, last)| {
                let expires = last + DELIVERY_SILENCE_LIMIT;
                if status.logged_slow {
                    expires
                } else {
                    (since + HEALTHY_RELAY_WINDOW).min(expires)
                }
            });
        reconnect.into_iter().chain(delivery).min()
    }
    fn take_reconcile(&self) -> bool {
        let mut status = self.0.lock().unwrap();
        Self::observe(&mut status, Instant::now());
        std::mem::take(&mut status.reconcile_pending)
    }
    fn slow_at(status: &Snapshot, now: Instant) -> bool {
        Self::covers_polling(status, now)
            && status
                .healthy_since
                .is_some_and(|since| now.saturating_duration_since(since) >= HEALTHY_RELAY_WINDOW)
            && status
                .last_delivery
                .is_some_and(|last| now.saturating_duration_since(last) < DELIVERY_SILENCE_LIMIT)
    }
    fn covers_polling(status: &Snapshot, now: Instant) -> bool {
        let mut provisioned = status
            .sources()
            .into_iter()
            .filter(|source| source.state != State::NoCredential)
            .peekable();
        provisioned.peek().is_some()
            && provisioned.all(|source| {
                source.state == State::Connected
                    || source.disconnected_at.is_some_and(|since| {
                        now.saturating_duration_since(since) <= CLEAN_RECONNECT_WINDOW
                    })
            })
    }
    pub(crate) fn polling_status(&self) -> Value {
        let mut s = self.0.lock().unwrap();
        let now = Instant::now();
        let slow = Self::observe(&mut s, now);
        self.1.notify_one();
        json!({
            "mode": if slow { "relay_slow" } else { "normal" },
            "relay_state": s.github.state.name(),
            "connected_for_ms": s.connected_since().map(|since| now.saturating_duration_since(since).as_millis()),
            "healthy_for_ms": s.healthy_since.map(|since| now.saturating_duration_since(since).as_millis()),
            "delivering": Self::covers_polling(&s, now) && s.connected_since().is_some() && s.healthy_since.is_some(),
            "last_delivery_age_ms": s.last_delivery.map(|last| now.saturating_duration_since(last).as_millis()),
            "missed_events": s.missed_events,
            "last_clock_reset": s.last_clock_reset,
        })
    }
    pub fn status(&self) -> Value {
        let mut s = self.0.lock().unwrap();
        Self::observe(&mut s, Instant::now());
        let mut sources = vec![Self::source_status(&s, Source::Github)];
        if s.apps.state != State::NoCredential {
            sources.push(Self::source_status(&s, Source::Apps));
        }
        json!({"sources":sources})
    }
    fn source_status(s: &Snapshot, source: Source) -> Value {
        let state = s.source(source);
        json!({"source":source.name(),"state":state.state.name(),"last_event_at":state.last_event_at,"message":Self::message(s, source)})
    }
    pub(crate) fn apps_state(&self) -> &'static str {
        match self.state(Source::Apps) {
            State::NoCredential => "disabled",
            state => state.name(),
        }
    }
    pub(crate) fn observe_app_ids(
        &self,
        store: &PlexusStore,
        ids: BTreeMap<String, i64>,
    ) -> Result<(), cortexkit_store::StoreError> {
        store.observe_relay_app_ids(&self.2, ids)
    }
    fn state(&self, source: Source) -> State {
        self.0.lock().unwrap().source(source).state
    }
    fn message(s: &Snapshot, source: Source) -> Option<&'static str> {
        let status = s.source(source);
        if status.superseded {
            Some(SUPERSEDED_MESSAGE)
        } else if status.state == State::Connected
            && s.last_clock_reset == "relay_missed_events"
            && s.healthy_since.is_none()
        {
            Some("The GitHub relay is connected but not delivering events; normal polling is active.")
        } else {
            status.state.message()
        }
    }
    pub(crate) fn degraded_message(&self) -> Option<&'static str> {
        let mut snapshot = self.0.lock().unwrap();
        Self::observe(&mut snapshot, Instant::now());
        [Source::Github, Source::Apps]
            .into_iter()
            .find_map(|source| {
                let current = snapshot.source(source);
                (current.superseded
                    || matches!(
                        current.state,
                        State::Connected | State::CredentialRejected | State::SourceNotServed
                    ))
                .then(|| Self::message(&snapshot, source))
                .flatten()
            })
    }
}

impl plexus_core::scheduler::RelayPollingHealth for Status {
    fn slow_polling(&self) -> bool {
        let slow = Self::observe(&mut self.0.lock().unwrap(), Instant::now());
        self.1.notify_one();
        slow
    }

    fn record_poll_inserts(&self, activity_at_ms: &[i64], poll_started_at_ms: i64) {
        self.polled_at(
            activity_at_ms,
            poll_started_at_ms,
            plexus_core::storage::now_ms(),
            Instant::now(),
        );
    }
}

impl Status {
    fn polled_at(
        &self,
        activity_at_ms: &[i64],
        poll_started_at_ms: i64,
        now_ms: i64,
        now: Instant,
    ) {
        let mut status = self.0.lock().unwrap();
        Self::observe(&mut status, now);
        let Some(connected) = status.connected_since() else {
            return;
        };
        let connected_ms = now
            .saturating_duration_since(connected)
            .as_millis()
            .min(i64::MAX as u128) as i64;
        let misses = activity_at_ms
            .iter()
            .filter(|&&activity| {
                poll_started_at_ms.saturating_sub(activity) > POLL_MISS_GRACE_MS
                    && activity >= now_ms.saturating_sub(connected_ms)
            })
            .count() as u64;
        if misses == 0 {
            return;
        }
        status.missed_events = status.missed_events.saturating_add(misses);
        Self::fall_back(&mut status, "relay_missed_events", true);
        plexus_core::diag!(warn relay: "GitHub relay connected but not delivering: reason=relay_missed_events count={misses}");
        Self::observe(&mut status, now);
        self.1.notify_one();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectionCause {
    Close4001,
    Http401AtConnect,
    InvalidAuthorizationHeader,
}
impl RejectionCause {
    fn name(self) -> &'static str {
        match self {
            Self::Close4001 => "close 4001",
            Self::Http401AtConnect => "HTTP 401 at connect",
            Self::InvalidAuthorizationHeader => "invalid authorization header",
        }
    }
}

fn log_transition(source: Source, state: State, cause: Option<RejectionCause>) {
    if source == Source::Apps {
        match (state, cause) {
            (State::NoCredential, _) => {}
            (State::Connected, _) => {
                plexus_core::diag!(info relay: "relay github-apps state changed: connected")
            }
            (_, Some(cause)) => {
                plexus_core::diag!(warn relay: "relay github-apps state changed: {} cause={}", state.name(), cause.name())
            }
            (_, None) => {
                plexus_core::diag!(warn relay: "relay github-apps state changed: {}", state.name())
            }
        }
        return;
    }
    match (state, cause) {
        (State::Connected, _) => {
            eprintln!(info relay: "relay state changed: {}", state.name());
        }
        (State::CredentialRejected, Some(cause)) => {
            eprintln!(warn relay: "relay state changed: {} cause={}", state.name(), cause.name());
        }
        _ => eprintln!(warn relay: "relay state changed: {}", state.name()),
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireFrame<E> {
    Hello(Hello),
    Event(E),
}

#[derive(Deserialize)]
struct AppEvent {
    #[serde(default)]
    app_id: Value,
    #[serde(flatten)]
    event: Event<Option<i64>>,
}

enum Delivery {
    Github(Event),
    Apps(AppEvent),
}

impl Delivery {
    fn fields(&self) -> (u64, bool, String, String) {
        fn fields<I>(e: &Event<I>) -> (u64, bool, String, String) {
            (
                e.seq,
                matches!(e.stub, Some(Stub::Overflow)),
                e.received_at.clone(),
                e.event.clone(),
            )
        }
        match self {
            Self::Github(event) => fields(event),
            Self::Apps(app) => fields(&app.event),
        }
    }

    fn commit(
        self,
        db: &PlexusStore,
        stream: &str,
        metadata: &AppRelayMetadata,
    ) -> Result<CommitOutcome, cortexkit_store::StoreError> {
        match self {
            Self::Github(event) => db.commit_relay_event_with_outcome(SOURCE, stream, &event),
            Self::Apps(app) => db.commit_app_relay_event(
                stream,
                &app.event,
                app.app_id.as_str().and_then(canonical_app_id),
                metadata,
            ),
        }
    }
}

fn read_frame(source: Source, text: &str) -> serde_json::Result<WireFrame<Delivery>> {
    match source {
        Source::Github => Ok(match serde_json::from_str::<WireFrame<Event>>(text)? {
            WireFrame::Hello(hello) => WireFrame::Hello(hello),
            WireFrame::Event(event) => WireFrame::Event(Delivery::Github(event)),
        }),
        Source::Apps => Ok(match serde_json::from_str::<WireFrame<AppEvent>>(text)? {
            WireFrame::Hello(hello) => WireFrame::Hello(hello),
            WireFrame::Event(event) => WireFrame::Event(Delivery::Apps(event)),
        }),
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    Reconnecting,
    Rejected(RejectionCause),
    SourceNotServed,
    Superseded,
    NotHome,
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn credential_failure_state(error: &plexus_core::CredentialError) -> State {
    if matches!(
        error,
        plexus_core::CredentialError::Permanent(plexus_core::PermanentCredentialError::NotFound)
    ) {
        State::NoCredential
    } else {
        State::Reconnecting
    }
}

fn reset_failure_count(state: State, failure: Failure, failures: &mut u32) {
    if state == State::Connected && failure != Failure::Superseded {
        *failures = 0;
    }
}

fn local_store_failed<T>(
    operation: &str,
    result: Result<Result<T, cortexkit_store::StoreError>, tokio::task::JoinError>,
) -> bool {
    match result {
        Ok(Ok(_)) => false,
        Ok(Err(error)) => {
            eprintln!(warn relay: "relay {operation} store failure: {error}");
            true
        }
        Err(error) => {
            eprintln!(warn relay: "relay {operation} worker failure: {error}");
            true
        }
    }
}

async fn dial(url: &str, credential: &[u8], home: &Arc<ConnectorHome>) -> Result<Socket, Failure> {
    let claim = Arc::clone(home);
    tokio::task::spawn_blocking(move || claim.refresh_legacy())
        .await
        .map_err(|_| Failure::Reconnecting)?;
    if !home.held() {
        return Err(Failure::NotHome);
    }
    let mut request = url
        .into_client_request()
        .map_err(|_| Failure::Reconnecting)?;
    let mut bearer = Zeroizing::new(b"Bearer ".to_vec());
    bearer.extend_from_slice(credential);
    let mut header = HeaderValue::from_bytes(&bearer)
        .map_err(|_| Failure::Rejected(RejectionCause::InvalidAuthorizationHeader))?;
    header.set_sensitive(true);
    request.headers_mut().insert("Authorization", header);
    let _leg = home
        .begin_act(CONNECT_BOUND)
        .map_err(|()| Failure::NotHome)?;
    // Do not format transport errors: peer replies may echo the Authorization header.
    connect_async_with_config(
        request,
        Some(
            tungstenite::protocol::WebSocketConfig::default()
                .max_message_size(Some(1_048_576))
                .max_frame_size(Some(1_048_576)),
        ),
        false,
    )
    .await
    .map(|(socket, _)| {
        // The credential id is not secret. Logging it lets an operator match
        // this connection against the vault's current record and the relay's
        // list of live credentials when checking a rotation.
        if let Some(id) = credential_id(credential) {
            eprintln!(info relay: "relay connection opened with credential id {id}");
        }
        socket
    })
    .map_err(connection_failure)
}

/// The public id inside a relay credential,
/// `ckwr_<account>.<id>.<key_id>.<mac>.<secret>`: the second dot-separated
/// field, a 26-character ULID. The relay requires exactly five fields. Returns
/// `None` for anything else, so a credential in an unexpected format is never
/// logged in part. The MAC and secret fields are never returned.
fn credential_id(credential: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(credential).ok()?;
    if !text.starts_with("ckwr_") {
        return None;
    }
    let fields: Vec<&str> = text.split('.').collect();
    if fields.len() != 5 {
        return None;
    }
    let id = fields[1];
    // Crockford base32, as ULIDs use: digits and upper-case letters except I, L, O, U.
    let is_ulid = id.len() == 26
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b.is_ascii_uppercase() && !b"ILOU".contains(&b)));
    is_ulid.then_some(id)
}

fn connection_failure(error: tungstenite::Error) -> Failure {
    match error {
        tungstenite::Error::Http(response) if response.status() == StatusCode::UNAUTHORIZED => {
            Failure::Rejected(RejectionCause::Http401AtConnect)
        }
        tungstenite::Error::Http(response)
            if response.status() == StatusCode::NOT_FOUND
                && response.body().as_deref() == Some(b"{\"error\":\"unknown_source\"}") =>
        {
            Failure::SourceNotServed
        }
        _ => Failure::Reconnecting,
    }
}

async fn protocol_error<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut WebSocketStream<S>,
) -> Failure {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Library(4400),
            reason: "invalid relay protocol".into(),
        })))
        .await;
    eprintln!(warn relay: "relay protocol error; reconnecting");
    Failure::Reconnecting
}

#[cfg(test)]
async fn consume<S: AsyncRead + AsyncWrite + Unpin>(
    socket: WebSocketStream<S>,
    store: Arc<PlexusStore>,
    status: &Status,
    home: &ConnectorHome,
) -> Failure {
    consume_source(Source::Github, socket, store, status, home).await
}

async fn consume_source<S: AsyncRead + AsyncWrite + Unpin>(
    source: Source,
    mut socket: WebSocketStream<S>,
    store: Arc<PlexusStore>,
    status: &Status,
    home: &ConnectorHome,
) -> Failure {
    let mut stream = None;
    let mut next = 0;
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + PING_PERIOD, PING_PERIOD);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut claim = home.decisions();
    let mut received_at = tokio::time::Instant::now();
    loop {
        let message = tokio::select! {
            _ = tokio::time::sleep_until(received_at + RECEIVE_DEADLINE) => return Failure::Reconnecting,
            _ = async { let _ = claim.wait_for(|held| !*held).await; } => return Failure::NotHome,
            _ = ping.tick() => { if !matches!(tokio::time::timeout_at(received_at + RECEIVE_DEADLINE, socket.send(Message::Ping(Vec::new().into()))).await, Ok(Ok(()))) { return Failure::Reconnecting; } continue; }
            message = socket.next() => message,
        };
        received_at = tokio::time::Instant::now();
        match message {
            Some(Ok(Message::Text(text))) => {
                let Ok(frame) = read_frame(source, &text) else {
                    return protocol_error(&mut socket).await;
                };
                match frame {
                    WireFrame::Hello(hello) if stream.is_none() => {
                        // Validate source before opening a cursor, admitting an event or sending an ack.
                        if hello.source != source.name() {
                            return protocol_error(&mut socket).await;
                        }
                        next = hello.oldest_seq.max(hello.last_acked_seq.saturating_add(1));
                        let db = Arc::clone(&store);
                        let stream_id = hello.stream_id.clone();
                        let hello_result = tokio::task::spawn_blocking(move || {
                            db.relay_hello(source.name(), &hello)
                        })
                        .await;
                        let reset = match hello_result {
                            Ok(Ok(reset)) => reset,
                            failure => {
                                local_store_failed("hello", failure);
                                return Failure::Reconnecting;
                            }
                        };
                        stream = Some(stream_id);
                        status.source_connected_at(
                            source,
                            stream.as_ref().unwrap().clone(),
                            reset,
                            Instant::now(),
                        );
                    }
                    WireFrame::Event(event) if stream.is_some() => {
                        let (seq, overflow, received, event_type) = event.fields();
                        if seq != next {
                            return protocol_error(&mut socket).await;
                        }
                        let stream_id = stream.as_ref().unwrap().clone();
                        let db = Arc::clone(&store);
                        let metadata = Arc::clone(&status.2);
                        // One received frame at a time bounds our queue below the relay's 64-frame window.
                        let committed = tokio::task::spawn_blocking(move || {
                            event.commit(&db, &stream_id, &metadata)
                        })
                        .await;
                        let outcome = match committed {
                            Ok(Ok(outcome)) => outcome,
                            failure => {
                                local_store_failed("event commit", failure);
                                return Failure::Reconnecting;
                            }
                        };
                        // Count stored and dropped outcomes after commit, even if the acknowledgement fails.
                        let committed_marker = overflow && outcome == CommitOutcome::CursorOnly;
                        status.source_committed(source, outcome, event_type);
                        if committed_marker {
                            status.reset_source_clock(source, "overflow");
                        }
                        #[cfg(test)]
                        if let Some(after_commit) =
                            status.0.lock().unwrap().after_event_commit.take()
                        {
                            after_commit();
                        }
                        if !home.held() {
                            return Failure::NotHome;
                        }
                        // No ack can leave the socket until the fenced store transaction has committed.
                        if socket
                            .send(Message::Text(
                                format!("{{\"type\":\"ack\",\"through_seq\":{seq}}}").into(),
                            ))
                            .await
                            .is_err()
                        {
                            return Failure::Reconnecting;
                        }
                        status.event(source, received);
                        next = seq + 1;
                    }
                    _ => return protocol_error(&mut socket).await,
                }
            }
            Some(Ok(Message::Close(frame))) => {
                return match frame.map(|frame| u16::from(frame.code)) {
                    Some(4001) => Failure::Rejected(RejectionCause::Close4001),
                    Some(4009) => Failure::Superseded,
                    _ => Failure::Reconnecting,
                }
            }
            Some(Ok(Message::Ping(_))) => {
                if socket.flush().await.is_err() {
                    return Failure::Reconnecting;
                }
            }
            Some(Ok(Message::Pong(_))) => {}
            Some(Ok(_)) => return protocol_error(&mut socket).await,
            _ => return Failure::Reconnecting,
        }
    }
}

pub(crate) fn spawn(
    state: Arc<ModuleState>,
    stop: mpsc::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_sources(
            URL,
            Some(APPS_URL),
            state.store().clone(),
            state.runtime.credential_source().clone(),
            state.runtime.connector_home.clone(),
            &state.health.relay,
            stop,
        )
        .await;
    })
}

#[cfg(test)]
async fn run(
    url: &str,
    store: Arc<PlexusStore>,
    credentials: Arc<dyn CredentialSource>,
    home: Arc<ConnectorHome>,
    status: &Status,
    stop: mpsc::Receiver<()>,
) {
    run_sources(url, None, store, credentials, home, status, stop).await;
}

async fn run_sources(
    github_url: &str,
    apps_url: Option<&str>,
    store: Arc<PlexusStore>,
    credentials: Arc<dyn CredentialSource>,
    home: Arc<ConnectorHome>,
    status: &Status,
    mut stop: mpsc::Receiver<()>,
) {
    let github = run_connections(
        Source::Github,
        github_url,
        store.clone(),
        credentials.clone(),
        home.clone(),
        status,
    );
    let apps = async {
        match apps_url {
            Some(url) => {
                run_connections(Source::Apps, url, store.clone(), credentials, home, status).await
            }
            None => std::future::pending().await,
        }
    };
    tokio::pin!(github, apps);
    // The outer relay loop survives reconnects and credential waits without a separate task.
    let mut summary =
        tokio::time::interval_at(tokio::time::Instant::now() + SUMMARY_PERIOD, SUMMARY_PERIOD);
    summary.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let deadline = status.polling_deadline();
        tokio::select! {
            _ = stop.recv() => return,
            _ = &mut github => return,
            _ = &mut apps => return,
            _ = summary.tick() => status.log_summary(),
            _ = status.1.notified() => {},
            _ = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                    None => std::future::pending().await,
                }
            } => {},
        }
        // Run even while credential lookup, dialing or receiving a hello is stalled.
        if status.take_reconcile() {
            let db = store.clone();
            local_store_failed(
                "disconnect reconcile",
                tokio::task::spawn_blocking(move || db.relay_disconnected()).await,
            );
        }
    }
}

async fn run_connections(
    source: Source,
    url: &str,
    store: Arc<PlexusStore>,
    credentials: Arc<dyn CredentialSource>,
    home: Arc<ConnectorHome>,
    status: &Status,
) {
    let mut rejected: Option<(Zeroizing<Vec<u8>>, RejectionCause)> = None;
    let mut failures = 0u32;
    let mut delay = Duration::ZERO;
    let mut credential_recheck = INITIAL_CREDENTIAL_RECHECK;
    let mut claim = home.decisions();
    loop {
        tokio::select! { _ = claim.changed() => {}, _ = tokio::time::sleep(delay) => {} }
        let provider = credentials.clone();
        let credential =
            tokio::task::spawn_blocking(move || provider.get_by_id(source.credential())).await;
        let credential = match credential {
            Ok(Ok(credential)) => credential,
            Ok(Err(error)) => {
                let state = credential_failure_state(&error);
                if source == Source::Github {
                    eprintln!(warn relay: "relay credential lookup failed: {}", error.class());
                    status.transition(source, state, None);
                } else if state == State::NoCredential
                    || status.state(source) != State::NoCredential
                {
                    status.transition(source, state, None);
                }
                delay = credential_recheck_delay(&mut credential_recheck);
                continue;
            }
            Err(error) => {
                if source == Source::Github || status.state(source) != State::NoCredential {
                    plexus_core::diag!(warn relay: "relay credential lookup worker failed: {error}");
                    status.transition(source, State::Reconnecting, None);
                }
                delay = credential_recheck_delay(&mut credential_recheck);
                continue;
            }
        };
        if rejected
            .as_ref()
            .is_some_and(|(old, _)| old.as_slice() == credential.payload())
        {
            status.transition(
                source,
                State::CredentialRejected,
                Some(rejected.as_ref().unwrap().1),
            );
            delay = credential_recheck_delay(&mut credential_recheck);
            continue;
        }
        rejected = None;
        credential_recheck = INITIAL_CREDENTIAL_RECHECK;
        // A periodic retry of a source the relay does not serve keeps that
        // state rather than flapping through `reconnecting` on every attempt.
        if status.state(source) != State::SourceNotServed {
            status.transition(source, State::Reconnecting, None);
        }
        let failure = async {
            let socket =
                tokio::time::timeout(CONNECT_BOUND, dial(url, credential.payload(), &home))
                    .await
                    .map_err(|_| Failure::Reconnecting)??;
            Ok::<_, Failure>(consume_source(source, socket, store.clone(), status, &home).await)
        }
        .await
        .unwrap_or_else(|failure| failure);
        reset_failure_count(status.state(source), failure, &mut failures);
        if status.state(source) == State::Connected && failure != Failure::Superseded {
            credential_recheck = INITIAL_CREDENTIAL_RECHECK;
        }
        match failure {
            Failure::Rejected(cause) => {
                // Relay revocation is not a vendor token failure; never report it to the vault.
                rejected = Some((Zeroizing::new(credential.payload().to_vec()), cause));
                status.transition(source, State::CredentialRejected, Some(cause));
                delay = credential_recheck_delay(&mut credential_recheck);
            }
            // The relay may start serving this source later (the account
            // enables it), so ask again at the credential recheck interval
            // instead of parking until a restart.
            Failure::SourceNotServed => {
                status.transition(source, State::SourceNotServed, None);
                delay = CREDENTIAL_RECHECK;
            }
            Failure::Superseded => {
                status.source_superseded(source);
                let claim = home.clone();
                let _ = tokio::task::spawn_blocking(move || claim.refresh_legacy()).await;
                status.transition(source, State::Reconnecting, None);
                if !home.held() {
                    delay = CREDENTIAL_RECHECK;
                } else {
                    failures = failures.saturating_add(1);
                    delay = backoff(failures);
                }
            }
            Failure::NotHome => {
                status.transition(source, State::NotHome, None);
                delay = NOT_HOME_RECHECK;
            }
            Failure::Reconnecting => {
                status.transition(source, State::Reconnecting, None);
                failures = failures.saturating_add(1);
                delay = backoff(failures);
            }
        }
    }
}

fn backoff(failures: u32) -> Duration {
    Duration::from_millis(plexus_core::backoff::doubling_ms(
        1_000, failures, 9, 300_000,
    ))
}
/// Kept apart from `backoff`: the connection loop carries this delay itself as
/// its state (reset to `INITIAL_CREDENTIAL_RECHECK` once a usable credential is
/// read), not a failure count, and its base is five seconds rather than one.
fn credential_recheck_delay(next: &mut Duration) -> Duration {
    let delay = *next;
    *next = (*next * 2).min(CREDENTIAL_RECHECK);
    delay
}

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;
