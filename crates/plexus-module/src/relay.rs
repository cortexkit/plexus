//! GitHub's hosted webhook stream. Polling remains the reconciliation mechanism.
use crate::{connector_home::ConnectorHome, ModuleState};
use futures_util::{SinkExt, StreamExt};
use plexus_core::{
    storage::relay::{CommitOutcome, Event, Hello, Stub},
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
const CREDENTIAL_RECHECK: Duration = Duration::from_secs(300);
/// How soon to try again after the connector home was not held. The home is
/// re-read every 30 seconds by the module's claim task (and again by `dial`),
/// so waiting the full credential recheck would leave the relay down for up
/// to five minutes after this machine regains the claim.
const NOT_HOME_RECHECK: Duration = Duration::from_secs(30);
const INITIAL_CREDENTIAL_RECHECK: Duration = Duration::from_secs(5);
const HEALTHY_RELAY_WINDOW: Duration = Duration::from_secs(3600);
const CLEAN_RECONNECT_WINDOW: Duration = Duration::from_secs(300);
const PING_PERIOD: Duration = Duration::from_secs(30);
const RECEIVE_DEADLINE: Duration = Duration::from_secs(60);
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
struct Snapshot {
    state: State,
    last_event_at: Option<String>,
    superseded: bool,
    connected_since: Option<Instant>,
    healthy_since: Option<Instant>,
    last_clock_reset: &'static str,
    stream_id: Option<String>,
    disconnected_at: Option<Instant>,
    logged_slow: bool,
    reconcile_pending: bool,
    activity: Activity,
}

#[derive(Default)]
struct Activity {
    stored: u64,
    dropped: BTreeMap<(String, String), u64>,
}
pub struct Status(Mutex<Snapshot>, tokio::sync::Notify);
impl Default for Status {
    fn default() -> Self {
        Self(
            Mutex::new(Snapshot {
                state: State::NoCredential,
                last_event_at: None,
                superseded: false,
                connected_since: None,
                healthy_since: None,
                last_clock_reset: "process_started",
                stream_id: None,
                disconnected_at: None,
                logged_slow: false,
                reconcile_pending: false,
                activity: Activity::default(),
            }),
            tokio::sync::Notify::new(),
        )
    }
}
impl Status {
    fn committed(&self, outcome: CommitOutcome, event: String) {
        let mut status = self.0.lock().unwrap();
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

    fn set(&self, state: State) {
        self.transition(state, None);
    }
    fn rejected(&self, cause: RejectionCause) {
        self.transition(State::CredentialRejected, Some(cause));
    }
    fn transition(&self, state: State, cause: Option<RejectionCause>) {
        let changed = {
            let mut status = self.0.lock().unwrap();
            let now = Instant::now();
            Self::observe(&mut status, now);
            let changed = status.state != state;
            if changed {
                if state == State::Connected {
                    status.connected_since = Some(now);
                    status.healthy_since = status.connected_since;
                    status.disconnected_at = None;
                } else if state == State::Reconnecting && Self::slow_at(&status, now) {
                    // Cursor replay can bridge a short transport outage without a full poll.
                    status.disconnected_at = Some(now);
                    status.connected_since = None;
                } else {
                    let reconcile =
                        status.state == State::Connected || status.disconnected_at.is_some();
                    Self::fall_back(&mut status, state.name(), reconcile);
                    status.connected_since = None;
                }
            }
            status.state = state;
            if state != State::Reconnecting {
                status.superseded = false;
            }
            Self::observe(&mut status, now);
            changed
        };
        self.1.notify_one();
        if changed {
            log_transition(state, cause);
        }
    }
    fn superseded(&self) {
        let changed = {
            let mut status = self.0.lock().unwrap();
            Self::observe(&mut status, Instant::now());
            let changed = status.state != State::Reconnecting;
            let reconcile = status.state == State::Connected || status.disconnected_at.is_some();
            Self::fall_back(&mut status, "superseded", reconcile);
            status.state = State::Reconnecting;
            status.superseded = true;
            status.connected_since = None;
            Self::observe(&mut status, Instant::now());
            changed
        };
        self.1.notify_one();
        if changed {
            log_transition(State::Reconnecting, None);
        }
    }
    fn event(&self, received: String) {
        self.0.lock().unwrap().last_event_at = Some(received);
    }
    fn reset_clock(&self, reason: &'static str) {
        let mut status = self.0.lock().unwrap();
        Self::observe(&mut status, Instant::now());
        Self::fall_back(&mut status, reason, false);
        status.healthy_since = status.connected_since.map(|_| Instant::now());
        Self::observe(&mut status, Instant::now());
        self.1.notify_one();
    }
    fn connected(&self, stream: String, reset: Option<plexus_core::storage::relay::CoverageReset>) {
        self.connected_at(stream, reset, Instant::now());
    }
    fn connected_at(
        &self,
        stream: String,
        reset: Option<plexus_core::storage::relay::CoverageReset>,
        now: Instant,
    ) {
        let mut status = self.0.lock().unwrap();
        Self::observe(&mut status, now);
        let disconnected = status.disconnected_at;
        let clean_resume = disconnected
            .is_some_and(|since| now.saturating_duration_since(since) <= CLEAN_RECONNECT_WINDOW)
            && status.stream_id.as_ref() == Some(&stream)
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
        let changed = status.state != State::Connected;
        if !clean_resume && (changed || status.healthy_since.is_none()) {
            status.healthy_since = Some(now);
        }
        status.connected_since = if changed {
            Some(now)
        } else {
            status.connected_since
        };
        status.state = State::Connected;
        status.stream_id = Some(stream);
        status.disconnected_at = None;
        status.superseded = false;
        Self::observe(&mut status, now);
        drop(status);
        self.1.notify_one();
        if changed {
            log_transition(State::Connected, None);
        }
    }
    fn fall_back(status: &mut Snapshot, reason: &'static str, reconcile: bool) {
        status.healthy_since = None;
        status.disconnected_at = None;
        status.last_clock_reset = reason;
        status.reconcile_pending |= reconcile;
    }
    fn observe(status: &mut Snapshot, now: Instant) -> bool {
        if status
            .disconnected_at
            .is_some_and(|since| now.saturating_duration_since(since) > CLEAN_RECONNECT_WINDOW)
        {
            Self::fall_back(status, "reconnect_timeout", true);
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
        if let Some(since) = status.disconnected_at {
            Some(since + CLEAN_RECONNECT_WINDOW + Duration::from_nanos(1))
        } else if status.state == State::Connected && !status.logged_slow {
            status
                .healthy_since
                .map(|since| since + HEALTHY_RELAY_WINDOW)
        } else {
            None
        }
    }
    fn take_reconcile(&self) -> bool {
        let mut status = self.0.lock().unwrap();
        Self::observe(&mut status, Instant::now());
        std::mem::take(&mut status.reconcile_pending)
    }
    fn slow_at(status: &Snapshot, now: Instant) -> bool {
        (status.state == State::Connected
            || status.disconnected_at.is_some_and(|since| {
                now.saturating_duration_since(since) <= CLEAN_RECONNECT_WINDOW
            }))
            && status
                .healthy_since
                .is_some_and(|since| now.saturating_duration_since(since) >= HEALTHY_RELAY_WINDOW)
    }
    pub(crate) fn polling_status(&self) -> Value {
        let mut s = self.0.lock().unwrap();
        let now = Instant::now();
        let slow = Self::observe(&mut s, now);
        self.1.notify_one();
        json!({
            "mode": if slow { "relay_slow" } else { "normal" },
            "relay_state": s.state.name(),
            "connected_for_ms": s.connected_since.map(|since| now.saturating_duration_since(since).as_millis()),
            "healthy_for_ms": s.healthy_since.map(|since| now.saturating_duration_since(since).as_millis()),
            "last_clock_reset": s.last_clock_reset,
        })
    }
    pub fn status(&self) -> Value {
        let s = self.0.lock().unwrap();
        json!({"sources":[{"source":SOURCE,"state":s.state.name(),"last_event_at":s.last_event_at,"message":if s.superseded { Some(SUPERSEDED_MESSAGE) } else { s.state.message() }}]})
    }
    pub(crate) fn degraded_message(&self) -> Option<&'static str> {
        let snapshot = self.0.lock().unwrap();
        if snapshot.superseded {
            return Some(SUPERSEDED_MESSAGE);
        }
        let s = snapshot.state;
        (snapshot.superseded || matches!(s, State::CredentialRejected | State::SourceNotServed))
            .then(|| s.message())
            .flatten()
    }
}

impl plexus_core::scheduler::RelayPollingHealth for Status {
    fn slow_polling(&self) -> bool {
        let slow = Self::observe(&mut self.0.lock().unwrap(), Instant::now());
        self.1.notify_one();
        slow
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

fn log_transition(state: State, cause: Option<RejectionCause>) {
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
enum Frame {
    Hello(Hello),
    Event(Event),
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
    tokio::task::spawn_blocking(move || {
        let _ = claim.refresh();
    })
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

async fn consume<S: AsyncRead + AsyncWrite + Unpin>(
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
                let Ok(frame) = serde_json::from_str::<Frame>(&text) else {
                    return protocol_error(&mut socket).await;
                };
                match frame {
                    Frame::Hello(hello) if stream.is_none() => {
                        // Validate source before opening a cursor, admitting an event or sending an ack.
                        if hello.source != SOURCE {
                            return protocol_error(&mut socket).await;
                        }
                        next = hello.oldest_seq.max(hello.last_acked_seq.saturating_add(1));
                        let db = Arc::clone(&store);
                        let stream_id = hello.stream_id.clone();
                        let hello_result =
                            tokio::task::spawn_blocking(move || db.relay_hello(SOURCE, &hello))
                                .await;
                        let reset = match hello_result {
                            Ok(Ok(reset)) => reset,
                            failure => {
                                local_store_failed("hello", failure);
                                return Failure::Reconnecting;
                            }
                        };
                        stream = Some(stream_id);
                        status.connected(stream.as_ref().unwrap().clone(), reset);
                    }
                    Frame::Event(event) if stream.is_some() => {
                        if event.seq != next {
                            return protocol_error(&mut socket).await;
                        }
                        let seq = event.seq;
                        let overflow = matches!(event.stub, Some(Stub::Overflow));
                        let received = event.received_at.clone();
                        let event_type = event.event.clone();
                        let stream_id = stream.as_ref().unwrap().clone();
                        let db = Arc::clone(&store);
                        // One received frame at a time bounds our queue below the relay's 64-frame window.
                        let committed = tokio::task::spawn_blocking(move || {
                            db.commit_relay_event_with_outcome(SOURCE, &stream_id, &event)
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
                        status.committed(outcome, event_type);
                        if overflow {
                            status.reset_clock("overflow");
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
                        status.event(received);
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
        run(
            URL,
            state.store().clone(),
            state.runtime.credential_source().clone(),
            state.runtime.connector_home.clone(),
            &state.health.relay,
            stop,
        )
        .await;
    })
}

async fn run(
    url: &str,
    store: Arc<PlexusStore>,
    credentials: Arc<dyn CredentialSource>,
    home: Arc<ConnectorHome>,
    status: &Status,
    stop: mpsc::Receiver<()>,
) {
    let connection = run_connections(url, store.clone(), credentials, home, status, stop);
    tokio::pin!(connection);
    // The outer relay loop survives reconnects and credential waits without a separate task.
    let mut summary =
        tokio::time::interval_at(tokio::time::Instant::now() + SUMMARY_PERIOD, SUMMARY_PERIOD);
    summary.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let deadline = status.polling_deadline();
        tokio::select! {
            _ = &mut connection => return,
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
    url: &str,
    store: Arc<PlexusStore>,
    credentials: Arc<dyn CredentialSource>,
    home: Arc<ConnectorHome>,
    status: &Status,
    mut stop: mpsc::Receiver<()>,
) {
    let mut rejected: Option<(Zeroizing<Vec<u8>>, RejectionCause)> = None;
    let mut failures = 0u32;
    let mut delay = Duration::ZERO;
    let mut credential_recheck = INITIAL_CREDENTIAL_RECHECK;
    let mut claim = home.decisions();
    loop {
        tokio::select! { biased; _ = stop.recv() => return, _ = claim.changed() => {}, _ = tokio::time::sleep(delay) => {} }
        let provider = credentials.clone();
        let credential = tokio::select! {
            biased;
            _ = stop.recv() => return,
            credential = tokio::task::spawn_blocking(move || provider.get_by_id(CREDENTIAL)) => credential,
        };
        let credential = match credential {
            Ok(Ok(credential)) => credential,
            Ok(Err(error)) => {
                eprintln!(warn relay: "relay credential lookup failed: {}", error.class());
                status.set(credential_failure_state(&error));
                delay = credential_recheck_delay(&mut credential_recheck);
                continue;
            }
            Err(error) => {
                eprintln!(warn relay: "relay credential lookup worker failed: {error}");
                status.set(State::Reconnecting);
                delay = credential_recheck_delay(&mut credential_recheck);
                continue;
            }
        };
        if rejected
            .as_ref()
            .is_some_and(|(old, _)| old.as_slice() == credential.payload())
        {
            status.rejected(rejected.as_ref().unwrap().1);
            delay = credential_recheck_delay(&mut credential_recheck);
            continue;
        }
        rejected = None;
        credential_recheck = INITIAL_CREDENTIAL_RECHECK;
        // A periodic retry of a source the relay does not serve keeps that
        // state rather than flapping through `reconnecting` on every attempt.
        if status.0.lock().unwrap().state != State::SourceNotServed {
            status.set(State::Reconnecting);
        }
        let failure = tokio::select! {
            biased;
            _ = stop.recv() => return,
            result = async {
                let socket = tokio::time::timeout(Duration::from_secs(30), dial(url, credential.payload(), &home)).await.map_err(|_| Failure::Reconnecting)??;
                Ok::<_, Failure>(consume(socket, store.clone(), status, &home).await)
            } => result.unwrap_or_else(|failure| failure),
        };
        reset_failure_count(status.0.lock().unwrap().state, failure, &mut failures);
        if status.0.lock().unwrap().state == State::Connected && failure != Failure::Superseded {
            credential_recheck = INITIAL_CREDENTIAL_RECHECK;
        }
        match failure {
            Failure::Rejected(cause) => {
                // Relay revocation is not a vendor token failure; never report it to the vault.
                rejected = Some((Zeroizing::new(credential.payload().to_vec()), cause));
                status.rejected(cause);
                delay = credential_recheck_delay(&mut credential_recheck);
            }
            // The relay may start serving this source later (the account
            // enables it), so ask again at the credential recheck interval
            // instead of parking until a restart.
            Failure::SourceNotServed => {
                status.set(State::SourceNotServed);
                delay = CREDENTIAL_RECHECK;
            }
            Failure::Superseded => {
                status.superseded();
                let claim = home.clone();
                let _ = tokio::task::spawn_blocking(move || claim.refresh()).await;
                status.set(State::Reconnecting);
                if !home.held() {
                    delay = CREDENTIAL_RECHECK;
                } else {
                    failures = failures.saturating_add(1);
                    delay = backoff(failures);
                }
            }
            Failure::NotHome => {
                status.set(State::NotHome);
                delay = NOT_HOME_RECHECK;
            }
            Failure::Reconnecting => {
                status.set(State::Reconnecting);
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
