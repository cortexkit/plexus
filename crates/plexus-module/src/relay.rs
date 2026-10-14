//! GitHub's hosted webhook stream. Polling remains the reconciliation mechanism.
use crate::{connector_home::ConnectorHome, ModuleState};
use futures_util::{SinkExt, StreamExt};
use plexus_core::{
    storage::relay::{Event, Hello},
    CredentialSource, PlexusStore,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpStream, sync::mpsc};
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
}
pub struct Status(Mutex<Snapshot>);
impl Default for Status {
    fn default() -> Self {
        Self(Mutex::new(Snapshot {
            state: State::NoCredential,
            last_event_at: None,
            superseded: false,
        }))
    }
}
impl Status {
    fn set(&self, state: State) {
        self.transition(state, None);
    }
    fn rejected(&self, cause: RejectionCause) {
        self.transition(State::CredentialRejected, Some(cause));
    }
    fn transition(&self, state: State, cause: Option<RejectionCause>) {
        let changed = {
            let mut status = self.0.lock().unwrap();
            let changed = status.state != state;
            status.state = state;
            if state != State::Reconnecting {
                status.superseded = false;
            }
            changed
        };
        if changed {
            log_transition(state, cause);
        }
    }
    fn superseded(&self) {
        let changed = {
            let mut status = self.0.lock().unwrap();
            let changed = status.state != State::Reconnecting;
            status.state = State::Reconnecting;
            status.superseded = true;
            changed
        };
        if changed {
            log_transition(State::Reconnecting, None);
        }
    }
    fn event(&self, received: String) {
        self.0.lock().unwrap().last_event_at = Some(received);
    }
    pub fn status(&self) -> Value {
        let s = self.0.lock().unwrap();
        json!({"sources":[{"source":SOURCE,"state":s.state.name(),"last_event_at":s.last_event_at,"message":s.state.message()}]})
    }
    pub(crate) fn degraded_message(&self) -> Option<&'static str> {
        let snapshot = self.0.lock().unwrap();
        let s = snapshot.state;
        (snapshot.superseded || matches!(s, State::CredentialRejected | State::SourceNotServed))
            .then(|| s.message())
            .flatten()
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
    .map(|(socket, _)| socket)
    .map_err(connection_failure)
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

async fn protocol_error(socket: &mut Socket) -> Failure {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Library(4400),
            reason: "invalid relay protocol".into(),
        })))
        .await;
    eprintln!(warn relay: "relay protocol error; reconnecting");
    Failure::Reconnecting
}

async fn consume(
    mut socket: Socket,
    store: Arc<PlexusStore>,
    status: &Status,
    home: &ConnectorHome,
) -> Failure {
    let mut stream = None;
    let mut next = 0;
    let mut ping = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(30),
        Duration::from_secs(30),
    );
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut claim = tokio::time::interval(Duration::from_secs(1));
    loop {
        let message = tokio::select! {
            _ = claim.tick() => { if !home.held() { return Failure::NotHome; } continue; }
            _ = ping.tick() => { if socket.send(Message::Ping(Vec::new().into())).await.is_err() { return Failure::Reconnecting; } continue; }
            message = socket.next() => message,
        };
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
                        if local_store_failed("hello", hello_result) {
                            return Failure::Reconnecting;
                        }
                        stream = Some(stream_id);
                        status.set(State::Connected);
                    }
                    Frame::Event(event) if stream.is_some() => {
                        if event.seq != next {
                            return protocol_error(&mut socket).await;
                        }
                        let seq = event.seq;
                        let received = event.received_at.clone();
                        let stream_id = stream.as_ref().unwrap().clone();
                        let db = Arc::clone(&store);
                        // One received frame at a time bounds our queue below the relay's 64-frame window.
                        let committed = tokio::task::spawn_blocking(move || {
                            db.commit_relay_event(SOURCE, &stream_id, &event)
                        })
                        .await;
                        if !matches!(committed, Ok(Ok(()))) {
                            local_store_failed("event commit", committed);
                            return Failure::Reconnecting;
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
    mut stop: mpsc::Receiver<()>,
) {
    let mut rejected: Option<(Zeroizing<Vec<u8>>, RejectionCause)> = None;
    let mut failures = 0u32;
    let mut delay = Duration::ZERO;
    let mut credential_recheck = INITIAL_CREDENTIAL_RECHECK;
    loop {
        tokio::select! { biased; _ = stop.recv() => return, _ = tokio::time::sleep(delay) => {} }
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
    Duration::from_secs((1u64 << failures.min(9)).min(300))
}
fn credential_recheck_delay(next: &mut Duration) -> Duration {
    let delay = *next;
    *next = (*next * 2).min(CREDENTIAL_RECHECK);
    delay
}

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;
