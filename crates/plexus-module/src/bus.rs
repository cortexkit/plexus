//! Authenticated NATS bus connection and outbox drain for plexus notices.
//! Obtains credentials from ck-bus, the NATS credential module, over subc,
//! the module supervisor. Never logs credential material and drains the store's
//! outbox markers to JetStream.
//! Connector home is the claim in engram that this machine may contact outside
//! services; Plexus blocks outward effects unless it holds the claim.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use base64::Engine;
use cortexkit_bus_naming::AccountNames;
use cortexkit_bus_nats::{ConnectConfig, NatsConnection};
use cortexkit_bus_trait::{BusError, ContentDigest, Headers, PublishReceipt, Stream};
use plexus_core::storage::event_outbox::{OutboxCursor, OutboxVersion};
use plexus_core::{event_key::PUBLISHED_EVENTS, storage::now_ms, EventHeaders, PlexusStore};
use serde::Deserialize;
use serde_json::{json, Value};
use subc_client_rs::{CallOptions, ConsumerIdentity, ConsumerOptions, SubcConsumer};
use subc_protocol::{BindIdentity, RouteTarget};
use tokio::sync::mpsc;

use tracing_subscriber::{layer::SubscriberExt, Layer};

use crate::ModuleState;

const OUTBOX_BATCH: usize = 50;
const OUTBOX_IDLE: Duration = Duration::from_secs(30);

fn session_reusable(error: &str) -> bool {
    matches!(
        error,
        "nats_publish_refused" | "nats_publish_clamped" | "nats_publish_capacity"
    )
}

fn zeroizing_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<zeroize::Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(zeroize::Zeroizing::new)
}

// Transport trace output includes authentication headers and NATS ConnectInfo.
// This filter is outside the fleet log filter, so CK_LOG cannot enable secret output.
pub(crate) fn safe_log_layer(
    config: cortexkit_log::Config,
) -> Result<
    (
        impl Layer<tracing_subscriber::Registry>,
        cortexkit_log::Handle,
    ),
    cortexkit_log::InitError,
> {
    let (layer, handle) = cortexkit_log::layer(config)?;
    Ok((
        layer.with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
            !metadata.target().starts_with("tungstenite")
                && !metadata.target().starts_with("tokio_tungstenite")
                && (!metadata.target().starts_with("async_nats")
                    || *metadata.level() <= tracing::Level::INFO)
        })),
        handle,
    ))
}

pub(crate) fn init_logger_from_env() -> Result<cortexkit_log::Handle, cortexkit_log::InitError> {
    let (layer, handle) = safe_log_layer(cortexkit_log::Config::from_env()?)?;
    tracing::subscriber::set_global_default(tracing_subscriber::Registry::default().with(layer))
        .map_err(|_| cortexkit_log::InitError::GlobalSubscriberAlreadySet)?;
    handle.install_panic_hook();
    Ok(handle)
}

/// NATS credential issued by ck-bus through the module supervisor.
/// Secret material (`jwt`, `credential_public`) is deliberately omitted from `Debug`.
#[derive(Clone, Deserialize)]
pub struct Credential {
    #[serde(deserialize_with = "zeroizing_string")]
    pub jwt: zeroize::Zeroizing<String>,
    pub exp: i64,
    pub acct: String,
    pub account_public: String,
    pub inbox_prefix: String,
    pub server_url: String,
    pub credential_public: String,
    pub user_jwt_id: String,
    pub spawn_generation: u64,
    pub credential_epoch: u64,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("acct", &self.acct)
            .field("account_public", &self.account_public)
            .field("server_url", &self.server_url)
            .field("user_jwt_id", &self.user_jwt_id)
            .field("spawn_generation", &self.spawn_generation)
            .field("credential_epoch", &self.credential_epoch)
            .field("exp", &self.exp)
            .finish_non_exhaustive()
    }
}

impl Credential {
    pub fn validate(&self) -> Result<(), String> {
        AccountNames::derive(&self.acct).map_err(|_| "ckbus_invalid_account")?;
        let config =
            ConnectConfig::new(&self.credential_public).map_err(|_| "ckbus_invalid_key")?;
        if config.inbox_prefix() != self.inbox_prefix {
            return Err("ckbus inbox prefix mismatch".into());
        }
        let address = self
            .server_url
            .parse::<async_nats::ServerAddr>()
            .map_err(|_| "ckbus_invalid_server_url")?;
        let is_local = address.scheme() == "nats"
            && address.username().is_none()
            && address.password().is_none()
            && matches!(address.host(), "127.0.0.1" | "localhost" | "::1");
        if !is_local {
            return Err("ckbus server must be local loopback".into());
        }
        if self.exp <= (now_ms() / 1000) {
            return Err("expired ckbus credential".into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct Renewal {
    #[serde(deserialize_with = "zeroizing_string")]
    jwt: zeroize::Zeroizing<String>,
    exp: i64,
    credential_public: String,
    user_jwt_id: String,
    spawn_generation: u64,
    credential_epoch: u64,
}

impl fmt::Debug for Renewal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Renewal")
            .field("exp", &self.exp)
            .finish_non_exhaustive()
    }
}

impl Credential {
    fn apply(&mut self, renew: Renewal) -> Result<(), String> {
        if renew.credential_public != self.credential_public
            || renew.spawn_generation != self.spawn_generation
            || renew.credential_epoch != self.credential_epoch
            || renew.exp <= self.exp
        {
            return Err("ckbus renewal identity or expiry mismatch".into());
        }
        self.jwt = renew.jwt;
        self.exp = renew.exp;
        self.user_jwt_id = renew.user_jwt_id;
        Ok(())
    }
}

/// Calls ck-bus at the `ckbus` module route over subc to issue and renew credentials.
pub struct CredentialRoute {
    consumer: SubcConsumer,
    identity: BindIdentity,
    principal: ConsumerIdentity,
}

impl CredentialRoute {
    pub async fn connect(path: &Path) -> Result<Self, String> {
        let nonce = subc_client_rs::launch_nonce()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "plexus launch nonce absent".to_string())?;
        let consumer = tokio::time::timeout(
            Duration::from_secs(2),
            SubcConsumer::connect(path, ConsumerOptions::default()),
        )
        .await
        .map_err(|_| "ckbus route connect timeout".to_string())?
        .map_err(|e| e.to_string())?;
        Ok(Self {
            consumer,
            identity: BindIdentity::new(
                path.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new(".")),
                "plexus",
                "bus",
            ),
            principal: ConsumerIdentity {
                module_id: "plexus".into(),
                launch_nonce: nonce.value().to_owned(),
            },
        })
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = serde_json::to_vec(&json!({"method": method, "params": params}))
            .map_err(|_| "ckbus_request_encode_failed")?;
        let reply = self
            .consumer
            .call(
                RouteTarget::ManagementSurface {
                    module_id: "ckbus".into(),
                },
                self.identity.clone(),
                body,
                CallOptions {
                    timeout: Duration::from_secs(2),
                    consumer_identity: Some(self.principal.clone()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| trusted_refusal_code(error.code()).to_string())?;
        let value: Value = serde_json::from_slice(&reply).map_err(|_| "ckbus_invalid_json")?;
        credential_result(value)
    }

    pub async fn issue(&self) -> Result<Credential, String> {
        let credential: Credential =
            serde_json::from_value(self.call("ckbus.credential", json!({})).await?)
                .map_err(|_| "ckbus_invalid_credential")?;
        credential.validate()?;
        Ok(credential)
    }

    pub async fn sign(&self, key: &str, nonce: &[u8]) -> Result<Vec<u8>, String> {
        let value = self
            .call(
                "ckbus.nonce_sign",
                json!({
                    "credential_public": key,
                    "nonce_b64": base64::engine::general_purpose::STANDARD.encode(nonce),
                }),
            )
            .await?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(
                value["signature_b64"]
                    .as_str()
                    .ok_or_else(|| "ckbus signature absent".to_string())?,
            )
            .map_err(|_| "ckbus_invalid_signature")?;
        if bytes.len() != 64 {
            return Err("ckbus signature must be 64 bytes".into());
        }
        Ok(bytes)
    }
}

type SignFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + Sync + 'a>,
>;
trait NonceSigner: Send + Sync {
    fn sign<'a>(&'a self, key: &'a str, nonce: &'a [u8]) -> SignFuture<'a>;
}

impl NonceSigner for CredentialRoute {
    fn sign<'a>(&'a self, key: &'a str, nonce: &'a [u8]) -> SignFuture<'a> {
        Box::pin(CredentialRoute::sign(self, key, nonce))
    }
}

#[async_trait]
#[allow(clippy::double_must_use)]
trait CredentialProvider: NonceSigner {
    async fn issue(&self) -> Result<Credential, String>;
    async fn renewal(&self, credential: &Credential) -> Result<Renewal, String>;
}

#[async_trait]
impl CredentialProvider for CredentialRoute {
    async fn issue(&self) -> Result<Credential, String> {
        CredentialRoute::issue(self).await
    }
    async fn renewal(&self, credential: &Credential) -> Result<Renewal, String> {
        let value = self
            .call(
                "ckbus.credential_renew",
                json!({"credential_public":credential.credential_public}),
            )
            .await?;
        serde_json::from_value(value).map_err(|_| "ckbus_invalid_renewal".into())
    }
}

async fn renew_credential(
    provider: &(impl CredentialProvider + ?Sized),
    credential: &mut Credential,
) -> Result<(), String> {
    match provider.renewal(credential).await {
        Ok(renewal) => credential.apply(renewal)?,
        Err(error) if fresh_required(&error) => *credential = provider.issue().await?,
        Err(error) => return Err(error),
    }
    credential.validate()
}

fn trusted_refusal_code(code: Option<&str>) -> &'static str {
    match code {
        Some("ckbus_credential_superseded") => "ckbus_credential_superseded",
        Some("ckbus_credential_revoked") => "ckbus_credential_revoked",
        Some("ckbus_generation_not_live") => "ckbus_generation_not_live",
        _ => "ckbus_refused",
    }
}

fn credential_result(value: Value) -> Result<Value, String> {
    if let Some(error) = value.get("error") {
        // Only trusted structural codes leave this boundary. Peer messages,
        // unrecognized codes and malformed replies can contain credential data.
        let code = trusted_refusal_code(error.get("code").and_then(Value::as_str));
        return Err(code.into());
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| "ckbus_missing_result".into())
}

pub fn fresh_required(error: &str) -> bool {
    error.contains("ckbus_credential_superseded")
        || error.contains("ckbus_credential_revoked")
        || error.contains("ckbus_generation_not_live")
}

async fn connect_with_signer(
    route: Arc<dyn NonceSigner>,
    credential: &Credential,
) -> Result<(NatsConnection, AccountNames), String> {
    credential.validate()?;
    let key = credential.credential_public.clone();
    let jwt = credential.jwt.clone();
    let auth_error = Arc::new(Mutex::new(None::<String>));
    let callback_error = auth_error.clone();
    let first_attempt = std::sync::atomic::AtomicBool::new(true);
    let options = async_nats::ConnectOptions::with_auth_callback(move |nonce| {
        let route = route.clone();
        let key = key.clone();
        let jwt = jwt.clone();
        let callback_error = callback_error.clone();
        async move {
            let mut last = String::new();
            for attempt in 0..=3 {
                match route.sign(&key, &nonce).await {
                    Ok(signature) => {
                        let mut auth = async_nats::Auth::new();
                        auth.jwt = Some(jwt.to_string());
                        auth.signature = Some(signature);
                        return Ok(auth);
                    }
                    Err(e) => {
                        last = e;
                        *callback_error.lock().unwrap() = Some(last.clone());
                        if fresh_required(&last) {
                            break;
                        }
                        if attempt < 3 {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
            *callback_error.lock().unwrap() = Some(last.clone());
            Err(async_nats::AuthError::new(last))
        }
    })
    .max_reconnects(1)
    // Suppress client auto-reconnect with a year-long delay on its one retry.
    // async-nats treats 0 as unlimited, so use a positive limit. Reconnect only
    // by rebuilding a session after the drain checks that this machine still
    // holds the connector-home claim.
    .reconnect_delay_callback(move |_| {
        if first_attempt.swap(false, std::sync::atomic::Ordering::SeqCst) {
            Duration::ZERO
        } else {
            Duration::from_secs(365 * 24 * 60 * 60)
        }
    })
    .ignore_discovered_servers()
    // Four nonce-sign calls can each take two seconds, plus retry spacing.
    .connection_timeout(Duration::from_secs(10));

    let connection = NatsConnection::connect(
        &credential.server_url,
        options,
        ConnectConfig::new(&credential.credential_public).map_err(|e| e.to_string())?,
    )
    .await
    .map_err(|_| {
        auth_error
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "nats_connect_failed".into())
    })?;
    let account = AccountNames::derive(&credential.acct).map_err(|e| e.to_string())?;
    Ok((connection, account))
}

/// Abstract publisher for event notices.
#[async_trait]
#[allow(clippy::double_must_use)]
pub trait EventPublisher: Send + Sync {
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

#[async_trait]
impl EventPublisher for NatsEventPublisher {
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
        Ok::<_, cortexkit_store::StoreError>(false)
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
    credential: Credential,
    account: AccountNames,
    publisher: Box<dyn EventPublisher>,
    route: Option<Arc<dyn CredentialProvider>>,
    _transport: Option<SessionRuntime>,
}

impl Drop for BusSession {
    fn drop(&mut self) {
        // Stop the transport before dropping the last client sender: sender
        // closure must not give the library a chance to flush queued commands.
        drop(self._transport.take());
    }
}

#[async_trait]
#[allow(clippy::double_must_use)]
pub(crate) trait SessionFactory: Send + Sync {
    async fn open(&self) -> Result<BusSession, String>;
    async fn renew(&self, session: &mut BusSession) -> Result<(), String>;
}

struct ProductionSessions {
    path: Option<PathBuf>,
}
pub(crate) fn session_factory(path: Option<PathBuf>) -> Arc<dyn SessionFactory> {
    Arc::new(ProductionSessions { path })
}

async fn build_session(
    route: Arc<dyn CredentialProvider>,
    credential: Credential,
) -> Result<BusSession, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(|_| "bus_runtime_failed")?;
    let transport = SessionRuntime(Some(runtime));
    let auth_route = route.clone();
    let auth_credential = credential.clone();
    let (connection, account) = transport
        .0
        .as_ref()
        .unwrap()
        .spawn(async move { connect_with_signer(auth_route, &auth_credential).await })
        .await
        .map_err(|_| "bus_connect_join_failed")??;
    let stream_name = account.streams().event.clone();
    Ok(BusSession {
        credential,
        account,
        publisher: Box::new(NatsEventPublisher {
            connection,
            stream_name,
        }),
        route: Some(route),
        _transport: Some(transport),
    })
}

#[async_trait]
impl SessionFactory for ProductionSessions {
    async fn open(&self) -> Result<BusSession, String> {
        let path = self.path.as_ref().ok_or("ckbus_connection_file_absent")?;
        let route = Arc::new(CredentialRoute::connect(path).await?);
        let credential = route.issue().await?;
        build_session(route, credential).await
    }
    async fn renew(&self, session: &mut BusSession) -> Result<(), String> {
        let route = session.route.as_ref().ok_or("ckbus_route_absent")?.clone();
        let mut credential = session.credential.clone();
        renew_credential(route.as_ref(), &mut credential).await?;
        // The auth callback captures a credential snapshot. Rebuild the whole
        // transport for both renewal and fresh issuance, never just the metadata.
        drop(session._transport.take());
        *session = build_session(route, credential).await?;
        Ok(())
    }
}

async fn wait_for_claim_loss(state: &ModuleState) {
    let mut claim = state.runtime.connector_home.decisions();
    let _ = claim.wait_for(|held| !*held).await;
}

// A full batch can have more rows behind it; otherwise a notification or the
// fallback timer starts the next pass.
fn reconnect_backoff(failures: u32) -> Duration {
    Duration::from_secs(1u64 << failures.min(9)).min(Duration::from_secs(300))
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
                if !outbox_has_pending(state.store()).await? {
                    return Ok(0);
                }
                if session.is_none() {
                    session = Some(factory.open().await?);
                }
                let active = session.as_mut().expect("opened session");
                if active.credential.exp.saturating_sub(now_ms() / 1000) < 300 {
                    factory.renew(active).await?;
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
                refresh_unpublishable_count(&state).await?;
                result
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
                    delay = if unpublishable.pending_more() {
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
                        state.health.record_publish_error(error);
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
pub mod tests {
    use super::*;
    use cortexkit_bus_trait::Message;
    use cortexkit_store_types::StorageDescriptor;
    use plexus_core::{
        storage::event_outbox::{EventHeaders, KeyedEventIdentity, KeyedPollEventInput},
        test_scratch::Scratch,
        ActorAttribution, PlexusStore, PollEventInput,
    };

    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    fn current_health(state: &ModuleState) -> subc_protocol::session::ModuleControlResponse {
        state.health.stamp_heartbeat();
        crate::connector_home_health(state)
    }

    struct TestSigner;
    impl NonceSigner for TestSigner {
        fn sign<'a>(&'a self, _: &'a str, _: &'a [u8]) -> SignFuture<'a> {
            Box::pin(async { Ok(vec![1; 64]) })
        }
    }

    #[tokio::test]
    async fn auth_callback_budget_includes_slow_nonce_retries() {
        struct SlowSigner(std::sync::atomic::AtomicU32);
        impl NonceSigner for SlowSigner {
            fn sign<'a>(&'a self, _: &'a str, _: &'a [u8]) -> SignFuture<'a> {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_millis(900)).await;
                    if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                        Err("ckbus_refused".into())
                    } else {
                        Ok(vec![1; 64])
                    }
                })
            }
        }
        let (url, mut auth, _, _, server) =
            loopback_with_deadlines(Duration::from_secs(8), Duration::from_secs(15)).await;
        let result = tokio::time::timeout(
            Duration::from_secs(12),
            connect_with_signer(
                Arc::new(SlowSigner(std::sync::atomic::AtomicU32::new(0))),
                &credential(url),
            ),
        )
        .await
        .unwrap();
        server.abort();
        assert!(
            result.is_ok(),
            "slow nonce retries must fit within the connection budget"
        );
        assert!(tokio::time::timeout(Duration::from_secs(3), auth.recv())
            .await
            .unwrap()
            .is_some());
    }

    fn credential(url: String) -> Credential {
        Credential {
            jwt: "SECRET-JWT-for-loopback".to_string().into(),
            exp: now_ms() / 1000 + 900,
            acct: "box_test".into(),
            account_public: "ACCOUNT".into(),
            inbox_prefix: "_INBOX.KEY".into(),
            server_url: url,
            credential_public: "KEY".into(),
            user_jwt_id: "id".into(),
            spawn_generation: 1,
            credential_epoch: 1,
        }
    }

    // Speaks only the protocol exercised by the real NATS adapter: INFO,
    // CONNECT, PING, SUB and HPUB with an explicitly released JetStream ack.
    async fn loopback() -> (
        String,
        mpsc::Receiver<String>,
        mpsc::Receiver<()>,
        Arc<tokio::sync::Notify>,
        tokio::task::JoinHandle<()>,
    ) {
        loopback_with_deadlines(Duration::from_secs(3), Duration::from_secs(10)).await
    }

    async fn loopback_with_deadlines(
        step_deadline: Duration,
        exchange_deadline: Duration,
    ) -> (
        String,
        mpsc::Receiver<String>,
        mpsc::Receiver<()>,
        Arc<tokio::sync::Notify>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("nats://{}", listener.local_addr().unwrap());
        let (auth_tx, auth_rx) = mpsc::channel(8);
        let (publish_tx, publish_rx) = mpsc::channel(8);
        let ack = Arc::new(tokio::sync::Notify::new());
        let release = ack.clone();
        let task = tokio::spawn(async move {
            tokio::time::timeout(exchange_deadline, async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let (read, mut write) = socket.into_split();
                write.write_all(b"INFO {\"server_id\":\"test\",\"version\":\"2.10.0\",\"proto\":1,\"nonce\":\"nonce\",\"headers\":true,\"max_payload\":1048576}\r\n").await.unwrap();
                let mut read = BufReader::new(read);
                let mut line = String::new();
                let mut sid = String::new();
                // An idle connection is owned by the test: SQLite or credential
                // preparation may precede the next command. Only the whole-exchange
                // watchdog, not a short idle timer, bounds these intervals.
                while { line.clear(); read.read_line(&mut line).await.unwrap_or(0) > 0 } {
                    if let Some(info) = line.strip_prefix("CONNECT ") {
                        let info: Value = serde_json::from_str(info.trim()).unwrap();
                        auth_tx.send(info["jwt"].as_str().unwrap_or_default().into()).await.unwrap();
                    } else if line.starts_with("PING") {
                        if write.write_all(b"PONG\r\n").await.is_err() { break; }
                    } else if line.starts_with("SUB ") {
                        sid = line.split_whitespace().last().unwrap().into();
                    } else if line.starts_with("HPUB ") {
                        let fields: Vec<_> = line.split_whitespace().collect();
                        let reply = fields[2].to_owned();
                        let size: usize = fields.last().unwrap().parse().unwrap();
                        let mut payload = vec![0; size + 2];
                        tokio::time::timeout(step_deadline, read.read_exact(&mut payload)).await.expect("loopback payload deadline").unwrap();
                        publish_tx.send(()).await.unwrap();
                        release.notified().await;
                        let body = r#"{"stream":"events","seq":7}"#;
                        let response = format!("MSG {reply} {sid} {}\r\n{body}\r\n", body.len());
                        if write.write_all(response.as_bytes()).await.is_err() { break; }
                    }
                }
            }
            }).await.expect("loopback server exchange deadline");
        });
        (url, auth_rx, publish_rx, ack, task)
    }

    struct TestCredentials {
        fresh: Credential,
        replaced: bool,
    }
    impl NonceSigner for TestCredentials {
        fn sign<'a>(&'a self, _: &'a str, _: &'a [u8]) -> SignFuture<'a> {
            Box::pin(async { Ok(vec![1; 64]) })
        }
    }
    #[async_trait]
    impl CredentialProvider for TestCredentials {
        async fn issue(&self) -> Result<Credential, String> {
            Ok(self.fresh.clone())
        }
        async fn renewal(&self, old: &Credential) -> Result<Renewal, String> {
            if self.replaced {
                return Err("ckbus_credential_revoked".into());
            }
            Ok(Renewal {
                jwt: self.fresh.jwt.clone(),
                exp: old.exp + 900,
                credential_public: old.credential_public.clone(),
                user_jwt_id: "renewed".into(),
                spawn_generation: old.spawn_generation,
                credential_epoch: old.credential_epoch,
            })
        }
    }

    #[tokio::test]
    async fn renewal_rebuild_authenticates_new_jwt_and_replacement_key() {
        tokio::time::timeout(Duration::from_secs(8), async {
            for replaced in [false, true] {
                let (url, mut auth, _, _, server) = loopback().await;
                let original = credential(url);
                let mut fresh = original.clone();
                fresh.jwt = "NEW-JWT-after-renewal".to_string().into();
                if replaced {
                    fresh.credential_public = "REPLACEMENT".into();
                    fresh.inbox_prefix = "_INBOX.REPLACEMENT".into();
                }
                let provider = Arc::new(TestCredentials {
                    fresh: fresh.clone(),
                    replaced,
                });
                let mut session = build_session(provider, original.clone()).await.unwrap();
                assert_eq!(
                    crate::bounded::recv_within(
                        auth.recv(),
                        Duration::from_secs(5),
                        "first CONNECT with the original JWT",
                    )
                    .await,
                    original.jwt.as_str()
                );
                ProductionSessions { path: None }
                    .renew(&mut session)
                    .await
                    .unwrap();
                assert_eq!(
                    crate::bounded::recv_within(
                        auth.recv(),
                        Duration::from_secs(5),
                        "next CONNECT after renewal",
                    )
                    .await,
                    fresh.jwt.as_str(),
                    "next CONNECT must use renewed JWT"
                );
                assert_eq!(
                    session.credential.credential_public,
                    fresh.credential_public
                );
                drop(session);
                server.abort();
            }
        })
        .await
        .expect("renewal loopback exchange deadline");
        for code in [
            "ckbus_credential_revoked",
            "ckbus_credential_superseded",
            "ckbus_generation_not_live",
        ] {
            let error = subc_client_rs::CallError::Module(subc_protocol::ErrorBody {
                code: code.into(),
                message: "secret".into(),
                detail: None,
            });
            assert!(fresh_required(trusted_refusal_code(error.code())));
        }
    }

    #[test]
    fn malformed_credential_errors_never_echo_peer_text() {
        for value in [
            json!({"jwt":"secret-reply", "alien":"secret-reply"}),
            json!({"error":{"code":"secret-reply", "message":"secret-reply"}}),
        ] {
            let error = credential_result(value).unwrap_err();
            assert!(!error.contains("secret-reply"));
        }
        let renewal = Renewal {
            jwt: "renewal-secret".to_string().into(),
            exp: 1,
            credential_public: "key-secret".into(),
            user_jwt_id: "id".into(),
            spawn_generation: 1,
            credential_epoch: 1,
        };
        assert!(!format!("{renewal:?}").contains("secret"));
    }

    #[test]
    fn credential_url_requires_exact_loopback_without_userinfo() {
        for url in [
            "nats://localhost:4222@evil.example:4222",
            "nats://localhost.evil:4222",
            "nats://user@localhost:4222",
            "tls://localhost:4222",
        ] {
            assert!(credential(url.into()).validate().is_err(), "{url}");
        }
        for url in [
            "nats://127.0.0.1:4222",
            "nats://localhost:4222",
            "nats://[::1]:4222",
        ] {
            assert!(credential(url.into()).validate().is_ok(), "{url}");
        }
    }

    #[tokio::test]
    async fn trace_loopback_never_logs_jwt() {
        const CHILD: &str = "PLEXUS_TRACE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            for spec in [
                "trace",
                "trace,async_nats=trace,async_nats::connection=trace",
            ] {
                let mut command = std::process::Command::new(std::env::current_exe().unwrap());
                command
                    .args([
                        "--exact",
                        "bus::tests::trace_loopback_never_logs_jwt",
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .env("CK_LOG", spec);
                let output = crate::bounded::child_output(
                    &mut command,
                    Duration::from_secs(30),
                    "trace-filter test child",
                )
                .expect("run trace-filter test child");
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                crate::test_support::assert_exactly_one_test_passed(
                    "bus::tests::trace_loopback_never_logs_jwt",
                    &output,
                );
            }
            return;
        }
        let scratch = Scratch::database("safe-trace");
        let logs = scratch.path().with_extension("logs");
        let (layer, handle) =
            safe_log_layer(cortexkit_log::Config::in_dir("plexus", &logs)).unwrap();
        tracing::subscriber::set_global_default(
            tracing_subscriber::Registry::default().with(layer),
        )
        .unwrap();
        let (url, mut auth, _, _, server) = loopback().await;
        let cred = credential(url);
        let (connection, _) = tokio::time::timeout(
            Duration::from_secs(3),
            connect_with_signer(Arc::new(TestSigner), &cred),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), auth.recv())
                .await
                .expect("CONNECT observation deadline")
                .unwrap(),
            cred.jwt.as_str()
        );
        tracing::trace!("trace-control-visible");
        let text = std::fs::read_to_string(handle.path()).unwrap();
        assert!(
            text.contains("trace-control-visible"),
            "trace must really be enabled: {text}"
        );
        assert!(!text.contains(cred.jwt.as_str()), "JWT leaked: {text}");
        drop(connection);
        server.abort();
        std::fs::remove_dir_all(logs).unwrap();
    }

    #[derive(Default, Clone)]
    pub struct MockPublisher {
        pub published: Arc<Mutex<Vec<Message>>>,
        pub acks: Arc<Mutex<u64>>,
        pub fail_with: Arc<Mutex<Option<String>>>,
    }

    #[async_trait]
    impl EventPublisher for MockPublisher {
        async fn publish(
            &self,
            subject: &str,
            id: &str,
            digest: ContentDigest,
            headers: Headers,
        ) -> Result<PublishReceipt, String> {
            if let Some(err) = self.fail_with.lock().unwrap().clone() {
                return Err(err);
            }
            let mut acks = self.acks.lock().unwrap();
            *acks += 1;
            let seq = *acks;
            self.published.lock().unwrap().push(Message {
                subject: subject.to_string(),
                id: id.to_string(),
                digest,
                headers,
            });
            Ok(PublishReceipt::new(seq, false))
        }
    }

    pub fn test_store(name: &str) -> (Scratch, Arc<PlexusStore>) {
        let scratch = Scratch::database(name);
        let store = open_test_store(&scratch);
        (scratch, store)
    }

    pub(crate) fn open_test_store(path: &Path) -> Arc<PlexusStore> {
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: "test".to_string(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        };
        Arc::new(PlexusStore::open(&descriptor).expect("open test plexus store"))
    }

    pub fn seed_connection_and_subscription(store: &PlexusStore, conn_id: &str) -> String {
        let manifest_source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github.jsonc"),
        )
        .expect("read shipped manifest");
        let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize manifest");
        let ingested = plexus_core::ingest_value(
            serde_json::from_str::<Value>(&normalized).expect("parse manifest"),
        )
        .expect("ingest manifest");
        store
            .upsert_manifest("system", &ingested)
            .expect("seed the shipped GitHub manifest");
        store
            .insert_connection(
                "direct",
                conn_id,
                &ingested.manifest.key,
                "active",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("seed the connection");
        store
            .upsert_catalog_action(&plexus_core::CatalogActionInput {
                connection_id: conn_id.to_string(),
                principal: "direct".to_string(),
                name: "list_issues".to_string(),
                title: None,
                schema: json!({"type": "object", "properties": {}}),
                schema_hash: "sha256:list-issues".to_string(),
                risk: "read".to_string(),
                severity: "S1".to_string(),
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
                ask_first: false,
            })
            .expect("seed the list_issues catalog action");
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: format!("grant-{conn_id}"),
                principal: "direct".to_string(),
                connection_id: conn_id.to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["list_issues".to_string(), "list_pull_requests".to_string()],
                authority_kind: "poll".to_string(),
                expires_at: Some(i64::MAX / 2),
            })
            .expect("seed the poll grant");
        let sub = store
            .subscribe("direct", conn_id, "list_issues", 300)
            .expect("store")
            .expect("sub");
        sub.subscription_id
    }

    // Existing crash and wire tests pin the v1 path. The v2 tests below exercise
    // the combined publisher explicitly through super::drain_pass.
    async fn drain_v1_pass(
        store: &Arc<PlexusStore>,
        account: &AccountNames,
        publisher: &(impl EventPublisher + ?Sized),
        batch_size: usize,
        held: &(impl Fn() -> bool + Sync),
    ) -> Result<usize, String> {
        super::drain_version_pass(
            store,
            account,
            publisher,
            batch_size,
            held,
            1,
            &super::UnpublishableRows::default(),
        )
        .await
    }

    pub fn insert_test_event(
        store: &PlexusStore,
        sub_id: &str,
        key: &str,
        event_name: &str,
        repo: &str,
        payload: &Value,
    ) {
        let headers = EventHeaders {
            repo: repo.to_string(),
            project: Some("p1".to_string()),
            pr: Some("42".to_string()),
            branch: Some("main".to_string()),
            conclusion: Some("failure".to_string()),
        };
        let identity = KeyedEventIdentity {
            event_key: key,
            event_name,
            repo_id: 101,
            change: Some("updated"),
            headers: &headers,
        };
        // Commit against the connection the subscription really belongs to,
        // so a test that seeds a different connection id gets a consistent row.
        let connection_id = store
            .subscription("direct", sub_id)
            .expect("read the subscription")
            .expect("insert_test_event needs a seeded subscription")
            .connection_id;
        let actor = ActorAttribution::NotEnriched;
        let input = KeyedPollEventInput {
            event: PollEventInput {
                vendor_event_id: key,
                payload,
                observed_at_ms: now_ms(),
                item_kind: Some("issue"),
                activity_at_ms: Some(now_ms()),
                actor: &actor,
            },
            identity: Some(identity),
            delivery_id: None,
            envelope_context: Default::default(),
        };
        store
            .commit_keyed_poll_success(
                "direct",
                &connection_id,
                sub_id,
                &json!({}),
                &[input],
                now_ms(),
                &[],
            )
            .expect("commit keyed poll success");
    }

    /// A poll success committed under the wrong connection advances nothing
    /// and inserts no event, without an error. So the shared helper must
    /// commit under the connection the subscription was seeded with.
    #[tokio::test]
    async fn insert_test_event_commits_under_the_seeded_connection() {
        let (_scratch, store) = test_store("event-own-connection");
        let sub = seed_connection_and_subscription(&store, "conn-2");
        insert_test_event(
            &store,
            &sub,
            &"e".repeat(64),
            "github_issue_changed",
            "owner/repo",
            &json!({"number": 1}),
        );
        assert!(
            super::outbox_has_pending(&store).await.unwrap(),
            "an event seeded for conn-2 must reach the outbox"
        );
    }

    struct Claim(std::sync::atomic::AtomicBool);
    impl crate::connector_home::RolePeer for Claim {
        fn call(&self, _: &str, _: Value) -> Result<Value, subc_protocol::ErrorBody> {
            Ok(
                json!({"role":"connector_home","epoch":1,"known":true,"stale":false,"holder":null,"holder_name":null,"source":"cloud", "held_here":self.0.load(std::sync::atomic::Ordering::SeqCst)}),
            )
        }
    }

    struct FlipPublisher {
        inner: MockPublisher,
        claim: Arc<Claim>,
        home: Arc<crate::connector_home::ConnectorHome>,
    }
    #[async_trait]
    impl EventPublisher for FlipPublisher {
        async fn publish(
            &self,
            subject: &str,
            id: &str,
            digest: ContentDigest,
            headers: Headers,
        ) -> Result<PublishReceipt, String> {
            let ack = self.inner.publish(subject, id, digest, headers).await?;
            self.claim
                .0
                .store(false, std::sync::atomic::Ordering::SeqCst);
            self.home.refresh().unwrap();
            Ok(ack)
        }
    }
    struct FixtureSessions {
        publisher: MockPublisher,
        claim: Arc<Claim>,
        home: Arc<crate::connector_home::ConnectorHome>,
        flip_at_setup: bool,
        opened: Arc<tokio::sync::Notify>,
    }
    #[async_trait]
    impl SessionFactory for FixtureSessions {
        async fn open(&self) -> Result<BusSession, String> {
            if self.flip_at_setup {
                self.claim
                    .0
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                self.home.refresh().unwrap();
            }
            self.opened.notify_one();
            Ok(BusSession {
                credential: credential("nats://localhost:4222".into()),
                account: AccountNames::derive("box_test").unwrap(),
                publisher: Box::new(FlipPublisher {
                    inner: self.publisher.clone(),
                    claim: self.claim.clone(),
                    home: self.home.clone(),
                }),
                route: None,
                _transport: None,
            })
        }
        async fn renew(&self, _: &mut BusSession) -> Result<(), String> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn task_claim_loss_during_setup_and_after_first_ack_keeps_pending() {
        for setup in [true, false] {
            let (_scratch, store) = test_store(if setup { "claim_setup" } else { "claim_batch" });
            let sub = seed_connection_and_subscription(&store, "conn-1");
            for i in 1..=3 {
                insert_test_event(
                    &store,
                    &sub,
                    &format!("{i:064x}"),
                    "github_issue_changed",
                    "owner/repo",
                    &json!({"i":i}),
                );
            }
            let claim = Arc::new(Claim(std::sync::atomic::AtomicBool::new(true)));
            let home = Arc::new(crate::connector_home::ConnectorHome::new(claim.clone()));
            home.refresh().unwrap();
            let mut runtime = crate::runtime_for_test(store.clone());
            runtime.connector_home = home.clone();
            let state = Arc::new(ModuleState {
                runtime,
                health: Arc::new(crate::health::HealthState::new()),
            });
            let publisher = MockPublisher::default();
            let opened = Arc::new(tokio::sync::Notify::new());
            let factory = Arc::new(FixtureSessions {
                publisher: publisher.clone(),
                claim,
                home,
                flip_at_setup: setup,
                opened: opened.clone(),
            });
            let (shutdown, stop) = mpsc::channel(1);
            let task = spawn_outbox_drain(state, stop, factory);
            tokio::time::timeout(Duration::from_secs(2), opened.notified())
                .await
                .unwrap();
            // Allow the in-flight drain attempt to observe claim loss.
            // The join timeout makes broken shutdown cancellation fail instead of hanging.
            tokio::time::sleep(Duration::from_millis(350)).await;
            drop(shutdown);
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            let expected = usize::from(!setup);
            assert_eq!(
                publisher.published.lock().unwrap().len(),
                expected,
                "claim loss must fence each publish"
            );
            assert_eq!(store.drain_event_outbox(50).unwrap().len(), 3 - expected);
        }
    }

    #[tokio::test]
    async fn task_stop_cancels_connection_setup() {
        struct Pending(Arc<tokio::sync::Notify>);
        #[async_trait]
        impl SessionFactory for Pending {
            async fn open(&self) -> Result<BusSession, String> {
                self.0.notify_one();
                std::future::pending().await
            }
            async fn renew(&self, _: &mut BusSession) -> Result<(), String> {
                unreachable!()
            }
        }
        let (_scratch, store) = test_store("stop_setup");
        let sub = seed_connection_and_subscription(&store, "conn-1");
        insert_test_event(
            &store,
            &sub,
            &format!("{:064x}", 1),
            "github_issue_changed",
            "owner/repo",
            &json!({}),
        );
        let state = Arc::new(ModuleState {
            runtime: crate::runtime_for_test(store),
            health: Arc::new(crate::health::HealthState::new()),
        });
        let (shutdown, stop) = mpsc::channel(1);
        let entered = Arc::new(tokio::sync::Notify::new());
        let task = spawn_outbox_drain(state, stop, Arc::new(Pending(entered.clone())));
        tokio::time::timeout(Duration::from_secs(3), entered.notified())
            .await
            .unwrap();
        drop(shutdown);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    struct CountingSessions {
        publisher: MockPublisher,
        passes: Arc<std::sync::atomic::AtomicUsize>,
        entered: Arc<tokio::sync::Notify>,
    }

    #[tokio::test(start_paused = true)]
    async fn idle_fallback_waits_thirty_seconds_and_wakes_do_not_defeat_backoff() {
        use futures_util::FutureExt;
        let (_scratch, store) = test_store("drain-fallback");
        let wait = wait_for_outbox(&store, OUTBOX_IDLE, 0);
        tokio::pin!(wait);
        assert!(wait.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(
            wait.as_mut().now_or_never().is_none(),
            "idle fallback must wait thirty seconds"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        wait.await;
        let sub = seed_connection_and_subscription(&store, "conn-1");
        insert_test_event(
            &store,
            &sub,
            &format!("{:064x}", 1),
            "github_issue_changed",
            "owner/repo",
            &json!({}),
        );
        let wait = wait_for_outbox(&store, Duration::from_millis(200), 1);
        tokio::pin!(wait);
        assert!(
            wait.as_mut().now_or_never().is_none(),
            "insert wakes must not defeat failure backoff"
        );
        tokio::time::advance(Duration::from_millis(199)).await;
        assert!(wait.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(1)).await;
        wait.await;
        assert!(
            wait_for_outbox(&store, OUTBOX_IDLE, 0)
                .now_or_never()
                .is_some(),
            "backoff must leave the insert permit for the recovered drain"
        );
    }
    #[async_trait]
    impl SessionFactory for CountingSessions {
        async fn open(&self) -> Result<BusSession, String> {
            let mut credential = credential("nats://localhost:4222".into());
            // Keep renewal due so this fixture observes every scheduler pass,
            // including empty passes that never call the publisher.
            credential.exp = 0;
            Ok(BusSession {
                credential,
                account: AccountNames::derive("box_test").unwrap(),
                publisher: Box::new(self.publisher.clone()),
                route: None,
                _transport: None,
            })
        }
        async fn renew(&self, _: &mut BusSession) -> Result<(), String> {
            self.passes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.entered.notify_one();
            Ok(())
        }
    }

    // Check scheduling separately from durable marker commits: ordinary parallel
    // suites can delay a SQLite COMMIT for seconds even after the notice was sent.
    const OUTBOX_WAKE_DEADLINE: Duration = Duration::from_secs(3);
    const OUTBOX_DRAIN_DEADLINE: Duration = Duration::from_secs(20);

    #[tokio::test]
    async fn idle_without_a_bus_is_healthy_pending_failure_degrades_and_publish_recovers() {
        struct OutageSessions {
            ready: std::sync::atomic::AtomicBool,
            opens: std::sync::atomic::AtomicUsize,
            publisher: MockPublisher,
        }
        #[async_trait]
        impl SessionFactory for OutageSessions {
            async fn open(&self) -> Result<BusSession, String> {
                self.opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if !self.ready.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err("nats_connect_failed".into());
                }
                Ok(BusSession {
                    credential: credential("nats://127.0.0.1:4222".into()),
                    account: AccountNames::derive("box_test").unwrap(),
                    publisher: Box::new(self.publisher.clone()),
                    route: None,
                    _transport: None,
                })
            }
            async fn renew(&self, _: &mut BusSession) -> Result<(), String> {
                Ok(())
            }
        }
        let (_scratch, store) = test_store("demand-health-boundary");
        let sub = seed_connection_and_subscription(&store, "conn-1");
        let state = Arc::new(ModuleState {
            runtime: crate::runtime_for_test(store.clone()),
            health: Arc::new(crate::health::HealthState::new()),
        });
        state.health.record_publish_error("waiting_for_idle_pass");
        let factory = Arc::new(OutageSessions {
            ready: std::sync::atomic::AtomicBool::new(false),
            opens: std::sync::atomic::AtomicUsize::new(0),
            publisher: MockPublisher::default(),
        });
        let (shutdown, stop) = mpsc::channel(1);
        let task = spawn_outbox_drain(state.clone(), stop, factory.clone());
        tokio::time::timeout(Duration::from_secs(3), async {
            while state.health.last_publish_error().is_some() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("idle without a bus must finish healthy");
        assert_eq!(factory.opens.load(std::sync::atomic::Ordering::SeqCst), 0);
        let subc_protocol::session::ModuleControlResponse::HealthCheck { status, .. } =
            current_health(&state)
        else {
            panic!("health")
        };
        assert_eq!(status, subc_protocol::session::HealthStatus::Ok);
        insert_test_event(
            &store,
            &sub,
            &format!("{:064x}", 1),
            "github_issue_changed",
            "owner/repo",
            &json!({}),
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            while state.health.last_publish_error().is_none() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let subc_protocol::session::ModuleControlResponse::HealthCheck {
            status, metrics, ..
        } = current_health(&state)
        else {
            panic!("health")
        };
        assert_eq!(status, subc_protocol::session::HealthStatus::Degraded);
        assert_eq!(metrics.unwrap()["lastPublishError"], "nats_connect_failed");
        factory
            .ready
            .store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(10), async {
            while state.health.last_publish_error().is_some() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(factory.publisher.published.lock().unwrap().len(), 2);
        let subc_protocol::session::ModuleControlResponse::HealthCheck { status, .. } =
            current_health(&state)
        else {
            panic!("health")
        };
        assert_eq!(status, subc_protocol::session::HealthStatus::Ok);
        drop(shutdown);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn claim_gain_wakes_an_idle_drain_with_an_existing_backlog() {
        let (_scratch, store) = test_store("drain-claim-gain");
        let sub = seed_connection_and_subscription(&store, "conn-1");
        insert_test_event(
            &store,
            &sub,
            &format!("{:064x}", 1),
            "github_issue_changed",
            "owner/repo",
            &json!({}),
        );
        store.outbox_committed().await;
        let claim = Arc::new(Claim(std::sync::atomic::AtomicBool::new(false)));
        let home = Arc::new(crate::connector_home::ConnectorHome::new(claim.clone()));
        home.refresh().unwrap();
        let mut runtime = crate::runtime_for_test(store.clone());
        runtime.connector_home = home.clone();
        let state = Arc::new(ModuleState {
            runtime,
            health: Arc::new(crate::health::HealthState::new()),
        });
        state.health.stamp_outbox_unpublishable(999);
        let entered = Arc::new(tokio::sync::Notify::new());
        let (shutdown, stop) = mpsc::channel(1);
        let task = spawn_outbox_drain(
            state.clone(),
            stop,
            Arc::new(CountingSessions {
                publisher: MockPublisher::default(),
                passes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                entered: entered.clone(),
            }),
        );
        tokio::time::timeout(OUTBOX_WAKE_DEADLINE, async {
            loop {
                let subc_protocol::session::ModuleControlResponse::HealthCheck { metrics, .. } =
                    state.health.report()
                else {
                    panic!("health")
                };
                if metrics.unwrap()["outboxUnpublishable"] == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        claim.0.store(true, std::sync::atomic::Ordering::SeqCst);
        home.refresh().unwrap();
        let woke = tokio::time::timeout(OUTBOX_WAKE_DEADLINE, entered.notified()).await;
        drop(shutdown);
        task.await.unwrap();
        woke.expect(
            "claim gain must wake the drain without an insert or the thirty-second fallback",
        );
    }

    async fn wait_for_outbox_empty(store: &Arc<PlexusStore>, limit: usize) {
        loop {
            let db = store.clone();
            let empty = tokio::task::spawn_blocking(move || {
                db.drain_event_outbox_version(limit, 1).unwrap().is_empty()
                    && db.drain_event_outbox_version(limit, 2).unwrap().is_empty()
            })
            .await
            .unwrap();
            if empty {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn task_waits_idle_then_publishes_committed_event_before_fallback() {
        let (_scratch, store) = test_store("demand-drain");
        let sub = seed_connection_and_subscription(&store, "conn-1");
        let publisher = MockPublisher::default();
        let passes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let entered = Arc::new(tokio::sync::Notify::new());
        let state = Arc::new(ModuleState {
            runtime: crate::runtime_for_test(store.clone()),
            health: Arc::new(crate::health::HealthState::new()),
        });
        let (shutdown, stop) = mpsc::channel(1);
        state.health.record_publish_error("waiting_for_idle_pass");
        let task = spawn_outbox_drain(
            state.clone(),
            stop,
            Arc::new(CountingSessions {
                publisher: publisher.clone(),
                passes: passes.clone(),
                entered: entered.clone(),
            }),
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            while state.health.last_publish_error().is_some() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("an empty drain must finish without opening a bus session");
        tokio::time::sleep(Duration::from_millis(800)).await;
        let idle_passes = passes.load(std::sync::atomic::Ordering::SeqCst);
        let db = store.clone();
        tokio::task::spawn_blocking(move || {
            insert_test_event(
                &db,
                &sub,
                &format!("{:064x}", 1),
                "github_issue_changed",
                "owner/repo",
                &json!({"number": 1}),
            );
        })
        .await
        .unwrap();
        let woke = tokio::time::timeout(OUTBOX_WAKE_DEADLINE, entered.notified()).await;
        let published = if woke.is_ok() {
            Some(
                tokio::time::timeout(OUTBOX_DRAIN_DEADLINE, wait_for_outbox_empty(&store, 50))
                    .await,
            )
        } else {
            None
        };
        drop(shutdown);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            idle_passes, 0,
            "idle drain must not open a bus session without pending work"
        );
        woke.expect("a commit must wake the idle drain before its thirty-second fallback");
        published
            .unwrap()
            .expect("the woken drain must publish and stamp both notices");
        assert_eq!(
            passes.load(std::sync::atomic::Ordering::SeqCst),
            idle_passes + 1
        );
        assert_eq!(publisher.published.lock().unwrap().len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn task_repeats_full_batches_without_waiting_for_another_wake() {
        let (_scratch, store) = test_store("full-batch-drain");
        let sub = seed_connection_and_subscription(&store, "conn-1");
        for i in 1..=51 {
            insert_test_event(
                &store,
                &sub,
                &format!("{i:064x}"),
                "github_issue_changed",
                "owner/repo",
                &json!({"number": i}),
            );
        }
        // Consume the coalesced insert permit so only the initial startup pass
        // and full-batch continuation can publish the fifty-first row.
        tokio::time::timeout(Duration::from_secs(1), store.outbox_committed())
            .await
            .unwrap();
        let publisher = MockPublisher::default();
        let state = Arc::new(ModuleState {
            runtime: crate::runtime_for_test(store.clone()),
            health: Arc::new(crate::health::HealthState::new()),
        });
        let (shutdown, stop) = mpsc::channel(1);
        let task = spawn_outbox_drain(
            state,
            stop,
            Arc::new(CountingSessions {
                publisher: publisher.clone(),
                passes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                entered: Arc::new(tokio::sync::Notify::new()),
            }),
        );
        let drained =
            tokio::time::timeout(OUTBOX_DRAIN_DEADLINE, wait_for_outbox_empty(&store, 100)).await;
        drop(shutdown);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        drained.expect("full batches must drain without another wake or fallback interval");
        assert_eq!(publisher.published.lock().unwrap().len(), 102);
    }

    #[tokio::test]
    async fn task_stop_cancels_real_ack_wait_and_leaves_marker_pending() {
        struct RealFixture {
            credential: Credential,
        }
        #[async_trait]
        impl SessionFactory for RealFixture {
            async fn open(&self) -> Result<BusSession, String> {
                build_session(
                    Arc::new(TestCredentials {
                        fresh: self.credential.clone(),
                        replaced: false,
                    }),
                    self.credential.clone(),
                )
                .await
            }
            async fn renew(&self, session: &mut BusSession) -> Result<(), String> {
                ProductionSessions { path: None }.renew(session).await
            }
        }
        let (_scratch, store) = test_store("stop_real_ack");
        let sub = seed_connection_and_subscription(&store, "conn-1");
        let key = format!("{:064x}", 1);
        insert_test_event(
            &store,
            &sub,
            &key,
            "github_issue_changed",
            "owner/repo",
            &json!({}),
        );
        let (url, _auth, mut received, _ack, server) = loopback().await;
        let state = Arc::new(ModuleState {
            runtime: crate::runtime_for_test(store.clone()),
            health: Arc::new(crate::health::HealthState::new()),
        });
        let (shutdown, stop) = mpsc::channel(1);
        let task = spawn_outbox_drain(
            state,
            stop,
            Arc::new(RealFixture {
                credential: credential(url),
            }),
        );
        tokio::time::timeout(OUTBOX_DRAIN_DEADLINE, received.recv())
            .await
            .expect("notice before stop deadline")
            .unwrap();
        drop(shutdown);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("stop must cancel real ack wait")
            .unwrap();
        assert!(store
            .canonical_event_by_key(&key)
            .unwrap()
            .unwrap()
            .published_at_ms
            .is_none());
        server.abort();
    }

    // Start transport deadlines at publish entry, not at the preceding SQLite
    // read. A slow blocking-worker dispatch is not a slow NATS publication.
    const REAL_NATS_STEP_DEADLINE: Duration = Duration::from_secs(6);

    struct AckObservedPublisher {
        inner: NatsEventPublisher,
        started: Arc<tokio::sync::Notify>,
        acked: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl EventPublisher for AckObservedPublisher {
        async fn publish(
            &self,
            subject: &str,
            id: &str,
            digest: ContentDigest,
            headers: Headers,
        ) -> Result<PublishReceipt, String> {
            self.started.notify_one();
            let receipt = self.inner.publish(subject, id, digest, headers).await?;
            self.acked.notify_one();
            Ok(receipt)
        }
    }

    async fn published_at(store: &Arc<PlexusStore>, key: &str) -> Option<i64> {
        let db = store.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            db.canonical_event_by_key(&key)
                .unwrap()
                .unwrap()
                .published_at_ms
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn real_nats_adapter_polls_publish_and_waits_for_ack_before_stamp() {
        assert_real_nats_ack_ordering("real_adapter_ack", Duration::ZERO).await;
    }

    #[test]
    fn real_nats_adapter_tolerates_delayed_outbox_read_before_publish() {
        // A single occupied blocking worker deterministically queues drain_pass's
        // SQLite read. Delay only that scheduling step, not the JetStream ack.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(assert_real_nats_ack_ordering(
            "real_adapter_delayed_read",
            REAL_NATS_STEP_DEADLINE + Duration::from_secs(1),
        ));
    }

    async fn assert_real_nats_ack_ordering(name: &str, outbox_read_delay: Duration) {
        let (_scratch, store) = test_store(name);
        let sub = seed_connection_and_subscription(&store, "conn-1");
        let key = format!("{:064x}", 1);
        insert_test_event(
            &store,
            &sub,
            &key,
            "github_issue_changed",
            "owner/repo",
            &json!({}),
        );
        tokio::time::timeout(Duration::from_secs(30), async {
            let (url, _auth, mut received, ack, server) =
                loopback_with_deadlines(REAL_NATS_STEP_DEADLINE, Duration::from_secs(30)).await;
            let cred = credential(url);
            let (connection, account) = connect_with_signer(Arc::new(TestSigner), &cred)
                .await
                .unwrap();
            let acked = Arc::new(tokio::sync::Notify::new());
            let started = Arc::new(tokio::sync::Notify::new());
            let publisher = AckObservedPublisher {
                inner: NatsEventPublisher {
                    connection,
                    stream_name: account.streams().event.clone(),
                },
                acked: acked.clone(),
                started: started.clone(),
            };
            let delayed_worker = if outbox_read_delay.is_zero() {
                None
            } else {
                let (started_tx, started_rx) = tokio::sync::oneshot::channel();
                let worker = tokio::task::spawn_blocking(move || {
                    started_tx.send(()).unwrap();
                    std::thread::sleep(outbox_read_delay);
                });
                tokio::time::timeout(REAL_NATS_STEP_DEADLINE, started_rx)
                    .await
                    .expect("delayed outbox worker start deadline")
                    .unwrap();
                Some(worker)
            };
            let db = store.clone();
            let task =
                tokio::spawn(
                    async move { drain_v1_pass(&db, &account, &publisher, 1, &|| true).await },
                );
            tokio::time::timeout(OUTBOX_DRAIN_DEADLINE, started.notified())
                .await
                .expect("outbox preparation must reach the publisher");
            tokio::time::timeout(REAL_NATS_STEP_DEADLINE, received.recv())
                .await
                .expect("real adapter must send notice")
                .expect("server observes HPUB");
            assert!(!task.is_finished(), "adapter must wait for JetStream ack");
            assert!(published_at(&store, &key).await.is_none());
            ack.notify_one();
            // Observe the transport receipt before waiting for SQLite's durable
            // stamp. Disk latency after an ack is not JetStream ack latency.
            tokio::time::timeout(REAL_NATS_STEP_DEADLINE, acked.notified())
                .await
                .expect("ack completion deadline");
            assert_eq!(
                tokio::time::timeout(OUTBOX_DRAIN_DEADLINE, task)
                    .await
                    .expect("acknowledged notice stamp deadline")
                    .unwrap()
                    .unwrap(),
                1
            );
            assert!(published_at(&store, &key).await.is_some());
            if let Some(worker) = delayed_worker {
                tokio::time::timeout(REAL_NATS_STEP_DEADLINE, worker)
                    .await
                    .expect("delayed outbox worker completion deadline")
                    .unwrap();
            }
            server.abort();
        })
        .await
        .expect("real NATS adapter exchange deadline");
    }

    #[tokio::test]
    async fn drain_publishes_to_naming_event_subject_with_headers_and_digest() {
        let (_scratch, store) = test_store("bus_drain_1");
        let sub_id = seed_connection_and_subscription(&store, "conn-1");
        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let payload = json!({"id": 42, "name": "test"});
        // A CI job event declares every filter label, so this drain checks all five.
        insert_test_event(
            &store,
            &sub_id,
            key,
            "github_ci_job_failed",
            "owner/repo",
            &payload,
        );

        let account = AccountNames::derive("box_test").unwrap();
        let publisher = MockPublisher::default();

        let count = drain_v1_pass(&store, &account, &publisher, 10, &|| true)
            .await
            .expect("drain");
        assert_eq!(count, 1);

        let messages = publisher.published.lock().unwrap().clone();
        assert_eq!(messages.len(), 1);
        let msg = &messages[0];
        assert_eq!(
            msg.subject,
            "ck.box_test.event.plexus.github_ci_job_failed.v1"
        );
        assert_eq!(msg.id, key);

        let canonical = store.canonical_event_by_key(key).unwrap().unwrap();
        assert_eq!(msg.digest.to_string(), canonical.digest);
        assert_eq!(msg.headers.get("kind").unwrap(), "github_ci_job_failed");
        assert_eq!(msg.headers.get("repo").unwrap(), "owner/repo");
        assert_eq!(msg.headers.get("project").unwrap(), "p1");
        assert_eq!(msg.headers.get("pr").unwrap(), "42");
        assert_eq!(msg.headers.get("branch").unwrap(), "main");
        assert_eq!(msg.headers.get("conclusion").unwrap(), "failure");

        // Verify published_at_ms was recorded
        assert!(canonical.published_at_ms.is_some());

        // Subsequent drain pass publishes nothing
        let count2 = drain_v1_pass(&store, &account, &publisher, 10, &|| true)
            .await
            .expect("drain 2");
        assert_eq!(count2, 0);
        assert_eq!(publisher.published.lock().unwrap().len(), 1);
    }

    #[test]
    fn regression_notice_headers_refuse_all_control_characters() {
        let mut headers = EventHeaders {
            repo: "owner/repo".into(),
            project: None,
            pr: None,
            branch: None,
            conclusion: None,
        };
        for control in ['\r', '\n', '\0', '\t', '\u{7f}', '\u{85}'] {
            headers.project = Some(format!("project{control}injected"));
            assert!(
                notice_headers("github_issue_changed", &headers).is_err(),
                "{control:?}"
            );
            headers.project = None;
            headers.repo = format!("repo{control}injected");
            assert!(
                notice_headers("github_issue_changed", &headers).is_err(),
                "{control:?}"
            );
            headers.repo = "owner/repo".into();
        }
        headers.project = Some("正常-project".into());
        assert!(notice_headers("github_issue_changed", &headers).is_ok());
    }

    #[tokio::test]
    async fn regression_invalid_header_does_not_block_later_notices() {
        let (scratch, store) = test_store("bus_invalid_header");
        let sub = seed_connection_and_subscription(&store, "conn-1");
        let bad = format!("{:064x}", 1);
        let good = format!("{:064x}", 2);
        for key in [&bad, &good] {
            insert_test_event(
                &store,
                &sub,
                key,
                "github_issue_changed",
                "owner/repo",
                &json!({}),
            );
        }
        rusqlite::Connection::open(scratch.path())
            .unwrap()
            .execute(
                "UPDATE event_outbox SET project = ?1 WHERE event_key = ?2",
                ["bad\nproject", bad.as_str()],
            )
            .unwrap();
        let account = AccountNames::derive("box_test").unwrap();
        let publisher = MockPublisher::default();
        drain_pass(&store, &account, &publisher, 10, &|| true)
            .await
            .unwrap();
        {
            let messages = publisher.published.lock().unwrap();
            assert!(messages.iter().all(|m| !m.id.starts_with(&bad)));
            assert!(messages.iter().any(|m| m.id == good));
        }
        drop(store);
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "test".into(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: scratch.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        assert_eq!(store.unpublishable_outbox_count().unwrap(), 1);
        let pending = store.drain_event_outbox_version_after(50, 1, None).unwrap();
        assert!(pending.iter().all(|(event, _)| event.event_key != bad));
        let state = ModuleState {
            health: Arc::new(crate::health::HealthState::new()),
            runtime: crate::runtime_for_test(store),
        };
        refresh_unpublishable_count(&state).await.unwrap();
        let subc_protocol::session::ModuleControlResponse::HealthCheck { status, .. } =
            state.health.report()
        else {
            panic!("health")
        };
        assert_eq!(status, subc_protocol::session::HealthStatus::Degraded);
    }

    struct SelectiveRefusal {
        all: bool,
        inner: MockPublisher,
    }
    #[async_trait]
    impl EventPublisher for SelectiveRefusal {
        async fn publish(
            &self,
            subject: &str,
            id: &str,
            digest: ContentDigest,
            headers: Headers,
        ) -> Result<PublishReceipt, String> {
            if self.all || id.starts_with(&format!("{:064x}", 1)) {
                return Err("nats_publish_refused".into());
            }
            self.inner.publish(subject, id, digest, headers).await
        }
    }

    #[tokio::test]
    async fn isolated_refusals_need_three_successful_peer_passes_but_systemic_refusals_never_quarantine(
    ) {
        for all in [false, true] {
            let (_scratch, store) = test_store(if all {
                "bus_systemic_refusal"
            } else {
                "bus_isolated_refusal"
            });
            let sub = seed_connection_and_subscription(&store, "conn-1");
            insert_test_event(
                &store,
                &sub,
                &format!("{:064x}", 1),
                "github_issue_changed",
                "owner/repo",
                &json!({}),
            );
            let publisher = SelectiveRefusal {
                all,
                inner: MockPublisher::default(),
            };
            let skips = UnpublishableRows::default();
            for pass in 1..=3 {
                insert_test_event(
                    &store,
                    &sub,
                    &format!("{:064x}", pass + 1),
                    "github_issue_changed",
                    "owner/repo",
                    &json!({}),
                );
                assert_eq!(
                    drain_pass_skipping(
                        &store,
                        &AccountNames::derive("box_test").unwrap(),
                        &publisher,
                        50,
                        &|| true,
                        &skips
                    )
                    .await
                    .unwrap_err(),
                    "nats_publish_refused"
                );
                assert_eq!(
                    store.unpublishable_outbox_count().unwrap(),
                    u64::from(!all && pass == 3)
                );
            }
            if !all {
                assert_eq!(publisher.inner.published.lock().unwrap().len(), 6);
            }
        }
        assert_eq!(reconnect_backoff(30), Duration::from_secs(300));
    }

    /// An outbox row that can never become a notice (here its event has no
    /// published declaration, as when a declaration is removed while old rows
    /// remain) is skipped and remembered, the pass still succeeds, and later
    /// passes read past it to the rows behind it. It must not panic the drain
    /// or fail the pass, which held back the whole queue.
    #[tokio::test]
    async fn an_unpublishable_outbox_row_is_skipped_and_does_not_block_the_queue() {
        let (scratch, store) = test_store("bus_drain_unpublishable");
        let sub_id = seed_connection_and_subscription(&store, "conn-1");
        let bad = "1111111111111111111111111111111111111111111111111111111111111111";
        let good = "2222222222222222222222222222222222222222222222222222222222222222";
        insert_test_event(
            &store,
            &sub_id,
            bad,
            "github_issue_changed",
            "owner/repo",
            &json!({"id": 1}),
        );
        insert_test_event(
            &store,
            &sub_id,
            good,
            "github_issue_changed",
            "owner/repo",
            &json!({"id": 2}),
        );
        rusqlite::Connection::open(scratch.path())
            .unwrap()
            .execute(
                "UPDATE event_outbox SET event_name = 'github_retired_event' WHERE event_key = ?1",
                [bad],
            )
            .unwrap();

        let account = AccountNames::derive("box_test").unwrap();
        let publisher = MockPublisher::default();
        let skips = super::UnpublishableRows::default();
        // A batch of one holds only the bad row: it is skipped, not an error.
        let first = super::drain_pass_skipping(&store, &account, &publisher, 1, &|| true, &skips)
            .await
            .expect("an unpublishable row must not fail the pass");
        assert_eq!(first, 0);
        assert!(skips.len() >= 1, "the bad row is remembered");
        // The next pass reads past it to the good row.
        let second = super::drain_pass_skipping(&store, &account, &publisher, 1, &|| true, &skips)
            .await
            .expect("second pass");
        assert!(second >= 1, "the row behind the bad one must publish");
        let published: Vec<String> = publisher
            .published
            .lock()
            .unwrap()
            .iter()
            .map(|message| message.id.clone())
            .collect();
        assert!(
            published.iter().any(|id| id.starts_with(good)),
            "{published:?}"
        );
        assert!(
            !published.iter().any(|id| id.starts_with(bad)),
            "{published:?}"
        );
    }

    #[test]
    fn issue_notice_carries_only_its_declared_labels() {
        // A flow filtering issue events on `branch` or `conclusion` would never
        // match, so the issue declaration omits them and the notice must too,
        // even when a producer fills them.
        let headers = notice_headers(
            "github_issue_changed",
            &EventHeaders {
                repo: "Owner/Repo".to_string(),
                project: Some("p1".to_string()),
                pr: Some("42".to_string()),
                branch: Some("main".to_string()),
                conclusion: Some("failure".to_string()),
            },
        )
        .expect("declared event");
        assert_eq!(
            headers.keys().map(String::as_str).collect::<Vec<_>>(),
            ["kind", "project", "repo"]
        );
        assert_eq!(headers["repo"], "owner/repo");
    }

    #[tokio::test]
    async fn deleted_poison_is_forgotten_after_the_next_complete_sweep() {
        let (scratch, store) = test_store("deleted-poison-sweep");
        let sub = seed_connection_and_subscription(&store, "conn-1");
        let bad = "1".repeat(64);
        let good = "2".repeat(64);
        for key in [&bad, &good] {
            insert_test_event(
                &store,
                &sub,
                key,
                "github_issue_changed",
                "owner/repo",
                &json!({"id":key}),
            );
        }
        let db = rusqlite::Connection::open(scratch.path()).unwrap();
        assert_eq!(
            db.execute(
                "UPDATE event_outbox SET event_name='github_retired_event' WHERE event_key=?1",
                [&bad]
            )
            .unwrap(),
            1
        );
        let account = AccountNames::derive("box_test").unwrap();
        let publisher = MockPublisher::default();
        let skips = UnpublishableRows::default();
        drain_pass_skipping(&store, &account, &publisher, 1, &|| true, &skips)
            .await
            .unwrap();
        assert!(skips.len() > 0, "poison must be remembered before deletion");
        assert_eq!(
            db.execute("DELETE FROM event_outbox WHERE event_key=?1", [&bad])
                .unwrap(),
            1
        );
        // Finish the current sweep, then scan from the beginning so a key
        // observed before its deletion is absent from the next sweep's set.
        for _ in 0..4 {
            drain_pass_skipping(&store, &account, &publisher, 1, &|| true, &skips)
                .await
                .unwrap();
        }
        assert_eq!(
            skips.len(),
            0,
            "deleted poison must disappear after a complete sweep"
        );
        assert!(publisher
            .published
            .lock()
            .unwrap()
            .iter()
            .any(|message| message.id.starts_with(&good)));
    }

    #[tokio::test]
    async fn v2_notice_digest_hashes_stored_envelope_and_matches_v1_labels() {
        use sha2::Digest;
        let (_scratch, store) = test_store("v2-digest");
        let sub = seed_connection_and_subscription(&store, "conn-1");
        let key = "a".repeat(64);
        insert_test_event(
            &store,
            &sub,
            &key,
            "github_issue_changed",
            "OWNER/Repo",
            &json!({"number":7}),
        );
        let account = AccountNames::derive("box_test").unwrap();
        let publisher = MockPublisher::default();
        assert_eq!(
            super::drain_pass(&store, &account, &publisher, 10, &|| true)
                .await
                .unwrap(),
            2
        );
        let event = store.canonical_event_by_key(&key).unwrap().unwrap();
        let messages = publisher.published.lock().unwrap();
        assert_eq!(messages.len(), 2);
        assert!(messages[0].subject.ends_with(".v1"));
        assert!(messages[1].subject.ends_with(".v2"));
        assert_eq!(messages[0].id, key);
        assert_eq!(messages[1].id, format!("{key}.v2"));
        assert_eq!(messages[1].headers.get("event_key"), Some(&messages[0].id));
        let mut v2_headers = messages[1].headers.clone();
        v2_headers.remove("event_key");
        assert_eq!(messages[0].headers, v2_headers);
        assert_eq!(messages[0].digest.to_string(), event.digest);
        let expected = format!(
            "{:x}",
            sha2::Sha256::digest(event.envelope_v2.as_ref().unwrap().as_bytes())
        );
        assert_ne!(event.digest, expected);
        assert_eq!(
            messages[1].digest.to_string(),
            expected,
            "v2 notice must hash stored envelope bytes"
        );
        assert_eq!(event.digest_v2.as_ref().unwrap(), &expected);
        assert!(event.published_at_ms.is_some() && event.published_v2_at_ms.is_some());
    }

    #[tokio::test]
    async fn real_nats_stream_stores_both_versions_with_distinct_transport_ids() {
        let (_scratch, store) = test_store("real-v2-stream");
        let sub = seed_connection_and_subscription(&store, "conn-1");
        let key = "c".repeat(64);
        insert_test_event(
            &store,
            &sub,
            &key,
            "github_issue_changed",
            "owner/repo",
            &json!({"number":7}),
        );
        // Schema migration and fixture writes are not a JetStream exchange.
        // Start the transport watchdog only once the database is ready.
        tokio::time::timeout(Duration::from_secs(10), async {
            let data = Scratch::directory("real-v2-nats-data");
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            struct Server(std::process::Child);
            impl Drop for Server {
                fn drop(&mut self) {
                    if let Err(error) = crate::bounded::kill_and_wait_within(
                        &mut self.0, Duration::from_secs(2), "real JetStream server cleanup deadline",
                    ) {
                        if std::thread::panicking() {
                            eprintln!(warn bus: "{error}");
                        } else {
                            panic!("{error}");
                        }
                    }
                }
            }
            // Unlike the protocol loopback above, this is a real JetStream
            // server: it must enforce stream-wide duplicate suppression.
            let _server = Server(
                std::process::Command::new("nats-server")
                    .args([
                        "--jetstream",
                        "--addr",
                        "127.0.0.1",
                        "--port",
                        &port.to_string(),
                        "--store_dir",
                    ])
                    .arg(&*data)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("nats-server must be installed for the JetStream regression test"),
            );
            let url = format!("nats://127.0.0.1:{port}");
            let client = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let Ok(client) = async_nats::connect(&url).await {
                        break client;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.expect("real JetStream server startup deadline: nats-server did not accept connections within 3 seconds");
            let (connection, account) = connect_with_signer(Arc::new(TestSigner), &credential(url))
                .await
                .unwrap();
            let context = async_nats::jetstream::new(client);
            let mut stream = context
                .create_stream(async_nats::jetstream::stream::Config {
                    name: account.streams().event.clone(),
                    subjects: vec![account.event_binding()],
                    duplicate_window: Duration::from_secs(120),
                    ..Default::default()
                })
                .await
                .unwrap();
            let publisher = NatsEventPublisher {
                connection,
                stream_name: account.streams().event.clone(),
            };
            assert_eq!(
                super::drain_pass(&store, &account, &publisher, 10, &|| true)
                    .await
                    .unwrap(),
                2,
                "both versions must be acknowledged"
            );
            assert_eq!(
                stream.info().await.unwrap().state.messages,
                2,
                "JetStream must store both versions, not silently deduplicate v2"
            );
            let v1 = stream.get_raw_message(1).await.unwrap();
            let v2 = stream.get_raw_message(2).await.unwrap();
            assert!(v1.subject.as_str().ends_with(".v1"));
            assert!(v2.subject.as_str().ends_with(".v2"));
            assert_eq!(v1.headers.get("Nats-Msg-Id").unwrap().as_str(), key);
            assert_eq!(
                v2.headers.get("Nats-Msg-Id").unwrap().as_str(),
                format!("{key}.v2")
            );
            assert!(v1.headers.get("event_key").is_none());
            assert_eq!(
                v2.headers.get("event_key").unwrap().as_str(),
                v1.headers.get("Nats-Msg-Id").unwrap().as_str()
            );
            let event = store.canonical_event_by_key(&key).unwrap().unwrap();
            assert!(event.published_at_ms.is_some() && event.published_v2_at_ms.is_some());
            // Retry the notices that the drain actually stored; receipts must retain
            // the original sequences and no extra entries may reach JetStream.
            for (version, digest, id, sequence) in [
                (1, event.digest.as_str(), key.clone(), 1),
                (2, event.digest_v2.as_deref().unwrap(), format!("{key}.v2"), 2),
            ] {
                let subject = account.event_subject("plexus", &event.event_name, version).unwrap();
                let mut headers = notice_headers(&event.event_name, &event.headers).expect("declared event");
                if version == 2 {
                    headers.insert(plexus_core::event_key::V2_EVENT_KEY_HEADER.into(), key.clone());
                }
                let retry = publisher.publish(&subject, &id, digest.parse().unwrap(), headers).await.unwrap();
                assert!(retry.duplicate(), "NATS adapter must preserve the duplicate receipt");
                assert_eq!(retry.stream_sequence(), sequence);
            }
            assert_eq!(super::drain_pass(&store, &account, &publisher, 10, &|| true).await.unwrap(), 0);
            assert_eq!(stream.info().await.unwrap().state.messages, 2);
        })
        .await
        .expect("real JetStream v2 exchange deadline");
    }

    struct FailVersion {
        inner: MockPublisher,
        version: u8,
    }
    #[async_trait]
    impl EventPublisher for FailVersion {
        async fn publish(
            &self,
            subject: &str,
            id: &str,
            digest: ContentDigest,
            headers: Headers,
        ) -> Result<PublishReceipt, String> {
            if subject.ends_with(&format!(".v{}", self.version)) {
                return Err("version unavailable".into());
            }
            self.inner.publish(subject, id, digest, headers).await
        }
    }

    #[tokio::test]
    async fn v1_and_v2_publish_independently_and_retry_only_failed_version() {
        for version in [1, 2] {
            let (_scratch, store) = test_store(&format!("independent-{version}"));
            let sub = seed_connection_and_subscription(&store, "conn-1");
            let key = "b".repeat(64);
            insert_test_event(
                &store,
                &sub,
                &key,
                "github_issue_changed",
                "owner/repo",
                &json!({"number":7}),
            );
            let account = AccountNames::derive("box_test").unwrap();
            let publisher = FailVersion {
                inner: MockPublisher::default(),
                version,
            };
            assert!(
                super::drain_pass(&store, &account, &publisher, 10, &|| true)
                    .await
                    .is_err()
            );
            let event = store.canonical_event_by_key(&key).unwrap().unwrap();
            assert_eq!(event.published_at_ms.is_none(), version == 1);
            assert_eq!(event.published_v2_at_ms.is_none(), version == 2);
            assert_eq!(
                publisher.inner.published.lock().unwrap().len(),
                1,
                "healthy version must still publish"
            );
            assert_eq!(
                store.drain_event_outbox_version(10, version).unwrap().len(),
                1
            );
            assert_eq!(
                store
                    .drain_event_outbox_version(10, 3 - version)
                    .unwrap()
                    .len(),
                0
            );
            assert_eq!(
                super::drain_pass(&store, &account, &publisher.inner, 10, &|| true)
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(publisher.inner.published.lock().unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn publish_failure_backs_off_and_does_not_stamp_published_at() {
        let (_scratch, store) = test_store("bus_drain_2");
        let sub_id = seed_connection_and_subscription(&store, "conn-1");
        let key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let payload = json!({"test": true});
        insert_test_event(
            &store,
            &sub_id,
            key,
            "github_issue_changed",
            "owner/repo",
            &payload,
        );

        let account = AccountNames::derive("box_test").unwrap();
        let publisher = MockPublisher::default();
        *publisher.fail_with.lock().unwrap() = Some("nats publish failed".to_string());

        let res = drain_v1_pass(&store, &account, &publisher, 10, &|| true).await;
        assert!(res.is_err());

        // published_at_ms must still be None
        let canonical = store.canonical_event_by_key(key).unwrap().unwrap();
        assert!(canonical.published_at_ms.is_none());

        // Clear error and retry: now it publishes and stamps
        *publisher.fail_with.lock().unwrap() = None;
        let count = drain_v1_pass(&store, &account, &publisher, 10, &|| true)
            .await
            .expect("drain retry");
        assert_eq!(count, 1);
        let canonical_after = store.canonical_event_by_key(key).unwrap().unwrap();
        assert!(canonical_after.published_at_ms.is_some());
    }

    #[tokio::test]
    async fn restart_between_commit_and_publish_publishes_exactly_once() {
        let (_scratch, store) = test_store("bus_drain_3");
        let sub_id = seed_connection_and_subscription(&store, "conn-1");
        let key = "1111111111111111111111111111111111111111111111111111111111111111";
        insert_test_event(
            &store,
            &sub_id,
            key,
            "github_pr_changed",
            "owner/repo",
            &json!({}),
        );

        let account = AccountNames::derive("box_test").unwrap();
        // First drain after restart
        let publisher1 = MockPublisher::default();
        let count1 = drain_v1_pass(&store, &account, &publisher1, 10, &|| true)
            .await
            .unwrap();
        assert_eq!(count1, 1);
        assert_eq!(publisher1.published.lock().unwrap().len(), 1);

        // Second drain after restart
        let publisher2 = MockPublisher::default();
        let count2 = drain_v1_pass(&store, &account, &publisher2, 10, &|| true)
            .await
            .unwrap();
        assert_eq!(count2, 0);
        assert_eq!(publisher2.published.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn kill_after_ack_before_published_at_republishes_same_event_key() {
        let (_scratch, store) = test_store("bus_drain_kill_after_ack");
        let sub_id = seed_connection_and_subscription(&store, "conn-1");
        let key = "2222222222222222222222222222222222222222222222222222222222222222";
        let payload = json!({"kill": "simulation"});
        insert_test_event(
            &store,
            &sub_id,
            key,
            "github_issue_changed",
            "owner/repo",
            &payload,
        );

        let account = AccountNames::derive("box_test").unwrap();
        let publisher = MockPublisher::default();

        // 1. Publish through the mock and receive its simulated ack. Skip the store's
        // published_at_ms write to model a process dying after ack but before marking.
        let events = store.drain_event_outbox(10).unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        let subject = account
            .event_subject("plexus", &event.event_name, 1)
            .unwrap();
        let digest = event.digest.parse::<ContentDigest>().unwrap();
        let mut headers = BTreeMap::new();
        headers.insert("kind".to_string(), event.event_name.clone());
        headers.insert("repo".to_string(), event.headers.repo.to_ascii_lowercase());
        let _ack = publisher
            .publish(&subject, &event.event_key, digest, headers)
            .await
            .unwrap();
        // Leave mark_event_published uncalled to keep the event pending.
        let canonical = store.canonical_event_by_key(key).unwrap().unwrap();
        assert!(canonical.published_at_ms.is_none());

        // 2. On restart / next drain pass: re-publishes with the SAME event_key
        let count = drain_v1_pass(&store, &account, &publisher, 10, &|| true)
            .await
            .unwrap();
        assert_eq!(count, 1);

        // The non-deduplicating mock records publish attempts, not stream entries.
        // Both attempts must carry the same immutable id, digest, and subject.
        let published_msgs = publisher.published.lock().unwrap().clone();
        assert_eq!(published_msgs.len(), 2);
        assert_eq!(published_msgs[0].id, key);
        assert_eq!(published_msgs[1].id, key);
        assert_eq!(published_msgs[0].digest, published_msgs[1].digest);
        assert_eq!(published_msgs[0].subject, published_msgs[1].subject);

        // And now published_at_ms is recorded
        let canonical_after = store.canonical_event_by_key(key).unwrap().unwrap();
        assert!(canonical_after.published_at_ms.is_some());

        // 3. Subsequent pass publishes nothing
        let count3 = drain_v1_pass(&store, &account, &publisher, 10, &|| true)
            .await
            .unwrap();
        assert_eq!(count3, 0);
    }

    #[derive(Clone)]
    struct MemoryPublisher(cortexkit_bus_inmemory::InMemoryBus);

    #[async_trait]
    impl EventPublisher for MemoryPublisher {
        async fn publish(
            &self,
            subject: &str,
            id: &str,
            digest: ContentDigest,
            headers: Headers,
        ) -> Result<PublishReceipt, String> {
            Stream::publish(&self.0, subject, id, digest, headers)
                .await
                .map_err(|error| error.to_string())
        }
    }

    #[tokio::test]
    async fn duplicate_retry_after_publish_before_stamp_finishes_both_versions() {
        use cortexkit_bus_inmemory::{InMemoryBus, InMemoryConfig};
        use cortexkit_bus_trait::{DurableOwner, StreamCursor};

        const CHILD: &str = "PLEXUS_DUPLICATE_RETRY_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // Prepare the durable fixture before timing the diagnostic child.
            // The child reopens it to exercise the real restart/retry path.
            // Its 30-second execution deadline then covers retry and diagnostics,
            // rather than cold schema creation.
            let (scratch, store) = test_store("duplicate-crash-retry");
            let sub = seed_connection_and_subscription(&store, "conn-1");
            insert_test_event(
                &store,
                &sub,
                &"d".repeat(64),
                "github_issue_changed",
                "owner/repo",
                &json!({"number":7}),
            );
            drop(store);
            let output = crate::bounded::child_output(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "bus::tests::duplicate_retry_after_publish_before_stamp_finishes_both_versions",
                        "--nocapture",
                    ])
                    .env(CHILD, scratch.path()),
                Duration::from_secs(30),
                "duplicate retry diagnostic child",
            )
            .unwrap();
            assert!(
                output.status.success(),
                "duplicate retry child failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stderr = String::from_utf8(output.stderr).unwrap();
            let lines: Vec<_> = stderr
                .lines()
                .filter(|line| line.contains("outbox notice retry acknowledged:"))
                .collect();
            assert_eq!(
                lines.len(),
                2,
                "duplicate retry diagnostic missing: {stderr}"
            );
            let key = "d".repeat(64);
            for (line, version, id, sequence) in [
                (lines[0], 1, key.clone(), 1),
                (lines[1], 2, format!("{key}.v2"), 2),
            ] {
                let parsed = cortexkit_log::parse_line(line)
                    .expect("fleet-formatted duplicate retry diagnostic");
                assert_eq!(parsed.level, cortexkit_log::ParsedLevel::Debug);
                assert_eq!(parsed.logger, "plexus.bus");
                assert!(line.ends_with(&format!(
                    "outbox notice retry acknowledged: subject=ck.box_test.event.plexus.github_issue_changed.v{version} id={id} event_key={key} stream_sequence={sequence}"
                )), "duplicate retry diagnostic identity: {line}");
            }
            return;
        }
        // The log directory is beneath a regular file, forcing the real fleet
        // renderer's stderr fallback without touching operator log directories.
        let mut config =
            cortexkit_log::Config::in_dir("plexus", std::env::current_exe().unwrap().join("logs"));
        config.spec = Some("debug".into());
        let handle = cortexkit_log::init(config).unwrap();
        assert!(handle.fallback_active());

        let store = open_test_store(Path::new(&std::env::var_os(CHILD).unwrap()));
        let key = "d".repeat(64);
        let account = AccountNames::derive("box_test").unwrap();
        let instant = std::time::Instant::now();
        let publisher = MemoryPublisher(InMemoryBus::new_with_deduplication_clock(
            InMemoryConfig::default().with_durable(DurableOwner::Module("plexus")),
            move || instant,
        ));
        let event = store.canonical_event_by_key(&key).unwrap().unwrap();
        for (version, id, digest, sequence) in [
            (1, key.clone(), event.digest.as_str(), 1),
            (
                2,
                format!("{key}.v2"),
                event.digest_v2.as_deref().unwrap(),
                2,
            ),
        ] {
            let subject = account
                .event_subject("plexus", &event.event_name, version)
                .unwrap();
            let mut headers =
                notice_headers(&event.event_name, &event.headers).expect("declared event");
            if version == 2 {
                headers.insert(
                    plexus_core::event_key::V2_EVENT_KEY_HEADER.into(),
                    key.clone(),
                );
            }
            let first = publisher
                .publish(&subject, &id, digest.parse().unwrap(), headers)
                .await
                .unwrap();
            assert!(!first.duplicate());
            assert_eq!(first.stream_sequence(), sequence);
        }
        // Keep the stream but not the publication stamps, as a restarted publisher
        // would find them after dying between each publish and its database write.
        assert!(event.published_at_ms.is_none() && event.published_v2_at_ms.is_none());
        let restarted = publisher.clone();
        assert_eq!(
            super::drain_pass(&store, &account, &restarted, 10, &|| true)
                .await
                .unwrap(),
            2
        );
        let stamped = store.canonical_event_by_key(&key).unwrap().unwrap();
        assert!(stamped.published_at_ms.is_some() && stamped.published_v2_at_ms.is_some());
        assert_eq!(
            super::drain_pass(&store, &account, &restarted, 10, &|| true)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store.canonical_event_by_key(&key).unwrap().unwrap(),
            stamped
        );

        // Read stored deliveries, not a count of publish calls: duplicates must
        // leave exactly one stream entry per version with the original sequence.
        let mut cursor = publisher
            .0
            .consumer(DurableOwner::Module("plexus"))
            .await
            .unwrap();
        for (version, id, digest, sequence) in [
            (1, key.clone(), event.digest.as_str(), 1),
            (
                2,
                format!("{key}.v2"),
                event.digest_v2.as_deref().unwrap(),
                2,
            ),
        ] {
            let delivery = cursor.next().await.unwrap().unwrap();
            assert_eq!(delivery.stream_seq, sequence);
            assert_eq!(delivery.message.id, id);
            assert_eq!(
                delivery.message.subject,
                account
                    .event_subject("plexus", &event.event_name, version)
                    .unwrap()
            );
            assert_eq!(delivery.message.digest.to_string(), digest);
            cursor.ack().await.unwrap();
        }
        assert!(
            cursor.next().await.unwrap().is_none(),
            "retry must not add stream entries"
        );
    }

    #[tokio::test]
    async fn health_shows_outbox_depth_last_publish_error_and_effective_ci_cadence() {
        let (scratch, store) = test_store("bus_health_metrics");
        let sub_id = seed_connection_and_subscription(&store, "conn-1");
        let key = "3333333333333333333333333333333333333333333333333333333333333333";
        insert_test_event(
            &store,
            &sub_id,
            key,
            "github_issue_changed",
            "owner/repo",
            &json!({"test": 1}),
        );

        // Seed an active CI watch to verify effective CI cadence
        let conn = rusqlite::Connection::open(scratch.path()).unwrap();
        conn.execute_batch(
            "INSERT INTO connections (connection_id, principal, app_key, status, created_at_ms, updated_at_ms)
             VALUES ('conn-actions', 'direct', 'github_actions', 'active', 1, 1);
             INSERT INTO trigger_subscriptions (subscription_id, principal, connection_id, action, cadence_s, cursor_kind, cursor_state, schema_hash, status, created_at_ms)
             VALUES ('ci-watch-1', 'direct', 'conn-actions', 'list_workflow_runs', 360, 'ci_runs', '{}', 'hash', 'active', 1),
                     ('ci-watch-2', 'direct', 'conn-actions', 'list_workflow_runs', 420, 'ci_runs', '{}', 'hash', 'active', 2);
            ",
        ).unwrap();

        let state = Arc::new(ModuleState {
            health: Arc::new(crate::health::HealthState::new()),
            runtime: crate::runtime_for_test(store.clone()),
        });

        state
            .health
            .record_publish_error("nats broker connection refused");
        crate::refresh_store_health(&state, &["direct".into()]);
        let report = current_health(&state);
        let subc_protocol::session::ModuleControlResponse::HealthCheck { metrics, .. } = report
        else {
            panic!("expected HealthCheck");
        };
        let metrics = metrics.expect("metrics present");

        // 1. Outbox depth is 1
        assert_eq!(metrics["outboxDepth"], 1);
        assert!(metrics.get("outbox_depth").is_none());

        // 2. Last publish error is shown
        assert_eq!(
            metrics["lastPublishError"],
            "nats broker connection refused"
        );

        // 3. The reported CI polling interval is 360 seconds, from the active
        // CI subscription's stored cadence_s above.
        assert_eq!(metrics["effectiveCiCadenceS"], 360);

        state.health.clear_publish_error();
    }

    #[test]
    fn credential_debug_never_exposes_secret_material() {
        let cred = Credential {
            jwt: "super-secret-jwt-token-xyz123".to_string().into(),
            exp: 1800000000,
            acct: "box_prod".to_string(),
            account_public: "ACCTPUBKEY".to_string(),
            inbox_prefix: "_INBOX.PUBKEY".to_string(),
            server_url: "nats://127.0.0.1:4222".to_string(),
            credential_public: "SENSITIVE_KEY_456".to_string(),
            user_jwt_id: "ujwt-1".to_string(),
            spawn_generation: 1,
            credential_epoch: 0,
        };
        let debug_str = format!("{cred:?}");
        assert!(
            !debug_str.contains("super-secret-jwt-token-xyz123"),
            "JWT must never appear in Debug: {debug_str}"
        );
        assert!(
            !debug_str.contains("SENSITIVE_KEY_456"),
            "credential_public must never appear in Debug: {debug_str}"
        );
    }
}
