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

/// Whether a callsite was compiled into one of plexus's own crates rather than
/// into a dependency. A plexus diagnostic is emitted by `diag!` (or the crate
/// `eprintln!` shadow) at its call site, so its module path starts with a
/// plexus crate name (`plexus_core::scheduler`, `plexus_module::relay`). A
/// dependency's events carry the dependency's own module path
/// (`hyper_util::client::legacy::pool`), and a dependency cannot change that by
/// choosing a target name. An event with no module path is treated as a
/// dependency's.
fn is_plexus_callsite(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.module_path().is_some_and(|path| {
        let crate_name = path.split("::").next().unwrap_or(path);
        crate_name.starts_with("plexus_")
    })
}

/// Whether the module log may carry anything from this callsite, before CK_LOG
/// is consulted.
///
/// Transport trace output includes authentication headers and NATS ConnectInfo,
/// so tungstenite is never admitted and async_nats never below INFO. These two
/// rules hold on their own, separately from the dependency cap below. This
/// check sits outside the fleet log filter, so CK_LOG cannot enable
/// secret output.
///
/// Every other dependency is admitted only at WARN and above, whatever CK_LOG
/// says. The fleet logger names a line after its tracing target and maps any
/// target containing `::` (a dependency's default target is its Rust module
/// path) to the bare `plexus` root logger. So CK_LOG can't give dependencies a
/// level of their own: whatever level it sets for plexus's root also applies to
/// every hyper/reqwest connection-pool line, and its logger-name grammar has no
/// way to name a dependency. Plexus's own callsites are left to CK_LOG.
fn admitted_before_ck_log(metadata: &tracing::Metadata<'_>) -> bool {
    !metadata.target().starts_with("tungstenite")
        && !metadata.target().starts_with("tokio_tungstenite")
        && (!metadata.target().starts_with("async_nats")
            || *metadata.level() <= tracing::Level::INFO)
        && (is_plexus_callsite(metadata) || *metadata.level() <= tracing::Level::WARN)
}

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
    // cortexkit-log applies CK_LOG only in its layer's `enabled`. A plain
    // `filter_fn` caches every callsite it admits as `Interest::always`, the
    // filtered wrapper drops the inner layer's own answer, and tracing skips
    // `enabled` for an `always` callsite. With that filter every admitted event
    // was written at every level and CK_LOG was never asked. Answering
    // `sometimes` for an admitted callsite makes tracing call `enabled` on each
    // event, so CK_LOG decides; a refused callsite is cached as `never`.
    let filter = tracing_subscriber::filter::dynamic_filter_fn(
        |metadata: &tracing::Metadata<'_>,
         _: &tracing_subscriber::layer::Context<'_, tracing_subscriber::Registry>| {
            admitted_before_ck_log(metadata)
        },
    )
    .with_callsite_filter(|metadata| {
        if admitted_before_ck_log(metadata) {
            tracing::subscriber::Interest::sometimes()
        } else {
            tracing::subscriber::Interest::never()
        }
    });
    Ok((layer.with_filter(filter), handle))
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

fn fresh_required(error: &str) -> bool {
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
#[path = "bus_tests.rs"]
pub mod tests;
