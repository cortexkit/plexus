//! MCP streamable-HTTP transport and the small client surface used by catalog
//! discovery. Credentials are not retained in pooled connection state; the HTTP
//! stack owns header copies for the lifetime of a request.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{BufReader, Read};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT};
use serde_json::{json, Value};

use crate::credentials::ResolvedCredential;
use crate::http_support::{
    build_headers, classify_reqwest_error, credentialed_redirect_policy, duration_ms,
    read_body_bounded, redact_value, redacted_endpoint, redirect_location_for_log,
    reqwest_error_cause, response_throttle, throttle_deadline, throttle_gate, throttle_refusal,
    with_request_deadline, BodyReadFailure, HttpAttemptFailure, ThrottleGate,
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_IDLE_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
    MAX_RESPONSE_BODY_BYTES, POOLED_CONNECTION_IDLE_LIMIT,
};
use crate::manifest::CredentialBinding;
#[cfg(test)]
use crate::mcp_payload::tools_from_response;
use crate::mcp_payload::{
    decode_tool_result, json_rpc_request, tool_result_from_response, tools_call_params,
    tools_list_params,
};
use crate::transport::{
    Retryability, TransmissionState, Transport, TransportRequest, TransportResponse,
};

const MCP_PROTOCOL_VERSION: &str = "2025-03-26";
const MCP_PROTOCOL_VERSION_JUNE: &str = "2025-06-18";
pub(crate) const MAX_TOOL_PAGES: usize = 100;
pub(crate) const MAX_DISCOVERED_TOOLS: usize = 10_000;

pub(crate) fn next_tool_cursor(
    response: &Value,
    seen: &mut HashSet<String>,
) -> Result<Option<String>, McpRemoteError> {
    match response["result"].get("nextCursor") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(cursor)) if !cursor.is_empty() && seen.insert(cursor.clone()) => {
            Ok(Some(cursor.clone()))
        }
        _ => Err(McpRemoteError::Protocol),
    }
}
const POISONED_LOCK_MESSAGE: &str =
    "MCP transport lock is poisoned; retry after pool recovery or restart if it persists";
const GREP_APP_APP_KEY: &str = crate::code_search::BACKEND;
const GREP_APP_SEARCH_ACTION: &str = crate::code_search::ACTION;
const GREP_APP_NO_RESULTS: &str = "No results found for your query.";
const GREP_APP_RATE_LIMIT_PREFIX: &str = "Unexpected token 'T', \"Too Many R";
const GREP_APP_RATE_LIMIT_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpRemoteError {
    Configuration,
    Connection,
    PoisonedLock,
    Timeout,
    OutcomeUnknown,
    Protocol,
    UnsupportedProtocol,
    AuthRejected,
    Throttled(Duration),
    /// An earlier response's throttle has longer to run than a request may
    /// wait for it, so this request was not sent.
    ThrottleInEffect(Duration),
    /// The vendor's answer was larger than the transport reads into memory.
    ResponseTooLarge,
    VendorStatus(u16),
    Vendor,
}

impl fmt::Display for McpRemoteError {
    /// Authentication errors carry an observed HTTP status; throttle errors
    /// carry the vendor's retry delay. Render known observations so operators
    /// can distinguish the cause without repeating a vendor request.
    ///
    /// Authentication classification uses only HTTP 401. Zero delays remain
    /// displayable for compatibility but are not emitted by HTTP classification,
    /// which uses a positive fallback when Retry-After is missing.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration => formatter.write_str("MCP transport configuration is invalid"),
            Self::Connection => formatter.write_str("MCP connection failed"),
            Self::PoisonedLock => formatter.write_str(POISONED_LOCK_MESSAGE),
            Self::Timeout => formatter.write_str("MCP request timed out"),
            Self::OutcomeUnknown => formatter.write_str("MCP vendor response was not definitive"),
            Self::Protocol => formatter.write_str("MCP response was invalid"),
            Self::UnsupportedProtocol => {
                formatter.write_str("MCP negotiated an unsupported protocol version")
            }
            Self::AuthRejected => formatter.write_str("MCP authentication was rejected (HTTP 401)"),
            Self::Throttled(retry_after) if retry_after.is_zero() => {
                formatter.write_str("MCP vendor throttled the request (no retry-after given)")
            }
            Self::Throttled(retry_after) => write!(
                formatter,
                "MCP vendor throttled the request (retry after {}s)",
                retry_after.as_secs()
            ),
            Self::ThrottleInEffect(remaining) => write!(
                formatter,
                "MCP vendor throttle still in effect; not sent (retry after {}ms)",
                duration_ms(*remaining)
            ),
            Self::ResponseTooLarge => {
                formatter.write_str("MCP vendor response exceeded the size limit")
            }
            Self::VendorStatus(status) => {
                write!(formatter, "MCP vendor request failed (HTTP {status})")
            }
            Self::Vendor => formatter.write_str("MCP vendor request failed"),
        }
    }
}

impl std::error::Error for McpRemoteError {}

fn poisoned_lock_error() -> McpRemoteError {
    eprintln!(error transport: "{POISONED_LOCK_MESSAGE}");
    McpRemoteError::PoisonedLock
}

/// Per-connection MCP settings. The endpoint is intentionally represented as a
/// string because it comes from the reviewed manifest and is not a secret.
#[derive(Clone, PartialEq, Eq)]
pub struct McpRemoteConfig {
    pub endpoint: String,
    /// Reviewed manifest key for this connection. It identifies the connector even
    /// when the connection uses an operator-supplied endpoint override.
    pub app_key: Option<String>,
    pub credential_bindings: Vec<CredentialBinding>,
    pub error_signals: std::collections::HashMap<String, Vec<crate::manifest::ErrorSignalRule>>,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// How long this connection's pooled entry (HTTP client plus MCP session)
    /// may sit unused before `sweep_idle` evicts it. Not the socket keep-alive
    /// limit; that is `pooled_connection_idle_limit`.
    pub idle_timeout: Duration,
    /// How long an idle keep-alive TCP connection stays in the HTTP client's
    /// pool before it is dropped rather than reused. Defaults to
    /// `http_support::POOLED_CONNECTION_IDLE_LIMIT`; see there for why it must
    /// stay below vendor keep-alive timeouts. Not the entry eviction timeout;
    /// that is `idle_timeout`.
    pub pooled_connection_idle_limit: Duration,
}

impl McpRemoteConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            app_key: None,
            credential_bindings: Vec::new(),
            error_signals: std::collections::HashMap::new(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            pooled_connection_idle_limit: POOLED_CONNECTION_IDLE_LIMIT,
        }
    }

    pub fn with_bindings(mut self, bindings: Vec<CredentialBinding>) -> Self {
        self.credential_bindings = bindings;
        self
    }

    pub fn with_app_key(mut self, app_key: impl Into<String>) -> Self {
        self.app_key = Some(app_key.into());
        self
    }

    pub fn from_manifest(manifest: &crate::manifest::AppManifest) -> Self {
        let mut config = Self::new(manifest.transport.url.clone())
            .with_bindings(manifest.credential_bindings.clone())
            .with_app_key(manifest.key.clone());
        config.error_signals = crate::error_signals::from_manifest(manifest);
        config
    }
}

impl Default for McpRemoteConfig {
    fn default() -> Self {
        Self::new(String::new())
    }
}

impl fmt::Debug for McpRemoteConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpRemoteConfig")
            .field("endpoint", &redacted_endpoint(&self.endpoint))
            .field("app_key", &self.app_key)
            .field("credential_binding_count", &self.credential_bindings.len())
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field(
                "pooled_connection_idle_limit",
                &self.pooled_connection_idle_limit,
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct McpConnection {
    pub connection_id: String,
    pub config: McpRemoteConfig,
}

impl McpConnection {
    pub fn new(connection_id: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            connection_id: connection_id.into(),
            config: McpRemoteConfig::new(endpoint),
        }
    }

    pub fn from_manifest(
        connection_id: impl Into<String>,
        manifest: &crate::manifest::AppManifest,
    ) -> Self {
        Self {
            connection_id: connection_id.into(),
            config: McpRemoteConfig::from_manifest(manifest),
        }
    }
}

impl fmt::Debug for McpConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpConnection")
            .field("connection_id", &self.connection_id)
            .field("config", &self.config)
            .finish()
    }
}

#[derive(Clone)]
struct ConnectionEntry {
    client: Client,
    initialized: bool,
    /// Session id assigned by `initialize`, replayed on every later request.
    ///
    /// Lives on the pooled entry rather than on the transport because it
    /// belongs to one server session: a reconnect must discard it along with
    /// `initialized`, or the retry replays a session the server has forgotten.
    session_id: Option<String>,
    protocol_version: &'static str,
    last_used: Instant,
    throttle_until: Option<Instant>,
    idle_timeout: Duration,
    /// The config this entry's client and session were built for. A
    /// connection whose registered config changes gets a fresh client and a
    /// fresh session: the client carries the timeouts, pool limit and redirect
    /// policy, and a session belongs to the endpoint that issued it.
    config: McpRemoteConfig,
    /// Makes the next tools/call panic just after it is sent, so a test can
    /// reach the panic recovery without a real defect.
    #[cfg(test)]
    panic_after_send: bool,
}

impl ConnectionEntry {
    fn build(config: &McpRemoteConfig) -> Result<Self, McpRemoteError> {
        Ok(Self {
            client: build_client(config)?,
            initialized: false,
            session_id: None,
            protocol_version: MCP_PROTOCOL_VERSION,
            last_used: Instant::now(),
            throttle_until: None,
            idle_timeout: config.idle_timeout,
            config: config.clone(),
            #[cfg(test)]
            panic_after_send: false,
        })
    }

    /// Rebuild the client and drop the session and throttle when the config
    /// differs from the one this entry was built for. The pool's lease count
    /// lives outside this state, so rebuilding a client cannot discard callers.
    fn ensure_current(&mut self, config: &McpRemoteConfig) -> Result<(), McpRemoteError> {
        if self.config != *config {
            self.rebuild(config)?;
        }
        Ok(())
    }

    fn rebuild(&mut self, config: &McpRemoteConfig) -> Result<(), McpRemoteError> {
        *self = Self::build(config)?;
        Ok(())
    }
}

/// An MCP client that never follows a redirect away from the endpoint's own
/// origin and never lets one turn its POST into a GET (see
/// `credentialed_redirect_policy`).
fn build_client(config: &McpRemoteConfig) -> Result<Client, McpRemoteError> {
    Client::builder()
        .user_agent(crate::http_support::USER_AGENT)
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .pool_idle_timeout(config.pooled_connection_idle_limit)
        .redirect(credentialed_redirect_policy(false))
        .build()
        .map_err(|_| McpRemoteError::Configuration)
}

struct PooledEntry {
    state: Mutex<ConnectionEntry>,
    leases: AtomicUsize,
}

impl std::ops::Deref for PooledEntry {
    type Target = Mutex<ConnectionEntry>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

struct Lease {
    entry: Arc<PooledEntry>,
}

#[cfg(test)]
struct LookupPause {
    connection_id: String,
    reached: std::sync::mpsc::SyncSender<usize>,
    resume: std::sync::mpsc::Receiver<()>,
}

impl Lease {
    fn acquire(entry: Arc<PooledEntry>) -> Self {
        // Reserve membership while the caller still holds the pool map. This
        // must not wait for a busy request's state mutex under the shared map.
        entry.leases.fetch_add(1, Ordering::Relaxed);
        Self { entry }
    }
}

impl std::ops::Deref for Lease {
    type Target = PooledEntry;

    fn deref(&self) -> &Self::Target {
        &self.entry
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.entry.try_lock() {
            state.last_used = Instant::now();
        }
        self.entry.leases.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A cloneable, per-connection MCP client pool implementing the substrate's
/// synchronous transport seam. Connections are initialized lazily and are
/// removed only when idle and free of in-flight leases.
#[derive(Clone)]
pub struct McpRemoteTransport {
    default_config: McpRemoteConfig,
    configs: Arc<Mutex<HashMap<String, McpRemoteConfig>>>,
    entries: Arc<Mutex<HashMap<String, Arc<PooledEntry>>>>,
    next_request_id: Arc<AtomicU64>,
    /// How many times a panic was recovered from: a dispatch that panicked
    /// while holding its connection, or a poisoned entry the sweep evicted.
    panic_recoveries: Arc<AtomicU64>,
    #[cfg(test)]
    lookup_pause: Arc<Mutex<Option<LookupPause>>>,
}

impl McpRemoteTransport {
    /// Explicit default endpoints are a fixture seam. Production callers must
    /// register each connection instead of routing unknown ids to a fallback.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(default_config: McpRemoteConfig) -> Self {
        Self::build(default_config)
    }

    fn build(default_config: McpRemoteConfig) -> Self {
        Self {
            default_config,
            configs: Arc::new(Mutex::new(HashMap::new())),
            entries: Arc::new(Mutex::new(HashMap::new())),
            next_request_id: Arc::new(AtomicU64::new(1)),
            panic_recoveries: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            lookup_pause: Arc::new(Mutex::new(None)),
        }
    }

    /// How many panics this transport has recovered from since it was built:
    /// dispatches that panicked mid-request (reported to their caller as
    /// outcome unknown) plus poisoned entries the sweep evicted. Each one is
    /// also logged at ERROR; this count keeps a healed connection visible.
    pub fn panic_recoveries(&self) -> u64 {
        self.panic_recoveries.load(Ordering::Relaxed)
    }

    /// Make the next tools/call on a pooled entry panic right after its
    /// request reaches the vendor.
    #[cfg(test)]
    pub(crate) fn panic_after_next_send_for_test(&self, connection_id: &str) -> bool {
        let Some(entry) = self
            .entries
            .lock()
            .ok()
            .and_then(|entries| entries.get(connection_id).cloned())
        else {
            return false;
        };
        let Ok(mut state) = entry.lock() else {
            return false;
        };
        state.panic_after_send = true;
        true
    }

    pub fn register_connection(&self, connection: McpConnection) {
        if let Ok(mut configs) = self.configs.lock() {
            configs.insert(connection.connection_id, connection.config);
        }
    }

    pub fn unregister_connection(&self, connection_id: &str) {
        if let Ok(mut configs) = self.configs.lock() {
            configs.remove(connection_id);
        }
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(connection_id);
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn register_config(&self, connection_id: impl Into<String>, config: McpRemoteConfig) {
        if let Ok(mut configs) = self.configs.lock() {
            configs.insert(connection_id.into(), config);
        }
    }

    /// Whether a connection's endpoint is registered on this transport.
    ///
    /// Mirrors `RestTransport::has_connection`, which the module's router already
    /// uses to decide transport ownership. Distinct from `connection_count`,
    /// which counts POOLED entries: a connection can be registered (its endpoint
    /// known) with no entry yet, and that is exactly the state a boot-time
    /// registration sweep produces and needs to be able to assert.
    pub fn has_connection(&self, connection_id: &str) -> bool {
        self.configs
            .lock()
            .map(|configs| configs.contains_key(connection_id))
            .unwrap_or(false)
    }

    pub fn connection_count(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0)
    }

    /// Take a lease on a pooled entry by id, so a test can hold one the way an
    /// in-flight vendor call does.
    #[cfg(test)]
    fn lease_for_test(&self, connection_id: &str) -> Option<Lease> {
        let entries = self.entries.lock().ok()?;
        Some(Lease::acquire(Arc::clone(entries.get(connection_id)?)))
    }

    /// Force an entry's idle clock backwards, so a test can reach the eviction
    /// branch without sleeping through a 300-second timeout.
    ///
    /// Ages the REAL field the sweep reads rather than shortening the timeout,
    /// because a test that sets a one-millisecond timeout proves the sweep can
    /// evict under a configuration production never uses.
    #[cfg(test)]
    pub(crate) fn age_entry_for_test(&self, connection_id: &str, by: Duration) -> bool {
        let Ok(entries) = self.entries.lock() else {
            return false;
        };
        let Some(entry) = entries.get(connection_id) else {
            return false;
        };
        let Ok(mut state) = entry.lock() else {
            return false;
        };
        state.last_used -= by;
        true
    }

    /// Sweep idle connections without waiting for a busy entry under the shared
    /// pool-map lock. Busy or leased entries are retained even if their idle
    /// deadline elapsed while a vendor call was in flight.
    ///
    /// A poisoned entry is evicted, so the next call builds a fresh client and
    /// session: otherwise every later call on that connection would refuse
    /// until a restart. The eviction is logged at ERROR and counted, because
    /// it means a panic happened while a request held the connection.
    pub fn sweep_idle(&self) -> usize {
        let Ok(mut entries) = self.entries.lock() else {
            return 0;
        };
        let now = Instant::now();
        let mut removed = 0;
        entries.retain(|connection_id, entry| {
            if entry.is_poisoned() {
                eprintln!(error transport:
                    "MCP connection {connection_id} evicted: a panic poisoned its pooled entry"
                );
                self.panic_recoveries.fetch_add(1, Ordering::Relaxed);
                removed += 1;
                return false;
            }
            let keep = entry
                .try_lock()
                .map(|state| {
                    entry.leases.load(Ordering::Relaxed) != 0
                        || state.throttle_until.is_some_and(|until| until > now)
                        || now.saturating_duration_since(state.last_used) < state.idle_timeout
                })
                .unwrap_or(true);
            if !keep {
                removed += 1;
            }
            keep
        });
        removed
    }

    /// Discover the vendor's current MCP tool catalog.
    pub fn discover(
        &self,
        connection: &McpConnection,
        credential: &ResolvedCredential,
    ) -> Result<Vec<DiscoveredAction>, McpRemoteError> {
        self.register_connection(connection.clone());
        let config = connection.config.clone();
        let entry = self.entry_for(&connection.connection_id, &config)?;
        #[cfg(test)]
        self.pause_after_lookup_for_test(
            &connection.connection_id,
            Arc::as_ptr(&entry.entry) as usize,
        );
        let mut state = entry.lock().map_err(|_| poisoned_lock_error())?;
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            state.ensure_current(&config)?;
            let mut actions = Vec::new();
            let mut params = tools_list_params();
            let mut cursors = HashSet::new();
            let mut names = HashSet::new();
            let mut bytes = 0usize;
            for _ in 0..MAX_TOOL_PAGES {
                let body = json_rpc_request(
                    self.next_request_id.fetch_add(1, Ordering::Relaxed),
                    "tools/list",
                    params,
                );
                let (response, _) = self
                    .rpc_with_reconnect(&mut state, &config, body, credential)
                    .map_err(McpCallError::into_remote)?;
                bytes = bytes.saturating_add(
                    serde_json::to_vec(&response)
                        .map_err(|_| McpRemoteError::Protocol)?
                        .len(),
                );
                if bytes > MAX_RESPONSE_BODY_BYTES {
                    return Err(McpRemoteError::ResponseTooLarge);
                }
                let tools = response
                    .pointer("/result/tools")
                    .and_then(Value::as_array)
                    .ok_or(McpRemoteError::Protocol)?;
                for tool in tools {
                    let action = DiscoveredAction::from_value(tool)?;
                    if !names.insert(action.name.clone()) {
                        return Err(McpRemoteError::Protocol);
                    }
                    if actions.len() >= MAX_DISCOVERED_TOOLS {
                        return Err(McpRemoteError::ResponseTooLarge);
                    }
                    actions.push(action);
                }
                match next_tool_cursor(&response, &mut cursors)? {
                    None => return Ok(actions),
                    Some(cursor) => params = json!({"cursor": cursor}),
                }
            }
            Err(McpRemoteError::Protocol)
        }));
        match outcome {
            Ok(result) => result,
            Err(_) => {
                eprintln!(error transport: "MCP discovery panicked; the session was discarded");
                self.panic_recoveries.fetch_add(1, Ordering::Relaxed);
                if state.rebuild(&config).is_err() {
                    reset_session(&mut state);
                }
                Err(McpRemoteError::OutcomeUnknown)
            }
        }
    }

    /// Mark a live connection as needing a new MCP initialize handshake. The
    /// next operation reconnects and retries only the operation that triggered
    /// the stale-session response.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reconnect(&self, connection_id: &str) {
        // The reset must wait for this connection's RPC, but that wait must
        // not hold the map needed by unrelated connections to find their clients.
        let entry = {
            let Ok(entries) = self.entries.lock() else {
                return;
            };
            entries.get(connection_id).cloned()
        };
        if let Some(entry) = entry {
            if let Ok(mut state) = entry.lock() {
                reset_session(&mut state);
            }
        }
    }

    fn config_for(&self, connection_id: &str) -> McpRemoteConfig {
        self.configs
            .lock()
            .ok()
            .and_then(|configs| configs.get(connection_id).cloned())
            .unwrap_or_else(|| self.default_config.clone())
    }

    fn entry_for(
        &self,
        connection_id: &str,
        supplied: &McpRemoteConfig,
    ) -> Result<Lease, McpRemoteError> {
        if supplied.endpoint.trim().is_empty() {
            return Err(McpRemoteError::Configuration);
        }
        if let Ok(entries) = self.entries.lock() {
            if let Some(entry) = entries.get(connection_id) {
                return Ok(Lease::acquire(Arc::clone(entry)));
            }
        }
        let entry = Arc::new(PooledEntry {
            state: Mutex::new(ConnectionEntry::build(supplied)?),
            leases: AtomicUsize::new(0),
        });
        let mut entries = self.entries.lock().map_err(|_| poisoned_lock_error())?;
        Ok(Lease::acquire(Arc::clone(
            entries
                .entry(connection_id.to_string())
                .or_insert_with(|| Arc::clone(&entry)),
        )))
    }

    #[cfg(test)]
    fn pause_after_lookup_for_test(&self, connection_id: &str, entry_address: usize) {
        let pause = {
            let mut pending = self.lookup_pause.lock().unwrap();
            if pending
                .as_ref()
                .is_some_and(|pause| pause.connection_id == connection_id)
            {
                pending.take()
            } else {
                None
            }
        };
        if let Some(pause) = pause {
            pause.reached.send(entry_address).unwrap();
            pause
                .resume
                .recv_timeout(Duration::from_secs(5))
                .expect("resume paused MCP lookup");
        }
    }

    fn ensure_initialized(
        &self,
        state: &mut ConnectionEntry,
        config: &McpRemoteConfig,
        credential: &ResolvedCredential,
    ) -> Result<Option<HttpReply>, AttemptError> {
        if state.initialized {
            return Ok(None);
        }
        reset_session(state);
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": self.next_request_id.fetch_add(1, Ordering::Relaxed),
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "ck-plexus", "version": env!("CARGO_PKG_VERSION")}
            }
        });
        let reply = self.post_json(state, config, &initialize, credential)?;
        if !is_successful_rpc(&reply) {
            return Ok(Some(reply));
        }
        state.protocol_version = match reply.body["result"].get("protocolVersion") {
            None => MCP_PROTOCOL_VERSION,
            Some(Value::String(version)) if version == MCP_PROTOCOL_VERSION => MCP_PROTOCOL_VERSION,
            Some(Value::String(version)) if version == MCP_PROTOCOL_VERSION_JUNE => {
                MCP_PROTOCOL_VERSION_JUNE
            }
            Some(_) => return Err(AttemptError::Local(McpRemoteError::UnsupportedProtocol)),
        };
        // Adopt the session before sending anything else. Servers that use
        // sessions reject every subsequent request without this header, and
        // they do it with 400 rather than 401 -- a PROTOCOL error that reads
        // like a credential problem and sends the reader to the vault.
        // Measured against mcp.context7.com, huggingface.co/mcp and
        // mcp.browserbase.com, all three of which answer
        // "Missing mcp-session-id" / "Session ID required".
        if reply.session_id.is_some() {
            state.session_id.clone_from(&reply.session_id);
        }
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        });
        // The session is usable only once the server has accepted this
        // notification. A refusal (an expired session, a throttle, a 401) is
        // handed back like a failed initialize, so the caller classifies it
        // instead of marking a session ready that the server never confirmed.
        match self.post_notification(state, config, &notification, credential) {
            Ok(None) => {}
            Ok(Some(refusal)) => {
                reset_session(state);
                return Ok(Some(refusal));
            }
            Err(error) => {
                reset_session(state);
                return Err(error);
            }
        }
        state.initialized = true;
        Ok(None)
    }

    fn rpc_with_reconnect(
        &self,
        state: &mut ConnectionEntry,
        config: &McpRemoteConfig,
        body: Value,
        credential: &ResolvedCredential,
    ) -> Result<(Value, Option<crate::manifest::ErrorSignal>), McpCallError> {
        let mut retry = true;
        loop {
            let initialized_reply = match self.ensure_initialized(state, config, credential) {
                Ok(Some(reply)) => Some(reply),
                Ok(None) => None,
                Err(error) => return Err(McpCallError::BeforeCall(Box::new(attempt_error(error)))),
            };
            let before_call = initialized_reply.is_some();
            let reply = match initialized_reply {
                Some(reply) => reply,
                None => match self.post_json(state, config, &body, credential) {
                    Ok(reply) => reply,
                    Err(error) => return Err(attempt_error(error)),
                },
            };
            #[cfg(test)]
            if std::mem::take(&mut state.panic_after_send) {
                panic!("injected panic after the request was sent");
            }
            if needs_new_session(&reply) && retry {
                retry = false;
                reset_session(state);
                continue;
            }
            let signal = reply.error_signal;
            return classify_reply(reply, state)
                .map(|value| (value, signal))
                .map_err(|error| {
                    let error = McpCallError::Remote(error);
                    let error = match signal {
                        Some(signal) => McpCallError::Signaled(signal, Box::new(error)),
                        None => error,
                    };
                    if before_call {
                        McpCallError::BeforeCall(Box::new(error))
                    } else {
                        error
                    }
                });
        }
    }

    fn post_json(
        &self,
        state: &mut ConnectionEntry,
        config: &McpRemoteConfig,
        body: &Value,
        credential: &ResolvedCredential,
    ) -> Result<HttpReply, AttemptError> {
        // A short throttle from an earlier response is waited out; a long one
        // refuses this request rather than parking the thread, and the
        // connection lock with it, for up to an hour.
        match throttle_gate(&mut state.throttle_until, Instant::now()) {
            ThrottleGate::Clear => {}
            ThrottleGate::Wait(remaining) => thread::sleep(remaining),
            ThrottleGate::Refuse(remaining) => {
                return Err(AttemptError::Local(McpRemoteError::ThrottleInEffect(
                    remaining,
                )))
            }
        }
        let mut headers = request_headers(config, credential, state.session_id.as_deref())?;
        headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static(state.protocol_version),
        );
        let deadline = Instant::now()
            .checked_add(config.request_timeout)
            .unwrap_or_else(Instant::now);
        let responder = SseResponder {
            client: &state.client,
            endpoint: &config.endpoint,
            headers: headers.clone(),
            deadline,
        };
        let builder = state
            .client
            .post(&config.endpoint)
            .headers(headers)
            .json(body);
        let response = with_request_deadline(builder, deadline)
            .send()
            .map_err(AttemptError::Request)?;
        let signals = if body.get("method").and_then(Value::as_str) == Some("tools/call") {
            body.pointer("/params/name")
                .and_then(Value::as_str)
                .and_then(|action| config.error_signals.get(action))
                .map(Vec::as_slice)
                .unwrap_or(&[])
        } else {
            &[]
        };
        let mut reply = decode_response(response, body.get("id"), Some(responder), signals)?;
        reply.sent_session = state.session_id.is_some();
        Ok(reply)
    }

    /// Send a notification. Returns the server's reply only when it refused
    /// (any status outside 2xx); an accepted notification has nothing to say.
    fn post_notification(
        &self,
        state: &mut ConnectionEntry,
        config: &McpRemoteConfig,
        body: &Value,
        credential: &ResolvedCredential,
    ) -> Result<Option<HttpReply>, AttemptError> {
        // The notification is part of the same session as the initialize that
        // preceded it, so it carries the header too. Both post paths need it:
        // a rule applied at one of two call sites is the shape that leaves the
        // surviving case to be found in production.
        let mut headers = request_headers(config, credential, state.session_id.as_deref())?;
        headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static(state.protocol_version),
        );
        let deadline = Instant::now()
            .checked_add(config.request_timeout)
            .unwrap_or_else(Instant::now);
        let notification_builder = state
            .client
            .post(&config.endpoint)
            .headers(headers)
            .json(body);
        let response = with_request_deadline(notification_builder, deadline)
            .send()
            .map_err(AttemptError::Request)?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            return Ok(None);
        }
        let mut reply = decode_response(response, None, None, &[])?;
        reply.sent_session = state.session_id.is_some();
        Ok(Some(reply))
    }
}

/// The headers every MCP POST carries: the credential, the accepted response
/// types and the session once the server assigned one. The caller adds the
/// negotiated protocol version from its connection state.
fn request_headers(
    config: &McpRemoteConfig,
    credential: &ResolvedCredential,
    session_id: Option<&str>,
) -> Result<HeaderMap, AttemptError> {
    let mut headers = build_headers(&config.credential_bindings, credential).map_err(|_| {
        eprintln!(warn transport: "MCP credential could not be rendered as a header");
        AttemptError::Local(McpRemoteError::Configuration)
    })?;
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/json, text/event-stream"),
    );
    insert_session_header(&mut headers, session_id);
    Ok(headers)
}

impl Default for McpRemoteTransport {
    fn default() -> Self {
        Self::build(McpRemoteConfig::default())
    }
}

impl fmt::Debug for McpRemoteTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.entries.try_lock().ok().map(|entries| entries.len());
        formatter
            .debug_struct("McpRemoteTransport")
            .field("connection_count", &count)
            .field("default_config", &self.default_config)
            .finish()
    }
}

impl Transport for McpRemoteTransport {
    fn dispatch(
        &self,
        request: TransportRequest,
        credential: &ResolvedCredential,
    ) -> TransportResponse {
        let config = self.config_for(&request.connection_id);
        let entry = match self.entry_for(&request.connection_id, &config) {
            Ok(entry) => entry,
            Err(error) => return local_error_response(error),
        };
        #[cfg(test)]
        self.pause_after_lookup_for_test(
            &request.connection_id,
            Arc::as_ptr(&entry.entry) as usize,
        );
        let mut state = match entry.lock() {
            Ok(state) => state,
            Err(_) => return local_error_response(poisoned_lock_error()),
        };
        if let Err(error) = state.ensure_current(&config) {
            return local_error_response(error);
        }
        let body = json_rpc_request(
            self.next_request_id.fetch_add(1, Ordering::Relaxed),
            "tools/call",
            tools_call_params(request.action.clone(), request.args),
        );
        // A panic while the request holds this connection would otherwise
        // unwind through the guard, poisoning the entry so every later call
        // refuses until a restart, and the caller would get no reply at all.
        // Catching it while the guard is still held keeps the entry usable and
        // tells the caller the outcome is unknown: the request may have been
        // sent.
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            self.rpc_with_reconnect(&mut state, &config, body, credential)
        }));
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(_) => {
                eprintln!(error transport:
                    "MCP request on connection {} panicked mid-request; reported as outcome unknown and the session discarded",
                    request.connection_id
                );
                self.panic_recoveries.fetch_add(1, Ordering::Relaxed);
                if state.rebuild(&config).is_err() {
                    reset_session(&mut state);
                }
                return TransportResponse::unknown_with_error(
                    "transport_panicked",
                    "MCP transport failed mid-request; the outcome is unknown",
                );
            }
        };
        match outcome {
            Ok((response, signal)) => {
                let Ok(result) = tool_result_from_response(response) else {
                    eprintln!(warn transport: "MCP vendor response was invalid");
                    return TransportResponse::unknown_with_error(
                        "mcp_protocol_error",
                        "MCP response was invalid",
                    );
                };
                if result
                    .get("isError")
                    .is_some_and(|value| !value.is_boolean())
                {
                    return TransportResponse::unknown_with_error(
                        "mcp_protocol_error",
                        "MCP isError must be boolean",
                    );
                }
                if result
                    .get("isError")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    let error_text = tool_error_text(&result);
                    match grep_app_tool_error_response(
                        config.app_key.as_deref().filter(|_| signal.is_none()),
                        &request.action,
                        &error_text,
                    ) {
                        Some((GrepAppToolError::NoResults, response)) => return response,
                        Some((GrepAppToolError::RateLimited, response)) => {
                            state.throttle_until =
                                throttle_deadline(Instant::now(), GREP_APP_RATE_LIMIT_DELAY);
                            eprintln!(warn transport:
                                "vendor tool rate limit on {}: retry after {}ms",
                                request.action,
                                duration_ms(GREP_APP_RATE_LIMIT_DELAY)
                            );
                            return response;
                        }
                        None => {}
                    }
                    // MCP tool failures carry vendor-specific details in content blocks. Keep
                    // those details in the operator log, but return a fixed caller-facing
                    // error so callers can match `mcp_tool_error` without vendor prose.
                    eprintln!(warn transport:
                        "vendor tool error on {}: {}",
                        request.action,
                        crate::http_support::bounded_text_for_log(&error_text, 4096)
                    );
                    return TransportResponse::vendor_error(
                        "mcp_tool_error",
                        "MCP vendor request failed",
                    )
                    .with_error_signal(signal);
                }
                // Delivered verbatim. This body previously passed through
                // `redact_value`, which fingerprints any field whose NAME
                // contains "token", "payload", "secret" and similar. On a
                // vendor response those are names we do not control, so the
                // match destroyed ordinary tool results — a field called
                // `payload` lost its entire contents — while protecting
                // nothing in exchange, since the credential travels in a header
                // and a vendor returning credential material names that field
                // whatever it likes. See the fuller note in `rest_api.rs`,
                // including what this reasoning does NOT claim.
                TransportResponse::success(decode_tool_result(result))
            }
            Err(error) => call_error_response(error),
        }
    }
}

fn call_error_response(error: McpCallError) -> TransportResponse {
    match error {
        McpCallError::Signaled(signal, error) => {
            call_error_response(*error).with_error_signal(Some(signal))
        }
        McpCallError::BeforeCall(error) => {
            let mut response = call_error_response(*error);
            response.transmission = TransmissionState::NotSent;
            if response.error_code.as_deref() == Some("timeout") {
                response.retryability = Retryability::AutoRetryable;
            }
            response
        }
        McpCallError::Http(failure)
            if !matches!(
                failure,
                HttpAttemptFailure::Timeout | HttpAttemptFailure::Connect
            ) =>
        {
            // Total by construction (only Timeout and Connect have no
            // diagnostic, and the guard excludes both), but this runs with
            // the connection lock held, where a panic would poison it.
            failure
                .outcome_unknown_response()
                .unwrap_or_else(TransportResponse::unknown)
        }
        error => match error.into_remote() {
            McpRemoteError::Timeout => TransportResponse::timeout("MCP"),
            McpRemoteError::Connection => TransportResponse::transient_not_sent(
                "MCP connection failed before the request was sent",
            ),
            McpRemoteError::PoisonedLock => poisoned_lock_response(),
            McpRemoteError::Protocol => TransportResponse::unknown_with_error(
                "mcp_protocol_error",
                "MCP response was invalid",
            ),
            McpRemoteError::OutcomeUnknown => TransportResponse::unknown(),
            McpRemoteError::AuthRejected => TransportResponse {
                transmission: TransmissionState::Sent,
                retryability: Retryability::Terminal,
                response: None,
                error_code: Some("http_401".to_string()),
                error_message: Some("MCP authentication was rejected".to_string()),
                vendor_request_id: None,
                served_from: None,
                observed_at_ms: None,
                retry_after_ms: None,
                error_signal: None,
            },
            McpRemoteError::VendorStatus(status) if status >= 500 => {
                TransportResponse::unknown_with_error(
                    &format!("http_{status}"),
                    "MCP gateway response was not definitive",
                )
            }
            McpRemoteError::VendorStatus(status) => TransportResponse::vendor_error(
                &format!("http_{status}"),
                "MCP vendor request failed",
            ),
            McpRemoteError::Configuration => local_error_response(McpRemoteError::Configuration),
            McpRemoteError::UnsupportedProtocol => TransportResponse::vendor_error(
                "mcp_unsupported_protocol_version",
                "MCP negotiated an unsupported protocol version",
            ),
            McpRemoteError::Throttled(delay) => throttled_response(delay),
            McpRemoteError::ThrottleInEffect(remaining) => throttle_refusal("MCP", remaining),
            McpRemoteError::ResponseTooLarge => TransportResponse::unknown_with_error(
                "response_too_large",
                "MCP vendor response exceeded the size limit",
            ),
            _ => {
                eprintln!(warn transport: "MCP vendor request failed without a usable reply");
                TransportResponse::vendor_error("mcp_request_failed", "MCP vendor request failed")
            }
        },
    }
}

#[derive(Clone)]
pub struct DiscoveredAction {
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub input_schema: Value,
    /// Vendor annotations are retained for diagnostics, not trusted to determine
    /// action risk; only the reviewed manifest classifies actions.
    pub annotations: Option<serde_json::Map<String, Value>>,
}

impl fmt::Debug for DiscoveredAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveredAction")
            .field("name", &self.name)
            .field("title", &self.title)
            .field("description", &self.description)
            .field("input_schema", &redact_value(&self.input_schema))
            .finish()
    }
}

impl DiscoveredAction {
    pub(crate) fn from_value(value: &Value) -> Result<Self, McpRemoteError> {
        let object = value.as_object().ok_or(McpRemoteError::Protocol)?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or(McpRemoteError::Protocol)?
            .to_string();
        let input_schema = object
            .get("inputSchema")
            .or_else(|| object.get("input_schema"))
            .cloned()
            .ok_or(McpRemoteError::Protocol)?;
        Ok(Self {
            name,
            title: object
                .get("title")
                .and_then(Value::as_str)
                .map(str::to_string),
            description: object
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_string),
            input_schema,
            annotations: object
                .get("annotations")
                .and_then(Value::as_object)
                .cloned(),
        })
    }
}

#[derive(Clone)]
struct HttpReply {
    error_signal: Option<crate::manifest::ErrorSignal>,
    status: u16,
    retry_after: Option<Duration>,
    /// The JSON-RPC message, or `Null` for a refusal whose body was not JSON.
    body: Value,
    /// The `mcp-session-id` the server assigned, if it sent one.
    ///
    /// Kept off the body deliberately: it arrives as a RESPONSE HEADER on
    /// `initialize` and must be echoed on every later request, so discarding
    /// headers here silently breaks every vendor that uses sessions.
    session_id: Option<String>,
    /// The request that drew this reply carried an `mcp-session-id`. Only
    /// then does a 404 mean the server has forgotten the session.
    sent_session: bool,
}

enum AttemptError {
    Request(reqwest::Error),
    /// A failure already classified and logged, such as a body that ended
    /// early.
    Http(HttpAttemptFailure),
    Local(McpRemoteError),
}

enum McpCallError {
    Signaled(crate::manifest::ErrorSignal, Box<McpCallError>),
    BeforeCall(Box<McpCallError>),
    Remote(McpRemoteError),
    Http(HttpAttemptFailure),
}

impl McpCallError {
    fn into_remote(self) -> McpRemoteError {
        match self {
            Self::Signaled(_, error) => error.into_remote(),
            Self::BeforeCall(error) => error.into_remote(),
            Self::Remote(error) => error,
            Self::Http(HttpAttemptFailure::Timeout) => McpRemoteError::Timeout,
            Self::Http(HttpAttemptFailure::Connect) => McpRemoteError::Connection,
            Self::Http(_) => McpRemoteError::OutcomeUnknown,
        }
    }
}

/// Forget a server session so the next request re-initializes.
///
/// Exists so the two fields cannot drift apart. Clearing `initialized` without
/// clearing `session_id` would make a reconnect replay a session the server has
/// already discarded, which is worse than having no session at all: the retry
/// that exists to recover from a stale session would carry the stale session
/// with it. Keeping the reset in one place prevents the readiness flag and
/// session header from drifting apart.
fn reset_session(state: &mut ConnectionEntry) {
    state.protocol_version = MCP_PROTOCOL_VERSION;
    state.initialized = false;
    state.session_id = None;
}

/// Add `mcp-session-id` when the server assigned one.
///
/// A session id is server-generated and opaque, so it can in principle contain
/// bytes that are not valid in a header value. An invalid one is DROPPED rather
/// than sent as a mangled value or made fatal: the request then fails the same
/// way it would have before any session support existed, which is a worse
/// outcome than working but a much better one than a malformed header, and it
/// keeps a hostile server from choosing what bytes we put on the wire.
fn insert_session_header(headers: &mut HeaderMap, session_id: Option<&str>) {
    let Some(session_id) = session_id else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(session_id) {
        headers.insert(HeaderName::from_static("mcp-session-id"), value);
    }
}

fn decode_response(
    response: Response,
    expected_id: Option<&Value>,
    responder: Option<SseResponder<'_>>,
    signals: &[crate::manifest::ErrorSignalRule],
) -> Result<HttpReply, AttemptError> {
    let status = response.status().as_u16();
    let path = response.url().path().to_owned();
    let retry_after = response_throttle(status, response.headers());
    let session_id = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if let Some(delay) = retry_after.filter(|_| signals.is_empty()) {
        eprintln!(warn transport: "MCP vendor throttle: status={status} path={path} retry_after_ms={}", duration_ms(delay));
        return Ok(HttpReply {
            error_signal: None,
            status,
            retry_after,
            body: Value::Null,
            session_id,
            sent_session: false,
        });
    }
    let headers = response.headers().clone();
    if (300..400).contains(&status) {
        // A redirect the policy declined: another origin, a status that would
        // turn this POST into a GET, or too many hops. The agent sees only the
        // status; where it pointed is for the operator.
        let location = redirect_location_for_log(response.headers());
        eprintln!(warn transport: "MCP redirect not followed: status={status} path={path} location={location}");
    }
    if (200..300).contains(&status) && content_type.contains("text/event-stream") {
        let body = read_matching_sse_response(response, expected_id, responder).inspect_err(|_| {
            eprintln!(warn transport: "MCP SSE response failed or exceeded its limit: status={status} path={path}");
        })?;
        return Ok(HttpReply {
            error_signal: mcp_error_signal(signals, status, &headers, &body),
            status,
            retry_after,
            body,
            session_id,
            sent_session: false,
        });
    }
    let success = (200..300).contains(&status);
    let limit = if success {
        MAX_RESPONSE_BODY_BYTES
    } else {
        4096
    };
    let body = read_body_bounded(response, limit).map_err(
        |BodyReadFailure { failure, cause }| {
            eprintln!(warn transport: "MCP response body failed: status={status} path={path}: {failure:?}: {cause}");
            AttemptError::Http(failure)
        },
    )?;
    if body.truncated && success {
        eprintln!(warn transport: "MCP response exceeded {MAX_RESPONSE_BODY_BYTES} bytes: status={status} path={path}");
        return Err(AttemptError::Local(McpRemoteError::ResponseTooLarge));
    }
    let text = body.text;
    if !success {
        if let Some(delay) = retry_after {
            eprintln!(warn transport: "MCP vendor throttle: status={status} path={path} retry_after_ms={}", duration_ms(delay));
        } else {
            crate::rest_api::log_vendor_error(
                "MCP",
                &reqwest::Method::POST,
                &path,
                status,
                &text,
                None,
            );
        }
        return Ok(HttpReply {
            error_signal: crate::error_signals::evaluate(
                signals,
                status,
                &headers,
                (!body.truncated)
                    .then(|| serde_json::from_str::<Value>(&text).ok())
                    .flatten()
                    .as_ref(),
            ),
            status,
            retry_after,
            body: Value::Null,
            session_id,
            sent_session: false,
        });
    }
    let parsed = if content_type.contains("text/event-stream") {
        parse_sse_reply(&text, expected_id)
    } else {
        serde_json::from_str(&text).map_err(|_| McpRemoteError::Protocol)
    };
    let body = match parsed {
        Ok(body) if success && expected_id.is_some_and(|id| body.get("id") != Some(id)) => {
            return Err(AttemptError::Local(McpRemoteError::Protocol));
        }
        Ok(body) => body,
        // Only a successful status promises a JSON-RPC body. A refusal is
        // classified by its status, and vendors and proxies routinely send
        // 401, 404, 429 and 502 with an HTML page or nothing at all; failing
        // those as a protocol error skipped the reconnect, the throttle and
        // the auth-failure report the status calls for.
        Err(_) if !success => Value::Null,
        Err(error) => return Err(AttemptError::Local(error)),
    };
    Ok(HttpReply {
        error_signal: mcp_error_signal(signals, status, &headers, &body),
        status,
        retry_after,
        body,
        session_id,
        sent_session: false,
    })
}

fn mcp_error_signal(
    signals: &[crate::manifest::ErrorSignalRule],
    status: u16,
    headers: &HeaderMap,
    body: &Value,
) -> Option<crate::manifest::ErrorSignal> {
    if body.get("error").is_some()
        || body.pointer("/result/isError").and_then(Value::as_bool) == Some(true)
    {
        crate::error_signals::evaluate(signals, status, headers, Some(body))
    } else {
        None
    }
}

/// The JSON-RPC response to request `expected_id` in a server-sent-event body.
///
/// A streamable-HTTP server may send progress notifications or requests of its
/// own before the response on the same stream, and an event's data may span
/// several `data:` lines that join with newlines. So events are assembled
/// first, and the answer is the first message that is a response (it has
/// `result` or `error`) carrying the request's id, not merely the first
/// parseable JSON.
fn sse_messages(text: &str) -> Vec<Value> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut events = Vec::new();
    let mut data: Option<String> = None;
    for line in text.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            events.extend(data.take());
            continue;
        }
        if let Some(field) = line.strip_prefix("data") {
            let value = match field.strip_prefix(':') {
                Some(value) => value.strip_prefix(' ').unwrap_or(value),
                // A line naming another field that starts with "data".
                None if !field.is_empty() => continue,
                None => "",
            };
            match &mut data {
                Some(joined) => {
                    joined.push('\n');
                    joined.push_str(value);
                }
                None => data = Some(value.to_string()),
            }
        }
    }
    events
        .iter()
        .filter_map(|event| serde_json::from_str::<Value>(event).ok())
        .flat_map(|message| match message {
            // A batch carries several messages in one event.
            Value::Array(messages) => messages,
            message => vec![message],
        })
        .collect()
}

fn parse_sse_reply(text: &str, expected_id: Option<&Value>) -> Result<Value, McpRemoteError> {
    sse_messages(text)
        .into_iter()
        .find(|message| {
            (message.get("result").is_some() || message.get("error").is_some())
                && expected_id.is_none_or(|id| message.get("id") == Some(id))
        })
        .ok_or(McpRemoteError::Protocol)
}

struct SseResponder<'a> {
    client: &'a Client,
    endpoint: &'a str,
    headers: HeaderMap,
    deadline: Instant,
}

impl SseResponder<'_> {
    fn answer_request(&self, method: &Value, id: &Value) -> Result<(), AttemptError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(AttemptError::Http(HttpAttemptFailure::Timeout));
        }
        // Ping needs no negotiated capability. Sampling and elicitation are not
        // advertised, so explicitly refuse those instead of leaving a server waiting.
        let body = if method.as_str() == Some("ping") {
            json!({"jsonrpc":"2.0","id":id,"result":{}})
        } else {
            json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Client method not supported"}})
        };
        let response = self
            .client
            .post(self.endpoint)
            .headers(self.headers.clone())
            .timeout(remaining)
            .json(&body)
            .send()
            .map_err(AttemptError::Request)?;
        if !response.status().is_success() {
            return Err(AttemptError::Local(McpRemoteError::Protocol));
        }
        Ok(())
    }
}

fn read_matching_sse_response(
    response: Response,
    expected_id: Option<&Value>,
    responder: Option<SseResponder<'_>>,
) -> Result<Value, AttemptError> {
    let mut reader = BufReader::new(response.take((MAX_RESPONSE_BODY_BYTES + 1) as u64));
    let mut total = 0;
    let mut event = Vec::new();
    let mut line_start = 0usize;
    let mut after_cr = false;
    loop {
        let mut byte = [0u8; 1];
        let read = reader.read(&mut byte).map_err(|error| {
            let failure = crate::http_support::classify_body_io_error(&error);
            let cause = crate::http_support::body_io_error_cause(error);
            eprintln!(warn transport: "MCP SSE body read failed: {failure:?}: {cause}");
            AttemptError::Http(failure)
        })?;
        total += read;
        if total > MAX_RESPONSE_BODY_BYTES {
            return Err(AttemptError::Local(McpRemoteError::ResponseTooLarge));
        }
        if read != 0 && after_cr && byte[0] == b'\n' {
            after_cr = false;
            continue;
        }
        after_cr = read != 0 && byte[0] == b'\r';
        let line_end = read != 0 && matches!(byte[0], b'\r' | b'\n');
        let boundary = (line_end && event.len() == line_start) || read == 0;
        if read != 0 {
            event.push(if line_end { b'\n' } else { byte[0] });
        }
        if line_end {
            line_start = event.len();
        }
        if boundary {
            if let Ok(text) = std::str::from_utf8(&event) {
                for message in sse_messages(text) {
                    if message.get("method").is_some() {
                        if let Some(id) = message.get("id") {
                            if let Some(responder) = &responder {
                                responder.answer_request(&message["method"], id)?;
                            }
                        }
                    } else if (message.get("result").is_some() || message.get("error").is_some())
                        && expected_id.is_none_or(|id| message.get("id") == Some(id))
                    {
                        return Ok(message);
                    }
                }
            }
            event.clear();
            line_start = 0;
        }
        if read == 0 {
            return Err(AttemptError::Local(McpRemoteError::Protocol));
        }
    }
}

fn classify_reply(reply: HttpReply, state: &mut ConnectionEntry) -> Result<Value, McpRemoteError> {
    if let Some(delay) = reply.retry_after {
        state.throttle_until = throttle_deadline(Instant::now(), delay);
        return Err(McpRemoteError::Throttled(delay));
    }
    if !(200..300).contains(&reply.status) {
        if reply.status == 401 {
            return Err(McpRemoteError::AuthRejected);
        }
        if reply.status == 403 || (300..400).contains(&reply.status) {
            return Err(McpRemoteError::VendorStatus(reply.status));
        }
        return Err(McpRemoteError::VendorStatus(reply.status));
    }
    let object = reply.body.as_object().ok_or(McpRemoteError::Protocol)?;
    if let Some(error) = object.get("error") {
        if error.get("code").and_then(Value::as_i64) == Some(-32001) {
            // MCP Request Timeout can arrive after the tool has acted. Treat it
            // like a network timeout so writes can be reconciled, never resent.
            return Err(McpRemoteError::Timeout);
        }
        // The JSON-RPC error object carries the vendor's code and message, and
        // the enum variant that replaces it carries neither. Logged for the same
        // reason as the tool-error path above: without it the only surviving
        // evidence is a fixed sentence that fits every possible cause.
        eprintln!(warn transport:
            "vendor rpc error: code={} message={}",
            error
                .get("code")
                .map_or_else(|| "<none>".to_string(), |value| crate::http_support::bounded_json_for_log(value, 128)),
            crate::http_support::bounded_text_for_log(error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("<none>"), 4096)
        );
        return Err(McpRemoteError::Vendor);
    }
    Ok(reply.body)
}

/// The vendor's own explanation for a failed tool call.
///
/// MCP returns tool errors as an ordinary result carrying `isError: true`, with
/// the reason in the content blocks rather than in a protocol error -- so the
/// text that names the cause sits one level inside a structure that otherwise
/// looks like success.
///
/// Joins every text block rather than taking the first: a vendor is free to
/// split its message, and reporting only the opening fragment would be worse
/// than reporting nothing, since a truncated reason reads as a complete one.
fn tool_error_text(result: &Value) -> String {
    let blocks = result.get("content").and_then(Value::as_array);
    let Some(blocks) = blocks else {
        return "<no content blocks>".to_string();
    };
    let text: Vec<&str> = blocks
        .iter()
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect();
    if text.is_empty() {
        // Distinguish "the vendor said nothing" from "we failed to read it":
        // both are quiet, and only one is the vendor's fault.
        return "<content carried no text>".to_string();
    }
    text.join(" ")
}

#[derive(Debug, PartialEq, Eq)]
enum GrepAppToolError {
    NoResults,
    RateLimited,
}

/// Recognize only grep.app's two known `searchGitHub` error replies. Other MCP
/// actions and endpoints keep the ordinary sanitized vendor-error path.
fn grep_app_tool_error_response(
    app_key: Option<&str>,
    action: &str,
    text: &str,
) -> Option<(GrepAppToolError, TransportResponse)> {
    if app_key != Some(GREP_APP_APP_KEY) || action != GREP_APP_SEARCH_ACTION {
        return None;
    }
    if text.starts_with(GREP_APP_NO_RESULTS) {
        Some((
            GrepAppToolError::NoResults,
            TransportResponse::success(json!({
                "content": [{"type": "text", "text": GREP_APP_NO_RESULTS}]
            })),
        ))
    } else if text.starts_with(GREP_APP_RATE_LIMIT_PREFIX) {
        Some((
            GrepAppToolError::RateLimited,
            throttled_response(GREP_APP_RATE_LIMIT_DELAY),
        ))
    } else {
        None
    }
}

fn throttled_response(delay: Duration) -> TransportResponse {
    crate::http_support::throttled_response("MCP", delay)
}

fn is_successful_rpc(reply: &HttpReply) -> bool {
    (200..300).contains(&reply.status)
        && reply
            .body
            .as_object()
            .is_some_and(|object| !object.contains_key("error"))
}

fn is_auth_response(reply: &HttpReply) -> bool {
    // Only the HTTP refusal proves that authentication prevented execution.
    // RPC error codes and prose do not establish that a tool did not act.
    reply.status == 401
}

/// The server has forgotten the session this request carried.
///
/// The MCP streamable-HTTP spec answers a request bearing an unknown or
/// expired `Mcp-Session-Id` with 404 and requires the client to start a new
/// session with a fresh initialize. A connection polled every minute is never
/// idle long enough to be swept, so without this the stale session was replayed
/// on every call until a restart.
fn is_expired_session(reply: &HttpReply) -> bool {
    reply.status == 404 && reply.sent_session
}

/// The reply calls for discarding the session and trying once more on a new
/// one: an authentication rejection or an expired session. The request was
/// refused before the server acted on it in both cases.
fn needs_new_session(reply: &HttpReply) -> bool {
    is_auth_response(reply) || is_expired_session(reply)
}

fn attempt_error(error: AttemptError) -> McpCallError {
    match error {
        AttemptError::Local(error) => McpCallError::Remote(error),
        AttemptError::Http(failure) => McpCallError::Http(failure),
        AttemptError::Request(error) => {
            let failure = classify_reqwest_error(&error);
            let cause = reqwest_error_cause(error);
            eprintln!(warn transport: "MCP HTTP transport failed: {failure:?}: {cause}");
            McpCallError::Http(failure)
        }
    }
}

pub(crate) fn poisoned_lock_response() -> TransportResponse {
    TransportResponse {
        transmission: TransmissionState::NotSent,
        retryability: Retryability::Terminal,
        response: None,
        error_code: Some("transport_restart_required".to_string()),
        error_message: Some(POISONED_LOCK_MESSAGE.to_string()),
        vendor_request_id: None,
        served_from: None,
        observed_at_ms: None,
        retry_after_ms: None,
        error_signal: None,
    }
}

fn local_error_response(error: McpRemoteError) -> TransportResponse {
    match error {
        McpRemoteError::PoisonedLock => poisoned_lock_response(),

        _ => TransportResponse {
            transmission: TransmissionState::NotSent,
            retryability: Retryability::Terminal,
            response: None,
            error_code: Some("mcp_transport_error".to_string()),
            error_message: Some("MCP transport could not construct a request".to_string()),
            vendor_request_id: None,
            served_from: None,
            observed_at_ms: None,
            retry_after_ms: None,
            error_signal: None,
        },
    }
}

#[cfg(test)]
#[path = "mcp_remote_concurrency_tests.rs"]
mod concurrency_tests;

#[cfg(test)]
#[path = "mcp_remote_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "mcp_remote_transport_integration_tests.rs"]
mod transport_integration_tests;

#[cfg(test)]
#[path = "mcp_remote_error_message_tests.rs"]
mod error_message_tests;

#[cfg(test)]
#[path = "mcp_remote_annotation_observation_tests.rs"]
mod annotation_observation_tests;

#[cfg(test)]
#[path = "mcp_remote_safety_tests.rs"]
mod safety_tests;

#[cfg(test)]
#[path = "mcp_remote_signal_tests.rs"]
mod signal_tests;
