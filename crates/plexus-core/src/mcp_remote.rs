//! MCP streamable-HTTP transport and the small client surface used by catalog
//! discovery. Credentials are not retained in pooled connection state; the HTTP
//! stack owns header copies for the lifetime of a request.

use std::collections::{HashMap, HashSet};
use std::fmt;
#[cfg(test)]
use std::io::BufRead;
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
        Self::new(manifest.transport.url.clone())
            .with_bindings(manifest.credential_bindings.clone())
            .with_app_key(manifest.key.clone())
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
                let response = self
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
    ) -> Result<Value, McpCallError> {
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
            return classify_reply(reply, state).map_err(|error| {
                let error = McpCallError::Remote(error);
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
        let mut reply = decode_response(response, body.get("id"), Some(responder))?;
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
        let mut reply = decode_response(response, None, None)?;
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
            Ok(response) => {
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
                        config.app_key.as_deref(),
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
                    );
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
    BeforeCall(Box<McpCallError>),
    Remote(McpRemoteError),
    Http(HttpAttemptFailure),
}

impl McpCallError {
    fn into_remote(self) -> McpRemoteError {
        match self {
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
    if let Some(delay) = retry_after {
        eprintln!(warn transport: "MCP vendor throttle: status={status} path={path} retry_after_ms={}", duration_ms(delay));
        return Ok(HttpReply {
            status,
            retry_after,
            body: Value::Null,
            session_id,
            sent_session: false,
        });
    }
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
        crate::rest_api::log_vendor_error(
            "MCP",
            &reqwest::Method::POST,
            &path,
            status,
            &text,
            None,
        );
        return Ok(HttpReply {
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
        status,
        retry_after,
        body,
        session_id,
        sent_session: false,
    })
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
        },
    }
}

#[cfg(test)]
#[path = "mcp_remote_concurrency_tests.rs"]
mod concurrency_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// The vendor's own explanation is recovered from a failed tool call.
    ///
    /// MCP reports a tool failure as an ordinary result carrying `isError:
    /// true`, with the reason in the content blocks -- so the text naming the
    /// cause sits inside a structure that otherwise looks like success, and
    /// dropping it leaves one fixed sentence as the only evidence anywhere.
    /// Narrowing one real failure without it took five separate probes.
    ///
    /// Every text block is joined rather than the first taken, because a
    /// truncated reason reads as a complete one -- the failure mode is a
    /// confident half-answer, not an obvious gap.
    ///
    /// The two empty cases are kept DISTINCT: a vendor that sent no content and
    /// a response we could not read are both quiet, and only one of them is the
    /// vendor's fault.
    ///
    /// Mutation-proved: taking only the first block fails the join assertion,
    /// and returning a constant fails the distinctness assertions.
    #[test]
    fn a_tool_error_recovers_the_vendor_text() {
        let split = serde_json::json!({
            "content": [
                {"type": "text", "text": "resource not accessible"},
                {"type": "text", "text": "by personal access token"}
            ]
        });
        assert_eq!(
            tool_error_text(&split),
            "resource not accessible by personal access token",
            "every text block must survive: a partial reason reads as a whole one"
        );

        assert_eq!(
            tool_error_text(&serde_json::json!({})),
            "<no content blocks>",
            "an unreadable response must not be reported as a silent vendor"
        );
        assert_eq!(
            tool_error_text(&serde_json::json!({"content": [{"type": "image"}]})),
            "<content carried no text>",
            "a vendor that sent no text is a different fact from an unreadable response"
        );
    }

    #[test]
    fn grep_app_no_results_tool_error_is_recognized_narrowly() {
        let prefix =
            include_str!("../tests/fixtures/grep_app/no_results_tool_error.txt").trim_end();
        let with_usage_advice = format!("{prefix} Add a repository or language filter.");
        let (kind, response) = grep_app_tool_error_response(
            Some(GREP_APP_APP_KEY),
            GREP_APP_SEARCH_ACTION,
            &with_usage_advice,
        )
        .expect("the no-match sentence is recognized");
        assert_eq!(kind, GrepAppToolError::NoResults);
        assert_eq!(
            response.response,
            Some(serde_json::json!({
                "content": [{"type": "text", "text": GREP_APP_NO_RESULTS}]
            })),
            "a tool error becomes the ordinary empty-result shape"
        );
        assert_eq!(response.retryability, Retryability::Terminal);
        assert!(
            grep_app_tool_error_response(
                Some(GREP_APP_APP_KEY),
                GREP_APP_SEARCH_ACTION,
                "No results found for your query"
            )
            .is_none(),
            "the complete sentence, including its period, is required"
        );
        assert!(
            grep_app_tool_error_response(
                Some("other_app"),
                GREP_APP_SEARCH_ACTION,
                &with_usage_advice
            )
            .is_none(),
            "other MCP endpoints keep their vendor errors"
        );
    }

    #[test]
    fn grep_app_upstream_rate_limit_tool_error_is_recognized_narrowly() {
        let text = include_str!("../tests/fixtures/grep_app/rate_limit_tool_error.txt").trim();
        let (kind, response) =
            grep_app_tool_error_response(Some(GREP_APP_APP_KEY), GREP_APP_SEARCH_ACTION, text)
                .expect("the upstream rate-limit parser error is recognized");
        assert_eq!(kind, GrepAppToolError::RateLimited);
        assert_eq!(response.retryability, Retryability::Throttle);
        assert_eq!(response.error_code.as_deref(), Some("throttled"));
        assert_eq!(response.retry_after_ms, Some(30_000));
        assert!(
            grep_app_tool_error_response(
                Some(GREP_APP_APP_KEY),
                GREP_APP_SEARCH_ACTION,
                "Unexpected token 'T', \"Too Many Tokens\" is not valid JSON"
            )
            .is_none(),
            "a different JSON parse failure is not a grep.app rate limit"
        );
        assert!(
            grep_app_tool_error_response(Some(GREP_APP_APP_KEY), "otherAction", text).is_none(),
            "only searchGitHub's response uses this vendor-specific hint"
        );
    }

    #[test]
    fn catalog_app_key_is_carried_into_mcp_connection_config() {
        let source = include_str!("../../../catalog/grep_app.jsonc");
        let source = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let manifest: crate::manifest::AppManifest =
            serde_json::from_str(&source).expect("reviewed grep.app manifest");

        let connection = McpConnection::from_manifest("grep", &manifest);
        assert_eq!(manifest.key, GREP_APP_APP_KEY);
        assert!(manifest
            .actions_baseline
            .iter()
            .any(|action| action.name == GREP_APP_SEARCH_ACTION));
        assert_eq!(
            connection.config.app_key.as_deref(),
            Some(manifest.key.as_str())
        );
    }

    use std::net::TcpListener;

    pub(super) fn start_server<F>(
        requests: usize,
        handler: F,
    ) -> (String, crate::test_http::FixedRequestServer)
    where
        F: Fn(usize, &str) -> String + Send + 'static,
    {
        let (base, task) =
            crate::test_http::FixedRequestServer::start(requests, "MCP", move |index, wire| {
                let reply = handler(index, wire);
                // Canned JSON fixtures describe the result, not the request counter.
                // Echo the actual RPC id just as a conforming server does. Protocol
                // mismatch tests use FixedRequestServer directly, without this helper.
                let Some((headers, body)) = reply.split_once("\r\n\r\n") else {
                    return reply;
                };
                if !headers.contains("Content-Type: application/json") {
                    return reply;
                }
                let Some(request) = wire
                    .split_once("\r\n\r\n")
                    .and_then(|(_, body)| serde_json::from_str::<Value>(body).ok())
                else {
                    return reply;
                };
                let Ok(mut envelope) = serde_json::from_str::<Value>(body) else {
                    return reply;
                };
                if request.get("id").is_none()
                    || (!envelope.get("result").is_some() && !envelope.get("error").is_some())
                {
                    return reply;
                }
                envelope["id"] = request["id"].clone();
                let encoded = envelope.to_string();
                let headers = headers.replace(
                    &format!("Content-Length: {}", body.len()),
                    &format!("Content-Length: {}", encoded.len()),
                );
                format!("{headers}\r\n\r\n{encoded}")
            });
        (format!("{base}/mcp"), task)
    }

    pub(super) fn response(status: u16, body: &str, extra_headers: &str) -> String {
        let crlf = [char::from(13), char::from(10)]
            .into_iter()
            .collect::<String>();
        let extra = if extra_headers.is_empty() {
            String::new()
        } else {
            format!("{extra_headers}{crlf}")
        };
        format!(
            "HTTP/1.1 {status}{crlf}Content-Type: application/json{crlf}Content-Length: {}{crlf}Connection: close{crlf}{extra}{crlf}{body}",
            body.len()
        )
    }

    pub(super) fn notification_response() -> String {
        let crlf = [char::from(13), char::from(10)]
            .into_iter()
            .collect::<String>();
        format!("HTTP/1.1 202 Accepted{crlf}Content-Length: 0{crlf}Connection: close{crlf}{crlf}")
    }

    pub(super) fn request(connection_id: &str, action: &str) -> TransportRequest {
        TransportRequest {
            request_id: "request-1".to_string(),
            connection_id: connection_id.to_string(),
            action: action.to_string(),
            args: json!({"value": "ordinary"}),
            credential_fingerprint: "fp".to_string(),
        }
    }

    pub(super) fn config(endpoint: String) -> McpRemoteConfig {
        McpRemoteConfig::new(endpoint).with_bindings(vec![CredentialBinding {
            ref_role: "credential".to_string(),
            placement: "header".to_string(),
            key: "authorization".to_string(),
            prefix: "Bearer ".to_string(),
            required: true,
        }])
    }

    fn poisoned_entry_response() -> TransportResponse {
        let config = config("http://127.0.0.1:0/mcp".to_string());
        let transport = McpRemoteTransport::new(config.clone());
        let entry = transport
            .entry_for("poisoned", &config)
            .expect("create pooled MCP entry");
        let poisoned_entry = Arc::clone(&entry.entry);
        let poisoner = std::thread::spawn(move || {
            let _guard = poisoned_entry
                .lock()
                .expect("entry must be healthy before the poison is induced");
            panic!("poison the real pooled MCP entry while holding its guard");
        });
        assert!(
            poisoner.join().is_err(),
            "the poisoner must panic while holding the real entry guard"
        );

        transport.dispatch(
            request("poisoned", "read_tool"),
            &ResolvedCredential::new(b"CANARY".to_vec(), None, 1),
        )
    }

    fn connect_failure_response() -> TransportResponse {
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve refused TCP endpoint");
        let address = listener.local_addr().expect("read refused TCP endpoint");
        drop(listener);

        McpRemoteTransport::new(config(format!("http://{address}/mcp"))).dispatch(
            request("refused", "read_tool"),
            &ResolvedCredential::new(b"CANARY".to_vec(), None, 1),
        )
    }

    #[test]
    fn invalid_request_diagnostic_is_not_sent_through_mcp() {
        let cfg = config("not a valid URL".to_string());
        let transport = McpRemoteTransport::new(cfg.clone());
        // Exercise the tool-post path, not a failed initialize. Initialization
        // failures now explicitly report that the tool was never sent.
        transport
            .entry_for("invalid", &cfg)
            .unwrap()
            .lock()
            .unwrap()
            .initialized = true;
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let result = transport.dispatch(request("invalid", "read_tool"), &credential);

        assert_eq!(
            (result.transmission, result.error_code.as_deref()),
            (TransmissionState::NotSent, Some("http_request_invalid"))
        );
    }

    #[test]
    fn poisoned_lock_and_connect_failure_have_distinct_wire_codes() {
        let poisoned = poisoned_entry_response();
        let refused = connect_failure_response();

        assert_eq!(
            poisoned.error_code.as_deref(),
            Some("transport_restart_required")
        );
        assert_eq!(refused.error_code.as_deref(), Some("transport_transient"));
        assert_ne!(poisoned.error_code, refused.error_code);
        assert_eq!(refused.transmission, TransmissionState::NotSent);
        assert_eq!(refused.retryability, Retryability::AutoRetryable);
    }

    #[test]
    fn poisoned_lock_is_terminal_without_claiming_transmission() {
        let response = poisoned_entry_response();

        assert_eq!(response.transmission, TransmissionState::NotSent);
        assert_eq!(response.retryability, Retryability::Terminal);
    }

    #[test]
    fn debug_projection_does_not_include_credential_binding_values() {
        let mut config = McpRemoteConfig::new("https://vendor.invalid/mcp?token=CANARY");
        config.credential_bindings.push(CredentialBinding {
            ref_role: "credential".to_string(),
            placement: "header".to_string(),
            key: "authorization".to_string(),
            prefix: "Bearer ".to_string(),
            required: true,
        });
        let transport = McpRemoteTransport::new(config);
        let rendered = format!("{transport:?}");
        assert!(!rendered.contains("CANARY"));

        // An empty projection satisfies the absence assertion above perfectly,
        // so it cannot stand alone: a debug projection is read during an
        // incident, and one that renders nothing leaks nothing and diagnoses
        // nothing. Assert the non-secret fields survive redaction.
        assert!(
            rendered.contains("vendor.invalid"),
            "the projection dropped the vendor host, leaving nothing to diagnose: {rendered}"
        );
        assert!(
            rendered.contains("credential_binding_count"),
            "the projection dropped the binding count: {rendered}"
        );
    }
}

#[cfg(test)]
mod transport_integration_tests {
    use super::tests::{config, notification_response, request, response, start_server};
    use super::*;
    use crate::test_scratch::Scratch;
    use crate::CredentialSource;

    #[test]
    fn mcp_lookup_reserves_lease_before_releasing_the_pool_map() {
        for discovery in [false, true] {
            let (endpoint, server) = start_server(3, move |index, _| match index {
                0 => response(200, r#"{"id":1,"result":{}}"#, ""),
                1 => notification_response(),
                _ if discovery => response(
                    200,
                    r#"{"id":2,"result":{"tools":[{"name":"read_tool","inputSchema":{}}]}}"#,
                    "",
                ),
                _ => response(200, r#"{"id":2,"result":{"ok":true}}"#, ""),
            });
            let cfg = config(endpoint);
            let transport = Arc::new(McpRemoteTransport::new(cfg.clone()));
            // Seed the zero reservations of an idle connection directly, so
            // fixture setup does not acquire/release the lease being tested.
            transport.entries.lock().unwrap().insert(
                "lease-gap".into(),
                Arc::new(PooledEntry {
                    state: Mutex::new(ConnectionEntry::build(&cfg).unwrap()),
                    leases: AtomicUsize::new(0),
                }),
            );
            assert!(transport.age_entry_for_test("lease-gap", Duration::from_secs(600)));
            let (reached, paused) = std::sync::mpsc::sync_channel(1);
            let (resume, released) = std::sync::mpsc::sync_channel(1);
            *transport.lookup_pause.lock().unwrap() = Some(LookupPause {
                connection_id: "lease-gap".into(),
                reached,
                resume: released,
            });
            let caller = Arc::clone(&transport);
            let worker = thread::spawn(move || {
                if discovery {
                    assert_eq!(
                        caller
                            .discover(
                                &McpConnection {
                                    connection_id: "lease-gap".into(),
                                    config: cfg
                                },
                                &ResolvedCredential::anonymous()
                            )
                            .unwrap()[0]
                            .name,
                        "read_tool"
                    );
                } else {
                    assert_eq!(
                        caller
                            .dispatch(
                                request("lease-gap", "read_tool"),
                                &ResolvedCredential::anonymous()
                            )
                            .response
                            .unwrap()["ok"],
                        true
                    );
                }
            });
            let borrowed = paused
                .recv_timeout(Duration::from_secs(5))
                .expect("caller paused after pool lookup");
            // Sweep in the exact lookup-to-entry-lock gap, without sleeps. The
            // caller must already own a lease even though it has not sent yet.
            let removed = transport.sweep_idle();
            let pooled = transport
                .entries
                .lock()
                .unwrap()
                .get("lease-gap")
                .map(|entry| Arc::as_ptr(entry) as usize);
            resume.send(()).unwrap();
            worker.join().unwrap();
            server.join().unwrap();
            assert_eq!(removed, 0, "lookup must reserve a lease before the pool map is released (discovery={discovery})");
            assert_eq!(
                pooled,
                Some(borrowed),
                "the paused caller must retain the same pooled entry"
            );
        }
    }

    // Keep serving after the first error: a duplicate call must reach the mock
    // vendor and increment its counter, not fail against a closed test socket.
    fn rpc_error_vendor(
        error: Value,
    ) -> (String, Arc<AtomicU64>, crate::test_http::KeepAliveServer) {
        let calls = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&calls);
        let vendor =
            crate::test_http::KeepAliveServer::start(Duration::from_secs(2), move |wire| {
                let rpc: Value =
                    serde_json::from_str(wire.split_once("\r\n\r\n").unwrap().1).unwrap();
                if rpc["method"] == "notifications/initialized" {
                    return notification_response().replace("Connection: close\r\n", "");
                }
                let body = if rpc["method"] == "initialize" {
                    json!({"jsonrpc":"2.0","id":rpc["id"],"result":{}})
                } else {
                    assert_eq!(rpc["method"], "tools/call");
                    observed.fetch_add(1, Ordering::Relaxed);
                    json!({"jsonrpc":"2.0","id":rpc["id"],"error":error})
                };
                response(200, &body.to_string(), "").replace("Connection: close\r\n", "")
            });
        (format!("http://{}/mcp", vendor.address()), calls, vendor)
    }

    #[test]
    fn vendor_error_diagnostics_are_bounded() {
        const TEST: &str =
            "mcp_remote::transport_integration_tests::vendor_error_diagnostics_are_bounded";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
            #[allow(dead_code)]
            mod logging {
                include!("../tests/support/logging.rs");
            }
            logging::init_child();
            for tool in [false, true] {
                let (endpoint, task) = start_server(3, move |index, _| match index {
                    0 => response(200, r#"{"id":1,"result":{}}"#, ""),
                    1 => notification_response(),
                    _ => {
                        let text = "界".repeat(1024 * 1024 / 3);
                        let envelope = if tool {
                            json!({"id":2,"result":{"isError":true,"content":[{"text":text}]}})
                        } else {
                            json!({"id":2,"error":{"code":"vendor_failure","message":text}})
                        };
                        response(200, &envelope.to_string(), "")
                    }
                });
                let result = McpRemoteTransport::new(config(endpoint)).dispatch(
                    request("logs", "read_tool"),
                    &ResolvedCredential::anonymous(),
                );
                assert!(result.error_code.is_some());
                task.join().unwrap();
            }
            return;
        }
        let output = crate::test_http::bounded::child_output(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env("PLEXUS_LOG_STDERR_CHILD", "1"),
            Duration::from_secs(30),
            "MCP bounded vendor diagnostic child",
        )
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        let lines: Vec<_> = stderr
            .lines()
            .filter(|line| {
                line.contains("vendor rpc error:") || line.contains("vendor tool error on")
            })
            .collect();
        assert_eq!(lines.len(), 2);
        println!(
            "vendor diagnostic bytes: rpc={} tool={}",
            lines[0].len(),
            lines[1].len()
        );
        assert!(
            lines.iter().all(|line| line.len() <= 4352),
            "vendor diagnostics must be capped near 4096 bytes"
        );
    }

    #[test]
    fn negotiated_protocol_accepts_capture_defaults_omission_and_refuses_unsupported() {
        let captured = parse_sse_reply(
            include_str!("../tests/fixtures/grep_app/initialize.sse"),
            Some(&json!(1)),
        )
        .unwrap();
        for version in [
            Some(MCP_PROTOCOL_VERSION),
            Some(MCP_PROTOCOL_VERSION_JUNE),
            None,
            Some("2099-01-01"),
        ] {
            let mut initialize = captured.clone();
            if let Some(version) = version {
                initialize["result"]["protocolVersion"] = json!(version);
            } else {
                initialize["result"]
                    .as_object_mut()
                    .unwrap()
                    .remove("protocolVersion");
            }
            let supported = version != Some("2099-01-01");
            let (endpoint, task) =
                start_server(if supported { 3 } else { 1 }, move |index, wire| {
                    if index == 0 {
                        let initialize_request: Value =
                            serde_json::from_str(wire.split_once("\r\n\r\n").unwrap().1).unwrap();
                        assert_eq!(
                            initialize_request["params"]["clientInfo"]["version"],
                            env!("CARGO_PKG_VERSION"),
                            "clientInfo must name the package version, not just User-Agent"
                        );
                        return response(200, &initialize.to_string(), "");
                    }
                    let expected = version.unwrap_or(MCP_PROTOCOL_VERSION);
                    assert!(wire
                        .to_ascii_lowercase()
                        .contains(&format!("mcp-protocol-version: {expected}")));
                    if index == 1 {
                        notification_response()
                    } else {
                        response(200, r#"{"id":2,"result":{"ok":true}}"#, "")
                    }
                });
            let result = McpRemoteTransport::new(config(endpoint)).dispatch(
                request("protocol", "read_tool"),
                &ResolvedCredential::anonymous(),
            );
            task.join().unwrap();
            if supported {
                assert_eq!(result.response.unwrap()["ok"], true);
            } else {
                assert_eq!(result.transmission, TransmissionState::NotSent);
                assert_eq!(
                    result.error_code.as_deref(),
                    Some("mcp_unsupported_protocol_version")
                );
            }
        }
    }

    #[test]
    fn sse_matching_answer_finishes_without_waiting_for_stream_eof() {
        use std::io::Write;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
        let (release, wait) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            for index in 0..3 {
                let (mut socket, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).unwrap();
                let body: Value = serde_json::from_slice(&bytes).unwrap();
                if index == 1 {
                    socket
                        .write_all(notification_response().as_bytes())
                        .unwrap();
                    continue;
                }
                if index == 0 {
                    socket
                        .write_all(
                            response(200, &json!({"id":body["id"],"result":{}}).to_string(), "")
                                .as_bytes(),
                        )
                        .unwrap();
                    continue;
                }
                let event = format!("data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}}\n\ndata: {}\n\n", json!({"id":body["id"],"result":{"ok":true}}));
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{event}\r\n", event.len()).as_bytes()).unwrap();
                socket.flush().unwrap();
                let _ = wait.recv_timeout(Duration::from_secs(3));
            }
        });
        let mut cfg = config(endpoint);
        cfg.request_timeout = Duration::from_millis(500);
        let result = McpRemoteTransport::new(cfg).dispatch(
            request("stream", "read_tool"),
            &ResolvedCredential::anonymous(),
        );
        let _ = release.send(());
        worker.join().unwrap();
        assert_eq!(
            result
                .response
                .expect("matching SSE answer must not await EOF")["ok"],
            true
        );
    }

    #[test]
    fn initialize_timeout_is_not_sent_with_zero_tool_calls() {
        let calls = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&calls);
        let (endpoint, task) = start_server(1, move |_, wire| {
            if wire.contains("tools/call") {
                observed.fetch_add(1, Ordering::Relaxed);
            }
            assert!(wire.contains("initialize"));
            thread::sleep(Duration::from_millis(150));
            response(200, r#"{"id":1,"result":{}}"#, "")
        });
        let mut cfg = config(endpoint);
        cfg.request_timeout = Duration::from_millis(40);
        let result = McpRemoteTransport::new(cfg).dispatch(
            request("init-timeout", "write_tool"),
            &ResolvedCredential::anonymous(),
        );
        task.join().unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(result.transmission, TransmissionState::NotSent);
        assert_eq!(result.retryability, Retryability::AutoRetryable);
        assert_eq!(result.error_code.as_deref(), Some("timeout"));
    }

    #[test]
    fn initialize_and_notification_refusals_are_not_tool_failures() {
        for status in [403, 500, 429] {
            for notification in [false, true] {
                let (endpoint, task) =
                    start_server(if notification { 2 } else { 1 }, move |index, wire| {
                        assert!(!wire.contains("tools/call"));
                        if notification && index == 0 {
                            response(200, r#"{"id":1,"result":{}}"#, "")
                        } else {
                            response(
                                status,
                                r#"{"error":{"code":"vendor_failed"}}"#,
                                "Retry-After: 1",
                            )
                        }
                    });
                let result = McpRemoteTransport::new(config(endpoint)).dispatch(
                    request("init-refusal", "write_tool"),
                    &ResolvedCredential::anonymous(),
                );
                task.join().unwrap();
                assert_eq!(
                    result.transmission,
                    TransmissionState::NotSent,
                    "{status} notification={notification}"
                );
                assert_eq!(
                    result.retryability,
                    if matches!(status, 403 | 429) {
                        Retryability::Throttle
                    } else {
                        Retryability::Terminal
                    }
                );
            }
        }
    }

    #[test]
    fn json_response_id_must_match_the_posted_tool_call() {
        let (base, task) =
            crate::test_http::FixedRequestServer::start(3, "MCP mismatched id", |index, wire| {
                if index == 1 {
                    return notification_response();
                }
                let body: Value =
                    serde_json::from_str(wire.split_once("\r\n\r\n").unwrap().1).unwrap();
                let id = if index == 0 {
                    body["id"].clone()
                } else {
                    json!(99999)
                };
                response(
                    200,
                    &json!({"jsonrpc":"2.0", "id":id, "result":{"ok":true}}).to_string(),
                    "",
                )
            });
        let result = McpRemoteTransport::new(config(format!("{base}/mcp"))).dispatch(
            request("mismatch", "write_tool"),
            &ResolvedCredential::anonymous(),
        );
        task.join().unwrap();
        assert!(
            result.response.is_none(),
            "a mismatched id is not this call's response"
        );
        assert_eq!(result.error_code.as_deref(), Some("mcp_protocol_error"));
    }

    #[test]
    fn remote_discovery_reads_all_tool_pages_and_rejects_repeated_cursors() {
        for repeat in [false, true] {
            let (endpoint, task) = start_server(4, move |index, wire| match index {
                0 => response(200, r#"{"id":1,"result":{}}"#, ""),
                1 => notification_response(),
                2 => response(
                    200,
                    r#"{"id":2,"result":{"tools":[{"name":"first","inputSchema":{}}],"nextCursor":"page2"}}"#,
                    "",
                ),
                _ => {
                    assert!(wire.contains(r#""cursor":"page2""#));
                    let mut result = json!({"tools":[{"name":"second", "inputSchema":{}}]});
                    if repeat {
                        result["nextCursor"] = json!("page2");
                    }
                    response(200, &json!({"id":3,"result":result}).to_string(), "")
                }
            });
            let transport = McpRemoteTransport::new(config(endpoint.clone()));
            let result = transport.discover(
                &McpConnection::new("pages", endpoint),
                &ResolvedCredential::anonymous(),
            );
            task.join().unwrap();
            if repeat {
                assert_eq!(result.unwrap_err(), McpRemoteError::Protocol);
            } else {
                assert_eq!(
                    result
                        .unwrap()
                        .iter()
                        .map(|action| action.name.as_str())
                        .collect::<Vec<_>>(),
                    ["first", "second"]
                );
            }
        }
    }

    #[test]
    fn pooled_mcp_throttle_survives_idle_sweep() {
        let transport = McpRemoteTransport::default();
        let cfg = config("http://127.0.0.1:1".into());
        let entry = transport.entry_for("throttled", &cfg).unwrap();
        {
            let mut state = entry.lock().unwrap();
            state.throttle_until = Some(Instant::now() + Duration::from_secs(3600));
        }
        drop(entry);
        assert!(transport.age_entry_for_test("throttled", Duration::from_secs(600)));
        assert_eq!(
            transport.sweep_idle(),
            0,
            "an active throttle must survive idle eviction"
        );
        assert_eq!(transport.connection_count(), 1);
    }

    #[test]
    fn unregister_mcp_removes_configuration_and_pooled_entry() {
        let transport = McpRemoteTransport::default();
        let connection = McpConnection::new("removed", "http://127.0.0.1:1");
        transport.register_connection(connection.clone());
        transport.entry_for("removed", &connection.config).unwrap();
        assert!(transport.has_connection("removed"));
        transport.unregister_connection("removed");
        assert!(!transport.has_connection("removed"));
        assert!(transport.configs.lock().unwrap().is_empty());
        assert_eq!(transport.connection_count(), 0);
    }

    #[test]
    fn debug_mcp_transport_does_not_wait_for_its_entries_lock() {
        let transport = Arc::new(McpRemoteTransport::default());
        let lock = transport.entries.lock().unwrap();
        let worker_transport = Arc::clone(&transport);
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || tx.send(format!("{worker_transport:?}")).unwrap());
        let formatted = rx.recv_timeout(Duration::from_millis(250));
        drop(lock);
        worker.join().unwrap();
        assert!(formatted.is_ok(), "Debug must not wait for the pool lock");
    }

    #[test]
    fn rpc_request_timeout_is_outcome_unknown_without_resending_the_write() {
        let (endpoint, calls, _vendor) =
            rpc_error_vendor(json!({"code":-32001,"message":"Request timed out"}));
        let result = McpRemoteTransport::new(config(endpoint)).dispatch(
            request("rpc-timeout", "write_tool"),
            &ResolvedCredential::anonymous(),
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "a timed-out write must not be resent"
        );
        assert_eq!(result.transmission, TransmissionState::OutcomeUnknown);
        assert_eq!(result.retryability, Retryability::Terminal);
        assert_eq!(result.error_code.as_deref(), Some("timeout"));
    }

    #[test]
    fn rpc_auth_or_session_words_are_vendor_errors_without_resending() {
        for code in ["session_timeout", "auth_backend_failed", "stale_data"] {
            let (endpoint, calls, _vendor) = rpc_error_vendor(
                json!({"code":code,"message":"session auth failed after applying write"}),
            );
            let result = McpRemoteTransport::new(config(endpoint)).dispatch(
                request("rpc-vendor", "write_tool"),
                &ResolvedCredential::anonymous(),
            );
            assert_eq!(
                calls.load(Ordering::Relaxed),
                1,
                "RPC prose must not resend {code}"
            );
            assert_eq!(result.transmission, TransmissionState::Sent, "{code}");
            assert_eq!(result.retryability, Retryability::Terminal, "{code}");
            assert_eq!(
                result.error_code.as_deref(),
                Some("mcp_request_failed"),
                "{code}"
            );
        }
    }

    #[test]
    fn http_401_on_tool_call_reconnects_and_resends_once() {
        let calls = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&calls);
        let (endpoint, task) = start_server(6, move |index, wire| match index {
            0 | 3 => response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, ""),
            1 | 4 => notification_response(),
            2 => {
                assert!(wire.contains("tools/call"));
                observed.fetch_add(1, Ordering::Relaxed);
                response(401, "", "")
            }
            _ => {
                assert!(wire.contains("tools/call"));
                observed.fetch_add(1, Ordering::Relaxed);
                response(200, r#"{"jsonrpc":"2.0","id":0,"result":{"ok":true}}"#, "")
            }
        });
        let result = McpRemoteTransport::new(config(endpoint)).dispatch(
            request("http-auth", "write_tool"),
            &ResolvedCredential::anonymous(),
        );
        task.join().expect("server exits after one reconnect");
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(result.response.expect("successful retry")["ok"], true);
    }

    #[test]
    fn auth_rejection_reconnects_and_retries_exactly_once() {
        let (seen, task) = start_server(4, |index, request| {
            if index == 0 {
                assert!(request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer canary"));
                return response(401, r#"{"error":{"code":"unauthorized"}}"#, "");
            }
            if index == 2 {
                return notification_response();
            }
            if index == 1 {
                return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
            }
            response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, "")
        });
        let transport = McpRemoteTransport::new(config(seen));
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
        let result = transport.dispatch(request("auth", "read_tool"), &credential);
        assert_eq!(result.retryability, Retryability::Terminal);
        assert_eq!(result.response.expect("successful MCP call")["ok"], true);
        task.join().expect("auth retry server exits");
    }

    #[test]
    fn forbidden_response_is_a_terminal_vendor_failure_without_auth_reporting() {
        let (endpoint, task) = start_server(3, |index, _request| match index {
            0 => response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, ""),
            1 => notification_response(),
            2 => response(
                403,
                r#"{"error":{"code":"forbidden","message":"missing permission"}}"#,
                "",
            ),
            _ => unreachable!("a 403 must not reconnect the MCP session"),
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);

        let result = transport.dispatch(request("forbidden", "read_tool"), &credential);
        task.join().expect("server exits");

        assert_eq!(
            result.transmission,
            TransmissionState::Sent,
            "forbidden response must be sent and terminal: {result:?}"
        );
        assert_eq!(result.retryability, Retryability::Terminal);
        assert_eq!(result.error_code.as_deref(), Some("http_403"));
        assert_eq!(result.provider_auth_status(), None);
        assert!(result.response.is_none());
    }

    /// An MCP tool result reaches the caller BYTE-FOR-BYTE, with no field
    /// rewritten in transit.
    ///
    /// Both transports once passed vendor responses through
    /// `http_support::redact_value`, which replaces the value of any field
    /// whose NAME contains "token", "payload", "secret" and similar with a
    /// fingerprint. On a vendor response those are names we do not control, so
    /// it destroyed ordinary data: `payload` is an ordinary field name in tool
    /// results, and the whole nested object was replaced with nothing marking
    /// the value as redacted. The REST transport carries the equivalent test;
    /// this covers the MCP path, since a guard on only one dispatch path
    /// leaves the other free to reacquire the behaviour.
    ///
    /// The assertion is non-vacuous: re-adding the `redact_value` call to this
    /// function makes this test fail.
    #[test]
    fn an_mcp_tool_result_reaches_the_caller_verbatim() {
        let (endpoint, task) = start_server(3, |index, _request| {
            if index == 0 {
                return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
            }
            if index == 1 {
                return notification_response();
            }
            response(
                200,
                r#"{"jsonrpc":"2.0","id":2,"result":{"payload":{"summary":"Standup"},"next_cursor":"tok-2"}}"#,
                "",
            )
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
        let result = transport.dispatch(request("verbatim", "read_tool"), &credential);
        task.join().expect("server exits");

        let body = result.response.expect("successful MCP call");
        assert_eq!(
            body["payload"]["summary"], "Standup",
            "a nested tool-result field was rewritten in transit: {body}"
        );
        assert_eq!(
            body["next_cursor"], "tok-2",
            "the cursor field was rewritten in transit: {body}"
        );
    }

    /// A JSON payload inside MCP's text content block is decoded, and everything
    /// the decoding does not understand keeps its envelope.
    ///
    /// Driven through the real dispatch path rather than by calling the decoder,
    /// because the defect was that no caller decoded at all: the poller looked
    /// for its manifest-declared items field at the top level, found `content`,
    /// and reported a successful poll with zero events against a repository with
    /// eleven issues. Nothing failed, because an absent items field is
    /// indistinguishable from a quiet period.
    ///
    /// All four arms matter, and three of them are the reason this is a widening
    /// rather than a rewrite: prose must not be mangled, a bare scalar must not
    /// replace an indexable result, and a multi-block result has no single
    /// payload to choose.
    ///
    /// Mutation-proved: returning `result` unchanged from `decode_tool_result`
    /// fails the first arm; returning the parsed value unconditionally fails the
    /// scalar arm.
    #[test]
    fn a_json_payload_in_an_mcp_text_block_is_decoded() {
        // What GitHub actually sends: the array serialized into a text block,
        // with no structuredContent alongside it.
        let wrapped = r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"issues\":[{\"number\":4,\"title\":\"Seam\"}]}"}]}}"#;
        let (endpoint, task) = start_server(3, move |index, _request| {
            if index == 0 {
                return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
            }
            if index == 1 {
                return notification_response();
            }
            response(200, wrapped, "")
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
        let body = transport
            .dispatch(request("decode", "list_issues"), &credential)
            .response
            .expect("successful MCP call");
        task.join().expect("server exits");
        assert_eq!(
            body["issues"][0]["number"], 4,
            "the declared items field must be reachable at the top level: {body}"
        );

        // Prose in a text block is not a payload and must survive untouched.
        let prose = decode_tool_result(serde_json::json!({
            "content": [{"type": "text", "text": "stub-ok:read_item"}]
        }));
        assert_eq!(
            prose["content"][0]["text"], "stub-ok:read_item",
            "a non-JSON text block must keep its envelope: {prose}"
        );

        // A bare JSON scalar parses, and replacing a result with it would leave
        // callers nothing to index.
        let scalar = decode_tool_result(serde_json::json!({
            "content": [{"type": "text", "text": "4"}]
        }));
        assert!(
            scalar.get("content").is_some(),
            "a scalar must not replace the result: {scalar}"
        );

        // structuredContent is the protocol's own answer and outranks the text
        // block when a vendor sends it.
        let structured = decode_tool_result(serde_json::json!({
            "structuredContent": {"issues": []},
            "content": [{"type": "text", "text": "{\"issues\":[{\"number\":9}]}"}]
        }));
        assert!(
            structured["issues"]
                .as_array()
                .is_some_and(|a| a.is_empty()),
            "structuredContent must win over the text block: {structured}"
        );
    }

    #[test]
    fn request_timeout_is_outcome_unknown_and_is_not_retried() {
        let (endpoint, task) = start_server(3, |index, _request| {
            if index == 0 {
                return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
            }
            if index == 1 {
                return notification_response();
            }
            std::thread::sleep(Duration::from_millis(150));
            response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, "")
        });
        let mut remote_config = config(endpoint);
        remote_config.request_timeout = Duration::from_millis(40);
        let transport = McpRemoteTransport::new(remote_config);
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let result = transport.dispatch(request("timeout", "read_tool"), &credential);
        assert_eq!(result.transmission, TransmissionState::OutcomeUnknown);
        assert_eq!(result.retryability, Retryability::Terminal);
        task.join().expect("timeout server exits after one request");
    }

    #[test]
    fn retry_after_is_returned_as_throttle_and_honored_before_next_call() {
        let (endpoint, task) = start_server(4, |index, request| {
            if request.contains("notifications/initialized") {
                return notification_response();
            }
            if request.contains("initialize") {
                return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
            }
            if index == 2 {
                return response(
                    429,
                    r#"{"error":{"code":"rate_limited"}}"#,
                    "Retry-After: 1",
                );
            }
            response(200, r#"{"jsonrpc":"2.0","id":3,"result":{"ok":true}}"#, "")
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let first = transport.dispatch(request("throttle", "read_tool"), &credential);
        assert_eq!(first.retryability, Retryability::Throttle);
        assert_eq!(
            first.retry_after_ms,
            Some(1_000),
            "the vendor's delay reaches the caller as a number, not only as prose"
        );
        let started = Instant::now();
        let second = transport.dispatch(request("throttle", "read_tool"), &credential);
        assert!(started.elapsed() >= Duration::from_millis(900));
        assert!(second.response.is_some());
        task.join().expect("throttle server exits");
    }

    #[test]
    fn tools_list_discovery_accepts_streamable_http_json() {
        let (endpoint, task) = start_server(3, |_index, request| {
            if request.contains("notifications/initialized") {
                return notification_response();
            }
            if request.contains("initialize") {
                return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
            }
            response(
                200,
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_tool","title":"Read","inputSchema":{"type":"object"}}]}}"#,
                "",
            )
        });
        let transport = McpRemoteTransport::new(config(endpoint.clone()));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let connection = McpConnection {
            connection_id: "discover".to_string(),
            config: config(endpoint),
        };
        let actions = transport
            .discover(&connection, &credential)
            .expect("tools/list discovery");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].name, "read_tool");
        assert!(crate::jcs::jcs_sha256(&actions[0].input_schema)
            .expect("test schema is JCS-compatible")
            .starts_with("sha256:"));
        task.join().expect("discovery server exits");
    }

    struct IntegrationCkcredPeer {
        calls: std::sync::Mutex<Vec<(String, Value)>>,
    }

    impl IntegrationCkcredPeer {
        fn new() -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl crate::CkcredRoutePeer for IntegrationCkcredPeer {
        fn call(&self, operation: &str, params: Value) -> Result<Value, crate::CkcredRouteError> {
            self.calls
                .lock()
                .map_err(|_| crate::CkcredRouteError::Transport)?
                .push((operation.to_string(), params));
            if operation == "credential.get_scoped" {
                Ok(json!({
                    "result": {
                        "payload": [67, 65, 78, 65, 82, 89, 45, 80, 65, 89, 76, 79, 65, 68],
                        "record_version": 11, "credential_id": "test:CANARY-HANDLE"
                    }
                }))
            } else {
                Err(crate::CkcredRouteError::Transport)
            }
        }
    }

    fn integration_manifest() -> crate::AppManifest {
        serde_json::from_value(json!({
            "schema_version": 1,
            "key": "mock",
            "name": "Mock",
            "description": "HTTP integration manifest",
            "reuse_path": "mcp_direct",
            "reuse_rationale": "in-process test server",
            "tier": "S1",
            "transport": {"kind": "mcp_remote", "url": "https://unused.invalid/mcp"},
            "auth": {"mode": "api_key"},
            "credential_bindings": [{
                "ref_role": "credential", "placement": "header", "key": "Authorization",
                "prefix": "Bearer ", "required": true
            }],
            "resource_filters": {"required": [], "optional": [], "write_enabling": []},
            "actions_baseline": [
                {"name": "read_tool", "risk": "read"},
                {"name": "write_tool", "risk": "write"}
            ],
            "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 30}},
            "availability": "ga"
        }))
        .expect("integration manifest")
    }

    #[test]
    fn full_http_catalog_governance_path_quarantines_schema_drift() {
        use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
        use std::sync::atomic::{AtomicBool, Ordering};

        let schema_changed = std::sync::Arc::new(AtomicBool::new(false));
        let schema_changed_for_server = std::sync::Arc::clone(&schema_changed);
        let wire_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let wire_requests_for_server = std::sync::Arc::clone(&wire_requests);
        // The macOS clock ticks in microseconds, so the counter prevents same-tick test nonce collisions.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = format!(
            "{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let path = Scratch::database("http-e2e");
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("http-e2e-{unique}"),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        };
        let store = std::sync::Arc::new(crate::PlexusStore::open(&descriptor).expect("e2e store"));
        store
            .insert_connection(
                "direct",
                "connection",
                "mock",
                "pending",
                &json!({"required": [], "write_enabling": []}),
            )
            .expect("e2e connection");
        let handle = b"test:CANARY-HANDLE";
        let ticket = store
            .create_binding_ticket("direct", "connection", handle)
            .expect("e2e binding ticket");
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("consume e2e ticket")
            .expect("active e2e connection");

        let manifest = integration_manifest();
        let ingested = crate::ingest_value(serde_json::to_value(&manifest).expect("manifest JSON"))
            .expect("ingest integration manifest");
        store
            .upsert_manifest("system", &ingested)
            .expect("store integration manifest");
        store
            .seed_catalog_from_manifest("direct", "connection", "mock")
            .expect("seed baseline catalog");
        store
            .insert_grant(&crate::GrantInput {
                grant_id: "read-grant".to_string(),
                principal: "direct".to_string(),
                connection_id: "connection".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["read_tool".to_string()],
                authority_kind: "invoke".to_string(),
                expires_at: None,
            })
            .expect("read grant");
        store
            .insert_policy(&crate::PolicyInput {
                policy_id: "read-policy".to_string(),
                principal: "direct".to_string(),
                connection_id: "connection".to_string(),
                action_selector: "read_tool".to_string(),
                effect: "allow".to_string(),
                expires_at: None,
            })
            .expect("read policy");

        let route_peer = std::sync::Arc::new(IntegrationCkcredPeer::new());
        let credentials = crate::CkcredCredentialSource::new(route_peer);
        let resolved = credentials
            .get_by_id(std::str::from_utf8(handle).unwrap())
            .expect("resolve canary credential");

        // Start the vendor only after database and credential setup: its bounded
        // accept wait measures missing HTTP requests, not unrelated fixture work.
        let catalog_server_started = std::time::Instant::now();
        let (endpoint, task) = start_server(5, move |_index, request| {
            wire_requests_for_server
                .lock()
                .expect("wire request log")
                .push(request.to_string());
            if request.contains("\"method\":\"initialize\"") {
                return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
            }
            if request.contains("\"method\":\"notifications/initialized\"") {
                return notification_response();
            }
            if request.contains("\"method\":\"tools/list\"") {
                let write_type = if schema_changed_for_server.load(Ordering::Acquire) {
                    "number"
                } else {
                    "string"
                };
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "tools": [
                            {
                                "name": "read_tool",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"q": {"type": "string"}}
                                }
                            },
                            {
                                "name": "write_tool",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"title": {"type": write_type}}
                                }
                            }
                        ]
                    }
                });
                return response(200, &body.to_string(), "");
            }
            response(
                200,
                r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"read-ok"}]}}"#,
                "",
            )
        });

        let connection = McpConnection {
            connection_id: "connection".to_string(),
            config: config(endpoint.clone()),
        };
        let transport = std::sync::Arc::new(McpRemoteTransport::new(config(endpoint)));
        let reconciler = crate::CatalogReconciler::new(
            std::sync::Arc::clone(&store),
            std::sync::Arc::clone(&transport),
            Default::default(),
        );
        reconciler
            .refresh("direct", &connection, &manifest, &resolved)
            .unwrap_or_else(|error| {
                panic!(
                    "HTTP catalog discovery: {error:?}; server age {:?}; completed requests {}",
                    catalog_server_started.elapsed(),
                    wire_requests.lock().expect("wire request log").len(),
                )
            });
        let first_rows = store
            .list_catalog_actions_all("direct", "connection")
            .expect("first catalog rows");
        assert!(first_rows
            .iter()
            .all(|row| row.schema_hash.starts_with("sha256:")));
        assert_eq!(
            first_rows
                .iter()
                .find(|row| row.name == "write_tool")
                .map(|row| row.status.as_str()),
            Some("active")
        );

        let engine = crate::GovernanceEngine::new(
            std::sync::Arc::clone(&store),
            std::sync::Arc::new(credentials.clone()),
            std::sync::Arc::clone(&transport),
        );
        let reservation = engine
            .authorize(crate::AuthorizationRequest::new(
                "direct",
                "connection",
                "read_tool",
                json!({"q": "hello"}),
            ))
            .expect("authorized read reservation");
        let read_outcome = engine.revalidate_and_dispatch(&reservation);
        assert!(matches!(
            read_outcome.outcome,
            crate::TransportOutcome::Completed { response: Some(_) }
        ));

        schema_changed.store(true, Ordering::Release);
        reconciler
            .refresh("direct", &connection, &manifest, &resolved)
            .expect("HTTP rediscovery after schema mutation");
        let changed_rows = store
            .list_catalog_actions_all("direct", "connection")
            .expect("changed catalog rows");
        assert_eq!(
            changed_rows
                .iter()
                .find(|row| row.name == "write_tool")
                .map(|row| (row.status.as_str(), row.quarantine_reason.as_deref())),
            Some(("quarantined", Some("schema_changed_requires_review")))
        );
        assert!(matches!(
            engine.authorize(crate::AuthorizationRequest::new(
                "direct",
                "connection",
                "write_tool",
                json!({"title": "new"}),
            )),
            Err(crate::Denial::Catalog(crate::CatalogDenial::Quarantined))
        ));

        let rendered_transport = format!("{transport:?}");
        let rendered_outcome = format!("{read_outcome:?}");
        assert!(!rendered_transport.contains("test:CANARY-HANDLE"));
        assert!(!rendered_transport.contains("CANARY-PAYLOAD"));
        assert!(!rendered_outcome.contains("test:CANARY-HANDLE"));
        assert!(!rendered_outcome.contains("CANARY-PAYLOAD"));
        for row in store.list_audit("direct").expect("audit rows") {
            let rendered = serde_json::to_string(&row).expect("audit JSON");
            assert!(!rendered.contains("test:CANARY-HANDLE"));
            assert!(!rendered.contains("CANARY-PAYLOAD"));
        }
        let requests = wire_requests.lock().expect("wire request log");
        assert!(requests.iter().any(|request| request
            .to_ascii_lowercase()
            .contains("authorization: bearer canary-payload")));
        for request in requests.iter() {
            assert!(!request.contains("test:CANARY-HANDLE"));
            if request.contains("CANARY-PAYLOAD") {
                assert!(request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().contains("authorization:")));
            }
        }
        task.join().expect("HTTP e2e server");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mcp_http_failure_writes_mcp_operator_diagnostic() {
        const TEST: &str =
            "mcp_remote::transport_integration_tests::mcp_http_failure_writes_mcp_operator_diagnostic";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
            #[allow(dead_code)]
            mod logging {
                include!("../tests/support/logging.rs");
            }
            logging::init_child();
            let (endpoint, task) = start_server(3, |_index, request| {
                if request.contains("notifications/initialized") {
                    return notification_response();
                }
                if request.contains("initialize") {
                    return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
                }
                response(503, r#"{"error":"ghs_SECRET123"}"#, "")
            });
            let transport = McpRemoteTransport::new(config(format!("{endpoint}?token=abc")));
            let result = transport.dispatch(
                request("canary", "read_tool"),
                &ResolvedCredential::new(b"credential".to_vec(), None, 1),
            );
            assert_eq!(result.error_code.as_deref(), Some("http_503"));
            task.join().expect("server exits");
            return;
        }
        let output = crate::test_http::bounded::child_output(
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", TEST, "--nocapture"])
                .env("PLEXUS_LOG_STDERR_CHILD", "1"),
            std::time::Duration::from_secs(30),
            "MCP diagnostic test child",
        )
        .expect("run MCP diagnostic test child");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        let line = stderr
            .lines()
            .find(|line| line.contains("vendor error on"))
            .expect("operator diagnostic on stderr");
        let parsed = cortexkit_log::parse_line(line).expect("fleet log line");
        assert_eq!(parsed.level, cortexkit_log::ParsedLevel::Warn);
        assert_eq!(parsed.logger, "plexus.transport");
        assert!(line.contains("MCP vendor error on POST /mcp"), "{stderr}");
        assert!(!line.contains("REST vendor error on"), "{stderr}");
        assert!(line.contains("status=503"), "{stderr}");
        assert!(!line.contains("?token=abc"), "{stderr}");
    }

    /// Drive one MCP call at a server that reads the request and hangs up
    /// without answering, and return the endpoint it served.
    ///
    /// Runs only inside the stderr-capturing child, where the fleet renderer is
    /// installed; the parent reads the resulting line off the child's stderr.
    fn dispatch_against_hang_up(query: &str) -> String {
        // An empty response closes the stream without answering the request.
        let (base, task) =
            crate::test_http::FixedRequestServer::start(1, "hang-up", |_, _| String::new());
        let endpoint = format!("{base}/mcp{query}");
        let result = McpRemoteTransport::new(config(endpoint.clone())).dispatch(
            request("hang-up", "read_tool"),
            &ResolvedCredential::new(b"credential".to_vec(), None, 1),
        );
        // The connection closed during initialize, before any tools/call was
        // posted. Keep the diagnostic category, but do not claim a tool was sent.
        assert_eq!(
            (result.transmission, result.error_code.as_deref()),
            (TransmissionState::NotSent, Some("http_request_failed"))
        );
        task.join().expect("hang-up server exits");
        endpoint
    }

    /// Re-run `test` in a child with the fleet renderer installed and return
    /// the child's stdout, its stderr, and the one `MCP HTTP transport failed`
    /// line on that stderr.
    fn hang_up_diagnostic(test: &str) -> (String, String, String) {
        let output = crate::test_http::bounded::child_output(
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", test, "--nocapture"])
                .env("PLEXUS_LOG_STDERR_CHILD", "1"),
            std::time::Duration::from_secs(30),
            "MCP diagnostic test child",
        )
        .expect("run MCP diagnostic test child");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(output.status.success(), "{stderr}");
        let lines: Vec<&str> = stderr
            .lines()
            .filter(|line| line.contains("MCP HTTP transport failed"))
            .collect();
        assert_eq!(lines.len(), 1, "one line per failure: {stderr}");
        let line = lines[0].to_string();
        let parsed = cortexkit_log::parse_line(&line).expect("fleet log line");
        assert_eq!(parsed.level, cortexkit_log::ParsedLevel::Warn);
        assert_eq!(parsed.logger, "plexus.transport");
        (stdout, stderr, line)
    }

    #[test]
    fn a_transport_failure_logs_its_cause_without_the_url() {
        const TEST: &str =
            "mcp_remote::transport_integration_tests::a_transport_failure_logs_its_cause_without_the_url";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
            #[allow(dead_code)]
            mod logging {
                include!("../tests/support/logging.rs");
            }
            logging::init_child();
            let endpoint = dispatch_against_hang_up("");
            // Hand the endpoint to the parent so it knows which port to look
            // for; this goes to stdout, never into the diagnostic line.
            println!("HANG-UP-ENDPOINT {endpoint}");
            return;
        }
        let (stdout, stderr, line) = hang_up_diagnostic(TEST);
        let endpoint = stdout
            .lines()
            .find_map(|line| line.strip_prefix("HANG-UP-ENDPOINT "))
            .expect("child reports its endpoint");
        let port = endpoint
            .trim_start_matches("http://127.0.0.1:")
            .trim_end_matches("/mcp");
        assert!(port.parse::<u16>().is_ok(), "port from {endpoint}");

        let message = line
            .split_once("MCP HTTP transport failed: ")
            .map(|(_, message)| message)
            .expect("diagnostic message");
        let (category, cause) = message.split_once(": ").expect("category then cause");
        assert_eq!(category, "Request", "{stderr}");
        // The cause must say more than the category: the error and the
        // chain beneath it, here the connection the server dropped.
        assert!(cause.len() > "Request".len(), "{stderr}");
        assert!(cause.contains("error sending request"), "{stderr}");
        assert!(
            cause.contains(": "),
            "the source chain is missing: {stderr}"
        );
        assert!(!line.contains(endpoint), "{stderr}");
        assert!(!line.contains("127.0.0.1"), "{stderr}");
        assert!(!line.contains(port), "{stderr}");
    }

    #[test]
    fn a_transport_failure_never_logs_a_query_credential() {
        const TEST: &str =
            "mcp_remote::transport_integration_tests::a_transport_failure_never_logs_a_query_credential";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
            #[allow(dead_code)]
            mod logging {
                include!("../tests/support/logging.rs");
            }
            logging::init_child();
            // A vendor-specific parameter name on purpose. The fleet renderer
            // already masks the value of well-known names such as `token`, so
            // a test using one would still pass if this transport logged the
            // full URL; only a name the renderer does not know proves the
            // URL never reaches the line.
            dispatch_against_hang_up("?exaApiKey=SENTINEL");
            return;
        }
        let (_, stderr, line) = hang_up_diagnostic(TEST);
        assert!(
            line.contains("MCP HTTP transport failed: Request: "),
            "{stderr}"
        );
        assert!(!line.contains("SENTINEL"), "{stderr}");
        assert!(!stderr.contains("SENTINEL"), "{stderr}");
    }

    #[test]
    fn vendor_error_body_and_debug_output_never_carry_canary() {
        let (endpoint, task) = start_server(3, |_index, request| {
            if request.contains("notifications/initialized") {
                return notification_response();
            }
            if request.contains("initialize") {
                return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
            }
            response(
                500,
                r#"{"error":{"code":"vendor_failure","message":"ghs_SECRET123 https://example.test/?token=abc"}}"#,
                "",
            )
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
        let result = transport.dispatch(request("canary", "read_tool"), &credential);
        let rendered = format!("{transport:?} {result:?}");
        let message = result.error_message.as_deref().expect("agent error text");
        assert!(message.contains("ck module logs plexus"), "{message}");
        assert!(!rendered.contains("ghs_SECRET123"), "{rendered}");
        assert!(!rendered.contains("?token=abc"), "{rendered}");
        assert!(!rendered.contains("CANARY"));
        task.join().expect("canary server exits");
    }

    /// The session id from `initialize` is replayed on every later request.
    ///
    /// The MCP streamable-HTTP transport lets a server assign a session in the
    /// `mcp-session-id` RESPONSE header of `initialize` and then require it on
    /// everything that follows. Dropping it is silent at the transport layer
    /// and fatal one call later, and it does NOT look like a transport bug from
    /// outside: the servers that do this answer 400 `Missing mcp-session-id`,
    /// which reads as a protocol quirk or, worse, as a credential problem.
    /// Three vendors in the catalog behave this way (context7, huggingface and
    /// browserbase), and none of them can be reached at all without it.
    ///
    /// The server here REQUIRES the header exactly as those vendors do, so the
    /// assertion is the tools/list succeeding rather than a header inspection:
    /// a test that only checked the header was present would still pass if the
    /// value were wrong.
    ///
    /// Mutation-proved: not storing the id from the reply, and omitting the
    /// header from post_json, each fail this with a protocol error.
    #[test]
    fn a_server_assigned_session_id_is_replayed_on_later_requests() {
        let (seen, task) = start_server(3, |index, request| {
            if index == 0 {
                // initialize: assign a session.
                return response(
                    200,
                    r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
                    "mcp-session-id: sess-abc123",
                );
            }
            // Everything after initialize must carry the session back, exactly
            // as context7/huggingface/browserbase require.
            if !request
                .to_ascii_lowercase()
                .contains("mcp-session-id: sess-abc123")
            {
                return response(
                    400,
                    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Missing mcp-session-id"}}"#,
                    "",
                );
            }
            response(
                200,
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_tool","inputSchema":{"type":"object"}}]}}"#,
                "",
            )
        });
        let transport = McpRemoteTransport::new(config(seen.clone()));
        let connection = McpConnection {
            connection_id: "sessioned".to_string(),
            config: config(seen),
        };
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);

        let discovered = transport
            .discover(&connection, &credential)
            .expect("discovery must succeed when the session is replayed");
        assert_eq!(
            discovered
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>(),
            vec!["read_tool"],
            "the vendor rejected the follow-up request, so the session was not carried"
        );

        task.join().expect("session server exits");
    }

    /// A reconnect must not replay the session it is reconnecting away from,
    /// INCLUDING when the new `initialize` assigns no session at all.
    ///
    /// That last clause is the whole test, and the first version of it did not
    /// have it. Written the obvious way — re-initialize hands out a second
    /// session — the mutation that stops `reset_session` clearing the id STILL
    /// PASSED, because adopting the new id overwrites the stale one regardless.
    /// The clear only becomes observable when there is nothing to overwrite it
    /// with, which is exactly the case a server hits when it stops issuing
    /// sessions: adoption is guarded on the reply carrying an id, so a stale
    /// value would survive and be replayed forever.
    ///
    /// Mutation-proved: making `reset_session` clear only `initialized` fails
    /// this, while every other test in the file stays green.
    #[test]
    fn a_reconnect_does_not_carry_the_stale_session() {
        let (seen, task) = start_server(6, |index, request| {
            let lowered = request.to_ascii_lowercase();
            match index {
                // First session.
                0 => response(
                    200,
                    r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
                    "mcp-session-id: sess-first",
                ),
                1 => response(200, r#"{"jsonrpc":"2.0","result":{}}"#, ""),
                // The server forgets the session and rejects the call, which is
                // what drives the reconnect.
                2 => response(
                    401,
                    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"session expired"}}"#,
                    "",
                ),
                // Re-initialize, assigning NO session this time. Nothing here
                // can overwrite a stale id, so the clear is the only thing that
                // can remove it.
                3 => response(
                    200,
                    r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
                    "",
                ),
                4 => response(200, r#"{"jsonrpc":"2.0","result":{}}"#, ""),
                // The retried call must carry NO session header at all.
                _ => {
                    if lowered.contains("mcp-session-id") {
                        return response(
                            400,
                            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"stale session replayed"}}"#,
                            "",
                        );
                    }
                    response(
                        200,
                        r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_tool","inputSchema":{"type":"object"}}]}}"#,
                        "",
                    )
                }
            }
        });
        let transport = McpRemoteTransport::new(config(seen.clone()));
        let connection = McpConnection {
            connection_id: "reconnecting".to_string(),
            config: config(seen),
        };
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);

        let discovered = transport
            .discover(&connection, &credential)
            .expect("the retry after an auth response must succeed with a fresh session");
        assert_eq!(
            discovered
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>(),
            vec!["read_tool"],
            "the reconnect replayed the stale session instead of the new one"
        );

        task.join().expect("reconnect server exits");
    }

    /// An idle pooled connection is evicted, and a LEASED one is not.
    ///
    /// Both halves are required and the second is the one that matters: a
    /// removal-only test cannot distinguish a correct sweep from one that
    /// evicts everything, and evicting a leased entry would drop the client
    /// out from under a vendor call that is still in flight.
    ///
    /// The test makes the entry idle by moving its real `last_used` time back
    /// rather than by configuring a tiny idle timeout, so the sweep is checked
    /// against the idle timeout production actually uses.
    #[test]
    fn the_sweep_evicts_an_idle_entry_and_spares_a_leased_one() {
        let (seen, task) = start_server(2, |_, _| {
            response(200, r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#, "")
        });
        let config = config(seen);
        let idle_timeout = config.idle_timeout;
        let transport = McpRemoteTransport::new(config);
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);

        let _ = transport.dispatch(request("pooled", "read_tool"), &credential);
        assert_eq!(
            transport.connection_count(),
            1,
            "the dispatch must have pooled an entry, or the sweep below has \
             nothing to act on and would pass vacuously"
        );

        // Still fresh: a sweep now must keep it.
        assert_eq!(transport.sweep_idle(), 0);
        assert_eq!(transport.connection_count(), 1);

        // Older than the real idle timeout: now it must go.
        assert!(transport.age_entry_for_test("pooled", idle_timeout + Duration::from_secs(1)));
        assert_eq!(transport.sweep_idle(), 1, "an idle entry must be evicted");
        assert_eq!(transport.connection_count(), 0);

        // A leased entry is exempt even when its idle deadline has passed,
        // because a lease means a vendor call is using the client right now.
        let _ = transport.dispatch(request("leased", "read_tool"), &credential);
        let lease = transport
            .lease_for_test("leased")
            .expect("lease pooled entry");
        assert!(transport.age_entry_for_test("leased", idle_timeout + Duration::from_secs(1)));
        assert_eq!(
            transport.sweep_idle(),
            0,
            "a leased entry must survive its idle deadline"
        );
        assert_eq!(transport.connection_count(), 1);
        drop(lease);

        task.join().expect("sweep server exits");
    }

    /// The mock vendor's keep-alive timeout in the pooled-connection tests.
    const VENDOR_KEEP_ALIVE: Duration = Duration::from_millis(1000);
    /// The idle gap between the two calls: longer than the vendor keeps an idle
    /// connection open, so any connection reused across it loses the race.
    const IDLE_GAP: Duration = Duration::from_millis(1300);

    /// A keep-alive MCP vendor: answers initialize, the initialized
    /// notification and any tool call, without ever asking to close.
    fn keep_alive_mcp_vendor() -> crate::test_http::KeepAliveServer {
        crate::test_http::KeepAliveServer::start(VENDOR_KEEP_ALIVE, |request| {
            let rpc: Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            let (status, body) = if request.contains("notifications/initialized") {
                ("202 Accepted", String::new())
            } else if request.contains("\"initialize\"") {
                (
                    "200 OK",
                    json!({"jsonrpc":"2.0", "id":rpc["id"], "result":{}}).to_string(),
                )
            } else {
                (
                    "200 OK",
                    json!({"jsonrpc":"2.0", "id":rpc["id"], "result":{"ok":true}}).to_string(),
                )
            };
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        })
    }

    /// Two tool calls through one transport, `IDLE_GAP` apart, with the HTTP
    /// client's keep-alive pool limited to `pool_limit`. Returns both results
    /// and the vendor's accepted-connection count before and after the second
    /// call.
    fn two_calls_across_an_idle_gap(
        pool_limit: Duration,
    ) -> (TransportResponse, TransportResponse, usize, usize) {
        let vendor = keep_alive_mcp_vendor();
        let mut config = config(format!("http://{}/mcp", vendor.address()));
        config.pooled_connection_idle_limit = pool_limit;
        let transport = McpRemoteTransport::new(config);
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);

        let first = transport.dispatch(request("keep-alive", "read_tool"), &credential);
        let before = vendor.connections();
        std::thread::sleep(IDLE_GAP);
        let second = transport.dispatch(request("keep-alive", "read_tool"), &credential);
        let after = vendor.connections();
        (first, second, before, after)
    }

    /// A pooled connection idle past the client's pool limit is replaced, not
    /// reused, so a vendor that already closed it at its keep-alive timeout
    /// never sees a request on it.
    ///
    /// This is the DeepWiki probe failure ("connection closed before message
    /// completed"): the vendor drops idle connections
    /// at about 60 seconds, probes run every 60, and the client kept idle
    /// connections for 90. Here the pool limit is below the gap and the
    /// vendor's keep-alive is shorter than the gap, the same ordering
    /// production has with `POOLED_CONNECTION_IDLE_LIMIT`.
    ///
    /// Asserted as a connection-count delta across the second call rather than
    /// an absolute count: the first call is three requests, and the client is
    /// free to open more than one connection for them.
    ///
    /// `a_connection_reused_past_the_vendor_keep_alive_fails_as_production_did`
    /// proves the mock vendor really does break a reused connection, so this
    /// success is not the mock being lenient.
    #[test]
    fn a_connection_idle_past_the_pool_limit_is_replaced_not_reused() {
        let (first, second, before, after) =
            two_calls_across_an_idle_gap(Duration::from_millis(250));
        assert_eq!(first.response.expect("first MCP call succeeds")["ok"], true);
        assert_eq!(
            second
                .response
                .as_ref()
                .map(|response| response["ok"].clone()),
            Some(Value::Bool(true)),
            "the second call was sent on a connection the vendor had closed: {second:?}"
        );
        assert_eq!(
            after - before,
            1,
            "the second call must have opened exactly one fresh connection"
        );
    }

    /// The control for `a_connection_idle_past_the_pool_limit_is_replaced_not_reused`:
    /// with the pool limit ABOVE the idle gap, the second call reuses the idle
    /// connection and fails with hyper's "connection closed before message
    /// completed", the same cause a real DeepWiki probe logs when it loses
    /// this race. Without this, a mock vendor that answered a reused
    /// connection would let that test pass for the wrong reason.
    ///
    /// The cause is not in the transport's response, only in the operator log
    /// line, so the calls run in a child process with the fleet log renderer
    /// installed and this test reads the line off the child's stderr.
    #[test]
    fn a_connection_reused_past_the_vendor_keep_alive_fails_as_production_did() {
        const TEST: &str = "mcp_remote::transport_integration_tests::a_connection_reused_past_the_vendor_keep_alive_fails_as_production_did";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
            #[allow(dead_code)]
            mod logging {
                include!("../tests/support/logging.rs");
            }
            logging::init_child();
            let (first, second, before, after) =
                two_calls_across_an_idle_gap(Duration::from_secs(60));
            assert_eq!(first.response.expect("first MCP call succeeds")["ok"], true);
            assert_eq!(
                (second.transmission, second.error_code.as_deref()),
                (
                    TransmissionState::OutcomeUnknown,
                    Some("http_request_failed")
                ),
                "the reused connection must fail: {second:?}"
            );
            assert_eq!(
                after, before,
                "the failing call must have reused a connection"
            );
            return;
        }
        let (_, stderr, line) = hang_up_diagnostic(TEST);
        assert!(
            line.contains("connection closed before message completed"),
            "{stderr}"
        );
    }

    const INITIALIZED: &str = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;

    /// A response with a non-JSON body and the given headers.
    fn text_response(status: &str, body: &str, extra_headers: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}",
            body.len()
        )
    }

    /// The JSON-RPC id of the request a mock vendor received.
    fn request_id(request: &str) -> Value {
        let body = request.split_once("\r\n\r\n").expect("request body").1;
        serde_json::from_str::<Value>(body).expect("JSON-RPC request")["id"].clone()
    }

    /// A `Retry-After` of any size is reported to the caller as a number, and
    /// one longer than a request may wait refuses the next request locally
    /// instead of sleeping under the connection lock.
    ///
    /// `u64::MAX` seconds is the value that used to panic while the lock was
    /// held (`Instant + Duration` overflow), poisoning the connection until
    /// restart; any value over a few seconds parked the next request's thread
    /// for as long as the vendor asked.
    #[test]
    fn an_over_long_retry_after_refuses_locally_instead_of_sleeping() {
        let (endpoint, task) = start_server(3, |index, _request| match index {
            0 => response(200, INITIALIZED, ""),
            1 => notification_response(),
            _ => response(429, "{}", "Retry-After: 18446744073709551615"),
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let first = transport.dispatch(request("throttle", "read_tool"), &credential);
        assert_eq!(first.retryability, Retryability::Throttle, "{first:?}");
        assert_eq!(first.retry_after_ms, Some(3_600_000), "{first:?}");

        let started = Instant::now();
        let second = transport.dispatch(request("throttle", "read_tool"), &credential);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "an hour-long throttle must not be slept through"
        );
        assert_eq!(
            second.transmission,
            TransmissionState::NotSent,
            "{second:?}"
        );
        assert_eq!(second.retryability, Retryability::Throttle);
        let remaining = second.retry_after_ms.expect("the refusal names the delay");
        assert!(
            remaining > 3_590_000 && remaining <= 3_600_000,
            "{remaining}"
        );
        task.join()
            .expect("only the throttled call reached the vendor");
    }

    /// A refusal is classified by its status even when its body is not JSON.
    ///
    /// Vendors and proxies send 401 and 429 with an HTML page or nothing at
    /// all. Parsing the body first made both a protocol error, so the 401
    /// never reconnected and the 429 never reported its throttle.
    #[test]
    fn a_refusal_with_a_non_json_body_is_classified_by_its_status() {
        let (endpoint, task) = start_server(7, |index, _request| match index {
            0 | 3 => response(200, INITIALIZED, ""),
            1 | 4 => notification_response(),
            2 => text_response("401 Unauthorized", "<html>login</html>", ""),
            5 => response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, ""),
            _ => text_response("429 Too Many Requests", "", "Retry-After: 1\r\n"),
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let reconnected = transport.dispatch(request("html", "read_tool"), &credential);
        assert_eq!(
            reconnected
                .response
                .expect("a 401 page reconnects and retries")["ok"],
            true
        );
        let throttled = transport.dispatch(request("html", "read_tool"), &credential);
        assert_eq!(
            throttled.retryability,
            Retryability::Throttle,
            "{throttled:?}"
        );
        assert_eq!(throttled.retry_after_ms, Some(1_000));
        task.join().expect("server exits");
    }

    /// A 404 to a request that carried a session means the server forgot the
    /// session, and the client starts a new one (the MCP spec requires it).
    /// The new initialize carries no session id, and the retried call carries
    /// the new one.
    #[test]
    fn an_expired_session_is_reinitialized_once() {
        let (endpoint, task) = start_server(6, |index, request| {
            let lowered = request.to_ascii_lowercase();
            match index {
                0 => response(200, INITIALIZED, "mcp-session-id: sess-old"),
                1 => notification_response(),
                2 => {
                    assert!(lowered.contains("mcp-session-id: sess-old"));
                    text_response("404 Not Found", "Session not found", "")
                }
                3 => {
                    assert!(lowered.contains("\"initialize\""), "{request}");
                    assert!(
                        !lowered.contains("mcp-session-id:"),
                        "a new initialize must not carry the forgotten session"
                    );
                    response(200, INITIALIZED, "mcp-session-id: sess-new")
                }
                4 => notification_response(),
                _ => {
                    assert!(lowered.contains("mcp-session-id: sess-new"), "{request}");
                    response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, "")
                }
            }
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let result = transport.dispatch(
            request("expired", "read_tool"),
            &ResolvedCredential::new(b"token".to_vec(), None, 1),
        );
        task.join().expect("server exits");
        assert_eq!(
            result.response.expect("the call succeeds on a new session")["ok"],
            true
        );
    }

    /// A 404 to a request that carried no session is an ordinary vendor
    /// failure, not an expired session, and is not retried.
    #[test]
    fn a_404_without_a_session_is_not_retried() {
        let (endpoint, task) = start_server(3, |index, _request| match index {
            0 => response(200, INITIALIZED, ""),
            1 => notification_response(),
            _ => text_response("404 Not Found", "no such tool", ""),
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let result = transport.dispatch(
            request("plain", "read_tool"),
            &ResolvedCredential::new(b"token".to_vec(), None, 1),
        );
        task.join().expect("exactly three requests");
        assert_eq!(result.transmission, TransmissionState::Sent, "{result:?}");
        assert!(result.response.is_none());
    }

    /// A refused `notifications/initialized` leaves the session unready, so
    /// the next call initializes again instead of sending a tool call on a
    /// session the server never confirmed.
    #[test]
    fn a_refused_initialized_notification_does_not_mark_the_session_ready() {
        let (endpoint, task) = start_server(5, |index, request| match index {
            0 => response(200, INITIALIZED, ""),
            1 => text_response("500 Internal Server Error", "boom", ""),
            2 => {
                assert!(request.contains("\"initialize\""), "{request}");
                response(200, INITIALIZED, "")
            }
            3 => notification_response(),
            _ => response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, ""),
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let refused = transport.dispatch(request("notify", "read_tool"), &credential);
        assert!(refused.response.is_none(), "{refused:?}");
        let retried = transport.dispatch(request("notify", "read_tool"), &credential);
        task.join().expect("server exits");
        assert_eq!(
            retried.response.expect("the second call re-initializes")["ok"],
            true
        );
    }

    /// The answer in a server-sent-event body is the response to THIS request:
    /// progress notifications and other messages before it are skipped, and
    /// an event's data split across several `data:` lines is joined.
    #[test]
    fn an_sse_reply_is_the_response_matching_the_request_id() {
        let (endpoint, task) = start_server(3, |index, request| match index {
            0 => response(200, INITIALIZED, ""),
            1 => notification_response(),
            _ => {
                let id = request_id(request);
                let body = format!(
                    concat!(
                        ": keep-alive comment\r\n\r\n",
                        "event: message\r\n",
                        "data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progress\":1}}}}\r\n\r\n",
                        "data: {{\"jsonrpc\":\"2.0\",\"id\":\"other\",\"result\":{{\"stale\":true}}}}\r\n\r\n",
                        "data: {{\"jsonrpc\":\"2.0\",\"id\":{id},\r\n",
                        "data: \"result\":{{\"ok\":true}}}}\r\n\r\n"
                    ),
                    id = id
                );
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let result = transport.dispatch(
            request("sse", "read_tool"),
            &ResolvedCredential::new(b"token".to_vec(), None, 1),
        );
        task.join().expect("server exits");
        let body = result.response.expect("the matching response is found");
        assert_eq!(body["ok"], true, "{body}");
    }

    /// Re-registering a connection with a new endpoint starts a new session
    /// there: the new server sees initialize first, never the old server's
    /// session id.
    #[test]
    fn a_changed_endpoint_starts_a_new_session() {
        let (old_endpoint, old_task) = start_server(3, |index, _request| match index {
            0 => response(200, INITIALIZED, "mcp-session-id: sess-old"),
            1 => notification_response(),
            _ => response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, ""),
        });
        let (new_endpoint, new_task) = start_server(3, |index, request| {
            assert!(
                !request.to_ascii_lowercase().contains("sess-old"),
                "the old server's session reached the new server: {request}"
            );
            match index {
                0 => {
                    assert!(request.contains("\"initialize\""), "{request}");
                    response(200, INITIALIZED, "")
                }
                1 => notification_response(),
                _ => response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, ""),
            }
        });
        let transport = McpRemoteTransport::default();
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        transport.register_config("moved", config(old_endpoint));
        assert!(transport
            .dispatch(request("moved", "read_tool"), &credential)
            .response
            .is_some());
        transport.register_config("moved", config(new_endpoint));
        let moved = transport.dispatch(request("moved", "read_tool"), &credential);
        old_task.join().expect("old server exits");
        new_task.join().expect("new server exits");
        assert_eq!(
            moved.response.expect("the new endpoint answers")["ok"],
            true
        );
    }

    /// An MCP POST never follows a redirect to another origin, even a 307
    /// that would keep the method: the credential stays on the endpoint the
    /// manifest names, and the caller sees only the status.
    #[test]
    fn a_cross_origin_redirect_is_not_followed() {
        let elsewhere = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        elsewhere.set_nonblocking(true).expect("nonblocking");
        let location = format!("http://{}/mcp", elsewhere.local_addr().expect("address"));
        let (endpoint, task) = start_server(3, move |index, _request| match index {
            0 => response(200, INITIALIZED, ""),
            1 => notification_response(),
            _ => text_response(
                "307 Temporary Redirect",
                "",
                &format!("Location: {location}\r\n"),
            ),
        });
        let mut remote_config = config(endpoint);
        // Bounds the test if a regression follows into the listener, which
        // accepts the connection but never answers.
        remote_config.request_timeout = Duration::from_secs(2);
        let transport = McpRemoteTransport::new(remote_config);
        let result = transport.dispatch(
            request("redirect", "read_tool"),
            &ResolvedCredential::new(b"CANARY".to_vec(), None, 1),
        );
        task.join().expect("server exits");
        assert!(
            matches!(elsewhere.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "the request was sent to another origin"
        );
        assert_eq!(result.error_code.as_deref(), Some("http_307"), "{result:?}");
    }

    /// A success body larger than the transport reads into memory is
    /// outcome-unknown rather than read whole.
    #[test]
    fn an_oversized_success_body_is_outcome_unknown() {
        let (endpoint, task) = start_server(3, |index, _request| match index {
            0 => response(200, INITIALIZED, ""),
            1 => notification_response(),
            _ => response(200, &" ".repeat(MAX_RESPONSE_BODY_BYTES + 1), ""),
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let result = transport.dispatch(
            request("large", "read_tool"),
            &ResolvedCredential::new(b"token".to_vec(), None, 1),
        );
        drop(task);
        assert_eq!(
            (result.transmission, result.error_code.as_deref()),
            (
                TransmissionState::OutcomeUnknown,
                Some("response_too_large")
            ),
            "{:?}",
            result.error_code
        );
    }

    /// A panic while a tool call holds its connection reaches the caller as
    /// outcome unknown (the call was already on the wire), the session is
    /// discarded, and the connection keeps working.
    #[test]
    fn a_panic_mid_request_reports_outcome_unknown_and_keeps_the_connection() {
        let (endpoint, task) = start_server(7, |index, request| match index {
            0 | 4 => {
                assert!(request.contains("\"initialize\""), "{request}");
                response(200, INITIALIZED, "")
            }
            1 | 5 => notification_response(),
            _ => response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, ""),
        });
        let transport = McpRemoteTransport::new(config(endpoint));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let call = || transport.dispatch(request("panics", "write_tool"), &credential);
        assert_eq!(call().response.expect("warm-up call")["ok"], true);
        assert!(transport.panic_after_next_send_for_test("panics"));

        let panicked = call();
        assert_eq!(
            (panicked.transmission, panicked.error_code.as_deref()),
            (
                TransmissionState::OutcomeUnknown,
                Some("transport_panicked")
            ),
            "{panicked:?}"
        );
        assert_eq!(transport.panic_recoveries(), 1);
        assert_eq!(
            call()
                .response
                .expect("the connection re-initializes and works")["ok"],
            true
        );
        task.join().expect("server exits");
    }
}

#[cfg(test)]
mod error_message_tests {
    use super::*;

    /// The cases asserted here must render distinctly from one another.
    ///
    /// Inequality rather than "the message contains X", because a containment
    /// assertion passes against a formatter that returns one constant for every
    /// variant -- which is what this formatter previously did with its payloads
    /// discarded. The claim is limited to the pairs below; it is not a proof
    /// that every possible cause renders distinctly.
    #[test]
    fn distinct_transport_failures_render_distinctly() {
        let refused = McpRemoteError::Connection.to_string();
        let unauthorized = McpRemoteError::AuthRejected.to_string();
        let forbidden = McpRemoteError::VendorStatus(403).to_string();
        let throttled = McpRemoteError::Throttled(Duration::from_secs(90)).to_string();

        // A connect-classified failure and an auth rejection: these two rendered
        // identically before the payloads were carried.
        assert_ne!(
            refused, unauthorized,
            "a connection failure and a rejected credential must be distinguishable"
        );

        // Different statuses must stay different. 401 and 403 are the pair a
        // reader is most likely to need apart, and collapsing both into
        // "authentication was rejected" loses the only detail that separates
        // them.
        assert_ne!(
            unauthorized, forbidden,
            "distinct auth statuses must remain distinguishable"
        );
        assert!(unauthorized.contains("401"), "got: {unauthorized}");
        assert!(forbidden.contains("403"), "got: {forbidden}");

        assert!(
            throttled.contains("90"),
            "the observed retry delay must reach the message: {throttled}"
        );
        assert_ne!(
            throttled,
            McpRemoteError::Throttled(Duration::from_secs(3600)).to_string(),
            "throttle delays of different magnitudes must be distinguishable"
        );

        let no_delay = McpRemoteError::Throttled(Duration::ZERO).to_string();
        assert!(
            !no_delay.contains("0s"),
            "an absent Retry-After means unknown, not immediate: {no_delay}"
        );
    }

    /// The catalog layer carries the transport cause rather than replacing it.
    ///
    /// Asserted separately because the two layers discard detail independently:
    /// the transport formatter dropping its payload and `CatalogError::Transport`
    /// dropping the whole inner error are distinct defects, and fixing one while
    /// the other stands still yields a message that still cannot be triaged.
    /// Covers a connection failure against an HTTP 401 only; other causes and
    /// other `CatalogError` variants are outside what this asserts.
    #[test]
    fn the_catalog_error_carries_the_transport_cause() {
        let refused = crate::catalog::CatalogError::Transport(McpRemoteError::Connection);
        let unauthorized = crate::catalog::CatalogError::Transport(McpRemoteError::AuthRejected);

        assert_ne!(
            refused.to_string(),
            unauthorized.to_string(),
            "the catalog layer must not flatten distinct transport causes"
        );
        assert!(
            unauthorized.to_string().contains("401"),
            "the status must survive the catalog layer: {unauthorized}"
        );
    }
}

#[cfg(test)]
mod annotation_observation_tests {
    use super::*;

    #[test]
    fn discovery_retains_optional_vendor_annotations() {
        let tools = serde_json::json!({"result": {"tools": [
            {"name": "read_only", "inputSchema": {}, "annotations": {"readOnlyHint": true}},
            {"name": "absent", "inputSchema": {}},
            {"name": "disagrees", "inputSchema": {}, "annotations": {"readOnlyHint": false}},
            {"name": "empty", "inputSchema": {}, "annotations": {}},
            {"name": "invalid", "inputSchema": {}, "annotations": {"readOnlyHint": null}}
        ]}});
        let discovered: Vec<_> = tools_from_response(&tools)
            .unwrap()
            .iter()
            .map(|value| DiscoveredAction::from_value(value).unwrap())
            .collect();
        assert_eq!(
            discovered[0].annotations.as_ref().unwrap()["readOnlyHint"],
            true
        );
        assert_eq!(discovered[1].annotations, None);
        assert_eq!(
            discovered[2].annotations.as_ref().unwrap()["readOnlyHint"],
            false
        );
        assert_eq!(discovered[3].annotations, Some(serde_json::Map::new()));
        assert_eq!(
            discovered[4].annotations.as_ref().unwrap()["readOnlyHint"],
            Value::Null
        );
    }
}

#[cfg(test)]
#[path = "mcp_remote_safety_tests.rs"]
mod safety_tests;
