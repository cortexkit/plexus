//! REST transport for hand-written `rest_api` manifests.
//!
//! Each action's HTTP shape (method, path template, argument schema) comes from
//! the reviewed manifest; this module only renders and dispatches it. Like the
//! MCP transport it is built on `reqwest::blocking`, so async callers must run
//! it inside a blocking section (see `blocking_section` in plexus-module) or the
//! client's internal runtime panics on drop mid-request.
//!
//! The timeout/retry discipline, credential-header construction, response
//! redaction, and transport-failure classification are shared with the MCP
//! transport in `http_support` rather than copied: a connect-phase failure is
//! definitively not sent, a timeout after the request was written is
//! outcome-unknown and is never reported as not-sent.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderValue, ACCEPT};
use serde_json::{Map, Value};

use crate::credentials::ResolvedCredential;
use crate::http_support::{
    build_headers, classify_reqwest_error, credentialed_redirect_policy, duration_ms,
    read_body_bounded, redacted_endpoint, redirect_location_for_log, reqwest_error_cause,
    response_throttle, throttle_deadline, throttle_gate, throttle_refusal, with_request_deadline,
    BodyReadFailure, HttpAttemptFailure, ThrottleGate, TransportClock, DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, MAX_RESPONSE_BODY_BYTES,
    POOLED_CONNECTION_IDLE_LIMIT,
};
use crate::manifest::{
    AppManifest, CredentialBinding, HttpMethod, HttpOperation, RestParameterLocation,
};
use crate::transport::{
    Retryability, TransmissionState, Transport, TransportRequest, TransportResponse,
};

pub(crate) mod artifact_file;
mod job_log;
mod read_envelope;

const REST_ERROR_BODY_CAP: usize = 4096;

/// A local REST transport problem: configuration or request preparation failed,
/// so nothing was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RestError {
    PoisonedLock,
    Configuration,
    ConstantArgument(String),
    /// The path contains a separator or dot segment whose routing interpretation
    /// can change when a vendor or proxy decodes it.
    DotSegment,
}

/// Per-connection REST settings. Fixed vendor URLs come from the reviewed
/// manifest; operator-selected instances come from validated connection state
/// and are hidden from diagnostics, including their host names.
#[derive(Clone, PartialEq)]
pub struct RestConfig {
    pub base_url: String,
    /// Operator-selected instance addresses must not appear even as log origins.
    pub private_endpoint: bool,
    pub credential_bindings: Vec<CredentialBinding>,
    /// Declared HTTP operation per action name, from the manifest baseline.
    pub actions: HashMap<String, HttpOperation>,
    pub error_signals: HashMap<String, Vec<crate::manifest::ErrorSignalRule>>,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// How long this connection's pooled entry (its HTTP client and throttle
    /// state) may sit unused before `sweep_idle` evicts it. Not the socket
    /// keep-alive limit; that is `pooled_connection_idle_limit`.
    pub idle_timeout: Duration,
    /// How long an idle keep-alive TCP connection stays in the HTTP client's
    /// pool before it is dropped rather than reused. Defaults to
    /// `http_support::POOLED_CONNECTION_IDLE_LIMIT`; see there for why it must
    /// stay below vendor keep-alive timeouts. Not the entry eviction timeout;
    /// that is `idle_timeout`.
    pub pooled_connection_idle_limit: Duration,
    #[cfg(test)]
    test_root_certificate: Option<Vec<u8>>,
}

impl RestConfig {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            private_endpoint: false,
            credential_bindings: Vec::new(),
            actions: HashMap::new(),
            error_signals: HashMap::new(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            pooled_connection_idle_limit: POOLED_CONNECTION_IDLE_LIMIT,
            #[cfg(test)]
            test_root_certificate: None,
        }
    }

    pub fn with_bindings(mut self, bindings: Vec<CredentialBinding>) -> Self {
        self.credential_bindings = bindings;
        self
    }

    pub fn with_actions(mut self, actions: HashMap<String, HttpOperation>) -> Self {
        self.actions = actions;
        self
    }

    pub fn from_manifest(manifest: &AppManifest) -> Self {
        let mut config = Self::new(manifest.transport.url.clone())
            .with_bindings(manifest.credential_bindings.clone())
            .with_actions(actions_from_manifest(manifest));
        config.private_endpoint = manifest.transport.url_from_connection;
        config.error_signals = crate::error_signals::from_manifest(manifest);
        config
    }
}

impl Default for RestConfig {
    fn default() -> Self {
        Self::new(String::new())
    }
}

impl fmt::Debug for RestConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestConfig")
            .field(
                "base_url",
                &if self.private_endpoint {
                    "[redacted]".to_string()
                } else {
                    redacted_endpoint(&self.base_url)
                },
            )
            .field("credential_binding_count", &self.credential_bindings.len())
            .field("action_count", &self.actions.len())
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

/// The HTTP operations a manifest declares, keyed by action name. Actions
/// without an `http` entry are skipped: ingest validation guarantees every
/// action carries one on a `rest_api` manifest, so this is total in practice.
pub fn actions_from_manifest(manifest: &AppManifest) -> HashMap<String, HttpOperation> {
    manifest
        .actions_baseline
        .iter()
        .filter_map(|action| {
            action
                .http
                .as_ref()
                .map(|http| (action.name.clone(), http.clone()))
        })
        .collect()
}

#[derive(Clone, PartialEq)]
pub struct RestConnection {
    pub connection_id: String,
    pub config: RestConfig,
}

impl RestConnection {
    pub fn new(connection_id: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self {
            connection_id: connection_id.into(),
            config: RestConfig::new(base_url),
        }
    }

    pub fn from_manifest(connection_id: impl Into<String>, manifest: &AppManifest) -> Self {
        Self {
            connection_id: connection_id.into(),
            config: RestConfig::from_manifest(manifest),
        }
    }
}

impl fmt::Debug for RestConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestConnection")
            .field("connection_id", &self.connection_id)
            .field("config", &self.config)
            .finish()
    }
}

/// The settings a pooled REST entry was built from. When a connection's
/// registered config changes any of them, the entry is rebuilt: its clients
/// carry the timeouts and pool limit, and its throttle belongs to the old base
/// URL's vendor.
#[derive(Clone, PartialEq, Eq)]
struct RestClientSettings {
    base_url: String,
    connect_timeout: Duration,
    request_timeout: Duration,
    idle_timeout: Duration,
    pooled_connection_idle_limit: Duration,
}

impl RestClientSettings {
    fn of(config: &RestConfig) -> Self {
        Self {
            base_url: config.base_url.clone(),
            connect_timeout: config.connect_timeout,
            request_timeout: config.request_timeout,
            idle_timeout: config.idle_timeout,
            pooled_connection_idle_limit: config.pooled_connection_idle_limit,
        }
    }
}

struct RestConnectionEntry {
    download_client: Option<Client>,
    /// Sends GET, the only method that may follow a method-changing redirect
    /// (see `credentialed_redirect_policy`).
    client: Client,
    /// Sends every other method; follows only same-origin 307 and 308.
    write_client: Client,
    last_used: Instant,
    throttle_until: Option<Instant>,
    idle_timeout: Duration,
    settings: RestClientSettings,
    /// The owning transport's clock, which `last_used` and `throttle_until`
    /// are read on. A rebuilt entry keeps it.
    clock: TransportClock,
    /// Makes the next dispatch panic just after its request is sent, so a
    /// test can reach the panic recovery without a real defect.
    #[cfg(test)]
    panic_after_send: bool,
}

impl RestConnectionEntry {
    fn build(config: &RestConfig, clock: TransportClock) -> Result<Self, RestError> {
        let client = |follow_method_changing| {
            Client::builder()
                .user_agent(crate::http_support::USER_AGENT)
                .connect_timeout(config.connect_timeout)
                .timeout(config.request_timeout)
                .pool_idle_timeout(config.pooled_connection_idle_limit)
                .redirect(credentialed_redirect_policy(follow_method_changing))
                .build()
                .map_err(|_| RestError::Configuration)
        };
        Ok(Self {
            download_client: None,
            client: client(true)?,
            write_client: client(false)?,
            last_used: clock.now(),
            throttle_until: None,
            idle_timeout: config.idle_timeout,
            settings: RestClientSettings::of(config),
            clock,
            #[cfg(test)]
            panic_after_send: false,
        })
    }

    fn download_client(&mut self, config: &RestConfig) -> Result<Client, RestError> {
        if let Some(client) = &self.download_client {
            return Ok(client.clone());
        }
        let download_client = Client::builder()
            .user_agent(crate::http_support::USER_AGENT)
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout.min(Duration::from_secs(30)))
            .pool_idle_timeout(config.pooled_connection_idle_limit)
            .redirect(reqwest::redirect::Policy::none());
        // The TLS fixture adds trust to the real client builder rather than
        // replacing the client and accidentally masking its redirect policy.
        #[cfg(test)]
        let download_client = if let Some(cert) = &config.test_root_certificate {
            download_client.add_root_certificate(
                reqwest::Certificate::from_der(cert).map_err(|_| RestError::Configuration)?,
            )
        } else {
            download_client
        };
        let client = download_client
            .build()
            .map_err(|_| RestError::Configuration)?;
        self.download_client = Some(client.clone());
        Ok(client)
    }
}

/// A cloneable, per-connection REST client pool implementing the substrate's
/// synchronous transport seam. REST is stateless (no session handshake), so the
/// pool holds only the HTTP client and throttle state per connection.
#[derive(Clone)]
pub struct RestTransport {
    default_config: Arc<RestConfig>,
    configs: Arc<Mutex<HashMap<String, Arc<RestConfig>>>>,
    entries: Arc<Mutex<HashMap<String, Arc<Mutex<RestConnectionEntry>>>>>,
    /// How many times a panic was recovered from: a dispatch that panicked
    /// while holding its connection, or a poisoned entry the sweep evicted.
    panic_recoveries: Arc<AtomicU64>,
    /// Reads idle and throttle time for every pooled entry; see
    /// [`TransportClock`].
    clock: TransportClock,
}

impl RestTransport {
    pub fn new(default_config: RestConfig) -> Self {
        Self {
            default_config: Arc::new(default_config),
            configs: Arc::new(Mutex::new(HashMap::new())),
            entries: Arc::new(Mutex::new(HashMap::new())),
            panic_recoveries: Arc::new(AtomicU64::new(0)),
            clock: TransportClock::real(),
        }
    }

    /// Run this transport's idle and throttle bookkeeping on `clock`. Each
    /// pooled entry copies the clock when it is built, so set it before the
    /// first call.
    #[cfg(test)]
    fn with_clock(mut self, clock: TransportClock) -> Self {
        self.clock = clock;
        self
    }

    pub fn register_connection(&self, connection: RestConnection) {
        if let Ok(mut configs) = self.configs.lock() {
            configs.insert(connection.connection_id, Arc::new(connection.config));
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
    pub fn register_config(&self, connection_id: impl Into<String>, config: RestConfig) {
        if let Ok(mut configs) = self.configs.lock() {
            configs.insert(connection_id.into(), Arc::new(config));
        }
    }

    /// Whether a connection is registered as REST. The module's transport router
    /// uses this to decide which transport owns a dispatch.
    pub fn has_connection(&self, connection_id: &str) -> bool {
        self.configs
            .lock()
            .map(|configs| configs.contains_key(connection_id))
            .unwrap_or(false)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn connection_count(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0)
    }

    /// How many panics this transport has recovered from since it was built:
    /// dispatches that panicked mid-request (reported to their caller as
    /// outcome unknown) plus poisoned entries the sweep evicted. Each one is
    /// also logged at ERROR; this count keeps a healed connection visible.
    pub fn panic_recoveries(&self) -> u64 {
        self.panic_recoveries.load(Ordering::Relaxed)
    }

    /// Make the next dispatch on a pooled entry panic right after its request
    /// reaches the vendor.
    #[cfg(test)]
    fn panic_after_next_send_for_test(&self, connection_id: &str) -> bool {
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

    /// Sweep idle connections without waiting for in-flight requests. The pool
    /// map is shared by all REST connections: waiting for an entry while holding
    /// it would block unrelated dispatches from looking up their own clients.
    /// A busy entry is retained and reconsidered on the next sweep.
    ///
    /// A poisoned entry is evicted, so the next dispatch builds a fresh one:
    /// otherwise every later call on that connection would refuse until a
    /// restart. The eviction is logged at ERROR and counted, because it means
    /// a panic happened while a request held the connection.
    pub fn sweep_idle(&self) -> usize {
        let Ok(mut entries) = self.entries.lock() else {
            return 0;
        };
        let now = self.clock.now();
        let mut removed = 0;
        entries.retain(|connection_id, entry| {
            if entry.is_poisoned() {
                eprintln!(error transport:
                    "REST connection {connection_id} evicted: a panic poisoned its pooled entry"
                );
                self.panic_recoveries.fetch_add(1, Ordering::Relaxed);
                removed += 1;
                return false;
            }
            let keep = entry
                .try_lock()
                .map(|state| {
                    Arc::strong_count(entry) > 1
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

    fn config_for(&self, connection_id: &str) -> Arc<RestConfig> {
        self.configs
            .lock()
            .ok()
            .and_then(|configs| configs.get(connection_id).cloned())
            .unwrap_or_else(|| self.default_config.clone())
    }

    fn entry_for(
        &self,
        connection_id: &str,
        config: &RestConfig,
    ) -> Result<Arc<Mutex<RestConnectionEntry>>, RestError> {
        if config.base_url.trim().is_empty() {
            return Err(RestError::Configuration);
        }
        {
            let entries = self.entries.lock().map_err(|_| RestError::PoisonedLock)?;
            if let Some(entry) = entries.get(connection_id) {
                return Ok(Arc::clone(entry));
            }
        }
        let entry = Arc::new(Mutex::new(RestConnectionEntry::build(
            config,
            self.clock.clone(),
        )?));
        let mut entries = self.entries.lock().map_err(|_| RestError::PoisonedLock)?;
        Ok(Arc::clone(
            entries
                .entry(connection_id.to_string())
                .or_insert_with(|| Arc::clone(&entry)),
        ))
    }
}

impl Default for RestTransport {
    fn default() -> Self {
        Self::new(RestConfig::default())
    }
}

impl fmt::Debug for RestTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.entries.try_lock().ok().map(|entries| entries.len());
        formatter
            .debug_struct("RestTransport")
            .field("connection_count", &count)
            .field("default_config", &self.default_config)
            .finish()
    }
}

impl Transport for RestTransport {
    fn dispatch_github_facade(
        &self,
        request: TransportRequest,
        credential: &ResolvedCredential,
    ) -> TransportResponse {
        self.dispatch_rest(request, credential, true)
    }

    fn dispatch(
        &self,
        request: TransportRequest,
        credential: &ResolvedCredential,
    ) -> TransportResponse {
        self.dispatch_rest(request, credential, false)
    }
}

impl RestTransport {
    fn dispatch_rest(
        &self,
        request: TransportRequest,
        credential: &ResolvedCredential,
        github_facade: bool,
    ) -> TransportResponse {
        let config = self.config_for(&request.connection_id);
        // An action with no declared HTTP shape cannot be routed. Ingest
        // validation rejects such manifests, so this is defence in depth: fail
        // closed locally rather than improvising a URL at invoke time.
        let Some(operation) = config.actions.get(&request.action) else {
            eprintln!(warn transport: "REST request has no reviewed HTTP operation");
            return local_not_sent();
        };
        let entry = match self.entry_for(&request.connection_id, &config) {
            Ok(entry) => entry,
            Err(RestError::PoisonedLock) => return rest_poisoned_lock_response(),
            Err(_) => return local_not_sent(),
        };
        // Keep sends ordered within a connection so the next request observes
        // any Retry-After returned by the previous response before it is sent.
        // Pool maintenance must skip this lock rather than wait while holding
        // the shared entry map.
        let mut state = match entry.lock() {
            Ok(state) => state,
            Err(_) => return rest_poisoned_lock_response(),
        };
        // A panic below would otherwise unwind through this guard, poisoning
        // the entry so every later call on the connection refuses until a
        // restart, and the caller would get no reply at all. Catching it while
        // the guard is still held keeps the entry usable and lets the caller
        // hear that the request's outcome is unknown.
        let sent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Self::send_locked(
                &mut state,
                &config,
                operation,
                &request,
                credential,
                github_facade,
            )
        }));
        match sent {
            Ok(response) => response,
            Err(_) => {
                eprintln!(error transport:
                    "REST request on connection {} panicked mid-request; reported as outcome unknown and the pooled entry rebuilt",
                    request.connection_id
                );
                self.panic_recoveries.fetch_add(1, Ordering::Relaxed);
                if let Ok(fresh) = RestConnectionEntry::build(&config, self.clock.clone()) {
                    *state = fresh;
                }
                TransportResponse::unknown_with_error("transport_panicked")
            }
        }
    }
}

impl RestTransport {
    /// Send one request on a connection whose entry lock the caller holds.
    fn send_locked(
        state: &mut RestConnectionEntry,
        config: &RestConfig,
        operation: &HttpOperation,
        request: &TransportRequest,
        credential: &ResolvedCredential,
        github_facade: bool,
    ) -> TransportResponse {
        // A registered config that changed since this entry was built gets fresh
        // clients (its timeouts and pool limit are baked into them) and loses the
        // old vendor's throttle.
        if state.settings != RestClientSettings::of(config) {
            match RestConnectionEntry::build(config, state.clock.clone()) {
                Ok(fresh) => *state = fresh,
                Err(_) => return local_not_sent(),
            }
        }
        state.last_used = state.clock.now();
        // Honor a vendor throttle recorded by an earlier call on this
        // connection, exactly as the MCP transport does: a short one is waited
        // out, a long one refuses locally rather than parking this thread.
        match throttle_gate(&mut state.throttle_until, state.clock.now()) {
            ThrottleGate::Refuse(remaining) => return throttle_refusal("REST", remaining),
            ThrottleGate::Wait(delay) => state.clock.sleep(delay),
            ThrottleGate::Clear => {}
        }
        if let Some(shape) = crate::github::reads::bot::envelope_shape(&request.action)
            .filter(|_| operation.credentialless_tail.is_none())
        {
            let client = match state.download_client(config) {
                Ok(client) => client,
                Err(_) => return local_not_sent(),
            };
            return read_envelope::send(
                &client,
                &mut state.throttle_until,
                &state.clock,
                config,
                operation,
                shape,
                request,
                credential,
            );
        }
        if let Some(tail) = &operation.credentialless_tail {
            let client = match state.download_client(config) {
                Ok(client) => client,
                Err(_) => return local_not_sent(),
            };
            if tail.kind == crate::manifest::CredentiallessTailKind::ArtifactFile {
                return artifact_file::download(
                    &client,
                    &mut state.throttle_until,
                    &state.clock,
                    config,
                    operation,
                    tail,
                    request,
                    credential,
                );
            }
            return job_log::download(
                &client,
                &mut state.throttle_until,
                &state.clock,
                config,
                operation,
                tail,
                request,
                credential,
            );
        }
        let prepared = match prepare_request(&config.base_url, operation, &request.args) {
            Ok(prepared) => prepared,
            Err(error) => return preparation_failure(error),
        };
        let prepared_method = &prepared.method;
        let prepared_path = &prepared.path;
        let mut headers = match build_headers(&config.credential_bindings, credential) {
            Ok(headers) => headers,
            Err(_) => {
                eprintln!(warn transport: "REST credential header binding is invalid");
                return local_not_sent();
            }
        };
        let accept =
            if github_facade && github_stack_status(prepared_method, prepared_path).is_some() {
                "application/vnd.github+json"
            } else {
                "application/json"
            };
        headers.insert(ACCEPT, HeaderValue::from_static(accept));
        // Ingest refuses a header parameter that names a credential or
        // transport header; refuse here too rather than let an argument
        // replace either.
        for (name, value) in &prepared.headers {
            if headers.contains_key(name) {
                eprintln!(warn transport: "REST header parameter would replace a reviewed header");
                return local_not_sent();
            }
            headers.insert(name.clone(), value.clone());
        }
        // Only GET may follow a redirect that rewrites the method; every other
        // method goes through the client that follows only 307 and 308.
        let facade_client;
        let client = if github_facade {
            facade_client = match state.download_client(config) {
                Ok(client) => client,
                Err(_) => return local_not_sent(),
            };
            &facade_client
        } else if prepared.method == reqwest::Method::GET {
            &state.client
        } else {
            &state.write_client
        };
        let mut builder = client
            .request(prepared.method.clone(), &prepared.url)
            .headers(headers);
        if let Some(body) = &prepared.body {
            builder = builder.json(body);
        }
        let deadline = Instant::now()
            .checked_add(config.request_timeout)
            .unwrap_or_else(Instant::now);
        let response = match with_request_deadline(builder, deadline).send() {
            Ok(response) => response,
            Err(error) => {
                if config.private_endpoint {
                    return private_request_failure(error);
                }
                return request_failure_response(error, prepared_method, prepared_path);
            }
        };
        #[cfg(test)]
        if std::mem::take(&mut state.panic_after_send) {
            panic!("injected panic after the request was sent");
        }
        classify_response_with_privacy(
            response,
            &mut state.throttle_until,
            &state.clock,
            prepared_method,
            prepared_path,
            github_facade,
            config.private_endpoint,
            config
                .error_signals
                .get(&request.action)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        )
    }
}

fn timeout_response() -> TransportResponse {
    TransportResponse::timeout("REST")
}

fn private_request_failure(error: reqwest::Error) -> TransportResponse {
    let failure = classify_reqwest_error(&error);
    eprintln!(warn transport: "REST private endpoint request failed: {failure:?}");
    match failure {
        HttpAttemptFailure::Timeout => timeout_response(),
        HttpAttemptFailure::Connect => local_not_sent(),
        other => other
            .outcome_unknown_response()
            .unwrap_or_else(TransportResponse::unknown),
    }
}

fn request_failure_response(
    error: reqwest::Error,
    method: &reqwest::Method,
    path: &str,
) -> TransportResponse {
    let failure = classify_reqwest_error(&error);
    let cause = reqwest_error_cause(error);
    eprintln!(warn transport: "REST transport failed on {method} {}: {failure:?}: {cause}", path.split('?').next().unwrap_or(path));
    match failure {
        HttpAttemptFailure::Timeout => timeout_response(),
        HttpAttemptFailure::Connect => TransportResponse::transient_not_sent(),
        failure => failure
            .outcome_unknown_response()
            .unwrap_or_else(TransportResponse::unknown),
    }
}

struct PreparedRequest {
    method: reqwest::Method,
    url: String,
    /// The rendered path for diagnostics only: free-text placeholders keep
    /// their `{name}`, so a caller's search text never reaches the log.
    path: String,
    body: Option<Value>,
    /// Headers carried by `header_parameters` arguments, already validated as
    /// one-line visible-ASCII values.
    headers: Vec<(reqwest::header::HeaderName, HeaderValue)>,
}

/// Render the action's path template against the invocation args and decide
/// where the remaining args travel using the reviewed parameter placement,
/// falling back to the method's default for older manifests.
fn prepare_request(
    base_url: &str,
    operation: &HttpOperation,
    args: &Value,
) -> Result<PreparedRequest, RestError> {
    let base = base_url.trim();
    if base.is_empty() {
        return Err(RestError::Configuration);
    }
    // A base URL may carry its own query (an API version or key parameter).
    // The action path goes after the base PATH, and the base query is kept in
    // front of the arguments' query, or the path would land inside the query.
    let base = base.split_once('#').map_or(base, |(before, _)| before);
    let (base_path, base_query) = match base.split_once('?') {
        Some((path, query)) => (path, Some(query).filter(|query| !query.is_empty())),
        None => (base, None),
    };
    let (template, text_values, args) = fill_text_path_parameters(operation, args)?;
    let args = &args;
    let (path, mut remaining) = if let Some(constants) = &operation.request_constants {
        let mut merged = if args.is_null() {
            Map::new()
        } else {
            args.as_object().ok_or(RestError::Configuration)?.clone()
        };
        for (key, value) in constants {
            if merged.contains_key(key) {
                return Err(RestError::ConstantArgument(key.clone()));
            }
            merged.insert(key.clone(), value.clone());
        }
        render_path(&template, &Value::Object(merged))?
    } else {
        // Without constants, preserve the existing treatment of non-object args:
        // a placeholder-free operation can still be called without arguments.
        render_path(&template, args)?
    };
    // The URL carries each free-text value; the diagnostic path names its
    // placeholder instead.
    let mut log_path = path.clone();
    let mut path = path;
    for value in &text_values {
        path = path.replace(&value.marker, &value.encoded);
        log_path = log_path.replace(&value.marker, &format!("{{{}}}", value.name));
    }
    if has_dot_segment(&path) {
        return Err(RestError::DotSegment);
    }
    if matches!(operation.method, HttpMethod::Post) && operation.path == "/graphql" {
        // Repository keys are governance context, not GraphQL body fields.
        // Select by the reviewed operation so newly catalogued GraphQL actions
        // get the same projection without a transport-side action inventory.
        remaining.remove("owner");
        remaining.remove("repo");
    }
    let headers = take_header_parameters(operation, &mut remaining)?;
    let mut url = format!("{}{}", base_path.trim_end_matches('/'), path);
    let path = log_path;
    if let Some(query) = base_query {
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str(query);
    }
    let parameters = operation.parameters.unwrap_or(match operation.method {
        HttpMethod::Get | HttpMethod::Delete => RestParameterLocation::Query,
        _ => RestParameterLocation::Body,
    });
    let body = match parameters {
        RestParameterLocation::Query => {
            append_query(&mut url, &remaining);
            None
        }
        RestParameterLocation::Body => Some(if remaining.is_empty() {
            Value::Object(Map::new())
        } else {
            Value::Object(remaining)
        }),
    };
    Ok(PreparedRequest {
        method: reqwest_method(operation.method),
        url,
        path,
        body,
        headers,
    })
}

/// One free-text path placeholder filled by [`fill_text_path_parameters`].
struct TextPathValue {
    /// Stands in for the value in the template until `render_path` has run.
    /// It holds NUL bytes, which neither a template nor an encoded value can
    /// contain, so it can only match its own position.
    marker: String,
    name: String,
    encoded: String,
}

/// Replace the operation's free-text path placeholders with markers, so the
/// ordinary placeholders can still be rendered and checked by `render_path`.
/// Returns that template, each filled placeholder, and the arguments left for
/// the ordinary placeholders, query or body.
///
/// A free-text value is encoded as one path segment: every byte outside the
/// RFC 3986 unreserved set is escaped, so `/`, `?`, `#`, `%`, `{` and `}`
/// cannot change the route, start a query, or form a new placeholder. A value
/// that is exactly `.` or `..` would still be read as a dot segment, and is
/// refused by the dot-segment check on the rendered path.
fn fill_text_path_parameters(
    operation: &HttpOperation,
    args: &Value,
) -> Result<(String, Vec<TextPathValue>, Value), RestError> {
    let Some(names) = operation
        .text_path_parameters
        .as_ref()
        .filter(|names| !names.is_empty())
    else {
        return Ok((operation.path.clone(), Vec::new(), args.clone()));
    };
    let mut remaining = args.as_object().ok_or(RestError::Configuration)?.clone();
    let mut template = operation.path.clone();
    let mut filled = Vec::with_capacity(names.len());
    for (index, name) in names.iter().enumerate() {
        let placeholder = format!("{{{name}}}");
        let value = remaining.remove(name).ok_or(RestError::Configuration)?;
        let text = scalar_to_string(&value).ok_or(RestError::Configuration)?;
        if text.is_empty() || !template.contains(&placeholder) {
            return Err(RestError::Configuration);
        }
        let marker = format!("\0{index}\0");
        template = template.replace(&placeholder, &marker);
        filled.push(TextPathValue {
            marker,
            name: name.clone(),
            encoded: percent_encode_component(&text),
        });
    }
    Ok((template, filled, Value::Object(remaining)))
}

/// Remove the operation's header-parameter arguments from `remaining` and
/// return them as headers. An absent or null argument sends no header. A
/// value that is not a scalar, or not one line of visible ASCII, refuses the
/// request: sending it elsewhere or dropping it would change the search.
fn take_header_parameters(
    operation: &HttpOperation,
    remaining: &mut Map<String, Value>,
) -> Result<Vec<(reqwest::header::HeaderName, HeaderValue)>, RestError> {
    let mut headers = Vec::new();
    for (argument, header) in operation.header_parameters.iter().flatten() {
        let value = match remaining.remove(argument) {
            None | Some(Value::Null) => continue,
            Some(value) => value,
        };
        let text = scalar_to_string(&value).ok_or(RestError::Configuration)?;
        let name = reqwest::header::HeaderName::from_bytes(header.as_bytes())
            .map_err(|_| RestError::Configuration)?;
        if text.is_empty()
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            return Err(RestError::Configuration);
        }
        let value = HeaderValue::from_str(&text).map_err(|_| RestError::Configuration)?;
        headers.push((name, value));
    }
    Ok(headers)
}

fn reqwest_method(method: HttpMethod) -> reqwest::Method {
    match method {
        HttpMethod::Get => reqwest::Method::GET,
        HttpMethod::Post => reqwest::Method::POST,
        HttpMethod::Put => reqwest::Method::PUT,
        HttpMethod::Patch => reqwest::Method::PATCH,
        HttpMethod::Delete => reqwest::Method::DELETE,
    }
}

/// Substitute `{placeholders}` in the template from args (percent-encoded) and
/// return the rendered path plus the args no placeholder consumed.
fn render_path(template: &str, args: &Value) -> Result<(String, Map<String, Value>), RestError> {
    let args_object = args.as_object();
    let mut rendered = String::with_capacity(template.len());
    let mut rest = template;
    let mut consumed = BTreeSet::new();
    while let Some(open) = rest.find('{') {
        rendered.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after.find('}').ok_or(RestError::Configuration)?;
        let name = &after[..close];
        let value = args_object
            .and_then(|object| object.get(name))
            .ok_or(RestError::Configuration)?;
        let text = scalar_to_string(value).ok_or(RestError::Configuration)?;
        if text.is_empty() {
            return Err(RestError::Configuration);
        }
        // Some vendors decode escapes before routing. Reject separators and
        // nested escape spellings instead of trusting a proxy's decode order.
        let mut decoded = text.to_ascii_lowercase();
        let mut depth = 0;
        loop {
            if decoded.contains(['/', '\\']) || has_dot_segment(&decoded) {
                return Err(RestError::DotSegment);
            }
            let next = decoded
                .replace("%25", "%")
                .replace("%2f", "/")
                .replace("%5c", "\\")
                .replace("%2e", ".");
            if next == decoded {
                break;
            }
            if depth == 8 {
                return Err(RestError::DotSegment);
            }
            depth += 1;
            decoded = next;
        }
        rendered.push_str(&percent_encode_component(&text));
        consumed.insert(name.to_string());
        rest = &after[close + 1..];
    }
    rendered.push_str(rest);
    let mut remaining = Map::new();
    if let Some(object) = args_object {
        for (key, value) in object {
            if !consumed.contains(key) {
                remaining.insert(key.clone(), value.clone());
            }
        }
    }
    Ok((rendered, remaining))
}

/// Whether a rendered path has a segment the URL parser treats as `.` or `..`.
///
/// Percent-encoding cannot neutralise these: the parser also reads `%2e` as a
/// dot, so `/repos/{repo}/issues` with `repo = ".."` would be resolved to
/// `/issues`, an endpoint nobody reviewed.
fn has_dot_segment(path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    path.split('/').any(|segment| {
        let segment = segment.to_ascii_lowercase().replace("%2e", ".");
        segment == "." || segment == ".."
    })
}

fn scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// Percent-encode one value for use inside a path segment or query parameter.
/// Only RFC 3986 unreserved characters pass through; in particular `/`, `?`,
/// `#`, `&`, and `=` are encoded, so an argument value can never change the
/// path structure or inject extra query parameters.
fn percent_encode_component(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push('%');
                encoded.push_str(&format!("{byte:02X}"));
            }
        }
    }
    encoded
}

fn append_query(url: &mut String, args: &Map<String, Value>) {
    if args.is_empty() {
        return;
    }
    let mut pairs = Vec::new();
    for (key, value) in args {
        let text = match value {
            // A null argument means "not supplied". Sending it as `key=`
            // would ask the vendor for an empty value instead, which many
            // treat as a filter that matches nothing.
            Value::Null => continue,
            Value::String(_) | Value::Number(_) | Value::Bool(_) => {
                scalar_to_string(value).unwrap_or_default()
            }
            // Structured values travel as compact JSON so the argument reaches
            // the vendor rather than being dropped silently.
            _ => serde_json::to_string(value).unwrap_or_default(),
        };
        pairs.push(format!(
            "{}={}",
            percent_encode_component(key),
            percent_encode_component(&text)
        ));
    }
    if pairs.is_empty() {
        return;
    }
    url.push(if url.contains('?') { '&' } else { '?' });
    url.push_str(&pairs.join("&"));
}

/// Format the diagnostic written for a non-successful vendor HTTP response.
///
/// The path is kept separate from the rendered URL so query parameters never enter
/// this projection. Error bodies are useful explanations, but they are bounded so
/// a vendor returning an HTML page cannot fill the daemon log indefinitely.
///
/// WHY LOGGING AN ERROR BODY IS SAFE HERE AND WOULD NOT BE EVERYWHERE, checked
/// rather than assumed: a vendor error body can echo what
/// was SUBMITTED, so at an OAuth token endpoint the body may contain the refresh
/// token just sent — the vault deliberately records a typed variant name instead
/// of provider text for exactly that reason. Two structural facts make this
/// boundary different, and both are enforced rather than conventional:
///
///   1. Credential placement is HEADER-ONLY, refused at manifest ingest for any
///      other value (`manifest.rs`, an_unimplemented_credential_placement_is_rejected).
///      So no credential plexus injects appears in a request body or query, and
///      an echo of either cannot carry one.
///   2. plexus performs NO token exchange. There is no `grant_type`, no
///      `refresh_token`, no token_url on either transport — credential issuance
///      belongs to the vault, so the endpoint class whose errors quote
///      credentials is not reachable from here.
///
/// SUCCESS bodies are still never logged, which is the load-bearing half: those
/// are vendor payload and can legitimately contain secret material (a keys
/// endpoint returns keys). Only refusals reach this projection.
///
/// If either fact above changes — a non-header placement, or any exchange
/// performed here — this projection needs a redactor before it is safe.
fn vendor_error_log_line(
    transport: &str,
    method: &reqwest::Method,
    path: &str,
    status: u16,
    body: &str,
    permissions: Option<&str>,
) -> Option<String> {
    if (200..300).contains(&status) {
        return None;
    }

    let path = path.split('?').next().unwrap_or(path);
    let clipped = crate::text::prefix_within_bytes(body, REST_ERROR_BODY_CAP);
    let body_was_truncated = clipped.len() < body.len();
    let body = clipped;
    let truncation =
        body_was_truncated.then(|| format!(" [body truncated to {REST_ERROR_BODY_CAP} bytes]"));
    let permissions = permissions
        .map(|value| format!(" X-Accepted-GitHub-Permissions={value:?}"))
        .unwrap_or_default();

    Some(format!(
        "{transport} vendor error on {} {}: status={status} body={body:?}{}{permissions}",
        method.as_str(),
        path,
        truncation.as_deref().unwrap_or_default(),
    ))
}

fn accepted_github_permissions(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get("X-Accepted-GitHub-Permissions")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// HTTP 200 can still refuse a GraphQL operation. Keep permission evidence in
/// the operator log at the transport boundary, never in a vendor body or receipt.
fn graphql_permission_log_line(body: &Value, permissions: Option<&str>) -> Option<String> {
    let permissions = permissions?;
    let errors = body.get("errors")?.as_array()?;
    let permission_refused = errors.iter().any(|error| {
        error["type"].as_str() == Some("FORBIDDEN")
            || error["extensions"]["code"].as_str() == Some("FORBIDDEN")
            || error["message"].as_str().is_some_and(|message| {
                message
                    .to_ascii_lowercase()
                    .contains("resource not accessible by integration")
            })
    });
    permission_refused.then(|| {
        format!(
            "github GraphQL permission refusal X-Accepted-GitHub-Permissions={:?}",
            crate::text::prefix_within_bytes(permissions, REST_ERROR_BODY_CAP)
        )
    })
}

pub(crate) fn log_vendor_error(
    transport: &str,
    method: &reqwest::Method,
    path: &str,
    status: u16,
    body: &str,
    permissions: Option<&str>,
) -> Option<String> {
    let line = vendor_error_log_line(transport, method, path, status, body, permissions);
    if let Some(line) = &line {
        eprintln!(warn transport: "{line}");
    }
    line
}

fn log_rest_error(
    method: &reqwest::Method,
    path: &str,
    status: u16,
    body: &str,
    permissions: Option<&str>,
) -> Option<String> {
    log_vendor_error("REST", method, path, status, body, permissions)
}

/// Map a received HTTP response onto the transmission model with the same care
/// the MCP transport takes: vendor answers (including errors) are definitive,
/// a mid-body read failure is outcome-unknown.
fn classify_response(
    response: Response,
    throttle_until: &mut Option<Instant>,
    clock: &TransportClock,
    method: &reqwest::Method,
    path: &str,
    github_facade: bool,
) -> TransportResponse {
    classify_response_with_privacy(
        response,
        throttle_until,
        clock,
        method,
        path,
        github_facade,
        false,
        &[],
    )
}

/// `clock` is the connection's: a throttle the response asks for is recorded
/// as ending that long after the clock's current reading.
#[allow(clippy::too_many_arguments)]
fn classify_response_with_privacy(
    response: Response,
    throttle_until: &mut Option<Instant>,
    clock: &TransportClock,
    method: &reqwest::Method,
    path: &str,
    github_facade: bool,
    private_endpoint: bool,
    signals: &[crate::manifest::ErrorSignalRule],
) -> TransportResponse {
    let status = response.status().as_u16();
    let retry_after = response_throttle(status, response.headers());
    if let Some(delay) = retry_after.filter(|_| signals.is_empty()) {
        *throttle_until = throttle_deadline(clock.now(), delay);
        eprintln!(warn transport: "REST vendor throttle: status={status} retry_after_ms={}", duration_ms(delay));
        return crate::http_support::throttled_response("REST", delay);
    }
    let headers = response.headers().clone();
    let permissions = accepted_github_permissions(response.headers());
    let location = (!private_endpoint && (300..400).contains(&status))
        .then(|| redirect_location_for_log(response.headers()));
    let body_limit = if (200..300).contains(&status) {
        MAX_RESPONSE_BODY_BYTES
    } else {
        REST_ERROR_BODY_CAP
    };
    let body = match read_body_bounded(response, body_limit) {
        Ok(body) => body,
        // Headers arrived but the body never completed: the request was sent,
        // so the outcome is unknown. Only a real timeout is reported as one;
        // a reset or decode failure keeps its own code.
        Err(BodyReadFailure { failure, cause }) => {
            if private_endpoint {
                eprintln!(warn transport: "REST private endpoint response body failed: {failure:?}");
            } else {
                eprintln!(warn transport: "REST response body failed on {} {}: {:?}: {cause}", method, path.split('?').next().unwrap_or(path), failure);
            }
            return match failure {
                HttpAttemptFailure::Timeout => timeout_response(),
                failure => failure
                    .outcome_unknown_response()
                    .unwrap_or_else(TransportResponse::unknown),
            };
        }
    };
    if body.truncated && (200..300).contains(&status) {
        // The vendor answered, but with more than this transport will hold in
        // memory, so what it said cannot be delivered: for a write it may well
        // have succeeded.
        eprintln!(warn transport: "REST response on {} {} exceeded {MAX_RESPONSE_BODY_BYTES} bytes: status={status}", method, path.split('?').next().unwrap_or(path));
        return TransportResponse::unknown_with_error("response_too_large");
    }
    let text = body.text;
    let signal = if !(200..300).contains(&status) {
        let parsed = (!body.truncated)
            .then(|| serde_json::from_str::<Value>(&text).ok())
            .flatten();
        crate::error_signals::evaluate(signals, status, &headers, parsed.as_ref())
    } else {
        None
    };
    if let Some(delay) = retry_after {
        *throttle_until = throttle_deadline(clock.now(), delay);
        eprintln!(warn transport: "REST vendor throttle: status={status} retry_after_ms={}", duration_ms(delay));
        return crate::http_support::throttled_response("REST", delay).with_error_signal(signal);
    }
    if !(200..300).contains(&status) && !private_endpoint {
        log_rest_error(method, path, status, &text, permissions.as_deref());
    }
    if let Some(location) = location {
        // A redirect the policy declined (another origin, a method-changing
        // status on a non-GET, or too many hops). The agent sees only the
        // status; where it pointed is for the operator.
        eprintln!(warn transport: "REST redirect not followed on {} {}: status={status} location={location}", method, path.split('?').next().unwrap_or(path));
    }
    if status == 401 {
        // `http_401` is what `provider_auth_status` recognizes, allowing the
        // credential source to record an actual authentication rejection.
        return TransportResponse {
            transmission: TransmissionState::Sent,
            retryability: Retryability::Terminal,
            response: None,
            error_code: Some(format!("http_{status}")),
            error_message: Some("REST authentication was rejected".to_string()),
            vendor_request_id: None,
            served_from: None,
            observed_at_ms: None,
            retry_after_ms: None,
            error_signal: signal,
        };
    }
    if !(200..300).contains(&status) {
        if github_facade && (300..400).contains(&status) {
            return TransportResponse::vendor_error("repository_redirected")
                .with_error_signal(signal);
        }
        if status >= 500 {
            return TransportResponse::unknown_with_error(&format!("http_{status}"))
                .with_error_signal(signal);
        }
        // Without a reviewed credential signal, treat 403 as a permission refusal
        // rather than evidence that the credential itself was rejected.
        // Some vendors use 403 for revoked credentials, but such a credential
        // fails every action on its connection and connection health detects it
        // without poisoning the shared credential. Misclassifying a permission
        // refusal disables a working integration until re-authentication; leaving
        // a dead credential active costs only one more failed call before a 401.
        // Do not infer revocation from response text: that vendor-specific guess
        // would make this credential-health boundary unreliable.
        let mut result = TransportResponse::vendor_error(&format!("http_{status}"));
        if github_facade && status == 422 {
            let errors = crate::github::facade::validation::errors(&text);
            if !errors.is_empty() {
                // Only the closed structured projection travels in this internal diagnostic.
                result.error_message = Some(serde_json::json!({"errors": errors}).to_string());
            }
        }
        return result.with_error_signal(signal);
    }
    // Stacks are a public preview. Validate the status/body pairing while the
    // HTTP status is still available: a 200 null is not a dissolved stack.
    if let Some(expected) = github_facade
        .then(|| github_stack_status(method, path))
        .flatten()
    {
        let unstack = path.ends_with("/unstack");
        let valid = if unstack && status == 204 {
            text.is_empty()
        } else {
            status == expected && serde_json::from_str::<Value>(&text).is_ok_and(|v| v.is_object())
        };
        if !valid {
            return TransportResponse::unknown_with_error("github_stack_response_invalid");
        }
    }
    let body = if text.is_empty() {
        Value::Null
    } else {
        // A 2xx body that is not JSON is still a definitive vendor answer; keep
        // it as text rather than failing a call that may have succeeded.
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    if github_facade && path == "/graphql" {
        if let Some(line) = graphql_permission_log_line(&body, permissions.as_deref()) {
            eprintln!(warn transport: "{line}");
        }
    }
    // Vendor payloads stay verbatim. Guessing secrets from vendor field names
    // destroys ordinary result data; credentials travel separately in headers.
    TransportResponse::success(body)
}

/// The reviewed stack routes are the only facade endpoints whose preview
/// replies require an HTTP status check as well as the facade's body checks.
fn github_stack_status(method: &reqwest::Method, path: &str) -> Option<u16> {
    let parts: Vec<_> = path.split('/').collect();
    match parts.as_slice() {
        ["", "repos", _, _, "stacks"] if method == reqwest::Method::POST => Some(201),
        ["", "repos", _, _, "stacks", _] if method == reqwest::Method::GET => Some(200),
        ["", "repos", _, _, "stacks", _, "add" | "unstack"] if method == reqwest::Method::POST => {
            Some(200)
        }
        _ => None,
    }
}

fn local_not_sent() -> TransportResponse {
    eprintln!(warn transport: "REST request refused during local preparation");
    TransportResponse {
        transmission: TransmissionState::NotSent,
        retryability: Retryability::Terminal,
        response: None,
        error_code: Some("rest_transport_error".to_string()),
        error_message: Some("REST transport could not construct a request".to_string()),
        vendor_request_id: None,
        served_from: None,
        observed_at_ms: None,
        retry_after_ms: None,
        error_signal: None,
    }
}

fn preparation_failure(error: RestError) -> TransportResponse {
    eprintln!(warn transport: "REST request preparation failed: {error:?}");
    let mut response = local_not_sent();
    match error {
        RestError::ConstantArgument(key) => {
            response.error_code = Some("request_constant_conflict".into());
            response.error_message = Some(format!(
                "REST argument '{key}' is a reviewed request constant and must not be supplied"
            ));
        }
        RestError::DotSegment => {
            response.error_code = Some("path_argument_invalid".into());
            response.error_message =
                Some("REST path arguments must not contain path separators or dot segments".into());
        }
        _ => {}
    }
    response
}

fn rest_poisoned_lock_response() -> TransportResponse {
    let mut response = local_not_sent();
    response.error_code = Some("transport_restart_required".into());
    response.error_message = Some(
        "REST transport lock is poisoned; retry after pool recovery or restart if it persists"
            .into(),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint;
    pub(super) use crate::test_logging as logging;
    use serde_json::json;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn unregister_rest_removes_configuration_and_pooled_entry() {
        let transport = RestTransport::default();
        let connection = RestConnection::new("removed", "http://127.0.0.1:1");
        transport.register_connection(connection.clone());
        transport.entry_for("removed", &connection.config).unwrap();
        assert!(transport.has_connection("removed"));
        transport.unregister_connection("removed");
        assert!(!transport.has_connection("removed"));
        assert!(transport.configs.lock().unwrap().is_empty());
        assert_eq!(transport.connection_count(), 0);
    }

    #[test]
    fn rest_throttle_and_checkout_survive_idle_sweep() {
        let transport = RestTransport::default();
        let cfg = config(
            "http://127.0.0.1:1".into(),
            vec![("read", http_op(HttpMethod::Get, "/"))],
        );
        let entry = transport.entry_for("leased", &cfg).unwrap();
        entry.lock().unwrap().last_used = Instant::now() - Duration::from_secs(600);
        assert_eq!(
            transport.sweep_idle(),
            0,
            "a checked-out entry is a lease before its request lock is acquired"
        );
        entry.lock().unwrap().throttle_until = Some(Instant::now() + Duration::from_secs(3600));
        drop(entry);
        assert_eq!(
            transport.sweep_idle(),
            0,
            "an active throttle must survive idle eviction"
        );
        assert_eq!(transport.connection_count(), 1);
    }

    #[test]
    fn debug_rest_transport_does_not_wait_for_its_entries_lock() {
        let transport = Arc::new(RestTransport::default());
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
    fn poisoned_rest_locks_report_restart_required_not_sent() {
        for poison_map in [false, true] {
            let cfg = config(
                "http://127.0.0.1:1".into(),
                vec![("read", http_op(HttpMethod::Get, "/"))],
            );
            let transport = RestTransport::new(cfg.clone());
            let entry = transport.entry_for("poisoned", &cfg).unwrap();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if poison_map {
                    let _lock = transport.entries.lock().unwrap();
                    panic!("poison pool");
                } else {
                    let _lock = entry.lock().unwrap();
                    panic!("poison entry");
                }
            }));
            let result = transport.dispatch(
                request("poisoned", "read", json!({})),
                &ResolvedCredential::anonymous(),
            );
            assert_eq!(result.transmission, TransmissionState::NotSent);
            assert_eq!(result.retryability, Retryability::Terminal);
            assert!(
                result
                    .error_message
                    .as_deref()
                    .unwrap()
                    .starts_with("REST transport lock is poisoned"),
                "REST lock failures must name the REST transport"
            );
            assert_eq!(
                result.error_code.as_deref(),
                Some("transport_restart_required")
            );
        }
    }

    #[test]
    fn empty_rest_path_placeholder_is_refused_locally() {
        assert!(
            render_path(
                "/repos/{owner}/{repo}/issues",
                &json!({"owner":"cortexkit", "repo":""})
            )
            .is_err(),
            "empty placeholder must not create an unintended path"
        );
        let cfg = config(
            "http://127.0.0.1:1".into(),
            vec![("read", http_op(HttpMethod::Get, "/repos/{repo}"))],
        );
        let result = RestTransport::new(cfg).dispatch(
            request("empty", "read", json!({"repo":""})),
            &ResolvedCredential::anonymous(),
        );
        assert_eq!(result.transmission, TransmissionState::NotSent);
        assert_eq!(result.retryability, Retryability::Terminal);
    }

    /// In-process HTTP server mirroring the MCP test pattern: serves `requests`
    /// sequential requests through a handler that sees the raw request text and
    /// returns a raw HTTP response. The base URL has no path suffix.
    pub(super) fn start_server<F>(
        requests: usize,
        handler: F,
    ) -> (String, crate::test_http::FixedRequestServer)
    where
        F: Fn(usize, &str) -> String + Send + 'static,
    {
        crate::test_http::FixedRequestServer::start(requests, "REST", handler)
    }

    fn http_response(status: u16, body: &str) -> String {
        let crlf = "\r\n";
        format!(
            "HTTP/1.1 {status}{crlf}Content-Type: application/json{crlf}Content-Length: {}{crlf}Connection: close{crlf}{crlf}{body}",
            body.len()
        )
    }

    fn request_line(request: &str) -> &str {
        request.lines().next().unwrap_or("")
    }

    #[test]
    fn pr_ready_caller_query_conflicts_with_reviewed_constant() {
        let mut operation = http_op(HttpMethod::Post, "/graphql");
        operation.request_constants = Some(std::collections::BTreeMap::from([(
            "query".into(),
            json!("reviewed query"),
        )]));
        for query in ["caller query", "reviewed query"] {
            let prepared = prepare_request(
                "https://api.github.com",
                &operation,
                &json!({"owner":"org","repo":"repo","variables":{"pullRequestId":"PR_7"},"query":query}),
            );
            assert!(matches!(prepared, Err(RestError::ConstantArgument(key)) if key == "query"));
        }
    }

    #[test]
    fn graphql_post_strips_repository_context_for_non_pr_actions() {
        let (endpoint, task) = start_server(1, |_, received| {
            assert_eq!(request_line(received), "POST /graphql HTTP/1.1");
            let body: Value =
                serde_json::from_str(received.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(
                body,
                json!({"query":"reviewed project mutation", "variables":{"projectId":"P_1"}})
            );
            http_response(200, r#"{"data":{"project":{"id":"P_1"}}}"#)
        });
        let mut operation = http_op(HttpMethod::Post, "/graphql");
        operation.request_constants = Some(std::collections::BTreeMap::from([(
            "query".into(),
            json!("reviewed project mutation"),
        )]));
        let transport = RestTransport::new(config(endpoint, vec![("update_project", operation)]));
        let result = transport.dispatch(
            request(
                "rest",
                "update_project",
                json!({"owner":"org","repo":"repo","variables":{"projectId":"P_1"}}),
            ),
            &ResolvedCredential::anonymous(),
        );
        assert_eq!(result.response.unwrap()["data"]["project"]["id"], "P_1");
        task.join()
            .expect("non-PR GraphQL operation reached the wire");

        for (method, path) in [
            (HttpMethod::Post, "/other"),
            (HttpMethod::Patch, "/graphql"),
        ] {
            let args = json!({"owner":"org","repo":"repo"});
            assert_eq!(
                prepare_request("https://api.github.com", &http_op(method, path), &args)
                    .unwrap()
                    .body,
                Some(args)
            );
        }
        let get = prepare_request(
            "https://api.github.com",
            &http_op(HttpMethod::Get, "/graphql"),
            &json!({"owner":"org","repo":"repo"}),
        )
        .unwrap();
        assert_eq!(
            get.url,
            "https://api.github.com/graphql?owner=org&repo=repo"
        );
    }

    /// A GET whose whole path is a free-text search query and whose site
    /// filter and a fixed option travel as headers, as Jina's search does.
    fn text_path_search_op() -> HttpOperation {
        let mut operation = http_op(HttpMethod::Get, "/{q}");
        operation.text_path_parameters = Some(vec!["q".into()]);
        operation.header_parameters = Some(std::collections::BTreeMap::from([
            ("site".to_string(), "X-Site".to_string()),
            ("respond_with".to_string(), "X-Respond-With".to_string()),
        ]));
        operation.request_constants = Some(std::collections::BTreeMap::from([(
            "respond_with".into(),
            json!("no-content"),
        )]));
        operation
    }

    #[test]
    fn a_free_text_path_value_is_one_encoded_segment_and_never_logged() {
        let prepared = prepare_request(
            "https://s.example",
            &text_path_search_op(),
            &json!({"q": "a/b\\c?d=e#f %2e{q}", "count": 3, "site": "jina.ai"}),
        )
        .unwrap();
        assert_eq!(
            prepared.url, "https://s.example/a%2Fb%5Cc%3Fd%3De%23f%20%252e%7Bq%7D?count=3",
            "every reserved character is escaped, so the value stays one path segment"
        );
        assert_eq!(
            prepared.path, "/{q}",
            "the diagnostic path names the placeholder, never the text"
        );
        assert_eq!(prepared.body, None);
        let headers: Vec<(String, String)> = prepared
            .headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_string()))
            .collect();
        assert_eq!(
            headers,
            [
                ("x-respond-with".to_string(), "no-content".to_string()),
                ("x-site".to_string(), "jina.ai".to_string()),
            ],
            "header arguments and constants become headers, not query parameters"
        );
    }

    #[test]
    fn a_free_text_path_value_that_is_a_dot_segment_is_refused() {
        for q in [".", ".."] {
            assert!(
                matches!(
                    prepare_request(
                        "https://s.example",
                        &text_path_search_op(),
                        &json!({"q": q})
                    ),
                    Err(RestError::DotSegment)
                ),
                "{q} would resolve to another path"
            );
        }
        // An ordinary placeholder still refuses a separator.
        assert!(matches!(
            prepare_request(
                "https://s.example",
                &http_op(HttpMethod::Get, "/{q}"),
                &json!({"q": "a/b"})
            ),
            Err(RestError::DotSegment)
        ));
        assert!(
            matches!(
                prepare_request(
                    "https://s.example",
                    &text_path_search_op(),
                    &json!({"count": 3})
                ),
                Err(RestError::Configuration)
            ),
            "a missing free-text value is refused"
        );
    }

    #[test]
    fn header_arguments_are_one_visible_ascii_line_or_absent() {
        let operation = text_path_search_op();
        for site in [json!(null), json!("jina.ai")] {
            let prepared = prepare_request(
                "https://s.example",
                &operation,
                &json!({"q": "x", "site": site}),
            )
            .unwrap();
            assert_eq!(
                prepared
                    .headers
                    .iter()
                    .any(|(name, _)| name.as_str() == "x-site"),
                !site.is_null(),
                "a null header argument sends no header"
            );
            assert_eq!(prepared.url, "https://s.example/x");
        }
        for site in [
            json!("a\r\nX-Injected: 1"),
            json!("é.example"),
            json!(""),
            json!(["a"]),
        ] {
            assert!(
                matches!(
                    prepare_request(
                        "https://s.example",
                        &operation,
                        &json!({"q": "x", "site": site})
                    ),
                    Err(RestError::Configuration)
                ),
                "{site} must be refused"
            );
        }
        assert!(
            matches!(
                prepare_request(
                    "https://s.example",
                    &operation,
                    &json!({"q": "x", "respond_with": "markdown"})
                ),
                Err(RestError::ConstantArgument(key)) if key == "respond_with"
            ),
            "a caller cannot replace a constant header"
        );
    }

    #[test]
    fn a_text_path_search_reaches_the_wire_with_its_headers() {
        let (endpoint, task) = start_server(1, |_, received| {
            assert_eq!(request_line(received), "GET /two%20words?count=2 HTTP/1.1");
            let lower = received.to_ascii_lowercase();
            assert!(lower.contains("\r\nx-site: jina.ai\r\n"), "{received}");
            assert!(
                lower.contains("\r\nx-respond-with: no-content\r\n"),
                "{received}"
            );
            assert!(
                lower.contains("\r\nauthorization: bearer key\r\n"),
                "{received}"
            );
            http_response(200, r#"{"data":[]}"#)
        });
        let transport =
            RestTransport::new(config(endpoint, vec![("search", text_path_search_op())]));
        let result = transport.dispatch(
            request(
                "rest",
                "search",
                json!({"q": "two words", "count": 2, "site": "jina.ai"}),
            ),
            &ResolvedCredential::new(b"key".to_vec(), None, 1),
        );
        task.join().expect("the search reached the wire");
        assert_eq!(result.response, Some(json!({"data": []})));
    }

    #[test]
    fn a_header_argument_never_replaces_a_credential_header() {
        let mut operation = http_op(HttpMethod::Get, "/search");
        operation.header_parameters = Some(std::collections::BTreeMap::from([(
            "token".to_string(),
            "Authorization".to_string(),
        )]));
        let transport = RestTransport::new(config(
            "http://127.0.0.1:9".into(),
            vec![("search", operation)],
        ));
        let result = transport.dispatch(
            request("rest", "search", json!({"token": "Bearer other"})),
            &ResolvedCredential::new(b"key".to_vec(), None, 1),
        );
        // Nothing listens on the discard port, so a request that was built
        // and sent would fail to connect with a different error code.
        assert_eq!(result.transmission, TransmissionState::NotSent);
        assert_eq!(
            result.error_code.as_deref(),
            Some("rest_transport_error"),
            "a header argument must not replace the credential header"
        );
    }

    #[test]
    fn pr_ready_api_redirect_never_sends_bot_token_to_another_host() {
        let (elsewhere, elsewhere_base) = unserved_listener();
        let location = format!(
            "{}/collect",
            elsewhere_base.replace("127.0.0.1", "localhost")
        );
        let (endpoint, task) = start_server(1, move |_, received| {
            assert!(received
                .to_ascii_lowercase()
                .contains("authorization: bearer bot-canary"));
            raw_response(
                "307 Temporary Redirect",
                &format!("Location: {location}\r\n"),
                "",
            )
        });
        let mut operation = http_op(HttpMethod::Post, "/graphql");
        operation.request_constants = Some(std::collections::BTreeMap::from([(
            "query".into(),
            json!("reviewed query"),
        )]));
        // The loopback server stands in for the catalog's fixed api.github.com
        // endpoint. Redirect handling must not forward the credential to any
        // other origin, even when the redirect preserves the POST method.
        let transport = RestTransport::new(
            config(endpoint, vec![("mark_pull_request_ready", operation)]).with_bindings(vec![
                CredentialBinding {
                    ref_role: "access_token".into(),
                    placement: "header".into(),
                    key: "Authorization".into(),
                    prefix: "Bearer ".into(),
                    required: true,
                },
            ]),
        );
        let result = transport.dispatch_github_facade(
            request(
                "rest",
                "mark_pull_request_ready",
                json!({"owner":"org","repo":"repo","variables":{"pullRequestId":"PR_7"}}),
            ),
            &ResolvedCredential::new(b"bot-canary".to_vec(), None, 1),
        );
        task.join().expect("API received one request");
        assert_never_contacted(&elsewhere);
        assert_eq!(result.error_code.as_deref(), Some("repository_redirected"));
    }

    pub(super) fn http_op(method: HttpMethod, path: &str) -> HttpOperation {
        HttpOperation {
            method,
            parameters: None,
            path: path.to_string(),
            args_schema: json!({"type": "object"}),
            request_constants: None,
            credentialless_tail: None,
            text_path_parameters: None,
            header_parameters: None,
        }
    }

    pub(super) fn config(base_url: String, actions: Vec<(&str, HttpOperation)>) -> RestConfig {
        RestConfig::new(base_url)
            .with_bindings(vec![CredentialBinding {
                ref_role: "credential".to_string(),
                placement: "header".to_string(),
                key: "authorization".to_string(),
                prefix: "Bearer ".to_string(),
                required: true,
            }])
            .with_actions(
                actions
                    .into_iter()
                    .map(|(name, op)| (name.to_string(), op))
                    .collect(),
            )
    }

    pub(super) fn request(connection_id: &str, action: &str, args: Value) -> TransportRequest {
        TransportRequest {
            request_id: "request-1".to_string(),
            connection_id: connection_id.to_string(),
            action: action.to_string(),
            args,
            credential_fingerprint: fingerprint(b"CANARY"),
        }
    }

    #[test]
    fn null_args_without_request_constants_still_reach_the_wire() {
        let (endpoint, task) = start_server(1, |_index, received| {
            assert_eq!(request_line(received), "GET /v1/ping HTTP/1.1");
            http_response(200, r#"{"ok":true}"#)
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![("ping", http_op(HttpMethod::Get, "/v1/ping"))],
        ));
        let response = transport.dispatch(
            request("rest", "ping", Value::Null),
            &ResolvedCredential::new(b"token".to_vec(), None, 1),
        );
        assert_eq!(
            response.response.expect("null args must still dispatch")["ok"],
            true
        );
        task.join().expect("no-argument request reached the vendor");
    }

    #[test]
    fn null_args_with_request_constants_use_an_empty_object() {
        let (endpoint, task) = start_server(1, |_index, received| {
            assert_eq!(request_line(received), "GET /v1/runs?per_page=100 HTTP/1.1");
            http_response(200, r#"{"ok":true}"#)
        });
        let mut operation = http_op(HttpMethod::Get, "/v1/runs");
        operation.request_constants = Some(std::collections::BTreeMap::from([(
            "per_page".into(),
            json!(100),
        )]));
        let transport = RestTransport::new(config(endpoint, vec![("list_runs", operation)]));
        let response = transport.dispatch(
            request("rest", "list_runs", Value::Null),
            &ResolvedCredential::new(b"token".to_vec(), None, 1),
        );
        assert_eq!(
            response.response.expect("constants supply the empty args")["ok"],
            true
        );
        task.join().expect("request constants reached the vendor");
    }

    #[test]
    fn http_request_constants_reach_the_query_and_body_on_the_wire() {
        let (endpoint, task) = start_server(2, |index, received| {
            if index == 0 {
                assert_eq!(
                    request_line(received),
                    "GET /v1/runs?page=2&per_page=100 HTTP/1.1"
                );
            } else {
                assert_eq!(request_line(received), "POST /v1/runs HTTP/1.1");
                let body = received.split_once("\r\n\r\n").unwrap().1;
                assert_eq!(
                    serde_json::from_str::<Value>(body).unwrap(),
                    json!({"page": 2, "per_page": 100})
                );
            }
            http_response(200, r#"{"ok":true}"#)
        });
        for (action, method) in [
            ("list_runs", HttpMethod::Get),
            ("post_runs", HttpMethod::Post),
        ] {
            let mut operation = http_op(method, "/v1/runs");
            operation.request_constants = Some(std::collections::BTreeMap::from([(
                "per_page".into(),
                json!(100),
            )]));
            let transport = RestTransport::new(config(endpoint.clone(), vec![(action, operation)]));
            let response = transport.dispatch(
                request("rest", action, json!({"page": 2})),
                &ResolvedCredential::new(b"token".to_vec(), None, 1),
            );
            assert_eq!(response.response.unwrap()["ok"], true);
        }
        task.join().expect("both wire requests completed");
    }

    #[test]
    fn caller_or_cursor_constant_collisions_are_named_and_send_nothing() {
        // A final allowed request proves the server is reachable and that only
        // one request arrived: neither the equal nor unequal override was sent.
        let (endpoint, task) = start_server(1, |_index, received| {
            assert_eq!(
                request_line(received),
                "GET /v1/runs?page=2&per_page=100 HTTP/1.1"
            );
            http_response(200, r#"{"ok":true}"#)
        });
        let mut operation = http_op(HttpMethod::Get, "/v1/runs");
        operation.request_constants = Some(std::collections::BTreeMap::from([(
            "per_page".into(),
            json!(100),
        )]));
        let transport = RestTransport::new(config(endpoint, vec![("list_runs", operation)]));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        for page_size in [100, 1] {
            let response = transport.dispatch(
                request(
                    "rest",
                    "list_runs",
                    json!({"per_page": page_size, "page": 2}),
                ),
                &credential,
            );
            assert_eq!(response.transmission, TransmissionState::NotSent);
            assert_eq!(
                response.error_code.as_deref(),
                Some("request_constant_conflict")
            );
            assert!(response.error_message.unwrap().contains("'per_page'"));
            assert!(response.response.is_none());
        }
        let response = transport.dispatch(
            request("rest", "list_runs", json!({"page": 2})),
            &credential,
        );
        assert_eq!(response.response.unwrap()["ok"], true);
        task.join()
            .expect("only the allowed request reached the vendor");
    }

    /// Every outbound request carries a `User-Agent`, asserted ON THE WIRE.
    ///
    /// Setting `.user_agent(..)` on the client builder is a DECISION; this test
    /// is the enforcement. `reqwest` sends no User-Agent by default, and GitHub's
    /// REST API refuses such a request with a 403 whose status is
    /// indistinguishable from a permissions failure.
    ///
    /// Asserted as the received request text rather than by reading the config
    /// back, because a config that holds the right value and a request that
    /// carries it are different propositions, and only the second one is what a
    /// vendor sees.
    #[test]
    fn every_request_carries_a_user_agent_header() {
        let (endpoint, task) = start_server(1, |_index, request| {
            let lowered = request.to_ascii_lowercase();
            assert!(
                lowered.contains("user-agent: ck-plexus/"),
                "a request with no User-Agent is refused by GitHub with a 403 \
                 that reads as a permissions failure; received request was: {request}"
            );
            http_response(200, r#"{"ok":true}"#)
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![("ping", http_op(HttpMethod::Get, "/v1/ping"))],
        ));
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
        let result = transport.dispatch(request("rest", "ping", json!({})), &credential);
        assert_eq!(
            result.response.expect("successful REST call")["ok"],
            true,
            "the mock refuses the request when the header is absent"
        );
        task.join().expect("server exits");
    }

    #[test]
    fn get_uses_path_parameter_and_query_for_remaining_args() {
        let (endpoint, task) = start_server(1, |_index, request| {
            assert_eq!(
                request_line(request),
                "GET /v1/issues/42?expand=comments&team=core HTTP/1.1"
            );
            assert!(request
                .to_ascii_lowercase()
                .contains("authorization: bearer canary"));
            http_response(200, r#"{"id":"42"}"#)
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![(
                "get_issue",
                http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
            )],
        ));
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
        let result = transport.dispatch(
            request(
                "rest",
                "get_issue",
                json!({"issue_id": "42", "team": "core", "expand": "comments"}),
            ),
            &credential,
        );
        assert_eq!(result.response.expect("successful REST call")["id"], "42");
        task.join().expect("server exits");
    }

    #[test]
    fn path_parameter_value_is_percent_encoded() {
        let (endpoint, task) = start_server(1, |_index, request| {
            // Query and fragment delimiters remain data inside the segment.
            assert_eq!(request_line(request), "GET /v1/issues/ab%3Fc%23d HTTP/1.1");
            http_response(200, r#"{"ok":true}"#)
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![(
                "get_issue",
                http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
            )],
        ));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let result = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "ab?c#d"})),
            &credential,
        );
        assert!(result.response.is_some());
        task.join().expect("server exits");
    }

    #[test]
    fn post_puts_remaining_args_in_a_json_body() {
        let (endpoint, task) = start_server(1, |_index, request| {
            assert_eq!(request_line(request), "POST /v1/issues HTTP/1.1");
            let lower = request.to_ascii_lowercase();
            assert!(lower.contains("content-type: application/json"));
            let body_start = request.find("\r\n\r\n").expect("body") + 4;
            let body: Value = serde_json::from_str(&request[body_start..]).expect("JSON body");
            assert_eq!(body, json!({"team": "core", "title": "hello"}));
            http_response(200, r#"{"id":"new-1"}"#)
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![("create_issue", http_op(HttpMethod::Post, "/v1/issues"))],
        ));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let result = transport.dispatch(
            request(
                "rest",
                "create_issue",
                json!({"team": "core", "title": "hello"}),
            ),
            &credential,
        );
        assert_eq!(result.response.expect("successful POST")["id"], "new-1");
        task.join().expect("server exits");
    }

    #[test]
    fn anonymous_credential_sends_no_authorization_header() {
        let (endpoint, task) = start_server(1, |_index, request| {
            assert!(
                !request.to_ascii_lowercase().contains("authorization:"),
                "anonymous credential must not emit a prefix-only header"
            );
            http_response(200, r#"{"ok":true}"#)
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![(
                "get_issue",
                http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
            )],
        ));
        let result = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
            &ResolvedCredential::anonymous(),
        );
        assert!(result.response.is_some());
        task.join().expect("server exits");
    }

    #[test]
    fn invalid_request_diagnostic_is_not_sent_through_rest() {
        let transport = RestTransport::new(config(
            "not a valid URL".to_string(),
            vec![("get_issue", http_op(HttpMethod::Get, "/v1/issues"))],
        ));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let result = transport.dispatch(request("rest", "get_issue", json!({})), &credential);

        assert_eq!(
            (result.transmission, result.error_code.as_deref()),
            (TransmissionState::NotSent, Some("http_request_invalid"))
        );
    }

    #[test]
    fn connect_failure_is_definitively_not_sent() {
        // Bind and immediately drop a listener so the port refuses connections.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let transport = RestTransport::new(config(
            format!("http://{address}"),
            vec![(
                "get_issue",
                http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
            )],
        ));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let result = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
            &credential,
        );
        assert_eq!(result.transmission, TransmissionState::NotSent);
        assert_eq!(result.retryability, Retryability::AutoRetryable);
    }

    #[test]
    fn timeout_after_the_request_was_written_is_outcome_unknown() {
        let (endpoint, task) = start_server(1, |_index, _request| {
            // The request was fully read before this sleep, so the timeout fires
            // after the write: the vendor may have acted on it.
            std::thread::sleep(Duration::from_millis(150));
            http_response(200, r#"{"ok":true}"#)
        });
        let mut rest_config = config(
            endpoint,
            vec![(
                "get_issue",
                http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
            )],
        );
        rest_config.request_timeout = Duration::from_millis(40);
        let transport = RestTransport::new(rest_config);
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let result = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
            &credential,
        );
        assert_eq!(result.transmission, TransmissionState::OutcomeUnknown);
        assert_eq!(result.retryability, Retryability::Terminal);
        assert_eq!(result.error_code.as_deref(), Some("timeout"));
        task.join().expect("server exits");
    }

    #[test]
    fn throttle_is_returned_as_throttle_retryability_and_honored() {
        // The transport waits on the manual clock, which moves only when
        // slept on, and the vendor stamps each arrival with the same clock:
        // the time between the second call starting and the vendor receiving
        // it is the wait the transport made.
        let clock = TransportClock::manual();
        let vendor_clock = clock.clone();
        let (arrived, arrivals) = std::sync::mpsc::channel();
        let (endpoint, task) = start_server(2, move |index, _request| {
            if index == 0 {
                let crlf = "\r\n";
                return format!(
                    "HTTP/1.1 429 Too Many Requests{crlf}Content-Type: application/json{crlf}Retry-After: 1{crlf}Content-Length: 2{crlf}Connection: close{crlf}{crlf}{{}}"
                );
            }
            arrived
                .send(vendor_clock.now())
                .expect("record next vendor send");
            http_response(200, r#"{"ok":true}"#)
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![(
                "get_issue",
                http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
            )],
        ))
        .with_clock(clock.clone());
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let first = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
            &credential,
        );
        assert_eq!(first.retryability, Retryability::Throttle);
        assert_eq!(
            first.retry_after_ms,
            Some(1_000),
            "the vendor's delay reaches the caller as a number, not only as prose"
        );
        let started = clock.now();
        let second = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
            &credential,
        );
        let received_at = arrivals
            .recv_timeout(crate::bounded::WAIT)
            .expect("second request reached the vendor");
        assert!(
            received_at.duration_since(started) >= Duration::from_millis(900),
            "retry-after must be honored before the next call"
        );
        assert!(second.response.is_some());
        task.join().expect("server exits");
    }

    /// A transport built for production reads the real clock. A manual clock
    /// advances at once when slept on, so in production it would let every
    /// throttle wait pass instantly.
    #[test]
    fn a_new_rest_transport_reads_the_real_clock() {
        let transport = RestTransport::default();
        let before = Instant::now();
        thread::sleep(Duration::from_millis(5));
        let read = transport.clock.now();
        assert!(
            read >= before + Duration::from_millis(5) && read <= Instant::now(),
            "the transport clock must be the real one"
        );
    }

    #[test]
    fn unauthorized_response_maps_to_the_provider_http_status() {
        let (endpoint, task) = start_server(1, |_index, _request| {
            http_response(401, r#"{"error":"unauthorized"}"#)
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![(
                "get_issue",
                http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
            )],
        ));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let result = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
            &credential,
        );
        assert_eq!(result.transmission, TransmissionState::Sent);
        assert_eq!(result.retryability, Retryability::Terminal);
        assert_eq!(result.provider_auth_status(), Some(401));
        task.join().expect("server exits");
    }

    #[test]
    fn forbidden_response_is_a_terminal_vendor_failure_without_auth_reporting() {
        let (endpoint, task) = start_server(1, |_index, _request| {
            http_response(
                403,
                r#"{"message":"Resource not accessible by integration"}"#,
            )
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![(
                "add_reaction",
                http_op(HttpMethod::Post, "/v1/issues/{issue_id}/reactions"),
            )],
        ));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let result = transport.dispatch(
            request("rest", "add_reaction", json!({"issue_id": "1"})),
            &credential,
        );
        assert_eq!(result.transmission, TransmissionState::Sent);
        assert_eq!(result.retryability, Retryability::Terminal);
        assert_eq!(result.error_code.as_deref(), Some("http_403"));
        assert_eq!(
            result.error_message.as_deref(),
            Some(crate::transport::OPERATOR_DIAGNOSTIC_MESSAGE)
        );
        assert_eq!(result.provider_auth_status(), None);
        assert!(result.response.is_none());
        task.join().expect("server exits");
    }

    #[test]
    fn vendor_error_status_writes_operator_stderr() {
        const TEST: &str = "rest_api::tests::vendor_error_status_writes_operator_stderr";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
            logging::init_child();
            let (endpoint, task) = start_server(1, |_index, _request| {
                http_response(
                    503,
                    r#"{"error":"ghs_SECRET123 https://example.test/?token=abc"}"#,
                )
            });
            let transport = RestTransport::new(config(
                endpoint,
                vec![(
                    "get_issue",
                    http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
                )],
            ));
            let result = transport.dispatch(
                request("rest", "get_issue", json!({"issue_id": "1"})),
                &ResolvedCredential::new(b"credential".to_vec(), None, 1),
            );
            assert_eq!(result.error_code.as_deref(), Some("http_503"));
            task.join().expect("server exits");
            return;
        }
        let output = crate::test_http::bounded::child_test_output(
            TEST,
            &[("PLEXUS_LOG_STDERR_CHILD", "1")],
            std::time::Duration::from_secs(30),
            "REST diagnostic test child",
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        let line = stderr
            .lines()
            .find(|line| line.contains("vendor error on"))
            .expect("operator diagnostic on stderr");
        assert!(line.contains("REST vendor error on"), "{stderr}");
        assert!(!line.contains("MCP vendor error on"), "{stderr}");
        let parsed = cortexkit_log::parse_line(line).expect("fleet log line");
        assert_eq!(parsed.level, cortexkit_log::ParsedLevel::Warn);
        assert_eq!(parsed.logger, "plexus.transport");
        assert!(line.contains("status=503"), "{stderr}");
        assert!(line.contains("[REDACTED]"), "{stderr}");
        assert!(stderr.contains("GET /v1/issues/1"), "{stderr}");
    }

    #[test]
    fn vendor_error_status_maps_to_a_vendor_failure() {
        let (endpoint, task) = start_server(1, |_index, _request| {
            http_response(
                404,
                r#"{"error":"ghs_SECRET123 https://example.test/?token=abc"}"#,
            )
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![(
                "get_issue",
                http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
            )],
        ));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let result = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
            &credential,
        );
        assert_eq!(result.transmission, TransmissionState::Sent);
        assert_eq!(result.retryability, Retryability::Terminal);
        assert_eq!(result.error_code.as_deref(), Some("http_404"));
        let message = result.error_message.as_deref().expect("agent error text");
        assert!(message.contains("ck module logs plexus"), "{message}");
        assert!(!message.contains("ghs_SECRET123"), "{message}");
        assert!(!message.contains("?token=abc"), "{message}");
        assert!(result.response.is_none());
        task.join().expect("server exits");
    }

    #[test]
    fn forbidden_response_body_reaches_the_rest_error_log_path() {
        let line = log_rest_error(
            &reqwest::Method::POST,
            "/v1/issues/42?token=CANARY",
            403,
            r#"{"message":"Resource not accessible by integration"}"#,
            Some("issues=read,contents=write"),
        )
        .expect("non-success responses produce a diagnostic");

        assert!(line.contains("POST /v1/issues/42"));
        assert!(line.contains("status=403"));
        assert!(line.contains("Resource not accessible by integration"));
        assert!(line.contains("X-Accepted-GitHub-Permissions=\"issues=read,contents=write\""));
        assert!(
            !line.contains("token=CANARY"),
            "query parameters must not enter the daemon log: {line}"
        );
    }

    #[test]
    fn successful_response_body_is_not_selected_for_error_logging() {
        assert_eq!(
            log_rest_error(
                &reqwest::Method::GET,
                "/v1/issues?token=CANARY",
                200,
                "successful vendor payload",
                Some("issues=read"),
            ),
            None,
            "successful bodies must never reach the error logger"
        );
    }

    #[test]
    fn accepted_github_permissions_header_is_optional() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert_eq!(accepted_github_permissions(&headers), None);

        headers.insert(
            reqwest::header::HeaderName::from_static("x-accepted-github-permissions"),
            reqwest::header::HeaderValue::from_static("issues=read"),
        );
        assert_eq!(
            accepted_github_permissions(&headers).as_deref(),
            Some("issues=read")
        );
    }

    #[test]
    fn rest_error_log_truncates_and_marks_a_large_body() {
        let body = "x".repeat(REST_ERROR_BODY_CAP + 1);
        let line = vendor_error_log_line(
            "REST",
            &reqwest::Method::GET,
            "/v1/issues",
            500,
            &body,
            None,
        )
        .expect("non-success responses produce a diagnostic");

        assert!(line.contains(&format!("[body truncated to {REST_ERROR_BODY_CAP} bytes]")));
        assert!(
            !line.contains(&body),
            "the complete body must not be logged"
        );
        assert!(
            !line.contains("X-Accepted-GitHub-Permissions"),
            "an absent permissions header must not create a fabricated field"
        );
    }

    #[test]
    fn undeclared_action_is_local_not_sent() {
        let transport = RestTransport::new(config(
            "http://127.0.0.1:1".to_string(),
            vec![(
                "get_issue",
                http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
            )],
        ));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let result = transport.dispatch(request("rest", "never_declared", json!({})), &credential);
        assert_eq!(result.transmission, TransmissionState::NotSent);
        assert_eq!(result.retryability, Retryability::Terminal);
        assert_eq!(result.error_code.as_deref(), Some("rest_transport_error"));
    }

    /// A vendor response reaches the caller BYTE-FOR-BYTE.
    ///
    /// This body is the real shape of a Google Calendar incremental sync: a
    /// `nextSyncToken` cursor and an event carrying a `payload`. Both field
    /// names contain a word on the secret-key list, and both were previously
    /// replaced with a fingerprint before the caller ever saw them — silently,
    /// with nothing marking the value as redacted.
    ///
    /// The cursor case is the one that made it structural rather than
    /// cosmetic: a poller reads its next watermark out of the response, and the
    /// field holding a sync cursor is the field most likely to be named
    /// "token", so the only cursor strategy we implement could never advance
    /// against a real vendor.
    ///
    /// Mutation-proved: restoring `redact_value` on the dispatch path fails
    /// here on the cursor assertion.
    #[test]
    fn a_vendor_response_reaches_the_caller_verbatim() {
        let (endpoint, task) = start_server(1, |_index, _request| {
            http_response(
                200,
                r#"{"items":[{"id":"ev1","payload":{"summary":"Standup"}}],"nextSyncToken":"CPjq7abc"}"#,
            )
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![("list_events", http_op(HttpMethod::Get, "/v1/events"))],
        ));
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
        let result = transport.dispatch(request("rest", "list_events", json!({})), &credential);
        task.join().expect("server thread");

        let body = result.response.expect("a 2xx body reaches the caller");
        assert_eq!(
            body["nextSyncToken"], "CPjq7abc",
            "the sync cursor was rewritten in transit, so a poller can never advance: {body}"
        );
        assert_eq!(
            body["items"][0]["payload"]["summary"], "Standup",
            "a nested vendor field was rewritten in transit: {body}"
        );
    }

    #[test]
    fn debug_projection_redacts_query_and_omits_credentials() {
        let mut rest_config = config(
            "https://vendor.invalid/api?token=CANARY".to_string(),
            vec![(
                "get_issue",
                http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
            )],
        );
        rest_config.credential_bindings.push(CredentialBinding {
            ref_role: "credential".to_string(),
            placement: "header".to_string(),
            key: "x-api-key".to_string(),
            prefix: "CANARY-PREFIX".to_string(),
            required: true,
        });
        let transport = RestTransport::new(rest_config);
        let rendered = format!("{transport:?}");
        assert!(!rendered.contains("CANARY"));

        // The absence assertion above is satisfied perfectly by a projection
        // that renders NOTHING — proved by mutation: making this Debug impl
        // write an empty string passed the whole core suite. A debug projection
        // exists to be read during an incident, so "leaks nothing" is only half
        // the requirement; it must still identify which vendor and which
        // configuration the transport is holding.
        assert!(
            rendered.contains("vendor.invalid"),
            "the projection dropped the vendor host, leaving nothing to diagnose: {rendered}"
        );
        assert!(
            rendered.contains("credential_binding_count"),
            "the projection dropped the binding count: {rendered}"
        );
        assert!(
            rendered.contains("action_count"),
            "the projection dropped the action count: {rendered}"
        );
    }

    /// The mock vendor's keep-alive timeout in the pooled-connection tests.
    const VENDOR_KEEP_ALIVE: Duration = Duration::from_millis(1000);
    /// The idle gap between the two calls: longer than the vendor keeps an idle
    /// connection open, so any connection reused across it loses the race.
    const IDLE_GAP: Duration = Duration::from_millis(1300);

    /// Two GETs through one transport, `IDLE_GAP` apart, with the HTTP
    /// client's keep-alive pool limited to `pool_limit`, against a vendor that
    /// keeps connections alive for `VENDOR_KEEP_ALIVE`. Returns both results
    /// and the vendor's accepted-connection count before and after the second
    /// call.
    fn two_calls_across_an_idle_gap(
        pool_limit: Duration,
    ) -> (TransportResponse, TransportResponse, usize, usize) {
        let vendor = crate::test_http::KeepAliveServer::start(VENDOR_KEEP_ALIVE, |_request| {
            let body = r#"{"ok":true}"#;
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        });
        let mut rest_config = config(
            format!("http://{}", vendor.address()),
            vec![("ping", http_op(HttpMethod::Get, "/v1/ping"))],
        );
        rest_config.pooled_connection_idle_limit = pool_limit;
        let transport = RestTransport::new(rest_config);
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);

        let first = transport.dispatch(request("rest", "ping", json!({})), &credential);
        let before = vendor.connections();
        std::thread::sleep(IDLE_GAP);
        let second = transport.dispatch(request("rest", "ping", json!({})), &credential);
        let after = vendor.connections();
        (first, second, before, after)
    }

    /// A pooled connection idle past the client's pool limit is replaced, not
    /// reused, so a vendor that already closed it at its keep-alive timeout
    /// never sees a request on it. The REST counterpart of the MCP test of the
    /// same name; the two transports build their HTTP clients separately, so
    /// each needs its own proof.
    ///
    /// The pool limit is below the gap and the vendor's keep-alive is shorter
    /// than the gap: the ordering production has with
    /// `POOLED_CONNECTION_IDLE_LIMIT` against a vendor that drops idle
    /// connections at about 60 seconds.
    #[test]
    fn a_connection_idle_past_the_pool_limit_is_replaced_not_reused() {
        let (first, second, before, after) =
            two_calls_across_an_idle_gap(Duration::from_millis(250));
        assert_eq!(
            first.response.expect("first REST call succeeds")["ok"],
            true
        );
        assert_eq!(
            second
                .response
                .as_ref()
                .map(|response| response["ok"].clone()),
            Some(Value::Bool(true)),
            "the second call was sent on a connection the vendor had closed: {second:?}"
        );
        assert_eq!(
            (before, after),
            (1, 2),
            "each call must have used its own connection"
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
        const TEST: &str =
            "rest_api::tests::a_connection_reused_past_the_vendor_keep_alive_fails_as_production_did";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
            logging::init_child();
            let (first, second, before, after) =
                two_calls_across_an_idle_gap(Duration::from_secs(60));
            assert_eq!(
                first.response.expect("first REST call succeeds")["ok"],
                true
            );
            assert_eq!(
                (second.transmission, second.error_code.as_deref()),
                (
                    TransmissionState::OutcomeUnknown,
                    Some("http_request_failed")
                ),
                "the reused connection must fail: {second:?}"
            );
            assert_eq!(
                (before, after),
                (1, 1),
                "the failing call must have reused the first connection"
            );
            return;
        }
        let output = crate::test_http::bounded::child_test_output(
            TEST,
            &[("PLEXUS_LOG_STDERR_CHILD", "1")],
            std::time::Duration::from_secs(30),
            "REST diagnostic test child",
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        let line = stderr
            .lines()
            .find(|line| line.contains("REST transport failed on"))
            .expect("operator diagnostic on stderr");
        assert!(
            line.contains("connection closed before message completed"),
            "{stderr}"
        );
    }

    /// A raw HTTP response with extra header lines (each ending in CRLF).
    fn raw_response(status: &str, headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
            body.len()
        )
    }

    fn get_issue_transport(endpoint: String) -> RestTransport {
        RestTransport::new(config(
            endpoint,
            vec![(
                "get_issue",
                http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
            )],
        ))
    }

    /// A listener that is never served. A redirect the transport followed to
    /// it would leave a connection waiting in its accept queue.
    fn unserved_listener() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind unserved listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking unserved listener");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        (listener, base)
    }

    fn assert_never_contacted(listener: &TcpListener) {
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("a request reached the other origin"),
            Err(error) => panic!("accept on the unserved listener failed: {error}"),
        }
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
        let (endpoint, task) = start_server(1, |_index, _request| {
            raw_response(
                "429 Too Many Requests",
                "Retry-After: 18446744073709551615\r\n",
                "{}",
            )
        });
        let transport = get_issue_transport(endpoint);
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let first = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
            &credential,
        );
        assert_eq!(first.retryability, Retryability::Throttle);
        assert_eq!(first.transmission, TransmissionState::Sent);
        assert_eq!(first.retry_after_ms, Some(3_600_000), "{first:?}");

        let started = Instant::now();
        let second = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
            &credential,
        );
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
        assert_eq!(second.error_code.as_deref(), Some("throttled"));
        let remaining = second.retry_after_ms.expect("the refusal names the delay");
        assert!(
            remaining > 3_590_000 && remaining <= 3_600_000,
            "{remaining}"
        );
        task.join()
            .expect("only the throttled request reached the vendor");
    }

    /// A body that ends before its declared length is not a timeout, and is
    /// not reported as one: the operator needs to tell a vendor that hung
    /// from one that cut the connection.
    #[test]
    fn a_body_that_ends_early_is_not_reported_as_a_timeout() {
        let (endpoint, task) = start_server(1, |_index, _request| {
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"partial\":".to_string()
        });
        let transport = get_issue_transport(endpoint);
        let result = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
            &ResolvedCredential::new(b"token".to_vec(), None, 1),
        );
        task.join().expect("server exits");
        assert_eq!(result.transmission, TransmissionState::OutcomeUnknown);
        assert_ne!(
            result.error_code.as_deref(),
            Some("timeout"),
            "a cut body was labelled a timeout: {result:?}"
        );
    }

    /// A success body larger than the transport reads into memory is not
    /// delivered, and the call is outcome-unknown: the vendor answered, but
    /// what it said cannot be passed on.
    #[test]
    fn an_oversized_success_body_is_outcome_unknown() {
        let (endpoint, task) = start_server(1, |_index, _request| {
            let body = "x".repeat(MAX_RESPONSE_BODY_BYTES + 1);
            raw_response("200 OK", "", &body)
        });
        let transport = get_issue_transport(endpoint);
        let result = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
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
        assert!(result.response.is_none());
    }

    /// A path argument cannot form a `.` or `..` segment.
    ///
    /// Percent-encoding does not help: the URL parser treats `%2e` as a dot
    /// too, so `repo = ".."` turned `/v1/repos/{repo}/issues` into
    /// `/v1/issues`, an endpoint the manifest never declared. Dots inside a
    /// longer value are ordinary and still reach the wire.
    #[test]
    fn path_arguments_cannot_form_dot_segments() {
        let (endpoint, task) = start_server(1, |_index, received| {
            assert_eq!(
                request_line(received),
                "GET /v1/repos/a..b/issues HTTP/1.1",
                "only the ordinary dotted value may reach the vendor"
            );
            http_response(200, r#"{"ok":true}"#)
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![(
                "list_issues",
                http_op(HttpMethod::Get, "/v1/repos/{repo}/issues"),
            )],
        ));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        for repo in ["..", "."] {
            let response = transport.dispatch(
                request("rest", "list_issues", json!({ "repo": repo })),
                &credential,
            );
            assert_eq!(response.transmission, TransmissionState::NotSent, "{repo}");
            assert_eq!(
                response.error_code.as_deref(),
                Some("path_argument_invalid"),
                "{repo}"
            );
        }
        let response = transport.dispatch(
            request("rest", "list_issues", json!({"repo": "a..b"})),
            &credential,
        );
        assert_eq!(
            response.response.expect("dotted value dispatches")["ok"],
            true
        );
        task.join().expect("exactly one request reached the vendor");
    }

    /// A base URL that carries its own query keeps it, and the action path
    /// goes after the base path rather than inside the query.
    #[test]
    fn a_base_url_query_is_kept_after_the_action_path() {
        let (endpoint, task) = start_server(1, |_index, received| {
            assert_eq!(
                request_line(received),
                "GET /api/v1/items?version=2&q=x HTTP/1.1"
            );
            http_response(200, r#"{"ok":true}"#)
        });
        let transport = RestTransport::new(config(
            format!("{endpoint}/api?version=2"),
            vec![("list_items", http_op(HttpMethod::Get, "/v1/items"))],
        ));
        let response = transport.dispatch(
            request("rest", "list_items", json!({"q": "x"})),
            &ResolvedCredential::new(b"token".to_vec(), None, 1),
        );
        assert_eq!(response.response.expect("dispatched")["ok"], true);
        task.join().expect("server exits");
    }

    /// A null argument means "not supplied" and is left out of the query; a
    /// `cursor=` would ask the vendor for an empty value instead.
    #[test]
    fn null_arguments_are_omitted_from_the_query() {
        let (endpoint, task) = start_server(1, |_index, received| {
            assert_eq!(request_line(received), "GET /v1/items?q=x HTTP/1.1");
            http_response(200, r#"{"ok":true}"#)
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![("list_items", http_op(HttpMethod::Get, "/v1/items"))],
        ));
        let response = transport.dispatch(
            request("rest", "list_items", json!({"q": "x", "cursor": null})),
            &ResolvedCredential::new(b"token".to_vec(), None, 1),
        );
        assert_eq!(response.response.expect("dispatched")["ok"], true);
        task.join().expect("server exits");
    }

    /// Re-registering a connection with new client settings rebuilds its
    /// pooled client. Check idle eviction as well as the request timeout: the
    /// per-request deadline can enforce a new timeout even on an old client.
    #[test]
    fn a_changed_config_rebuilds_the_pooled_client() {
        let (endpoint, task) = start_server(2, |index, _request| {
            if index == 1 {
                std::thread::sleep(Duration::from_millis(400));
            }
            http_response(200, r#"{"ok":true}"#)
        });
        let ops = || {
            vec![(
                "get_issue",
                http_op(HttpMethod::Get, "/v1/issues/{issue_id}"),
            )]
        };
        let transport = RestTransport::new(RestConfig::default());
        transport.register_config("rest", config(endpoint.clone(), ops()));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let first = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
            &credential,
        );
        assert_eq!(first.response.expect("first call")["ok"], true);

        let mut short = config(endpoint, ops());
        short.request_timeout = Duration::from_millis(100);
        short.idle_timeout = Duration::from_secs(1);
        transport.register_config("rest", short);
        let second = transport.dispatch(
            request("rest", "get_issue", json!({"issue_id": "1"})),
            &credential,
        );
        assert_eq!(
            (second.transmission, second.error_code.as_deref()),
            (TransmissionState::OutcomeUnknown, Some("timeout")),
            "the new 100ms timeout must apply: {second:?}"
        );
        {
            let entries = transport.entries.lock().unwrap();
            entries["rest"].lock().unwrap().last_used = Instant::now() - Duration::from_secs(2);
        }
        assert_eq!(
            transport.sweep_idle(),
            1,
            "the rebuilt entry must use the new idle timeout"
        );
        task.join().expect("server exits");
    }

    fn api_key_config(base_url: String, actions: Vec<(&str, HttpOperation)>) -> RestConfig {
        let mut rest_config = config(base_url, actions).with_bindings(vec![CredentialBinding {
            ref_role: "credential".to_string(),
            placement: "header".to_string(),
            key: "x-api-key".to_string(),
            prefix: String::new(),
            required: true,
        }]);
        // Bounds the test if a regression follows the redirect into the
        // unserved listener, which accepts the connection but never answers.
        rest_config.request_timeout = Duration::from_secs(2);
        rest_config
    }

    /// A redirect to another origin is not followed, so a credential in a
    /// custom header (which the HTTP client strips only for `Authorization`
    /// and `Cookie`) never reaches it. The caller sees the status only.
    #[test]
    fn a_cross_origin_redirect_never_carries_the_credential_header() {
        let (elsewhere, elsewhere_base) = unserved_listener();
        let location = format!("{elsewhere_base}/collect?key=x");
        let (endpoint, task) = start_server(1, move |_index, received| {
            assert!(received.to_ascii_lowercase().contains("x-api-key: canary"));
            raw_response("302 Found", &format!("Location: {location}\r\n"), "")
        });
        let transport = RestTransport::new(api_key_config(
            endpoint,
            vec![("get_issue", http_op(HttpMethod::Get, "/v1/issues"))],
        ));
        let result = transport.dispatch(
            request("rest", "get_issue", json!({})),
            &ResolvedCredential::new(b"CANARY".to_vec(), None, 1),
        );
        task.join().expect("server exits");
        assert_never_contacted(&elsewhere);
        assert_eq!(result.error_code.as_deref(), Some("http_302"), "{result:?}");
        assert!(!format!("{result:?}").contains("collect"), "{result:?}");
    }

    /// A same-origin 307 on a write is followed with the same method and body,
    /// and the vendor sees the write once at the new location.
    #[test]
    fn a_same_origin_307_post_resends_the_body_exactly_once() {
        let (endpoint, task) = start_server(2, |index, received| {
            let body = received.split_once("\r\n\r\n").expect("body").1;
            assert_eq!(
                serde_json::from_str::<Value>(body).expect("JSON body"),
                json!({"title": "hello"})
            );
            if index == 0 {
                assert_eq!(request_line(received), "POST /v1/issues HTTP/1.1");
                return raw_response("307 Temporary Redirect", "Location: /v2/issues\r\n", "");
            }
            assert_eq!(request_line(received), "POST /v2/issues HTTP/1.1");
            http_response(201, r#"{"id":"new-1"}"#)
        });
        let transport = RestTransport::new(api_key_config(
            endpoint,
            vec![("create_issue", http_op(HttpMethod::Post, "/v1/issues"))],
        ));
        let result = transport.dispatch(
            request("rest", "create_issue", json!({"title": "hello"})),
            &ResolvedCredential::new(b"CANARY".to_vec(), None, 1),
        );
        assert_eq!(result.response.expect("followed write")["id"], "new-1");
        task.join()
            .expect("the write was sent once and redirected once");
    }

    /// A 301 on a POST is not followed: the HTTP client would resend it as a
    /// body-less GET, turning a write into a read that could report success.
    #[test]
    fn a_301_on_a_post_is_not_followed() {
        let (endpoint, task) = start_server(1, |_index, _received| {
            raw_response("301 Moved Permanently", "Location: /v2/issues\r\n", "")
        });
        let transport = RestTransport::new(api_key_config(
            endpoint,
            vec![("create_issue", http_op(HttpMethod::Post, "/v1/issues"))],
        ));
        let result = transport.dispatch(
            request("rest", "create_issue", json!({"title": "hello"})),
            &ResolvedCredential::new(b"CANARY".to_vec(), None, 1),
        );
        task.join().expect("the write was sent once");
        assert_eq!(result.transmission, TransmissionState::Sent);
        assert_eq!(result.error_code.as_deref(), Some("http_301"), "{result:?}");
    }

    /// A same-origin redirect on a read is followed, as GitHub answers a
    /// renamed repository with `301` to `/repositories/{id}` on the same host.
    #[test]
    fn a_same_origin_301_on_a_get_is_followed() {
        let (endpoint, task) = start_server(2, |index, received| {
            if index == 0 {
                return raw_response("301 Moved Permanently", "Location: /repositories/7\r\n", "");
            }
            assert_eq!(request_line(received), "GET /repositories/7 HTTP/1.1");
            assert!(received.to_ascii_lowercase().contains("x-api-key: canary"));
            http_response(200, r#"{"id":7}"#)
        });
        let transport = RestTransport::new(api_key_config(
            endpoint,
            vec![("get_repo", http_op(HttpMethod::Get, "/repos/old/name"))],
        ));
        let result = transport.dispatch(
            request("rest", "get_repo", json!({})),
            &ResolvedCredential::new(b"CANARY".to_vec(), None, 1),
        );
        assert_eq!(result.response.expect("followed read")["id"], 7);
        task.join().expect("server exits");
    }

    /// A redirect chain is followed for at most three hops; the fourth
    /// redirect is returned as the answer.
    #[test]
    fn a_redirect_chain_stops_after_three_hops() {
        let (endpoint, task) = start_server(4, |index, received| {
            assert_eq!(
                request_line(received),
                format!("GET /hop/{index} HTTP/1.1"),
                "hops are followed in order"
            );
            raw_response(
                "302 Found",
                &format!("Location: /hop/{}\r\n", index + 1),
                "",
            )
        });
        let transport = RestTransport::new(api_key_config(
            endpoint,
            vec![("chain", http_op(HttpMethod::Get, "/hop/0"))],
        ));
        let result = transport.dispatch(
            request("rest", "chain", json!({})),
            &ResolvedCredential::new(b"CANARY".to_vec(), None, 1),
        );
        task.join()
            .expect("the original request and three hops were sent");
        assert_eq!(result.error_code.as_deref(), Some("http_302"), "{result:?}");
    }

    /// Report a panic after sending a request as an unknown outcome: the vendor
    /// may have applied it even though the caller received no result. Keep the
    /// connection usable rather than leaving its mutex poisoned by the panic.
    #[test]
    fn a_panic_mid_request_reports_outcome_unknown_and_keeps_the_connection() {
        let (endpoint, task) = start_server(3, |index, received| {
            if index == 1 {
                assert_eq!(request_line(received), "POST /v1/issues HTTP/1.1");
            }
            http_response(200, r#"{"ok":true}"#)
        });
        let transport = RestTransport::new(config(
            endpoint,
            vec![("create_issue", http_op(HttpMethod::Post, "/v1/issues"))],
        ));
        let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
        let call = || {
            transport.dispatch(
                request("rest", "create_issue", json!({"title": "hello"})),
                &credential,
            )
        };
        assert_eq!(call().response.expect("warm-up call")["ok"], true);
        assert!(transport.panic_after_next_send_for_test("rest"));

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
            call().response.expect("the connection still works")["ok"],
            true
        );
        task.join().expect("server exits");
    }

    /// Have `sweep_idle` evict a connection entry whose mutex a panic poisoned.
    /// Eviction lets later calls rebuild it without a restart and increments
    /// the transport's panic-recovery counter.
    #[test]
    fn the_sweep_evicts_a_poisoned_entry() {
        let transport = RestTransport::default();
        let rest_config = config("http://127.0.0.1:1".to_string(), vec![]);
        let entry = transport
            .entry_for("poisoned", &rest_config)
            .expect("entry is built");
        let poison = std::thread::spawn(move || {
            let _state = entry.lock().expect("unpoisoned before the panic");
            panic!("poison the entry");
        });
        assert!(
            poison.join().is_err(),
            "the entry must actually be poisoned"
        );
        assert_eq!(
            transport.sweep_idle(),
            1,
            "a poisoned entry must be evicted"
        );
        assert_eq!(transport.connection_count(), 0);
        assert_eq!(transport.panic_recoveries(), 1);
    }
}

#[cfg(test)]
mod allocation_tests {
    use super::*;

    #[test]
    fn ordinary_calls_share_config_and_do_not_build_the_download_client() {
        let cfg = tests::config(
            "http://127.0.0.1:1".into(),
            vec![("read", tests::http_op(HttpMethod::Get, "/"))],
        );
        let transport = RestTransport::new(cfg.clone());
        let first = transport.config_for("test");
        let second = transport.config_for("test");
        assert!(
            Arc::ptr_eq(&first, &second),
            "dispatch must share the operation schema instead of cloning the manifest"
        );
        let entry = RestConnectionEntry::build(&cfg, TransportClock::real()).unwrap();
        assert!(
            entry.download_client.is_none(),
            "ordinary REST connections must not allocate a download runtime"
        );
    }
}

#[cfg(test)]
mod local_diagnostic_tests {
    use super::*;
    #[test]
    fn local_preparation_errors_are_logged_without_argument_values() {
        const TEST: &str = "rest_api::local_diagnostic_tests::local_preparation_errors_are_logged_without_argument_values";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
            tests::logging::init_child();
            let transport = RestTransport::new(tests::config(
                "http://127.0.0.1:1".into(),
                vec![("read", tests::http_op(HttpMethod::Get, "/repos/{repo}"))],
            ));
            let reply = transport.dispatch(
                tests::request(
                    "local",
                    "read",
                    serde_json::json!({"unrelated":"PRIVATE-ARGUMENT"}),
                ),
                &ResolvedCredential::anonymous(),
            );
            assert_eq!(reply.transmission, TransmissionState::NotSent);
            return;
        }
        let output = crate::test_http::bounded::child_test_output(
            TEST,
            &[("PLEXUS_LOG_STDERR_CHILD", "1")],
            Duration::from_secs(10),
            "local REST diagnostic",
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(
            stderr.contains("REST request preparation failed: Configuration"),
            "local refusal must name the safe cause: {stderr}"
        );
        assert!(
            !stderr.contains("PRIVATE-ARGUMENT"),
            "argument values must not reach the operator diagnostic: {stderr}"
        );
    }
}

#[cfg(test)]
#[path = "rest_api/signal_tests.rs"]
mod signal_tests;

#[cfg(test)]
mod graphql_permission_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn permission_refusal_log_includes_only_the_accepted_permissions_header() {
        for error in [
            json!({"type":"FORBIDDEN", "message":"PRIVATE_MARKER"}),
            json!({"extensions":{"code":"FORBIDDEN"}}),
            json!({"message":"Resource not accessible by integration"}),
        ] {
            let body = json!({"errors":[error]});
            let line = graphql_permission_log_line(&body, Some("merge_queues=write")).unwrap();
            assert!(
                line.contains("X-Accepted-GitHub-Permissions=\"merge_queues=write\""),
                "{line}"
            );
            assert!(!line.contains("PRIVATE_MARKER"));
            assert!(graphql_permission_log_line(&body, None).is_none());
        }
        assert!(graphql_permission_log_line(
            &json!({"data":{"ok":true}}),
            Some("merge_queues=write")
        )
        .is_none());
        assert!(graphql_permission_log_line(
            &json!({"errors":[{"type":"NOT_FOUND"}]}),
            Some("merge_queues=write")
        )
        .is_none());
        for status in [401, 403] {
            let line = vendor_error_log_line(
                "REST",
                &reqwest::Method::POST,
                "/graphql",
                status,
                "{}",
                Some("merge_queues=write"),
            )
            .unwrap();
            assert!(line.contains("X-Accepted-GitHub-Permissions=\"merge_queues=write\""));
        }
    }
}
