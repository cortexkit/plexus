//! ck-plexus: the thin subc wire module for the connector substrate.
//!
//! At startup, ck-plexus authenticates to subc, registers its fixed facade
//! manifest, receives the storage descriptor, opens and migrates the store,
//! loads catalog files, and then serves control and tool-route frames.

#![forbid(unsafe_code)]

// Shadow the standard macro throughout the daemon crate. The fleet event lives in
// `plexus-core`, which this crate already depends on, so every daemon diagnostic
// receives shared-log attribution without a second implementation. A site must
// name a level and a component, both documented on `plexus_core::diag!`; a bare
// message does not compile.
macro_rules! eprintln {
    ($level:ident $component:ident: $($arg:tt)*) => {
        plexus_core::diag!($level $component: $($arg)*)
    };
}

#[cfg(test)]
#[path = "../../plexus-core/tests/support/bounded.rs"]
mod bounded;
pub mod bus;
pub mod ceremony;
pub mod composition;
pub mod connector_home;
#[cfg(test)]
mod connector_home_tests;
#[cfg(test)]
mod consent_capacity_tests;
#[cfg(test)]
mod consent_test_support;
mod engram_catalog;
pub mod health;
pub mod manifest;
pub mod operator_confirmation;
pub mod principal;
pub mod relay;
mod request_execution;
pub mod scope_reader;
pub mod smoke;
#[cfg(test)]
#[path = "../../plexus-core/tests/support/http_server.rs"]
mod test_http;
mod tool_provider;
pub mod wire;
#[cfg(test)]
mod wire_safety_tests;
#[cfg(test)]
use bounded::recv_within;

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use composition::ModuleRuntime;
use cortexkit_store_types::StorageDescriptor;
use plexus_core::poller::PollCycle;
use plexus_core::scope::{resolve_call_agent, CallScope};
use plexus_core::storage::{
    AUDIT_DELETE_FLOOR_DAYS, AUDIT_MILLIS_PER_DAY, DEFAULT_AUDIT_RETENTION_DAYS,
};
#[cfg(any(test, feature = "test-support"))]
use plexus_core::test_scratch::Scratch;
use plexus_core::withdraw::{WithdrawCall, WithdrawRefusal, WITHDRAW_NOT_PERMITTED};
use plexus_core::{
    ActorSource, AuditRecord, AuthorizationRequest, CatalogError, ConfigureOutcome,
    ConnectionAdminRevokeOutcome, DispatchOutcome, EventLookupOutcome, EventReader, PlexusStore,
    TransportOutcome,
};
#[cfg(any(test, feature = "test-support"))]
use plexus_core::{MockTransport, StubCredentialSource};
use scope_reader::{DaemonScopeReader, PendingControlReplies};
use serde_json::{json, Value};
use subc_protocol::call_mode::{derive_call_mode, CallMode};
use subc_protocol::session::{
    ModuleControlRequest, ModuleControlResponse, MODULE_CONTROL_OP_HEALTH_CHECK,
};
use subc_protocol::tool_call::{validate_call_key, CALL_KEY_FIELD};
use subc_protocol::{
    ErrorBody, Flags, Frame, FrameType, ModuleHelloAckBody, ModuleHelloBody, Principal, Priority,
    PROTOCOL_VERSION, SUBC_MODULE_ID_ENV,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub const DEFAULT_MODULE_ID: &str = "plexus";
const AUDIT_RETENTION_DAYS_ENV: &str = "PLEXUS_AUDIT_RETENTION_DAYS";
const HELLO_CORRELATION: u64 = 1;
const EGRESS_BUFFER: usize = 64;
/// Refresh the diagnostic heartbeat age even while the dispatcher is idle.
const IDLE_HEARTBEAT_WAKE: std::time::Duration = std::time::Duration::from_millis(1_000);
/// How often the trigger scheduler wakes to look for due subscriptions.
///
/// Cadences are whole seconds and due-selection is a cheap store query, so a
/// one-second tick keeps a poll's start within a second of its cadence without
/// meaningful overhead. The tick is NOT the expensive part — the vendor round
/// trip is — and that only runs when something is actually due. A tick that
/// fires while a pass is still running is deliberately dropped rather than
/// queued (see `spawn_trigger_scheduler`), so a slow vendor cannot build up a
/// backlog of replayed polls.
const SCHEDULER_TICK: std::time::Duration = std::time::Duration::from_secs(1);
/// How often the scheduler task sweeps idle vendor connections out of the
/// transport pools.
///
/// Rides the scheduler tick because that tick already runs inside a blocking
/// section, which an eviction requires: dropping a pooled entry drops a
/// `reqwest::blocking` client and its internal runtime with it. Gated on an
/// interval rather than running every tick because the pools use a 300s idle
/// timeout, so sweeping at 1Hz would take the pool lock 300 times per eviction
/// it could possibly make.
const POOL_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// How often the scheduler refreshes connection health from vendor catalogs.
///
/// A health probe may make one blocking vendor call per connection, so it must
/// not run on the one-second scheduler tick. Sixty seconds bounds recovery
/// latency while keeping that work off the five-second control-lane deadline;
/// no caller depends on sub-minute connection recovery.
const HEALTH_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// One accepted route bind: the principal the daemon stamped, and the daemon
/// scope the route was opened under when the bind carried one.
#[derive(Clone)]
struct RouteBinding {
    admission: Arc<tokio::sync::Semaphore>,
    principal: Principal,
    scope: Option<CallScope>,
    mode: CallMode,
}

// Held approval calls live for up to 110 seconds and share this budget with
// bursty searches. Blocking jobs have a separate, smaller budget: waiting
// requests do not occupy blocking threads, and controls acquire neither permit.
const MAX_IN_FLIGHT_REQUESTS: usize = 256;
const MAX_BLOCKING_REQUESTS: usize = 32;
// One caller may retain a quarter of admission, leaving room for other modules.
const MAX_PRINCIPAL_REQUESTS: usize = 64;
// A quiet route still carries authority; bound retention instead of expiring it.
const MAX_ROUTE_BINDINGS: usize = 4096;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_PROBE_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_PROBE_ACTIONS: usize = 100;

#[derive(Clone)]
pub struct RouteBindings {
    control_replies: Arc<PendingControlReplies>,
    inner: Arc<RwLock<HashMap<(u16, u32), RouteBinding>>>,
    in_flight: Arc<tokio::sync::Semaphore>,
    blocking: Arc<tokio::sync::Semaphore>,
    last_capacity_warning: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    principals: Arc<std::sync::Mutex<HashMap<String, std::sync::Weak<tokio::sync::Semaphore>>>>,
}

impl Default for RouteBindings {
    fn default() -> Self {
        Self {
            control_replies: Arc::default(),
            inner: Arc::default(),
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_REQUESTS)),
            blocking: Arc::new(tokio::sync::Semaphore::new(MAX_BLOCKING_REQUESTS)),
            last_capacity_warning: Arc::default(),
            principals: Arc::default(),
        }
    }
}

impl RouteBindings {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn insert(&self, channel: u16, epoch: u32, principal: Principal) -> Result<(), ModuleError> {
        self.insert_scoped(channel, epoch, principal, None)
    }

    #[cfg(test)]
    fn insert_scoped(
        &self,
        channel: u16,
        epoch: u32,
        principal: Principal,
        scope: Option<CallScope>,
    ) -> Result<(), ModuleError> {
        let mode = if scope.as_ref().is_some_and(|scope| scope.flow_id.is_some()) {
            CallMode::Flow
        } else {
            CallMode::Classic
        };
        self.insert_mode(channel, epoch, principal, scope, mode)
    }

    fn insert_mode(
        &self,
        channel: u16,
        epoch: u32,
        principal: Principal,
        scope: Option<CallScope>,
        mode: CallMode,
    ) -> Result<(), ModuleError> {
        let mut routes = self
            .inner
            .write()
            .map_err(|_| ModuleError::Message("route binding state was poisoned".to_string()))?;
        // The daemon's bind for a reused channel supersedes its released epoch.
        routes.retain(|(bound_channel, _), _| *bound_channel != channel);
        if routes.len() >= MAX_ROUTE_BINDINGS {
            if self.should_log_route_capacity(std::time::Instant::now()) {
                eprintln!(warn wire: "route binding capacity exhausted ({MAX_ROUTE_BINDINGS} open routes); daemon close notifications may be missing");
            }
            return Err(ModuleError::RouteCapacity);
        }
        let admission = {
            let mut principals = self.principals.lock().map_err(|_| {
                ModuleError::Message("principal capacity state was poisoned".into())
            })?;
            principals.retain(|_, semaphore| semaphore.strong_count() > 0);
            let key = principal::principal_key(&principal);
            match principals.get(&key).and_then(std::sync::Weak::upgrade) {
                Some(semaphore) => semaphore,
                None => {
                    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_PRINCIPAL_REQUESTS));
                    principals.insert(key, Arc::downgrade(&semaphore));
                    semaphore
                }
            }
        };
        routes.insert(
            (channel, epoch),
            RouteBinding {
                admission,
                principal,
                scope,
                mode,
            },
        );
        Ok(())
    }

    fn should_log_route_capacity(&self, now: std::time::Instant) -> bool {
        let mut last = self
            .last_capacity_warning
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if last.is_some_and(|at| {
            now.saturating_duration_since(at) < std::time::Duration::from_secs(60)
        }) {
            return false;
        }
        *last = Some(now);
        true
    }

    #[cfg(test)]
    fn get(&self, channel: u16, epoch: u32) -> Result<Option<Principal>, ModuleError> {
        self.binding(channel, epoch)
            .map(|binding| binding.map(|binding| binding.principal))
    }

    /// The whole binding on `(channel, epoch)`: principal, daemon scope and
    /// call mode, read under one lock. A caller that needs more than the
    /// principal reads them together here, because separate reads could
    /// straddle a re-bind and pair one bind's principal with another's scope.
    fn binding(&self, channel: u16, epoch: u32) -> Result<Option<RouteBinding>, ModuleError> {
        let routes = self
            .inner
            .read()
            .map_err(|_| ModuleError::Message("route binding state was poisoned".to_string()))?;
        Ok(routes.get(&(channel, epoch)).cloned())
    }

    fn clear(&self) {
        self.control_replies.clear();
        self.inner
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }

    fn remove(&self, channel: u16, epoch: u32) -> Result<(), ModuleError> {
        self.inner
            .write()
            .map_err(|_| ModuleError::Message("route binding state was poisoned".into()))?
            .remove(&(channel, epoch));
        Ok(())
    }
}

/// A daemon connection owns its bindings; every loop exit invalidates the cache.
struct ClearBindingsOnClose(Arc<RouteBindings>);
impl Drop for ClearBindingsOnClose {
    fn drop(&mut self) {
        self.0.clear();
    }
}

struct ModuleState {
    health: Arc<health::HealthState>,
    runtime: ModuleRuntime,
}

impl ModuleState {
    fn store(&self) -> &Arc<PlexusStore> {
        &self.runtime.store
    }
}

struct ModuleConfig {
    connection_file_path: PathBuf,
    module_id: String,
    audit_retention_window_ms: i64,
}

impl ModuleConfig {
    fn from_env() -> Result<Self, ModuleError> {
        let connection_file_path = parse_subc_arg(std::env::args_os().skip(1))?;
        let module_id = std::env::var(SUBC_MODULE_ID_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MODULE_ID.to_string());
        let audit_retention_window_ms =
            audit_retention_window_ms(std::env::var_os(AUDIT_RETENTION_DAYS_ENV))?;
        Ok(Self {
            connection_file_path,
            module_id,
            audit_retention_window_ms,
        })
    }
}

/// Resolve the audit retention policy from deployment configuration.
///
/// Absence defaults to 30 days, unlike an absent `PLEXUS_CATALOG_DIR` below.
/// The catalog's old fallback pointed into a developer working tree, so serving
/// from a guessed path was less safe than refusing startup. Retention is a
/// deployment-independent safety policy: 30 days is safe until an operator
/// states a different window, while a present but invalid value is an intention
/// the module cannot honor and therefore remains a boot refusal.
fn audit_retention_window_ms(configured: Option<OsString>) -> Result<i64, ModuleError> {
    let days = match configured {
        None => DEFAULT_AUDIT_RETENTION_DAYS,
        Some(value) => {
            let text = value.to_str().ok_or_else(|| {
                ModuleError::Message(format!(
                    "{AUDIT_RETENTION_DAYS_ENV} is not valid Unicode and cannot be parsed as days"
                ))
            })?;
            text.parse::<i64>().map_err(|_| {
                ModuleError::Message(format!(
                    "{AUDIT_RETENTION_DAYS_ENV} value {text:?} cannot be parsed as whole days"
                ))
            })?
        }
    };
    if days <= AUDIT_DELETE_FLOOR_DAYS {
        return Err(ModuleError::Message(format!(
            "{AUDIT_RETENTION_DAYS_ENV} must be greater than the audit delete floor \
             (configured window: {days} days; floor: {AUDIT_DELETE_FLOOR_DAYS} days)"
        )));
    }
    days.checked_mul(AUDIT_MILLIS_PER_DAY).ok_or_else(|| {
        ModuleError::Message(format!(
            "{AUDIT_RETENTION_DAYS_ENV} value {days} days is too large"
        ))
    })
}

/// The build identity `ck-plexus --version` prints: crate version, the commit
/// the binary was built from and its lock digest, the same values health
/// reports as `buildCommit` and `lockDigest`.
pub fn version_line() -> String {
    format!(
        "ck-plexus {} (commit {}, lock {})",
        env!("CARGO_PKG_VERSION"),
        env!("PLEXUS_BUILD_COMMIT"),
        env!("PLEXUS_LOCK_DIGEST")
    )
}

/// The JSON `ck-plexus --manifest` prints: the manifest this module registers,
/// including its `provenance` object. Under a supervisor the module id comes
/// from `SUBC_MODULE_ID`; a placement check runs without one and gets the
/// default id.
pub fn printed_manifest() -> String {
    let module_id = std::env::var(SUBC_MODULE_ID_ENV)
        .ok()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| DEFAULT_MODULE_ID.to_string());
    serde_json::to_string(&manifest::build(&module_id)).expect("module manifest serializes")
}

/// Binary entry point used by `ck-plexus`.
pub async fn run_entry() -> Result<(), ModuleError> {
    // Placement scripts check a staged binary before the supervisor launches
    // it, where there is no module id, launch nonce or connection file. The
    // version answer must not depend on any of them, so it is handled before
    // the logger and the module config read their environment.
    // `args_os`, not `args`: `args` panics on an argument that is not UTF-8,
    // which would turn a bad command line into a crash with no usable message.
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--version") {
        println!("{}", version_line());
        return Ok(());
    }
    // SUBC's placement gate runs a staged binary with only `--manifest`, with
    // no daemon, store, network or stdin and a short alarm, and reads the
    // build provenance from the printed JSON. It is the manifest this module
    // registers, so it is answered here, before anything reads the supervisor
    // environment or opens a store.
    if args.first().is_some_and(|arg| arg == "--manifest") {
        if args.len() != 1 {
            std::eprintln!("usage: ck-plexus --manifest");
            std::process::exit(2);
        }
        println!("{}", printed_manifest());
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "--check-catalog") {
        if args.len() != 2 {
            std::eprintln!("usage: ck-plexus --check-catalog <dir>");
            std::process::exit(2);
        }
        std::process::exit(check_catalog(Path::new(&args[1])));
    }
    // Staging and post-placement checks run `--smoke-probe` on a freshly
    // signed file with no supervisor, so, like `--version`, it is answered
    // before the logger and module config read any supervisor environment.
    if args.first().is_some_and(|arg| arg == "--smoke-probe") {
        if args.len() != 1 {
            std::eprintln!("usage: ck-plexus --smoke-probe");
            std::process::exit(2);
        }
        // Inside `blocking_section`, like the scheduler's real probe runs: the
        // sandbox's synchronous WASI layer drives tokio itself, which panics
        // on an async worker thread.
        match blocking_section(smoke::smoke_probe) {
            Ok(line) => {
                println!("{line}");
                return Ok(());
            }
            Err(reason) => {
                std::eprintln!("ck-plexus smoke-probe FAILED: {reason}");
                std::process::exit(1);
            }
        }
    }
    if args
        .first()
        .is_some_and(|arg| arg == "--help" || arg == "-h")
    {
        println!("usage: ck-plexus [--version | --help | --manifest | --check-catalog <dir> | --smoke-probe]\n\n  --manifest             Print the module manifest with its build provenance as JSON, without supervisor, store or network access\n  --check-catalog <dir>  Validate catalog manifests without supervisor, store or network access\n                        Exit 0: all ok; 1: refused manifest; 2: usage or I/O error\n  --smoke-probe          Run one guest through the probe sandbox without supervisor, store or network access\n                        Exit 0: the guest ran and answered correctly; 1: it did not; 2: usage error");
        return Ok(());
    }
    // Only the executable owns the subscriber; library hosts install their own.
    let _logger = crate::bus::init_logger_from_env()
        .map_err(|error| ModuleError::Message(format!("initializing fleet logger: {error}")))?;
    let config = ModuleConfig::from_env()?;
    run(config).await
}

async fn run(config: ModuleConfig) -> Result<(), ModuleError> {
    let stream = connect_to_subc(&config.connection_file_path).await?;
    let (mut reader, writer_half) = tokio::io::split(stream);
    let (writer, receiver) = mpsc::channel::<Frame>(EGRESS_BUFFER);
    let writer_task = tokio::spawn(drain_writer(writer_half, receiver));
    let health = Arc::new(health::HealthState::new().with_poller_credential_repair());
    let route_bindings = Arc::new(RouteBindings::new());
    let loop_result =
        module_loop(&mut reader, writer.clone(), &config, health, route_bindings).await;
    drop(writer);

    let writer_result = writer_task
        .await
        .map_err(|error| ModuleError::Message(error.to_string()))?;
    match (loop_result, writer_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error),
    }
}

async fn connect_to_subc(connection_file_path: &Path) -> Result<TcpStream, ModuleError> {
    let connection = connection_file::read(connection_file_path)
        .map_err(|error| ModuleError::Message(format!("reading connection file: {error}")))?;
    let endpoint = connection
        .endpoints
        .first()
        .ok_or_else(|| ModuleError::Message("connection file has no endpoints".to_string()))?;
    let address = format!("{}:{}", endpoint.host, endpoint.port);
    let mut stream = TcpStream::connect(&address)
        .await
        .map_err(|error| ModuleError::Message(format!("connect {address}: {error}")))?;
    authenticate_client(&mut stream, &connection, std::time::Duration::from_secs(5))
        .await
        .map_err(|error| ModuleError::Message(format!("authenticate: {error}")))?;
    Ok(stream)
}

async fn module_loop<R>(
    reader: &mut R,
    writer: mpsc::Sender<Frame>,
    config: &ModuleConfig,
    health: Arc<health::HealthState>,
    route_bindings: Arc<RouteBindings>,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
{
    send_hello(&writer, config).await?;
    let hello_ack = expect_hello_ack(reader).await?;
    let store = blocking_section(|| {
        let (store, data_directory) = initialize_store(&hello_ack)?;
        if let Some(data_directory) = data_directory {
            engram_catalog::write_best_effort(&data_directory);
        }
        ingest_catalog(&store)?;
        Ok::<_, ModuleError>(Arc::new(store))
    })?;
    // Production composition opens configured route peers synchronously. Run
    // these connections outside the async worker because dropping a runtime
    // from within its own worker is unsafe; later route calls follow the same
    // restriction.
    let mut runtime =
        blocking_section(|| ModuleRuntime::production(store, &config.connection_file_path));
    // The engine re-checks a stored approval raised under a daemon scope with
    // `scope.describe`, sent on this module's subc connection, just before the
    // approval is sent. subc answers on channel 0, and the dispatch loop hands
    // those replies to `control_replies`.
    let control_replies = Arc::clone(&route_bindings.control_replies);
    runtime.engine = runtime
        .engine
        .clone()
        .with_scope_reader(Arc::new(DaemonScopeReader::new(
            writer.clone(),
            PROTOCOL_VERSION,
            Arc::clone(&control_replies),
        )));
    let state = Arc::new(ModuleState { health, runtime });
    state.health.stamp_heartbeat();

    // Re-register transport endpoints BEFORE the scheduler starts.
    //
    // Transport config is in-memory process state, populated as a side effect of
    // connect-time discovery and health probes. After a restart it is empty while
    // the store still holds every connection, so a poll falls back to a default
    // config carrying an EMPTY ENDPOINT and the MCP transport refuses it as a
    // configuration error. It self-heals on the supervisor's first health probe
    // ~30s later, but the scheduler's first pass runs within a second of start.
    //
    // The cost is not one wasted pass: `record_poll_attempt` stamps the cadence
    // BEFORE dispatch, so each subscription caught in that window waits a full
    // cadence before retrying. After a restart, every due subscription can
    // lose its first poll this way and wait a full cadence for the next one.
    //
    // Runs for every principal with connections rather than a hardcoded one, so
    // a fleet that grows past the operator principal does not silently keep the
    // defect for the new ones.
    blocking_section(|| {
        let principals = health_probe_principals(&state);
        refresh_store_health(&state, &principals);
        for principal in principals {
            let registered = state.runtime.reconciler.register_transports(&principal);
            if registered > 0 {
                eprintln!(info transport:
                    "registered {registered} transport endpoint(s) for principal '{principal}' before scheduling"
                );
            }
        }
    });

    // Drive trigger polling on a dedicated task rather than from the dispatch
    // loop below (see `spawn_trigger_scheduler`). The shutdown sender is held
    // here: when the loop exits on ANY path the sender is dropped, the task
    // observes the closed channel and stops. Shutdown waits a bounded time for
    // that (`stop_task`), then aborts the task, so one wedged pass cannot hold
    // the module open after its route has closed. A poll in flight at shutdown
    // is left to finish or abandoned; `commit_poll_success` is a single fenced
    // transaction, so an abandoned poll leaves the cursor unadvanced and the
    // events unwritten, which is the correct outcome.
    let (claim_shutdown, mut claim_stop) = mpsc::channel::<()>(1);
    let claim_state = Arc::clone(&state);
    let claim_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_refresh_error: Option<String> = None;
        loop {
            tokio::select! {
                _ = claim_stop.recv() => break,
                _ = tick.tick() => {
                    // The refresh logs ownership transitions itself; a failed
                    // read keeps the last state by design. The failure is
                    // logged when its code changes (not every 30 seconds), so
                    // a claim route that never answers is visible without
                    // flooding the log.
                    let outcome = blocking_section(|| claim_state.runtime.connector_home.refresh());
                    let code = outcome.as_ref().err().map(|error| error.code.clone());
                    if code != last_refresh_error {
                        match &outcome {
                            Err(error) => eprintln!(warn wire: "connector home refresh failed ({}): {}", error.code, error.message),
                            Ok(_) => eprintln!(info wire: "connector home refresh recovered"),
                        }
                        last_refresh_error = code;
                    }
                }
            }
        }
    });
    // Compile the probe sandbox in the background so the first probe poll does
    // not pay for it inside a scheduler pass. It must not delay the dispatch
    // loop below: compiling can take seconds on a slow machine, and the
    // supervisor's first health check gives the module only five seconds to
    // answer. A probe that runs before warm-up finishes waits on the same
    // one-time initialization.
    tokio::task::spawn_blocking(|| {
        if let Err(error) = plexus_probe::ProbeSandbox::warm_up() {
            eprintln!(warn scheduler: "probe sandbox warm-up failed; initialization will retry on use: {error}");
        }
    });
    let (scheduler_shutdown, scheduler_stop) = mpsc::channel::<()>(1);
    let scheduler_task = spawn_trigger_scheduler(
        Arc::clone(&state),
        scheduler_stop,
        config.audit_retention_window_ms,
    );

    let (outbox_shutdown, outbox_stop) = mpsc::channel::<()>(1);
    let outbox_task = crate::bus::spawn_outbox_drain(
        Arc::clone(&state),
        outbox_stop,
        crate::bus::session_factory(Some(config.connection_file_path.clone())),
    );

    let (relay_shutdown, relay_stop) = mpsc::channel::<()>(1);
    let relay_task = relay::spawn(Arc::clone(&state), relay_stop);

    let result = dispatch_loop(reader, writer, state, route_bindings, control_replies).await;

    drop(claim_shutdown);
    drop(scheduler_shutdown);
    drop(outbox_shutdown);
    drop(relay_shutdown);
    stop_task("connector-home refresh", claim_task, TASK_SHUTDOWN_GRACE).await;
    stop_task("trigger scheduler", scheduler_task, TASK_SHUTDOWN_GRACE).await;
    stop_task("outbox drain", outbox_task, BUS_SHUTDOWN_GRACE).await;
    stop_task("relay", relay_task, BUS_SHUTDOWN_GRACE).await;
    result
}

/// How long shutdown waits for the connector-home refresh, scheduler and
/// scheduler tasks after signalling them. Their slowest step is one vendor or
/// route call, each with its own timeout of a few seconds.
const TASK_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
/// How long shutdown waits for the outbox drain and the relay.
const BUS_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// Wait up to `grace` for a signalled background task to stop, then abort it.
///
/// Every outcome other than a clean stop is logged by name. Abort takes effect
/// at the task's next await, so a task inside a blocking call finishes that
/// call first, but shutdown itself no longer waits on it.
async fn stop_task(name: &str, mut task: tokio::task::JoinHandle<()>, grace: std::time::Duration) {
    match tokio::time::timeout(grace, &mut task).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!(warn wire: "{name} task ended abnormally before shutdown: {error}");
        }
        Err(_) => {
            eprintln!(warn wire: "{name} task did not stop within {grace:?} of shutdown; aborting it");
            task.abort();
        }
    }
}

/// The frame-handling loop: read a frame (with an idle heartbeat wake), dispatch
/// it, repeat until the peer closes the route or says goodbye.
async fn dispatch_loop<R>(
    reader: &mut R,
    writer: mpsc::Sender<Frame>,
    state: Arc<ModuleState>,
    route_bindings: Arc<RouteBindings>,
    control_replies: Arc<PendingControlReplies>,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
{
    let _clear_on_exit = ClearBindingsOnClose(route_bindings.clone());
    loop {
        // Keep the diagnostic heartbeat age fresh while idle.
        //
        // The read future is pinned and polled through select! rather than
        // wrapped in `timeout()`: a timeout would DROP the future on expiry,
        // corrupting the stream if it fired while a frame was mid-read
        // (read_exact is not cancellation-safe). Re-polling the same pinned
        // future preserves partial-read state across idle wakes.
        state.health.stamp_heartbeat();
        let read = std::pin::pin!(read_frame(reader));
        let mut read = read;
        let frame = loop {
            let mut idle_wake = std::pin::pin!(tokio::time::sleep(IDLE_HEARTBEAT_WAKE));
            tokio::select! {
                result = &mut read => {
                    let Some(frame) =
                        result.map_err(|error| ModuleError::Message(error.to_string()))?
                    else {
                        return Ok(());
                    };
                    break frame;
                }
                _ = &mut idle_wake => {
                    state.health.stamp_heartbeat();
                }
            }
        };
        // Replies to module-originated controls, including operator confirmation,
        // wake only the caller waiting on their correlation id.
        if frame.header.channel == 0
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            if !control_replies.complete(frame) {
                eprintln!(warn wire: "unmatched control reply (late, duplicate or unknown correlation)");
            }
            continue;
        }
        if !handle_frame(frame, &writer, &state, &route_bindings).await? {
            return Ok(());
        }
    }
}

fn connector_gate_transition(gate: &Value) -> (Value, Value, Value) {
    (
        gate["state"].clone(),
        gate["epoch"].clone(),
        gate["holder_name"].clone(),
    )
}

fn spawn_trigger_scheduler(
    state: Arc<ModuleState>,
    mut stop: mpsc::Receiver<()>,
    audit_retention_window_ms: i64,
) -> tokio::task::JoinHandle<()> {
    let scheduler =
        plexus_core::Scheduler::new(state.runtime.engine.clone(), audit_retention_window_ms)
            .with_relay_health(state.health.relay.clone())
            .with_agent_registry(Arc::clone(&state.runtime.agent_registry));
    let scheduler = match &state.runtime.repository_registry {
        Some(registry) => scheduler.with_repository_registry(Arc::clone(registry)),
        None => scheduler,
    };
    tokio::spawn(async move {
        // Held for the life of the task: dropping it — on a clean break, or on
        // an unwind if a pass panics — marks the scheduler dead in the health
        // report, so a module that has silently stopped polling stops claiming
        // to be ok.
        let _liveness = health::SchedulerLiveness::new(Arc::clone(&state.health));
        let mut tick = tokio::time::interval(SCHEDULER_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Start due, so the first tick performs each periodic task rather than
        // waiting a full interval. That is the ordinary reading of "every 60
        // seconds" and makes the wiring observable in a test measured in ticks
        // instead of minutes — a call site nothing can reach in a test is one
        // nothing proves is reached at all.
        let mut last_gate_state = None;
        // `None` means "never run", so both are due on the first tick. Not
        // `Instant::now() - interval`: that panics when the monotonic clock
        // reads less than the interval, as it can shortly after boot.
        let mut last_sweep: Option<std::time::Instant> = None;
        let mut last_health_probe: Option<std::time::Instant> = None;
        loop {
            tokio::select! {
                _ = stop.recv() => break,
                _ = tick.tick() => {
                    // Checked on every tick, because the tick is this task's
                    // first action once the host comes back: a suspended machine
                    // polls nothing, and without this check the time it spent
                    // asleep counts against the poller and reports a stall
                    // nobody can act on. Cheap enough for a one-second tick --
                    // two clock reads and an atomic load, writing only on the
                    // rare tick that follows a wake.
                    let gate = state.runtime.connector_home.status();
                    let transition = connector_gate_transition(&gate);
                    if last_gate_state.as_ref() != Some(&transition) {
                        eprintln!(info scheduler: "connector home scheduler gate: {gate}");
                        last_gate_state = Some(transition);
                    }
                    if !state.runtime.connector_home.held() { continue; }
                    state.health.note_host_suspension();
                    state.health.stamp_scheduler_pass();
                    // Poll for the same principals the health probes refresh:
                    // the operator principal plus every principal that owns a
                    // subscription or connection. Due-selection is
                    // principal-scoped, so each is scanned through its own query.
                     let principals = blocking_section(|| health_probe_principals(&state));
                     let now = plexus_core::storage::now_ms();
                    let sweep_due = last_sweep.is_none_or(|last| last.elapsed() >= POOL_SWEEP_INTERVAL);
                    if sweep_due {
                        last_sweep = Some(std::time::Instant::now());
                    }
                    let health_probe_due = last_health_probe
                        .is_none_or(|last| last.elapsed() >= HEALTH_PROBE_INTERVAL);
                    if health_probe_due {
                        last_health_probe = Some(std::time::Instant::now());
                    }
                    // The poll pass, health probe, and pool sweep run inside one
                    // blocking section. The probe makes blocking vendor calls, and
                    // the sweep is not merely tidy work that happens to sit here:
                    // evicting a pooled entry drops a reqwest::blocking client,
                    // which owns an internal tokio runtime, and dropping that on
                    // an async worker panics. This is the same hazard as every
                    // other transport call site in this module.
                    blocking_section(|| {
                        // The pass outcomes were previously DISCARDED here, and
                        // discarding them is what made a scheduler that refuses
                        // every poll indistinguishable from an idle one on the
                        // health surface.
                        // Timed around run_pass only, not around the sweep: the
                        // sweep is fixed housekeeping, and folding it in would
                        // attribute its cost to vendor latency, which is the one
                        // thing this measurement exists to isolate.
                        let started = std::time::Instant::now();
                        let report = scheduler.run_pass_report(&principals, now);
                        state.health.stamp_scheduler_selection_failures(report.selection_failures);
                        let (attempted, completed) = report.poll_counts();
                        let outcomes = report.outcomes;
                        let elapsed_ms = started.elapsed().as_millis() as u64;
                        // NAME THE UNCOMPLETED OUTCOMES, because the counters
                        // cannot.
                        //
                        // `schedulerPollsAttempted` and `schedulerPollsCompleted`
                        // are deliberately unclassified -- the useful reading of
                        // a healthy poller needs no judgement about why. But a
                        // persistent gap between them then has no explanation
                        // anywhere: twice now a restart has left a frozen
                        // shortfall (20, then 59) with every subscription active
                        // and zero vendor failures, and neither the gauges nor
                        // the store could say what the difference was.
                        //
                        // Logged per pass rather than counted per variant, so
                        // the numbers stay judgement-free and the DIAGNOSIS
                        // lives in the log where an operator reads it. Silent
                        // when every poll completes, which is the normal case,
                        // so this costs nothing on a healthy module.
                        if completed < attempted {
                            let mut reasons: Vec<String> = outcomes
                                .iter()
                                .filter(|outcome| {
                                    !matches!(outcome.cycle, PollCycle::Completed { .. } | PollCycle::Deferred { .. })
                                })
                                .map(|outcome| {
                                    let cause = match &outcome.cycle {
                                         PollCycle::Completed { .. } | PollCycle::Deferred { .. } => unreachable!("filtered outcomes"),
                                        PollCycle::VendorFailed { code } => {
                                            format!("vendor_failed:{code}")
                                        }
                                        PollCycle::Inconclusive { code } => {
                                            format!("inconclusive:{code}")
                                        }
                                        PollCycle::Suspended { reason } => {
                                            format!("suspended:{reason}")
                                        }
                                        PollCycle::NotEligible { reason } => {
                                            format!("not_eligible:{reason}")
                                        }
                                        PollCycle::StoreFailed { reason } => {
                                            format!("store_failed:{reason}")
                                        }
                                    };
                                    format!("{}={}", outcome.subscription_id, cause)
                                })
                                .collect();
                            // Bounded: a pass over every subscription could
                            // otherwise write one enormous line into a shared
                            // fleet log. The count is reported in full even when
                            // the list is truncated, so the number is never a
                            // sample.
                            let total = reasons.len();
                            reasons.truncate(8);
                            eprintln!(warn scheduler:
                                "scheduler pass: {} of {} polls did not complete: {}{}",
                                total,
                                attempted,
                                reasons.join(" "),
                                if total > 8 { " ..." } else { "" }
                            );
                        }
                        // Re-read after the pass because it may have suspended the
                        // final active subscription. Reporting the pre-pass count
                        // would briefly turn a deliberate circuit-breaker state into
                        // a scheduler-stall alarm.
                        match scheduler.store().active_subscription_schedule() {
                            Ok(Some((active, max_cadence_s))) => {
                                state
                                    .health
                                    .stamp_scheduler_subscription_count(active, max_cadence_s);
                            }
                            Ok(None) => {
                                // An empty active set has no maximum cadence. Clear
                                // both observations explicitly rather than assigning
                                // an invented cadence to scheduler idleness.
                                state.health.stamp_scheduler_no_active_subscriptions();
                            }
                            Err(error) => {
                                eprintln!(warn scheduler:
                                    "scheduler active-subscription schedule failed: {error}"
                                );
                            }
                        }
                        state
                            .health
                            .stamp_scheduler_outcomes(attempted, completed);
                        state
                            .health
                            .stamp_scheduler_pass_duration(attempted, elapsed_ms);
                        if health_probe_due {
                             run_health_probes_for(&state, &principals);
                             refresh_store_health(&state, &principals);
                        }
                        if sweep_due {
                            state.runtime.mcp_transport.sweep_idle();
                            state.runtime.rest_transport.sweep_idle();
                        }
                    });
                }
            }
        }
    })
}

async fn drain_writer<W>(
    writer_half: W,
    mut receiver: mpsc::Receiver<Frame>,
) -> Result<(), ModuleError>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = BufWriter::new(writer_half);
    while let Some(frame) = receiver.recv().await {
        write_frame(&mut writer, &frame)
            .await
            .map_err(|error| ModuleError::Message(error.to_string()))?;
        while let Ok(frame) = receiver.try_recv() {
            write_frame(&mut writer, &frame)
                .await
                .map_err(|error| ModuleError::Message(error.to_string()))?;
        }
        writer
            .flush()
            .await
            .map_err(|error| ModuleError::Message(error.to_string()))?;
    }
    writer
        .flush()
        .await
        .map_err(|error| ModuleError::Message(error.to_string()))?;
    Ok(())
}

async fn send_hello(
    writer: &mpsc::Sender<Frame>,
    config: &ModuleConfig,
) -> Result<(), ModuleError> {
    // Read through the process's one cached accessor, never the environment
    // directly. The daemon hands the nonce over as a pipe on descriptor 3 (the
    // SUBC_LAUNCH_NONCE environment copy is being retired), and the pipe can
    // be read only once. This process has a second reader: the subc client
    // library presents the same nonce when plexus opens its outbound routes
    // (vault reads, Prefrontal calls), and it reads this same cache. Reading
    // the pipe here by any other means would leave that reader with nothing.
    // Nothing is spawned before this point, so no child has inherited the
    // descriptor.
    //
    // A descriptor that is named but unreadable stops startup with the
    // accessor's own error. Sending HELLO without the nonce instead would get
    // a reserved module refused by the daemon for a missing nonce, an error
    // that says nothing about the unreadable descriptor.
    let launch_nonce = subc_os::launch_nonce().map_err(launch_nonce_refused)?;
    let launch_nonce_source = launch_nonce.as_ref().map(|nonce| {
        subc_protocol::manifest::LaunchNonceSource::from_wire_name(nonce.source().as_str())
    });
    let hello = ModuleHelloBody {
        manifest: manifest::build_with_launch_nonce_source(&config.module_id, launch_nonce_source),
        protocol_ver: PROTOCOL_VERSION,
        control_ops: Some(vec![
            "route.bind".to_string(),
            MODULE_CONTROL_OP_HEALTH_CHECK.to_string(),
        ]),
        launch_nonce: launch_nonce.map(|nonce| nonce.value().to_string()),
    };
    let body = serde_json::to_vec(&hello).map_err(ModuleError::Json)?;
    let frame = Frame::build(
        FrameType::Hello,
        wire::control_flags(),
        0,
        0,
        HELLO_CORRELATION,
        body,
    )
    .map_err(|error| ModuleError::Message(error.to_string()))?;
    send(writer, frame).await
}

/// The startup error for a launch nonce the accessor refused.
///
/// It carries the refusal's variant and fields (`NotOpen { fd: 3, errno: 9 }`)
/// as well as its prose, so the one line `ck-plexus` prints to stderr on exit
/// says which check failed without anyone matching prose back to a variant.
/// Neither form contains the nonce: every variant describes the descriptor or
/// the `SUBC_LAUNCH_NONCE_FD` value (`<fd>:<inode>`), never the pipe's bytes.
fn launch_nonce_refused(error: subc_os::LaunchNonceError) -> ModuleError {
    ModuleError::Message(format!("read launch nonce: refused as {error:?}: {error}"))
}

async fn expect_hello_ack<R>(reader: &mut R) -> Result<ModuleHelloAckBody, ModuleError>
where
    R: AsyncRead + Unpin,
{
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), read_frame(reader))
        .await
        .map_err(|_| ModuleError::Message("HELLO_ACK timeout".into()))?
        .map_err(|error| ModuleError::Message(error.to_string()))?
        .ok_or_else(|| ModuleError::Message("connection closed before HELLO_ACK".to_string()))?;
    match frame.header.ty {
        FrameType::HelloAck => serde_json::from_slice(&frame.body).map_err(ModuleError::Json),
        FrameType::Error => {
            let body: ErrorBody = serde_json::from_slice(&frame.body).map_err(ModuleError::Json)?;
            Err(ModuleError::Message(format!(
                "subc rejected HELLO: {} — {}",
                body.code, body.message
            )))
        }
        frame_type => Err(ModuleError::Message(format!(
            "unexpected frame {frame_type:?} awaiting HELLO_ACK"
        ))),
    }
}

fn initialize_store(
    hello_ack: &ModuleHelloAckBody,
) -> Result<(PlexusStore, Option<PathBuf>), ModuleError> {
    let value = hello_ack.storage.as_ref().ok_or_else(|| {
        ModuleError::Message("subc HELLO_ACK omitted the storage descriptor".to_string())
    })?;
    let descriptor: StorageDescriptor = serde_json::from_value(value.clone())
        .map_err(|error| ModuleError::Message(format!("invalid storage descriptor: {error}")))?;
    let data_directory = engram_catalog::data_directory(&descriptor);
    let store = PlexusStore::open(&descriptor)
        .map_err(|error| ModuleError::Message(format!("open plexus store: {error}")))?;
    Ok((store, data_directory))
}

fn ingest_catalog(store: &PlexusStore) -> Result<(), ModuleError> {
    let directory = catalog_directory(
        std::env::var_os("PLEXUS_CATALOG_DIR"),
        cfg!(debug_assertions),
    )?;
    ingest_catalog_from(store, &directory)
}

/// Resolve the catalog directory from the deployment environment.
///
/// A release build refuses to run without `PLEXUS_CATALOG_DIR` rather than
/// falling back to the compile-time repository path. The fallback exists for
/// `cargo run` during development - but on the machine where the repository
/// tree actually exists, a production daemon that lost its env line would not
/// fail: it would silently ingest the WORKING TREE's catalog, serving
/// uncommitted manifest edits as though they were reviewed and staged. A
/// missing variable must be a named boot refusal, not a plausible guess.
///
/// Both arms take their inputs as parameters (the env value and the build
/// kind) so each is testable from any build without mutating process-global
/// environment state.
fn catalog_directory(
    configured: Option<std::ffi::OsString>,
    dev_fallback_allowed: bool,
) -> Result<PathBuf, ModuleError> {
    if let Some(directory) = configured {
        return Ok(PathBuf::from(directory));
    }
    if dev_fallback_allowed {
        return Ok(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog"));
    }
    Err(ModuleError::Message(
        "PLEXUS_CATALOG_DIR is not set: a release build does not guess a catalog \
         location, because the compile-time fallback points at the development \
         tree. Set it in the module's env block in subc.jsonc."
            .to_string(),
    ))
}

fn catalog_paths(directory: &Path) -> Result<Vec<PathBuf>, ModuleError> {
    let mut paths = std::fs::read_dir(directory)
        .map_err(|error| ModuleError::Message(format!("read catalog directory: {error}")))?
        .map(|entry| entry.map(|item| item.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ModuleError::Message(format!("read catalog entry: {error}")))?;
    paths.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "jsonc")
    });
    paths.sort();
    Ok(paths)
}

// Both boot and the offline check use this pipeline so a rollback is tested
// against the schema and semantic validation the candidate will actually run.
fn parse_catalog_manifest(source: &str) -> Result<plexus_core::IngestedManifest, ModuleError> {
    let normalized = subc_jsonc::jsonc_to_json(source)
        .map_err(|error| ModuleError::Message(format!("normalize catalog manifest: {error}")))?;
    let value: Value = serde_json::from_str(&normalized)
        .map_err(|error| ModuleError::Message(format!("parse catalog manifest: {error}")))?;
    plexus_core::ingest_value(value)
        .map_err(|error| ModuleError::Message(format!("validate catalog manifest: {error}")))
}

fn check_catalog(directory: &Path) -> i32 {
    let paths = match catalog_paths(directory) {
        Ok(paths) => paths,
        Err(error) => {
            std::eprintln!("cannot check catalog {}: {error}", directory.display());
            println!("catalog: 0 ok, 0 refused, 1 I/O errors");
            return 2;
        }
    };
    let (ok, refused, io_errors) = tally_catalog(&paths);
    println!("catalog: {ok} ok, {refused} refused, {io_errors} I/O errors");
    if io_errors > 0 {
        2
    } else if refused > 0 {
        1
    } else {
        0
    }
}

/// Check each manifest and print one line per file; returns the counts of
/// files that parsed, were refused, and could not be read. A file that cannot
/// be read counts as an I/O error only, not also as a refusal, so the summary
/// adds up to the number of files.
fn tally_catalog(paths: &[PathBuf]) -> (usize, usize, usize) {
    let (mut ok, mut refused, mut io_errors) = (0, 0, 0);
    for path in paths {
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(error) => {
                io_errors += 1;
                println!(
                    "unreadable {}: read catalog manifest: {error}",
                    path.display()
                );
                continue;
            }
        };
        match parse_catalog_manifest(&source) {
            Ok(_) => {
                ok += 1;
                println!("ok {}", path.display());
            }
            Err(error) => {
                refused += 1;
                println!("refused {}: {error}", path.display());
            }
        }
    }
    (ok, refused, io_errors)
}

/// The catalog ingest itself, with the directory supplied rather than read from
/// the environment.
///
/// Split out so a test can drive the real boot path against a temporary catalog:
/// resolving the directory from a process-wide environment variable would make
/// any such test mutate global state shared with every other test in the binary.
/// The point of testing here rather than against the store directly is that the
/// retirement sweep's CALL SITE is what makes it effective, and a sweep nobody
/// invokes is indistinguishable from an absent one.
fn ingest_catalog_from(store: &PlexusStore, directory: &Path) -> Result<(), ModuleError> {
    let paths = catalog_paths(directory)?;
    // The retirement pass below withdraws every stored manifest the directory
    // does not contain. A directory holding no manifests at all is a wrong or
    // half-synced PLEXUS_CATALOG_DIR far more often than a deliberate
    // withdrawal of every vendor, and following it would retire the whole
    // catalog on this boot. Refuse to boot instead.
    if paths.is_empty() {
        return Err(ModuleError::Message(format!(
            "catalog directory {} holds no .jsonc manifests; refusing to boot rather \
             than retire every stored manifest (check PLEXUS_CATALOG_DIR)",
            directory.display()
        )));
    }
    let mut reviewed = Vec::new();
    for path in &paths {
        let source = std::fs::read_to_string(path).map_err(|error| {
            ModuleError::Message(format!("read catalog manifest {}: {error}", path.display()))
        })?;
        let ingested = parse_catalog_manifest(&source).map_err(|error| {
            ModuleError::Message(format!(
                "refused catalog manifest {}: {error}",
                path.display()
            ))
        })?;
        let key = ingested.manifest.key.clone();
        // The store records a content change in the upsert's own transaction.
        store
            .upsert_manifest("system", &ingested)
            .map_err(|error| {
                ModuleError::Message(format!(
                    "store catalog manifest {}: {error}",
                    path.display()
                ))
            })?;
        reviewed.push(key);
    }

    // Withdrawals need their own pass, because the loop above can only express
    // what the directory CONTAINS. Upserting the files present leaves a manifest
    // deleted from the catalog untouched in the store, still listed as
    // connectable and still ticketable -- so retiring a vendor for being
    // ungovernable had no effect on a running module.
    //
    // Failing the boot on a retirement error is deliberate: reaching here means
    // the directory parsed cleanly, so a store error is a real fault, and
    // serving a catalog whose withdrawals were silently skipped is the state
    // this pass exists to prevent.
    // Each retirement's audit row is written in the retirement's transaction.
    store
        .retire_absent_manifests("system", &reviewed)
        .map_err(|error| ModuleError::Message(format!("retire absent manifests: {error}")))?;

    // GitHub handle rows seeded before the seeder pinned reviewed argument
    // schemas still hold the open placeholder, which leaves the
    // undeclared-argument check with nothing to refuse on any bot write, and
    // nothing else ever rewrites them. This runs after the loop that stores
    // each catalog file and after absent manifests are retired, so the schemas
    // come from the manifests this boot just stored and never from a retired
    // one. A store error fails the boot, as a retirement error does.
    let pins = store
        .pin_handle_placeholder_schemas()
        .map_err(|error| ModuleError::Message(format!("pin handle schemas: {error}")))?;
    eprintln!(info catalog:
        "pinned reviewed argument schemas on {} GitHub handle catalog rows that held the open placeholder",
        pins.pinned.len()
    );
    let mut per_connection: std::collections::BTreeMap<(&str, &str), usize> =
        std::collections::BTreeMap::new();
    for pin in &pins.pinned {
        *per_connection
            .entry((pin.principal.as_str(), pin.connection_id.as_str()))
            .or_default() += 1;
    }
    for ((principal, connection_id), count) in per_connection {
        eprintln!(debug catalog:
            "pinned reviewed argument schemas on {count} catalog rows of {principal}/{connection_id}"
        );
    }
    // Every handle on the same manifest has the same gap, because the missing
    // schema is in the shared manifest, so one line per action says it all.
    let mut gaps: std::collections::BTreeMap<(&str, &str), usize> =
        std::collections::BTreeMap::new();
    for gap in &pins.gaps {
        *gaps.entry((gap.action.as_str(), gap.reason)).or_default() += 1;
    }
    for ((action, reason), count) in gaps {
        eprintln!(warn catalog:
            "GitHub handle action {action} keeps the open placeholder schema on {count} connections: {reason}"
        );
    }
    Ok(())
}

async fn handle_frame(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<bool, ModuleError> {
    match frame.header.ty {
        FrameType::Ping if frame.header.channel == 0 => {
            let response = Frame::build_with_version(
                frame.header.ver,
                FrameType::Pong,
                frame.header.flags,
                0,
                0,
                frame.header.corr,
                Vec::new(),
            )
            .map_err(|error| ModuleError::Message(error.to_string()))?;
            send(writer, response).await?;
            Ok(true)
        }
        FrameType::Goodbye if frame.header.channel == 0 => Ok(false),
        FrameType::Goodbye => {
            route_bindings.remove(frame.header.channel, frame.header.epoch)?;
            Ok(true)
        }
        FrameType::Request if frame.header.channel == 0 => {
            handle_control_request(frame, writer, state, route_bindings).await?;
            Ok(true)
        }
        FrameType::Request => {
            let budget = request_execution::RequestBudget::new();
            if frame.body.len() > MAX_REQUEST_BYTES {
                send_tool_error(
                    writer,
                    frame.header.ver,
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                    "invalid_request",
                    "request body exceeds the 1 MiB limit",
                )
                .await?;
                return Ok(true);
            }
            let binding = match route_bindings.binding(frame.header.channel, frame.header.epoch) {
                Ok(Some(binding)) => binding,
                Ok(None) => {
                    send_tool_error(
                        writer,
                        frame.header.ver,
                        frame.header.channel,
                        frame.header.epoch,
                        frame.header.corr,
                        "route_not_bound",
                        "plexus tools require an accepted route.bind",
                    )
                    .await?;
                    return Ok(true);
                }
                Err(error) => {
                    eprintln!(error wire: "request on channel {} epoch {} correlation {} failed before its reply was sent: {error}", frame.header.channel, frame.header.epoch, frame.header.corr);
                    send_tool_error(
                        writer,
                        frame.header.ver,
                        frame.header.channel,
                        frame.header.epoch,
                        frame.header.corr,
                        "internal_error",
                        "plexus failed while serving this request; the module log names the cause",
                    )
                    .await?;
                    return Ok(true);
                }
            };
            let principal_permit = binding.admission.try_acquire_owned();
            let permit = route_bindings.in_flight.clone().try_acquire_owned();
            let (Ok(permit), Ok(principal_permit)) = (permit, principal_permit) else {
                let response = Frame::build_with_version(
                    frame.header.ver, FrameType::Error, wire::control_flags(),
                    frame.header.channel, frame.header.epoch, frame.header.corr,
                    serde_json::to_vec(&json!({"code":"resource_exhausted", "retryable":true,
                        "retry_after_ms":1000, "message":"Plexus request capacity is full; retry in one second."}))
                        .map_err(ModuleError::Json)?,
                ).map_err(|error| ModuleError::Message(error.to_string()))?;
                send(writer, response).await?;
                return Ok(true);
            };
            let writer = writer.clone();
            let state = Arc::clone(state);
            let route_bindings = Arc::clone(route_bindings);
            tokio::spawn(async move {
                let _permit = permit;
                let _principal_permit = principal_permit;
                let coordinates = (
                    frame.header.ver,
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                );
                let queue_deadline = tokio::time::Instant::from_std(budget.deadline)
                    .min(tokio::time::Instant::now() + std::time::Duration::from_secs(5));
                let Ok(Ok(blocking)) = tokio::time::timeout_at(
                    queue_deadline,
                    route_bindings.blocking.clone().acquire_owned(),
                )
                .await
                else {
                    let _ = send_tool_error(
                        &writer,
                        coordinates.0,
                        coordinates.1,
                        coordinates.2,
                        coordinates.3,
                        "resource_exhausted",
                        "request expired while waiting for work capacity; nothing was sent",
                    )
                    .await;
                    return;
                };
                let failure_writer = writer.clone();
                // All synchronous route/store/vendor work, including denial and
                // agent resolution, runs on the blocking pool. The async sends
                // can still await writer capacity without occupying a worker.
                let runtime = tokio::runtime::Handle::current();
                let worker_result = tokio::task::spawn_blocking(move || {
                    let _blocking = request_execution::RequestSlot::enter(
                        route_bindings.blocking.clone(),
                        blocking,
                        budget.clone(),
                    );
                    runtime.block_on(async {
                        serve_tool_request(frame, &writer, &state, &route_bindings, budget).await;
                    })
                })
                .await;
                answer_worker_failure(worker_result, coordinates, &failure_writer).await;
            });
            Ok(true)
        }
        _ => Ok(true),
    }
}

async fn answer_worker_failure(
    result: Result<(), tokio::task::JoinError>,
    coordinates: (u8, u16, u32, u64),
    writer: &mpsc::Sender<Frame>,
) {
    if let Err(error) = result {
        eprintln!(warn wire: "request worker failed: {error}");
        if let Err(error) = send_tool_error(
            writer,
            coordinates.0,
            coordinates.1,
            coordinates.2,
            coordinates.3,
            "internal_error",
            "request worker failed; the module log names the cause",
        )
        .await
        {
            eprintln!(error wire: "could not send request worker failure: {error}");
        }
    }
}

/// Serve one route request so that it always gets an answer.
///
/// `handle_tool_request` returns `Err` only when it could not send its own
/// reply: a store or lock failure before the reply was built, or a failed
/// send. Dropped silently, the caller waits for an answer that never comes and
/// the module log has nothing. So the error is logged and the caller gets an
/// `internal_error` reply; if that send fails too (the route is gone), that is
/// logged as well.
async fn serve_tool_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    budget: Arc<request_execution::RequestBudget>,
) {
    let version = frame.header.ver;
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    let correlation = frame.header.corr;
    let Err(error) =
        handle_tool_request_with_budget(frame, writer, state, route_bindings, budget).await
    else {
        return;
    };
    eprintln!(error wire:
        "request on channel {channel} epoch {epoch} correlation {correlation} failed before its reply was sent: {error}"
    );
    if let Err(send_error) = send_tool_error(
        writer,
        version,
        channel,
        epoch,
        correlation,
        "internal_error",
        "plexus failed while serving this request; the module log names the cause",
    )
    .await
    {
        eprintln!(error wire:
            "could not send the internal_error reply on channel {channel} epoch {epoch} correlation {correlation}: {send_error}"
        );
    }
}

/// Mark a reply whose effect already happened but whose audit row could not be
/// written. The effect stands, so the caller still gets the real reply rather
/// than an error that would read as "nothing happened"; the warning and the
/// log line say the journal is missing this row.
fn warn_audit_failed(response: &mut Value, what: &str, error: &dyn std::fmt::Display) {
    eprintln!(error governance: "audit append failed after {what} took effect: {error}");
    if let Some(object) = response.as_object_mut() {
        object.insert(
            "warning".into(),
            json!({
                "code": "audit_append_failed",
                "message": format!("{what} took effect, but its audit row could not be written; the module log names the cause"),
            }),
        );
    }
}

async fn handle_control_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    if frame.body.len() > MAX_REQUEST_BYTES {
        let response = wire::build_error_frame(
            frame.header.ver,
            0,
            0,
            frame.header.corr,
            "invalid_request",
            "control request body exceeds the 1 MiB limit",
        )?;
        return send(writer, response).await;
    }
    let request: ModuleControlRequest = match serde_json::from_slice(&frame.body) {
        Ok(request) => request,
        Err(error) => {
            eprintln!(warn wire: "refused undecodable control request: {error}");
            let response = wire::build_error_frame(
                frame.header.ver,
                0,
                0,
                frame.header.corr,
                "invalid_request",
                &format!("cannot decode control request: {error}"),
            )?;
            return send(writer, response).await;
        }
    };
    let body = match request {
        ModuleControlRequest::RouteBind {
            route_channel,
            epoch,
            principal,
            scope,
            call_mode,
            ..
        } => {
            let mode = call_mode.unwrap_or_else(|| derive_call_mode(scope.as_ref()));
            if matches!(mode, CallMode::Unknown(_)) {
                let refusal = tool_provider::mode_refusal("route.bind", &mode)
                    .expect("unknown call modes are refused");
                let response = Frame::build_with_version(
                    frame.header.ver,
                    FrameType::Error,
                    wire::control_flags(),
                    0,
                    0,
                    frame.header.corr,
                    serde_json::to_vec(&refusal).map_err(ModuleError::Json)?,
                )
                .map_err(|error| ModuleError::Message(error.to_string()))?;
                return send(writer, response).await;
            }
            let trust = principal::trust_for_principal(&principal);
            // EVERY BIND OUTCOME IS LOGGED, accepted and refused alike, because
            // this is where a consumer's identity is decided and neither side of
            // a route can see the decision otherwise.
            //
            // The refusal path had five error sites and no logging at all: a
            // rejected consumer received an error frame and this module recorded
            // nothing, so an operator asking "did that module even try to bind"
            // had no way to answer. A consumer whose client turns an error frame
            // into an empty result then presents as a quiet, working lane that is
            // simply always empty -- indistinguishable from a correct scoping
            // decision, which is the exact confusion that cost two seats an
            // evening on the tool-call layer below.
            //
            // Accepted binds are logged too. Logging only refusals would make an
            // ABSENT line ambiguous between "never arrived" and "arrived and was
            // fine", and the first of those is a real diagnosis.
            let bind_label = principal
                .as_ref()
                .map(principal::principal_key)
                .unwrap_or_else(|| "absent".into());
            eprintln!(info wire:
                "route bind from principal '{bind_label}' on channel {route_channel}: {}",
                if trust.is_first_party() {
                    "ACCEPTED"
                } else {
                    "REFUSED (not first-party)"
                }
            );
            if !trust.is_first_party() {
                return send_principal_denied(
                    writer,
                    frame.header.ver,
                    frame.header.corr,
                    &principal,
                )
                .await;
            }
            let accepted = principal.ok_or_else(|| {
                ModuleError::Message("first-party trust classification lost principal".to_string())
            })?;
            // The daemon stamps the scope a route was opened under: the
            // session it belongs to and the agent it may act for. Plexus takes
            // that identity only from this stamp, never from a request
            // payload. A bind without a stamp behaves exactly as before.
            let scope = scope.as_ref().map(CallScope::from_stamp);
            if let Some(scope) = &scope {
                eprintln!(info wire:
                    "route bind on channel {route_channel} is under scope {}/{}@{} (agent {}, delegates {}, owner authorized {})",
                    scope.owner,
                    scope.scope_ref,
                    scope.scope_epoch,
                    scope.agent_id.as_deref().unwrap_or("none"),
                    scope.delegates,
                    scope.owner_authorized
                );
            }
            match route_bindings.insert_mode(route_channel, epoch, accepted, scope, mode) {
                Ok(()) => {}
                Err(ModuleError::RouteCapacity) => {
                    let response = wire::build_error_frame(
                        frame.header.ver,
                        0,
                        0,
                        frame.header.corr,
                        "resource_exhausted",
                        "route binding capacity exhausted",
                    )?;
                    return send(writer, response).await;
                }
                Err(error) => return Err(error),
            }
            ModuleControlResponse::RouteBindAck {}
        }
        ModuleControlRequest::HealthCheck {} => {
            // The supervisor gives this inline dispatch-loop handler five
            // seconds to answer. A probe makes sequential blocking vendor calls
            // across every connection, so it runs on the scheduler task and this
            // path reports the last observed state instead.
            connector_home_health(state)
        }
    };
    let body = serde_json::to_vec(&body).map_err(ModuleError::Json)?;
    let response = Frame::build_with_version(
        frame.header.ver,
        FrameType::Response,
        wire::control_flags(),
        0,
        0,
        frame.header.corr,
        body,
    )
    .map_err(|error| ModuleError::Message(error.to_string()))?;
    send(writer, response).await
}

async fn send_principal_denied(
    writer: &mpsc::Sender<Frame>,
    version: u8,
    correlation: u64,
    principal: &Option<Principal>,
) -> Result<(), ModuleError> {
    let label = principal
        .as_ref()
        .map(principal::principal_key)
        .unwrap_or_else(|| "absent".to_string());
    let frame = wire::build_error_frame(
        version,
        0,
        0,
        correlation,
        "principal_denied",
        &format!(
            "plexus connector tools are first-party only; principal '{label}' is not eligible"
        ),
    )?;
    send(writer, frame).await
}

/// Run synchronous connector work that may touch the vendor transport.
///
/// The MCP transport is built on a blocking HTTP client, which owns an internal
/// runtime. Executing that on an async worker is illegal: tokio panics with
/// "cannot drop a runtime in a context where blocking is not allowed" when the
/// client's runtime is released, which kills the module mid-request and closes
/// the route under the caller. `block_in_place` moves the current task off the
/// async worker for the duration, making the blocking work — and the drops it
/// performs — legal.
///
/// `block_in_place` exists only on the multi-threaded runtime and panics on a
/// current-thread one, so there (and outside any runtime) the work runs
/// directly: a current-thread runtime has no other worker to hand the async
/// tasks to, so running inline is the only option it offers.
fn blocking_section<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(work),
        _ => work(),
    }
}

/// Where a route frame came from: the wire coordinates every response must echo.
#[derive(Debug, Clone, Copy)]
struct RouteFrameContext {
    version: u8,
    channel: u16,
    epoch: u32,
    correlation: u64,
}

/// Serve the privileged ceremony. Direct admission excludes supervised modules,
/// not other code running as this user. Minting or widening authority therefore
/// also requires operation-bound confirmation from the daemon's operator UI;
/// narrowing authority and read-only previews require no step-up.
async fn handle_management_request(
    route: RouteFrameContext,
    method: &str,
    params: &Value,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    let RouteFrameContext {
        version,
        channel,
        epoch,
        correlation,
    } = route;
    if !matches!(
        method,
        manifest::ADMIN_ISSUE_TICKET_OP
            | manifest::ADMIN_GRANT_OP
            | manifest::ADMIN_WIDEN_CEILING_OP
            | manifest::ADMIN_REVOKE_GRANT_OP
            | manifest::ADMIN_LIST_GRANTS_OP
            | manifest::ADMIN_SET_POLICY_OP
            | manifest::ADMIN_LIST_POLICIES_OP
            | manifest::ADMIN_REMOVE_POLICY_OP
            | manifest::ADMIN_REVIEW_ACTION_OP
            | manifest::ADMIN_REPIN_ACTION_OP
            | manifest::ADMIN_DELETE_CONNECTION_OP
            | manifest::ADMIN_REBIND_CREDENTIAL_OP
            | manifest::ADMIN_SET_WEB_SEARCH_LIMIT_OP
            | manifest::ADMIN_SET_WEB_SEARCH_ORDER_OP
            | manifest::ADMIN_SET_WEB_SEARCH_ALLOWANCE_OP
            | manifest::ADMIN_RECIPIENTS_ADD_OP
            | manifest::ADMIN_RECIPIENTS_REMOVE_OP
            | manifest::ADMIN_RECIPIENTS_LIST_OP
            | manifest::GITHUB_IMPORT_OP
            | manifest::GITHUB_PROBE_OP
            | manifest::GITHUB_GRANT_OP
            | manifest::GITHUB_BIND_OP
            | manifest::GITHUB_UNBIND_OP
            | connector_home::STATUS_OP
            | relay::STATUS_OP
    ) {
        // THE LAST SILENT GATE, and the one that actually bit: a consumer sent
        // {"method":"events","params":{"op":"list"}}, which lands here rather
        // than on the tool surface, because a `method` key routes to management
        // BEFORE any tool name is read. It was refused correctly and invisibly.
        //
        // The two shapes are easy to confuse and the failure is quiet: the
        // facade ops (connections, catalog, invoke, requests, events) live on
        // the TOOL surface and take {"name","arguments"}; this surface serves
        // administrative and status operations.
        // A consumer using the management shape for a facade op gets unknown_method, and a client
        // that renders an error frame as an empty result then shows a working
        // lane that is permanently empty.
        //
        // The message names both the surface and the correct shape, because
        // "unknown plexus management operation" is true and useless to someone
        // who does not yet know they are on the wrong surface.
        let method = diagnostic_label(method);
        eprintln!(info wire:
            "management call refused: '{method}' is not a management operation on channel {channel}; facade tools take {{name, arguments}}"
        );
        return send_tool_error(
            writer,
            version,
            channel,
            epoch,
            correlation,
            "unknown_method",
            &format!(
                "'{method}' is not a plexus management operation. The management surface serves administration and status operations; facade tools (connections, catalog, invoke, requests, events) take {{\"name\": \"events\", \"arguments\": {{...}}}}"
            ),
        )
        .await;
    }
    let Some(binding) = route_bindings.binding(channel, epoch)? else {
        return send_tool_error(
            writer,
            version,
            channel,
            epoch,
            correlation,
            "route_not_bound",
            "plexus management operations require an accepted route.bind",
        )
        .await;
    };
    let principal = binding.principal;
    if !matches!(principal, Principal::Direct)
        || binding.mode != CallMode::Classic
        || binding.scope.is_some()
    {
        let mut response = tool_error(
            "operator_authority_required",
            "plexus management operations require an unscoped Classic direct principal",
        );
        if matches!(
            method,
            manifest::GITHUB_IMPORT_OP
                | manifest::GITHUB_PROBE_OP
                | manifest::GITHUB_GRANT_OP
                | manifest::GITHUB_BIND_OP
                | manifest::GITHUB_UNBIND_OP
        ) {
            if let Err(error) = state.store().audit_github_control(
                &principal::principal_key(&principal),
                None,
                params.get("app_handle_id").and_then(Value::as_str),
                method,
                &fresh_request_id(),
                Some("operator_authority_required"),
            ) {
                warn_audit_failed(&mut response, "github control refusal", &error);
            }
        }
        return send_tool_response(writer, version, channel, epoch, correlation, response).await;
    }
    let principal_key = principal::principal_key(&principal);
    if matches!(
        method,
        manifest::GITHUB_IMPORT_OP
            | manifest::GITHUB_PROBE_OP
            | manifest::GITHUB_BIND_OP
            | manifest::ADMIN_ISSUE_TICKET_OP
            | manifest::ADMIN_REBIND_CREDENTIAL_OP
    ) {
        if let Some(refusal) = state.runtime.connector_home.refusal() {
            return send_tool_response(writer, version, channel, epoch, correlation, refusal).await;
        }
    }
    if let Some(summary) = operator_confirmation::summary(method, params) {
        if let Err(refusal) =
            operator_confirmation::confirm(&summary, route, writer, &route_bindings.control_replies)
                .await
        {
            let response = operator_confirmation::audit_refusal(state, method, &refusal);
            return send_tool_response(writer, version, channel, epoch, correlation, response)
                .await;
        }
        if route_bindings.binding(channel, epoch)?.is_none() {
            let response = operator_confirmation::audit_refusal(
                state,
                method,
                &operator_confirmation::Refusal {
                    code: "operator_confirmation_unavailable",
                    reason: "the caller route closed while awaiting confirmation".to_string(),
                },
            );
            return send_tool_response(writer, version, channel, epoch, correlation, response)
                .await;
        }
    }
    let mut response = match method {
        relay::STATUS_OP => json!({"result": state.health.relay.status()}),
        manifest::ADMIN_RECIPIENTS_ADD_OP
        | manifest::ADMIN_RECIPIENTS_REMOVE_OP
        | manifest::ADMIN_RECIPIENTS_LIST_OP => ceremony::recipients(state, params, method),
        connector_home::STATUS_OP => {
            blocking_section(|| state.runtime.connector_home.live_status())
        }
        manifest::GITHUB_IMPORT_OP => {
            let inventory = serde_json::from_value::<plexus_core::github::control::Inventory>(
                params.get("inventory").cloned().unwrap_or(Value::Null),
            );
            match (inventory, state.runtime.github_handle_credentials.as_ref()) {
                (Ok(inventory), Some(provider)) => {
                    // The reader owns a blocking HTTP client whose runtime may
                    // only be built and dropped off the async worker, so it
                    // lives inside the section.
                    match blocking_section(|| {
                        let reader = github_control_reader(state);
                        plexus_core::github::control::import(
                            state.store(),
                            &principal_key,
                            &inventory,
                            provider.as_ref(),
                            reader.as_ref(),
                            plexus_core::storage::now_ms(),
                            params
                                .get("dry_run")
                                .and_then(Value::as_bool)
                                .unwrap_or(true),
                        )
                    }) {
                        Ok(plan) => json!({"result":plan}),
                        Err(code) => json!({"error":{"code":code}}),
                    }
                }
                (Err(error), _) => {
                    eprintln!(warn wire: "GitHub inventory could not be decoded: {error}");
                    json!({"error":{"code":"inventory_invalid"}})
                }
                (_, None) => json!({"error":{"code":"handle_credential_unresolvable"}}),
            }
        }
        manifest::GITHUB_PROBE_OP => {
            match (
                params.get("app_handle_id").and_then(Value::as_str),
                state.runtime.github_handle_credentials.as_ref(),
            ) {
                (Some(id), Some(provider)) => {
                    // The reader must be built and dropped inside
                    // `blocking_section`, as in the import arm above.
                    match blocking_section(|| {
                        let reader = github_control_reader(state);
                        plexus_core::github::control::probe(
                            state.store(),
                            &principal_key,
                            id,
                            provider.as_ref(),
                            reader.as_ref(),
                            plexus_core::storage::now_ms(),
                        )
                    }) {
                        Ok(proof) => json!({"result":proof}),
                        Err(code) => json!({"error":{"code":code}}),
                    }
                }
                _ => json!({"error":{"code":"invalid_request"}}),
            }
        }
        manifest::GITHUB_GRANT_OP => github_handle_grant(state, &principal_key, params),
        manifest::GITHUB_BIND_OP => github_handle_bind(state, &principal_key, params),
        manifest::GITHUB_UNBIND_OP => {
            github_handle_unbind(state, &principal_key, params, &fresh_request_id())
        }
        manifest::ADMIN_ISSUE_TICKET_OP => ceremony::issue_ticket(state, &principal_key, params),
        manifest::ADMIN_REBIND_CREDENTIAL_OP => {
            ceremony::rebind_credential(state, &principal_key, params)
        }
        manifest::ADMIN_GRANT_OP => ceremony::grant(state, &principal_key, params),
        manifest::ADMIN_WIDEN_CEILING_OP => ceremony::widen_ceiling(state, &principal_key, params),
        manifest::ADMIN_LIST_GRANTS_OP => ceremony::list_grants(state, &principal_key, params),
        manifest::ADMIN_SET_POLICY_OP => ceremony::set_policy(state, &principal_key, params),
        manifest::ADMIN_LIST_POLICIES_OP => ceremony::list_policies(state, &principal_key, params),
        manifest::ADMIN_REMOVE_POLICY_OP => ceremony::remove_policy(state, &principal_key, params),
        manifest::ADMIN_REVIEW_ACTION_OP => ceremony::review_action(state, &principal_key, params),
        manifest::ADMIN_REPIN_ACTION_OP => ceremony::repin_action(state, &principal_key, params),
        manifest::ADMIN_REVOKE_GRANT_OP => ceremony::revoke_grant(state, &principal_key, params),
        manifest::ADMIN_DELETE_CONNECTION_OP => {
            ceremony::delete_connection(state, &principal_key, params)
        }
        manifest::ADMIN_SET_WEB_SEARCH_LIMIT_OP => {
            ceremony::set_web_search_limit(state, &principal_key, params)
        }
        manifest::ADMIN_SET_WEB_SEARCH_ORDER_OP => {
            ceremony::set_web_search_order(state, &principal_key, params)
        }
        manifest::ADMIN_SET_WEB_SEARCH_ALLOWANCE_OP => {
            ceremony::set_web_search_allowance(state, &principal_key, params)
        }
        _ => unreachable!("management operation was checked above"),
    };
    if matches!(
        method,
        manifest::GITHUB_IMPORT_OP
            | manifest::GITHUB_PROBE_OP
            | manifest::GITHUB_GRANT_OP
            | manifest::GITHUB_BIND_OP
    ) {
        // The op has run (an applied bind or grant has changed the store), so
        // a failed audit row is reported alongside its reply, not in place of it.
        if let Err(error) = state.store().audit_github_control(
            &principal_key,
            None,
            params.get("app_handle_id").and_then(Value::as_str),
            method,
            &fresh_request_id(),
            response.pointer("/error/code").and_then(Value::as_str),
        ) {
            warn_audit_failed(&mut response, method, &error);
        }
    }
    send_tool_response(writer, version, channel, epoch, correlation, response).await
}

fn github_handle_unbind(
    state: &ModuleState,
    principal_key: &str,
    params: &Value,
    request_id: &str,
) -> Value {
    let (Some(handle), Some(repository)) = (
        params.get("app_handle_id").and_then(Value::as_str),
        params.get("repository").and_then(Value::as_str),
    ) else {
        return json!({"error":{"code":"invalid_request"}});
    };
    let dry_run = params
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    // Applied unbinds record their audit in the deletion transaction so an
    // audit failure cannot leave an unaudited removal behind.
    match blocking_section(|| {
        plexus_core::github::control::unbind(
            state.store(),
            principal_key,
            handle,
            repository,
            request_id,
            dry_run,
        )
    }) {
        Ok(plan) => json!({"result":plan}),
        Err(code) => github_handle_refusal(&code, handle),
    }
}

fn github_control_reader(
    state: &ModuleState,
) -> Arc<dyn plexus_core::github::control::InstallationReader + Send + Sync> {
    state
        .runtime
        .github_control_reader
        .clone()
        .unwrap_or_else(|| Arc::new(plexus_core::github::control::GithubApiReader::default()))
}

/// Decode `github.handle.bind` parameters and run the bind against the
/// handle's installation, read with its vault token as the probe reads it.
/// `dry_run` defaults to true, as for the import and the grant.
fn github_handle_bind(state: &ModuleState, principal_key: &str, params: &Value) -> Value {
    let Some(app_handle_id) = params.get("app_handle_id").and_then(Value::as_str) else {
        return json!({"error":{"code":"invalid_request",
            "message":"app_handle_id and repositories are required"}});
    };
    let repositories: Option<Vec<String>> = params
        .get("repositories")
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .map(|value| value.as_str().map(str::to_owned))
                .collect()
        });
    let Some(repositories) = repositories else {
        return json!({"error":{"code":"invalid_request",
            "message":"repositories must be an array of owner/name strings"}});
    };
    let Some(provider) = state.runtime.github_handle_credentials.as_ref() else {
        return json!({"error":{"code":"handle_credential_unresolvable"}});
    };
    let dry_run = params
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    // The reader owns a blocking HTTP client whose runtime may only be built
    // and dropped off the async worker, so it lives inside the section.
    match blocking_section(|| {
        let reader = github_control_reader(state);
        plexus_core::github::control::bind(
            state.store(),
            principal_key,
            app_handle_id,
            &repositories,
            provider.as_ref(),
            reader.as_ref(),
            plexus_core::storage::now_ms(),
            dry_run,
        )
    }) {
        Ok(plan) => json!({"result":plan}),
        Err(code) => github_handle_refusal(&code, app_handle_id),
    }
}

/// Decode `github.handle.grant` parameters and run the grant. `module` and
/// `effect` have no default because each changes what the grant authorizes;
/// `dry_run` defaults to true, as for the import.
///
/// `kind: "poll"` selects the poll form: scheduled-poll read authority for the
/// handle connection's own principal. It takes no `module` or `effect`, since
/// its grantee is fixed and it mints no policy; either is refused rather than
/// silently ignored.
fn github_handle_grant(state: &ModuleState, principal_key: &str, params: &Value) -> Value {
    let text = |name: &str| params.get(name).and_then(Value::as_str);
    match params.get("kind").map(|kind| kind.as_str()) {
        None | Some(Some("invoke")) => {}
        Some(Some("poll")) => return github_handle_poll_grant(state, principal_key, params),
        Some(_) => {
            return json!({"error":{"code":"invalid_request",
                "message":"kind must be \"invoke\" or \"poll\""}})
        }
    }
    let (Some(app_handle_id), Some(module), Some(effect)) =
        (text("app_handle_id"), text("module"), text("effect"))
    else {
        return json!({"error":{"code":"invalid_request",
            "message":"app_handle_id, actions, module and effect are required"}});
    };
    let actions: Option<Vec<String>> =
        params
            .get("actions")
            .and_then(Value::as_array)
            .and_then(|values| {
                values
                    .iter()
                    .map(|value| value.as_str().map(str::to_owned))
                    .collect()
            });
    let Some(actions) = actions else {
        return json!({"error":{"code":"invalid_request",
            "message":"actions must be an array of action names"}});
    };
    let dry_run = params
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    match plexus_core::github::control::grant(
        state.store(),
        principal_key,
        app_handle_id,
        &actions,
        module,
        effect,
        dry_run,
    ) {
        Ok(plan) => json!({"result":plan}),
        Err(code) => github_handle_refusal(&code, app_handle_id),
    }
}

/// The poll form of `github.handle.grant`: `app_handle_id`, `actions`, and
/// `dry_run` (default true).
fn github_handle_poll_grant(state: &ModuleState, principal_key: &str, params: &Value) -> Value {
    if params.get("module").is_some() || params.get("effect").is_some() {
        return json!({"error":{"code":"invalid_request",
            "message":"the poll form takes no module or effect: its grantee is the connection's own principal"}});
    }
    let Some(app_handle_id) = params.get("app_handle_id").and_then(Value::as_str) else {
        return json!({"error":{"code":"invalid_request",
            "message":"app_handle_id and actions are required"}});
    };
    let actions: Option<Vec<String>> =
        params
            .get("actions")
            .and_then(Value::as_array)
            .and_then(|values| {
                values
                    .iter()
                    .map(|value| value.as_str().map(str::to_owned))
                    .collect()
            });
    let Some(actions) = actions else {
        return json!({"error":{"code":"invalid_request",
            "message":"actions must be an array of action names"}});
    };
    let dry_run = params
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    match plexus_core::github::control::grant_poll(
        state.store(),
        principal_key,
        app_handle_id,
        &actions,
        dry_run,
    ) {
        Ok(plan) => json!({"result":plan}),
        Err(code) => github_handle_refusal(&code, app_handle_id),
    }
}

fn github_handle_refusal(code: &str, app_handle_id: &str) -> Value {
    if code == "agent_handle_unknown" {
        json!({"error":{"code":code,"detail":{"app_handle_id":app_handle_id}}})
    } else {
        json!({"error":{"code":code}})
    }
}

#[cfg(any(test, feature = "test-support"))]
async fn handle_tool_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    handle_tool_request_with_budget(
        frame,
        writer,
        state,
        route_bindings,
        request_execution::RequestBudget::new(),
    )
    .await
}

async fn handle_tool_request_with_budget(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    budget: Arc<request_execution::RequestBudget>,
) -> Result<(), ModuleError> {
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    let correlation = frame.header.corr;
    if budget.expired() {
        return send_tool_response(
            writer,
            frame.header.ver,
            channel,
            epoch,
            correlation,
            request_expired_reply(),
        )
        .await;
    }
    // Record entry to the body handler before its validation and authority
    // gates. Saturated requests are refused earlier by handle_frame, so an
    // absent entry log can also mean admission capacity was exhausted.
    // Log only shape and wire coordinates: arguments can contain vendor data.
    eprintln!(info wire:
        "tool frame received on channel {channel} epoch {epoch} ({} bytes)",
        frame.body.len()
    );
    if frame.body.len() > MAX_REQUEST_BYTES {
        return send_tool_error(
            writer,
            frame.header.ver,
            channel,
            epoch,
            correlation,
            "invalid_request",
            "request body exceeds the 1 MiB limit",
        )
        .await;
    }
    let value: Value = match serde_json::from_slice(&frame.body) {
        Ok(value) => value,
        Err(error) => {
            return send_tool_error(
                writer,
                frame.header.ver,
                channel,
                epoch,
                correlation,
                "invalid_request",
                &format!("request body not decodable: {error}"),
            )
            .await;
        }
    };
    let object = match value.as_object() {
        Some(object) => object,
        None => {
            return send_tool_error(
                writer,
                frame.header.ver,
                channel,
                epoch,
                correlation,
                "invalid_request",
                "tool request must be an object",
            )
            .await;
        }
    };
    if object.contains_key("method") {
        if let Some(field) = object
            .get("params")
            .and_then(Value::as_object)
            .and_then(retired_identity_field)
        {
            return send_tool_response(
                writer,
                frame.header.ver,
                channel,
                epoch,
                correlation,
                retired_identity_refusal(field),
            )
            .await;
        }
    }
    // Management-surface calls arrive on the same route frame type as tool calls
    // but carry {method, params} rather than {name, arguments}.
    if object.get("method").and_then(Value::as_str) == Some(grants_would_ask::METHOD) {
        let reply = match route_bindings.binding(channel, epoch)? {
            Some(binding) => blocking_section(|| {
                grants_would_ask::run(
                    state,
                    &principal::principal_key(&binding.principal),
                    binding.scope.as_ref(),
                    object,
                )
            }),
            None => tool_error(
                "route_not_bound",
                "grants.would_ask requires an accepted route.bind",
            ),
        };
        return send_tool_response(writer, frame.header.ver, channel, epoch, correlation, reply)
            .await;
    }
    // permissions/v1 operations are route operations served to cingulate and
    // the local operator; `permissions::run` admits the caller.
    if let Some(method) = object
        .get("method")
        .and_then(Value::as_str)
        .filter(|method| permissions::is_method(method))
    {
        let reply = match route_bindings.binding(channel, epoch)? {
            Some(binding) => blocking_section(|| {
                permissions::run(
                    state,
                    &principal::principal_key(&binding.principal),
                    Some(&binding.mode),
                    binding.scope.as_ref(),
                    method,
                    object,
                )
            }),
            None => tool_error(
                "route_not_bound",
                "permissions operations require an accepted route.bind",
            ),
        };
        return send_tool_response(writer, frame.header.ver, channel, epoch, correlation, reply)
            .await;
    }
    if let Some(method) = object.get("method").and_then(Value::as_str) {
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        return handle_management_request(
            RouteFrameContext {
                version: frame.header.ver,
                channel,
                epoch,
                correlation,
            },
            method,
            &params,
            writer,
            state,
            route_bindings,
        )
        .await;
    }
    let tool = object.get("name").and_then(Value::as_str);
    let reply = blocking_section(|| {
        facade_tool_reply_with_budget(&frame, object, state, route_bindings, budget)
    })?;
    if tool.is_some_and(tool_provider::is_metadata_op) {
        // Role metadata is not an MCP tool result: consumers decode the role's
        // answer directly, and refusals are terminal ERROR frames.
        let (kind, body) = match reply.get("error") {
            Some(error) => (FrameType::Error, error),
            None => (FrameType::Response, &reply),
        };
        let response = Frame::build_with_version(
            frame.header.ver,
            kind,
            Flags::new(false, Priority::Interactive, false),
            channel,
            epoch,
            correlation,
            serde_json::to_vec(body).map_err(ModuleError::Json)?,
        )
        .map_err(|error| ModuleError::Message(error.to_string()))?;
        return send(writer, response).await;
    }
    send_tool_response(
        writer,
        frame.header.ver,
        channel,
        epoch,
        correlation,
        with_call_tool_result_with_repo(
            tool,
            reply,
            object
                .get("arguments")
                .and_then(|arguments| arguments.get("repo"))
                .and_then(Value::as_str),
        ),
    )
    .await
}

pub mod flow_audience;
mod github_react;
mod grants_would_ask;
mod permissions;

// Only Basal may carry flows so relaying cannot replace its module grants with
// a broader module's grants and widen the flow's authority.
// Basal also needs first-party standing at route.bind (principal.rs) to reach
// Plexus at all.
//
// The rule also runs the other way: a flow carrier's call must carry a flow
// stamp. Basal holds broad module grants on behalf of flows. A call without the
// stamp would use them with no flow attached, outside the flow rules
// (`consent_unavailable` would not apply, so an ask_first action could file a
// consent card), and with no owning flow on the audit row.
const ADMITTED_FLOW_CARRIERS: &[&str] = &[principal::BASAL_PRINCIPAL];

/// Serve one facade tool call (a `{name, arguments}` request naming one of
/// the tools in `manifest`, as opposed to a `{method, params}` management
/// request) and return its reply body,
/// `{"result": ...}` or `{"error": ...}`. The caller sends it, adding the MCP
/// `CallToolResult` fields in one place, so every early refusal below returns
/// its body rather than sending a frame of its own.
#[cfg(test)]
fn facade_tool_reply(
    frame: &Frame,
    object: &serde_json::Map<String, Value>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<Value, ModuleError> {
    facade_tool_reply_with_budget(
        frame,
        object,
        state,
        route_bindings,
        request_execution::RequestBudget::new(),
    )
}

fn facade_tool_reply_with_budget(
    frame: &Frame,
    object: &serde_json::Map<String, Value>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    budget: Arc<request_execution::RequestBudget>,
) -> Result<Value, ModuleError> {
    let reply = facade_tool_reply_inner(frame, object, state, route_bindings, budget)?;
    let name = object.get("name").and_then(Value::as_str).unwrap_or("");
    if let Some(error) = reply.get("error") {
        if tool_provider::is_metadata_op(name)
            || (object.contains_key("preset") && error["field"] == "preset")
        {
            log_tool_provider_refusal(frame, object, route_bindings, name, error)?;
        }
    }
    Ok(reply)
}

fn log_tool_provider_refusal(
    frame: &Frame,
    object: &serde_json::Map<String, Value>,
    route_bindings: &Arc<RouteBindings>,
    name: &str,
    error: &Value,
) -> Result<(), ModuleError> {
    fn keys(value: Option<&Value>) -> Vec<String> {
        value
            .and_then(Value::as_object)
            .map(|object| object.keys().map(|key| diagnostic_label(key)).collect())
            .unwrap_or_default()
    }
    let caller = route_bindings
        .binding(frame.header.channel, frame.header.epoch)?
        .map(|binding| principal::principal_key(&binding.principal))
        .unwrap_or_else(|| "unbound".to_owned());
    let arguments = object.get("arguments");
    let argument_keys = keys(arguments);
    let params_keys = keys(arguments.and_then(|arguments| arguments.get("params")));
    let preset = object
        .get("preset")
        .and_then(Value::as_str)
        .filter(|preset| subc_protocol::tool_call::validate_preset(preset).is_ok())
        .map(|preset| format!(" preset={preset}"))
        .unwrap_or_default();
    // Catalog errors may echo a capability or a malformed JSON value to the
    // caller. Logs retain the reason but must not copy those request values.
    let message = if error["detail"].get("capability").is_some() {
        "plexus serves no requested capability (value redacted)"
    } else if error["detail"]["field"] == "arguments" {
        "malformed catalog arguments (values redacted)"
    } else {
        error["message"].as_str().unwrap_or("request refused")
    };
    let op = diagnostic_label(name);
    let caller = diagnostic_label(&caller);
    let code = error["code"].as_str().unwrap_or("unknown");
    let message = diagnostic_label(message);
    eprintln!(warn wire: "tool call refused: op={op} caller={caller} code={code} message={message} argument_keys={argument_keys:?} params_keys={params_keys:?}{preset}");
    Ok(())
}

fn facade_tool_reply_inner(
    frame: &Frame,
    object: &serde_json::Map<String, Value>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    budget: Arc<request_execution::RequestBudget>,
) -> Result<Value, ModuleError> {
    let held_deadline = budget.deadline;
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    let name = match object.get("name").and_then(Value::as_str) {
        Some(name) => name,
        None => {
            return Ok(tool_error(
                "invalid_request",
                "tool request requires a string name",
            ));
        }
    };
    let log_name = diagnostic_label(name);
    let arguments = match object.get("arguments").and_then(Value::as_object) {
        Some(arguments) => arguments,
        None => {
            return Ok(tool_error(
                "invalid_request",
                "tool request requires an arguments object",
            ));
        }
    };
    // Retired identity tokens are undeclared on every tool, even if their
    // value is null or contains secrets. Refuse the field before any handler
    // can read credentials, send a request or silently discard it.
    if let Some(field) = retired_identity_field(arguments) {
        return Ok(retired_identity_refusal(field));
    }
    // Broca, the model runner, copies the preset name from the session's plan
    // ("worker", "reader" or "head") onto every request it sends a provider, the
    // catalog fetch and each later tool call alike. Accept the presets plexus's
    // tool catalog serves and refuse any other. Which plexus tools a session gets
    // is decided by capability tags when the plan is built, and every call is
    // still authorized on its own, so the preset grants nothing.
    if let Some(preset) = object.get("preset") {
        if !preset.as_str().is_some_and(tool_provider::serves_preset) {
            return Ok(json!({"error":{"code":"invalid_request", "field":"preset",
                "preset":preset, "message":"unknown or malformed plexus preset"}}));
        }
        if name == cortexkit_role_tool_provider::ops::TOOL_CATALOG
            && arguments
                .get("preset")
                .is_some_and(|argument| argument != preset)
        {
            return Ok(json!({"error":{"code":"invalid_request", "field":"preset",
                "message":"top-level preset must equal arguments.preset"}}));
        }
    }
    // `call_key` is the consumer's name for this call, a sibling of `name` and
    // `arguments`. Its shape is checked here, before any handler runs, so a
    // malformed key is refused rather than silently dropped the way unknown
    // top-level members are. Absent and `null` both mean no key, as they do
    // when the protocol's `ToolCallRequest` decodes the same body.
    //
    // A valid key is stored on the approval request if the call is held for
    // approval, so its carrier or its scope's owner can withdraw it with
    // `tool.withdraw`. A call that runs in its own request keeps nothing.
    if let Some(refusal) = call_key_refusal(object.get(CALL_KEY_FIELD)) {
        eprintln!(info wire: "tool call refused: malformed {CALL_KEY_FIELD} on channel {channel} (tool '{log_name}'): {refusal}");
        return Ok(json!({"error": {
            "code": "invalid_request",
            "message": refusal,
            "field": CALL_KEY_FIELD,
        }}));
    }
    // `origin` names the call from which a relayed call came. It is checked
    // here, beside `call_key`, so a malformed one is refused before any
    // handler runs. A valid one is recorded for attribution on the call's
    // audit rows and on any approval request it raises; nothing keys,
    // authorizes or withdraws on it. Its value is never logged or echoed: the
    // log line and the refusal name only the faulty field.
    let relay_origin = match relay_origin_of(object) {
        Ok(relay_origin) => relay_origin,
        Err(refusal) => {
            eprintln!(info wire: "tool call refused: malformed {} on channel {channel} (tool '{log_name}')", refusal.field);
            return Ok(json!({"error": {
                "code": "invalid_request",
                "message": refusal.message,
                "field": refusal.field,
            }}));
        }
    };
    if !matches!(
        name,
        manifest::CONNECTIONS_TOOL
            | manifest::CATALOG_TOOL
            | manifest::INVOKE_TOOL
            | manifest::GITHUB_TOOL
            | manifest::GITHUB_READ_TOOL
            | manifest::GITHUB_REACT_TOOL
            | manifest::EVENTS_GET_TOOL
            | manifest::REQUESTS_TOOL
            | manifest::EVENTS_TOOL
            | manifest::WEB_SEARCH_TOOL
            | manifest::CODE_SEARCH_TOOL
            | manifest::WITHDRAW_TOOL
            | cortexkit_role_tool_provider::ops::TOOL_CATALOG
            | cortexkit_role_tool_provider::ops::ROLE_DESCRIBE
    ) {
        // Logged for the same reason as the bind gates: a tool call refused
        // before any handler runs leaves no trace otherwise, so an operator
        // cannot tell a REFUSED call from one that never arrived -- and those
        // have different owners.
        eprintln!(info wire: "tool call refused: unknown facade tool '{log_name}' on channel {channel}");
        return Ok(tool_error("unknown_method", "unknown plexus facade tool"));
    }

    let Some(RouteBinding {
        principal,
        scope: route_scope,
        mode,
        ..
    }) = route_bindings.binding(channel, epoch)?
    else {
        // THE CHANNEL AND EPOCH ARE PRINTED because this refusal can follow a
        // SUCCESSFUL bind: the binding is keyed on (channel, epoch), so a tool
        // frame carrying a different pair finds nothing even though the consumer
        // bound correctly moments earlier. Without both numbers the log cannot
        // distinguish that from a client that never bound at all, and the two
        // have different fixes.
        eprintln!(info wire:
            "tool call refused: no binding for channel {channel} epoch {epoch} (tool '{log_name}') -- a bind on a DIFFERENT channel/epoch does not cover this call"
        );
        return Ok(tool_error(
            "route_not_bound",
            "plexus tools require an accepted route.bind",
        ));
    };
    let principal_key = principal::principal_key(&principal);
    if let Some(refusal) = tool_provider::mode_refusal(name, &mode) {
        return Ok(json!({"error": refusal}));
    }
    if name == manifest::GITHUB_TOOL {
        let operation = arguments.get("op").and_then(Value::as_str);
        if !matches!(operation, Some("bot_request" | "bindings.read")) {
            return Ok(json!({"error": {
                "code": "invalid_operation",
                "op": operation,
                "message": "unsupported github operation"
            }}));
        }
    }
    if (mode == CallMode::Flow
        || route_scope
            .as_ref()
            .is_some_and(|scope| scope.flow_id.is_some()))
        && !ADMITTED_FLOW_CARRIERS.contains(&principal_key.as_str())
    {
        eprintln!(info wire: "tool call refused: flow carrier {principal_key} is not admitted (tool '{log_name}')");
        return Ok(json!({"error": {
            "code": "flow_carrier_not_admitted",
            "message": format!("flow carrier {principal_key} is not admitted"),
            "carrier": principal_key,
            "transmission": "not_sent",
        }}));
    }
    // role.describe and tool.catalog only describe plexus's tools and carry no
    // authority. Basal reads them on an unscoped route when it installs a flow,
    // before any flow scope exists, so they are exempt from the flow-scope
    // requirement; every real tool still needs a flow scope from Basal.
    if !tool_provider::is_metadata_op(name)
        && (mode == CallMode::Flow || ADMITTED_FLOW_CARRIERS.contains(&principal_key.as_str()))
        && !route_scope
            .as_ref()
            .is_some_and(|scope| scope.flow_id.is_some())
    {
        eprintln!(info wire: "tool call refused: flow carrier {principal_key} sent no flow scope (tool '{log_name}')");
        return Ok(json!({"error": {
            "code": "flow_scope_required",
            "message": format!("{principal_key} carries only flow calls; this route carries no flow scope"),
            "carrier": principal_key,
            "transmission": "not_sent",
        }}));
    }
    if tool_provider::is_metadata_op(name) {
        // Metadata needs only the existing route admission, not connector
        // authority. Composition is opaque, so secret-shaped keys inside it
        // must not pass through the connector-argument filter.
        return Ok(match tool_provider::reply(name, arguments) {
            Ok(answer) => answer,
            Err(error) => json!({"error": error}),
        });
    }
    let audience = match state
        .runtime
        .flow_audiences
        .for_route(&principal_key, route_scope.as_ref())
    {
        Ok(audience) => audience,
        Err(refusal) => return Ok(refusal),
    };
    if let Some(audience) = &audience {
        if let Err(refusal) = flow_audience::check_call(state, audience, name, arguments) {
            return Ok(refusal);
        }
    }
    if name == manifest::GITHUB_READ_TOOL {
        let action = arguments
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("");
        // Refuse by action name before inspecting repository/args, secrets, or
        // connection authority. The read-only surface cannot carry a bot write.
        if !plexus_core::github::reads::ACTIONS.contains(&action) {
            return Ok(json!({"error": {
                "code": "read_action_unsupported",
                "action": action,
                "message": format!("GitHub read action {action:?} is not supported"),
            }}));
        }
        if arguments
            .keys()
            .any(|key| !matches!(key.as_str(), "action" | "repository" | "args"))
            || !arguments.get("args").is_some_and(Value::is_object)
            || !arguments.get("repository").is_some_and(|repository| {
                repository.is_string()
                    || repository
                        .as_array()
                        .is_some_and(|items| items.iter().all(Value::is_string))
            })
        {
            if action == "github.actions.run.superseded" {
                return Ok(tool_error(
                    "run_arguments_invalid",
                    "run.superseded requires repository and args containing only a positive run_id",
                ));
            }
            return Ok(tool_error("invalid_request", "github_read requires only action, repository (string or string array), and args (object)"));
        }
    }
    // github_react's arguments are checked here, after the same mode, flow
    // and audience checks as every tool. They are turned into the same
    // `request` object a `github` tool `bot_request` reaction would carry
    // (action, repository, target number and reaction), and dispatch below
    // sends it through the bot_request path, so both tools share one
    // implementation.
    let reaction_request = if name == manifest::GITHUB_REACT_TOOL {
        match github_react::reaction_request(arguments) {
            Ok(built) => Some(built),
            Err(refusal) => return Ok(refusal),
        }
    } else {
        None
    };
    if name == manifest::EVENTS_GET_TOOL
        || (name == manifest::EVENTS_TOOL
            && arguments.get("op").and_then(Value::as_str) == Some("get"))
    {
        let invalid_key = arguments.keys().any(|key| {
            !matches!(key.as_str(), "event_key" | "event_name" | "version")
                && !(name == manifest::EVENTS_TOOL && key == "op")
        });
        if invalid_key {
            return Ok(tool_error(
                "invalid_request",
                "event reads accept only event_key, event_name and version",
            ));
        }
    }
    let op = arguments.get("op").and_then(Value::as_str);
    if name == manifest::EVENTS_TOOL
        && route_scope
            .as_ref()
            .is_some_and(|scope| scope.flow_id.is_some())
        && op != Some("get")
    {
        return Ok(tool_error(
            "events_op_not_for_flows",
            "events operations other than get are not admitted on flow routes",
        ));
    }
    if name == manifest::REQUESTS_TOOL
        && matches!(
            arguments.get("op").and_then(Value::as_str),
            Some("approve" | "deny")
        )
        && route_scope
            .as_ref()
            .is_some_and(|scope| scope.flow_id.is_some())
    {
        return Ok(tool_error(
            "flow_cannot_decide_approvals",
            "flows cannot approve or deny held calls",
        ));
    }
    if name == manifest::CONNECTIONS_TOOL
        && arguments.get("op").and_then(Value::as_str) == Some("connect")
        && arguments.contains_key("handle")
    {
        return Ok(tool_error(
            "handle_bindings_removed",
            "use credential_id during issue_ticket enrollment, then connect with ticket_id",
        ));
    }
    if contains_secret_input(arguments) {
        return Ok(tool_error(
            "secret_input_rejected",
            "credential material may only enter through the binding-ticket ceremony",
        ));
    }
    if connector_home::tool_effect(name, op) {
        if let Some(refusal) = state.runtime.connector_home.refusal() {
            return Ok(refusal);
        }
    }
    let call = FacadeArguments {
        state,
        arguments,
        principal_key: &principal_key,
        op,
    };
    let response = match (name, op) {
        (manifest::GITHUB_TOOL, Some("bindings.read")) => {
            let mut response = match arguments.get("connection_id").and_then(Value::as_str) {
                Some(id) => match plexus_core::github::control::bindings_read(
                    state.store(),
                    &principal_key,
                    id,
                ) {
                    Ok(result) => json!({"result":result}),
                    Err(denial) => denial_response(&denial),
                },
                None => json!({"error":{"code":"invalid_request"}}),
            };
            if let Err(error) = state.store().audit_github_control(
                &principal_key,
                None,
                None,
                "github.bindings.read",
                &fresh_request_id(),
                response.pointer("/error/code").and_then(Value::as_str),
            ) {
                warn_audit_failed(&mut response, "github.bindings.read", &error);
            }
            response
        }
        (manifest::GITHUB_READ_TOOL, _) => {
            let action = arguments
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("");
            let repository = arguments.get("repository").cloned().unwrap_or(Value::Null);
            let args = arguments.get("args").cloned().unwrap_or_else(|| json!({}));
            blocking_section(|| {
                let read = if mode == CallMode::Codemode {
                    plexus_core::github::reads::read_codemode
                } else {
                    plexus_core::github::reads::read_scoped
                };
                match read(
                    &state.runtime.engine,
                    &principal_key,
                    action,
                    &repository,
                    &args,
                    route_scope.as_ref(),
                ) {
                    Ok(result) => json!({"result": result}),
                    Err(plexus_core::github::reads::ReadError::UnsupportedAction) => {
                        json!({"error":{"code":"read_action_unsupported"}})
                    }
                    Err(plexus_core::github::reads::ReadError::Denied(denial)) => {
                        denial_response(&denial)
                    }
                    Err(plexus_core::github::reads::ReadError::Dispatch(outcome)) => {
                        github_read_failure(outcome)
                    }
                    Err(plexus_core::github::reads::ReadError::InvalidResponse) => {
                        json!({"error":{"code":"read_response_invalid"}})
                    }
                    Err(plexus_core::github::reads::ReadError::PageBound) => {
                        json!({"error":{"code":"pre_dispatch_read_incomplete","reason":"page_bound"}})
                    }
                    Err(plexus_core::github::reads::ReadError::LeaseExpired) => {
                        json!({"error":{"code":"pre_dispatch_read_incomplete","reason":"lease_expired"}})
                    }
                    Err(plexus_core::github::reads::ReadError::Refused(
                        "repository_not_visible",
                    )) => {
                        json!({"error":{"code":"repository_not_visible","message":"repository_not_visible","transmission":"not_sent"}})
                    }
                    Err(plexus_core::github::reads::ReadError::Refused(code)) => {
                        tool_error(code, code)
                    }
                    Err(plexus_core::github::reads::ReadError::QuotaExhausted {
                        retry_after_ms,
                    }) => {
                        json!({"error":{"code":"github_actions_quota_exhausted","message":"CI read interrupted before the next GitHub request; earlier requests may already have been sent","transmission":"not_sent","detail":{"retry_after_ms":retry_after_ms}}})
                    }
                }
            })
        }
        (manifest::GITHUB_TOOL, Some("bot_request")) | (manifest::GITHUB_REACT_TOOL, _) => {
            let (request, nonce) = match &reaction_request {
                Some(built) => (built.request.clone(), built.request_nonce.as_str()),
                None => (
                    arguments.get("request").cloned().unwrap_or(Value::Null),
                    arguments
                        .get("request_nonce")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                ),
            };
            let request_id = fresh_request_id();
            let owner = request_id.clone();
            let now = plexus_core::now_ms();
            blocking_section(|| {
                plexus_core::github::facade::bot_request_scoped(
                    state.store(),
                    &state.runtime.engine,
                    &principal_key,
                    route_scope.as_ref(),
                    &request,
                    nonce,
                    &request_id,
                    &owner,
                    now,
                )
            })
        }
        (manifest::CONNECTIONS_TOOL, Some("list")) => return facade_connections_list(&call),
        (manifest::CONNECTIONS_TOOL, Some("connect")) => return facade_connections_connect(&call),
        // Without configure, a connection's filters stay at their empty
        // default and every write action is denied as write_filters_absent
        // with no way to narrow scope through the tool surface. The store
        // bounds the request against the vendor's reviewed manifest.
        (manifest::CONNECTIONS_TOOL, Some("configure")) => {
            return facade_connections_configure(&call)
        }
        (manifest::CONNECTIONS_TOOL, Some("revoke")) => return facade_connections_revoke(&call),
        (manifest::CONNECTIONS_TOOL, Some("check" | "inspect")) => {
            return facade_connections_check(&call)
        }
        (manifest::CONNECTIONS_TOOL, _) => {
            json!({"error": {"code": "invalid_operation", "message": "unsupported connection operation"}})
        }
        // Pre-connection discovery: which vendors can be connected at all.
        // Every other catalog projection is connection-scoped, so on a fresh
        // install this is the only way to see what the module carries.
        (manifest::CATALOG_TOOL, Some("apps")) => return facade_catalog_apps(&call),
        (manifest::CATALOG_TOOL, Some("list" | "inspect")) => return facade_catalog_list(&call),
        (manifest::CATALOG_TOOL, _) => {
            json!({"error": {"code": "invalid_operation", "message": "catalog requires apps, list, or inspect"}})
        }
        (manifest::INVOKE_TOOL, Some("call")) => {
            if let Some(missing) = missing_string_fields(arguments, &["connection", "action"]) {
                return Ok(json!({"error": {
                    "code": "invalid_request",
                    "message": format!("invoke requires {}", missing.join(" and ")),
                    "missing": missing,
                    "example": {"op": "call", "connection": "conn-exa", "action": "web_search_exa", "args": {}}
                }}));
            }
            let connection_id = arguments
                .get("connection")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let action = arguments
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let call_agent = resolve_call_agent(route_scope.as_ref());
            let args = arguments.get("args").cloned().unwrap_or_else(|| json!({}));
            let mut request =
                AuthorizationRequest::new(&principal_key, connection_id, action, args);
            if let Some(agent_id) = call_agent.attributed {
                request = request.with_attributed_agent(agent_id);
            }
            // Under a delegating scope whose owner is authorized, the engine
            // judges this call as the scope's agent: the agent's own grant is
            // required on top of this module's grant.
            if let Some(scope) = route_scope.clone() {
                request = request.with_scope(scope);
            }
            if let Some(schema_hash) = arguments.get("schema_hash").and_then(Value::as_str) {
                request = request.with_schema_hash(schema_hash);
            }
            if let Some(call_key) = object.get(CALL_KEY_FIELD).and_then(Value::as_str) {
                request = request.with_call_key(call_key);
            }
            if let Some(relay_origin) = relay_origin.clone() {
                request = request.with_relay_origin(relay_origin);
            }
            // Authorization first: the freshness check `dispatch_checked`
            // runs before sending may contact the vendor, so it never runs for
            // a caller the engine refused.
            let home = state.runtime.connector_home.clone();
            let guard_budget = budget.clone();
            let engine = state
                .runtime
                .engine
                .clone()
                .with_connector_home_guard(Arc::new(move || {
                    home.refusal()
                        .or_else(|| guard_budget.expired().then(request_expired_reply))
                }));
            blocking_section(|| match engine.invoke_held(request, held_deadline) {
                Ok(outcome) => dispatch_response(outcome),
                Err(denial) => denial_response(&denial),
            })
        }
        (manifest::INVOKE_TOOL, _) => {
            // Name the whole shape rather than only the missing op. A caller who
            // reaches here guessed the envelope, and telling them "requires
            // call" sends them round again to guess the parameter names — which
            // are `connection` and `args`, not the `connection_id`/`arguments`
            // an operator naturally reaches for.
            json!({"error": {
                "code": "invalid_operation",
                "message": "invoke requires op=call with connection, action, and optional args",
                "example": {"op": "call", "connection": "conn-exa", "action": "web_search_exa", "args": {}}
            }})
        }
        (manifest::WEB_SEARCH_TOOL, _) => {
            // Pass every web-search argument to core's closed-schema validator;
            // undeclared identity-token fields were already refused at ingress.
            blocking_section(|| {
                match state.runtime.web_search.search_scoped(
                    &state.runtime.engine,
                    &principal_key,
                    arguments,
                    route_scope.as_ref(),
                    relay_origin.as_ref(),
                ) {
                    Ok(response) => json!({"result": response}),
                    Err(refusal) => refusal.to_wire(),
                }
            })
        }
        (manifest::CODE_SEARCH_TOOL, _) => blocking_section(|| {
            match state.runtime.code_search.search_scoped(
                &state.runtime.engine,
                &principal_key,
                arguments,
                route_scope.as_ref(),
                relay_origin.as_ref(),
            ) {
                Ok(response) => json!({"result": response}),
                Err(refusal) => refusal.to_wire(),
            }
        }),
        (manifest::WITHDRAW_TOOL, _) => blocking_section(|| {
            withdraw_response(
                &state.runtime.engine,
                &principal_key,
                route_scope.as_ref(),
                object.get(CALL_KEY_FIELD),
                arguments,
            )
        }),
        (manifest::REQUESTS_TOOL, Some("inspect")) => return facade_requests_inspect(&call),
        (manifest::REQUESTS_TOOL, Some("list")) => return facade_requests_list(&call),
        (manifest::REQUESTS_TOOL, Some("approve")) => return facade_requests_approve(&call),
        (manifest::REQUESTS_TOOL, Some("deny")) => return facade_requests_deny(&call),
        (manifest::REQUESTS_TOOL, _) => {
            json!({"error": {"code": "invalid_operation", "message": "unsupported request operation"}})
        }
        (manifest::EVENTS_TOOL, Some("register_probe")) => {
            return facade_events_register_probe(&call)
        }
        (manifest::EVENTS_TOOL, Some("subscribe")) => return facade_events_subscribe(&call),
        (manifest::EVENTS_TOOL, Some("get")) | (manifest::EVENTS_GET_TOOL, _) => event_get_reply(
            state.store(),
            arguments,
            &principal_key,
            route_scope.as_ref(),
            audience.as_ref(),
        ),
        (manifest::EVENTS_TOOL, Some("resume")) => return facade_events_resume(&call),
        (manifest::EVENTS_TOOL, Some("list")) => return facade_events_list(&call),
        (manifest::EVENTS_TOOL, Some("ack")) => return facade_events_ack(&call),
        (manifest::EVENTS_TOOL, Some("unsubscribe")) => return facade_events_unsubscribe(&call),
        (manifest::EVENTS_TOOL, Some("set_project")) => return facade_events_set_project(&call),
        (manifest::EVENTS_TOOL, Some("set_deliver_to")) => {
            return facade_events_set_deliver_to(&call)
        }
        (manifest::EVENTS_TOOL, Some("set_actor_source")) => {
            return facade_events_set_actor_source(&call)
        }
        (manifest::EVENTS_TOOL, _) => {
            json!({"error": {"code": "invalid_operation", "message": "unsupported events operation"}})
        }
        _ => json!({"error": {"code": "unknown_method", "message": "unknown plexus facade tool"}}),
    };
    Ok(response)
}

struct FacadeArguments<'a> {
    state: &'a Arc<ModuleState>,
    arguments: &'a serde_json::Map<String, Value>,
    principal_key: &'a str,
    op: Option<&'a str>,
}

fn facade_connections_list(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let principal_key = call.principal_key;
    Ok({
        match state.store().list_connections(principal_key) {
            Ok(connections) => json!({"result": {"connections": connections}}),
            Err(error) => crate::wire::store_failure(
                "connections listed",
                "connections could not be listed",
                &error,
            ),
        }
    })
}

fn facade_connections_connect(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(ticket_id) = arguments.get("ticket_id").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "connect requires ticket_id"}}),
            );
        };
        match state.store().connect_with_ticket(principal_key, ticket_id) {
            Ok(Some(connection)) => {
                // The connection's catalog is first seeded from the
                // reviewed manifest, and discovery then reconciles it with
                // the vendor. A failed seed leaves the connection active
                // (the ticket is spent) but its catalog incomplete, so it
                // is reported as degraded discovery, never as complete.
                if let Err(error) = state.store().seed_catalog_from_manifest(
                    principal_key,
                    &connection.connection_id,
                    &connection.app_key,
                ) {
                    eprintln!(warn catalog:
                        "catalog seed failed during connect of {}: {error}",
                        connection.connection_id
                    );
                    return Ok(json!({"result": {
                        "connection": connection,
                        "discovery": "degraded",
                        "reason": "the reviewed manifest's actions could not be seeded; the module log names the cause",
                    }}));
                }
                // Consuming the ticket has already committed the binding and
                // activated the connection, and the ticket is now spent. So a
                // discovery failure here is NOT a failed connect: reporting
                // one would tell the operator to retry a ticket that no longer
                // exists, while an active connection they cannot see sits in
                // the store. Every outcome therefore returns the connection,
                // with discovery reported separately and honestly — the
                // catalog is refreshed again at invoke time.
                match blocking_section(|| {
                    state.runtime.reconciler.discover_for_connection(
                        principal_key,
                        &connection.connection_id,
                        state.runtime.credential_source().as_ref(),
                        state.runtime.endpoint_override.as_deref(),
                    )
                }) {
                    Ok(_) => {
                        json!({"result": {"connection": connection, "discovery": "complete"}})
                    }
                    Err(CatalogError::TransportUnavailable { kind }) => {
                        json!({"result": {"connection": connection, "discovery": "unavailable", "reason": format!("transport kind '{kind}' is not available")}})
                    }
                    Err(CatalogError::Credential) => {
                        json!({"result": {"connection": connection, "discovery": "credential_unresolved", "reason": "credential could not be resolved during connect discovery"}})
                    }
                    // Not a store failure and deliberately not an error:
                    // connect SUCCEEDS while reporting that discovery did
                    // not complete, because refusing here would consume the
                    // single-use ticket and leave the operator with neither
                    // a connection nor a ticket. The cause is still logged,
                    // since a degraded discovery with no recorded reason is
                    // the same dead end this pass exists to close.
                    Err(error) => {
                        eprintln!(warn catalog: "discovery degraded during connect: {error}");
                        json!({"result": {"connection": connection, "discovery": "degraded"}})
                    }
                }
            }
            Ok(None) => {
                json!({"error": {"code": "binding_ticket_invalid", "message": "binding ticket is expired, consumed, or unknown"}})
            }
            Err(error) => crate::wire::store_failure(
                "connection completed",
                "connection could not be completed",
                &error,
            ),
        }
    })
}

fn facade_connections_configure(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(connection_id) = arguments.get("connection").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "configure requires connection"}}),
            );
        };
        let Some(filters) = arguments.get("resource_filters") else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "configure requires resource_filters"}}),
            );
        };
        // The store checks the admin grant and writes the filters in one
        // fenced transaction, so a grant revoked mid-request cannot be outrun.
        match state.store().configure_connection_filters_if_admin(
            principal_key,
            connection_id,
            principal_key,
            filters,
        ) {
            Ok(ConfigureOutcome::AdminRequired) => {
                json!({"error": {"code": "connection_admin_required", "message": "connection administration grant required"}})
            }
            Ok(ConfigureOutcome::Configured(stored)) => {
                json!({"result": {"resource_filters": stored}})
            }
            Ok(ConfigureOutcome::ConnectionNotFound) => {
                json!({"error": {"code": "connection_not_found", "message": "connection was not found"}})
            }
            Ok(ConfigureOutcome::ManifestMissing) => {
                json!({"error": {"code": "manifest_missing", "message": "vendor manifest is not in the catalog"}})
            }
            Ok(ConfigureOutcome::UndeclaredFilter(key)) => {
                json!({"error": {"code": "undeclared_filter", "message": format!("filter key '{key}' is not declared by the vendor manifest"), "key": key}})
            }
            // Distinct from undeclared_filter because the fixes differ:
            // an undeclared filter names a key the VENDOR does not have,
            // while this names one this OPERATION does not read. Telling
            // an operator their key is not in the manifest when they
            // actually mistyped `write_enabling` sends them to read
            // vendor documentation for a spelling mistake.
            Ok(ConfigureOutcome::UnreadFilterKey { key, accepted }) => {
                json!({"error": {
                    "code": "unread_filter_key",
                    "message": format!(
                        "resource_filters key '{key}' is not read by configure (accepted: {})",
                        accepted.join(", ")
                    ),
                    "key": key,
                    "accepted": accepted
                }})
            }
            Ok(ConfigureOutcome::MalformedFilters { field, expected }) => {
                json!({"error": {
                    "code": "malformed_filters",
                    "message": format!("resource_filters {field} must be {expected}"),
                    "field": field,
                    "expected": expected
                }})
            }
            Err(error) => crate::wire::store_failure(
                "filters configured",
                "filters could not be configured",
                &error,
            ),
        }
    })
}

fn facade_connections_revoke(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(connection_id) = arguments.get("connection").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "revoke requires connection"}}),
            );
        };
        // The admin check and the revocation share one fenced transaction.
        // Transports are unregistered only once `Revoked` reports the commit.
        match state
            .store()
            .revoke_connection_if_admin(principal_key, connection_id, principal_key)
        {
            Ok(ConnectionAdminRevokeOutcome::AdminRequired) => {
                json!({"error": {"code": "connection_admin_required", "message": "connection administration grant required"}})
            }
            Ok(ConnectionAdminRevokeOutcome::Revoked) => {
                state
                    .runtime
                    .mcp_transport
                    .unregister_connection(connection_id);
                state
                    .runtime
                    .rest_transport
                    .unregister_connection(connection_id);
                json!({"result": {"revoked": true}})
            }
            Ok(ConnectionAdminRevokeOutcome::ConnectionNotFound) => {
                json!({"error": {"code": "connection_not_found", "message": "connection was not found"}})
            }
            Err(error) => crate::wire::store_failure(
                "connection revoked",
                "connection could not be revoked",
                &error,
            ),
        }
    })
}

fn facade_connections_check(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(connection_id) = arguments.get("connection").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "check requires connection"}}),
            );
        };
        match state.store().connection(principal_key, connection_id) {
            Ok(Some(connection)) => json!({"result": {"connection": {
                "connection_id": connection.connection_id,
                "app_key": connection.app_key,
                "status": connection.status,
                "generation": connection.generation,
                "credential_bound": connection.has_credential_binding
            }}}),
            Ok(None) => {
                json!({"error": {"code": "connection_not_found", "message": "connection was not found"}})
            }
            Err(error) => crate::wire::store_failure(
                "connection read",
                "connection could not be read",
                &error,
            ),
        }
    })
}

fn facade_catalog_apps(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let principal_key = call.principal_key;
    Ok({
        match state.store().list_manifest_summaries(principal_key) {
            Ok(apps) => json!({"result": {"apps": apps}}),
            Err(error) => crate::wire::store_failure(
                "app catalog read",
                "app catalog could not be read",
                &error,
            ),
        }
    })
}

fn facade_catalog_list(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let op = call.op;
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(connection_id) = arguments.get("connection").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "catalog list/inspect requires connection; use op=apps to discover connectable vendors"}}),
            );
        };
        match state
            .store()
            .list_catalog_actions(principal_key, connection_id)
        {
            Ok(actions) => {
                let actions = if op == Some("inspect") {
                    let Some(action) = arguments
                        .get("action")
                        .and_then(Value::as_str)
                        .filter(|action| !action.is_empty())
                    else {
                        return Ok(tool_error(
                            "invalid_request",
                            "catalog inspect requires action",
                        ));
                    };
                    actions
                        .into_iter()
                        .filter(|row| row.name == action)
                        .collect::<Vec<_>>()
                } else {
                    actions
                };
                json!({"result": {"actions": actions}})
            }
            Err(error) => {
                crate::wire::store_failure("catalog read", "catalog could not be read", &error)
            }
        }
    })
}

fn facade_requests_inspect(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(id) = arguments
            .get("request_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            return Ok(tool_error(
                "invalid_request",
                "requests inspect requires request_id",
            ));
        };
        match state.store().list_action_requests(principal_key) {
            Ok(requests) => {
                json!({"result":{"requests":requests.into_iter().filter(|request| request.request_id == id).collect::<Vec<_>>(),"reconciliations":[]}})
            }
            Err(error) => {
                wire::store_failure("request inspected", "request could not be read", &error)
            }
        }
    })
}

fn facade_requests_list(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let principal_key = call.principal_key;
    Ok({
        match state
            .store()
            .list_action_requests(principal_key)
            .and_then(|requests| {
                state
                    .store()
                    .list_write_reconciliations(principal_key)
                    .map(|reconciliations| (requests, reconciliations))
            }) {
            Ok((requests, (reconciliations, reconciliations_truncated))) => {
                json!({"result": {"requests": requests, "reconciliations": reconciliations, "reconciliations_truncated": reconciliations_truncated}})
            }
            Err(error) => {
                crate::wire::store_failure("requests read", "requests could not be read", &error)
            }
        }
    })
}

fn facade_requests_approve(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(request_id) = arguments.get("request_id").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "approve requires request_id"}}),
            );
        };
        // Approving dispatches the call, which may reach a blocking vendor
        // transport and, for a request raised under a daemon scope, waits
        // on the daemon's scope.describe reply.
        blocking_section(|| {
            match state
                .runtime
                .engine
                .approve_request(principal_key, request_id, principal_key)
            {
                Ok(outcome) => dispatch_response(outcome),
                Err(denial) => denial_response(&denial),
            }
        })
    })
}

fn facade_requests_deny(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(request_id) = arguments.get("request_id").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "deny requires request_id"}}),
            );
        };
        match state
            .runtime
            .engine
            .deny_request(principal_key, request_id, principal_key)
        {
            Ok(true) => json!({"result": {"denied": true}}),
            Ok(false) => {
                json!({"error": {"code": "request_not_pending", "message": "request is no longer pending"}})
            }
            Err(denial) => denial_response(&denial),
        }
    })
}

fn facade_events_register_probe(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let mut missing =
            missing_string_fields(arguments, &["connection", "name", "script_source"])
                .unwrap_or_default();
        let cadence = arguments.get("cadence_s").and_then(Value::as_i64);
        if cadence.is_none_or(|value| value <= 0) {
            missing.push("cadence_s".to_string());
        }
        let actions = arguments.get("actions").and_then(Value::as_array);
        if actions.is_none() {
            missing.push("actions".to_string());
        }
        if arguments.get("return_schema").is_none() {
            missing.push("return_schema".to_string());
        }
        if arguments.get("rearm").and_then(Value::as_str).is_none() {
            missing.push("rearm".to_string());
        }
        if !missing.is_empty() {
            return Ok(json!({"error": {
                "code": "invalid_request",
                "message": format!("register_probe requires {}", missing.join(" and ")),
                "missing": missing
            }}));
        }
        let connection_id = arguments
            .get("connection")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let name = arguments
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let script_source = arguments
            .get("script_source")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if script_source.len() > MAX_PROBE_SCRIPT_BYTES
            || actions.is_some_and(|items| items.len() > MAX_PROBE_ACTIONS)
        {
            return Ok(tool_error(
                "invalid_request",
                "probe script exceeds 64 KiB or actions exceed 100",
            ));
        }
        let rearm = arguments
            .get("rearm")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let action_names = actions
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if action_names.len() != actions.map_or(0, Vec::len) {
            return Ok(json!({"error": {
                "code": "invalid_request",
                "message": "actions must contain only strings"
            }}));
        }
        let return_schema = arguments
            .get("return_schema")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let fixed_args = arguments
            .get("fixed_args")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let cursor_state = arguments
            .get("cursor_state")
            .cloned()
            .unwrap_or_else(|| json!({}));
        match state.store().register_probe(
            principal_key,
            connection_id,
            plexus_core::ProbeRegistration {
                name,
                actions: &action_names,
                script_source,
                return_schema: &return_schema,
                rearm,
                cadence_s: cadence.unwrap_or_default(),
                fixed_args: &fixed_args,
                cursor_state: &cursor_state,
            },
        ) {
            Ok(Ok(subscription)) => json!({"result": {"subscription": subscription}}),
            Ok(Err(refusal)) => json!({
                "error": {
                    "code": refusal.code(),
                    "message": refusal.to_string()
                }
            }),
            Err(error) => crate::wire::store_failure(
                "probe registered",
                "probe could not be registered",
                &error,
            ),
        }
    })
}

fn facade_events_subscribe(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let mut missing =
            missing_string_fields(arguments, &["connection", "action"]).unwrap_or_default();
        let cadence = arguments.get("cadence_s").and_then(Value::as_i64);
        if cadence.is_none_or(|value| value <= 0) {
            missing.push("cadence_s".to_string());
        }
        let mut invalid = Vec::new();
        if arguments
            .get("fixed_args")
            .is_some_and(|value| !value.is_object())
        {
            invalid.push("fixed_args".to_string());
        }
        if !missing.is_empty() || !invalid.is_empty() {
            let mut reasons = Vec::new();
            if !missing.is_empty() {
                reasons.push(format!("requires {}", missing.join(" and ")));
            }
            if !invalid.is_empty() {
                reasons.push(format!("{} must be an object", invalid.join(" and ")));
            }
            return Ok(json!({"error": {
                "code": "invalid_request",
                "message": format!("subscribe {}", reasons.join("; ")),
                "missing": missing,
                "invalid": invalid,
                "example": {"op": "subscribe", "connection": "conn-exa", "action": "web_search_exa", "cadence_s": 300, "fixed_args": {}}
            }}));
        }
        let connection_id = arguments
            .get("connection")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let action = arguments
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let cadence_s = cadence.unwrap_or_default();
        let cursor_state = arguments
            .get("cursor_state")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let fixed_args = arguments
            .get("fixed_args")
            .cloned()
            .unwrap_or_else(|| json!({}));
        match state.store().subscribe_with_cursor_state(
            principal_key,
            connection_id,
            action,
            cadence_s,
            &cursor_state,
            &fixed_args,
        ) {
            Ok(Ok(subscription)) => json!({"result": {"subscription": subscription}}),
            Ok(Err(refusal)) => json!({
                "error": {
                    "code": refusal.code(),
                    "message": refusal.to_string()
                }
            }),
            Err(error) => crate::wire::store_failure(
                "subscription created",
                "subscription could not be created",
                &error,
            ),
        }
    })
}

fn facade_events_resume(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(subscription_id) = subscription_id_arg(arguments) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "resume requires subscription_id"}}),
            );
        };
        match state.store().resume(principal_key, subscription_id) {
            Ok(Ok(subscription)) => json!({"result": {"subscription": subscription}}),
            Ok(Err(refusal)) => json!({
                "error": {
                    "code": refusal.code(),
                    "message": refusal.to_string()
                }
            }),
            Err(error) => crate::wire::store_failure(
                "subscription resumed",
                "subscription could not be resumed",
                &error,
            ),
        }
    })
}

fn facade_events_list(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let limit = match arguments.get("limit") {
            None => None,
            Some(value) => match value.as_u64().filter(|size| (1..=1000).contains(size)) {
                Some(size) => Some(size as usize),
                None => {
                    return Ok(tool_error(
                        "invalid_request",
                        "limit must be an integer from 1 to 1000",
                    ))
                }
            },
        };
        let after = match arguments.get("after") {
            None => None,
            Some(value) => match (
                value.get("created_at_ms").and_then(Value::as_i64),
                value.get("event_id").and_then(Value::as_str),
            ) {
                (Some(at), Some(id))
                    if !id.is_empty()
                        && value.as_object().is_some_and(|cursor| cursor.len() == 2) =>
                {
                    Some((at, id))
                }
                _ => {
                    return Ok(tool_error(
                        "invalid_request",
                        "after requires only created_at_ms and event_id",
                    ))
                }
            },
        };
        let connection_id = arguments.get("connection").and_then(Value::as_str);
        let subscription_id = subscription_id_arg(arguments);
        // Log the principal resolved from the route stamp so an operator can
        // distinguish a quiet feed from a consumer using the wrong identity.
        // The caller's intended identity does not establish its actual authority.
        eprintln!(info governance:
            "events list from principal '{principal_key}' (connection={}, subscription={})",
            connection_id.unwrap_or("<any>"),
            subscription_id.unwrap_or("<any>")
        );
        // This projection names every grant the caller can exercise, so a
        // principal and connection absent from `grants` has no consume grant.
        // It reveals none of another principal's authority. Keep each stored
        // grant separate: one connection can be live while another is
        // expired, and a caller-wide scalar would hide that failure.
        let now = plexus_core::now_ms();
        match (
            state.store().list_events_page_with_consume_authority(
                principal_key,
                connection_id,
                subscription_id,
                now,
                limit,
                after,
            ),
            state.store().list_subscriptions_including_granted(
                principal_key,
                connection_id,
                subscription_id,
                now,
            ),
        ) {
            (Ok((listing, has_more)), Ok(subscriptions)) => {
                let next_after = has_more.then(|| listing.events.last().map(|event| json!({"created_at_ms":event.created_at_ms,"event_id":event.event_id}))).flatten();
                let mut reply = json!({"result": {
                    "events": listing.events,
                    "subscriptions": subscriptions,
                    "events_consume_authority": {"grants": listing.consume_authority}
                }});
                if let Some(cursor) = next_after {
                    reply["result"]["next_after"] = cursor;
                }
                reply
            }
            // Each failed read is logged with its cause; the reply stays
            // the same generic store_failure.
            (Err(error), _) => {
                crate::wire::store_failure("events listed", "events could not be read", &error)
            }
            (Ok(_), Err(error)) => crate::wire::store_failure(
                "subscriptions listed",
                "events could not be read",
                &error,
            ),
        }
    })
}

fn facade_events_ack(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(event_ids) = arguments.get("event_ids").and_then(Value::as_array) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "ack requires event_ids"}}),
            );
        };
        let event_ids = event_ids
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>();
        if event_ids.len() != arguments["event_ids"].as_array().map_or(0, Vec::len) {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "event_ids must contain only strings"}}),
            );
        }
        let mut event_ids = event_ids;
        event_ids.sort();
        event_ids.dedup();
        let ack_now = plexus_core::now_ms();
        match state
            .store()
            .ack_events_including_granted(principal_key, &event_ids, ack_now)
        {
            // Report the count AND which ids did not land. A consumer acks
            // what it has delivered, so an id that acks nothing means the
            // two sides disagree about what exists: a wrong id, another
            // principal's event, or one already acked. Returning only a
            // count makes that indistinguishable from success -- the caller
            // would have to compare it against its own request length to
            // notice, and the failure is silent redelivery forever while
            // both sides report healthy.
            //
            // Not an error: a partial ack genuinely acked something, and
            // failing the whole call would make one stale id block a batch
            // of good ones. The unacked list is the actionable half.
            Ok(acked) if acked == event_ids.len() => {
                json!({"result": {"acked": acked, "unacked": []}})
            }
            Ok(acked) => partial_ack_reply(
                acked,
                state
                    .store()
                    .unacked_of_at(principal_key, &event_ids, ack_now),
            ),
            Err(error) => crate::wire::store_failure(
                "events acknowledged",
                "events could not be acknowledged",
                &error,
            ),
        }
    })
}

fn facade_events_unsubscribe(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(subscription_id) = subscription_id_arg(arguments) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "unsubscribe requires subscription_id"}}),
            );
        };
        match state.store().unsubscribe(principal_key, subscription_id) {
            Ok(true) => json!({"result": {"unsubscribed": true}}),
            Ok(false) => {
                json!({"error": {"code": "subscription_not_found", "message": "subscription was not found"}})
            }
            Err(error) => crate::wire::store_failure(
                "subscription removed",
                "subscription could not be removed",
                &error,
            ),
        }
    })
}

fn facade_events_set_project(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(subscription_id) = subscription_id_arg(arguments) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "set_project requires subscription_id"}}),
            );
        };
        // An explicit null clears the binding. An absent `project_id` is
        // refused rather than read as a clear: otherwise a misspelled
        // field name (projectId, project) would silently wipe the binding
        // the caller meant to set. Any other value is refused for the same
        // reason.
        let project_id = match arguments.get("project_id") {
            None => {
                return Ok(json!({"error": {
                    "code": "invalid_request",
                    "message": "set_project requires project_id (a string, or null to clear)",
                    "missing": ["project_id"],
                }}));
            }
            Some(Value::Null) => None,
            Some(Value::String(project_id)) if project_id.chars().any(char::is_control) => {
                return Ok(json!({"error": {
                    "code": "invalid_request",
                    "message": "project_id must not contain control characters",
                }}));
            }
            Some(Value::String(project_id)) => Some(project_id.as_str()),
            Some(_) => {
                return Ok(json!({"error": {
                    "code": "invalid_request",
                    "message": "project_id must be a string, or null to clear",
                }}));
            }
        };
        match state
            .store()
            .set_subscription_project(principal_key, subscription_id, project_id)
        {
            Ok(true) => json!({"result": {
                "subscription_id": subscription_id,
                "project_id": project_id
            }}),
            Ok(false) => {
                json!({"error": {"code": "subscription_not_found", "message": "subscription was not found"}})
            }
            Err(error) => crate::wire::store_failure(
                "subscription project set",
                "subscription project could not be set",
                &error,
            ),
        }
    })
}

fn facade_events_set_deliver_to(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let mut missing = Vec::new();
        // Prefer `subscription_id` over its `subscription` alias, as the
        // other operations do. Calls supplying both fields must act on the
        // same subscription regardless of the operation.
        let subscription_id = subscription_id_arg(arguments).filter(|value| !value.is_empty());
        if subscription_id.is_none() {
            missing.push("subscription_id".to_string());
        }
        let deliver_to = match arguments.get("deliver_to") {
            Some(Value::Null) => Some(None),
            Some(Value::String(agent_id)) => Some(Some(agent_id.as_str())),
            Some(_) => None,
            None => {
                missing.push("deliver_to".to_string());
                None
            }
        };
        if !missing.is_empty() {
            return Ok(json!({"error": {
                "code": "invalid_request",
                "message": format!("set_deliver_to requires {}", missing.join(" and ")),
                "missing": missing,
            }}));
        }
        let Some(subscription_id) = subscription_id else {
            unreachable!("missing subscription returned above");
        };
        let Some(deliver_to) = deliver_to else {
            return Ok(json!({"error": {
                "code": "invalid_request",
                "message": "deliver_to must be a string or null",
            }}));
        };
        match deliver_to {
            Some(agent_id) => match state.runtime.agent_registry.lookup(agent_id) {
                plexus_core::AgentLookup::Known => {
                    match state.store().set_subscription_deliver_to(
                        principal_key,
                        subscription_id,
                        Some(agent_id),
                    ) {
                        Ok(true) => json!({"result": {
                            "subscription_id": subscription_id,
                            "deliver_to": agent_id,
                        }}),
                        Ok(false) => {
                            json!({"error": {"code": "subscription_not_found", "message": "subscription was not found"}})
                        }
                        Err(error) => crate::wire::store_failure(
                            "subscription delivery target set",
                            "subscription delivery target could not be set",
                            &error,
                        ),
                    }
                }
                plexus_core::AgentLookup::Unknown => json!({"error": {
                    "code": "deliver_to_unknown_agent",
                    "message": "deliver_to does not name a known agent",
                }}),
                plexus_core::AgentLookup::Retired => json!({"error": {
                    "code": "deliver_to_agent_retired",
                    "message": "deliver_to names a retired agent",
                }}),
                plexus_core::AgentLookup::Unavailable => json!({"error": {
                    "code": "agent_registry_unavailable",
                    "message": "agent registry is unavailable; retry later",
                }}),
            },
            None => match state.store().set_subscription_deliver_to(
                principal_key,
                subscription_id,
                None,
            ) {
                Ok(true) => json!({"result": {
                    "subscription_id": subscription_id,
                    "deliver_to": Value::Null,
                }}),
                Ok(false) => {
                    json!({"error": {"code": "subscription_not_found", "message": "subscription was not found"}})
                }
                Err(error) => crate::wire::store_failure(
                    "subscription delivery target cleared",
                    "subscription delivery target could not be cleared",
                    &error,
                ),
            },
        }
    })
}

fn facade_events_set_actor_source(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(subscription_id) = subscription_id_arg(arguments) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "set_actor_source requires subscription_id"}}),
            );
        };
        // An explicit null clears; a missing key is refused, matching
        // `set_project` and `set_deliver_to`, so a misspelled field cannot
        // wipe the binding. An object is decoded through the closed
        // ActorSource shape before any store write, so malformed types or
        // unknown fields cannot be persisted as a complete-looking binding.
        let actor_source = match arguments.get("actor_source") {
            None => {
                return Ok(json!({"error": {
                    "code": "invalid_request",
                    "message": "set_actor_source requires actor_source (an object, or null to clear)",
                    "missing": ["actor_source"],
                }}));
            }
            Some(Value::Null) => None,
            Some(value) => match serde_json::from_value::<ActorSource>(value.clone()) {
                Ok(source) => Some(source),
                Err(error) => {
                    return Ok(json!({"error": {
                        "code": "invalid_request",
                        "message": format!("actor_source is invalid: {error}")
                    }}));
                }
            },
        };
        match state.store().set_subscription_actor_source(
            principal_key,
            subscription_id,
            actor_source.as_ref(),
        ) {
            Ok(true) => json!({"result": {
                "subscription_id": subscription_id,
                "actor_source": actor_source
            }}),
            Ok(false) => {
                json!({"error": {"code": "subscription_not_found", "message": "subscription was not found"}})
            }
            Err(error) => crate::wire::store_failure(
                "subscription actor source set",
                "subscription actor source could not be set",
                &error,
            ),
        }
    })
}

fn subscription_id_arg(arguments: &serde_json::Map<String, Value>) -> Option<&str> {
    arguments
        .get("subscription_id")
        .or_else(|| arguments.get("subscription"))
        .and_then(Value::as_str)
}

/// Build the reply when a call acknowledges fewer events than it requested.
///
/// Return an error if reading the remaining unacknowledged IDs fails. An empty
/// `unacked` list would falsely claim that the call acknowledged every named
/// event. Include the count already acknowledged because those changes have
/// committed even though the follow-up read failed.
fn partial_ack_reply<E: std::fmt::Display>(acked: usize, unacked: Result<Vec<String>, E>) -> Value {
    match unacked {
        Ok(unacked) => json!({"result": {"acked": acked, "unacked": unacked}}),
        Err(error) => {
            let mut reply = crate::wire::store_failure(
                "unacknowledged events read",
                "some events were acknowledged, but which ones were not could not be read; list the events to see what remains",
                &error,
            );
            reply["error"]["acked"] = json!(acked);
            reply
        }
    }
}

fn event_get_reply(
    store: &PlexusStore,
    arguments: &serde_json::Map<String, Value>,
    principal_key: &str,
    route_scope: Option<&CallScope>,
    audience: Option<&flow_audience::Audience>,
) -> Value {
    let is_basal_flow = principal_key == principal::BASAL_PRINCIPAL
        && route_scope.is_some_and(|scope| scope.flow_id.is_some());
    let is_prefrontal_core = principal_key == plexus_core::github::PREFRONTAL_PRINCIPAL;
    if !is_basal_flow && !is_prefrontal_core {
        return tool_error(
            "events_get_carrier_refused",
            "events.get is restricted to reserved:basal on a flow route or reserved:prefrontal-core",
        );
    }
    let Some(event_key) = arguments.get("event_key").and_then(Value::as_str) else {
        return json!({
            "error": {
                "code": "invalid_request",
                "field": "event_key",
                "message": "get requires event_key",
            }
        });
    };
    if event_key.len() != 64
        || !event_key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return json!({
            "error": {
                "code": "invalid_request",
                "field": "event_key",
                "message": "event_key must be 64 lowercase hex characters",
            }
        });
    }
    let Some(event_name) = arguments.get("event_name").and_then(Value::as_str) else {
        return json!({
            "error": {
                "code": "invalid_request",
                "field": "event_name",
                "message": "get requires event_name",
            }
        });
    };
    // The source body is the default. V2 is an immutable stored envelope;
    // absent envelopes are refused without falling back to another version.
    let version = match arguments.get("version") {
        None => 1,
        Some(value) => match value.as_u64() {
            Some(version @ (1 | 2)) => version,
            _ => {
                return json!({
                    "error": {
                        "code": "invalid_request",
                        "field": "version",
                        "message": "version must be 1 or 2",
                    }
                });
            }
        },
    };

    // Who may see the event decides which reader is used:
    // - a flow run by Basal (the flow module) whose session the daemon stamped
    //   with an agent reads as that agent, so it sees only events from
    //   repositories bound to that agent's GitHub bot;
    // - every other caller, Prefrontal core included, reads only through its own
    //   events_consume grants, even on a route that carries an agent, so an
    //   agent's scope never widens a module's access.
    let reader = if let Some(agent_id) =
        plexus_core::scope::basal_flow_read_agent(principal_key, route_scope)
    {
        EventReader::Agent { agent_id }
    } else {
        EventReader::Consumer {
            principal: principal_key,
        }
    };
    match store.event_by_key_version(event_key, reader, plexus_core::now_ms(), version as u8) {
        Ok(EventLookupOutcome::Found(event)) => {
            if audience.is_some_and(|audience| {
                !flow_audience::repository_allowed(store, audience, &event.headers.repo)
            }) {
                return tool_error("event_not_visible", "event not visible");
            }
            let (body, digest, published_at) = if version == 2 {
                let (Some(body), Some(digest)) = (&event.envelope_v2, &event.digest_v2) else {
                    return tool_error("event_not_visible", "event not visible");
                };
                (body, digest, event.published_v2_at_ms)
            } else {
                (&event.body, &event.digest, event.published_at_ms)
            };
            if event.event_name != event_name {
                tool_error(
                    "event_name_mismatch",
                    &format!(
                        "event_name mismatch: expected {}, got {}",
                        event.event_name, event_name
                    ),
                )
            } else {
                json!({
                    "result": {
                        "body": body,
                        "digest": digest,
                        "event_key": event.event_key,
                        "event_name": event.event_name,
                        "repo": event.headers.repo,
                        "published_at": published_at,
                    }
                })
            }
        }
        Ok(EventLookupOutcome::NotFound) | Ok(EventLookupOutcome::NotVisible) => {
            tool_error("event_not_visible", "event not visible")
        }
        Err(error) => crate::wire::store_failure("read event", "event could not be read", &error),
    }
}

/// Build the last observed health report without doing store or vendor IO.
fn connector_home_health(state: &ModuleState) -> ModuleControlResponse {
    let mut report = state
        .health
        .report_with_transports(Some(health::TransportPanicRecoveries {
            mcp: state.runtime.mcp_transport.panic_recoveries(),
            rest: state.runtime.rest_transport.panic_recoveries(),
        }));
    if let ModuleControlResponse::HealthCheck {
        status,
        detail,
        metrics,
    } = &mut report
    {
        if !state.runtime.connector_home.held() {
            *status = subc_protocol::session::HealthStatus::Degraded;
            *detail = Some("connector_home_not_held".into());
        }
        if let Some(metrics) = metrics {
            metrics["connectorHome"] = state.runtime.connector_home.status();
            let cached = state
                .health
                .store_metrics
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cached) = cached.as_object() {
                for (key, value) in cached {
                    metrics[key] = value.clone();
                }
            }
            metrics["lastPublishError"] = json!(state.health.last_publish_error());
        }
    }
    report
}

fn refresh_store_health(state: &ModuleState, principals: &[String]) {
    let mut metrics = json!({});
    match state.store().event_outbox_health() {
        Ok(outbox) => {
            metrics["outboxDepth"] = json!(outbox.depth);
            metrics["overlappingKeyRows"] = json!(outbox.overlapping_key_rows);
            metrics["droppedOnUnsubscribe"] = json!(outbox.dropped_on_unsubscribe);
            metrics["droppedOnDelete"] = json!(outbox.dropped_on_delete);
            metrics["orphanedMarkers"] = json!(outbox.orphaned_markers);
        }
        Err(error) => eprintln!(warn health: "outbox health read failed: {error}"),
    }
    let stored_cadence = effective_ci_cadence_from_store(
        state.store(),
        principals,
        plexus_core::scheduler::RelayPollingHealth::slow_polling(state.health.relay.as_ref()),
    );
    match stored_cadence
        .map(Ok)
        .unwrap_or_else(|| state.store().ci_quota_cadence_s())
    {
        Ok(cadence) => metrics["effectiveCiCadenceS"] = json!(cadence),
        Err(error) => {
            eprintln!(warn health: "CI quota cadence read failed: {error}");
            metrics["effectiveCiCadenceS"] = Value::Null;
        }
    }
    *state
        .health
        .store_metrics
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = metrics;
}

fn effective_ci_cadence_from_store(
    store: &PlexusStore,
    principals: &[String],
    relay_slow: bool,
) -> Option<i64> {
    let mut stored_cadence: Option<i64> = None;
    let mut cadences = plexus_core::scheduler::PollingCadences::new(store, relay_slow);
    for principal in principals {
        match store.list_subscriptions(principal, None, None) {
            Ok(subs) => {
                for sub in subs {
                    if sub.status == "active" && sub.cursor_kind.as_str() == "ci_runs" {
                        // The CI cadence reported is the shortest among active
                        // CI-run watches, since that watch is due soonest.
                        let cadence = cadences.effective_cadence_s(&sub);
                        stored_cadence = Some(stored_cadence.map_or(cadence, |s| s.min(cadence)));
                    }
                }
            }
            Err(error) => eprintln!(warn health: "CI cadence read failed for {principal}: {error}"),
        }
    }
    stored_cadence
}

#[cfg(test)]
fn run_health_probes(state: &ModuleState) {
    run_health_probes_for(state, &health_probe_principals(state));
}

fn run_health_probes_for(state: &ModuleState, principals: &[String]) {
    let mut total = 0_u64;
    let mut degraded = 0_u64;
    for principal in principals {
        let connections = match state.store().list_connections(principal) {
            Ok(connections) => connections,
            Err(error) => {
                eprintln!(warn health:
                    "health probe connection listing failed for principal {principal}: {error}"
                );
                continue;
            }
        };
        for summary in connections {
            // `degraded` is probed alongside `active`, and that is the whole
            // point of the probe rather than an edge case.
            //
            // A refresh failure sets `degraded`, and only a successful refresh
            // clears it. Skipping non-active connections would make that
            // recovery unreachable: nothing else re-runs discovery either,
            // because reads return early from the freshness check (only writes
            // reach it) and `connect` consumes a single-use ticket that no
            // longer exists.
            //
            // Without this, a connection can stay degraded indefinitely, across
            // restarts, while its vendor is reachable the whole time. Every
            // other status is deliberately skipped: `revoked` and `pending`
            // describe authority, not health, and probing them would resurrect
            // a connection an operator deliberately stopped, so a revoked one
            // is neither probed nor logged here. No production path writes any
            // further status, so none is probed for recovery.
            if summary.status != "active" && summary.status != "degraded" {
                continue;
            }
            total += 1;
            if summary.status == "degraded" {
                degraded += 1;
            }
            if let Err(error) = state.runtime.reconciler.health_probe_connection(
                principal,
                &summary.connection_id,
                state.runtime.credential_source().as_ref(),
            ) {
                eprintln!(warn health:
                    "health probe failed for principal {principal}, connection {}: {error}",
                    summary.connection_id
                );
            }
        }
    }
    // Counted BEFORE probing, from the rows as they stood, so the numbers
    // describe what this pass set out to check. Counting after would report
    // recoveries this pass performed and hide the condition that prompted them.
    state.health.stamp_connections(total, degraded);
}

/// The principals worth scanning: the operator principal plus owners of a
/// subscription or connection.
///
/// The operator principal remains unconditional so a fresh store still gets its
/// boot-time transport registration and health-probe pass. The stored owners
/// come from the two bounded tables that represent work the scheduler can act
/// on; audit history can remain after that work disappears.
fn health_probe_principals(state: &ModuleState) -> Vec<String> {
    let mut principals = vec!["direct".to_string()];
    match state.store().poll_and_probe_principals() {
        Ok(rows) => {
            for principal in rows {
                if !principals.iter().any(|value| value == &principal) {
                    principals.push(principal);
                }
            }
        }
        // Falling back to direct narrows polling as well as probing. The
        // selection-failure gauge cannot see omitted principals: they never
        // reach selection. Keep the lost coverage visible in the diagnostic.
        Err(error) => eprintln!(error health:
            "health probe principal enumeration failed for stored subscription and connection owners; falling back to principal direct only: {error}"
        ),
    }
    principals
}

fn fresh_request_id() -> String {
    static NONCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = NONCE.get_or_init(|| {
        use std::io::Read;
        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .expect("request identity requires operating-system randomness");
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    });
    format!(
        "gh-{nonce}-{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

fn request_expired_reply() -> Value {
    json!({"error":{"code":"request_deadline_exceeded", "transmission":"not_sent", "message":"request deadline passed; recall the approved call to retry"}})
}

fn retired_identity_field(arguments: &serde_json::Map<String, Value>) -> Option<&'static str> {
    ["assertion", "agent_assertion"]
        .into_iter()
        .find(|field| arguments.contains_key(*field))
}

fn retired_identity_refusal(field: &str) -> Value {
    json!({"error":{"code":"argument_undeclared", "field":field,
        "message":format!("argument_undeclared{{field: {field}}}"), "transmission":"not_sent"}})
}

fn contains_secret_input(value: &serde_json::Map<String, Value>) -> bool {
    value
        .iter()
        .any(|(key, child)| plexus_core::secret_input::contains_secret_entry(key, child))
}

const CONSENT_PENDING_TEXT: &str = "Waiting for the user to approve <service> <action>. The request has gone to them. End your turn now; you will be resumed with the answer, and then you should run this same call again.";

fn denial_response(denial: &plexus_core::Denial) -> Value {
    if let plexus_core::Denial::AccessPending {
        elicitation_id,
        service,
        action,
    } = denial
    {
        let text = CONSENT_PENDING_TEXT
            .replace("<service>", service)
            .replace("<action>", action);
        return json!({"error": {"code": "access_pending", "message": text, "elicitation_id": elicitation_id}});
    }
    if let plexus_core::Denial::ConsentRefused {
        code,
        elicitation_id,
    } = denial
    {
        return json!({"error": {"code": code, "message": code, "elicitation_id": elicitation_id}});
    }
    if let plexus_core::Denial::ConnectorHomeNotHeld { state } = denial {
        if state.pointer("/error/code").and_then(Value::as_str) == Some("request_deadline_exceeded")
        {
            return state.clone();
        }
        return json!({"error":{"code":"connector_home_not_held", "message":format!("connector home not held: {state}"),"connectorHome":state,"transmission":"not_sent"}});
    }
    let mut response = json!({
        "error": {
            "code": denial.reason_code(),
            "terminal": denial.terminal(),
            "message": "governance denied the connector operation"
        }
    });
    if matches!(denial, plexus_core::Denial::NeedsDecisionPlane(_)) {
        response["error"]["message"] =
            json!("S3/S4 execution is not active: no production decision plane is configured.");
    }
    if let plexus_core::Denial::GrantRefusal(refusal) = denial {
        response["error"]["detail"] = json!(refusal.detail());
    }
    // Include the ID of the request waiting for approval in the error response
    // so the caller can identify it without searching a list of requests.
    if let plexus_core::Denial::ActionRequestCreated { request_id } = denial {
        response["error"]["request_id"] = json!(request_id);
    }
    // Name the refused argument so the caller can drop it. Only the name is
    // echoed, never the argument's value.
    if let plexus_core::Denial::ArgumentUndeclared { field } = denial {
        response["error"]["field"] = Value::String(field.clone());
    }
    if let plexus_core::Denial::ConsentUnavailable { action } = denial {
        response["error"]["action"] = json!(action);
        response["error"]["message"] = json!(format!(
            "consent_unavailable for action '{action}': no admissible session or consent route is available"
        ));
        response["error"]["transmission"] = json!("not_sent");
    }
    if let plexus_core::Denial::RecipientArgumentInvalid { pointer } = denial {
        response["error"]["pointer"] = json!(pointer);
    }
    if let plexus_core::Denial::ApprovalPreviewTooLong {
        action,
        length,
        limit,
    } = denial
    {
        response["error"]["action"] = json!(action);
        response["error"]["message"] = json!(format!("approval_preview_too_long for action '{action}': {length} bytes exceeds {limit} byte frame-body limit"));
        response["error"]["length"] = json!(length);
        response["error"]["limit"] = json!(limit);
    }
    response
}

fn github_read_failure(outcome: TransportOutcome) -> Value {
    let (transmission, code) = match outcome {
        TransportOutcome::Completed { .. } => ("completed", None),
        TransportOutcome::VendorFailed { code, .. } => ("failed", Some(code)),
        TransportOutcome::OutcomeUnknown => ("unknown", None),
        TransportOutcome::NotSent { code, .. } => ("not_sent", Some(code)),
    };
    json!({"error":{"code":"read_dispatch_failed", "outcome":{"transmission":transmission,"code":code,
        "message":"GitHub read dispatch did not complete"}}})
}

fn dispatch_response(outcome: DispatchOutcome) -> Value {
    let (transmission, result, message) = match outcome.outcome {
        TransportOutcome::Completed { response } => ("completed", response, None),
        TransportOutcome::VendorFailed { code, message } => {
            ("failed", Some(json!({"code": code})), Some(message))
        }
        TransportOutcome::OutcomeUnknown => (
            "outcome_unknown",
            None,
            Some("vendor outcome is unresolved".to_string()),
        ),
        TransportOutcome::NotSent { code, message } => {
            ("not_sent", Some(json!({"code": code})), Some(message))
        }
    };
    let mut body = json!({
        "result": {
            "reservation_id": outcome.reservation_id,
            "transmission": transmission,
            "retryability": match outcome.retryability {
                plexus_core::Retryability::Terminal => "terminal",
                plexus_core::Retryability::AutoRetryable => "autoretryable",
                plexus_core::Retryability::Throttle => "throttle",
            },
            "response": result
        }
    });
    if let Some(reconciliation) = outcome.reconciliation {
        body["result"]["reconciliation"] = json!(reconciliation);
    }
    if let Some(message) = message {
        body["result"]["message"] = Value::String(message);
    }
    body
}

/// Report EVERY missing required field, not the first one found.
///
/// A validator holds all of its failed conditions at the moment it refuses, so
/// disclosing one throws away information it already computed. The cost lands
/// on the caller: an error that reveals one problem at a time costs a round
/// trip per discovery, and the second failure is indistinguishable from the
/// first, so the caller cannot tell whether their correction made progress.
/// That matters most for callers with no access to this source, which is every
/// agent reaching the module through the facade.
///
/// Returns `None` when nothing is missing.
fn missing_string_fields(
    arguments: &serde_json::Map<String, Value>,
    required: &[&str],
) -> Option<Vec<String>> {
    let missing: Vec<String> = required
        .iter()
        .filter(|field| {
            arguments
                .get(**field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
        .map(|field| (*field).to_string())
        .collect();
    (!missing.is_empty()).then_some(missing)
}

async fn send_tool_response(
    writer: &mpsc::Sender<Frame>,
    version: u8,
    channel: u16,
    epoch: u32,
    correlation: u64,
    body: Value,
) -> Result<(), ModuleError> {
    let body = serde_json::to_vec(&body).map_err(ModuleError::Json)?;
    let frame = Frame::build_with_version(
        version,
        FrameType::Response,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        correlation,
        body,
    )
    .map_err(|error| ModuleError::Message(error.to_string()))?;
    send(writer, frame).await
}

/// Why a tool request's `call_key` member is refused, or `None` when it is
/// absent, `null`, or a string the protocol's validator accepts.
fn call_key_refusal(call_key: Option<&Value>) -> Option<String> {
    match call_key {
        None | Some(Value::Null) => None,
        Some(Value::String(key)) => validate_call_key(key).err().map(|error| error.to_string()),
        Some(_) => Some(format!("{CALL_KEY_FIELD} must be a string")),
    }
}

/// The top-level tool-call member naming the call a relayed call came from:
/// `{"carrier": <principal>, "call_key": <that carrier's key>}`.
const ORIGIN_FIELD: &str = "origin";
const ORIGIN_CARRIER_FIELD: &str = "origin.carrier";
const ORIGIN_CALL_KEY_FIELD: &str = "origin.call_key";

/// Why a tool request's `origin` was refused: the field to name, and a
/// message that describes the fault without repeating the value.
#[derive(Debug, PartialEq, Eq)]
struct OriginRefusal {
    field: &'static str,
    message: String,
}

impl OriginRefusal {
    fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }
}

/// Read and check a tool request's top-level `origin`: absent or `null` is
/// no origin; otherwise it must be an object with `carrier`, a
/// subc-protocol [`Principal`] object such as
/// `{"kind": "reserved", "module_id": "broca"}`, and `call_key`, a string the
/// protocol's call-key validator accepts, plus the protocol's optional
/// `message_position`, which is checked and ignored. The carrier is returned in the
/// stored principal form (`reserved:broca`), the same form as the carrier
/// principal every record is keyed on.
///
/// A relay always keys the call it sends on, so an `origin` without a
/// top-level `call_key` is refused too. The shape of that `call_key` is
/// checked separately, before this runs.
///
/// Parsed from the raw request rather than through subc-protocol's typed
/// `ToolCallRequest.origin` (added in 0.28), so each malformed shape keeps
/// its own named refusal code instead of one generic decode error. All of
/// the parsing lives in this one function, so adopting the typed
/// field later replaces only this function.
fn relay_origin_of(
    object: &serde_json::Map<String, Value>,
) -> Result<Option<plexus_core::RelayOrigin>, OriginRefusal> {
    let origin = match object.get(ORIGIN_FIELD) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(origin)) => origin,
        Some(_) => {
            return Err(OriginRefusal::new(
                ORIGIN_FIELD,
                "origin must be an object with carrier and call_key",
            ))
        }
    };
    if origin
        .keys()
        .any(|member| !matches!(member.as_str(), "carrier" | "call_key" | "message_position"))
    {
        return Err(OriginRefusal::new(
            ORIGIN_FIELD,
            "origin must have only the members carrier, call_key and message_position",
        ));
    }
    // The protocol's optional position of the call within the model message.
    // Plexus orders nothing by it, so it is checked for shape and then ignored;
    // a forwarder can send one origin shape to every module.
    if let Some(position) = origin.get("message_position") {
        let valid =
            serde_json::from_value::<subc_protocol::tool_call::MessagePosition>(position.clone())
                .ok()
                .is_some_and(|position| validate_call_key(&position.message_id).is_ok());
        if !valid {
            return Err(OriginRefusal::new(
                subc_protocol::tool_call::ORIGIN_MESSAGE_ID_FIELD,
                "origin.message_position must be {message_id, index} with a valid message_id",
            ));
        }
    }
    let carrier = origin
        .get("carrier")
        .and_then(|carrier| serde_json::from_value::<Principal>(carrier.clone()).ok())
        .map(|carrier| principal::principal_key(&carrier))
        .ok_or_else(|| {
            OriginRefusal::new(
                ORIGIN_CARRIER_FIELD,
                "origin.carrier must be a principal object",
            )
        })?;
    // The stored form is an identifier like every other key column: non-empty
    // printable ASCII, at most 256 bytes. A reserved principal's module id
    // could otherwise carry anything.
    if carrier.is_empty()
        || carrier.len() > 256
        || !carrier.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(OriginRefusal::new(
            ORIGIN_CARRIER_FIELD,
            "origin.carrier must name a principal in printable ASCII of at most 256 bytes",
        ));
    }
    let call_key = match origin.get("call_key") {
        Some(Value::String(call_key)) => match validate_call_key(call_key) {
            Ok(()) => call_key.clone(),
            // The validator's message names `call_key` and states the fault
            // (empty, length, or the index of a bad byte), never the value.
            Err(error) => {
                return Err(OriginRefusal::new(
                    ORIGIN_CALL_KEY_FIELD,
                    format!("{ORIGIN_FIELD}.{error}"),
                ))
            }
        },
        _ => {
            return Err(OriginRefusal::new(
                ORIGIN_CALL_KEY_FIELD,
                "origin.call_key must be a string",
            ))
        }
    };
    if !matches!(object.get(CALL_KEY_FIELD), Some(Value::String(_))) {
        return Err(OriginRefusal::new(
            ORIGIN_FIELD,
            "origin requires a top-level call_key",
        ));
    }
    Ok(Some(plexus_core::RelayOrigin { carrier, call_key }))
}

/// Serve a `tool.withdraw` request: withdraw the held call named by
/// `arguments.call_key`, on behalf of `caller`, the principal of the route the
/// request arrived on.
///
/// The reply is `{"result": {"answer": ...}}` with the answer read from the
/// stored request, or the route error `withdraw_not_permitted` when the caller
/// may not withdraw that call. A malformed request is `invalid_request`
/// naming the field. When the call is withdrawn, its consent card, if it has
/// one, is withdrawn from Prefrontal core too.
fn withdraw_response(
    engine: &crate::composition::FacadeEngine,
    caller: &str,
    route_scope: Option<&CallScope>,
    own_call_key: Option<&Value>,
    arguments: &serde_json::Map<String, Value>,
) -> Value {
    let invalid = |field: &str, message: String| json!({"error": {"code": "invalid_request", "field": field, "message": message}});
    let not_permitted = |why: &str| {
        eprintln!(info wire: "tool.withdraw refused for {caller}: {why}");
        json!({"error": {"code": WITHDRAW_NOT_PERMITTED, "message": why}})
    };
    // The call being withdrawn is named inside `arguments`. A top-level key
    // would give the withdrawal a key of its own, as though it were a call
    // that could itself be held and withdrawn, which it is not.
    if !matches!(own_call_key, None | Some(Value::Null)) {
        return invalid(
            CALL_KEY_FIELD,
            format!(
                "{} names the call in arguments.{CALL_KEY_FIELD}; \
                 its own {CALL_KEY_FIELD} must be absent",
                manifest::WITHDRAW_TOOL
            ),
        );
    }
    let call_key = match arguments.get(CALL_KEY_FIELD) {
        Some(Value::String(key)) => match validate_call_key(key) {
            Ok(()) => key.as_str(),
            Err(error) => return invalid("arguments.call_key", error.to_string()),
        },
        Some(_) => {
            return invalid(
                "arguments.call_key",
                "arguments.call_key must be a string".to_string(),
            )
        }
        None => {
            return invalid(
                "arguments.call_key",
                format!("{} requires arguments.call_key", manifest::WITHDRAW_TOOL),
            )
        }
    };
    let carrier = match arguments.get("carrier") {
        None | Some(Value::Null) => None,
        Some(Value::String(carrier)) => Some(carrier.as_str()),
        Some(_) => {
            return invalid(
                "arguments.carrier",
                "arguments.carrier must be a principal string".to_string(),
            )
        }
    };
    // The scope always comes from the route's stamp. A caller that also
    // states one is only accepted when it states that same scope: a
    // different one is refused, never used in place of the stamp's.
    match arguments.get("scope") {
        None | Some(Value::Null) => {}
        Some(claimed) => {
            let matches_stamp = route_scope.is_some_and(|scope| {
                claimed.get("owner").and_then(Value::as_str) == Some(scope.owner.as_str())
                    && claimed.get("ref").and_then(Value::as_str) == Some(scope.scope_ref.as_str())
                    && claimed.get("scope_epoch").and_then(Value::as_u64) == Some(scope.scope_epoch)
            });
            if !matches_stamp {
                return not_permitted("arguments.scope is not the scope stamped on this route");
            }
        }
    }
    match engine.withdraw_call(&WithdrawCall {
        caller,
        call_key,
        carrier,
        scope: route_scope,
    }) {
        Ok(answer) => json!({"result": answer.to_wire()}),
        Err(WithdrawRefusal::NotPermitted(why)) => not_permitted(why),
        Err(WithdrawRefusal::Store(error)) => crate::wire::store_failure(
            "withdrawal completed",
            "the withdrawal could not be completed",
            &error,
        ),
    }
}

async fn send_tool_error(
    writer: &mpsc::Sender<Frame>,
    version: u8,
    channel: u16,
    epoch: u32,
    correlation: u64,
    code: &str,
    message: &str,
) -> Result<(), ModuleError> {
    send_tool_response(
        writer,
        version,
        channel,
        epoch,
        correlation,
        tool_error(code, message),
    )
    .await
}

/// The route error body `{"error": {"code", "message"}}`.
fn tool_error(code: &str, message: &str) -> Value {
    json!({"error": {"code": code, "message": message}})
}

fn diagnostic_label(value: &str) -> String {
    let mut label: String = value
        .chars()
        .take(128)
        .flat_map(char::escape_default)
        .collect();
    if value.chars().count() > 128 {
        label.push_str("...");
    }
    label
}

/// Full envelopes remain JSON text for relays. Large events/catalog listings
/// keep their full legacy result but summarize text and omit structuredContent.
/// Other tools keep the MCP fields and legacy facade envelope they already serve.
///
/// Model-facing callers, such as Broca routing a model's tool call here, read
/// only `content[].text`, `structuredContent` and `isError`; relays that
/// decode the reply themselves, such as prefrontal's web search relay and
/// AFT's gh-shim relay, read `result`/`error`. Web search keeps these members
/// for Prefrontal's relay; code search has no legacy-envelope consumer.
/// A success adds `content`, `isError: false` and `structuredContent` (a copy
/// of `result`, when it is a JSON object, as MCP requires). For web search the
/// text is a readable listing, and code search renders its parsed matches.
/// For other tools the text is the WHOLE facade
/// reply as JSON, not just `result`, because relays that predate these fields
/// (AFT's gh-shim `facade_reply`) unwrap a JSON text block as the complete
/// reply and then read `result.status` and `repo_binding_generation` from it.
/// A refusal adds `content` and `isError: true`. Web search retains Prefrontal's
/// web search relay wording so moving providers does not change model text.
/// For other tools, typed grant refusals carry
/// the full envelope as JSON text so restoration clients can read detail;
/// other refusals retain the code, message, retry delay and field in one line.
///
/// What may be disclosed does not change: the text is rendered only from the
/// `result` or `error` value already in this reply, never from anything wider
/// such as a vendor error body the handler kept out of it.
///
/// Management-surface replies (`{method, params}`) do not pass through here;
/// the operator's admin client reads them as they are.
fn with_call_tool_result_with_repo(
    tool: Option<&str>,
    mut reply: Value,
    code_search_repo: Option<&str>,
) -> Value {
    if reply["error"]["code"] == "access_pending" {
        let text = reply["error"]["message"].as_str().unwrap_or_default();
        return json!({
            "content": text_content(text.to_string()),
            "isError": true,
            "structuredContent": {"success": false, "code": "access_pending", "message": text, "text": text, "elicitation_id": reply["error"]["elicitation_id"]}
        });
    }
    if let Some(tool @ (manifest::WEB_SEARCH_TOOL | manifest::CODE_SEARCH_TOOL)) = tool {
        return search_content_result(tool, reply, code_search_repo);
    }
    let listing = matches!(tool, Some(manifest::EVENTS_TOOL | manifest::CATALOG_TOOL))
        && ["events", "actions", "apps"]
            .into_iter()
            .any(|key| reply["result"][key].is_array());
    let bounded_listing = listing && !json_fits(&reply, 64 * 1024);
    let text = if let Some(error) = reply.get("error") {
        if error.get("detail").is_some() {
            pretty_json(&reply)
        } else {
            refusal_text(error)
        }
    } else if bounded_listing {
        json!({"result":{"summary":"Listing is large; read result for full data or request an events page.",
            "next_after":reply["result"]["next_after"]}}).to_string()
    } else {
        pretty_json(&reply)
    };
    let Some(fields) = reply.as_object_mut() else {
        return reply;
    };
    if fields.contains_key("error") {
        fields.insert("content".to_string(), text_content(text));
        fields.insert("isError".to_string(), Value::Bool(true));
    } else if let Some(result) = fields.get("result") {
        let structured = (!bounded_listing && result.is_object()).then(|| result.clone());
        fields.insert("content".to_string(), text_content(text));
        fields.insert("isError".to_string(), Value::Bool(false));
        if let Some(structured) = structured {
            fields.insert("structuredContent".to_string(), structured);
        }
    }
    reply
}

fn json_fits(value: &Value, limit: usize) -> bool {
    struct BoundedSize(usize);
    impl std::io::Write for BoundedSize {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.0 {
                return Err(std::io::Error::other("JSON size limit"));
            }
            self.0 -= bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(BoundedSize(limit), value).is_ok()
}

#[cfg(test)]
fn with_call_tool_result(tool: Option<&str>, reply: Value) -> Value {
    with_call_tool_result_with_repo(tool, reply, None)
}

fn search_content_result(tool: &str, mut legacy: Value, code_search_repo: Option<&str>) -> Value {
    use cortexkit_role_tool_provider::result::{validate, ContentPart, ToolResult};
    let mut result = if let Some(error) = legacy.get("error") {
        let text = if tool == manifest::WEB_SEARCH_TOOL {
            web_search_refusal_text(error)
        } else if error.get("detail").is_some() {
            pretty_json(&legacy)
        } else {
            refusal_text(error)
        };
        let code = if tool == manifest::WEB_SEARCH_TOOL {
            web_search_text_field(error, "code").unwrap_or("unknown")
        } else {
            error.get("code").and_then(Value::as_str).unwrap_or("error")
        };
        ToolResult::new(vec![ContentPart::text(text)]).with_error(code)
    } else {
        let parsed = legacy.get("result").cloned().unwrap_or(Value::Null);
        let text = if tool == manifest::WEB_SEARCH_TOOL {
            web_search_text(&parsed)
        } else {
            serde_json::from_value::<plexus_core::code_search::CodeSearchResponse>(parsed.clone())
                .ok()
                .map(|response| {
                    plexus_core::code_search::reply::render_with_repo_filter(
                        &response,
                        code_search_repo,
                    )
                })
                .unwrap_or_else(|| pretty_json(&legacy))
        };
        let mut result = ToolResult::new(vec![ContentPart::text(text)]);
        result.is_error = Some(false);
        if let Some(parsed) = parsed.as_object() {
            result = result.with_structured_content(parsed.clone());
        }
        result
    };
    // Refuse an invalid or oversized result by name rather than sending content
    // that a content/v1 consumer cannot accept, or silently truncating it.
    if validate(&result).is_err() {
        let message = "plexus could not produce a valid content/v1 result";
        result = ToolResult::new(vec![ContentPart::text(message)]).with_error("invalid_answer");
        legacy = tool_error("invalid_answer", message);
    }
    validate(&result).expect("the bounded content/v1 refusal is valid");
    let mut body = serde_json::to_value(result).expect("search ToolResult serializes");
    if tool == manifest::WEB_SEARCH_TOOL {
        for key in ["result", "error"] {
            if let Some(value) = legacy.get(key) {
                body.as_object_mut()
                    .unwrap()
                    .insert(key.into(), value.clone());
            }
        }
    }
    body
}

/// A `CallToolResult` content list holding one text block.
fn text_content(text: String) -> Value {
    json!([{"type": "text", "text": text}])
}

fn pretty_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// One line naming a refusal: `code: message`, then the retry delay in whole
/// seconds (rounded up) when the error states one, then the refused field
/// when it names one. A model reading only this text can still tell that the
/// call failed, why, and when it may try again.
fn refusal_text(error: &Value) -> String {
    let code = error.get("code").and_then(Value::as_str).unwrap_or("error");
    let mut text = match error.get("message").and_then(Value::as_str) {
        Some(message) => format!("{code}: {message}"),
        None => code.to_string(),
    };
    if let Some(retry_after_ms) = error.get("retry_after_ms").and_then(Value::as_u64) {
        text.push_str(&format!(
            " (retry after {} s)",
            retry_after_ms.div_ceil(1_000)
        ));
    }
    if let Some(field) = error.get("field").and_then(Value::as_str) {
        text.push_str(&format!(" field: {field}"));
    }
    text
}

/// The text a model reads for a web search: a count line, then each result
/// numbered with title, url, publication day and excerpt. Until this moved
/// here, Prefrontal (the agent runtime) authored the web_search tool and
/// rendered this same text from plexus's reply. Keeping it byte-identical means
/// switching the tool's provider changes nothing a model sees.
fn web_search_text(result: &Value) -> String {
    let cached = result.get("cached").and_then(Value::as_bool) == Some(true);
    let cached_note = if cached { " (cached)" } else { "" };
    let results = result
        .get("results")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if results.is_empty() {
        return format!("No web results{cached_note}.");
    }
    let noun = if results.len() == 1 {
        "result"
    } else {
        "results"
    };
    let mut text = format!("{} web {noun}{cached_note}:", results.len());
    for (index, item) in results.iter().enumerate() {
        text.push_str(&format!(
            "\n\n{}. {}",
            index + 1,
            web_search_text_field(item, "title")
                .map(web_search_collapse_whitespace)
                .unwrap_or_else(|| "(untitled)".to_string())
        ));
        if let Some(url) = web_search_text_field(item, "url") {
            text.push_str(&format!("\n   {url}"));
        }
        if let Some(published) = web_search_text_field(item, "published_at") {
            // RFC 3339 timestamps carry precision the model does not need;
            // show only the publication day.
            let day = published.split('T').next().unwrap_or(published);
            text.push_str(&format!("\n   Published {day}"));
        }
        if let Some(excerpt) = web_search_text_field(item, "excerpt") {
            text.push_str(&format!("\n   {}", web_search_collapse_whitespace(excerpt)));
        }
    }
    text
}

fn web_search_text_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn web_search_collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn web_search_wait_words(retry_after_ms: u64) -> String {
    let seconds = retry_after_ms.div_ceil(1_000).max(1);
    let (minutes, rest) = (seconds / 60, seconds % 60);
    let unit = |count: u64, one: &str| {
        if count == 1 {
            format!("1 {one}")
        } else {
            format!("{count} {one}s")
        }
    };
    match (minutes, rest) {
        (0, _) => unit(rest, "second"),
        (_, 0) => unit(minutes, "minute"),
        _ => format!("{} {}", unit(minutes, "minute"), unit(rest, "second")),
    }
}

fn web_search_refusal_text(error: &Value) -> String {
    let code = web_search_text_field(error, "code").unwrap_or("unknown");
    let message = web_search_text_field(error, "message").unwrap_or("no detail given");
    let backend = web_search_text_field(error, "backend").unwrap_or("the search backend");
    let head = format!("web_search was refused ({code}):");
    match code {
        "rate_limited" => match error.get("retry_after_ms").and_then(Value::as_u64) {
            Some(retry_after_ms) => format!(
                "{head} the web search rate limit is reached. Retry in {} (retry_after_ms {retry_after_ms}).",
                web_search_wait_words(retry_after_ms)
            ),
            None => format!("{head} the web search rate limit is reached. Retry in a minute."),
        },
        "invalid_query" => {
            let field = web_search_text_field(error, "field").unwrap_or("an argument");
            format!("{head} the `{field}` argument is not valid. Correct it and search again.")
        }
        "web_search_code_lookup" => format!("{head} {message}"),
        "web_search_not_granted" => format!(
            "{head} plexus grants no web search backend to the calling module. An operator must grant it; retrying fails the same way until then."
        ),
        "agent_not_granted" => format!(
            "{head} plexus holds no web search grant for this agent. An operator must grant it; retrying fails the same way until then."
        ),
        "backend_unavailable" => {
            format!("{head} {backend} is unavailable right now. Retry in a little while.")
        }
        "backend_quarantined" => format!(
            "{head} {backend} is quarantined pending operator review; retrying fails the same way until an operator clears it."
        ),
        "backend_ambiguous" => format!(
            "{head} more than one plexus connection could serve this search, and plexus will not pick whose account pays. An operator must leave one; retrying fails the same way until then."
        ),
        _ => {
            let retry = if error.get("retryable").and_then(Value::as_bool) == Some(true) {
                " Retry shortly."
            } else {
                ""
            };
            format!("{head} {message}.{retry}")
        }
    }
}

async fn send(writer: &mpsc::Sender<Frame>, frame: Frame) -> Result<(), ModuleError> {
    writer
        .send(frame)
        .await
        .map_err(|_| ModuleError::Message("egress channel closed".to_string()))
}

fn parse_subc_arg(args: impl IntoIterator<Item = OsString>) -> Result<PathBuf, ModuleError> {
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        if argument == "--subc" {
            let value = args
                .next()
                .ok_or_else(|| ModuleError::Message("--subc requires a value".to_string()))?;
            return Ok(PathBuf::from(value));
        }
        if let Some(raw) = argument
            .to_str()
            .and_then(|value| value.strip_prefix("--subc="))
        {
            if raw.is_empty() {
                return Err(ModuleError::Message("--subc= requires a value".to_string()));
            }
            return Ok(PathBuf::from(raw));
        }
    }
    Err(ModuleError::Message(
        "--subc <connection-file> is required".to_string(),
    ))
}

#[derive(Debug)]
pub enum ModuleError {
    RouteCapacity,
    Message(String),
    Json(serde_json::Error),
}

#[cfg(test)]
fn assert_bind_ack(frame: &Frame) {
    assert_eq!(
        frame.header.ty,
        FrameType::Response,
        "bind must be accepted"
    );
    let reply: Value = serde_json::from_slice(&frame.body).expect("bind ACK JSON");
    assert!(
        reply.get("error").is_none(),
        "bind must not carry an error: {reply}"
    );
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RouteCapacity => write!(formatter, "route binding capacity exhausted"),
            Self::Message(message) => write!(formatter, "{message}"),
            Self::Json(error) => write!(formatter, "json: {error}"),
        }
    }
}

impl std::error::Error for ModuleError {}

/// Explicit test constructor: stub credentials + mock transport.
#[cfg(any(test, feature = "test-support"))]
pub fn runtime_for_test(store: Arc<PlexusStore>) -> ModuleRuntime {
    ModuleRuntime::with_stub_credentials_and_mock_transport(
        store,
        Arc::new(StubCredentialSource::with_default_success(
            b"mock-credential".to_vec(),
        )),
        Arc::new(MockTransport::default()),
    )
}

/// Create a credential-free MCP manifest by replacing the shipped DeepWiki
/// manifest's key and endpoint with `key` and `url`. Tests can store it so the
/// pre-write catalog check can load the connection's manifest without needing
/// credentials. Creating the manifest alone does not establish catalog freshness.
#[cfg(test)]
pub(crate) fn test_mcp_manifest(key: &str, url: &str) -> plexus_core::IngestedManifest {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/deepwiki.jsonc"),
    )
    .expect("read the shipped deepwiki manifest");
    let mut value: Value =
        serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).expect("normalize manifest"))
            .expect("parse manifest");
    value["key"] = json!(key);
    value["transport"]["url"] = json!(url);
    plexus_core::ingest_value(value).expect("ingest test manifest")
}

/// Create an MCP manifest under `key` at `url` with the fixture write
/// `held_write`, restricted by the `team` filter. The app declares S1, the
/// lowest severity tier, making its write S2. Only S3 and S4 require the separate
/// approval service, so an ordinary grant can authorize this write. Require an
/// `api_key` credential; the pre-write catalog check must resolve the connection's
/// bound credential before refreshing the catalog.
#[cfg(test)]
pub(crate) fn test_write_manifest(key: &str, url: &str) -> plexus_core::IngestedManifest {
    plexus_core::ingest_value(json!({
        "schema_version": 1,
        "key": key,
        "name": key,
        "description": "test vendor with one write",
        "reuse_path": "mcp_direct",
        "reuse_rationale": "test fixture",
        "tier": "S1",
        "transport": {"kind": "mcp_remote", "url": url},
        "auth": {"mode": "api_key"},
        "credential_bindings": [{
            "ref_role": "api_key", "placement": "header", "key": "Authorization",
            "prefix": "Bearer ", "required": true
        }],
        "resource_filters": {"required": [], "optional": ["team"], "write_enabling": ["team"]},
        "actions_baseline": [{"name": "held_write", "risk": "write", "input_schema":{
            "type":"object", "properties":{"team":{"type":"string"}}
        }}],
        "defaults": {"ask_first_risk": ["write", "destructive"], "rate_limit": {"calls_per_min": 30}},
        "availability": "ga"
    }))
    .expect("ingest test write manifest")
}

/// Exercise route.bind and health handlers without opening a daemon socket.
#[cfg(any(test, feature = "test-support"))]
pub async fn handle_control_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health: &Arc<health::HealthState>,
) -> Result<(), ModuleError> {
    // Declared before the store so it outlives it: the guard removes the
    // directory the store's file sits in.
    let scratch = Scratch::database("handler-test-store");
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: "test".to_string(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: scratch.to_string_lossy().into_owned(),
        },
    };
    let store = Arc::new(
        PlexusStore::open(&descriptor)
            .map_err(|error| ModuleError::Message(format!("open test plexus store: {error}")))?,
    );
    let state = Arc::new(ModuleState {
        health: Arc::clone(health),
        runtime: runtime_for_test(store),
    });
    handle_control_request(frame, writer, &state, &Arc::new(RouteBindings::new())).await
}

/// Exercise an already accepted principal's facade call without a daemon socket.
#[cfg(any(test, feature = "test-support"))]
pub async fn handle_tool_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    runtime: ModuleRuntime,
    principal: Principal,
) -> Result<(), ModuleError> {
    handle_scoped_tool_request_for_test(frame, writer, runtime, principal, None).await
}

/// [`handle_tool_request_for_test`] on a route whose bind carried the daemon
/// scope stamp `scope`, as a scoped `route.bind` records it.
#[cfg(any(test, feature = "test-support"))]
pub async fn handle_scoped_tool_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    runtime: ModuleRuntime,
    principal: Principal,
    scope: Option<subc_protocol::scope::ScopeStamp>,
) -> Result<(), ModuleError> {
    let routes = Arc::new(RouteBindings::new());
    routes.insert_mode(
        frame.header.channel,
        frame.header.epoch,
        principal,
        scope.as_ref().map(CallScope::from_stamp),
        derive_call_mode(scope.as_ref()),
    )?;
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    });
    handle_tool_request_with_confirmed_test_peer(frame, writer, &state, &routes).await
}

/// Handler fixtures explicitly approve confirmation frames with a fake daemon;
/// confirmation refusal tests use the production handler and their own peer.
#[cfg(any(test, feature = "test-support"))]
async fn handle_tool_request_with_confirmed_test_peer(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    routes: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    let needs_fake_peer = serde_json::from_slice::<Value>(&frame.body)
        .ok()
        .is_some_and(|request| {
            request["method"].as_str().is_some_and(|method| {
                operator_confirmation::may_need_confirmation(method, &request["params"])
            })
        });
    if needs_fake_peer {
        let (proxy, requests) = mpsc::channel(4);
        let (result, ()) = tokio::join!(
            handle_tool_request(frame, &proxy, state, routes),
            operator_confirmation::approving_test_peer(requests, writer, &routes.control_replies),
        );
        result
    } else {
        handle_tool_request(frame, writer, state, routes).await
    }
}

#[cfg(test)]
// Shared with the core test suites; this crate's tests use only part of it.
#[allow(dead_code)]
#[path = "../../plexus-core/tests/support/audit.rs"]
mod audit_test;

#[cfg(test)]
mod relay_vectors;

#[cfg(test)]
mod call_mode_tests;
#[cfg(test)]
mod code_search_tests;
#[cfg(test)]
mod web_search_tests;

#[cfg(test)]
mod web_search_rendering_tests;

#[cfg(test)]
mod rest_pool_tests;

#[cfg(test)]
mod withdraw_tests;

#[cfg(test)]
mod github_react_tests;

#[cfg(test)]
mod recipient_tests;

#[cfg(test)]
mod permissions_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{BindIdentity, RouteTarget};

    #[tokio::test]
    async fn undecodable_control_bind_refuses_only_that_request_and_loop_survives() {
        let scratch = Scratch::database("control-decode-loop");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: DEFAULT_MODULE_ID.into(),
                storage_namespace: "test".into(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: scratch.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(store),
        });
        let (mut input, mut reader) = tokio::io::duplex(8192);
        let (writer, mut replies) = mpsc::channel(8);
        let task = tokio::spawn(async move {
            dispatch_loop(
                &mut reader,
                writer,
                state,
                Arc::new(RouteBindings::new()),
                Arc::new(PendingControlReplies::default()),
            )
            .await
        });
        let mut malformed: Value = serde_json::from_slice(
            &bind(Some(Principal::Reserved {
                module_id: "basal".into(),
            }))
            .body,
        )
        .unwrap();
        malformed["scope"] = serde_json::to_value(
            subc_protocol::scope::ScopeStamp::new(
                Principal::Reserved {
                    module_id: "prefrontal".into(),
                },
                "flow",
                1,
                subc_protocol::scope::ScopeKind::Head,
            )
            .with_owner_authorized(true),
        )
        .unwrap();
        assert!(serde_json::from_value::<ModuleControlRequest>(malformed.clone()).is_ok());
        malformed["scope"]["attributes"] = json!({"future_unknown_field":true});
        let decode_error =
            serde_json::from_value::<ModuleControlRequest>(malformed.clone()).unwrap_err();
        assert!(decode_error.to_string().contains("future_unknown_field"));
        for (corr, body) in [
            (17, serde_json::to_vec(&malformed).unwrap()),
            (
                18,
                serde_json::to_vec(&ModuleControlRequest::HealthCheck {}).unwrap(),
            ),
        ] {
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                wire::control_flags(),
                0,
                0,
                corr,
                body,
            )
            .unwrap();
            write_frame(&mut input, &frame).await.unwrap();
            let response = tokio::time::timeout(std::time::Duration::from_secs(5), replies.recv())
                .await
                .unwrap()
                .expect("loop must answer");
            assert_eq!(response.header.corr, corr);
            if corr == 17 {
                assert_eq!(response.header.ty, FrameType::Error);
                let body: subc_protocol::ErrorBody =
                    serde_json::from_slice(&response.body).unwrap();
                assert_eq!(body.code, "invalid_request");
                assert!(body.message.contains("future_unknown_field"));
            } else {
                assert_eq!(response.header.ty, FrameType::Response);
                assert!(matches!(
                    serde_json::from_slice::<subc_protocol::session::ModuleControlResponse>(
                        &response.body
                    )
                    .unwrap(),
                    subc_protocol::session::ModuleControlResponse::HealthCheck { .. }
                ));
            }
            assert!(!task.is_finished(), "dispatch loop must remain live");
        }
        drop(input);
        task.await.unwrap().unwrap();
    }

    #[test]
    fn a_refused_launch_nonce_names_its_kind() {
        let error = launch_nonce_refused(subc_os::LaunchNonceError::NotOpen { fd: 3, errno: 9 });
        let line = error.to_string();
        assert!(
            line.starts_with("read launch nonce: refused as NotOpen { fd: 3, errno: 9 }: "),
            "{line}"
        );
        assert!(line.contains("which is not open"), "{line}");
        assert!(!line.contains('\n'), "{line}");
    }

    async fn selection_health_scenario(scenario: &str) {
        let path = Scratch::database("selection");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: path.to_string_lossy().into_owned(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        let conn = rusqlite::Connection::open(&path).unwrap();
        let now = plexus_core::storage::now_ms();
        conn.execute("INSERT INTO trigger_subscriptions (subscription_id, principal, connection_id, action, cadence_s, cursor_kind, cursor_state, schema_hash, status, last_polled_at_ms, consecutive_vendor_failures, created_at_ms) VALUES ('watch', 'selection-owner', 'unused', 'read', 300, 'sync_token', '{}', 'hash', 'active', ?1, 4, 0)", [now - 301_000]).unwrap();
        // Cadence-due but held in exponential backoff, so a valid selection polls nothing.
        if scenario != "backoff" {
            conn.execute(
                "UPDATE trigger_subscriptions SET cursor_state = 'broken-json'",
                [],
            )
            .unwrap();
        }
        let health = Arc::new(health::HealthState::new());
        let state = Arc::new(ModuleState {
            health: Arc::clone(&health),
            runtime: runtime_for_test(Arc::clone(&store)),
        });
        let (shutdown, stop) = mpsc::channel(1);
        let task = spawn_trigger_scheduler(
            state,
            stop,
            DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY,
        );
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        if scenario == "recovery" {
            conn.execute("UPDATE trigger_subscriptions SET cursor_state = '{}'", [])
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        } else if scenario == "empty" {
            conn.execute("DELETE FROM trigger_subscriptions", [])
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        }
        health.backdate_scheduler_success(health::scheduler_stall_threshold_ms_for_test(300) + 1);
        health.stamp_heartbeat();
        let response = health.report();
        drop(shutdown);
        task.await.unwrap();
        let subc_protocol::session::ModuleControlResponse::HealthCheck {
            status, metrics, ..
        } = response
        else {
            panic!("health response")
        };
        let metrics = metrics.unwrap();
        assert_eq!(metrics["schedulerPollsAttempted"], json!(0));
        assert_eq!(metrics["schedulerPollsCompleted"], json!(0));
        assert_eq!(
            store
                .active_subscription_schedule()
                .unwrap()
                .map(|(count, _)| count)
                .unwrap_or(0),
            if scenario == "empty" { 0 } else { 1 }
        );
        if scenario != "log" {
            assert_eq!(
                status,
                if scenario == "failure" {
                    subc_protocol::session::HealthStatus::Degraded
                } else {
                    subc_protocol::session::HealthStatus::Ok
                },
                "{metrics}"
            );
        }
        drop(conn);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selection_failure_reaches_stall_verdict() {
        selection_health_scenario("failure").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selection_failure_clears_on_successful_retry() {
        selection_health_scenario("recovery").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn all_watches_deferred_in_backoff_are_healthy() {
        selection_health_scenario("backoff").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn empty_active_set_after_selection_failure_never_stalls() {
        selection_health_scenario("empty").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selection_log_fixture() {
        logging::init_child();
        selection_health_scenario("log").await;
    }

    #[test]
    fn selection_failure_logs_principal_and_error_to_stderr() {
        let stderr = module_diagnostic_output("tests::selection_log_fixture");
        assert!(
            stderr.contains(
                " ERROR plexus.scheduler: scheduler selection failed for principal selection-owner:"
            ),
            "{stderr}"
        );
        assert!(
            stderr.contains("Conversion error") || stderr.contains("expected value"),
            "missing decoding error: {stderr}"
        );
    }

    fn health_probe_scenario(scenario: &str) {
        logging::init_child();
        let path = Scratch::database("health-probe");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: path.to_string_lossy().into_owned(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        // REST catalog refresh uses the manifest's actions, not a vendor request.
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/exa_rest.jsonc"),
        )
        .unwrap();
        let ingested = plexus_core::ingest_value(
            serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap(),
        )
        .unwrap();
        store.upsert_manifest("system", &ingested).unwrap();
        let owners = ["direct", "probe-owner", "z-other-owner"];
        for principal in owners {
            for suffix in ["a", "b"] {
                let id = format!("{principal}-{suffix}");
                store
                    .insert_connection(
                        principal,
                        &id,
                        &ingested.manifest.key,
                        "pending",
                        &json!({}),
                    )
                    .unwrap();
                let ticket = store
                    .create_binding_ticket(principal, &id, b"test:probe-handle")
                    .unwrap();
                store
                    .connect_with_ticket(principal, &ticket.ticket_id)
                    .unwrap()
                    .unwrap();
                store
                    .set_connection_health(principal, &id, "degraded", &json!({}))
                    .unwrap();
            }
        }
        let state = ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        };
        assert_eq!(health_probe_principals(&state), owners);
        let conn = rusqlite::Connection::open(&path).unwrap();
        match scenario {
            "listing" => {
                // Owner enumeration still succeeds; only this owner's summary cannot decode.
                conn.execute("UPDATE connections SET generation = 'broken-generation' WHERE principal = 'probe-owner'", []).unwrap();
            }
            "probe" => {
                // Summaries still decode, but loading this connection for refresh fails.
                conn.execute("UPDATE connections SET health_state = 'broken-json' WHERE connection_id = 'probe-owner-a'", []).unwrap();
            }
            "principals" => {
                conn.execute("DROP TABLE trigger_subscriptions", [])
                    .unwrap();
                assert_eq!(health_probe_principals(&state), ["direct"]);
            }
            "happy" => {}
            _ => panic!("unknown probe scenario"),
        }
        if scenario != "principals" {
            run_health_probes(&state);
            for principal in owners {
                for suffix in ["a", "b"] {
                    let id = format!("{principal}-{suffix}");
                    let expected = if (scenario == "listing" && principal == "probe-owner")
                        || (scenario == "probe" && id == "probe-owner-a")
                    {
                        "degraded"
                    } else {
                        "active"
                    };
                    let status: String = conn
                        .query_row(
                            "SELECT status FROM connections WHERE connection_id = ?1",
                            [&id],
                            |row| row.get(0),
                        )
                        .unwrap();
                    assert_eq!(status, expected, "{scenario}: {id}");
                }
            }
        }
        drop(conn);
        drop(state);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn health_probe_listing_error_fixture() {
        health_probe_scenario("listing");
    }

    #[test]
    fn health_probe_connection_error_fixture() {
        health_probe_scenario("probe");
    }

    #[test]
    fn health_probe_principals_error_fixture() {
        health_probe_scenario("principals");
    }

    #[test]
    fn health_probe_visits_every_connection_of_every_principal() {
        health_probe_scenario("happy");
    }

    /// A request whose handler fails before it can reply (here: the route
    /// binding lock is poisoned, so the binding cannot be read) still gets an
    /// `internal_error` answer, and the failure is logged. Run as a child so
    /// the log line can be read back.
    #[test]
    fn failed_request_fixture() {
        logging::init_child();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("fixture runtime");
        runtime.block_on(async {
            let descriptor = StorageDescriptor {
                module_id: DEFAULT_MODULE_ID.to_string(),
                storage_namespace: format!("failed-request-{}", plexus_core::now_ms()),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: ":memory:".to_string(),
                },
            };
            let store = Arc::new(PlexusStore::open(&descriptor).expect("open test store"));
            let state = Arc::new(ModuleState {
                health: Arc::new(health::HealthState::new()),
                runtime: runtime_for_test(store),
            });
            let bindings = Arc::new(RouteBindings::new());
            let poisoner = Arc::clone(&bindings.inner);
            let _ = std::thread::spawn(move || {
                let _held = poisoner.write().unwrap();
                panic!("poison the route binding lock");
            })
            .join();
            let body = json!({"name":"connections","arguments":{"op":"list"}});
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                wire::control_flags(),
                3,
                1,
                77,
                serde_json::to_vec(&body).unwrap(),
            )
            .unwrap();
            let (writer, mut responses) = mpsc::channel(4);
            assert!(handle_frame(frame, &writer, &state, &bindings)
                .await
                .expect("dispatch"));
            let reply = recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "a reply to a request whose handler failed",
            )
            .await;
            assert_eq!(reply.header.corr, 77);
            let reply: Value = serde_json::from_slice(&reply.body).expect("reply JSON");
            assert_eq!(reply["error"]["code"], "internal_error", "{reply}");
        });
    }

    #[test]
    fn a_request_whose_handler_fails_is_answered_and_logged() {
        let stderr = module_diagnostic_output("tests::failed_request_fixture");
        assert!(
            stderr.contains("plexus.wire: request on channel 3 epoch 1 correlation 77 failed before its reply was sent: route binding state was poisoned"),
            "{stderr}"
        );
    }

    #[test]
    fn health_probe_listing_failure_logs_principal_and_error_to_stderr() {
        let stderr = module_diagnostic_output("tests::health_probe_listing_error_fixture");
        assert!(
            stderr.contains(
                " WARN  plexus.health: health probe connection listing failed for principal probe-owner:"
            ),
            "{stderr}"
        );
        assert!(
            stderr.contains("generation"),
            "missing decoding error: {stderr}"
        );
    }

    #[test]
    fn health_probe_connection_failure_logs_principal_connection_and_error_to_stderr() {
        let stderr = module_diagnostic_output("tests::health_probe_connection_error_fixture");
        assert!(stderr.contains(" WARN  plexus.health: health probe failed for principal probe-owner, connection probe-owner-a: catalog store operation failed"), "{stderr}");
    }

    #[test]
    fn health_probe_principals_failure_logs_narrowing_and_error_to_stderr() {
        let stderr = module_diagnostic_output("tests::health_probe_principals_error_fixture");
        assert!(stderr.contains(" ERROR plexus.health: health probe principal enumeration failed for stored subscription and connection owners; falling back to principal direct only:"), "{stderr}");
        assert!(
            stderr.contains("no such table: trigger_subscriptions"),
            "missing enumeration error: {stderr}"
        );
    }

    /// A failed probe must say WHY it failed. The fixture breaks one row's
    /// `health_state` JSON so loading that connection fails in the store; the
    /// log line must carry that JSON decoding error, not only the fixed
    /// summary.
    #[test]
    fn health_probe_store_failure_logs_the_underlying_cause() {
        let stderr = module_diagnostic_output("tests::health_probe_connection_error_fixture");
        let line = stderr
            .lines()
            .find(|line| {
                line.contains(
                    "health probe failed for principal probe-owner, connection probe-owner-a",
                )
            })
            .unwrap_or_else(|| panic!("no probe failure line: {stderr}"));
        assert!(
            line.contains("catalog store operation failed: storage backend:")
                && line.contains("Conversion error from type Text")
                && line.contains("expected value"),
            "the probe failure must name the store error that caused it: {line}"
        );
    }

    /// One imported GitHub handle connection in the production shape: the
    /// reviewed github_rest manifest, a connection row created by the import
    /// with NO stored credential binding, and the handle credential provider
    /// installed on the runtime. Runs one health-probe pass with the
    /// connection starting in `status`, then checks it ends `active`.
    fn imported_handle_probe_scenario(status: &str) {
        logging::init_child();
        let path = Scratch::database("handle-probe");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: path.to_string_lossy().into_owned(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github_rest.jsonc"),
        )
        .unwrap();
        let ingested = plexus_core::ingest_value(
            serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap(),
        )
        .unwrap();
        store.upsert_manifest("system", &ingested).unwrap();
        let connection_id = "github-handle-app-probe";
        store
            .import_github_handles(&[plexus_core::storage::github_store::GithubImportRow {
                handle: plexus_core::storage::github_store::GithubHandle {
                    app_handle_id: "app-probe".into(),
                    agent_id: "agent-probe".into(),
                    app_id: 1,
                    installation_id: None,
                    credential_reference: "github_app:app-probe".into(),
                    credential_generation: 0,
                    status: "enabled".into(),
                    proven_at: None,
                    connection_principal: "direct".into(),
                    connection_id: connection_id.into(),
                },
                repositories: vec!["o/probe".into()],
                grants: vec![],
                module_actions: vec!["github.issue.get".into()],
                policies: vec![],
            }])
            .unwrap();
        let imported = store.connection("direct", connection_id).unwrap().unwrap();
        assert!(
            !imported.has_credential_binding,
            "an imported handle connection carries no stored credential binding"
        );
        if status != "active" {
            store
                .set_connection_health("direct", connection_id, status, &json!({"reason": "test"}))
                .unwrap();
        }
        let mut runtime = runtime_for_test(Arc::clone(&store));
        runtime.github_handle_credentials = Some(Arc::new(AnyHandleToken));
        let state = ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        };
        run_health_probes(&state);
        let after = store.connection("direct", connection_id).unwrap().unwrap();
        assert_eq!(after.status, "active", "started {status}");
        drop(state);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn health_probe_imported_handle_fixture() {
        imported_handle_probe_scenario("active");
    }

    #[test]
    fn health_probe_imported_handle_degraded_fixture() {
        imported_handle_probe_scenario("degraded");
    }

    /// A probe over an imported GitHub handle connection succeeds and logs
    /// nothing. Every such connection used to log a probe failure once a
    /// minute, because the probe looked for a stored credential binding these
    /// connections never have.
    #[test]
    fn health_probe_over_an_imported_handle_connection_logs_no_warning() {
        let stderr = module_diagnostic_output("tests::health_probe_imported_handle_fixture");
        assert!(
            !stderr.contains("health probe failed"),
            "a healthy handle connection must probe cleanly: {stderr}"
        );
    }

    /// A handle connection left `degraded` recovers on a successful probe, the
    /// same as any other connection. The fixture asserts the recovered status;
    /// this also checks the pass logged no failure.
    #[test]
    fn health_probe_recovers_a_degraded_handle_connection() {
        let fixture = "tests::health_probe_imported_handle_degraded_fixture";
        let stderr = module_diagnostic_output(fixture);
        assert!(
            !stderr.contains("health probe failed"),
            "{fixture}: {stderr}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_invoke_connection_lookup_failure_is_refused_as_a_store_failure() {
        let (path, _store, state) = two_connection_fixture("invoke-lookup-error");
        rusqlite::Connection::open(path.path())
            .unwrap()
            .execute(
                "UPDATE connections SET generation = 'broken-generation' WHERE connection_id = 'conn-keep-rest'",
                [],
            )
            .unwrap();
        let object = json!({"name":"invoke","arguments":{"op":"call",
            "connection":"conn-keep-rest","action":"web_search_exa","args":{"query":"x"}}});
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            wire::control_flags(),
            2,
            1,
            8,
            serde_json::to_vec(&object).unwrap(),
        )
        .unwrap();
        let routes = Arc::new(RouteBindings::new());
        routes.insert(2, 1, Principal::Direct).unwrap();
        let reply = facade_tool_reply(&frame, object.as_object().unwrap(), &state, &routes)
            .expect("a reply");
        assert_eq!(
            reply["error"]["code"], "store_failure",
            "a connection lookup failure must be refused as store_failure: {reply}"
        );
    }

    /// A credential-free MCP connection `conn-mcp` holding one catalogued
    /// write, `held_write`, whose stored schema declares `team`. The engine
    /// dispatches through a mock transport (counted), while the freshness
    /// check's catalog refresh goes to `url` over real MCP.
    struct McpWriteFixture {
        scratch: Scratch,
        state: Arc<ModuleState>,
        transport: Arc<plexus_core::MockTransport>,
    }

    fn write_schema() -> Value {
        json!({"type": "object", "properties": {"team": {"type": "string"}}})
    }

    fn mcp_write_fixture(
        label: &str,
        url: &str,
        ask_first: bool,
        granted: bool,
    ) -> McpWriteFixture {
        let scratch = Scratch::database(label);
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: scratch.to_string_lossy().into_owned(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: scratch.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        store
            .upsert_manifest("system", &crate::test_mcp_manifest("stubmcp", url))
            .unwrap();
        store
            .insert_connection(
                "direct",
                "conn-mcp",
                "stubmcp",
                "active",
                &json!({"required": [], "optional": [], "write_enabling": ["team"]}),
            )
            .unwrap();
        let schema = write_schema();
        store
            .upsert_catalog_action(&plexus_core::CatalogActionInput {
                connection_id: "conn-mcp".to_string(),
                principal: "direct".to_string(),
                name: "held_write".to_string(),
                title: None,
                schema: schema.clone(),
                schema_hash: plexus_core::jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
                risk: "write".to_string(),
                severity: "write".to_string(),
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
                ask_first,
            })
            .unwrap();
        if granted {
            for (grant_id, kind) in [
                ("grant-invoke", "invoke"),
                ("grant-admin", "connection_admin"),
            ] {
                store
                    .insert_grant(&plexus_core::GrantInput {
                        grant_id: grant_id.into(),
                        principal: "direct".into(),
                        connection_id: "conn-mcp".into(),
                        grantee_principal: "direct".into(),
                        risk_ceiling: "write".into(),
                        action_selectors: vec!["held_write".into()],
                        authority_kind: kind.into(),
                        expires_at: None,
                    })
                    .unwrap();
            }
        }
        let transport = Arc::new(plexus_core::MockTransport::default());
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: ModuleRuntime::with_stub_credentials_and_mock_transport(
                Arc::clone(&store),
                Arc::new(StubCredentialSource::with_default_success(
                    b"unused".to_vec(),
                )),
                Arc::clone(&transport),
            ),
        });
        McpWriteFixture {
            scratch,
            state,
            transport,
        }
    }

    impl McpWriteFixture {
        /// Age the catalog past every staleness bound, so the next write's
        /// freshness check must refresh it from the vendor.
        fn age_catalog(&self) {
            rusqlite::Connection::open(self.scratch.path())
                .unwrap()
                .execute("UPDATE catalog_actions SET last_seen_at_ms = 0", [])
                .unwrap();
        }

        fn invoke(&self) -> Value {
            let object = json!({"name":"invoke","arguments":{"op":"call",
                "connection":"conn-mcp","action":"held_write","args":{"team":"plexus"}}});
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                wire::control_flags(),
                2,
                1,
                8,
                serde_json::to_vec(&object).unwrap(),
            )
            .unwrap();
            let routes = Arc::new(RouteBindings::new());
            routes.insert(2, 1, Principal::Direct).unwrap();
            facade_tool_reply(&frame, object.as_object().unwrap(), &self.state, &routes)
                .expect("a reply")
        }

        fn audit_rows(&self, gate: &str) -> i64 {
            rusqlite::Connection::open(self.scratch.path())
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM audit_journal WHERE gate = ?1 AND actor = 'direct'",
                    [gate],
                    |row| row.get(0),
                )
                .unwrap()
        }
    }

    /// A caller without a grant causes no vendor contact at all: the freshness
    /// check, whose catalog refresh is an MCP `tools/list` call, runs only
    /// after authorization. The vendor counts every connection it receives
    /// and closes it at once, so a refresh fails fast instead of waiting.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_write_causes_no_vendor_contact() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let vendor = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        vendor.set_nonblocking(true).unwrap();
        let url = format!("http://{}/mcp", vendor.local_addr().unwrap());
        let contacts = Arc::new(AtomicUsize::new(0));
        let running = Arc::new(AtomicBool::new(true));
        let counter = {
            let contacts = Arc::clone(&contacts);
            let running = Arc::clone(&running);
            std::thread::spawn(move || {
                while running.load(Ordering::Acquire) {
                    match vendor.accept() {
                        Ok((stream, _)) => {
                            contacts.fetch_add(1, Ordering::SeqCst);
                            drop(stream);
                        }
                        Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                    }
                }
            })
        };
        let fixture = mcp_write_fixture("freshness-ungranted", &url, false, false);
        fixture.age_catalog();
        let reply = blocking_section(|| fixture.invoke());
        running.store(false, Ordering::Release);
        let _ = counter.join();
        let code = reply["error"]["code"].as_str().unwrap_or_default();
        assert!(
            !code.is_empty() && code != "freshness_check_failed" && code != "catalog_stale_write",
            "an ungranted write must get its authorization refusal: {reply}"
        );
        assert_eq!(
            contacts.load(Ordering::SeqCst),
            0,
            "an ungranted write must cause zero vendor requests"
        );
        assert_eq!(fixture.transport.requests().len(), 0);
    }

    /// A granted write whose tool schema changed at the vendor is caught by
    /// the freshness refresh (run after authorization, audited under the
    /// caller) and not sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_granted_write_whose_schema_changed_is_not_sent() {
        let mut changed = write_schema();
        changed["properties"]["title"] = json!({"type": "string"});
        let vendor = plexus_conformance::stub_server::StubMcpServer::start(vec![
            plexus_conformance::stub_server::StubTool::new("held_write", changed),
        ])
        .expect("stub MCP vendor");
        let fixture = mcp_write_fixture("freshness-schema-changed", vendor.endpoint(), false, true);
        fixture.age_catalog();
        let reply = blocking_section(|| fixture.invoke());
        assert_eq!(
            reply["result"]["transmission"], "not_sent",
            "a write whose schema changed must not be sent: {reply}"
        );
        assert_eq!(fixture.transport.requests().len(), 0, "{reply}");
        assert_eq!(
            fixture.audit_rows("freshness"),
            1,
            "the refresh that reached the vendor is audited under the caller"
        );
    }

    /// An approved request runs the same freshness check when it executes: a
    /// schema that changed while the request waited for approval stops it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_approved_write_whose_schema_changed_while_waiting_is_not_sent() {
        let mut changed = write_schema();
        changed["properties"]["title"] = json!({"type": "string"});
        let vendor = plexus_conformance::stub_server::StubMcpServer::start(vec![
            plexus_conformance::stub_server::StubTool::new("held_write", changed),
        ])
        .expect("stub MCP vendor");
        let fixture = mcp_write_fixture("freshness-approved", vendor.endpoint(), true, true);
        // A tool call over a route with no session scope cannot file a consent
        // card, so it can't create this held approval. Hold it through
        // internal authorization; only the operator can then approve it.
        let request_id = match fixture
            .state
            .runtime
            .engine
            .authorize(AuthorizationRequest::new(
                "direct",
                "conn-mcp",
                "held_write",
                json!({"team":"plexus"}),
            )) {
            Err(plexus_core::Denial::ActionRequestCreated { request_id }) => request_id,
            other => panic!("operator approval was not parked: {other:?}"),
        };
        // Time passes while it waits: the catalog is now past its bound.
        fixture.age_catalog();
        let outcome = blocking_section(|| {
            fixture
                .state
                .runtime
                .engine
                .approve_request("direct", &request_id, "direct")
        })
        .expect("approval is accepted");
        assert_eq!(
            outcome.transmission,
            plexus_core::TransmissionState::NotSent,
            "an approved write whose schema changed while it waited must not be sent: {outcome:?}"
        );
        assert_eq!(fixture.transport.requests().len(), 0);
    }

    /// When the ids still unacknowledged cannot be read, a partial ack is an
    /// error naming the committed count, never `"unacked": []`, which would
    /// claim every event was acknowledged.
    #[test]
    fn a_partial_ack_whose_unacked_read_fails_is_an_error() {
        let failed = partial_ack_reply(2, Err::<Vec<String>, _>("store unavailable"));
        assert_eq!(
            failed["error"]["code"], "store_failure",
            "an unreadable unacked list must be an error, not an empty list: {failed}"
        );
        assert_eq!(failed["error"]["acked"], 2, "{failed}");
        assert!(failed.get("result").is_none(), "{failed}");
        let read = partial_ack_reply(2, Ok::<_, String>(vec!["event-3".to_string()]));
        assert_eq!(read["result"]["unacked"], json!(["event-3"]), "{read}");
    }

    /// A write whose freshness check cannot run (here the connection's
    /// credential cannot be resolved) is refused after authorization: a caller
    /// without a grant gets its grant refusal and learns nothing about the
    /// target, and a granted caller gets `freshness_check_failed` as not sent,
    /// audited as a pre-dispatch refusal, with nothing dispatched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_write_whose_freshness_check_cannot_run_is_not_sent() {
        let path = Scratch::database("freshness-check-failed");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: path.to_string_lossy().into_owned(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        // Authorize `held_write` with an ordinary grant: the manifest's lowest
        // app tier makes this write too low-severity to need the separate
        // approval service. The pre-write catalog check then stops because the
        // manifest requires a credential but the source resolves none. Report
        // a credential failure, not a stale catalog or missing transport.
        // Configure the `team` filter to permit writes within that team, and
        // redeem a binding ticket to attach the credential reference.
        store
            .upsert_manifest(
                "system",
                &crate::test_write_manifest("credentialed", "https://vendor.invalid/mcp"),
            )
            .unwrap();
        store
            .insert_connection(
                "direct",
                "conn-keep-rest",
                "credentialed",
                "pending",
                &json!({"required": [], "optional": [], "write_enabling": ["team"]}),
            )
            .unwrap();
        let ticket = store
            .create_binding_ticket("direct", "conn-keep-rest", b"test:freshness-handle")
            .expect("ticket");
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("connect")
            .expect("connection activates");
        // A stub with no responses resolves no credential at all.
        let transport = Arc::new(plexus_core::MockTransport::default());
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: ModuleRuntime::with_stub_credentials_and_mock_transport(
                Arc::clone(&store),
                Arc::new(StubCredentialSource::default()),
                Arc::clone(&transport),
            ),
        });
        let schema = json!({"type": "object"});
        store
            .upsert_catalog_action(&plexus_core::CatalogActionInput {
                connection_id: "conn-keep-rest".to_string(),
                principal: "direct".to_string(),
                name: "held_write".to_string(),
                title: None,
                schema: schema.clone(),
                schema_hash: plexus_core::jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
                risk: "write".to_string(),
                // The column holds the app's tier, as the catalog seed writes it.
                severity: "S1".to_string(),
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
                ask_first: false,
            })
            .expect("seed write action");
        // Set the connection's catalog rows as last seen at time zero, so the
        // catalog is stale.
        // A stale catalog makes the pre-write check rediscover the vendor's
        // actions, which needs the credential this fixture cannot resolve, so
        // the write is refused as `catalog_stale_write`. With a fresh catalog
        // the check would pass without a credential, and the call would fail
        // later, at the credential lookup before dispatch, which is not what
        // this test is about.
        let db = rusqlite::Connection::open(path.path()).unwrap();
        assert!(
            db.execute(
                "UPDATE catalog_actions SET last_seen_at_ms=0 WHERE connection_id='conn-keep-rest'",
                []
            )
            .unwrap()
                > 0
        );
        let object = json!({"name":"invoke","arguments":{"op":"call",
            "connection":"conn-keep-rest","action":"held_write","args":{"team":"plexus"}}});
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            wire::control_flags(),
            2,
            1,
            8,
            serde_json::to_vec(&object).unwrap(),
        )
        .unwrap();
        let routes = Arc::new(RouteBindings::new());
        routes.insert(2, 1, Principal::Direct).unwrap();
        let invoke = || {
            facade_tool_reply(&frame, object.as_object().unwrap(), &state, &routes)
                .expect("a reply")
        };

        let ungranted = invoke();
        let code = ungranted["error"]["code"].as_str().unwrap_or_default();
        assert!(
            !code.is_empty() && code != "catalog_stale_write",
            "an ungranted caller must get its authorization refusal: {ungranted}"
        );

        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "grant-held-write".into(),
                principal: "direct".into(),
                connection_id: "conn-keep-rest".into(),
                grantee_principal: "direct".into(),
                risk_ceiling: "write".into(),
                action_selectors: vec!["held_write".into()],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .expect("grant");
        let granted = invoke();
        assert_eq!(
            granted["result"]["transmission"], "not_sent",
            "a write whose freshness check cannot run must not be sent: {granted}"
        );
        assert_eq!(
            granted["result"]["response"]["code"], "catalog_stale_write",
            "a write whose freshness check cannot run must not be sent: {granted}"
        );
        let db = rusqlite::Connection::open(path.path()).unwrap();
        let count = |reason: &str| -> i64 {
            db.query_row(
                "SELECT COUNT(*) FROM audit_journal WHERE action = 'held_write' AND reason_code = ?1",
                [reason],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert!(count("catalog_stale_write") >= 1, "the refusal is audited");
        assert_eq!(count("dispatched"), 0, "nothing was dispatched");
        assert_eq!(
            transport.requests().len(),
            0,
            "nothing reached the transport"
        );
    }

    /// A connect whose catalog seed fails reports degraded discovery with the
    /// reason, never `complete`: the connection is active but its reviewed
    /// actions were not stored.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_catalog_seed_is_reported_as_degraded_discovery() {
        let (path, store, state) = two_connection_fixture("connect-seed-error");
        let app_key = store
            .connection("direct", "conn-keep-rest")
            .unwrap()
            .expect("fixture connection")
            .app_key;
        store
            .insert_connection("direct", "conn-seed", &app_key, "pending", &json!({}))
            .unwrap();
        let ticket = store
            .create_binding_ticket("direct", "conn-seed", b"test:seed-handle")
            .expect("ticket");
        rusqlite::Connection::open(path.path())
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER refuse_seed BEFORE INSERT ON catalog_actions
                 WHEN NEW.connection_id = 'conn-seed'
                 BEGIN SELECT RAISE(ABORT, 'catalog table unavailable'); END;",
            )
            .unwrap();
        let object = json!({"name":"connections","arguments":{"op":"connect",
            "ticket_id": ticket.ticket_id}});
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            wire::control_flags(),
            2,
            1,
            8,
            serde_json::to_vec(&object).unwrap(),
        )
        .unwrap();
        let routes = Arc::new(RouteBindings::new());
        routes.insert(2, 1, Principal::Direct).unwrap();
        let reply = facade_tool_reply(&frame, object.as_object().unwrap(), &state, &routes)
            .expect("a reply");
        assert_eq!(
            reply["result"]["discovery"], "degraded",
            "a failed seed must report degraded discovery: {reply}"
        );
        assert!(
            reply["result"]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("seeded")),
            "a failed seed must report degraded discovery with the seed as its reason: {reply}"
        );
    }

    /// `blocking_section` must not panic on a current-thread runtime, where
    /// `block_in_place` is unavailable; it runs the work inline there.
    #[test]
    fn blocking_section_runs_on_a_current_thread_runtime() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        let answer = runtime.block_on(async { blocking_section(|| 41 + 1) });
        assert_eq!(answer, 42);
        // Outside any runtime it runs inline too.
        assert_eq!(blocking_section(|| 7), 7);
    }

    /// Shutdown waits a bounded time for a signalled task, then aborts it, so
    /// a task that never stops cannot hold the module open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_aborts_a_task_that_does_not_stop_within_its_grace() {
        let stuck = tokio::spawn(std::future::pending::<()>());
        let abort = stuck.abort_handle();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stop_task("stuck", stuck, std::time::Duration::from_millis(50)),
        )
        .await
        .expect("stop_task must return once the grace has passed");
        // Cancellation lands when the runtime next polls the task.
        for _ in 0..100 {
            if abort.is_finished() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(abort.is_finished(), "the stuck task must be aborted");
    }

    /// Send one management call bound as `principal` and return its response
    /// body through the same management handler the admin client uses.
    fn management_call(
        state: &Arc<ModuleState>,
        principal: Principal,
        method: &str,
        params: Value,
    ) -> Value {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("management test runtime");
        runtime.block_on(async {
            let (writer, mut responses) = mpsc::channel(4);
            let bindings = Arc::new(RouteBindings::new());
            let route = RouteFrameContext {
                version: PROTOCOL_VERSION,
                channel: 5,
                epoch: 2,
                correlation: 91,
            };
            bindings
                .insert(route.channel, route.epoch, principal)
                .expect("bind principal");
            confirmed_management_request(route, method, &params, &writer, state, &bindings)
                .await
                .expect("management request receives a response");
            let frame = recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "management response",
            )
            .await;
            serde_json::from_slice(&frame.body).expect("management response JSON")
        })
    }

    async fn confirmed_management_request(
        route: RouteFrameContext,
        method: &str,
        params: &Value,
        writer: &mpsc::Sender<Frame>,
        state: &Arc<ModuleState>,
        bindings: &Arc<RouteBindings>,
    ) -> Result<(), ModuleError> {
        let (proxy, requests) = mpsc::channel(4);
        let (result, ()) = tokio::join!(
            handle_management_request(route, method, params, &proxy, state, bindings),
            operator_confirmation::approving_test_peer(requests, writer, &bindings.control_replies),
        );
        result
    }

    /// Create a file-backed store with two active REST connections owned by
    /// `direct` and no credential bindings. Credential checks cannot resolve
    /// credentials for either connection and log a failure on each pass while
    /// that connection remains active.
    fn two_connection_fixture(label: &str) -> (Scratch, Arc<PlexusStore>, Arc<ModuleState>) {
        two_connection_fixture_with_retire_status(label, "active")
    }

    // `retire_status` is the status of `conn-retire-rest`; `conn-keep-rest` is
    // always active. The credential-rebind tests pass "pending" because they
    // redeem a binding ticket for `conn-retire-rest`, which needs a pending
    // connection. The missing-credential health tests use the default, both
    // connections active, through `two_connection_fixture`.
    fn two_connection_fixture_with_retire_status(
        label: &str,
        retire_status: &str,
    ) -> (Scratch, Arc<PlexusStore>, Arc<ModuleState>) {
        let path = Scratch::database(label);
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: path.to_string_lossy().into_owned(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/exa_rest.jsonc"),
        )
        .unwrap();
        let ingested = plexus_core::ingest_value(
            serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap(),
        )
        .unwrap();
        store.upsert_manifest("system", &ingested).unwrap();
        for id in ["conn-retire-rest", "conn-keep-rest"] {
            store
                .insert_connection(
                    "direct",
                    id,
                    &ingested.manifest.key,
                    if id == "conn-retire-rest" {
                        retire_status
                    } else {
                        "active"
                    },
                    &json!({}),
                )
                .unwrap();
        }
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        });
        (path, store, state)
    }

    mod credential_rebind {
        include!("credential_rebind_tests.rs");
    }

    mod operator_confirmation_tests {
        include!("operator_confirmation_tests.rs");
    }

    fn delete_audit_rows(path: &Path, connection_id: &str) -> i64 {
        rusqlite::Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM audit_journal
                 WHERE reason_code = 'ceremony_delete_connection' AND connection_id = ?1",
                [connection_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn all_audit_rows(path: &Path, connection_id: &str) -> i64 {
        rusqlite::Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM audit_journal WHERE connection_id = ?1",
                [connection_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn connection_status(store: &PlexusStore, connection_id: &str) -> String {
        store
            .connection("direct", connection_id)
            .unwrap()
            .expect("connection row exists")
            .status
    }

    fn connection_exists(store: &PlexusStore, connection_id: &str) -> bool {
        store.connection("direct", connection_id).unwrap().is_some()
    }

    fn delete_params(connection_id: &str, apply: bool) -> Value {
        json!({"connection_id": connection_id, "dry_run": !apply})
    }

    /// Revokes one of the two fixture connections, then runs one
    /// health-probe pass. Its stderr is read by
    /// `a_revoked_connection_is_neither_probed_nor_logged`.
    #[test]
    fn revoke_then_probe_fixture() {
        logging::init_child();
        let (path, store, state) = two_connection_fixture("revoke-probe");
        assert!(store
            .revoke_connection("direct", "conn-retire-rest")
            .unwrap());
        run_health_probes(&state);
        assert_eq!(
            connection_status(&store, "conn-retire-rest"),
            "revoked",
            "a probe pass must not bring a revoked connection back"
        );
        drop(state);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    /// A revoked connection is neither probed nor logged by the next health
    /// pass. The connection left active beside it IS logged in the same pass,
    /// so a quiet stderr cannot come from a probe that never ran or a log
    /// that was never captured.
    #[test]
    fn a_revoked_connection_is_neither_probed_nor_logged() {
        let stderr = module_diagnostic_output("tests::revoke_then_probe_fixture");
        assert!(
            stderr.contains("health probe failed for principal direct, connection conn-keep-rest"),
            "the active sibling must still be probed and logged: {stderr}"
        );
        assert!(
            !stderr.contains("conn-retire-rest"),
            "a revoked connection must not be probed or logged: {stderr}"
        );
    }

    /// A live grant makes the delete fail with `connection_has_live_grants`
    /// and leaves the connection untouched; an expired grant does not count
    /// and is deleted with the connection. Revoking the live grant first is
    /// what lets the delete go through.
    #[test]
    fn delete_connection_refuses_while_a_grant_is_live_and_changes_nothing() {
        let (path, store, state) = two_connection_fixture("delete-live-grant");
        for (grant_id, expires_at) in [("g-live", None), ("g-expired", Some(1))] {
            store
                .insert_grant(&plexus_core::GrantInput {
                    grant_id: grant_id.into(),
                    principal: "direct".into(),
                    connection_id: "conn-retire-rest".into(),
                    grantee_principal: "reserved:aft".into(),
                    risk_ceiling: "read".into(),
                    action_selectors: vec!["*".into()],
                    authority_kind: "invoke".into(),
                    expires_at,
                })
                .unwrap();
        }
        let generation = store
            .connection("direct", "conn-retire-rest")
            .unwrap()
            .unwrap()
            .generation;
        let refused = management_call(
            &state,
            Principal::Direct,
            manifest::ADMIN_DELETE_CONNECTION_OP,
            delete_params("conn-retire-rest", true),
        );
        // The code is the fixed string `connection_has_live_grants`, so a
        // script can match it exactly; the number of grants is a separate field.
        assert_eq!(
            refused["error"]["code"], "connection_has_live_grants",
            "{refused}"
        );
        assert_eq!(refused["error"]["count"], 1, "{refused}");
        let after = store
            .connection("direct", "conn-retire-rest")
            .unwrap()
            .unwrap();
        assert_eq!(after.status, "active");
        assert_eq!(after.generation, generation);
        assert_eq!(delete_audit_rows(&path, "conn-retire-rest"), 0);

        let revoked = management_call(
            &state,
            Principal::Direct,
            manifest::ADMIN_REVOKE_GRANT_OP,
            json!({"grant_id": "g-live"}),
        );
        assert_eq!(revoked["result"]["revoked"], true, "{revoked}");
        let deleted = management_call(
            &state,
            Principal::Direct,
            manifest::ADMIN_DELETE_CONNECTION_OP,
            delete_params("conn-retire-rest", true),
        );
        assert_eq!(deleted["result"]["outcome"], "deleted", "{deleted}");
        assert_eq!(deleted["result"]["rows"]["grants"], 1, "{deleted}");
        assert!(!connection_exists(&store, "conn-retire-rest"));
        assert_eq!(delete_audit_rows(&path, "conn-retire-rest"), 1);
        drop(state);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    /// `list_grants` honours `connection_id`, and the revoke and remove-policy
    /// audit rows name what was removed: the connection, the grant's ceiling
    /// or the policy's effect, and the id.
    #[test]
    fn list_grants_filters_by_connection_and_removals_audit_their_target() {
        let (path, store, state) = two_connection_fixture("grant-list-audit");
        for (grant_id, connection_id, risk) in [
            ("g-retire", "conn-retire-rest", "read"),
            ("g-keep", "conn-keep-rest", "write"),
        ] {
            store
                .insert_grant(&plexus_core::GrantInput {
                    grant_id: grant_id.into(),
                    principal: "direct".into(),
                    connection_id: connection_id.into(),
                    grantee_principal: "reserved:aft".into(),
                    risk_ceiling: risk.into(),
                    action_selectors: vec!["*".into()],
                    authority_kind: "invoke".into(),
                    expires_at: None,
                })
                .unwrap();
        }
        let listed = management_call(
            &state,
            Principal::Direct,
            manifest::ADMIN_LIST_GRANTS_OP,
            json!({"connection_id": "conn-keep-rest"}),
        );
        let ids: Vec<&str> = listed["result"]["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .filter_map(|grant| grant["grant_id"].as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["g-keep"],
            "list_grants must narrow to the named connection: {listed}"
        );

        let revoked = management_call(
            &state,
            Principal::Direct,
            manifest::ADMIN_REVOKE_GRANT_OP,
            json!({"grant_id": "g-keep"}),
        );
        assert_eq!(revoked["result"]["revoked"], true, "{revoked}");
        let policy = management_call(
            &state,
            Principal::Direct,
            manifest::ADMIN_SET_POLICY_OP,
            json!({"connection_id": "conn-keep-rest", "action_selector": "*", "effect": "block"}),
        );
        let policy_id = policy["result"]["policy"]["policy_id"]
            .as_str()
            .unwrap_or_else(|| panic!("policy id: {policy}"))
            .to_string();
        let removed = management_call(
            &state,
            Principal::Direct,
            manifest::ADMIN_REMOVE_POLICY_OP,
            json!({"policy_id": policy_id}),
        );
        assert_eq!(removed["result"]["removed"], true, "{removed}");

        let db = rusqlite::Connection::open(path.path()).unwrap();
        let row = |reason: &str| -> (Option<String>, Option<String>, Option<String>) {
            db.query_row(
                "SELECT connection_id, risk, args_redaction_summary FROM audit_journal
                 WHERE reason_code = ?1",
                [reason],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
        };
        assert_eq!(
            row("ceremony_revoke_grant"),
            (
                Some("conn-keep-rest".into()),
                Some("write".into()),
                Some("grant g-keep revoked".into())
            ),
            "the revoke audit row must name the grant"
        );
        assert_eq!(
            row("ceremony_remove_policy"),
            (
                Some("conn-keep-rest".into()),
                None,
                Some(format!("policy {policy_id} removed; effect=block"))
            ),
            "policy effects belong in the audit summary, never the risk column"
        );
    }

    /// The normal path: revoke the connection, then delete it. A dry run
    /// reports the plan and writes nothing. The apply deletes the connection
    /// and writes one audit row. It keeps the audit rows that already existed,
    /// including one old enough for the audit delete trigger to allow
    /// removing, so the test shows the delete itself skips audit rows. A
    /// repeat finds nothing. An unknown connection is refused with
    /// `connection_not_found`.
    #[test]
    fn delete_connection_dry_run_writes_nothing_and_the_apply_keeps_the_audit_trail() {
        let (path, store, state) = two_connection_fixture("delete-dry-run");
        assert!(store
            .revoke_connection("direct", "conn-retire-rest")
            .unwrap());
        rusqlite::Connection::open(&*path)
            .unwrap()
            .execute(
                "INSERT INTO audit_journal (ts, principal, actor, acting_principal,
                     connection_id, decision, reason_code)
                 VALUES (1, 'direct', 'agent', 'direct', 'conn-retire-rest', 'allow', 'invoke')",
                [],
            )
            .unwrap();
        let planned = management_call(
            &state,
            Principal::Direct,
            manifest::ADMIN_DELETE_CONNECTION_OP,
            json!({"connection_id": "conn-retire-rest"}),
        );
        assert_eq!(planned["result"]["outcome"], "would_delete", "{planned}");
        assert_eq!(planned["result"]["status"], "revoked", "{planned}");
        assert_eq!(planned["result"]["dry_run"], true, "{planned}");
        assert!(connection_exists(&store, "conn-retire-rest"));
        assert_eq!(all_audit_rows(&path, "conn-retire-rest"), 1);

        let applied = management_call(
            &state,
            Principal::Direct,
            manifest::ADMIN_DELETE_CONNECTION_OP,
            delete_params("conn-retire-rest", true),
        );
        assert_eq!(applied["result"]["outcome"], "deleted", "{applied}");
        assert!(!connection_exists(&store, "conn-retire-rest"));
        assert_eq!(delete_audit_rows(&path, "conn-retire-rest"), 1);
        assert_eq!(
            all_audit_rows(&path, "conn-retire-rest"),
            2,
            "the delete must keep the audit rows the connection already had"
        );
        assert_eq!(connection_status(&store, "conn-keep-rest"), "active");

        for connection in ["conn-retire-rest", "conn-missing-rest"] {
            let unknown = management_call(
                &state,
                Principal::Direct,
                manifest::ADMIN_DELETE_CONNECTION_OP,
                delete_params(connection, true),
            );
            assert_eq!(
                unknown["error"]["code"], "connection_not_found",
                "{connection}: {unknown}"
            );
        }
        assert_eq!(delete_audit_rows(&path, "conn-retire-rest"), 1);
        drop(state);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    /// A GitHub App handle's connection is created and ended with its
    /// handle, so the delete refuses it and writes nothing.
    #[test]
    fn delete_connection_refuses_a_github_handle_connection() {
        let (path, store, state) = two_connection_fixture("delete-handle");
        let app_key = store
            .connection("direct", "conn-retire-rest")
            .unwrap()
            .unwrap()
            .app_key;
        store
            .insert_connection("direct", "github-handle-h1", &app_key, "active", &json!({}))
            .unwrap();
        let refused = management_call(
            &state,
            Principal::Direct,
            manifest::ADMIN_DELETE_CONNECTION_OP,
            delete_params("github-handle-h1", true),
        );
        assert_eq!(
            refused["error"]["code"], "connection_is_github_handle",
            "{refused}"
        );
        assert!(connection_exists(&store, "github-handle-h1"));
        assert_eq!(delete_audit_rows(&path, "github-handle-h1"), 0);
        drop(state);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    /// Only a direct principal may delete a connection; a supervised module
    /// is refused before anything is read or written.
    #[test]
    fn delete_connection_refuses_a_non_direct_caller() {
        let (path, store, state) = two_connection_fixture("delete-non-direct");
        let denied = management_call(
            &state,
            Principal::Reserved {
                module_id: "aft".to_string(),
            },
            manifest::ADMIN_DELETE_CONNECTION_OP,
            delete_params("conn-retire-rest", true),
        );
        assert_eq!(
            denied["error"]["code"], "operator_authority_required",
            "{denied}"
        );
        assert!(connection_exists(&store, "conn-retire-rest"));
        assert_eq!(delete_audit_rows(&path, "conn-retire-rest"), 0);
        drop(state);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    /// Capture the actual stderr of an isolated test process, not a formatting proxy.
    mod logging {
        include!("../../plexus-core/tests/support/logging.rs");
    }

    fn module_diagnostic_output(test: &str) -> String {
        let output = bounded::child_output(
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", test, "--nocapture"])
                .env("PLEXUS_LOG_STDERR_CHILD", "1"),
            std::time::Duration::from_secs(30),
            "module diagnostic test child",
        )
        .expect("run diagnostic fixture");
        assert!(
            output.status.success(),
            "fixture {test} failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stderr).expect("UTF-8 stderr")
    }

    #[test]
    fn route_capacity_log_fixture() {
        logging::init_child();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (_scratch, _store, state) = two_connection_fixture("route-capacity-log");
                let routes = Arc::new(RouteBindings::new());
                for channel in 10..(10 + MAX_ROUTE_BINDINGS as u16) {
                    routes.insert(channel, 1, Principal::Direct).unwrap();
                }
                let (writer, mut responses) = mpsc::channel(4);
                for _ in 0..3 {
                    handle_control_request(bind(Some(Principal::Direct)), &writer, &state, &routes)
                        .await
                        .unwrap();
                    let reply = recv_within(
                        responses.recv(),
                        std::time::Duration::from_secs(5),
                        "route capacity refusal",
                    )
                    .await;
                    assert_eq!(reply.header.ty, FrameType::Error);
                    let body: Value = serde_json::from_slice(&reply.body).unwrap();
                    assert_eq!(body["code"], "resource_exhausted");
                }
                assert_eq!(routes.inner.read().unwrap().len(), MAX_ROUTE_BINDINGS);
            });
    }

    #[test]
    fn route_capacity_refusals_emit_one_warning_per_period() {
        let stderr = module_diagnostic_output("tests::route_capacity_log_fixture");
        assert_eq!(
            stderr.matches("route binding capacity exhausted").count(),
            1,
            "cap pressure must emit exactly one warning per minute: {stderr}"
        );
    }

    #[test]
    fn diagnostic_shadow_fixture() {
        logging::init_child();
        eprintln!(warn wire: "diagnostic_shadow_probe");
    }

    #[test]
    fn diagnostic_shadow_writes_fleet_attribution_to_real_stderr() {
        let stderr = module_diagnostic_output("tests::diagnostic_shadow_fixture");
        let lines: Vec<_> = stderr
            .lines()
            .filter(|line| line.contains("diagnostic_shadow_probe"))
            .collect();
        assert_eq!(lines.len(), 1, "{stderr}");
        logging::assert_diagnostic(
            lines[0],
            cortexkit_log::ParsedLevel::Warn,
            "plexus.wire",
            "diagnostic_shadow_probe",
        );
    }

    fn bind(principal: Option<Principal>) -> Frame {
        let request = ModuleControlRequest::RouteBind {
            scope: None,
            call_mode: None,
            role_versions: None,
            route_channel: 4,
            epoch: 2,
            target: RouteTarget::ToolProvider {
                module_id: DEFAULT_MODULE_ID.to_string(),
            },
            identity: BindIdentity::new("/tmp/project", "test".to_string(), "session".to_string()),
            principal,
            consumer_capabilities: None,
            admission_facts: None,
        };
        Frame::build(
            FrameType::Request,
            wire::control_flags(),
            0,
            0,
            7,
            serde_json::to_vec(&request).expect("serialize bind"),
        )
        .expect("build bind frame")
    }

    /// The boot ingest retires a manifest whose file has been removed from the
    /// catalog directory.
    ///
    /// This is the CALL-SITE test for the retirement sweep. The store method has
    /// its own tests in plexus-core, and those pass whether or not anything
    /// invokes it -- a correct mechanism nobody calls is indistinguishable from
    /// an absent one, and this sweep's whole purpose is to run on every boot.
    ///
    /// Driven through two real ingests against a temporary directory with a file
    /// deleted in between, because that is what a catalog sync actually does.
    ///
    /// Mutation-proved: discarding the sweep's result at the call site, leaving
    /// the store method itself untouched, fails this on the listing.
    #[test]
    fn the_boot_ingest_retires_a_withdrawn_manifest() {
        let unique = format!("{}-{}", std::process::id(), plexus_core::now_ms());
        let directory = Scratch::directory("retire");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
        for name in ["deepwiki.jsonc", "tavily.jsonc"] {
            std::fs::copy(source.join(name), directory.join(name)).expect("seed manifest");
        }

        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("retire-{unique}"),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: directory.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let store = PlexusStore::open(&descriptor).expect("test store");

        ingest_catalog_from(&store, &directory).expect("first ingest");
        let before: Vec<String> = store
            .list_manifest_summaries("direct")
            .expect("list manifests")
            .into_iter()
            .map(|summary| summary.key)
            .collect();
        assert_eq!(before, vec!["deepwiki".to_string(), "tavily".to_string()]);

        // What a catalog sync that drops a vendor looks like on disk.
        std::fs::remove_file(directory.join("tavily.jsonc")).expect("withdraw manifest");
        ingest_catalog_from(&store, &directory).expect("second ingest");

        let after: Vec<String> = store
            .list_manifest_summaries("direct")
            .expect("list manifests")
            .into_iter()
            .map(|summary| summary.key)
            .collect();
        assert_eq!(
            after,
            vec!["deepwiki".to_string()],
            "the withdrawn vendor must stop being offered after a boot ingest"
        );
    }

    /// The offline check counts each file once: an unreadable manifest is an
    /// I/O error and not also a refusal.
    #[test]
    fn the_catalog_check_counts_an_unreadable_manifest_once() {
        let directory = Scratch::directory("check-tally");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
        std::fs::copy(
            source.join("deepwiki.jsonc"),
            directory.join("deepwiki.jsonc"),
        )
        .expect("seed manifest");
        std::fs::write(directory.join("broken.jsonc"), "{").expect("broken manifest");
        // A directory with the manifest extension cannot be read as a file.
        std::fs::create_dir(directory.join("unreadable.jsonc")).expect("unreadable entry");
        let paths = catalog_paths(&directory).expect("paths");
        assert_eq!(
            tally_catalog(&paths),
            (1, 1, 1),
            "an unreadable manifest is counted once, as an I/O error only"
        );
    }

    /// A catalog directory with no manifests refuses the boot and retires
    /// nothing: an empty or wrong PLEXUS_CATALOG_DIR must not withdraw every
    /// vendor the store already serves.
    #[test]
    fn an_empty_catalog_directory_refuses_the_boot_and_retires_nothing() {
        let unique = format!("{}-{}", std::process::id(), plexus_core::now_ms());
        let directory = Scratch::directory("empty-catalog");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
        std::fs::copy(
            source.join("deepwiki.jsonc"),
            directory.join("deepwiki.jsonc"),
        )
        .expect("seed manifest");
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("empty-catalog-{unique}"),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: directory.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let store = PlexusStore::open(&descriptor).expect("test store");
        ingest_catalog_from(&store, &directory).expect("first ingest");

        // Reject an existing directory with no manifests, such as one selected
        // by a mistyped `PLEXUS_CATALOG_DIR`. Preserve existing catalog entries
        // rather than retiring them because the selected directory is empty.
        let empty = Scratch::directory("empty-catalog-dir");
        let error = ingest_catalog_from(&store, &empty)
            .expect_err("an empty catalog directory must refuse the boot");
        assert!(error.to_string().contains("no .jsonc manifests"), "{error}");
        let after: Vec<String> = store
            .list_manifest_summaries("direct")
            .expect("list manifests")
            .into_iter()
            .map(|summary| summary.key)
            .collect();
        assert_eq!(
            after,
            vec!["deepwiki".to_string()],
            "nothing may be retired"
        );
    }

    /// The boot ingest pins reviewed argument schemas on GitHub handle rows
    /// that still hold the open placeholder.
    ///
    /// The CALL-SITE test for `pin_handle_placeholder_schemas`: the plexus-core
    /// tests of the store method pass whether or not a boot ever calls it, so
    /// only a test through the boot ingest proves the pass runs.
    #[test]
    fn the_boot_ingest_pins_reviewed_schemas_on_placeholder_handle_rows() {
        let unique = format!("{}-{}", std::process::id(), plexus_core::now_ms());
        let directory = Scratch::directory("handle-pin");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
        std::fs::copy(
            source.join("github_rest.jsonc"),
            directory.join("github_rest.jsonc"),
        )
        .expect("seed manifest");
        let path = directory.join("store.db");
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("handle-pin-{unique}"),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        };
        let store = PlexusStore::open(&descriptor).expect("test store");
        let connection = "github-handle-app-fixture";
        store
            .insert_connection("direct", connection, "github_rest", "active", &json!({}))
            .expect("handle connection");
        store
            .put_github_handle(&plexus_core::storage::github_store::GithubHandle {
                app_handle_id: "app-fixture".into(),
                agent_id: "agent-fixture".into(),
                app_id: 1,
                installation_id: None,
                credential_reference: "github_app:app-fixture".into(),
                credential_generation: 1,
                status: "enabled".into(),
                proven_at: Some(1),
                connection_principal: "direct".into(),
                connection_id: connection.into(),
            })
            .expect("handle");
        // The first boot adds the handle's missing rows from the manifest.
        ingest_catalog_from(&store, &directory).expect("first ingest");
        let db = rusqlite::Connection::open(&path).expect("raw store");
        // Put every row back on the placeholder, as the old seeder left them.
        let rewound = db
            .execute(
                "UPDATE catalog_actions
                 SET schema_json = '{\"additionalProperties\":true,\"type\":\"object\"}'
                 WHERE connection_id = ?1",
                [connection],
            )
            .expect("rewind rows");
        assert!(rewound > 0);

        ingest_catalog_from(&store, &directory).expect("second ingest");

        let still_open: i64 = db
            .query_row(
                "SELECT count(*) FROM catalog_actions
                 WHERE connection_id = ?1 AND json_extract(schema_json, '$.properties') IS NULL",
                [connection],
                |row| row.get(0),
            )
            .expect("count open rows");
        assert_eq!(
            still_open, 0,
            "every placeholder handle row must hold its reviewed schema after a boot ingest"
        );
    }

    #[tokio::test]
    async fn untrusted_bind_is_default_denied() {
        let (writer, mut responses) = mpsc::channel(4);
        let health = Arc::new(health::HealthState::new());
        let scratch = Scratch::database("untrusted-test");
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: "test-untrusted".to_string(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));
        let state = Arc::new(ModuleState {
            health,
            runtime: runtime_for_test(store),
        });
        let bindings = Arc::new(RouteBindings::new());
        handle_control_request(
            bind(Some(Principal::Reserved {
                module_id: "subc-mcp".to_string(),
            })),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("handler succeeds");
        let response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "denial response",
        )
        .await;
        assert_eq!(response.header.ty, FrameType::Error);
        let body: ErrorBody = serde_json::from_slice(&response.body).expect("error body");
        assert_eq!(body.code, "principal_denied");
    }

    /// Schema review changes which catalog action may run, so it must remain on
    /// the management route and require the same Direct-principal gate as the
    /// other ceremony operations. A facade response alone would not prove either
    /// boundary: this drives the management handler's denied and allowed arms,
    /// then proves a facade-shaped call cannot name the operation.
    #[tokio::test]
    async fn review_action_is_management_only_and_requires_a_direct_principal() {
        let (writer, mut responses) = mpsc::channel(4);
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("review-action-gate-{}", plexus_core::now_ms()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("open test store"));
        store
            .upsert_catalog_action(&plexus_core::CatalogActionInput {
                connection_id: "conn-review".to_string(),
                principal: "direct".to_string(),
                name: "list_issues".to_string(),
                title: Some("list_issues".to_string()),
                schema: json!({"type": "object", "properties": {"since": {"type": "string"}}}),
                schema_hash: "sha256:current".to_string(),
                risk: "read".to_string(),
                severity: "S2".to_string(),
                ask_first: false,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("seed catalog action");
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        });
        let bindings = Arc::new(RouteBindings::new());
        let route = RouteFrameContext {
            version: PROTOCOL_VERSION,
            channel: 4,
            epoch: 2,
            correlation: 71,
        };
        bindings
            .insert(
                route.channel,
                route.epoch,
                Principal::Reserved {
                    module_id: "another-module".to_string(),
                },
            )
            .expect("bind reserved principal");
        handle_management_request(
            route,
            manifest::ADMIN_REVIEW_ACTION_OP,
            &json!({"connection_id": "conn-review", "action": "list_issues"}),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("reserved request receives a response");
        let denied = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "reserved response",
        )
        .await;
        let denied: Value = serde_json::from_slice(&denied.body).expect("reserved response JSON");
        assert_eq!(denied["error"]["code"], "operator_authority_required");

        bindings
            .insert(route.channel, route.epoch, Principal::Direct)
            .expect("bind direct principal");
        handle_management_request(
            route,
            manifest::ADMIN_REVIEW_ACTION_OP,
            &json!({"connection_id": "conn-review", "action": "list_issues"}),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("direct request receives a response");
        let allowed = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "direct response",
        )
        .await;
        let allowed: Value = serde_json::from_slice(&allowed.body).expect("direct response JSON");
        assert_eq!(allowed["result"]["current_schema_hash"], "sha256:current");

        let facade = Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            route.channel,
            route.epoch,
            72,
            serde_json::to_vec(&json!({
                "name": manifest::ADMIN_REVIEW_ACTION_OP,
                "arguments": {"connection_id": "conn-review", "action": "list_issues"}
            }))
            .expect("serialize facade request"),
        )
        .expect("build facade request");
        handle_tool_request(facade, &writer, &state, &bindings)
            .await
            .expect("facade refusal response");
        let refused = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "facade response",
        )
        .await;
        let refused: Value = serde_json::from_slice(&refused.body).expect("facade response JSON");
        assert_eq!(refused["error"]["code"], "unknown_method");
    }

    #[tokio::test]
    async fn widen_ceiling_is_management_only_and_requires_a_direct_principal() {
        let (writer, mut responses) = mpsc::channel(4);
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: DEFAULT_MODULE_ID.into(),
                storage_namespace: "widen-ceiling-gate".into(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: ":memory:".into(),
                },
            })
            .unwrap(),
        );
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(store),
        });
        let bindings = Arc::new(RouteBindings::new());
        let route = RouteFrameContext {
            version: PROTOCOL_VERSION,
            channel: 4,
            epoch: 2,
            correlation: 71,
        };
        let params = json!({"connection_id":"ci","actions":["get_job"],"dry_run":false});
        for (principal, expected) in [
            (
                Principal::Reserved {
                    module_id: "basal".into(),
                },
                "operator_authority_required",
            ),
            (Principal::Direct, "connection_not_found"),
        ] {
            bindings
                .insert(route.channel, route.epoch, principal)
                .unwrap();
            confirmed_management_request(
                route,
                manifest::ADMIN_WIDEN_CEILING_OP,
                &params,
                &writer,
                &state,
                &bindings,
            )
            .await
            .unwrap();
            let response = recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "widen ceiling response",
            )
            .await;
            let response: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(response["error"]["code"], expected);
        }
        for params in [
            json!({"connection_id":"ci","actions":["get_job"],"dry_run":"false"}),
            json!({"connection_id":"ci","actions":"get_job"}),
            json!({"connection_id":"ci","actions":[1]}),
            json!({"connection_id":"ci","actions":["get_job"],"risk":"write"}),
        ] {
            assert_eq!(
                ceremony::widen_ceiling(&state, "direct", &params)["error"]["code"],
                "invalid_request"
            );
        }
        let facade = Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            route.channel,
            route.epoch,
            72,
            serde_json::to_vec(
                &json!({"name":manifest::ADMIN_WIDEN_CEILING_OP,"arguments":params}),
            )
            .unwrap(),
        )
        .unwrap();
        handle_tool_request(facade, &writer, &state, &bindings)
            .await
            .unwrap();
        let refused = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "facade refusal",
        )
        .await;
        let refused: Value = serde_json::from_slice(&refused.body).unwrap();
        assert_eq!(refused["error"]["code"], "unknown_method");
    }

    /// `github.handle.grant` is routed on the management surface, refused for
    /// a module principal, and for the operator reaches the grant itself: an
    /// unknown handle comes back as the grant's own named refusal, not as an
    /// unknown method or a decode failure. The parameters are the shape
    /// `ck-plexus-admin handle-grant` sends.
    #[tokio::test]
    async fn handle_grant_is_a_direct_only_management_op_that_reaches_the_grant() {
        let (writer, mut responses) = mpsc::channel(4);
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("handle-grant-gate-{}", plexus_core::now_ms()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("open test store"));
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        });
        let bindings = Arc::new(RouteBindings::new());
        let route = RouteFrameContext {
            version: PROTOCOL_VERSION,
            channel: 5,
            epoch: 2,
            correlation: 81,
        };
        let params = json!({"app_handle_id":"app-unknown","actions":["create_issue"],
            "module":"reserved:aft","effect":"allow","dry_run":false});
        bindings
            .insert(
                route.channel,
                route.epoch,
                Principal::Reserved {
                    module_id: "aft".to_string(),
                },
            )
            .expect("bind reserved principal");
        confirmed_management_request(
            route,
            manifest::GITHUB_GRANT_OP,
            &params,
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("reserved request receives a response");
        let denied = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "reserved response",
        )
        .await;
        let denied: Value = serde_json::from_slice(&denied.body).expect("reserved response JSON");
        assert_eq!(denied["error"]["code"], "operator_authority_required");

        bindings
            .insert(route.channel, route.epoch, Principal::Direct)
            .expect("bind direct principal");
        confirmed_management_request(
            route,
            manifest::GITHUB_GRANT_OP,
            &params,
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("direct request receives a response");
        let reached = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "direct response",
        )
        .await;
        let reached: Value = serde_json::from_slice(&reached.body).expect("direct response JSON");
        assert_eq!(reached["error"]["code"], "agent_handle_unknown");
        assert_eq!(reached["error"]["detail"]["app_handle_id"], "app-unknown");
    }

    #[test]
    fn handle_poll_grant_unknown_handle_has_a_bare_code_and_detail() {
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: "poll-grant-unknown-handle-detail".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).unwrap());
        let state = ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(store),
        };
        let reply = github_handle_grant(
            &state,
            "direct",
            &json!({"kind":"poll","app_handle_id":"app-unknown",
                "actions":["github.issue.get"],"dry_run":false}),
        );
        assert_eq!(reply["error"]["code"], "agent_handle_unknown");
        assert_eq!(reply["error"]["detail"]["app_handle_id"], "app-unknown");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_unbind_is_direct_only_and_needs_no_credentials() {
        let (writer, mut responses) = mpsc::channel(4);
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("handle-unbind-gate-{}", plexus_core::now_ms()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).unwrap());
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(store),
        });
        let bindings = Arc::new(RouteBindings::new());
        let route = RouteFrameContext {
            version: PROTOCOL_VERSION,
            channel: 5,
            epoch: 2,
            correlation: 82,
        };
        let params = json!({"app_handle_id":"unknown", "repository":"org/repo"});
        for (principal, expected) in [
            (
                Principal::Reserved {
                    module_id: "aft".into(),
                },
                "operator_authority_required",
            ),
            (Principal::Direct, "agent_handle_unknown"),
        ] {
            bindings
                .insert(route.channel, route.epoch, principal)
                .unwrap();
            handle_management_request(
                route,
                manifest::GITHUB_UNBIND_OP,
                &params,
                &writer,
                &state,
                &bindings,
            )
            .await
            .unwrap();
            let response = recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "expected reply",
            )
            .await;
            let response: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(response["error"]["code"], expected);
            if expected == "agent_handle_unknown" {
                assert_eq!(response["error"]["detail"]["app_handle_id"], "unknown");
            }
        }
    }

    /// Hands out a token for any handle; the bind below refuses an unknown
    /// handle before it would be used.
    struct AnyHandleToken;
    impl plexus_core::github::credential::HandleCredentialProvider for AnyHandleToken {
        fn prepare(
            &self,
            _: &str,
            _: i64,
            reference: &str,
        ) -> Result<plexus_core::credentials::ResolvedCredential, &'static str> {
            Ok(plexus_core::credentials::ResolvedCredential::new(
                reference.as_bytes().to_vec(),
                None,
                1,
            ))
        }
        fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
    }

    /// `github.handle.bind` is routed on the management surface, refused for a
    /// module principal, and for the operator reaches the bind itself: an
    /// unknown handle comes back as the bind's own named refusal. The
    /// parameters are the shape `ck-plexus-admin handle-bind` sends. Multi
    /// threaded because the bind runs inside `block_in_place`.
    #[tokio::test(flavor = "multi_thread")]
    async fn handle_bind_is_a_direct_only_management_op_that_reaches_the_bind() {
        let (writer, mut responses) = mpsc::channel(4);
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("handle-bind-gate-{}", plexus_core::now_ms()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("open test store"));
        let mut runtime = runtime_for_test(Arc::clone(&store));
        runtime.github_handle_credentials = Some(Arc::new(AnyHandleToken));
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        });
        let bindings = Arc::new(RouteBindings::new());
        let route = RouteFrameContext {
            version: PROTOCOL_VERSION,
            channel: 5,
            epoch: 2,
            correlation: 82,
        };
        let params = json!({"app_handle_id":"app-unknown","repositories":["org/second"],
            "dry_run":false});
        bindings
            .insert(
                route.channel,
                route.epoch,
                Principal::Reserved {
                    module_id: "aft".to_string(),
                },
            )
            .expect("bind reserved principal");
        confirmed_management_request(
            route,
            manifest::GITHUB_BIND_OP,
            &params,
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("reserved request receives a response");
        let denied = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "reserved response",
        )
        .await;
        let denied: Value = serde_json::from_slice(&denied.body).expect("reserved response JSON");
        assert_eq!(denied["error"]["code"], "operator_authority_required");

        bindings
            .insert(route.channel, route.epoch, Principal::Direct)
            .expect("bind direct principal");
        confirmed_management_request(
            route,
            manifest::GITHUB_BIND_OP,
            &params,
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("direct request receives a response");
        let reached = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "direct response",
        )
        .await;
        let reached: Value = serde_json::from_slice(&reached.body).expect("direct response JSON");
        assert_eq!(reached["error"]["code"], "agent_handle_unknown");
        assert_eq!(reached["error"]["detail"]["app_handle_id"], "app-unknown");
    }

    /// Run each GitHub credential operation on a multi-threaded runtime, as the
    /// module does, and require a reply. Operations that read the installation
    /// must construct, use, and drop their blocking HTTP client in a blocking
    /// section, not in an async runtime context. Reqwest can panic there,
    /// especially when dropping the client's internal runtime, and end request
    /// handling without replying to the operator.
    #[tokio::test(flavor = "multi_thread")]
    async fn github_handle_ops_answer_from_an_async_worker() {
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("handle-ops-worker-{}", plexus_core::now_ms()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("open test store"));
        let mut runtime = runtime_for_test(Arc::clone(&store));
        runtime.github_handle_credentials = Some(Arc::new(AnyHandleToken));
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        });
        let bindings = Arc::new(RouteBindings::new());
        let route = RouteFrameContext {
            version: PROTOCOL_VERSION,
            channel: 5,
            epoch: 2,
            correlation: 83,
        };
        bindings
            .insert(route.channel, route.epoch, Principal::Direct)
            .expect("bind direct principal");
        for (method, params) in [
            (
                manifest::GITHUB_IMPORT_OP,
                json!({"inventory":{"version":"1","handles":[]},"dry_run":true}),
            ),
            (
                manifest::GITHUB_PROBE_OP,
                json!({"app_handle_id":"app-unknown"}),
            ),
            (
                manifest::GITHUB_BIND_OP,
                json!({"app_handle_id":"app-unknown","repositories":["org/a"]}),
            ),
        ] {
            let (writer, mut responses) = mpsc::channel(4);
            let served = tokio::spawn({
                let state = Arc::clone(&state);
                let bindings = Arc::clone(&bindings);
                async move {
                    handle_management_request(route, method, &params, &writer, &state, &bindings)
                        .await
                }
            })
            .await;
            assert!(
                matches!(served, Ok(Ok(()))),
                "{method} must be served without a panic: {served:?}"
            );
            let reply = recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "github handle op response",
            )
            .await;
            let reply: Value = serde_json::from_slice(&reply.body).expect("response JSON");
            assert!(
                reply.get("result").is_some() || reply.get("error").is_some(),
                "{method} must answer: {reply}"
            );
        }
    }
}

#[cfg(test)]
mod events_delivery_tests {
    use super::*;
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{BindIdentity, RouteTarget};

    fn consume_authority_store(test_name: &str) -> Arc<PlexusStore> {
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!(
                "events-consume-authority-{test_name}-{}",
                std::process::id()
            ),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));
        let manifest_source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github.jsonc"),
        )
        .expect("read the shipped github manifest");
        let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize manifest");
        let ingested = plexus_core::ingest_value(
            serde_json::from_str::<Value>(&normalized).expect("parse manifest"),
        )
        .expect("ingest manifest");
        store
            .upsert_manifest("system", &ingested)
            .expect("seed manifest");
        store
            .insert_connection(
                "direct",
                "conn-consume-authority",
                &ingested.manifest.key,
                "active",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("seed connection");
        store
    }

    fn insert_consume_grant(store: &PlexusStore, grant_id: &str, expires_at: Option<i64>) {
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: grant_id.to_string(),
                principal: "direct".to_string(),
                connection_id: "conn-consume-authority".to_string(),
                grantee_principal: "reserved:prefrontal-core".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["list_issues".to_string()],
                authority_kind: plexus_core::AUTHORITY_EVENTS_CONSUME.to_string(),
                expires_at,
            })
            .expect("seed consume grant");
    }

    async fn list_as_reserved_consumer(store: Arc<PlexusStore>) -> Value {
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(store),
        });
        let bindings = Arc::new(RouteBindings::new());
        bindings
            .insert(
                4,
                2,
                Principal::Reserved {
                    module_id: "prefrontal-core".to_string(),
                },
            )
            .expect("bind reserved consumer");
        let (writer, mut responses) = mpsc::channel(1);
        handle_tool_request(
            Frame::build(
                FrameType::Request,
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                4,
                2,
                9,
                serde_json::to_vec(&json!({
                    "name": manifest::EVENTS_TOOL,
                    "arguments": {"op": "list"}
                }))
                .expect("serialize tool request"),
            )
            .expect("build tool frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("tool request succeeds");
        serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "events response",
            )
            .await
            .body,
        )
        .expect("events response body")
    }

    #[tokio::test]
    async fn expired_consume_authority_is_visible_on_an_empty_wire_list() {
        let store = consume_authority_store("expired");
        let deadline = plexus_core::now_ms() - 1;
        insert_consume_grant(&store, "grant-consume-expired", Some(deadline));

        let body = list_as_reserved_consumer(store).await;
        assert_eq!(body["result"]["events"], json!([]));
        let grants = body["result"]["events_consume_authority"]["grants"]
            .as_array()
            .unwrap_or_else(|| panic!("consume authority grants missing: {body}"));
        assert_eq!(grants.len(), 1, "expired grant missing: {body}");
        assert_eq!(grants[0]["authority_state"], "expired");
        assert_eq!(grants[0]["authority_expires_at_ms"], deadline);
    }

    #[tokio::test]
    async fn absent_consume_authority_is_visible_on_an_empty_wire_list() {
        let body = list_as_reserved_consumer(consume_authority_store("absent")).await;

        assert_eq!(body["result"]["events"], json!([]));
        assert_eq!(
            body["result"]["events_consume_authority"]["grants"],
            json!([]),
            "the complete caller-authority list must be empty: {body}"
        );
    }

    #[tokio::test]
    async fn live_consume_authority_is_visible_on_a_quiet_wire_list() {
        let store = consume_authority_store("live-empty");
        let deadline = i64::MAX / 2;
        insert_consume_grant(&store, "grant-consume-live-empty", Some(deadline));

        let body = list_as_reserved_consumer(store).await;
        assert_eq!(body["result"]["events"], json!([]));
        let grants = body["result"]["events_consume_authority"]["grants"]
            .as_array()
            .unwrap_or_else(|| panic!("consume authority grants missing: {body}"));
        assert_eq!(grants.len(), 1, "live grant missing: {body}");
        assert_eq!(grants[0]["authority_state"], "live");
        assert_eq!(grants[0]["authority_expires_at_ms"], deadline);
    }

    /// A reserved consumer sees another principal's stored events only through
    /// live consume authority. Check both denied and granted reads on the wire
    /// so neither an always-empty response nor an unscoped read can pass.
    #[tokio::test]
    async fn a_reserved_consumer_sees_granted_events_only_through_the_wire() {
        let (writer, mut responses) = mpsc::channel(8);
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("events-consume-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));

        let manifest_source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github.jsonc"),
        )
        .expect("read the shipped github manifest");
        let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize manifest");
        let ingested = plexus_core::ingest_value(
            serde_json::from_str::<Value>(&normalized).expect("parse manifest"),
        )
        .expect("ingest manifest");
        store
            .upsert_manifest("system", &ingested)
            .expect("seed manifest");
        store
            .insert_connection(
                "direct",
                "conn-consume",
                &ingested.manifest.key,
                "active",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("seed connection");
        store
            .upsert_catalog_action(&plexus_core::CatalogActionInput {
                connection_id: "conn-consume".to_string(),
                principal: "direct".to_string(),
                name: "list_issues".to_string(),
                title: None,
                schema: json!({
                    "type": "object",
                    "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}}
                }),
                schema_hash: "sha256:events-consume".to_string(),
                risk: "read".to_string(),
                severity: "S1".to_string(),
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
                ask_first: false,
            })
            .expect("seed catalog action");
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "grant-consume-poll".to_string(),
                principal: "direct".to_string(),
                connection_id: "conn-consume".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["list_issues".to_string()],
                authority_kind: "poll".to_string(),
                expires_at: Some(i64::MAX / 2),
            })
            .expect("seed poll grant");
        let subscription = store
            .subscribe_with_cursor_state(
                "direct",
                "conn-consume",
                "list_issues",
                30,
                &json!({}),
                &json!({"owner": "cortexkit", "repo": "plexus"}),
            )
            .expect("subscribe")
            .expect("subscribable");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis() as i64;
        let outcome = store
            .insert_event(
                "direct",
                "conn-consume",
                &subscription.subscription_id,
                "vendor-consume-1",
                &json!({"title": "owned by direct"}),
                now,
            )
            .expect("seed event");
        assert!(
            matches!(
                outcome,
                plexus_core::TriggerEventInsertOutcome::Inserted { .. }
            ),
            "the seed stored no event: {outcome:?}"
        );
        assert!(store
            .set_subscription_deliver_to(
                "direct",
                &subscription.subscription_id,
                Some("agent-route")
            )
            .expect("seed delivery target"));

        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        });
        let bindings = Arc::new(RouteBindings::new());
        // Bound as RESERVED, not Direct. That is the whole point: this principal
        // owns nothing, so every row it sees must arrive by grant.
        handle_control_request(
            Frame::build(
                FrameType::Request,
                wire::control_flags(),
                0,
                0,
                7,
                serde_json::to_vec(&ModuleControlRequest::RouteBind {
                    scope: None,
                    call_mode: None,
                    role_versions: None,
                    route_channel: 4,
                    epoch: 2,
                    target: RouteTarget::ToolProvider {
                        module_id: DEFAULT_MODULE_ID.to_string(),
                    },
                    identity: BindIdentity::new(
                        "/tmp/project",
                        "test".to_string(),
                        "consumer".to_string(),
                    ),
                    // The REAL consumer identity rather than an invented one.
                    // Reserved principals must be first-party to bind at all, so
                    // an invented module id is refused at the bind and every
                    // later assertion then fails for the wrong reason.
                    principal: Some(Principal::Reserved {
                        module_id: "prefrontal-core".to_string(),
                    }),
                    consumer_capabilities: None,
                    admission_facts: None,
                })
                .expect("serialize bind"),
            )
            .expect("build bind frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("bind succeeds");
        // The bind ACK is asserted rather than discarded. A refused bind makes
        // every later tool call answer `route_not_bound`, and an unchecked ack
        // turns that into a confusing assertion failure about events instead of
        // naming the real cause.
        let bind_ack = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "bind response",
        )
        .await;
        assert_bind_ack(&bind_ack);

        let list = |writer: mpsc::Sender<Frame>,
                    state: Arc<ModuleState>,
                    bindings: Arc<RouteBindings>| async move {
            handle_tool_request(
                Frame::build(
                    FrameType::Request,
                    subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                    4,
                    2,
                    9,
                    serde_json::to_vec(&json!({
                        "name": manifest::EVENTS_TOOL,
                        "arguments": {"op": "list"}
                    }))
                    .expect("serialize tool request"),
                )
                .expect("build tool frame"),
                &writer,
                &state,
                &bindings,
            )
            .await
            .expect("tool request succeeds");
        };

        // ARM 1: no grant yet.
        list(writer.clone(), Arc::clone(&state), Arc::clone(&bindings)).await;
        let body: Value = serde_json::from_slice(
            &recv_within(responses.recv(), std::time::Duration::from_secs(5), "resp")
                .await
                .body,
        )
        .expect("body");
        assert_eq!(
            body["result"]["events"].as_array().map(Vec::len),
            Some(0),
            "an ungranted reserved consumer must see nothing: {body}"
        );

        // ARM 2: the operator names this consumer.
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "grant-consume-events".to_string(),
                principal: "direct".to_string(),
                connection_id: "conn-consume".to_string(),
                grantee_principal: "reserved:prefrontal-core".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["list_issues".to_string()],
                authority_kind: plexus_core::AUTHORITY_EVENTS_CONSUME.to_string(),
                expires_at: Some(i64::MAX / 2),
            })
            .expect("mint consume grant");

        list(writer.clone(), Arc::clone(&state), Arc::clone(&bindings)).await;
        let body: Value = serde_json::from_slice(
            &recv_within(responses.recv(), std::time::Duration::from_secs(5), "resp")
                .await
                .body,
        )
        .expect("body");
        let events = body["result"]["events"]
            .as_array()
            .unwrap_or_else(|| panic!("events array missing: {body}"));
        assert_eq!(
            events.len(),
            1,
            "the granted consumer saw no events through the wire: {body}"
        );
        // Asserted on identity and payload, not the count: a handler returning a
        // placeholder row would satisfy a length check.
        assert_eq!(events[0]["vendor_event_id"], "vendor-consume-1");
        assert_eq!(events[0]["payload"], json!({"title": "owned by direct"}));
        let consume_grants = body["result"]["events_consume_authority"]["grants"]
            .as_array()
            .unwrap_or_else(|| panic!("consume authority grants missing: {body}"));
        assert_eq!(consume_grants.len(), 1, "live grant missing: {body}");
        assert_eq!(consume_grants[0]["authority_state"], "live");
        assert_eq!(consume_grants[0]["authority_expires_at_ms"], i64::MAX / 2);

        // SUBSCRIPTIONS MUST BE WIDENED TOO, and this assertion exists because
        // without it a grantee can see every event and ZERO subscriptions. An
        // event names its subscription and nothing else -- which repository it
        // came from lives in the
        // subscription`s `fixed_args` -- so events without subscriptions are
        // payloads the consumer cannot attribute, and the failure looks like an
        // empty lane rather than a partial one.
        let subscriptions = body["result"]["subscriptions"]
            .as_array()
            .unwrap_or_else(|| panic!("subscriptions array missing: {body}"));
        assert_eq!(
            subscriptions.len(),
            1,
            "the granted consumer must receive the subscription behind its events: {body}"
        );
        // Mutation proved: removing `deliver_to` from the subscription projection
        // leaves events readable but makes the grantee unable to apply the first
        // delivery-routing rung.
        assert_eq!(
            subscriptions[0]["fixed_args"]["repo"], "plexus",
            "the subscription must carry the container it watches: {body}"
        );
        assert_eq!(
            subscriptions[0]["deliver_to"], "agent-route",
            "the grantee list must carry explicit delivery routing: {body}"
        );
    }

    #[tokio::test]
    async fn a_consumer_ack_respects_the_same_action_selectors_as_its_read() {
        let (writer, mut responses) = mpsc::channel(2);
        let store = consume_authority_store("ack-action-selectors");
        for (action, hash) in [
            ("list_issues", "sha256:ack-list-issues"),
            ("get_latest_release", "sha256:ack-latest-release"),
        ] {
            store
                .upsert_catalog_action(&plexus_core::CatalogActionInput {
                    connection_id: "conn-consume-authority".to_string(),
                    principal: "direct".to_string(),
                    name: action.to_string(),
                    title: None,
                    schema: json!({"type": "object", "properties": {}}),
                    schema_hash: hash.to_string(),
                    risk: "read".to_string(),
                    severity: "S1".to_string(),
                    status: "active".to_string(),
                    quarantine_reason: None,
                    reconciliation: None,
                    ask_first: false,
                })
                .expect("seed catalog action");
        }
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "grant-ack-poll".to_string(),
                principal: "direct".to_string(),
                connection_id: "conn-consume-authority".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["list_issues".to_string(), "get_latest_release".to_string()],
                authority_kind: "poll".to_string(),
                expires_at: Some(i64::MAX / 2),
            })
            .expect("seed poll grant");
        let allowed_subscription = store
            .subscribe("direct", "conn-consume-authority", "list_issues", 30)
            .expect("subscribe to allowed action")
            .expect("allowed action is subscribable");
        let excluded_subscription = store
            .subscribe("direct", "conn-consume-authority", "get_latest_release", 30)
            .expect("subscribe to excluded action")
            .expect("excluded action is subscribable");
        let allowed_payload = json!({"title": "visible to consumer"});
        let excluded_payload = json!({"tag_name": "v2.0.0"});
        let allowed_event_id = match store
            .insert_event(
                "direct",
                "conn-consume-authority",
                &allowed_subscription.subscription_id,
                "vendor-allowed",
                &allowed_payload,
                100,
            )
            .expect("insert allowed event")
        {
            plexus_core::TriggerEventInsertOutcome::Inserted { event_id } => event_id,
            other => panic!("expected allowed insertion, got {other:?}"),
        };
        let excluded_event_id = match store
            .insert_event(
                "direct",
                "conn-consume-authority",
                &excluded_subscription.subscription_id,
                "vendor-excluded",
                &excluded_payload,
                101,
            )
            .expect("insert excluded event")
        {
            plexus_core::TriggerEventInsertOutcome::Inserted { event_id } => event_id,
            other => panic!("expected excluded insertion, got {other:?}"),
        };
        insert_consume_grant(&store, "grant-ack-consume", Some(i64::MAX / 2));

        let now = plexus_core::now_ms();
        let visible = store
            .list_events_including_granted(
                "reserved:prefrontal-core",
                Some("conn-consume-authority"),
                None,
                now,
            )
            .expect("list granted events");
        assert_eq!(
            visible
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            vec![allowed_event_id.as_str()],
            "the consume grant must expose only its selected action"
        );

        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        });
        let bindings = Arc::new(RouteBindings::new());
        bindings
            .insert(
                4,
                2,
                Principal::Reserved {
                    module_id: "prefrontal-core".to_string(),
                },
            )
            .expect("bind reserved consumer");
        handle_tool_request(
            Frame::build(
                FrameType::Request,
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                4,
                2,
                10,
                serde_json::to_vec(&json!({
                    "name": manifest::EVENTS_TOOL,
                    "arguments": {
                        "op": "ack",
                        "event_ids": [allowed_event_id, excluded_event_id]
                    }
                }))
                .expect("serialize ack request"),
            )
            .expect("build ack frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("ack request succeeds");

        let response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "ack response",
        )
        .await;
        let body: Value = serde_json::from_slice(&response.body).expect("ack response body");
        assert_eq!(
            body["result"]["acked"], 1,
            "only the event selected by the grant may be acknowledged: {body}"
        );
        assert_eq!(
            body["result"]["unacked"],
            json!([excluded_event_id]),
            "only the excluded event may remain unacked: {body}"
        );

        assert!(
            store
                .list_events(
                    "direct",
                    Some("conn-consume-authority"),
                    Some(&allowed_subscription.subscription_id),
                )
                .expect("read allowed lane after ack")
                .is_empty(),
            "the selected event must be acknowledged"
        );
        let excluded_rows = store
            .list_events(
                "direct",
                Some("conn-consume-authority"),
                Some(&excluded_subscription.subscription_id),
            )
            .expect("read excluded lane after ack");
        assert_eq!(
            excluded_rows.len(),
            1,
            "the excluded event must remain unacked"
        );
        assert_eq!(excluded_rows[0].event_id, excluded_event_id);
        assert_eq!(
            excluded_rows[0].payload, excluded_payload,
            "a refused ack must leave the excluded event payload intact"
        );
        assert_eq!(
            excluded_rows[0].acked_at_ms, None,
            "the excluded event row must remain unacked"
        );
    }

    #[tokio::test]
    /// A stored event must survive the facade's list and ack delivery path.
    async fn a_stored_event_is_delivered_through_the_tool_surface() {
        let (writer, mut responses) = mpsc::channel(8);
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("events-delivery-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));

        // Built through the store's ordinary API, because each row is a real
        // precondition of the next: `insert_event` refuses an orphan, and
        // `subscribe` refuses without a poll grant and a manifest-declared poll
        // shape. Assembling the chain proves those compose, and adds no
        // production surface that exists only for tests.
        let manifest_source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github.jsonc"),
        )
        .expect("read the shipped github manifest");
        let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize manifest");
        let ingested = plexus_core::ingest_value(
            serde_json::from_str::<Value>(&normalized).expect("parse manifest"),
        )
        .expect("ingest manifest");
        store
            .upsert_manifest("system", &ingested)
            .expect("seed manifest");
        store
            .insert_connection(
                "direct",
                "conn-events",
                &ingested.manifest.key,
                "active",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("seed connection");
        store
            .upsert_catalog_action(&plexus_core::CatalogActionInput {
                connection_id: "conn-events".to_string(),
                principal: "direct".to_string(),
                name: "list_issues".to_string(),
                title: None,
                schema: json!({
                    "type": "object",
                    "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}}
                }),
                schema_hash: "sha256:events-delivery".to_string(),
                risk: "read".to_string(),
                severity: "S1".to_string(),
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
                ask_first: false,
            })
            .expect("seed catalog action");
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "grant-events-delivery".to_string(),
                principal: "direct".to_string(),
                connection_id: "conn-events".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["list_issues".to_string()],
                authority_kind: "poll".to_string(),
                expires_at: Some(i64::MAX / 2),
            })
            .expect("seed poll grant");
        let subscription = store
            .subscribe_with_cursor_state(
                "direct",
                "conn-events",
                "list_issues",
                30,
                &json!({}),
                &json!({"owner": "rust-lang", "repo": "rust"}),
            )
            .expect("subscribe")
            .expect("the shipped manifest must be subscribable");

        // The OUTCOME is asserted, not just the Result: `insert_event` returns
        // Ok for a duplicate and for a payload conflict too, so a seed that
        // stored nothing would look successful and the test would then fail
        // with an empty list that reads as a broken delivery path.
        //
        // Observation time describes the source event. Retention uses its
        // insertion timestamp, and listing itself does not prune events.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis() as i64;
        let outcome = store
            .insert_event(
                "direct",
                "conn-events",
                &subscription.subscription_id,
                "vendor-evt-1",
                &json!({"title": "a real payload"}),
                now,
            )
            .expect("seed event");
        assert!(
            matches!(
                outcome,
                plexus_core::TriggerEventInsertOutcome::Inserted { .. }
            ),
            "the seed stored no event: {outcome:?}"
        );

        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        });
        let bindings = Arc::new(RouteBindings::new());
        // Bind the route first: the tool handler resolves its principal from
        // this table, and an unbound channel is refused before any store read.
        handle_control_request(
            Frame::build(
                FrameType::Request,
                wire::control_flags(),
                0,
                0,
                7,
                serde_json::to_vec(&ModuleControlRequest::RouteBind {
                    scope: None,
                    call_mode: None,
                    role_versions: None,
                    route_channel: 4,
                    epoch: 2,
                    target: RouteTarget::ToolProvider {
                        module_id: DEFAULT_MODULE_ID.to_string(),
                    },
                    identity: BindIdentity::new(
                        "/tmp/project",
                        "test".to_string(),
                        "session".to_string(),
                    ),
                    principal: Some(Principal::Direct),
                    consumer_capabilities: None,
                    admission_facts: None,
                })
                .expect("serialize bind"),
            )
            .expect("build bind frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("bind succeeds");
        let _bind_ack = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "bind response",
        )
        .await;
        assert_bind_ack(&_bind_ack);

        handle_tool_request(
            Frame::build(
                FrameType::Request,
                // A tool frame carries ordinary interactive flags, unlike the
                // control frame above which sets the control bit.
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                4,
                2,
                9,
                serde_json::to_vec(&json!({
                    "name": manifest::EVENTS_TOOL,
                    "arguments": {"op": "list"}
                }))
                .expect("serialize tool request"),
            )
            .expect("build tool frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("tool request succeeds");

        let response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "events response",
        )
        .await;
        let body: Value = serde_json::from_slice(&response.body).expect("events response body");
        let events = body["result"]["events"]
            .as_array()
            .unwrap_or_else(|| panic!("events array missing from response: {body}"));

        assert_eq!(
            events.len(),
            1,
            "the stored event was not delivered to the caller: {body}"
        );
        // Asserted on the vendor id, not the count alone: a handler returning
        // some other row or a placeholder would satisfy a length check while
        // delivering the wrong thing.
        assert_eq!(
            events[0]["vendor_event_id"], "vendor-evt-1",
            "a different event was delivered: {body}"
        );
        assert_eq!(
            events[0]["payload"],
            json!({"title": "a real payload"}),
            "the payload did not survive delivery: {body}"
        );

        // ACK, and prove the event stops being delivered.
        //
        // Delivery and acknowledgement are one loop: a feed that delivers but
        // never forgets is as broken as one that never delivers, and it fails
        // in the noisier direction — the same event is returned on every poll
        // forever, so a caller processing its feed acts on it repeatedly.
        //
        // Measured before this existed: acking an EMPTY slice instead of the
        // requested ids (the store is never told anything) left the whole
        // module suite green.
        //
        // The count is asserted as well as the disappearance, because they
        // fail differently: a handler reporting 0 while acking correctly is a
        // caller-visible lie about what happened, and one reporting the
        // requested count while acking nothing is the silent redelivery loop.
        let event_id = events[0]["event_id"]
            .as_str()
            .expect("delivered event carries an id")
            .to_string();

        handle_tool_request(
            Frame::build(
                FrameType::Request,
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                4,
                2,
                10,
                serde_json::to_vec(&json!({
                    "name": manifest::EVENTS_TOOL,
                    "arguments": {"op": "ack", "event_ids": [event_id]}
                }))
                .expect("serialize ack request"),
            )
            .expect("build ack frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("ack request succeeds");

        let ack_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "ack response",
        )
        .await;
        let ack_body: Value =
            serde_json::from_slice(&ack_response.body).expect("ack response body");
        assert_eq!(
            ack_body["result"]["acked"], 1,
            "ack must report the event it acknowledged: {ack_body}"
        );
        assert_eq!(
            ack_body["result"]["unacked"],
            json!([]),
            "a fully successful ack must report nothing outstanding: {ack_body}"
        );

        // An id that acks nothing must be NAMED, not merely absent from a count.
        // A consumer acks what it has already delivered, so an id that lands on
        // no row means the two sides disagree about what exists -- and with only
        // a count, noticing requires the caller to compare against its own
        // request length. Missing it means the event redelivers forever while
        // both sides report healthy, which is why the ack path is the one where
        // a swallowed refusal costs the most.
        handle_tool_request(
            Frame::build(
                FrameType::Request,
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                4,
                2,
                12,
                serde_json::to_vec(&json!({
                    "name": manifest::EVENTS_TOOL,
                    "arguments": {"op": "ack", "event_ids": ["event_does_not_exist"]}
                }))
                .expect("serialize unknown ack request"),
            )
            .expect("build unknown ack frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("unknown ack request succeeds");
        let unknown_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "unknown ack response",
        )
        .await;
        let unknown_body: Value =
            serde_json::from_slice(&unknown_response.body).expect("unknown ack body");
        assert_eq!(
            unknown_body["result"]["acked"], 0,
            "an unknown id must ack nothing: {unknown_body}"
        );
        assert_eq!(
            unknown_body["result"]["unacked"],
            json!(["event_does_not_exist"]),
            "an id that acked nothing must be named so the caller can act on it: \
             {unknown_body}"
        );

        // Re-acking an ALREADY-acked id reports zero acked and nothing
        // outstanding: it landed on no row, but the caller's goal for it is
        // satisfied and it will not redeliver. Reporting it as outstanding would
        // name a problem with no remedy, and a consumer retrying after an
        // ambiguous reply does exactly this.
        handle_tool_request(
            Frame::build(
                FrameType::Request,
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                4,
                2,
                13,
                serde_json::to_vec(&json!({
                    "name": manifest::EVENTS_TOOL,
                    "arguments": {"op": "ack", "event_ids": [event_id]}
                }))
                .expect("serialize repeat ack request"),
            )
            .expect("build repeat ack frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("repeat ack request succeeds");
        let repeat_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "repeat ack response",
        )
        .await;
        let repeat_body: Value =
            serde_json::from_slice(&repeat_response.body).expect("repeat ack body");
        assert_eq!(repeat_body["result"]["acked"], 0, "re-ack must be a no-op");
        assert_eq!(
            repeat_body["result"]["unacked"],
            json!([]),
            "re-acking an already-acked event must not report it outstanding: \
             {repeat_body}"
        );

        handle_tool_request(
            Frame::build(
                FrameType::Request,
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                4,
                2,
                11,
                serde_json::to_vec(&json!({
                    "name": manifest::EVENTS_TOOL,
                    "arguments": {"op": "list"}
                }))
                .expect("serialize second list"),
            )
            .expect("build second list frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("second list succeeds");

        let after = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "second list response",
        )
        .await;
        let after_body: Value = serde_json::from_slice(&after.body).expect("second list body");
        assert_eq!(
            after_body["result"]["events"],
            json!([]),
            "an acked event must not be delivered again: {after_body}"
        );
    }
}

#[cfg(test)]
mod subscription_lifecycle_tests {
    use super::*;
    use plexus_core::{AgentLookup, StubAgentRegistry};
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{BindIdentity, RouteTarget};

    /// Subscribe, resume, and unsubscribe take effect THROUGH the tool surface.
    ///
    /// A store call can be neutered at the handler and nothing notices when every
    /// behaviour test calls the store directly. Measured before this existed — passing an empty
    /// object where `fixed_args` belongs, and unsubscribing an id the caller
    /// never named, both left the whole module suite green.
    ///
    /// The subscribe half is the one that matters. `fixed_args` carries WHICH
    /// container a subscription watches, and the poller builds its request from
    /// the cursor strategy, the manifest's constants and that object alone. So
    /// a handler that drops it creates a subscription the vendor rejects on
    /// every poll — accepted at the surface, dead in operation, and reported as
    /// a vendor failure rather than as the misconfiguration it is.
    ///
    /// The unsubscribe half fails the other way: a subscription that survives
    /// its own removal keeps polling a vendor the operator believes they
    /// stopped watching, which is authority outliving the decision to withdraw
    /// it.
    ///
    /// Asserted on STORE STATE rather than on the response, in both halves. A
    /// handler can report success while doing nothing, and that is exactly the
    /// mutation this has to catch.
    #[tokio::test]
    async fn subscribe_resume_and_unsubscribe_take_effect_through_the_tool_surface() {
        let (writer, mut responses) = mpsc::channel(8);
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("sub-lifecycle-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));

        let manifest_source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github.jsonc"),
        )
        .expect("read the shipped github manifest");
        let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize manifest");
        let ingested = plexus_core::ingest_value(
            serde_json::from_str::<Value>(&normalized).expect("parse manifest"),
        )
        .expect("ingest manifest");
        store
            .upsert_manifest("system", &ingested)
            .expect("seed manifest");
        store
            .insert_connection(
                "direct",
                "conn-lifecycle",
                &ingested.manifest.key,
                "active",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("seed connection");
        store
            .upsert_catalog_action(&plexus_core::CatalogActionInput {
                connection_id: "conn-lifecycle".to_string(),
                principal: "direct".to_string(),
                name: "list_issues".to_string(),
                title: None,
                schema: json!({
                    "type": "object",
                    "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}}
                }),
                schema_hash: "sha256:sub-lifecycle".to_string(),
                risk: "read".to_string(),
                severity: "S1".to_string(),
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
                ask_first: false,
            })
            .expect("seed catalog action");
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "grant-sub-lifecycle".to_string(),
                principal: "direct".to_string(),
                connection_id: "conn-lifecycle".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["list_issues".to_string()],
                authority_kind: "poll".to_string(),
                expires_at: Some(i64::MAX / 2),
            })
            .expect("seed poll grant");

        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        });
        let bindings = Arc::new(RouteBindings::new());
        handle_control_request(
            Frame::build(
                FrameType::Request,
                wire::control_flags(),
                0,
                0,
                7,
                serde_json::to_vec(&ModuleControlRequest::RouteBind {
                    scope: None,
                    call_mode: None,
                    role_versions: None,
                    route_channel: 4,
                    epoch: 2,
                    target: RouteTarget::ToolProvider {
                        module_id: DEFAULT_MODULE_ID.to_string(),
                    },
                    identity: BindIdentity::new(
                        "/tmp/project",
                        "test".to_string(),
                        "session".to_string(),
                    ),
                    principal: Some(Principal::Direct),
                    consumer_capabilities: None,
                    admission_facts: None,
                })
                .expect("serialize bind"),
            )
            .expect("build bind frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("bind succeeds");
        let _bind_ack = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "bind response",
        )
        .await;
        assert_bind_ack(&_bind_ack);

        let tool_frame = |correlation: u64, arguments: Value| {
            Frame::build(
                FrameType::Request,
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                4,
                2,
                correlation,
                serde_json::to_vec(&json!({
                    "name": manifest::EVENTS_TOOL,
                    "arguments": arguments
                }))
                .expect("serialize tool request"),
            )
            .expect("build tool frame")
        };

        handle_tool_request(
            tool_frame(
                20,
                json!({
                    "op": "subscribe",
                    "connection": "conn-lifecycle",
                    "action": "list_issues",
                    "cadence_s": 30,
                    "fixed_args": {"owner": "rust-lang", "repo": "rust"}
                }),
            ),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("subscribe request succeeds");
        let subscribe_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "subscribe response",
        )
        .await;
        let subscribe_body: Value =
            serde_json::from_slice(&subscribe_response.body).expect("subscribe body");
        assert!(
            subscribe_body["error"].is_null(),
            "subscribe failed: {subscribe_body}"
        );

        let stored = store
            .list_subscriptions("direct", None, None)
            .expect("read subscriptions");
        assert_eq!(stored.len(), 1, "subscribe stored no subscription");
        assert_eq!(
            stored[0].fixed_args,
            json!({"owner": "rust-lang", "repo": "rust"}),
            "the caller's container scope did not reach the store"
        );
        let subscription_id = stored[0].subscription_id.clone();

        // A handler that reports a successful resume without calling the store
        // leaves the subscription suspended. Assert the durable state and the
        // scheduler input after the tool call, not its self-authored reply.
        //
        // Mutation proved: replacing the handler's store call with a success
        // response leaves `status` suspended and fails the assertions below.
        let cursor_before_resume = json!({"watermark_ms": 1_700_000_000_000i64});
        assert!(store
            .record_poll_success("direct", &subscription_id, &cursor_before_resume, 1,)
            .expect("seed cursor"));
        assert!(store
            .record_vendor_failure("direct", &subscription_id)
            .expect("seed vendor failure"));
        assert!(store
            .suspend(
                "direct",
                &subscription_id,
                plexus_core::CIRCUIT_BREAKER_SUSPENSION_REASON,
            )
            .expect("trip circuit breaker"));
        assert!(
            !store
                .due_subscriptions("direct", plexus_core::now_ms())
                .expect("due subscriptions before resume")
                .iter()
                .any(|candidate| candidate.subscription_id == subscription_id),
            "suspension must keep the watch out of scheduling before resume"
        );

        handle_tool_request(
            tool_frame(
                21,
                json!({"op": "resume", "subscription_id": subscription_id}),
            ),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("resume request succeeds");
        let _resume_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "resume response",
        )
        .await;
        let resume_body: Value =
            serde_json::from_slice(&_resume_response.body).expect("resume body");
        assert!(
            resume_body["error"].is_null(),
            "resume must answer success: {resume_body}"
        );
        let resumed = store
            .subscription("direct", &subscription_id)
            .expect("read resumed subscription")
            .expect("subscription exists");
        assert_eq!(
            resumed.status, "active",
            "the handler did not resume the watch"
        );
        assert_eq!(resumed.suspended_reason, None);
        assert_eq!(resumed.consecutive_vendor_failures, 0);
        assert_eq!(
            resumed.cursor_state, cursor_before_resume,
            "resume through the facade must preserve the durable cursor"
        );
        assert!(
            store
                .due_subscriptions("direct", plexus_core::now_ms())
                .expect("due subscriptions after resume")
                .iter()
                .any(|candidate| candidate.subscription_id == subscription_id),
            "resume through the facade must return the watch to scheduling"
        );

        // The authority deadline must reach the WIRE, not merely the store. A
        // consumer warning that a watch is about to lapse reads this field off
        // the facade response, and the store method being correct says nothing
        // about whether the handler serializes it -- the whole point of a
        // subscription is that it dies silently when its poll grant expires, so
        // a field that stops at the store boundary leaves the consumer exactly
        // as blind as before.
        handle_tool_request(
            tool_frame(22, json!({"op": "list"})),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("list request succeeds");
        let list_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "list response",
        )
        .await;
        let list_body: Value = serde_json::from_slice(&list_response.body).expect("list body");
        let listed = &list_body["result"]["subscriptions"][0];
        assert_eq!(
            listed["authority_state"], "live",
            "the wire must report whether the authority behind a watch still holds: {list_body}"
        );
        assert!(
            listed["authority_expires_at_ms"]
                .as_i64()
                .is_some_and(|at| at > plexus_core::now_ms()),
            "the wire must carry the deadline itself, or a consumer cannot warn \
             before it passes: {list_body}"
        );

        // A SEEDED cursor state must reach the store, because seeding IS how a
        // threshold watch is expressed. A scalar-diff subscription that starts
        // empty baselines silently on its first poll; one seeded with a value
        // the subscriber has already seen reports immediately if the vendor has
        // moved past it. Those are the same mechanism with different starting
        // states, which is why no threshold field exists -- and it means a
        // handler that dropped the seed would silently convert every threshold
        // watch into a plain change watch, losing exactly one event: the one the
        // subscriber asked for.
        //
        // Asserted on the wire because the store honours the seed and the
        // strategy honours it, while nothing proved the handler PASSES it. The
        // whole workspace stayed green with the seed discarded.
        handle_tool_request(
            tool_frame(
                23,
                json!({
                    "op": "subscribe",
                    "connection": "conn-lifecycle",
                    "action": "list_issues",
                    "cadence_s": 30,
                    "fixed_args": {"owner": "cortexkit", "repo": "plexus"},
                    // The correct key for list_issues, whose cursor kind is
                    // ordered-timestamp: its resume point is `watermark_ms`. A
                    // scalar key is refused here because that strategy never
                    // reads one, so seeding with it would leave the watch
                    // behaving as though it had no starting state at all.
                    "cursor_state": {"watermark_ms": 1_700_000_000_000i64}
                }),
            ),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("seeded subscribe request succeeds");
        let seeded_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "seeded subscribe response",
        )
        .await;
        let seeded_body: Value =
            serde_json::from_slice(&seeded_response.body).expect("seeded subscribe body");
        assert!(
            seeded_body["error"].is_null(),
            "seeded subscribe failed: {seeded_body}"
        );
        assert_eq!(
            seeded_body["result"]["subscription"]["cursor_state"],
            json!({"watermark_ms": 1_700_000_000_000i64}),
            "the caller's seed must survive the handler: dropping it turns every \
             threshold watch into a plain change watch"
        );
        let seeded_id = seeded_body["result"]["subscription"]["subscription_id"]
            .as_str()
            .expect("seeded subscription id")
            .to_string();
        let stored_seed = store
            .list_subscriptions("direct", None, Some(&seeded_id))
            .expect("read seeded subscription");
        assert_eq!(
            stored_seed[0].cursor_state,
            json!({"watermark_ms": 1_700_000_000_000i64}),
            "the seed must be durable, not merely echoed back in the response"
        );

        handle_tool_request(
            tool_frame(
                24,
                json!({"op": "unsubscribe", "subscription_id": subscription_id}),
            ),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("unsubscribe request succeeds");
        let unsubscribe_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "unsubscribe response",
        )
        .await;
        assert_eq!(
            unsubscribe_response.header.corr, 24,
            "unsubscribe must echo its unique correlation"
        );
        let unsubscribe_body: Value =
            serde_json::from_slice(&unsubscribe_response.body).expect("unsubscribe body");
        assert_eq!(
            unsubscribe_body["result"]["unsubscribed"],
            json!(true),
            "unsubscribe did not report success: {unsubscribe_body}"
        );

        assert!(
            store
                .list_subscriptions("direct", None, Some(&subscription_id))
                .expect("read subscriptions after unsubscribe")
                .is_empty(),
            "the subscription survived its own removal"
        );
        // Scoped to the removed id rather than asserting an empty store, because
        // the seeded subscription above is still live -- and an unsubscribe that
        // removed BYSTANDERS would pass an emptiness check while destroying
        // watches the caller never named.
        assert_eq!(
            store
                .list_subscriptions("direct", None, Some(&seeded_id))
                .expect("read the bystander subscription")
                .len(),
            1,
            "unsubscribing one watch must not remove another"
        );
    }

    /// Subscription project, delivery-target, and actor-source bindings persist
    /// THROUGH the tool surface, and each clearing path works.
    ///
    /// This call-site test verifies that the handler reaches the store methods
    /// and that each binding and clearing path works through the tool surface.
    /// Store-level tests cannot detect a handler that never invokes a correct
    /// store method.
    ///
    /// Asserted against the STORE after each call rather than against the
    /// response body alone. A handler that echoed its own argument back would
    /// satisfy a response check while writing nothing -- the echo is the caller's
    /// input, not evidence about persistence.
    #[tokio::test]
    async fn subscription_bindings_persist_through_the_tool_surface() {
        let (writer, mut responses) = mpsc::channel(8);
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("set-project-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));

        let manifest_source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github.jsonc"),
        )
        .expect("read the shipped github manifest");
        let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize manifest");
        let ingested = plexus_core::ingest_value(
            serde_json::from_str::<Value>(&normalized).expect("parse manifest"),
        )
        .expect("ingest manifest");
        store
            .upsert_manifest("system", &ingested)
            .expect("seed manifest");
        store
            .insert_connection(
                "direct",
                "conn-project",
                &ingested.manifest.key,
                "active",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("seed connection");
        store
            .upsert_catalog_action(&plexus_core::CatalogActionInput {
                connection_id: "conn-project".to_string(),
                principal: "direct".to_string(),
                name: "list_issues".to_string(),
                title: None,
                schema: json!({
                    "type": "object",
                    "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}}
                }),
                schema_hash: "sha256:set-project".to_string(),
                risk: "read".to_string(),
                severity: "S1".to_string(),
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
                ask_first: false,
            })
            .expect("seed catalog action");
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "grant-set-project".to_string(),
                principal: "direct".to_string(),
                connection_id: "conn-project".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["list_issues".to_string()],
                authority_kind: "poll".to_string(),
                expires_at: Some(i64::MAX / 2),
            })
            .expect("seed poll grant");
        let subscription = store
            .subscribe_with_cursor_state(
                "direct",
                "conn-project",
                "list_issues",
                30,
                &json!({}),
                &json!({"owner": "cortexkit", "repo": "plexus"}),
            )
            .expect("subscribe")
            .expect("subscribable");

        let registry = Arc::new(StubAgentRegistry::with_default_response(AgentLookup::Known));
        let mut runtime = runtime_for_test(Arc::clone(&store));
        runtime.agent_registry = registry.clone();
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        });
        let bindings = Arc::new(RouteBindings::new());
        handle_control_request(
            Frame::build(
                FrameType::Request,
                wire::control_flags(),
                0,
                0,
                7,
                serde_json::to_vec(&ModuleControlRequest::RouteBind {
                    scope: None,
                    call_mode: None,
                    role_versions: None,
                    route_channel: 4,
                    epoch: 2,
                    target: RouteTarget::ToolProvider {
                        module_id: DEFAULT_MODULE_ID.to_string(),
                    },
                    identity: BindIdentity::new(
                        "/tmp/project",
                        "test".to_string(),
                        "session".to_string(),
                    ),
                    principal: Some(Principal::Direct),
                    consumer_capabilities: None,
                    admission_facts: None,
                })
                .expect("serialize bind"),
            )
            .expect("build bind frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("bind succeeds");
        let bind_ack = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "bind response",
        )
        .await;
        assert_bind_ack(&bind_ack);

        let call = |args: Value,
                    writer: mpsc::Sender<Frame>,
                    state: Arc<ModuleState>,
                    bindings: Arc<RouteBindings>| async move {
            handle_tool_request(
                Frame::build(
                    FrameType::Request,
                    subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                    4,
                    2,
                    9,
                    serde_json::to_vec(&json!({
                        "name": manifest::EVENTS_TOOL,
                        "arguments": args
                    }))
                    .expect("serialize tool request"),
                )
                .expect("build tool frame"),
                &writer,
                &state,
                &bindings,
            )
            .await
            .expect("tool request succeeds");
        };
        let stored = |store: &PlexusStore| {
            store
                .subscription("direct", &subscription.subscription_id)
                .expect("read subscription")
                .expect("row present")
                .project_id
        };
        let stored_delivery = |store: &PlexusStore| {
            store
                .subscription("direct", &subscription.subscription_id)
                .expect("read subscription")
                .expect("row present")
                .deliver_to
        };

        assert_eq!(stored(&store), None, "a fresh subscription has no project");
        assert_eq!(
            stored_delivery(&store),
            None,
            "a fresh subscription has no explicit delivery target"
        );

        call(
            json!({
                "op": "set_project",
                "subscription_id": subscription.subscription_id,
                "project_id": "proj_plexus"
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(responses.recv(), std::time::Duration::from_secs(5), "resp")
                .await
                .body,
        )
        .expect("body");
        assert!(
            body.get("error").is_none(),
            "set_project was refused: {body}"
        );
        assert_eq!(
            stored(&store),
            Some("proj_plexus".to_string()),
            "the handler did not persist the project: {body}"
        );

        for project_id in ["a\nb", "a\rb", "a\tb", "a\0b", "a\u{85}b"] {
            call(
                json!({"op":"set_project", "subscription_id":subscription.subscription_id, "project_id":project_id}),
                writer.clone(), Arc::clone(&state), Arc::clone(&bindings),
            ).await;
            let body: Value = serde_json::from_slice(
                &recv_within(
                    responses.recv(),
                    std::time::Duration::from_secs(5),
                    "invalid project response",
                )
                .await
                .body,
            )
            .unwrap();
            assert_eq!(body["error"]["code"], "invalid_request", "{body}");
            assert_eq!(stored(&store).as_deref(), Some("proj_plexus"));
        }

        // Omitting the key is refused and leaves the binding alone: read as a
        // clear, a misspelled field name would wipe it.
        call(
            json!({
                "op": "set_project",
                "subscription_id": subscription.subscription_id
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "omitted resp",
            )
            .await
            .body,
        )
        .expect("body");
        assert_eq!(
            body["error"]["missing"],
            json!(["project_id"]),
            "omitting project_id must be refused: {body}"
        );
        assert_eq!(
            stored(&store),
            Some("proj_plexus".to_string()),
            "omitting project_id must not clear the binding"
        );

        // An explicit null clears it.
        call(
            json!({
                "op": "set_project",
                "subscription_id": subscription.subscription_id,
                "project_id": null
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let _ = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "clear resp",
        )
        .await;
        assert_eq!(
            stored(&store),
            None,
            "an explicit null project_id must clear the binding"
        );

        // A value that is not a string or null is refused, never read as a
        // clear: the binding set below must survive it.
        call(
            json!({
                "op": "set_project",
                "subscription_id": subscription.subscription_id,
                "project_id": "proj_plexus"
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let _ = recv_within(responses.recv(), std::time::Duration::from_secs(5), "set").await;
        call(
            json!({
                "op": "set_project",
                "subscription_id": subscription.subscription_id,
                "project_id": 42
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(responses.recv(), std::time::Duration::from_secs(5), "resp")
                .await
                .body,
        )
        .expect("body");
        assert_eq!(body["error"]["code"], "invalid_request", "{body}");
        assert_eq!(
            stored(&store),
            Some("proj_plexus".to_string()),
            "a non-string project_id must not clear the binding"
        );

        // An unknown subscription is refused rather than silently accepted.
        call(
            json!({
                "op": "set_project",
                "subscription_id": "subscription_missing",
                "project_id": "proj_x"
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(responses.recv(), std::time::Duration::from_secs(5), "resp")
                .await
                .body,
        )
        .expect("body");
        assert_eq!(
            body["error"]["code"], "subscription_not_found",
            "an unknown subscription must be refused: {body}"
        );

        // Mutation proved: replacing the set_deliver_to handler arm with a
        // success response that discards its value leaves this store assertion
        // and the owner-path list assertion below red.
        call(
            json!({"op": "set_deliver_to"}),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "missing response",
            )
            .await
            .body,
        )
        .expect("missing body");
        assert_eq!(
            body["error"]["missing"],
            json!(["subscription_id", "deliver_to"]),
            "set_deliver_to must report every missing field: {body}"
        );

        let generation_before_delivery_set = store
            .subscription("direct", &subscription.subscription_id)
            .expect("read subscription")
            .expect("row present")
            .generation;
        call(
            json!({
                "op": "set_deliver_to",
                "subscription": subscription.subscription_id,
                "deliver_to": "agent-live"
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "delivery response",
            )
            .await
            .body,
        )
        .expect("delivery body");
        assert!(
            body.get("error").is_none(),
            "set_deliver_to refused: {body}"
        );
        assert_eq!(
            stored_delivery(&store),
            Some("agent-live".to_string()),
            "the handler discarded the delivery target: {body}"
        );
        let stored_generation = store
            .subscription("direct", &subscription.subscription_id)
            .expect("read subscription")
            .expect("row present")
            .generation;
        assert_eq!(
            stored_generation, generation_before_delivery_set,
            "a routing rebind must preserve an in-flight subscription generation"
        );

        call(
            json!({"op": "list", "subscription": subscription.subscription_id}),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "owner list response",
            )
            .await
            .body,
        )
        .expect("owner list body");
        assert_eq!(
            body["result"]["subscriptions"][0]["deliver_to"], "agent-live",
            "the owner list must surface delivery routing: {body}"
        );

        // With both spellings present, `subscription_id` wins, as it does for
        // every sibling op.
        call(
            json!({
                "op": "set_deliver_to",
                "subscription_id": subscription.subscription_id,
                "subscription": "subscription_missing",
                "deliver_to": "agent-live"
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "both spellings response",
            )
            .await
            .body,
        )
        .expect("both spellings body");
        assert!(
            body.get("error").is_none(),
            "set_deliver_to must read subscription_id first: {body}"
        );

        // Principal scoping is proven through the handler and durable state. A
        // refusal body alone could hide a handler that wrote before refusing.
        bindings
            .insert(
                4,
                2,
                Principal::Reserved {
                    module_id: "other".to_string(),
                },
            )
            .expect("bind foreign principal");
        call(
            json!({
                "op": "set_deliver_to",
                "subscription": subscription.subscription_id,
                "deliver_to": "agent-foreign"
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "foreign response",
            )
            .await
            .body,
        )
        .expect("foreign body");
        assert_eq!(body["error"]["code"], "subscription_not_found");
        assert_eq!(
            stored_delivery(&store),
            Some("agent-live".to_string()),
            "a foreign set must leave the owner's row unchanged"
        );
        bindings
            .insert(4, 2, Principal::Direct)
            .expect("restore owner principal");

        registry.set_response("agent-unknown", AgentLookup::Unknown);
        registry.set_response("agent-retired", AgentLookup::Retired);
        registry.set_response("agent-unavailable", AgentLookup::Unavailable);
        let mut refusal_codes = Vec::new();
        for (agent_id, expected_code) in [
            ("agent-unknown", "deliver_to_unknown_agent"),
            ("agent-retired", "deliver_to_agent_retired"),
            ("agent-unavailable", "agent_registry_unavailable"),
        ] {
            call(
                json!({
                    "op": "set_deliver_to",
                    "subscription": subscription.subscription_id,
                    "deliver_to": agent_id
                }),
                writer.clone(),
                Arc::clone(&state),
                Arc::clone(&bindings),
            )
            .await;
            let body: Value = serde_json::from_slice(
                &recv_within(
                    responses.recv(),
                    std::time::Duration::from_secs(5),
                    "registry refusal response",
                )
                .await
                .body,
            )
            .expect("registry refusal body");
            assert_eq!(
                body["error"]["code"], expected_code,
                "the registry verdict needs its own operator remedy: {body}"
            );
            refusal_codes.push(body["error"]["code"].clone());
            assert_eq!(
                stored_delivery(&store),
                Some("agent-live".to_string()),
                "a refused registry verdict must not alter the stored target"
            );
        }
        assert_ne!(refusal_codes[0], refusal_codes[1]);
        assert_ne!(refusal_codes[0], refusal_codes[2]);
        assert_ne!(refusal_codes[1], refusal_codes[2]);

        registry.set_default_response(AgentLookup::Unavailable);
        let registry_requests_before_clear = registry.requests().len();
        call(
            json!({
                "op": "set_deliver_to",
                "subscription": subscription.subscription_id,
                "deliver_to": null
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "delivery clear response",
            )
            .await
            .body,
        )
        .expect("delivery clear body");
        assert!(body.get("error").is_none(), "clear was refused: {body}");
        assert_eq!(stored_delivery(&store), None, "clear must restore absence");
        assert_eq!(
            registry.requests().len(),
            registry_requests_before_clear,
            "clearing must not consult an unavailable registry"
        );
        call(
            json!({"op": "list", "subscription": subscription.subscription_id}),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "cleared list response",
            )
            .await
            .body,
        )
        .expect("cleared list body");
        assert!(
            body["result"]["subscriptions"][0]["deliver_to"].is_null(),
            "the owner list must show that clearing removed delivery routing: {body}"
        );

        let source = ActorSource {
            connection_id: "conn-github-comments".to_string(),
            action: "issue_read".to_string(),
            methods: vec!["get_comments".to_string()],
        };
        call(
            json!({
                "op": "set_actor_source",
                "subscription_id": subscription.subscription_id,
                "actor_source": source
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "actor resp",
            )
            .await
            .body,
        )
        .expect("actor body");
        assert!(
            body.get("error").is_none(),
            "set_actor_source was refused: {body}"
        );
        assert_eq!(
            store
                .subscription("direct", &subscription.subscription_id)
                .expect("read subscription")
                .expect("row present")
                .actor_source,
            Some(ActorSource {
                connection_id: "conn-github-comments".to_string(),
                action: "issue_read".to_string(),
                methods: vec!["get_comments".to_string()],
            }),
            "the handler must persist the actor source rather than echoing input"
        );

        call(
            json!({
                "op": "set_actor_source",
                "subscription_id": subscription.subscription_id
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "actor omitted resp",
            )
            .await
            .body,
        )
        .expect("body");
        assert_eq!(body["error"]["missing"], json!(["actor_source"]), "{body}");
        assert!(
            store
                .subscription("direct", &subscription.subscription_id)
                .expect("read subscription")
                .expect("row present")
                .actor_source
                .is_some(),
            "omitting actor_source must not clear the persisted binding"
        );

        call(
            json!({
                "op": "set_actor_source",
                "subscription_id": subscription.subscription_id,
                "actor_source": null
            }),
            writer,
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let _ = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "actor clear resp",
        )
        .await;
        assert_eq!(
            store
                .subscription("direct", &subscription.subscription_id)
                .expect("read subscription")
                .expect("row present")
                .actor_source,
            None,
            "an explicit null actor_source must clear the persisted binding"
        );
    }
}

#[cfg(test)]
mod events_get_tests {
    use super::*;
    use cortexkit_bus_trait::ContentDigest;
    use cortexkit_store_types::StorageDescriptor;
    use plexus_core::{
        storage::event_outbox::{EventHeaders, KeyedEventIdentity, KeyedPollEventInput},
        test_scratch::Scratch,
        ActorAttribution, GrantInput, PlexusStore, PollEventInput,
    };

    fn test_store(name: &str) -> (Scratch, Arc<PlexusStore>, PathBuf) {
        let scratch = Scratch::database(name);
        let path = scratch.path().to_path_buf();
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: "test".to_string(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("open test plexus store"));
        (scratch, store, path)
    }

    fn seed_agent_binding(path: &Path, agent_id: &str, repo: &str) {
        let conn = rusqlite::Connection::open(path).expect("open sqlite for seeding");
        let handle = format!("handle-{agent_id}");
        conn.execute("INSERT INTO github_app_handle(app_handle_id, agent_id, app_id, credential_reference, status, proven_at, connection_principal, connection_id)
            VALUES (?1, ?2, 1, ?3, 'enabled', 1, 'direct', 'conn-github')
            ON CONFLICT(app_handle_id) DO UPDATE SET status='enabled'", rusqlite::params![handle, agent_id, format!("github_app:{agent_id}")]).expect("seed handle");
        conn.execute(
            "INSERT INTO github_repo_binding(repository, app_handle_id) VALUES (?1, ?2)
            ON CONFLICT(repository) DO UPDATE SET app_handle_id=excluded.app_handle_id",
            rusqlite::params![repo, handle],
        )
        .expect("seed binding");
    }

    fn unbind_repo(path: &Path, repo: &str) {
        let conn = rusqlite::Connection::open(path).expect("open sqlite for unbind");
        conn.execute(
            "DELETE FROM github_repo_binding WHERE repository = ?1",
            [repo],
        )
        .expect("unbind repo");
    }

    pub(super) fn seed_test_events(path: &Path, store: &PlexusStore) -> (String, String) {
        let conn = rusqlite::Connection::open(path).expect("open test db");
        conn.execute_batch(
            "INSERT INTO connections (connection_id, principal, app_key, status, created_at_ms, updated_at_ms)
             VALUES ('conn-github', 'direct', 'github', 'active', 1, 1),
                    ('conn-github-actions', 'direct', 'github_actions', 'active', 1, 1);
             INSERT INTO trigger_subscriptions (subscription_id, principal, connection_id, action, cadence_s, cursor_kind, cursor_state, schema_hash, status, created_at_ms)
             VALUES ('issue-sub-1', 'direct', 'conn-github', 'list_issues', 300, 'ordered_timestamp', '{}', 'hash', 'active', 1),
                    ('ci-sub-1', 'direct', 'conn-github-actions', 'list_workflow_runs', 300, 'ci_runs', '{}', 'hash', 'active', 1);
            ",
        )
        .expect("seed connections and subscriptions");

        // Grant core consume authority on conn-github
        store
            .insert_grant(&GrantInput {
                grant_id: "grant-core-consume".to_string(),
                principal: "direct".to_string(),
                connection_id: "conn-github".to_string(),
                grantee_principal: "reserved:prefrontal-core".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["list_issues".to_string()],
                authority_kind: "events_consume".to_string(),
                expires_at: Some(i64::MAX / 2),
            })
            .expect("seed core consume grant");

        let issue_sub_id = "issue-sub-1".to_string();
        let ci_sub_id = "ci-sub-1".to_string();

        // Insert issue event
        let issue_key =
            "0000000000000000000000000000000000000000000000000000000000000001".to_string();
        let issue_payload = json!({"id": 1, "title": "bug report"});
        let issue_headers = EventHeaders {
            repo: "owner/repo".to_string(),
            project: Some("project-1".to_string()),
            pr: None,
            branch: None,
            conclusion: None,
        };
        let actor = ActorAttribution::NotEnriched;
        let issue_input = KeyedPollEventInput {
            event: PollEventInput {
                vendor_event_id: "issue-1",
                payload: &issue_payload,
                observed_at_ms: plexus_core::now_ms(),
                item_kind: Some("issue"),
                activity_at_ms: Some(plexus_core::now_ms()),
                actor: &actor,
            },
            identity: Some(KeyedEventIdentity {
                event_key: &issue_key,
                event_name: "github_issue_changed",
                repo_id: 101,
                change: Some("opened"),
                headers: &issue_headers,
            }),
            delivery_id: None,
            envelope_context: Default::default(),
        };
        store
            .commit_keyed_poll_success(
                "direct",
                "conn-github",
                &issue_sub_id,
                &json!({}),
                &[issue_input],
                plexus_core::now_ms(),
                &[],
            )
            .expect("commit issue event");

        // Insert CI event
        let ci_key = "0000000000000000000000000000000000000000000000000000000000000002".to_string();
        let ci_payload = json!({"run_id": 99, "status": "completed"});
        let ci_headers = EventHeaders {
            repo: "owner/repo".to_string(),
            project: Some("project-1".to_string()),
            pr: None,
            branch: Some("main".to_string()),
            conclusion: Some("failure".to_string()),
        };
        let ci_input = KeyedPollEventInput {
            event: PollEventInput {
                vendor_event_id: "run-99",
                payload: &ci_payload,
                observed_at_ms: plexus_core::now_ms(),
                item_kind: Some("ci_run"),
                activity_at_ms: Some(plexus_core::now_ms()),
                actor: &actor,
            },
            identity: Some(KeyedEventIdentity {
                event_key: &ci_key,
                event_name: "github_ci_run_completed",
                repo_id: 101,
                change: None,
                headers: &ci_headers,
            }),
            delivery_id: None,
            envelope_context: Default::default(),
        };
        store
            .commit_keyed_poll_success(
                "direct",
                "conn-github-actions",
                &ci_sub_id,
                &json!({"pinned": {}, "open": {}}),
                &[ci_input],
                plexus_core::now_ms(),
                &[],
            )
            .expect("commit ci event");

        (issue_key, ci_key)
    }

    async fn execute_tool_call(
        store: Arc<PlexusStore>,
        principal: Principal,
        scope: Option<CallScope>,
        tool_name: &str,
        arguments: Value,
    ) -> Value {
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(store),
        });
        let bindings = Arc::new(RouteBindings::new());
        bindings
            .insert_scoped(10, 1, principal, scope)
            .expect("bind route");
        let (writer, mut responses) = mpsc::channel(1);
        handle_tool_request(
            Frame::build(
                FrameType::Request,
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                10,
                1,
                1,
                serde_json::to_vec(&json!({
                    "name": tool_name,
                    "arguments": arguments,
                }))
                .unwrap(),
            )
            .unwrap(),
            &writer,
            &state,
            &bindings,
        )
        .await
        .unwrap();
        let frame = crate::bounded::recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "events tool response",
        )
        .await;
        serde_json::from_slice(&frame.body).unwrap()
    }

    #[tokio::test]
    async fn event_pages_preserve_full_listing_and_stable_ties() {
        let (_scratch, store, path) = test_store("event_pages");
        seed_test_events(&path, &store);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE trigger_events SET created_at_ms=123", [])
            .unwrap();
        for principal in [
            Principal::Direct,
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        ] {
            let full = execute_tool_call(
                store.clone(),
                principal.clone(),
                None,
                manifest::EVENTS_TOOL,
                json!({"op":"list"}),
            )
            .await;
            let mut expected = store.list_events("direct", None, None).unwrap();
            if !matches!(principal, Principal::Direct) {
                expected.retain(|event| event.connection_id == "conn-github");
            }
            assert_eq!(full["result"]["events"], json!(expected));
            let first = execute_tool_call(
                store.clone(),
                principal.clone(),
                None,
                manifest::EVENTS_TOOL,
                json!({"op":"list","limit":1}),
            )
            .await;
            assert_eq!(first["result"]["events"].as_array().unwrap().len(), 1);
            let mut collected = first["result"]["events"].as_array().unwrap().clone();
            if full["result"]["events"].as_array().unwrap().len() > 1 {
                assert!(first["result"]["next_after"].is_object());
                let second = execute_tool_call(
                    store.clone(),
                    principal.clone(),
                    None,
                    manifest::EVENTS_TOOL,
                    json!({"op":"list","limit":1,"after":first["result"]["next_after"]}),
                )
                .await;
                collected.extend(second["result"]["events"].as_array().unwrap().clone());
                assert!(second["result"].get("next_after").is_none());
            } else {
                assert!(first["result"].get("next_after").is_none());
            }
            assert_eq!(json!(collected), full["result"]["events"]);
            assert_eq!(
                first["result"]["events_consume_authority"],
                full["result"]["events_consume_authority"]
            );
            assert!(full["result"].get("next_after").is_none());
        }
        let invalid = execute_tool_call(
            store,
            Principal::Direct,
            None,
            manifest::EVENTS_TOOL,
            json!({"op":"list","limit":1001}),
        )
        .await;
        assert_eq!(invalid["error"]["code"], "invalid_request");
    }

    fn basal_flow_scope(agent_id: Option<&str>) -> CallScope {
        CallScope {
            owner: "basal".to_string(),
            scope_ref: "scope-1".to_string(),
            scope_epoch: 1,
            kind: None,
            parent: None,
            parent_state: None,
            agent_id: agent_id.map(str::to_string),
            flow_id: Some("flow-100".to_string()),
            delegates: false,
            owner_authorized: true,
        }
    }

    #[tokio::test]
    async fn events_get_carrier_and_flow_scope_checks() {
        let (_scratch, store, path) = test_store("events_get_carrier_checks");
        let (issue_key, _) = seed_test_events(&path, &store);

        // 1. reserved:basal without flow scope -> flow_scope_required
        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            None,
            manifest::EVENTS_TOOL,
            json!({"op": "get", "event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        assert_eq!(res["error"]["code"], "flow_scope_required");

        // 2. non-admitted carrier with flow scope -> flow_carrier_not_admitted
        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "aft".to_string(),
            },
            Some(basal_flow_scope(None)),
            manifest::EVENTS_GET_TOOL,
            json!({ "event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        assert_eq!(res["error"]["code"], "flow_carrier_not_admitted");

        // 3. direct caller without flow scope -> events_get_carrier_refused
        let res = execute_tool_call(
            store.clone(),
            Principal::Direct,
            None,
            manifest::EVENTS_TOOL,
            json!({"op": "get", "event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        assert_eq!(res["error"]["code"], "events_get_carrier_refused");

        // 4. The consumer events lane is classic-only, including list and ack.
        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            Some(basal_flow_scope(None)),
            manifest::EVENTS_TOOL,
            json!({"op": "list"}),
        )
        .await;
        assert_eq!(res["error"]["code"], "call_mode_unsupported");
        assert_eq!(
            res["error"]["detail"],
            json!({"tool":"events","mode":"flow"})
        );

        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            Some(basal_flow_scope(None)),
            manifest::EVENTS_TOOL,
            json!({"op": "ack", "event_ids": ["123"]}),
        )
        .await;
        assert_eq!(res["error"]["code"], "call_mode_unsupported");
        assert_eq!(
            res["error"]["detail"],
            json!({"tool":"events","mode":"flow"})
        );
    }

    async fn compare_get_replies(
        store: Arc<PlexusStore>,
        principal: Principal,
        scope: Option<CallScope>,
        arguments: Value,
    ) -> Value {
        let get = execute_tool_call(
            store.clone(),
            principal.clone(),
            scope.clone(),
            manifest::EVENTS_GET_TOOL,
            arguments.clone(),
        )
        .await;
        if scope.as_ref().is_some_and(|scope| scope.flow_id.is_some()) {
            return get;
        }
        let mut legacy_arguments = arguments;
        legacy_arguments["op"] = json!("get");
        let legacy = execute_tool_call(
            store,
            principal,
            scope,
            manifest::EVENTS_TOOL,
            legacy_arguments,
        )
        .await;
        assert_eq!(
            get, legacy,
            "both event fetch surfaces must reply identically"
        );
        get
    }

    fn assert_issue_reply(reply: &Value, issue_key: &str) {
        use sha2::Digest;
        let result = reply["result"].as_object().expect("event lookup succeeds");
        assert_eq!(result.len(), 6);
        assert_eq!(result["event_key"], issue_key);
        assert_eq!(result["event_name"], "github_issue_changed");
        assert_eq!(result["repo"], "owner/repo");
        let body = result["body"].as_str().expect("stored body string");
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap(),
            json!({"id": 1, "title": "bug report"})
        );
        assert_eq!(
            result["digest"],
            format!("{:x}", sha2::Sha256::digest(body.as_bytes()))
        );
        assert_eq!(result["published_at"], Value::Null);
        assert_eq!(reply["structuredContent"], reply["result"]);
        assert_eq!(reply["isError"], false);
        assert_eq!(reply["content"][0]["type"], "text");
        assert_eq!(
            serde_json::from_str::<Value>(reply["content"][0]["text"].as_str().unwrap()).unwrap(),
            json!({"result": reply["result"]})
        );
    }

    #[tokio::test]
    async fn events_get_tool_matches_legacy_for_consumer() {
        let (_scratch, store, path) = test_store("get_tool_consumer");
        let (issue_key, _) = seed_test_events(&path, &store);
        let reply = compare_get_replies(
            store,
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            None,
            json!({"event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        assert_issue_reply(&reply, &issue_key);
    }

    #[tokio::test]
    async fn events_get_tool_fetches_for_basal_agent_flow() {
        let (_scratch, store, path) = test_store("get_tool_agent");
        let (issue_key, _) = seed_test_events(&path, &store);
        seed_agent_binding(&path, "agent-a", "Owner/Repo");
        let reply = compare_get_replies(
            store,
            Principal::Reserved {
                module_id: "basal".into(),
            },
            Some(basal_flow_scope(Some("agent-a"))),
            json!({"event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        assert_issue_reply(&reply, &issue_key);
    }

    #[tokio::test]
    async fn events_get_tool_matches_legacy_refusals() {
        let (_scratch, store, path) = test_store("get_tool_refusals");
        let (issue_key, ci_key) = seed_test_events(&path, &store);
        seed_agent_binding(&path, "agent-a", "owner/repo");
        for (principal, scope, invisible_key, invisible_name) in [
            (
                Principal::Reserved {
                    module_id: "prefrontal-core".into(),
                },
                None,
                ci_key,
                "github_ci_run_completed",
            ),
            (
                Principal::Reserved {
                    module_id: "basal".into(),
                },
                Some(basal_flow_scope(Some("agent-a"))),
                issue_key.clone(),
                "github_issue_changed",
            ),
        ] {
            for (key, name, code) in [
                ("f".repeat(64), "github_issue_changed", "event_not_visible"),
                (
                    issue_key.clone(),
                    "github_pr_changed",
                    "event_name_mismatch",
                ),
            ] {
                let reply = compare_get_replies(
                    store.clone(),
                    principal.clone(),
                    scope.clone(),
                    json!({"event_key": key, "event_name": name}),
                )
                .await;
                assert_eq!(reply["error"]["code"], code);
                assert_eq!(reply["isError"], true, "a refusal must set isError");
            }
            let invisible_scope = scope.map(|_| basal_flow_scope(Some("agent-b")));
            let reply = compare_get_replies(
                store.clone(),
                principal,
                invisible_scope,
                json!({"event_key": invisible_key, "event_name": invisible_name}),
            )
            .await;
            assert_eq!(reply["error"]["code"], "event_not_visible");
        }
    }

    #[tokio::test]
    async fn events_get_tool_rejects_non_basal_flow_carrier() {
        let (_scratch, store, _) = test_store("get_tool_carrier");
        let reply = execute_tool_call(
            store,
            Principal::Reserved {
                module_id: "aft".into(),
            },
            Some(basal_flow_scope(Some("agent-a"))),
            manifest::EVENTS_GET_TOOL,
            json!({"event_key": "0".repeat(64), "event_name": "github_issue_changed"}),
        )
        .await;
        assert_eq!(reply["error"]["code"], "flow_carrier_not_admitted");
        assert_eq!(reply["error"]["transmission"], "not_sent");
    }

    #[tokio::test]
    async fn events_get_tool_requires_basal_flow_scope() {
        let (_scratch, store, _) = test_store("get_tool_scope");
        let mut non_flow_scope = basal_flow_scope(Some("agent-a"));
        non_flow_scope.flow_id = None;
        for scope in [None, Some(non_flow_scope)] {
            let reply = execute_tool_call(
                store.clone(),
                Principal::Reserved {
                    module_id: "basal".into(),
                },
                scope,
                manifest::EVENTS_GET_TOOL,
                json!({"event_key": "0".repeat(64), "event_name": "github_issue_changed"}),
            )
            .await;
            assert_eq!(reply["error"]["code"], "flow_scope_required");
            assert_eq!(reply["error"]["transmission"], "not_sent");
        }
    }

    #[tokio::test]
    async fn events_get_tool_rejects_extra_arguments() {
        let (_scratch, store, path) = test_store("get_tool_extra");
        let (issue_key, _) = seed_test_events(&path, &store);
        for (key, value) in [
            ("op", json!("get")),
            ("agent_id", json!("agent-a")),
            ("extra", json!(null)),
        ] {
            let mut arguments =
                json!({"event_key": issue_key, "event_name": "github_issue_changed"});
            arguments[key] = value;
            let reply = execute_tool_call(
                store.clone(),
                Principal::Reserved {
                    module_id: "prefrontal-core".into(),
                },
                None,
                manifest::EVENTS_GET_TOOL,
                arguments,
            )
            .await;
            assert_eq!(reply["error"]["code"], "invalid_request");
        }
    }

    #[tokio::test]
    async fn events_get_version_one_is_the_default_and_version_two_never_falls_back() {
        let (_scratch, store, path) = test_store("get_tool_version");
        let (issue_key, _) = seed_test_events(&path, &store);
        let core = || Principal::Reserved {
            module_id: "prefrontal-core".into(),
        };
        let call = |arguments: Value| {
            execute_tool_call(
                store.clone(),
                core(),
                None,
                manifest::EVENTS_GET_TOOL,
                arguments,
            )
        };
        let base = json!({"event_key": issue_key, "event_name": "github_issue_changed"});
        let default = call(base.clone()).await;
        let mut explicit = base.clone();
        explicit["version"] = json!(1);
        assert_eq!(call(explicit).await["result"], default["result"]);
        assert!(default["result"]["body"].is_string());

        // Model a pre-v2 row: migration never backfills old events. Version 2
        // must refuse exactly as an unknown key does, never return the v1 body.
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE event_outbox SET envelope_v2=NULL, digest_v2=NULL WHERE event_key=?1",
                [&issue_key],
            )
            .unwrap();
        let mut v2 = base.clone();
        v2["version"] = json!(2);
        let v2_reply = call(v2).await;
        let unknown =
            call(json!({"event_key": "0".repeat(64), "event_name": "github_issue_changed"})).await;
        assert_eq!(
            v2_reply["error"], unknown["error"],
            "version 2 must not fall back to version 1"
        );
        assert!(v2_reply.get("result").is_none());

        for bad in [json!(0), json!(3), json!("2"), json!(1.5), json!(null)] {
            let mut arguments = base.clone();
            arguments["version"] = bad;
            let reply = call(arguments).await;
            assert_eq!(reply["error"]["code"], "invalid_request");
            assert_eq!(reply["error"]["field"], "version");
        }
    }

    #[tokio::test]
    async fn v2_fetch_preserves_pre_workflow_name_ci_job_envelope_and_digest() {
        use sha2::Digest;

        let (_scratch, store, path) = test_store("v2-old-ci-job-envelope");
        seed_test_events(&path, &store);
        store
            .insert_grant(&GrantInput {
                grant_id: "grant-core-ci-consume".into(),
                principal: "direct".into(),
                connection_id: "conn-github-actions".into(),
                grantee_principal: "reserved:prefrontal-core".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["list_workflow_runs".into()],
                authority_kind: "events_consume".into(),
                expires_at: Some(i64::MAX / 2),
            })
            .unwrap();

        let key = "0000000000000000000000000000000000000000000000000000000000000003";
        let payload = json!({
            "id": 703,
            "name": "legacy CI job",
            "workflow_name": "workflow name from newer source",
            "conclusion": "failure",
            "status": "completed",
            "head_branch": "main",
            "head_sha": "0123456789abcdef",
            "html_url": "https://github.com/owner/repo/actions/runs/702/job/703",
            "run_id": 702,
            "run_attempt": 1,
            "completed_at": "2026-10-11T00:45:44Z",
            "created_at": "2026-10-11T00:30:12Z",
            "updated_at": "2026-10-11T00:45:44Z"
        });
        let event_headers = EventHeaders {
            repo: "owner/repo".into(),
            project: Some("project-1".into()),
            pr: None,
            branch: Some("main".into()),
            conclusion: Some("failure".into()),
        };
        let actor = ActorAttribution::NotEnriched;
        let job = KeyedPollEventInput {
            event: PollEventInput {
                vendor_event_id: "job-703",
                payload: &payload,
                observed_at_ms: plexus_core::now_ms(),
                item_kind: Some("ci_job"),
                activity_at_ms: Some(plexus_core::now_ms()),
                actor: &actor,
            },
            identity: Some(KeyedEventIdentity {
                event_key: key,
                event_name: "github_ci_job_failed",
                repo_id: 101,
                change: Some("completed"),
                headers: &event_headers,
            }),
            delivery_id: None,
            envelope_context: Default::default(),
        };
        store
            .commit_keyed_poll_success(
                "direct",
                "conn-github-actions",
                "ci-sub-1",
                &json!({"pinned": {}, "open": {}}),
                &[job],
                plexus_core::now_ms(),
                &[],
            )
            .unwrap();

        // A ci_job envelope exactly as plexus stored it before the envelope gained
        // workflow_name. Stored envelopes are never rewritten, so fetching this
        // event must return these bytes and their original digest unchanged.
        let historical = r#"{"action":"updated","actor_logins":null,"actor_unknown":null,"completed_at":"2026-10-11T00:45:44Z","conclusion":"failure","event_key":"0000000000000000000000000000000000000000000000000000000000000003","head_branch":"main","head_sha":"0123456789abcdef","id":703,"kind":"ci_job","name":"legacy CI job","repo":"owner/repo","run_attempt":1,"run_id":702,"status":"completed","url":"https://github.com/owner/repo/actions/runs/702/job/703"}"#;
        let digest = format!("{:x}", sha2::Sha256::digest(historical.as_bytes()));
        let db = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            db.execute(
                "UPDATE event_outbox SET envelope_v2=?1,digest_v2=?2 WHERE event_key=?3",
                rusqlite::params![historical, digest, key],
            )
            .unwrap(),
            1
        );

        let result = execute_tool_call(
            store,
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            None,
            manifest::EVENTS_GET_TOOL,
            json!({"event_key":key,"event_name":"github_ci_job_failed","version":2}),
        )
        .await;
        assert_eq!(result["result"]["body"], historical);
        assert_eq!(result["result"]["digest"], digest);
    }

    #[tokio::test]
    async fn v2_fetch_returns_stored_bytes_and_digest_without_recomputation() {
        use sha2::Digest;
        let (_scratch, store, path) = test_store("v2-stored-fetch");
        let (key, _) = seed_test_events(&path, &store);
        let db = rusqlite::Connection::open(&path).unwrap();
        let (stored, digest, legacy): (String,String,String) = db.query_row(
            "SELECT o.envelope_v2,o.digest_v2,e.payload FROM event_outbox o JOIN trigger_events e USING(event_id) WHERE o.event_key=?1", [&key],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(
            digest,
            format!("{:x}", sha2::Sha256::digest(stored.as_bytes()))
        );
        let body: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(body["event_key"], key);
        assert_eq!(body["kind"], "issue");
        assert_eq!(body["actor_unknown"]["reason"], "actor_source_unbound");
        assert!(body["actor_logins"].is_null());
        let core = || Principal::Reserved {
            module_id: "prefrontal-core".into(),
        };
        let default = execute_tool_call(
            store.clone(),
            core(),
            None,
            manifest::EVENTS_GET_TOOL,
            json!({"event_key":key,"event_name":"github_issue_changed"}),
        )
        .await;
        assert_eq!(
            default["result"]["body"], legacy,
            "v1 must retain original stored bytes"
        );
        // A changed source body must not reconstruct or overwrite the envelope.
        assert_eq!(db.execute("UPDATE trigger_events SET payload='{\"number\":999,\"title\":\"changed after insert\"}' WHERE event_key=?1", [&key]).unwrap(), 1, "source-body mutation must touch one row");
        assert_eq!(db.execute("UPDATE event_outbox SET body_v1='{\"number\":999,\"title\":\"changed after insert\"}' WHERE event_key=?1", [&key]).unwrap(), 1, "canonical-body mutation must touch one row");
        let v2 = execute_tool_call(
            store.clone(),
            core(),
            None,
            manifest::EVENTS_GET_TOOL,
            json!({"event_key":key,"event_name":"github_issue_changed","version":2}),
        )
        .await;
        assert_eq!(
            v2["result"]["body"], stored,
            "v2 fetch must return stored envelope bytes without recomputing"
        );
        assert_eq!(v2["result"]["digest"], digest);
        let legacy_get = execute_tool_call(
            store.clone(),
            core(),
            None,
            manifest::EVENTS_TOOL,
            json!({"op":"get","event_key":key,"event_name":"github_issue_changed","version":2}),
        )
        .await;
        assert_eq!(legacy_get, v2);
        assert_eq!(
            digest,
            format!(
                "{:x}",
                sha2::Sha256::digest(v2["result"]["body"].as_str().unwrap().as_bytes())
            )
        );
        db.execute(
            "DELETE FROM grants WHERE authority_kind='events_consume'",
            [],
        )
        .unwrap();
        let denied = execute_tool_call(
            store,
            core(),
            None,
            manifest::EVENTS_GET_TOOL,
            json!({"event_key":key,"event_name":"github_issue_changed","version":2}),
        )
        .await;
        assert_eq!(denied["error"]["code"], "event_not_visible");
    }

    #[tokio::test]
    async fn events_get_tool_matches_legacy_argument_validation() {
        let (_scratch, store, _) = test_store("get_tool_validation");
        for (arguments, field) in [
            (json!({"event_name": "github_issue_changed"}), "event_key"),
            (
                json!({"event_key": 1, "event_name": "github_issue_changed"}),
                "event_key",
            ),
            (
                json!({"event_key": "A".repeat(64), "event_name": "github_issue_changed"}),
                "event_key",
            ),
            (
                json!({"event_key": "0".repeat(63), "event_name": "github_issue_changed"}),
                "event_key",
            ),
            (json!({"event_key": "0".repeat(64)}), "event_name"),
            (
                json!({"event_key": "0".repeat(64), "event_name": null}),
                "event_name",
            ),
        ] {
            let reply = compare_get_replies(
                store.clone(),
                Principal::Reserved {
                    module_id: "prefrontal-core".into(),
                },
                None,
                arguments,
            )
            .await;
            assert_eq!(reply["error"]["code"], "invalid_request");
            assert_eq!(reply["error"]["field"], field);
        }
    }

    #[tokio::test]
    async fn events_get_validates_request_fields() {
        let (_scratch, store, path) = test_store("events_get_val");
        let (issue_key, _) = seed_test_events(&path, &store);

        // Missing event_key
        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            Some(basal_flow_scope(Some("agent-1"))),
            manifest::EVENTS_GET_TOOL,
            json!({ "event_name": "github_issue_changed"}),
        )
        .await;
        assert_eq!(res["error"]["code"], "invalid_request");
        assert_eq!(res["error"]["field"], "event_key");

        // Malformed event_key (not 64 lowercase hex)
        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            Some(basal_flow_scope(Some("agent-1"))),
            manifest::EVENTS_GET_TOOL,
            json!({ "event_key": "not-64-hex", "event_name": "github_issue_changed"}),
        )
        .await;
        assert_eq!(res["error"]["code"], "invalid_request");
        assert_eq!(res["error"]["field"], "event_key");

        // Missing event_name
        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            Some(basal_flow_scope(Some("agent-1"))),
            manifest::EVENTS_GET_TOOL,
            json!({ "event_key": issue_key}),
        )
        .await;
        assert_eq!(res["error"]["code"], "invalid_request");
        assert_eq!(res["error"]["field"], "event_name");
    }

    #[tokio::test]
    async fn events_get_refusals_and_mismatches() {
        let (_scratch, store, path) = test_store("events_get_refusals");
        let (issue_key, _) = seed_test_events(&path, &store);

        seed_agent_binding(&path, "agent-a", "owner/repo");

        // 1. Unknown key gives event_not_visible (NOT event_not_found)
        let unknown_key = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            Some(basal_flow_scope(Some("agent-a"))),
            manifest::EVENTS_GET_TOOL,
            json!({ "event_key": unknown_key, "event_name": "github_issue_changed"}),
        )
        .await;
        assert_eq!(res["error"]["code"], "event_not_visible");

        // 2. Mismatched event_name gives event_name_mismatch
        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            Some(basal_flow_scope(Some("agent-a"))),
            manifest::EVENTS_GET_TOOL,
            json!({ "event_key": issue_key, "event_name": "github_pr_changed"}),
        )
        .await;
        assert_eq!(res["error"]["code"], "event_name_mismatch");
    }

    #[tokio::test]
    async fn events_get_agent_owned_flow_and_unbind() {
        let (_scratch, store, path) = test_store("events_get_agent_flow");
        let (issue_key, _) = seed_test_events(&path, &store);

        seed_agent_binding(&path, "agent-a", "Owner/Repo");

        // Agent A can read (case-insensitive binding check works!)
        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            Some(basal_flow_scope(Some("agent-a"))),
            manifest::EVENTS_GET_TOOL,
            json!({ "event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        assert!(
            res.get("result").is_some(),
            "agent-a must read bound event: {res}"
        );
        let result = &res["result"];
        assert_eq!(result["event_key"], issue_key);
        assert_eq!(result["event_name"], "github_issue_changed");
        assert_eq!(result["repo"], "owner/repo");
        let body_str = result["body"].as_str().expect("body string");
        let digest_str = result["digest"].as_str().expect("digest string");
        let computed_digest = ContentDigest::of_bytes(body_str.as_bytes()).to_string();
        assert_eq!(digest_str, computed_digest);

        // Agent B cannot read -> event_not_visible
        let res_b = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            Some(basal_flow_scope(Some("agent-b"))),
            manifest::EVENTS_GET_TOOL,
            json!({ "event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        assert_eq!(res_b["error"]["code"], "event_not_visible");

        // Unbind repository -> Agent A immediately gets event_not_visible
        unbind_repo(&path, "Owner/Repo");
        let res_after_unbind = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            Some(basal_flow_scope(Some("agent-a"))),
            manifest::EVENTS_GET_TOOL,
            json!({ "event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        assert_eq!(res_after_unbind["error"]["code"], "event_not_visible");
    }

    #[tokio::test]
    async fn review_events_get_enforces_live_agent_repository_binding() {
        use plexus_core::storage::relay::{Event, Hello};
        let (_scratch, store, path) = test_store("review-event-visibility");
        seed_test_events(&path, &store);
        rusqlite::Connection::open(&path).unwrap().execute_batch(
            "UPDATE trigger_subscriptions SET fixed_args='{\"owner\":\"org\",\"repo\":\"repo\"}' WHERE subscription_id='issue-sub-1';
             INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,schema_hash,status,created_at_ms,fixed_args)
             VALUES ('pr-review','direct','conn-github','list_pull_requests',300,'ordered_timestamp','hash','active',1,'{\"owner\":\"org\",\"repo\":\"repo\"}');"
        ).unwrap();
        let hello: Hello = serde_json::from_value(json!({"v":1,"source":"github","stream_id":"reviews","next_seq":1,"oldest_seq":1,"last_acked_seq":0})).unwrap();
        store.relay_hello("github", &hello).unwrap();
        seed_agent_binding(&path, "review-agent", "ORG/REPO");
        for (seq, event_type, source, kind) in [
            (
                1,
                "pull_request_review",
                include_str!("../tests/fixtures/webhook-relay/review-submitted.json"),
                "github_pr_review_submitted",
            ),
            (
                2,
                "pull_request_review_comment",
                include_str!("../tests/fixtures/webhook-relay/review-comment-created.json"),
                "github_pr_review_comment_created",
            ),
        ] {
            let body: Value = serde_json::from_str(source).unwrap();
            let event: Event = serde_json::from_value(json!({"seq":seq,"delivery_id":format!("visibility-{seq}"),"event":event_type,
                "action":body["action"],"installation_id":42,"received_at":"2030-10-08T09:00:00.000Z","stub":null,"body":body})).unwrap();
            store
                .commit_relay_event("github", "reviews", &event)
                .unwrap();
            let row = store
                .drain_event_outbox(10)
                .unwrap()
                .into_iter()
                .find(|row| row.event_name == kind)
                .unwrap();
            for (agent, visible) in [
                ("review-agent".to_owned(), true),
                ("unbound-agent".into(), false),
            ] {
                let reply = execute_tool_call(
                    store.clone(),
                    Principal::Reserved {
                        module_id: "basal".into(),
                    },
                    Some(basal_flow_scope(Some(&agent))),
                    manifest::EVENTS_GET_TOOL,
                    json!({"event_key":row.event_key,"event_name":kind}),
                )
                .await;
                if visible {
                    assert_eq!(reply["result"]["body"], row.body);
                } else {
                    assert_eq!(
                        reply["error"]["code"], "event_not_visible",
                        "review events must enforce the calling agent's repository binding"
                    );
                }
            }
        }
        unbind_repo(&path, "ORG/REPO");
        for row in store
            .drain_event_outbox(10)
            .unwrap()
            .into_iter()
            .filter(|row| row.event_name.starts_with("github_pr_review"))
        {
            let reply = execute_tool_call(
                store.clone(),
                Principal::Reserved {
                    module_id: "basal".into(),
                },
                Some(basal_flow_scope(Some("review-agent"))),
                manifest::EVENTS_GET_TOOL,
                json!({"event_key":row.event_key,"event_name":row.event_name}),
            )
            .await;
            assert_eq!(reply["error"]["code"], "event_not_visible");
        }
    }

    #[tokio::test]
    async fn events_get_global_flow_and_core_grants() {
        let (_scratch, store, path) = test_store("events_get_global_core");
        let (issue_key, ci_key) = seed_test_events(&path, &store);

        // Global flow without grant -> event_not_visible
        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            Some(basal_flow_scope(None)),
            manifest::EVENTS_GET_TOOL,
            json!({ "event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        assert_eq!(res["error"]["code"], "event_not_visible");

        // Add events_consume grant for reserved:basal on conn-github
        store
            .insert_grant(&GrantInput {
                grant_id: "grant-basal-consume".to_string(),
                principal: "direct".to_string(),
                connection_id: "conn-github".to_string(),
                grantee_principal: "reserved:basal".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["list_issues".to_string()],
                authority_kind: "events_consume".to_string(),
                expires_at: Some(i64::MAX / 2),
            })
            .expect("grant basal consume");

        // Global flow now sees issue event!
        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".to_string(),
            },
            Some(basal_flow_scope(None)),
            manifest::EVENTS_GET_TOOL,
            json!({ "event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        assert!(res.get("result").is_some());

        // Prefrontal-core: sees issue event on conn-github
        let res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "prefrontal-core".to_string(),
            },
            None,
            manifest::EVENTS_TOOL,
            json!({"op": "get", "event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        assert!(res.get("result").is_some());

        // Prefrontal-core: cannot see CI event on conn-github-actions -> event_not_visible
        let res_ci = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "prefrontal-core".to_string(),
            },
            None,
            manifest::EVENTS_TOOL,
            json!({"op": "get", "event_key": ci_key, "event_name": "github_ci_run_completed"}),
        )
        .await;
        assert_eq!(res_ci["error"]["code"], "event_not_visible");
    }

    #[tokio::test]
    async fn scoped_core_requires_own_consume_grant() {
        let (_scratch, store, path) = test_store("scoped_core_grant");
        let (_, ci_key) = seed_test_events(&path, &store);
        seed_agent_binding(&path, "agent-a", "owner/repo");
        let mut scope = basal_flow_scope(Some("agent-a"));
        scope.flow_id = None;
        let reply = execute_tool_call(
            store,
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            Some(scope),
            manifest::EVENTS_TOOL,
            json!({"op":"get", "event_key":ci_key, "event_name":"github_ci_run_completed"}),
        )
        .await;
        assert_eq!(reply["error"]["code"], "event_not_visible");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn codemode_events_get_keeps_module_visibility_despite_delegation() {
        let (_scratch, store, path) = test_store("run_events");
        let (issue_key, ci_key) = seed_test_events(&path, &store);
        seed_agent_binding(&path, "agent-a", "owner/repo");
        let principal = Principal::Reserved {
            module_id: "prefrontal-core".into(),
        };
        let stamp = subc_protocol::scope::ScopeStamp::new(
            principal.clone(),
            "run-events",
            1,
            subc_protocol::scope::ScopeKind::Worker,
        )
        .with_attributes(
            subc_protocol::scope::ScopeAttributes::new()
                .with_agent_id(Some("agent-a".into()))
                .with_run_id(Some("run-events".into()))
                .with_delegates(true),
        )
        .with_owner_authorized(true);
        for (key, name, visible) in [
            (issue_key, "github_issue_changed", true),
            (ci_key, "github_ci_run_completed", false),
        ] {
            let reply = crate::call_mode_tests::bound_call(
                runtime_for_test(store.clone()),
                principal.clone(),
                Some(stamp.clone()),
                Some(CallMode::Codemode),
                manifest::EVENTS_GET_TOOL,
                json!({"event_key":key,"event_name":name}),
            )
            .await;
            if visible {
                assert!(reply.get("result").is_some(), "{reply}");
            } else {
                assert_eq!(
                    reply["error"]["code"], "event_not_visible",
                    "a run cannot borrow its agent's event bindings: {reply}"
                );
            }
        }
    }

    #[test]
    fn hostile_argument_agent_id_never_overrides_stamp() {
        let (_scratch, store, path) = test_store("hostile_event_identity");
        let (issue_key, _) = seed_test_events(&path, &store);
        seed_agent_binding(&path, "agent-a", "owner/repo");
        for (stamp, argument, visible) in
            [("agent-b", "agent-a", false), ("agent-a", "agent-b", true)]
        {
            // Exercise the reader itself with hostile input. The public
            // events_get schema rejects this field before reaching the reader.
            let reply = event_get_reply(&store,
                json!({"event_key":issue_key, "event_name":"github_issue_changed", "agent_id":argument}).as_object().unwrap(),
                "reserved:basal", Some(&basal_flow_scope(Some(stamp))), None);
            if visible {
                assert!(reply.get("result").is_some(), "{reply}");
            } else {
                assert_eq!(reply["error"]["code"], "event_not_visible");
            }
        }
    }

    #[tokio::test]
    async fn events_get_body_matches_independent_sqlite_payload_bytes() {
        use sha2::Digest;
        let (_scratch, store, path) = test_store("verbatim_event_body");
        let (key, _) = seed_test_events(&path, &store);
        let db = rusqlite::Connection::open(&path).unwrap();
        // Overwrite the stored version-1 body with JSON spacing and a `\u00e9`
        // escape that a serializer would not produce, as a body written by an
        // older producer may look. Fetching the event must return these exact
        // bytes, not JSON rebuilt from the watch's linked `trigger_events` row.
        let raw = "{ \"z\": 1,\n  \"a\": \"\\u00e9\" }\n";
        let digest = format!("{:x}", sha2::Sha256::digest(raw.as_bytes()));
        assert_eq!(
            db.execute(
                "UPDATE event_outbox SET body_v1=?1,digest_v1=?2 WHERE event_key=?3",
                (raw, &digest, &key),
            )
            .unwrap(),
            1,
            "verbatim payload mutation must touch one seeded row"
        );
        let stored: String = db
            .query_row(
                "SELECT body_v1 FROM event_outbox WHERE event_key = ?1",
                [&key],
                |r| r.get(0),
            )
            .unwrap();
        let reply = execute_tool_call(
            store,
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            None,
            manifest::EVENTS_TOOL,
            json!({"op":"get", "event_key":key, "event_name":"github_issue_changed"}),
        )
        .await;
        assert_eq!(
            reply["result"]["body"].as_str().unwrap().as_bytes(),
            stored.as_bytes(),
            "reply must preserve stored bytes"
        );
        assert_eq!(
            reply["result"]["digest"],
            format!("{:x}", sha2::Sha256::digest(stored.as_bytes()))
        );
    }

    #[tokio::test]
    async fn events_get_read_only_and_survives_ack() {
        let (_scratch, store, path) = test_store("events_get_ack");
        let (issue_key, _) = seed_test_events(&path, &store);

        // Core reads before ack
        let res_before = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "prefrontal-core".to_string(),
            },
            None,
            manifest::EVENTS_TOOL,
            json!({"op": "get", "event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        let body_before = res_before["result"]["body"].as_str().unwrap();
        let digest_before = res_before["result"]["digest"].as_str().unwrap();

        // Core lists events
        let list_res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "prefrontal-core".to_string(),
            },
            None,
            manifest::EVENTS_TOOL,
            json!({"op": "list"}),
        )
        .await;
        let event_id = list_res["result"]["events"][0]["event_id"]
            .as_str()
            .unwrap();

        // Core acks the event
        let ack_res = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "prefrontal-core".to_string(),
            },
            None,
            manifest::EVENTS_TOOL,
            json!({"op": "ack", "event_ids": [event_id]}),
        )
        .await;
        assert_eq!(ack_res["result"]["acked"], 1);

        // Core reads after ack: body is verbatim, sha256(body) == digest
        let res_after = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "prefrontal-core".to_string(),
            },
            None,
            manifest::EVENTS_TOOL,
            json!({"op": "get", "event_key": issue_key, "event_name": "github_issue_changed"}),
        )
        .await;
        let body_after = res_after["result"]["body"].as_str().unwrap();
        let digest_after = res_after["result"]["digest"].as_str().unwrap();

        assert_eq!(body_before, body_after);
        assert_eq!(digest_before, digest_after);
        assert_eq!(
            digest_after,
            ContentDigest::of_bytes(body_after.as_bytes()).to_string()
        );
    }
}

#[cfg(test)]
mod approval_gate_tests {
    use super::*;
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{BindIdentity, RouteTarget};

    /// Approve and deny reach the engine with the request the CALLER named.
    ///
    /// These are the highest-stakes ops on the facade: an ask-first write waits
    /// as a pending request, and these two decide whether it executes. Both
    /// were unproven at the handler — measured, passing an id the caller never
    /// sent (so the engine is asked about a request that does not exist) left
    /// the whole module suite green for each of them.
    ///
    /// The two failure directions are not symmetric. A broken APPROVE reports
    /// success while the write never happens, which an operator eventually
    /// notices because the effect is missing. A broken DENY reports success
    /// while the request stays pending and approvable, so an operator who
    /// believes they refused an action has not refused it — a decision to
    /// withhold authority that silently did not take.
    ///
    /// Asserted on STORE STATE and on the TRANSPORT, never on the response
    /// alone: reporting success while doing nothing is precisely the mutation
    /// being caught.
    // Multi-threaded, because the invoke and approve paths reach a real
    // transport call wrapped in `blocking_section` (tokio::task::block_in_place),
    // which panics on the single-threaded runtime the default #[tokio::test]
    // provides. The same wrapper is what production uses on every connector
    // call, so a test driving these paths has to run where it is legal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn approve_and_deny_act_on_the_request_the_caller_named() {
        let (writer, mut responses) = mpsc::channel(8);
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("approval-gate-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));
        // The approved write is checked for freshness before it is sent, which
        // loads the connection's manifest; its catalog row is fresh, so no
        // vendor is contacted. The manifest declares `held_write` on an S1
        // app, so the write is S2 and an ordinary grant admits it.
        store
            .upsert_manifest(
                "system",
                &crate::test_write_manifest("mock", "https://vendor.invalid/mcp"),
            )
            .expect("mock manifest");
        store
            .insert_connection(
                "direct",
                "conn-approval",
                "mock",
                "pending",
                &json!({"required": [], "optional": [], "write_enabling": ["team"]}),
            )
            .expect("seed connection");
        // Activated through the real ticket ceremony rather than by writing an
        // `active` row directly, because dispatch resolves a credential from
        // the binding a ticket installs — a connection marked active with no
        // binding stops at the credential gate, which would leave the approval
        // assertions unreachable.
        let ticket = store
            .create_binding_ticket("direct", "conn-approval", b"test:canary-binding-handle")
            .expect("issue binding ticket");
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("consume binding ticket")
            .expect("connection activates");

        // An ask-first WRITE, so `authorize` parks it as a pending request
        // rather than dispatching — which is the only way to get a row for
        // approve/deny to act on.
        let schema = json!({"type": "object"});
        store
            .upsert_catalog_action(&plexus_core::CatalogActionInput {
                connection_id: "conn-approval".to_string(),
                principal: "direct".to_string(),
                name: "held_write".to_string(),
                title: None,
                schema: schema.clone(),
                schema_hash: plexus_core::jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
                risk: "write".to_string(),
                // The column holds the app's tier, as the catalog seed writes
                // it. Freshness judges the write from it; a value that is not
                // a tier reads as S4, whose staleness bound is zero, so every
                // dispatch would first refresh from the (unreachable) vendor
                // and be refused as a stale write.
                severity: "S1".to_string(),
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
                ask_first: true,
            })
            .expect("seed catalog action");
        for (grant_id, authority_kind) in [
            ("grant-approval-invoke", "invoke"),
            // approve/deny both require connection-admin authority, so the
            // decision itself is gated rather than available to any caller who
            // can invoke.
            ("grant-approval-admin", "connection_admin"),
        ] {
            store
                .insert_grant(&plexus_core::GrantInput {
                    grant_id: grant_id.to_string(),
                    principal: "direct".to_string(),
                    connection_id: "conn-approval".to_string(),
                    grantee_principal: "direct".to_string(),
                    risk_ceiling: "write".to_string(),
                    action_selectors: vec!["held_write".to_string()],
                    authority_kind: authority_kind.to_string(),
                    expires_at: None,
                })
                .expect("seed grant");
        }

        let transport = Arc::new(MockTransport::default());
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: ModuleRuntime::with_stub_credentials_and_mock_transport(
                Arc::clone(&store),
                Arc::new(StubCredentialSource::with_default_success(
                    b"mock-credential".to_vec(),
                )),
                transport.clone(),
            ),
        });
        let bindings = Arc::new(RouteBindings::new());
        handle_control_request(
            Frame::build(
                FrameType::Request,
                wire::control_flags(),
                0,
                0,
                7,
                serde_json::to_vec(&ModuleControlRequest::RouteBind {
                    scope: None,
                    call_mode: None,
                    role_versions: None,
                    route_channel: 4,
                    epoch: 2,
                    target: RouteTarget::ToolProvider {
                        module_id: DEFAULT_MODULE_ID.to_string(),
                    },
                    identity: BindIdentity::new(
                        "/tmp/project",
                        "test".to_string(),
                        "session".to_string(),
                    ),
                    principal: Some(Principal::Direct),
                    consumer_capabilities: None,
                    admission_facts: None,
                })
                .expect("serialize bind"),
            )
            .expect("build bind frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("bind succeeds");
        let _bind_ack = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "bind response",
        )
        .await;
        assert_bind_ack(&_bind_ack);

        let tool_frame = |correlation: u64, name: &str, arguments: Value| {
            Frame::build(
                FrameType::Request,
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                4,
                2,
                correlation,
                serde_json::to_vec(&json!({"name": name, "arguments": arguments}))
                    .expect("serialize tool request"),
            )
            .expect("build tool frame")
        };

        // Park two requests: one to deny, one to approve. They are separate
        // rows so neither decision can be satisfied by the other's effect.
        let mut request_ids = Vec::new();
        for (correlation, team) in [(30u64, "alpha"), (31, "beta")] {
            handle_tool_request(
                tool_frame(
                    correlation,
                    manifest::INVOKE_TOOL,
                    json!({
                        "op": "call",
                        "connection": "conn-approval",
                        "action": "held_write",
                        "args": {"team": team}
                    }),
                ),
                &writer,
                &state,
                &bindings,
            )
            .await
            .expect("invoke request succeeds");
            let response = recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "invoke response",
            )
            .await;
            let body: Value = serde_json::from_slice(&response.body).expect("invoke body");
            assert_eq!(
                body["error"]["code"], "consent_unavailable",
                "an unscoped call cannot park a card: {body}"
            );
            // The operator can still approve or deny a held request through
            // the `requests` tool, without any card. An unscoped call can't
            // create one (asserted above), so hold it through internal
            // authorization, then exercise the admin tool and listing below.
            let created_id = match state.runtime.engine.authorize(AuthorizationRequest::new(
                "direct",
                "conn-approval",
                "held_write",
                json!({"team":team}),
            )) {
                Err(plexus_core::Denial::ActionRequestCreated { request_id }) => request_id,
                other => panic!("operator approval was not parked: {other:?}"),
            };
            let denial_body = denial_response(&plexus_core::Denial::ActionRequestCreated {
                request_id: created_id.clone(),
            });
            assert_eq!(
                denial_body["error"]["request_id"],
                json!(created_id),
                "the denial must name the parked request"
            );
            let request_id = store
                .list_action_requests("direct")
                .expect("read requests")
                .into_iter()
                .find(|request| request.args_snapshot["team"] == json!(team))
                .map(|request| request.request_id)
                .unwrap_or_else(|| panic!("the parked request for {team} is not listed"));
            assert_eq!(
                created_id, request_id,
                "the operator's request must be listed"
            );
            request_ids.push(request_id);
        }

        // DENY the first. The request must stop being actionable, and nothing
        // may reach the vendor.
        handle_tool_request(
            tool_frame(
                32,
                manifest::REQUESTS_TOOL,
                json!({"op": "deny", "request_id": request_ids[0]}),
            ),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("deny request succeeds");
        let deny_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "deny response",
        )
        .await;
        let deny_body: Value = serde_json::from_slice(&deny_response.body).expect("deny body");
        assert_eq!(
            deny_body["result"]["denied"],
            json!(true),
            "deny did not report success: {deny_body}"
        );
        let denied = store
            .list_action_requests("direct")
            .expect("read requests")
            .into_iter()
            .find(|request| request.request_id == request_ids[0])
            .expect("the request row survives the decision");
        assert_eq!(
            denied.status, "denied",
            "the denied request is still actionable: {denied:?}"
        );

        // APPROVE the second, and require the vendor call to actually happen.
        // Approving is the only path here that can produce one, so a transport
        // request is unambiguous evidence the engine acted on THIS row.
        let pending = store
            .list_action_requests("direct")
            .expect("read requests")
            .into_iter()
            .find(|request| request.request_id == request_ids[1])
            .expect("the second request is present");
        assert_eq!(
            pending.status, "pending",
            "the second request must still be awaiting a decision: {pending:?}"
        );
        handle_tool_request(
            tool_frame(
                33,
                manifest::REQUESTS_TOOL,
                json!({"op": "approve", "request_id": request_ids[1]}),
            ),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("approve request succeeds");
        let approve_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "approve response",
        )
        .await;
        let approve_body: Value =
            serde_json::from_slice(&approve_response.body).expect("approve body");
        assert!(
            approve_body["error"].is_null(),
            "approve failed: {approve_body}"
        );

        assert_eq!(
            transport.requests().len(),
            1,
            "approve must contact the vendor exactly once"
        );
        assert_eq!(
            transport.requests()[0].args["team"],
            "beta",
            "approve must dispatch the named request's arguments"
        );

        // A consumed row also proves the approval cannot be used twice.
        let decided = store
            .list_action_requests("direct")
            .expect("read requests")
            .into_iter()
            .find(|request| request.request_id == request_ids[1])
            .expect("the approved request survives the decision");
        assert_eq!(
            decided.status, "consumed",
            "the approved request was not dispatched: {decided:?}"
        );

        // Approving it again must name the used approval, not a lapsed window.
        handle_tool_request(
            tool_frame(
                34,
                manifest::REQUESTS_TOOL,
                json!({"op": "approve", "request_id": request_ids[1]}),
            ),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("second approve request succeeds");
        let again_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "second approve response",
        )
        .await;
        let again_body: Value =
            serde_json::from_slice(&again_response.body).expect("second approve body");
        assert_eq!(
            again_body["error"]["code"],
            json!("approval_consumed"),
            "a second approve must be refused as consumed: {again_body}"
        );

        // The denied request must NOT have moved with it: each decision acts on
        // the row the caller named, not on whatever is pending.
        let untouched = store
            .list_action_requests("direct")
            .expect("read requests")
            .into_iter()
            .find(|request| request.request_id == request_ids[0])
            .expect("the denied request is still present");
        assert_eq!(
            untouched.status, "denied",
            "approving one request changed another: {untouched:?}"
        );
    }
}

#[cfg(test)]
mod connection_admin_tests {
    use super::*;
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{BindIdentity, RouteTarget};

    /// Configure and revoke take effect on the connection the caller named.
    ///
    /// Revoke matters most here, and not because it is destructive — because it
    /// WITHDRAWS authority. An operator who suspects a credential is compromised
    /// and hits revoke must actually lose the connection; a revoke that reports
    /// success while the connection stays active is worse than no button at
    /// all, because it ends the operator's search for a problem that is still
    /// live. Without this test, pointing the handler's store call at a
    /// different connection id left the whole module suite green.
    ///
    /// Configure carries the write-enabling filters. A connection starts with
    /// empty filters and writes require a non-empty `write_enabling` set, so a
    /// handler that drops the caller's filters leaves every write permanently
    /// refused — a capability that reads as configured and is not.
    ///
    /// Both assertions inspect STORED STATE rather than the response, so a
    /// handler that answers successfully while writing nothing still fails.
    #[tokio::test]
    async fn configure_and_revoke_take_effect_on_the_named_connection() {
        let (writer, mut responses) = mpsc::channel(8);
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("conn-admin-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));

        // Configure validates the requested filters against the vendor's
        // declared selectors, so the manifest has to be in the catalog or the
        // op refuses before reaching the store write under test.
        let ingested = test_write_manifest("configure_fixture", "https://example.invalid/mcp");
        store
            .upsert_manifest("system", &ingested)
            .expect("seed manifest");
        let app_key = ingested.manifest.key.clone();

        // Two connections, so a handler acting on "the only one there is"
        // cannot pass: each decision must land on the id the caller named.
        for connection_id in ["conn-target", "conn-bystander"] {
            store
                .insert_connection(
                    "direct",
                    connection_id,
                    &app_key,
                    "active",
                    &json!({"required": [], "optional": ["team"], "write_enabling": []}),
                )
                .expect("seed connection");
            store
                .insert_grant(&plexus_core::GrantInput {
                    grant_id: format!("grant-admin-{connection_id}"),
                    principal: "direct".to_string(),
                    connection_id: connection_id.to_string(),
                    grantee_principal: "direct".to_string(),
                    risk_ceiling: "write".to_string(),
                    action_selectors: vec!["*".to_string()],
                    authority_kind: "connection_admin".to_string(),
                    expires_at: None,
                })
                .expect("seed admin grant");
        }

        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        });
        state
            .runtime
            .mcp_transport
            .register_connection(plexus_core::McpConnection::new(
                "conn-target",
                "http://127.0.0.1:1",
            ));
        state
            .runtime
            .rest_transport
            .register_connection(plexus_core::RestConnection::new(
                "conn-target",
                "http://127.0.0.1:1",
            ));
        let bindings = Arc::new(RouteBindings::new());
        handle_control_request(
            Frame::build(
                FrameType::Request,
                wire::control_flags(),
                0,
                0,
                7,
                serde_json::to_vec(&ModuleControlRequest::RouteBind {
                    scope: None,
                    call_mode: None,
                    role_versions: None,
                    route_channel: 4,
                    epoch: 2,
                    target: RouteTarget::ToolProvider {
                        module_id: DEFAULT_MODULE_ID.to_string(),
                    },
                    identity: BindIdentity::new(
                        "/tmp/project",
                        "test".to_string(),
                        "session".to_string(),
                    ),
                    principal: Some(Principal::Direct),
                    consumer_capabilities: None,
                    admission_facts: None,
                })
                .expect("serialize bind"),
            )
            .expect("build bind frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("bind succeeds");
        let _bind_ack = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "bind response",
        )
        .await;
        assert_bind_ack(&_bind_ack);

        let tool_frame = |correlation: u64, arguments: Value| {
            Frame::build(
                FrameType::Request,
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                4,
                2,
                correlation,
                serde_json::to_vec(&json!({
                    "name": manifest::CONNECTIONS_TOOL,
                    "arguments": arguments
                }))
                .expect("serialize tool request"),
            )
            .expect("build tool frame")
        };
        // `connection()` rather than the list projection, because the list
        // deliberately omits resource filters and this test's whole subject is
        // whether the caller's filters landed.
        let connection_of = |store: &PlexusStore, id: &str| {
            store
                .connection("direct", id)
                .expect("read connection")
                .unwrap_or_else(|| panic!("connection {id} is missing"))
        };

        handle_tool_request(
            tool_frame(
                40,
                json!({
                    "op": "configure",
                    "connection": "conn-target",
                    "resource_filters": {"write_enabling": ["team"]}
                }),
            ),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("configure request succeeds");
        let configure_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "configure response",
        )
        .await;
        let configure_body: Value =
            serde_json::from_slice(&configure_response.body).expect("configure body");
        assert!(
            configure_body["error"].is_null(),
            "configure failed: {configure_body}"
        );
        assert_eq!(
            connection_of(&store, "conn-target").resource_filters["write_enabling"],
            json!(["team"]),
            "the caller's write-enabling filters did not reach the store"
        );
        assert_eq!(
            connection_of(&store, "conn-bystander").resource_filters["write_enabling"],
            json!([]),
            "configuring one connection changed another"
        );

        handle_tool_request(
            tool_frame(41, json!({"op": "revoke", "connection": "conn-target"})),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("revoke request succeeds");
        let revoke_response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "revoke response",
        )
        .await;
        let revoke_body: Value =
            serde_json::from_slice(&revoke_response.body).expect("revoke body");
        assert!(
            revoke_body["error"].is_null(),
            "revoke failed: {revoke_body}"
        );
        assert_eq!(
            connection_of(&store, "conn-target").status,
            "revoked",
            "the connection survived its own revocation"
        );
        assert!(
            !state.runtime.mcp_transport.has_connection("conn-target"),
            "revocation must unregister MCP configuration"
        );
        assert!(
            !state.runtime.rest_transport.has_connection("conn-target"),
            "revocation must unregister REST configuration"
        );
        assert_eq!(
            connection_of(&store, "conn-bystander").status,
            "active",
            "revoking one connection revoked another"
        );
    }
}

#[cfg(test)]
mod pool_sweep_tests {
    use super::*;

    /// The scheduler must STAMP each pass, not merely have a stamp available.
    ///
    /// Found by enumerating every state mutator on `HealthState` and asking
    /// which had a call-site test, after the same gap appeared three times
    /// separately: a health field is written by one production line, and every
    /// test that reads the field writes it too, so deleting that line changes
    /// nothing anyone asserts.
    ///
    /// The failure direction here is a FALSE ALARM rather than a false
    /// all-clear, which is why it would have survived review: without the
    /// stamp, `schedulerPassAgeMs` counts from module start and grows forever,
    /// so a perfectly healthy scheduler reports the exact signature of a wedged
    /// one. That makes the field worse than absent — it is the only thing that
    /// can diagnose a stuck pass, and a liveness flag cannot, because a stuck
    /// task is still a live one.
    ///
    /// Asserted against a real spawned scheduler and a generous bound: the tick
    /// is one second, so a stamping scheduler reports well under 1500ms while
    /// an unstamped one reports the full time since construction.
    ///
    /// Mutation-proved: deleting the `stamp_scheduler_pass()` call from the
    /// tick fails this while the rest of the suite stays green.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_spawned_scheduler_stamps_each_pass() {
        use subc_protocol::session::ModuleControlResponse;

        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("pass-stamp-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        });

        let (shutdown, stop) = mpsc::channel::<()>(1);
        let task = spawn_trigger_scheduler(
            Arc::clone(&state),
            stop,
            DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY,
        );
        // Long enough that an unstamped age is unambiguously larger than a
        // stamped one, rather than a difference that could be scheduling noise.
        tokio::time::sleep(std::time::Duration::from_millis(2_500)).await;

        let ModuleControlResponse::HealthCheck { metrics, .. } = state.health.report() else {
            panic!("expected a health check response");
        };
        let age = metrics
            .expect("metrics present")
            .get("schedulerPassAgeMs")
            .and_then(serde_json::Value::as_u64)
            .expect("schedulerPassAgeMs present");
        assert!(
            age < 1_500,
            "pass age {age}ms means the scheduler is not stamping its passes, so a \
             healthy scheduler reports the signature of a wedged one"
        );

        drop(shutdown);
        task.await.expect("scheduler task joins");
    }

    /// The scheduler task must actually RUN the pool sweep.
    ///
    /// `sweep_idle` is proven correct in plexus-core, and it had ZERO callers
    /// anywhere in the workspace before this: a maintenance operation nobody
    /// scheduled, which meant `idle_timeout` described behaviour that never
    /// happened and a pooled client outlived the connection that created it.
    /// Proving the sweep works says nothing about whether anything invokes it:
    /// a correct mechanism nobody calls is indistinguishable from an absent
    /// one, so the call site needs its own test.
    ///
    /// Observes the effect through a REALLY SPAWNED scheduler rather than by
    /// reading the source: an entry is pooled, and the task must remove it
    /// without anyone calling the sweep by hand.
    ///
    /// Uses a deliberately tiny `idle_timeout` because this test asks only
    /// whether the sweep is INVOKED. Whether the eviction predicate is right —
    /// that an entry past the production timeout goes and a leased one stays —
    /// is proven in plexus-core against the real default. Splitting it that way
    /// keeps this test measured in ticks rather than minutes.
    ///
    /// Mutation-proved: deleting the `sweep_idle` calls from the tick leaves
    /// the entry pooled and fails this test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_spawned_scheduler_sweeps_the_transport_pools() {
        use plexus_core::Transport as _;

        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("pool-sweep-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));

        let mcp_transport = Arc::new(plexus_core::McpRemoteTransport::default());
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: ModuleRuntime::with_stub_credentials_and_mcp_transport(
                Arc::clone(&store),
                Arc::new(StubCredentialSource::with_default_success(
                    b"unused".to_vec(),
                )),
                Arc::clone(&mcp_transport),
                None,
            ),
        });

        // Pool an entry. The endpoint never resolves, which is fine: the pool
        // entry is created before the request is attempted, and a failed
        // dispatch leaves exactly the idle entry this test is about.
        let mut config = plexus_core::McpRemoteConfig::new("https://vendor.invalid/mcp");
        config.idle_timeout = std::time::Duration::from_millis(1);
        mcp_transport.register_connection(plexus_core::McpConnection {
            connection_id: "pooled".to_string(),
            config,
        });
        // Wrapped exactly as production wraps every transport call: this is
        // `reqwest::blocking`, and dropping its runtime on an async worker
        // panics. Without the wrapper this test panics in its own setup, which
        // is a useful demonstration that the hazard is immediate rather than
        // theoretical.
        blocking_section(|| {
            let _ = mcp_transport.dispatch(
                plexus_core::TransportRequest {
                    request_id: "sweep-test".to_string(),
                    connection_id: "pooled".to_string(),
                    action: "read_tool".to_string(),
                    args: json!({}),
                    credential_fingerprint: "fp".to_string(),
                },
                &plexus_core::ResolvedCredential::new(b"unused".to_vec(), None, 1),
            );
        });
        assert_eq!(
            mcp_transport.connection_count(),
            1,
            "nothing was pooled, so the assertion below would pass vacuously"
        );

        // Wait past the pooled entry's idle timeout BEFORE the scheduler
        // starts.
        //
        // The sweep begins due, so its first pass runs within a millisecond or
        // two of the entry being pooled. `sweep_idle` compares elapsed idle
        // time against the timeout, so at that instant the entry is legitimately
        // still fresh and is kept -- correctly. The pass then consumes the sweep
        // window and the next one is sixty seconds away, long past when this
        // test gives up.
        //
        // So the original test passed only when the first tick happened to land
        // more than a millisecond after pooling, which is most of the time and
        // not all of it: it failed roughly one run in six here and failed in CI.
        // The race is in the test's ordering, not in the sweep -- the entry was
        // not yet idle when the only sweep it would ever see ran.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let (shutdown, stop) = mpsc::channel::<()>(1);
        let task = spawn_trigger_scheduler(
            Arc::clone(&state),
            stop,
            DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY,
        );
        // One tick is enough because the sweep starts due rather than waiting
        // a full interval.
        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;

        assert_eq!(
            mcp_transport.connection_count(),
            0,
            "the scheduler tick must sweep idle pooled connections"
        );

        drop(shutdown);
        task.await.expect("scheduler task joins");
    }
}

#[cfg(test)]
mod health_probe_scope_tests {
    use super::*;

    /// The spawned scheduler must probe DEGRADED connections, not only active ones.
    ///
    /// This is the call-site half of the recovery fix. `clear_connection_degraded`
    /// and its use inside `refresh` are proven in plexus-core, and both were
    /// useless while this filter excluded the only connections
    /// with something to recover: a refresh failure sets `degraded`, and the
    /// probe that would succeed and clear it declined to look. Nothing else
    /// re-runs discovery either -- reads return early from the freshness check
    /// and `connect` needs a spent single-use ticket -- so the connection stays
    /// stuck indefinitely with the vendor reachable throughout.
    ///
    /// Uses a REST connector because its discovery is synthesized from the
    /// manifest, so a real probe runs end to end with no vendor and no network.
    /// The probe is observed through a spawned scheduler, because a correct
    /// probe function with no reachable scheduler caller cannot recover anyone.
    ///
    /// Mutation-proved: removing the scheduler tick's `run_health_probes` call
    /// leaves this row degraded and fails this test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_spawned_scheduler_probes_degraded_connections() {
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("probe-scope-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));

        let manifest_source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/exa_rest.jsonc"),
        )
        .expect("read rest manifest");
        let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize jsonc");
        let ingested = plexus_core::ingest_value(
            serde_json::from_str::<serde_json::Value>(&normalized).expect("parse manifest"),
        )
        .expect("ingest manifest");
        store
            .upsert_manifest("system", &ingested)
            .expect("store manifest");
        store
            .insert_connection(
                "direct",
                "conn-rest",
                &ingested.manifest.key,
                "pending",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("connection");
        // The manifest declares api_key auth, so the probe resolves a
        // credential before it can reach discovery. Bound through the real
        // ticket path rather than by writing the column, so the test exercises
        // the same shape production does.
        let ticket = store
            .create_binding_ticket("direct", "conn-rest", b"test:probe-scope-test-handle")
            .expect("binding ticket");
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("consume ticket")
            .expect("connection activated");
        store
            .set_connection_health(
                "direct",
                "conn-rest",
                "degraded",
                &json!({"reason": "catalog_refresh_failed"}),
            )
            .expect("mark degraded");

        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        });
        let (shutdown, stop) = mpsc::channel::<()>(1);
        let task = spawn_trigger_scheduler(
            Arc::clone(&state),
            stop,
            DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY,
        );
        // The first probe is due immediately; wait one scheduler tick so the
        // spawned task, rather than this test, performs the recovery.
        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
        let status = store
            .connection("direct", "conn-rest")
            .expect("read")
            .expect("row")
            .status;
        drop(shutdown);
        task.await.expect("scheduler task joins");

        assert_eq!(
            status, "active",
            "the scheduler's health probe must reach a degraded connection and recover it"
        );
    }

    /// The probe must PUBLISH what it counted, not merely count it.
    ///
    /// `stamp_connections` and the null-until-observed rule are proven in
    /// health.rs, and both are worthless if nothing calls them: deleting the
    /// stamp from `run_health_probes` left the entire module suite green,
    /// because those tests stamp the counts themselves. This observes the
    /// numbers through a real probe over a real connection instead.
    ///
    /// The point is operator-facing. Without it, a claim like "the live
    /// connector is unaffected by this deploy" can only be taken on the word of
    /// whoever made it; with it, the health report answers the question.
    ///
    /// Mutation-proved: dropping the `stamp_connections` call from
    /// `run_health_probes` fails this while every other test stays green.
    #[test]
    fn the_health_probe_publishes_the_connection_counts() {
        use subc_protocol::session::ModuleControlResponse;

        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("probe-counts-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));

        let manifest_source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/exa_rest.jsonc"),
        )
        .expect("read rest manifest");
        let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize jsonc");
        let ingested = plexus_core::ingest_value(
            serde_json::from_str::<serde_json::Value>(&normalized).expect("parse manifest"),
        )
        .expect("ingest manifest");
        store
            .upsert_manifest("system", &ingested)
            .expect("store manifest");
        store
            .insert_connection(
                "direct",
                "conn-rest",
                &ingested.manifest.key,
                "pending",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("connection");
        let ticket = store
            .create_binding_ticket("direct", "conn-rest", b"test:probe-counts-test-handle")
            .expect("binding ticket");
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("consume ticket")
            .expect("connection activated");
        store
            .set_connection_health(
                "direct",
                "conn-rest",
                "degraded",
                &json!({"reason": "catalog_refresh_failed"}),
            )
            .expect("mark degraded");

        let state = ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        };

        // Guard against a vacuous pass: before the probe the counts must be
        // null, so a green assertion below cannot come from a stale default.
        let ModuleControlResponse::HealthCheck { metrics, .. } = state.health.report() else {
            panic!("expected a health check response");
        };
        assert_eq!(
            metrics.expect("metrics").get("connections"),
            Some(&serde_json::Value::Null),
            "the fixture must start unobserved"
        );

        run_health_probes(&state);

        let ModuleControlResponse::HealthCheck { metrics, .. } = state.health.report() else {
            panic!("expected a health check response");
        };
        let metrics = metrics.expect("metrics present");
        assert_eq!(
            metrics
                .get("connections")
                .and_then(serde_json::Value::as_u64),
            Some(1),
            "the probe counted a connection but did not publish it"
        );
        // Counted from the rows as they stood at the start of the pass. The
        // probe RECOVERS this connection, so a count taken afterwards would
        // report zero degraded and hide the condition that prompted the work.
        assert_eq!(
            metrics
                .get("connectionsDegraded")
                .and_then(serde_json::Value::as_u64),
            Some(1),
            "the degraded count must describe what the pass set out to check"
        );
    }

    /// The WHOLE recovery chain, asserted end to end on a production-shaped
    /// fixture rather than link by link.
    ///
    /// Each link is tested on its own elsewhere, and that is exactly what made
    /// an earlier claim about this wrong: reasoning "the probe runs, so
    /// reconcile runs, so ask_first is rewritten" skipped over the fact that
    /// the probe declined to look at degraded connections at all. A chain of
    /// individually-correct links is not a working chain.
    ///
    /// The fixture is the state a store can be in after migration 8:
    /// a connection stuck `degraded` from an earlier refresh failure, and a
    /// read action whose `ask_first` still carries the migration's fail-closed
    /// default of 1. Both must clear from one probe, because that is precisely
    /// what a restage is expected to fix.
    #[test]
    fn one_probe_clears_both_the_degraded_status_and_the_ask_first_default() {
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("probe-chain-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));

        let manifest_source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/exa_rest.jsonc"),
        )
        .expect("read rest manifest");
        let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize jsonc");
        let ingested = plexus_core::ingest_value(
            serde_json::from_str::<serde_json::Value>(&normalized).expect("parse manifest"),
        )
        .expect("ingest manifest");
        let action_name = ingested.manifest.actions_baseline[0].name.clone();
        store
            .upsert_manifest("system", &ingested)
            .expect("store manifest");
        store
            .insert_connection(
                "direct",
                "conn-rest",
                &ingested.manifest.key,
                "pending",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("connection");
        let ticket = store
            .create_binding_ticket("direct", "conn-rest", b"test:probe-chain-test-handle")
            .expect("binding ticket");
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("consume ticket")
            .expect("connection activated");

        // Reproduce what migration 8 leaves behind: it added the `ask_first`
        // column with a fail-closed default of 1, so every pre-existing row
        // — including reads that never asked before — comes back asking for
        // approval until a refresh recomputes the value from the manifest.
        store
            .upsert_catalog_action(&plexus_core::CatalogActionInput {
                connection_id: "conn-rest".to_string(),
                principal: "direct".to_string(),
                name: action_name.clone(),
                title: None,
                schema: json!({"type": "object"}),
                schema_hash: "sha256:stale".to_string(),
                risk: "read".to_string(),
                severity: "S1".to_string(),
                ask_first: true,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("seed migrated row");
        store
            .set_connection_health(
                "direct",
                "conn-rest",
                "degraded",
                &json!({"reason": "catalog_refresh_failed"}),
            )
            .expect("mark degraded");

        // Both halves of the stuck state must really be present, or the
        // assertions below would pass without the fix doing anything.
        assert_eq!(
            store
                .connection("direct", "conn-rest")
                .expect("read")
                .expect("row")
                .status,
            "degraded"
        );
        assert!(
            store
                .catalog_action("direct", "conn-rest", &action_name)
                .expect("read")
                .expect("row")
                .ask_first,
            "the fixture must start from the migrated fail-closed default"
        );

        let state = ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(Arc::clone(&store)),
        };
        run_health_probes(&state);

        assert_eq!(
            store
                .connection("direct", "conn-rest")
                .expect("read")
                .expect("row")
                .status,
            "active",
            "the probe must clear the degraded status"
        );
        assert!(
            !store
                .catalog_action("direct", "conn-rest", &action_name)
                .expect("read")
                .expect("row")
                .ask_first,
            "the same probe must rewrite ask_first from the manifest, or a read \
             keeps asking for approval after the connection recovers"
        );
    }

    /// The scheduler must not run a health probe on every one-second tick.
    ///
    /// First observe the start-due probe over an empty store, then add a pending
    /// connection. Pending connections are counted but never contacted, so a
    /// second probe would change only the published count and makes the interval
    /// gate observable without waiting sixty seconds or using a vendor.
    ///
    /// Mutation-proved: removing the `health_probe_due` gate updates the count
    /// to one on the next tick and fails this test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_spawned_scheduler_gates_health_probes_to_their_interval() {
        use subc_protocol::session::ModuleControlResponse;

        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("probe-interval-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));
        let health = Arc::new(health::HealthState::new());
        let state = Arc::new(ModuleState {
            health: Arc::clone(&health),
            runtime: runtime_for_test(Arc::clone(&store)),
        });
        let (shutdown, stop) = mpsc::channel::<()>(1);
        let task = spawn_trigger_scheduler(
            state,
            stop,
            DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY,
        );

        let initial_metrics = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                health.stamp_heartbeat();
                let ModuleControlResponse::HealthCheck { metrics, .. } = health.report() else {
                    unreachable!("HealthState always returns a health check response");
                };
                let metrics = metrics.expect("health report includes metrics");
                if !metrics["connections"].is_null() {
                    break metrics;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the start-due scheduler probe runs");
        assert_eq!(
            initial_metrics["connections"],
            json!(0),
            "the initial probe must observe the empty store before the gate is tested"
        );

        store
            .insert_connection(
                "direct",
                "conn-pending",
                "unused-app",
                "pending",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("seed pending connection");
        // Wait beyond one scheduler tick. An ungated probe would now publish the
        // pending row; a correctly gated probe keeps the initial observation.
        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
        health.stamp_heartbeat();
        let ModuleControlResponse::HealthCheck { metrics, .. } = health.report() else {
            unreachable!("HealthState always returns a health check response");
        };
        let metrics = metrics.expect("health report includes metrics");
        drop(shutdown);
        task.await.expect("scheduler task joins");

        assert_eq!(
            metrics["connections"],
            json!(0),
            "the next one-second tick must not run another health probe"
        );
    }
}

#[cfg(test)]
mod health_handler_tests {
    use super::*;

    /// A health-check handler must report state without probing a recoverable connection.
    ///
    /// The handler runs inline on the dispatch loop and the supervisor waits only
    /// five seconds for its response. A sequential vendor probe belongs on the
    /// scheduler task: answering this request must leave a connection that needs
    /// recovery unchanged while still returning a fresh, populated health report.
    ///
    /// Mutation-proved: restoring `run_health_probes` in the HealthCheck arm
    /// recovers this REST connection and fails the unchanged-status assertion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_health_check_reports_without_probing_recoverable_connections() {
        use subc_protocol::session::{HealthStatus, ModuleControlResponse};

        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("handler-without-probe-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));
        let manifest_source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/exa_rest.jsonc"),
        )
        .expect("read rest manifest");
        let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize jsonc");
        let ingested = plexus_core::ingest_value(
            serde_json::from_str::<serde_json::Value>(&normalized).expect("parse manifest"),
        )
        .expect("ingest manifest");
        store
            .upsert_manifest("system", &ingested)
            .expect("store manifest");
        store
            .insert_connection(
                "direct",
                "conn-rest",
                &ingested.manifest.key,
                "pending",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("connection");
        let ticket = store
            .create_binding_ticket("direct", "conn-rest", b"test:handler-without-probe-handle")
            .expect("binding ticket");
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("consume ticket")
            .expect("connection activated");
        store
            .set_connection_health(
                "direct",
                "conn-rest",
                "degraded",
                &json!({"reason": "catalog_refresh_failed"}),
            )
            .expect("mark degraded");

        let (writer, mut responses) = mpsc::channel(4);
        let health = Arc::new(health::HealthState::new());
        let state = Arc::new(ModuleState {
            health: Arc::clone(&health),
            runtime: runtime_for_test(Arc::clone(&store)),
        });
        let frame = Frame::build(
            FrameType::Request,
            wire::control_flags(),
            0,
            0,
            77,
            serde_json::to_vec(&subc_protocol::session::ModuleControlRequest::HealthCheck {})
                .expect("serialize health check"),
        )
        .expect("build health check frame");

        handle_control_request(frame, &writer, &state, &Arc::new(RouteBindings::new()))
            .await
            .expect("health check handled");

        let response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "health response frame",
        )
        .await;
        let body: ModuleControlResponse =
            serde_json::from_slice(&response.body).expect("health response body");
        let ModuleControlResponse::HealthCheck {
            status,
            detail,
            metrics,
        } = body
        else {
            panic!("expected a health check response");
        };
        assert_eq!(
            status,
            HealthStatus::Ok,
            "health check reports cached state; detail={detail:?}"
        );
        let metrics = metrics.expect("health report includes metrics");

        assert!(
            metrics.get("schedulerAlive").is_some(),
            "the response must carry the regular health metrics: {metrics}"
        );
        assert_eq!(
            store
                .connection("direct", "conn-rest")
                .expect("read")
                .expect("row")
                .status,
            "degraded",
            "answering health.check must not perform the recovery probe"
        );
    }
}

#[cfg(test)]
mod scheduler_liveness_tests {
    use super::*;

    /// A scheduler with active work that fails every poll must differ from an
    /// idle scheduler even when both remain alive and keep their heartbeat fresh.
    /// Drive the real scheduler so missing counter updates cannot pass the test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failing_scheduler_is_distinguishable_from_an_idle_one() {
        let health = Arc::new(health::HealthState::new());
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("sched-outcomes-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));

        // A non-operator subscription with no audit history proves the spawned
        // tick discovers owners from live scheduler state. Its mock transport
        // returns a vendor failure while the credential path succeeds, leaving
        // the subscription active for later retries. That is the shape of a real
        // broken connector, and it is what used to render as idleness.
        let subscription_owner = "subscription-owner";
        let manifest_source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github.jsonc"),
        )
        .expect("read the shipped github manifest");
        let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize manifest");
        let ingested = plexus_core::ingest_value(
            serde_json::from_str::<Value>(&normalized).expect("parse manifest"),
        )
        .expect("ingest manifest");
        store
            .upsert_manifest("system", &ingested)
            .expect("seed manifest");
        store
            .insert_connection(
                subscription_owner,
                "conn-sched",
                &ingested.manifest.key,
                "pending",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("seed connection");
        let ticket = store
            .create_binding_ticket(subscription_owner, "conn-sched", b"test:mock-handle")
            .expect("bind mock credential handle");
        store
            .connect_with_ticket(subscription_owner, &ticket.ticket_id)
            .expect("consume initial ticket")
            .expect("activate scheduler fixture");
        store
            .upsert_catalog_action(&plexus_core::CatalogActionInput {
                connection_id: "conn-sched".to_string(),
                principal: subscription_owner.to_string(),
                name: "list_issues".to_string(),
                title: None,
                // The argument names GitHub's MCP server declares for
                // list_issues, which include the shipped poll shape's request
                // constants; governance refuses an undeclared argument, and
                // this poll must reach the failing vendor.
                schema: json!({
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string"},
                        "repo": {"type": "string"},
                        "after": {"type": "string"},
                        "direction": {"type": "string"},
                        "orderBy": {"type": "string"},
                        "perPage": {"type": "number"},
                        "since": {"type": "string"},
                        "state": {"type": "string"}
                    }
                }),
                schema_hash: "sha256:sched-outcomes".to_string(),
                risk: "read".to_string(),
                severity: "S1".to_string(),
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
                ask_first: false,
            })
            .expect("seed catalog action");
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "grant-sched-outcomes".to_string(),
                principal: subscription_owner.to_string(),
                connection_id: "conn-sched".to_string(),
                grantee_principal: subscription_owner.to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["list_issues".to_string()],
                authority_kind: "poll".to_string(),
                expires_at: Some(i64::MAX / 2),
            })
            .expect("seed poll grant");
        store
            .subscribe_with_cursor_state(
                subscription_owner,
                "conn-sched",
                "list_issues",
                1,
                &json!({}),
                &json!({"owner": "cortexkit", "repo": "plexus"}),
            )
            .expect("subscribe")
            .expect("the shipped manifest must be subscribable");
        assert!(
            store
                .list_audit(subscription_owner)
                .expect("read audit history")
                .is_empty(),
            "the scheduler owner must have no audit rows before the call-site check"
        );

        let transport = Arc::new(MockTransport::default());
        transport.set_response(plexus_core::transport::MockResponse::VendorError {
            code: "vendor_down".to_string(),
            message: "vendor is unavailable".to_string(),
        });
        let state = Arc::new(ModuleState {
            health: Arc::clone(&health),
            runtime: ModuleRuntime::with_stub_credentials_and_mock_transport(
                Arc::clone(&store),
                Arc::new(StubCredentialSource::with_default_success(
                    b"mock-credential".to_vec(),
                )),
                transport,
            ),
        });
        let (shutdown, stop) = mpsc::channel::<()>(1);
        let task = spawn_trigger_scheduler(
            Arc::clone(&state),
            stop,
            DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY,
        );

        // Long enough for at least one tick to select and attempt the
        // subscription.
        tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
        // Cross the real stall threshold without making a scheduler wiring test
        // sleep for fifteen minutes. All other state below still comes from the
        // spawned production task.
        health.backdate_scheduler_success(health::scheduler_stall_threshold_ms_for_test(1) + 1);
        health.stamp_heartbeat();
        let (status, detail, metrics) = match health.report() {
            subc_protocol::session::ModuleControlResponse::HealthCheck {
                status,
                detail,
                metrics,
            } => (status, detail, metrics.expect("metrics present")),
            other => panic!("expected a health check, got {other:?}"),
        };

        drop(shutdown);
        task.await.expect("scheduler task joins");

        assert_eq!(
            metrics["schedulerAlive"],
            json!(true),
            "the control: this scheduler IS alive, which is exactly why the \
             alive flag cannot distinguish these two states"
        );
        assert!(
            metrics["schedulerPollsAttempted"].as_u64().unwrap_or(0) > 0,
            "the scheduler attempted no poll, so this proves nothing about a \
             failing one: {metrics}"
        );
        assert_eq!(
            metrics["schedulerPollsCompleted"],
            json!(0),
            "the configured vendor failure must not complete a poll: {metrics}"
        );
        assert_eq!(
            status,
            subc_protocol::session::HealthStatus::Degraded,
            "the spawned scheduler must feed the active-work side of the stall \
             predicate; deleting that production call must leave this incorrectly ok"
        );
        assert!(
            detail
                .as_deref()
                .is_some_and(|value| value.contains("no poll has completed")),
            "the health detail must identify missing scheduler progress: {detail:?}"
        );
        assert_eq!(
            metrics["schedulerSuccessAgeMs"],
            Value::Null,
            "the success age must stay null until a poll actually succeeds, or \
             never-worked reads as worked-at-boot: {metrics}"
        );
        // The pass-duration gauge shares this test's spawned scheduler rather
        // than getting its own, because what needs proving is identical: that
        // the TICK invokes it. Stamping the gauge directly passes with the call
        // site deleted, which is how an uninvoked mechanism reaches production
        // looking correct.
        //
        // Asserted as non-null rather than as a value, since a real pass takes
        // however long the machine takes. Null here means the tick polled
        // something and never recorded how long it took -- exactly the state
        // that leaves the sequential poller's head-of-line cost unmeasurable.
        assert!(
            !metrics["schedulerPassMaxMs"].is_null(),
            "a pass that attempted a poll must record its duration: {metrics}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    /// Starting and stopping the real scheduler must update its liveness flag;
    /// a standalone guard test would not prove that the task constructs a guard.
    async fn the_spawned_scheduler_holds_a_liveness_guard() {
        let health = Arc::new(health::HealthState::new());
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("sched-liveness-{}", std::process::id()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));
        let state = Arc::new(ModuleState {
            health: Arc::clone(&health),
            runtime: runtime_for_test(store),
        });

        let (shutdown, stop) = mpsc::channel::<()>(1);
        let task = spawn_trigger_scheduler(
            Arc::clone(&state),
            stop,
            DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY,
        );

        // Let the task reach its loop and construct the guard.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        health.stamp_heartbeat();
        let alive = match health.report() {
            subc_protocol::session::ModuleControlResponse::HealthCheck { metrics, .. } => metrics
                .and_then(|value| value["schedulerAlive"].as_bool())
                .unwrap_or(false),
            other => panic!("expected a health check, got {other:?}"),
        };
        assert!(
            alive,
            "a running scheduler must report alive, or the second assertion \
             below would pass for the wrong reason"
        );

        drop(shutdown);
        task.await.expect("scheduler task joins");

        health.stamp_heartbeat();
        let alive_after = match health.report() {
            subc_protocol::session::ModuleControlResponse::HealthCheck { metrics, .. } => metrics
                .and_then(|value| value["schedulerAlive"].as_bool())
                .unwrap_or(false),
            other => panic!("expected a health check, got {other:?}"),
        };
        assert!(
            !alive_after,
            "a stopped scheduler must report dead; the task is not holding a \
             liveness guard"
        );
    }
}

#[cfg(test)]
mod secret_input_tests {
    use super::*;
    use serde_json::json;

    fn args(value: Value) -> serde_json::Map<String, Value> {
        value.as_object().expect("object").clone()
    }

    /// The B1 rule: credential material may only enter through the binding
    /// ceremony, never as a tool argument, because an ordinary tool arg puts a
    /// bearer capability into request bytes, fleet carriage, deserialization
    /// buffers, and span attributes.
    ///
    /// This exists because the guard was previously provable only in the ALLOW
    /// direction: a constant-accept mutation making `contains_secret_input`
    /// always return false broke NO test, so nothing established that it ever
    /// refuses anything. A suite whose vectors all share one expected outcome
    /// cannot distinguish a real implementation from a constant returning it.
    #[test]
    fn secret_shaped_keys_are_rejected_at_the_top_level() {
        for key in [
            "credential_handle",
            "credential",
            "api_token",
            "client_secret",
            "password",
        ] {
            let value = args(json!({ "op": "connect", key: "ckh_pretend_secret" }));
            assert!(
                contains_secret_input(&value),
                "argument key '{key}' must be refused as credential material"
            );
        }
    }

    /// Nesting is the interesting case: a guard that only inspects top-level
    /// keys is trivially bypassed by wrapping the secret one level down.
    #[test]
    fn secret_shaped_keys_are_rejected_when_nested() {
        let nested = args(json!({
            "op": "connect",
            "config": { "auth": { "token": "ckh_pretend_secret" } }
        }));
        assert!(
            contains_secret_input(&nested),
            "a secret nested inside an object must still be refused"
        );

        let in_array = args(json!({
            "op": "connect",
            "items": [ { "ok": 1 }, { "secret": "ckh_pretend_secret" } ]
        }));
        assert!(
            contains_secret_input(&in_array),
            "a secret nested inside an array element must still be refused"
        );
    }

    /// The tests above prove `contains_secret_input` refuses secret-shaped
    /// keys. This one proves it also accepts ordinary arguments: an
    /// implementation that refused everything would pass every test above
    /// while making the facade unusable.
    #[test]
    fn ordinary_arguments_are_not_flagged() {
        let ordinary = args(json!({
            "op": "call",
            "connection": "conn-exa",
            "action": "web_search_exa",
            "args": { "query": "cortexkit", "numResults": 1 },
            "ticket_id": "ticket_abc123"
        }));
        assert!(
            !contains_secret_input(&ordinary),
            "a normal invoke must not be refused as credential material; \
             note ticket_id is deliberately NOT secret-shaped, since the \
             ceremony returns it precisely so the handle never travels"
        );
    }
}

#[cfg(test)]
mod stamp_invoke_tests {
    use super::*;
    use plexus_core::{jcs_sha256, CatalogActionInput, GrantInput};

    fn seeded_runtime(
        label: &str,
    ) -> (ModuleRuntime, Arc<PlexusStore>, Arc<MockTransport>, Scratch) {
        let path = Scratch::database(&format!("stamp-{label}"));
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".to_string(),
                storage_namespace: label.to_string(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .expect("open stamp facade store"),
        );
        store
            .insert_connection(
                "direct",
                "conn-github",
                "github_rest",
                "pending",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("insert stamp connection");
        let handle = b"test:stamp-test-handle";
        let ticket = store
            .create_binding_ticket("direct", "conn-github", handle)
            .expect("create binding ticket");
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("consume binding ticket")
            .expect("activate connection");
        let schema = json!({"type": "object"});
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "conn-github".to_string(),
                principal: "direct".to_string(),
                name: "read_item".to_string(),
                title: Some("Read item".to_string()),
                schema: schema.clone(),
                schema_hash: jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
                risk: "read".to_string(),
                severity: "S1".to_string(),
                ask_first: false,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("insert stamp action");
        store
            .insert_grant(&GrantInput {
                grant_id: "grant-stamp".to_string(),
                principal: "direct".to_string(),
                connection_id: "conn-github".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["read_item".to_string()],
                authority_kind: "invoke".to_string(),
                expires_at: None,
            })
            .expect("insert stamp grant");
        let credentials = Arc::new(StubCredentialSource::default());
        credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
        let transport = Arc::new(MockTransport::default());
        let runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
            Arc::clone(&store),
            credentials,
            Arc::clone(&transport),
        );
        (runtime, store, transport, path)
    }

    fn invoke_frame(correlation: u64) -> Frame {
        let arguments = json!({
            "op": "call",
            "connection": "conn-github",
            "action": "read_item",
            "args": {"query": "safe"}
        });
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            41,
            1,
            correlation,
            serde_json::to_vec(&json!({
                "name": manifest::INVOKE_TOOL,
                "arguments": arguments
            }))
            .expect("serialize stamp invoke"),
        )
        .expect("build stamp invoke")
    }

    async fn invoke(
        runtime: ModuleRuntime,
        frame: Frame,
        scope: Option<subc_protocol::scope::ScopeStamp>,
    ) -> Value {
        let (writer, mut responses) = mpsc::channel(1);
        handle_scoped_tool_request_for_test(frame, &writer, runtime, Principal::Direct, scope)
            .await
            .expect("handle stamp invoke");
        serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "stamp response",
            )
            .await
            .body,
        )
        .expect("stamp response JSON")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bot_request_module_entry_dispatches_through_governed_transport() {
        use plexus_core::credentials::CredentialSource;
        use plexus_core::github::credential::HandleCredentialProvider;
        use plexus_core::governance::GovernanceEngine;
        use plexus_core::storage::github_store::{GithubGovernanceSeams, GithubHandle};
        use plexus_core::transport::Transport;
        use rusqlite::{params, Connection};
        struct Token;
        impl HandleCredentialProvider for Token {
            fn prepare(
                &self,
                _: &str,
                _: i64,
                _: &str,
            ) -> Result<plexus_core::ResolvedCredential, &'static str> {
                Ok(plexus_core::ResolvedCredential::anonymous())
            }
            fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
        }
        let path = Scratch::database("module-facade-dispatch");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "module-facade-dispatch".into(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        store
            .insert_connection(
                "operator",
                "conn-facade",
                "github_rest",
                "active",
                &json!({}),
            )
            .unwrap();
        store
            .put_github_handle(&GithubHandle {
                app_handle_id: "app-fixture".into(),
                agent_id: "agent-fixture".into(),
                app_id: 1,
                installation_id: None,
                credential_reference: "github_app:app-fixture".into(),
                credential_generation: 1,
                status: "enabled".into(),
                proven_at: Some(1),
                connection_principal: "operator".into(),
                connection_id: "conn-facade".into(),
            })
            .unwrap();
        store.bind_github_repo("org/repo", "app-fixture").unwrap();
        let db = Connection::open(path.as_ref()).unwrap();
        db.execute("INSERT INTO catalog_actions (connection_id,principal,name,schema_json,schema_hash,risk,severity,status,first_seen_at_ms,last_seen_at_ms,ask_first)
            VALUES ('conn-facade','operator','add_reaction','{}','schema','write','S1','active',1,1,0)", []).unwrap();
        // The facade sends each call only the arguments the reviewed manifest
        // declares for its action, so the shipped GitHub REST manifest must be
        // stored. Stored directly, so no other catalog row is seeded from it.
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github_rest.jsonc"),
        )
        .unwrap();
        let ingested = plexus_core::ingest_value(
            serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap(),
        )
        .unwrap();
        db.execute(
            "INSERT INTO app_manifests (principal,key,schema_version,content_hash,manifest_json,ingested_at_ms)
             VALUES ('system','github_rest',1,'fixture',?1,1)",
            params![serde_json::to_string(&ingested.manifest).unwrap()],
        )
        .unwrap();
        for (id, agent) in [("module", None), ("agent", Some("agent-fixture"))] {
            db.execute("INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,authority_kind,created_at_ms,action_selectors,agent_id)
                VALUES (?1,'operator','conn-facade','reserved:aft','write','invoke',1,'[\"add_reaction\"]',?2)", params![id, agent]).unwrap();
        }
        let transport = Arc::new(MockTransport::default());
        let mut runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
            store.clone(),
            Arc::new(StubCredentialSource::default()),
            transport.clone(),
        );
        runtime.engine = GovernanceEngine::new(
            store.clone(),
            Arc::new(StubCredentialSource::default()) as Arc<dyn CredentialSource>,
            transport.clone() as Arc<dyn Transport>,
        )
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: Some(Arc::new(Token)),
        }));
        let stamp = subc_protocol::scope::ScopeStamp::new(
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            "bot-session",
            1,
            subc_protocol::scope::ScopeKind::Head,
        )
        .with_attributes(
            subc_protocol::scope::ScopeAttributes::new()
                .with_agent_id(Some("agent-fixture".into()))
                .with_delegates(true),
        )
        .with_owner_authorized(true);
        struct Live(plexus_core::scope::CallScope);
        impl plexus_core::scope::ScopeReader for Live {
            fn describe(
                &self,
                _: &str,
                _: &str,
            ) -> Result<plexus_core::scope::ScopeDescription, plexus_core::scope::ScopeReadError>
            {
                Ok(plexus_core::scope::ScopeDescription {
                    status: plexus_core::scope::ScopeStatus::Live,
                    owner_synced: true,
                    owner_configured: true,
                    live: Some(self.0.clone()),
                })
            }
        }
        runtime.engine = runtime
            .engine
            .with_scope_reader(Arc::new(Live(CallScope::from_stamp(&stamp))));
        let frame = Frame::build_with_version(PROTOCOL_VERSION, FrameType::Request,
            Flags::new(false, Priority::Interactive, false), 41, 1, 99,
            serde_json::to_vec(&json!({"name":manifest::GITHUB_TOOL,"arguments":{
                "op":"bot_request","request_nonce":"module-nonce",
                "request":{"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}}
            }})).unwrap()).unwrap();
        let (writer, mut response) = mpsc::channel(1);
        handle_scoped_tool_request_for_test(
            frame,
            &writer,
            runtime,
            Principal::Reserved {
                module_id: "aft".into(),
            },
            Some(stamp),
        )
        .await
        .unwrap();
        let reply: Value = serde_json::from_slice(
            &recv_within(
                response.recv(),
                std::time::Duration::from_secs(5),
                "expected reply",
            )
            .await
            .body,
        )
        .unwrap();
        assert_eq!(reply["result"]["status"], "completed", "{reply}");
        assert_eq!(transport.requests().len(), 1);
        assert_eq!(transport.requests()[0].action, "add_reaction");
        for (op, nested, secret) in [
            (
                "bot_request",
                json!({"request":{"body":{"api_token":"ckh_pretend_secret"}}}),
                "ckh_pretend_secret",
            ),
            (
                "bindings.read",
                json!({"api_token":"ckh_pretend_secret"}),
                "ckh_pretend_secret",
            ),
        ] {
            let mut arguments = json!({"op":op});
            for (key, value) in nested.as_object().unwrap() {
                arguments[key] = value.clone();
            }
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                41,
                1,
                100,
                serde_json::to_vec(&json!({"name":manifest::GITHUB_TOOL,"arguments":arguments}))
                    .unwrap(),
            )
            .unwrap();
            let (writer, mut response) = mpsc::channel(1);
            handle_tool_request_for_test(
                frame,
                &writer,
                runtime_for_test(store.clone()),
                Principal::Reserved {
                    module_id: "aft".into(),
                },
            )
            .await
            .unwrap();
            let response = String::from_utf8(
                recv_within(
                    response.recv(),
                    std::time::Duration::from_secs(5),
                    "expected reply",
                )
                .await
                .body
                .to_vec(),
            )
            .unwrap();
            let decoded: Value = serde_json::from_str(&response).unwrap();
            assert_eq!(
                decoded["error"]["code"], "secret_input_rejected",
                "{response}"
            );
            assert!(
                !response.contains(secret),
                "secret appeared in refusal response"
            );
        }
        assert_eq!(
            transport.requests().len(),
            1,
            "refused calls never reach transport"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stamped_invoke_sends_only_vendor_args_and_audits_agent() {
        let (runtime, store, transport, _path) = seeded_runtime("stamped");
        let stamp = subc_protocol::scope::ScopeStamp::new(
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            "head-fixture",
            1,
            subc_protocol::scope::ScopeKind::Head,
        )
        .with_attributes(
            subc_protocol::scope::ScopeAttributes::new().with_agent_id(Some("agent_wire".into())),
        )
        .with_owner_authorized(true);
        let response = invoke(runtime, invoke_frame(1), Some(stamp)).await;
        assert_eq!(
            response["result"]["transmission"], "completed",
            "{response}"
        );
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].args, json!({"query": "safe"}));
        assert!(store
            .list_audit("direct")
            .expect("audit rows")
            .iter()
            .any(|row| {
                row.agent_id.as_deref() == Some("agent_wire") && row.agent_handle.is_none()
            }));
        drop(store);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unscoped_invoke_preserves_the_module_principal_path() {
        let (runtime, store, transport, _path) = seeded_runtime("absent");
        let response = invoke(runtime, invoke_frame(3), None).await;
        assert_eq!(
            response["result"]["transmission"], "completed",
            "{response}"
        );
        assert_eq!(transport.requests().len(), 1);
        assert!(store
            .list_audit("direct")
            .expect("audit rows")
            .iter()
            .all(|row| row.agent_id.is_none() && row.agent_handle.is_none()));
        drop(store);
    }

    #[test]
    fn an_absent_audit_retention_window_defaults_to_30_days() {
        let window = audit_retention_window_ms(None).expect("default retention window");
        assert_eq!(window, DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY);
        assert_eq!(DEFAULT_AUDIT_RETENTION_DAYS, 30);
    }

    #[test]
    fn an_unparseable_audit_retention_window_refuses_startup() {
        let error = audit_retention_window_ms(Some(OsString::from("thirty")))
            .expect_err("a stated but unparseable policy must refuse");
        let ModuleError::Message(message) = error else {
            panic!("unexpected error shape");
        };
        assert!(
            message.contains(AUDIT_RETENTION_DAYS_ENV) && message.contains("thirty"),
            "the refusal must name the variable and rejected value: {message}"
        );
    }

    #[test]
    fn an_audit_retention_window_not_greater_than_the_floor_refuses_startup() {
        let configured = AUDIT_DELETE_FLOOR_DAYS.to_string();
        let error = audit_retention_window_ms(Some(OsString::from(configured)))
            .expect_err("a window at the delete floor disables retention");
        let ModuleError::Message(message) = error else {
            panic!("unexpected error shape");
        };
        assert!(
            message.contains(&format!(
                "configured window: {AUDIT_DELETE_FLOOR_DAYS} days"
            )),
            "the refusal must name the configured window: {message}"
        );
        assert!(
            message.contains(&format!("floor: {AUDIT_DELETE_FLOOR_DAYS} days")),
            "the refusal must name the delete floor: {message}"
        );
    }

    // Mutations proved by hand against these three: swapping the release arm
    // to return the dev fallback (the pre-fix behavior) reddens the refusal
    // test; dropping the configured-wins arm reddens the explicit test in
    // both build kinds.
    #[test]
    fn a_configured_catalog_dir_wins_in_both_build_kinds() {
        for dev_fallback_allowed in [true, false] {
            let resolved = catalog_directory(
                Some(std::ffi::OsString::from("/staged/catalog")),
                dev_fallback_allowed,
            )
            .expect("configured directory resolves");
            assert_eq!(resolved, PathBuf::from("/staged/catalog"));
        }
    }

    #[test]
    fn a_dev_build_without_config_falls_back_to_the_repo_tree() {
        let resolved = catalog_directory(None, true).expect("dev fallback resolves");
        assert!(
            resolved.ends_with("catalog"),
            "dev fallback must point at the repository catalog: {resolved:?}"
        );
    }

    #[test]
    fn a_release_build_without_config_refuses_by_name() {
        let error = catalog_directory(None, false).expect_err("release build must refuse");
        let ModuleError::Message(message) = &error else {
            panic!("unexpected error shape: {error:?}");
        };
        assert!(
            message.contains("PLEXUS_CATALOG_DIR"),
            "the refusal must name the missing variable: {message}"
        );
        assert!(
            !message.contains(env!("CARGO_MANIFEST_DIR")),
            "the refusal must not leak the compile-time path as advice"
        );
    }
}

#[cfg(test)]
mod github_read_frame_tests {
    mod issue_flow_tests {
        include!("issue_flow_read_tests.rs");
    }
    mod ci_read_tests {
        include!("ci_read_tests.rs");
    }
    mod job_log_tests {
        include!("job_log_read_tests.rs");
    }
    mod artifact_file_tests {
        include!("artifact_file_read_tests.rs");
    }
    mod review_threads_tests {
        include!("review_threads_read_tests.rs");
    }
    use super::*;
    use plexus_core::github::credential::HandleCredentialProvider;
    use plexus_core::storage::github_store::{
        GithubGovernanceSeams, GithubHandle, GithubImportRow,
    };
    use plexus_core::{ingest_value, MockResponse, ResolvedCredential, CATALOG_PRINCIPAL};

    struct ReadyToken;
    impl HandleCredentialProvider for ReadyToken {
        fn prepare(&self, _: &str, _: i64, _: &str) -> Result<ResolvedCredential, &'static str> {
            Ok(ResolvedCredential::anonymous())
        }
        fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
    }

    pub(super) fn github_manifest() -> plexus_core::IngestedManifest {
        let source = include_str!("../../../catalog/github_rest.jsonc");
        ingest_value(serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap())
            .unwrap()
    }

    pub(super) fn imported_runtime() -> (
        Arc<ModuleState>,
        Arc<PlexusStore>,
        Arc<MockTransport>,
        Scratch,
    ) {
        imported_runtime_with_actions(&[
            "github.issue.get",
            "github.issue_comments.list",
            "github.issue.search",
        ])
    }

    fn imported_runtime_with_actions(
        actions: &[&str],
    ) -> (
        Arc<ModuleState>,
        Arc<PlexusStore>,
        Arc<MockTransport>,
        Scratch,
    ) {
        let scratch = Scratch::database("github-read-frame");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: scratch.to_string_lossy().into_owned(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: scratch.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        store
            .upsert_manifest(CATALOG_PRINCIPAL, &github_manifest())
            .unwrap();
        store
            .import_github_handles(&[GithubImportRow {
                handle: GithubHandle {
                    app_handle_id: "app-x".into(),
                    agent_id: "agent-x".into(),
                    app_id: 1,
                    installation_id: None,
                    credential_reference: "github_app:app-x".into(),
                    credential_generation: 0,
                    status: "enabled".into(),
                    proven_at: None,
                    connection_principal: "direct".into(),
                    connection_id: "github-handle-app-x".into(),
                },
                repositories: vec!["o/x".into()],
                grants: vec![],
                module_actions: actions.iter().map(|action| (*action).to_owned()).collect(),
                policies: vec![],
            }])
            .unwrap();
        let transport = Arc::new(MockTransport::default());
        transport.set_response(MockResponse::Success(json!({"items":[
            {"repository":{"full_name":"o/x"}},
            {"repository":{"full_name":"o/unbound"}}
        ]})));
        let mut runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
            store.clone(),
            Arc::new(StubCredentialSource::default()),
            transport.clone(),
        );
        runtime.engine = runtime
            .engine
            .with_governance_seams(Arc::new(GithubGovernanceSeams {
                store: store.clone(),
                credential_provider: Some(Arc::new(ReadyToken)),
            }));
        (
            Arc::new(ModuleState {
                health: Arc::new(health::HealthState::new()),
                runtime,
            }),
            store,
            transport,
            scratch,
        )
    }

    async fn send_github_read_frame(runtime: Arc<ModuleState>, action: &str) -> Value {
        send_facade_frame(
            runtime,
            manifest::GITHUB_READ_TOOL,
            json!({"repository":["o/x"], "action":action, "args":{"terms":"bug"}}),
            "prefrontal-core",
            None,
        )
        .await
    }

    async fn send_facade_frame(
        runtime: Arc<ModuleState>,
        name: &str,
        arguments: Value,
        module_id: &str,
        scope: Option<subc_protocol::scope::ScopeStamp>,
    ) -> Value {
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            72,
            1,
            701,
            serde_json::to_vec(&json!({
                "name": name,
                "arguments": arguments
            }))
            .unwrap(),
        )
        .unwrap();
        let (writer, mut responses) = mpsc::channel(1);
        let routes = Arc::new(RouteBindings::new());
        routes
            .insert_mode(
                frame.header.channel,
                frame.header.epoch,
                Principal::Reserved {
                    module_id: module_id.into(),
                },
                scope.as_ref().map(CallScope::from_stamp),
                derive_call_mode(scope.as_ref()),
            )
            .unwrap();
        handle_tool_request(frame, &writer, &runtime, &routes)
            .await
            .unwrap();
        serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "expected reply",
            )
            .await
            .body,
        )
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn github_read_returns_the_governed_envelope_for_all_three_actions() {
        for (action, repository, args, vendor_reply, expected) in [
            (
                "github.issue.get",
                json!("o/x"),
                json!({"issue_number":42}),
                json!({"number":42,"title":"a bug"}),
                json!({"number":42,"title":"a bug"}),
            ),
            (
                "github.issue_comments.list",
                json!("o/x"),
                json!({"issue_number":42,"since":"2026-01-01T00:00:00Z"}),
                json!([{ "id": 123, "body": "hello" }]),
                json!([{ "id": 123, "body": "hello" }]),
            ),
            (
                "github.issue.search",
                json!(["o/x"]),
                json!({"terms":"bug"}),
                json!({"items":[{"repository":{"full_name":"o/x"}},{"repository":{"full_name":"o/unbound"}}]}),
                json!({"items":[{"repository":{"full_name":"o/x"}}],"total_count":1,"incomplete":true,"incomplete_results":true}),
            ),
        ] {
            let (runtime, _store, transport, _scratch) = imported_runtime();
            transport.set_response(MockResponse::Success(vendor_reply));
            let arguments = json!({"action":action,"repository":repository,"args":args});
            let reply = send_facade_frame(
                runtime.clone(),
                manifest::GITHUB_READ_TOOL,
                arguments.clone(),
                "prefrontal-core",
                None,
            )
            .await;
            assert_eq!(reply["result"], expected, "{action}: {reply}");
            assert_eq!(reply["isError"], false);
            assert_eq!(reply["content"][0]["type"], "text");
            let text: Value =
                serde_json::from_str(reply["content"][0]["text"].as_str().unwrap()).unwrap();
            assert_eq!(text, json!({"result":expected}));
            if expected.is_object() {
                assert_eq!(reply["structuredContent"], expected);
            } else {
                assert!(reply.get("structuredContent").is_none());
            }
            let requests = transport.requests();
            assert_eq!(
                requests.len(),
                1,
                "{action}: github_read must dispatch exactly once"
            );
            assert_eq!(requests[0].action, action);
            assert_eq!(requests[0].connection_id, "github-handle-app-x");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn github_facade_refuses_removed_read_op_by_name_and_keeps_bindings_read() {
        let (runtime, store, transport, _scratch) = imported_runtime();
        let refused = send_facade_frame(
            runtime.clone(),
            manifest::GITHUB_TOOL,
            json!({"op":"read","action":"github.issue.get","repository":"o/x","args":{"issue_number":42}}),
            "prefrontal-core",
            None,
        )
        .await;
        assert_eq!(refused["error"]["code"], "invalid_operation", "{refused}");
        assert_eq!(refused["error"]["op"], "read", "{refused}");
        assert!(transport.requests().is_empty());

        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "prefrontal-bindings-read".into(),
                principal: "direct".into(),
                connection_id: "github-handle-app-x".into(),
                grantee_principal: "reserved:prefrontal-core".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec![],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
        let bindings = send_facade_frame(
            runtime,
            manifest::GITHUB_TOOL,
            json!({"op":"bindings.read","connection_id":"github-handle-app-x"}),
            "prefrontal-core",
            None,
        )
        .await;
        assert_eq!(bindings["isError"], false, "{bindings}");
        assert_eq!(bindings["result"]["bindings"][0]["repository"], "o/x");
        assert_eq!(bindings["result"]["bindings"][0]["app_handle_id"], "app-x");
        assert!(transport.requests().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn github_read_refuses_write_and_unknown_actions_by_name_before_other_inputs() {
        let (runtime, store, transport, _scratch) = imported_runtime();
        for action in ["add_issue_comment", "unknown_action"] {
            // The action check runs first. A malformed repository and a
            // credential-like argument must not change the refusal to some other
            // error, and nothing may be looked up or written to the audit
            // journal for an action github_read never serves.
            let reply = send_facade_frame(
                runtime.clone(),
                manifest::GITHUB_READ_TOOL,
                json!({"action":action,"repository":null,"args":{"api_token":"ckh_secret"}}),
                "prefrontal-core",
                None,
            )
            .await;
            assert_eq!(reply["error"]["code"], "read_action_unsupported", "{reply}");
            assert_eq!(
                reply["error"]["action"], action,
                "unsupported reads must be refused by action name: {reply}"
            );
            assert!(reply["error"]["message"].as_str().unwrap().contains(action));
            assert_eq!(reply["isError"], true, "a refusal must set isError");
            assert!(!reply.to_string().contains("ckh_secret"));
        }
        assert!(transport.requests().is_empty());
        assert!(store.list_audit("direct").unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn github_read_rejects_extra_or_missing_fields_without_dispatch() {
        let (runtime, store, transport, _scratch) = imported_runtime();
        let valid =
            json!({"action":"github.issue.get","repository":"o/x","args":{"issue_number":42}});
        for field in ["action", "repository", "args", "op", "request"] {
            let mut arguments = valid.clone();
            if matches!(field, "op" | "request") {
                arguments[field] = json!("bot_request");
            } else {
                arguments.as_object_mut().unwrap().remove(field);
            }
            let reply = send_facade_frame(
                runtime.clone(),
                manifest::GITHUB_READ_TOOL,
                arguments,
                "prefrontal-core",
                None,
            )
            .await;
            assert_eq!(
                reply["error"]["code"],
                if field == "action" {
                    "read_action_unsupported"
                } else {
                    "invalid_request"
                },
                "{field}: {reply}"
            );
        }
        assert!(transport.requests().is_empty());
        assert!(store.list_audit("direct").unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn github_read_requires_the_calling_modules_grant() {
        let (runtime, store, transport, _scratch) = imported_runtime();
        let arguments =
            json!({"action":"github.issue.get","repository":"o/x","args":{"issue_number":42}});
        let refused = send_facade_frame(
            runtime.clone(),
            manifest::GITHUB_READ_TOOL,
            arguments.clone(),
            "ungranted-reader",
            None,
        )
        .await;
        // The fixture grants prefrontal-core read access on this bot's
        // connection. A different module with no grant of its own must not
        // borrow that one: it cannot even see the connection.
        assert_eq!(
            refused["error"]["code"], "connection_not_found",
            "{refused}"
        );
        assert!(transport.requests().is_empty());
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "reader-grant".into(),
                principal: "direct".into(),
                connection_id: "github-handle-app-x".into(),
                grantee_principal: "reserved:ungranted-reader".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["github.issue.get".into()],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
        let allowed = send_facade_frame(
            runtime,
            manifest::GITHUB_READ_TOOL,
            arguments,
            "ungranted-reader",
            None,
        )
        .await;
        assert!(allowed.get("result").is_some(), "{allowed}");
        assert_eq!(transport.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delegated_codemode_github_read_keeps_only_module_authority() {
        let (runtime, store, transport, _scratch) = imported_runtime();
        let scope = subc_protocol::scope::ScopeStamp::new(
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            "run-read",
            1,
            subc_protocol::scope::ScopeKind::Worker,
        )
        .with_attributes(
            subc_protocol::scope::ScopeAttributes::new()
                .with_agent_id(Some("agent-x".into()))
                .with_run_id(Some("run-read".into()))
                .with_delegates(true),
        )
        .with_owner_authorized(true);
        let args =
            json!({"action":"github.issue.get","repository":"o/x","args":{"issue_number":42}});
        let reply = crate::call_mode_tests::bound_state_call(
            runtime.clone(),
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            Some(scope.clone()),
            Some(CallMode::Codemode),
            manifest::GITHUB_READ_TOOL,
            args.clone(),
        )
        .await;
        assert!(
            reply.get("result").is_some(),
            "run reads need only module grants: {reply}"
        );
        assert_eq!(transport.requests().len(), 1);
        let rows = store.list_audit("direct").unwrap();
        let rows: Vec<_> = rows
            .iter()
            .filter(|row| {
                row.scope
                    .as_ref()
                    .is_some_and(|scope| scope.scope_ref == "run-read")
            })
            .collect();
        assert_eq!(
            rows.len(),
            2,
            "authorization and dispatch retain run attribution"
        );
        assert!(rows
            .iter()
            .all(|row| row.agent_id.as_deref() == Some("agent-x")));
        let denied = crate::call_mode_tests::bound_state_call(
            runtime.clone(),
            Principal::Reserved {
                module_id: "broca".into(),
            },
            Some(scope),
            Some(CallMode::Codemode),
            manifest::GITHUB_READ_TOOL,
            args,
        )
        .await;
        assert_eq!(
            denied["error"]["code"], "connection_not_found",
            "delegation cannot replace module grants: {denied}"
        );
        assert_eq!(transport.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unscoped_basal_can_read_tool_metadata_but_no_real_tool() {
        let (runtime, _store, transport, _scratch) = imported_runtime();
        let described = send_facade_frame(
            runtime.clone(),
            cortexkit_role_tool_provider::ops::ROLE_DESCRIBE,
            json!({}),
            "basal",
            None,
        )
        .await;
        // Role metadata replies are the bare answer, and a refusal is a bare
        // error body, so check for the answer's own fields, not an "error" key.
        assert!(
            described.get("code").is_none() && described.get("tool_capabilities").is_some(),
            "basal installs read role.describe before any flow scope exists: {described}"
        );
        let catalog = send_facade_frame(
            runtime.clone(),
            cortexkit_role_tool_provider::ops::TOOL_CATALOG,
            json!({"params": {"capabilities": ["plexus:github.react/v1"]}}),
            "basal",
            None,
        )
        .await;
        assert!(
            catalog.get("code").is_none()
                && catalog["tools"]
                    .as_array()
                    .is_some_and(|tools| tools.iter().any(|tool| tool["name"] == "github_react")),
            "basal installs read tool.catalog before any flow scope exists: {catalog}"
        );
        let refused = send_facade_frame(
            runtime,
            manifest::GITHUB_READ_TOOL,
            json!({"action":"github.issue.get","repository":"o/x","args":{"issue_number":42}}),
            "basal",
            None,
        )
        .await;
        assert_eq!(
            refused["error"]["code"], "flow_scope_required",
            "the metadata exemption must not reach real tools: {refused}"
        );
        assert!(transport.requests().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn github_read_requires_flow_scoped_basal_and_dispatches_with_its_grant() {
        let (runtime, store, transport, scratch) = imported_runtime();
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "basal-read".into(),
                principal: "direct".into(),
                connection_id: "github-handle-app-x".into(),
                grantee_principal: "reserved:basal".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["github.issue.get".into()],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
        let arguments =
            json!({"action":"github.issue.get","repository":"o/x","args":{"issue_number":42}});
        let refused = send_facade_frame(
            runtime.clone(),
            manifest::GITHUB_READ_TOOL,
            arguments.clone(),
            "basal",
            None,
        )
        .await;
        assert_eq!(
            refused["error"]["code"], "flow_scope_required",
            "github_read cannot bypass the common flow check: {refused}"
        );
        assert_eq!(refused["error"]["transmission"], "not_sent");
        assert!(transport.requests().is_empty());
        assert!(store.list_audit("direct").unwrap().is_empty());
        let scope = subc_protocol::scope::ScopeStamp::new(
            Principal::Reserved {
                module_id: "basal".into(),
            },
            "read-flow",
            1,
            subc_protocol::scope::ScopeKind::Head,
        )
        .with_attributes(
            subc_protocol::scope::ScopeAttributes::new()
                .with_agent_id(Some("agent-x".into()))
                .with_flow_id(Some("github-read-flow".into())),
        )
        .with_owner_authorized(true);
        let impostor = send_facade_frame(
            runtime.clone(),
            manifest::GITHUB_READ_TOOL,
            arguments.clone(),
            "basal-impostor",
            Some(scope.clone()),
        )
        .await;
        assert_eq!(
            impostor["error"]["code"], "flow_carrier_not_admitted",
            "{impostor}"
        );
        assert!(transport.requests().is_empty());
        let allowed = send_facade_frame(
            runtime,
            manifest::GITHUB_READ_TOOL,
            arguments,
            "basal",
            Some(scope),
        )
        .await;
        assert!(allowed.get("result").is_some(), "{allowed}");
        assert_eq!(allowed["isError"], false);
        assert_eq!(transport.requests().len(), 1);
        let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
        let attributed: i64 = db.query_row(
            "SELECT count(*) FROM audit_journal WHERE scope_flow_id = 'github-read-flow' AND acting_principal = 'reserved:basal'",
            [], |row| row.get(0)).unwrap();
        assert_eq!(
            attributed, 2,
            "authorization and dispatch must attribute the flow"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prefrontal_read_frame_returns_only_bound_search_hits() {
        let (runtime, store, transport, _scratch) = imported_runtime();
        let reply = send_github_read_frame(runtime, "github.issue.search").await;
        assert_eq!(
            reply["result"]["items"],
            json!([{"repository":{"full_name":"o/x"}}]),
            "{reply}"
        );
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].connection_id, "github-handle-app-x");
        assert_eq!(requests[0].args["q"], "bug repo:o/x");
        let rows = store.list_audit("direct").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].request_id, rows[1].request_id);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prefrontal_read_frame_refuses_unsupported_action_by_name() {
        let (runtime, store, transport, _scratch) = imported_runtime();
        let reply = send_github_read_frame(runtime, "add_issue_comment").await;
        assert_eq!(reply["error"]["code"], "read_action_unsupported", "{reply}");
        assert!(transport.requests().is_empty());
        assert!(store.list_audit("direct").unwrap().is_empty());
    }
}

#[cfg(test)]
mod consent_pending_tests {
    use super::*;
    #[test]
    fn pending_consent_has_the_exact_content_v1_shape() {
        let reply = with_call_tool_result(
            Some(manifest::INVOKE_TOOL),
            denial_response(&plexus_core::Denial::AccessPending {
                elicitation_id: "el_42".into(),
                service: "Mock Chat".into(),
                action: "Post a message".into(),
            }),
        );
        let text = "Waiting for the user to approve Mock Chat Post a message. The request has gone to them. End your turn now; you will be resumed with the answer, and then you should run this same call again.";
        assert_eq!(
            reply,
            json!({"isError":true, "content":[{"type":"text","text":text}],
            "structuredContent":{"success":false,"code":"access_pending","message":text,"text":text,"elicitation_id":"el_42"}})
        );
    }
}
