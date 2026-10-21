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
/// The shared stderr-capture helpers, compiled once so every test module uses
/// the same one-time logger initialization. plexus-core's support/audit.rs,
/// which this crate also compiles, declares its own private copy that this
/// crate cannot reach, hence the allowance.
#[cfg(test)]
#[allow(clippy::duplicate_mod)]
#[path = "../../plexus-core/tests/support/logging.rs"]
mod test_logging;
#[cfg(test)]
mod test_support;
#[cfg(test)]
use test_support::{
    assert_bind_ack, facade_tool_reply, run_health_probes, test_mcp_manifest, test_write_manifest,
    with_call_tool_result,
};
mod tool_provider;
mod web_search_health;
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
    /// A worker scope's `on_behalf_of_agent` from the bind stamp: the agent
    /// whose bot serves the worker's GitHub bot reads. Kept beside the scope,
    /// not in it, so nothing that reads the scope's agent can mistake it for
    /// one. It chooses a bot, charges its read budget and limits reads to its
    /// repositories; it grants no write and no authority to act as the agent.
    on_behalf_of_agent: Option<String>,
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

    #[cfg(any(test, feature = "test-support"))]
    fn insert_mode(
        &self,
        channel: u16,
        epoch: u32,
        principal: Principal,
        scope: Option<CallScope>,
        mode: CallMode,
    ) -> Result<(), ModuleError> {
        self.insert_bound(channel, epoch, principal, scope, mode, None)
    }

    fn insert_bound(
        &self,
        channel: u16,
        epoch: u32,
        principal: Principal,
        scope: Option<CallScope>,
        mode: CallMode,
        on_behalf_of_agent: Option<String>,
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
                on_behalf_of_agent,
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
    stop: mpsc::Receiver<()>,
    audit_retention_window_ms: i64,
) -> tokio::task::JoinHandle<()> {
    spawn_trigger_scheduler_every(SCHEDULER_TICK, state, stop, audit_retention_window_ms)
}

/// `spawn_trigger_scheduler` with its tick interval named. The module always
/// runs `SCHEDULER_TICK`; tests pass a short tick so that waiting for the
/// scheduler's next pass takes milliseconds instead of a second.
fn spawn_trigger_scheduler_every(
    tick_interval: std::time::Duration,
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
        let mut tick = tokio::time::interval(tick_interval);
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
            let on_behalf_of_agent = scope
                .as_ref()
                .and_then(|stamp| stamp.attributes.on_behalf_of_agent.clone());
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
            match route_bindings.insert_bound(
                route_channel,
                epoch,
                accepted,
                scope,
                mode,
                on_behalf_of_agent,
            ) {
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
    ) && !(method == manifest::GITHUB_GRANT_OP && params["kind"] == "read")
    {
        // Read upgrades audit changes inside their transaction and leave previews
        // and no-ops untouched, rather than appending a second control audit here.
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
        Some(Some("read")) => return github_handle_read_grant(state, principal_key, params),
        Some(_) => {
            return json!({"error":{"code":"invalid_request",
                "message":"kind must be \"invoke\", \"poll\" or \"read\""}})
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

fn github_handle_read_grant(state: &ModuleState, principal_key: &str, params: &Value) -> Value {
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
    let module = params.get("module").and_then(Value::as_str);
    let handle = params.get("app_handle_id").and_then(Value::as_str);
    let all_handles = params
        .get("all_handles")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (Some(actions), Some(module)) = (actions, module) else {
        return json!({"error":{"code":"invalid_request","message":"module and an array of actions are required"}});
    };
    if params.get("effect").is_some() || all_handles == handle.is_some() || handle == Some("") {
        return json!({"error":{"code":"invalid_request","message":"read takes no effect and requires exactly one of app_handle_id or all_handles: true"}});
    }
    let request = plexus_core::storage::github_store::GithubHandleReadGrant {
        app_handle_id: handle.map(str::to_owned),
        all_handles,
        module: module.to_owned(),
        actions,
        dry_run: params
            .get("dry_run")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    };
    match plexus_core::github::control::grant_read(state.store(), principal_key, &request) {
        Ok(plan) => json!({"result":plan}),
        Err(code) => github_handle_refusal(&code, handle.unwrap_or("all enabled handles")),
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
        on_behalf_of_agent,
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
            if let Some(bot_read) = BotReadForm::of(action, &principal_key, &args) {
                return Ok(blocking_section(|| {
                    let engine = &state.runtime.engine;
                    let scope = route_scope.as_ref();
                    let on_behalf_of = on_behalf_of_agent.as_deref();
                    bot_read_reply(match bot_read {
                        BotReadForm::Repository => plexus_core::github::reads::bot::read(
                            engine,
                            &principal_key,
                            action,
                            &repository,
                            &args,
                            scope,
                            on_behalf_of,
                        ),
                        BotReadForm::JobLogRange => plexus_core::github::reads::bot::job_log(
                            engine,
                            &principal_key,
                            &repository,
                            &args,
                            scope,
                            on_behalf_of,
                        ),
                    })
                }));
            }
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
        // The destination is approved on the operator's ticket. Accepting it
        // here would let a ticket holder redirect the bound bearer key.
        if arguments.contains_key("instance_url") {
            return Ok(
                json!({"error":{"code":"argument_undeclared", "field":"instance_url",
                "message":"argument_undeclared{field: instance_url}", "transmission":"not_sent"}}),
            );
        }
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
            Ok(apps) => {
                let mut values = Vec::with_capacity(apps.len());
                for app in apps {
                    let takes_instance_url =
                        match state.store().manifest_takes_instance_url(&app.key) {
                            Ok(value) => value,
                            Err(error) => {
                                return Ok(crate::wire::store_failure(
                                    "app catalog read",
                                    "app catalog could not be read",
                                    &error,
                                ))
                            }
                        };
                    let mut value = json!(app);
                    value["takes_instance_url"] = json!(takes_instance_url);
                    values.push(value);
                }
                json!({"result": {"apps": values}})
            }
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
            metrics["webSearch"] = web_search_health::render(
                state
                    .health
                    .web_search
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref(),
                &state.runtime.web_search,
            );
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
    let web_search = match web_search_health::snapshot(
        state.store(),
        principals,
        state.runtime.web_search.now_ms(),
    ) {
        Ok(snapshot) => Some(snapshot),
        Err(error) => {
            eprintln!(warn health: "web search health read failed: {error}");
            None
        }
    };
    *state
        .health
        .web_search
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = web_search;
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

/// Which `github_read` calls are agent bot reads, served with the stamped
/// agent's own bot rather than the calling module's connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BotReadForm {
    /// `github.repo.get`, `github.search.code` and `github.search.issues`,
    /// whichever module carries the call.
    Repository,
    /// `github.actions.job_log` carried by AFT (principal `reserved:aft`, the
    /// module whose `gh` shim routes agents' GitHub reads) without `max_bytes`:
    /// a byte range of the log, read with the agent's bot. All other
    /// `github.actions.job_log` calls, from AFT with `max_bytes` or from any
    /// other module, are not bot reads: they keep the older bounded tail read
    /// through the operator's Actions connection.
    JobLogRange,
}

impl BotReadForm {
    fn of(action: &str, principal_key: &str, args: &Value) -> Option<Self> {
        if plexus_core::github::reads::bot::ACTIONS.contains(&action) {
            return Some(Self::Repository);
        }
        (action == "github.actions.job_log"
            && principal_key == plexus_core::github::AFT_PRINCIPAL
            && args.get("max_bytes").is_none())
        .then_some(Self::JobLogRange)
    }
}

/// The reply body for a bot read: `{"result": ...}`, or an error whose
/// `transmission` says whether GitHub was asked. These codes and fields are a
/// contract AFT's `gh` shim reads (see tests/fixtures/github-read-bot).
fn bot_read_reply(result: Result<Value, plexus_core::github::reads::bot::BotReadError>) -> Value {
    use plexus_core::github::reads::bot::BotReadError;
    let refusal = |code: &str, message: &str, transmission: &str| json!({"error": {"code": code, "message": message, "transmission": transmission}});
    match result {
        Ok(result) => json!({"result": result}),
        Err(BotReadError::AgentIdentityRequired) => refusal(
            "agent_identity_required",
            "GitHub bot reads need a head scope's agent or a worker scope working on behalf of one",
            "not_sent",
        ),
        Err(BotReadError::RepositoryNotVisible) => refusal(
            "repository_not_visible",
            "repository_not_visible",
            "not_sent",
        ),
        Err(BotReadError::EndpointNotAllowed { field }) => {
            let mut reply = refusal(
                "endpoint_not_allowed",
                "this argument is not one GitHub bot reads serve",
                "not_sent",
            );
            reply["error"]["field"] = json!(field);
            reply
        }
        Err(BotReadError::BudgetExhausted { retry_after_ms }) => {
            let mut reply = refusal(
                "read_budget_exhausted",
                "this bot's GitHub read budget is spent; retry later",
                "not_sent",
            );
            reply["error"]["retry_after_ms"] = json!(retry_after_ms);
            reply
        }
        Err(BotReadError::ResponseTooLarge) => refusal(
            "response_too_large",
            "GitHub's reply is larger than 1 MiB and was not returned",
            "sent",
        ),
        Err(BotReadError::Vendor { status }) => {
            let mut reply = refusal("vendor_error", "GitHub refused the read", "sent");
            reply["error"]["status"] = json!(status);
            reply
        }
        Err(BotReadError::JobNotFinished) => {
            refusal("job_not_finished", "the job has not completed", "sent")
        }
        Err(BotReadError::JobLog(code)) => refusal(code, code, "sent"),
        Err(BotReadError::Denied(denial)) => denial_response(&denial),
        Err(BotReadError::Dispatch(outcome)) => github_read_failure(outcome),
        Err(BotReadError::InvalidResponse) => json!({"error":{"code":"read_response_invalid"}}),
    }
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
    let (kept, cut) = plexus_core::text::prefix_within_chars(value, 128);
    let mut label: String = kept.chars().flat_map(char::escape_default).collect();
    if cut {
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
mod tests;

#[cfg(test)]
mod events_delivery_tests;

#[cfg(test)]
mod subscription_lifecycle_tests;

#[cfg(test)]
mod events_get_tests;

#[cfg(test)]
mod approval_gate_tests;

#[cfg(test)]
mod connection_admin_tests;

#[cfg(test)]
mod pool_sweep_tests;

#[cfg(test)]
mod health_probe_scope_tests;

#[cfg(test)]
mod health_handler_tests;

#[cfg(test)]
mod scheduler_liveness_tests;

#[cfg(test)]
mod secret_input_tests;

#[cfg(test)]
mod stamp_invoke_tests;

#[cfg(test)]
mod github_read_frame_tests;

#[cfg(test)]
mod consent_pending_tests;
