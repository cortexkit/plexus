use std::{
    collections::BTreeSet,
    fmt,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        mpsc::{self, RecvTimeoutError},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasmtime::{
    Caller, Config, Engine, Extern, InstancePre, Linker, Module, ResourceLimiter, Store,
    StoreLimits, StoreLimitsBuilder, Trap, UpdateDeadline,
};
use wasmtime_wasi::{
    p1::{self, WasiP1Ctx},
    p2::pipe::{MemoryInputPipe, MemoryOutputPipe},
    Deterministic, HostMonotonicClock, HostWallClock, WasiCtxBuilder,
};

use crate::{ProbeValue, ReturnSchema, ReturnSchemaError, ReturnValidationError};

/// How long the probe's own JavaScript may execute. Time spent inside host
/// action callbacks does not count: each callback carries its own deadline, and
/// charging it here turned a vendor call that finished inside that deadline into
/// a discarded, correct result.
pub const WALL_TIMEOUT: Duration = Duration::from_secs(5);
/// The ceiling on one whole run, callbacks included. Polls run one at a time on
/// the scheduler, so every second a probe holds is a second every other watch
/// waits; this keeps a probe that loops over slow callbacks from holding it for
/// long. A callback already in flight is not interrupted (nothing here can
/// preempt host code), so the run ends at the first guest step or callback
/// entry after the ceiling.
pub const RUN_CEILING: Duration = Duration::from_secs(15);
pub const MEMORY_LIMIT_BYTES: usize = 32 * 1024 * 1024;
/// Maximum UTF-8 source size accepted before serializing a guest request.
pub const MAX_SOURCE_BYTES: usize = 64 * 1024;
const MAX_ACTION_BYTES: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;

/// The most the guest may write as its response. The guest enforces the same
/// figure (`RESPONSE_LIMIT` in guest/src/main.rs) and answers an oversize
/// return with a typed outcome, so this cap is never what a probe runs into.
const OUTPUT_CAPACITY: usize = 64 * 1024;
/// How often the engine epoch advances while a run is in progress. Each advance
/// makes the running guest consult its own budget, so this bounds how far past
/// a budget a run can go.
const EPOCH_TICK: Duration = Duration::from_millis(10);
const GUEST_WASM: &[u8] = include_bytes!("../assets/plexus-probe-guest.wasm");

/// Serializes probe runs process-wide, by design. The only production caller,
/// the poller, runs polls one at a time inside a scheduler pass, so running
/// probes concurrently would buy nothing, while one run at a time keeps the
/// host's guest memory to a single 32 MiB instance. The lock is held across
/// host callbacks for the same reason: the run is one unit of the scheduler's
/// sequential work. Budget enforcement does not depend on it, because each run
/// checks its own clock at every epoch tick.
static EXECUTION_LOCK: Mutex<()> = Mutex::new(());
static RUNTIME_ARTIFACTS: OnceLock<RuntimeArtifacts> = OnceLock::new();
static RUNTIME_INITIALIZATION: Mutex<()> = Mutex::new(());

/// Caller-provided dispatch for the sandbox's only JavaScript host capability.
///
/// THE SANDBOX CANNOT INTERRUPT THIS CALL, and an implementor must enforce its
/// own deadline.
///
/// The probe timeout is epoch interruption, which preempts GUEST execution. While
/// this callback runs, the guest is not executing, so no epoch check fires and
/// nothing here is interrupted. Callback time is not charged to the 5 s guest
/// budget at all; it counts only toward [`RUN_CEILING`], which is checked when
/// the callback returns. A vendor request that hangs for an hour therefore hangs
/// the whole poll pass for an hour before the run is ended as a timeout.
///
/// This is easy to get backwards because every other limit in this module IS
/// enforced by the runtime: the memory ceiling, the tight-loop timeout, the
/// absent capabilities. The one boundary the runtime cannot hold is the one that
/// leaves it.
pub trait ActionInvoker: Send + Sync {
    fn invoke(&self, action: &str, argument: Value) -> Result<Value, String>;
}

impl<F> ActionInvoker for F
where
    F: Fn(&str, Value) -> Result<Value, String> + Send + Sync,
{
    fn invoke(&self, action: &str, argument: Value) -> Result<Value, String> {
        self(action, argument)
    }
}

/// A cached QuickJS/WASM module. Every call still receives a fresh store and guest context.
#[derive(Clone)]
pub struct ProbeSandbox {
    engine: Engine,
    pre: InstancePre<StoreState>,
    ticker: mpsc::Sender<bool>,
    executor: mpsc::SyncSender<ExecutionRequest>,
    #[cfg(test)]
    module_imports: Vec<String>,
    allowed_actions: Arc<BTreeSet<String>>,
    wasi_policy: WasiPolicy,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProbeError {
    InvalidSchema(ReturnSchemaError),
    Timeout {
        elapsed: Duration,
    },
    MemoryLimit {
        limit_bytes: usize,
    },
    ActionRefused {
        action: String,
    },
    ActionFailed {
        action: String,
        message: String,
    },
    ReturnValidation(ReturnValidationError),
    Execution {
        message: String,
    },
    HostConfiguration {
        environment_variable_count: usize,
        preopened_directory_count: usize,
    },
    Sandbox {
        message: String,
    },
}

struct RuntimeArtifacts {
    engine: Engine,
    pre: InstancePre<StoreState>,
    ticker: mpsc::Sender<bool>,
    executor: mpsc::SyncSender<ExecutionRequest>,
    #[cfg(test)]
    module_imports: Vec<String>,
}

struct ExecutionRequest {
    sandbox: ProbeSandbox,
    source: String,
    argument: Value,
    schema: ReturnSchema,
    invoker: Box<dyn ActionInvoker>,
    reply: mpsc::SyncSender<Result<ProbeValue, ProbeError>>,
}

struct StoreState {
    wasi: WasiP1Ctx,
    limits: TrackingLimits,
    allowed_actions: Arc<BTreeSet<String>>,
    invoker: Box<dyn ActionInvoker>,
    action_failure: Option<ActionFailure>,
    clock: RunClock,
}

/// One run's time accounting: when it started, how much of that was spent in
/// host callbacks, and whether a budget ended it.
struct RunClock {
    started: Instant,
    callback_time: Duration,
    timed_out: bool,
}

impl RunClock {
    fn start() -> Self {
        Self {
            started: Instant::now(),
            callback_time: Duration::ZERO,
            timed_out: false,
        }
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    fn guest_elapsed(&self) -> Duration {
        self.elapsed().saturating_sub(self.callback_time)
    }

    fn over_budget(&self) -> bool {
        self.guest_elapsed() >= WALL_TIMEOUT || self.elapsed() >= RUN_CEILING
    }
}

struct TrackingLimits {
    inner: StoreLimits,
    memory_denied: bool,
}

#[derive(Clone, Debug)]
enum ActionFailure {
    Refused { action: String },
    Failed { action: String, message: String },
}

#[derive(Clone, Copy)]
enum WasiPolicy {
    Isolated,
    #[cfg(test)]
    InheritEnvironment,
    #[cfg(test)]
    PreopenCurrentDirectory,
}

#[derive(Serialize)]
struct GuestRequest<'a> {
    source: &'a str,
    argument: Value,
}

#[derive(Deserialize)]
struct GuestResponse {
    host: GuestHostObservation,
    outcome: GuestOutcome,
}

#[derive(Deserialize)]
struct GuestHostObservation {
    environment_variable_count: usize,
    preopened_directory_count: usize,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum GuestOutcome {
    Ok { value: Value },
    Execution { message: String },
    Memory,
    ResultTooLarge { bytes: usize, limit: usize },
}

impl ProbeSandbox {
    /// Compile the embedded interpreter before admitting scheduled work.
    /// Failures are retryable; only successfully initialized artifacts are cached.
    pub fn warm_up() -> Result<(), ProbeError> {
        runtime_artifacts().map(|_| ())
    }

    pub fn new<I, S>(allowed_actions: I) -> Result<Self, ProbeError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::with_policy(allowed_actions, WasiPolicy::Isolated)
    }

    fn with_policy<I, S>(allowed_actions: I, wasi_policy: WasiPolicy) -> Result<Self, ProbeError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let artifacts = runtime_artifacts()?;
        Ok(Self {
            engine: artifacts.engine.clone(),
            pre: artifacts.pre.clone(),
            ticker: artifacts.ticker.clone(),
            executor: artifacts.executor.clone(),
            #[cfg(test)]
            module_imports: artifacts.module_imports.clone(),
            allowed_actions: Arc::new(allowed_actions.into_iter().map(Into::into).collect()),
            wasi_policy,
        })
    }

    /// Evaluate a source expression that yields a function, passing `argument` to it.
    ///
    /// Only the pinned QuickJS base, eval, and JSON intrinsics plus `invoke` are visible
    /// as JavaScript globals. `invoke(action, value)` calls the supplied dispatcher only
    /// when `action` belongs to the set passed to [`ProbeSandbox::new`].
    pub fn run<F>(
        &self,
        source: &str,
        argument: Value,
        schema: &ReturnSchema,
        invoker: F,
    ) -> Result<ProbeValue, ProbeError>
    where
        F: ActionInvoker + 'static,
    {
        if source.len() > MAX_SOURCE_BYTES {
            return Err(ProbeError::Execution {
                message: format!("probe source exceeds {MAX_SOURCE_BYTES} bytes"),
            });
        }
        schema
            .validate_declaration()
            .map_err(ProbeError::InvalidSchema)?;
        // Synchronous WASI internally enters a Tokio runtime. A reusable worker
        // keeps it off the caller's runtime and serializes all guest execution.
        // The rendezvous channel never accumulates queued work.
        let (reply, result) = mpsc::sync_channel(1);
        self.executor
            .send(ExecutionRequest {
                sandbox: self.clone(),
                source: source.to_owned(),
                argument,
                schema: schema.clone(),
                invoker: Box::new(invoker),
                reply,
            })
            .map_err(|_| ProbeError::Sandbox {
                message: "probe execution worker is unavailable".to_owned(),
            })?;
        result.recv().map_err(sandbox_error)?
    }

    fn run_serialized(
        &self,
        source: &str,
        argument: Value,
        schema: &ReturnSchema,
        invoker: Box<dyn ActionInvoker>,
    ) -> Result<ProbeValue, ProbeError> {
        let request =
            serde_json::to_vec(&GuestRequest { source, argument }).map_err(sandbox_error)?;
        let output = MemoryOutputPipe::new(OUTPUT_CAPACITY);
        let wasi = build_wasi_context(request, output.clone(), self.wasi_policy)?;
        let state = StoreState {
            wasi,
            limits: TrackingLimits::new(),
            allowed_actions: Arc::clone(&self.allowed_actions),
            invoker,
            action_failure: None,
            clock: RunClock::start(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        // Every epoch advance asks the running guest to check its own clock,
        // rather than one timer trapping at a fixed instant: a fixed instant
        // counts callback time as guest time, and the engine's epoch is shared,
        // so a trap scheduled for one run would land on whichever run happened
        // to be executing.
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(|mut context| {
            if context.data().clock.over_budget() {
                context.data_mut().clock.timed_out = true;
                Ok(UpdateDeadline::Interrupt)
            } else {
                Ok(UpdateDeadline::Continue(1))
            }
        });

        let instance = self.pre.instantiate(&mut store).map_err(sandbox_error)?;
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(sandbox_error)?;
        self.ticker.send(true).map_err(sandbox_error)?;
        let _ticker_run = TickerRun(&self.ticker);
        store.data_mut().clock = RunClock::start();
        let call_result = start.call(&mut store, ());

        if let Some(failure) = store.data().action_failure.clone() {
            return Err(match failure {
                ActionFailure::Refused { action } => ProbeError::ActionRefused { action },
                ActionFailure::Failed { action, message } => {
                    ProbeError::ActionFailed { action, message }
                }
            });
        }
        // Only a run that a budget actually INTERRUPTED is a timeout. A guest
        // that returned on its own is judged on what it returned, however long
        // its callbacks took.
        if store.data().clock.timed_out {
            return Err(ProbeError::Timeout {
                elapsed: store.data().clock.elapsed(),
            });
        }
        if let Err(error) = call_result {
            if store.data().limits.memory_denied {
                return Err(ProbeError::MemoryLimit {
                    limit_bytes: MEMORY_LIMIT_BYTES,
                });
            }
            // The probe's own recursion, not a host fault: say so in terms the
            // probe author can act on.
            if error.downcast_ref::<Trap>() == Some(&Trap::StackOverflow) {
                return Err(ProbeError::Execution {
                    message: "probe exceeded the maximum call stack depth".to_owned(),
                });
            }
            return Err(sandbox_error(error));
        }

        let response: GuestResponse =
            serde_json::from_slice(&output.contents()).map_err(|error| ProbeError::Sandbox {
                message: format!("invalid probe guest response: {error}"),
            })?;
        if response.host.environment_variable_count != 0
            || response.host.preopened_directory_count != 0
        {
            return Err(ProbeError::HostConfiguration {
                environment_variable_count: response.host.environment_variable_count,
                preopened_directory_count: response.host.preopened_directory_count,
            });
        }
        match response.outcome {
            GuestOutcome::Ok { value } => schema
                .validate_value(value)
                .map_err(ProbeError::ReturnValidation),
            GuestOutcome::Execution { message } => Err(ProbeError::Execution { message }),
            GuestOutcome::Memory => Err(ProbeError::MemoryLimit {
                limit_bytes: MEMORY_LIMIT_BYTES,
            }),
            GuestOutcome::ResultTooLarge { bytes, limit } => Err(ProbeError::ReturnValidation(
                ReturnValidationError::TooLarge { bytes, limit },
            )),
        }
    }

    /// Returns the imports requested by the guest so its host-facing interface can be verified.
    #[cfg(test)]
    pub fn module_imports(&self) -> &[String] {
        &self.module_imports
    }
}

/// The Wasmtime target every guest is compiled for: Pulley, Wasmtime's
/// interpreter, matched to the host's pointer width and byte order (Wasmtime
/// refuses to load a Pulley module whose width or byte order differs from the
/// host's).
///
/// Always Pulley, with no native fallback and no switch. The shipped binaries
/// are signed with macOS hardened runtime and no entitlements, so that no
/// same-user process can attach a debugger to them. Under that signature the
/// first execution of natively compiled guest code is killed by the kernel
/// (exit 137); `allow-jit` does not help, and the entitlement that does
/// (`allow-unsigned-executable-memory`) permits writable-and-executable memory
/// for the whole process. Interpreting bytecode generates no executable memory,
/// so the hardened binary runs guests unchanged. The price is speed: interpreted
/// guest code runs an order of magnitude slower than native, which still keeps
/// a heavy guest call well inside the 5 s budget.
const PULLEY_TARGET: &str = match (
    cfg!(target_pointer_width = "64"),
    cfg!(target_endian = "little"),
) {
    (true, true) => "pulley64",
    (false, true) => "pulley32",
    (true, false) => "pulley64be",
    (false, false) => "pulley32be",
};

fn runtime_artifacts() -> Result<&'static RuntimeArtifacts, ProbeError> {
    if let Some(artifacts) = RUNTIME_ARTIFACTS.get() {
        return Ok(artifacts);
    }
    let _initializing = execution_guard(&RUNTIME_INITIALIZATION);
    if let Some(artifacts) = RUNTIME_ARTIFACTS.get() {
        return Ok(artifacts);
    }
    let build = || -> Result<RuntimeArtifacts, String> {
        let mut config = Config::new();
        config.epoch_interruption(true);
        config
            .target(PULLEY_TARGET)
            .map_err(|error| error.to_string())?;
        let engine = Engine::new(&config).map_err(|error| error.to_string())?;
        let module = Module::new(&engine, GUEST_WASM).map_err(|error| error.to_string())?;
        #[cfg(test)]
        let module_imports = module
            .imports()
            .map(|import| format!("{}::{}", import.module(), import.name()))
            .collect();
        let mut linker = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |state: &mut StoreState| &mut state.wasi)
            .map_err(|error| error.to_string())?;
        linker
            .func_wrap("plexus", "invoke_declared_action", invoke_declared_action)
            .map_err(|error| error.to_string())?;
        let pre = linker
            .instantiate_pre(&module)
            .map_err(|error| error.to_string())?;
        let (executor, requests) = mpsc::sync_channel::<ExecutionRequest>(0);
        thread::Builder::new()
            .name("plexus-probe-execution".to_owned())
            .spawn(move || {
                while let Ok(request) = requests.recv() {
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        let _guard = execution_guard(&EXECUTION_LOCK);
                        request.sandbox.run_serialized(
                            &request.source,
                            request.argument,
                            &request.schema,
                            request.invoker,
                        )
                    }))
                    .unwrap_or_else(|_| {
                        Err(ProbeError::Sandbox {
                            message: "probe execution worker panicked".to_owned(),
                        })
                    });
                    let _ = request.reply.send(result);
                }
            })
            .map_err(|error| error.to_string())?;
        let (ticker, commands) = mpsc::channel();
        let ticker_engine = engine.clone();
        thread::Builder::new()
            .name("plexus-probe-epoch".to_owned())
            .spawn(move || {
                let mut active = false;
                loop {
                    let command = if active {
                        commands.recv_timeout(EPOCH_TICK)
                    } else {
                        commands.recv().map_err(|_| RecvTimeoutError::Disconnected)
                    };
                    match command {
                        Ok(value) => active = value,
                        Err(RecvTimeoutError::Timeout) => ticker_engine.increment_epoch(),
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
            })
            .map_err(|error| error.to_string())?;
        Ok(RuntimeArtifacts {
            engine,
            pre,
            ticker,
            executor,
            #[cfg(test)]
            module_imports,
        })
    };
    let artifacts = build().map_err(|message| ProbeError::Sandbox { message })?;
    let _ = RUNTIME_ARTIFACTS.set(artifacts);
    Ok(RUNTIME_ARTIFACTS
        .get()
        .expect("runtime initialized under lock"))
}

struct TickerRun<'a>(&'a mpsc::Sender<bool>);

impl Drop for TickerRun<'_> {
    fn drop(&mut self) {
        let _ = self.0.send(false);
    }
}

struct FixedClock;

impl HostWallClock for FixedClock {
    fn resolution(&self) -> Duration {
        Duration::from_nanos(1)
    }
    fn now(&self) -> Duration {
        Duration::from_secs(1)
    }
}

impl HostMonotonicClock for FixedClock {
    fn resolution(&self) -> u64 {
        1
    }
    fn now(&self) -> u64 {
        1
    }
}

fn build_wasi_context(
    request: Vec<u8>,
    output: MemoryOutputPipe,
    policy: WasiPolicy,
) -> Result<WasiP1Ctx, ProbeError> {
    let mut builder = WasiCtxBuilder::new();
    builder
        .stdin(MemoryInputPipe::new(request))
        .stdout(output)
        .arg("plexus-probe-guest")
        .wall_clock(FixedClock)
        .monotonic_clock(FixedClock)
        .secure_random(Deterministic::new(vec![7]))
        .insecure_random(Deterministic::new(vec![7]))
        .insecure_random_seed(0);
    match policy {
        WasiPolicy::Isolated => {}
        #[cfg(test)]
        WasiPolicy::InheritEnvironment => {
            builder.inherit_env();
        }
        #[cfg(test)]
        WasiPolicy::PreopenCurrentDirectory => {
            use wasmtime_wasi::FsPerms;
            builder
                .preopened_dir(".", ".", FsPerms::ReadOnly)
                .map_err(sandbox_error)?;
        }
    }
    Ok(builder.build_p1())
}

fn invoke_declared_action(
    mut caller: Caller<'_, StoreState>,
    action_pointer: i32,
    action_length: i32,
    argument_pointer: i32,
    argument_length: i32,
    output_pointer: i32,
    output_capacity: i32,
) -> wasmtime::Result<i32> {
    // Budgets are checked on both sides of the callback: before, so a probe
    // looping over invokes cannot start another vendor call past the run
    // ceiling, and after, so the run ends as soon as a slow callback has used
    // it up rather than at the guest's next epoch check. Returning an error
    // traps the guest, which JavaScript cannot catch.
    if caller.data().clock.over_budget() {
        caller.data_mut().clock.timed_out = true;
        return Err(wasmtime::Error::msg("probe exceeded its time budget"));
    }
    let status = match invoke_declared_action_inner(
        &mut caller,
        action_pointer,
        action_length,
        argument_pointer,
        argument_length,
        output_pointer,
        output_capacity,
    ) {
        Ok(length) => length,
        Err(failure) => {
            if caller.data().action_failure.is_none() {
                caller.data_mut().action_failure = Some(failure);
            }
            // A failed run cannot recover; trapping also prevents JavaScript
            // from catching the bridge error and spending more vendor reads.
            return Err(wasmtime::Error::msg("probe action failed"));
        }
    };
    if caller.data().clock.over_budget() {
        caller.data_mut().clock.timed_out = true;
        return Err(wasmtime::Error::msg("probe exceeded its time budget"));
    }
    Ok(status)
}

fn invoke_declared_action_inner(
    caller: &mut Caller<'_, StoreState>,
    action_pointer: i32,
    action_length: i32,
    argument_pointer: i32,
    argument_length: i32,
    output_pointer: i32,
    output_capacity: i32,
) -> Result<i32, ActionFailure> {
    let action = read_guest_string(caller, action_pointer, action_length, "action name")?;
    if !caller.data().allowed_actions.contains(&action) {
        return Err(ActionFailure::Refused { action });
    }
    let argument_text = read_guest_string(caller, argument_pointer, argument_length, "argument")
        .map_err(|failure| match failure {
            ActionFailure::Failed { message, .. } => ActionFailure::Failed {
                action: action.clone(),
                message,
            },
            other => other,
        })?;
    let argument = serde_json::from_str(&argument_text).map_err(|error| ActionFailure::Failed {
        action: action.clone(),
        message: format!("invalid action argument JSON: {error}"),
    })?;
    let callback_started = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| {
        caller.data().invoker.invoke(&action, argument)
    }));
    caller.data_mut().clock.callback_time += callback_started.elapsed();
    let result = result
        .map_err(|_| ActionFailure::Failed {
            action: action.clone(),
            message: "action callback panicked".to_owned(),
        })?
        .map_err(|message| ActionFailure::Failed {
            action: action.clone(),
            message,
        })?;
    let encoded = serde_json::to_vec(&result).map_err(|error| ActionFailure::Failed {
        action: action.clone(),
        message: format!("action result could not be encoded: {error}"),
    })?;
    let capacity = usize::try_from(output_capacity).map_err(|_| ActionFailure::Failed {
        action: action.clone(),
        message: "guest supplied a negative action output capacity".to_owned(),
    })?;
    if encoded.len() > capacity || encoded.len() > i32::MAX as usize {
        return Err(ActionFailure::Failed {
            action,
            message: "action result exceeds the guest bridge capacity".to_owned(),
        });
    }
    let memory = guest_memory(caller, &action)?;
    let output_offset = usize::try_from(output_pointer).map_err(|_| ActionFailure::Failed {
        action: action.clone(),
        message: "guest supplied a negative action output pointer".to_owned(),
    })?;
    memory
        .write(caller, output_offset, &encoded)
        .map_err(|error| ActionFailure::Failed {
            action,
            message: format!("could not write action result to guest memory: {error}"),
        })?;
    Ok(encoded.len() as i32)
}

fn read_guest_string(
    caller: &mut Caller<'_, StoreState>,
    pointer: i32,
    length: i32,
    label: &str,
) -> Result<String, ActionFailure> {
    let action = format!("<invalid {label}>");
    let offset = usize::try_from(pointer).map_err(|_| ActionFailure::Failed {
        action: action.clone(),
        message: format!("guest supplied a negative {label} pointer"),
    })?;
    let length = usize::try_from(length).map_err(|_| ActionFailure::Failed {
        action: action.clone(),
        message: format!("guest supplied a negative {label} length"),
    })?;
    let limit = if label == "action name" {
        MAX_ACTION_BYTES
    } else {
        MAX_ARGUMENT_BYTES
    };
    if length > limit {
        return Err(ActionFailure::Failed {
            action,
            message: format!("guest {label} exceeds {limit} bytes"),
        });
    }
    // The pointer and length are guest-supplied, so check them against the
    // guest's linear memory BEFORE allocating anything: allocating `length`
    // first would let the guest pick a host allocation of up to 2 GiB, far
    // beyond the memory ceiling the guest itself runs under. Copying the
    // in-bounds slice allocates at most what the guest really holds.
    let memory = guest_memory(caller, &action)?;
    let data = memory.data(&*caller);
    let Some(bytes) = offset
        .checked_add(length)
        .and_then(|end| data.get(offset..end))
    else {
        return Err(ActionFailure::Failed {
            action,
            message: format!(
                "guest {label} at offset {offset} with length {length} lies outside its {} byte memory",
                data.len()
            ),
        });
    };
    String::from_utf8(bytes.to_vec()).map_err(|error| ActionFailure::Failed {
        action: format!("<invalid {label}>"),
        message: format!("guest supplied non-UTF-8 {label}: {error}"),
    })
}

fn guest_memory(
    caller: &mut Caller<'_, StoreState>,
    action: &str,
) -> Result<wasmtime::Memory, ActionFailure> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| ActionFailure::Failed {
            action: action.to_owned(),
            message: "probe guest does not export linear memory".to_owned(),
        })
}

impl TrackingLimits {
    fn new() -> Self {
        Self {
            inner: StoreLimitsBuilder::new()
                .memory_size(MEMORY_LIMIT_BYTES)
                .memories(1)
                .instances(1)
                .build(),
            memory_denied: false,
        }
    }
}

impl ResourceLimiter for TrackingLimits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let allowed = self.inner.memory_growing(current, desired, maximum)?;
        if !allowed {
            self.memory_denied = true;
        }
        Ok(allowed)
    }

    fn memory_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.memory_denied = true;
        self.inner.memory_grow_failed(error)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.inner.table_growing(current, desired, maximum)
    }

    fn table_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.inner.table_grow_failed(error)
    }

    fn instances(&self) -> usize {
        self.inner.instances()
    }

    fn tables(&self) -> usize {
        self.inner.tables()
    }

    fn memories(&self) -> usize {
        self.inner.memories()
    }
}

fn sandbox_error(error: impl fmt::Display) -> ProbeError {
    ProbeError::Sandbox {
        message: format!("{error:#}"),
    }
}

fn execution_guard(lock: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    // The lock only prevents concurrent runs; it protects no shared data that
    // a panic could leave inconsistent.
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchema(error) => write!(f, "invalid probe return schema: {error}"),
            Self::Timeout { elapsed } => write!(
                f,
                "probe exceeded its time budget ({} s of script execution, {} s per run \
                 including action callbacks) after {elapsed:?}",
                WALL_TIMEOUT.as_secs(),
                RUN_CEILING.as_secs()
            ),
            Self::MemoryLimit { limit_bytes } => {
                write!(f, "probe exceeded the {limit_bytes} byte memory limit")
            }
            Self::ActionRefused { action } => write!(f, "probe action {action} was not declared"),
            Self::ActionFailed { action, message } => {
                write!(f, "probe action {action} failed: {message}")
            }
            Self::ReturnValidation(error) => write!(f, "invalid probe return: {error}"),
            Self::Execution { message } => write!(f, "probe execution failed: {message}"),
            Self::HostConfiguration {
                environment_variable_count,
                preopened_directory_count,
            } => write!(
                f,
                "probe WASI host exposed {environment_variable_count} environment variables and {preopened_directory_count} preopened directories"
            ),
            Self::Sandbox { message } => write!(f, "probe sandbox failed: {message}"),
        }
    }
}

impl std::error::Error for ProbeError {}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Barrier, Mutex,
        },
        thread,
        time::Duration,
    };

    use serde_json::{json, Value};

    use super::*;
    use crate::{ProbeValue, ScalarSchema};

    fn empty_invoker(_: &str, _: Value) -> Result<Value, String> {
        Err("probe unexpectedly invoked an action".to_owned())
    }

    fn bool_schema() -> ReturnSchema {
        ReturnSchema::Bool
    }

    #[test]
    fn a_caught_action_failure_stops_further_vendor_reads() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let sandbox = ProbeSandbox::new(["test.call"]).unwrap();
        let result = sandbox.run(
            "() => { try { invoke('test.call', null); } catch (_) {} invoke('test.call', null); return true; }",
            Value::Null, &bool_schema(), move |_: &str, _: Value| {
                observed.fetch_add(1, Ordering::SeqCst);
                Err("vendor unavailable".to_owned())
            });
        assert!(matches!(result, Err(ProbeError::ActionFailed { .. })));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_probe_can_run_inside_an_async_runtime() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let result = wasmtime_wasi::runtime::in_tokio(async {
            sandbox.run("() => true", Value::Null, &bool_schema(), empty_invoker)
        });
        assert_eq!(result.unwrap(), ProbeValue::Bool(true));
    }

    #[test]
    fn sequential_runs_reuse_one_execution_worker() {
        let sandbox = ProbeSandbox::new(["test.call"]).unwrap();
        let threads = Arc::new(Mutex::new(Vec::new()));
        for _ in 0..2 {
            let threads = threads.clone();
            sandbox
                .run(
                    "() => { invoke('test.call', null); return true; }",
                    Value::Null,
                    &bool_schema(),
                    move |_: &str, _: Value| {
                        threads.lock().unwrap().push(thread::current().id());
                        Ok(Value::Null)
                    },
                )
                .unwrap();
        }
        let threads = threads.lock().unwrap();
        assert_eq!(threads.len(), 2);
        assert_eq!(threads[0], threads[1]);
    }

    #[test]
    fn guest_randomness_does_not_expose_the_host_clock() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let first = sandbox
            .run(
                "() => Math.random()",
                Value::Null,
                &ReturnSchema::Number,
                empty_invoker,
            )
            .unwrap();
        let second = sandbox
            .run(
                "() => Math.random()",
                Value::Null,
                &ReturnSchema::Number,
                empty_invoker,
            )
            .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn wasi_clock_and_random_imports_are_deterministic() {
        let artifacts = runtime_artifacts().unwrap();
        let module = Module::new(&artifacts.engine, r#"(module
            (import "wasi_snapshot_preview1" "clock_time_get" (func $clock (param i32 i64 i32) (result i32)))
            (import "wasi_snapshot_preview1" "random_get" (func $random (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "sample") (result i32)
                (drop (call $clock (i32.const 0) (i64.const 0) (i32.const 0)))
                (drop (call $clock (i32.const 1) (i64.const 0) (i32.const 8)))
                (call $random (i32.const 16) (i32.const 8))))"#).unwrap();
        let mut linker = Linker::new(&artifacts.engine);
        p1::add_to_linker_sync(&mut linker, |ctx: &mut WasiP1Ctx| ctx).unwrap();
        let wasi = build_wasi_context(Vec::new(), MemoryOutputPipe::new(16), WasiPolicy::Isolated)
            .unwrap();
        let mut store = Store::new(&artifacts.engine, wasi);
        store.set_epoch_deadline(u64::MAX / 2);
        let instance = linker.instantiate(&mut store, &module).unwrap();
        assert_eq!(
            instance
                .get_typed_func::<(), i32>(&mut store, "sample")
                .unwrap()
                .call(&mut store, ())
                .unwrap(),
            0
        );
        let memory = instance.get_memory(&mut store, "memory").unwrap();
        let bytes = memory.data(&store);
        assert_eq!(
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            1_000_000_000
        );
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 1);
        assert_eq!(&bytes[16..24], &[7; 8]);
    }

    #[test]
    fn sandbox_diagnostics_preserve_the_trap_cause() {
        let error = sandbox_error(wasmtime::Error::msg("underlying trap").context("guest call"));
        let text = error.to_string();
        assert!(
            text.contains("guest call") && text.contains("underlying trap"),
            "{text}"
        );
    }

    #[test]
    fn a_recovered_allocation_failure_does_not_override_a_returned_value() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let value = sandbox.run("() => { try { let a = 'x'.repeat(64*1024*1024); return false; } catch (_) { return true; } }", Value::Null, &bool_schema(), empty_invoker).unwrap();
        assert_eq!(value, ProbeValue::Bool(true));
    }

    #[test]
    fn oversized_source_is_refused_before_guest_execution() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let source = format!("() => true /*{}*/", " ".repeat(64 * 1024));
        let error = sandbox
            .run(&source, Value::Null, &bool_schema(), empty_invoker)
            .unwrap_err();
        assert!(error.to_string().contains("source"), "{error}");
    }

    #[test]
    fn oversized_invoke_inputs_never_reach_the_dispatcher() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let sandbox = ProbeSandbox::new(["test.call", &"x".repeat(257)]).unwrap();
        for source in [
            "() => { invoke('test.call', 'x'.repeat(65537)); return true; }",
            "() => { invoke('x'.repeat(257), null); return true; }",
        ] {
            let observed = observed.clone();
            assert!(sandbox
                .run(
                    source,
                    Value::Null,
                    &bool_schema(),
                    move |_: &str, _: Value| {
                        observed.fetch_add(1, Ordering::SeqCst);
                        Ok(Value::Null)
                    }
                )
                .is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn execution_serialization_recovers_after_panic() {
        let lock = Mutex::new(());
        let _ = std::panic::catch_unwind(|| {
            let _guard = lock.lock().unwrap();
            panic!("poison execution lock");
        });
        drop(execution_guard(&lock));
    }

    #[test]
    #[ignore = "performance measurement"]
    fn measure_repeated_invokes() {
        let sandbox = ProbeSandbox::new(["test.call"]).unwrap();
        let started = std::time::Instant::now();
        let value = sandbox
            .run(
                "() => { for (let i=0; i<50; i++) invoke('test.call', null); return 42; }",
                Value::Null,
                &ReturnSchema::Number,
                |_: &str, _: Value| Ok(Value::Null),
            )
            .unwrap();
        assert_eq!(value, ProbeValue::Number(42.into()));
        println!("50 invokes: {:?}", started.elapsed());
    }

    #[test]
    #[ignore = "run alone in a fresh process for cold-start measurement"]
    fn measure_cold_start_and_heavy_run() {
        assert!(
            RUNTIME_ARTIFACTS.get().is_none(),
            "cold measurement requires a fresh process"
        );
        let started = std::time::Instant::now();
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let creation_ms = started.elapsed().as_secs_f64() * 1_000.0;
        let started = std::time::Instant::now();
        let value = sandbox.run(
            "() => { let total = 0; for (let i = 0; i < 2000000; i++) total = (total + i) % 1000003; return total; }",
            Value::Null, &ReturnSchema::Number, empty_invoker,
        ).unwrap();
        let execution_ms = started.elapsed().as_secs_f64() * 1_000.0;
        let expected = (2_000_000_u64 * 1_999_999 / 2) % 1_000_003;
        assert_eq!(value, ProbeValue::Number(expected.into()));
        println!(
            "COLD_HEAVY_TIMING {{\"creation_ms\":{creation_ms},\"execution_ms\":{execution_ms}}}"
        );
    }

    // Every other test here passes on native code too, when the test binary is
    // unsigned. Only this one notices the engine falling back to native, which
    // would otherwise surface as the hardened release binary being killed on
    // its first guest run.
    #[test]
    fn guests_run_on_the_pulley_interpreter() {
        let artifacts = runtime_artifacts().unwrap();
        assert!(artifacts.engine.is_pulley());
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        assert!(sandbox.engine.is_pulley());
    }

    #[test]
    fn runs_all_typed_return_shapes() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        assert_eq!(
            sandbox
                .run(
                    "input => input.ready",
                    json!({"ready": true}),
                    &bool_schema(),
                    empty_invoker
                )
                .unwrap(),
            ProbeValue::Bool(true)
        );
        assert_eq!(
            sandbox
                .run(
                    "() => 42.5",
                    Value::Null,
                    &ReturnSchema::Number,
                    empty_invoker
                )
                .unwrap(),
            ProbeValue::Number(serde_json::Number::from_f64(42.5).unwrap())
        );
        assert_eq!(
            sandbox
                .run(
                    "input => `hello ${input.name}`",
                    json!({"name": "Plexus"}),
                    &ReturnSchema::String { max_len: 32 },
                    empty_invoker,
                )
                .unwrap(),
            ProbeValue::String("hello Plexus".to_owned())
        );

        let fields = BTreeMap::from([
            ("healthy".to_owned(), ScalarSchema::Bool),
            ("latency".to_owned(), ScalarSchema::Number),
            ("status".to_owned(), ScalarSchema::String { max_len: 16 }),
        ]);
        let result = sandbox
            .run(
                "() => ({healthy: true, latency: 7, status: 'ready'})",
                Value::Null,
                &ReturnSchema::Struct { fields },
                empty_invoker,
            )
            .unwrap();
        assert!(matches!(result, ProbeValue::Struct(_)));
    }

    #[test]
    fn returned_values_are_validated_on_every_run_including_struct_strings() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let schema = ReturnSchema::Struct {
            fields: BTreeMap::from([("message".to_owned(), ScalarSchema::String { max_len: 4 })]),
        };
        let error = sandbox
            .run(
                "input => ({message: input.message})",
                json!({"message": "12345"}),
                &schema,
                empty_invoker,
            )
            .unwrap_err();
        assert_eq!(
            error,
            ProbeError::ReturnValidation(ReturnValidationError::StringTooLong {
                path: "$.message".to_owned(),
                max_len: 4,
                actual_len: 5,
            })
        );

        let valid = sandbox
            .run(
                "input => ({message: input.message})",
                json!({"message": "1234"}),
                &schema,
                empty_invoker,
            )
            .unwrap();
        assert!(matches!(valid, ProbeValue::Struct(_)));
    }

    #[test]
    fn schema_declarations_enforce_string_and_struct_caps() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        assert_eq!(
            sandbox
                .run(
                    "() => ''",
                    Value::Null,
                    &ReturnSchema::String { max_len: 257 },
                    empty_invoker,
                )
                .unwrap_err(),
            ProbeError::InvalidSchema(ReturnSchemaError::StringLimitTooLarge {
                path: "$".to_owned(),
                max_len: 257,
            })
        );

        let fields = (0..17)
            .map(|index| (format!("field_{index}"), ScalarSchema::Bool))
            .collect();
        assert_eq!(
            sandbox
                .run(
                    "() => ({})",
                    Value::Null,
                    &ReturnSchema::Struct { fields },
                    empty_invoker,
                )
                .unwrap_err(),
            ProbeError::InvalidSchema(ReturnSchemaError::TooManyFields { count: 17 })
        );
    }

    #[test]
    fn undeclared_actions_are_refused_before_dispatch() {
        let sandbox = ProbeSandbox::new(["declared"]).unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let callback_called = Arc::clone(&called);
        let error = sandbox
            .run(
                "() => { try { invoke('not-declared', {secret: true}); } catch (_) { return true; } }",
                Value::Null,
                &bool_schema(),
                move |_: &str, _: Value| {
                    callback_called.store(true, Ordering::SeqCst);
                    Ok(Value::Bool(true))
                },
            )
            .unwrap_err();
        assert_eq!(
            error,
            ProbeError::ActionRefused {
                action: "not-declared".to_owned(),
            }
        );
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn embedded_guest_has_no_absolute_build_paths() {
        for prefix in [
            "/Users/",
            "/home/",
            "/root/",
            "/tmp/",
            "/private/tmp/",
            "/var/folders/",
            "/worktrees/",
            "/run/motor/",
        ] {
            assert!(
                !GUEST_WASM
                    .windows(prefix.len())
                    .any(|window| window == prefix.as_bytes()),
                "embedded probe guest contains an absolute home or worktree path: {prefix}"
            );
        }
    }

    #[test]
    fn declared_action_is_the_only_host_callback() {
        let sandbox = ProbeSandbox::new(["status.read"]).unwrap();
        let value = sandbox
            .run(
                "input => invoke('status.read', {id: input.id}).healthy",
                json!({"id": 7}),
                &bool_schema(),
                |action: &str, argument: Value| {
                    assert_eq!(action, "status.read");
                    assert_eq!(argument, json!({"id": 7}));
                    Ok(json!({"healthy": true}))
                },
            )
            .unwrap();
        assert_eq!(value, ProbeValue::Bool(true));
        let mut imports = sandbox.module_imports().to_vec();
        imports.sort();
        assert_eq!(
            imports,
            vec![
                "plexus::invoke_declared_action",
                "wasi_snapshot_preview1::clock_time_get",
                "wasi_snapshot_preview1::environ_get",
                "wasi_snapshot_preview1::environ_sizes_get",
                "wasi_snapshot_preview1::fd_close",
                "wasi_snapshot_preview1::fd_fdstat_get",
                "wasi_snapshot_preview1::fd_prestat_get",
                "wasi_snapshot_preview1::fd_read",
                "wasi_snapshot_preview1::fd_seek",
                "wasi_snapshot_preview1::fd_write",
                "wasi_snapshot_preview1::proc_exit",
                "wasi_snapshot_preview1::random_get",
            ]
        );
    }

    #[test]
    fn hostile_os_capabilities_are_absent() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let attempts = [
            ("() => std.loadFile('/etc/passwd')", "std is not defined"),
            (
                "() => new WebSocket('ws://127.0.0.1:9')",
                "WebSocket is not defined",
            ),
            ("() => os.exec(['id'])", "os is not defined"),
            ("() => std.getenv('HOME')", "std is not defined"),
        ];
        for (source, expected) in attempts {
            let ProbeError::Execution { message } = sandbox
                .run(source, Value::Null, &bool_schema(), empty_invoker)
                .unwrap_err()
            else {
                panic!("hostile attempt did not produce an execution error");
            };
            assert!(message.contains(expected), "unexpected error: {message}");
        }
    }

    #[test]
    fn exception_formatting_cannot_invoke_after_failure() {
        let sandbox = ProbeSandbox::new(["test.call"]).unwrap();
        for source in [
            "() => { const e = new Error('failed'); e.toString = () => { invoke('test.call', null); return 'failed'; }; throw e; }",
            "() => { const e = new Error('failed'); Object.defineProperty(e, 'message', { get() { invoke('test.call', null); return 'failed'; } }); throw e; }",
        ] {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let error = sandbox.run(source, Value::Null, &bool_schema(), move |_: &str, _: Value| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(Value::Null)
        }).unwrap_err();
        assert!(matches!(error, ProbeError::Execution { .. }));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "formatting an exception must not invoke actions"
        );
        }
    }

    #[test]
    fn probe_cannot_replace_the_json_bridge() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let value = sandbox
            .run(
                "() => { JSON.stringify = () => 'true'; return false; }",
                Value::Null,
                &bool_schema(),
                empty_invoker,
            )
            .unwrap();
        assert_eq!(
            value,
            ProbeValue::Bool(false),
            "probe must not replace bridge serialization"
        );
    }

    #[test]
    fn global_surface_is_exactly_the_pinned_intrinsics_and_invoke() {
        let sandbox = ProbeSandbox::new(["test.record-globals"]).unwrap();
        let observed = Arc::new(Mutex::new(None));
        let callback_observed = Arc::clone(&observed);
        let result = sandbox
            .run(
                "() => invoke('test.record-globals', Object.getOwnPropertyNames(globalThis).sort())",
                Value::Null,
                &bool_schema(),
                move |_: &str, globals: Value| {
                    *callback_observed.lock().unwrap() = Some(globals);
                    Ok(Value::Bool(true))
                },
            )
            .unwrap();
        assert_eq!(result, ProbeValue::Bool(true));
        let actual = observed.lock().unwrap().take().unwrap();
        assert_eq!(
            actual,
            json!([
                "AggregateError",
                "Array",
                "BigInt",
                "Boolean",
                "DisposableStack",
                "Error",
                "EvalError",
                "Function",
                "Infinity",
                "InternalError",
                "Iterator",
                "JSON",
                "Math",
                "NaN",
                "Number",
                "Object",
                "RangeError",
                "ReferenceError",
                "Reflect",
                "String",
                "SuppressedError",
                "Symbol",
                "SyntaxError",
                "TypeError",
                "URIError",
                "decodeURI",
                "decodeURIComponent",
                "encodeURI",
                "encodeURIComponent",
                "escape",
                "eval",
                "globalThis",
                "invoke",
                "isFinite",
                "isNaN",
                "parseFloat",
                "parseInt",
                "queueMicrotask",
                "undefined",
                "unescape"
            ])
        );
    }

    #[test]
    fn each_run_gets_a_fresh_javascript_context() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        sandbox
            .run(
                "() => { globalThis.authorState = 42; return true; }",
                Value::Null,
                &bool_schema(),
                empty_invoker,
            )
            .unwrap();
        assert_eq!(
            sandbox
                .run(
                    "() => typeof authorState === 'undefined'",
                    Value::Null,
                    &bool_schema(),
                    empty_invoker,
                )
                .unwrap(),
            ProbeValue::Bool(true)
        );
    }

    #[test]
    fn runs_are_serialized() {
        let sandboxes = [
            Arc::new(ProbeSandbox::new(["test.pause"]).unwrap()),
            Arc::new(ProbeSandbox::new(["test.pause"]).unwrap()),
        ];
        let barrier = Arc::new(Barrier::new(3));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let (completed_tx, completed_rx) = std::sync::mpsc::channel();
        let mut threads = Vec::new();
        for sandbox in sandboxes {
            let sandbox = Arc::clone(&sandbox);
            let barrier = Arc::clone(&barrier);
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            let completed_tx = completed_tx.clone();
            threads.push(thread::spawn(move || {
                barrier.wait();
                let result = sandbox
                    .run(
                        "() => invoke('test.pause', null)",
                        Value::Null,
                        &bool_schema(),
                        move |_: &str, _: Value| {
                            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                            maximum.fetch_max(now, Ordering::SeqCst);
                            thread::sleep(Duration::from_millis(100));
                            active.fetch_sub(1, Ordering::SeqCst);
                            Ok(Value::Bool(true))
                        },
                    )
                    .unwrap();
                completed_tx
                    .send(result)
                    .expect("sandbox completion receiver stays available");
            }));
        }
        drop(completed_tx);
        barrier.wait();
        for _ in 0..2 {
            // Generous because runs are serialized process-wide: the budget
            // tests in this binary hold the same lock for up to about 25 s, and
            // these workers may queue behind them.
            let result = completed_rx
                .recv_timeout(Duration::from_secs(120))
                .expect("sandbox worker did not finish within 120s");
            assert_eq!(result, ProbeValue::Bool(true));
        }
        for worker in threads {
            worker
                .join()
                .expect("sandbox worker exits after completion");
        }
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn no_allocation_loop_times_out_and_the_next_probe_runs() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let error = sandbox
            .run(
                "() => { while (true) {} }",
                Value::Null,
                &bool_schema(),
                empty_invoker,
            )
            .unwrap_err();
        let ProbeError::Timeout { elapsed } = error else {
            panic!("tight loop was not interrupted: {error}");
        };
        eprintln!(
            "probe timeout elapsed={elapsed:?} overrun={:?}",
            elapsed.saturating_sub(WALL_TIMEOUT)
        );
        assert!(elapsed >= WALL_TIMEOUT);
        assert_eq!(
            sandbox
                .run("() => true", Value::Null, &bool_schema(), empty_invoker)
                .unwrap(),
            ProbeValue::Bool(true)
        );
    }

    /// A callback that takes longer than the guest budget, but finishes inside
    /// its own deadline, must not cost the probe its correct result. The
    /// poller's callback deadline equals the guest budget, so before callback
    /// time was excluded, any vendor call near that deadline turned a finished
    /// probe into a timeout.
    #[test]
    fn a_slow_callback_inside_its_own_deadline_keeps_the_correct_result() {
        let sandbox = ProbeSandbox::new(["test.slow"]).unwrap();
        let result = sandbox.run(
            "() => invoke('test.slow', null)",
            Value::Null,
            &bool_schema(),
            |_: &str, _: Value| {
                thread::sleep(WALL_TIMEOUT + Duration::from_millis(100));
                Ok(Value::Bool(true))
            },
        );
        assert_eq!(
            result,
            Ok(ProbeValue::Bool(true)),
            "a correct result was discarded because its callback was slow"
        );
    }

    /// Excluding callback time from the guest budget must not make a probe
    /// that loops over callbacks unbounded: the whole run stops at the ceiling.
    #[test]
    fn a_loop_of_callbacks_stops_at_the_run_ceiling() {
        let sandbox = ProbeSandbox::new(["test.slow"]).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let error = sandbox
            .run(
                "() => { for (;;) { invoke('test.slow', null); } }",
                Value::Null,
                &bool_schema(),
                move |_: &str, _: Value| {
                    // Past 20 calls the ceiling has already failed; refusing
                    // ends the run so a broken ceiling fails this test instead
                    // of hanging it.
                    if counted.fetch_add(1, Ordering::SeqCst) >= 20 {
                        return Err("the callback loop ran past the run ceiling".to_owned());
                    }
                    thread::sleep(Duration::from_secs(1));
                    Ok(Value::Bool(true))
                },
            )
            .unwrap_err();
        // `elapsed` is the run's own clock, so time spent queued behind other
        // tests for the process-wide lock does not count against it.
        let ProbeError::Timeout { elapsed } = error else {
            panic!("a callback loop was not stopped by the run ceiling: {error}");
        };
        assert!(elapsed >= RUN_CEILING, "stopped early: {elapsed:?}");
        assert!(
            elapsed < RUN_CEILING + Duration::from_secs(2),
            "the run outlived its ceiling by more than one callback: {elapsed:?}"
        );
        assert!(
            calls.load(Ordering::SeqCst) <= 16,
            "a callback started after the ceiling"
        );
    }

    /// Unbounded recursion is the probe's own fault and must read as one, not
    /// as an opaque sandbox failure with a wasm backtrace.
    #[test]
    fn unbounded_recursion_is_reported_as_an_execution_error() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let error = sandbox
            .run(
                "() => { const f = n => f(n + 1) + 1; return f(0) > 0; }",
                Value::Null,
                &bool_schema(),
                empty_invoker,
            )
            .unwrap_err();
        let ProbeError::Execution { message } = &error else {
            panic!("recursion was not an execution error: {error:?}");
        };
        assert!(
            message.contains("stack"),
            "the error must name the stack: {message}"
        );
    }

    /// A probe that throws an error whose text merely SAYS "out of memory" did
    /// not run out of memory; only a failed allocation may report the limit.
    #[test]
    fn a_thrown_out_of_memory_message_is_not_a_memory_limit() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let error = sandbox
            .run(
                "() => { throw new InternalError('out of memory'); }",
                Value::Null,
                &bool_schema(),
                empty_invoker,
            )
            .unwrap_err();
        let ProbeError::Execution { message } = &error else {
            panic!("a thrown message was read as a memory limit: {error:?}");
        };
        assert!(message.contains("out of memory"), "{message}");
    }

    /// A return far beyond anything a schema accepts must fail as a named
    /// return error, not as a sandbox failure from an overflowing pipe.
    #[test]
    fn an_oversize_return_is_a_named_return_error() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let error = sandbox
            .run(
                "() => { let s = 'x'; while (s.length < 200000) s += s; return s; }",
                Value::Null,
                &ReturnSchema::String { max_len: 256 },
                empty_invoker,
            )
            .unwrap_err();
        assert!(
            matches!(
                error,
                ProbeError::ReturnValidation(ReturnValidationError::TooLarge { bytes, limit })
                    if bytes > limit && limit == OUTPUT_CAPACITY
            ),
            "{error:?}"
        );
    }

    /// The probe source is compiled on its own, so text in it cannot reach into
    /// the wrapper that checks it: closing the expression early and returning
    /// from the wrapper used to yield a value from a source that is not a
    /// function at all.
    #[test]
    fn probe_source_cannot_break_out_of_its_wrapper() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let error = sandbox
            .run(
                "0); return \"7\"; (0",
                Value::Null,
                &ReturnSchema::Number,
                empty_invoker,
            )
            .unwrap_err();
        assert!(
            matches!(error, ProbeError::Execution { .. }),
            "a source that is not a function returned a value: {error:?}"
        );
        // An ordinary function expression, including the anonymous `function`
        // form that is only legal as an expression, still runs.
        assert_eq!(
            sandbox
                .run(
                    "function (input) { return input.n + 1; }",
                    json!({"n": 41}),
                    &ReturnSchema::Number,
                    empty_invoker,
                )
                .unwrap(),
            ProbeValue::Number(42.into())
        );
    }

    #[test]
    fn linear_memory_ceiling_kills_allocation_and_the_next_probe_runs() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        let error = sandbox
            .run(
                "() => { const retained = new Array(5000000).fill(1); return retained.length === 5000000; }",
                Value::Null,
                &bool_schema(),
                empty_invoker,
            )
            .unwrap_err();
        assert_eq!(
            error,
            ProbeError::MemoryLimit {
                limit_bytes: MEMORY_LIMIT_BYTES,
            }
        );
        assert_eq!(
            sandbox
                .run("() => true", Value::Null, &bool_schema(), empty_invoker)
                .unwrap(),
            ProbeValue::Bool(true)
        );
    }

    #[test]
    fn isolated_wasi_has_no_environment_or_preopened_directories() {
        let sandbox = ProbeSandbox::new(Vec::<String>::new()).unwrap();
        assert_eq!(
            sandbox
                .run("() => true", Value::Null, &bool_schema(), empty_invoker)
                .unwrap(),
            ProbeValue::Bool(true)
        );
    }

    #[test]
    fn inheriting_environment_breaks_the_host_configuration_assertion() {
        assert!(std::env::vars_os().next().is_some());
        let sandbox =
            ProbeSandbox::with_policy(Vec::<String>::new(), WasiPolicy::InheritEnvironment)
                .unwrap();
        let ProbeError::HostConfiguration {
            environment_variable_count,
            preopened_directory_count,
        } = sandbox
            .run("() => true", Value::Null, &bool_schema(), empty_invoker)
            .unwrap_err()
        else {
            panic!("inherited environment did not widen the observed WASI surface");
        };
        assert!(environment_variable_count > 0);
        assert_eq!(preopened_directory_count, 0);
    }

    #[test]
    fn adding_a_preopen_breaks_the_host_configuration_assertion() {
        let sandbox =
            ProbeSandbox::with_policy(Vec::<String>::new(), WasiPolicy::PreopenCurrentDirectory)
                .unwrap();
        let ProbeError::HostConfiguration {
            environment_variable_count,
            preopened_directory_count,
        } = sandbox
            .run("() => true", Value::Null, &bool_schema(), empty_invoker)
            .unwrap_err()
        else {
            panic!("preopened directory did not widen the observed WASI surface");
        };
        assert_eq!(environment_variable_count, 0);
        assert!(preopened_directory_count > 0);
    }

    /// The embedded guest only ever passes the lengths of strings it really
    /// holds, so this drives the host function from a hand-written module that
    /// claims a 2 GiB action name inside a 64 KiB memory. The host must refuse
    /// it without allocating anything near that size: the guest's own memory is
    /// capped at 32 MiB, and a length it merely names must not buy it more.
    #[test]
    fn a_guest_supplied_length_cannot_choose_a_host_allocation() {
        let artifacts = runtime_artifacts().unwrap();
        let module = Module::new(
            &artifacts.engine,
            r#"(module
                 (import "plexus" "invoke_declared_action"
                   (func $invoke (param i32 i32 i32 i32 i32 i32) (result i32)))
                 (memory (export "memory") 1)
                 (func (export "oversize") (result i32)
                   (call $invoke (i32.const 0) (i32.const 2147483647)
                     (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))))"#,
        )
        .unwrap();
        let mut linker = Linker::new(&artifacts.engine);
        linker
            .func_wrap("plexus", "invoke_declared_action", invoke_declared_action)
            .unwrap();
        let state = StoreState {
            wasi: build_wasi_context(Vec::new(), MemoryOutputPipe::new(16), WasiPolicy::Isolated)
                .unwrap(),
            limits: TrackingLimits::new(),
            allowed_actions: Arc::new(BTreeSet::new()),
            invoker: Box::new(empty_invoker),
            action_failure: None,
            clock: RunClock::start(),
        };
        let mut store = Store::new(&artifacts.engine, state);
        store.limiter(|state| &mut state.limits);
        // The engine is shared with other tests whose timers advance its epoch,
        // so give this store a deadline no timer here can reach.
        store.set_epoch_deadline(u64::MAX / 2);
        let instance = linker.instantiate(&mut store, &module).unwrap();
        let oversize = instance
            .get_typed_func::<(), i32>(&mut store, "oversize")
            .unwrap();

        largest_allocation::reset();
        let status = oversize.call(&mut store, ());
        let largest = largest_allocation::largest();

        assert!(status.is_err(), "an oversized action name must trap");
        assert!(
            matches!(
                store.data().action_failure,
                Some(ActionFailure::Failed { ref message, .. }) if message.contains("exceeds") || message.contains("outside")
            ),
            "the refusal must name the bounds: {:?}",
            store.data().action_failure
        );
        assert!(
            largest < 1024 * 1024,
            "a guest-named length allocated {largest} bytes on the host"
        );
    }
}

/// Records the largest single allocation made on the current thread, so a test
/// can bound what one host call allocated. Per thread because tests run in
/// parallel and each only cares about its own call.
#[cfg(test)]
#[allow(unsafe_code)]
mod largest_allocation {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static LARGEST: Cell<usize> = const { Cell::new(0) };
    }

    pub fn reset() {
        LARGEST.with(|largest| largest.set(0));
    }

    pub fn largest() -> usize {
        LARGEST.with(Cell::get)
    }

    fn record(size: usize) {
        // `try_with`: an allocation during thread teardown must not panic.
        let _ = LARGEST.try_with(|largest| {
            if size > largest.get() {
                largest.set(size);
            }
        });
    }

    struct Counting;

    // SAFETY: every method forwards unchanged to the system allocator; the
    // only addition is recording a size in a thread-local cell, which does
    // not allocate.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            record(layout.size());
            System.alloc(layout)
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            record(layout.size());
            System.alloc_zeroed(layout)
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            System.dealloc(pointer, layout)
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            record(size);
            System.realloc(pointer, layout, size)
        }
    }

    #[global_allocator]
    static COUNTING: Counting = Counting;
}
