use std::{
    collections::BTreeMap,
    error::Error,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Instant,
};

use serde::Serialize;
use wasmtime::{
    Config, Engine, InstancePre, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
};
use wasmtime_wasi::{
    WasiCtxBuilder,
    p1::{self, WasiP1Ctx},
    p2::pipe::MemoryOutputPipe,
};

use super::{Distribution, Outcome, TIMEOUT, distribution, resident_bytes};

const WASM_SAMPLE_COUNT: usize = 200;
const LIVE_STORE_COUNT: usize = 16;
const NORMAL_STORE_MEMORY_LIMIT: usize = 64 * 1024 * 1024;
const WASM_MEMORY_LIMIT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Serialize)]
pub(super) struct WasmReport {
    arm: &'static str,
    engine: &'static str,
    guest_path: String,
    module_imports: Vec<String>,
    no_import_module_control: NoImportModuleControl,
    no_host_capability_instantiation: Outcome,
    default_script_globals: BTreeMap<String, String>,
    happy_probe_result: String,
    happy_probe_host_action_calls: usize,
    resource_containment: WasmResourceContainment,
    lifecycle: WasmLifecycle,
    memory: WasmMemory,
}

#[derive(Serialize)]
struct NoImportModuleControl {
    import_count: usize,
    run_result: i32,
}

#[derive(Serialize)]
struct WasmResourceContainment {
    quickjs_memory_limit_bytes: usize,
    quickjs_memory_limit_result: String,
    wasm_linear_memory_limit_bytes: usize,
    wasm_linear_memory_allocation_bytes: usize,
    wasm_linear_memory_result: String,
    quickjs_stack_limit_bytes: usize,
    quickjs_stack_result: String,
    timeout_limit_us: u128,
    timeout_result: String,
    timeout_actual_us: u128,
    timeout_overrun_us: u128,
    post_interrupt_new_store_result: String,
}

#[derive(Serialize)]
struct WasmLifecycle {
    cold_engine_module_store_instance_guest_us: u128,
    cached_module_fresh_store_instance_guest_us: Distribution,
}

#[derive(Serialize)]
struct WasmMemory {
    live_store_count: usize,
    process_resident_before_bytes: Option<u64>,
    process_resident_with_live_stores_bytes: Option<u64>,
    process_resident_after_teardown_bytes: Option<u64>,
    process_resident_delta_per_store_bytes: Option<i64>,
}

struct WasmState {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

struct WasmHarness {
    engine: Engine,
    module: Module,
    pre: InstancePre<WasmState>,
    action_calls: Arc<AtomicUsize>,
}

pub(super) fn guest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/wasm32-wasip1/release/quickjs-wasm-guest.wasm")
}

pub(super) fn run(guest_path: &Path) -> Result<WasmReport, Box<dyn Error>> {
    if !guest_path.is_file() {
        return Err(format!(
            "QuickJS WASM guest is missing at {}. Run `cargo build -p quickjs-wasm-guest --release --target wasm32-wasip1` first.",
            guest_path.display()
        )
        .into());
    }

    let cold_started = Instant::now();
    let cold_harness = WasmHarness::new(guest_path)?;
    let cold_output = cold_harness.run_scenario("happy", None)?;
    assert_eq!(cold_output, r#"{"ok":true,"value":7,"summary":"probe:7"}"#);
    let cold_engine_module_store_instance_guest_us = cold_started.elapsed().as_micros();

    let harness = WasmHarness::new(guest_path)?;
    let no_import_module_control = no_import_module_control(&harness.engine)?;
    let no_host_capability_instantiation = no_host_capability_instantiation(&harness)?;
    let default_script_globals = parse_default_output(&harness.run_scenario("default", None)?);
    harness.action_calls.store(0, Ordering::SeqCst);
    let happy_probe_result = harness.run_scenario("happy", None)?;
    let happy_probe_host_action_calls = harness.action_calls.load(Ordering::SeqCst);

    let resource_containment = resource_containment(&harness, guest_path)?;
    // Epoch interruption advances an Engine-wide counter. Use a fresh engine for
    // lifecycle and memory measurements so the one-shot timeout cannot affect them.
    let post_timeout_harness = WasmHarness::new(guest_path)?;
    let lifecycle = lifecycle(
        &post_timeout_harness,
        cold_engine_module_store_instance_guest_us,
    )?;
    let memory = memory_measurement(&post_timeout_harness)?;

    Ok(WasmReport {
        arm: "QuickJS-NG compiled to wasm32-wasip1, run by Wasmtime",
        engine: if cfg!(feature = "production-pulley") {
            "Wasmtime 47.0.3 Pulley; WASI Preview 1, no environment or preopens"
        } else {
            "Wasmtime 47.0.3 native Cranelift; WASI Preview 1, no environment or preopens"
        },
        guest_path: guest_path.display().to_string(),
        module_imports: harness.module_imports(),
        no_import_module_control,
        no_host_capability_instantiation,
        default_script_globals,
        happy_probe_result,
        happy_probe_host_action_calls,
        resource_containment,
        lifecycle,
        memory,
    })
}

impl WasmHarness {
    fn new(guest_path: &Path) -> Result<Self, Box<dyn Error>> {
        let mut config = Config::new();
        if cfg!(feature = "production-pulley") {
            config.target(
                match (
                    cfg!(target_pointer_width = "64"),
                    cfg!(target_endian = "little"),
                ) {
                    (true, true) => "pulley64",
                    (false, true) => "pulley32",
                    (true, false) => "pulley64be",
                    (false, false) => "pulley32be",
                },
            )?;
        }
        config.epoch_interruption(true);
        let engine = Engine::new(&config)?;
        let module = Module::from_file(&engine, guest_path)?;
        let action_calls = Arc::new(AtomicUsize::new(0));
        let mut linker = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |state: &mut WasmState| &mut state.wasi)?;
        let action_calls_for_import = Arc::clone(&action_calls);
        linker.func_wrap("plexus", "invoke_declared_action", move || -> i32 {
            action_calls_for_import.fetch_add(1, Ordering::SeqCst);
            7
        })?;
        let pre = linker.instantiate_pre(&module)?;
        Ok(Self {
            engine,
            module,
            pre,
            action_calls,
        })
    }

    fn new_store(
        &self,
        scenario: &str,
        memory_limit: Option<usize>,
    ) -> (Store<WasmState>, MemoryOutputPipe) {
        let output = MemoryOutputPipe::new(64 * 1024);
        let mut wasi = WasiCtxBuilder::new();
        // Deliberately do not inherit the host environment, standard input, or directories.
        wasi.stdout(output.clone())
            .arg("quickjs-wasm-guest")
            .arg(scenario);
        let state = WasmState {
            wasi: wasi.build_p1(),
            limits: StoreLimitsBuilder::new()
                .memory_size(memory_limit.unwrap_or(NORMAL_STORE_MEMORY_LIMIT))
                .build(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        // Epoch deadlines are relative to the engine's current epoch. A finite,
        // distant deadline keeps ordinary runs live after the timeout test advances it.
        store.set_epoch_deadline(1_000_000);
        (store, output)
    }

    fn run_scenario(
        &self,
        scenario: &str,
        memory_limit: Option<usize>,
    ) -> Result<String, Box<dyn Error>> {
        let (mut store, output) = self.new_store(scenario, memory_limit);
        let instance = self.pre.instantiate(&mut store)?;
        let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
        start.call(&mut store, ())?;
        Ok(String::from_utf8(output.contents().to_vec())?)
    }

    fn module_imports(&self) -> Vec<String> {
        self.module
            .imports()
            .map(|import| format!("{}::{}", import.module(), import.name()))
            .collect()
    }
}

fn no_import_module_control(engine: &Engine) -> Result<NoImportModuleControl, Box<dyn Error>> {
    let bytes = wat::parse_str(r#"(module (func (export "run") (result i32) i32.const 42))"#)?;
    let module = Module::new(engine, bytes)?;
    let output = MemoryOutputPipe::new(16);
    let state = WasmState {
        wasi: WasiCtxBuilder::new().stdout(output).build_p1(),
        limits: StoreLimitsBuilder::new().build(),
    };
    let mut store = Store::new(engine, state);
    store.set_epoch_deadline(1_000_000);
    let linker = Linker::<WasmState>::new(engine);
    let instance = linker.instantiate(&mut store, &module)?;
    let run = instance.get_typed_func::<(), i32>(&mut store, "run")?;
    Ok(NoImportModuleControl {
        import_count: module.imports().count(),
        run_result: run.call(&mut store, ())?,
    })
}

fn no_host_capability_instantiation(harness: &WasmHarness) -> Result<Outcome, Box<dyn Error>> {
    let mut linker = Linker::new(&harness.engine);
    p1::add_to_linker_sync(&mut linker, |state: &mut WasmState| &mut state.wasi)?;
    let (mut store, _) = harness.new_store("happy", None);
    match linker.instantiate(&mut store, &harness.module) {
        Ok(_) => Ok(Outcome {
            status: "completed",
            value: "unexpectedly instantiated without plexus::invoke_declared_action".to_owned(),
        }),
        Err(error) => Ok(Outcome {
            status: "error",
            value: error.to_string(),
        }),
    }
}

fn parse_default_output(output: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

fn resource_containment(
    harness: &WasmHarness,
    guest_path: &Path,
) -> Result<WasmResourceContainment, Box<dyn Error>> {
    let quickjs_memory_limit_result = run_or_error(harness.run_scenario("memory", None));
    let wasm_linear_memory_result =
        run_or_error(harness.run_scenario("wasm_memory", Some(WASM_MEMORY_LIMIT_BYTES)));
    let quickjs_stack_result = run_or_error(harness.run_scenario("stack", None));

    let (mut store, output) = harness.new_store("timeout", None);
    store.set_epoch_deadline(1);
    let instance = harness.pre.instantiate(&mut store)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    let epoch_engine = harness.engine.clone();
    let timer = thread::spawn(move || {
        thread::sleep(TIMEOUT);
        epoch_engine.increment_epoch();
    });
    let timeout_started = Instant::now();
    let timeout_result = match start.call(&mut store, ()) {
        Ok(()) => String::from_utf8(output.contents().to_vec())?,
        Err(error) => error.to_string(),
    };
    let timeout_actual_us = timeout_started.elapsed().as_micros();
    timer.join().expect("epoch timer thread panicked");
    let post_interrupt_harness = WasmHarness::new(guest_path)?;
    let post_interrupt_new_store_result = post_interrupt_harness.run_scenario("health", None)?;

    Ok(WasmResourceContainment {
        quickjs_memory_limit_bytes: 2 * 1024 * 1024,
        quickjs_memory_limit_result,
        wasm_linear_memory_limit_bytes: WASM_MEMORY_LIMIT_BYTES,
        wasm_linear_memory_allocation_bytes: 64 * 1024 * 1024,
        wasm_linear_memory_result,
        quickjs_stack_limit_bytes: 64 * 1024,
        quickjs_stack_result,
        timeout_limit_us: TIMEOUT.as_micros(),
        timeout_result,
        timeout_actual_us,
        timeout_overrun_us: timeout_actual_us.saturating_sub(TIMEOUT.as_micros()),
        post_interrupt_new_store_result,
    })
}

fn run_or_error(result: Result<String, Box<dyn Error>>) -> String {
    result.unwrap_or_else(|error| format!("host error: {error}"))
}

fn lifecycle(
    harness: &WasmHarness,
    cold_engine_module_store_instance_guest_us: u128,
) -> Result<WasmLifecycle, Box<dyn Error>> {
    let mut samples = Vec::with_capacity(WASM_SAMPLE_COUNT);
    for _ in 0..WASM_SAMPLE_COUNT {
        let started = Instant::now();
        let output = harness.run_scenario("happy", None)?;
        assert_eq!(output, r#"{"ok":true,"value":7,"summary":"probe:7"}"#);
        samples.push(started.elapsed().as_micros());
    }
    Ok(WasmLifecycle {
        cold_engine_module_store_instance_guest_us,
        cached_module_fresh_store_instance_guest_us: distribution(samples),
    })
}

fn memory_measurement(harness: &WasmHarness) -> Result<WasmMemory, Box<dyn Error>> {
    let process_resident_before_bytes = resident_bytes();
    let mut live_stores = Vec::with_capacity(LIVE_STORE_COUNT);

    for _ in 0..LIVE_STORE_COUNT {
        let (mut store, output) = harness.new_store("happy", None);
        let instance = harness.pre.instantiate(&mut store)?;
        let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
        start.call(&mut store, ())?;
        assert_eq!(
            String::from_utf8(output.contents().to_vec())?,
            r#"{"ok":true,"value":7,"summary":"probe:7"}"#
        );
        live_stores.push((store, instance, output));
    }

    let process_resident_with_live_stores_bytes = resident_bytes();
    drop(live_stores);
    let process_resident_after_teardown_bytes = resident_bytes();
    let process_resident_delta_per_store_bytes = match (
        process_resident_before_bytes,
        process_resident_with_live_stores_bytes,
    ) {
        (Some(before), Some(with_stores)) => Some(
            (with_stores as i128 - before as i128)
                .div_euclid(LIVE_STORE_COUNT as i128)
                .try_into()?,
        ),
        _ => None,
    };

    Ok(WasmMemory {
        live_store_count: LIVE_STORE_COUNT,
        process_resident_before_bytes,
        process_resident_with_live_stores_bytes,
        process_resident_after_teardown_bytes,
        process_resident_delta_per_store_bytes,
    })
}
