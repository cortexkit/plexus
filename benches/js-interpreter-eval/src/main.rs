use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs,
    path::Path,
    time::{Duration, Instant},
};

use rquickjs::{Context, Ctx, Runtime, function::Func};
use serde::Serialize;

mod bellard;
mod wasm;

const SAMPLE_COUNT: usize = 1_000;
const LIVE_CONTEXT_COUNT: usize = 128;
const TIMEOUT: Duration = Duration::from_millis(10);
const MEMORY_LIMIT_BYTES: usize = 2 * 1024 * 1024;
const STACK_LIMIT_BYTES: usize = 64 * 1024;

// This is deliberately a small, representative probe rather than a throughput workload.
const PROBE_SCRIPT: &str = r#"
const actionValue = invoke();
const isExpected = actionValue === 7;
const label = "probe";
const result = {
    ok: isExpected,
    value: actionValue,
    label,
};
const summary = `${result.label}:${result.value}`;
const typed = {
    ok: result.ok,
    value: result.value,
    summary,
};
JSON.stringify(typed);
"#;

#[derive(Serialize)]
struct Report {
    harness_version: &'static str,
    arm: &'static str,
    engine: &'static str,
    platform: String,
    rustc: String,
    sample_count: usize,
    defaults: BTreeMap<&'static str, Outcome>,
    resource_containment: ResourceContainment,
    lifecycle: Lifecycle,
    memory: Memory,
    bellard: bellard::BellardReport,
    wasm: wasm::WasmReport,
}

#[derive(Serialize)]
struct Outcome {
    status: &'static str,
    value: String,
}

#[derive(Serialize)]
struct ResourceContainment {
    memory_limit_bytes: usize,
    memory_allocation_bytes: usize,
    memory_limit_result: Outcome,
    stack_limit_bytes: usize,
    stack_result: Outcome,
    timeout_limit_us: u128,
    timeout_result: Outcome,
    timeout_actual_us: u128,
    timeout_overrun_us: u128,
    post_interrupt_result: Outcome,
}

#[derive(Serialize)]
struct Lifecycle {
    cold_first_execution_us: u128,
    fresh_runtime_context_run_teardown_us: Distribution,
}

#[derive(Serialize)]
struct Distribution {
    min_us: u128,
    p50_us: u128,
    p95_us: u128,
    max_us: u128,
    mean_us: u128,
}

#[derive(Serialize)]
struct ByteDistribution {
    min_bytes: u128,
    p50_bytes: u128,
    p95_bytes: u128,
    max_bytes: u128,
    mean_bytes: u128,
}

#[derive(Serialize)]
struct Memory {
    live_context_count: usize,
    process_resident_before_bytes: Option<u64>,
    process_resident_with_live_contexts_bytes: Option<u64>,
    process_resident_after_teardown_bytes: Option<u64>,
    process_resident_delta_per_context_bytes: Option<i64>,
    quickjs_memory_used_per_live_context_bytes: ByteDistribution,
}

fn main() -> Result<(), Box<dyn Error>> {
    let output_path = env::args().nth(1);
    let report = run()?;
    let json = serde_json::to_string_pretty(&report)?;

    if let Some(output_path) = output_path {
        let path = Path::new(&output_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, format!("{json}\n"))?;
    } else {
        println!("{json}");
    }

    Ok(())
}

fn run() -> Result<Report, Box<dyn Error>> {
    // Keep the first real execution separate: it is the process-cold result.
    let cold_started = Instant::now();
    let cold_result = run_probe()?;
    assert_eq!(cold_result, r#"{"ok":true,"value":7,"summary":"probe:7"}"#);
    let cold_first_execution_us = cold_started.elapsed().as_micros();

    let defaults = default_capability_probes()?;
    let resource_containment = resource_containment()?;
    let lifecycle = Lifecycle {
        cold_first_execution_us,
        fresh_runtime_context_run_teardown_us: lifecycle_distribution()?,
    };
    let memory = memory_measurement()?;
    let bellard = bellard::run()?;
    let wasm = wasm::run(&wasm::guest_path())?;

    Ok(Report {
        harness_version: "1",
        arm: "rquickjs",
        engine: "QuickJS-NG through rquickjs 0.12.2",
        platform: format!("{}-{}", env::consts::ARCH, env::consts::OS),
        rustc: rustc_version(),
        sample_count: SAMPLE_COUNT,
        defaults,
        resource_containment,
        lifecycle,
        memory,
        bellard,
        wasm,
    })
}

fn default_capability_probes() -> Result<BTreeMap<&'static str, Outcome>, Box<dyn Error>> {
    let (_, context) = fresh_context()?;
    let probes = [
        (
            "file_read",
            r#"try { std.loadFile('/etc/passwd') } catch (error) { String(error) }"#,
        ),
        (
            "socket_open",
            r#"try { new WebSocket('ws://127.0.0.1:9') } catch (error) { String(error) }"#,
        ),
        (
            "process_spawn",
            r#"try { os.exec(['id']) } catch (error) { String(error) }"#,
        ),
        (
            "environment_read",
            r#"try { std.getenv('HOME') } catch (error) { String(error) }"#,
        ),
        (
            "host_adjacent_globals",
            r#"[typeof std, typeof os, typeof process, typeof Deno, typeof Bun, typeof require, typeof fetch, typeof WebSocket, typeof invoke].join(',')"#,
        ),
    ];

    let mut results = BTreeMap::new();
    for (name, source) in probes {
        results.insert(name, eval_string(&context, source));
    }
    Ok(results)
}

fn resource_containment() -> Result<ResourceContainment, Box<dyn Error>> {
    let memory_limit_result = {
        let (runtime, context) = fresh_context_with_limits(MEMORY_LIMIT_BYTES, 0)?;
        let result = eval_string(
            &context,
            r#"try { new ArrayBuffer(64 * 1024 * 1024); 'allocation completed' } catch (error) { String(error) }"#,
        );
        drop(context);
        drop(runtime);
        result
    };

    let stack_result = {
        let (runtime, context) = fresh_context_with_limits(0, STACK_LIMIT_BYTES)?;
        let result = eval_string(&context, "(function dive(n) { return dive(n + 1); })(0)");
        drop(context);
        drop(runtime);
        result
    };

    let (runtime, context) = fresh_context()?;
    let interrupt_started = Instant::now();
    let limit = TIMEOUT;
    runtime.set_interrupt_handler(Some(Box::new(move || interrupt_started.elapsed() >= limit)));
    let timeout_result = eval_string(&context, "while (true) {};");
    let timeout_actual_us = interrupt_started.elapsed().as_micros();
    runtime.set_interrupt_handler(None);
    let post_interrupt_result = eval_string(&context, "String(6 * 7)");

    Ok(ResourceContainment {
        memory_limit_bytes: MEMORY_LIMIT_BYTES,
        memory_allocation_bytes: 64 * 1024 * 1024,
        memory_limit_result,
        stack_limit_bytes: STACK_LIMIT_BYTES,
        stack_result,
        timeout_limit_us: TIMEOUT.as_micros(),
        timeout_result,
        timeout_actual_us,
        timeout_overrun_us: timeout_actual_us.saturating_sub(TIMEOUT.as_micros()),
        post_interrupt_result,
    })
}

fn lifecycle_distribution() -> Result<Distribution, Box<dyn Error>> {
    let mut samples = Vec::with_capacity(SAMPLE_COUNT);
    for _ in 0..SAMPLE_COUNT {
        let started = Instant::now();
        let result = run_probe()?;
        assert_eq!(result, r#"{"ok":true,"value":7,"summary":"probe:7"}"#);
        samples.push(started.elapsed().as_micros());
    }
    Ok(distribution(samples))
}

fn memory_measurement() -> Result<Memory, Box<dyn Error>> {
    let process_resident_before_bytes = resident_bytes();
    let mut probes = Vec::with_capacity(LIVE_CONTEXT_COUNT);
    let mut quickjs_memory = Vec::with_capacity(LIVE_CONTEXT_COUNT);

    for _ in 0..LIVE_CONTEXT_COUNT {
        let (runtime, context) = fresh_context()?;
        let result = install_and_run(&context)?;
        assert_eq!(result, r#"{"ok":true,"value":7,"summary":"probe:7"}"#);
        quickjs_memory.push(runtime.memory_usage().memory_used_size as u128);
        probes.push((runtime, context));
    }

    let process_resident_with_live_contexts_bytes = resident_bytes();
    drop(probes);
    let process_resident_after_teardown_bytes = resident_bytes();
    let process_resident_delta_per_context_bytes = match (
        process_resident_before_bytes,
        process_resident_with_live_contexts_bytes,
    ) {
        (Some(before), Some(with_contexts)) => Some(
            (with_contexts as i128 - before as i128)
                .div_euclid(LIVE_CONTEXT_COUNT as i128)
                .try_into()?,
        ),
        _ => None,
    };

    Ok(Memory {
        live_context_count: LIVE_CONTEXT_COUNT,
        process_resident_before_bytes,
        process_resident_with_live_contexts_bytes,
        process_resident_after_teardown_bytes,
        process_resident_delta_per_context_bytes,
        quickjs_memory_used_per_live_context_bytes: byte_distribution(quickjs_memory),
    })
}

fn run_probe() -> Result<String, Box<dyn Error>> {
    let (runtime, context) = fresh_context()?;
    let result = install_and_run(&context)?;
    drop(context);
    drop(runtime);
    Ok(result)
}

fn fresh_context() -> Result<(Runtime, Context), rquickjs::Error> {
    fresh_context_with_limits(0, 0)
}

fn fresh_context_with_limits(
    memory_limit_bytes: usize,
    stack_limit_bytes: usize,
) -> Result<(Runtime, Context), rquickjs::Error> {
    let runtime = Runtime::new()?;
    runtime.set_memory_limit(memory_limit_bytes);
    runtime.set_max_stack_size(stack_limit_bytes);
    let context = Context::full(&runtime)?;
    Ok((runtime, context))
}

fn install_and_run(context: &Context) -> Result<String, rquickjs::Error> {
    context.with(|ctx| {
        ctx.globals().set("invoke", Func::from(|| 7_i32))?;
        ctx.eval(PROBE_SCRIPT)
    })
}

fn eval_string(context: &Context, source: &str) -> Outcome {
    context.with(|ctx| match ctx.eval::<String, _>(source) {
        Ok(value) => Outcome {
            status: "completed",
            value,
        },
        Err(error) => Outcome {
            status: "error",
            value: exception_message(&ctx, error),
        },
    })
}

fn exception_message(ctx: &Ctx<'_>, error: rquickjs::Error) -> String {
    if !ctx.has_exception() {
        return error.to_string();
    }

    let exception = ctx.catch();
    if ctx.globals().set("__eval_exception", exception).is_err() {
        return error.to_string();
    }

    ctx.eval::<String, _>("String(__eval_exception)")
        .unwrap_or_else(|_| error.to_string())
}

fn distribution(mut values: Vec<u128>) -> Distribution {
    assert!(!values.is_empty());
    values.sort_unstable();
    let len = values.len();
    let sum: u128 = values.iter().sum();
    Distribution {
        min_us: values[0],
        p50_us: values[(len - 1) / 2],
        p95_us: values[((len - 1) * 95) / 100],
        max_us: values[len - 1],
        mean_us: sum / len as u128,
    }
}

fn byte_distribution(mut values: Vec<u128>) -> ByteDistribution {
    assert!(!values.is_empty());
    values.sort_unstable();
    let len = values.len();
    let sum: u128 = values.iter().sum();
    ByteDistribution {
        min_bytes: values[0],
        p50_bytes: values[(len - 1) / 2],
        p95_bytes: values[((len - 1) * 95) / 100],
        max_bytes: values[len - 1],
        mean_bytes: sum / len as u128,
    }
}

fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
        .unwrap_or_else(|| "unavailable".to_owned())
}

#[cfg(target_os = "macos")]
fn resident_bytes() -> Option<u64> {
    use std::mem::MaybeUninit;

    use mach2::{
        kern_return::KERN_SUCCESS,
        task::task_info,
        task_info::{TASK_BASIC_INFO_64, TASK_BASIC_INFO_64_COUNT, task_basic_info_64},
        traps::mach_task_self,
    };

    let mut info = MaybeUninit::<task_basic_info_64>::zeroed();
    let mut count = TASK_BASIC_INFO_64_COUNT;
    let status = unsafe {
        task_info(
            mach_task_self(),
            TASK_BASIC_INFO_64,
            info.as_mut_ptr().cast(),
            &mut count,
        )
    };
    (status == KERN_SUCCESS).then(|| unsafe { info.assume_init().resident_size as u64 })
}

#[cfg(not(target_os = "macos"))]
fn resident_bytes() -> Option<u64> {
    None
}
