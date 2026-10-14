use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use quickjs_runtime::{
    builder::QuickJsRuntimeBuilder, facades::QuickJsRuntimeFacade, jsutils::Script,
    values::JsValueFacade,
};
use serde::Serialize;

const SAMPLE_COUNT: usize = 100;
const LIVE_RUNTIME_COUNT: usize = 16;
const TIMEOUT: Duration = Duration::from_millis(10);
const MEMORY_LIMIT_BYTES: u64 = 2 * 1024 * 1024;
const STACK_LIMIT_BYTES: u64 = 64 * 1024;

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
    arm: &'static str,
    binding: &'static str,
    sample_count: usize,
    defaults: BTreeMap<&'static str, Outcome>,
    resource_containment: ResourceContainment,
    lifecycle: Lifecycle,
    memory: Memory,
}

#[derive(Serialize)]
struct Outcome {
    status: &'static str,
    value: String,
}

#[derive(Serialize)]
struct ResourceContainment {
    memory_limit_bytes: u64,
    memory_allocation_bytes: u64,
    memory_limit_result: Outcome,
    stack_limit_bytes: u64,
    stack_result: Outcome,
    timeout_limit_us: u128,
    timeout_result: Outcome,
    timeout_actual_us: u128,
    timeout_overrun_us: u128,
    post_interrupt_result: Outcome,
}

#[derive(Serialize)]
struct Lifecycle {
    cold_process_first_execution_us: u128,
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
    live_runtime_count: usize,
    process_resident_before_bytes: Option<u64>,
    process_resident_with_live_runtimes_bytes: Option<u64>,
    process_resident_after_teardown_bytes: Option<u64>,
    process_resident_delta_per_runtime_bytes: Option<i64>,
    quickjs_memory_used_per_live_runtime_bytes: ByteDistribution,
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
    let cold_started = Instant::now();
    let cold = run_probe()?;
    assert_eq!(cold, r#"{"ok":true,"value":7,"summary":"probe:7"}"#);

    Ok(Report {
        arm: "Bellard upstream QuickJS through quickjs_runtime",
        binding: "quickjs_runtime 0.17.2 with only its bellard feature; no wrapper-added JS features enabled",
        sample_count: SAMPLE_COUNT,
        defaults: default_capability_probes()?,
        resource_containment: resource_containment()?,
        lifecycle: Lifecycle {
            cold_process_first_execution_us: cold_started.elapsed().as_micros(),
            fresh_runtime_context_run_teardown_us: lifecycle_distribution()?,
        },
        memory: memory_measurement()?,
    })
}

fn default_capability_probes() -> Result<BTreeMap<&'static str, Outcome>, Box<dyn Error>> {
    let runtime = new_runtime(None, None, None);
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
        results.insert(name, eval_string(&runtime, source));
    }
    Ok(results)
}

fn resource_containment() -> Result<ResourceContainment, Box<dyn Error>> {
    let memory_runtime = new_runtime(Some(MEMORY_LIMIT_BYTES), None, None);
    let memory_limit_result = eval_string(
        &memory_runtime,
        r#"try { new ArrayBuffer(64 * 1024 * 1024); 'allocation completed' } catch (error) { String(error) }"#,
    );

    let stack_runtime = new_runtime(None, Some(STACK_LIMIT_BYTES), None);
    let stack_result = eval_string(
        &stack_runtime,
        "(function dive(n) { return dive(n + 1); })(0)",
    );

    let deadline = Arc::new(Mutex::new(None));
    let runtime = new_runtime(None, None, Some(Arc::clone(&deadline)));
    *deadline.lock().expect("interrupt deadline mutex poisoned") = Some(Instant::now());
    let timeout_result = eval_string(&runtime, "while (true) {};");
    let timeout_actual_us = deadline
        .lock()
        .expect("interrupt deadline mutex poisoned")
        .expect("interrupt deadline set")
        .elapsed()
        .as_micros();
    *deadline.lock().expect("interrupt deadline mutex poisoned") = None;
    let post_interrupt_result = eval_string(&runtime, "String(6 * 7)");

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
    let mut runtimes = Vec::with_capacity(LIVE_RUNTIME_COUNT);
    let mut quickjs_memory = Vec::with_capacity(LIVE_RUNTIME_COUNT);

    for _ in 0..LIVE_RUNTIME_COUNT {
        let runtime = installed_runtime()?;
        let result = eval_string(&runtime, PROBE_SCRIPT);
        assert_eq!(result.value, r#"{"ok":true,"value":7,"summary":"probe:7"}"#);
        quickjs_memory.push(
            runtime
                .exe_rt_task_in_event_loop(|quickjs| quickjs.memory_usage().memory_used_size)
                .max(0) as u128,
        );
        runtimes.push(runtime);
    }

    let process_resident_with_live_runtimes_bytes = resident_bytes();
    drop(runtimes);
    let process_resident_after_teardown_bytes = resident_bytes();
    let process_resident_delta_per_runtime_bytes = match (
        process_resident_before_bytes,
        process_resident_with_live_runtimes_bytes,
    ) {
        (Some(before), Some(with_runtimes)) => Some(
            (with_runtimes as i128 - before as i128)
                .div_euclid(LIVE_RUNTIME_COUNT as i128)
                .try_into()?,
        ),
        _ => None,
    };

    Ok(Memory {
        live_runtime_count: LIVE_RUNTIME_COUNT,
        process_resident_before_bytes,
        process_resident_with_live_runtimes_bytes,
        process_resident_after_teardown_bytes,
        process_resident_delta_per_runtime_bytes,
        quickjs_memory_used_per_live_runtime_bytes: byte_distribution(quickjs_memory),
    })
}

fn run_probe() -> Result<String, Box<dyn Error>> {
    let runtime = installed_runtime()?;
    let outcome = eval_string(&runtime, PROBE_SCRIPT);
    if outcome.status == "completed" {
        Ok(outcome.value)
    } else {
        Err(format!("probe failed: {}", outcome.value).into())
    }
}

fn installed_runtime() -> Result<QuickJsRuntimeFacade, Box<dyn Error>> {
    let runtime = new_runtime(None, None, None);
    runtime.set_function(&[], "invoke", |_realm, _args| Ok(JsValueFacade::new_i32(7)))?;
    Ok(runtime)
}

fn new_runtime(
    memory_limit: Option<u64>,
    stack_limit: Option<u64>,
    deadline: Option<Arc<Mutex<Option<Instant>>>>,
) -> QuickJsRuntimeFacade {
    let builder = QuickJsRuntimeBuilder::new();
    let builder = match memory_limit {
        Some(limit) => builder.memory_limit(limit),
        None => builder,
    };
    let builder = match stack_limit {
        Some(limit) => builder.max_stack_size(limit),
        None => builder,
    };
    let builder = match deadline {
        Some(deadline) => builder.set_interrupt_handler(move |_| {
            deadline
                .lock()
                .expect("interrupt deadline mutex poisoned")
                .is_some_and(|started| started.elapsed() >= TIMEOUT)
        }),
        None => builder,
    };
    builder.build()
}

fn eval_string(runtime: &QuickJsRuntimeFacade, source: &str) -> Outcome {
    match runtime.eval_sync(None, Script::new("eval.js", source)) {
        Ok(value) if value.is_string() => Outcome {
            status: "completed",
            value: value.get_str().to_owned(),
        },
        Ok(value) => Outcome {
            status: "completed",
            value: value.stringify(),
        },
        Err(error) => Outcome {
            status: "error",
            value: format!("{}: {}", error.get_name(), error.get_message()),
        },
    }
}

fn distribution(mut values: Vec<u128>) -> Distribution {
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
