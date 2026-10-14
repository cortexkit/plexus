use std::env;

use rquickjs::{Context, Ctx, Runtime, function::Func};

const MEMORY_LIMIT_BYTES: usize = 2 * 1024 * 1024;
const STACK_LIMIT_BYTES: usize = 64 * 1024;

#[link(wasm_import_module = "plexus")]
unsafe extern "C" {
    // The WebAssembly host decides whether to provide this one declared action.
    fn invoke_declared_action() -> i32;
}

fn main() {
    let scenario = env::args().nth(1).unwrap_or_else(|| "default".to_owned());
    let output = match scenario.as_str() {
        "default" => default_capability_probes(),
        "happy" => run_probe(),
        "memory" => limited_memory(),
        "wasm_memory" => wasm_limited_memory(),
        "stack" => limited_stack(),
        "timeout" => {
            let (_, context) = fresh_context(0, 0).expect("context");
            eval_string(&context, "while (true) {};")
        }
        "health" => {
            let (_, context) = fresh_context(0, 0).expect("context");
            eval_string(&context, "String(6 * 7)")
        }
        unknown => format!("unknown scenario: {unknown}"),
    };
    print!("{output}");
}

fn default_capability_probes() -> String {
    let (_, context) = fresh_context(0, 0).expect("context");
    [
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
    ]
    .into_iter()
    .map(|(name, source)| format!("{name}={}", eval_string(&context, source)))
    .collect::<Vec<_>>()
    .join("\n")
}

fn run_probe() -> String {
    let (_, context) = fresh_context(0, 0).expect("context");
    context
        .with(|ctx| {
            ctx.globals()
                .set("invoke", Func::from(|| unsafe { invoke_declared_action() }))?;
            ctx.eval::<String, _>(
                r#"
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
"#,
            )
        })
        .unwrap_or_else(|error| format!("error: {error}"))
}

fn limited_memory() -> String {
    let (_, context) = fresh_context(MEMORY_LIMIT_BYTES, 0).expect("context");
    eval_string(
        &context,
        r#"try { new ArrayBuffer(64 * 1024 * 1024); 'allocation completed' } catch (error) { String(error) }"#,
    )
}

fn wasm_limited_memory() -> String {
    let (_, context) = fresh_context(0, 0).expect("context");
    eval_string(
        &context,
        r#"try { new ArrayBuffer(64 * 1024 * 1024); 'allocation completed' } catch (error) { String(error) }"#,
    )
}

fn limited_stack() -> String {
    let (_, context) = fresh_context(0, STACK_LIMIT_BYTES).expect("context");
    eval_string(&context, "(function dive(n) { return dive(n + 1); })(0)")
}

fn fresh_context(
    memory_limit_bytes: usize,
    stack_limit_bytes: usize,
) -> Result<(Runtime, Context), rquickjs::Error> {
    let runtime = Runtime::new()?;
    runtime.set_memory_limit(memory_limit_bytes);
    runtime.set_max_stack_size(stack_limit_bytes);
    let context = Context::full(&runtime)?;
    Ok((runtime, context))
}

fn eval_string(context: &Context, source: &str) -> String {
    context.with(|ctx| match ctx.eval::<String, _>(source) {
        Ok(value) => value,
        Err(error) => exception_message(&ctx, error),
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
