use std::{
    cell::Cell,
    env,
    io::Read,
    mem::MaybeUninit,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};

use rquickjs::{
    Context, Ctx, Exception, Function, Runtime,
    allocator::{Allocator, RustAllocator},
    context::intrinsic,
    function::Func,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const ACTION_RESULT_CAPACITY: usize = 1024 * 1024;
const MAX_ERROR_BYTES: usize = 4096;
/// Limit the guest response to 64 KiB, matching the host's stdout pipe capacity
/// (`OUTPUT_CAPACITY` in plexus-probe/src/sandbox.rs). Writing beyond that
/// capacity makes `print!` panic, so the host sees a trap instead of a reason.
/// Answer an oversized return with a typed error small enough to fit the pipe.
const RESPONSE_LIMIT: usize = 64 * 1024;
/// Request a 256 KiB C-stack budget from QuickJS. This setting does not size the
/// linked WebAssembly stack. The pinned QuickJS implementation disables its
/// software stack check on WASI, so this value cannot guarantee a catchable
/// JavaScript exception for deep recursion. The host handles WebAssembly
/// stack-overflow traps as execution errors.
const MAX_STACK_BYTES: usize = 256 * 1024;

/// Set when QuickJS asked for memory and was refused. This, not the text of an
/// exception, is what makes a failure a memory-limit failure: a probe can throw
/// an error reading "out of memory" (or an `InternalError` of any message), but
/// it cannot make an allocation fail without actually exhausting memory.
static ALLOCATION_FAILED: AtomicBool = AtomicBool::new(false);

/// QuickJS's allocator: Rust's global allocator, recording any refusal.
struct RecordingAllocator(RustAllocator);

// SAFETY: every method forwards to `RustAllocator`, which upholds the trait's
// contract; the only addition is setting a flag when a request returns null.
unsafe impl Allocator for RecordingAllocator {
    fn alloc(&mut self, size: usize) -> *mut u8 {
        record_failure(self.0.alloc(size), size)
    }

    fn calloc(&mut self, count: usize, size: usize) -> *mut u8 {
        record_failure(self.0.calloc(count, size), count.saturating_mul(size))
    }

    unsafe fn dealloc(&mut self, pointer: *mut u8) {
        unsafe { self.0.dealloc(pointer) }
    }

    unsafe fn realloc(&mut self, pointer: *mut u8, new_size: usize) -> *mut u8 {
        record_failure(unsafe { self.0.realloc(pointer, new_size) }, new_size)
    }

    unsafe fn usable_size(pointer: *mut u8) -> usize {
        unsafe { RustAllocator::usable_size(pointer) }
    }
}

/// A null answer to a request for zero bytes is not a failure.
fn record_failure(pointer: *mut u8, size: usize) -> *mut u8 {
    if pointer.is_null() && size != 0 {
        ALLOCATION_FAILED.store(true, Ordering::SeqCst);
    }
    pointer
}

/// Uses JSON functions captured before the probe source runs to parse the
/// argument and serialize the probe's result.
const WRAPPER: &str = r#"
((parse, stringify) => function (entry, argument) {
    "use strict";
    if (typeof entry !== "function") {
        throw new TypeError("probe source must evaluate to a function");
    }
    const value = entry(parse(argument));
    const encoded = stringify(value);
    if (encoded === undefined) {
        throw new TypeError("probe return is not JSON-serializable");
    }
    return encoded;
})(JSON.parse, JSON.stringify)
"#;

#[link(wasm_import_module = "plexus")]
unsafe extern "C" {
    fn invoke_declared_action(
        action_pointer: i32,
        action_length: i32,
        argument_pointer: i32,
        argument_length: i32,
        output_pointer: i32,
        output_capacity: i32,
    ) -> i32;
}

#[link(wasm_import_module = "wasi_snapshot_preview1")]
unsafe extern "C" {
    #[link_name = "fd_prestat_get"]
    fn wasi_fd_prestat_get(descriptor: i32, prestat: *mut WasiPrestat) -> u16;
}

#[repr(C)]
union WasiPrestatBody {
    directory_name_length: u32,
}

#[repr(C)]
struct WasiPrestat {
    tag: u8,
    body: WasiPrestatBody,
}

#[derive(Deserialize)]
struct Request {
    source: String,
    argument: Value,
}

#[derive(Serialize)]
struct Response {
    host: HostObservation,
    outcome: Outcome,
}

#[derive(Serialize)]
struct HostObservation {
    environment_variable_count: usize,
    preopened_directory_count: usize,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome {
    Ok { value: Value },
    Execution { message: String },
    Memory,
    ResultTooLarge { bytes: usize, limit: usize },
}

fn main() {
    let host = HostObservation {
        environment_variable_count: env::vars_os().count(),
        preopened_directory_count: preopened_directory_count(),
    };
    let outcome = read_request()
        .and_then(run_probe)
        .unwrap_or_else(|message| Outcome::Execution {
            message: truncate(message),
        });
    let mut response = Response { host, outcome };
    let mut encoded = serde_json::to_string(&response).unwrap_or_else(|_| {
        r#"{"host":{"environment_variable_count":0,"preopened_directory_count":0},"outcome":{"status":"memory"}}"#.to_owned()
    });
    if encoded.len() > RESPONSE_LIMIT {
        // Only a returned value can be this large: error messages are
        // truncated to MAX_ERROR_BYTES. The replacement is a few dozen bytes.
        response.outcome = Outcome::ResultTooLarge {
            bytes: encoded.len(),
            limit: RESPONSE_LIMIT,
        };
        encoded = serde_json::to_string(&response).unwrap_or_default();
    }
    print!("{encoded}");
}

fn read_request() -> Result<Request, String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("could not read probe request: {error}"))?;
    serde_json::from_str(&input).map_err(|error| format!("invalid probe request: {error}"))
}

fn run_probe(request: Request) -> Result<Outcome, String> {
    let runtime =
        Runtime::new_with_alloc(RecordingAllocator(RustAllocator)).map_err(|error| error.to_string())?;
    runtime.set_max_stack_size(MAX_STACK_BYTES);
    let context = Context::builder()
        .with::<intrinsic::Eval>()
        .with::<intrinsic::Json>()
        .build(&runtime)
        .map_err(|error| error.to_string())?;
    let argument = serde_json::to_string(&request.argument).map_err(|error| error.to_string())?;

    context.with(|ctx| {
        let actions_enabled = Rc::new(Cell::new(true));
        install_invoke(&ctx, actions_enabled.clone()).map_err(|error| exception_message(&ctx, error))?;
        let evaluated = (|| -> rquickjs::Result<String> {
            let wrapper: Function = ctx.eval(WRAPPER)?;
            // The source is compiled as a script of its own, in parentheses so
            // that any function EXPRESSION is accepted, including the anonymous
            // `function (input) { ... }` form. Unbalanced text in it can only
            // break that script, never the wrapper: its completion value is
            // what the wrapper receives, and the wrapper still refuses anything
            // that is not a function.
            let entry: rquickjs::Value =
                ctx.eval(format!("\"use strict\";(\n{}\n)", request.source))?;
            wrapper.call((entry, argument))
        })();
        match evaluated {
            Ok(encoded) => serde_json::from_str(&encoded)
                .map(|value| Outcome::Ok { value })
                .map_err(|error| format!("probe returned invalid JSON: {error}")),
            Err(error) => {
                // Accessing an exception's message can execute a user-defined
                // getter. Once evaluation fails, that getter must not call the host.
                actions_enabled.set(false);
                let message = exception_message(&ctx, error);
                if ALLOCATION_FAILED.load(Ordering::SeqCst) {
                    Ok(Outcome::Memory)
                } else {
                    Ok(Outcome::Execution {
                        message: truncate(message),
                    })
                }
            }
        }
    })
}

fn install_invoke(ctx: &Ctx<'_>, actions_enabled: Rc<Cell<bool>>) -> rquickjs::Result<()> {
    ctx.globals().set(
        "__plexus_raw_invoke",
        Func::from(move |ctx: Ctx<'_>, action: String, argument: String| {
            if !actions_enabled.get() {
                return Err(Exception::throw_message(&ctx, "actions are disabled after probe failure"));
            }
            invoke_raw(&ctx, action, argument)
        }),
    )?;
    ctx.eval::<(), _>(
        r#"
Object.defineProperty(globalThis, "invoke", {
    value: ((hostInvoke, parse, stringify) => function invoke(action, argument) {
        if (typeof action !== "string") {
            throw new TypeError("invoke action must be a string");
        }
        const encoded = stringify(argument);
        if (encoded === undefined) {
            throw new TypeError("invoke argument is not JSON-serializable");
        }
        return parse(hostInvoke(action, encoded));
    })(__plexus_raw_invoke, JSON.parse, JSON.stringify),
    writable: false,
    configurable: false,
    enumerable: true,
});
delete globalThis.__plexus_raw_invoke;
"#,
    )
}

fn invoke_raw(ctx: &Ctx<'_>, action: String, argument: String) -> rquickjs::Result<String> {
    let mut output = vec![0_u8; ACTION_RESULT_CAPACITY];
    // The host validates all guest pointers before reading or writing linear memory.
    let length = unsafe {
        invoke_declared_action(
            action.as_ptr() as i32,
            action.len() as i32,
            argument.as_ptr() as i32,
            argument.len() as i32,
            output.as_mut_ptr() as i32,
            output.len() as i32,
        )
    };
    if length < 0 {
        return Err(Exception::throw_message(
            ctx,
            "declared action invocation was refused by the host",
        ));
    }
    let length = usize::try_from(length)
        .map_err(|_| Exception::throw_message(ctx, "host returned an invalid action length"))?;
    String::from_utf8(output[..length].to_vec())
        .map_err(|_| Exception::throw_message(ctx, "host returned non-UTF-8 action data"))
}

fn exception_message(ctx: &Ctx<'_>, error: rquickjs::Error) -> String {
    if !ctx.has_exception() {
        return error.to_string();
    }
    let exception = ctx.catch();
    if let Some(exception) = exception.as_exception() {
        exception.message().unwrap_or_else(|| error.to_string())
    } else if let Some(message) = exception.as_string() {
        message.to_string().unwrap_or_else(|_| error.to_string())
    } else {
        error.to_string()
    }
}

fn preopened_directory_count() -> usize {
    (3..128)
        .filter(|descriptor| {
            let mut prestat = MaybeUninit::<WasiPrestat>::uninit();
            // WASI reserves descriptors from three upward for host preopens. Invalid
            // descriptors return an errno without initializing or exposing memory.
            unsafe { wasi_fd_prestat_get(*descriptor, prestat.as_mut_ptr()) == 0 }
        })
        .count()
}

fn truncate(mut message: String) -> String {
    if message.len() <= MAX_ERROR_BYTES {
        return message;
    }
    let mut boundary = MAX_ERROR_BYTES;
    while !message.is_char_boundary(boundary) {
        boundary -= 1;
    }
    message.truncate(boundary);
    message
}
