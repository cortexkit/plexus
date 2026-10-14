//! `ck-plexus --smoke-probe`: run one real guest through the production probe
//! sandbox and report whether it worked.
//!
//! A binary can look perfectly healthy and still be unable to run a guest. The
//! release binaries are signed with macOS hardened runtime, and a signature or
//! engine setting that forbids the code the sandbox needs is only discovered
//! when a guest first executes: the process is killed, not refused. Flags read
//! back from `codesign` describe the signature, not whether the sandbox
//! survives it. Staging and post-placement acceptance therefore run this
//! against the exact file they signed or placed.
//!
//! No supervisor environment, store or network is involved: the guest is the
//! embedded QuickJS module, the script is a constant, and it declares no
//! actions, so the sandbox's only host callback cannot be reached.

use plexus_probe::{ProbeSandbox, ProbeValue, ReturnSchema};
use serde_json::{json, Value};

/// The script the smoke run evaluates. Computing the answer from the input,
/// rather than returning a literal, shows that the argument crossed into the
/// guest and the result came back out of it.
///
/// The binary-level tests locate this exact text in the built executable and
/// overwrite it, to prove that a failing guest makes the flag exit non-zero.
/// Keep it a single literal that appears nowhere else in the binary.
pub const SMOKE_PROBE_SOURCE: &str = "input => input.left * input.right";

const SMOKE_PROBE_EXPECTED: f64 = 42.0;

/// Runs the smoke guest. `Ok` carries the line to print on success; `Err`
/// carries the reason the guest did not produce the expected answer.
pub fn smoke_probe() -> Result<String, String> {
    let sandbox = ProbeSandbox::new(Vec::<String>::new())
        .map_err(|error| format!("the probe sandbox could not start: {error}"))?;
    let value = sandbox
        .run(
            SMOKE_PROBE_SOURCE,
            json!({ "left": 6, "right": 7 }),
            &ReturnSchema::Number,
            |action: &str, _: Value| {
                Err(format!(
                    "the smoke probe declares no actions but invoked {action}"
                ))
            },
        )
        .map_err(|error| format!("the smoke guest failed: {error}"))?;
    match value {
        ProbeValue::Number(number) if number.as_f64() == Some(SMOKE_PROBE_EXPECTED) => Ok(format!(
            "ck-plexus smoke-probe ok: sandbox guest returned {number}"
        )),
        other => Err(format!(
            "the smoke guest returned {other:?}, expected {SMOKE_PROBE_EXPECTED}"
        )),
    }
}
