#![forbid(unsafe_code)]

use std::process::ExitCode;

/// A startup failure is printed to stderr as one plain line before the process
/// exits. Plexus's other diagnostics go to its log file under its data
/// directory, but the daemon captures each module's stderr separately (that
/// capture is what `ck module logs` and test harnesses read), so a module that
/// dies during startup, such as when the daemon's one-time launch secret
/// cannot be read, must say why there too.
fn main() -> ExitCode {
    let runtime = match plexus_module::daemon_runtime::build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ck-plexus: failed to build runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(plexus_module::run_entry()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ck-plexus: {error}");
            ExitCode::FAILURE
        }
    }
}
