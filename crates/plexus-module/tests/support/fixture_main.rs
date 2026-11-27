//! Subprocess entry point for supervised test peers. Not a release binary.

use std::path::Path;
use std::process::{self, Command};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(target_os = "macos")]
    subc_os::privacy_identity::trampoline_main(&args);

    // The supervisor appends its own flags. Each mode reads only its own
    // positional arguments, so none of those flags reach the Rust test runner.
    match args[0].to_str() {
        Some("test" | "legacy-test" | "legacy-test-fd") => {
            let mut command = Command::new(&args[1]);
            command.arg("--exact").arg(&args[2]).arg("--nocapture");
            if args[0] != "test" {
                legacy_handoff(&mut command, args[0] == "legacy-test-fd");
            }
            launch(command);
        }
        Some("confirmation" | "confirmation-fd") => {
            // The test daemon publishes its key before the fake confirmation
            // peer can write a connection file. Bound the startup wait.
            let connection = Path::new(&args[2]);
            let end = Instant::now() + Duration::from_secs(30);
            while !connection.is_file() {
                assert!(Instant::now() < end, "confirmation file was not written");
                std::thread::sleep(Duration::from_millis(10));
            }
            let mut command = Command::new(&args[1]);
            command.arg("--subc").arg(connection);
            legacy_handoff(&mut command, args[0] == "confirmation-fd");
            launch(command);
        }
        Some("nonce") => {
            // The stand-in consumes the nonce itself, from fd 3 on Unix and
            // from the supervisor's named pipe on Windows. The test process
            // registers on its behalf while this supervised process stays up.
            let nonce = subc_os::launch_nonce()
                .unwrap()
                .expect("fixture launch nonce");
            #[cfg(unix)]
            assert_eq!(nonce.source(), subc_os::LaunchNonceSource::Fd);
            let output = Path::new(&args[1]);
            let temporary = output.with_extension("partial");
            std::fs::write(&temporary, nonce.value()).expect("write fixture nonce");
            std::fs::rename(temporary, output).expect("publish fixture nonce");
            std::thread::sleep(Duration::from_secs(120));
        }
        _ => process::exit(2),
    }
}

fn legacy_handoff(command: &mut Command, fd_only: bool) {
    command.env_remove("SUBC_REGISTRATION_FD");
    command.env_remove("SUBC_REGISTRATION_PIPE");
    if fd_only {
        command.env_remove(subc_os::LAUNCH_NONCE_ENV);
    }
}

#[cfg(unix)]
fn launch(mut command: Command) -> ! {
    use std::os::unix::process::CommandExt;
    // Exec preserves the supervised PID and the inherited nonce descriptor.
    panic!("exec fixture: {}", command.exec());
}

#[cfg(windows)]
fn launch(mut command: Command) -> ! {
    // The supervisor's nonce pipe authenticates the wrapper's PID, not its
    // child. The legacy peer uses the environment copy instead.
    command.env_remove(subc_os::LAUNCH_NONCE_PIPE_ENV);
    let status = command.status().expect("run fixture");
    process::exit(status.code().unwrap_or(1));
}
