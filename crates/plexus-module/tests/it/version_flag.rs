//! `ck-plexus --version` must answer outside supervision. Placement scripts run
//! it on a staged binary before any supervisor has set SUBC_MODULE_ID, and it
//! used to exit with "SUBC_MODULE_ID is not set" like a normal launch.

use super::bounded;

use std::process::Command;

use cortexkit_test_support::ckdev_binary;

#[test]
fn test_binary_spawns_use_ckdev_names() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates");
    cortexkit_test_support::assert_test_binary_spawns(&[crates]);
}

#[test]
fn version_answers_with_no_supervisor_environment() {
    let binary = ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus"));
    let output = bounded::child_output(
        Command::new(&binary).arg("--version").env_clear(),
        std::time::Duration::from_secs(60),
        "test binary command",
    )
    .expect("run ck-plexus --version");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "--version exited {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout.trim(), plexus_module::version_line());
    assert!(
        stdout.contains(env!("PLEXUS_BUILD_COMMIT")),
        "the version line names the build commit: {stdout}"
    );
}

#[test]
fn a_normal_launch_still_requires_the_supervisor_environment() {
    let binary = ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus"));
    let output = bounded::child_output(
        Command::new(&binary).env_clear(),
        std::time::Duration::from_secs(60),
        "test binary command",
    )
    .expect("run ck-plexus");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // A refusal, not a crash: a panic also exits unsuccessfully (101), so the
    // exit code and the reason are checked, not only failure.
    assert_eq!(
        output.status.code(),
        Some(1),
        "a launch without SUBC_MODULE_ID must refuse, not start or crash: {stderr}"
    );
    assert!(
        stderr.starts_with("ck-plexus: ") && stderr.contains("SUBC_MODULE_ID"),
        "the refusal must name the missing supervisor variable: {stderr}"
    );
}

/// An argument that is not UTF-8 is refused like any other unexpected launch,
/// never by a panic while reading the command line.
#[cfg(unix)]
#[test]
fn a_non_utf8_argument_does_not_panic() {
    use std::os::unix::ffi::OsStrExt;
    let binary = ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus"));
    let output = bounded::child_output(
        Command::new(&binary)
            .arg(std::ffi::OsStr::from_bytes(b"--vers\xffion"))
            .env_clear(),
        std::time::Duration::from_secs(60),
        "test binary command",
    )
    .expect("run ck-plexus");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "a non-UTF-8 argument must not panic: {stderr}"
    );
    assert_ne!(output.status.code(), Some(101), "{stderr}");
}
