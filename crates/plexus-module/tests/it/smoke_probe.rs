//! `ck-plexus --smoke-probe` must run a real guest outside supervision and let
//! its exit status say whether the guest worked. Staging and post-placement
//! checks refuse a binary on a non-zero exit, so a flag that exits 0 without
//! running the guest would pass every binary, including one that dies on its
//! first real probe.

use super::bounded;

use cortexkit_test_support::ckdev_binary;
use plexus_core::test_scratch::Scratch;
use plexus_module::smoke::SMOKE_PROBE_SOURCE;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::Duration,
};

/// Runs `binary --smoke-probe` with an empty environment, as a placement
/// script would before any supervisor has set one up.
///
/// Retries while the kernel still reports the freshly written copy as busy:
/// on Linux another test thread forking while the copy was open for writing
/// can hold it open briefly, which is unrelated to what these tests check.
fn smoke(binary: &Path) -> Output {
    for _ in 0..20 {
        match bounded::child_output(
            Command::new(binary).arg("--smoke-probe").env_clear(),
            std::time::Duration::from_secs(60),
            "test binary command",
        ) {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                thread::sleep(Duration::from_millis(50));
            }
            result => return result.expect("run ck-plexus --smoke-probe"),
        }
    }
    panic!("{} stayed busy", binary.display());
}

/// Signs `binary` the way scripts/stage-binaries.sh does: ad-hoc, hardened
/// runtime, no entitlements. Also required after patching bytes, because
/// macOS kills a process whose pages no longer match its signature, which
/// would make the failure test pass for the wrong reason.
#[cfg(target_os = "macos")]
fn sign_hardened(binary: &Path) {
    let status = bounded::child_output(
        Command::new("codesign")
            .args(["--force", "--sign", "-", "-o", "runtime", "--identifier"])
            .arg("ck-plexus")
            .arg(binary),
        std::time::Duration::from_secs(60),
        "codesign",
    )
    .expect("run codesign")
    .status;
    assert!(status.success(), "codesign failed: {status:?}");
}

#[cfg(not(target_os = "macos"))]
fn sign_hardened(_: &Path) {}

fn copy_of_shipped(scratch: &Scratch) -> PathBuf {
    let shipped = ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus"));
    let copy = scratch.path().join("ckdev-plexus");
    fs::copy(&shipped, &copy).expect("copy ckdev-plexus");
    // Publication is read-only; only this private copy may be patched or re-signed.
    let mut permissions = fs::metadata(&copy)
        .expect("stat private copy")
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(permissions.mode() | 0o200);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(false);
    fs::set_permissions(&copy, permissions).expect("make private copy writable");
    copy
}

#[test]
fn smoke_probe_runs_a_guest_with_no_supervisor_environment() {
    let binary = ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus"));
    let output = smoke(&binary);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "--smoke-probe exited {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout.trim(),
        "ck-plexus smoke-probe ok: sandbox guest returned 42"
    );
    assert_eq!(stdout.lines().count(), 1, "one line: {stdout}");
}

/// The failure is injected into a copy of the real executable by overwriting
/// the smoke script's text with a same-length script that throws. Nothing in
/// the shipped binary exists to make this possible: an environment variable or
/// hidden flag would be a way to change what the production check runs. The
/// assertion that stderr names the thrown value proves the guest ran and
/// failed, rather than the copy failing to start.
#[test]
fn smoke_probe_exits_non_zero_when_the_guest_fails() {
    let scratch = Scratch::directory("smoke-probe-failing-guest");
    let copy = copy_of_shipped(&scratch);
    let mut image = fs::read(&copy).expect("read the copy");
    let needle = SMOKE_PROBE_SOURCE.as_bytes();
    let offsets: Vec<usize> = image
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(offset, _)| offset)
        .collect();
    assert_eq!(
        offsets.len(),
        1,
        "the smoke script must appear exactly once in the executable"
    );
    let failing = format!(
        "{:<width$}",
        "() => { throw 'injected-fault' }",
        width = needle.len()
    );
    assert_eq!(failing.len(), needle.len(), "replacement must fit in place");
    image[offsets[0]..offsets[0] + needle.len()].copy_from_slice(failing.as_bytes());
    fs::write(&copy, &image).expect("write the patched copy");
    sign_hardened(&copy);

    let output = smoke(&copy);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a failing guest must exit 1, not {:?}; stderr: {stderr}",
        output.status
    );
    assert!(
        stderr.contains("injected-fault"),
        "stderr must carry the guest's own error: {stderr}"
    );
    assert!(output.stdout.is_empty(), "no success line on failure");
}

/// The property the signing change exists for: the release binary, signed
/// with hardened runtime and no entitlements, can still run a guest. If the
/// sandbox ever executed native generated code again, the kernel would kill
/// this process (exit 137) instead of letting it answer.
#[cfg(target_os = "macos")]
#[test]
fn smoke_probe_passes_under_hardened_runtime_with_no_entitlements() {
    let scratch = Scratch::directory("smoke-probe-hardened");
    let copy = copy_of_shipped(&scratch);
    sign_hardened(&copy);
    let flags = bounded::child_output(
        Command::new("codesign").arg("-dv").arg(&copy),
        std::time::Duration::from_secs(60),
        "test binary command",
    )
    .expect("read the signature");
    let described = String::from_utf8_lossy(&flags.stderr);
    assert!(
        described.contains("(adhoc,runtime)"),
        "the copy must be hardened for this test to mean anything: {described}"
    );
    let entitlements = bounded::child_output(
        Command::new("codesign")
            .args(["-d", "--entitlements", "-"])
            .arg(&copy),
        std::time::Duration::from_secs(60),
        "test binary command",
    )
    .expect("read the entitlements");
    assert!(
        !String::from_utf8_lossy(&entitlements.stdout).contains("com.apple"),
        "the copy must carry no entitlements"
    );

    let output = smoke(&copy);
    assert_eq!(
        output.status.code(),
        Some(0),
        "hardened --smoke-probe exited {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
