use std::process::Command;
use std::time::Duration;

use cortexkit_test_support::ckdev_binary;
use plexus_core::test_scratch::Scratch;

#[test]
fn fixture_child() {
    if std::env::var_os("PLEXUS_FIXTURE_LAUNCH_TEST").is_some() {
        println!("selected fixture child");
    }
}

#[test]
fn launcher_handles_native_paths_and_discards_supervisor_flags() {
    let scratch = Scratch::directory("fixture-launcher");
    let directory = scratch.join("peer's files & logs");
    std::fs::create_dir(&directory).unwrap();
    let child = ckdev_binary(std::env::current_exe().unwrap());
    let moved = directory.join(child.file_name().unwrap());
    std::fs::copy(child, &moved).unwrap();
    #[cfg(windows)]
    {
        // Windows will not remove the copy while it inherits the read-only bit.
        let mut permissions = std::fs::metadata(&moved).unwrap().permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&moved, permissions).unwrap();
    }
    let launcher = ckdev_binary(env!("CARGO_BIN_EXE_ckdev-plexus-test-launcher"));
    let output = crate::bounded::child_output(
        Command::new(launcher)
            .arg("test")
            .arg(moved)
            .args(["fixture_launch::fixture_child", "--subc", "unused"])
            .env("PLEXUS_FIXTURE_LAUNCH_TEST", "1"),
        Duration::from_secs(30),
        "launch only the fixture test",
    )
    .unwrap();
    assert!(
        output.status.success(),
        "fixture exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("selected fixture child"), "{stdout}");
    assert!(stdout.contains("1 passed; 0 failed"), "{stdout}");
}
