//! The launcher scripts the live-daemon harnesses write must survive any path
//! the checkout, target directory or `$TMPDIR` can produce. A quoting mistake
//! there shows up only as a fixture module that never registers, far from the
//! cause, so the quoting is checked directly against `/bin/sh`.

use std::process::Command;

use crate::shell::single_quoted;

/// What `/bin/sh` reads back from `value` once it is quoted into a script.
fn shell_round_trip(value: &str) -> String {
    let output = crate::bounded::child_output(
        Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("printf '%s' {}", single_quoted(value))),
        std::time::Duration::from_secs(30),
        "quoting check shell",
    )
    .expect("run /bin/sh");
    assert!(
        output.status.success(),
        "/bin/sh rejected the quoted word for {value:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 shell output")
}

#[test]
fn a_quoted_path_reaches_the_shell_unchanged() {
    for value in [
        "/tmp/plain/target/debug/deps/it-0123",
        "/tmp/o'brien/target/debug/deps/it-0123",
        "/tmp/''/x",
        "'",
        "/tmp/with space/and \"double\" $HOME `id` \\ quotes",
        "",
    ] {
        assert_eq!(shell_round_trip(value), value, "quoted word for {value:?}");
    }
}
