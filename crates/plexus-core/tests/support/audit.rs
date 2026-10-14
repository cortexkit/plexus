use std::path::Path;

use crate::bounded;

#[path = "logging.rs"]
mod logging;

#[path = "github_facade.rs"]
#[allow(dead_code)]
pub mod github_facade;

pub fn reject_inserts(path: &Path) {
    rusqlite::Connection::open(path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_audit_insert BEFORE INSERT ON audit_journal
             BEGIN SELECT RAISE(ABORT, 'injected audit insert failure'); END;",
        )
        .unwrap();
}

// Each child runs the real operation with libtest capture disabled. The parent
// checks the OS stderr pipe, including the fleet level and the full
// module.component attribution. An audit append that fails loses a record while
// its subject stands and tells nobody, so the level it goes out at is part of
// the property, not decoration around it.
pub fn captured_by_parent(test: &str, context: &str) -> bool {
    if std::env::var("PLEXUS_AUDIT_STDERR_CHILD").as_deref() == Ok(test) {
        logging::init_child();
        return false;
    }
    let output = bounded::child_output(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("PLEXUS_AUDIT_STDERR_CHILD", test)
            .env("PLEXUS_LOG_STDERR_CHILD", "1"),
        std::time::Duration::from_secs(30),
        "test binary child",
    )
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "fixture did not run: {stdout}");
    let lines: Vec<_> = stderr
        .lines()
        .filter(|line| line.contains("audit append failed:"))
        .collect();
    assert_eq!(lines.len(), 1, "{stderr}");
    let message = lines[0]
        .split_once("plexus.governance: ")
        .expect("component attribution")
        .1;
    logging::assert_diagnostic(
        lines[0],
        cortexkit_log::ParsedLevel::Error,
        "plexus.governance",
        message,
    );
    assert!(message.starts_with("audit append failed:"), "{stderr}");
    assert!(lines[0].contains(context), "{stderr}");
    assert!(lines[0].contains("principal=\"direct\""), "{stderr}");
    assert!(
        lines[0].contains("injected audit insert failure"),
        "{stderr}"
    );
    true
}
