use std::path::Path;

use crate::bounded;
// Every crate that compiles this file also declares the shared stderr-capture
// helpers at its root as `test_logging`, so the one-time logger initialization
// is shared rather than duplicated here.
use crate::test_logging as logging;

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
    let output = bounded::child_test_output(
        test,
        &[
            ("PLEXUS_AUDIT_STDERR_CHILD", test),
            ("PLEXUS_LOG_STDERR_CHILD", "1"),
        ],
        std::time::Duration::from_secs(30),
        "test binary child",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "fixture did not run: {stdout}");
    let lines: Vec<_> = stderr
        .lines()
        .filter(|line| line.contains("audit append failed:"))
        .collect();
    assert_eq!(lines.len(), 1, "{stderr}");
    // The message carries per-call ids the test cannot predict, so its text is
    // checked by its fixed parts below: the prefix naming the record that
    // failed, the principal, and the injected cause. `assert_diagnostic` then
    // checks the level, the logger and the column layout around that message;
    // it cannot check the message itself, which is read from the same line.
    let message = cortexkit_log::parse_line(lines[0])
        .expect("fleet-formatted diagnostic")
        .body;
    assert!(
        message.starts_with(&format!("audit append failed: {context}")),
        "{stderr}"
    );
    assert!(message.contains("principal=\"direct\""), "{stderr}");
    assert!(
        message.contains("injected audit insert failure"),
        "{stderr}"
    );
    logging::assert_diagnostic(
        lines[0],
        cortexkit_log::ParsedLevel::Error,
        "plexus.governance",
        message,
    );
    true
}
