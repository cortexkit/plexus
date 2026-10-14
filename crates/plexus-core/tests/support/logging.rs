/// Install the real fleet renderer only in an isolated diagnostic child.
/// A file cannot contain a log directory, so this exercises its stderr fallback
/// without writing to the operator's module data directory.
pub fn init_child() {
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_none() {
        return;
    }
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let mut config =
            cortexkit_log::Config::in_dir("plexus", std::env::current_exe().unwrap().join("logs"));
        config.spec = Some("info".into());
        let handle = cortexkit_log::init(config).unwrap();
        assert!(handle.fallback_active());
    });
}

/// Assert one rendered fleet line: its level, its full `module.component`
/// logger, and its message.
///
/// The level and the logger are asserted as well as the text because they are
/// what decides whether an operator ever sees the line: a diagnostic demoted
/// out of the default view, or one that lost its component back to the bare
/// `plexus` root, still carries the same message and would pass a text-only
/// check. The expected tail is built with the renderer's own five-column level
/// padding rather than hand-spaced, so `ERROR` and `WARN` are stated the same
/// way.
pub fn assert_diagnostic(
    line: &str,
    level: cortexkit_log::ParsedLevel,
    logger: &str,
    message: &str,
) {
    let parsed = cortexkit_log::parse_line(line).expect("fleet-formatted diagnostic");
    assert_eq!(parsed.logger, logger, "{line}");
    assert_eq!(parsed.level, level, "{line}");
    assert!(
        line.ends_with(&format!(" {:<5} {logger}: {message}", level_column(level))),
        "{line}"
    );
}

fn level_column(level: cortexkit_log::ParsedLevel) -> &'static str {
    match level {
        cortexkit_log::ParsedLevel::Error => "ERROR",
        cortexkit_log::ParsedLevel::Warn => "WARN",
        cortexkit_log::ParsedLevel::Info => "INFO",
        cortexkit_log::ParsedLevel::Debug => "DEBUG",
        cortexkit_log::ParsedLevel::Trace => "TRACE",
    }
}
