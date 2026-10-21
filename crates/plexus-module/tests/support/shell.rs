//! Quoting for the `/bin/sh` launcher scripts the live-daemon harnesses write.
//!
//! The subc supervisor appends its own flags to a module's command line, and
//! the Rust test runner rejects them, so each harness writes a small shell
//! script that execs the test binary (or the module binary) with only the
//! arguments it wants. Paths go into that script, and a path can contain any
//! byte the filesystem allows, including an apostrophe.

use std::ffi::OsStr;

/// `value` as one POSIX single-quoted shell word, quotes included.
///
/// Inside single quotes nothing is special except the closing quote itself,
/// so each `'` becomes `'"'"'`: close the quoted run, emit the apostrophe from
/// a double-quoted run, then reopen.
pub fn single_quoted(value: impl AsRef<OsStr>) -> String {
    let text = value.as_ref().to_string_lossy();
    format!("'{}'", text.replace('\'', "'\"'\"'"))
}
