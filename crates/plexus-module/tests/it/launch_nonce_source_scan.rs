use std::fs;

use crate::rust_sources::shipped_rust_sources;

fn code_portion(line: &str) -> &str {
    line.split_once("//").map_or(line, |(code, _)| code).trim()
}

fn direct_nonce_lines(source: &str) -> Vec<usize> {
    source
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let code = code_portion(line);
            let names_nonce =
                code.contains("SUBC_LAUNCH_NONCE") || code.contains("SUBC_LAUNCH_NONCE_FD");
            (names_nonce && !code.contains("remove_var(")).then_some(index + 1)
        })
        .collect()
}

/// Shipped Rust source must use the nonce accessor rather than read launch-nonce
/// environment variables directly. HELLO uses `subc_os::launch_nonce()`; route
/// opens use subc-client-rs, which uses the same accessor. Non-daemon entry points
/// may scrub these variables with `std::env::remove_var`.
///
/// Only `crates/*/src/**/*.rs` is shipped: `examples/` and `tests/` are out of
/// scope. Line comments are ignored, including trailing `//` comments.
#[test]
fn shipped_source_does_not_read_launch_nonce_environment() {
    assert_eq!(
        direct_nonce_lines("let _ = std::env::var(\"SUBC_LAUNCH_NONCE\");"),
        vec![1],
        "positive control must detect the environment nonce read"
    );
    assert_eq!(
        direct_nonce_lines("let _ = std::env::var_os(\"SUBC_LAUNCH_NONCE_FD\");"),
        vec![1],
        "positive control must detect the descriptor variable read"
    );

    let (root, files) = shipped_rust_sources();

    let hello_source = root.join("crates/plexus-module/src/lib.rs");
    let mut visited_hello = false;
    let mut accessor_calls = 0;
    let mut violations = Vec::new();
    for file in files {
        let source = fs::read_to_string(&file).expect("read shipped Rust source");
        if file == hello_source {
            visited_hello = true;
            accessor_calls += source
                .lines()
                .filter(|line| code_portion(line).contains("subc_os::launch_nonce("))
                .count();
        }
        for line in direct_nonce_lines(&source) {
            violations.push(format!(
                "{}:{line}",
                file.strip_prefix(&root)
                    .expect("workspace source")
                    .display()
            ));
        }
    }
    assert!(
        visited_hello,
        "scan must visit crates/plexus-module/src/lib.rs"
    );
    assert!(accessor_calls > 0, "HELLO must call subc_os::launch_nonce");
    assert!(
        violations.is_empty(),
        "direct launch-nonce environment references in shipped source:\n{}",
        violations.join("\n")
    );
}
