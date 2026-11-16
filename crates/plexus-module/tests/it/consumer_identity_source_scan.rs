use crate::rust_sources::shipped_rust_sources;
use std::fs;

fn overrides(source: &str) -> Vec<usize> {
    let mut test_item = false;
    let mut depth = 0_i32;
    let mut entered = false;
    let mut violations = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let code = line.split_once("//").map_or(line, |(code, _)| code).trim();
        if code == "#[cfg(test)]" {
            test_item = true;
            continue;
        }
        if test_item {
            // Attributes on an out-of-line test module precede its semicolon;
            // inline test modules end when their braces return to depth zero.
            if code.starts_with("#[") || code.is_empty() {
                continue;
            }
            entered |= code.contains('{');
            depth += code.matches('{').count() as i32 - code.matches('}').count() as i32;
            if (entered && depth == 0) || (!entered && code.ends_with(';')) {
                test_item = false;
                entered = false;
            }
            continue;
        }
        if code.contains("consumer_identity") {
            violations.push(index + 1);
        }
    }
    violations
}

/// Shipped binds use the SDK's connection identity, never a per-call override.
/// Test doubles deliberately pose as other modules, so test-only items and
/// `*_tests.rs` files are excluded along with the integration-test tree.
#[test]
fn no_shipped_outbound_bind_overrides_consumer_identity() {
    assert_eq!(overrides("consumer_identity: Some(identity),"), vec![1]);
    assert_eq!(overrides("options.consumer_identity = None;"), vec![1]);
    assert!(
        overrides("#[cfg(test)]\nmod tests {\nconsumer_identity: Some(identity),\n}\n").is_empty()
    );
    assert_eq!(
        overrides("#[cfg(test)]\nmod tests;\nconsumer_identity: Some(identity),"),
        vec![3]
    );
    let (root, files) = shipped_rust_sources();
    let mut violations = Vec::new();
    let mut visited_bus = false;
    for file in files {
        if file
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with("_tests.rs"))
            || file.components().any(|part| part.as_os_str() == "tests")
        {
            continue;
        }
        visited_bus |= file.ends_with("plexus-module/src/bus.rs");
        for line in overrides(&fs::read_to_string(&file).expect("read shipped source")) {
            violations.push(format!(
                "{}:{line}",
                file.strip_prefix(&root).unwrap().display()
            ));
        }
    }
    assert!(visited_bus, "scan must include the ckbus credential route");
    assert!(
        violations.is_empty(),
        "explicit consumer identities:\n{}",
        violations.join("\n")
    );
}
