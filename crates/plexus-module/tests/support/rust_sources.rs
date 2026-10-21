//! The workspace's shipped Rust source, for tests that scan it for a pattern.

use std::fs;
use std::path::{Path, PathBuf};

/// Every `crates/*/src/**/*.rs` file under the workspace root, sorted. Only
/// `src/` ships: `examples/`, `tests/` and build scripts are out of scope.
pub fn shipped_rust_sources() -> (PathBuf, Vec<PathBuf>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("plexus-module must live under crates/")
        .to_path_buf();
    let mut files = Vec::new();
    for entry in fs::read_dir(root.join("crates")).expect("read workspace crates") {
        let entry = entry.expect("read crate entry");
        if entry.file_type().expect("read crate type").is_dir() {
            let source = entry.path().join("src");
            if source.is_dir() {
                walk(&source, &mut files).expect("walk shipped Rust source");
            }
        }
    }
    files.sort();
    (root, files)
}

fn walk(directory: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let path = entry.path();
        if kind.is_dir() {
            walk(&path, files)?;
        } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    Ok(())
}
