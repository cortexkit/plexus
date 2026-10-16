use std::fs;
use std::path::{Path, PathBuf};

fn removed_peer_operations(source: &str) -> Vec<&'static str> {
    ["claim.read", "claim.force", "agent-sync"]
        .into_iter()
        .filter(|operation| source.contains(&format!("\"{operation}\"")))
        .collect()
}

fn rust_sources(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("read source directory") {
        let entry = entry.expect("read source entry");
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            rust_sources(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn shipped_sources_never_call_removed_claim_operations() {
    for operation in ["claim.read", "claim.force", "agent-sync"] {
        let planted = format!("peer.call(\"{operation}\", params);");
        assert_eq!(
            removed_peer_operations(&planted),
            vec![operation],
            "planted control must detect {operation}"
        );
    }
    assert!(removed_peer_operations("peer.call(\"role.read\", params);").is_empty());
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut files = Vec::new();
    for entry in fs::read_dir(root.join("crates")).unwrap() {
        let source = entry.unwrap().path().join("src");
        if source.is_dir() {
            rust_sources(&source, &mut files);
        }
    }
    assert!(
        files.contains(&root.join("crates/plexus-module/src/connector_home.rs")),
        "scan must reach the actual reader"
    );
    let violations: Vec<_> = files
        .iter()
        .flat_map(|file| {
            removed_peer_operations(&fs::read_to_string(file).unwrap())
                .into_iter()
                .map(|operation| {
                    format!(
                        "{}: {operation}",
                        file.strip_prefix(root).unwrap().display()
                    )
                })
        })
        .collect();
    assert!(
        violations.is_empty(),
        "removed claim operation in shipped source: {violations:?}"
    );
}
