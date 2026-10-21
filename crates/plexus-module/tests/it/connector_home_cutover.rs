use std::fs;

use crate::rust_sources::shipped_rust_sources;

fn removed_peer_operations(source: &str) -> Vec<&'static str> {
    ["claim.read", "claim.force", "agent-sync"]
        .into_iter()
        .filter(|operation| source.contains(&format!("\"{operation}\"")))
        .collect()
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
    let (root, files) = shipped_rust_sources();
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
                        file.strip_prefix(&root).unwrap().display()
                    )
                })
        })
        .collect();
    assert!(
        violations.is_empty(),
        "removed claim operation in shipped source: {violations:?}"
    );
}
