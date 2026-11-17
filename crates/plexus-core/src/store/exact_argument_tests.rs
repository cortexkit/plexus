//! Exact action-request argument reuse regression tests.

use super::*;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use serde_json::json;

#[test]
fn action_request_reuse_distinguishes_large_integers() {
    let store = PlexusStore::open(&StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "exact-arguments".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    })
    .unwrap();
    let a = json!({"n": 9007199254740992_u64});
    let b = json!({"n": 9007199254740993_u64});
    let expires = now_ms() + 60_000;
    let first = store
        .ensure_action_request(
            "direct", "conn", "write", &a, "schema", "actor", expires, None, None,
        )
        .unwrap();
    let second = store
        .ensure_action_request(
            "direct", "conn", "write", &b, "schema", "actor", expires, None, None,
        )
        .unwrap();
    assert_ne!(first, second);
    assert_eq!(
        second,
        store
            .ensure_action_request(
                "direct", "conn", "write", &b, "schema", "actor", expires, None, None
            )
            .unwrap()
    );
    assert!(matches!(
        store
            .ensure_keyed_action_request(
                "direct", "conn", "write", &a, "schema", "actor", "key", expires, None, None
            )
            .unwrap(),
        EnsuredRequest::Held(_)
    ));
    assert!(matches!(
        store
            .ensure_keyed_action_request(
                "direct", "conn", "write", &b, "schema", "actor", "key", expires, None, None
            )
            .unwrap(),
        EnsuredRequest::KeyTaken(_)
    ));
}
