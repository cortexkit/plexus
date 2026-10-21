//! The store an integration test opens: an empty SQLite database in a scratch
//! directory of its own, removed when the returned guard drops.

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::test_scratch::Scratch;
use plexus_core::PlexusStore;

/// Open an empty store for one test. `label` names the scratch directory and
/// the store's namespace; the scratch path alone makes each store unique.
///
/// The scratch guard comes back FIRST on purpose. Local bindings drop in
/// reverse order, so `let (path, store) = open(..)` closes the store before the
/// guard removes the directory holding its database file. The other order
/// deletes the directory under an open SQLite connection, which only works
/// while nothing reopens the file by path.
pub fn open(label: &str) -> (Scratch, PlexusStore) {
    let path = Scratch::database(label);
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: label.to_string(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).expect("open test store");
    (path, store)
}
