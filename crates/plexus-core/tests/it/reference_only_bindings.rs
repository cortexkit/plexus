use cortexkit_store::{open_sqlite, StorageDescriptor};
use cortexkit_store_types::{Isolation, StorageBackend};
use plexus_core::{test_scratch::Scratch, PlexusStore};
use rusqlite::{params, Connection};

const REFERENCE: &[u8] = b"plexus:vault-reference:v1\0apikey:fixture";
const LEGACY: &[u8] = &[42; 64];

fn descriptor(path: &std::path::Path) -> StorageDescriptor {
    StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: path.to_string_lossy().into_owned(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    }
}

/// Position in the migration chain of generation 33, which clears legacy
/// credential bindings on revoked connections and is what these tests check.
/// The previous store stops just before it rather than before the last
/// migration, because later generations append to the chain.
fn scrub_position() -> usize {
    plexus_core::storage::MIGRATIONS
        .iter()
        .position(|migration| migration.version == 33)
        .expect("the binding scrub is generation 33")
}

/// Position in the migration chain of generation 40, which deletes every
/// revoked connection outright. The scrub above is checked on the chain that
/// stops just before it, because after it no revoked row is left to inspect.
fn purge_position() -> usize {
    plexus_core::storage::MIGRATIONS
        .iter()
        .position(|migration| migration.version == 40)
        .expect("the revoked-connection purge is generation 40")
}

fn binding(conn: &Connection, id: &str) -> rusqlite::Result<Option<Option<Vec<u8>>>> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT credential_binding FROM connections WHERE connection_id=?1",
        [id],
        |row| row.get(0),
    )
    .optional()
}

fn seed_previous(path: &std::path::Path, rows: &[(&str, &str, &[u8])]) {
    let store = open_sqlite(&descriptor(path)).unwrap();
    let migrations = plexus_core::storage::MIGRATIONS;
    store
        .migrate("plexus", &migrations[..scrub_position()])
        .unwrap();
    store.with_conn(|conn| {
        for (id, status, binding) in rows {
            conn.execute("INSERT INTO connections (principal,connection_id,app_key,status,credential_binding,created_at_ms,updated_at_ms) VALUES ('direct',?1,'mock',?2,?3,1,1)", params![id, status, binding])?;
        }
        Ok(())
    }).unwrap();
}

#[test]
fn opening_without_a_key_creates_no_key() {
    let path = Scratch::database("no-binding-key");
    let store = PlexusStore::open(&descriptor(&path)).unwrap();
    assert!(store.list_connections("direct").unwrap().is_empty());
    assert!(!path.parent().unwrap().join(".plexus-binding-key").exists());
}

#[test]
fn active_legacy_binding_refuses_open_and_names_connection() {
    let path = Scratch::database("active-legacy");
    seed_previous(&path, &[("legacy-active", "active", LEGACY)]);
    let error = PlexusStore::open(&descriptor(&path))
        .err()
        .expect("legacy active must refuse")
        .to_string();
    assert!(error.contains("legacy-active"), "{error}");
    assert!(error.contains("handle_bindings_removed"), "{error}");
    assert!(
        error.contains("ck-plexus-admin rebind-credential"),
        "{error}"
    );
    assert!(error.contains("previous build"), "{error}");
}

#[test]
fn recoverable_legacy_bindings_refuse_open_without_scrubbing() {
    for status in ["degraded", "auth_required", "pending", "disabled"] {
        let path = Scratch::database(status);
        seed_previous(&path, &[("recoverable", status, LEGACY)]);
        let error = PlexusStore::open(&descriptor(&path))
            .err()
            .expect("recoverable legacy must refuse")
            .to_string();
        assert!(error.contains("recoverable"), "{error}");
        let bytes: Vec<u8> = Connection::open(&path)
            .unwrap()
            .query_row("SELECT credential_binding FROM connections", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            bytes, LEGACY,
            "{status} must retain operator recovery evidence"
        );
    }
}

#[test]
fn migration_scrubs_only_revoked_legacy_and_preserves_reference_bytes() {
    let path = Scratch::database("binding-migration");
    seed_previous(
        &path,
        &[
            ("legacy-active", "active", LEGACY),
            ("legacy-revoked", "revoked", LEGACY),
            ("reference-active", "active", REFERENCE),
            ("reference-revoked", "revoked", REFERENCE),
        ],
    );
    // Apply through the real version guard, independently of the open refusal.
    let store = open_sqlite(&descriptor(&path)).unwrap();
    let migrations = plexus_core::storage::MIGRATIONS;
    let first = store
        .migrate("plexus", &migrations[..purge_position()])
        .unwrap();
    assert_eq!(
        first.applied as usize,
        purge_position() - scrub_position(),
        "generation 33 and every generation up to the purge apply"
    );
    store
        .with_conn(|conn| {
            for (id, expected) in [
                ("legacy-active", Some(LEGACY)),
                ("legacy-revoked", None),
                ("reference-active", Some(REFERENCE)),
                ("reference-revoked", Some(REFERENCE)),
            ] {
                let bytes = binding(conn, id)?.expect("the row exists before the purge");
                assert_eq!(bytes.as_deref(), expected, "{id}");
            }
            Ok(())
        })
        .unwrap();

    // The rest of the chain deletes the revoked rows and leaves the active
    // rows' bytes alone; a second run applies nothing.
    store.migrate("plexus", migrations).unwrap();
    let second = store.migrate("plexus", migrations).unwrap();
    assert_eq!(second.applied, 0);
    store
        .with_conn(|conn| {
            for (id, expected) in [
                ("legacy-active", Some(Some(LEGACY))),
                ("legacy-revoked", None),
                ("reference-active", Some(Some(REFERENCE))),
                ("reference-revoked", None),
            ] {
                let bytes = binding(conn, id)?;
                assert_eq!(
                    bytes.as_ref().map(|inner| inner.as_deref()),
                    expected,
                    "{id}"
                );
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn revoked_legacy_binding_is_scrubbed_and_opens_without_key() {
    let path = Scratch::database("revoked-legacy");
    seed_previous(
        &path,
        &[
            ("revoked", "revoked", LEGACY),
            ("reference", "active", REFERENCE),
        ],
    );
    // Opening runs the whole chain: generation 33 scrubs the revoked row's
    // legacy bytes and generation 40 then deletes the row, so no legacy
    // binding is left for the open to refuse.
    let store = PlexusStore::open(&descriptor(&path)).unwrap();
    assert_eq!(store.list_connections("direct").unwrap().len(), 1);
    let conn = Connection::open(&path).unwrap();
    assert_eq!(binding(&conn, "revoked").unwrap(), None);
    assert_eq!(
        binding(&conn, "reference").unwrap(),
        Some(Some(REFERENCE.to_vec()))
    );
    assert!(!path.parent().unwrap().join(".plexus-binding-key").exists());
}
