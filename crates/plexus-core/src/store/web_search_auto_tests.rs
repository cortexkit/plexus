use crate::storage::MIGRATIONS;

#[test]
fn migration_59_forward_rollback_and_reforward_preserves_consent() {
    let descriptor = cortexkit_store_types::StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "search-auto-migration".into(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let inner = cortexkit_store::open_sqlite(&descriptor).unwrap();
    let boundary = MIGRATIONS
        .iter()
        .position(|migration| migration.version == 59)
        .unwrap();
    let prior = &MIGRATIONS[..boundary];
    // Through 59 only, so later migrations don't change the counts this
    // test asserts.
    let through = &MIGRATIONS[..=boundary];
    inner.migrate("plexus", prior).unwrap();
    inner.with_conn_fenced(|conn| conn.execute_batch("INSERT INTO connections(principal,connection_id,app_key,status,created_at_ms,updated_at_ms) VALUES ('direct','before','fixture','active',1,1)")).unwrap();
    assert_eq!(inner.migrate("plexus", through).unwrap().applied, 1);
    inner.with_conn_fenced(|conn| conn.execute_batch("INSERT INTO web_search_auto_connections VALUES ('direct','exa','apikey:exa','incarnation',1,'before',2,3)")).unwrap();
    let rollback = inner.migrate("plexus", prior).unwrap();
    assert!(rollback.store_ahead());
    assert_eq!(rollback.applied, 0);
    inner.with_conn_fenced(|conn| conn.execute_batch("INSERT INTO connections(principal,connection_id,app_key,status,created_at_ms,updated_at_ms) VALUES ('direct','older-write','fixture','active',1,1)")).unwrap();
    assert_eq!(inner.migrate("plexus", through).unwrap().applied, 0);
    let counts: (i64, String, i64, i64) = inner
        .with_read(|conn| {
            Ok((
                conn.query_row("SELECT COUNT(*) FROM connections", [], |row| row.get(0))?,
                conn.query_row(
                    "SELECT connection_id FROM web_search_auto_connections",
                    [],
                    |row| row.get(0),
                )?,
                conn.query_row(
                    "SELECT appended_at_ms FROM web_search_auto_connections",
                    [],
                    |row| row.get(0),
                )?,
                conn.query_row(
                    "SELECT revoked_at_ms FROM web_search_auto_connections",
                    [],
                    |row| row.get(0),
                )?,
            ))
        })
        .unwrap();
    assert_eq!(counts, (2, "before".into(), 2, 3));
}
