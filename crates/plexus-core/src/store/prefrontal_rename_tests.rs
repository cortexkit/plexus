use super::*;
use cortexkit_store_types::Isolation;
use serde_json::{json, Value};

fn descriptor(label: &str) -> StorageDescriptor {
    StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: label.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    }
}

fn seed(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(r#"
INSERT INTO connections (principal,connection_id,app_key,status,generation,created_at_ms,updated_at_ms,ceiling_risk,ceiling_selectors)
VALUES ('direct','bot','github_rest','active',10,1,2,'write','["add_reaction"]'),
       ('direct','events','github_rest','active',11,1,2,'read','["list_issues"]'),
       ('direct','existing','github_rest','active',12,1,2,'write','["add_reaction"]');
INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,expires_at,generation,created_at_ms,agent_id)
VALUES ('github-import:bot:prefrontal','direct','bot','reserved:prefrontal-core','write','["add_reaction"]','invoke',NULL,7,100,NULL),
       ('grant_0123456789abcdef01234567','direct','events','reserved:prefrontal-core','read','["list_issues"]','events_consume',12345,8,200,'agent'),
       ('grant_abcdef0123456789abcdef01','direct','events','reserved:prefrontal-core','read','["list_prs"]','events_consume',NULL,9,300,NULL),
       ('github-import:existing:prefrontal','direct','existing','reserved:prefrontal-core','write','["add_reaction"]','invoke',NULL,4,400,NULL),
       ('keep-existing','direct','existing','reserved:prefrontal','read','["add_reaction"]','invoke',98765,5,500,'other-agent'),
       ('lookalike','direct','bot','reserved:prefrontal-core-evil','read','["read"]','invoke',NULL,1,600,NULL);
"#)
}

fn grants(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<Value>> {
    conn.prepare("SELECT json_object('grant_id',grant_id,'principal',principal,'connection_id',connection_id,'grantee_principal',grantee_principal,'risk_ceiling',risk_ceiling,'action_selectors',action_selectors,'authority_kind',authority_kind,'expires_at',expires_at,'generation',generation,'created_at_ms',created_at_ms,'agent_id',agent_id) FROM grants ORDER BY grant_id")?
        .query_map([], |row| row.get::<_, String>(0))?
        .map(|row| Ok(serde_json::from_str(&row?).expect("grant JSON")))
        .collect()
}

#[test]
fn prefrontal_rename_migration_63_is_additive_and_idempotent() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let boundary = MIGRATIONS.iter().position(|m| m.version == 63).unwrap();
    for migration in &MIGRATIONS[..boundary] {
        conn.execute_batch(migration.statements).unwrap();
    }
    seed(&conn).unwrap();
    let before = grants(&conn).unwrap();
    let connections = |conn: &rusqlite::Connection| {
        conn.prepare("SELECT json_array(connection_id,generation,ceiling_risk,ceiling_selectors) FROM connections ORDER BY connection_id").unwrap()
            .query_map([], |row| row.get::<_, String>(0)).unwrap()
            .collect::<rusqlite::Result<Vec<_>>>().unwrap()
    };
    let ceilings = connections(&conn);
    conn.execute_batch(MIGRATIONS[boundary].statements).unwrap();
    let after = grants(&conn).unwrap();
    assert_eq!(after.len(), before.len() + 3);
    for original in &before {
        assert!(after.contains(original), "original changed: {original}");
    }
    for original_id in [
        "github-import:bot:prefrontal",
        "grant_0123456789abcdef01234567",
        "grant_abcdef0123456789abcdef01",
    ] {
        let original = before
            .iter()
            .find(|row| row["grant_id"] == original_id)
            .unwrap();
        let copy = after
            .iter()
            .find(|row| {
                row["grantee_principal"] == "reserved:prefrontal"
                    && row["connection_id"] == original["connection_id"]
                    && row["action_selectors"] == original["action_selectors"]
            })
            .unwrap();
        let id = copy["grant_id"].as_str().unwrap();
        if original_id.starts_with("github-import:") {
            assert_eq!(id, "github-import:bot:reserved-prefrontal");
        } else {
            assert_eq!(id, format!("{original_id}-reserved-prefrontal"));
            assert!(!before.iter().any(|row| row["grant_id"] == id));
        }
        let mut expected = original.clone();
        expected["grant_id"] = json!(id);
        expected["grantee_principal"] = json!("reserved:prefrontal");
        assert_eq!(*copy, expected);
    }
    assert!(!after
        .iter()
        .any(|row| row["grant_id"] == "github-import:existing:reserved-prefrontal"));
    conn.execute_batch(MIGRATIONS[boundary].statements).unwrap();
    assert_eq!(grants(&conn).unwrap(), after);
    assert_eq!(connections(&conn), ceilings);
    for table in ["grant_revocations", "audit_journal"] {
        let count: i64 = conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
}

#[test]
fn prefrontal_rename_pre63_store_import_backfills_both_id_shapes() {
    let directory = crate::test_scratch::Scratch::directory("prefrontal-old-store-move");
    let from = directory.join("old.db");
    let to = directory.join("new.db");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "prefrontal-old-store-move".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: from.to_string_lossy().into_owned(),
        },
    };
    let source = cortexkit_store::open_sqlite(&descriptor).unwrap();
    let boundary = MIGRATIONS.iter().position(|m| m.version == 63).unwrap();
    source.migrate("plexus", &MIGRATIONS[..boundary]).unwrap();
    source.with_conn_fenced(|conn| {
        seed(conn)?;
        conn.execute("INSERT INTO app_manifests(principal,key,schema_version,content_hash,manifest_json,ingested_at_ms,status) VALUES ('system','github_rest',1,'hash','{}',1,'retired')", [])?;
        Ok(())
    }).unwrap();
    drop(source);
    let report = crate::import_store::import_store(&from, &to).unwrap();
    let carried = report.iter().find(|row| row.table == "grants").unwrap();
    assert_eq!((carried.read, carried.carried, carried.scrubbed), (6, 9, 0));
    let conn = rusqlite::Connection::open(to).unwrap();
    let rows = grants(&conn).unwrap();
    assert_eq!(rows.len(), 9);
    for id in [
        "github-import:bot:reserved-prefrontal",
        "grant_0123456789abcdef01234567-reserved-prefrontal",
        "grant_abcdef0123456789abcdef01-reserved-prefrontal",
    ] {
        assert!(rows
            .iter()
            .any(|row| row["grant_id"] == id && row["grantee_principal"] == "reserved:prefrontal"));
    }
    assert_eq!(
        rows.iter()
            .filter(|row| row["grantee_principal"] == "reserved:prefrontal-core")
            .count(),
        4
    );
}

#[test]
fn prefrontal_rename_revoked_copies_stay_revoked_after_pre63_restore() {
    let directory = crate::test_scratch::Scratch::directory("prefrontal-restore");
    let path = directory.join("store.db");
    let backup = directory.join("pre63.db");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "prefrontal-restore".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    let source = cortexkit_store::open_sqlite(&descriptor).unwrap();
    let boundary = MIGRATIONS.iter().position(|m| m.version == 63).unwrap();
    source.migrate("plexus", &MIGRATIONS[..boundary]).unwrap();
    source.with_conn_fenced(|conn| {
        seed(conn)?;
        conn.execute("INSERT INTO app_manifests(principal,key,schema_version,content_hash,manifest_json,ingested_at_ms,status) VALUES ('system','github_rest',1,'hash','{}',1,'retired')", [])?;
        Ok(())
    }).unwrap();
    drop(source);
    std::fs::copy(&path, &backup).unwrap();
    let store = PlexusStore::open(&descriptor).unwrap();
    let ids = [
        "github-import:bot:reserved-prefrontal",
        "grant_0123456789abcdef01234567-reserved-prefrontal",
    ];
    for id in ids {
        assert!(store.revoke_grant("direct", id).unwrap(), "{id}");
    }
    drop(store);
    std::fs::copy(&backup, &path).unwrap();
    let restored = PlexusStore::open(&descriptor).unwrap();
    let rows = grants(&rusqlite::Connection::open(&path).unwrap()).unwrap();
    for id in ids {
        assert!(
            !rows.iter().any(|row| row["grant_id"] == id),
            "revoked copy returned: {id}"
        );
    }
    for id in [
        "github-import:bot:prefrontal",
        "grant_0123456789abcdef01234567",
    ] {
        assert!(
            rows.iter().any(|row| row["grant_id"] == id),
            "original lost: {id}"
        );
    }
    assert!(restored
        .revoke_grant("direct", "grant_abcdef0123456789abcdef01")
        .unwrap());
    drop(restored);
    let moved = directory.join("moved.db");
    let report = crate::import_store::import_store(&backup, &moved).unwrap();
    let carried = report.iter().find(|row| row.table == "grants").unwrap();
    assert_eq!((carried.read, carried.carried, carried.scrubbed), (6, 5, 3));
    let rows = grants(&rusqlite::Connection::open(moved).unwrap()).unwrap();
    assert_eq!(rows.len(), 5);
    for id in ids.into_iter().chain([
        "grant_abcdef0123456789abcdef01",
        "grant_abcdef0123456789abcdef01-reserved-prefrontal",
    ]) {
        assert!(
            !rows.iter().any(|row| row["grant_id"] == id),
            "revoked authority returned on import: {id}"
        );
    }
}

fn seed_v62_restore(label: &str) -> (crate::test_scratch::Scratch, StorageDescriptor) {
    let directory = crate::test_scratch::Scratch::directory(label);
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: label.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: directory.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let source = cortexkit_store::open_sqlite(&descriptor).unwrap();
    let boundary = MIGRATIONS.iter().position(|m| m.version == 63).unwrap();
    source.migrate("plexus", &MIGRATIONS[..boundary]).unwrap();
    source.with_conn_fenced(|conn| seed(conn)).unwrap();
    (directory, descriptor)
}

fn journal_legacy_revocation(directory: &crate::test_scratch::Scratch) {
    let path = directory.join(crate::grant_journal::NAME);
    crate::grant_journal::ensure(&path).unwrap();
    crate::grant_journal::append(
        &path,
        &crate::grant_journal::Revocation {
            principal: "direct".into(),
            grant_id: "github-import:bot:prefrontal".into(),
            revoked_at_ms: 123,
        },
    )
    .unwrap();
}

#[test]
fn prefrontal_rename_open_v62_restore_revokes_new_alias_of_revoked_original() {
    let (directory, descriptor) = seed_v62_restore("prefrontal-v62-revocation");
    journal_legacy_revocation(&directory);
    let _store = PlexusStore::open(&descriptor).unwrap();
    let conn = rusqlite::Connection::open(directory.join("store.db")).unwrap();
    let rows = grants(&conn).unwrap();
    assert!(
        rows.iter().all(|row| row["connection_id"] != "bot"
            || !matches!(
                row["grantee_principal"].as_str(),
                Some("reserved:prefrontal-core" | "reserved:prefrontal")
            )),
        "revoked rename authority returned: {rows:?}"
    );
    let snapshots: Vec<(String, String, i64)> = conn
        .prepare("SELECT grant_id, grantee_principal, revoked_at_ms FROM grant_revocations ORDER BY grant_id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        snapshots,
        [
            ("github-import:bot:prefrontal".into(), "reserved:prefrontal-core".into(), 123),
            ("github-import:bot:reserved-prefrontal".into(), "reserved:prefrontal".into(), 123),
        ]
    );
    let audits: i64 = conn
        .query_row("SELECT count(*) FROM audit_journal", [], |row| row.get(0))
        .unwrap();
    assert_eq!(audits, 0);
}

#[test]
fn prefrontal_rename_open_v63_replays_legacy_revocation_without_touching_twin() {
    let (directory, descriptor) = seed_v62_restore("prefrontal-v63-revocation");
    drop(PlexusStore::open(&descriptor).unwrap());
    journal_legacy_revocation(&directory);
    let _store = PlexusStore::open(&descriptor).unwrap();
    let conn = rusqlite::Connection::open(directory.join("store.db")).unwrap();
    let rows = grants(&conn).unwrap();
    assert!(!rows.iter().any(|row| row["grant_id"] == "github-import:bot:prefrontal"));
    assert!(rows.iter().any(|row| row["grant_id"] == "github-import:bot:reserved-prefrontal"
        && row["grantee_principal"] == "reserved:prefrontal"));
}

#[test]
fn prefrontal_rename_migration_63_forward_rollback_reforward_serves_grants() {
    let inner = cortexkit_store::open_sqlite(&descriptor("prefrontal-rollback")).unwrap();
    let boundary = MIGRATIONS.iter().position(|m| m.version == 63).unwrap();
    let older = &MIGRATIONS[..boundary];
    let through_63 = &MIGRATIONS[..=boundary];
    inner.migrate("plexus", older).unwrap();
    inner.with_conn_fenced(|conn| seed(conn)).unwrap();
    assert_eq!(inner.migrate("plexus", through_63).unwrap().applied, 1);
    let forward = inner.with_read(grants).unwrap();
    assert_eq!(forward.len(), 9);
    let rollback = inner.migrate("plexus", older).unwrap();
    assert!(rollback.store_ahead());
    assert_eq!(rollback.applied, 0);
    inner.with_conn_fenced(|conn| {
        // Older readers select their caller's exact principal; the added
        // identity does not become authority for an unrelated caller.
        for (caller, count) in [("reserved:prefrontal-core", 4), ("reserved:prefrontal-evil", 0)] {
            let found: i64 = conn.query_row("SELECT count(*) FROM grants WHERE principal='direct' AND grantee_principal=?1", [caller], |r| r.get(0))?;
            assert_eq!(found, count);
        }
        conn.execute("INSERT INTO grants(grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,created_at_ms) VALUES ('rollback-write','direct','bot','reserved:aft','read','[\"read\"]','invoke',700)", [])?;
        Ok(())
    }).unwrap();
    assert_eq!(inner.migrate("plexus", through_63).unwrap().applied, 0);
    let reforward = inner.with_read(grants).unwrap();
    assert_eq!(reforward.len(), forward.len() + 1);
    for row in forward {
        assert!(reforward.contains(&row));
    }
    assert!(reforward
        .iter()
        .any(|row| row["grant_id"] == "rollback-write"));
}

#[test]
fn prefrontal_rename_migration_63_copies_survive_store_move_and_connection_delete() {
    let directory = crate::test_scratch::Scratch::directory("prefrontal-store-move");
    let from = directory.join("old.db");
    let to = directory.join("new.db");
    let descriptor = |path: &std::path::Path| StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "prefrontal-store-move".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    let source = cortexkit_store::open_sqlite(&descriptor(&from)).unwrap();
    let boundary = MIGRATIONS.iter().position(|m| m.version == 63).unwrap();
    source.migrate("plexus", &MIGRATIONS[..boundary]).unwrap();
    source.with_conn_fenced(|conn| {
        seed(conn)?;
        conn.execute("INSERT INTO app_manifests(principal,key,schema_version,content_hash,manifest_json,ingested_at_ms,status) VALUES ('system','github_rest',1,'hash','{}',1,'retired')", [])?;
        Ok(())
    }).unwrap();
    source.migrate("plexus", MIGRATIONS).unwrap();
    let expected = source.with_read(grants).unwrap();
    assert_eq!(expected.len(), 9);
    drop(source);
    let report = crate::import_store::import_store(&from, &to).unwrap();
    let carried = report.iter().find(|row| row.table == "grants").unwrap();
    assert_eq!((carried.read, carried.carried, carried.scrubbed), (9, 9, 0));
    let conn = rusqlite::Connection::open(&to).unwrap();
    assert_eq!(grants(&conn).unwrap(), expected);
    let store = PlexusStore::open(&descriptor(&to)).unwrap();
    assert_eq!(
        store.delete_connection("direct", "events", true).unwrap(),
        DeleteConnectionOutcome::HasLiveGrants { count: 2 }
    );
    conn.execute(
        "UPDATE grants SET expires_at=0 WHERE principal='direct' AND connection_id='events'",
        [],
    )
    .unwrap();
    let DeleteConnectionOutcome::Deleted { rows, .. } =
        store.delete_connection("direct", "events", true).unwrap()
    else {
        panic!("expired connection grants must permit deletion");
    };
    assert!(rows.contains(&("grants", 4)));
    let remaining = grants(&conn).unwrap();
    assert_eq!(remaining.len(), 5);
    assert!(!remaining.iter().any(|row| row["connection_id"] == "events"));
    assert!(remaining
        .iter()
        .any(|row| row["grant_id"] == "github-import:bot:reserved-prefrontal"));
}
