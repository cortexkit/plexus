use super::*;
use rusqlite::types::Value as SqlValue;

fn columns(conn: &Connection, table: &str) -> rusqlite::Result<Vec<(String, bool)>> {
    conn.prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |row| Ok((row.get(1)?, row.get(3)?)))?
        .collect()
}

fn snapshot(
    conn: &Connection,
    table: &str,
    names: &[String],
) -> rusqlite::Result<Vec<Vec<SqlValue>>> {
    conn.prepare(&format!("SELECT {} FROM {table}", names.join(",")))?
        .query_map([], |row| {
            (0..names.len()).map(|index| row.get(index)).collect()
        })?
        .collect()
}

#[test]
fn migration_61_preserves_local_rows_and_is_idempotent() {
    let scratch = crate::test_scratch::Scratch::directory("federated-migration");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "federated-migration".into(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let store = open_sqlite(&descriptor).unwrap();
    let boundary = MIGRATIONS.iter().position(|m| m.version == 61).unwrap();
    assert_eq!(MIGRATIONS[boundary - 1].version, 60);
    assert_eq!(
        store
            .migrate("plexus", &MIGRATIONS[..boundary])
            .unwrap()
            .recorded,
        60
    );
    store.with_conn_fenced(|conn| conn.execute_batch(
        "INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,
             action_selectors,authority_kind,created_at_ms,agent_id)
         VALUES ('local-grant','direct','conn','reserved:prefrontal-core','read','[\"read\"]','invoke',1,'agent');
         INSERT INTO audit_journal (ts,principal,actor,acting_principal,decision,reason_code,agent_id)
         VALUES (1,'direct','agent','reserved:prefrontal-core','allow','local','agent');
         INSERT INTO reservations (reservation_id,principal,connection_id,action,snapshot_generations,
             approved_args_hash,schema_hash,expires_at,status,created_at_ms,grant_id,agent_grant_id)
         VALUES ('local-reservation','direct','conn','read','{}','hash','schema',2,'reserved',1,'local-grant','agent-grant');"
    )).unwrap();
    let before = store
        .with_read(|conn| {
            ["grants", "audit_journal", "reservations"]
                .into_iter()
                .map(|table| {
                    let names: Vec<_> = columns(conn, table)?
                        .into_iter()
                        .map(|(name, _)| name)
                        .collect();
                    let rows = snapshot(conn, table, &names)?;
                    assert_eq!(rows.len(), 1);
                    Ok((table, names, rows))
                })
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap();

    for expected_applied in [1, 0] {
        let outcome = store.migrate("plexus", &MIGRATIONS[..=boundary]).unwrap();
        assert_eq!((outcome.applied, outcome.recorded), (expected_applied, 61));
        store
            .with_read(|conn| {
                for (table, names, rows) in &before {
                    assert_eq!(
                        snapshot(conn, table, names)?,
                        *rows,
                        "{table} must be unchanged"
                    );
                }
                for (table, additions) in [
                    (
                        "audit_journal",
                        vec![
                            "peer_fingerprint",
                            "pairing_id",
                            "peer_class",
                            "claim_kind",
                            "canonical_claim_identity",
                            "federated_row_id",
                            "card_ref",
                        ],
                    ),
                    ("reservations", vec!["federated_row_id", "card_ref"]),
                ] {
                    let schema = columns(conn, table)?;
                    for name in additions {
                        assert!(
                            schema.contains(&(name.into(), false)),
                            "{table}.{name} must be nullable"
                        );
                        let nulls: i64 = conn.query_row(
                            &format!("SELECT COUNT(*) FROM {table} WHERE {name} IS NULL"),
                            [],
                            |row| row.get(0),
                        )?;
                        assert_eq!(nulls, 1, "local {table}.{name} stays NULL");
                    }
                }
                Ok(())
            })
            .unwrap();
    }
}

const KEY: [&str; 9] = [
    "peer_fingerprint",
    "pairing_id",
    "peer_class",
    "selector",
    "claim_kind",
    "canonical_claim_identity",
    "owner_principal",
    "subject",
    "scope",
];

fn insert_row(conn: &Connection, key: &[&str; 9]) -> rusqlite::Result<String> {
    let id = crate::federated::new_row_id();
    conn.execute(
        "INSERT INTO federated_rows (id,peer_fingerprint,pairing_id,peer_class,selector,claim_kind,
            canonical_claim_identity,owner_principal,subject,scope,peer_name,effect,granted_at_ms,
            card_ref,card_refs_json,claim_json)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'Juniper','allow',123,'el_mint',
             '[\"el_mint\",\"el_reaffirm\"]',
             '{\"kind\":\"worker\",\"owner_module_id\":\"core\",\"worker_ref\":\"worker\",\"on_behalf_of\":\"Sage\",\"agent_name\":\"Remote Sage\"}')",
        rusqlite::params![id, key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8]],
    )?;
    Ok(id)
}

#[test]
fn rows_have_the_exact_nonnullable_key_and_random_stored_ids() {
    let conn = Connection::open_in_memory().unwrap();
    PlexusStore::apply_migrations(&conn).unwrap();
    let schema = columns(&conn, "federated_rows").unwrap();
    for name in KEY {
        assert!(
            schema.contains(&(name.into(), true)),
            "key column {name} must be NOT NULL"
        );
    }
    let key = [
        "fingerprint",
        "pairing",
        "computer",
        "claimless",
        "",
        "",
        "direct",
        "conn",
        "read",
    ];
    let id = insert_row(&conn, &key).unwrap();
    assert!(id.starts_with("plxf_"));
    assert!(
        insert_row(&conn, &key).is_err(),
        "claimless sentinel must conflict"
    );
    // Changing each key component independently must yield a distinct row.
    for index in 0..KEY.len() {
        let mut other = key;
        other[index] = if index == 8 { "write" } else { "different" };
        assert_ne!(insert_row(&conn, &other).unwrap(), id);
    }
    let stored: (String, String, i64, String, String, String) = conn.query_row(
        "SELECT id,peer_name,granted_at_ms,card_ref,card_refs_json,claim_json FROM federated_rows WHERE id=?1",
        [&id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
    ).unwrap();
    assert_eq!(
        (&stored.0, stored.1.as_str(), stored.2, stored.3.as_str()),
        (&id, "Juniper", 123, "el_mint")
    );
    assert_eq!(
        serde_json::from_str::<Value>(&stored.4).unwrap(),
        serde_json::json!(["el_mint", "el_reaffirm"])
    );
    assert_eq!(
        serde_json::from_str::<Value>(&stored.5).unwrap()["agent_name"],
        "Remote Sage"
    );
    conn.execute("DELETE FROM federated_rows WHERE id=?1", [&id])
        .unwrap();
    assert_ne!(
        insert_row(&conn, &key).unwrap(),
        id,
        "regrant never derives an old id from its key"
    );
}

#[test]
fn cards_store_binding_scope_schema_and_state_without_owning_processed_refs() {
    let conn = Connection::open_in_memory().unwrap();
    PlexusStore::apply_migrations(&conn).unwrap();
    conn.execute_batch(
        "INSERT INTO federated_card_records (id,peer_fingerprint,pairing_id,peer_class,claim_kind,
            canonical_claim_identity,owner_principal,subject,action,args_digest,selector,scope,
            filed_scope_json,schema_hash,state,card_ref,standing_choices_offered)
         VALUES ('record','fp','pair','computer','','','direct','conn','read','digest',
             'claimless','read','{\"scope_ref\":\"ref\"}','schema','pending','el_card',1);
         INSERT INTO federated_processed_cards (card_ref) VALUES ('el_card');",
    )
    .unwrap();
    assert!(conn
        .execute(
            "INSERT INTO federated_processed_cards VALUES ('el_card')",
            []
        )
        .is_err());
    assert_eq!(
        columns(&conn, "federated_processed_cards").unwrap(),
        vec![("card_ref".into(), true)]
    );
    let stored: (String, String, String, String, String, String) = conn.query_row(
        "SELECT action,args_digest,scope,filed_scope_json,schema_hash,state FROM federated_card_records WHERE id='record'", [],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
    ).unwrap();
    assert_eq!(
        stored,
        (
            "read".into(),
            "digest".into(),
            "read".into(),
            "{\"scope_ref\":\"ref\"}".into(),
            "schema".into(),
            "pending".into()
        )
    );
    conn.execute("DELETE FROM federated_card_records", [])
        .unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM federated_processed_cards",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "processed refs have an independent lifetime");
}

#[test]
fn fresh_migration_61_requires_boolean_standing_choice_metadata() {
    let conn = Connection::open_in_memory().unwrap();
    PlexusStore::apply_migrations(&conn).unwrap();
    let column: (String, bool) = conn.query_row(
        "SELECT type, \"notnull\" FROM pragma_table_info('federated_card_records') WHERE name='standing_choices_offered'",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(column, ("INTEGER".into(), true));
    for (suffix, value, valid) in [
        ("missing", None, false),
        ("bad", Some(2), false),
        ("false", Some(0), true),
        ("true", Some(1), true),
    ] {
        let result = conn.execute("INSERT INTO federated_card_records
            (id,peer_fingerprint,pairing_id,peer_class,claim_kind,canonical_claim_identity,owner_principal,subject,action,args_digest,selector,scope,filed_scope_json,state,standing_choices_offered)
            VALUES (?1,'fp','pair','computer','','','direct','connection','read','digest','claimless','read','{}','pending',?2)", rusqlite::params![suffix,value]);
        assert_eq!(result.is_ok(), valid, "{suffix}: {result:?}");
    }
}
