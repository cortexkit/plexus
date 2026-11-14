use super::*;

fn insert_connection(store: &PlexusStore, principal: &str, connection_id: &str) {
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO connections (principal,connection_id,app_key,status,created_at_ms,
                     updated_at_ms) VALUES (?1,?2,'mock','active',1,1)",
                (principal, connection_id),
            )
        })
        .unwrap();
}

fn card_count(store: &PlexusStore, principal: &str, subject: &str) -> i64 {
    store
        .inner
        .with_read(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM federated_card_records
                 WHERE owner_principal=?1 AND subject=?2",
                (principal, subject),
                |row| row.get(0),
            )
        })
        .unwrap()
}

fn delete(store: &PlexusStore, apply: bool) -> DeleteConnectionOutcome {
    store.delete_connection("direct", "conn", apply).unwrap()
}

fn snapshot(
    store: &PlexusStore,
    scratch: &Scratch,
    descriptor: &StorageDescriptor,
) -> StorageDescriptor {
    let path = scratch.join("snapshot.db");
    // Capture committed WAL pages too. Opening the older database beside the
    // journal models a restore without reusing the live database's sidecars.
    store
        .inner
        .with_conn(|conn| conn.execute("VACUUM INTO ?1", [path.to_string_lossy().as_ref()]))
        .unwrap();
    let conn = Connection::open(&path).unwrap();
    let state: String = conn
        .query_row(
            "SELECT state FROM federated_card_records WHERE id='pending'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        state, "pending",
        "the snapshot must contain the pending card"
    );
    StorageDescriptor {
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
        ..descriptor.clone()
    }
}

#[test]
fn connection_delete_journals_each_row_and_rowless_pending_key_before_reuse() {
    let (scratch, descriptor) = fixture("federated-connection-delete");
    let store = PlexusStore::open(&descriptor).unwrap();
    insert_connection(&store, "direct", "conn");
    let read_id = insert_row(&store, &key());
    insert_card(&store, &key(), "pending", Some("el_pending"), "pending");
    insert_card(&store, &key(), "unfiled", None, "pending");
    for terminal in [
        "consumed",
        "declined",
        "expired",
        "withdrawn",
        "committed",
        "retired",
    ] {
        insert_card(
            &store,
            &key(),
            terminal,
            Some(&format!("el_{terminal}")),
            terminal,
        );
    }
    let mut write = key();
    write.scope = "write".into();
    let write_id = insert_row(&store, &write);
    insert_card(&store, &write, "write", Some("el_write"), "pending");
    let mut rowless = key();
    rowless.pairing_id = "rowless".into();
    insert_card(&store, &rowless, "rowless", Some("el_rowless"), "pending");
    insert_card(
        &store,
        &rowless,
        "rowless-second",
        Some("el_rowless_second"),
        "pending",
    );
    let mut others = Vec::new();
    for (owner, subject) in [("other", "conn"), ("direct", "sibling"), ("", "web_search")] {
        let mut other = key();
        other.owner_principal = owner.into();
        other.subject = subject.into();
        others.push(insert_row(&store, &other));
        insert_card(
            &store,
            &other,
            subject,
            Some(&format!("el_{owner}_{subject}")),
            "pending",
        );
    }
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO federated_processed_cards VALUES ('el_preexisting')",
                [],
            )
        })
        .unwrap();
    let older = snapshot(&store, &scratch, &descriptor);

    assert!(matches!(
        delete(&store, true),
        DeleteConnectionOutcome::Deleted { .. }
    ));
    assert!(!exists(&store, &read_id));
    assert!(!exists(&store, &write_id));
    assert_eq!(card_count(&store, "direct", "conn"), 0);
    assert_eq!(
        processed(&store),
        [
            "el_mint",
            "el_pending",
            "el_preexisting",
            "el_reaffirm",
            "el_rowless",
            "el_rowless_second",
            "el_write"
        ]
    );
    for id in others {
        assert!(exists(&store, &id));
    }
    for (owner, subject) in [("other", "conn"), ("direct", "sibling"), ("", "web_search")] {
        assert_eq!(card_count(&store, owner, subject), 1);
        assert_eq!(state(&store, subject), "pending");
    }
    let journal = entries(&scratch);
    assert_eq!(journal.len(), 3);
    for (id, expected_refs) in [
        (
            Some(read_id.as_str()),
            vec!["el_mint", "el_pending", "el_reaffirm"],
        ),
        (
            Some(write_id.as_str()),
            vec!["el_mint", "el_reaffirm", "el_write"],
        ),
        (None, vec!["el_rowless", "el_rowless_second"]),
    ] {
        let entry = journal
            .iter()
            .find(|entry| entry.row_id.as_deref() == id)
            .unwrap();
        assert_eq!(entry.card_refs, expected_refs);
        assert!(entry.deleted_at_ms > 0);
    }
    insert_connection(&store, "direct", "conn");
    assert!(!exists(&store, &read_id));
    assert!(!exists(&store, &write_id));
    assert_eq!(card_count(&store, "direct", "conn"), 0);
    drop(store);
    let store = PlexusStore::open(&descriptor).unwrap();
    assert!(!exists(&store, &read_id));
    assert!(!exists(&store, &write_id));
    assert_eq!(card_count(&store, "direct", "conn"), 0);
    drop(store);
    let store = PlexusStore::open(&older).unwrap();
    assert!(!exists(&store, &read_id));
    assert!(!exists(&store, &write_id));
    assert_eq!(
        processed(&store),
        [
            "el_mint",
            "el_pending",
            "el_preexisting",
            "el_reaffirm",
            "el_rowless",
            "el_rowless_second",
            "el_write"
        ]
    );
}

#[test]
fn connection_delete_rowless_card_ref_is_processed_after_pending_snapshot_restore() {
    let (scratch, descriptor) = fixture("federated-connection-rowless-restore");
    let older;
    {
        let store = PlexusStore::open(&descriptor).unwrap();
        insert_connection(&store, "direct", "conn");
        insert_card(&store, &key(), "pending", Some("el_pending"), "pending");
        older = snapshot(&store, &scratch, &descriptor);
    }
    {
        let store = PlexusStore::open(&descriptor).unwrap();
        assert!(matches!(
            delete(&store, true),
            DeleteConnectionOutcome::Deleted { .. }
        ));
        assert_eq!(card_count(&store, "direct", "conn"), 0);
        assert_eq!(processed(&store), ["el_pending"]);
    }
    let journal = entries(&scratch);
    assert_eq!(journal.len(), 1);
    assert!(journal[0].row_id.is_none());
    assert_eq!(journal[0].card_refs, ["el_pending"]);
    let store = PlexusStore::open(&older).unwrap();
    assert_eq!(state(&store, "pending"), "pending");
    assert_eq!(processed(&store), ["el_pending"]);
}

#[test]
fn connection_delete_dry_run_does_not_journal_retire_or_process_even_after_reboot() {
    let (scratch, descriptor) = fixture("federated-connection-dry-run");
    let id;
    let before;
    {
        let store = PlexusStore::open(&descriptor).unwrap();
        insert_connection(&store, "direct", "conn");
        id = insert_row(&store, &key());
        insert_card(&store, &key(), "pending", Some("el_pending"), "pending");
        before = std::fs::read(scratch.join(federated_journal::NAME)).unwrap();
        assert!(matches!(
            delete(&store, false),
            DeleteConnectionOutcome::WouldDelete { .. }
        ));
        assert!(exists(&store, &id));
        assert_eq!(state(&store, "pending"), "pending");
        assert!(processed(&store).is_empty());
        assert_eq!(
            std::fs::read(scratch.join(federated_journal::NAME)).unwrap(),
            before
        );
    }
    let store = PlexusStore::open(&descriptor).unwrap();
    assert!(exists(&store, &id));
    assert_eq!(state(&store, "pending"), "pending");
    assert!(processed(&store).is_empty());
    assert_eq!(
        std::fs::read(scratch.join(federated_journal::NAME)).unwrap(),
        before
    );
}

#[test]
fn connection_delete_live_local_grants_refuse_before_federated_cleanup() {
    let (scratch, descriptor) = fixture("federated-connection-live-local-grant");
    let store = PlexusStore::open(&descriptor).unwrap();
    insert_connection(&store, "direct", "conn");
    let id = insert_row(&store, &key());
    insert_card(&store, &key(), "pending", Some("el_pending"), "pending");
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute(
        "INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,
             authority_kind,created_at_ms)
         VALUES ('local','direct','conn','direct','read','invoke',1)", [],
    )
        })
        .unwrap();
    for apply in [false, true] {
        assert_eq!(
            delete(&store, apply),
            DeleteConnectionOutcome::HasLiveGrants { count: 1 }
        );
        assert!(exists(&store, &id));
        assert_eq!(state(&store, "pending"), "pending");
        assert!(processed(&store).is_empty());
        assert!(entries(&scratch).is_empty());
    }
}

#[test]
fn connection_delete_journal_failure_leaves_rows_and_cards_untouched() {
    let (scratch, descriptor) = fixture("federated-connection-journal-failure");
    let store = PlexusStore::open(&descriptor).unwrap();
    insert_connection(&store, "direct", "conn");
    let id = insert_row(&store, &key());
    insert_card(&store, &key(), "pending", Some("el_pending"), "pending");
    let journal = scratch.join(federated_journal::NAME);
    std::fs::remove_file(&journal).unwrap();
    std::fs::create_dir(&journal).unwrap();
    assert!(store.delete_connection("direct", "conn", true).is_err());
    assert!(exists(&store, &id));
    assert_eq!(state(&store, "pending"), "pending");
    assert!(processed(&store).is_empty());
    assert!(matches!(
        delete(&store, false),
        DeleteConnectionOutcome::WouldDelete { .. }
    ));
}

#[test]
fn connection_delete_sql_failure_rolls_back_cleanup_after_journaling() {
    let (scratch, descriptor) = fixture("federated-connection-sql-failure");
    let store = PlexusStore::open(&descriptor).unwrap();
    insert_connection(&store, "direct", "conn");
    let id = insert_row(&store, &key());
    insert_card(&store, &key(), "pending", Some("el_pending"), "pending");
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER refuse_connection_delete BEFORE DELETE ON connections
         BEGIN SELECT RAISE(ABORT, 'delete refused'); END;",
            )
        })
        .unwrap();
    assert!(store.delete_connection("direct", "conn", true).is_err());
    assert!(exists(&store, &id));
    assert_eq!(state(&store, "pending"), "pending");
    assert!(processed(&store).is_empty());
    assert!(matches!(
        delete(&store, false),
        DeleteConnectionOutcome::WouldDelete { .. }
    ));
    let journal = entries(&scratch);
    assert_eq!(journal.len(), 1);
    assert_eq!(journal[0].row_id.as_deref(), Some(id.as_str()));
    assert_eq!(
        journal[0].card_refs,
        ["el_mint", "el_pending", "el_reaffirm"]
    );
}
