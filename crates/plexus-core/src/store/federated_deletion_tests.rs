use super::*;
use crate::test_scratch::Scratch;

#[path = "federated_connection_delete_tests.rs"]
mod connection_tests;

fn fixture(label: &str) -> (Scratch, StorageDescriptor) {
    let scratch = Scratch::directory(label);
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: label.into(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.join("store.db").to_string_lossy().into_owned(),
        },
    };
    (scratch, descriptor)
}

fn key() -> FederatedRowKey {
    FederatedRowKey {
        peer_fingerprint: "a".repeat(32),
        pairing_id: "pairing".into(),
        peer_class: "computer".into(),
        selector: "claimless".into(),
        claim_kind: "".into(),
        canonical_claim_identity: "".into(),
        owner_principal: "direct".into(),
        subject: "conn".into(),
        scope: "read".into(),
    }
}

fn insert_row(store: &PlexusStore, key: &FederatedRowKey) -> String {
    let id = crate::federated::new_row_id();
    store.inner.with_conn_fenced(|conn| conn.execute(
        "INSERT INTO federated_rows (id,peer_fingerprint,pairing_id,peer_class,selector,claim_kind,
            canonical_claim_identity,owner_principal,subject,scope,peer_name,effect,granted_at_ms,
            card_ref,card_refs_json)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'Juniper','allow',1,'el_mint',
                 '[\"el_mint\",\"el_reaffirm\",\"el_reaffirm\"]')",
        rusqlite::params![id,key.peer_fingerprint,key.pairing_id,key.peer_class,key.selector,key.claim_kind,
            key.canonical_claim_identity,key.owner_principal,key.subject,key.scope],
    )).unwrap();
    id
}

fn insert_card(
    store: &PlexusStore,
    key: &FederatedRowKey,
    id: &str,
    card_ref: Option<&str>,
    state: &str,
) {
    store.inner.with_conn_fenced(|conn| conn.execute(
        "INSERT INTO federated_card_records (id,peer_fingerprint,pairing_id,peer_class,selector,claim_kind,
             canonical_claim_identity,owner_principal,subject,scope,action,args_digest,filed_scope_json,
             schema_hash,state,card_ref,standing_choices_offered)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'read','args','{}','schema',?11,?12,1)",
        rusqlite::params![id,key.peer_fingerprint,key.pairing_id,key.peer_class,key.selector,key.claim_kind,
            key.canonical_claim_identity,key.owner_principal,key.subject,key.scope,state,card_ref],
    )).unwrap();
}

fn exists(store: &PlexusStore, id: &str) -> bool {
    store
        .inner
        .with_read(|conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM federated_rows WHERE id=?1)",
                [id],
                |row| row.get(0),
            )
        })
        .unwrap()
}

fn processed(store: &PlexusStore) -> Vec<String> {
    store
        .inner
        .with_read(|conn| {
            conn.prepare("SELECT card_ref FROM federated_processed_cards ORDER BY card_ref")?
                .query_map([], |row| row.get(0))?
                .collect()
        })
        .unwrap()
}

fn state(store: &PlexusStore, id: &str) -> String {
    store
        .inner
        .with_read(|conn| {
            conn.query_row(
                "SELECT state FROM federated_card_records WHERE id=?1",
                [id],
                |row| row.get(0),
            )
        })
        .unwrap()
}

fn entries(scratch: &Scratch) -> Vec<Deletion> {
    let mut entries = Vec::new();
    federated_journal::scan(&scratch.join(federated_journal::NAME), |entry| {
        entries.push(entry);
        Ok(())
    })
    .unwrap();
    entries
}

fn snapshot(
    store: &PlexusStore,
    scratch: &Scratch,
    descriptor: &StorageDescriptor,
    row_ids: &[&str],
    pending_card_ids: &[&str],
) -> StorageDescriptor {
    let path = scratch.join("snapshot.db");
    // Capture committed WAL pages too. Opening the older database beside the
    // journal models a restore without reusing the live database's sidecars.
    store
        .inner
        .with_conn(|conn| conn.execute("VACUUM INTO ?1", [path.to_string_lossy().as_ref()]))
        .unwrap();
    let conn = Connection::open(&path).unwrap();
    for id in row_ids {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM federated_rows WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "the snapshot must contain row {id}");
    }
    for id in pending_card_ids {
        let state: String = conn
            .query_row(
                "SELECT state FROM federated_card_records WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            state, "pending",
            "the snapshot must contain pending card {id}"
        );
    }
    StorageDescriptor {
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
        ..descriptor.clone()
    }
}

#[test]
fn torn_boot_acknowledged_revoke_reboot_and_older_restore_keep_row_deleted() {
    let (scratch, descriptor) = fixture("federated-torn-restore");
    let id;
    let older;
    {
        let store = PlexusStore::open(&descriptor).unwrap();
        id = insert_row(&store, &key());
        insert_card(&store, &key(), "pending", Some("el_pending"), "pending");
        older = snapshot(&store, &scratch, &descriptor, &[&id], &["pending"]);
    }
    std::fs::write(
        scratch.join(federated_journal::NAME),
        b"{\"row_id\":\"plxf_torn",
    )
    .unwrap();
    {
        let store = PlexusStore::open(&descriptor).expect("torn final line permits boot");
        assert!(exists(&store, &id));
        assert!(store
            .delete_federated_row(&id)
            .expect("acknowledged revoke"));
        assert_eq!(state(&store, "pending"), "retired");
    }
    {
        let store = PlexusStore::open(&descriptor).expect("append repaired the torn tail");
        assert!(!exists(&store, &id));
        assert_eq!(processed(&store), ["el_mint", "el_pending", "el_reaffirm"]);
    }
    let store = PlexusStore::open(&older).expect("restore replays durable deletes");
    assert!(!exists(&store, &id));
    assert_eq!(processed(&store), ["el_mint", "el_pending", "el_reaffirm"]);
    let entries = entries(&scratch);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].row_id.as_deref(), Some(id.as_str()));
    assert_eq!(
        entries[0].card_refs,
        ["el_mint", "el_pending", "el_reaffirm"]
    );
    assert!(entries[0].deleted_at_ms > 0);
}

#[test]
fn delete_retires_only_pending_cards_of_the_exact_key_and_keeps_processed_refs() {
    let (scratch, descriptor) = fixture("federated-delete-key");
    let store = PlexusStore::open(&descriptor).unwrap();
    let id = insert_row(&store, &key());
    insert_card(&store, &key(), "pending", Some("el_pending"), "pending");
    insert_card(&store, &key(), "not-filed", None, "pending");
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
    for index in 0..9 {
        let mut other = key();
        let fields = [
            &mut other.peer_fingerprint,
            &mut other.pairing_id,
            &mut other.peer_class,
            &mut other.selector,
            &mut other.claim_kind,
            &mut other.canonical_claim_identity,
            &mut other.owner_principal,
            &mut other.subject,
            &mut other.scope,
        ];
        *fields.into_iter().nth(index).unwrap() = if index == 8 { "write" } else { "other" }.into();
        insert_card(
            &store,
            &other,
            &format!("other-{index}"),
            Some(&format!("el_other-{index}")),
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
    assert!(store.delete_federated_row(&id).unwrap());
    assert!(!store.delete_federated_row(&id).unwrap());
    assert!(!store.delete_federated_row("plx_local").unwrap());
    assert_eq!(entries(&scratch).len(), 1);
    assert_eq!(
        processed(&store),
        ["el_mint", "el_pending", "el_preexisting", "el_reaffirm"]
    );
    assert_eq!(state(&store, "pending"), "retired");
    assert_eq!(state(&store, "not-filed"), "retired");
    for terminal in [
        "consumed",
        "declined",
        "expired",
        "withdrawn",
        "committed",
        "retired",
    ] {
        assert_eq!(state(&store, terminal), terminal);
    }
    for index in 0..9 {
        assert_eq!(state(&store, &format!("other-{index}")), "pending");
    }
}

#[test]
fn rowless_keys_journal_retired_refs_but_not_unfiled_or_terminal_cards() {
    let (scratch, descriptor) = fixture("federated-orphan-cards");
    let store = PlexusStore::open(&descriptor).unwrap();
    insert_card(&store, &key(), "pending", Some("el_orphan"), "pending");
    insert_card(&store, &key(), "not-filed", None, "pending");
    insert_card(
        &store,
        &key(),
        "committed",
        Some("el_committed"),
        "committed",
    );
    store
        .inner
        .with_conn_fenced(|conn| {
            assert!(!store.delete_federated_key_on_conn(conn, &key(), None, 42)?);
            Ok(())
        })
        .unwrap();
    assert_eq!(processed(&store), ["el_orphan"]);
    assert_eq!(state(&store, "pending"), "retired");
    assert_eq!(state(&store, "not-filed"), "retired");
    assert_eq!(state(&store, "committed"), "committed");
    let lines = entries(&scratch);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].row_id.is_none());
    assert_eq!(lines[0].card_refs, ["el_orphan"]);
    assert_eq!(lines[0].deleted_at_ms, 42);
    insert_card(&store, &key(), "another-unfiled", None, "pending");
    store
        .inner
        .with_conn_fenced(|conn| {
            store
                .delete_federated_key_on_conn(conn, &key(), None, 43)
                .map(|_| ())
        })
        .unwrap();
    assert_eq!(entries(&scratch).len(), 1);
    assert_eq!(state(&store, "another-unfiled"), "retired");
    drop(store);
    let store = PlexusStore::open(&descriptor).unwrap();
    assert_eq!(processed(&store), ["el_orphan"]);
}

#[test]
fn flip_journal_excludes_its_answer_even_when_the_transaction_never_commits() {
    let (scratch, descriptor) = fixture("federated-flip-crash");
    let old_id;
    {
        let store = PlexusStore::open(&descriptor).unwrap();
        old_id = insert_row(&store, &key());
        insert_card(&store, &key(), "flip", Some("el_flip"), "pending");
        insert_card(&store, &key(), "other", Some("el_other"), "pending");
        let failure: Result<(), StoreError> = store.inner.with_conn_fenced(|conn| {
            assert!(store.delete_federated_row_on_conn(conn, &old_id, Some("flip"), 7)?);
            assert_eq!(
                conn.query_row(
                    "SELECT state FROM federated_card_records WHERE id='flip'",
                    [],
                    |row| row.get::<_, String>(0),
                )?,
                "pending"
            );
            Err(rusqlite::Error::InvalidQuery)
        });
        assert!(failure.is_err());
        assert!(exists(&store, &old_id));
        assert!(processed(&store).is_empty());
    }
    let store = PlexusStore::open(&descriptor).unwrap();
    assert!(!exists(&store, &old_id));
    assert_eq!(processed(&store), ["el_mint", "el_other", "el_reaffirm"]);
    assert_eq!(state(&store, "flip"), "pending");
    let line = entries(&scratch).pop().unwrap();
    assert_eq!(line.card_refs, ["el_mint", "el_other", "el_reaffirm"]);
    let new_id = insert_row(&store, &key());
    assert_ne!(new_id, old_id);
    drop(store);
    let store = PlexusStore::open(&descriptor).unwrap();
    assert!(exists(&store, &new_id), "replay must not delete by key");
    assert!(!exists(&store, &old_id));
}

#[test]
fn missing_journal_refuses_delete_without_retiring_or_processing_cards() {
    let (scratch, descriptor) = fixture("federated-append-failure");
    let store = PlexusStore::open(&descriptor).unwrap();
    let id = insert_row(&store, &key());
    insert_card(&store, &key(), "pending", Some("el_pending"), "pending");
    std::fs::remove_file(scratch.join(federated_journal::NAME)).unwrap();
    assert!(store.delete_federated_row(&id).is_err());
    assert!(exists(&store, &id));
    assert_eq!(state(&store, "pending"), "pending");
    assert!(processed(&store).is_empty());
}

#[test]
fn sql_delete_failure_rolls_back_cards_but_the_prior_journal_append_survives() {
    let (scratch, descriptor) = fixture("federated-sql-failure");
    let store = PlexusStore::open(&descriptor).unwrap();
    let id = insert_row(&store, &key());
    insert_card(&store, &key(), "pending", Some("el_pending"), "pending");
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER refuse_federated_delete BEFORE DELETE ON federated_rows
         BEGIN SELECT RAISE(ABORT, 'delete refused'); END;",
            )
        })
        .unwrap();
    assert!(store.delete_federated_row(&id).is_err());
    assert!(exists(&store, &id));
    assert_eq!(state(&store, "pending"), "pending");
    assert!(processed(&store).is_empty());
    assert_eq!(
        entries(&scratch).len(),
        1,
        "durable append precedes SQL deletion"
    );
    store
        .inner
        .with_conn_fenced(|conn| conn.execute_batch("DROP TRIGGER refuse_federated_delete"))
        .unwrap();
    drop(store);
    let store = PlexusStore::open(&descriptor).unwrap();
    assert!(!exists(&store, &id));
    assert_eq!(processed(&store), ["el_mint", "el_pending", "el_reaffirm"]);
}

#[test]
fn malformed_complete_journal_refuses_boot_before_creating_or_changing_database() {
    let (scratch, descriptor) = fixture("federated-refuse-boot");
    let path = scratch.join(federated_journal::NAME);
    std::fs::write(&path, b"not json\n").unwrap();
    assert!(PlexusStore::open(&descriptor).is_err());
    assert!(!scratch.join("store.db").exists());
    std::fs::write(&path, b"").unwrap();
    let id;
    let older;
    {
        let store = PlexusStore::open(&descriptor).unwrap();
        id = insert_row(&store, &key());
        older = snapshot(&store, &scratch, &descriptor, &[&id], &[]);
    }
    let before = std::fs::read(scratch.join("snapshot.db")).unwrap();
    std::fs::write(
        &path,
        format!(
            "{{\"row_id\":\"{id}\",\"card_refs\":[\"el_mint\"],\"deleted_at_ms\":1}}\nnot json\n",
        ),
    )
    .unwrap();
    assert!(PlexusStore::open(&older).is_err());
    assert_eq!(std::fs::read(scratch.join("snapshot.db")).unwrap(), before);
    let conn = Connection::open(scratch.join("snapshot.db")).unwrap();
    let row_survived: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM federated_rows WHERE id=?1)",
            [&id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(row_survived);
    let processed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM federated_processed_cards",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(processed, 0);
}

#[test]
fn boot_creates_owner_only_journal_and_honours_parseable_final_deletion() {
    use std::os::unix::fs::PermissionsExt;
    let (scratch, descriptor) = fixture("federated-journal-boot");
    let id;
    {
        let store = PlexusStore::open(&descriptor).unwrap();
        let path = scratch.join(federated_journal::NAME);
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        id = insert_row(&store, &key());
    }
    std::fs::write(
        scratch.join(federated_journal::NAME),
        format!(
        "{{\"row_id\":\"{id}\",\"card_refs\":[\"el_mint\",\"el_pending\"],\"deleted_at_ms\":1}}",
    ),
    )
    .unwrap();
    let store = PlexusStore::open(&descriptor).unwrap();
    assert!(!exists(&store, &id));
    assert_eq!(processed(&store), ["el_mint", "el_pending"]);
}
