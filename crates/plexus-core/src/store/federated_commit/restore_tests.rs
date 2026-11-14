use super::*;
use crate::federated_journal::{self, Deletion};

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
    rows: &[&str],
    pending: &[&str],
) -> StorageDescriptor {
    let path = scratch.join("snapshot.db");
    // VACUUM includes committed WAL pages. Assert the captured records before
    // replay so an empty database cannot make a restore test pass vacuously.
    store
        .inner
        .with_conn(|db| db.execute("VACUUM INTO ?1", [path.to_string_lossy().as_ref()]))
        .unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    for id in rows {
        let found: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM federated_rows WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(found, 1, "snapshot must hold row {id}");
    }
    for id in pending {
        let state: String = db
            .query_row(
                "SELECT state FROM federated_card_records WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "pending", "snapshot must hold pending card {id}");
    }
    StorageDescriptor {
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
        ..descriptor.clone()
    }
}

#[test]
fn two_pending_answers_stay_processed_after_revoke_and_pending_snapshot_restore() {
    let (scratch, descriptor, store) = fixture();
    let caller = caller(None);
    let first = card(&store, &caller, "first");
    let second = card(&store, &caller, "second");
    let older = snapshot(&store, &scratch, &descriptor, &[], &[&first.id, &second.id]);
    let id = committed(
        commit(
            &store,
            Some(&live()),
            &caller,
            &first,
            Answer::AllowAlways,
            1,
        ),
        Effect::Allow,
    );
    assert_eq!(
        id,
        committed(
            commit(
                &store,
                Some(&live()),
                &caller,
                &second,
                Answer::AllowAlways,
                2
            ),
            Effect::Allow
        )
    );
    assert!(store.delete_federated_row(&id).unwrap());
    assert_eq!(processed(&store), ["el_first", "el_second"]);
    assert_eq!(
        commit(
            &store,
            Some(&live()),
            &caller,
            &second,
            Answer::AllowAlways,
            3
        )
        .unwrap(),
        CommitOutcome::Reask
    );
    assert_eq!(count(&store, "federated_rows"), 0);
    drop(store);
    let restored = PlexusStore::open(&older).unwrap();
    for r in [&first, &second] {
        assert_eq!(
            state(&restored, &r.id),
            State::Pending,
            "replay records refs, not old tracking ids"
        );
        assert_eq!(
            commit(&restored, Some(&live()), &caller, r, Answer::AllowAlways, 4).unwrap(),
            CommitOutcome::Reask
        );
        assert_eq!(state(&restored, &r.id), State::Retired);
        assert_eq!(count(&restored, "federated_rows"), 0);
    }
    let fresh = card(&restored, &caller, "fresh");
    let new_id = committed(
        commit(
            &restored,
            Some(&live()),
            &caller,
            &fresh,
            Answer::AllowAlways,
            5,
        ),
        Effect::Allow,
    );
    assert_ne!(id, new_id);
    assert_eq!(count(&restored, "federated_rows"), 1);
    assert_eq!(processed(&restored), ["el_first", "el_fresh", "el_second"]);
}

#[test]
fn deleted_connection_with_only_a_pending_card_cannot_mint_after_restore() {
    let (scratch, descriptor, store) = fixture();
    store
        .inner
        .with_conn_fenced(|db| {
            db.execute(
                "INSERT INTO connections
        (principal,connection_id,app_key,status,created_at_ms,updated_at_ms)
        VALUES ('direct','conn','mock','active',1,1)",
                [],
            )
        })
        .unwrap();
    let caller = caller(None);
    let pending = card(&store, &caller, "pending");
    let older = snapshot(&store, &scratch, &descriptor, &[], &[&pending.id]);
    store.delete_connection("direct", "conn", true).unwrap();
    assert_eq!(count(&store, "federated_card_records"), 0);
    let journal = entries(&scratch);
    assert_eq!(journal.len(), 1);
    assert_eq!(journal[0].row_id, None);
    assert_eq!(journal[0].card_refs, ["el_pending"]);
    drop(store);
    let restored = PlexusStore::open(&older).unwrap();
    assert_eq!(processed(&restored), ["el_pending"]);
    assert_eq!(
        commit(
            &restored,
            Some(&live()),
            &caller,
            &pending,
            Answer::AllowAlways,
            1
        )
        .unwrap(),
        CommitOutcome::Reask
    );
    assert_eq!(state(&restored, &pending.id), State::Retired);
    assert_eq!(count(&restored, "federated_rows"), 0);
}

#[test]
fn flips_get_fresh_ids_and_journal_every_ref_except_the_flipping_card() {
    for (first_answer, flip_answer) in [
        (Answer::AllowAlways, Answer::DenyAlways),
        (Answer::DenyAlways, Answer::AllowAlways),
    ] {
        let (scratch, _descriptor, store) = fixture();
        let caller = caller(None);
        let first = card(&store, &caller, "first");
        let old = committed(
            commit(&store, Some(&live()), &caller, &first, first_answer, 1),
            first_answer.standing_effect().unwrap(),
        );
        let reaffirm = card(&store, &caller, "reaffirm");
        committed(
            commit(&store, Some(&live()), &caller, &reaffirm, first_answer, 2),
            first_answer.standing_effect().unwrap(),
        );
        let other = card(&store, &caller, "other");
        let flip = card(&store, &caller, "flip");
        let new = committed(
            commit(&store, Some(&live()), &caller, &flip, flip_answer, 3),
            flip_answer.standing_effect().unwrap(),
        );
        assert_ne!(old, new);
        assert!(new.starts_with("plxf_"));
        assert_eq!(count(&store, "federated_rows"), 1);
        assert_eq!(state(&store, &flip.id), State::Committed);
        assert_eq!(state(&store, &other.id), State::Retired);
        assert_eq!(row(&store, &new)["card_refs"], json!(["el_flip"]));
        let journal = entries(&scratch);
        assert_eq!(journal.len(), 1);
        assert_eq!(journal[0].row_id.as_deref(), Some(old.as_str()));
        assert_eq!(
            journal[0].card_refs,
            ["el_first", "el_other", "el_reaffirm"]
        );
        assert_eq!(
            processed(&store),
            ["el_first", "el_flip", "el_other", "el_reaffirm"]
        );
        assert_eq!(
            commit(&store, Some(&live()), &caller, &flip, flip_answer, 4).unwrap(),
            CommitOutcome::Reask
        );
    }
}

fn fail_commit_state(store: &PlexusStore) {
    store
        .inner
        .with_conn_fenced(|db| {
            db.execute_batch(
                "CREATE TRIGGER fail_commit
        BEFORE UPDATE OF state ON federated_card_records WHEN NEW.state='committed'
        BEGIN SELECT RAISE(ABORT,'injected commit failure'); END;",
            )
        })
        .unwrap();
}

#[test]
fn row_processed_ref_and_record_commit_are_one_transaction() {
    for same_effect in [false, true] {
        let (_scratch, _descriptor, store) = fixture();
        let caller = caller(None);
        let mut original = None;
        if same_effect {
            let first = card(&store, &caller, "first");
            let id = committed(
                commit(
                    &store,
                    Some(&live()),
                    &caller,
                    &first,
                    Answer::AllowAlways,
                    1,
                ),
                Effect::Allow,
            );
            original = Some((id.clone(), row(&store, &id)));
        }
        let pending = card(&store, &caller, "pending");
        fail_commit_state(&store);
        let error = commit(
            &store,
            Some(&live()),
            &caller,
            &pending,
            Answer::AllowAlways,
            2,
        )
        .unwrap_err();
        assert_eq!(error.denial.reason_code(), "store_failure");
        assert_eq!(state(&store, &pending.id), State::Pending);
        assert_eq!(
            processed(&store),
            if same_effect {
                vec!["el_first"]
            } else {
                vec![]
            }
        );
        assert_eq!(count(&store, "federated_rows"), i64::from(same_effect));
        if let Some((id, before)) = original {
            assert_eq!(row(&store, &id), before);
        }
    }
}

#[test]
fn a_flip_journal_survives_sql_rollback_without_processing_its_own_answer() {
    let (scratch, descriptor, store) = fixture();
    let caller = caller(None);
    let first = card(&store, &caller, "first");
    let old = committed(
        commit(
            &store,
            Some(&live()),
            &caller,
            &first,
            Answer::AllowAlways,
            1,
        ),
        Effect::Allow,
    );
    let other = card(&store, &caller, "other");
    let flip = card(&store, &caller, "flip");
    let older = snapshot(
        &store,
        &scratch,
        &descriptor,
        &[&old],
        &[&other.id, &flip.id],
    );
    fail_commit_state(&store);
    assert!(commit(&store, Some(&live()), &caller, &flip, Answer::DenyAlways, 2).is_err());
    assert_eq!(
        row(&store, &old)["effect"],
        "allow",
        "SQL transaction rolled back"
    );
    assert_eq!(state(&store, &flip.id), State::Pending);
    assert_eq!(state(&store, &other.id), State::Pending);
    assert_eq!(processed(&store), ["el_first"]);
    let journal = entries(&scratch);
    assert_eq!(journal.len(), 1);
    assert_eq!(journal[0].row_id.as_deref(), Some(old.as_str()));
    assert_eq!(journal[0].card_refs, ["el_first", "el_other"]);
    drop(store);
    let restored = PlexusStore::open(&older).unwrap();
    assert_eq!(
        count(&restored, "federated_rows"),
        0,
        "replay removes old row even though flip never committed"
    );
    assert_eq!(processed(&restored), ["el_first", "el_other"]);
    let new = committed(
        commit(
            &restored,
            Some(&live()),
            &caller,
            &flip,
            Answer::DenyAlways,
            3,
        ),
        Effect::Deny,
    );
    assert_ne!(old, new);
    assert_eq!(row(&restored, &new)["card_ref"], "el_flip");
    assert_eq!(
        commit(
            &restored,
            Some(&live()),
            &caller,
            &other,
            Answer::AllowAlways,
            4
        )
        .unwrap(),
        CommitOutcome::Reask
    );
    assert_eq!(state(&restored, &other.id), State::Retired);
    drop(restored);
    let rebooted = PlexusStore::open(&older).unwrap();
    assert_eq!(
        row(&rebooted, &new)["effect"],
        "deny",
        "old journal id cannot delete replacement row"
    );
}
