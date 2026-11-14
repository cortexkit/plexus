use super::*;

fn options(requester: &Requester, index: usize) -> Value {
    requester.cards.lock().unwrap()[index]["options"].clone()
}

fn per_call_options() -> Value {
    json!([
        {"id":"allow_once","label":"Allow this time","effect":"grant"},
        {"id":"deny_once","label":"Don't allow","effect":"decline"}
    ])
}

fn write_action(db: &rusqlite::Connection) {
    db.execute_batch(
        "UPDATE catalog_actions SET risk='write',ask_first=1;
         UPDATE connections SET resource_filters='{\"write_enabling\":[\"repo\"]}'",
    )
    .unwrap();
}

#[test]
fn late_standing_denial_waits_for_its_own_call_to_collect() {
    let (engine, db, requester, reader) = setup();
    let first = req(None);
    let mut other = first.clone();
    other.args = json!({"repo":"other"});
    pending(&engine, first.clone());
    requester.answer(0, "answered", Some("deny_always"));
    let reads = requester.reads.load(Ordering::SeqCst);

    pending(&engine, other.clone());
    assert_eq!(requester.cards.lock().unwrap().len(), 2);
    assert_eq!(count(&db, "federated_rows"), 0);
    assert_eq!(count(&db, "federated_processed_cards"), 0);
    assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
    assert_eq!(requester.reads.load(Ordering::SeqCst), reads + 2);
    assert_eq!(
        run(&engine, first).unwrap_err().reason_code(),
        "consent_denied"
    );
    assert_eq!(count(&db, "federated_rows"), 1);
    let row: (String, String) = db
        .query_row("SELECT effect,card_ref FROM federated_rows", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(row, ("deny".into(), "el_0".into()));
    assert_eq!(count(&db, "federated_processed_cards"), 1);

    let reads = requester.reads.load(Ordering::SeqCst);
    assert_eq!(
        run(&engine, other).unwrap_err().reason_code(),
        "consent_denied"
    );
    assert_eq!(requester.reads.load(Ordering::SeqCst), reads);
    assert_eq!(count(&db, "reservations"), 0);
    assert!(engine.transport().requests().is_empty());
}

#[test]
fn default_write_policy_asks_each_call_but_stored_allow_serves_without_cards() {
    let (engine, db, requester, _) = setup();
    write_action(&db);
    seed(&db, None, "write", "allow");
    assert_eq!(count(&db, "policies"), 0);
    for index in 0..2 {
        pending(&engine, req(None));
        assert_eq!(requester.cards.lock().unwrap().len(), index + 1);
        assert_eq!(options(&requester, index), per_call_options());
        requester.answer(index, "answered", Some("allow_once"));
        sent(&engine, req(None));
    }
    assert_eq!(count(&db, "action_requests"), 0);
    assert_eq!(count(&db, "federated_rows"), 1);
    assert_eq!(count(&db, "federated_processed_cards"), 0);
    engine
        .store()
        .set_policy("direct", "connection", "*", "allow", None)
        .unwrap();
    let reads = requester.reads.load(Ordering::SeqCst);
    sent(&engine, req(None));
    sent(&engine, req(None));
    assert_eq!(requester.reads.load(Ordering::SeqCst), reads);
    assert_eq!(requester.cards.lock().unwrap().len(), 2);
    assert_eq!(engine.transport().requests().len(), 4);
    assert_eq!(count(&db, "action_requests"), 0);
}

#[test]
fn ask_first_without_a_row_uses_one_claim_appropriate_card() {
    for claim in [
        None,
        Some(json!({"kind":"agent","agent_id":"remote"})),
        Some(json!({"kind":"worker","owner_module_id":"aft","worker_ref":"w"})),
    ] {
        let worker = claim
            .as_ref()
            .is_some_and(|claim| claim["kind"] == "worker");
        let choices: &[&str] = if worker {
            &["allow_once", "deny_once"]
        } else {
            &["allow_once", "allow_always", "deny_once", "deny_always"]
        };
        for &choice in choices {
            let (engine, db, requester, _) = setup();
            write_action(&db);
            let request = req(claim.clone());
            pending(&engine, request.clone());
            let cards = requester.cards.lock().unwrap();
            assert_eq!(cards.len(), 1);
            assert_eq!(cards[0]["default"], "deny_once");
            let ids: Vec<&str> = cards[0]["options"]
                .as_array()
                .unwrap()
                .iter()
                .map(|option| option["id"].as_str().unwrap())
                .collect();
            assert_eq!(ids, choices);
            drop(cards);
            requester.answer(0, "answered", Some(choice));
            if choice.starts_with("allow") {
                sent(&engine, request);
            } else {
                assert_eq!(
                    run(&engine, request).unwrap_err().reason_code(),
                    "consent_denied"
                );
            }
            assert_eq!(requester.cards.lock().unwrap().len(), 1);
            assert_eq!(count(&db, "action_requests"), 0);
            assert_eq!(
                count(&db, "federated_rows"),
                i64::from(choice.ends_with("always"))
            );
            assert_eq!(
                engine.transport().requests().len(),
                usize::from(choice.starts_with("allow"))
            );
        }
    }
}

#[test]
fn recipient_gate_asks_per_call_despite_local_allowlist_and_standing_allow() {
    let (engine, db, requester, _) = setup();
    let claim = Some(json!({"kind":"agent","agent_id":"local-agent"}));
    let row_id = seed(&db, claim.clone(), "read", "allow");
    let manifest = engine
        .store()
        .parsed_manifest(crate::storage::CATALOG_PRINCIPAL, "mock")
        .unwrap()
        .unwrap()
        .unwrap();
    let mut manifest = serde_json::to_value(manifest.as_ref()).unwrap();
    manifest["actions_baseline"][0]["recipients"] = json!(["/repo"]);
    engine
        .store()
        .upsert_manifest(
            crate::storage::CATALOG_PRINCIPAL,
            &crate::ingest_value(manifest).unwrap(),
        )
        .unwrap();
    engine
        .store()
        .change_recipient(
            "direct",
            "connection",
            Some("local-agent"),
            "o/r",
            true,
            true,
        )
        .unwrap();
    assert_eq!(
        engine
            .store()
            .list_recipients("direct", "connection", Some("local-agent"))
            .unwrap(),
        vec!["o/r"]
    );
    engine
        .store()
        .set_policy("direct", "connection", "*", "allow", None)
        .unwrap();
    let mut request = req(claim);
    request.attributed_agent_id = Some("local-agent".into());
    request.scope.as_mut().unwrap().agent_id = Some("local-agent".into());
    request.scope.as_mut().unwrap().delegates = true;
    for index in 0..2 {
        pending(&engine, request.clone());
        assert_eq!(requester.cards.lock().unwrap().len(), index + 1);
        assert_eq!(options(&requester, index), per_call_options());
        requester.answer(index, "answered", Some("allow_once"));
        sent(&engine, request.clone());
    }
    assert_eq!(count(&db, "federated_rows"), 1);
    assert_eq!(count(&db, "action_requests"), 0);
    assert!(engine
        .store()
        .list_action_requests("direct")
        .unwrap()
        .is_empty());
    let audits: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_journal WHERE federated_row_id=?1
             AND card_ref IN ('el_0','el_1') AND agent_id IS NULL",
            [row_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(audits, 4);
    engine
        .store()
        .set_policy("direct", "connection", "*", "block", None)
        .unwrap();
    let reads = requester.reads.load(Ordering::SeqCst);
    assert_eq!(
        run(&engine, request).unwrap_err().reason_code(),
        "policy_blocked"
    );
    assert_eq!(requester.reads.load(Ordering::SeqCst), reads);
    assert_eq!(requester.cards.lock().unwrap().len(), 2);
    assert_eq!(engine.transport().requests().len(), 2);
}

#[test]
fn read_row_cannot_skip_a_write_scope_card_on_the_same_connection() {
    let (engine, db, requester, _) = setup();
    seed(&db, None, "read", "allow");
    sent(&engine, req(None));
    assert!(requester.cards.lock().unwrap().is_empty());
    write_action(&db);
    pending(&engine, req(None));
    let cards = requester.cards.lock().unwrap();
    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0]["options"].as_array().unwrap().len(), 4);
    assert!(cards[0]["prompt"]
        .as_str()
        .unwrap()
        .starts_with("make changes in "));
    drop(cards);
    let scope: String = db
        .query_row("SELECT scope FROM federated_card_records", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(scope, "write");
    assert_eq!(count(&db, "federated_rows"), 1);
    assert_eq!(engine.transport().requests().len(), 1);
}

#[test]
fn two_held_answers_absorb_then_revoke_and_restore_cannot_remint() {
    let (engine, db, requester, reader) = setup();
    let clock = Arc::new(std::sync::atomic::AtomicI64::new(engine.now_ms()));
    let reading = clock.clone();
    let engine = engine.with_clock(Arc::new(move || reading.load(Ordering::SeqCst)));
    let first = req(None);
    let mut second = first.clone();
    second.args = json!({"repo":"second"});
    pending(&engine, first.clone());
    pending(&engine, second.clone());

    // Startup reads revoked row ids and card refs from the database directory's
    // journal. Keep the snapshot there to replay those deletions on restore;
    // VACUUM includes committed WAL pages too.
    let snapshot = std::path::Path::new(db.path().unwrap()).with_file_name("pending.db");
    db.execute("VACUUM INTO ?1", [snapshot.to_str().unwrap()])
        .unwrap();
    let captured = rusqlite::Connection::open(&snapshot).unwrap();
    assert_eq!(count(&captured, "federated_rows"), 0);
    assert_eq!(count(&captured, "federated_processed_cards"), 0);
    assert_eq!(count(&captured, "federated_card_records"), 2);
    let pending_refs = captured
        .prepare(
            "SELECT card_ref FROM federated_card_records WHERE state='pending' ORDER BY card_ref",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(pending_refs, ["el_0", "el_1"]);
    drop(captured);

    struct Gate {
        started: std::sync::mpsc::Sender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl ConsentWaitHook for Gate {
        fn before_wait(&self) {
            self.started.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        }
        fn after_wait(&self) {}
    }
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let held = engine.clone().with_consent_wait_hook(Arc::new(Gate {
        started: started_tx,
        release: Mutex::new(release_rx),
    }));
    let mut mint = None;
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            let result = run(&held, second.clone());
            done_tx.send(()).unwrap();
            result
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        requester.answer(0, "answered", Some("allow_always"));
        sent(&engine, first.clone());
        assert_eq!(count(&db, "federated_rows"), 1);
        mint = Some(
            db.query_row(
                "SELECT id,card_ref,granted_at_ms FROM federated_rows",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap(),
        );
        assert_eq!(requester.cards.lock().unwrap()[1]["state"], "pending");
        assert!(matches!(
            done_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        let reads = requester.reads.load(Ordering::SeqCst);
        let mut third = req(None);
        third.args = json!({"repo":"third"});
        sent(&engine, third);
        assert_eq!(requester.reads.load(Ordering::SeqCst), reads);
        assert_eq!(requester.cards.lock().unwrap().len(), 2);

        // A later answer must not reset the row's original grant timestamp.
        clock.fetch_add(1_000, Ordering::SeqCst);
        requester.answer(1, "answered", Some("allow_always"));
        release_tx.send(()).unwrap();
        assert_eq!(
            waiter.join().unwrap().unwrap().transmission,
            TransmissionState::Sent
        );
    });
    drop(held);
    let (id, card_ref, granted_at_ms) = mint.unwrap();
    let stored: (String, String, i64, String) = db
        .query_row(
            "SELECT id,card_ref,granted_at_ms,card_refs_json FROM federated_rows",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(stored.0, id);
    assert_eq!(stored.1, card_ref);
    assert_eq!(stored.2, granted_at_ms);
    assert_eq!(
        serde_json::from_str::<Value>(&stored.3).unwrap(),
        json!(["el_0", "el_1"])
    );
    assert_eq!(count(&db, "federated_rows"), 1);
    assert_eq!(count(&db, "federated_processed_cards"), 2);
    assert_eq!(engine.transport().requests().len(), 3);
    assert!(engine.store().delete_federated_row(&id).unwrap());
    pending(&engine, second.clone());
    assert_eq!(requester.cards.lock().unwrap().len(), 3);
    assert_eq!(count(&db, "federated_rows"), 0);
    assert_eq!(engine.transport().requests().len(), 3);

    let credentials = engine.credential_source().clone();
    let transport = engine.transport().clone();
    drop(engine);
    drop(db);
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: new_request_id(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: snapshot.to_str().unwrap().into(),
            },
        })
        .unwrap(),
    );
    let restored_db = rusqlite::Connection::open(&snapshot).unwrap();
    assert_eq!(count(&restored_db, "federated_processed_cards"), 2);
    let restored = GovernanceEngine::new(store, credentials, transport)
        .with_consent_cards(Arc::new(ConsentCards::new(requester.clone())))
        .with_scope_reader(reader);
    for request in [first, second] {
        pending(&restored, request);
        assert_eq!(count(&restored_db, "federated_rows"), 0);
        assert_eq!(restored.transport().requests().len(), 3);
    }
    assert_eq!(requester.cards.lock().unwrap().len(), 5);
    let retired: i64 = restored_db.query_row(
        "SELECT count(*) FROM federated_card_records WHERE card_ref IN ('el_0','el_1') AND state='retired'", [], |row| row.get(0),
    ).unwrap();
    assert_eq!(retired, 2);
}
