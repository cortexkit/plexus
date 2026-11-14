use super::*;
use crate::scope::{ScopeDescription, ScopeReadError, ScopeStatus};
use std::sync::Mutex;
use std::time::Duration;

fn fixture() -> (Engine, rusqlite::Connection) {
    let (engine, db) = super::fixture();
    let manifest = engine
        .store()
        .parsed_manifest(crate::storage::CATALOG_PRINCIPAL, "mock")
        .unwrap()
        .unwrap()
        .unwrap();
    let mut manifest = serde_json::to_value(manifest.as_ref()).unwrap();
    manifest["auth"] = json!({"mode":"none"});
    manifest["credential_bindings"] = json!([]);
    engine
        .store()
        .upsert_manifest(
            crate::storage::CATALOG_PRINCIPAL,
            &crate::ingest_value(manifest).unwrap(),
        )
        .unwrap();
    (engine, db)
}

struct Reader {
    answer: Result<ScopeDescription, ScopeReadError>,
    calls: Mutex<Vec<(String, String)>>,
}

impl ScopeReader for Reader {
    fn describe(&self, owner: &str, scope_ref: &str) -> Result<ScopeDescription, ScopeReadError> {
        self.calls
            .lock()
            .unwrap()
            .push((owner.into(), scope_ref.into()));
        self.answer.clone()
    }
}

fn reader(status: ScopeStatus, owner_synced: bool, owner_configured: bool) -> Arc<Reader> {
    Arc::new(Reader {
        answer: Ok(ScopeDescription {
            status,
            owner_synced,
            owner_configured,
            live: None,
            parent: None,
            expires_at_ms: None,
        }),
        calls: Mutex::new(Vec::new()),
    })
}

fn seed(db: &rusqlite::Connection, claim: Option<Value>, scope: &str, effect: &str) -> String {
    let claim = claim.map(|claim| serde_json::from_value(claim).unwrap());
    let canonical = crate::federated::canonicalize_claim(claim.as_ref()).unwrap();
    let id = crate::federated::new_row_id();
    db.execute("INSERT INTO federated_rows
        (id,peer_fingerprint,pairing_id,peer_class,selector,claim_kind,canonical_claim_identity,
         owner_principal,subject,scope,claim_json,peer_name,effect,granted_at_ms,card_ref,card_refs_json)
        VALUES (?1,?2,'pairing','computer',?3,?4,?5,'direct','connection',?6,?7,'Peer',?8,1,'el_mint','[\"el_mint\"]')",
        rusqlite::params![id, "a".repeat(32), if claim.is_some() { "exact_claim" } else { "claimless" },
            canonical.claim_kind, canonical.canonical_claim_identity, scope,
            claim.as_ref().map(|claim| serde_json::to_string(claim).unwrap()), effect]).unwrap();
    id
}

fn count(db: &rusqlite::Connection, table: &str) -> i64 {
    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

fn no_card(engine: &Engine, db: &rusqlite::Connection) {
    assert_eq!(count(db, "action_requests"), 0);
    assert_eq!(count(db, "federated_card_records"), 0);
    assert!(engine.transport().requests().is_empty());
}

#[test]
fn standing_read_allow_serves_without_policy_or_card_and_pins_audit() {
    let (engine, db) = fixture();
    let id = seed(&db, None, "read", "allow");
    let reader = reader(ScopeStatus::Live, false, false);
    let engine = engine.with_scope_reader(reader.clone());
    for _ in 0..2 {
        let reservation = engine.authorize(request(None)).unwrap();
        assert_eq!(reservation.federated_row_id.as_deref(), Some(id.as_str()));
        let pins: (Option<String>, Option<String>, String, Option<String>) = db.query_row(
            "SELECT grant_id,agent_grant_id,federated_row_id,card_ref FROM reservations WHERE reservation_id=?1",
            [&reservation.reservation_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))).unwrap();
        assert_eq!(pins, (None, None, id.clone(), None));
        let outcome = engine.revalidate_and_dispatch(&reservation);
        assert_eq!(outcome.transmission, TransmissionState::Sent, "{outcome:?}");
    }
    assert_eq!(engine.transport().requests().len(), 2);
    assert_eq!(
        reader.calls.lock().unwrap().as_slice(),
        &[
            (
                "reserved:callosum".into(),
                format!("fed-base:{}:pairing", "a".repeat(32))
            ),
            (
                "reserved:callosum".into(),
                format!("fed-base:{}:pairing", "a".repeat(32))
            ),
        ]
    );
    let audits: i64 = db.query_row("SELECT count(*) FROM audit_journal WHERE agent_id IS NULL
        AND peer_fingerprint=?1 AND pairing_id='pairing' AND peer_class='computer'
        AND claim_kind='' AND canonical_claim_identity='' AND federated_row_id=?2 AND card_ref IS NULL",
        rusqlite::params!["a".repeat(32), id], |row| row.get(0)).unwrap();
    assert_eq!(audits, 4);
    assert_eq!(count(&db, "action_requests"), 0);
    assert_eq!(count(&db, "federated_card_records"), 0);
}

#[test]
fn standing_denial_refuses_and_ask_first_allow_never_serves_alone() {
    for effect in ["allow", "deny"] {
        let (engine, db) = fixture();
        let id = seed(&db, None, "read", effect);
        let engine = engine.with_scope_reader(reader(ScopeStatus::Live, true, true));
        if effect == "allow" {
            engine
                .store()
                .set_policy("direct", "connection", "*", "ask_first", None)
                .unwrap();
        }
        assert_eq!(
            engine.authorize(request(None)).unwrap_err().reason_code(),
            if effect == "allow" {
                "consent_unavailable"
            } else {
                "consent_denied"
            }
        );
        let pin: Option<String> = db
            .query_row("SELECT federated_row_id FROM audit_journal WHERE acting_principal='reserved:callosum'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(pin.as_deref(), Some(id.as_str()));
        assert_eq!(count(&db, "reservations"), 0);
        no_card(&engine, &db);
    }
}

#[test]
fn standing_denial_and_ask_first_do_not_require_a_credential() {
    for effect in ["allow", "deny"] {
        let (engine, db) = super::fixture();
        seed(&db, None, "read", effect);
        if effect == "allow" {
            engine
                .store()
                .set_policy("direct", "connection", "*", "ask_first", None)
                .unwrap();
        }
        let engine = engine.with_scope_reader(reader(ScopeStatus::Live, true, true));
        assert_eq!(
            engine.authorize(request(None)).unwrap_err().reason_code(),
            if effect == "deny" {
                "consent_denied"
            } else {
                "consent_unavailable"
            }
        );
        no_card(&engine, &db);
    }
}

#[test]
fn kept_gates_win_over_both_standing_effects() {
    for effect in ["allow", "deny"] {
        for &(sql, expected) in GATE_CASES {
            let (engine, db) = fixture();
            seed(&db, None, "read", effect);
            db.execute_batch(sql).unwrap();
            db.execute_batch("UPDATE federated_rows SET scope=COALESCE((SELECT risk FROM catalog_actions LIMIT 1),'read')").unwrap();
            let reader = reader(ScopeStatus::Live, true, true);
            let engine = engine.with_scope_reader(reader.clone());
            assert_eq!(
                engine.authorize(request(None)).unwrap_err().reason_code(),
                expected,
                "{effect}/{sql}"
            );
            assert!(reader.calls.lock().unwrap().is_empty());
            assert_eq!(count(&db, "federated_rows"), 1);
            no_card(&engine, &db);
        }
        let (engine, db) = fixture();
        seed(&db, None, "read", effect);
        for (req, expected) in [
            (
                request(None).with_schema_hash("wrong"),
                "catalog_schema_mismatch",
            ),
            (
                {
                    let mut req = request(None);
                    req.args = json!({"extra":"not-reviewed"});
                    req
                },
                "argument_undeclared",
            ),
        ] {
            assert_eq!(engine.authorize(req).unwrap_err().reason_code(), expected);
        }
        engine
            .store()
            .set_policy("direct", "connection", "*", "block", None)
            .unwrap();
        assert_eq!(
            engine.authorize(request(None)).unwrap_err().reason_code(),
            "policy_blocked"
        );
        let engine = engine.with_connector_home_guard(Arc::new(|| {
            Some(json!({"error":{"code":"connector_home_not_held"}}))
        }));
        assert_eq!(
            engine.authorize(request(None)).unwrap_err().reason_code(),
            "connector_home_not_held"
        );
        no_card(&engine, &db);
    }
    for (risk, tier) in [
        ("destructive", "S1"),
        ("unknown", "S1"),
        ("write", "S3"),
        ("write", "S4"),
    ] {
        let (engine, db) = fixture();
        seed(&db, None, "write", "allow");
        super::super::tests::install_system_manifest(engine.store(), "mock", tier);
        db.execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        db.execute("UPDATE catalog_actions SET risk=?1", [risk])
            .unwrap();
        assert_eq!(
            engine.authorize(request(None)).unwrap_err().reason_code(),
            "needs_decision_plane"
        );
        no_card(&engine, &db);
    }
}

#[test]
fn write_scope_requires_stored_allow_and_recipients_still_ask_per_call() {
    for stored_allow in [false, true] {
        let (engine, db) = fixture();
        seed(&db, None, "write", "allow");
        db.execute_batch(
            "UPDATE catalog_actions SET risk='write',ask_first=1;
            UPDATE connections SET resource_filters='{\"write_enabling\":[\"repo\"]}'",
        )
        .unwrap();
        if stored_allow {
            engine
                .store()
                .set_policy("direct", "connection", "*", "allow", None)
                .unwrap();
        }
        let engine = engine.with_scope_reader(reader(ScopeStatus::Live, true, true));
        let result = engine.authorize(request(None));
        if stored_allow {
            assert_eq!(
                engine
                    .revalidate_and_dispatch(&result.unwrap())
                    .transmission,
                TransmissionState::Sent
            );
        } else {
            assert_eq!(result.unwrap_err().reason_code(), "consent_unavailable");
            no_card(&engine, &db);
        }
        assert_eq!(count(&db, "action_requests"), 0);
        assert_eq!(count(&db, "federated_card_records"), 0);
    }
    let (engine, db) = fixture();
    seed(&db, None, "read", "allow");
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
        .set_policy("direct", "connection", "*", "allow", None)
        .unwrap();
    db.execute_batch("ALTER TABLE recipient_allowlist RENAME TO local_lists_not_for_federation")
        .unwrap();
    let engine = engine.with_scope_reader(reader(ScopeStatus::Live, true, true));
    assert_eq!(
        engine.authorize(request(None)).unwrap_err().reason_code(),
        "consent_unavailable"
    );
    no_card(&engine, &db);
}

#[test]
fn scopes_match_catalog_risk_exactly_and_subjects_never_alias() {
    for (row_scope, effect, action_risk) in [
        ("read", "allow", "write"),
        ("write", "allow", "read"),
        ("write", "deny", "read"),
    ] {
        let (engine, db) = fixture();
        seed(&db, None, row_scope, effect);
        db.execute("UPDATE catalog_actions SET risk=?1", [action_risk])
            .unwrap();
        db.execute_batch(
            "UPDATE connections SET resource_filters='{\"write_enabling\":[\"repo\"]}'",
        )
        .unwrap();
        let reader = reader(ScopeStatus::Live, true, true);
        let engine = engine.with_scope_reader(reader.clone());
        assert_eq!(
            engine.authorize(request(None)).unwrap_err().reason_code(),
            "consent_unavailable"
        );
        assert!(reader.calls.lock().unwrap().is_empty());
        no_card(&engine, &db);
    }
    for sql in [
        "UPDATE federated_rows SET owner_principal='reserved:callosum'",
        "UPDATE federated_rows SET owner_principal='',subject='web_search'",
        "UPDATE federated_rows SET subject='other'",
    ] {
        let (engine, db) = fixture();
        seed(&db, None, "read", "allow");
        db.execute_batch(sql).unwrap();
        assert_eq!(
            engine.authorize(request(None)).unwrap_err().reason_code(),
            "consent_unavailable"
        );
        no_card(&engine, &db);
    }
}

#[test]
fn flow_rows_serve_but_run_rows_never_match_and_kept_gates_still_win() {
    for kind in ["flow", "run"] {
        let claim = if kind == "flow" {
            json!({"kind":"flow","flow_id":"flow-a","flow_version":1,
            "flow_install_id":"install","flow_code_hash":"b".repeat(64)})
        } else {
            json!({"kind":"run","agent_id":"agent-a"})
        };
        let (engine, db) = fixture();
        let reader = reader(ScopeStatus::Live, true, true);
        let engine = engine.with_scope_reader(reader.clone());
        assert_eq!(
            engine
                .authorize(request(Some(claim.clone())))
                .unwrap_err()
                .reason_code(),
            "consent_unavailable"
        );
        seed(&db, Some(claim.clone()), "read", "allow");
        let result = engine.invoke_held(request(Some(claim.clone())), std::time::Instant::now());
        if kind == "flow" {
            assert_eq!(result.unwrap().transmission, TransmissionState::Sent);
        } else {
            assert_eq!(result.unwrap_err().reason_code(), "consent_unavailable");
            assert!(reader.calls.lock().unwrap().is_empty());
        }
        db.execute_batch("UPDATE connections SET status='disabled'")
            .unwrap();
        assert_eq!(
            engine
                .authorize(request(Some(claim)))
                .unwrap_err()
                .reason_code(),
            "connection_disabled"
        );
        assert_eq!(count(&db, "action_requests"), 0);
        assert_eq!(count(&db, "federated_card_records"), 0);
    }
}

#[test]
fn apply_liveness_table_describes_each_effect_and_never_deletes() {
    for effect in ["allow", "deny"] {
        let mut answers = Vec::new();
        for status in [ScopeStatus::Live, ScopeStatus::Ended, ScopeStatus::NotLive] {
            for synced in [false, true] {
                for configured in [false, true] {
                    let expected = match status {
                        ScopeStatus::Live => {
                            if effect == "allow" {
                                "allow"
                            } else {
                                "consent_denied"
                            }
                        }
                        ScopeStatus::Ended => "federated_pairing_ended",
                        ScopeStatus::NotLive if synced && configured => "federated_pairing_ended",
                        _ => "federated_liveness_unavailable",
                    };
                    answers.push((reader(status, synced, configured), expected));
                }
            }
        }
        answers.push((
            Arc::new(Reader {
                answer: Err(ScopeReadError("offline".into())),
                calls: Mutex::new(Vec::new()),
            }),
            "federated_liveness_unavailable",
        ));
        for (reader, expected) in answers {
            let (engine, db) = fixture();
            seed(&db, None, "read", effect);
            let engine = engine.with_scope_reader(reader.clone());
            let result = engine.authorize(request(None));
            if expected == "allow" {
                assert!(result.is_ok(), "{result:?}");
            } else {
                let denial = result.unwrap_err();
                assert_eq!(
                    denial.reason_code(),
                    expected,
                    "{effect}/{:?}",
                    reader.answer
                );
                assert_eq!(
                    denial.retryability() == Retryability::AutoRetryable,
                    expected == "federated_liveness_unavailable"
                );
                assert_eq!(count(&db, "reservations"), 0);
            }
            assert_eq!(reader.calls.lock().unwrap().len(), 1);
            assert_eq!(count(&db, "federated_rows"), 1);
            assert_eq!(count(&db, "federated_processed_cards"), 0);
            no_card(&engine, &db);
        }
        let (engine, db) = fixture();
        seed(&db, None, "read", effect);
        assert_eq!(
            engine.authorize(request(None)).unwrap_err().reason_code(),
            "federated_liveness_unavailable"
        );
        assert_eq!(count(&db, "federated_rows"), 1);
    }
}

#[test]
fn revoke_during_held_describe_commits_without_waiting_and_never_admits() {
    struct HeldReader {
        entered: std::sync::mpsc::Sender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl ScopeReader for HeldReader {
        fn describe(&self, _: &str, _: &str) -> Result<ScopeDescription, ScopeReadError> {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            reader(ScopeStatus::Live, true, true).answer.clone()
        }
    }
    let (engine, db) = fixture();
    let id = seed(&db, None, "read", "allow");
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let store = engine.store().clone();
    let engine = engine.with_scope_reader(Arc::new(HeldReader {
        entered: entered_tx,
        release: Mutex::new(release_rx),
    }));
    let authorize = std::thread::spawn(move || engine.authorize(request(None)));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let (deleted_tx, deleted_rx) = std::sync::mpsc::channel();
    let revoke = std::thread::spawn(move || {
        deleted_tx
            .send(store.delete_federated_row(&id).unwrap())
            .unwrap();
    });
    let deleted = deleted_rx.recv_timeout(Duration::from_secs(5));
    release_tx.send(()).unwrap();
    revoke.join().unwrap();
    let result = authorize.join().unwrap();
    assert!(deleted.unwrap(), "describe must not hold the writer fence");
    assert_eq!(result.unwrap_err().reason_code(), "consent_unavailable");
    assert_eq!(count(&db, "federated_rows"), 0);
    assert_eq!(count(&db, "reservations"), 0);
}

#[test]
fn revoke_after_reservation_pins_exact_row_before_dispatch() {
    let (engine, db) = fixture();
    let id = seed(&db, None, "read", "allow");
    let engine = engine.with_scope_reader(reader(ScopeStatus::Live, true, true));
    let reservation = engine.authorize(request(None)).unwrap();
    assert!(engine.store().delete_federated_row(&id).unwrap());
    // A new row under the same key cannot inherit an old reservation's pin.
    seed(&db, None, "read", "allow");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert_eq!(outcome.transmission, TransmissionState::NotSent);
    assert!(
        matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. } if code == "aborted_stale_authorization")
    );
    no_card(&engine, &db);
    let audit: Option<String> = db
        .query_row(
            "SELECT federated_row_id FROM audit_journal WHERE gate='dispatch'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(audit.as_deref(), Some(id.as_str()));
}
