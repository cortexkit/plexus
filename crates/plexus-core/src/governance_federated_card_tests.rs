use super::standing::{count, fixture, seed};
use super::*;
use crate::consent_card::{ElicitationCallError, ElicitationRoute};
use crate::scope::{ScopeDescription, ScopeReadError, ScopeStatus};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

#[path = "governance_federated_ask_first_tests.rs"]
mod ask_first;

#[derive(Default)]
struct Requester {
    cards: Mutex<Vec<Value>>,
    scopes: Mutex<Vec<CallScope>>,
    reads: AtomicUsize,
    fail: Mutex<Option<String>>,
}

impl Requester {
    fn answer(&self, index: usize, state: &str, choice: Option<&str>) {
        let mut cards = self.cards.lock().unwrap();
        cards[index]["state"] = json!(state);
        if let Some(choice) = choice {
            cards[index]["answered_choice_id"] = json!(choice);
        }
    }
}

impl ElicitationRoute for Requester {
    fn call_scoped(
        &self,
        scope: &CallScope,
        op: &str,
        params: Value,
        _: Duration,
    ) -> Result<Value, ElicitationCallError> {
        self.scopes.lock().unwrap().push(scope.clone());
        if self.fail.lock().unwrap().as_deref() == Some(op) {
            return Err(ElicitationCallError::Transport);
        }
        let mut cards = self.cards.lock().unwrap();
        if op == "consent.request" {
            let id = format!("el_{}", cards.len());
            let mut card = params;
            card["elicitation_id"] = json!(id);
            card["state"] = json!("pending");
            cards.push(card);
            return Ok(json!({"elicitation_id":id}));
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        let card = cards
            .iter()
            .find(|card| card["elicitation_id"] == params["elicitation_id"])
            .or_else(|| cards.first())
            .unwrap();
        Ok(card.clone())
    }
}

struct Reader {
    status: Mutex<ScopeStatus>,
    calls: AtomicUsize,
}
impl ScopeReader for Reader {
    fn describe(&self, owner: &str, scope: &str) -> Result<ScopeDescription, ScopeReadError> {
        assert_eq!(owner, "reserved:callosum");
        assert_eq!(scope, format!("fed-base:{}:pairing", "a".repeat(32)));
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ScopeDescription {
            status: *self.status.lock().unwrap(),
            owner_synced: true,
            owner_configured: true,
            live: None,
            parent: None,
            expires_at_ms: None,
        })
    }
}

fn setup() -> (Engine, rusqlite::Connection, Arc<Requester>, Arc<Reader>) {
    let (engine, db) = fixture();
    let requester = Arc::new(Requester::default());
    let reader = Arc::new(Reader {
        status: Mutex::new(ScopeStatus::Live),
        calls: AtomicUsize::new(0),
    });
    let engine = engine
        .with_consent_cards(Arc::new(ConsentCards::new(requester.clone())))
        .with_scope_reader(reader.clone());
    (engine, db, requester, reader)
}

fn req(claim: Option<Value>) -> AuthorizationRequest {
    request(claim)
        .with_scope(CallScope {
            owner: "reserved:callosum".into(),
            scope_ref: "fed-claim:route-one".into(),
            scope_epoch: 1,
            kind: Some("federated".into()),
            parent: None,
            parent_state: None,
            agent_id: None,
            flow_id: None,
            delegates: false,
            owner_authorized: false,
        })
        .with_federated_held_reply(true)
}

fn run(engine: &Engine, req: AuthorizationRequest) -> Result<DispatchOutcome, Denial> {
    engine.invoke_held(req, Instant::now())
}

fn pending(engine: &Engine, req: AuthorizationRequest) {
    assert_eq!(
        run(engine, req).unwrap_err().reason_code(),
        "access_pending"
    );
}

fn sent(engine: &Engine, req: AuthorizationRequest) {
    let outcome = run(engine, req).unwrap();
    assert_eq!(outcome.transmission, TransmissionState::Sent, "{outcome:?}");
}

#[test]
fn permissions_revoke_denial_asks_again_and_never_grants() {
    let (engine, db, requester, reader) = setup();
    let id = seed(&db, None, "read", "deny");
    assert_eq!(
        run(&engine, req(None)).unwrap_err().reason_code(),
        "consent_denied"
    );
    assert!(requester.cards.lock().unwrap().is_empty());
    let describes = reader.calls.load(Ordering::SeqCst);
    assert_eq!(
        crate::permissions::revoke(engine.store(), "direct", &id, 1).unwrap(),
        crate::permissions::RevokeOutcome::FederatedRevoked
    );
    assert_eq!(reader.calls.load(Ordering::SeqCst), describes);
    pending(&engine, req(None));
    assert_eq!(requester.cards.lock().unwrap().len(), 1);
    assert_eq!(
        reader.calls.load(Ordering::SeqCst),
        describes,
        "filing needs no describe"
    );
    assert_eq!(count(&db, "federated_rows"), 0);
    assert_eq!(count(&db, "reservations"), 0);
    assert!(engine.transport().requests().is_empty());
    assert_eq!(
        crate::permissions::revoke(engine.store(), "direct", &id, 1).unwrap(),
        crate::permissions::RevokeOutcome::NotFound
    );
}

#[test]
fn four_choices_on_first_read_call_without_any_local_grant() {
    for claim in [None, Some(json!({"kind":"agent","agent_id":"remote"}))] {
        for choice in ["allow_once", "allow_always", "deny_once", "deny_always"] {
            let (engine, db, requester, reader) = setup();
            assert_eq!(count(&db, "grants"), 0);
            let request = req(claim.clone());
            pending(&engine, request.clone());
            assert_eq!(
                reader.calls.load(Ordering::SeqCst),
                0,
                "filing never describes"
            );
            let cards = requester.cards.lock().unwrap();
            assert_eq!(cards.len(), 1);
            assert_eq!(
                cards[0]["options"],
                json!([
                {"id":"allow_once","label":"Allow this time","effect":"grant"},
                {"id":"allow_always","label":"Always allow","effect":"grant"},
                {"id":"deny_once","label":"Don't allow","effect":"decline"},
                {"id":"deny_always","label":"Don't allow, and don't ask again","effect":"decline"}])
            );
            drop(cards);
            requester.answer(0, "answered", Some(choice));
            if choice.starts_with("allow") {
                sent(&engine, request.clone());
            } else {
                assert_eq!(
                    run(&engine, request.clone()).unwrap_err().reason_code(),
                    "consent_denied"
                );
            }
            assert_eq!(
                count(&db, "federated_rows"),
                i64::from(choice.ends_with("always"))
            );
            if choice.ends_with("once") {
                pending(&engine, request);
                assert_eq!(requester.cards.lock().unwrap().len(), 2);
            }
            assert_eq!(count(&db, "action_requests"), 0);
            assert!(requester
                .scopes
                .lock()
                .unwrap()
                .iter()
                .all(|scope| scope.owner == "reserved:callosum"
                    && scope.scope_ref == "fed-claim:route-one"));
        }
    }
}

#[test]
fn cannot_wait_and_unavailable_requester_admit_nothing() {
    for claim in [
        None,
        Some(json!({"kind":"run","agent_id":"a"})),
        Some(
            json!({"kind":"flow","flow_id":"f","flow_version":1,"flow_code_hash":"h","flow_install_id":"i"}),
        ),
    ] {
        let (engine, db, requester, _) = setup();
        let mut request = req(claim.clone());
        if claim.is_none() {
            request = request.with_federated_held_reply(false);
        }
        assert_eq!(
            run(&engine, request).unwrap_err().reason_code(),
            "consent_unavailable"
        );
        assert!(requester.cards.lock().unwrap().is_empty());
        assert_eq!(count(&db, "federated_card_records"), 0);
    }
    for op in ["consent.request", "consent.get", "consent.detach"] {
        let (engine, db, requester, _) = setup();
        *requester.fail.lock().unwrap() = Some(op.into());
        assert_eq!(
            run(&engine, req(None)).unwrap_err().reason_code(),
            "consent_unavailable"
        );
        assert_eq!(count(&db, "reservations"), 0);
        assert!(engine.transport().requests().is_empty());
    }
}

#[test]
fn per_call_outcomes_are_terminal_and_replay_asks_again() {
    for (state, choice, expected, terminal) in [
        ("answered", Some("deny_once"), "consent_denied", "declined"),
        ("expired", None, "consent_expired", "expired"),
        ("withdrawn", None, "consent_withdrawn", "withdrawn"),
    ] {
        let (engine, db, requester, _) = setup();
        pending(&engine, req(None));
        let id: String = db
            .query_row("SELECT id FROM federated_card_records", [], |row| {
                row.get(0)
            })
            .unwrap();
        requester.answer(0, state, choice);
        assert_eq!(run(&engine, req(None)).unwrap_err().reason_code(), expected);
        let stored: String = db
            .query_row(
                "SELECT state FROM federated_card_records WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, terminal);
        pending(&engine, req(None));
        assert_ne!(requester.cards.lock().unwrap()[1]["requester_ref"], id);
    }
}

#[test]
fn same_binding_collects_on_later_route_and_audit_has_card_ref() {
    let (engine, db, requester, _) = setup();
    let request = req(Some(json!({"kind":"agent","agent_id":"a"})));
    pending(&engine, request.clone());
    requester.answer(0, "answered", Some("allow_once"));
    let mut later = request;
    later.scope.as_mut().unwrap().scope_ref = "later".into();
    later.scope.as_mut().unwrap().scope_epoch = 999;
    sent(&engine, later.clone());
    let audits: i64 = db.query_row("SELECT count(*) FROM audit_journal WHERE card_ref='el_0' AND agent_id IS NULL AND claim_kind='agent'", [], |r| r.get(0)).unwrap();
    assert_eq!(audits, 2);
    let pins: (Option<String>, Option<String>, Option<String>, String) = db
        .query_row(
            "SELECT grant_id,agent_grant_id,federated_row_id,card_ref FROM reservations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(pins, (None, None, None, "el_0".into()));
    pending(&engine, later);
}

#[test]
fn another_peer_pairing_claim_arguments_or_action_never_collects_first_answer() {
    for difference in ["peer", "pairing", "claim", "args", "action"] {
        let (engine, db, requester, _) = setup();
        let request = req(Some(json!({"kind":"agent","agent_id":"a"})));
        pending(&engine, request.clone());
        requester.answer(0, "answered", Some("allow_once"));
        let mut other = request.clone();
        match difference {
            "peer" => {
                other
                    .federated_caller
                    .as_mut()
                    .unwrap()
                    .attributes
                    .peer_fingerprint = "b".repeat(32)
            }
            "pairing" => {
                other
                    .federated_caller
                    .as_mut()
                    .unwrap()
                    .attributes
                    .pairing_id = "other".into()
            }
            "claim" => {
                other = req(Some(json!({"kind":"agent","agent_id":"b"})));
            }
            "args" => other.args = json!({"repo":"other"}),
            _ => {
                engine
                    .store()
                    .upsert_catalog_action(&CatalogActionInput {
                        principal: "direct".into(),
                        connection_id: "connection".into(),
                        name: "other_action".into(),
                        title: None,
                        schema: json!({"type":"object","properties":{"repo":{"type":"string"}}}),
                        schema_hash: "schema".into(),
                        risk: "read".into(),
                        severity: "S1".into(),
                        ask_first: false,
                        status: "active".into(),
                        quarantine_reason: None,
                        reconciliation: None,
                    })
                    .unwrap();
                db.execute(
                    "UPDATE connections SET ceiling_selectors='[\"write_item\",\"other_action\"]'",
                    [],
                )
                .unwrap();
                other.action = "other_action".into();
            }
        }
        pending(&engine, other);
        assert_eq!(requester.cards.lock().unwrap().len(), 2, "{difference}");
        sent(&engine, request);
        assert_eq!(engine.transport().requests().len(), 1);
    }
}

#[test]
fn worker_and_constructed_run_answers_are_single_use_and_never_mint() {
    for claim in [
        json!({"kind":"worker","owner_module_id":"aft","worker_ref":"w"}),
        json!({"kind":"run","agent_id":"r"}),
    ] {
        let (engine, db, requester, _) = setup();
        let mut request = req(Some(claim));
        if request.federated_caller.as_ref().unwrap().claim.claim_kind == "run" {
            use crate::federated::card::{Context, PreparedCard};
            let connection = engine
                .store()
                .connection("direct", "connection")
                .unwrap()
                .unwrap();
            let action = engine
                .store()
                .catalog_action("direct", "connection", "write_item")
                .unwrap()
                .unwrap();
            let prepared = PreparedCard::invoke(
                engine.store(),
                &Context {
                    caller: request.federated_caller.as_ref().unwrap(),
                    filed_scope: request.scope.as_ref().unwrap(),
                    expires_in_ms: 60_000,
                    per_call_only: false,
                },
                &connection,
                &action,
                &request.args,
                false,
            )
            .unwrap();
            let mut record = engine
                .store()
                .ensure_federated_card(&prepared.record)
                .unwrap();
            engine
                .store()
                .attach_federated_card(&record.id, "el_constructed_run")
                .unwrap();
            record.card_ref = Some("el_constructed_run".into());
            request.federated_answer = Some((
                record,
                crate::storage::federated_store::commit::Answer::AllowOnce,
            ));
            let reservation = engine.authorize(request.clone()).unwrap();
            assert_eq!(
                engine.revalidate_and_dispatch(&reservation).transmission,
                TransmissionState::Sent
            );
            assert!(engine.authorize(request).is_err());
        } else {
            pending(&engine, request.clone());
            assert_eq!(
                requester.cards.lock().unwrap()[0]["options"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
            requester.answer(0, "answered", Some("allow_once"));
            sent(&engine, request.clone());
            pending(&engine, request);
        }
        assert_eq!(count(&db, "federated_rows"), 0);
        assert_eq!(engine.transport().requests().len(), 1);
    }
}

#[test]
fn per_call_answer_is_not_consumed_on_non_live_base() {
    for status in [ScopeStatus::Ended, ScopeStatus::NotLive] {
        let (engine, db, requester, reader) = setup();
        pending(&engine, req(None));
        requester.answer(0, "answered", Some("allow_once"));
        *reader.status.lock().unwrap() = status;
        assert_eq!(
            run(&engine, req(None)).unwrap_err().reason_code(),
            "federated_pairing_ended"
        );
        let state: String = db
            .query_row("SELECT state FROM federated_card_records", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "pending");
        assert_eq!(count(&db, "reservations"), 0);
        *reader.status.lock().unwrap() = ScopeStatus::Live;
        sent(&engine, req(None));
        assert_eq!(
            reader.calls.load(Ordering::SeqCst),
            2,
            "each use makes its own describe"
        );
    }
}

#[test]
fn indeterminate_or_missing_base_reader_keeps_per_call_answer() {
    struct Indeterminate(Option<(bool, bool)>);
    impl ScopeReader for Indeterminate {
        fn describe(&self, _: &str, _: &str) -> Result<ScopeDescription, ScopeReadError> {
            let Some((owner_synced, owner_configured)) = self.0 else {
                return Err(ScopeReadError("unavailable".into()));
            };
            Ok(ScopeDescription {
                status: ScopeStatus::NotLive,
                owner_synced,
                owner_configured,
                live: None,
                parent: None,
                expires_at_ms: None,
            })
        }
    }
    for answer in [
        None,
        Some((false, false)),
        Some((false, true)),
        Some((true, false)),
    ] {
        let (engine, db, requester, _) = setup();
        pending(&engine, req(None));
        requester.answer(0, "answered", Some("allow_once"));
        let unavailable = engine
            .clone()
            .with_scope_reader(Arc::new(Indeterminate(answer)));
        assert_eq!(
            run(&unavailable, req(None)).unwrap_err().reason_code(),
            "federated_liveness_unavailable"
        );
        assert_eq!(count(&db, "reservations"), 0);
        sent(&engine, req(None));
    }
    let (mut engine, db, requester, reader) = setup();
    pending(&engine, req(None));
    requester.answer(0, "answered", Some("allow_once"));
    engine.scope_reader = None;
    assert_eq!(
        run(&engine, req(None)).unwrap_err().reason_code(),
        "federated_liveness_unavailable"
    );
    assert_eq!(count(&db, "reservations"), 0);
    engine.scope_reader = Some(reader);
    sent(&engine, req(None));
}

#[test]
fn rows_decide_before_reading_existing_pending_card() {
    for effect in ["allow", "deny"] {
        let (engine, db, requester, _) = setup();
        pending(&engine, req(None));
        requester.answer(0, "answered", Some("deny_once"));
        seed(&db, None, "read", effect);
        let reads = requester.reads.load(Ordering::SeqCst);
        if effect == "allow" {
            sent(&engine, req(None));
        } else {
            assert_eq!(
                run(&engine, req(None)).unwrap_err().reason_code(),
                "consent_denied"
            );
        }
        assert_eq!(requester.reads.load(Ordering::SeqCst), reads);
        let state: String = db
            .query_row("SELECT state FROM federated_card_records", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "pending");
    }
}

#[test]
fn changed_risk_or_schema_asks_fresh_and_mints_nothing() {
    for change in ["UPDATE catalog_actions SET risk='write'; UPDATE connections SET resource_filters='{\"write_enabling\":[\"repo\"]}'", "UPDATE catalog_actions SET schema_hash='repinned'"] {
        for choice in ["allow_once", "allow_always"] {
            let (engine, db, requester, _) = setup();
            pending(&engine, req(None));
            requester.answer(0, "answered", Some(choice));
            db.execute_batch(change).unwrap();
            pending(&engine, req(None));
            assert_eq!(requester.cards.lock().unwrap().len(), 2);
            assert_eq!(count(&db, "federated_rows"), 0);
            assert!(engine.transport().requests().is_empty());
        }
    }
}

#[test]
fn concurrent_distinct_calls_get_two_cards() {
    let (engine, db, requester, _) = setup();
    std::thread::scope(|scope| {
        let a = scope.spawn(|| pending(&engine, req(None)));
        let b = scope.spawn(|| {
            let mut request = req(None);
            request.args = json!({"repo":"other"});
            pending(&engine, request);
        });
        a.join().unwrap();
        b.join().unwrap();
    });
    assert_eq!(requester.cards.lock().unwrap().len(), 2);
    assert_eq!(count(&db, "federated_card_records"), 2);
}

#[test]
fn concurrent_collection_reserves_a_per_call_allow_only_once() {
    let (engine, db, requester, _) = setup();
    pending(&engine, req(None));
    requester.answer(0, "answered", Some("allow_once"));
    let successes = std::thread::scope(|scope| {
        let a = scope.spawn(|| run(&engine, req(None)));
        let b = scope.spawn(|| run(&engine, req(None)));
        usize::from(a.join().unwrap().is_ok()) + usize::from(b.join().unwrap().is_ok())
    });
    assert_eq!(successes, 1);
    assert_eq!(count(&db, "reservations"), 1);
    assert_eq!(engine.transport().requests().len(), 1);
}

#[test]
fn standing_denial_added_during_per_call_describe_wins_transaction() {
    let (engine, db, requester, _) = setup();
    pending(&engine, req(None));
    requester.answer(0, "answered", Some("allow_once"));
    struct InsertDeny(Mutex<rusqlite::Connection>);
    impl ScopeReader for InsertDeny {
        fn describe(&self, _: &str, _: &str) -> Result<ScopeDescription, ScopeReadError> {
            seed(&self.0.lock().unwrap(), None, "read", "deny");
            Ok(ScopeDescription {
                status: ScopeStatus::Live,
                owner_synced: true,
                owner_configured: true,
                live: None,
                parent: None,
                expires_at_ms: None,
            })
        }
    }
    let engine = engine.with_scope_reader(Arc::new(InsertDeny(Mutex::new(
        rusqlite::Connection::open(db.path().unwrap()).unwrap(),
    ))));
    assert_eq!(
        run(&engine, req(None)).unwrap_err().reason_code(),
        "consent_denied"
    );
    assert_eq!(count(&db, "reservations"), 0);
    assert!(engine.transport().requests().is_empty());
}

#[test]
fn ask_first_under_standing_allow_uses_two_choices_and_both_audit_pins() {
    let (engine, db, requester, _) = setup();
    let row_id = seed(&db, None, "read", "allow");
    engine
        .store()
        .set_policy("direct", "connection", "*", "ask_first", None)
        .unwrap();
    pending(&engine, req(None));
    assert_eq!(
        requester.cards.lock().unwrap()[0]["options"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    requester.answer(0, "answered", Some("allow_once"));
    sent(&engine, req(None));
    let audits: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_journal WHERE card_ref='el_0' AND federated_row_id=?1",
            [row_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(audits, 2);
    assert_eq!(count(&db, "federated_rows"), 1);
    assert_eq!(count(&db, "action_requests"), 0);
    pending(&engine, req(None));
    assert_eq!(requester.cards.lock().unwrap().len(), 2);
}

#[test]
fn a_call_already_held_keeps_its_card_after_another_call_mints_the_row() {
    let (engine, db, requester, _) = setup();
    let first = req(None);
    let mut second = req(None);
    second.args = json!({"repo":"second"});
    pending(&engine, first.clone());
    pending(&engine, second.clone());
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
    let held = engine.clone().with_consent_wait_hook(Arc::new(Gate {
        started: started_tx,
        release: Mutex::new(release_rx),
    }));
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| run(&held, second));
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        requester.answer(0, "answered", Some("allow_always"));
        sent(&engine, first);
        assert_eq!(count(&db, "federated_rows"), 1);
        requester.answer(1, "answered", Some("allow_always"));
        release_tx.send(()).unwrap();
        assert_eq!(
            waiter.join().unwrap().unwrap().transmission,
            TransmissionState::Sent
        );
    });
    let refs: String = db
        .query_row("SELECT card_refs_json FROM federated_rows", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&refs).unwrap(),
        json!(["el_0", "el_1"])
    );
    let reads = requester.reads.load(Ordering::SeqCst);
    sent(&engine, req(None));
    assert_eq!(requester.reads.load(Ordering::SeqCst), reads);
    assert_eq!(count(&db, "federated_rows"), 1);
}

#[test]
fn failed_reservation_rolls_back_per_call_consumption() {
    let (engine, db, requester, _) = setup();
    pending(&engine, req(None));
    requester.answer(0, "answered", Some("allow_once"));
    db.execute_batch("CREATE TRIGGER reservation_failure BEFORE INSERT ON reservations BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
    assert_eq!(
        run(&engine, req(None)).unwrap_err().reason_code(),
        "store_failure"
    );
    let state: String = db
        .query_row("SELECT state FROM federated_card_records", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(state, "pending");
    db.execute_batch("DROP TRIGGER reservation_failure")
        .unwrap();
    sent(&engine, req(None));
}

#[test]
fn malformed_readback_and_unoffered_standing_choices_refuse() {
    for field in ["requester_ref", "args_digest", "kind", "elicitation_id"] {
        let (engine, db, requester, _) = setup();
        pending(&engine, req(None));
        requester.answer(0, "answered", Some("allow_once"));
        requester.cards.lock().unwrap()[0][field] = json!("wrong");
        assert_eq!(
            run(&engine, req(None)).unwrap_err().reason_code(),
            "consent_unavailable"
        );
        assert_eq!(count(&db, "reservations"), 0);
    }
    let (engine, db, requester, _) = setup();
    let id = seed(&db, None, "read", "allow");
    engine
        .store()
        .set_policy("direct", "connection", "*", "ask_first", None)
        .unwrap();
    pending(&engine, req(None));
    assert_eq!(
        requester.cards.lock().unwrap()[0]["options"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // Remove just the row to simulate an old pending card surviving a store
    // restore; normal revoke also retires pending records under the row key.
    db.execute("DELETE FROM federated_rows WHERE id=?1", [&id])
        .unwrap();
    let path = db.path().unwrap().to_owned();
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: new_request_id(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite { path },
        })
        .unwrap(),
    );
    let engine = GovernanceEngine::new(
        store,
        engine.credential_source().clone(),
        engine.transport().clone(),
    )
    .with_consent_cards(Arc::new(ConsentCards::new(requester.clone())))
    .with_scope_reader(Arc::new(Reader {
        status: Mutex::new(ScopeStatus::Live),
        calls: AtomicUsize::new(0),
    }));
    requester.answer(0, "answered", Some("allow_always"));
    assert_eq!(
        run(&engine, req(None)).unwrap_err().reason_code(),
        "consent_unavailable"
    );
    assert_eq!(count(&db, "federated_rows"), 0);
}

#[test]
fn revoked_two_choice_card_cannot_mint_after_store_reopens() {
    let (engine, db, requester, reader) = setup();
    let id = seed(&db, None, "read", "allow");
    engine
        .store()
        .set_policy("direct", "connection", "*", "ask_first", None)
        .unwrap();
    pending(&engine, req(None));
    requester.answer(0, "answered", Some("allow_always"));
    assert!(engine.store().delete_federated_row(&id).unwrap());
    let path = db.path().unwrap().to_owned();
    let credentials = engine.credential_source().clone();
    let transport = engine.transport().clone();
    drop(engine);
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: new_request_id(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite { path },
        })
        .unwrap(),
    );
    let engine = GovernanceEngine::new(store, credentials, transport)
        .with_consent_cards(Arc::new(ConsentCards::new(requester.clone())))
        .with_scope_reader(reader);
    let (state, offered): (String, bool) = db
        .query_row(
            "SELECT state,standing_choices_offered FROM federated_card_records",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "retired");
    assert!(!offered);
    pending(&engine, req(None));
    assert_eq!(requester.cards.lock().unwrap().len(), 2);
    assert_eq!(count(&db, "federated_rows"), 0);
    assert_eq!(count(&db, "reservations"), 0);
}
