//! Withdrawing a held call by its `call_key` at the engine and store level:
//! the race between a withdrawal and the claim that consumes an approval,
//! carriers that reuse each other's keys, and a withdrawal surviving a
//! restart. The daemon is replaced by a scripted `ScopeReader`; the answers a
//! caller sees on the tool route are covered in plexus-module.

use std::sync::{Arc, Barrier, Mutex};

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::scope::{CallScope, ScopeDescription, ScopeReadError, ScopeReader, ScopeStatus};
use plexus_core::test_scratch::Scratch;
use plexus_core::withdraw::{withdraw_call, WithdrawAnswer, WithdrawCall};
use plexus_core::{
    jcs_sha256, AuthorizationRequest, CatalogActionInput, Denial, GovernanceEngine, GrantInput,
    MockTransport, PlexusStore, StubCredentialSource,
};
use serde_json::json;

const ACTION: &str = "held_write";
const AFT: &str = "reserved:aft";
const BROCA: &str = "reserved:broca";
const OWNER: &str = "reserved:prefrontal-core";
const HANDLE: &[u8] = b"test:call-withdrawal-handle";

/// Answers `scope.describe` from a script the test changes.
#[derive(Default)]
struct ScriptedReader {
    answer: Mutex<Option<ScopeDescription>>,
}

impl ScriptedReader {
    fn answer(&self, answer: ScopeDescription) {
        *self.answer.lock().unwrap() = Some(answer);
    }
}

impl ScopeReader for ScriptedReader {
    fn describe(&self, _: &str, _: &str) -> Result<ScopeDescription, ScopeReadError> {
        self.answer
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| ScopeReadError("no answer scripted".into()))
    }
}

/// A non-delegating head scope, so calls are judged on the module grant.
fn scope() -> CallScope {
    CallScope {
        owner: OWNER.into(),
        scope_ref: "head-1".into(),
        scope_epoch: 3,
        kind: Some("head".into()),
        parent: None,
        parent_state: None,
        agent_id: None,
        delegates: false,
        owner_authorized: true,
        flow_id: None,
    }
}

fn live() -> ScopeDescription {
    ScopeDescription {
        status: ScopeStatus::Live,
        owner_synced: true,
        owner_configured: true,
        live: Some(scope()),
    }
}

/// The owner has not re-synced since the daemon started: approvals are held.
fn not_resynced() -> ScopeDescription {
    ScopeDescription {
        status: ScopeStatus::NotLive,
        owner_synced: false,
        owner_configured: true,
        live: None,
    }
}

fn open_store(path: &Scratch, label: &str) -> PlexusStore {
    PlexusStore::open(&StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!("call-withdrawal-{label}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    })
    .expect("open store")
}

type Engine = GovernanceEngine<StubCredentialSource, MockTransport>;

fn engine(store: PlexusStore, reader: &Arc<ScriptedReader>) -> Engine {
    let credentials = StubCredentialSource::default();
    credentials.set_success(HANDLE, b"vendor-token".to_vec(), None, 1);
    GovernanceEngine::new(
        Arc::new(store),
        Arc::new(credentials),
        Arc::new(MockTransport::default()),
    )
    .with_scope_reader(Arc::clone(reader) as Arc<dyn ScopeReader>)
}

struct Fixture {
    engine: Engine,
    reader: Arc<ScriptedReader>,
    label: String,
    path: Scratch,
}

/// A `direct`-owned connection with one ask-first write, module grants for
/// the carriers `reserved:aft` and `reserved:broca`, and connection-admin
/// authority for `direct` to decide requests.
fn fixture(label: &str) -> Fixture {
    let path = Scratch::database(&format!("call-withdrawal-{label}"));
    let store = open_store(&path, label);
    store
        .insert_connection(
            "direct",
            "conn-1",
            "mock",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("insert connection");
    let ticket = store
        .create_binding_ticket("direct", "conn-1", HANDLE)
        .expect("ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("connect")
        .expect("activate");
    let schema = json!({"type": "object"});
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "conn-1".into(),
            principal: "direct".into(),
            name: ACTION.into(),
            title: None,
            schema: schema.clone(),
            schema_hash: jcs_sha256(&schema).expect("hash"),
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: true,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("action");
    for (grant_id, grantee, kind, selector) in [
        ("aft", AFT, "invoke", ACTION),
        ("broca", BROCA, "invoke", ACTION),
        ("admin", "direct", "connection_admin", "*"),
    ] {
        store
            .insert_grant(&GrantInput {
                grant_id: grant_id.into(),
                principal: "direct".into(),
                connection_id: "conn-1".into(),
                grantee_principal: grantee.into(),
                risk_ceiling: "destructive".into(),
                action_selectors: vec![selector.to_string()],
                authority_kind: kind.into(),
                expires_at: None,
            })
            .expect("grant");
    }
    let reader = Arc::new(ScriptedReader::default());
    Fixture {
        engine: engine(store, &reader),
        reader,
        label: label.to_string(),
        path,
    }
}

impl Fixture {
    /// Make the ask-first call as `carrier` under the test scope, keyed
    /// `call_key` when one is given, and return the request it parked.
    fn park(&self, carrier: &str, call_key: Option<&str>, n: u64) -> String {
        let mut request = AuthorizationRequest::new(carrier, "conn-1", ACTION, json!({"n": n}))
            .with_scope(scope());
        if let Some(call_key) = call_key {
            request = request.with_call_key(call_key);
        }
        match self.engine.authorize(request) {
            Err(Denial::ActionRequestCreated { request_id }) => request_id,
            other => panic!("an ask-first call must park a request: {other:?}"),
        }
    }

    fn withdraw(&self, caller: &str, call_key: &str, carrier: Option<&str>) -> WithdrawAnswer {
        let scope = scope();
        withdraw_call(
            self.engine.store(),
            &WithdrawCall {
                caller,
                call_key,
                carrier,
                scope: Some(&scope),
            },
        )
        .expect("the caller may withdraw this call")
    }

    fn status(&self, request_id: &str) -> String {
        self.engine
            .store()
            .list_action_requests("direct")
            .expect("list requests")
            .into_iter()
            .find(|request| request.request_id == request_id)
            .expect("request exists")
            .status
    }

    fn sent(&self) -> usize {
        self.engine.transport().requests().len()
    }

    /// Approve the request while its scope cannot be confirmed, so the
    /// approval is held `approved` and unsent, waiting for the scheduler's
    /// retry to claim it.
    fn approve_and_hold(&self, request_id: &str) {
        self.reader.answer(not_resynced());
        self.engine
            .approve_request("direct", request_id, "direct")
            .expect("the approval is decided");
        assert_eq!(self.status(request_id), "approved");
    }
}

/// Withdrawing before the scheduler claims an approval cancels it permanently.
#[test]
fn a_withdrawal_before_the_claim_prevents_a_send() {
    let fixture = fixture("withdraw-first");
    let request_id = fixture.park(AFT, Some("withdraw-first"), 0);
    fixture.approve_and_hold(&request_id);

    assert_eq!(
        fixture.withdraw(AFT, "withdraw-first", None),
        WithdrawAnswer::Withdrawn
    );
    fixture.reader.answer(live());
    let retried = fixture.engine.retry_waiting_approvals(16);
    assert_eq!(fixture.sent(), 0, "withdrawn approval must never be sent");
    assert_eq!(retried, 0);
    assert_eq!(fixture.status(&request_id), "cancelled");
}

/// Once the scheduler has claimed and sent, withdrawal reports it started.
#[test]
fn a_claim_before_the_withdrawal_sends_exactly_once() {
    let fixture = fixture("claim-first");
    let request_id = fixture.park(AFT, Some("claim-first"), 0);
    fixture.approve_and_hold(&request_id);
    fixture.reader.answer(live());

    assert_eq!(fixture.engine.retry_waiting_approvals(16), 1);
    assert_eq!(
        fixture.withdraw(AFT, "claim-first", None),
        WithdrawAnswer::AlreadyStarted {
            outcome: "completed".into()
        }
    );
    assert_eq!(fixture.status(&request_id), "consumed");
    assert_eq!(fixture.sent(), 1);
    assert_eq!(fixture.engine.retry_waiting_approvals(16), 0);
    assert_eq!(fixture.sent(), 1, "a claimed approval cannot be sent twice");
}

/// Release withdrawal and claim together and check their mutual-exclusion fence.
/// Either order is valid in each round; the sequential tests cover both orders
/// without depending on which thread the scheduler runs first.
#[test]
fn a_withdrawal_and_the_claim_never_both_win() {
    let fixture = Arc::new(fixture("race"));

    const ROUNDS: u32 = 40;
    for round in 1..=ROUNDS {
        let call_key = format!("race-{round}");
        let request_id = fixture.park(AFT, Some(&call_key), u64::from(round));
        fixture.approve_and_hold(&request_id);
        fixture.reader.answer(live());
        let barrier = Arc::new(Barrier::new(3));
        let sent_before = fixture.sent();
        let scheduler_fixture = Arc::clone(&fixture);
        let scheduler_barrier = Arc::clone(&barrier);
        let scheduler = crate::bounded::Task::spawn(move || {
            scheduler_barrier.wait();
            scheduler_fixture.engine.retry_waiting_approvals(16)
        });
        let withdrawal_fixture = Arc::clone(&fixture);
        let withdrawal_barrier = Arc::clone(&barrier);
        let withdrawal_call_key = call_key.clone();
        let withdrawal = crate::bounded::Task::spawn(move || {
            withdrawal_barrier.wait();
            withdrawal_fixture.withdraw(AFT, &withdrawal_call_key, None)
        });
        barrier.wait();
        scheduler.join().expect("scheduler worker completion");
        let answer = withdrawal.join().expect("withdrawal worker completion");

        let sent = fixture.sent() - sent_before;
        assert!(sent <= 1, "round {round}: sent {sent} times");
        match answer {
            WithdrawAnswer::Withdrawn => {
                assert_eq!(sent, 0, "round {round}: withdrawn but also sent");
                assert_eq!(fixture.status(&request_id), "cancelled");
            }
            WithdrawAnswer::AlreadyStarted { .. } => {
                assert_eq!(sent, 1, "round {round}: reported started but never sent");
                assert_eq!(fixture.status(&request_id), "consumed");
            }
            other => panic!("round {round}: unexpected answer {other:?}"),
        }
    }
    // Nothing withdrawn is left for a later retry to send.
    let sent = fixture.sent();
    assert_eq!(fixture.engine.retry_waiting_approvals(16), 0);
    assert_eq!(fixture.sent(), sent);
}

/// A withdrawal after the claim reports how the send settled, and every
/// repeat gives the same answer, even after audit retention has deleted the
/// dispatch row the outcome was first recorded on.
#[test]
fn an_already_started_answer_outlives_its_audit_row() {
    let fixture = fixture("settled-outcome");
    let request_id = fixture.park(AFT, Some("settled"), 1);
    fixture.approve_and_hold(&request_id);
    fixture.reader.answer(live());
    assert_eq!(fixture.engine.retry_waiting_approvals(16), 1);
    assert_eq!(fixture.sent(), 1);
    let first = fixture.withdraw(AFT, "settled", None);
    assert_eq!(
        first,
        WithdrawAnswer::AlreadyStarted {
            outcome: "completed".into()
        }
    );

    // Stand in for audit retention, which would delete these rows after 30
    // days. The `audit_journal_append_only_delete` trigger refuses to delete
    // any audit row younger than 7 days by the real clock, so drop it and
    // delete the dispatch rows directly.
    let db = rusqlite::Connection::open(fixture.path.path()).expect("open store file");
    db.execute_batch(
        "DROP TRIGGER audit_journal_append_only_delete;
         DELETE FROM audit_journal WHERE gate = 'dispatch';",
    )
    .expect("delete the dispatch audit rows");
    let left: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM audit_journal WHERE gate = 'dispatch'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(left, 0, "the audit rows are gone");

    assert_eq!(fixture.withdraw(AFT, "settled", None), first);
}

/// Keys are unique per carrier, not globally: two carriers using the same
/// key for different calls each get their own request, and withdrawing one
/// leaves the other held.
#[test]
fn two_carriers_may_use_the_same_key_for_different_calls() {
    let fixture = fixture("two-carriers");
    let aft_request = fixture.park(AFT, Some("call-0"), 1);
    let broca_request = fixture.park(BROCA, Some("call-0"), 2);
    assert_ne!(aft_request, broca_request);

    assert_eq!(
        fixture.withdraw(AFT, "call-0", None),
        WithdrawAnswer::Withdrawn
    );
    assert_eq!(fixture.status(&aft_request), "cancelled");
    assert_eq!(
        fixture.status(&broca_request),
        "pending",
        "another carrier's call under the same key is untouched"
    );

    // Broca's call is still sent when approved.
    fixture.reader.answer(live());
    fixture
        .engine
        .approve_request("direct", &broca_request, "direct")
        .expect("broca's request is approved");
    assert_eq!(fixture.sent(), 1);
    assert_eq!(
        fixture.withdraw(OWNER, "call-0", Some(BROCA)),
        WithdrawAnswer::AlreadyStarted {
            outcome: "completed".into()
        }
    );
}

/// The same call arriving again while held reuses its request. A key already
/// used for a different call, or for a call that was withdrawn, raises no new
/// request: a withdrawn call must not come back under its own key.
#[test]
fn a_key_names_one_call() {
    let fixture = fixture("one-call");
    let request_id = fixture.park(AFT, Some("k"), 1);
    assert_eq!(fixture.park(AFT, Some("k"), 1), request_id);

    let reused = fixture.engine.authorize(
        AuthorizationRequest::new(AFT, "conn-1", ACTION, json!({"n": 2}))
            .with_scope(scope())
            .with_call_key("k"),
    );
    assert_eq!(
        reused
            .expect_err("a different call under a held key is refused")
            .reason_code(),
        "call_key_reused"
    );

    assert_eq!(fixture.withdraw(AFT, "k", None), WithdrawAnswer::Withdrawn);
    let again = fixture.engine.authorize(
        AuthorizationRequest::new(AFT, "conn-1", ACTION, json!({"n": 1}))
            .with_scope(scope())
            .with_call_key("k"),
    );
    assert_eq!(
        again
            .expect_err("a withdrawn call is not raised again")
            .reason_code(),
        "approval_withdrawn"
    );
    assert_eq!(
        fixture
            .engine
            .store()
            .list_action_requests("direct")
            .unwrap()
            .len(),
        1,
        "no second request was raised under the key"
    );
}

/// A withdrawal is durable: after a restart the approval still finds nothing
/// to send, and the withdrawal still answers `withdrawn`.
#[test]
fn a_withdrawal_survives_a_restart() {
    let fixture = fixture("restart");
    let request_id = fixture.park(AFT, Some("k"), 1);
    assert_eq!(fixture.withdraw(AFT, "k", None), WithdrawAnswer::Withdrawn);
    let Fixture {
        engine,
        label,
        path,
        ..
    } = fixture;
    drop(engine);

    let reader = Arc::new(ScriptedReader::default());
    reader.answer(live());
    let restarted = Fixture {
        engine: engine_after_restart(&path, &label, &reader),
        reader,
        label,
        path,
    };
    assert_eq!(
        restarted
            .engine
            .approve_request("direct", &request_id, "direct")
            .expect_err("a withdrawn request cannot be approved")
            .reason_code(),
        "approval_withdrawn"
    );
    assert_eq!(restarted.engine.retry_waiting_approvals(16), 0);
    assert_eq!(restarted.sent(), 0, "a withdrawn call is never sent");
    assert_eq!(
        restarted.withdraw(OWNER, "k", Some(AFT)),
        WithdrawAnswer::Withdrawn
    );
}

fn engine_after_restart(path: &Scratch, label: &str, reader: &Arc<ScriptedReader>) -> Engine {
    // Dropping the final engine synchronously drops its store and writer lease.
    // No background task owns this fixture's store, so reopening needs no sleep.
    engine(open_store(path, label), reader)
}
