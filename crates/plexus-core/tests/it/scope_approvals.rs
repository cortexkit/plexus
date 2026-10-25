//! A stored approval raised under a daemon scope is re-checked against that
//! scope at the point of execution, just before the claim that consumes it and
//! sends. The daemon is replaced by a scripted `ScopeReader`.

use std::sync::{Arc, Mutex};

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::scope::{CallScope, ScopeDescription, ScopeReadError, ScopeReader, ScopeStatus};
use plexus_core::test_scratch::Scratch;
use plexus_core::{
    jcs_sha256, AuthorizationRequest, CatalogActionInput, Denial, GovernanceEngine, GrantInput,
    MockTransport, PlexusStore, StubCredentialSource, TransportOutcome,
};
use serde_json::json;

const ACTION: &str = "scoped_write";
const AGENT: &str = "agent-a";

/// Answers `scope.describe` from a script the test changes, and counts reads.
#[derive(Default)]
struct ScriptedReader {
    answer: Mutex<Option<Result<ScopeDescription, ScopeReadError>>>,
    reads: Mutex<usize>,
}

impl ScriptedReader {
    fn answer(&self, answer: Result<ScopeDescription, ScopeReadError>) {
        *self.answer.lock().unwrap() = Some(answer);
    }

    fn reads(&self) -> usize {
        *self.reads.lock().unwrap()
    }
}

impl ScopeReader for ScriptedReader {
    fn describe(&self, owner: &str, scope_ref: &str) -> Result<ScopeDescription, ScopeReadError> {
        assert_eq!((owner, scope_ref), ("reserved:prefrontal-core", "head-1"));
        *self.reads.lock().unwrap() += 1;
        self.answer
            .lock()
            .unwrap()
            .clone()
            .expect("the test scripted an answer before the approval ran")
    }
}

fn scope(delegates: bool) -> CallScope {
    CallScope {
        owner: "reserved:prefrontal-core".into(),
        scope_ref: "head-1".into(),
        scope_epoch: 3,
        kind: Some("head".into()),
        parent: None,
        parent_state: None,
        agent_id: Some(AGENT.into()),
        delegates,
        owner_authorized: true,
        flow_id: None,
    }
}

fn live(scope: CallScope) -> ScopeDescription {
    ScopeDescription {
        parent: None,
        expires_at_ms: None,
        status: ScopeStatus::Live,
        owner_synced: true,
        owner_configured: true,
        live: Some(scope),
    }
}

fn ended() -> ScopeDescription {
    ScopeDescription {
        parent: None,
        expires_at_ms: None,
        status: ScopeStatus::Ended,
        owner_synced: true,
        owner_configured: true,
        live: None,
    }
}

/// The scope's owner has not registered its scopes again since the daemon
/// (re)started, so the daemon cannot yet say whether the scope is live.
fn not_resynced() -> ScopeDescription {
    ScopeDescription {
        parent: None,
        expires_at_ms: None,
        status: ScopeStatus::NotLive,
        owner_synced: false,
        owner_configured: true,
        live: None,
    }
}

struct Fixture {
    engine: GovernanceEngine<StubCredentialSource, MockTransport>,
    reader: Arc<ScriptedReader>,
    path: Scratch,
}

/// A `direct`-owned connection with one ask-first write, a module grant for
/// the calling module `reserved:aft`, an agent grant for `agent-a` (the agent
/// the test scopes name), and connection-admin authority for `direct` to
/// decide requests.
fn fixture(label: &str) -> Fixture {
    let path = Scratch::database(&format!("scope-approvals-{label}"));
    let store = PlexusStore::open(&StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!("scope-approvals-{label}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    })
    .expect("open store");
    store
        .insert_connection(
            "direct",
            "conn-1",
            "mock",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("insert connection");
    let handle = b"test:scope-approvals-handle";
    let ticket = store
        .create_binding_ticket("direct", "conn-1", handle)
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
    for (grant_id, grantee, kind, selectors) in [
        ("module", "reserved:aft", "invoke", vec![ACTION.to_string()]),
        ("agent", "reserved:aft", "invoke", vec![ACTION.to_string()]),
        ("admin", "direct", "connection_admin", vec!["*".to_string()]),
    ] {
        store
            .insert_grant(&GrantInput {
                grant_id: grant_id.into(),
                principal: "direct".into(),
                connection_id: "conn-1".into(),
                grantee_principal: grantee.into(),
                risk_ceiling: "destructive".into(),
                action_selectors: selectors,
                authority_kind: kind.into(),
                expires_at: None,
            })
            .expect("grant");
    }
    rusqlite::Connection::open(&path as &std::path::Path)
        .expect("open store file")
        .execute(
            "UPDATE grants SET agent_id = ?1 WHERE grant_id = 'agent'",
            [AGENT],
        )
        .expect("attribute the agent grant");
    let credentials = StubCredentialSource::default();
    credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
    let reader = Arc::new(ScriptedReader::default());
    let engine = GovernanceEngine::new(
        Arc::new(store),
        Arc::new(credentials),
        Arc::new(MockTransport::default()),
    )
    .with_scope_reader(Arc::clone(&reader) as Arc<dyn ScopeReader>);
    Fixture {
        engine,
        reader,
        path,
    }
}

impl Fixture {
    fn make_retries_due(&self) {
        rusqlite::Connection::open(&self.path as &std::path::Path)
            .unwrap()
            .execute(
                "UPDATE action_requests SET scope_checked_at_ms=0 WHERE status='approved'",
                [],
            )
            .unwrap();
    }
    /// Make the ask-first call on a route bound under `scope` (or none) and
    /// return the request it parked.
    fn park(&self, scope: Option<CallScope>) -> String {
        let mut request =
            AuthorizationRequest::new("reserved:aft", "conn-1", ACTION, json!({"n": 1}));
        if let Some(scope) = scope {
            request = request.with_attributed_agent(AGENT).with_scope(scope);
        }
        match self.engine.authorize(request) {
            Err(Denial::ActionRequestCreated { request_id }) => request_id,
            other => panic!("an ask-first call must park a request: {other:?}"),
        }
    }

    fn request(&self, request_id: &str) -> plexus_core::ActionRequestRecord {
        self.engine
            .store()
            .list_action_requests("direct")
            .expect("list requests")
            .into_iter()
            .find(|request| request.request_id == request_id)
            .expect("request exists")
    }

    fn sent(&self) -> usize {
        self.engine.transport().requests().len()
    }

    fn not_sent_code(outcome: &plexus_core::DispatchOutcome) -> &str {
        match &outcome.outcome {
            TransportOutcome::NotSent { code, .. } => code,
            other => panic!("expected nothing sent, got {other:?}"),
        }
    }
}

/// The request keeps the scope it was raised under, with the scope's agent.
#[test]
fn a_request_raised_under_a_scope_records_that_scope() {
    let fixture = fixture("recorded");
    let request_id = fixture.park(Some(scope(true)));
    let request = fixture.request(&request_id);
    let recorded = request.scope.expect("scope recorded on the request");
    assert_eq!(
        (
            recorded.owner.as_str(),
            recorded.scope_ref.as_str(),
            recorded.scope_epoch,
            recorded.agent_id.as_deref(),
            recorded.delegates,
            recorded.owner_authorized,
        ),
        (
            "reserved:prefrontal-core",
            "head-1",
            3,
            Some(AGENT),
            true,
            true
        )
    );
    // An identical call on an unscoped route parks its own request: one
    // session's approval never collects another's call.
    let unscoped = fixture.park(None);
    assert_ne!(unscoped, request_id);
    assert!(fixture.request(&unscoped).scope.is_none());
}

/// Approving a request whose scope ended refuses it `scope_ended` at the
/// claim: nothing reaches the vendor, and the approval is retired so no later
/// attempt can send it.
#[test]
fn an_approval_whose_scope_ended_refuses_scope_ended_and_sends_nothing() {
    let fixture = fixture("ended");
    let request_id = fixture.park(Some(scope(true)));
    fixture.reader.answer(Ok(ended()));
    let outcome = fixture
        .engine
        .approve_request("direct", &request_id, "direct")
        .expect("the approval is decided");
    assert_eq!(Fixture::not_sent_code(&outcome), "scope_ended");
    assert_eq!(fixture.sent(), 0, "an ended scope's approval is never sent");
    let request = fixture.request(&request_id);
    assert_eq!(request.status, "consumed");
    assert_eq!(
        request.scope_outcome.as_deref(),
        Some("not_run:scope_ended")
    );
    let audit = fixture.engine.store().list_audit("direct").expect("audit");
    assert!(
        audit
            .iter()
            .any(|row| row.reason_code == "scope_ended"
                && row.outcome.as_deref() == Some("not_sent")),
        "the refusal is audited by name: {audit:?}"
    );
}

/// The same scope at a new epoch is a new session under a reused ref: the old
/// session's approval is refused `scope_ended`.
#[test]
fn an_approval_from_an_earlier_epoch_refuses_scope_ended() {
    let fixture = fixture("epoch");
    let request_id = fixture.park(Some(scope(true)));
    let mut new_session = scope(true);
    new_session.scope_epoch = 4;
    fixture.reader.answer(Ok(live(new_session)));
    let outcome = fixture
        .engine
        .approve_request("direct", &request_id, "direct")
        .expect("decided");
    assert_eq!(Fixture::not_sent_code(&outcome), "scope_ended");
    assert_eq!(fixture.sent(), 0);
}

/// A request raised while the scope delegated is refused
/// `delegation_withdrawn` once the scope stops delegating.
#[test]
fn an_approval_whose_delegation_was_withdrawn_refuses_by_name() {
    let fixture = fixture("withdrawn");
    let request_id = fixture.park(Some(scope(true)));
    fixture.reader.answer(Ok(live(scope(false))));
    let outcome = fixture
        .engine
        .approve_request("direct", &request_id, "direct")
        .expect("decided");
    assert_eq!(Fixture::not_sent_code(&outcome), "delegation_withdrawn");
    assert_eq!(fixture.sent(), 0);
    assert_eq!(
        fixture.request(&request_id).scope_outcome.as_deref(),
        Some("not_run:delegation_withdrawn")
    );
}

/// When the scope's owner has not re-synced since a daemon restart, the
/// approval is kept, unsent and still approved, and marked waiting. The
/// scheduler's retry sends it exactly once after the scope reads live again.
#[test]
fn a_not_yet_resynced_scope_leaves_the_approval_pending_until_it_is_confirmed() {
    let fixture = fixture("resync");
    let request_id = fixture.park(Some(scope(true)));
    fixture.reader.answer(Ok(not_resynced()));
    let outcome = fixture
        .engine
        .approve_request("direct", &request_id, "direct")
        .expect("decided");
    assert_eq!(Fixture::not_sent_code(&outcome), "approved_waiting");
    assert_eq!(fixture.sent(), 0);
    let held = fixture.request(&request_id);
    assert_eq!(
        held.status, "approved",
        "a held approval is kept, not refused"
    );
    assert_eq!(held.scope_outcome.as_deref(), Some("approved_waiting"));

    // Still not re-synced: the retry holds again and sends nothing.
    assert_eq!(fixture.engine.retry_waiting_approvals(16), 1);
    assert_eq!(fixture.sent(), 0);
    assert_eq!(fixture.request(&request_id).status, "approved");

    // The owner re-synced the same session: the approval runs once.
    fixture.reader.answer(Ok(live(scope(true))));
    assert_eq!(
        fixture.engine.retry_waiting_approvals(16),
        0,
        "the retry interval still applies after a scope change"
    );
    fixture.make_retries_due();
    assert_eq!(fixture.engine.retry_waiting_approvals(16), 1);
    assert_eq!(fixture.sent(), 1);
    let sent = fixture.request(&request_id);
    assert_eq!(sent.status, "consumed");
    assert_eq!(sent.scope_outcome, None);
    assert_eq!(
        fixture.engine.retry_waiting_approvals(16),
        0,
        "nothing is left waiting, so nothing is sent twice"
    );
    assert_eq!(fixture.sent(), 1);
}

/// When the daemon cannot answer, nothing is sent: the approval is held.
#[test]
fn an_unanswered_scope_read_sends_nothing() {
    let fixture = fixture("unanswered");
    let request_id = fixture.park(Some(scope(true)));
    fixture
        .reader
        .answer(Err(ScopeReadError("daemon connection closed".into())));
    let outcome = fixture
        .engine
        .approve_request("direct", &request_id, "direct")
        .expect("decided");
    assert_eq!(Fixture::not_sent_code(&outcome), "approved_waiting");
    assert_eq!(fixture.sent(), 0);
    assert_eq!(fixture.request(&request_id).status, "approved");
}

/// A hold never outlives the approval: once the approval has expired, the
/// retry retires it `scope_unverifiable` without asking the daemon again.
#[test]
fn a_held_approval_past_its_expiry_refuses_scope_unverifiable() {
    let fixture = fixture("lapsed");
    let request_id = fixture.park(Some(scope(true)));
    fixture.reader.answer(Ok(not_resynced()));
    fixture
        .engine
        .approve_request("direct", &request_id, "direct")
        .expect("decided");
    let reads = fixture.reader.reads();
    rusqlite::Connection::open(&fixture.path as &std::path::Path)
        .expect("open store file")
        .execute(
            "UPDATE action_requests SET expires_at = 1 WHERE request_id = ?1",
            [&request_id],
        )
        .expect("lapse the approval");
    fixture.reader.answer(Ok(live(scope(true))));
    assert_eq!(fixture.engine.retry_waiting_approvals(16), 1);
    assert_eq!(fixture.sent(), 0, "a lapsed approval is never sent");
    assert_eq!(
        fixture.reader.reads(),
        reads,
        "no daemon read for a lapsed approval"
    );
    let request = fixture.request(&request_id);
    assert_eq!(request.status, "consumed");
    assert_eq!(
        request.scope_outcome.as_deref(),
        Some("not_run:scope_unverifiable")
    );
}

/// A live scope with the same session and authority lets the approval run,
/// and the call is still judged as the agent: without the agent's grant the
/// approved call is refused.
#[test]
fn a_confirmed_scope_runs_the_approval_under_the_agents_grant() {
    let first = fixture("confirmed");
    let request_id = first.park(Some(scope(true)));
    first.reader.answer(Ok(live(scope(true))));
    let outcome = first
        .engine
        .approve_request("direct", &request_id, "direct")
        .expect("decided");
    assert!(
        matches!(outcome.outcome, TransportOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(first.sent(), 1);

    let second = fixture("confirmed-no-agent-grant");
    let request_id = second.park(Some(scope(true)));
    rusqlite::Connection::open(&second.path as &std::path::Path)
        .expect("open store file")
        .execute("DELETE FROM grants WHERE grant_id = 'agent'", [])
        .expect("revoke the agent grant");
    second.reader.answer(Ok(live(scope(true))));
    let refused = second
        .engine
        .approve_request("direct", &request_id, "direct")
        .expect_err("the re-authorization needs the agent grant");
    assert_eq!(refused.reason_code(), "agent_grant_absent");
    assert_eq!(second.sent(), 0);
}

/// A request raised with no scope keeps today's behaviour: approving it runs
/// the call without ever asking the daemon.
#[test]
fn an_unscoped_approval_never_reads_a_scope() {
    let fixture = fixture("unscoped");
    let request_id = fixture.park(None);
    let outcome = fixture
        .engine
        .approve_request("direct", &request_id, "direct")
        .expect("decided");
    assert!(
        matches!(outcome.outcome, TransportOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(fixture.sent(), 1);
    assert_eq!(fixture.reader.reads(), 0);
}

/// A call whose scope is attribution only (a search or a GitHub read names
/// the agent on its audit rows but never needs the agent's own grant) keeps
/// that standing when its approval runs. Re-authorizing it as the agent would
/// refuse every such approval for want of an agent grant it never needed.
#[test]
fn an_attribution_only_approval_runs_without_the_agents_grant() {
    let fixture = fixture("attribution-only");
    rusqlite::Connection::open(&fixture.path as &std::path::Path)
        .expect("open store file")
        .execute("DELETE FROM grants WHERE grant_id = 'agent'", [])
        .expect("the agent holds no grant of its own");
    let request = AuthorizationRequest::new("reserved:aft", "conn-1", ACTION, json!({"n": 1}))
        .with_attributed_agent(AGENT)
        .with_scope_attribution_only(scope(true));
    let request_id = match fixture.engine.authorize(request) {
        Err(Denial::ActionRequestCreated { request_id }) => request_id,
        other => panic!("an ask-first call must park a request: {other:?}"),
    };
    let recorded = fixture.request(&request_id).scope.expect("scope recorded");
    assert_eq!(recorded.agent_id.as_deref(), Some(AGENT));
    assert!(
        !recorded.delegates,
        "the request records that the call did not act as the agent"
    );
    fixture.reader.answer(Ok(live(scope(true))));
    let outcome = fixture
        .engine
        .approve_request("direct", &request_id, "direct")
        .expect("the approved call is re-authorized without an agent grant");
    assert!(
        matches!(outcome.outcome, TransportOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(fixture.sent(), 1);
}

/// A held approval refused by a passing failure (here the vault is locked)
/// is still the user's valid approval: it stays waiting and is sent once the
/// failure clears, instead of being retired for good on the first refusal.
#[test]
fn a_passing_failure_keeps_a_held_approval_waiting_until_it_clears() {
    use plexus_core::{CredentialError, TransientCredentialError};
    let handle = b"test:scope-approvals-handle";
    let fixture = fixture("passing-failure");
    let request_id = fixture.park(Some(scope(true)));
    fixture.reader.answer(Ok(not_resynced()));
    fixture
        .engine
        .approve_request("direct", &request_id, "direct")
        .expect("decided");
    assert_eq!(
        fixture.request(&request_id).scope_outcome.as_deref(),
        Some("approved_waiting")
    );

    fixture.reader.answer(Ok(live(scope(true))));
    fixture.engine.credential_source().set_error(
        handle,
        CredentialError::Transient(TransientCredentialError::VaultLocked),
    );
    assert_eq!(fixture.engine.retry_waiting_approvals(16), 1);
    assert_eq!(fixture.sent(), 0);
    let held = fixture.request(&request_id);
    assert_eq!(
        (held.status.as_str(), held.scope_outcome.as_deref()),
        ("approved", Some("approved_waiting")),
        "a locked vault must not retire the approval"
    );

    fixture
        .engine
        .credential_source()
        .set_success(handle, b"vendor-token".to_vec(), None, 1);
    fixture.make_retries_due();
    assert_eq!(fixture.engine.retry_waiting_approvals(16), 1);
    assert_eq!(
        fixture.sent(),
        1,
        "the approval runs once the vault answers"
    );
    assert_eq!(fixture.request(&request_id).status, "consumed");

    // A refusal of the call's authority still retires a held approval.
    let second = fixture.park(Some(scope(true)));
    fixture.reader.answer(Ok(not_resynced()));
    fixture
        .engine
        .approve_request("direct", &second, "direct")
        .expect("decided");
    rusqlite::Connection::open(&fixture.path as &std::path::Path)
        .expect("open store file")
        .execute("DELETE FROM grants WHERE grant_id = 'agent'", [])
        .expect("revoke the agent grant");
    fixture.reader.answer(Ok(live(scope(true))));
    assert_eq!(fixture.engine.retry_waiting_approvals(16), 1);
    let retired = fixture.request(&second);
    assert_eq!(retired.status, "consumed");
    assert_eq!(
        retired.scope_outcome.as_deref(),
        Some("not_run:agent_grant_absent")
    );
    assert_eq!(fixture.sent(), 1);
}

/// A held approval whose re-authorization is refused for a passing reason
/// (here this instance does not hold the connector home) stays waiting rather
/// than being retired, and runs once an instance that does hold it retries.
#[test]
fn a_passing_refusal_at_reauthorization_keeps_a_held_approval_waiting() {
    let fixture = fixture("passing-refusal");
    let request_id = fixture.park(Some(scope(true)));
    fixture.reader.answer(Ok(not_resynced()));
    fixture
        .engine
        .approve_request("direct", &request_id, "direct")
        .expect("decided");
    fixture.reader.answer(Ok(live(scope(true))));
    let elsewhere = fixture
        .engine
        .clone()
        .with_connector_home_guard(Arc::new(|| Some(json!({"holder": "another instance"}))));
    assert_eq!(elsewhere.retry_waiting_approvals(16), 1);
    let held = fixture.request(&request_id);
    assert_eq!(
        (held.status.as_str(), held.scope_outcome.as_deref()),
        ("approved", Some("approved_waiting")),
        "a connector-home refusal must not retire the approval"
    );
    assert_eq!(fixture.sent(), 0);

    fixture.make_retries_due();
    assert_eq!(fixture.engine.retry_waiting_approvals(16), 1);
    assert_eq!(fixture.sent(), 1);
    assert_eq!(fixture.request(&request_id).status, "consumed");
}
