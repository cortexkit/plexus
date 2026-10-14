//! Decision-plane wiring: intent_id stability, grant_hash verification, and
//! mandatory outcome reports on every decision-authorized terminal.

#[path = "support/bounded.rs"]
mod bounded;

use std::fs;
use std::sync::Arc;

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::test_scratch::Scratch;
use plexus_core::{
    compute_grant_hash, jcs_sha256, AuthorizationRequest, CatalogActionInput, DecisionPlane,
    DecisionPlaneError, Denial, GovernanceEngine, GrantHashInput, GrantInput, MockResponse,
    MockTransport, OutcomeTerminal, OutcomeUnknownRecord, PlexusStore, PolicyInput,
    ReconcileResult, StubCredentialSource, StubDecisionPlane, TransportOutcome, Verdict,
};
use serde_json::json;

fn test_store(label: &str) -> (PlexusStore, Scratch) {
    // The macOS clock ticks in microseconds, so the counter prevents same-tick test nonce collisions.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let path = Scratch::database(&format!("decision-{label}"));
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("{label}-{unique}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    (
        PlexusStore::open(&descriptor).expect("open test store"),
        path,
    )
}

fn seed_s3(
    label: &str,
    plane: Arc<StubDecisionPlane>,
) -> (
    GovernanceEngine<StubCredentialSource, MockTransport>,
    Scratch,
    Arc<StubDecisionPlane>,
) {
    let (store, path) = test_store(label);
    let principal = "direct";
    let connection = "conn-1";
    store
        .insert_connection(
            principal,
            connection,
            "mock",
            "pending",
            &json!({"required": ["team"], "write_enabling": ["team"]}),
        )
        .expect("insert connection");
    let handle = b"test:canary-binding-handle";
    let ticket = store
        .create_binding_ticket(principal, connection, handle)
        .expect("ticket");
    store
        .connect_with_ticket(principal, &ticket.ticket_id)
        .expect("consume")
        .expect("active");

    let schema = json!({"type": "object"});
    // Destructive risk is base S3, so the severity gate routes to the decision plane.
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: connection.to_string(),
            principal: principal.to_string(),
            name: "destroy_item".to_string(),
            title: Some("Destroy".to_string()),
            schema: schema.clone(),
            schema_hash: plexus_core::jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
            risk: "destructive".to_string(),
            severity: "S3".to_string(),
            ask_first: true,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: Some(json!({
                "correlation_fields": ["team", "title"],
                "read_back_action": "search_items",
                "timeout_s": 300
            })),
        })
        .expect("write action");
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: connection.to_string(),
            principal: principal.to_string(),
            name: "search_items".to_string(),
            title: Some("Search".to_string()),
            schema: schema.clone(),
            schema_hash: plexus_core::jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
            risk: "read".to_string(),
            severity: "S1".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("read action");
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-1".to_string(),
            principal: principal.to_string(),
            connection_id: connection.to_string(),
            grantee_principal: principal.to_string(),
            risk_ceiling: "destructive".to_string(),
            action_selectors: vec!["*".to_string()],
            authority_kind: "invoke".to_string(),
            expires_at: None,
        })
        .expect("grant");
    store
        .insert_policy(&PolicyInput {
            policy_id: "policy-write".to_string(),
            principal: principal.to_string(),
            connection_id: connection.to_string(),
            action_selector: "destroy_item".to_string(),
            effect: "allow".to_string(),
            expires_at: None,
        })
        .expect("write policy");
    store
        .insert_policy(&PolicyInput {
            policy_id: "policy-read".to_string(),
            principal: principal.to_string(),
            connection_id: connection.to_string(),
            action_selector: "search_items".to_string(),
            effect: "allow".to_string(),
            expires_at: None,
        })
        .expect("read policy");

    let credentials = StubCredentialSource::default();
    credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
    let transport = MockTransport::default();
    let engine = GovernanceEngine::new(Arc::new(store), Arc::new(credentials), Arc::new(transport))
        .with_decision_plane(plane.clone() as Arc<dyn DecisionPlane>);
    (engine, path, plane)
}

fn write_args() -> serde_json::Value {
    json!({"team": "core", "title": "retire-legacy"})
}

fn write_request() -> AuthorizationRequest {
    AuthorizationRequest::new("direct", "conn-1", "destroy_item", write_args())
}

#[test]
fn intent_id_stable_across_transient_reattempt_and_fresh_for_new_write() {
    let plane = Arc::new(StubDecisionPlane::new());
    let (engine, path, plane) = seed_s3("intent-stable", plane);

    let first = engine.authorize(write_request()).expect("first allow");
    let intent_a = first.intent_id.clone().expect("intent on reservation");
    let second = engine.authorize(write_request()).expect("reattempt allow");
    let intent_b = second.intent_id.clone().expect("intent on reattempt");
    assert_eq!(
        intent_a, intent_b,
        "same logical write reuses action_request"
    );

    let envelopes = plane.envelopes();
    assert!(envelopes.len() >= 2);
    assert_eq!(envelopes[0].intent_id, intent_a);
    assert_eq!(envelopes[1].intent_id, intent_a);

    let other = AuthorizationRequest::new(
        "direct",
        "conn-1",
        "destroy_item",
        json!({"team": "core", "title": "different-write"}),
    );
    let third = engine.authorize(other).expect("new write");
    let intent_c = third.intent_id.expect("new intent");
    assert_ne!(intent_a, intent_c);

    let _ = fs::remove_file(path);
}

#[test]
fn grant_hash_mismatch_on_verdict_is_rejected() {
    let plane = Arc::new(StubDecisionPlane::new());
    plane.force_next_grant_hash(
        "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    );
    let (engine, path, _) = seed_s3("grant-mismatch", plane);

    let err = engine.authorize(write_request()).expect_err("must reject");
    assert_eq!(err.reason_code(), "grant_hash_mismatch");
    assert!(engine
        .store()
        .list_audit("direct")
        .expect("audit")
        .iter()
        .any(|row| row.reason_code == "grant_hash_mismatch"));
    let _ = fs::remove_file(path);
}

#[test]
fn decision_authorized_dispatch_reports_every_terminal() {
    let plane = Arc::new(StubDecisionPlane::new());
    let (engine, path, plane) = seed_s3("reports", plane);

    let reservation = engine.authorize(write_request()).expect("allow");
    let decision_id = reservation.decision_id.clone().expect("decision_id");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(
        outcome.outcome,
        TransportOutcome::Completed { .. }
    ));

    engine
        .transport()
        .set_response(MockResponse::OutcomeUnknown);
    let reservation = engine
        .authorize(AuthorizationRequest::new(
            "direct",
            "conn-1",
            "destroy_item",
            json!({"team": "core", "title": "unknown-write"}),
        ))
        .expect("allow unknown");
    let unknown_decision = reservation.decision_id.clone().expect("decision");
    let unknown_intent = reservation.intent_id.clone().expect("intent");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(outcome.outcome, TransportOutcome::OutcomeUnknown));

    let reservation = engine
        .authorize(AuthorizationRequest::new(
            "direct",
            "conn-1",
            "destroy_item",
            json!({"team": "core", "title": "stale-write"}),
        ))
        .expect("allow stale");
    let stale_decision = reservation.decision_id.clone().expect("decision");
    engine
        .store()
        .quarantine_action("direct", "conn-1", "destroy_item", "changed")
        .expect("quarantine");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(
        outcome.outcome,
        TransportOutcome::NotSent { ref code, .. } if code == "aborted_stale_authorization"
    ));

    let reports = plane.reports();
    assert_eq!(
        reports.len(),
        3,
        "exactly one report per decision-authorized terminal"
    );
    assert_eq!(reports[0].decision_id, decision_id);
    assert!(matches!(
        reports[0].terminal,
        OutcomeTerminal::Executed { .. }
    ));
    assert_eq!(reports[1].decision_id, unknown_decision);
    assert!(matches!(
        reports[1].terminal,
        OutcomeTerminal::OutcomeUnknown { .. }
    ));
    assert_eq!(reports[2].decision_id, stale_decision);
    assert!(matches!(
        reports[2].terminal,
        OutcomeTerminal::Refused { ref reason } if reason == "stale_authorization"
    ));

    let requests = engine
        .store()
        .list_action_requests("direct")
        .expect("requests");
    assert!(requests.iter().any(|row| {
        row.request_id == unknown_intent && row.reconciliation_status.as_deref() == Some("pending")
    }));

    let _ = fs::remove_file(path);
}

#[test]
fn grant_hash_pins_args_bidirectionally_at_dispatch() {
    let plane = Arc::new(StubDecisionPlane::new());
    let (engine, path, _) = seed_s3("dispatch-grant", plane);
    let mut reservation = engine.authorize(write_request()).expect("allow");
    reservation.args = json!({"team": "core", "title": "TAMPERED"});
    reservation.approved_args_hash =
        plexus_core::jcs_sha256(&reservation.args).expect("test JSON is JCS-compatible");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(
        outcome.outcome,
        TransportOutcome::NotSent { ref code, .. } if code == "grant_hash_mismatch"
    ));
    let mut request = write_request();
    request.args["n"] = json!(9007199254740992_u64);
    let mut reservation = engine.authorize(request).expect("allow integer args");
    reservation.args["n"] = json!(9007199254740993_u64);
    reservation.approved_args_hash = jcs_sha256(&reservation.args).unwrap();
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. } if code == "aborted_stale_authorization")
    );
    assert!(engine.transport().requests().is_empty());
    let _ = fs::remove_file(path);
}

#[test]
fn needs_quorum_surfaces_pending_action_request_with_stable_intent() {
    let plane = Arc::new(StubDecisionPlane::new());
    plane.push_verdict(Verdict::NeedsQuorum {
        decision_id: "dec_org_quorum".to_string(),
    });
    plane.push_verdict(Verdict::NeedsQuorum {
        decision_id: "dec_org_quorum2".to_string(),
    });
    let (engine, path, plane) = seed_s3("quorum", plane);

    let Err(Denial::ActionRequestCreated { request_id: first }) = engine.authorize(write_request())
    else {
        panic!("needs_quorum must create pending request");
    };
    let Err(Denial::ActionRequestCreated { request_id: second }) =
        engine.authorize(write_request())
    else {
        panic!("reattempt must reuse pending request");
    };
    assert_eq!(first, second);
    let envelopes = plane.envelopes();
    assert_eq!(envelopes[0].intent_id, first);
    assert_eq!(envelopes[1].intent_id, first);
    let _ = fs::remove_file(path);
}

#[test]
fn compute_grant_hash_matches_envelope_fields() {
    let args_hash = jcs_sha256(&write_args()).expect("args");
    let schema = json!({"type": "object"});
    let schema_hash = plexus_core::jcs_sha256(&schema).expect("test JSON is JCS-compatible");
    let hash = compute_grant_hash(GrantHashInput {
        decision_id: "dec_org_1",
        app_key: "mock",
        action: "destroy_item",
        args_snapshot_hash: &args_hash,
        schema_hash: &schema_hash,
    })
    .expect("grant hash");
    assert!(hash.starts_with("sha256:"));
}

#[test]
fn reconciliation_confirmed_not_found_ambiguous_and_denied_on_revoke() {
    let plane = Arc::new(StubDecisionPlane::new());
    let (engine, path, _) = seed_s3("reconcile", plane);

    let reservation = engine
        .authorize(write_request())
        .expect("seed uncertain write intent");
    let intent_id = reservation.intent_id.clone().expect("intent");
    let record = OutcomeUnknownRecord {
        acting_principal: "direct".to_string(),
        request_id: reservation.request_id,
        principal: "direct".to_string(),
        actor: "direct".to_string(),
        connection_id: "conn-1".to_string(),
        action: "destroy_item".to_string(),
        args: write_args(),
        occurred_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_millis() as i64)
            .unwrap_or(0),
    };

    // A reservation and its approval intent have distinct ids; persist their
    // link so reconciliation updates the approval rather than an unrelated row.
    engine
        .store()
        .enqueue_write_reconciliation(&record, Some(&intent_id))
        .unwrap();
    // Confirmed: read-back returns a matching object.
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "team": "core",
            "title": "retire-legacy",
            "id": "item-1"
        })));
    let confirmed = engine.reconcile(&record);
    assert!(
        matches!(confirmed, ReconcileResult::Confirmed { .. }),
        "got {confirmed:?}"
    );

    // A returned, fully shaped item differs on the declared correlation fields.
    engine.transport().set_response(MockResponse::Success(
        json!([{"team":"core","title":"different"}]),
    ));
    let not_found = engine.reconcile(&record);
    assert!(matches!(not_found, ReconcileResult::NotFound));

    // Ambiguous: multiple matches.
    engine
        .transport()
        .set_response(MockResponse::Success(json!([
            {"team": "core", "title": "retire-legacy", "id": "a"},
            {"team": "core", "title": "retire-legacy", "id": "b"}
        ])));
    let ambiguous = engine.reconcile(&record);
    assert!(matches!(ambiguous, ReconcileResult::Ambiguous { .. }));

    // Audit linkage via reconciliation_of.
    let audit = engine.store().list_audit("direct").expect("audit");
    assert!(audit.iter().any(|row| {
        row.reconciliation_of.as_deref() == Some(record.request_id.as_str())
            && row.gate.as_deref() == Some("reconciliation")
    }));

    // Fail-closed when connection is revoked before read-back.
    engine
        .store()
        .revoke_connection("direct", "conn-1")
        .expect("revoke");
    let denied = engine.reconcile(&record);
    assert!(
        matches!(denied, ReconcileResult::Denied { .. }),
        "got {denied:?}"
    );

    let requests = engine
        .store()
        .list_action_requests("direct")
        .expect("requests");
    assert!(requests
        .iter()
        .any(|row| row.request_id == intent_id && row.reconciliation_status.is_some()));

    let _ = fs::remove_file(path);
}

/// A report-back that keeps failing is RETRIED and then AUDITED, never dropped.
///
/// The contract with the decision plane is that every decision-authorized
/// terminal reports its outcome, because an unreported outcome leaves a grant
/// burned with an ambiguous result on their side. So the failure of the report
/// itself must leave a trace here — otherwise the two sides disagree about what
/// happened and nothing on either side knows it.
///
/// Three things are asserted separately because they fail independently:
/// every attempt is spent (not one try), the dispatch outcome is unchanged (a
/// failed REPORT must not rewrite a completed dispatch into a failure), and the
/// audit row exists with a machine-readable reason.
///
/// This path had no coverage at all: `fail_next_reports` is the only way to
/// make the stub reject a report, and nothing called it, so the retry loop and
/// its audit record had never executed in a test.
/// A decision-plane Deny settles its intent as denied, not as a pending question
/// an operator can approve. Neither local approval nor approved re-entry may
/// reopen it or contact the vendor.
#[test]
fn an_explicit_deny_is_terminal_and_its_intent_row_confers_no_authority() {
    let plane = Arc::new(StubDecisionPlane::new());
    plane.push_verdict(Verdict::Deny {
        reason: "policy_impossible".to_string(),
    });
    let plane_handle = Arc::clone(&plane);
    let (engine, path, _) = seed_s3("decision-deny", plane);

    let err = engine
        .authorize(write_request())
        .expect_err("an explicit deny must refuse");
    assert_eq!(err.reason_code(), "decision_denied");

    assert!(
        engine.transport().requests().is_empty(),
        "the vendor was contacted despite the deny: {:?}",
        engine.transport().requests()
    );

    // A denial settles the intent. It must not look like a pending question an
    // operator can approve, and local approval cannot reopen it.
    let denied = engine
        .store()
        .list_action_requests("direct")
        .expect("requests")
        .into_iter()
        .find(|row| row.status == "denied")
        .expect("the deny settles its intent row");
    assert!(!engine
        .store()
        .decide_action_request("direct", &denied.request_id, true, "operator")
        .expect("try to approve locally"));

    let err = engine
        .authorize(write_request().approved_from(&denied.request_id))
        .expect_err("a local approval must not launder a decision-plane deny");
    assert_eq!(
        err.reason_code(),
        "approval_shape_mismatch",
        "a denied intent must not count as an approval"
    );
    assert!(
        engine.transport().requests().is_empty(),
        "the vendor was contacted on the approved re-entry: {:?}",
        engine.transport().requests()
    );

    assert_eq!(
        plane_handle.envelopes().len(),
        1,
        "a settled denial must not re-enter the decision plane"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn an_allowed_intent_is_consumed_and_cannot_send_twice() {
    let (engine, path, _) = seed_s3("allow-consumes-intent", Arc::new(StubDecisionPlane::new()));
    engine
        .store()
        .insert_grant(&plexus_core::storage::GrantInput {
            grant_id: "approval-admin".into(),
            principal: "direct".into(),
            connection_id: "conn-1".into(),
            grantee_principal: "operator".into(),
            risk_ceiling: "destructive".into(),
            action_selectors: vec!["*".into()],
            authority_kind: "connection_admin".into(),
            expires_at: None,
        })
        .unwrap();
    let reservation = engine.authorize(write_request()).expect("allow");
    let intent = reservation.intent_id.as_deref().expect("intent");
    assert!(matches!(
        engine.revalidate_and_dispatch(&reservation).outcome,
        TransportOutcome::Completed { .. }
    ));
    let row = engine
        .store()
        .list_action_requests("direct")
        .unwrap()
        .into_iter()
        .find(|row| row.request_id == intent)
        .unwrap();
    assert_eq!(
        row.status, "consumed",
        "decision-plane Allow left an approvable intent"
    );
    let refusal = engine
        .approve_request("direct", intent, "operator")
        .expect_err("already spent");
    assert!(matches!(
        refusal.reason_code(),
        "approval_consumed" | "approval_already_decided"
    ));
    assert_eq!(
        engine.transport().requests().len(),
        1,
        "operator approval sent twice"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn quorum_intents_preserve_call_key_and_attribution_only_scope() {
    let plane = Arc::new(StubDecisionPlane::new());
    plane.push_verdict(Verdict::NeedsQuorum {
        decision_id: String::new(),
    });
    let (engine, path, _) = seed_s3("quorum-scope", plane);
    let scope = plexus_core::scope::CallScope {
        owner: "direct".into(),
        scope_ref: "scope-ref".into(),
        scope_epoch: 1,
        kind: Some("head".into()),
        parent: None,
        parent_state: None,
        agent_id: Some("agent-a".into()),
        flow_id: None,
        delegates: true,
        owner_authorized: true,
    };
    let err = engine
        .authorize(
            write_request()
                .with_scope_attribution_only(scope.clone())
                .with_call_key("held-key"),
        )
        .expect_err("quorum");
    let Denial::ActionRequestCreated { request_id } = err else {
        panic!("{err:?}")
    };
    let row = engine
        .store()
        .list_action_requests("direct")
        .unwrap()
        .into_iter()
        .find(|row| row.request_id == request_id)
        .unwrap();
    assert_eq!(row.call_key.as_deref(), Some("held-key"));
    assert!(
        !row.scope.as_ref().unwrap().delegates,
        "attribution became delegated authority"
    );
    assert_eq!(row.status, "pending");
    engine
        .withdraw_call(&plexus_core::withdraw::WithdrawCall {
            caller: "direct",
            call_key: "held-key",
            carrier: None,
            scope: Some(&scope),
        })
        .expect("withdraw");
    assert_eq!(
        engine
            .store()
            .list_action_requests("direct")
            .unwrap()
            .into_iter()
            .find(|row| row.request_id == request_id)
            .unwrap()
            .status,
        "cancelled"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn a_new_quorum_verdict_invalidates_an_earlier_unclaimed_allow() {
    let plane = Arc::new(StubDecisionPlane::new());
    let (engine, path, plane) = seed_s3("allow-then-quorum", plane);
    let first = engine.authorize(write_request()).unwrap();
    let intent = first.intent_id.as_deref().unwrap();
    plane.push_verdict(Verdict::NeedsQuorum {
        decision_id: String::new(),
    });
    let refusal = engine.authorize(write_request()).unwrap_err();
    assert!(
        matches!(refusal, Denial::ActionRequestCreated { ref request_id } if request_id == intent)
    );
    let row = engine
        .store()
        .list_action_requests("direct")
        .unwrap()
        .into_iter()
        .find(|row| row.request_id == intent)
        .unwrap();
    assert_eq!(
        row.status, "pending",
        "old Allow survived the new quorum verdict"
    );
    assert!(matches!(
        engine.revalidate_and_dispatch(&first).outcome,
        TransportOutcome::NotSent { .. }
    ));
    assert!(engine.transport().requests().is_empty());
    let _ = fs::remove_file(path);
}

#[test]
fn a_failed_allow_verdict_write_refuses_before_reservation_or_dispatch() {
    let (engine, path, _) = seed_s3(
        "plane-verdict-store-failure",
        Arc::new(StubDecisionPlane::new()),
    );
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_plane_verdict BEFORE UPDATE ON action_requests
         BEGIN SELECT RAISE(ABORT, 'verdict write unavailable'); END;",
        )
        .unwrap();
    let refusal = engine.authorize(write_request()).unwrap_err();
    assert_eq!(
        refusal.reason_code(),
        "store_failure",
        "failed verdict persistence still authorized"
    );
    assert!(engine.transport().requests().is_empty());
    let requests = engine.store().list_action_requests("direct").unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].status, "pending");
    assert!(requests[0].decision_id.is_none());
    let _ = fs::remove_file(path);
}

/// An S3 write must be REFUSED when the decision plane cannot be reached.
///
/// This is the fail-closed property the whole severity gate exists for: a
/// destructive action routes to the decision plane precisely because nobody
/// here is allowed to authorize it alone, so an unreachable plane must deny
/// rather than fall through. The opposite behaviour would be the worst
/// possible failure mode -- an outage silently converting governed writes into
/// ungoverned ones -- and it would look like nothing at all from the outside.
///
/// `push_error` was the only way to make the stub fail this way and had zero
/// callers, so this path had never executed in any test: a dead fault-injector
/// means an unreached code path, not an unused function.
///
/// Asserts the DENIAL, the audit reason, and that NO REQUEST REACHED THE
/// VENDOR. The last one is the point: a refusal returned while the write was
/// already sent is the failure this gate exists to prevent, and only a
/// zero-call assertion can see the difference.
#[test]
fn an_unreachable_decision_plane_refuses_the_write_without_dispatching() {
    let plane = Arc::new(StubDecisionPlane::new());
    plane.push_error(DecisionPlaneError::Peer("route unavailable".to_string()));
    let (engine, path, _) = seed_s3("plane-unreachable", plane);

    let err = engine
        .authorize(write_request())
        .expect_err("an unreachable decision plane must deny");
    assert_eq!(err.reason_code(), "decision_plane_failure");

    assert!(
        engine.transport().requests().is_empty(),
        "the vendor was contacted despite the refusal: {:?}",
        engine.transport().requests()
    );

    assert!(
        engine
            .store()
            .list_audit("direct")
            .expect("audit")
            .iter()
            .any(|row| row.reason_code == "decision_plane_failure"),
        "the refusal must be auditable, or an outage leaves no trace"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn a_failing_outcome_report_is_retried_then_audited() {
    let plane = Arc::new(StubDecisionPlane::new());
    let (engine, path, plane) = seed_s3("report-failure", plane);

    // Fail more times than the engine will attempt, so every attempt is spent
    // and the exhausted path runs. Derived from the engine's own constant so
    // raising OUTCOME_REPORT_ATTEMPTS cannot silently make this test stop
    // reaching the branch it exists to cover.
    plane.fail_next_reports(plexus_core::OUTCOME_REPORT_ATTEMPTS + 1);

    let reservation = engine.authorize(write_request()).expect("allow");
    let decision_id = reservation.decision_id.clone().expect("decision");
    let outcome = engine.revalidate_and_dispatch(&reservation);

    assert!(
        matches!(outcome.outcome, TransportOutcome::Completed { .. }),
        "a failed report must not rewrite the dispatch outcome, got {:?}",
        outcome.outcome
    );
    assert!(
        plane.reports().is_empty(),
        "the stub rejected every attempt, so no report should have landed"
    );

    let audit = engine.store().list_audit("direct").expect("audit");
    let row = audit
        .iter()
        .find(|row| row.reason_code == "outcome_report_failed")
        .expect("a failed report-back must leave an audit row");
    assert_eq!(
        row.attempt_no,
        Some(plexus_core::OUTCOME_REPORT_ATTEMPTS as i64),
        "the audit must record how many attempts were spent"
    );
    assert!(
        row.args_redaction_summary
            .as_deref()
            .is_some_and(|summary| summary.contains(&decision_id)),
        "the audit row must name the decision whose outcome was lost, so the \
         two sides can be reconciled: {:?}",
        row.args_redaction_summary
    );

    let _ = fs::remove_file(path);
}

fn reconciliation_record(action: &str) -> OutcomeUnknownRecord {
    OutcomeUnknownRecord {
        acting_principal: "direct".to_string(),
        request_id: "unknown-write".to_string(),
        principal: "direct".to_string(),
        actor: "direct".to_string(),
        connection_id: "conn-1".to_string(),
        action: action.to_string(),
        args: write_args(),
        occurred_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
    }
}

#[test]
fn reconciliation_target_becomes_write_is_refused_without_dispatch() {
    let (engine, path, _) = seed_s3("reconcile-risk-drift", Arc::new(StubDecisionPlane::new()));
    // The stored manifest remains read while the live catalog changes. A static
    // manifest lookup at dispatch must not stand in for current classification.
    let manifest = plexus_core::ingest_value(json!({
        "schema_version": 1, "key": "mock", "name": "Mock", "description": "Risk drift fixture",
        "reuse_path": "mcp_direct", "reuse_rationale": "Mock transport", "tier": "S2",
        "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
        "auth": {"mode": "api_key"}, "credential_bindings": [],
        "resource_filters": {"required": [], "optional": [], "write_enabling": []},
        "actions_baseline": [
            {"name": "destroy_item", "risk": "destructive", "reconciliation": {
                "correlation_fields": ["team", "title"], "read_back_action": "search_items", "timeout_s": 300
            }},
            {"name": "search_items", "risk": "read"}
        ],
        "defaults": {"ask_first_risk": [], "rate_limit": {"calls_per_min": 30}},
        "availability": "ga"
    })).expect("ingest reviewed read target");
    engine
        .store()
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &manifest)
        .unwrap();
    let record = reconciliation_record("destroy_item");
    engine.transport().set_response(MockResponse::Success(
        json!([{"team":"core","title":"different"}]),
    ));
    assert_eq!(engine.reconcile(&record), ReconcileResult::NotFound);
    let before = engine.transport().requests().len();
    assert_eq!(before, 1, "positive control reaches the transport");
    let schema = json!({"type": "object"});
    engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            name: "search_items".to_string(),
            title: None,
            schema_hash: jcs_sha256(&schema).unwrap(),
            schema,
            risk: "write".to_string(),
            severity: "S2".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    assert_eq!(
        engine.reconcile(&record),
        ReconcileResult::Denied {
            reason_code: "reconciliation_target_not_read".to_string(),
        }
    );
    assert_eq!(engine.transport().requests().len(), before);
    assert!(engine
        .store()
        .list_audit("direct")
        .unwrap()
        .iter()
        .any(|row| row.reason_code == "reconciliation_target_not_read"
            && row.reconciliation_of.as_deref() == Some("unknown-write")));
    let _ = fs::remove_file(path);
}

#[test]
fn reconciliation_non_read_preflight_refuses_before_authorization() {
    let (engine, path, _) = seed_s3("reconcile-preflight", Arc::new(StubDecisionPlane::new()));
    engine.transport().set_response(MockResponse::Success(
        json!([{"team":"core","title":"different"}]),
    ));
    let record = reconciliation_record("destroy_item");
    assert_eq!(engine.reconcile(&record), ReconcileResult::NotFound);
    assert_eq!(
        engine.transport().requests().len(),
        1,
        "read positive control dispatches"
    );
    set_reconciliation_target_write(engine.store());
    let before = reservation_count(&path);
    let audit_before = engine.store().list_audit("direct").unwrap().len();
    assert_eq!(
        engine.reconcile(&record),
        ReconcileResult::Denied {
            reason_code: "reconciliation_target_not_read".into(),
        }
    );
    assert_eq!(
        reservation_count(&path),
        before,
        "preflight must refuse before creating a reservation"
    );
    let audit = engine.store().list_audit("direct").unwrap();
    assert_eq!(
        audit.len(),
        audit_before + 1,
        "preflight must write only the reconciliation audit, not an authorization audit"
    );
    assert_eq!(engine.transport().requests().len(), 1);
}

fn reservation_count(path: &Scratch) -> i64 {
    rusqlite::Connection::open(path.path())
        .unwrap()
        .query_row("SELECT count(*) FROM reservations", [], |row| row.get(0))
        .unwrap()
}

fn set_reconciliation_target_write(store: &PlexusStore) {
    let schema = json!({"type": "object"});
    store
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: "conn-1".into(),
            name: "search_items".into(),
            title: None,
            schema_hash: jcs_sha256(&schema).unwrap(),
            schema,
            risk: "write".into(),
            severity: "S2".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
}

#[test]
fn reconciliation_authorization_snapshot_refuses_risk_changed_after_preflight() {
    use plexus_core::governance::{GovernanceSeams, ResolverDenial};
    use plexus_core::storage::CatalogAction;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RiskFlip {
        store: Arc<PlexusStore>,
        calls: AtomicUsize,
    }
    impl GovernanceSeams for RiskFlip {
        fn resolve_invoke(&self, request: &AuthorizationRequest) -> Result<(), ResolverDenial> {
            assert_eq!(request.action, "search_items");
            assert_eq!(
                self.store
                    .catalog_action("direct", "conn-1", "search_items")
                    .unwrap()
                    .unwrap()
                    .risk,
                "read"
            );
            // resolve_invoke runs inside authorize, before its catalog reload;
            // reconciliation has already completed the read-only preflight.
            set_reconciliation_target_write(&self.store);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn facade_only(&self, _: &CatalogAction) -> bool {
            false
        }
    }

    let (engine, path, _) = seed_s3("reconcile-snapshot", Arc::new(StubDecisionPlane::new()));
    engine.transport().set_response(MockResponse::Success(
        json!([{"team":"core","title":"different"}]),
    ));
    let record = reconciliation_record("destroy_item");
    assert_eq!(engine.reconcile(&record), ReconcileResult::NotFound);
    assert_eq!(
        engine.transport().requests().len(),
        1,
        "read positive control dispatches"
    );
    let before = reservation_count(&path);
    let flip = Arc::new(RiskFlip {
        store: engine.store().clone(),
        calls: AtomicUsize::new(0),
    });
    let engine = engine.with_governance_seams(flip.clone());
    assert_eq!(
        engine.reconcile(&record),
        ReconcileResult::Denied {
            reason_code: "reconciliation_target_not_read".into(),
        },
        "authorization snapshot must refuse the newly write-classified target"
    );
    assert_eq!(
        flip.calls.load(Ordering::SeqCst),
        1,
        "preflight passed and authorization ran"
    );
    assert_eq!(
        reservation_count(&path),
        before + 1,
        "authorization reserved the write snapshot before reconciliation refused it"
    );
    assert_eq!(
        engine.transport().requests().len(),
        1,
        "snapshot refusal must not dispatch"
    );
    let live: i64 = rusqlite::Connection::open(path.path())
        .unwrap()
        .query_row(
            "SELECT count(*) FROM reservations WHERE status='reserved'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        live, 0,
        "refused reconciliation must abandon its unclaimed reservation"
    );
}

#[test]
fn reconciliation_self_target_is_refused_without_dispatch() {
    let (engine, path, _) = seed_s3("reconcile-self", Arc::new(StubDecisionPlane::new()));
    let schema = json!({"type": "object"});
    engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            name: "search_items".to_string(),
            title: None,
            schema_hash: jcs_sha256(&schema).unwrap(),
            schema,
            risk: "read".to_string(),
            severity: "S1".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: Some(json!({"correlation_fields": ["team", "title"],
            "read_back_action": "search_items", "timeout_s": 300})),
        })
        .unwrap();
    assert_eq!(
        engine.reconcile(&reconciliation_record("search_items")),
        ReconcileResult::Denied {
            reason_code: "reconciliation_self_target".to_string(),
        }
    );
    assert!(engine.transport().requests().is_empty());
    assert!(engine
        .store()
        .list_audit("direct")
        .unwrap()
        .iter()
        .any(|row| row.reason_code == "reconciliation_self_target"));
    let _ = fs::remove_file(path);
}

fn reconciliation_statuses(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
) -> Vec<(String, String, Option<String>)> {
    let mut rows: Vec<_> = engine
        .store()
        .list_write_reconciliations("direct")
        .unwrap()
        .into_iter()
        .map(|row| (row.request_id, row.status, row.reason))
        .collect();
    rows.sort();
    rows
}

fn pending_reconciliation_count(path: &Scratch) -> i64 {
    rusqlite::Connection::open(path.path())
        .unwrap()
        .query_row(
            "SELECT count(*) FROM pending_write_reconciliations",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

/// The default audit retention, used where a test does not exercise retention.
const THIRTY_DAYS_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Settled reconciliation results age out with the operator's configured
/// audit retention, not a fixed default.
#[test]
fn settled_reconciliation_results_follow_the_configured_retention() {
    let (engine, path, _) = seed_s3("reconcile-retention", Arc::new(StubDecisionPlane::new()));
    let day = 24 * 60 * 60 * 1000;
    let now = plexus_core::now_ms();
    rusqlite::Connection::open(path.path())
        .unwrap()
        .execute(
            "INSERT INTO write_reconciliation_results
                (principal, request_id, acting_principal, connection_id, action, status, updated_at_ms)
                VALUES ('direct', 'old', 'direct', 'conn-1', 'destroy_item', 'confirmed', ?1)",
            [now - 10 * day],
        )
        .unwrap();
    engine
        .sweep_write_reconciliations(now, THIRTY_DAYS_MS)
        .unwrap();
    assert_eq!(
        reconciliation_statuses(&engine).len(),
        1,
        "a ten-day-old result is inside a thirty-day window"
    );
    engine.sweep_write_reconciliations(now, 8 * day).unwrap();
    assert!(
        reconciliation_statuses(&engine).is_empty(),
        "an eight-day window must prune the ten-day-old result"
    );
}

/// One queued record that no longer decodes must not stop reconciliation for
/// every other write: it settles as ambiguous on its own and the rest proceed.
#[test]
fn an_undecodable_queued_reconciliation_does_not_stop_the_sweep() {
    let (engine, path, _) = seed_s3("reconcile-undecodable", Arc::new(StubDecisionPlane::new()));
    let record = reconciliation_record("destroy_item");
    engine
        .store()
        .enqueue_write_reconciliation(&record, None)
        .expect("queue the decodable record");
    rusqlite::Connection::open(path.path())
        .unwrap()
        .execute_batch(
            "INSERT INTO pending_write_reconciliations
                (principal, request_id, record_json, intent_id, expires_at_ms)
                VALUES ('direct', 'broken', '{not json', NULL, 9007199254740991);
             INSERT INTO write_reconciliation_results
                (principal, request_id, acting_principal, connection_id, action, status, updated_at_ms)
                VALUES ('direct', 'broken', 'direct', 'conn-1', 'destroy_item', 'pending', 1);",
        )
        .unwrap();
    engine
        .transport()
        .set_response(MockResponse::Success(json!([write_args()])));
    engine
        .sweep_write_reconciliations(plexus_core::now_ms(), THIRTY_DAYS_MS)
        .expect("the sweep must survive an undecodable row");
    assert_eq!(
        reconciliation_statuses(&engine),
        vec![
            (
                "broken".into(),
                "ambiguous".into(),
                Some("record_undecodable".into())
            ),
            ("unknown-write".into(), "confirmed".into(), None),
        ]
    );
    assert_eq!(pending_reconciliation_count(&path), 0);
}

/// A read-back the vendor failed is not evidence either way, so the write
/// stays queued and the next sweep reads back again.
#[test]
fn a_failed_read_back_keeps_the_write_queued_for_the_next_sweep() {
    let (engine, path, _) = seed_s3("reconcile-retry", Arc::new(StubDecisionPlane::new()));
    let record = reconciliation_record("destroy_item");
    engine
        .store()
        .enqueue_write_reconciliation(&record, None)
        .expect("queue");
    engine.transport().set_response(MockResponse::VendorError {
        code: "http_503".into(),
        message: "unavailable".into(),
    });
    engine
        .sweep_write_reconciliations(plexus_core::now_ms(), THIRTY_DAYS_MS)
        .expect("first sweep");
    assert_eq!(
        reconciliation_statuses(&engine),
        vec![("unknown-write".into(), "pending".into(), None)],
        "a failed read-back must not settle the write"
    );
    assert_eq!(pending_reconciliation_count(&path), 1);
    engine
        .transport()
        .set_response(MockResponse::Success(json!([write_args()])));
    engine
        .sweep_write_reconciliations(plexus_core::now_ms().saturating_add(5_000), THIRTY_DAYS_MS)
        .expect("second sweep");
    assert_eq!(
        reconciliation_statuses(&engine),
        vec![("unknown-write".into(), "confirmed".into(), None)]
    );
    assert_eq!(pending_reconciliation_count(&path), 0);
}

#[path = "support/audit.rs"]
mod audit_test;

#[test]
fn outcome_report_audit_failure_is_loud_and_preserves_completion() {
    if audit_test::captured_by_parent(
        "outcome_report_audit_failure_is_loud_and_preserves_completion",
        "outcome_report_failed",
    ) {
        return;
    }
    for fail in [false, true] {
        let (engine, path, plane) =
            seed_s3("report-audit-failure", Arc::new(StubDecisionPlane::new()));
        plane.fail_next_reports(plexus_core::OUTCOME_REPORT_ATTEMPTS + 1);
        let reservation = engine.authorize(write_request()).unwrap();
        if fail {
            audit_test::reject_inserts(&path);
            // Reject only the outcome_report_failed audit row; the transport
            // result's separate audit record must still be written.
            rusqlite::Connection::open(&path)
                .unwrap()
                .execute_batch(
                    "DROP TRIGGER reject_audit_insert;
                CREATE TRIGGER reject_audit_insert BEFORE INSERT ON audit_journal
                WHEN NEW.reason_code = 'outcome_report_failed'
                BEGIN SELECT RAISE(ABORT, 'injected audit insert failure'); END;",
                )
                .unwrap();
        }
        let result = engine.revalidate_and_dispatch(&reservation);
        assert!(matches!(result.outcome, TransportOutcome::Completed { .. }));
        assert_eq!(engine.transport().requests().len(), 1);
        assert!(plane.reports().is_empty());
        assert_eq!(
            engine.store().list_audit("direct").unwrap().len(),
            if fail { 2 } else { 3 }
        );
        drop(engine);
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn empty_read_back_retries_until_deadline_then_stays_unknown() {
    let (engine, _path, _) = seed_s3("reconcile-empty", Arc::new(StubDecisionPlane::new()));
    let mut record = reconciliation_record("destroy_item");
    engine
        .transport()
        .set_response(MockResponse::Success(json!([])));
    assert!(
        matches!(engine.reconcile(&record), ReconcileResult::Retrying { .. }),
        "an empty search before deadline must keep the write uncertain"
    );
    record.occurred_at_ms = plexus_core::now_ms().saturating_sub(300_000);
    assert!(
        matches!(engine.reconcile(&record), ReconcileResult::Ambiguous { .. }),
        "an empty search at deadline must remain unknown, never NotFound"
    );
    let fresh = reconciliation_record("destroy_item");
    engine
        .transport()
        .set_response(MockResponse::Success(json!([write_args()])));
    assert!(matches!(
        engine.reconcile(&fresh),
        ReconcileResult::Confirmed { .. }
    ));
}
#[test]
fn transient_original_catalog_read_keeps_reconciliation_queued() {
    let (engine, path, _) = seed_s3(
        "reconcile-catalog-outage",
        Arc::new(StubDecisionPlane::new()),
    );
    let record = reconciliation_record("destroy_item");
    engine
        .store()
        .enqueue_write_reconciliation(&record, None)
        .unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE catalog_actions")
        .unwrap();
    assert!(
        matches!(engine.reconcile(&record), ReconcileResult::Retrying { .. }),
        "a catalog store error must not settle original_action_missing"
    );
    assert_eq!(pending_reconciliation_count(&path), 1);
}

#[test]
fn reconciliation_owner_change_abandons_the_unused_reservation() {
    let (engine, path, _) = seed_s3("reconcile-owner-change", Arc::new(StubDecisionPlane::new()));
    let connection = engine
        .store()
        .connection("direct", "conn-1")
        .unwrap()
        .unwrap();
    engine
        .store()
        .insert_connection(
            "old-owner",
            "conn-1",
            &connection.app_key,
            "active",
            &json!({}),
        )
        .unwrap();
    for name in ["destroy_item", "search_items"] {
        let action = engine
            .store()
            .catalog_action("direct", "conn-1", name)
            .unwrap()
            .unwrap();
        engine
            .store()
            .upsert_catalog_action(&CatalogActionInput {
                principal: "old-owner".into(),
                connection_id: "conn-1".into(),
                name: name.into(),
                title: action.title,
                schema: action.schema,
                schema_hash: action.schema_hash,
                risk: action.risk,
                severity: action.severity,
                ask_first: action.ask_first,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: action.reconciliation,
            })
            .unwrap();
    }
    let mut record = reconciliation_record("destroy_item");
    record.principal = "old-owner".into();
    assert_eq!(
        engine.reconcile(&record),
        ReconcileResult::Denied {
            reason_code: "reconciliation_owner_changed".into()
        }
    );
    let live: i64 = rusqlite::Connection::open(path.path())
        .unwrap()
        .query_row(
            "SELECT count(*) FROM reservations WHERE status='reserved'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        live, 0,
        "owner-changed reconciliation must abandon its unclaimed reservation"
    );
    assert!(engine.transport().requests().is_empty());
}
