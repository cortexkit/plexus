use plexus_core::credentials::ResolvedCredential;
use plexus_core::github::receipt::DEFAULT_CLAIM_LEASE_SECONDS;
use plexus_core::github::receipt::{Claim, Effect, RETENTION_MS};
use plexus_core::github::sweeper::sweep_receipts;
use plexus_core::transport::{MockTransport, Transport, TransportRequest};
use plexus_core::PlexusStore;
use serde_json::json;
use std::sync::{Arc, Barrier};

fn fixture() -> (plexus_core::test_scratch::Scratch, PlexusStore) {
    let (file, store) = crate::scratch_store::open("github-receipt");
    (file, store)
}

#[test]
fn unsettled_receipt_survives_audit_prune_until_its_own_lease_based_horizon() {
    for state in ["pending", "pending_approval", "outcome_unknown"] {
        let (file, store) = fixture();
        claim(&store, "worker", 1000);
        let db = rusqlite::Connection::open(file.path()).unwrap();
        db.execute(
            "UPDATE github_bot_receipt SET state=?1,updated_at=1000,claim_lease_expires_at=9000",
            [state],
        )
        .unwrap();
        store.prune_audit(8000, 1000).unwrap();
        assert!(
            store.github_receipt("agent", "nonce").unwrap().is_some(),
            "audit pruning deleted {state}"
        );
        sweep_receipts(&store, 9000 + RETENTION_MS - 1).unwrap();
        assert!(
            store.github_receipt("agent", "nonce").unwrap().is_some(),
            "lease horizon was ignored for {state}"
        );
        sweep_receipts(&store, 9000 + RETENTION_MS).unwrap();
        assert!(store.github_receipt("agent", "nonce").unwrap().is_none());
    }
}

#[test]
fn production_receipt_lease_is_120_seconds() {
    assert_eq!(DEFAULT_CLAIM_LEASE_SECONDS, 120);
}

fn effects() -> Vec<Effect> {
    (0..6)
        .map(|index| Effect {
            effect: format!("leg-{index}"),
            dispatch_attempted_at: None,
            request_id: None,
            outcome: None,
        })
        .collect()
}

// The facade dispatches only after the ledger gives this worker ownership and
// the pre-transmit marker commits. Record the actual transport call separately.
fn retry_effect(store: &PlexusStore, transport: &MockTransport, owner: &str, now: i64) -> Claim {
    let result = claim(store, owner, now);
    if matches!(result, Claim::Owned(_))
        && store
            .mark_github_dispatch("agent", "nonce", owner, 0, now, "test-request")
            .unwrap()
    {
        transport.dispatch(
            TransportRequest {
                request_id: "write".into(),
                connection_id: "handle".into(),
                action: "github.comment.add".into(),
                args: json!({"body":"one"}),
                credential_fingerprint: "test".into(),
            },
            &ResolvedCredential::anonymous(),
        );
    }
    result
}

fn claim(store: &PlexusStore, owner: &str, now: i64) -> Claim {
    store
        .claim_github_receipt(
            "agent",
            "nonce",
            "fingerprint",
            owner,
            &json!({"generation": owner}),
            &effects(),
            None,
            now,
            120,
        )
        .unwrap()
}

#[test]
fn claim_is_atomic_and_rejects_mismatched_nonce_and_live_lease() {
    let (_file, store) = fixture();
    let Claim::Owned(first) = claim(&store, "first", 1000) else {
        panic!("claim failed")
    };
    assert_eq!(first.claim_lease_expires_at, Some(121000));
    assert_eq!(claim(&store, "second", 1001), Claim::InFlight);
    assert_eq!(
        store
            .claim_github_receipt(
                "agent",
                "nonce",
                "different",
                "second",
                &json!({}),
                &effects(),
                None,
                1001,
                120
            )
            .unwrap(),
        Claim::PayloadMismatch
    );
    let Claim::Owned(taken) = claim(&store, "second", 121000) else {
        panic!("takeover failed")
    };
    assert_eq!(taken.authority_baseline, json!({"generation":"second"}));
    assert_eq!(taken.claim_owner.as_deref(), Some("second"));
    assert_eq!(taken.created_at, 1000);
    assert_eq!(taken.claim_lease_expires_at, Some(241000));
}

#[test]
fn claim_lease_covers_first_request_for_at_least_sixty_seconds() {
    let (_file, store) = fixture();
    let first = store
        .claim_github_receipt(
            "agent",
            "nonce",
            "fingerprint",
            "first",
            &json!({}),
            &effects(),
            None,
            1000,
            1,
        )
        .unwrap();
    let Claim::Owned(row) = first else {
        panic!("not owned")
    };
    assert_eq!(row.claim_lease_expires_at, Some(61000));
    assert_eq!(claim(&store, "second", 20000), Claim::InFlight);
}

#[test]
fn killed_before_marker_retries_once_after_expiry() {
    let (_file, store) = fixture();
    claim(&store, "dead", 1000);
    assert!(store
        .github_receipt("agent", "nonce")
        .unwrap()
        .unwrap()
        .effects
        .iter()
        .all(|leg| leg.dispatch_attempted_at.is_none()));
    let Claim::Owned(_) = claim(&store, "retry", 121000) else {
        panic!("not reclaimable")
    };
    assert!(store
        .mark_github_dispatch("agent", "nonce", "retry", 0, 121001, "test-request")
        .unwrap());
    assert!(!store
        .mark_github_dispatch("agent", "nonce", "retry", 0, 121002, "test-request")
        .unwrap());
}

#[test]
fn killed_after_marker_is_unknown_on_retry_and_enqueued() {
    let (_file, store) = fixture();
    claim(&store, "dead", 1000);
    assert!(store
        .mark_github_dispatch("agent", "nonce", "dead", 0, 1001, "test-request")
        .unwrap());
    let Claim::Unknown(row) = claim(&store, "retry", 121000) else {
        panic!("redispatched")
    };
    assert_eq!(row.state, "outcome_unknown");
    assert_eq!(row.effects[0].dispatch_attempted_at, Some(1001));
    assert!(!store
        .mark_github_dispatch("agent", "nonce", "retry", 0, 121001, "test-request")
        .unwrap());
}

#[test]
fn startup_sweeper_enqueues_unknown_without_retry_and_leaves_approvals_alone() {
    let (_file, store) = fixture();
    claim(&store, "dead", 1000);
    store
        .mark_github_dispatch("agent", "nonce", "dead", 0, 1001, "test-request")
        .unwrap();
    store
        .claim_github_receipt(
            "agent",
            "approval",
            "fingerprint",
            "owner",
            &json!({}),
            &effects(),
            Some("approval-id"),
            1000,
            120,
        )
        .unwrap();
    assert!(sweep_receipts(&store, 120999).unwrap().is_empty());
    let queued = sweep_receipts(&store, 121000).unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].state, "outcome_unknown");
    assert_eq!(
        store
            .github_receipt("agent", "approval")
            .unwrap()
            .unwrap()
            .state,
        "pending_approval"
    );
    assert!(sweep_receipts(&store, 121001).unwrap().is_empty());
}

#[test]
fn paused_worker_loses_pre_transmit_cas_to_takeover() {
    let (_file, store) = fixture();
    claim(&store, "paused", 1000);
    let Claim::Owned(_) = claim(&store, "retry", 121000) else {
        panic!("no takeover")
    };
    assert!(!store
        .mark_github_dispatch("agent", "nonce", "paused", 0, 121001, "test-request")
        .unwrap());
    assert!(store
        .mark_github_dispatch("agent", "nonce", "retry", 0, 121001, "test-request")
        .unwrap());
    assert_eq!(
        store
            .github_receipt("agent", "nonce")
            .unwrap()
            .unwrap()
            .effects[0]
            .dispatch_attempted_at,
        Some(121001)
    );
}

#[test]
fn release_without_marker_allows_immediate_retry_and_refusal_is_sticky() {
    let (_file, store) = fixture();
    claim(&store, "first", 1000);
    assert!(store
        .release_github_claim("agent", "nonce", "first", 1001)
        .unwrap());
    let Claim::Owned(_) = claim(&store, "second", 1001) else {
        panic!("lease wait")
    };
    assert!(store
        .finish_github_facade(
            "agent",
            "nonce",
            "second",
            "refused",
            &json!({"code":"handle_disabled"}),
            Some("handle_disabled"),
            1002
        )
        .unwrap());
    let Claim::Replay(row) = claim(&store, "third", 1003) else {
        panic!("not sticky")
    };
    assert_eq!(row.outcome, Some(json!({"code":"handle_disabled"})));
}

/// A write GitHub answered with no body (a 204) succeeded. Its effect must read
/// back as settled, not as a write in doubt: the claim can be released between
/// legs, and a takeover after the lease resumes instead of declaring the
/// receipt outcome_unknown.
#[test]
fn an_empty_success_body_is_a_settled_effect() {
    let (_file, store) = fixture();
    claim(&store, "first", 1000);
    assert!(store
        .mark_github_dispatch("agent", "nonce", "first", 0, 1001, "test-request")
        .unwrap());
    assert!(store
        .finish_github_effect("agent", "nonce", "first", 0, &serde_json::Value::Null, 1002)
        .unwrap());
    let row = store.github_receipt("agent", "nonce").unwrap().unwrap();
    assert!(
        row.effects[0].outcome.is_some(),
        "an empty success body must record a settled outcome: {:?}",
        row.effects[0]
    );
    assert!(store
        .release_github_claim_between_legs("agent", "nonce", "first", 1003)
        .unwrap());
    let Claim::Owned(resumed) = claim(&store, "second", 121000) else {
        panic!("a settled effect was treated as uncertain")
    };
    assert_eq!(resumed.state, "pending");
}

#[test]
fn release_never_clears_a_transmitted_effect() {
    let (_file, store) = fixture();
    claim(&store, "first", 1000);
    store
        .mark_github_dispatch("agent", "nonce", "first", 0, 1001, "test-request")
        .unwrap();
    assert!(!store
        .release_github_claim("agent", "nonce", "first", 1002)
        .unwrap());
}

#[test]
fn six_ordered_effects_replay_completed_outcome() {
    let (_file, store) = fixture();
    claim(&store, "first", 1000);
    for index in 0..6 {
        assert!(store
            .mark_github_dispatch(
                "agent",
                "nonce",
                "first",
                index,
                1001 + index as i64,
                "test-request"
            )
            .unwrap());
        assert!(store
            .finish_github_effect(
                "agent",
                "nonce",
                "first",
                index,
                &json!({"ok":index}),
                1011 + index as i64
            )
            .unwrap());
    }
    assert!(store
        .finish_github_facade(
            "agent",
            "nonce",
            "first",
            "completed",
            &json!({"done":true}),
            None,
            1020
        )
        .unwrap());
    let Claim::Replay(row) = claim(&store, "retry", 1021) else {
        panic!("not replayed")
    };
    assert_eq!(row.effects.len(), 6);
    assert_eq!(row.effects[5].outcome, Some(json!({"ok":5})));
    assert_eq!(row.outcome, Some(json!({"done":true})));
}

#[test]
fn retention_uses_updated_at_and_never_prunes_a_live_lease() {
    let (_file, store) = fixture();
    claim(&store, "first", 1000);
    store
        .finish_github_facade(
            "agent",
            "nonce",
            "first",
            "completed",
            &json!("ok"),
            None,
            RETENTION_MS - 100,
        )
        .unwrap();
    sweep_receipts(&store, RETENTION_MS + 1000).unwrap();
    assert!(
        store.github_receipt("agent", "nonce").unwrap().is_some(),
        "created_at is not the retention clock"
    );
    sweep_receipts(&store, 2 * RETENTION_MS).unwrap();
    assert!(store.github_receipt("agent", "nonce").unwrap().is_none());

    store
        .claim_github_receipt(
            "agent",
            "live",
            "f",
            "owner",
            &json!({}),
            &effects(),
            None,
            1000,
            3 * RETENTION_MS / 1000,
        )
        .unwrap();
    // Even a terminal row cannot be pruned before its live lease ends.
    store
        .finish_github_facade(
            "agent",
            "live",
            "owner",
            "completed",
            &json!("ok"),
            None,
            1001,
        )
        .unwrap();
    // Completion expires its lease, so a separate SQL fixture retains a live lease.
    let conn = rusqlite::Connection::open(_file.path()).unwrap();
    conn.execute(
        "UPDATE github_bot_receipt SET claim_lease_expires_at=?1 WHERE request_nonce='live'",
        [3 * RETENTION_MS],
    )
    .unwrap();
    sweep_receipts(&store, RETENTION_MS + 1002).unwrap();
    assert!(
        store.github_receipt("agent", "live").unwrap().is_some(),
        "live lease pruned"
    );
}

#[test]
fn completed_leg_survives_takeover_and_only_next_leg_dispatches() {
    let (_file, store) = fixture();
    claim(&store, "first", 1000);
    store
        .mark_github_dispatch("agent", "nonce", "first", 0, 1001, "test-request")
        .unwrap();
    store
        .finish_github_effect(
            "agent",
            "nonce",
            "first",
            0,
            &json!("comment-created"),
            1002,
        )
        .unwrap();
    let Claim::Owned(row) = claim(&store, "second", 121000) else {
        panic!("no takeover")
    };
    assert_eq!(row.effects[0].outcome, Some(json!("comment-created")));
    assert!(!store
        .mark_github_dispatch("agent", "nonce", "second", 0, 121001, "test-request")
        .unwrap());
    assert!(store
        .mark_github_dispatch("agent", "nonce", "second", 1, 121001, "test-request")
        .unwrap());
}

#[test]
fn terminal_replay_returns_stored_outcome_without_transport() {
    let (_file, store) = fixture();
    let transport = MockTransport::default();
    claim(&store, "first", 1000);
    store
        .mark_github_dispatch("agent", "nonce", "first", 0, 1001, "test-request")
        .unwrap();
    store
        .finish_github_effect("agent", "nonce", "first", 0, &json!("created"), 1002)
        .unwrap();
    store
        .finish_github_facade(
            "agent",
            "nonce",
            "first",
            "completed",
            &json!({"id": 42}),
            None,
            1003,
        )
        .unwrap();
    let result = retry_effect(&store, &transport, "retry", 121000);
    assert_eq!(
        transport.requests().len(),
        0,
        "terminal replay transmitted a second write"
    );
    let Claim::Replay(row) = result else {
        panic!("completed receipt was re-claimed")
    };
    assert_eq!(row.outcome, Some(json!({"id":42})));
}

#[test]
fn unknown_retry_and_post_sweep_retry_never_transmit() {
    for sweep_first in [false, true] {
        let (_file, store) = fixture();
        let transport = MockTransport::default();
        claim(&store, "first", 1000);
        store
            .mark_github_dispatch("agent", "nonce", "first", 0, 1001, "test-request")
            .unwrap();
        if sweep_first {
            assert_eq!(sweep_receipts(&store, 121000).unwrap().len(), 1);
        }
        let result = retry_effect(&store, &transport, "retry", 121000);
        assert_eq!(
            transport.requests().len(),
            0,
            "unknown receipt re-transmitted"
        );
        let Claim::Unknown(row) = result else {
            panic!("unknown receipt was re-claimed")
        };
        assert_eq!(row.state, "outcome_unknown");
        // The facade maps the unknown receipt to a pending reply, not a new dispatch.
        assert_eq!(
            store
                .github_receipt("agent", "nonce")
                .unwrap()
                .unwrap()
                .effects[0]
                .dispatch_attempted_at,
            Some(1001)
        );
    }
}

#[test]
fn simultaneous_nonce_claims_have_exactly_one_owner() {
    let (_file, store) = fixture();
    let store = Arc::new(store);
    let barrier = Arc::new(Barrier::new(3));
    let workers: Vec<_> = ["first", "second"]
        .into_iter()
        .map(|owner| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            crate::bounded::Task::spawn(move || {
                barrier.wait();
                claim(&store, owner, 1000)
            })
        })
        .collect();
    barrier.wait();
    let claims: Vec<_> = workers
        .into_iter()
        .map(|worker| {
            worker
                .join_timeout(crate::bounded::STORE_WORK_WAIT)
                .expect("claim worker completion")
        })
        .collect();
    assert_eq!(
        claims
            .iter()
            .filter(|result| matches!(result, Claim::Owned(_)))
            .count(),
        1
    );
    assert_eq!(
        claims
            .iter()
            .filter(|result| matches!(result, Claim::InFlight))
            .count(),
        1
    );
    let row = store.github_receipt("agent", "nonce").unwrap().unwrap();
    let winner = claims
        .iter()
        .find_map(|claim| match claim {
            Claim::Owned(row) => row.claim_owner.as_deref(),
            _ => None,
        })
        .unwrap();
    assert_eq!(row.claim_owner.as_deref(), Some(winner));
}

#[test]
fn takeover_rotates_owner_lease_and_baseline_in_one_transaction() {
    let (_file, store) = fixture();
    let Claim::Owned(original) = claim(&store, "first", 1000) else {
        panic!("missing initial claim")
    };
    let Claim::Owned(taken) = claim(&store, "second", 121000) else {
        panic!("missing takeover")
    };
    assert_eq!(taken.claim_owner.as_deref(), Some("second"));
    assert_eq!(taken.claim_lease_expires_at, Some(241000));
    assert_eq!(taken.authority_baseline, json!({"generation":"second"}));
    assert_ne!(taken.authority_baseline, original.authority_baseline);
    let persisted = store.github_receipt("agent", "nonce").unwrap().unwrap();
    assert_eq!(persisted.claim_owner, taken.claim_owner);
    assert_eq!(
        persisted.claim_lease_expires_at,
        taken.claim_lease_expires_at
    );
    assert_eq!(persisted.authority_baseline, taken.authority_baseline);
    assert!(!store
        .mark_github_dispatch("agent", "nonce", "first", 0, 121001, "test-request")
        .unwrap());
    assert!(store
        .mark_github_dispatch("agent", "nonce", "second", 0, 121001, "test-request")
        .unwrap());
}
