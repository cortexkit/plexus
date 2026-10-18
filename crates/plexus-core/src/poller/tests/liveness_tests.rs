use super::*;

fn probe(store: &PlexusStore, source: &str) -> String {
    store
        .register_probe(
            "direct",
            "connection",
            crate::storage::ProbeRegistration {
                name: "liveness",
                actions: &["read_action".into()],
                script_source: source,
                return_schema: &json!({"kind":"bool"}),
                rearm: "always",
                cadence_s: 30,
                fixed_args: &json!({}),
                cursor_state: &json!({}),
            },
        )
        .unwrap()
        .unwrap()
        .subscription_id
}

#[test]
fn a_failed_probe_callback_cannot_be_caught_and_retried() {
    let (store, engine, transport) = poll_engine(json!(true));
    let id = probe(&store, "() => { try { invoke('read_action', {}); } catch (e) {} return invoke('read_action', {}); }");
    transport.set_response_sequence_for_method(
        "read_action",
        "",
        vec![
            MockResponse::VendorError {
                code: "http_503".into(),
                message: "first call failed".into(),
            },
            MockResponse::Success(json!(true)),
        ],
    );
    assert_eq!(
        Poller::new(engine).poll_once("direct", &id),
        PollCycle::VendorFailed {
            code: "http_503".into()
        }
    );
    assert_eq!(transport.requests().len(), 1);
    let sub = store.subscription("direct", &id).unwrap().unwrap();
    assert_eq!(sub.consecutive_vendor_failures, 1);
    assert_eq!(sub.cursor_state, json!({}));
}

#[test]
fn timed_out_probe_feeds_breaker_and_can_resume() {
    let (store, engine, _) = poll_engine(json!(true));
    let id = probe(&store, "() => { while (true) {} }");
    let poller = Poller::new(engine.clone());
    assert_eq!(
        poller.poll_once("direct", &id),
        PollCycle::VendorFailed {
            code: "probe_timeout".into()
        }
    );
    assert_eq!(
        store
            .subscription("direct", &id)
            .unwrap()
            .unwrap()
            .consecutive_vendor_failures,
        1
    );
    for _ in 1..5 {
        assert!(matches!(
            poller.probe_failure_cycle(
                "direct",
                &id,
                &ProbeError::Timeout {
                    elapsed: Duration::from_secs(5)
                }
            ),
            PollCycle::VendorFailed { .. }
        ));
    }
    let now = now_ms();
    store
        .record_poll_attempt("direct", &id, now - 31_000)
        .unwrap();
    let scheduler = crate::scheduler::Scheduler::new(engine, 86_400_000);
    let outcomes = scheduler.run_pass(&["direct".into()], now);
    assert!(outcomes.iter().any(|outcome| matches!(&outcome.cycle, PollCycle::Suspended { reason } if reason == crate::storage::CIRCUIT_BREAKER_SUSPENSION_REASON)));
    assert!(store.resume("direct", &id).unwrap().is_ok());
    assert_eq!(
        store
            .subscription("direct", &id)
            .unwrap()
            .unwrap()
            .cursor_state,
        json!({})
    );
}

#[test]
fn expired_pass_budget_never_dispatches_or_stamps_an_attempt() {
    let (store, engine, transport) = poll_engine(json!({"items":[]}));
    let sub = store
        .subscribe("direct", "connection", "read_action", 30)
        .unwrap()
        .unwrap();
    let cycle = Poller::new(engine).poll_loaded("direct", &sub, Some(std::time::Instant::now()));
    assert!(matches!(cycle, PollCycle::Deferred { reason } if reason == "poll_pass_budget"));
    assert!(transport.requests().is_empty());
    assert_eq!(
        store
            .subscription("direct", &sub.subscription_id)
            .unwrap()
            .unwrap()
            .last_polled_at_ms,
        None
    );
    budget::with_deadline(Some(std::time::Instant::now()), || {
        assert!(CallBudget::new(32).try_take(1).is_none());
    });
}

#[test]
fn mixed_tiebreaker_ids_have_a_transitive_order() {
    let ids = ["2", "02", "10", "1a", "z"];
    for a in ids {
        for b in ids {
            for c in ids {
                if tiebreaker_id_is_greater(a, Some(b)) && tiebreaker_id_is_greater(b, Some(c)) {
                    assert!(
                        tiebreaker_id_is_greater(a, Some(c)),
                        "{a} > {b} > {c} must be transitive"
                    );
                }
            }
        }
    }
}
