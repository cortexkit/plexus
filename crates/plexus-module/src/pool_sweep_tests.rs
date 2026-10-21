use super::*;

/// The scheduler must STAMP each pass, not merely have a stamp available.
///
/// Found by enumerating every state mutator on `HealthState` and asking
/// which had a call-site test, after the same gap appeared three times
/// separately: a health field is written by one production line, and every
/// test that reads the field writes it too, so deleting that line changes
/// nothing anyone asserts.
///
/// The failure direction here is a FALSE ALARM rather than a false
/// all-clear, which is why it would have survived review: without the
/// stamp, `schedulerPassAgeMs` counts from module start and grows forever,
/// so a perfectly healthy scheduler reports the exact signature of a wedged
/// one. That makes the field worse than absent — it is the only thing that
/// can diagnose a stuck pass, and a liveness flag cannot, because a stuck
/// task is still a live one.
///
/// Asserted against a real spawned scheduler and a generous bound: the tick
/// is one second, so a stamping scheduler reports well under 1500ms while
/// an unstamped one reports the full time since construction.
///
/// Mutation-proved: deleting the `stamp_scheduler_pass()` call from the
/// tick fails this while the rest of the suite stays green.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_spawned_scheduler_stamps_each_pass() {
    use subc_protocol::session::ModuleControlResponse;

    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "pass-stamp-{}",
        std::process::id()
    )));
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    });

    let (shutdown, stop) = mpsc::channel::<()>(1);
    let task = crate::test_support::spawn_test_scheduler(Arc::clone(&state), stop);
    // An unstamped scheduler never moves the stamp, so this wait runs to
    // its full bound and the age below is at least that long.
    let stamped = crate::test_support::scheduler_passes(&state.health, 2).await;

    let ModuleControlResponse::HealthCheck { metrics, .. } = state.health.report() else {
        panic!("expected a health check response");
    };
    let age = metrics
        .expect("metrics present")
        .get("schedulerPassAgeMs")
        .and_then(serde_json::Value::as_u64)
        .expect("schedulerPassAgeMs present");
    assert!(
        stamped && age < 1_500,
        "pass age {age}ms means the scheduler is not stamping its passes, so a \
             healthy scheduler reports the signature of a wedged one"
    );

    drop(shutdown);
    task.await.expect("scheduler task joins");
}

/// The scheduler task must actually RUN the pool sweep.
///
/// `sweep_idle` is proven correct in plexus-core, and it had ZERO callers
/// anywhere in the workspace before this: a maintenance operation nobody
/// scheduled, which meant `idle_timeout` described behaviour that never
/// happened and a pooled client outlived the connection that created it.
/// Proving the sweep works says nothing about whether anything invokes it:
/// a correct mechanism nobody calls is indistinguishable from an absent
/// one, so the call site needs its own test.
///
/// Observes the effect through a REALLY SPAWNED scheduler rather than by
/// reading the source: an entry is pooled, and the task must remove it
/// without anyone calling the sweep by hand.
///
/// Uses a deliberately tiny `idle_timeout` because this test asks only
/// whether the sweep is INVOKED. Whether the eviction predicate is right —
/// that an entry past the production timeout goes and a leased one stays —
/// is proven in plexus-core against the real default. Splitting it that way
/// keeps this test measured in ticks rather than minutes.
///
/// Mutation-proved: deleting the `sweep_idle` calls from the tick leaves
/// the entry pooled and fails this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_spawned_scheduler_sweeps_the_transport_pools() {
    use plexus_core::Transport as _;

    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "pool-sweep-{}",
        std::process::id()
    )));

    let mcp_transport = Arc::new(plexus_core::McpRemoteTransport::default());
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: ModuleRuntime::with_stub_credentials_and_mcp_transport(
            Arc::clone(&store),
            Arc::new(StubCredentialSource::with_default_success(
                b"unused".to_vec(),
            )),
            Arc::clone(&mcp_transport),
            None,
        ),
    });

    // Pool an entry. Nothing listens on the endpoint, which is fine: the
    // pool entry is created before the request is attempted, and a failed
    // dispatch leaves exactly the idle entry this test is about.
    crate::test_support::assert_loopback_is_not_proxied();
    let mut config =
        plexus_core::McpRemoteConfig::new(crate::test_support::closed_loopback_url("/mcp"));
    config.idle_timeout = std::time::Duration::from_millis(1);
    mcp_transport.register_connection(plexus_core::McpConnection {
        connection_id: "pooled".to_string(),
        config,
    });
    // Wrapped exactly as production wraps every transport call: this is
    // `reqwest::blocking`, and dropping its runtime on an async worker
    // panics. Without the wrapper this test panics in its own setup, which
    // is a useful demonstration that the hazard is immediate rather than
    // theoretical.
    blocking_section(|| {
        let _ = mcp_transport.dispatch(
            plexus_core::TransportRequest {
                request_id: "sweep-test".to_string(),
                connection_id: "pooled".to_string(),
                action: "read_tool".to_string(),
                args: json!({}),
                credential_fingerprint: "fp".to_string(),
            },
            &plexus_core::ResolvedCredential::new(b"unused".to_vec(), None, 1),
        );
    });
    assert_eq!(
        mcp_transport.connection_count(),
        1,
        "nothing was pooled, so the assertion below would pass vacuously"
    );

    // Wait past the pooled entry's idle timeout BEFORE the scheduler
    // starts.
    //
    // The sweep begins due, so its first pass runs within a millisecond or
    // two of the entry being pooled. `sweep_idle` compares elapsed idle
    // time against the timeout, so at that instant the entry is legitimately
    // still fresh and is kept -- correctly. The pass then consumes the sweep
    // window and the next one is sixty seconds away, long past when this
    // test gives up.
    //
    // So the original test passed only when the first tick happened to land
    // more than a millisecond after pooling, which is most of the time and
    // not all of it: it failed roughly one run in six here and failed in CI.
    // The race is in the test's ordering, not in the sweep -- the entry was
    // not yet idle when the only sweep it would ever see ran.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let (shutdown, stop) = mpsc::channel::<()>(1);
    let task = crate::test_support::spawn_test_scheduler(Arc::clone(&state), stop);
    // One pass is enough because the sweep starts due rather than waiting
    // a full interval.
    assert!(
        crate::test_support::scheduler_passes(&state.health, 2).await,
        "the scheduler must run a pass"
    );

    assert_eq!(
        mcp_transport.connection_count(),
        0,
        "the scheduler tick must sweep idle pooled connections"
    );

    drop(shutdown);
    task.await.expect("scheduler task joins");
}
