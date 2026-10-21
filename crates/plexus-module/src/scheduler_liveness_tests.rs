use super::*;

/// A scheduler with active work that fails every poll must differ from an
/// idle scheduler even when both remain alive and keep their heartbeat fresh.
/// Drive the real scheduler so missing counter updates cannot pass the test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_scheduler_is_distinguishable_from_an_idle_one() {
    let health = Arc::new(health::HealthState::new());
    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "sched-outcomes-{}",
        std::process::id()
    )));

    // A non-operator subscription with no audit history proves the spawned
    // tick discovers owners from live scheduler state. Its mock transport
    // returns a vendor failure while the credential path succeeds, leaving
    // the subscription active for later retries. That is the shape of a real
    // broken connector, and it is what used to render as idleness.
    let subscription_owner = "subscription-owner";
    let manifest_source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github.jsonc"),
    )
    .expect("read the shipped github manifest");
    let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize manifest");
    let ingested = plexus_core::ingest_value(
        serde_json::from_str::<Value>(&normalized).expect("parse manifest"),
    )
    .expect("ingest manifest");
    store
        .upsert_manifest("system", &ingested)
        .expect("seed manifest");
    store
        .insert_connection(
            subscription_owner,
            "conn-sched",
            &ingested.manifest.key,
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("seed connection");
    let ticket = store
        .create_binding_ticket(subscription_owner, "conn-sched", b"test:mock-handle")
        .expect("bind mock credential handle");
    store
        .connect_with_ticket(subscription_owner, &ticket.ticket_id)
        .expect("consume initial ticket")
        .expect("activate scheduler fixture");
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: "conn-sched".to_string(),
            principal: subscription_owner.to_string(),
            name: "list_issues".to_string(),
            title: None,
            // The argument names GitHub's MCP server declares for
            // list_issues, which include the shipped poll shape's request
            // constants; governance refuses an undeclared argument, and
            // this poll must reach the failing vendor.
            schema: json!({
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "after": {"type": "string"},
                    "direction": {"type": "string"},
                    "orderBy": {"type": "string"},
                    "perPage": {"type": "number"},
                    "since": {"type": "string"},
                    "state": {"type": "string"}
                }
            }),
            schema_hash: "sha256:sched-outcomes".to_string(),
            risk: "read".to_string(),
            severity: "S1".to_string(),
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
            ask_first: false,
        })
        .expect("seed catalog action");
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "grant-sched-outcomes".to_string(),
            principal: subscription_owner.to_string(),
            connection_id: "conn-sched".to_string(),
            grantee_principal: subscription_owner.to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["list_issues".to_string()],
            authority_kind: "poll".to_string(),
            expires_at: Some(i64::MAX / 2),
        })
        .expect("seed poll grant");
    store
        .subscribe_with_cursor_state(
            subscription_owner,
            "conn-sched",
            "list_issues",
            1,
            &json!({}),
            &json!({"owner": "cortexkit", "repo": "plexus"}),
        )
        .expect("subscribe")
        .expect("the shipped manifest must be subscribable");
    assert!(
        store
            .list_audit(subscription_owner)
            .expect("read audit history")
            .is_empty(),
        "the scheduler owner must have no audit rows before the call-site check"
    );

    let transport = Arc::new(MockTransport::default());
    transport.set_response(plexus_core::transport::MockResponse::VendorError {
        code: "vendor_down".to_string(),
        message: "vendor is unavailable".to_string(),
    });
    let state = Arc::new(ModuleState {
        health: Arc::clone(&health),
        runtime: ModuleRuntime::with_stub_credentials_and_mock_transport(
            Arc::clone(&store),
            Arc::new(StubCredentialSource::with_default_success(
                b"mock-credential".to_vec(),
            )),
            transport,
        ),
    });
    let (shutdown, stop) = mpsc::channel::<()>(1);
    let task = crate::test_support::spawn_test_scheduler(Arc::clone(&state), stop);

    // A whole pass selects and attempts the subscription.
    assert!(
        crate::test_support::scheduler_passes(&health, 2).await,
        "the scheduler must run a pass"
    );
    // Cross the real stall threshold without making a scheduler wiring test
    // sleep for fifteen minutes. All other state below still comes from the
    // spawned production task.
    health.backdate_scheduler_success(health::scheduler_stall_threshold_ms_for_test(1) + 1);
    health.stamp_heartbeat();
    let (status, detail, metrics) = match health.report() {
        subc_protocol::session::ModuleControlResponse::HealthCheck {
            status,
            detail,
            metrics,
        } => (status, detail, metrics.expect("metrics present")),
        other => panic!("expected a health check, got {other:?}"),
    };

    drop(shutdown);
    task.await.expect("scheduler task joins");

    assert_eq!(
        metrics["schedulerAlive"],
        json!(true),
        "the control: this scheduler IS alive, which is exactly why the \
             alive flag cannot distinguish these two states"
    );
    assert!(
        metrics["schedulerPollsAttempted"].as_u64().unwrap_or(0) > 0,
        "the scheduler attempted no poll, so this proves nothing about a \
             failing one: {metrics}"
    );
    assert_eq!(
        metrics["schedulerPollsCompleted"],
        json!(0),
        "the configured vendor failure must not complete a poll: {metrics}"
    );
    assert_eq!(
        status,
        subc_protocol::session::HealthStatus::Degraded,
        "the spawned scheduler must feed the active-work side of the stall \
             predicate; deleting that production call must leave this incorrectly ok"
    );
    assert!(
        detail
            .as_deref()
            .is_some_and(|value| value.contains("no poll has completed")),
        "the health detail must identify missing scheduler progress: {detail:?}"
    );
    assert_eq!(
        metrics["schedulerSuccessAgeMs"],
        Value::Null,
        "the success age must stay null until a poll actually succeeds, or \
             never-worked reads as worked-at-boot: {metrics}"
    );
    // The pass-duration gauge shares this test's spawned scheduler rather
    // than getting its own, because what needs proving is identical: that
    // the TICK invokes it. Stamping the gauge directly passes with the call
    // site deleted, which is how an uninvoked mechanism reaches production
    // looking correct.
    //
    // Asserted as non-null rather than as a value, since a real pass takes
    // however long the machine takes. Null here means the tick polled
    // something and never recorded how long it took -- exactly the state
    // that leaves the sequential poller's head-of-line cost unmeasurable.
    assert!(
        !metrics["schedulerPassMaxMs"].is_null(),
        "a pass that attempted a poll must record its duration: {metrics}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
/// Starting and stopping the real scheduler must update its liveness flag;
/// a standalone guard test would not prove that the task constructs a guard.
async fn the_spawned_scheduler_holds_a_liveness_guard() {
    let health = Arc::new(health::HealthState::new());
    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "sched-liveness-{}",
        std::process::id()
    )));
    let state = Arc::new(ModuleState {
        health: Arc::clone(&health),
        runtime: runtime_for_test(store),
    });

    let (shutdown, stop) = mpsc::channel::<()>(1);
    let task = spawn_trigger_scheduler(
        Arc::clone(&state),
        stop,
        DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY,
    );

    // Wait, with a generous bound, for the task to reach its loop and
    // construct the guard; a fixed short sleep assumed it is polled at once.
    let alive = crate::test_support::eventually(std::time::Duration::from_secs(20), || {
        health.stamp_heartbeat();
        match health.report() {
            subc_protocol::session::ModuleControlResponse::HealthCheck { metrics, .. } => metrics
                .and_then(|value| value["schedulerAlive"].as_bool())
                .unwrap_or(false),
            other => panic!("expected a health check, got {other:?}"),
        }
    })
    .await;
    assert!(
        alive,
        "a running scheduler must report alive, or the second assertion \
             below would pass for the wrong reason"
    );

    drop(shutdown);
    task.await.expect("scheduler task joins");

    health.stamp_heartbeat();
    let alive_after = match health.report() {
        subc_protocol::session::ModuleControlResponse::HealthCheck { metrics, .. } => metrics
            .and_then(|value| value["schedulerAlive"].as_bool())
            .unwrap_or(false),
        other => panic!("expected a health check, got {other:?}"),
    };
    assert!(
        !alive_after,
        "a stopped scheduler must report dead; the task is not holding a \
             liveness guard"
    );
}
