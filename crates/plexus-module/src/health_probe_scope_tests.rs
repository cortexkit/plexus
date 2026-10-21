use super::*;

/// The spawned scheduler must probe DEGRADED connections, not only active ones.
///
/// This is the call-site half of the recovery fix. `clear_connection_degraded`
/// and its use inside `refresh` are proven in plexus-core, and both were
/// useless while this filter excluded the only connections
/// with something to recover: a refresh failure sets `degraded`, and the
/// probe that would succeed and clear it declined to look. Nothing else
/// re-runs discovery either -- reads return early from the freshness check
/// and `connect` needs a spent single-use ticket -- so the connection stays
/// stuck indefinitely with the vendor reachable throughout.
///
/// Uses a REST connector because its discovery is synthesized from the
/// manifest, so a real probe runs end to end with no vendor and no network.
/// The probe is observed through a spawned scheduler, because a correct
/// probe function with no reachable scheduler caller cannot recover anyone.
///
/// Mutation-proved: removing the scheduler tick's `run_health_probes` call
/// leaves this row degraded and fails this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_spawned_scheduler_probes_degraded_connections() {
    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "probe-scope-{}",
        std::process::id()
    )));

    let manifest_source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/exa_rest.jsonc"),
    )
    .expect("read rest manifest");
    let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize jsonc");
    let ingested = plexus_core::ingest_value(
        serde_json::from_str::<serde_json::Value>(&normalized).expect("parse manifest"),
    )
    .expect("ingest manifest");
    store
        .upsert_manifest("system", &ingested)
        .expect("store manifest");
    store
        .insert_connection(
            "direct",
            "conn-rest",
            &ingested.manifest.key,
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("connection");
    // The manifest declares api_key auth, so the probe resolves a
    // credential before it can reach discovery. Bound through the real
    // ticket path rather than by writing the column, so the test exercises
    // the same shape production does.
    let ticket = store
        .create_binding_ticket("direct", "conn-rest", b"test:probe-scope-test-handle")
        .expect("binding ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume ticket")
        .expect("connection activated");
    store
        .set_connection_health(
            "direct",
            "conn-rest",
            "degraded",
            &json!({"reason": "catalog_refresh_failed"}),
        )
        .expect("mark degraded");

    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    let (shutdown, stop) = mpsc::channel::<()>(1);
    let task = crate::test_support::spawn_test_scheduler(Arc::clone(&state), stop);
    // The first probe is due immediately; wait for a whole pass so the
    // spawned task, rather than this test, performs the recovery.
    assert!(
        crate::test_support::scheduler_passes(&state.health, 2).await,
        "the scheduler must run a pass"
    );
    let status = store
        .connection("direct", "conn-rest")
        .expect("read")
        .expect("row")
        .status;
    drop(shutdown);
    task.await.expect("scheduler task joins");

    assert_eq!(
        status, "active",
        "the scheduler's health probe must reach a degraded connection and recover it"
    );
}

/// The probe must PUBLISH what it counted, not merely count it.
///
/// `stamp_connections` and the null-until-observed rule are proven in
/// health.rs, and both are worthless if nothing calls them: deleting the
/// stamp from `run_health_probes` left the entire module suite green,
/// because those tests stamp the counts themselves. This observes the
/// numbers through a real probe over a real connection instead.
///
/// The point is operator-facing. Without it, a claim like "the live
/// connector is unaffected by this deploy" can only be taken on the word of
/// whoever made it; with it, the health report answers the question.
///
/// Mutation-proved: dropping the `stamp_connections` call from
/// `run_health_probes` fails this while every other test stays green.
#[test]
fn the_health_probe_publishes_the_connection_counts() {
    use subc_protocol::session::ModuleControlResponse;

    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "probe-counts-{}",
        std::process::id()
    )));

    let manifest_source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/exa_rest.jsonc"),
    )
    .expect("read rest manifest");
    let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize jsonc");
    let ingested = plexus_core::ingest_value(
        serde_json::from_str::<serde_json::Value>(&normalized).expect("parse manifest"),
    )
    .expect("ingest manifest");
    store
        .upsert_manifest("system", &ingested)
        .expect("store manifest");
    store
        .insert_connection(
            "direct",
            "conn-rest",
            &ingested.manifest.key,
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("connection");
    let ticket = store
        .create_binding_ticket("direct", "conn-rest", b"test:probe-counts-test-handle")
        .expect("binding ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume ticket")
        .expect("connection activated");
    store
        .set_connection_health(
            "direct",
            "conn-rest",
            "degraded",
            &json!({"reason": "catalog_refresh_failed"}),
        )
        .expect("mark degraded");

    let state = ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    };

    // Guard against a vacuous pass: before the probe the counts must be
    // null, so a green assertion below cannot come from a stale default.
    let ModuleControlResponse::HealthCheck { metrics, .. } = state.health.report() else {
        panic!("expected a health check response");
    };
    assert_eq!(
        metrics.expect("metrics").get("connections"),
        Some(&serde_json::Value::Null),
        "the fixture must start unobserved"
    );

    run_health_probes(&state);

    let ModuleControlResponse::HealthCheck { metrics, .. } = state.health.report() else {
        panic!("expected a health check response");
    };
    let metrics = metrics.expect("metrics present");
    assert_eq!(
        metrics
            .get("connections")
            .and_then(serde_json::Value::as_u64),
        Some(1),
        "the probe counted a connection but did not publish it"
    );
    // Counted from the rows as they stood at the start of the pass. The
    // probe RECOVERS this connection, so a count taken afterwards would
    // report zero degraded and hide the condition that prompted the work.
    assert_eq!(
        metrics
            .get("connectionsDegraded")
            .and_then(serde_json::Value::as_u64),
        Some(1),
        "the degraded count must describe what the pass set out to check"
    );
}

/// The WHOLE recovery chain, asserted end to end on a production-shaped
/// fixture rather than link by link.
///
/// Each link is tested on its own elsewhere, and that is exactly what made
/// an earlier claim about this wrong: reasoning "the probe runs, so
/// reconcile runs, so ask_first is rewritten" skipped over the fact that
/// the probe declined to look at degraded connections at all. A chain of
/// individually-correct links is not a working chain.
///
/// The fixture is the state a store can be in after migration 8:
/// a connection stuck `degraded` from an earlier refresh failure, and a
/// read action whose `ask_first` still carries the migration's fail-closed
/// default of 1. Both must clear from one probe, because that is precisely
/// what a restage is expected to fix.
#[test]
fn one_probe_clears_both_the_degraded_status_and_the_ask_first_default() {
    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "probe-chain-{}",
        std::process::id()
    )));

    let manifest_source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/exa_rest.jsonc"),
    )
    .expect("read rest manifest");
    let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize jsonc");
    let ingested = plexus_core::ingest_value(
        serde_json::from_str::<serde_json::Value>(&normalized).expect("parse manifest"),
    )
    .expect("ingest manifest");
    let action_name = ingested.manifest.actions_baseline[0].name.clone();
    store
        .upsert_manifest("system", &ingested)
        .expect("store manifest");
    store
        .insert_connection(
            "direct",
            "conn-rest",
            &ingested.manifest.key,
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("connection");
    let ticket = store
        .create_binding_ticket("direct", "conn-rest", b"test:probe-chain-test-handle")
        .expect("binding ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume ticket")
        .expect("connection activated");

    // Reproduce what migration 8 leaves behind: it added the `ask_first`
    // column with a fail-closed default of 1, so every pre-existing row
    // — including reads that never asked before — comes back asking for
    // approval until a refresh recomputes the value from the manifest.
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: "conn-rest".to_string(),
            principal: "direct".to_string(),
            name: action_name.clone(),
            title: None,
            schema: json!({"type": "object"}),
            schema_hash: "sha256:stale".to_string(),
            risk: "read".to_string(),
            severity: "S1".to_string(),
            ask_first: true,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("seed migrated row");
    store
        .set_connection_health(
            "direct",
            "conn-rest",
            "degraded",
            &json!({"reason": "catalog_refresh_failed"}),
        )
        .expect("mark degraded");

    // Both halves of the stuck state must really be present, or the
    // assertions below would pass without the fix doing anything.
    assert_eq!(
        store
            .connection("direct", "conn-rest")
            .expect("read")
            .expect("row")
            .status,
        "degraded"
    );
    assert!(
        store
            .catalog_action("direct", "conn-rest", &action_name)
            .expect("read")
            .expect("row")
            .ask_first,
        "the fixture must start from the migrated fail-closed default"
    );

    let state = ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    };
    run_health_probes(&state);

    assert_eq!(
        store
            .connection("direct", "conn-rest")
            .expect("read")
            .expect("row")
            .status,
        "active",
        "the probe must clear the degraded status"
    );
    assert!(
        !store
            .catalog_action("direct", "conn-rest", &action_name)
            .expect("read")
            .expect("row")
            .ask_first,
        "the same probe must rewrite ask_first from the manifest, or a read \
             keeps asking for approval after the connection recovers"
    );
}

/// The scheduler must not run a health probe on every one-second tick.
///
/// First observe the start-due probe over an empty store, then add a pending
/// connection. Pending connections are counted but never contacted, so a
/// second probe would change only the published count and makes the interval
/// gate observable without waiting sixty seconds or using a vendor.
///
/// Mutation-proved: removing the `health_probe_due` gate updates the count
/// to one on the next tick and fails this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_spawned_scheduler_gates_health_probes_to_their_interval() {
    use subc_protocol::session::ModuleControlResponse;

    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "probe-interval-{}",
        std::process::id()
    )));
    let health = Arc::new(health::HealthState::new());
    let state = Arc::new(ModuleState {
        health: Arc::clone(&health),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    let (shutdown, stop) = mpsc::channel::<()>(1);
    let task = crate::test_support::spawn_test_scheduler(state, stop);

    let initial_metrics = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            health.stamp_heartbeat();
            let ModuleControlResponse::HealthCheck { metrics, .. } = health.report() else {
                unreachable!("HealthState always returns a health check response");
            };
            let metrics = metrics.expect("health report includes metrics");
            if !metrics["connections"].is_null() {
                break metrics;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the start-due scheduler probe runs");
    assert_eq!(
        initial_metrics["connections"],
        json!(0),
        "the initial probe must observe the empty store before the gate is tested"
    );

    store
        .insert_connection(
            "direct",
            "conn-pending",
            "unused-app",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("seed pending connection");
    // Wait for a whole later pass. An ungated probe would now publish the
    // pending row; a correctly gated probe keeps the initial observation.
    assert!(
        crate::test_support::scheduler_passes(&health, 2).await,
        "the scheduler must keep running passes"
    );
    health.stamp_heartbeat();
    let ModuleControlResponse::HealthCheck { metrics, .. } = health.report() else {
        unreachable!("HealthState always returns a health check response");
    };
    let metrics = metrics.expect("health report includes metrics");
    drop(shutdown);
    task.await.expect("scheduler task joins");

    assert_eq!(
        metrics["connections"],
        json!(0),
        "the next scheduler pass must not run another health probe"
    );
}
