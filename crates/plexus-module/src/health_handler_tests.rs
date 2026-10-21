use super::*;

/// A health-check handler must report state without probing a recoverable connection.
///
/// The handler runs inline on the dispatch loop and the supervisor waits only
/// five seconds for its response. A sequential vendor probe belongs on the
/// scheduler task: answering this request must leave a connection that needs
/// recovery unchanged while still returning a fresh, populated health report.
///
/// Mutation-proved: restoring `run_health_probes` in the HealthCheck arm
/// recovers this REST connection and fails the unchanged-status assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_health_check_reports_without_probing_recoverable_connections() {
    use subc_protocol::session::{HealthStatus, ModuleControlResponse};

    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("handler-without-probe-{}", std::process::id()),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));
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
        .create_binding_ticket("direct", "conn-rest", b"test:handler-without-probe-handle")
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

    let (writer, mut responses) = mpsc::channel(4);
    let health = Arc::new(health::HealthState::new());
    let state = Arc::new(ModuleState {
        health: Arc::clone(&health),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    let frame = Frame::build(
        FrameType::Request,
        wire::control_flags(),
        0,
        0,
        77,
        serde_json::to_vec(&subc_protocol::session::ModuleControlRequest::HealthCheck {})
            .expect("serialize health check"),
    )
    .expect("build health check frame");

    handle_control_request(frame, &writer, &state, &Arc::new(RouteBindings::new()))
        .await
        .expect("health check handled");

    let response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "health response frame",
    )
    .await;
    let body: ModuleControlResponse =
        serde_json::from_slice(&response.body).expect("health response body");
    let ModuleControlResponse::HealthCheck {
        status,
        detail,
        metrics,
    } = body
    else {
        panic!("expected a health check response");
    };
    assert_eq!(
        status,
        HealthStatus::Ok,
        "health check reports cached state; detail={detail:?}"
    );
    let metrics = metrics.expect("health report includes metrics");

    assert!(
        metrics.get("schedulerAlive").is_some(),
        "the response must carry the regular health metrics: {metrics}"
    );
    assert_eq!(
        store
            .connection("direct", "conn-rest")
            .expect("read")
            .expect("row")
            .status,
        "degraded",
        "answering health.check must not perform the recovery probe"
    );
}
