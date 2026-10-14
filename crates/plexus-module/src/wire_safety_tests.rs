use super::*;
use crate::bounded::recv_within;
use std::time::Duration;

fn state() -> Arc<ModuleState> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let namespace = format!(
        "wire-safety-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let store = Arc::new(
        PlexusStore::open(&cortexkit_store_types::StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.into(),
            storage_namespace: namespace,
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap(),
    );
    Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(store),
    })
}
fn frame(kind: FrameType, channel: u16, corr: u64, value: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        kind,
        wire::control_flags(),
        channel,
        if channel == 0 { 0 } else { 1 },
        corr,
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_capacity_includes_waiting_and_held_calls_but_not_controls() {
    let state = state();
    let routes = Arc::new(RouteBindings::new());
    routes.insert(1, 1, Principal::Direct).unwrap();
    let blocked = routes
        .blocking
        .clone()
        .acquire_many_owned(MAX_BLOCKING_REQUESTS as u32)
        .await
        .unwrap();
    let (writer, mut rx) = mpsc::channel(512);
    for corr in 0..256u64 {
        handle_frame(
            frame(
                FrameType::Request,
                1,
                corr,
                json!({"name":"connections","arguments":{"op":"list"}}),
            ),
            &writer,
            &state,
            &routes,
        )
        .await
        .unwrap();
    }
    assert_eq!(
        routes.in_flight.available_permits(),
        0,
        "held and waiting calls must retain their admission permits"
    );
    handle_frame(
        frame(FrameType::Request, 1, 257, json!({})),
        &writer,
        &state,
        &routes,
    )
    .await
    .unwrap();
    let refused = recv_within(rx.recv(), Duration::from_secs(5), "overload reply").await;
    let body: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(refused.header.ty, FrameType::Error);
    assert_eq!(refused.header.corr, 257);
    assert_eq!(
        body["code"], "resource_exhausted",
        "257th request must be refused"
    );
    assert_eq!(body["retryable"], true);
    assert_eq!(body["retry_after_ms"], 1000);
    handle_frame(
        frame(FrameType::Ping, 0, 300, Value::Null),
        &writer,
        &state,
        &routes,
    )
    .await
    .unwrap();
    assert_eq!(
        recv_within(rx.recv(), Duration::from_secs(5), "pong")
            .await
            .header
            .ty,
        FrameType::Pong
    );
    handle_frame(
        frame(
            FrameType::Request,
            0,
            301,
            serde_json::to_value(ModuleControlRequest::HealthCheck {}).unwrap(),
        ),
        &writer,
        &state,
        &routes,
    )
    .await
    .unwrap();
    let health = recv_within(rx.recv(), Duration::from_secs(5), "health response").await;
    assert_eq!(
        health.header.ty,
        FrameType::Response,
        "health must bypass request admission"
    );
    drop(blocked);
    for _ in 0..256 {
        recv_within(
            rx.recv(),
            Duration::from_secs(10),
            "waiting request completes",
        )
        .await;
    }
}

#[tokio::test]
async fn thirty_third_blocking_job_waits_without_refusal() {
    let routes = RouteBindings::new();
    let slots = routes
        .blocking
        .clone()
        .acquire_many_owned(32)
        .await
        .unwrap();
    let waiting = routes.blocking.clone().acquire_owned();
    tokio::pin!(waiting);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut waiting)
            .await
            .is_err(),
        "33rd blocking job must wait"
    );
    drop(slots);
    assert!(tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .unwrap()
        .is_ok());
}

#[tokio::test]
async fn route_goodbye_removes_only_its_epoch() {
    let routes = Arc::new(RouteBindings::new());
    routes.insert(3, 1, Principal::Direct).unwrap();
    routes.insert(3, 2, Principal::Direct).unwrap();
    let (writer, _) = mpsc::channel(1);
    handle_frame(
        frame(FrameType::Goodbye, 3, 0, Value::Null),
        &writer,
        &state(),
        &routes,
    )
    .await
    .unwrap();
    assert!(
        routes.binding(3, 1).unwrap().is_none(),
        "closed route must lose its authority"
    );
    assert!(routes.binding(3, 2).unwrap().is_some());
}

#[test]
fn unknown_tools_require_connector_home() {
    assert!(
        connector_home::tool_effect("future_tool", None),
        "unknown tools must fail closed"
    );
    assert!(!connector_home::tool_effect("events_get", None));
}

#[test]
fn body_error_from_claim_peer_is_not_a_success() {
    let error = connector_home::claim_reply(
        json!({"error":{"code":"verify_failed","message":"invalid evidence"}}),
    )
    .unwrap_err();
    assert_eq!(
        error.code, "verify_failed",
        "claim body errors must retain their refusal code"
    );
    assert_eq!(
        connector_home::claim_reply(json!({"result":{"epoch":9}})).unwrap(),
        json!({"epoch":9})
    );
}

#[test]
fn health_report_reads_the_last_store_snapshot() {
    let state = state();
    *state.health.store_metrics.lock().unwrap() =
        json!({"outboxDepth":17,"effectiveCiCadenceS":300});
    let report = serde_json::to_value(connector_home_health(&state)).unwrap();
    assert_eq!(
        report["metrics"]["outboxDepth"], 17,
        "control health must read the cache, not SQLite"
    );
    assert!(report["metrics"].get("outbox_depth").is_none());
}

#[test]
#[ignore = "manual performance measurement"]
fn measure_static_catalog_and_reply_rendering() {
    let started = std::time::Instant::now();
    for _ in 0..100 {
        std::hint::black_box(
            tool_provider::reply(
                cortexkit_role_tool_provider::ops::TOOL_CATALOG,
                &serde_json::Map::new(),
            )
            .unwrap(),
        );
    }
    println!("catalog_100_us={}", started.elapsed().as_micros());
    let payload = json!({"result":{"body":"x".repeat(200_000)}});
    let started = std::time::Instant::now();
    for _ in 0..100 {
        std::hint::black_box(with_call_tool_result(Some("events_get"), payload.clone()));
    }
    println!("render_200KB_100_us={}", started.elapsed().as_micros());
}

#[test]
fn optional_ceremony_strings_and_policy_filter_are_not_silently_defaulted() {
    let state = state();
    for field in ["risk_ceiling", "connection_id"] {
        let mut request = json!({"app_key":"deepwiki","action_selectors":["*"]});
        request[field] = json!(7);
        let reply = ceremony::issue_ticket(&state, "direct", &request);
        assert_eq!(
            reply["error"]["code"], "invalid_request",
            "optional ticket strings must be validated"
        );
        assert_eq!(reply["error"]["field"], field);
    }
    for field in ["grantee_principal", "authority_kind", "risk_ceiling"] {
        let mut request = json!({"connection_id":"conn"});
        request[field] = json!(false);
        let reply = ceremony::grant(&state, "direct", &request);
        assert_eq!(
            reply["error"]["code"], "invalid_request",
            "optional grant strings must be validated"
        );
        assert_eq!(reply["error"]["field"], field);
    }
    let reply = ceremony::list_policies(&state, "direct", &json!({"connection_id":42}));
    assert_eq!(
        reply["error"]["code"], "invalid_request",
        "a malformed filter must not widen the read"
    );
}

#[test]
fn publish_errors_are_isolated_per_module_instance() {
    let left = health::HealthState::new();
    let right = health::HealthState::new();
    left.record_publish_error("left broker unavailable");
    assert_eq!(
        left.last_publish_error().as_deref(),
        Some("left broker unavailable")
    );
    assert!(
        right.last_publish_error().is_none(),
        "publish errors must not leak across instances"
    );
    left.clear_publish_error();
    assert!(left.last_publish_error().is_none());
}

#[test]
fn diagnostic_names_are_bounded_and_escape_controls() {
    let name = diagnostic_label(&format!("bad\nname{}", "x".repeat(1000)));
    assert!(!name.contains('\n'));
    assert!(name.len() < 800, "diagnostic label must be bounded");
    assert!(name.ends_with("..."));
}

#[test]
fn boot_catalog_refusal_names_the_input_file() {
    let scratch = Scratch::directory("refused-catalog-path");
    let path = scratch.path().join("broken_vendor.jsonc");
    std::fs::write(&path, "{\"bogus\":true}").unwrap();
    let state = state();
    let error = ingest_catalog_from(state.store(), scratch.path())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(&path.display().to_string()),
        "catalog refusal must name its file: {error}"
    );
}

#[test]
fn permissions_refuse_unknown_top_level_fields() {
    let state = state();
    let reply = permissions::run(
        &state,
        "direct",
        Some(&CallMode::Classic),
        None,
        "permissions.list",
        json!({"method":"permissions.list","params":{},"typo":true})
            .as_object()
            .unwrap(),
    );
    assert_eq!(
        reply["error"]["code"], "invalid_request",
        "unknown top-level permissions fields must be refused"
    );
    assert_eq!(reply["error"]["field"], "typo");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scope_describe_control_reply_bypasses_full_request_budget() {
    use plexus_core::scope::ScopeReader;
    let routes = Arc::new(RouteBindings::new());
    let _held = routes
        .in_flight
        .clone()
        .acquire_many_owned(256)
        .await
        .unwrap();
    let (writer, mut outbound) = mpsc::channel(4);
    let replies = Arc::new(PendingControlReplies::default());
    let scope_reader = DaemonScopeReader::new(writer.clone(), PROTOCOL_VERSION, replies.clone());
    let described = tokio::task::spawn_blocking(move || {
        scope_reader.describe("reserved:prefrontal-core", "worker-1")
    });
    let request = recv_within(outbound.recv(), Duration::from_secs(5), "scope request").await;
    let (mut peer, mut reader) = tokio::io::duplex(8192);
    let dispatcher =
        tokio::spawn(
            async move { dispatch_loop(&mut reader, writer, state(), routes, replies).await },
        );
    write_frame(
        &mut peer,
        &frame(
            FrameType::Response,
            0,
            request.header.corr,
            serde_json::to_value(
                subc_protocol::session::ModuleControlResponseToModule::ScopeDescribe {
                    status: subc_protocol::scope::ScopeStatus::Live,
                    scope_epoch: Some(7),
                    daemon_incarnation: "test-incarnation".into(),
                    owner_synced: true,
                    owner_configured: true,
                    scope: None,
                },
            )
            .unwrap(),
        ),
    )
    .await
    .unwrap();
    let description = tokio::time::timeout(Duration::from_secs(5), described)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        description.status,
        plexus_core::scope::ScopeStatus::Live,
        "scope reply must bypass request saturation"
    );
    drop(peer);
    tokio::time::timeout(Duration::from_secs(5), dispatcher)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

fn file_state(label: &str) -> (Scratch, Arc<ModuleState>) {
    let scratch = Scratch::database(label);
    let store = Arc::new(
        PlexusStore::open(&cortexkit_store_types::StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.into(),
            storage_namespace: scratch.to_string_lossy().into_owned(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(store),
    });
    (scratch, state)
}

#[test]
fn refused_grant_inspection_records_the_real_actor_and_decision() {
    let (scratch, state) = file_state("inspection-journal-identity");
    let reply = grants_would_ask::run(
        &state,
        "reserved:basal",
        None,
        json!({"method":"grants.would_ask","params":{}})
            .as_object()
            .unwrap(),
    );
    assert_eq!(reply["error"]["code"], "flow_scope_required");
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    let (actor, decision, gate): (String, String, String) = db
        .query_row(
            "SELECT actor,decision,gate FROM audit_journal WHERE action='grants.would_ask'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (actor, decision, gate),
        ("module".into(), "deny".into(), "grants.would_ask".into()),
        "grant inspection must audit its actual actor and refusal"
    );
}

#[test]
fn unavailable_grant_target_is_not_reported_as_malformed() {
    let state = state();
    let reply = grants_would_ask::run(&state, "reserved:prefrontal-core", None,
        json!({"method":"grants.would_ask","params":{"flow_id":"f1","items":[{"tool":"invoke","connection":"missing","action":"read"}]}}).as_object().unwrap());
    let reason = reply["result"]["items"][0]["reason"].as_str().unwrap();
    assert_ne!(
        reason, "invalid_target",
        "an unavailable target must retain its governance reason"
    );
}

#[test]
fn revoked_connections_are_not_counted_as_probe_work() {
    let (scratch, state) = file_state("probe-count-revoked");
    crate::bus::tests::seed_connection_and_subscription(state.store(), "conn-1");
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    assert_eq!(
        db.execute(
            "UPDATE connections SET status='revoked' WHERE connection_id='conn-1'",
            []
        )
        .unwrap(),
        1
    );
    run_health_probes(&state);
    let report = serde_json::to_value(state.health.report()).unwrap();
    assert_eq!(
        report["metrics"]["connections"], 0,
        "revoked connections must not count as probe work"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn journal_failure_preserves_management_and_binding_refusals() {
    let (scratch, state) = file_state("journal-error-survival");
    let routes = Arc::new(RouteBindings::new());
    routes
        .insert(
            1,
            1,
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        )
        .unwrap();
    let request = frame(
        FrameType::Request,
        1,
        10,
        json!({"name":"github","arguments":{"op":"bindings.read","connection_id":"missing"}}),
    );
    let object: Value = serde_json::from_slice(&request.body).unwrap();
    let original =
        facade_tool_reply(&request, object.as_object().unwrap(), &state, &routes).unwrap();
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    db.execute_batch("CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_journal BEGIN SELECT RAISE(ABORT, 'audit sink unavailable'); END;").unwrap();
    let (writer, mut replies) = mpsc::channel(2);
    handle_management_request(
        RouteFrameContext {
            version: PROTOCOL_VERSION,
            channel: 1,
            epoch: 1,
            correlation: 9,
        },
        manifest::GITHUB_GRANT_OP,
        &json!({}),
        &writer,
        &state,
        &routes,
    )
    .await
    .expect("original authority refusal must survive audit failure");
    let refused = recv_within(replies.recv(), Duration::from_secs(5), "management refusal").await;
    let body: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(body["error"]["code"], "operator_authority_required");
    assert_eq!(body["warning"]["code"], "audit_append_failed");
    handle_tool_request(request, &writer, &state, &routes)
        .await
        .expect("bindings.read reply must survive audit failure");
    let replied = recv_within(replies.recv(), Duration::from_secs(5), "binding refusal").await;
    let body: Value = serde_json::from_slice(&replied.body).unwrap();
    assert_eq!(
        body["error"], original["error"],
        "audit failures must preserve the binding refusal"
    );
    assert_eq!(body["warning"]["code"], "audit_append_failed");
}

#[test]
fn quota_configuration_records_a_write_not_a_read() {
    let (scratch, state) = file_state("quota-record-risk");
    let reply = ceremony::set_web_search_limit(
        &state,
        "direct",
        &json!({
            "backend":state.runtime.web_search.backend_name(), "per_caller_per_minute":30,
            "per_backend_per_minute":60, "dry_run":false,
        }),
    );
    assert_eq!(reply["result"]["outcome"], "set");
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    let risk: String = db
        .query_row(
            "SELECT risk FROM audit_journal WHERE action='set_web_search_limit'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        risk, "write",
        "quota configuration must be audited as a mutation"
    );
}
