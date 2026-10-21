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
    for channel in 1..=4 {
        routes
            .insert(
                channel,
                1,
                Principal::Reserved {
                    module_id: format!("caller-{channel}"),
                },
            )
            .unwrap();
    }
    let blocked = routes
        .blocking
        .clone()
        .acquire_many_owned(MAX_BLOCKING_REQUESTS as u32)
        .await
        .unwrap();
    let (writer, mut rx) = mpsc::channel(512);
    for corr in 0..MAX_IN_FLIGHT_REQUESTS as u64 {
        handle_frame(
            frame(
                FrameType::Request,
                (corr / 64 + 1) as u16,
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
    for _ in 0..MAX_IN_FLIGHT_REQUESTS {
        recv_within(
            rx.recv(),
            Duration::from_secs(10),
            "waiting request completes",
        )
        .await;
    }
}

/// A request that finds every blocking slot taken waits for one instead of
/// being refused: it is answered only after a slot frees, and the answer is
/// the request's own reply rather than a capacity error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_beyond_blocking_capacity_waits_for_a_slot() {
    let state = state();
    let routes = Arc::new(RouteBindings::new());
    routes
        .insert(
            1,
            1,
            Principal::Reserved {
                module_id: "caller".into(),
            },
        )
        .unwrap();
    let slots = routes
        .blocking
        .clone()
        .acquire_many_owned(MAX_BLOCKING_REQUESTS as u32)
        .await
        .unwrap();
    let (writer, mut rx) = mpsc::channel(4);
    handle_frame(
        frame(
            FrameType::Request,
            1,
            7,
            json!({"name":"connections","arguments":{"op":"list"}}),
        ),
        &writer,
        &state,
        &routes,
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "a request must wait while every blocking slot is taken, not be answered"
    );
    drop(slots);
    let reply = recv_within(rx.recv(), Duration::from_secs(10), "queued request reply").await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply.header.corr, 7);
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "the queued request must be served once a slot frees: {body}"
    );
    assert!(body["error"].is_null(), "{body}");
}

#[tokio::test]
async fn route_goodbye_removes_only_its_epoch() {
    let routes = Arc::new(RouteBindings::new());
    routes.insert(3, 1, Principal::Direct).unwrap();
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
    routes.insert(3, 2, Principal::Direct).unwrap();
    // The daemon may resend an old pair's close after the channel has been reused.
    handle_frame(
        frame(FrameType::Goodbye, 3, 0, Value::Null),
        &writer,
        &state(),
        &routes,
    )
    .await
    .unwrap();
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
fn body_error_from_role_peer_is_not_a_success() {
    let error = connector_home::role_reply(
        json!({"error":{"code":"claim_integrity_failed","message":"invalid evidence"}}),
    )
    .unwrap_err();
    assert_eq!(
        error.code, "claim_integrity_failed",
        "role body errors must retain their refusal code"
    );
    assert_eq!(
        connector_home::role_reply(json!({"result":{"epoch":9}})).unwrap(),
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
fn diagnostic_labels_keep_128_characters_then_mark_the_cut() {
    let exact = "é".repeat(128);
    let counted = "label cut after a character count";
    assert_eq!(diagnostic_label(&exact), "\\u{e9}".repeat(128), "{counted}");
    let long = format!("a\n{}", "b".repeat(200));
    assert_eq!(
        diagnostic_label(&long),
        format!("a\\n{}...", "b".repeat(126)),
        "{counted}"
    );
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
        .acquire_many_owned(MAX_IN_FLIGHT_REQUESTS as u32)
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

async fn reply_to(value: Value) -> Value {
    let routes = Arc::new(RouteBindings::new());
    routes.insert(1, 1, Principal::Direct).unwrap();
    let (writer, mut rx) = mpsc::channel(1);
    handle_tool_request(
        frame(FrameType::Request, 1, 900, value),
        &writer,
        &state(),
        &routes,
    )
    .await
    .unwrap();
    serde_json::from_slice(
        &recv_within(rx.recv(), Duration::from_secs(5), "tool reply")
            .await
            .body,
    )
    .unwrap()
}

#[tokio::test]
async fn oversized_body_is_refused_before_json_decoding() {
    let reply = reply_to(
        json!({"name":"connections", "arguments":{"op":"list"}, "padding":"x".repeat(1024 * 1024)}),
    )
    .await;
    assert_eq!(reply["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn large_ack_batch_remains_compatible_with_unpaged_consumers() {
    let ids: Vec<String> = (0..1001).map(|id| format!("unknown-{id}")).collect();
    let reply = reply_to(json!({"name":"events", "arguments":{"op":"ack", "event_ids":ids}})).await;
    assert_eq!(reply["result"]["acked"], 0);
    assert_eq!(reply["result"]["unacked"].as_array().unwrap().len(), 1001);
}

#[tokio::test]
async fn oversized_probe_script_is_refused_before_registration() {
    let reply = reply_to(json!({"name":"events", "arguments":{"op":"register_probe", "connection":"missing", "name":"probe", "cadence_s":30,"actions":[],"script_source":"x".repeat(64 * 1024 + 1),"rearm":"once","return_schema":{}}})).await;
    assert_eq!(reply["error"]["code"], "invalid_request");
}

#[test]
fn oversized_would_ask_batch_is_refused_before_evaluation() {
    let request = json!({"method":"grants.would_ask","params":{"agent_id":"agent","flow_id":"flow","items":vec![json!({"tool":"invoke","connection":"missing","action":"read"});101]}});
    let reply = grants_would_ask::run(
        &state(),
        "reserved:prefrontal-core",
        None,
        request.as_object().unwrap(),
    );
    assert_eq!(reply["error"]["code"], "invalid_request");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_refuses_non_classic_direct_routes() {
    let routes = Arc::new(RouteBindings::new());
    routes
        .insert_mode(1, 1, Principal::Direct, None, CallMode::Codemode)
        .unwrap();
    let (writer, mut rx) = mpsc::channel(1);
    handle_tool_request(
        frame(
            FrameType::Request,
            1,
            900,
            json!({"method":"plexus.admin.list_grants","params":{}}),
        ),
        &writer,
        &state(),
        &routes,
    )
    .await
    .unwrap();
    let reply: Value = serde_json::from_slice(
        &recv_within(rx.recv(), Duration::from_secs(5), "management refusal")
            .await
            .body,
    )
    .unwrap();
    assert_eq!(reply["error"]["code"], "operator_authority_required");
}

#[tokio::test]
async fn management_refuses_retired_identity_fields() {
    let reply =
        reply_to(json!({"method":"plexus.admin.list_grants","params":{"assertion":null}})).await;
    assert_eq!(reply["error"]["code"], "argument_undeclared");
}

#[test]
fn audit_failure_warning_does_not_expose_backend_errors() {
    let mut response = json!({"result":{"ok":true}});
    warn_audit_failed(&mut response, "bindings read", &"private_constraint canary");
    assert_eq!(response["warning"]["code"], "audit_append_failed");
    assert!(!response.to_string().contains("private_constraint"));
}

#[tokio::test(start_paused = true)]
async fn hello_ack_wait_is_bounded() {
    let (_writer, mut reader) = tokio::io::duplex(64);
    let reply = tokio::time::timeout(Duration::from_secs(6), expect_hello_ack(&mut reader)).await;
    assert!(reply.is_ok(), "HELLO must fail before the outer deadline");
    assert!(reply
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("HELLO_ACK timeout"));
}

#[tokio::test(start_paused = true)]
async fn queued_request_expires_before_work_capacity_returns() {
    let state = state();
    let routes = Arc::new(RouteBindings::new());
    routes.insert(1, 1, Principal::Direct).unwrap();
    let _blocked = routes
        .blocking
        .clone()
        .acquire_many_owned(MAX_BLOCKING_REQUESTS as u32)
        .await
        .unwrap();
    let (writer, mut rx) = mpsc::channel(1);
    handle_frame(
        frame(
            FrameType::Request,
            1,
            777,
            json!({"name":"connections","arguments":{"op":"list"}}),
        ),
        &writer,
        &state,
        &routes,
    )
    .await
    .unwrap();
    let reply = recv_within(rx.recv(), Duration::from_secs(111), "queue timeout reply").await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["error"]["code"], "resource_exhausted");
    assert_eq!(reply.header.corr, 777);
}

#[test]
fn large_bot_reply_text_remains_a_full_envelope() {
    let envelope = json!({"result":{"status":"completed", "payload":"x".repeat(256 * 1024)}});
    for tool in [manifest::GITHUB_TOOL, manifest::GITHUB_REACT_TOOL] {
        let reply = with_call_tool_result(Some(tool), envelope.clone());
        let decoded: Value =
            serde_json::from_str(reply["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, envelope);
    }
}

#[test]
fn decision_plane_refusal_explains_inactive_execution() {
    let reply = denial_response(&plexus_core::Denial::NeedsDecisionPlane(Box::new(
        plexus_core::governance::DecisionPlaneEnvelope {
            request_id: "r".into(),
            connection_id: "c".into(),
            action: "a".into(),
            args_hash: "h".into(),
            schema_hash: "s".into(),
            severity: plexus_core::Severity::S3,
            expires_at_ms: 1,
        },
    )));
    assert_eq!(reply["error"]["code"], "needs_decision_plane");
    assert_eq!(
        reply["error"]["message"],
        "S3/S4 execution is not active: no production decision plane is configured."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_principal_cannot_exhaust_global_admission() {
    let state = state();
    let routes = Arc::new(RouteBindings::new());
    routes.insert(1, 1, Principal::Direct).unwrap();
    routes
        .insert(
            2,
            1,
            Principal::Reserved {
                module_id: "cingulate".into(),
            },
        )
        .unwrap();
    let blocked = routes
        .blocking
        .clone()
        .acquire_many_owned(MAX_BLOCKING_REQUESTS as u32)
        .await
        .unwrap();
    let (writer, mut rx) = mpsc::channel(512);
    for corr in 0..65 {
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
    let refusal = recv_within(rx.recv(), Duration::from_secs(5), "per-principal refusal").await;
    assert_eq!(refusal.header.corr, 64);
    assert!(routes.in_flight.available_permits() >= 192);
    handle_frame(
        frame(
            FrameType::Request,
            2,
            100,
            json!({"name":"connections","arguments":{"op":"list"}}),
        ),
        &writer,
        &state,
        &routes,
    )
    .await
    .unwrap();
    drop(blocked);
    let mut other_replied = false;
    for _ in 0..65 {
        let reply = recv_within(rx.recv(), Duration::from_secs(10), "admitted work reply").await;
        if reply.header.channel == 2 {
            other_replied = true;
        }
    }
    assert!(other_replied);
}

#[test]
fn route_bindings_are_bounded_without_evicting_open_routes() {
    let routes = RouteBindings::new();
    for channel in 1..=MAX_ROUTE_BINDINGS as u16 {
        routes.insert(channel, 1, Principal::Direct).unwrap();
    }
    assert!(matches!(
        routes.insert(9000, 1, Principal::Direct),
        Err(ModuleError::RouteCapacity)
    ));
    for channel in 1..=MAX_ROUTE_BINDINGS as u16 {
        assert!(
            routes.binding(channel, 1).unwrap().is_some(),
            "a full cache must preserve open route authority"
        );
    }
}

#[test]
fn closing_a_route_does_not_reset_its_principals_capacity() {
    let routes = RouteBindings::new();
    routes.insert(1, 1, Principal::Direct).unwrap();
    let semaphore = routes.binding(1, 1).unwrap().unwrap().admission;
    let permit = semaphore
        .clone()
        .try_acquire_many_owned(MAX_PRINCIPAL_REQUESTS as u32)
        .unwrap();
    routes.remove(1, 1).unwrap();
    routes.insert(2, 1, Principal::Direct).unwrap();
    assert_eq!(
        routes
            .binding(2, 1)
            .unwrap()
            .unwrap()
            .admission
            .available_permits(),
        0
    );
    drop(permit);
}

#[test]
fn request_identifiers_do_not_repeat_across_calls() {
    let ids: std::collections::HashSet<_> = (0..1000).map(|_| fresh_request_id()).collect();
    assert_eq!(ids.len(), 1000);
}

#[test]
fn large_listings_avoid_duplicate_payloads_but_preserve_the_result() {
    for (tool, key) in [
        (manifest::EVENTS_TOOL, "events"),
        (manifest::CATALOG_TOOL, "actions"),
    ] {
        let mut envelope = json!({"result":{}});
        envelope["result"][key] = json!(["x".repeat(128 * 1024)]);
        let rendered = with_call_tool_result(Some(tool), envelope.clone());
        assert_eq!(rendered["result"], envelope["result"]);
        assert!(rendered.get("structuredContent").is_none());
        assert!(rendered["content"][0]["text"].as_str().unwrap().len() < 1024);
    }
}

#[test]
fn github_read_failures_are_structured_and_do_not_leak_debug_messages() {
    let reply = github_read_failure(TransportOutcome::VendorFailed {
        code: "vendor_failure".into(),
        message: "private transport debug".into(),
    });
    assert_eq!(reply["error"]["code"], "read_dispatch_failed");
    assert_eq!(reply["error"]["outcome"]["transmission"], "failed");
    assert_eq!(reply["error"]["outcome"]["code"], "vendor_failure");
    assert!(!reply.to_string().contains("private transport debug"));
}

#[tokio::test]
async fn inspect_requires_a_target_and_legacy_event_get_is_closed() {
    for request in [
        json!({"name":"requests","arguments":{"op":"inspect"}}),
        json!({"name":"catalog","arguments":{"op":"inspect","connection":"missing"}}),
        json!({"name":"events","arguments":{"op":"get","event_key":"x","event_name":"y","extra":1}}),
    ] {
        assert_eq!(reply_to(request).await["error"]["code"], "invalid_request");
    }
}

#[tokio::test]
async fn panicking_request_worker_is_answered_with_its_coordinates() {
    let worker = tokio::task::spawn_blocking(|| panic!("test request worker panic"));
    let (writer, mut rx) = mpsc::channel(1);
    answer_worker_failure(worker.await, (PROTOCOL_VERSION, 17, 3, 99), &writer).await;
    let reply = recv_within(rx.recv(), Duration::from_secs(5), "panic reply").await;
    assert_eq!(
        (reply.header.channel, reply.header.epoch, reply.header.corr),
        (17, 3, 99)
    );
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["error"]["code"], "internal_error");
}

#[test]
fn gate_transitions_include_the_reported_holder_name() {
    let before = json!({"state":"held","epoch":1,"holder_name":"before"});
    let after = json!({"state":"held","epoch":1,"holder_name":"after"});
    assert_ne!(
        connector_gate_transition(&before),
        connector_gate_transition(&after)
    );
}

#[tokio::test]
async fn admission_limits_accept_the_documented_boundary() {
    let request = json!({"name":"connections","arguments":{"op":"list"},"padding":""});
    let size = serde_json::to_vec(&request).unwrap().len();
    let mut request = request;
    request["padding"] = json!("x".repeat(MAX_REQUEST_BYTES - size));
    assert_eq!(
        serde_json::to_vec(&request).unwrap().len(),
        MAX_REQUEST_BYTES
    );
    assert!(reply_to(request).await.get("result").is_some());
    let reply = reply_to(json!({"name":"events", "arguments":{"op":"register_probe", "connection":"missing", "name":"probe", "cadence_s":30,"actions":[],"script_source":"x".repeat(MAX_PROBE_SCRIPT_BYTES),"rearm":"once","return_schema":{}}})).await;
    assert_eq!(reply["error"]["code"], "probe_actions_required");
}

#[test]
fn would_ask_accepts_one_hundred_items() {
    let request = json!({"method":"grants.would_ask","params":{"agent_id":"agent","flow_id":"flow","items":vec![json!({"tool":"invoke","connection":"missing","action":"read"});100]}});
    let reply = grants_would_ask::run(
        &state(),
        "reserved:prefrontal-core",
        None,
        request.as_object().unwrap(),
    );
    assert_eq!(reply["result"]["items"].as_array().unwrap().len(), 100);
}

#[test]
fn poisoned_health_snapshot_is_replaced_instead_of_frozen() {
    let state = state();
    let health = state.health.clone();
    let _ = std::thread::spawn(move || {
        *health.store_metrics.lock().unwrap() = json!({"stale":true});
        let _lock = health.store_metrics.lock().unwrap();
        panic!("poison snapshot");
    })
    .join();
    refresh_store_health(&state, &["direct".into()]);
    let snapshot = state
        .health
        .store_metrics
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert!(snapshot.get("stale").is_none());
    assert!(snapshot["effectiveCiCadenceS"].is_number());
}

#[test]
fn failed_ci_cadence_read_is_null_not_an_infinite_cadence() {
    let scratch = Scratch::database("failed-ci-cadence");
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.into(),
            storage_namespace: "failed-ci-cadence".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    db.execute_batch("DROP TABLE trigger_subscriptions")
        .unwrap();
    let state = ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(store),
    };
    refresh_store_health(&state, &["direct".into()]);
    let snapshot = state.health.store_metrics.lock().unwrap();
    assert_eq!(snapshot.get("effectiveCiCadenceS"), Some(&Value::Null));
}

#[tokio::test]
async fn oversized_frames_do_not_take_admission() {
    let state = state();
    let routes = Arc::new(RouteBindings::new());
    routes.insert(1, 1, Principal::Direct).unwrap();
    let _blocked = routes
        .blocking
        .clone()
        .acquire_many_owned(MAX_BLOCKING_REQUESTS as u32)
        .await
        .unwrap();
    let (writer, mut rx) = mpsc::channel(1);
    handle_frame(
        frame(
            FrameType::Request,
            1,
            990,
            json!({"padding":"x".repeat(MAX_REQUEST_BYTES)}),
        ),
        &writer,
        &state,
        &routes,
    )
    .await
    .unwrap();
    assert_eq!(routes.in_flight.available_permits(), MAX_IN_FLIGHT_REQUESTS);
    let reply = recv_within(rx.recv(), Duration::from_secs(5), "oversize refusal").await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_refuses_classic_agent_scopes() {
    let routes = Arc::new(RouteBindings::new());
    let scope = CallScope::from_stamp(&crate::consent_test_support::worker_stamp("worker", 1));
    routes
        .insert_mode(1, 1, Principal::Direct, Some(scope), CallMode::Classic)
        .unwrap();
    let (writer, mut rx) = mpsc::channel(1);
    handle_tool_request(
        frame(
            FrameType::Request,
            1,
            991,
            json!({"method":"plexus.admin.list_grants","params":{}}),
        ),
        &writer,
        &state(),
        &routes,
    )
    .await
    .unwrap();
    let reply = recv_within(
        rx.recv(),
        Duration::from_secs(5),
        "scoped management refusal",
    )
    .await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["error"]["code"], "operator_authority_required");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inspect_returns_only_the_named_request_and_action() {
    let fixture = crate::withdraw_tests::Fixture::new("targeted-inspect");
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: fixture.runtime(),
    });
    let routes = Arc::new(RouteBindings::new());
    routes
        .insert_scoped(
            1,
            1,
            Principal::Reserved {
                module_id: "aft".into(),
            },
            Some(CallScope::from_stamp(
                &crate::consent_test_support::worker_stamp("worker-7", 4),
            )),
        )
        .unwrap();
    routes.insert(2, 1, Principal::Direct).unwrap();
    async fn call(
        state: &Arc<ModuleState>,
        routes: &Arc<RouteBindings>,
        channel: u16,
        body: Value,
    ) -> Value {
        let (writer, mut rx) = mpsc::channel(1);
        handle_tool_request(
            frame(FrameType::Request, channel, 1, body),
            &writer,
            state,
            routes,
        )
        .await
        .unwrap();
        let reply = recv_within(rx.recv(), Duration::from_secs(5), "inspect fixture reply").await;
        serde_json::from_slice(&reply.body).unwrap()
    }
    for index in 0..2 {
        let reply=call(&state, &routes, 1, json!({"name":"invoke","arguments":{"op":"call","connection":"conn-held","action":"search","args":{"query":format!("query-{index}")}}})).await;
        assert_eq!(
            reply["structuredContent"]["code"], "access_pending",
            "{reply}"
        );
    }
    let requests = fixture.store.list_action_requests("direct").unwrap();
    assert_eq!(requests.len(), 2);
    let reply = call(
        &state,
        &routes,
        2,
        json!({"name":"requests","arguments":{"op":"inspect","request_id":requests[0].request_id}}),
    )
    .await;
    assert_eq!(reply["result"]["requests"].as_array().unwrap().len(), 1);
    assert_eq!(
        reply["result"]["requests"][0]["request_id"],
        requests[0].request_id
    );
    assert_eq!(reply["result"]["reconciliations"], json!([]));
    let schema = json!({"type":"object"});
    fixture
        .store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: "conn-held".into(),
            principal: "direct".into(),
            name: "second".into(),
            title: None,
            schema: schema.clone(),
            schema_hash: plexus_core::jcs_sha256(&schema).unwrap(),
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    let reply=call(&state,&routes,2,json!({"name":"catalog","arguments":{"op":"inspect","connection":"conn-held","action":"search"}})).await;
    assert_eq!(reply["result"]["actions"].as_array().unwrap().len(), 1);
    assert_eq!(reply["result"]["actions"][0]["name"], "search");
}

#[test]
fn route_capacity_warning_is_rate_limited_by_monotonic_time() {
    let routes = RouteBindings::new();
    let now = std::time::Instant::now();
    assert!(routes.should_log_route_capacity(now));
    assert!(!routes.should_log_route_capacity(now));
    assert!(!routes.should_log_route_capacity(now + Duration::from_secs(59)));
    assert!(routes.should_log_route_capacity(now + Duration::from_secs(60)));
}

#[tokio::test]
async fn connection_end_and_read_failure_clear_all_route_bindings() {
    for (bytes, expect_error) in [(Vec::new(), false), (vec![0u8; 128], true)] {
        let routes = Arc::new(RouteBindings::new());
        routes.insert(1, 1, Principal::Direct).unwrap();
        routes.insert(2, 7, Principal::Direct).unwrap();
        let (writer, _rx) = mpsc::channel(1);
        let mut reader = bytes.as_slice();
        let result = dispatch_loop(
            &mut reader,
            writer,
            state(),
            routes.clone(),
            Arc::new(PendingControlReplies::default()),
        )
        .await;
        assert_eq!(result.is_err(), expect_error);
        assert!(routes.binding(1, 1).unwrap().is_none());
        assert!(routes.binding(2, 7).unwrap().is_none());
    }
}

#[tokio::test]
async fn daemon_goodbye_clears_bindings_but_request_error_and_cancel_do_not() {
    let routes = Arc::new(RouteBindings::new());
    routes.insert(1, 1, Principal::Direct).unwrap();
    let (writer, _rx) = mpsc::channel(1);
    let state = state();
    for kind in [FrameType::Error, FrameType::Cancel] {
        handle_frame(frame(kind, 1, 42, Value::Null), &writer, &state, &routes)
            .await
            .unwrap();
        assert!(routes.binding(1, 1).unwrap().is_some());
    }
    let goodbye = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Goodbye,
        wire::control_flags(),
        0,
        0,
        0,
        Vec::new(),
    )
    .unwrap();
    let (mut daemon, mut reader) = tokio::io::duplex(256);
    subc_transport::write_frame(&mut daemon, &goodbye)
        .await
        .unwrap();
    dispatch_loop(
        &mut reader,
        writer,
        state,
        routes.clone(),
        Arc::new(PendingControlReplies::default()),
    )
    .await
    .unwrap();
    assert!(routes.binding(1, 1).unwrap().is_none());
}

#[test]
fn rebinding_a_channel_replaces_the_released_epoch() {
    let routes = RouteBindings::new();
    routes.insert(3, 1, Principal::Direct).unwrap();
    routes.insert(4, 1, Principal::Direct).unwrap();
    assert!(routes.binding(3, 1).unwrap().is_some());
    let next = Principal::Reserved {
        module_id: "aft".into(),
    };
    routes.insert(3, 2, next.clone()).unwrap();
    assert!(routes.binding(3, 1).unwrap().is_none());
    assert_eq!(routes.get(3, 2).unwrap(), Some(next));
    assert!(routes.binding(4, 1).unwrap().is_some());
    assert_eq!(routes.inner.read().unwrap().len(), 2);
}
