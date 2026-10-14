use super::*;
use crate::connector_home::{ClaimPeer, ConnectorHome};
use std::sync::Mutex;
use subc_protocol::ErrorBody;

struct Double {
    replies: Mutex<std::collections::VecDeque<Result<Value, ErrorBody>>>,
    calls: Mutex<Vec<(String, Value)>>,
}
impl Double {
    fn new(replies: Vec<Result<Value, ErrorBody>>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies.into()),
            calls: Mutex::new(vec![]),
        })
    }
}
impl ClaimPeer for Double {
    fn call(&self, method: &str, params: Value) -> Result<Value, ErrorBody> {
        self.calls.lock().unwrap().push((method.into(), params));
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(error("unavailable")))
    }
}
fn error(code: &str) -> ErrorBody {
    ErrorBody {
        code: code.into(),
        message: code.into(),
        detail: None,
    }
}
fn held() -> Result<Value, ErrorBody> {
    Ok(json!({"epoch":7,"held_here":true,"source":"cloud","holder":"here"}))
}
fn fixture(home: Arc<ConnectorHome>) -> (Scratch, Arc<ModuleState>) {
    let scratch = Scratch::database("connector-home");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "test".into(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: scratch.to_string_lossy().into_owned(),
        },
    };
    let mut runtime = runtime_for_test(Arc::new(PlexusStore::open(&descriptor).unwrap()));
    runtime.connector_home = home.clone();
    runtime.engine = runtime.engine.with_connector_home_guard(Arc::new(move || {
        if home.held() {
            None
        } else {
            Some(home.status())
        }
    }));
    (
        scratch,
        Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        }),
    )
}
fn call_tool(state: &Arc<ModuleState>, name: &str, op: &str) -> Value {
    let arguments = if name == "github_read" {
        json!({"action":"github.issue.get","repository":"o/x","args":{"issue_number":42}})
    } else {
        json!({"op":op})
    };
    let object = json!({"name":name,"arguments":arguments});
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        wire::control_flags(),
        2,
        1,
        8,
        serde_json::to_vec(&object).unwrap(),
    )
    .unwrap();
    let routes = Arc::new(RouteBindings::new());
    routes.insert(2, 1, Principal::Direct).unwrap();
    facade_tool_reply(&frame, object.as_object().unwrap(), state, &routes).unwrap()
}
#[test]
fn unknown_refuses_every_facade_effect_before_dispatch() {
    let (_scratch, state) = fixture(Arc::new(ConnectorHome::unavailable()));
    for (name, op) in [
        ("invoke", "call"),
        ("github", "bot_request"),
        ("github", "read"),
        ("github_read", ""),
        ("web_search", "search"),
        ("code_search", ""),
        ("requests", "approve"),
        ("requests", "deny"),
        ("connections", "connect"),
        ("tool.withdraw", ""),
    ] {
        let reply = call_tool(&state, name, op);
        assert_eq!(
            reply["error"]["code"], "connector_home_not_held",
            "{name}/{op}: {reply}"
        );
        assert_eq!(reply["error"]["transmission"], "not_sent");
        assert_eq!(reply["error"]["connectorHome"]["state"], "unknown");
    }
    assert_ne!(
        call_tool(&state, "connections", "list")["error"]["code"],
        "connector_home_not_held"
    );
}
#[test]
fn held_admits_facade_dispatch_boundary() {
    let home = Arc::new(ConnectorHome::new(Double::new(vec![held()])));
    home.refresh().unwrap();
    let (_scratch, state) = fixture(home);
    let reply = call_tool(&state, "invoke", "call");
    assert_ne!(reply["error"]["code"], "connector_home_not_held");
    assert_eq!(reply["error"]["code"], "invalid_request");
}
#[test]
fn not_held_refusal_names_holder_and_epoch() {
    let home = ConnectorHome::new(Double::new(vec![Ok(
        json!({"epoch":9,"holder":"other","held_here":false,"source":"cloud"}),
    )]));
    home.refresh().unwrap();
    let reply = home.refusal().unwrap();
    assert_eq!(reply["error"]["connectorHome"]["holder"], "other");
    assert_eq!(reply["error"]["connectorHome"]["epoch"], 9);
    assert_eq!(reply["error"]["connectorHome"]["state"], "not_held");
}
#[test]
fn unavailable_after_held_preserves_admission() {
    let home = ConnectorHome::new(Double::new(vec![
        held(),
        Err(error("unavailable")),
        Err(error("key_unavailable")),
    ]));
    home.refresh().unwrap();
    for _ in 0..2 {
        assert!(home.refresh().is_err());
        assert!(home.held());
    }
}
#[test]
fn unavailable_at_boot_never_admits() {
    let home = ConnectorHome::unavailable();
    assert!(home.refresh().is_err());
    assert_eq!(home.status()["state"], "unknown");
    assert!(home.refusal().is_some());
}
#[test]
fn verify_failed_revokes_held_admission() {
    let home = ConnectorHome::new(Double::new(vec![held(), Err(error("verify_failed"))]));
    home.refresh().unwrap();
    assert!(home.refresh().is_err());
    assert_eq!(home.status()["state"], "not_held");
    assert!(home.refusal().is_some());
}
#[test]
fn claim_apply_rereads_immediately_and_preserves_retry_request() {
    let absent = || Ok(json!({"epoch":0,"absent":true,"held_here":false}));
    let peer = Double::new(vec![
        absent(),
        Ok(json!({"epoch":1})),
        held(),
        held(),
        Ok(json!({"epoch":1})),
        held(),
    ]);
    let home = ConnectorHome::new(peer.clone());
    let params =
        json!({"apply":true,"reason":"bootstrap","request_id":"0123456789abcdef0123456789abcdef"});
    assert!(home.claim(&params).get("error").is_none());
    assert!(home.held());
    assert!(home.claim(&params).get("error").is_none());
    let calls = peer.calls.lock().unwrap();
    assert_eq!(
        calls.iter().map(|(m, _)| m.as_str()).collect::<Vec<_>>(),
        vec![
            "claim.read",
            "claim.force",
            "claim.read",
            "claim.read",
            "claim.force",
            "claim.read"
        ]
    );
    assert_eq!(
        calls[1].1,
        json!({"subject":"role:connector_home","expected_epoch":0,"request_id":"0123456789abcdef0123456789abcdef","to_device":"self","cut":"","reason":"bootstrap"})
    );
    assert_eq!(calls[1].1, calls[4].1);
}
#[test]
fn claim_requires_reason_and_previews_without_apply() {
    let peer = Double::new(vec![held()]);
    let home = ConnectorHome::new(peer.clone());
    for params in [json!({}), json!({"reason":"  ","apply":true})] {
        assert_eq!(home.claim(&params)["error"]["code"], "invalid_request");
    }
    assert_eq!(peer.calls.lock().unwrap().len(), 0);
    assert_eq!(
        home.claim(&json!({"reason":"bootstrap"}))["result"]["preview"],
        true
    );
    assert_eq!(peer.calls.lock().unwrap().len(), 1);
}
#[test]
fn health_reports_unknown_degraded_and_held_state() {
    let home = Arc::new(ConnectorHome::new(Double::new(vec![held()])));
    let (_scratch, state) = fixture(home.clone());
    let value = serde_json::to_value(connector_home_health(&state)).unwrap();
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["detail"], "connector_home_not_held");
    assert_eq!(value["metrics"]["connectorHome"]["state"], "unknown");
    home.refresh().unwrap();
    let value = serde_json::to_value(connector_home_health(&state)).unwrap();
    assert_eq!(value["metrics"]["connectorHome"]["state"], "held");
    assert_eq!(value["metrics"]["connectorHome"]["epoch"], 7);
    assert_eq!(value["metrics"]["connectorHome"]["source"], "cloud");
    assert!(value["metrics"]["connectorHome"]["checkedAt"].is_i64());
}
/// Report panic-recovery counts for the runtime's MCP and REST transports in
/// `connector_home_health`. Expect zero for both because neither has panicked.
#[test]
fn health_reports_the_runtime_transports_panic_recoveries() {
    let home = Arc::new(ConnectorHome::new(Double::new(vec![held()])));
    home.refresh().unwrap();
    let (_scratch, state) = fixture(home);
    let value = serde_json::to_value(connector_home_health(&state)).unwrap();
    assert_eq!(
        value["metrics"]["transportPanicRecoveries"],
        json!({"mcp": 0, "rest": 0}),
        "the health check must judge the runtime's transports: {value}"
    );
    assert_eq!(value["metrics"]["transportPanicRecoveryAgeMs"], Value::Null);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_skips_whole_scheduler_pass() {
    let (_scratch, state) = fixture(Arc::new(ConnectorHome::unavailable()));
    let (shutdown, stop) = mpsc::channel(1);
    let task = spawn_trigger_scheduler(
        state.clone(),
        stop,
        DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY,
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    drop(shutdown);
    task.await.unwrap();
    let value = serde_json::to_value(state.health.report()).unwrap();
    assert!(value["metrics"]["schedulerPassAgeMs"].as_u64().unwrap() >= 1000);
}

#[test]
fn unknown_core_guard_refuses_reservations_and_approved_execution() {
    let (_scratch, state) = fixture(Arc::new(ConnectorHome::unavailable()));
    let request = plexus_core::AuthorizationRequest::new("direct", "missing", "action", json!({}));
    let denial = state.runtime.engine.authorize(request).unwrap_err();
    assert_eq!(denial.reason_code(), "connector_home_not_held");
    let denial = state
        .runtime
        .engine
        .approve_request("direct", "missing", "direct")
        .unwrap_err();
    assert_eq!(denial.reason_code(), "connector_home_not_held");
}

#[test]
fn claim_epoch_moved_reports_holder_and_epoch_detail() {
    let peer = Double::new(vec![
        held(),
        Err(ErrorBody {
            code: "epoch_moved".into(),
            message: "epoch_moved".into(),
            detail: Some(json!({"epoch":8,"holder":"other"})),
        }),
    ]);
    let home = ConnectorHome::new(peer);
    let reply = home.claim(
        &json!({"reason":"bootstrap","apply":true,"request_id":"0123456789abcdef0123456789abcdef"}),
    );
    assert_eq!(reply["error"]["code"], "epoch_moved");
    assert_eq!(reply["error"]["detail"]["epoch"], 8);
    assert_eq!(reply["error"]["detail"]["holder"], "other");
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("epoch=8"));
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("other"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connector_home_management_is_direct_only_and_audits_apply_outcome() {
    let home = Arc::new(ConnectorHome::new(Double::new(vec![
        held(),
        Ok(json!({"epoch":8})),
        held(),
    ])));
    let (scratch, state) = fixture(home);
    let params =
        json!({"reason":"bootstrap","apply":true,"request_id":"0123456789abcdef0123456789abcdef"});
    let routes = Arc::new(RouteBindings::new());
    routes
        .insert(
            4,
            1,
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        )
        .unwrap();
    routes.insert(5, 1, Principal::Direct).unwrap();
    let (writer, mut replies) = mpsc::channel(2);
    for channel in [4, 5] {
        handle_management_request(
            RouteFrameContext {
                version: PROTOCOL_VERSION,
                channel,
                epoch: 1,
                correlation: 9,
            },
            crate::connector_home::CLAIM_OP,
            &params,
            &writer,
            &state,
            &routes,
        )
        .await
        .unwrap();
        let reply: Value = serde_json::from_slice(
            &recv_within(
                replies.recv(),
                std::time::Duration::from_secs(5),
                "expected reply",
            )
            .await
            .body,
        )
        .unwrap();
        if channel == 4 {
            assert_eq!(reply["error"]["code"], "operator_authority_required");
        } else {
            assert_eq!(reply["result"]["outcome"]["epoch"], 8, "{reply}");
        }
    }
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    let rows:i64 = db.query_row("SELECT COUNT(*) FROM audit_journal WHERE gate='connector_home' AND request_id='0123456789abcdef0123456789abcdef'",[],|row|row.get(0)).unwrap();
    assert_eq!(rows, 2);
    let outcome: String = db
        .query_row(
            "SELECT outcome FROM audit_journal WHERE action='connector_home.claim.outcome'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        outcome, "applied",
        "audit outcome must not store the peer response body"
    );
}

/// An applied claim whose outcome row cannot be written still answers with the
/// claim's real outcome, plus a warning that the audit row is missing. The
/// claim has already moved in engram, so an error reply (or no reply) would
/// tell the operator nothing happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_claim_answers_even_when_its_outcome_audit_fails() {
    let home = Arc::new(ConnectorHome::new(Double::new(vec![
        held(),
        Ok(json!({"epoch":8})),
        held(),
    ])));
    let (scratch, state) = fixture(home);
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    db.execute_batch(
        "CREATE TRIGGER refuse_claim_outcome BEFORE INSERT ON audit_journal
         WHEN NEW.action = 'connector_home.claim.outcome'
         BEGIN SELECT RAISE(ABORT, 'audit journal unavailable'); END;",
    )
    .unwrap();
    let routes = Arc::new(RouteBindings::new());
    routes.insert(5, 1, Principal::Direct).unwrap();
    let (writer, mut replies) = mpsc::channel(2);
    handle_management_request(
        RouteFrameContext {
            version: PROTOCOL_VERSION,
            channel: 5,
            epoch: 1,
            correlation: 9,
        },
        crate::connector_home::CLAIM_OP,
        &json!({"reason":"bootstrap","apply":true,"request_id":"0123456789abcdef0123456789abcdef"}),
        &writer,
        &state,
        &routes,
    )
    .await
    .expect("an applied claim must be answered even when its outcome audit fails");
    let reply: Value = serde_json::from_slice(
        &recv_within(
            replies.recv(),
            std::time::Duration::from_secs(5),
            "claim reply",
        )
        .await
        .body,
    )
    .unwrap();
    assert_eq!(reply["result"]["outcome"]["epoch"], 8, "{reply}");
    assert_eq!(reply["warning"]["code"], "audit_append_failed", "{reply}");
}

/// Require an explicit entry for every served tool in `TOOL_EFFECTS`, which
/// decides whether a call requires this instance's lease to serve connectors.
/// An omitted tool would bypass that check and could send vendor requests
/// from an instance that does not hold the lease.
#[test]
fn every_advertised_tool_has_a_connector_home_decision() {
    let manifest = manifest::build("plexus");
    let mut served: Vec<&str> = manifest
        .provides
        .iter()
        .flat_map(|role| match role {
            subc_protocol::manifest::ProviderRole::ToolProvider { tools, .. } => {
                tools.iter().map(|tool| tool.name.as_str()).collect()
            }
            _ => Vec::new(),
        })
        .collect();
    served.push(manifest::WITHDRAW_TOOL);
    assert!(served.len() >= 10, "advertised tools: {served:?}");
    for name in served {
        assert!(
            crate::connector_home::TOOL_EFFECTS
                .iter()
                .any(|(tool, _)| *tool == name),
            "tool {name} has no connector-home decision in TOOL_EFFECTS"
        );
    }
}

/// The remembered apply requests are bounded: past the cap the oldest id is
/// forgotten, while a recent id still resends its original request.
#[test]
fn remembered_apply_requests_are_bounded() {
    let cap = crate::connector_home::MAX_REMEMBERED_APPLIES;
    // One claim.read and one claim.force per apply, plus the force's re-read.
    let mut replies = Vec::new();
    for _ in 0..=cap + 2 {
        replies.extend([held(), Ok(json!({"epoch":8})), held()]);
    }
    let peer = Double::new(replies);
    let home = ConnectorHome::new(peer.clone());
    let id = |n: usize| format!("{n:032x}");
    for n in 0..=cap {
        let reply = home.claim(&json!({"apply":true,"reason":"r","request_id":id(n)}));
        assert!(reply.get("error").is_none(), "{reply}");
    }
    // The first id was evicted, so reusing it with a different reason is not
    // recognised as a reuse; the most recent id still is.
    let evicted = home.claim(&json!({"apply":true,"reason":"other","request_id":id(0)}));
    assert_ne!(
        evicted["error"]["code"], "id_reused",
        "the oldest apply id must be forgotten past the cap: {evicted}"
    );
    let recent = home.claim(&json!({"apply":true,"reason":"other","request_id":id(cap)}));
    assert_eq!(recent["error"]["code"], "id_reused", "{recent}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preview_claim_does_not_write_outcome_audit_rows() {
    let home = Arc::new(ConnectorHome::new(Double::new(vec![held()])));
    let (scratch, state) = fixture(home);
    let routes = Arc::new(RouteBindings::new());
    routes.insert(5, 1, Principal::Direct).unwrap();
    let (writer, mut replies) = mpsc::channel(2);
    handle_management_request(
        RouteFrameContext {
            version: PROTOCOL_VERSION,
            channel: 5,
            epoch: 1,
            correlation: 9,
        },
        crate::connector_home::CLAIM_OP,
        &json!({"reason":"bootstrap"}),
        &writer,
        &state,
        &routes,
    )
    .await
    .unwrap();
    let frame = recv_within(
        replies.recv(),
        std::time::Duration::from_secs(5),
        "preview claim reply",
    )
    .await;
    let reply: Value = serde_json::from_slice(&frame.body).unwrap();
    assert_eq!(reply["result"]["preview"], true);
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    let rows: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM audit_journal WHERE gate='connector_home'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "preview claims must not append outcome audit rows");
}

#[test]
fn missing_claim_epoch_is_a_peer_protocol_fault() {
    let home = ConnectorHome::new(Double::new(vec![Ok(json!({"held_here":true}))]));
    let reply = home.claim(&json!({"reason":"bootstrap"}));
    assert_eq!(
        reply["error"]["code"], "peer_protocol_error",
        "missing claim epoch is the peer's fault, not the operator's"
    );
}
