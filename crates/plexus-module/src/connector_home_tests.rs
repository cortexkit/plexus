use super::*;
use crate::connector_home::{ConnectorHome, RolePeer};
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
impl RolePeer for Double {
    fn call(&self, method: &str, params: Value) -> Result<Value, ErrorBody> {
        self.calls.lock().unwrap().push((method.into(), params));
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(error("unavailable")))
            .and_then(|reply| crate::connector_home::role_reply(json!({"result":reply})))
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
    Ok(role_answer(true, true, false))
}
fn role_answer(known: bool, held_here: bool, stale: bool) -> Value {
    json!({"role":"connector_home", "epoch":7, "known":known, "held_here":held_here,
        "stale":stale, "holder":"device", "holder_name":"Other Mac", "source":"cloud"})
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
    assert_ne!(
        call_tool(&state, "github", "bindings.read")["error"]["code"],
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
    let home = ConnectorHome::new(Double::new(vec![Ok(role_answer(true, false, false))]));
    home.refresh().unwrap();
    let reply = home.refusal().unwrap();
    assert_eq!(reply["error"]["connectorHome"]["holder_name"], "Other Mac");
    assert_eq!(reply["error"]["connectorHome"]["epoch"], 7);
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
    let confirmed = home.status();
    for _ in 0..2 {
        assert!(home.refresh().is_err());
        assert!(home.held());
        assert_eq!(home.status(), confirmed);
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
fn integrity_failure_revokes_held_admission() {
    let home = ConnectorHome::new(Double::new(vec![
        held(),
        Err(error("claim_integrity_failed")),
    ]));
    home.refresh().unwrap();
    assert!(home.refresh().is_err());
    assert_eq!(home.status()["state"], "integrity_failed");
    assert_eq!(home.status()["code"], "claim_integrity_failed");
    assert!(home.refusal().is_some());
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

#[test]
fn reader_requires_held_here_and_known() {
    for (known, held_here, expected) in [
        (true, false, "not_held"),
        (false, true, "unknown"),
        (true, true, "held"),
    ] {
        let peer = Double::new(vec![Ok(role_answer(known, held_here, false))]);
        let home = ConnectorHome::new(peer.clone());
        home.refresh().unwrap();
        assert_eq!(home.status()["state"], expected);
        assert_eq!(
            home.held(),
            known && held_here,
            "serving requires held_here and known"
        );
        assert_eq!(
            *peer.calls.lock().unwrap(),
            vec![("role.read".into(), json!({"role":"connector_home"}))]
        );
    }
}

#[test]
fn reader_never_read_and_read_unheld() {
    for (known, stale, expected) in [(false, true, "unknown"), (true, false, "not_held")] {
        let reply = json!({"epoch":0,"held_here":false,"holder":null,"holder_name":null,"known":known,"role":"connector_home","source":if known {json!("cloud")} else {Value::Null},"stale":stale});
        let home = ConnectorHome::new(Double::new(vec![Ok(reply)]));
        home.refresh().unwrap();
        assert!(!home.held());
        assert_eq!(home.status()["state"], expected);
        assert_eq!(
            home.status()["epoch"],
            if known { json!(0) } else { Value::Null }
        );
    }
}

#[test]
fn reader_stale_never_replaces_a_confirmed_answer() {
    let home = ConnectorHome::new(Double::new(vec![
        Ok(role_answer(true, true, true)),
        held(),
        Ok(role_answer(true, true, true)),
        Ok(role_answer(true, false, true)),
        Ok(role_answer(true, false, false)),
    ]));
    home.refresh().unwrap();
    assert!(!home.held(), "a stale held answer cannot start service");
    home.refresh().unwrap();
    let confirmed = home.status();
    for _ in 0..2 {
        home.refresh().unwrap();
        assert!(
            home.held(),
            "any stale answer must preserve confirmed admission"
        );
        assert_eq!(home.status(), confirmed);
    }
    home.refresh().unwrap();
    assert!(!home.held(), "a fresh not-held answer must stop service");
    assert_eq!(home.status()["holder_name"], "Other Mac");
}

#[test]
fn reader_integrity_stops_serving_until_verified_read() {
    for prior_hold in [true, false] {
        let mut replies = if prior_hold { vec![held()] } else { vec![] };
        replies.extend([
            Err(crate::connector_home::role_reply(
                json!({"error":{"code":"claim_integrity_failed","message":"bad signature"}}),
            )
            .unwrap_err()),
            Err(error("transport_error")),
            Ok(role_answer(true, true, true)),
            held(),
        ]);
        let home = Arc::new(ConnectorHome::new(Double::new(replies)));
        let (_scratch, state) = fixture(home.clone());
        if prior_hold {
            home.refresh().unwrap();
        }
        assert!(home.refresh().is_err());
        assert!(!home.held(), "integrity failure must revoke admission");
        let health = serde_json::to_value(connector_home_health(&state)).unwrap();
        assert_eq!(
            health["metrics"]["connectorHome"]["state"],
            "integrity_failed"
        );
        assert_eq!(
            health["metrics"]["connectorHome"]["code"],
            "claim_integrity_failed"
        );
        assert!(home.refresh().is_err());
        home.refresh().unwrap();
        assert!(!home.held());
        assert_eq!(home.status()["state"], "integrity_failed");
        home.refresh().unwrap();
        assert!(home.held());
        assert!(home.status()["code"].is_null());
    }
}

#[test]
fn reader_malformed_is_never_a_new_hold() {
    let complete = role_answer(true, true, false);
    let mut malformed = vec![Value::Null, json!([]), json!({"held_here":true})];
    for key in [
        "epoch",
        "known",
        "held_here",
        "stale",
        "holder",
        "holder_name",
        "role",
        "source",
    ] {
        let mut missing = complete.clone();
        missing.as_object_mut().unwrap().remove(key);
        malformed.push(missing);
        let mut wrong_type = complete.clone();
        wrong_type[key] = json!([]);
        malformed.push(wrong_type);
    }
    for bad in malformed {
        let home = ConnectorHome::new(Double::new(vec![Ok(bad.clone()), held(), Ok(bad.clone())]));
        assert!(home.refresh().is_err(), "malformed reply admitted: {bad}");
        assert!(
            !home.held(),
            "malformed reply must never start serving: {bad}"
        );
        home.refresh().unwrap();
        let confirmed = home.status();
        assert!(home.refresh().is_err());
        assert!(
            home.held(),
            "malformed replies are unreachable, not revocations"
        );
        assert_eq!(home.status(), confirmed);
    }
}

#[test]
fn reader_ignores_unknown_reply_fields_and_status_prints_reply() {
    let mut reply = role_answer(true, true, false);
    reply["future_field"] = json!({"ignored":true});
    let home = ConnectorHome::new(Double::new(vec![Ok(reply.clone())]));
    let status = home.live_status();
    assert_eq!(status["result"]["role"], reply);
    assert!(home.held());
}

/// One Entorhinal vector: the case name, the request it answers, and the reply
/// as plexus's peer would hand it over (a module error arrives as `Err`).
fn entorhinal_vector_cases(value: &Value) -> Vec<(String, Value, Result<Value, ErrorBody>)> {
    value
        .as_array()
        .expect("Entorhinal vectors are a list of records")
        .iter()
        .map(|record| {
            let name = record["case"]
                .as_str()
                .expect("vector case name")
                .to_owned();
            let request: Value = serde_json::from_str(
                record["request_bytes"]
                    .as_str()
                    .expect("vector request bytes"),
            )
            .expect("vector request is JSON");
            let reply: Value =
                serde_json::from_str(record["reply_bytes"].as_str().expect("vector reply bytes"))
                    .expect("vector reply is JSON");
            let reply = match record["outcome"].as_str() {
                Some("response") => crate::connector_home::role_reply(reply),
                Some("error") => Err(serde_json::from_value(reply).expect("vector error body")),
                other => panic!("unknown vector outcome {other:?} in {name}"),
            };
            (name, request, reply)
        })
        .collect()
}

#[test]
fn entorhinal_role_vectors_through_real_reader() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/entorhinal-roles/role-claims-v1/records.json");
    let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    // Plexus's own expectations for each role.read answer: the state it leads to
    // from a fresh start, and whether plexus may then serve outside effects.
    let reads = [
        ("never_read", "unknown", false),
        ("read_unheld", "not_held", false),
        ("held_here", "held", true),
        ("held_elsewhere", "not_held", false),
        ("stale_after_restart", "unknown", false),
        ("integrity_failure", "integrity_failed", false),
    ];
    // Plexus never calls role.take: the operator takes the role with `ck roles
    // take`, and Entorhinal refuses `reserved:plexus`. These cases are only
    // checked to be take requests.
    let takes = ["take_epoch_moved", "take_reserved_plexus"];
    let mut seen = std::collections::BTreeSet::new();
    for (name, request, reply) in entorhinal_vector_cases(&value) {
        seen.insert(name.clone());
        if takes.contains(&name.as_str()) {
            assert_eq!(request["method"], "role.take", "{name}");
            continue;
        }
        let (_, state, may_serve) = reads
            .iter()
            .find(|(case, _, _)| *case == name)
            .unwrap_or_else(|| panic!("Entorhinal case plexus has no expectation for: {name}"));
        assert_eq!(request["method"], "role.read", "{name}");
        // Entorhinal's vectors read a placeholder role named "x". Plexus refuses
        // an answer about any role but connector_home, so a held-here answer for
        // "x" must never let it serve; the role is then renamed to test the rest.
        if let Ok(answer) = &reply {
            if answer["held_here"] == true {
                let home = ConnectorHome::new(Double::new(vec![reply.clone()]));
                let _ = home.refresh();
                assert!(
                    !home.held(),
                    "an answer about another role must not count: {name}"
                );
            }
        }
        let reply = reply.map(|mut answer| {
            answer["role"] = json!(crate::connector_home::ROLE);
            answer
        });
        let home = ConnectorHome::new(Double::new(vec![reply.clone()]));
        let _ = home.refresh();
        assert_eq!(home.status()["state"], *state, "{name}");
        assert_eq!(home.held(), *may_serve, "{name}");
        if name == "stale_after_restart" {
            // A stale answer that says "held here" must neither start service nor
            // change an answer plexus already confirmed.
            let home = ConnectorHome::new(Double::new(vec![
                held(),
                reply,
                Ok(role_answer(true, false, false)),
            ]));
            home.refresh().unwrap();
            let confirmed = home.status();
            let _ = home.refresh();
            assert_eq!(
                home.status(),
                confirmed,
                "stale must keep the confirmed answer"
            );
            assert!(home.held());
            home.refresh().unwrap();
            assert!(!home.held(), "a fresh not-held answer must stop service");
        }
    }
    for (name, _, _) in reads {
        assert!(seen.contains(name), "missing Entorhinal case: {name}");
    }
    for name in takes {
        assert!(seen.contains(name), "missing Entorhinal case: {name}");
    }
}
