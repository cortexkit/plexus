use super::*;
use cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY;
use plexus_core::test_scratch::Scratch;
use plexus_core::{CatalogActionInput, GrantInput};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::path::Path;
use subc_protocol::BindIdentity;

const REGENERATE: &str = "PLEXUS_REGENERATE_REPLY_TOO_LARGE_V1";
const TOOLS: &[&str] = &[
    manifest::CONNECTIONS_TOOL,
    manifest::CATALOG_TOOL,
    manifest::REQUESTS_TOOL,
    manifest::EVENTS_TOOL,
    manifest::INVOKE_TOOL,
    manifest::EVENTS_GET_TOOL,
    manifest::WITHDRAW_TOOL,
];

thread_local! {
    // Only fixture dispatches use a stable sample identity; the actual engine
    // still reserves and dispatches normally, with its production-generated ID.
    static STABLE_DISPATCH: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn stable_dispatch_identity(mut outcome: DispatchOutcome) -> DispatchOutcome {
    if STABLE_DISPATCH.get() {
        outcome.reservation_id = "reservation-sample".into();
    }
    outcome
}

struct StableDispatch;

impl Drop for StableDispatch {
    fn drop(&mut self) {
        STABLE_DISPATCH.set(false);
    }
}

struct Fixture {
    path: Scratch,
    store: Arc<PlexusStore>,
    transport: Arc<MockTransport>,
}

impl Fixture {
    fn new() -> Self {
        let path = Scratch::database("remaining-reply-guard");
        let store = Arc::new(test_support::open_file_store(&path));
        Self {
            path,
            store,
            transport: Arc::new(MockTransport::default()),
        }
    }

    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.path).unwrap()
    }

    fn connection(&self, id: &str) {
        self.store
            .insert_connection(
                "direct",
                id,
                "sample",
                "active",
                &json!({"required":[],"optional":[],"write_enabling":[]}),
            )
            .unwrap();
    }

    fn action(&self, large: bool) {
        self.connection("conn-sample");
        let schema = json!({"type":"object", "description": if large { "x".repeat(70_000) } else { "sample".into() }});
        self.store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "conn-sample".into(),
                principal: "direct".into(),
                name: "sample".into(),
                title: Some("Sample".into()),
                schema_hash: plexus_core::jcs_sha256(&schema).unwrap(),
                schema,
                risk: "read".into(),
                severity: "S1".into(),
                ask_first: false,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
    }

    fn invoke(&self, large: bool) {
        self.action(false);
        self.sql()
            .execute(
                "UPDATE connections SET status='pending' WHERE connection_id='conn-sample'",
                [],
            )
            .unwrap();
        let ticket = self
            .store
            .create_binding_ticket("direct", "conn-sample", b"test:reply-guard-fixture")
            .unwrap();
        self.store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .unwrap()
            .unwrap();
        self.store
            .insert_grant(&GrantInput {
                grant_id: "grant-sample".into(),
                principal: "direct".into(),
                connection_id: "conn-sample".into(),
                grantee_principal: "direct".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["sample".into()],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
        self.transport
            .set_response(plexus_core::MockResponse::Success(
                json!({"data": if large { "x".repeat(70_000) } else { "small".into() }}),
            ));
    }

    fn event(&self, large: bool) -> (String, String) {
        let (key, _) = events_get_tests::seed_test_events(&self.path, &self.store);
        let raw = format!(
            "{{ \"sample\": \"{}\" }}\n",
            if large {
                "🦀\\\"".repeat(14_000)
            } else {
                "small".into()
            }
        );
        let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
        assert_eq!(self.sql().execute(
            "UPDATE event_outbox SET body_v1=?1,digest_v1=?2,envelope_v2=?1,digest_v2=?2 WHERE event_key=?3",
            (&raw, &digest, &key),
        ).unwrap(), 1);
        (key, raw)
    }

    async fn send(&self, request: Value, negotiated: bool, enabled: bool) -> Vec<u8> {
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: ModuleRuntime::with_stub_credentials_and_mock_transport(
                self.store.clone(),
                Arc::new(StubCredentialSource::with_default_success(
                    b"sample-key".to_vec(),
                )),
                self.transport.clone(),
            ),
        });
        let routes = Arc::new(RouteBindings::new());
        let principal = if request["name"] == manifest::EVENTS_GET_TOOL
            || (request["name"] == manifest::EVENTS_TOOL && request["arguments"]["op"] == "get")
        {
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            }
        } else {
            Principal::Direct
        };
        let bind = ModuleControlRequest::RouteBind {
            route_channel: 41,
            epoch: 1,
            target: subc_protocol::RouteTarget::ToolProvider {
                module_id: DEFAULT_MODULE_ID.into(),
            },
            identity: BindIdentity::new("reply-guard-fixtures", "session"),
            principal: Some(principal),
            scope: None,
            call_mode: None,
            role_versions: None,
            consumer_capabilities: negotiated.then(|| vec![TOOL_RESULT_V1_CAPABILITY.into()]),
            admission_facts: None,
        };
        let (writer, mut responses) = mpsc::channel(1);
        handle_control_request(
            Frame::build(
                FrameType::Request,
                wire::control_flags(),
                0,
                0,
                1,
                serde_json::to_vec(&bind).unwrap(),
            )
            .unwrap(),
            &writer,
            &state,
            &routes,
        )
        .await
        .unwrap();
        let ack = bounded::recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "reply guard fixture bind",
        )
        .await;
        assert_eq!(ack.header.ty, FrameType::Response);
        assert_eq!(
            routes.binding(41, 1).unwrap().unwrap().reads_tool_result_v1,
            negotiated
        );
        STABLE_DISPATCH.set(true);
        let _stable = StableDispatch;
        handle_tool_request_with_reply_guard(
            Frame::build(
                FrameType::Request,
                wire::control_flags(),
                41,
                1,
                7,
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap(),
            &writer,
            &state,
            &routes,
            request_execution::RequestBudget::new(),
            false,
            enabled,
        )
        .await
        .unwrap();
        let reply = bounded::recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "reply guard fixture response",
        )
        .await;
        assert_eq!(reply.header.ty, FrameType::Response);
        reply.body
    }
}

fn call(tool: &str, arguments: Value) -> Value {
    json!({"name":tool,"arguments":arguments})
}

fn parsed(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

fn sample_case(tool: &str, large: bool) -> (Fixture, Value) {
    let fixture = Fixture::new();
    let arguments = match tool {
        manifest::CONNECTIONS_TOOL => {
            if large {
                fixture.connection(&"x".repeat(70_000));
            }
            json!({"op":"list"})
        }
        manifest::CATALOG_TOOL => {
            fixture.action(large);
            json!({"op":"list","connection":"conn-sample"})
        }
        manifest::REQUESTS_TOOL => {
            if large {
                fixture.connection("conn-sample");
                fixture.sql().execute(
                    "INSERT INTO action_requests(request_id,principal,connection_id,action,args_snapshot,schema_hash,requester,status,expires_at,created_at_ms)
                     VALUES ('request-sample','direct','conn-sample','sample',?1,'hash','direct','pending',9223372036854775807,1)",
                    [json!({"data":"x".repeat(70_000)}).to_string()],
                ).unwrap();
            }
            json!({"op":"list"})
        }
        // `op:list` pages pass unguarded until they are cut by bytes (see the
        // guard), so the oversized sample is the guarded `op:get` read.
        manifest::EVENTS_TOOL => {
            if large {
                let (key, _) = fixture.event(true);
                json!({"op":"get","event_key":key,"event_name":"github_issue_changed"})
            } else {
                json!({"op":"list"})
            }
        }
        manifest::INVOKE_TOOL => {
            fixture.invoke(large);
            json!({"op":"call","connection":"conn-sample","action":"sample","args":{}})
        }
        manifest::EVENTS_GET_TOOL => {
            let (key, _) = fixture.event(large);
            json!({"event_key":key,"event_name":"github_issue_changed"})
        }
        manifest::WITHDRAW_TOOL => json!({}),
        _ => unreachable!(),
    };
    let mut request = call(tool, arguments);
    if large && tool == manifest::WITHDRAW_TOOL {
        // Withdrawal has no unbounded success output. Exercise its common
        // pre-dispatch refusal instead, without inventing a held-call shape.
        request["preset"] = json!("x".repeat(70_000));
    }
    (fixture, request)
}

#[tokio::test]
async fn handler_reply_fixtures_match_bytes() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/reply-too-large-v1");
    let regenerate = std::env::var(REGENERATE).as_deref() == Ok("1");
    let mut samples = std::collections::BTreeMap::new();
    for tool in TOOLS {
        for negotiated in [false, true] {
            let route = if negotiated { "capable" } else { "legacy" };
            for large in [false, true] {
                let (fixture, request) = sample_case(tool, large);
                let disabled = fixture.send(request.clone(), negotiated, false).await;
                let before = fixture.transport.requests().len();
                let enabled = fixture.send(request, negotiated, true).await;
                assert_eq!(
                    fixture.transport.requests().len() - before,
                    usize::from(*tool == manifest::INVOKE_TOOL),
                    "{tool}: one dispatch per call, never a replay"
                );
                let reply = parsed(&enabled);
                assert!(
                    reply_guard::EffectiveFormat::Legacy.fits(&reply),
                    "{tool}: {reply}"
                );
                if large {
                    assert!(
                        !reply_guard::EffectiveFormat::Legacy.fits(&parsed(&disabled)),
                        "{tool}: fixture must overflow without the guard"
                    );
                    if *tool == manifest::INVOKE_TOOL {
                        assert_eq!(reply["result"]["transmission"], "completed", "{reply}");
                        assert_eq!(
                            reply["result"]["response"]["error"]["code"],
                            "response_too_large"
                        );
                        assert_eq!(reply["result"]["reservation_id"], "reservation-sample");
                    } else if *tool == manifest::WITHDRAW_TOOL {
                        assert_eq!(reply["error"]["code"], "invalid_request");
                    } else {
                        assert_eq!(reply["error"]["code"], "response_too_large");
                        assert_eq!(reply["error"]["transmission"], "completed");
                        assert_eq!(reply["error"]["output_discarded"], true);
                    }
                } else {
                    assert_eq!(
                        enabled, disabled,
                        "{tool}: small replies must be byte-identical"
                    );
                }
                let size = if large { "oversized" } else { "small" };
                samples.insert(format!("{tool}-{size}-{route}.json"), enabled);
            }
        }
    }
    let mut sums = String::new();
    for (name, bytes) in samples {
        sums.push_str(&format!("{:x}  {name}\n", Sha256::digest(&bytes)));
        let path = directory.join(&name);
        if regenerate {
            std::fs::write(path, bytes).unwrap();
        } else {
            assert_eq!(
                std::fs::read(&path).unwrap_or_else(|error| panic!(
                    "{}: {error}; regenerate with {REGENERATE}=1",
                    path.display()
                )),
                bytes,
                "{name}: routed reply bytes changed"
            );
        }
    }
    if regenerate {
        std::fs::write(directory.join("SHA256SUMS"), sums).unwrap();
    } else {
        assert_eq!(
            std::fs::read_to_string(directory.join("SHA256SUMS")).unwrap(),
            sums
        );
    }
}

#[tokio::test]
async fn stored_event_bodies_are_never_modified_by_the_guard() {
    for version in [1, 2] {
        let fixture = Fixture::new();
        let (key, raw) = fixture.event(true);
        let stored = || {
            fixture.sql().query_row(
            "SELECT body_v1,digest_v1,envelope_v2,digest_v2 FROM event_outbox WHERE event_key=?1", [&key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)),
        ).unwrap()
        };
        let before = stored();
        for tool in [manifest::EVENTS_GET_TOOL, manifest::EVENTS_TOOL] {
            let mut args =
                json!({"event_key":key,"event_name":"github_issue_changed","version":version});
            if tool == manifest::EVENTS_TOOL {
                args["op"] = json!("get");
            }
            let unguarded = parsed(&fixture.send(call(tool, args.clone()), true, false).await);
            assert_eq!(unguarded["result"]["body"], raw);
            let guarded = parsed(&fixture.send(call(tool, args), true, true).await);
            assert_eq!(guarded["error"]["code"], "response_too_large");
            assert_eq!(guarded["error"]["retryable"], false);
            assert!(reply_guard::EffectiveFormat::Legacy.fits(&guarded));
        }
        assert_eq!(stored(), before, "neither body nor digest may change");
    }
}

#[tokio::test]
async fn oversized_early_refusals_keep_their_code_and_do_not_dispatch() {
    for tool in TOOLS {
        let fixture = Fixture::new();
        for negotiated in [false, true] {
            let mut request = call(tool, json!({}));
            request["preset"] = json!("🦀\"\\".repeat(20_000));
            let disabled = fixture.send(request.clone(), negotiated, false).await;
            assert!(
                !reply_guard::EffectiveFormat::Legacy.fits(&parsed(&disabled)),
                "{tool}"
            );
            let enabled = parsed(&fixture.send(request, negotiated, true).await);
            assert!(
                reply_guard::EffectiveFormat::Legacy.fits(&enabled),
                "{tool}"
            );
            assert_eq!(enabled["error"]["code"], "invalid_request");
            assert_eq!(enabled["error"]["field"], "preset");
            assert_eq!(
                enabled["error"]["preset"],
                plexus_core::text::refusal_echo(&"🦀\"\\".repeat(20_000)).into_owned()
            );
        }
        assert!(fixture.transport.requests().is_empty());
    }
}

#[tokio::test]
async fn excluded_tools_keep_identical_routed_bytes_even_when_oversized() {
    for tool in [
        manifest::GITHUB_TOOL,
        manifest::GITHUB_REACT_TOOL,
        manifest::GITHUB_READ_TOOL,
        manifest::WEB_SEARCH_TOOL,
        manifest::CODE_SEARCH_TOOL,
    ] {
        let fixture = Fixture::new();
        for negotiated in [false, true] {
            let mut request = call(tool, json!({}));
            request["preset"] = json!("x".repeat(70_000));
            let disabled = fixture.send(request.clone(), negotiated, false).await;
            let enabled = fixture.send(request, negotiated, true).await;
            assert_eq!(enabled, disabled, "{tool}");
            if matches!(tool, manifest::GITHUB_TOOL | manifest::GITHUB_REACT_TOOL) {
                assert!(!reply_guard::EffectiveFormat::Legacy.fits(&parsed(&enabled)));
            }
        }
        assert!(fixture.transport.requests().is_empty());
    }
}

#[test]
fn refusal_detail_and_pending_identity_are_not_completed_output() {
    let guard = |facade: Value| {
        let rendered = with_call_tool_result_with_repo(
            Some(manifest::INVOKE_TOOL),
            facade.clone(),
            None,
            false,
        );
        remaining_tool_guard::guard(Some(manifest::INVOKE_TOOL), facade, rendered)
    };
    let refusal = guard(json!({"error": {
        "code":"permission_denied", "retryable":false, "retry_after_ms":17,
        "transmission":"not_sent", "detail":vec![true; 80_000]
    }}));
    assert_eq!(refusal["error"]["code"], "permission_denied");
    assert_eq!(refusal["error"]["retryable"], false);
    assert_eq!(refusal["error"]["retry_after_ms"], 17);
    assert_eq!(refusal["error"]["transmission"], "not_sent");
    assert_eq!(refusal["error"]["detail_omitted"], true);
    assert!(refusal["error"].get("detail").is_none());
    let pending = guard(json!({"error": {
        "code":"access_pending", "message":"x".repeat(70_000), "elicitation_id":"pending-sample"
    }}));
    assert_eq!(pending["error"]["code"], "access_pending");
    assert_eq!(pending["error"]["transmission"], "pending");
    assert_eq!(pending["error"]["elicitation_id"], "pending-sample");
    assert!(reply_guard::EffectiveFormat::Legacy.fits(&pending));
    let many_echoes = guard(json!({"error": {
        "code":"invalid_request", "preset":vec![false; 80_000]
    }}));
    assert_eq!(many_echoes["error"]["code"], "response_too_large");
    assert_eq!(many_echoes["error"]["transmission"], "refused");
}

#[test]
fn dispatch_states_and_execution_evidence_survive_discarded_output() {
    for transmission in ["completed", "failed", "not_sent", "outcome_unknown"] {
        let facade = json!({"result":{
            "reservation_id":"reservation-sample", "transmission":transmission,
            "retryability":"terminal", "response":{"data":"x".repeat(70_000)},
            "reconciliation":{"status":"pending"}, "message":"original execution message"
        }});
        let rendered = with_call_tool_result_with_repo(
            Some(manifest::INVOKE_TOOL),
            facade.clone(),
            None,
            false,
        );
        let guarded = remaining_tool_guard::guard(Some(manifest::INVOKE_TOOL), facade, rendered);
        assert_eq!(guarded["result"]["transmission"], transmission);
        assert_eq!(guarded["result"]["reservation_id"], "reservation-sample");
        assert_eq!(guarded["result"]["retryability"], "terminal");
        assert_eq!(
            guarded["result"]["reconciliation"],
            json!({"status":"pending"})
        );
        assert_eq!(guarded["result"]["message"], "original execution message");
        assert_eq!(
            guarded["result"]["response"]["error"]["code"],
            "response_too_large"
        );
        assert!(reply_guard::EffectiveFormat::Legacy.fits(&guarded));
    }
}

#[test]
fn exclusions_are_explicit_and_the_guard_ships_enabled() {
    assert!(std::hint::black_box(remaining_tool_guard::ENABLED));
    for tool in TOOLS {
        assert!(remaining_tool_guard::covers(Some(tool)));
    }
    for tool in [
        manifest::GITHUB_TOOL,
        manifest::GITHUB_REACT_TOOL,
        manifest::GITHUB_READ_TOOL,
        manifest::WEB_SEARCH_TOOL,
        manifest::CODE_SEARCH_TOOL,
        "tool.catalog",
        "role.describe",
        "github.read.bulk",
        manifest::ADMIN_LIST_GRANTS_OP,
    ] {
        assert!(!remaining_tool_guard::covers(Some(tool)), "{tool}");
    }
}
