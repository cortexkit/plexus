use super::*;
use subc_protocol::session::{OperatorConfirmReply, OperatorConfirmRequest};

#[path = "operator_confirmation_tests/bulk_invoke.rs"]
mod bulk_invoke;

const CONNECTION: &str = "conn-retire-rest";
const HANDLE: &str = "app-confirm";

struct Installation;
impl plexus_core::github::control::InstallationReader for Installation {
    fn repositories_page(
        &self,
        _: &plexus_core::credentials::ResolvedCredential,
        _: usize,
        _: usize,
    ) -> Result<Value, String> {
        Ok(json!({"repositories":[{"full_name":"org/one"},{"full_name":"org/two"}]}))
    }
}

fn inventory() -> Value {
    json!({"version":"github-grant-import.v1","handles":[{
        "app_handle_id":HANDLE,"agent_id":"agent-confirm","app_id":42,
        "installation_id":null,"credential_id":"github_app:app-confirm","status":"enabled",
        "grants":[{"action":"create_issue","repository":"org/one","provenance":"operator","policy":"allow"}]
    }]})
}

struct Case {
    path: DiagnosticStorePath,
    state: Arc<ModuleState>,
    method: &'static str,
    params: Value,
    /// The MCP vendor discovery reaches, for the cases that connect to one.
    _vendor: Option<plexus_conformance::stub_server::StubMcpServer>,
}

fn install_catalog_manifest(store: &PlexusStore, source: &str) {
    let manifest = plexus_core::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap();
    store.upsert_manifest("system", &manifest).unwrap();
}

impl Case {
    fn new(method: &'static str) -> Self {
        let (path, store, _) = two_connection_fixture("operator-confirm");
        store
            .seed_catalog_from_manifest("direct", CONNECTION, "exa_rest")
            .unwrap();
        let database = rusqlite::Connection::open(&path).unwrap();
        database
            .execute(
                "UPDATE connections SET ceiling_risk = 'read', ceiling_selectors = '[\"search\"]'",
                [],
            )
            .unwrap();
        let mut runtime = runtime_for_test(store.clone());
        runtime.github_handle_credentials = Some(Arc::new(AnyHandleToken));
        runtime.github_control_reader = Some(Arc::new(Installation));
        let mut vendor = None;
        let params = match method {
            manifest::ADMIN_ISSUE_TICKET_OP => {
                json!({"app_key":"exa_rest","connection_id":"conn-new","credential_id":"apikey:exa"})
            }
            manifest::ADMIN_GRANT_OP => {
                json!({"connection_id":CONNECTION,"grantee_principal":"reserved:basal","action_selectors":["search"]})
            }
            manifest::ADMIN_WIDEN_CEILING_OP => {
                database
                    .execute("UPDATE connections SET ceiling_selectors = '[]'", [])
                    .unwrap();
                json!({"connection_id":CONNECTION,"actions":["search"],"dry_run":false})
            }
            manifest::ADMIN_SET_POLICY_OP => {
                json!({"connection_id":CONNECTION,"action_selector":"search","effect":"allow"})
            }
            manifest::ADMIN_REPIN_ACTION_OP => {
                let action = store
                    .catalog_action("direct", CONNECTION, "search")
                    .unwrap()
                    .unwrap();
                store
                    .quarantine_action("direct", CONNECTION, "search", "schema changed")
                    .unwrap();
                json!({"connection_id":CONNECTION,"action":"search","expected_schema_hash":action.schema_hash})
            }
            manifest::ADMIN_REBIND_CREDENTIAL_OP => {
                json!({"connection_id":CONNECTION,"credential_id":"apikey:exa","apply":true})
            }
            manifest::ADMIN_RECIPIENTS_ADD_OP => {
                json!({"connection":CONNECTION,"recipient":"person@example.com","dry_run":false})
            }
            manifest::ADMIN_ADD_WEB_SEARCH_PROVIDER_OP => {
                let source = include_str!("../../../catalog/tavily_rest.jsonc");
                let manifest = plexus_core::ingest_value(
                    serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
                )
                .unwrap();
                store.upsert_manifest("system", &manifest).unwrap();
                json!({"provider":"tavily","grantees":["reserved:basal"],"dry_run":false})
            }
            manifest::ADMIN_ADD_WRITE_CONNECTION_OP => {
                store
                    .upsert_manifest(
                        "system",
                        &test_write_manifest("confirm_write", "https://confirm.invalid/mcp"),
                    )
                    .unwrap();
                let stub = plexus_conformance::stub_server::StubMcpServer::start(vec![
                    plexus_conformance::stub_server::StubTool::simple("held_write"),
                ])
                .unwrap();
                runtime.endpoint_override = Some(stub.endpoint().to_string());
                vendor = Some(stub);
                json!({"app_key":"confirm_write","connection_id":"conn-confirm-write",
                    "credential_id":"apikey:write","actions":["held_write"],
                    "grantees":["reserved:basal"],"dry_run":false})
            }
            manifest::ADMIN_ADD_POLL_CONNECTION_OP => {
                install_catalog_manifest(
                    &store,
                    include_str!("../../../catalog/github_actions.jsonc"),
                );
                json!({"app_key":"github_actions","connection_id":"conn-confirm-poll",
                    "credential_id":"apikey:github","actions":["list_workflow_runs"],
                    "dry_run":false})
            }
            manifest::ADMIN_WIDEN_AND_GRANT_OP => {
                database
                    .execute("UPDATE connections SET ceiling_selectors = '[]'", [])
                    .unwrap();
                json!({"connection_id":CONNECTION,"actions":["search"],
                    "grantees":["reserved:basal"],"dry_run":false})
            }
            manifest::ADMIN_ONBOARD_GITHUB_BOT_OP => {
                install_catalog_manifest(
                    &store,
                    include_str!("../../../catalog/github_rest.jsonc"),
                );
                json!({"inventory":inventory(),"actions":["add_issue_comment"],
                    "carrier":"reserved:basal","effect":"allow",
                    "shim_manifest_maps_repo":true,"dry_run":false})
            }
            manifest::GITHUB_IMPORT_OP | manifest::GITHUB_BIND_OP | manifest::GITHUB_GRANT_OP => {
                let source = include_str!("../../../catalog/github_rest.jsonc");
                let manifest = plexus_core::ingest_value(
                    serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
                )
                .unwrap();
                store.upsert_manifest("system", &manifest).unwrap();
                if method != manifest::GITHUB_IMPORT_OP {
                    plexus_core::github::control::import(
                        &store,
                        "direct",
                        &serde_json::from_value(inventory()).unwrap(),
                        &AnyHandleToken,
                        &Installation,
                        plexus_core::now_ms(),
                        false,
                    )
                    .unwrap();
                }
                match method {
                    manifest::GITHUB_IMPORT_OP => json!({"inventory":inventory(),"dry_run":false}),
                    manifest::GITHUB_BIND_OP => {
                        json!({"app_handle_id":HANDLE,"repositories":["org/two"],"dry_run":false})
                    }
                    _ => {
                        json!({"app_handle_id":HANDLE,"actions":["create_issue"],"module":"reserved:basal","effect":"allow","dry_run":false})
                    }
                }
            }
            _ => unreachable!(),
        };
        Self {
            path,
            state: Arc::new(ModuleState {
                health: Arc::new(health::HealthState::new()),
                runtime,
            }),
            method,
            params,
            _vendor: vendor,
        }
    }

    // Compare every durable table, not just the operation's expected row. Audit
    // entries are excluded only after a refusal, which must append its own row.
    fn snapshot(&self, include_audit: bool) -> Vec<(String, Vec<String>)> {
        let db = rusqlite::Connection::open(&self.path).unwrap();
        let tables: Vec<String> = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap()
            .query_map([], |row| row.get(0)).unwrap().map(Result::unwrap).collect();
        tables
            .into_iter()
            .filter(|table| include_audit || table != "audit_journal")
            .map(|table| {
                let mut statement = db
                    .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
                    .unwrap();
                let count = statement.column_count();
                let mut rows: Vec<String> = statement
                    .query_map([], |row| {
                        Ok((0..count)
                            .map(|column| format!("{:?}", row.get_ref(column).unwrap()))
                            .collect::<Vec<_>>()
                            .join("|"))
                    })
                    .unwrap()
                    .map(Result::unwrap)
                    .collect();
                rows.sort();
                (table, rows)
            })
            .collect()
    }
}

const WIDENING: &[&str] = &[
    manifest::ADMIN_ISSUE_TICKET_OP,
    manifest::ADMIN_GRANT_OP,
    manifest::ADMIN_WIDEN_CEILING_OP,
    manifest::ADMIN_SET_POLICY_OP,
    manifest::ADMIN_REPIN_ACTION_OP,
    manifest::ADMIN_REBIND_CREDENTIAL_OP,
    manifest::ADMIN_RECIPIENTS_ADD_OP,
    manifest::GITHUB_IMPORT_OP,
    manifest::GITHUB_BIND_OP,
    manifest::GITHUB_GRANT_OP,
    manifest::ADMIN_ADD_WEB_SEARCH_PROVIDER_OP,
    manifest::ADMIN_ADD_WRITE_CONNECTION_OP,
    manifest::ADMIN_ADD_POLL_CONNECTION_OP,
    manifest::ADMIN_WIDEN_AND_GRANT_OP,
    manifest::ADMIN_ONBOARD_GITHUB_BOT_OP,
];

fn route() -> RouteFrameContext {
    RouteFrameContext {
        version: PROTOCOL_VERSION,
        channel: 7,
        epoch: 3,
        correlation: 92,
    }
}

#[test]
fn summary_validator_matches_daemon_boundaries() {
    use operator_confirmation::valid_summary;
    assert!(valid_summary("a"));
    assert!(valid_summary(&"é".repeat(200)));
    assert!(!valid_summary(&"é".repeat(201)));
    for text in [
        "",
        " leading",
        "trailing ",
        "\u{a0}leading",
        "trailing\u{3000}",
    ] {
        assert!(!valid_summary(text), "accepted {text:?}");
    }
    for c in (0..=0x9f)
        .filter_map(char::from_u32)
        .filter(|c| c.is_control())
        .chain((0x200b..=0x200f).filter_map(char::from_u32))
        .chain((0x202a..=0x202e).filter_map(char::from_u32))
        .chain((0x2060..=0x2069).filter_map(char::from_u32))
        .chain(['\u{2028}', '\u{2029}', '\u{feff}'])
    {
        assert!(!valid_summary(&format!("before{c}after")), "accepted {c:?}");
    }
    for c in [
        '\u{200a}', '\u{2010}', '\u{2027}', '\u{202f}', '\u{205f}', '\u{206a}', '\u{fefe}',
    ] {
        assert!(valid_summary(&format!("before{c}after")), "rejected {c:?}");
    }
}

#[tokio::test]
async fn oversized_summary_is_refused_locally_without_sending_or_applying() {
    use crate::composite_admin::{self, Caller, Composite, ConnectorHome};
    struct Oversized;
    impl Composite for Oversized {
        fn dry_run(&self) -> bool {
            false
        }
        fn preview(&self) -> Value {
            json!({})
        }
        fn summary(&self) -> String {
            "x".repeat(201)
        }
    }
    let case = Case::new(manifest::ADMIN_GRANT_OP);
    let before = case.snapshot(false);
    let (writer, mut frames) = mpsc::channel(4);
    let bindings = Arc::new(RouteBindings::new());
    bindings
        .insert(route().channel, route().epoch, Principal::Direct)
        .unwrap();
    let applied = std::sync::atomic::AtomicBool::new(false);
    let run = composite_admin::run(
        Caller {
            route: route(),
            writer: &writer,
            state: &case.state,
            route_bindings: &bindings,
            method: case.method,
        },
        ConnectorHome::BeforeApplying,
        || Ok(Oversized),
        |_| {
            applied.store(true, std::sync::atomic::Ordering::SeqCst);
            json!({"applied": true})
        },
    );
    // Even a peer willing to approve invalid text must never receive it.
    let peer = async {
        if let Ok(Some(frame)) =
            tokio::time::timeout(std::time::Duration::from_millis(100), frames.recv()).await
        {
            let reply = Frame::build_with_version(
                frame.header.ver,
                FrameType::Response,
                wire::control_flags(),
                0,
                0,
                frame.header.corr,
                serde_json::to_vec(&OperatorConfirmReply::confirmed()).unwrap(),
            )
            .unwrap();
            assert!(bindings.control_replies.complete(reply));
            true
        } else {
            false
        }
    };
    let (result, sent) = tokio::join!(run, peer);
    let response = result.unwrap();
    assert_eq!(
        response["error"]["code"], "operator_summary_invalid",
        "invalid summary must be refused locally"
    );
    assert!(!sent, "invalid summary must not be sent");
    assert!(!applied.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        case.snapshot(false),
        before,
        "invalid summary must write no authority rows"
    );
    let db = rusqlite::Connection::open(&case.path).unwrap();
    let audits: i64 = db.query_row("SELECT COUNT(*) FROM audit_journal WHERE gate = 'operator_confirmation' AND reason_code = 'operator_summary_invalid' AND decision = 'deny' AND outcome = 'refused'", [], |row| row.get(0)).unwrap();
    assert_eq!(audits, 1, "local summary refusal must be audited");
}

fn answer(frame: &Frame, response: Result<(), &str>) -> Frame {
    let request: OperatorConfirmRequest = serde_json::from_slice(&frame.body).unwrap();
    assert!(
        operator_confirmation::valid_summary(&request.summary),
        "invalid operator summary: {}",
        request.summary
    );
    let (ty, body) = match response {
        Ok(()) => (
            FrameType::Response,
            serde_json::to_vec(&OperatorConfirmReply::confirmed()).unwrap(),
        ),
        Err(code) => (
            FrameType::Error,
            serde_json::to_vec(&subc_protocol::ErrorBody::new(code, "fake peer reason")).unwrap(),
        ),
    };
    Frame::build_with_version(
        frame.header.ver,
        ty,
        wire::control_flags(),
        0,
        0,
        frame.header.corr,
        body,
    )
    .unwrap()
}

async fn ceremony_with_peer(case: &Case, decision: Result<(), &str>, expect_prompt: bool) -> Value {
    let (writer, mut frames) = mpsc::channel(4);
    let bindings = Arc::new(RouteBindings::new());
    bindings
        .insert(route().channel, route().epoch, Principal::Direct)
        .unwrap();
    let before = case.snapshot(true);
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        wire::control_flags(),
        route().channel,
        route().epoch,
        route().correlation,
        serde_json::to_vec(&json!({"method":case.method,"params":case.params})).unwrap(),
    )
    .unwrap();
    let handler = handle_tool_request(frame, &writer, &case.state, &bindings);
    let peer = async {
        let mut frame = recv_within(
            frames.recv(),
            std::time::Duration::from_secs(5),
            "ceremony or confirmation",
        )
        .await;
        if expect_prompt {
            assert_eq!(
                frame.header.ty,
                FrameType::Request,
                "{} must ask before writing",
                case.method
            );
            assert_eq!((frame.header.channel, frame.header.epoch), (0, 0));
            let request: OperatorConfirmRequest = serde_json::from_slice(&frame.body).unwrap();
            assert!(operator_confirmation::valid_summary(&request.summary));
            if case.params["all_handles"] == true && case.params["kind"] == "invoke" {
                assert!(request.summary.contains("7 writes"));
                assert!(request.summary.contains("10 expanded"));
                assert!(request
                    .summary
                    .contains("all enabled GitHub handles (26 planned)"));
                assert!(!request.summary.contains("edit_pull_request"));
            }
            assert_eq!(
                (request.route_channel, request.route_epoch),
                (route().channel, route().epoch)
            );
            assert!(
                !request.summary.contains("apikey:")
                    && !request.summary.contains("github_app:")
                    && !request.summary.contains('\n')
            );
            assert_eq!(
                case.snapshot(true),
                before,
                "{} wrote before confirmation",
                case.method
            );
            assert!(bindings.control_replies.complete(answer(&frame, decision)));
            frame = recv_within(
                frames.recv(),
                std::time::Duration::from_secs(5),
                "ceremony result",
            )
            .await;
        }
        assert_eq!(
            frame.header.ty,
            FrameType::Response,
            "{} must not ask",
            case.method
        );
        assert_eq!(frame.header.channel, route().channel);
        serde_json::from_slice(&frame.body).unwrap()
    };
    let (result, response) = tokio::join!(handler, peer);
    result.unwrap();
    response
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_widening_ceremonies_refuse_without_confirmation() {
    for method in WIDENING {
        for (reason, code) in [
            ("operator_declined", "operator_confirmation_declined"),
            (
                "operator_presence_unavailable",
                "operator_confirmation_unavailable",
            ),
            (
                "unsupported_control_frame",
                "operator_confirmation_unavailable",
            ),
        ] {
            let case = Case::new(method);
            let before = case.snapshot(false);
            let response = ceremony_with_peer(&case, Err(reason), true).await;
            assert_eq!(response["error"]["code"], code, "{method}: {response}");
            assert!(response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("fake peer reason"));
            assert_eq!(
                case.snapshot(false),
                before,
                "{method} wrote after a refusal"
            );
            let db = rusqlite::Connection::open(&case.path).unwrap();
            let audit: (String, String) = db.query_row("SELECT decision, reason_code FROM audit_journal WHERE gate='operator_confirmation'", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
            assert_eq!(audit, ("deny".to_string(), code.to_string()));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_widening_ceremonies_write_only_after_confirmation() {
    for method in WIDENING {
        let case = Case::new(method);
        let before = case.snapshot(false);
        let response = ceremony_with_peer(&case, Ok(()), true).await;
        assert!(response.get("result").is_some(), "{method}: {response}");
        assert_ne!(
            case.snapshot(false),
            before,
            "{method} must commit its authority change"
        );
    }
    let mut poll = Case::new(manifest::GITHUB_GRANT_OP);
    poll.params = json!({"app_handle_id":HANDLE,"kind":"poll","actions":["github.issue.get"],"dry_run":false});
    let before = poll.snapshot(false);
    assert!(ceremony_with_peer(&poll, Ok(()), true)
        .await
        .get("result")
        .is_some());
    assert_ne!(poll.snapshot(false), before);
    let before = poll.snapshot(false);
    assert_eq!(
        ceremony_with_peer(&poll, Err("operator_declined"), true).await["error"]["code"],
        "operator_confirmation_declined"
    );
    assert_eq!(poll.snapshot(false), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn previews_never_request_confirmation() {
    for method in [
        manifest::ADMIN_WIDEN_CEILING_OP,
        manifest::ADMIN_REBIND_CREDENTIAL_OP,
        manifest::ADMIN_RECIPIENTS_ADD_OP,
        manifest::GITHUB_IMPORT_OP,
        manifest::GITHUB_BIND_OP,
        manifest::GITHUB_GRANT_OP,
        manifest::ADMIN_ADD_WEB_SEARCH_PROVIDER_OP,
        manifest::ADMIN_ADD_WRITE_CONNECTION_OP,
        manifest::ADMIN_ADD_POLL_CONNECTION_OP,
        manifest::ADMIN_WIDEN_AND_GRANT_OP,
        manifest::ADMIN_ONBOARD_GITHUB_BOT_OP,
    ] {
        for explicit_preview in [true, false] {
            let mut case = Case::new(method);
            let field = if method == manifest::ADMIN_REBIND_CREDENTIAL_OP {
                "apply"
            } else {
                "dry_run"
            };
            case.params.as_object_mut().unwrap().remove(field);
            if explicit_preview {
                case.params[field] = Value::Bool(field != "apply");
            }
            let before = case.snapshot(false);
            let response = ceremony_with_peer(&case, Err("operator_declined"), false).await;
            assert!(response.get("result").is_some(), "{method}: {response}");
            assert_eq!(
                case.snapshot(false),
                before,
                "{method} preview changed authority"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ungated_ceremonies_never_request_confirmation() {
    for effect in ["block", "ask_first"] {
        let mut case = Case::new(manifest::ADMIN_SET_POLICY_OP);
        case.params["effect"] = json!(effect);
        assert!(ceremony_with_peer(&case, Err("operator_declined"), false)
            .await
            .get("result")
            .is_some());
    }
    let mut case = Case::new(manifest::ADMIN_GRANT_OP);
    let minted = ceremony::grant(&case.state, "direct", &case.params);
    let policy = ceremony::set_policy(
        &case.state,
        "direct",
        &json!({"connection_id":CONNECTION,"action_selector":"search","effect":"allow"}),
    );
    ceremony::recipients(
        &case.state,
        &json!({"connection":CONNECTION,"recipient":"person@example.com","dry_run":false}),
        manifest::ADMIN_RECIPIENTS_ADD_OP,
    );
    for (method, params) in [
        (
            manifest::ADMIN_LIST_GRANTS_OP,
            json!({"connection_id":CONNECTION}),
        ),
        (
            manifest::ADMIN_LIST_POLICIES_OP,
            json!({"connection_id":CONNECTION}),
        ),
        (
            manifest::ADMIN_REVIEW_ACTION_OP,
            json!({"connection_id":CONNECTION,"action":"search"}),
        ),
        (
            manifest::ADMIN_RECIPIENTS_LIST_OP,
            json!({"connection":CONNECTION}),
        ),
        (
            manifest::ADMIN_REVOKE_GRANT_OP,
            json!({"grant_id":minted["result"]["grant"]["grant_id"]}),
        ),
        (
            manifest::ADMIN_REMOVE_POLICY_OP,
            json!({"policy_id":policy["result"]["policy"]["policy_id"]}),
        ),
        (
            manifest::ADMIN_RECIPIENTS_REMOVE_OP,
            json!({"connection":CONNECTION,"recipient":"person@example.com","dry_run":false}),
        ),
        (
            manifest::ADMIN_SET_WEB_SEARCH_LIMIT_OP,
            json!({"backend":"exa","per_caller_per_minute":100,"per_backend_per_minute":200,"dry_run":false}),
        ),
        (
            manifest::ADMIN_SET_WEB_SEARCH_ORDER_OP,
            json!({"providers":["exa","brave"],"dry_run":false}),
        ),
        (
            manifest::ADMIN_SET_WEB_SEARCH_ALLOWANCE_OP,
            json!({"provider":"exa","count":100,"dry_run":false}),
        ),
        (
            manifest::ADMIN_SET_WEB_SEARCH_ALLOWANCE_OP,
            json!({"provider":"exa","clear":true,"dry_run":false}),
        ),
        (
            manifest::ADMIN_SET_WEB_SEARCH_ORDER_OP,
            json!({"clear":true,"dry_run":false}),
        ),
        (relay::STATUS_OP, json!({})),
        (
            manifest::ADMIN_DELETE_CONNECTION_OP,
            json!({"connection_id":CONNECTION,"dry_run":false}),
        ),
    ] {
        case.method = method;
        case.params = params;
        let response = ceremony_with_peer(&case, Err("operator_declined"), false).await;
        assert!(response.get("result").is_some(), "{method}: {response}");
    }
    case.method = connector_home::STATUS_OP;
    case.params = json!({});
    let response = ceremony_with_peer(&case, Err("operator_declined"), false).await;
    assert_eq!(response["error"]["code"], "unavailable");
    let mut case = Case::new(manifest::GITHUB_BIND_OP);
    for (method, params) in [
        (manifest::GITHUB_PROBE_OP, json!({"app_handle_id":HANDLE})),
        (
            manifest::GITHUB_UNBIND_OP,
            json!({"app_handle_id":HANDLE,"repository":"org/one","dry_run":false}),
        ),
    ] {
        case.method = method;
        case.params = params;
        let response = ceremony_with_peer(&case, Err("operator_declined"), false).await;
        assert!(response.get("result").is_some(), "{method}: {response}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirmation_fails_closed_on_disconnect_malformed_reply_and_deadline() {
    let pending = Arc::new(PendingControlReplies::default());
    let (writer, frames) = mpsc::channel(1);
    drop(frames);
    let refusal = operator_confirmation::confirm("mint one grant", route(), &writer, &pending)
        .await
        .unwrap_err();
    assert_eq!(refusal.code, "operator_confirmation_unavailable");

    let (writer, mut frames) = mpsc::channel(1);
    let request = operator_confirmation::confirm("mint one grant", route(), &writer, &pending);
    let malformed_peer = async {
        let frame = recv_within(
            frames.recv(),
            std::time::Duration::from_secs(5),
            "confirmation request",
        )
        .await;
        let reply = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Response,
            wire::control_flags(),
            0,
            0,
            frame.header.corr,
            br#"{"op":"operator.confirm","outcome":"maybe"}"#.to_vec(),
        )
        .unwrap();
        assert!(pending.complete(reply));
    };
    let (result, ()) = tokio::join!(request, malformed_peer);
    assert_eq!(
        result.unwrap_err().code,
        "operator_confirmation_unavailable"
    );

    let request = operator_confirmation::confirm_with_timeout(
        "mint one grant",
        route(),
        &writer,
        &pending,
        std::time::Duration::from_millis(20),
    );
    let silent_peer = async {
        let frame = recv_within(
            frames.recv(),
            std::time::Duration::from_secs(5),
            "confirmation request",
        )
        .await;
        let cancel = recv_within(
            frames.recv(),
            std::time::Duration::from_secs(5),
            "confirmation withdrawal",
        )
        .await;
        assert_eq!(
            (cancel.header.ty, cancel.header.corr),
            (FrameType::Cancel, frame.header.corr)
        );
        assert!(
            !pending.complete(answer(&frame, Ok(()))),
            "a late approval cannot authorize another write"
        );
    };
    let (result, ()) = tokio::join!(request, silent_peer);
    assert_eq!(
        result.unwrap_err().code,
        "operator_confirmation_unavailable"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_read_upgrade_confirmation_and_preview_are_fenced() {
    for all in [false, true] {
        let mut case = Case::new(manifest::GITHUB_GRANT_OP);
        case.params = json!({"kind":"read","module":"reserved:basal","actions":["github.repo.get"],"dry_run":true});
        if all {
            case.params["all_handles"] = json!(true);
        } else {
            case.params["app_handle_id"] = json!(HANDLE);
        }
        let db = rusqlite::Connection::open(&case.path).unwrap();
        db.execute(
            "DELETE FROM catalog_actions WHERE name='github.repo.get'",
            [],
        )
        .unwrap();
        let before = case.snapshot(true);
        let preview = ceremony_with_peer(&case, Err("operator_declined"), false).await;
        assert!(preview.get("result").is_some(), "{preview}");
        assert_eq!(
            case.snapshot(true),
            before,
            "read preview must write no audit or catalog rows"
        );
        case.params["dry_run"] = json!(false);
        for (reason, code) in [
            ("operator_declined", "operator_confirmation_declined"),
            (
                "unsupported_control_frame",
                "operator_confirmation_unavailable",
            ),
        ] {
            let before = case.snapshot(false);
            let reply = ceremony_with_peer(&case, Err(reason), true).await;
            assert_eq!(reply["error"]["code"], code, "{reply}");
            assert_eq!(case.snapshot(false), before);
            let count: i64 = db.query_row("SELECT count(*) FROM audit_journal WHERE gate='operator_confirmation' AND reason_code=?1", [code], |row| row.get(0)).unwrap();
            assert_eq!(count, 1);
        }
        let applied = ceremony_with_peer(&case, Ok(()), true).await;
        assert!(applied.get("result").is_some(), "{applied}");
        let before = case.snapshot(true);
        let no_op = ceremony_with_peer(&case, Ok(()), true).await;
        assert!(no_op.get("result").is_some(), "{no_op}");
        assert_eq!(
            case.snapshot(true),
            before,
            "read no-op must change nothing"
        );
    }
}
