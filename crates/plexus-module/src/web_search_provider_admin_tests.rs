//! `plexus.admin.add_web_search_provider`: one confirmation for a provider's
//! ticket, connection and caller grants, with the rows the manual commands
//! write, idempotent reruns, and nothing written or sent before confirmation.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use subc_protocol::session::{OperatorConfirmReply, OperatorConfirmRequest};

const ADD: &str = manifest::ADMIN_ADD_WEB_SEARCH_PROVIDER_OP;
/// The callers that hold search grants on the deployed Exa connection.
const CALLERS: [&str; 3] = [
    "reserved:broca",
    "reserved:prefrontal-core",
    "reserved:basal",
];
const SEARXNG_CANARY: &str = "https://private-searx-canary.invalid/secret-instance-path";

pub(super) struct Fixture {
    pub(super) path: DiagnosticStorePath,
    pub(super) store: Arc<PlexusStore>,
    pub(super) state: Arc<ModuleState>,
}

pub(super) fn install(store: &PlexusStore, app: &str) {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../catalog/{app}.jsonc")),
    )
    .unwrap();
    let manifest = plexus_core::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap(),
    )
    .unwrap();
    store.upsert_manifest("system", &manifest).unwrap();
}

/// A state whose discovery is sent to `endpoint` instead of the vendor. Every
/// test that can reach MCP discovery passes a local endpoint, so no test can
/// contact Z.AI.
pub(super) fn state_with_endpoint(
    store: &Arc<PlexusStore>,
    endpoint: Option<&str>,
) -> Arc<ModuleState> {
    let mut runtime = runtime_for_test(Arc::clone(store));
    runtime.endpoint_override = endpoint.map(str::to_owned);
    Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    })
}

fn fixture(label: &str) -> Fixture {
    let path = DiagnosticStorePath::new(label);
    let store = Arc::new(crate::test_support::open_file_store(&path));
    for app in ["exa_rest", "tavily_rest", "searxng_rest", "zai"] {
        install(&store, app);
    }
    let state = state_with_endpoint(&store, None);
    Fixture { path, store, state }
}

pub(super) fn sql(path: &Path, statement: &str) {
    rusqlite::Connection::open(path)
        .unwrap()
        .execute(statement, [])
        .unwrap();
}

fn mint(store: &PlexusStore, connection: &str, grantee: &str, kind: &str) -> String {
    store
        .mint_grant_bounded(&plexus_core::GrantMintRequest {
            principal: "direct",
            connection_id: connection,
            grantee_principal: grantee,
            authority_kind: kind,
            requested_risk: "read",
            requested_selectors: &["search".to_string()],
            expires_at: None,
        })
        .unwrap()
        .unwrap()
        .grant_id
}

/// The deployed shape: Exa on `conn-exa-rest` with a search grant per caller.
fn seed_exa_callers(fixture: &Fixture) {
    fixture
        .store
        .insert_connection("direct", "conn-exa-rest", "exa_rest", "active", &json!({}))
        .unwrap();
    sql(
        &fixture.path,
        "UPDATE connections SET ceiling_risk = 'read', ceiling_selectors = '[\"search\"]'
         WHERE connection_id = 'conn-exa-rest'",
    );
    for caller in CALLERS {
        mint(&fixture.store, "conn-exa-rest", caller, "invoke");
    }
}

pub(super) fn snapshot(path: &Path, include_audit: bool) -> Vec<(String, Vec<String>)> {
    let db = rusqlite::Connection::open(path).unwrap();
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
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

/// Rows of `table` with every column named, minus the ones that differ
/// between two runs by construction: generated ids and clock readings
/// (`proven_at` is when a GitHub handle's installation was last proven).
pub(super) fn rows(path: &Path, table: &str, filter: &str) -> Vec<Vec<(String, String)>> {
    let db = rusqlite::Connection::open(path).unwrap();
    let mut statement = db
        .prepare(&format!("SELECT * FROM {table} {filter}"))
        .unwrap();
    let names: Vec<String> = statement
        .column_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let volatile = |name: &str| {
        name.ends_with("_ms")
            || matches!(
                name,
                "ts" | "journal_id"
                    | "request_id"
                    | "grant_id"
                    | "ticket_id"
                    | "policy_id"
                    | "proven_at"
            )
            || (table == "binding_tickets" && name == "expires_at")
    };
    let mut rows: Vec<Vec<(String, String)>> = statement
        .query_map([], |row| {
            Ok(names
                .iter()
                .enumerate()
                .filter(|(_, name)| !volatile(name))
                .map(|(index, name)| (name.clone(), format!("{:?}", row.get_ref(index).unwrap())))
                .collect())
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    rows.sort();
    rows
}

pub(super) fn count(path: &Path, query: &str) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(query, [], |row| row.get(0))
        .unwrap()
}

fn answer(frame: &Frame, decision: Result<(), &str>) -> Frame {
    let request: OperatorConfirmRequest = serde_json::from_slice(&frame.body).unwrap();
    assert!(
        operator_confirmation::valid_summary(&request.summary),
        "invalid operator summary: {}",
        request.summary
    );
    let (ty, body) = match decision {
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

pub(super) struct Outcome {
    pub(super) reply: Value,
    /// The summary of every operator confirmation the request asked for.
    pub(super) prompts: Vec<String>,
}

/// Serve one request as the daemon would, answering every operator
/// confirmation with `decision` through a fake presence peer, never a real confirmation prompt.
/// At each prompt the store must still be exactly as it was before the
/// request: nothing is written before confirmation.
pub(super) async fn request(
    state: &Arc<ModuleState>,
    path: &Path,
    body: Value,
    decision: Result<(), &'static str>,
) -> Outcome {
    let (writer, mut frames) = mpsc::channel(4);
    let bindings = Arc::new(RouteBindings::new());
    bindings.insert(7, 3, Principal::Direct).unwrap();
    let before = snapshot(path, true);
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        wire::control_flags(),
        7,
        3,
        92,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let handler = handle_tool_request(frame, &writer, state, &bindings);
    let peer = async {
        let mut prompts = Vec::new();
        loop {
            let frame = recv_within(
                frames.recv(),
                std::time::Duration::from_secs(60),
                "reply or confirmation",
            )
            .await;
            if frame.header.channel == 0 && frame.header.ty == FrameType::Request {
                let asked: OperatorConfirmRequest = serde_json::from_slice(&frame.body).unwrap();
                assert!(
                    !asked.summary.contains("apikey:")
                        && !asked.summary.contains("github_app:")
                        && !asked.summary.contains('\n'),
                    "a prompt names no vault reference and is one line: {}",
                    asked.summary
                );
                assert_eq!(
                    snapshot(path, true),
                    before,
                    "nothing may be written before confirmation"
                );
                prompts.push(asked.summary);
                assert!(bindings.control_replies.complete(answer(&frame, decision)));
                continue;
            }
            assert_eq!(frame.header.ty, FrameType::Response);
            return Outcome {
                reply: serde_json::from_slice(&frame.body).unwrap(),
                prompts,
            };
        }
    };
    let (result, outcome) = tokio::join!(handler, peer);
    result.unwrap();
    outcome
}

async fn add(
    state: &Arc<ModuleState>,
    path: &Path,
    params: Value,
    decision: Result<(), &'static str>,
) -> Outcome {
    request(
        state,
        path,
        json!({"method": ADD, "params": params}),
        decision,
    )
    .await
}

fn grantees(reply: &Value) -> Vec<(String, String)> {
    reply["result"]["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|grant| {
            (
                grant["grantee"].as_str().unwrap().to_string(),
                grant["status"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[tokio::test]
async fn longest_provider_with_all_callers_has_a_daemon_valid_summary() {
    let fixture = fixture("longest-provider-summary");
    let provider = plexus_core::web_search::providers::PROVIDER_NAMES
        .iter()
        .max_by_key(|p| p.name.len())
        .unwrap();
    install(&fixture.store, provider.app_key);
    let outcome = add(
        &fixture.state,
        &fixture.path,
        json!({"provider": provider.name, "grantees": CALLERS}),
        Ok(()),
    )
    .await;
    let summary = outcome.reply["result"]["summary"]
        .as_str()
        .unwrap_or_else(|| panic!("{}", outcome.reply));
    assert!(operator_confirmation::valid_summary(summary), "{summary}");
    assert!(summary.contains(provider.name));
    assert!(summary.contains("3 callers"));
    assert!(!summary.contains("private-instance"));
    assert!(!summary.contains("apikey:"));
}

/// A vendor that counts every connection and closes it at once, so MCP
/// discovery against it fails fast and every contact is visible.
pub(super) struct CountingVendor {
    pub(super) url: String,
    contacts: Arc<AtomicUsize>,
    running: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CountingVendor {
    pub(super) fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let contacts = Arc::new(AtomicUsize::new(0));
        let running = Arc::new(AtomicBool::new(true));
        let thread = {
            let contacts = Arc::clone(&contacts);
            let running = Arc::clone(&running);
            std::thread::spawn(move || {
                while running.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            contacts.fetch_add(1, Ordering::SeqCst);
                            drop(stream);
                        }
                        Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                    }
                }
            })
        };
        Self {
            url,
            contacts,
            running,
            thread: Some(thread),
        }
    }

    pub(super) fn contacts(&self) -> usize {
        self.contacts.load(Ordering::SeqCst)
    }
}

impl Drop for CountingVendor {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_add_asks_once_and_writes_what_the_manual_commands_write() {
    let combined = fixture("add-provider-combined");
    let outcome = add(
        &combined.state,
        &combined.path,
        json!({"provider":"tavily","grantees":CALLERS,"dry_run":false}),
        Ok(()),
    )
    .await;
    assert_eq!(
        outcome.prompts.len(),
        1,
        "one applied add must ask exactly once: {:?}",
        outcome.prompts
    );
    let summary = &outcome.prompts[0];
    for named in [
        "tavily",
        "conn-web-search-tavily",
        "stored key",
        "ceiling read on search",
        "grant invoke read to 3 callers",
    ] {
        assert!(summary.contains(named), "{named} missing from {summary}");
    }
    let result = &outcome.reply["result"];
    assert_eq!(result["applied"], true, "{}", outcome.reply);
    assert_eq!(result["discovery"], "complete");
    assert_eq!(result["connection_id"], "conn-web-search-tavily");
    assert!(grantees(&outcome.reply)
        .iter()
        .all(|(_, status)| status == "minted"));

    // The four manual commands the rollout guide documents, through the same
    // surfaces the admin client and facade use: four confirmations.
    let manual = fixture("add-provider-manual");
    let mut prompts = 0;
    let issued = request(
        &manual.state,
        &manual.path,
        json!({"method": manifest::ADMIN_ISSUE_TICKET_OP, "params": {
            "app_key":"tavily_rest","connection_id":"conn-web-search-tavily",
            "action_selectors":["search"],"risk_ceiling":"read","credential_id":"apikey:tavily"}}),
        Ok(()),
    )
    .await;
    prompts += issued.prompts.len();
    let ticket = issued.reply["result"]["ticket_id"].as_str().unwrap();
    let connected = request(
        &manual.state,
        &manual.path,
        json!({"name":"connections","arguments":{"op":"connect","ticket_id":ticket}}),
        Ok(()),
    )
    .await;
    prompts += connected.prompts.len();
    assert_eq!(
        connected.reply["result"]["discovery"], "complete",
        "{}",
        connected.reply
    );
    for caller in CALLERS {
        let granted = request(
            &manual.state,
            &manual.path,
            json!({"method": manifest::ADMIN_GRANT_OP, "params": {
                "connection_id":"conn-web-search-tavily","grantee_principal":caller,
                "authority_kind":"invoke","risk_ceiling":"read","action_selectors":["search"]}}),
            Ok(()),
        )
        .await;
        assert!(granted.reply.get("result").is_some(), "{}", granted.reply);
        prompts += granted.prompts.len();
    }
    assert_eq!(prompts, 4, "the manual sequence asks four times");

    for (table, filter) in [
        (
            "connections",
            "WHERE connection_id = 'conn-web-search-tavily'",
        ),
        ("grants", ""),
        ("binding_tickets", ""),
        ("audit_journal", ""),
        ("catalog_actions", ""),
    ] {
        let expected = rows(&manual.path, table, filter);
        assert!(!expected.is_empty(), "the manual run wrote no {table} rows");
        assert_eq!(
            rows(&combined.path, table, filter),
            expected,
            "{table} differs from the manual run"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preview_and_refused_confirmation_write_nothing_and_contact_no_vendor() {
    let fixture = fixture("add-provider-preview");
    seed_exa_callers(&fixture);
    let vendor = CountingVendor::start();
    let state = state_with_endpoint(&fixture.store, Some(&vendor.url));
    let before = snapshot(&fixture.path, true);
    for params in [
        json!({"provider":"zai"}),
        json!({"provider":"zai","dry_run":true}),
    ] {
        let preview = add(&state, &fixture.path, params, Err("operator_declined")).await;
        assert!(preview.prompts.is_empty(), "a preview never asks");
        let result = &preview.reply["result"];
        assert_eq!(
            (
                &result["dry_run"],
                &result["applied"],
                &result["connection_id"],
                &result["app_key"],
                &result["credential"],
                &result["connection"],
            ),
            (
                &json!(true),
                &json!(false),
                &json!("conn-web-search-zai"),
                &json!("zai"),
                &json!("apikey:zai"),
                &json!("create"),
            ),
            "{}",
            preview.reply
        );
        assert_eq!(
            result["ceiling"],
            json!({"risk":"read","action_selectors":["web_search_prime"]})
        );
        assert_eq!(snapshot(&fixture.path, true), before, "a preview wrote");
    }
    for (reason, code) in [
        ("operator_declined", "operator_confirmation_declined"),
        (
            "operator_presence_unavailable",
            "operator_confirmation_unavailable",
        ),
    ] {
        let before = snapshot(&fixture.path, false);
        let refused = add(
            &state,
            &fixture.path,
            json!({"provider":"zai","dry_run":false}),
            Err(reason),
        )
        .await;
        assert_eq!(refused.prompts.len(), 1);
        assert_eq!(refused.reply["error"]["code"], code, "{}", refused.reply);
        assert_eq!(
            snapshot(&fixture.path, false),
            before,
            "a refusal wrote authority"
        );
        assert_eq!(
            count(
                &fixture.path,
                &format!(
                    "SELECT COUNT(*) FROM audit_journal WHERE gate = 'operator_confirmation'
                     AND decision = 'deny' AND reason_code = '{code}'
                     AND action = '{ADD}'"
                )
            ),
            1,
            "a refusal records its own audit row"
        );
    }
    assert_eq!(
        vendor.contacts(),
        0,
        "a preview or refusal sends no vendor request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rerun_reuses_the_providers_connection_instead_of_duplicating_it() {
    // A connection the operator made by hand under another id is the
    // provider's connection too; it is reused, not joined by a second one.
    let by_hand = fixture("add-provider-by-hand");
    let issued = ceremony::issue_ticket(
        &by_hand.state,
        "direct",
        &json!({"app_key":"tavily_rest","connection_id":"conn-tavily-by-hand",
            "action_selectors":["search"],"credential_id":"apikey:tavily"}),
    );
    by_hand
        .store
        .connect_with_ticket("direct", issued["result"]["ticket_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    let added = add(
        &by_hand.state,
        &by_hand.path,
        json!({"provider":"tavily","grantees":["reserved:basal"],"dry_run":false}),
        Ok(()),
    )
    .await;
    assert_eq!(
        count(
            &by_hand.path,
            "SELECT COUNT(*) FROM connections WHERE app_key = 'tavily_rest'"
        ),
        1,
        "a second tavily connection was created"
    );
    assert_eq!(
        (
            &added.reply["result"]["connection_id"],
            &added.reply["result"]["connection"]
        ),
        (&json!("conn-tavily-by-hand"), &json!("reuse")),
        "{}",
        added.reply
    );
    assert_eq!(
        count(
            &by_hand.path,
            "SELECT COUNT(*) FROM grants WHERE connection_id = 'conn-tavily-by-hand'"
        ),
        1
    );

    let fixture = self::fixture("add-provider-rerun");
    let params = json!({"provider":"tavily","grantees":CALLERS,"dry_run":false});
    let first = add(&fixture.state, &fixture.path, params.clone(), Ok(())).await;
    assert_eq!(first.reply["result"]["applied"], true, "{}", first.reply);
    let rerun = add(&fixture.state, &fixture.path, params, Ok(())).await;
    assert_eq!(rerun.prompts.len(), 1);
    assert_eq!(rerun.reply["result"]["applied"], true, "{}", rerun.reply);
    assert_eq!(rerun.reply["result"]["connection"], "reuse");
    assert!(grantees(&rerun.reply)
        .iter()
        .all(|(_, status)| status == "already_present"));
    for (query, expected) in [
        (
            "SELECT COUNT(*) FROM connections WHERE app_key = 'tavily_rest'",
            1,
        ),
        ("SELECT COUNT(*) FROM grants", 3),
        ("SELECT COUNT(*) FROM binding_tickets", 1),
    ] {
        assert_eq!(
            count(&fixture.path, query),
            expected,
            "a rerun duplicated: {query}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_discovery_mints_no_grant_and_a_rerun_finishes() {
    let fixture = fixture("add-provider-discovery");
    let params = json!({"provider":"zai","grantees":CALLERS,"dry_run":false});
    {
        let vendor = CountingVendor::start();
        let failing = state_with_endpoint(&fixture.store, Some(&vendor.url));
        let failed = add(&failing, &fixture.path, params.clone(), Ok(())).await;
        assert_eq!(failed.prompts.len(), 1);
        assert_eq!(
            count(&fixture.path, "SELECT COUNT(*) FROM grants"),
            0,
            "no grant may be minted when discovery fails"
        );
        assert_eq!(
            failed.reply["error"]["code"], "discovery_incomplete",
            "{}",
            failed.reply
        );
        assert!(vendor.contacts() > 0, "discovery reached the local vendor");
        // The ticket is spent and the connection stays, marked degraded by
        // the failed discovery; it is reported, not undone.
        let status = fixture
            .store
            .connection("direct", "conn-web-search-zai")
            .unwrap()
            .map(|connection| connection.status);
        assert!(
            matches!(status.as_deref(), Some("active" | "degraded")),
            "the connection must remain after a failed discovery: {status:?}"
        );
    }
    let vendor = plexus_conformance::stub_server::StubMcpServer::start(vec![
        plexus_conformance::stub_server::StubTool::simple("web_search_prime"),
    ])
    .expect("stub MCP vendor");
    let working = state_with_endpoint(&fixture.store, Some(vendor.endpoint()));
    let finished = add(&working, &fixture.path, params, Ok(())).await;
    assert_eq!(finished.prompts.len(), 1, "a rerun asks once again");
    assert_eq!(
        finished.reply["result"]["applied"], true,
        "{}",
        finished.reply
    );
    assert_eq!(finished.reply["result"]["connection"], "reuse");
    assert!(grantees(&finished.reply)
        .iter()
        .all(|(_, status)| status == "minted"));
    for (query, expected) in [
        ("SELECT COUNT(*) FROM connections WHERE app_key = 'zai'", 1),
        ("SELECT COUNT(*) FROM binding_tickets", 1),
        (
            "SELECT COUNT(*) FROM grants WHERE connection_id = 'conn-web-search-zai'
             AND action_selectors = '[\"web_search_prime\"]'",
            3,
        ),
    ] {
        assert_eq!(count(&fixture.path, query), expected, "{query}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_unknown_or_wildcard_requests_refuse_and_write_nothing() {
    let collision = fixture("add-provider-collision");
    collision
        .store
        .insert_connection(
            "direct",
            "conn-web-search-tavily",
            "exa_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    let other_key = fixture("add-provider-other-key");
    let issued = ceremony::issue_ticket(
        &other_key.state,
        "direct",
        &json!({"app_key":"tavily_rest","connection_id":"conn-web-search-tavily",
            "action_selectors":["search"],"credential_id":"apikey:tavily-other"}),
    );
    other_key
        .store
        .connect_with_ticket("direct", issued["result"]["ticket_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    let plain = fixture("add-provider-refusals");
    let tavily = json!({"provider":"tavily","grantees":["reserved:basal"],"dry_run":false});
    let mut wildcard = tavily.clone();
    wildcard["grantees"] = json!(["reserved:basal", "*"]);
    let mut keyed = tavily.clone();
    keyed["with_key"] = json!(true);
    for (case, params, code) in [
        (&collision, tavily.clone(), "provider_connection_mismatch"),
        (&other_key, tavily.clone(), "provider_connection_mismatch"),
        (
            &plain,
            json!({"provider":"google","grantees":["reserved:basal"],"dry_run":false}),
            "unknown_provider",
        ),
        (&plain, wildcard, "wildcard_grantee"),
        (&plain, keyed, "with_key_not_applicable"),
    ] {
        for dry_run in [false, true] {
            let mut params = params.clone();
            params["dry_run"] = json!(dry_run);
            let before = snapshot(&case.path, true);
            let refused = add(&case.state, &case.path, params, Ok(())).await;
            assert_eq!(refused.reply["error"]["code"], code, "{}", refused.reply);
            assert!(refused.prompts.is_empty(), "a refusal never asks");
            assert_eq!(snapshot(&case.path, true), before, "{code} wrote");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_grantees_are_the_live_search_callers_and_never_a_wildcard() {
    let fixture = fixture("add-provider-defaults");
    seed_exa_callers(&fixture);
    let lapsed = mint(&fixture.store, "conn-exa-rest", "reserved:lapsed", "invoke");
    sql(
        &fixture.path,
        &format!("UPDATE grants SET expires_at = 1 WHERE grant_id = '{lapsed}'"),
    );
    let revoked = mint(
        &fixture.store,
        "conn-exa-rest",
        "reserved:revoked",
        "invoke",
    );
    assert!(fixture.store.revoke_grant("direct", &revoked).unwrap());
    mint(
        &fixture.store,
        "conn-exa-rest",
        "reserved:admin",
        "connection_admin",
    );
    // The store refuses to mint a wildcard grantee; plant one directly, as
    // an old or hand-edited store might hold it.
    let wild = mint(&fixture.store, "conn-exa-rest", "reserved:wild", "invoke");
    sql(
        &fixture.path,
        &format!("UPDATE grants SET grantee_principal = '*' WHERE grant_id = '{wild}'"),
    );
    let expected: Vec<(String, String)> = [
        "reserved:basal",
        "reserved:broca",
        "reserved:prefrontal-core",
    ]
    .into_iter()
    .map(|grantee| (grantee.to_string(), "to_mint".to_string()))
    .collect();
    let preview = add(
        &fixture.state,
        &fixture.path,
        json!({"provider":"tavily"}),
        Ok(()),
    )
    .await;
    assert_eq!(
        preview.reply["result"]["grantees_source"],
        "existing_search_grants"
    );
    assert_eq!(
        grantees(&preview.reply),
        expected,
        "the default grantees are exactly the live search callers, never a wildcard"
    );
    let applied = add(
        &fixture.state,
        &fixture.path,
        json!({"provider":"tavily","dry_run":false}),
        Ok(()),
    )
    .await;
    assert_eq!(applied.prompts.len(), 1);
    assert_eq!(
        count(
            &fixture.path,
            "SELECT COUNT(*) FROM grants WHERE connection_id = 'conn-web-search-tavily'
             AND grantee_principal IN ('reserved:basal','reserved:broca','reserved:prefrontal-core')"
        ),
        3,
        "{}",
        applied.reply
    );
    assert_eq!(
        count(
            &fixture.path,
            "SELECT COUNT(*) FROM grants WHERE connection_id = 'conn-web-search-tavily'"
        ),
        3
    );
}

/// Run the SearXNG flow and return every reply and prompt it produced, so the
/// caller can check that none repeats the instance address.
async fn searxng_flow(fixture: &Fixture) -> Vec<String> {
    let mut seen = Vec::new();
    let missing = add(
        &fixture.state,
        &fixture.path,
        json!({"provider":"searxng","grantees":["reserved:basal"],"dry_run":false}),
        Ok(()),
    )
    .await;
    assert_eq!(missing.reply["error"]["code"], "invalid_request");
    assert!(missing.reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("--instance-url"));
    assert!(missing.prompts.is_empty());
    seen.push(missing.reply.to_string());
    let params = json!({"provider":"searxng","grantees":["reserved:basal"],
        "instance_url":SEARXNG_CANARY});
    let preview = add(&fixture.state, &fixture.path, params.clone(), Ok(())).await;
    assert_eq!(
        (
            &preview.reply["result"]["auth"],
            &preview.reply["result"]["credential"],
            &preview.reply["result"]["instance_url"]
        ),
        (
            &json!("anonymous"),
            &Value::Null,
            &json!("supplied (not shown)")
        ),
        "{}",
        preview.reply
    );
    seen.push(preview.reply.to_string());
    let mut apply = params.clone();
    apply["dry_run"] = json!(false);
    let applied = add(&fixture.state, &fixture.path, apply.clone(), Ok(())).await;
    assert_eq!(
        applied.reply["result"]["applied"], true,
        "{}",
        applied.reply
    );
    assert_eq!(applied.prompts.len(), 1);
    assert!(applied.prompts[0].contains("anonymous"));
    seen.push(applied.reply.to_string());
    seen.extend(applied.prompts);
    let connection = fixture
        .store
        .connection("direct", "conn-web-search-searxng")
        .unwrap()
        .unwrap();
    assert_eq!(
        connection.instance_url.as_ref().map(|url| url.as_str()),
        Some(SEARXNG_CANARY)
    );
    assert_eq!(
        fixture
            .store
            .connection_credential_reference("direct", "conn-web-search-searxng")
            .unwrap(),
        None
    );
    let mut keyed = apply.clone();
    keyed["with_key"] = json!(true);
    let mut moved = apply;
    moved["instance_url"] = json!("https://another-searx.invalid/");
    for refused in [keyed, moved] {
        let before = snapshot(&fixture.path, true);
        let reply = add(&fixture.state, &fixture.path, refused, Ok(())).await;
        assert_eq!(
            reply.reply["error"]["code"], "provider_connection_mismatch",
            "{}",
            reply.reply
        );
        assert_eq!(snapshot(&fixture.path, true), before);
        seen.push(reply.reply.to_string());
    }
    seen
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn searxng_requires_an_instance_and_never_repeats_it() {
    let fixture = fixture("add-provider-searxng");
    for text in searxng_flow(&fixture).await {
        assert!(
            !text.contains("private-searx-canary") && !text.contains("secret-instance-path"),
            "the instance address was repeated: {text}"
        );
    }
}

#[test]
fn searxng_log_fixture() {
    if !diagnostic_child() {
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let fixture = fixture("add-provider-searxng-log");
            searxng_flow(&fixture).await;
        });
}

#[test]
fn searxng_instance_address_never_reaches_the_log() {
    let stderr =
        module_diagnostic_output("tests::web_search_provider_admin_tests::searxng_log_fixture");
    assert!(
        !stderr.contains("private-searx-canary") && !stderr.contains("secret-instance-path"),
        "the instance address was logged: {stderr}"
    );
}

/// Without the connector home role this process must not enroll a provider:
/// an applied add is refused before anyone is asked and before any ticket,
/// connection, grant or vendor request, while a preview still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_add_without_the_connector_home_role_is_refused_before_asking() {
    let fixture = fixture("add-provider-no-connector-home");
    seed_exa_callers(&fixture);
    let vendor = CountingVendor::start();
    let mut runtime = runtime_for_test(Arc::clone(&fixture.store));
    runtime.endpoint_override = Some(vendor.url.clone());
    runtime.connector_home = Arc::new(crate::connector_home::ConnectorHome::unavailable());
    assert!(!runtime.connector_home.held());
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    });
    let before = snapshot(&fixture.path, true);

    let preview = add(&state, &fixture.path, json!({"provider":"zai"}), Ok(())).await;
    assert!(preview.prompts.is_empty(), "a preview never asks");
    assert_eq!(
        (
            &preview.reply["result"]["dry_run"],
            &preview.reply["result"]["connection_id"]
        ),
        (&json!(true), &json!("conn-web-search-zai")),
        "a preview works without the connector home role: {}",
        preview.reply
    );

    let refused = add(
        &state,
        &fixture.path,
        json!({"provider":"zai","dry_run":false}),
        Ok(()),
    )
    .await;
    assert!(
        refused.prompts.is_empty(),
        "an applied add without the connector home role must not ask: {:?}",
        refused.prompts
    );
    assert_eq!(
        refused.reply["error"]["code"], "connector_home_not_held",
        "{}",
        refused.reply
    );
    for query in [
        "SELECT COUNT(*) FROM binding_tickets",
        "SELECT COUNT(*) FROM connections WHERE app_key = 'zai'",
        "SELECT COUNT(*) FROM grants WHERE connection_id <> 'conn-exa-rest'",
    ] {
        assert_eq!(count(&fixture.path, query), 0, "{query}");
    }
    assert_eq!(
        snapshot(&fixture.path, true),
        before,
        "nothing may be written without the connector home role"
    );
    assert_eq!(vendor.contacts(), 0, "no vendor request may be sent");
}
