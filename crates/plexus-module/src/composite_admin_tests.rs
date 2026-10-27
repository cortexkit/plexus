//! The composite admin commands that bundle several authority changes under
//! one operator confirmation: `add_write_connection`, `add_poll_connection`,
//! `widen_and_grant` and `onboard_github_bot`. Each applied run asks exactly
//! once and writes the rows the manual commands write; a declined or
//! unavailable confirmation writes nothing and sends no vendor request beyond
//! the GitHub listing an onboarding reads while planning; a rerun reuses what
//! exists and refuses what does not match.

use super::web_search_provider_admin_tests::{
    count, install, request, rows, snapshot, sql, state_with_endpoint, CountingVendor, Fixture,
    Outcome,
};
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const WRITE: &str = manifest::ADMIN_ADD_WRITE_CONNECTION_OP;
const POLL: &str = manifest::ADMIN_ADD_POLL_CONNECTION_OP;
const WIDEN: &str = manifest::ADMIN_WIDEN_AND_GRANT_OP;
const ONBOARD: &str = manifest::ADMIN_ONBOARD_GITHUB_BOT_OP;

const WRITE_APP: &str = "write_vendor";
const WRITE_CONNECTION: &str = "conn-write";
const AGENTS: [&str; 2] = ["reserved:broca", "reserved:basal"];
const POLL_READS: [&str; 4] = [
    "list_workflow_runs",
    "get_workflow_run",
    "list_jobs_for_workflow_run_attempt",
    "get_repository",
];
const CI_FLOW: [&str; 2] = ["get_job", "github.actions.job_log"];
const HANDLE: &str = "app-onboard";
const AGENT: &str = "agent-onboard";

async fn call(state: &Arc<ModuleState>, path: &Path, method: &str, params: Value) -> Outcome {
    request(
        state,
        path,
        json!({"method": method, "params": params}),
        Ok(()),
    )
    .await
}

async fn call_with(
    state: &Arc<ModuleState>,
    path: &Path,
    method: &str,
    params: Value,
    decision: Result<(), &'static str>,
) -> Outcome {
    request(
        state,
        path,
        json!({"method": method, "params": params}),
        decision,
    )
    .await
}

/// A state like [`state_with_endpoint`]'s without the connector-home role.
fn homeless(store: &Arc<PlexusStore>, endpoint: Option<&str>) -> Arc<ModuleState> {
    let mut runtime = runtime_for_test(Arc::clone(store));
    runtime.endpoint_override = endpoint.map(str::to_owned);
    runtime.connector_home = Arc::new(crate::connector_home::ConnectorHome::unavailable());
    Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    })
}

/// Every row of each table must match between the composite run and the
/// manual commands, generated ids and clock readings aside.
fn assert_same_rows(combined: &Path, manual: &Path, tables: &[(&str, &str)]) {
    for (table, filter) in tables {
        let expected = rows(manual, table, filter);
        assert!(!expected.is_empty(), "the manual run wrote no {table} rows");
        assert_eq!(
            rows(combined, table, filter),
            expected,
            "{table} differs from the manual run"
        );
    }
}

/// The confirmation-refusal audit row a declined or unavailable run writes.
fn refusal_audits(path: &Path, method: &str, code: &str) -> i64 {
    count(
        path,
        &format!(
            "SELECT COUNT(*) FROM audit_journal WHERE gate = 'operator_confirmation'
             AND decision = 'deny' AND reason_code = '{code}' AND action = '{method}'"
        ),
    )
}

fn statuses(reply: &Value) -> Vec<String> {
    reply["result"]["steps"]
        .as_array()
        .unwrap_or_else(|| panic!("no steps in {reply}"))
        .iter()
        .map(|step| step["status"].as_str().unwrap().to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// add_write_connection

fn write_fixture(label: &str, endpoint: Option<&str>) -> Fixture {
    let path = DiagnosticStorePath::new(label);
    let store = Arc::new(crate::test_support::open_file_store(&path));
    store
        .upsert_manifest(
            "system",
            &test_write_manifest(WRITE_APP, "https://write-vendor.invalid/mcp"),
        )
        .unwrap();
    let state = state_with_endpoint(&store, endpoint);
    Fixture { path, store, state }
}

fn write_params(dry_run: bool) -> Value {
    json!({
        "app_key": WRITE_APP,
        "connection_id": WRITE_CONNECTION,
        "credential_id": "apikey:write",
        "actions": ["held_write"],
        "grantees": AGENTS,
        "resource_filters": {"write_enabling": ["team"], "values": {"team": "core"}},
        "allow_actions": ["held_write"],
        "dry_run": dry_run,
    })
}

fn write_vendor() -> plexus_conformance::stub_server::StubMcpServer {
    plexus_conformance::stub_server::StubMcpServer::start(vec![
        plexus_conformance::stub_server::StubTool::simple("held_write"),
    ])
    .expect("stub MCP vendor")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_write_connection_asks_once_and_writes_what_the_manual_commands_write() {
    let vendor = write_vendor();
    let combined = write_fixture("write-combined", Some(vendor.endpoint()));
    let outcome = call(&combined.state, &combined.path, WRITE, write_params(false)).await;
    assert_eq!(
        outcome.prompts.len(),
        1,
        "one applied add_write_connection must ask exactly once: {:?}",
        outcome.prompts
    );
    let summary = &outcome.prompts[0];
    for named in [
        WRITE_CONNECTION,
        WRITE_APP,
        "stored credential",
        "ceiling write on 1 actions",
        "grant 1 admin(write), 2 invoke(write)",
        "1 filter config",
        "allow 1 without asking",
    ] {
        assert!(summary.contains(named), "{named} missing from {summary}");
    }
    let result = &outcome.reply["result"];
    assert_eq!(result["applied"], true, "{}", outcome.reply);
    assert_eq!(result["discovery"], "complete");
    assert_eq!(
        statuses(&outcome.reply),
        ["minted", "set", "minted", "minted", "set"]
    );

    // The manual sequence, through the surfaces the admin client and the
    // facade use: ticket, connect, admin grant, configure, one invoke grant
    // per agent and the allow policy, five confirmations.
    let manual = write_fixture("write-manual", Some(vendor.endpoint()));
    let mut prompts = 0;
    let issued = call(
        &manual.state,
        &manual.path,
        manifest::ADMIN_ISSUE_TICKET_OP,
        json!({"app_key": WRITE_APP, "connection_id": WRITE_CONNECTION,
            "credential_id": "apikey:write", "risk_ceiling": "write",
            "action_selectors": ["held_write"]}),
    )
    .await;
    prompts += issued.prompts.len();
    let ticket = issued.reply["result"]["ticket_id"].as_str().unwrap();
    let connected = request(
        &manual.state,
        &manual.path,
        json!({"name": "connections", "arguments": {"op": "connect", "ticket_id": ticket}}),
        Ok(()),
    )
    .await;
    prompts += connected.prompts.len();
    assert_eq!(connected.reply["result"]["discovery"], "complete");
    let admin = call(
        &manual.state,
        &manual.path,
        manifest::ADMIN_GRANT_OP,
        json!({"connection_id": WRITE_CONNECTION, "grantee_principal": "direct",
            "authority_kind": "connection_admin", "risk_ceiling": "write",
            "action_selectors": ["held_write"]}),
    )
    .await;
    assert!(admin.reply.get("result").is_some(), "{}", admin.reply);
    prompts += admin.prompts.len();
    let configured = request(
        &manual.state,
        &manual.path,
        json!({"name": "connections", "arguments": {"op": "configure",
            "connection": WRITE_CONNECTION,
            "resource_filters": {"write_enabling": ["team"], "values": {"team": "core"}}}}),
        Ok(()),
    )
    .await;
    assert!(
        configured.reply.get("result").is_some(),
        "{}",
        configured.reply
    );
    prompts += configured.prompts.len();
    for agent in AGENTS {
        let granted = call(
            &manual.state,
            &manual.path,
            manifest::ADMIN_GRANT_OP,
            json!({"connection_id": WRITE_CONNECTION, "grantee_principal": agent,
                "authority_kind": "invoke", "risk_ceiling": "write",
                "action_selectors": ["held_write"]}),
        )
        .await;
        assert!(granted.reply.get("result").is_some(), "{}", granted.reply);
        prompts += granted.prompts.len();
    }
    let allowed = call(
        &manual.state,
        &manual.path,
        manifest::ADMIN_SET_POLICY_OP,
        json!({"connection_id": WRITE_CONNECTION, "action_selector": "held_write",
            "effect": "allow"}),
    )
    .await;
    assert!(allowed.reply.get("result").is_some(), "{}", allowed.reply);
    prompts += allowed.prompts.len();
    assert_eq!(prompts, 5, "the manual sequence asks five times");

    assert_same_rows(
        &combined.path,
        &manual.path,
        &[
            ("connections", "WHERE connection_id = 'conn-write'"),
            ("grants", ""),
            ("binding_tickets", ""),
            ("policies", ""),
            ("audit_journal", ""),
            ("catalog_actions", ""),
        ],
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declined_write_connection_writes_nothing_and_contacts_no_vendor() {
    let vendor = CountingVendor::start();
    let fixture = write_fixture("write-declined", Some(&vendor.url));
    let before = snapshot(&fixture.path, true);
    let preview = call(&fixture.state, &fixture.path, WRITE, write_params(true)).await;
    assert!(preview.prompts.is_empty(), "a preview never asks");
    assert_eq!(
        (
            &preview.reply["result"]["dry_run"],
            &preview.reply["result"]["connection"]
        ),
        (&json!(true), &json!("create")),
        "{}",
        preview.reply
    );
    assert_eq!(
        statuses(&preview.reply),
        ["to_mint", "to_set", "to_mint", "to_mint", "to_set"]
    );
    assert_eq!(snapshot(&fixture.path, true), before, "a preview wrote");
    for (reason, code) in [
        ("operator_declined", "operator_confirmation_declined"),
        (
            "operator_presence_unavailable",
            "operator_confirmation_unavailable",
        ),
    ] {
        let before = snapshot(&fixture.path, false);
        let refused = call_with(
            &fixture.state,
            &fixture.path,
            WRITE,
            write_params(false),
            Err(reason),
        )
        .await;
        assert_eq!(refused.prompts.len(), 1);
        assert_eq!(refused.reply["error"]["code"], code, "{}", refused.reply);
        assert_eq!(
            snapshot(&fixture.path, false),
            before,
            "a refused confirmation wrote authority"
        );
        assert_eq!(refusal_audits(&fixture.path, WRITE, code), 1);
    }
    assert_eq!(
        vendor.contacts(),
        0,
        "a preview or a refused confirmation sends no vendor request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rerun_reuses_the_write_connection_and_refuses_a_mismatch() {
    let vendor = write_vendor();
    let fixture = write_fixture("write-rerun", Some(vendor.endpoint()));
    let first = call(&fixture.state, &fixture.path, WRITE, write_params(false)).await;
    assert_eq!(first.reply["result"]["applied"], true, "{}", first.reply);
    let tally = |path: &Path| {
        [
            "SELECT COUNT(*) FROM connections",
            "SELECT COUNT(*) FROM grants",
            "SELECT COUNT(*) FROM binding_tickets",
            "SELECT COUNT(*) FROM policies",
        ]
        .map(|query| count(path, query))
    };
    let after_first = tally(&fixture.path);
    assert_eq!(after_first, [1, 3, 1, 1]);
    let rerun = call(&fixture.state, &fixture.path, WRITE, write_params(false)).await;
    assert_eq!(rerun.prompts.len(), 1, "a rerun asks once again");
    assert_eq!(rerun.reply["result"]["applied"], true, "{}", rerun.reply);
    assert_eq!(rerun.reply["result"]["connection"], "reuse");
    assert_eq!(
        statuses(&rerun.reply),
        [
            "already_present",
            "unchanged",
            "already_present",
            "already_present",
            "unchanged"
        ],
        "a rerun must reuse every step: {}",
        rerun.reply
    );
    assert_eq!(tally(&fixture.path), after_first, "a rerun duplicated");

    let mut other_filters = write_params(false);
    other_filters["resource_filters"] = json!({"write_enabling": ["team"]});
    let mut other_credential = write_params(false);
    other_credential["credential_id"] = json!("apikey:other");
    let mut other_app = write_params(false);
    sql(
        &fixture.path,
        "INSERT INTO connections (connection_id, principal, app_key, status, resource_filters,
             created_at_ms, updated_at_ms)
         VALUES ('conn-other-app', 'direct', 'exa_rest', 'active', '{}', 1, 1)",
    );
    other_app["connection_id"] = json!("conn-other-app");
    for (params, code) in [
        (other_filters, "resource_filters_mismatch"),
        (other_credential, "connection_credential_mismatch"),
        (other_app, "connection_app_mismatch"),
    ] {
        let before = snapshot(&fixture.path, true);
        let refused = call(&fixture.state, &fixture.path, WRITE, params).await;
        assert_eq!(refused.reply["error"]["code"], code, "{}", refused.reply);
        assert!(
            refused.prompts.is_empty(),
            "a mismatch is refused before asking"
        );
        assert_eq!(snapshot(&fixture.path, true), before, "{code} wrote");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_write_discovery_leaves_the_connection_and_a_rerun_finishes() {
    let fixture = write_fixture("write-discovery", None);
    {
        let vendor = CountingVendor::start();
        let failing = state_with_endpoint(&fixture.store, Some(&vendor.url));
        let failed = call(&failing, &fixture.path, WRITE, write_params(false)).await;
        assert_eq!(failed.prompts.len(), 1);
        assert_eq!(
            failed.reply["error"]["code"], "discovery_incomplete",
            "{}",
            failed.reply
        );
        let message = failed.reply["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("connection conn-write is")
                && message.contains("rerun add-write-connection"),
            "the failure names what was left behind and how to finish: {message}"
        );
        assert!(vendor.contacts() > 0, "discovery reached the local vendor");
        assert_eq!(
            count(&fixture.path, "SELECT COUNT(*) FROM grants"),
            0,
            "no grant may be minted when discovery fails"
        );
    }
    let vendor = write_vendor();
    let working = state_with_endpoint(&fixture.store, Some(vendor.endpoint()));
    let finished = call(&working, &fixture.path, WRITE, write_params(false)).await;
    assert_eq!(finished.prompts.len(), 1);
    assert_eq!(
        finished.reply["result"]["applied"], true,
        "{}",
        finished.reply
    );
    assert_eq!(finished.reply["result"]["connection"], "reuse");
    assert_eq!(count(&fixture.path, "SELECT COUNT(*) FROM grants"), 3);
    assert_eq!(
        count(&fixture.path, "SELECT COUNT(*) FROM binding_tickets"),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_write_connection_without_the_connector_home_role_is_refused_before_asking() {
    let vendor = CountingVendor::start();
    let fixture = write_fixture("write-no-home", None);
    let state = homeless(&fixture.store, Some(&vendor.url));
    let before = snapshot(&fixture.path, true);
    let preview = call(&state, &fixture.path, WRITE, write_params(true)).await;
    assert_eq!(
        preview.reply["result"]["dry_run"], true,
        "{}",
        preview.reply
    );
    let refused = call(&state, &fixture.path, WRITE, write_params(false)).await;
    assert!(
        refused.prompts.is_empty(),
        "an applied write connection without the connector home role must not ask: {:?}",
        refused.prompts
    );
    assert_eq!(
        refused.reply["error"]["code"], "connector_home_not_held",
        "{}",
        refused.reply
    );
    assert_eq!(snapshot(&fixture.path, true), before);
    assert_eq!(vendor.contacts(), 0);
}

// ---------------------------------------------------------------------------
// add_poll_connection

fn poll_fixture(label: &str, endpoint: Option<&str>) -> Fixture {
    let path = DiagnosticStorePath::new(label);
    let store = Arc::new(crate::test_support::open_file_store(&path));
    install(&store, "github_actions");
    let state = state_with_endpoint(&store, endpoint);
    Fixture { path, store, state }
}

fn poll_params(dry_run: bool) -> Value {
    json!({
        "app_key": "github_actions",
        "connection_id": "conn-github-actions",
        "credential_id": "apikey:github",
        "actions": POLL_READS,
        "consumers": ["reserved:basal"],
        "consume_actions": ["list_workflow_runs"],
        "dry_run": dry_run,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_poll_connection_asks_once_and_writes_what_the_manual_commands_write() {
    let combined = poll_fixture("poll-combined", None);
    let outcome = call(&combined.state, &combined.path, POLL, poll_params(false)).await;
    assert_eq!(
        outcome.prompts.len(),
        1,
        "one applied add_poll_connection must ask exactly once: {:?}",
        outcome.prompts
    );
    for named in [
        "conn-github-actions",
        "ceiling read on 4 actions",
        "grant 1 consumer(read), 1 poll(read)",
    ] {
        assert!(
            outcome.prompts[0].contains(named),
            "{named} missing from {}",
            outcome.prompts[0]
        );
    }
    assert_eq!(
        outcome.reply["result"]["applied"], true,
        "{}",
        outcome.reply
    );
    assert_eq!(statuses(&outcome.reply), ["minted", "minted"]);

    // docs/rollout/github-events-poll-mode.md step 3: ticket, connect, poll
    // grant and consume grant, three confirmations.
    let manual = poll_fixture("poll-manual", None);
    let mut prompts = 0;
    let issued = call(
        &manual.state,
        &manual.path,
        manifest::ADMIN_ISSUE_TICKET_OP,
        json!({"app_key": "github_actions", "connection_id": "conn-github-actions",
            "credential_id": "apikey:github", "risk_ceiling": "read",
            "action_selectors": POLL_READS}),
    )
    .await;
    prompts += issued.prompts.len();
    let ticket = issued.reply["result"]["ticket_id"].as_str().unwrap();
    let connected = request(
        &manual.state,
        &manual.path,
        json!({"name": "connections", "arguments": {"op": "connect", "ticket_id": ticket}}),
        Ok(()),
    )
    .await;
    prompts += connected.prompts.len();
    for (grantee, kind, actions) in [
        ("direct", "poll", POLL_READS.to_vec()),
        (
            "reserved:basal",
            "events_consume",
            vec!["list_workflow_runs"],
        ),
    ] {
        let granted = call(
            &manual.state,
            &manual.path,
            manifest::ADMIN_GRANT_OP,
            json!({"connection_id": "conn-github-actions", "grantee_principal": grantee,
                "authority_kind": kind, "risk_ceiling": "read", "action_selectors": actions}),
        )
        .await;
        assert!(granted.reply.get("result").is_some(), "{}", granted.reply);
        prompts += granted.prompts.len();
    }
    assert_eq!(prompts, 3, "the manual sequence asks three times");
    assert_same_rows(
        &combined.path,
        &manual.path,
        &[
            ("connections", ""),
            ("grants", ""),
            ("binding_tickets", ""),
            ("audit_journal", ""),
            ("catalog_actions", ""),
        ],
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declined_poll_connection_writes_nothing_and_contacts_no_vendor() {
    let vendor = CountingVendor::start();
    let fixture = poll_fixture("poll-declined", Some(&vendor.url));
    let before = snapshot(&fixture.path, true);
    let preview = call(&fixture.state, &fixture.path, POLL, poll_params(true)).await;
    assert!(preview.prompts.is_empty());
    assert_eq!(statuses(&preview.reply), ["to_mint", "to_mint"]);
    assert_eq!(snapshot(&fixture.path, true), before, "a preview wrote");
    let before = snapshot(&fixture.path, false);
    let refused = call_with(
        &fixture.state,
        &fixture.path,
        POLL,
        poll_params(false),
        Err("operator_declined"),
    )
    .await;
    assert_eq!(refused.prompts.len(), 1);
    assert_eq!(
        refused.reply["error"]["code"], "operator_confirmation_declined",
        "{}",
        refused.reply
    );
    assert_eq!(snapshot(&fixture.path, false), before, "a decline wrote");
    assert_eq!(
        refusal_audits(&fixture.path, POLL, "operator_confirmation_declined"),
        1
    );
    assert_eq!(vendor.contacts(), 0, "a decline sends no vendor request");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rerun_reuses_the_poll_connection_and_its_grants() {
    let fixture = poll_fixture("poll-rerun", None);
    let first = call(&fixture.state, &fixture.path, POLL, poll_params(false)).await;
    assert_eq!(first.reply["result"]["applied"], true, "{}", first.reply);
    let rerun = call(&fixture.state, &fixture.path, POLL, poll_params(false)).await;
    assert_eq!(
        rerun.reply["result"]["connection"], "reuse",
        "a rerun must reuse the poll connection: {}",
        rerun.reply
    );
    assert_eq!(rerun.prompts.len(), 1);
    assert_eq!(
        statuses(&rerun.reply),
        ["already_present", "already_present"]
    );
    for (query, expected) in [
        ("SELECT COUNT(*) FROM connections", 1),
        ("SELECT COUNT(*) FROM grants", 2),
        ("SELECT COUNT(*) FROM binding_tickets", 1),
    ] {
        assert_eq!(
            count(&fixture.path, query),
            expected,
            "a rerun duplicated: {query}"
        );
    }
    // A wider request than the connection's ceiling is refused by name, not
    // enrolled again.
    let mut wider = poll_params(false);
    wider["actions"] = json!(["list_workflow_runs", "get_job"]);
    let before = snapshot(&fixture.path, true);
    let refused = call(&fixture.state, &fixture.path, POLL, wider).await;
    assert_eq!(
        refused.reply["error"]["code"], "connection_ceiling_mismatch",
        "{}",
        refused.reply
    );
    assert!(refused.prompts.is_empty());
    assert_eq!(snapshot(&fixture.path, true), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_poll_connection_without_the_connector_home_role_is_refused_before_asking() {
    let fixture = poll_fixture("poll-no-home", None);
    let state = homeless(&fixture.store, None);
    let before = snapshot(&fixture.path, true);
    let refused = call(&state, &fixture.path, POLL, poll_params(false)).await;
    assert!(
        refused.prompts.is_empty(),
        "an applied poll connection without the connector home role must not ask: {:?}",
        refused.prompts
    );
    assert_eq!(
        refused.reply["error"]["code"], "connector_home_not_held",
        "{}",
        refused.reply
    );
    assert_eq!(snapshot(&fixture.path, true), before);
}

// ---------------------------------------------------------------------------
// widen_and_grant

/// `conn-github-actions` as step 3 of the poll-mode guide leaves it: active,
/// its catalog seeded from the reviewed manifest, its ceiling the four poll
/// reads.
fn widen_fixture(label: &str) -> Fixture {
    let fixture = poll_fixture(label, None);
    fixture
        .store
        .insert_connection(
            "direct",
            "conn-github-actions",
            "github_actions",
            "active",
            &json!({}),
        )
        .unwrap();
    fixture
        .store
        .seed_catalog_from_manifest("direct", "conn-github-actions", "github_actions")
        .unwrap();
    sql(
        &fixture.path,
        &format!(
            "UPDATE connections SET ceiling_risk = 'read', ceiling_selectors = '{}'",
            serde_json::to_string(&POLL_READS).unwrap()
        ),
    );
    fixture
}

fn widen_params(dry_run: bool) -> Value {
    json!({
        "connection_id": "conn-github-actions",
        "actions": CI_FLOW,
        "grantees": ["reserved:basal"],
        "dry_run": dry_run,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_widen_and_grant_asks_once_and_writes_what_the_manual_commands_write() {
    let combined = widen_fixture("widen-combined");
    let outcome = call(&combined.state, &combined.path, WIDEN, widen_params(false)).await;
    assert_eq!(
        outcome.prompts.len(),
        1,
        "one applied widen_and_grant must ask exactly once: {:?}",
        outcome.prompts
    );
    for named in [
        "conn-github-actions",
        "add 2 ceiling actions at read risk",
        "grant invoke read on 2 actions to 1 callers",
    ] {
        assert!(
            outcome.prompts[0].contains(named),
            "{named} missing from {}",
            outcome.prompts[0]
        );
    }
    assert_eq!(
        statuses(&outcome.reply),
        ["widened", "minted"],
        "{}",
        outcome.reply
    );

    // docs/rollout/github-events-poll-mode.md, "Enabling CI flow reads":
    // widen-ceiling --apply, then grant, two confirmations.
    let manual = widen_fixture("widen-manual");
    let widened = call(
        &manual.state,
        &manual.path,
        manifest::ADMIN_WIDEN_CEILING_OP,
        json!({"connection_id": "conn-github-actions", "actions": CI_FLOW, "dry_run": false}),
    )
    .await;
    assert_eq!(
        widened.reply["result"]["applied"], true,
        "{}",
        widened.reply
    );
    let granted = call(
        &manual.state,
        &manual.path,
        manifest::ADMIN_GRANT_OP,
        json!({"connection_id": "conn-github-actions", "grantee_principal": "reserved:basal",
            "authority_kind": "invoke", "risk_ceiling": "read", "action_selectors": CI_FLOW}),
    )
    .await;
    assert!(granted.reply.get("result").is_some(), "{}", granted.reply);
    assert_eq!(
        widened.prompts.len() + granted.prompts.len(),
        2,
        "the manual sequence asks twice"
    );
    assert_same_rows(
        &combined.path,
        &manual.path,
        &[("connections", ""), ("grants", ""), ("audit_journal", "")],
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declined_or_refused_widen_and_grant_writes_nothing() {
    let fixture = widen_fixture("widen-declined");
    let before = snapshot(&fixture.path, true);
    let preview = call(&fixture.state, &fixture.path, WIDEN, widen_params(true)).await;
    assert!(preview.prompts.is_empty());
    assert_eq!(
        statuses(&preview.reply),
        ["to_widen", "to_mint"],
        "{}",
        preview.reply
    );
    assert_eq!(
        snapshot(&fixture.path, true),
        before,
        "a preview runs the change and rolls it back"
    );
    let before = snapshot(&fixture.path, false);
    let refused = call_with(
        &fixture.state,
        &fixture.path,
        WIDEN,
        widen_params(false),
        Err("operator_declined"),
    )
    .await;
    assert_eq!(refused.prompts.len(), 1);
    assert_eq!(
        refused.reply["error"]["code"],
        "operator_confirmation_declined"
    );
    assert_eq!(snapshot(&fixture.path, false), before, "a decline wrote");
    assert_eq!(
        refusal_audits(&fixture.path, WIDEN, "operator_confirmation_declined"),
        1
    );
    // A grant the widened ceiling cannot hold is refused while planning, and
    // the widening it would have committed with is not written either.
    let mut too_risky = widen_params(false);
    too_risky["risk_ceiling"] = json!("write");
    let before = snapshot(&fixture.path, true);
    let refused = call(&fixture.state, &fixture.path, WIDEN, too_risky).await;
    assert_eq!(
        refused.reply["error"]["code"], "risk_above_ceiling",
        "{}",
        refused.reply
    );
    assert!(refused.prompts.is_empty(), "a planning refusal never asks");
    assert_eq!(snapshot(&fixture.path, true), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rerun_of_widen_and_grant_reuses_the_ceiling_and_the_grant() {
    let fixture = widen_fixture("widen-rerun");
    let first = call(&fixture.state, &fixture.path, WIDEN, widen_params(false)).await;
    assert_eq!(first.reply["result"]["applied"], true, "{}", first.reply);
    let before = snapshot(&fixture.path, false);
    let rerun = call(&fixture.state, &fixture.path, WIDEN, widen_params(false)).await;
    assert_eq!(rerun.prompts.len(), 1);
    assert_eq!(
        statuses(&rerun.reply),
        ["unchanged", "already_present"],
        "a rerun must reuse the ceiling and the grant: {}",
        rerun.reply
    );
    assert_eq!(
        snapshot(&fixture.path, false),
        before,
        "a rerun changed authority"
    );
    assert_eq!(count(&fixture.path, "SELECT COUNT(*) FROM grants"), 1);
}

// ---------------------------------------------------------------------------
// onboard_github_bot

/// The handle's installation as GitHub would list it, counting every page
/// read so a test can prove when GitHub is contacted.
struct CountingInstallation {
    reads: Arc<AtomicUsize>,
    repositories: &'static [&'static str],
}

impl plexus_core::github::control::InstallationReader for CountingInstallation {
    fn repositories_page(
        &self,
        _: &plexus_core::credentials::ResolvedCredential,
        _: usize,
        _: usize,
    ) -> Result<Value, String> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"total_count": self.repositories.len(),
            "repositories": self.repositories.iter().map(|name| json!({"full_name": name})).collect::<Vec<_>>()}))
    }
}

struct GithubFixture {
    path: DiagnosticStorePath,
    store: Arc<PlexusStore>,
    state: Arc<ModuleState>,
    reads: Arc<AtomicUsize>,
}

fn github_state(
    store: &Arc<PlexusStore>,
    reads: &Arc<AtomicUsize>,
    home: bool,
) -> Arc<ModuleState> {
    let mut runtime = runtime_for_test(Arc::clone(store));
    runtime.github_handle_credentials = Some(Arc::new(AnyHandleToken));
    runtime.github_control_reader = Some(Arc::new(CountingInstallation {
        reads: Arc::clone(reads),
        repositories: &["org/one", "org/two"],
    }));
    if !home {
        runtime.connector_home = Arc::new(crate::connector_home::ConnectorHome::unavailable());
    }
    Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    })
}

fn github_fixture(label: &str) -> GithubFixture {
    let path = DiagnosticStorePath::new(label);
    let store = Arc::new(crate::test_support::open_file_store(&path));
    install(&store, "github_rest");
    let reads = Arc::new(AtomicUsize::new(0));
    let state = github_state(&store, &reads, true);
    GithubFixture {
        path,
        store,
        state,
        reads,
    }
}

fn inventory(agent: &str) -> Value {
    json!({"version": "github-grant-import.v1", "handles": [{
        "app_handle_id": HANDLE, "agent_id": agent, "app_id": 42,
        "installation_id": null, "credential_id": "github_app:app-onboard",
        "status": "enabled",
        "grants": [{"action": "create_issue", "repository": "org/one",
            "provenance": "operator", "policy": "allow"}]
    }]})
}

fn onboard_params(dry_run: bool) -> Value {
    json!({
        "inventory": inventory(AGENT),
        "repositories": ["org/two"],
        "actions": ["add_issue_comment"],
        "carrier": "reserved:aft",
        "effect": "allow",
        "read_actions": ["github.repo.get"],
        "poll_actions": ["github.issue.get"],
        "shim_manifest_maps_repo": true,
        "dry_run": dry_run,
    })
}

#[tokio::test]
async fn full_onboarding_summary_fits_and_preview_lists_every_action() {
    let mut fixture = github_fixture("full-onboard-summary");
    const REPOS: &[&str] = &[
        "cortexkit/motor",
        "cortexkit/prefrontal",
        "cortexkit/plexus",
    ];
    const WRITES: &[&str] = &[
        "add_issue_comment",
        "add_pr_review",
        "add_reaction",
        "create_issue",
        "create_pull_request",
        "edit_issue",
        "update_issue_comment",
        "close_issue",
        "reopen_issue",
        "mark_pull_request_ready",
        "convert_pull_request_to_draft",
    ];
    let reads = plexus_core::github::reads::bot::GRANT_ACTIONS;
    Arc::get_mut(&mut fixture.state)
        .unwrap()
        .runtime
        .github_control_reader = Some(Arc::new(CountingInstallation {
        reads: fixture.reads.clone(),
        repositories: REPOS,
    }));
    let mut params = onboard_params(true);
    params["inventory"]["handles"][0]["app_handle_id"] = json!("motor-alfonso");
    params["inventory"]["handles"][0]["credential_id"] = json!("github_app:motor-alfonso");
    params["inventory"]["handles"][0]["agent_id"] = json!("agent_ef98bc82ef005a63");
    params["inventory"]["handles"][0]["app_id"] = json!(5453881);
    params["inventory"]["handles"][0]["grants"][0]["repository"] = json!(REPOS[0]);
    params["repositories"] = json!(REPOS);
    params["actions"] = json!(WRITES);
    params["read_actions"] = json!(reads);
    let preview = call(&fixture.state, &fixture.path, ONBOARD, params.clone()).await;
    let result = &preview.reply["result"];
    let summary = result["summary"]
        .as_str()
        .unwrap_or_else(|| panic!("{}", preview.reply));
    assert!(
        operator_confirmation::valid_summary(summary),
        "full onboarding summary must satisfy daemon rules: {summary}"
    );
    assert_eq!(summary, "onboard bot motor-alfonso for agent agent_ef98bc82ef005a63: import app 5453881; bind 3 repositories; grant 11 writes via reserved:aft (allow), 6 reads, 1 poll read; you state AFT's manifest maps it");
    let steps = result["steps"].as_array().unwrap();
    for (step, expected) in [
        ("grant_writes", json!(WRITES)),
        ("grant_reads", json!(reads)),
        ("grant_poll", json!(["github.issue.get"])),
    ] {
        let row = steps
            .iter()
            .find(|row| row["step"] == step)
            .unwrap_or_else(|| panic!("missing {step} in {result}"));
        let actual = row["params"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        let expected = expected
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, expected, "preview must list every {step} action");
    }
    assert_eq!(
        result["installation_repositories"],
        json!([
            "cortexkit/motor",
            "cortexkit/plexus",
            "cortexkit/prefrontal"
        ])
    );
    assert!(preview.prompts.is_empty());
    params["dry_run"] = json!(false);
    let declined = call_with(
        &fixture.state,
        &fixture.path,
        ONBOARD,
        params,
        Err(subc_protocol::error_codes::OPERATOR_DECLINED),
    )
    .await;
    assert_eq!(declined.prompts, [summary]);
    assert_eq!(
        declined.reply["error"]["code"],
        "operator_confirmation_declined"
    );
}

#[tokio::test]
async fn large_connection_and_widen_plans_have_daemon_valid_summaries() {
    let callers = (0..128)
        .map(|i| format!("reserved:agent_{i:016x}"))
        .collect::<Vec<_>>();
    let write = write_fixture("large-write-summary", None);
    let poll = poll_fixture("large-poll-summary", None);
    let widen = widen_fixture("large-widen-summary");
    let mut write_request = write_params(true);
    write_request["grantees"] = json!(callers);
    write_request["resource_filters"] =
        json!({"write_enabling": ["team"], "values": {"team": "x".repeat(512)}});
    let mut poll_request = poll_params(true);
    poll_request["consumers"] = json!(callers);
    let mut widen_request = widen_params(true);
    widen_request["grantees"] = json!(callers);
    widen_request["actions"] = json!(POLL_READS.iter().chain(&CI_FLOW).collect::<Vec<_>>());
    for (fixture, method, params) in [
        (&write, WRITE, write_request),
        (&poll, POLL, poll_request),
        (&widen, WIDEN, widen_request),
    ] {
        let outcome = call(&fixture.state, &fixture.path, method, params).await;
        let summary = outcome.reply["result"]["summary"]
            .as_str()
            .unwrap_or_else(|| panic!("{}", outcome.reply));
        assert!(
            operator_confirmation::valid_summary(summary),
            "{method}: {summary}"
        );
        assert!(
            summary.contains("128"),
            "{method} must count callers: {summary}"
        );
        assert!(outcome.prompts.is_empty());
    }
}

#[test]
fn prompt_labels_preserve_full_subject_identifiers() {
    let subject = format!("connection_{}", "a".repeat(80));
    assert_eq!(crate::composite_admin::prompt_label(&subject), subject);
}

const GITHUB_TABLES: [(&str, &str); 8] = [
    ("github_app_handle", ""),
    ("github_repo_binding", ""),
    ("github_repo_binding_generation", ""),
    ("connections", ""),
    ("grants", ""),
    ("policies", ""),
    ("catalog_actions", ""),
    ("audit_journal", ""),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_onboarding_asks_once_and_writes_what_the_manual_commands_write() {
    let combined = github_fixture("onboard-combined");
    let outcome = call(
        &combined.state,
        &combined.path,
        ONBOARD,
        onboard_params(false),
    )
    .await;
    assert_eq!(
        outcome.prompts.len(),
        1,
        "one applied onboarding must ask exactly once: {:?}",
        outcome.prompts
    );
    let summary = &outcome.prompts[0];
    for named in [
        HANDLE,
        AGENT,
        "import app 42",
        "bind org/one,org/two",
        "grant 1 writes via reserved:aft (allow), 1 reads, 1 poll read",
        "you state AFT's manifest maps it",
    ] {
        assert!(summary.contains(named), "{named} missing from {summary}");
    }
    assert_eq!(
        outcome.reply["result"]["applied"], true,
        "{}",
        outcome.reply
    );
    assert_eq!(
        combined.reads.load(Ordering::SeqCst),
        1,
        "the installation is listed once, while planning"
    );

    // The manual sequence: import, probe, bind, then the write, read and poll
    // grants, five confirmations (the probe asks none).
    let manual = github_fixture("onboard-manual");
    let mut prompts = 0;
    for (method, params) in [
        (
            manifest::GITHUB_IMPORT_OP,
            json!({"inventory": inventory(AGENT), "dry_run": false}),
        ),
        (manifest::GITHUB_PROBE_OP, json!({"app_handle_id": HANDLE})),
        (
            manifest::GITHUB_BIND_OP,
            json!({"app_handle_id": HANDLE, "repositories": ["org/two"], "dry_run": false}),
        ),
        (
            manifest::GITHUB_GRANT_OP,
            json!({"app_handle_id": HANDLE, "actions": ["add_issue_comment"],
                "module": "reserved:aft", "effect": "allow", "dry_run": false}),
        ),
        (
            manifest::GITHUB_GRANT_OP,
            json!({"kind": "read", "app_handle_id": HANDLE, "module": "reserved:aft",
                "actions": ["github.repo.get"], "all_handles": false, "dry_run": false}),
        ),
        (
            manifest::GITHUB_GRANT_OP,
            json!({"kind": "poll", "app_handle_id": HANDLE,
                "actions": ["github.issue.get"], "dry_run": false}),
        ),
    ] {
        let done = call(&manual.state, &manual.path, method, params).await;
        assert!(
            done.reply.get("result").is_some(),
            "{method}: {}",
            done.reply
        );
        prompts += done.prompts.len();
    }
    assert_eq!(prompts, 5, "the manual sequence asks five times");
    assert_same_rows(&combined.path, &manual.path, &GITHUB_TABLES);
}

/// An onboarded handle serves its first write with no restart. The applied
/// import commits the handle connection without running discovery, so the
/// in-memory REST config is missing until something registers it; the import
/// registers it from the reviewed manifest, and the dispatch router then
/// sends to REST instead of falling through to MCP. Without that step the
/// first write reports `mcp_transport_error` and never reaches GitHub.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_onboarded_handle_serves_its_first_write_without_a_restart() {
    use plexus_core::Transport as _;
    use std::sync::Mutex;

    // The fake GitHub API: records the request line and answers the creation.
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let (endpoint, server) = crate::test_http::FixedRequestServer::start(
        1,
        "github-create-issue",
        {
            let seen = Arc::clone(&seen);
            move |_, raw| {
                let head = raw.split("\r\n").next().unwrap_or("").to_owned();
                seen.lock().unwrap().push(head);
                let body = json!({"id": 1, "number": 7,
                    "html_url": "https://github.com/org/one/issues/7"})
                .to_string();
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }
        },
    );
    let mut fixture = github_fixture("onboard-first-write-no-restart");
    // Discovery and the new registration both point at the fake server. No
    // restart runs between the import below and the write: a restart would
    // re-register every transport at boot and hide the defect.
    Arc::get_mut(&mut fixture.state)
        .unwrap()
        .runtime
        .endpoint_override = Some(endpoint);
    let outcome = call(
        &fixture.state,
        &fixture.path,
        ONBOARD,
        onboard_params(false),
    )
    .await;
    assert_eq!(
        outcome.reply["result"]["applied"], true,
        "onboarding must apply: {}",
        outcome.reply
    );
    let connection_id = format!("github-handle-{HANDLE}");
    assert!(
        fixture
            .state
            .runtime
            .rest_transport
            .has_connection(&connection_id),
        "the applied import must register the handle connection's REST transport"
    );
    let credential =
        plexus_core::credentials::ResolvedCredential::new(b"handle-token".to_vec(), None, 1);
    let response = crate::blocking_section(|| {
        fixture.state.runtime.rest_transport.dispatch_github_facade(
            plexus_core::TransportRequest {
                request_id: "first-write".to_string(),
                connection_id: connection_id.clone(),
                action: "create_issue".to_string(),
                args: json!({"owner": "org", "repo": "one", "title": "hello"}),
                credential_fingerprint: "test".to_string(),
            },
            &credential,
        )
    });
    assert_eq!(
        response.transmission,
        plexus_core::TransmissionState::Sent,
        "the first write must send: {response:?}"
    );
    assert!(
        response.response.is_some(),
        "the fake server's answer must come back: {response:?}"
    );
    server
        .join()
        .expect("the first write must reach the fake GitHub server");
    assert_eq!(
        *seen.lock().unwrap(),
        vec!["POST /repos/org/one/issues HTTP/1.1".to_string()],
        "the write must arrive as the reviewed create_issue request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declined_onboarding_writes_nothing_and_reads_github_only_while_planning() {
    let fixture = github_fixture("onboard-declined");
    let before = snapshot(&fixture.path, true);
    let mut unattested = onboard_params(true);
    unattested["shim_manifest_maps_repo"] = json!(false);
    let preview = call(&fixture.state, &fixture.path, ONBOARD, unattested.clone()).await;
    assert!(preview.prompts.is_empty(), "a preview never asks");
    assert_eq!(
        (
            &preview.reply["result"]["handle"],
            &preview.reply["result"]["newly_bound"],
            &preview.reply["result"]["installation_repositories"],
        ),
        (
            &json!("import"),
            &json!(["org/one", "org/two"]),
            &json!(["org/one", "org/two"])
        ),
        "{}",
        preview.reply
    );
    assert_eq!(snapshot(&fixture.path, true), before, "a preview wrote");
    // Applying a bind without the operator's statement about the gh shim
    // manifest is refused before anyone is asked.
    unattested["dry_run"] = json!(false);
    let refused = call(&fixture.state, &fixture.path, ONBOARD, unattested).await;
    assert_eq!(
        refused.reply["error"]["code"], "shim_manifest_unconfirmed",
        "an applied bind without the shim statement must be refused before asking: {}",
        refused.reply
    );
    assert!(refused.prompts.is_empty());
    assert_eq!(snapshot(&fixture.path, true), before);

    let reads_before = fixture.reads.load(Ordering::SeqCst);
    let before = snapshot(&fixture.path, false);
    let declined = call_with(
        &fixture.state,
        &fixture.path,
        ONBOARD,
        onboard_params(false),
        Err("operator_declined"),
    )
    .await;
    assert_eq!(declined.prompts.len(), 1);
    assert_eq!(
        declined.reply["error"]["code"], "operator_confirmation_declined",
        "{}",
        declined.reply
    );
    assert_eq!(snapshot(&fixture.path, false), before, "a decline wrote");
    assert_eq!(
        refusal_audits(&fixture.path, ONBOARD, "operator_confirmation_declined"),
        1
    );
    assert_eq!(
        fixture.reads.load(Ordering::SeqCst),
        reads_before + 1,
        "only planning reads GitHub; nothing is sent after a decline"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rerun_of_the_onboarding_reuses_the_handle_and_refuses_a_different_one() {
    let fixture = github_fixture("onboard-rerun");
    let first = call(
        &fixture.state,
        &fixture.path,
        ONBOARD,
        onboard_params(false),
    )
    .await;
    assert_eq!(first.reply["result"]["applied"], true, "{}", first.reply);
    let tally = |path: &Path| {
        [
            "SELECT COUNT(*) FROM github_app_handle",
            "SELECT COUNT(*) FROM github_repo_binding",
            "SELECT COUNT(*) FROM grants",
            "SELECT COUNT(*) FROM policies",
            "SELECT COUNT(*) FROM connections",
        ]
        .map(|query| count(path, query))
    };
    let after_first = tally(&fixture.path);
    let rerun = call(
        &fixture.state,
        &fixture.path,
        ONBOARD,
        onboard_params(false),
    )
    .await;
    assert_eq!(rerun.prompts.len(), 1, "a rerun asks once again");
    assert_eq!(rerun.reply["result"]["applied"], true, "{}", rerun.reply);
    assert_eq!(
        rerun.reply["result"]["handle"], "reuse",
        "a rerun must reuse the imported handle: {}",
        rerun.reply
    );
    assert_eq!(
        rerun.reply["result"]["newly_bound"],
        json!([]),
        "{}",
        rerun.reply
    );
    assert_eq!(tally(&fixture.path), after_first, "a rerun duplicated");

    let mut other = onboard_params(false);
    other["inventory"] = inventory("agent-other");
    let before = snapshot(&fixture.path, true);
    let refused = call(&fixture.state, &fixture.path, ONBOARD, other).await;
    assert_eq!(
        refused.reply["error"]["code"], "github_handle_mismatch",
        "{}",
        refused.reply
    );
    assert!(refused.prompts.is_empty());
    assert_eq!(snapshot(&fixture.path, true), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_onboarding_without_the_connector_home_role_reads_and_asks_nothing() {
    let fixture = github_fixture("onboard-no-home");
    let state = github_state(&fixture.store, &fixture.reads, false);
    let before = snapshot(&fixture.path, true);
    for dry_run in [true, false] {
        let refused = call(&state, &fixture.path, ONBOARD, onboard_params(dry_run)).await;
        assert_eq!(
            refused.reply["error"]["code"], "connector_home_not_held",
            "an onboarding without the connector home role must be refused, even as a preview: {}",
            refused.reply
        );
        assert!(
            refused.prompts.is_empty(),
            "an onboarding without the connector home role must not ask"
        );
    }
    assert_eq!(
        fixture.reads.load(Ordering::SeqCst),
        0,
        "an onboarding without the connector home role must not read GitHub"
    );
    assert_eq!(snapshot(&fixture.path, true), before);
}

// ---------------------------------------------------------------------------
// Wildcards
//
// The store accepts an explicit `*` selector as "every action the ceiling
// allows", so a wildcard reaching a composite's ticket, grant or policy would
// authorize every action. Each composite names exactly what it grants and
// refuses a wildcard action or grantee while planning: before any prompt,
// with nothing written.

/// Every action list a composite takes, each set to `*` and to a name that
/// contains `*`.
fn wildcard_action_cases() -> Vec<(&'static str, &'static str, Value)> {
    let mut cases = Vec::new();
    for wildcard in ["*", "held_*"] {
        for field in ["actions", "invoke_actions", "allow_actions"] {
            let mut params = write_params(false);
            params[field] = json!([wildcard]);
            cases.push((WRITE, field, params));
        }
    }
    for wildcard in ["*", "list_workflow_*"] {
        for field in ["actions", "consume_actions"] {
            let mut params = poll_params(false);
            params[field] = json!(["list_workflow_runs", wildcard]);
            cases.push((POLL, field, params));
        }
    }
    for wildcard in ["*", "get_*"] {
        let mut params = widen_params(false);
        params["actions"] = json!(["get_job", wildcard]);
        cases.push((WIDEN, "actions", params));
    }
    cases
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wildcard_action_is_refused_before_asking_and_writes_nothing() {
    let vendor = CountingVendor::start();
    let write = write_fixture("wildcard-action-write", Some(&vendor.url));
    let poll = poll_fixture("wildcard-action-poll", Some(&vendor.url));
    let widen = widen_fixture("wildcard-action-widen");
    for (method, field, params) in wildcard_action_cases() {
        let fixture = match method {
            WRITE => &write,
            POLL => &poll,
            _ => &widen,
        };
        let named = params[field].clone();
        for dry_run in [false, true] {
            let mut params = params.clone();
            params["dry_run"] = json!(dry_run);
            let before = snapshot(&fixture.path, true);
            let refused = call(&fixture.state, &fixture.path, method, params).await;
            assert_eq!(
                refused.reply["error"]["code"], "explicit_actions_required",
                "a wildcard action must be refused: {method} {field}={named}: {}",
                refused.reply
            );
            assert!(
                refused.prompts.is_empty(),
                "a wildcard action is refused before asking: {method} {field}={named}"
            );
            assert_eq!(
                snapshot(&fixture.path, true),
                before,
                "a refused wildcard action wrote: {method} {field}={named}"
            );
        }
    }
    // The onboarding's write, read and poll action lists are named too.
    let github = github_fixture("wildcard-action-onboard");
    for field in ["actions", "read_actions", "poll_actions"] {
        for wildcard in ["*", "github.*"] {
            let mut params = onboard_params(false);
            params[field] = json!([wildcard]);
            let before = snapshot(&github.path, true);
            let refused = call(&github.state, &github.path, ONBOARD, params).await;
            assert_eq!(
                refused.reply["error"]["code"], "explicit_actions_required",
                "a wildcard action must be refused: onboarding {field}={wildcard}: {}",
                refused.reply
            );
            assert!(refused.prompts.is_empty());
            assert_eq!(snapshot(&github.path, true), before);
        }
    }
    assert_eq!(vendor.contacts(), 0, "a refused wildcard reaches no vendor");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wildcard_grantee_is_refused_before_asking_and_writes_nothing() {
    let vendor = CountingVendor::start();
    let write = write_fixture("wildcard-grantee-write", Some(&vendor.url));
    let poll = poll_fixture("wildcard-grantee-poll", Some(&vendor.url));
    let widen = widen_fixture("wildcard-grantee-widen");
    let mut cases = Vec::new();
    for wildcard in ["*", "reserved:*"] {
        let mut params = write_params(false);
        params["grantees"] = json!(["reserved:basal", wildcard]);
        cases.push((&write, WRITE, params));
        let mut params = poll_params(false);
        params["consumers"] = json!([wildcard]);
        cases.push((&poll, POLL, params));
        let mut params = widen_params(false);
        params["grantees"] = json!([wildcard]);
        cases.push((&widen, WIDEN, params));
    }
    for (fixture, method, params) in cases {
        for dry_run in [false, true] {
            let mut params = params.clone();
            params["dry_run"] = json!(dry_run);
            let before = snapshot(&fixture.path, true);
            let refused = call(&fixture.state, &fixture.path, method, params.clone()).await;
            assert_eq!(
                refused.reply["error"]["code"], "wildcard_grantee",
                "a wildcard grantee must be refused: {method} {params}: {}",
                refused.reply
            );
            assert!(refused.prompts.is_empty(), "{method} asked: {params}");
            assert_eq!(snapshot(&fixture.path, true), before, "{method} wrote");
        }
    }
    assert_eq!(vendor.contacts(), 0, "a refused wildcard reaches no vendor");
}
