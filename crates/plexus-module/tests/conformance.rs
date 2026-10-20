//! Wire-v2 acceptance proof for the first plexus substrate slice.
//!
//! The test boots the real module under an in-process subc daemon, checks the
//! fixed facade registration, exercises the real store-backed empty connection
//! listing, probes health-v2, and checks the in-module principal backstop.

#![cfg(test)]

#[path = "support/bounded.rs"]
mod bounded;
#[path = "support/operator_confirmation.rs"]
mod operator_confirmation_peer;

use bounded::recv_within;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use cortexkit_test_support::ckdev_binary;
use plexus_conformance::{catalog_manifests, StubRestRoute, StubRestServer};
use plexus_core::test_scratch::Scratch;
use plexus_core::{
    ingest_value, GrantInput, McpRemoteTransport, PlexusStore, StubCredentialSource,
    CATALOG_PRINCIPAL,
};
use plexus_module::composition::ModuleRuntime;
use plexus_module::manifest;
use serde_json::{json, Value};
use subc_control::{ClientControlRequest, ClientControlResponse};
use subc_protocol::manifest::ProviderRole;
use subc_protocol::session::{HealthStatus, ModuleControlRequest};
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Principal, Priority, RouteTarget, PROTOCOL_VERSION,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

const MODULE_ID: &str = "plexus";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_daemon_proves_hello_empty_connections_health_and_deny() {
    let (mut daemon, connection) = start_live_daemon().await;
    let mut client = connect_client(&connection).await;

    let catalog = wait_for_module_catalog(&mut client).await;
    let ClientControlResponse::CatalogList { modules, .. } = catalog else {
        panic!("expected catalog.list response");
    };
    let entry = modules
        .iter()
        .find(|module| module.module_id == MODULE_ID)
        .expect("plexus must register with subc");
    let role = entry.roles.first().expect("plexus provider role");
    let ProviderRole::ToolProvider { tools, .. } = role else {
        panic!("plexus must register a ToolProvider role");
    };
    assert_eq!(tools.len(), 11);
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "connections",
            "catalog",
            "invoke",
            "requests",
            "github",
            "github_read",
            "github_react",
            "events_get",
            "events",
            "web_search",
            "code_search"
        ]
    );

    // Every advertised name must be MCP-safe, checked as a PROPERTY rather than
    // against the list above.
    //
    // The list is a snapshot and says nothing about a tool added later. This
    // rule does: MCP admits only ASCII letters, digits, `_` and `-` in a tool
    // name, and the gateway refuses a provider whose manifest breaks it. A
    // dotted name such as `plexus.connections` is refused at that boundary,
    // with the failure surfacing as a transport error at the client and the
    // cause staying in the daemon log, which is why it goes undiagnosed rather
    // than being read off a message.
    for tool in tools {
        assert!(
            !tool.name.is_empty()
                && tool
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "tool name '{}' is not MCP-safe: the gateway will refuse this module's whole surface",
            tool.name
        );
    }

    let route = open_live_route(&mut client).await;
    let response = send_tool_request(
        &mut client,
        route,
        20,
        manifest::CONNECTIONS_TOOL,
        json!({"op": "list"}),
    )
    .await;
    assert_eq!(response.header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&response.body).expect("connections response JSON");
    assert_eq!(body["result"]["connections"], json!([]));

    let events = send_tool_request(
        &mut client,
        route,
        23,
        manifest::EVENTS_TOOL,
        json!({"op": "list"}),
    )
    .await;
    let events_body: Value = serde_json::from_slice(&events.body).expect("events response JSON");
    assert_eq!(events_body["result"]["events"], json!([]));
    assert_eq!(events_body["result"]["subscriptions"], json!([]));

    // Pre-connection vendor discovery: with zero connections (the correct
    // fresh-install state) the ingested manifests must still be visible, or an
    // operator has no way to learn what can be connected.
    let apps = send_tool_request(
        &mut client,
        route,
        22,
        manifest::CATALOG_TOOL,
        json!({"op": "apps"}),
    )
    .await;
    let apps_body: Value = serde_json::from_slice(&apps.body).expect("apps response JSON");
    let listed = apps_body["result"]["apps"]
        .as_array()
        .expect("apps array")
        .iter()
        .map(|app| app["key"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert!(
        listed.contains(&"exa".to_string()),
        "ingested manifests must be discoverable before any connection exists: {listed:?}"
    );
    let exa = apps_body["result"]["apps"]
        .as_array()
        .and_then(|apps| apps.iter().find(|app| app["key"] == "exa"))
        .expect("exa summary");
    assert_eq!(exa["connection_count"], json!(0));
    assert!(exa["name"].is_string() && exa["tier"].is_string());
    let rendered = apps_body.to_string();
    assert!(
        !rendered.contains("mcp.exa.ai") && !rendered.contains("credential_bindings"),
        "discovery must not leak transport or credential detail"
    );

    let health = send_control_request(
        &mut client,
        21,
        ClientControlRequest::SupervisorHealthProbe {
            module_id: MODULE_ID.to_string(),
        },
    )
    .await;
    let ClientControlResponse::SupervisorHealthProbe { status, .. } =
        serde_json::from_slice(&health.body).expect("health probe response")
    else {
        panic!("expected supervisor health probe response");
    };
    assert_eq!(status, HealthStatus::Ok);

    let (writer, mut responses) = tokio::sync::mpsc::channel(4);
    let untrusted_bind = Frame::build(
        FrameType::Request,
        plexus_module::wire::control_flags(),
        0,
        0,
        30,
        serde_json::to_vec(&ModuleControlRequest::RouteBind {
            scope: None,
            call_mode: None,
            role_versions: None,
            route_channel: 8,
            epoch: 1,
            target: RouteTarget::ToolProvider {
                module_id: MODULE_ID.to_string(),
            },
            identity: BindIdentity::new("/tmp", "conformance".to_string(), "session".to_string()),
            principal: Some(Principal::Reserved {
                module_id: "subc-mcp".to_string(),
            }),
            consumer_capabilities: None,
            admission_facts: None,
        })
        .expect("serialize untrusted bind"),
    )
    .expect("build untrusted bind");
    plexus_module::handle_control_request_for_test(
        untrusted_bind,
        &writer,
        &std::sync::Arc::new(plexus_module::health::HealthState::new()),
    )
    .await
    .expect("principal backstop response");
    let denial = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "principal denial frame",
    )
    .await;
    assert_eq!(denial.header.ty, FrameType::Error);
    let error: subc_protocol::ErrorBody = serde_json::from_slice(&denial.body).expect("error body");
    assert_eq!(error.code, "principal_denied");

    drop(client);
    daemon.stop();
}

/// The operator path, end to end over the real wire, from an empty store.
///
/// This is the acceptance property that the fixtures structurally cannot prove:
/// they seed tickets, grants, and connections directly through the store, so
/// they assert "the machinery works GIVEN authority" and never "an operator can
/// OBTAIN authority". Everything here is created through a surface an operator
/// actually has — the management route for the ceremony, the tool route for the
/// facade — with no store access anywhere in the test.
///
/// The chain: discover vendors → issue a ticket (the only step proving
/// credential possession) → connect → configure resource filters → mint a grant
/// → invoke. The invoke terminal is asserted honestly: this daemon has no vault
/// and no vendor endpoint, so the call cannot succeed. What it must NOT do is
/// fail for lack of AUTHORITY — a grant_missing or connection_admin_required
/// here would mean the operator path did not actually confer what it claims.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_can_reach_invoke_from_an_empty_store_over_the_wire() {
    let (mut daemon, connection) = start_live_daemon().await;
    let mut client = connect_client(&connection).await;
    wait_for_module_catalog(&mut client).await;

    let tools = open_live_route(&mut client).await;
    let admin = open_management_route(&mut client).await;

    // 1. Discovery: what can be connected at all.
    let apps = send_tool_request(
        &mut client,
        tools,
        40,
        manifest::CATALOG_TOOL,
        json!({"op": "apps"}),
    )
    .await;
    let apps: Value = serde_json::from_slice(&apps.body).expect("apps response");
    let app_key = apps["result"]["apps"]
        .as_array()
        .expect("apps array")
        .iter()
        .find(|app| app["key"] == "linear")
        .map(|app| app["key"].as_str().expect("key").to_string())
        .expect("a write-capable vendor must be discoverable");

    // 2. Ceremony: place a handle and receive a ticket bounded by the manifest.
    let issued = send_management_request(
        &mut client,
        admin,
        41,
        "plexus.admin.issue_ticket",
        json!({
            "app_key": app_key,
            "credential_id": "test:operator_path",
            "risk_ceiling": "write",
            "action_selectors": ["*"]
        }),
    )
    .await;
    let issued: Value = serde_json::from_slice(&issued.body).expect("issue_ticket response");
    assert!(issued["error"].is_null(), "issue_ticket failed: {issued}");
    assert!(daemon.operator_peer.approvals() > 0);
    let ticket_id = issued["result"]["ticket_id"]
        .as_str()
        .expect("ticket id")
        .to_string();
    let connection_id = issued["result"]["connection_id"]
        .as_str()
        .expect("connection id")
        .to_string();
    let granted_actions = issued["result"]["ceiling"]["action_selectors"]
        .as_array()
        .expect("expanded ceiling")
        .clone();
    assert!(
        !granted_actions.iter().any(|value| value == "*"),
        "the ceiling must be stored expanded, not as a wildcard: {granted_actions:?}"
    );

    // 3. Connect: consume the ticket through the ordinary tool surface.
    let connected = send_tool_request(
        &mut client,
        tools,
        42,
        manifest::CONNECTIONS_TOOL,
        json!({"op": "connect", "ticket_id": ticket_id}),
    )
    .await;
    let connected: Value = serde_json::from_slice(&connected.body).expect("connect response");
    assert!(connected["error"].is_null(), "connect failed: {connected}");

    // 4. Configure: without this every write is denied write_filters_absent.
    let configured = send_tool_request(
        &mut client,
        tools,
        43,
        manifest::CONNECTIONS_TOOL,
        json!({
            "op": "configure",
            "connection": connection_id,
            "resource_filters": {"write_enabling": ["team"]}
        }),
    )
    .await;
    let configured: Value = serde_json::from_slice(&configured.body).expect("configure response");
    // configure requires a connection-admin grant, which the operator has not
    // minted yet: the refusal proves the gate is live, and the mint below is
    // what clears it.
    assert_eq!(
        configured["error"]["code"], "connection_admin_required",
        "configure before an admin grant must be refused: {configured}"
    );

    let admin_grant = send_management_request(
        &mut client,
        admin,
        44,
        "plexus.admin.grant",
        json!({
            "connection_id": connection_id,
            "authority_kind": "connection_admin",
            "risk_ceiling": "write"
        }),
    )
    .await;
    let admin_grant: Value = serde_json::from_slice(&admin_grant.body).expect("grant response");
    assert!(
        admin_grant["error"].is_null(),
        "connection-admin grant failed: {admin_grant}"
    );

    let configured = send_tool_request(
        &mut client,
        tools,
        45,
        manifest::CONNECTIONS_TOOL,
        json!({
            "op": "configure",
            "connection": connection_id,
            "resource_filters": {"write_enabling": ["team"]}
        }),
    )
    .await;
    let configured: Value = serde_json::from_slice(&configured.body).expect("configure response");
    assert!(
        configured["error"].is_null(),
        "configure after the admin grant must succeed: {configured}"
    );

    // 5. Grant invoke authority, then 6. invoke.
    let invoke_grant = send_management_request(
        &mut client,
        admin,
        46,
        "plexus.admin.grant",
        json!({
            "connection_id": connection_id,
            "authority_kind": "invoke",
            "risk_ceiling": "write"
        }),
    )
    .await;
    let invoke_grant: Value = serde_json::from_slice(&invoke_grant.body).expect("grant response");
    assert!(
        invoke_grant["error"].is_null(),
        "invoke grant failed: {invoke_grant}"
    );

    let invoked = send_tool_request(
        &mut client,
        tools,
        47,
        manifest::INVOKE_TOOL,
        json!({
            "op": "call",
            "connection": connection_id,
            "action": "search_issues",
            "args": {"query": "conformance"}
        }),
    )
    .await;
    let invoked: Value = serde_json::from_slice(&invoked.body).expect("invoke response");
    let code = invoked["error"]["code"].as_str().unwrap_or("");
    // The governance gates run in order: connection, catalog, grant, policy,
    // severity, resource filters, then credential. Reaching the CREDENTIAL gate
    // is the positive proof this test exists for — it means every authority gate
    // passed, so the operator path really did confer invoke authority. This
    // daemon has no vault, so credential resolution is the honest terminal; a
    // future test environment with one would see success instead.
    // Matched on the prefix rather than one exact code, because the credential
    // gate reports WHICH transient failure occurred (route, vault lock,
    // context) and this test only cares that the gate was REACHED. Pinning one
    // variant would make an unrelated change to the failure taxonomy look like
    // a broken operator path.
    assert!(
        invoked["error"].is_null() || code.starts_with("credential_"),
        "operator path must reach the credential gate; got: {invoked}"
    );

    // Setting a policy must change the live governance decision, not only
    // create a row that a separate store test can inspect. With the default
    // `ask_first` policy (hold the call for approval), this unscoped write is
    // refused, because a call with no session scope can't file an approval
    // card. Once the operator sets `allow` for the action, the same write goes
    // on to the credential check.
    let write_arguments = json!({
        "op": "call",
        "connection": connection_id,
        "action": "create_issue",
        "args": {
            "workspace": "core",
            "team": "core",
            "title": "policy wire conformance"
        }
    });
    let parked = send_tool_request(
        &mut client,
        tools,
        60,
        manifest::INVOKE_TOOL,
        write_arguments.clone(),
    )
    .await;
    let parked: Value = serde_json::from_slice(&parked.body).expect("parked write response");
    assert_eq!(
        parked["error"]["code"], "consent_unavailable",
        "an unscoped write cannot create a consent card: {parked}"
    );

    let set = send_management_request(
        &mut client,
        admin,
        61,
        manifest::ADMIN_SET_POLICY_OP,
        json!({
            "connection_id": connection_id,
            "action_selector": "create_issue",
            "effect": "ask_first"
        }),
    )
    .await;
    let set: Value = serde_json::from_slice(&set.body).expect("set policy response");
    let policy_id = set["result"]["policy"]["policy_id"]
        .as_str()
        .expect("set_policy returns a policy id")
        .to_string();

    // Set the same scope again to prove the operation updates an existing row
    // instead of accumulating conflicting policies for one action.
    let updated = send_management_request(
        &mut client,
        admin,
        62,
        manifest::ADMIN_SET_POLICY_OP,
        json!({
            "connection_id": connection_id,
            "action_selector": "create_issue",
            "effect": "allow"
        }),
    )
    .await;
    let updated: Value = serde_json::from_slice(&updated.body).expect("updated policy response");
    assert_eq!(
        updated["result"]["policy"]["policy_id"], policy_id,
        "setting the same scope must update its policy rather than create another"
    );

    // This asserts store-backed state, not merely the set_policy reply. A handler
    // changed to report success without storing the policy leaves this array empty
    // and fails here.
    let listed = send_management_request(
        &mut client,
        admin,
        63,
        manifest::ADMIN_LIST_POLICIES_OP,
        json!({"connection_id": connection_id}),
    )
    .await;
    let listed: Value = serde_json::from_slice(&listed.body).expect("list policies response");
    let policy = listed["result"]["policies"]
        .as_array()
        .expect("list_policies returns an array")
        .iter()
        .find(|policy| policy["policy_id"] == policy_id)
        .unwrap_or_else(|| panic!("the policy just set must be listed: {listed}"));
    assert_eq!(policy["app_key"], "linear");
    assert_eq!(policy["action_selector"], "create_issue");
    assert_eq!(policy["effect"], "allow");
    assert_eq!(policy["state"], "until_revoked");

    let allowed = send_tool_request(
        &mut client,
        tools,
        64,
        manifest::INVOKE_TOOL,
        write_arguments,
    )
    .await;
    let allowed: Value = serde_json::from_slice(&allowed.body).expect("allowed write response");
    let code = allowed["error"]["code"].as_str().unwrap_or("");
    assert!(
        allowed["error"].is_null() || code.starts_with("credential_"),
        "an allow policy must skip action-request parking and reach credential resolution: {allowed}"
    );

    let removed = send_management_request(
        &mut client,
        admin,
        65,
        manifest::ADMIN_REMOVE_POLICY_OP,
        json!({"policy_id": policy_id}),
    )
    .await;
    let removed: Value = serde_json::from_slice(&removed.body).expect("remove policy response");
    assert_eq!(
        removed["result"]["removed"], true,
        "remove must report a stored row"
    );

    let retried_removal = send_management_request(
        &mut client,
        admin,
        66,
        manifest::ADMIN_REMOVE_POLICY_OP,
        json!({"policy_id": policy_id}),
    )
    .await;
    let retried_removal: Value =
        serde_json::from_slice(&retried_removal.body).expect("retried removal response");
    assert_eq!(
        retried_removal["result"]["removed"], false,
        "removing an absent policy must be idempotent"
    );

    let listed_after_remove = send_management_request(
        &mut client,
        admin,
        67,
        manifest::ADMIN_LIST_POLICIES_OP,
        json!({}),
    )
    .await;
    let listed_after_remove: Value = serde_json::from_slice(&listed_after_remove.body)
        .expect("post-removal policy list response");
    assert!(
        listed_after_remove["result"]["policies"]
            .as_array()
            .expect("list_policies returns an array")
            .iter()
            .all(|policy| policy["policy_id"] != policy_id),
        "the removed policy must no longer be listed: {listed_after_remove}"
    );

    // 7. Poll authority, which is what a trigger subscription needs and which no
    //    agent may ask for. Asserted HERE, on the wire, because the store has
    //    accepted poll grants since migration 6 and the poller has always
    //    claimed poll authority -- while both minting entry points rejected the
    //    value, so the whole trigger plane was unreachable in production with
    //    every core test green. A kind the store stores and no operator can type
    //    is the reachability defect this repo keeps meeting.
    let poll_grant = send_management_request(
        &mut client,
        admin,
        48,
        "plexus.admin.grant",
        json!({
            "connection_id": connection_id,
            "authority_kind": "poll",
            "risk_ceiling": "read",
            "expires_at": plexus_core::now_ms() + 3_600_000
        }),
    )
    .await;
    let poll_grant: Value = serde_json::from_slice(&poll_grant.body).expect("grant response");
    assert!(
        poll_grant["error"].is_null(),
        "poll grant must be mintable by an operator: {poll_grant}"
    );
    assert_eq!(
        poll_grant["result"]["grant"]["authority_kind"], "poll",
        "the minted grant must carry poll authority rather than a default: {poll_grant}"
    );

    // A poll grant with NO expiry is minted over the wire, not refused.
    //
    // This asserts the reversal of an earlier rule requiring poll authority to be
    // finite. The rule charged the common case -- an operator who still wants the
    // watch -- a recurring re-consent, and its failure mode was silent: at the
    // deadline the watches stopped collecting with no error raised anywhere, so a
    // revoked feed and a quiet week looked identical.
    //
    // Checked at the WIRE rather than only in the store, because that is where an
    // operator actually mints: a store that accepts an unexpiring grant while the
    // wire path rejects it would leave the feature unreachable from the tool
    // people use.
    let unbounded = send_management_request(
        &mut client,
        admin,
        49,
        "plexus.admin.grant",
        json!({
            "connection_id": connection_id,
            "authority_kind": "poll",
            "risk_ceiling": "read"
        }),
    )
    .await;
    let unbounded: Value = serde_json::from_slice(&unbounded.body).expect("grant response");
    assert_eq!(
        unbounded["result"]["grant"]["authority_kind"], "poll",
        "an unexpiring poll grant must be MINTED over the wire: {unbounded}"
    );
    assert_eq!(
        unbounded["result"]["grant"]["expires_at"],
        Value::Null,
        "the minted grant must carry no deadline rather than a substituted one: {unbounded}"
    );
    let unbounded_grant_id = unbounded["result"]["grant"]["grant_id"]
        .as_str()
        .expect("the minted poll grant has an id");

    // THE GRANTS AN OPERATOR CAN SEE MUST BE THE GRANTS THAT EXIST.
    //
    // Revocation is only reachable for someone who can first see what there is to
    // revoke, and the grant most needing revocation is the one they forgot about.
    // So this asserts the list REFLECTS what was just minted rather than merely
    // returning successfully: a handler answering with a constant empty array
    // passes every check that only counts a 200.
    let listed = send_management_request(
        &mut client,
        admin,
        50,
        "plexus.admin.list_grants",
        json!({}),
    )
    .await;
    let listed: Value = serde_json::from_slice(&listed.body).expect("list response");
    let grants = listed["result"]["grants"]
        .as_array()
        .unwrap_or_else(|| panic!("list_grants must return an array: {listed}"));
    let poll_grant = grants
        .iter()
        .find(|grant| grant["grant_id"] == unbounded_grant_id)
        .unwrap_or_else(|| panic!("the poll grant just minted must be listed: {listed}"));
    assert_eq!(
        poll_grant["state"], "until_revoked",
        "a grant with no deadline must report until_revoked, distinctly from live: {listed}"
    );
    assert_eq!(
        poll_grant["app_key"], "linear",
        "the list must name the VENDOR, not only a connection id: {listed}"
    );

    drop(client);
    daemon.stop();
}

/// Mutation proved: scope facade preflight or core authorization to rows owned
/// by the invoking principal; the granted call no longer reaches the owner's REST vendor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn granted_reserved_principal_invokes_the_owners_rest_connection_through_the_facade() {
    let stub = StubRestServer::start(
        vec![StubRestRoute::new(
            "GET",
            "/v1/items/{item_id}",
            200,
            json!({"served": true}),
        )],
        None,
    )
    .expect("start REST stub");
    // The macOS clock ticks in microseconds, so the counter prevents same-tick test nonce collisions.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let unique = format!(
        "{nonce}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let path = Scratch::database("module-cross-principal");
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: MODULE_ID.to_string(),
            storage_namespace: format!("cross-principal-{unique}"),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        })
        .expect("open facade test store"),
    );
    let manifest = ingest_value(json!({
        "schema_version": 1,
        "key": "facade_rest",
        "name": "Facade REST",
        "description": "cross-principal facade test vendor",
        "reuse_path": "openapi_shim",
        "reuse_rationale": "tests the reviewed REST path",
        "tier": "S1",
        "transport": {"kind": "rest_api", "url": stub.endpoint()},
        "auth": {"mode": "api_key"},
        "credential_bindings": [{
            "ref_role": "api_key",
            "placement": "header",
            "key": "Authorization",
            "prefix": "Bearer ",
            "required": true
        }],
        "resource_filters": {"required": [], "optional": [], "write_enabling": []},
        "actions_baseline": [{
            "name": "get_item",
            "risk": "read",
            "http": {
                "method": "GET",
                "path": "/v1/items/{item_id}",
                "args_schema": {
                    "type": "object",
                    "properties": {"item_id": {"type": "string"}},
                    "required": ["item_id"]
                }
            }
        }],
        "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 30}},
        "availability": "ga"
    }))
    .expect("ingest facade REST manifest");
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest)
        .expect("store facade REST manifest");
    store
        .insert_connection(
            "direct",
            "conn-facade-rest",
            "facade_rest",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("insert owner connection");
    let credential_handle = b"test:facade-rest-credential-handle";
    let ticket = store
        .create_binding_ticket("direct", "conn-facade-rest", credential_handle)
        .expect("create owner binding ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume owner binding ticket")
        .expect("activate owner connection");
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-facade-cross-principal".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-facade-rest".to_string(),
            grantee_principal: "reserved:prefrontal-core".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["get_item".to_string()],
            authority_kind: "invoke".to_string(),
            expires_at: None,
        })
        .expect("grant reserved principal invoke authority");

    let credentials = Arc::new(StubCredentialSource::default());
    credentials.set_success(
        credential_handle,
        b"facade-rest-credential".to_vec(),
        None,
        1,
    );
    let runtime = ModuleRuntime::with_stub_credentials_and_mcp_transport(
        Arc::clone(&store),
        Arc::clone(&credentials),
        Arc::new(McpRemoteTransport::default()),
        Some(stub.endpoint().to_string()),
    );
    runtime
        .reconciler
        .discover_for_connection(
            "direct",
            "conn-facade-rest",
            credentials.as_ref(),
            Some(stub.endpoint()),
        )
        .expect("register owner REST connection and reconcile its action");

    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        72,
        1,
        700,
        serde_json::to_vec(&json!({
            "name": manifest::INVOKE_TOOL,
            "arguments": {
                "op": "call",
                "connection": "conn-facade-rest",
                "action": "get_item",
                "args": {"item_id": "42"}
            }
        }))
        .expect("serialize facade invoke"),
    )
    .expect("build facade invoke frame");
    let (writer, mut responses) = tokio::sync::mpsc::channel(1);
    plexus_module::handle_tool_request_for_test(
        frame,
        &writer,
        runtime,
        Principal::Reserved {
            module_id: "prefrontal-core".to_string(),
        },
    )
    .await
    .expect("invoke through facade");
    let response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "facade response",
    )
    .await;
    let body: Value = serde_json::from_slice(&response.body).expect("facade response JSON");
    assert_eq!(body["result"]["transmission"], "completed", "{body}");
    assert_eq!(body["result"]["response"]["served"], true, "{body}");

    drop(store);
    let _ = fs::remove_file(path);
}

struct LiveDaemonGuard {
    task: Option<JoinHandle<Result<(), subc_daemon::bootstrap::BootstrapError>>>,
    operator_peer: operator_confirmation_peer::ConfirmationPeer,
    connection_file_path: PathBuf,
    // Removed here as well as by the `Scratch` guard's own drop, because
    // `stop()` is also called directly by tests that want the daemon's tree
    // gone before they finish.
    directory: Scratch,
    /// Held for the daemon's lifetime so the next live test cannot start until
    /// this one has torn down.
    _serialized: tokio::sync::MutexGuard<'static, ()>,
}

impl LiveDaemonGuard {
    fn stop(&mut self) {
        if std::thread::panicking() {
            if let Ok(entries) = fs::read_dir(self.directory.join("run-logs")) {
                for entry in entries.flatten() {
                    if let Ok(log) = fs::read_to_string(entry.path()) {
                        eprintln!("{}: {log}", entry.path().display());
                    }
                }
            }
            // The module's stderr capture above is usually empty even when
            // plexus failed: its diagnostics go to its fleet log under the
            // data home this harness gave it, not to stderr.
            for log in fleet_log_files(&self.directory.join("home")) {
                eprintln!(
                    "{} (fleet log, last {FAILURE_DUMP_TAIL_BYTES} bytes): {}",
                    log.display(),
                    file_tail(&log, FAILURE_DUMP_TAIL_BYTES)
                );
            }
            dump_daemon_trace_for(MODULE_ID);
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
        self.operator_peer.stop();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

impl Drop for LiveDaemonGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

/// How much of each fleet log a failing live-daemon test prints. The end of
/// the file is where a startup refusal or the last thing the module did sits.
const FAILURE_DUMP_TAIL_BYTES: u64 = 64 * 1024;

/// Every `*.log` file directly inside a directory named `logs`, anywhere under
/// `home`. The harness points each supervised module's `HOME` and
/// `XDG_DATA_HOME` into `home`, so plexus's own log file
/// (`<home>/.local/share/cortexkit/plexus/logs/plexus.<date>.log`) is among
/// them. Searching rather than building that path keeps the dump working if
/// the logging crate changes its layout.
fn fleet_log_files(home: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![home.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file()
                && path.extension().is_some_and(|extension| extension == "log")
                && directory.file_name().is_some_and(|name| name == "logs")
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The last `limit` bytes of `path`, lossily decoded, or why it could not be
/// read.
fn file_tail(path: &Path, limit: u64) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let read = || -> std::io::Result<String> {
        let mut file = fs::File::open(path)?;
        let length = file.metadata()?.len();
        file.seek(SeekFrom::Start(length.saturating_sub(limit)))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    };
    read().unwrap_or_else(|error| format!("<unreadable: {error}>"))
}

/// Everything the in-process daemon has logged since the current live daemon
/// started, kept so a failing test can print the lines about one module next
/// to that module's own logs. Live daemons run one at a time (`LIVE_DAEMON`),
/// and each start clears this, so it holds one daemon's lines.
static DAEMON_TRACE: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

/// Stop recording daemon lines past this size rather than grow without bound
/// during a long test. A failure worth reading shows up well before it.
const DAEMON_TRACE_LIMIT_BYTES: usize = 8 * 1024 * 1024;

/// A writer that appends each daemon log line to [`DAEMON_TRACE`]. The
/// subscriber writes every line both here and to the test's normal output.
struct DaemonTraceRecorder;

impl std::io::Write for DaemonTraceRecorder {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut trace = DAEMON_TRACE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if trace.len() < DAEMON_TRACE_LIMIT_BYTES {
            trace.push_str(&String::from_utf8_lossy(bytes));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn clear_daemon_trace() {
    DAEMON_TRACE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

/// Print the recorded daemon lines that mention `module_id` (its spawn, its
/// HELLO and any refusal, its exit), the last 200 of them.
fn dump_daemon_trace_for(module_id: &str) {
    let trace = DAEMON_TRACE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let lines: Vec<&str> = trace
        .lines()
        .filter(|line| line.contains(module_id))
        .collect();
    let shown = &lines[lines.len().saturating_sub(200)..];
    eprintln!(
        "daemon tracing lines mentioning {module_id:?} ({} of {}):\n{}",
        shown.len(),
        lines.len(),
        shown.join("\n")
    );
}

/// Serializes the live-daemon tests.
///
/// Route the in-process daemon's `tracing` output to captured test stderr.
///
/// The daemon runs on a tokio task inside the test process and logs through
/// `tracing`, which DISCARDS every event when no subscriber is installed. So a
/// test that fails during a daemon interaction shows the client-side error and
/// nothing about what the daemon did — which is exactly one string, and the
/// daemon has more than one code path that emits it. A bind-relay failure here
/// reported "connection closed during route.bind relay", and subc has two
/// producers for that text: one where the connection genuinely went away, and
/// one where a module re-registered and the old endpoint's pending relays were
/// drained under the same message. The client side cannot tell them apart.
///
/// Installing the subscriber is what makes the next occurrence diagnosable
/// instead of a second observation of the same ambiguity.
///
/// Global and once-only by construction: `try_init` returns Err when a
/// subscriber is already set, which is the normal case for every test after the
/// first, so the result is deliberately ignored rather than unwrapped.
///
/// The default filter names the crate the daemon's events come from, and that
/// name is DERIVED from the bootstrap this harness actually calls, not written
/// out. It used to be the literal `subc_core=debug`. When the bootstrap moved to
/// its own crate, its events started carrying the `subc_daemon` target, the
/// literal selected nothing, and the harness went silent while every test
/// stayed green: an unrestricted filter shows hundreds of daemon lines, all
/// `subc_daemon`, and the old literal selected none of them.
fn install_daemon_tracing() {
    use tracing_subscriber::fmt::writer::MakeWriterExt;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(daemon_log_directive())),
        )
        // Each line also goes into `DAEMON_TRACE`, from which a failing
        // live-daemon test prints the lines about plexus beside plexus's own
        // logs (see `LiveDaemonGuard::stop`).
        .with_writer(tracing_subscriber::fmt::TestWriter::new().and(|| DaemonTraceRecorder))
        .try_init();
}

/// `<crate of the bootstrap this harness spawns>=debug`.
fn daemon_log_directive() -> String {
    let path = std::any::type_name_of_val(&subc_daemon::bootstrap::run_with_config);
    let crate_name = path.split("::").next().unwrap_or(path);
    format!("{crate_name}=debug")
}

/// Each of these boots a real subc daemon AND has it spawn a supervised
/// ck-plexus process. Run concurrently they contend for the machine, and the
/// symptom is not a clean timeout: the daemon closes a client connection
/// mid-request, so the test fails at `daemon connection remains open` and reads
/// like a module defect rather than harness contention. Nothing here tests two
/// daemons at once, so the contention is pure artifact.
///
/// `tokio::sync::Mutex` rather than `std::sync::Mutex`, deliberately: a std
/// guard held across an `.await` blocks the worker thread it runs on, and these
/// tests have only two, so serializing with a std mutex made failures MORE
/// frequent rather than fewer. An async-aware lock parks the waiting task
/// instead of its thread.
static LIVE_DAEMON: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Only these manifests are needed by this file: Exa verifies that a newly
/// installed manifest is discoverable, and Linear exercises the operator-facing
/// setup flow. Keeping the fixture narrow prevents unrelated shipped-catalog
/// changes from slowing or breaking this wire-conformance suite.
fn conformance_catalog_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/catalog")
}

fn shipped_catalog_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog")
}

async fn start_live_daemon() -> (LiveDaemonGuard, subc_transport::ConnectionInfo) {
    start_live_daemon_with_catalog(conformance_catalog_dir()).await
}

async fn start_live_daemon_with_catalog(
    catalog: PathBuf,
) -> (LiveDaemonGuard, subc_transport::ConnectionInfo) {
    start_live_daemon_with(catalog, NonceHandoff::DescriptorAndEnvironment).await
}

/// How the supervised modules receive their launch nonce.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NonceHandoff {
    /// As the daemon hands it over today: the pipe on descriptor 3 named by
    /// `SUBC_LAUNCH_NONCE_FD`, plus the `SUBC_LAUNCH_NONCE` environment copy.
    DescriptorAndEnvironment,
    /// The pipe only. Each module is launched through a shell that unsets the
    /// environment copy and then execs the module, which keeps descriptor 3.
    /// This is what a module sees once the daemon stops setting the copy.
    DescriptorOnly,
}

/// How long the harness waits for the in-process daemon to publish its
/// connection file after it is spawned.
///
/// Spawn-to-file usually takes milliseconds, but its tail is long: the daemon
/// writes the file with `write_atomic`, which fsyncs it, and on a busy disk
/// that can take a second or more, while the readiness probe before it stays
/// fast. A 5 s bound proved too tight on rare starts. 30 s leaves a wide
/// margin over the slowest starts seen in ordinary runs. A daemon that gives
/// up on startup is reported at once from its
/// task's result (see `start_live_daemon_with`), so this bound only fires for
/// a daemon that never publishes.
const DAEMON_PUBLISH_BOUND: Duration = Duration::from_secs(30);

async fn start_live_daemon_with(
    catalog: PathBuf,
    nonce_handoff: NonceHandoff,
) -> (LiveDaemonGuard, subc_transport::ConnectionInfo) {
    let serialized = LIVE_DAEMON.lock().await;
    // A wall-clock nonce alone is not unique enough. These tests run in
    // parallel, and two that start within the same clock tick derive the SAME
    // directory, so one writes subc.jsonc while the other reads it half-written
    // and fails with an EOF parse error that looks like a module defect rather
    // than a harness collision. `Scratch` makes the path unique by construction
    // instead of by timing luck.
    let directory = Scratch::directory("conformance-daemon");
    let home = directory.join("home");
    fs::create_dir_all(&home).expect("create isolated data home");
    let connection_file_path = directory.join("subc-connection.json");
    let confirmation_file = directory.join("confirmation-peer.json");
    let confirmation_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let binary = ckdev_binary(
        std::env::var_os("CARGO_BIN_EXE_ck-plexus")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/ck-plexus")
            }),
    );
    assert_eq!(
        binary.file_name().and_then(|name| name.to_str()),
        Some("ckdev-plexus")
    );
    let binary_path = binary;
    // The supervisor appends module CLI flags; the Rust test runner does not
    // accept those flags, so this wrapper selects only the vault fixture test.
    let vault_launcher = directory.join("vault-fixture.sh");
    let test_binary = std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .replace('\'', "'\\\"'\\\"'");
    // Empty, or the line that removes the environment copy of the nonce
    // before a launcher execs its module.
    let unset_nonce = match nonce_handoff {
        NonceHandoff::DescriptorAndEnvironment => "",
        NonceHandoff::DescriptorOnly => "unset SUBC_LAUNCH_NONCE\n",
    };
    fs::write(
        &vault_launcher,
        format!("{unset_nonce}exec '{test_binary}' --exact vault_route_fixture --nocapture\n"),
    )
    .unwrap();
    let entorhinal_launcher = directory.join("entorhinal-fixture.sh");
    fs::write(
        &entorhinal_launcher,
        format!("{unset_nonce}exec '{test_binary}' --exact vault_route_fixture --nocapture\n"),
    )
    .unwrap();
    // Only the module's supervisor connection uses the fake confirmation peer.
    // The daemon publishes its key before this harness can publish the peer's
    // connection file, so the launcher waits with a bounded startup deadline.
    let launcher = directory.join("plexus-confirmation-peer.sh");
    let quoted_binary = binary_path.to_string_lossy().replace('\'', "'\\\"'\\\"'");
    let quoted_connection = confirmation_file
        .to_string_lossy()
        .replace('\'', "'\\\"'\\\"'");
    fs::write(&launcher, format!("{unset_nonce}attempts=0\nwhile [ ! -f '{quoted_connection}' ]; do\n  attempts=$((attempts + 1))\n  [ \"$attempts\" -lt 3000 ] || exit 1\n  sleep 0.01\ndone\nexec '{quoted_binary}' --subc '{quoted_connection}'\n")).unwrap();
    let plexus_program = PathBuf::from("/bin/sh");
    let plexus_args = json!([launcher]);
    let daemon_config_path = directory.join("subc.jsonc");
    fs::write(
        &daemon_config_path,
        serde_json::to_vec(&json!({
            "version": 1,
            "storage": {"backend": "sqlite", "data_home": home},
            "modules": {
                MODULE_ID: {
                    "program": plexus_program,
                    "args": plexus_args,
                    // XDG_DATA_HOME as well as HOME: the module resolves its
                    // store from the data home, and an inherited
                    // XDG_DATA_HOME would otherwise point it at the
                    // operator's live store.
                    "env": {
                        "HOME": home,
                        "XDG_DATA_HOME": home.join(".local/share"),
                        "PLEXUS_CATALOG_DIR": catalog,
                        "PLEXUS_CKCRED_MODULE_ID": "test-vault"
                    },
                    "reserved": true
                },
                "entorhinal": {
                    "program": "/bin/sh",
                    "args": [entorhinal_launcher],
                    "env": {"TEST_VAULT_CONNECTION": connection_file_path, "TEST_ROLE_SERVICE": "1"},
                    "reserved": true
                },
                "test-vault": {
                    "program": "/bin/sh",
                    "args": [vault_launcher],
                    "env": {"TEST_VAULT_CONNECTION": connection_file_path},
                    "reserved": true
                }
            }
        }))
        .expect("serialize daemon config"),
    )
    .expect("write daemon config");

    // SEE ALSO `install_daemon_tracing`: this captures the MODULE's stderr, while
    // the daemon we spawn in-process logs through `tracing` and needs a
    // subscriber to be heard at all.
    //
    // Child stderr capture resolves from the environment unless a directory is
    // named, so an unfenced harness writes `plexus.stderr.log` into the
    // operator's live run directory. Everything else here is already isolated
    // into the fixture tree; this was the one dimension subc did not expose a
    // knob for until 0.17.49, and 245 KB of real frame logs reached the live
    // data home before it did.
    let capture_logs = directory.join("run-logs");
    fs::create_dir_all(&capture_logs).expect("create capture log dir");
    install_daemon_tracing();
    // `LIVE_DAEMON` (held since the top of this function) lets only one live
    // daemon run at a time, so the lines recorded from here on are all from
    // the daemon this call starts.
    clear_daemon_trace();
    let daemon_config = subc_daemon::bootstrap::BootstrapConfig::new(&connection_file_path, 0)
        .with_capture_logs_dir(&capture_logs)
        .with_daemon_config_path(&daemon_config_path)
        .expect("load daemon config");
    let spawned = std::time::Instant::now();
    let mut task = tokio::spawn(subc_daemon::bootstrap::run_with_config(daemon_config));
    let publish_deadline = spawned + DAEMON_PUBLISH_BOUND;
    let connection = loop {
        if let Ok(connection) = connection_file::read(&connection_file_path) {
            break connection;
        }
        // A daemon that gives up on startup returns a typed error and never
        // publishes; report that error rather than waiting out the bound.
        if task.is_finished() {
            let result = (&mut task).await;
            panic!("the daemon stopped before publishing its connection file: {result:?}");
        }
        assert!(
            std::time::Instant::now() < publish_deadline,
            "daemon did not publish its connection file within {DAEMON_PUBLISH_BOUND:?}"
        );
        sleep(Duration::from_millis(10)).await;
    };
    eprintln!(
        "daemon published its connection file {:?} after it was spawned",
        spawned.elapsed()
    );
    let mut peer_connection = connection.clone();
    peer_connection.endpoints = vec![subc_transport::Endpoint {
        host: "127.0.0.1".to_string(),
        port: confirmation_listener.local_addr().unwrap().port(),
    }];
    let operator_peer = operator_confirmation_peer::ConfirmationPeer::spawn(
        confirmation_listener,
        connection.clone(),
    );
    connection_file::write_atomic(&confirmation_file, &peer_connection)
        .expect("publish fake confirmation peer");
    (
        LiveDaemonGuard {
            task: Some(task),
            operator_peer,
            connection_file_path,
            directory,
            _serialized: serialized,
        },
        connection,
    )
}

async fn connect_client(connection: &subc_transport::ConnectionInfo) -> TcpStream {
    let endpoint = connection.endpoints.first().expect("daemon endpoint");
    let mut stream = TcpStream::connect(format!("{}:{}", endpoint.host, endpoint.port))
        .await
        .expect("connect daemon");
    authenticate_client(&mut stream, connection, Duration::from_secs(5))
        .await
        .expect("authenticate daemon client");
    stream
}

async fn send_control_request(
    stream: &mut TcpStream,
    correlation: u64,
    request: ClientControlRequest,
) -> Frame {
    send_control_request_within(stream, correlation, request, Duration::from_secs(5)).await
}

/// [`send_control_request`] with its own answer deadline. A missed deadline
/// names the request, because the same panic line otherwise covers every
/// control request a test sends.
async fn send_control_request_within(
    stream: &mut TcpStream,
    correlation: u64,
    request: ClientControlRequest,
    deadline: Duration,
) -> Frame {
    let mut label = format!("{request:?}");
    label.truncate(160);
    let frame = Frame::build(
        FrameType::Request,
        plexus_module::wire::control_flags(),
        0,
        0,
        correlation,
        serde_json::to_vec(&request).expect("serialize control request"),
    )
    .expect("build control request");
    write_frame(stream, &frame)
        .await
        .expect("write control request");
    timeout(deadline, read_frame(stream))
        .await
        .unwrap_or_else(|_| {
            panic!("control response deadline: no answer within {deadline:?} to {label}")
        })
        .expect("read control response")
        .expect("daemon connection remains open")
}

/// The fixture modules every live daemon starts beside plexus, and that plexus
/// calls: `entorhinal` answers its connector-home role reads and `test-vault` its
/// credential reads.
const FIXTURE_MODULE_IDS: [&str; 2] = ["entorhinal", "test-vault"];

/// Wait until plexus is registered AND serving, and the fixture modules it
/// calls are registered. Returns plexus's `catalog.list` entry.
///
/// Being listed in `catalog.list` does not mean a module can serve a route yet,
/// for two reasons, both seen failing these tests on Linux under load:
///
/// - Plexus sends HELLO first, and only then opens its store, ingests its
///   catalog and builds its runtime before it starts reading frames. The
///   daemon lists it from HELLO on, so a route.open sent in that gap waits
///   until plexus reads the route.bind. With the shipped catalog under load the
///   gap outlasted the next request's 5 s deadline: "control response
///   deadline: no answer within 5s to RouteOpen".
/// - The daemon adds a module to the catalog a moment before it installs the
///   connection that forwards to it. A route.open in that gap is refused:
///   "module_id 'plexus' has no live forwarding connection".
///
/// An answered `supervisor.health_probe` rules out both. The daemon sends the
/// probe over the same forwarding connection a route.bind uses, and plexus
/// answers it from the same loop that reads route.bind. Before then the daemon
/// answers `target_unavailable` (no forwarding connection yet) or
/// `module_timeout` (plexus did not answer the probe within the daemon's own
/// 5 s probe timeout), and this asks again.
///
/// The bound is ELAPSED TIME, not a poll count: a poll-count bound silently
/// becomes a shorter wall-clock deadline whenever the machine is busy, because
/// each round trip takes longer AND the fixed sleep no longer dominates. That
/// made this fail under parallel load while passing on an idle machine — the
/// shape that reads as "green because the laptop was fast today" and then
/// flakes on a loaded CI runner. The ceiling is deliberately generous: it is
/// there to catch a module that will NEVER come up, so being slow to fire
/// costs nothing, while being tight costs false failures.
async fn wait_for_module_catalog(stream: &mut TcpStream) -> ClientControlResponse {
    let started = std::time::Instant::now();
    let deadline = started + Duration::from_secs(60);
    let mut correlation = 10;
    let mut plexus_entry = None;
    for module_id in std::iter::once(MODULE_ID).chain(FIXTURE_MODULE_IDS) {
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "{module_id} did not register within 60s: the module is not coming up"
            );
            correlation += 1;
            let frame = send_control_request(
                stream,
                correlation,
                ClientControlRequest::CatalogList {
                    module_id: Some(module_id.to_string()),
                },
            )
            .await;
            assert_eq!(frame.header.ty, FrameType::Response);
            let response: ClientControlResponse =
                serde_json::from_slice(&frame.body).expect("catalog response");
            if let ClientControlResponse::CatalogList { modules, .. } = &response {
                if modules.iter().any(|module| module.module_id == module_id) {
                    if module_id == MODULE_ID {
                        plexus_entry = Some(response);
                    }
                    break;
                }
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
    let listed_after = started.elapsed();

    loop {
        let now = std::time::Instant::now();
        assert!(
            now < deadline,
            "plexus registered but did not answer a health probe within 60s"
        );
        correlation += 1;
        // Wait as long as the overall bound allows rather than the usual 5 s:
        // the daemon itself answers within its own 5 s probe limit, and giving
        // up early would leave its late answer unread on this connection.
        let frame = send_control_request_within(
            stream,
            correlation,
            ClientControlRequest::SupervisorHealthProbe {
                module_id: MODULE_ID.to_string(),
            },
            deadline - now,
        )
        .await;
        if frame.header.ty == FrameType::Response {
            let response: ClientControlResponse =
                serde_json::from_slice(&frame.body).expect("health probe response");
            assert!(
                matches!(
                    response,
                    ClientControlResponse::SupervisorHealthProbe { .. }
                ),
                "expected a health probe response, got {response:?}"
            );
            eprintln!(
                "plexus and its fixtures listed after {listed_after:?}; plexus answered a health probe after {:?}",
                started.elapsed()
            );
            return plexus_entry.expect("plexus was listed above");
        }
        let refusal: Value = serde_json::from_slice(&frame.body).expect("health probe refusal");
        assert!(
            matches!(
                refusal["code"].as_str(),
                Some("target_unavailable" | "module_timeout")
            ),
            "health probe refused for a reason waiting will not fix: {refusal}"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

async fn open_live_route(stream: &mut TcpStream) -> (u16, u32) {
    // Establish the fixture's held connector-home claim first. Until a read
    // confirms it, every vendor-facing tool is refused as connector_home_not_held
    // before its arguments are even validated.
    let _ = open_management_route(stream).await;
    let frame = send_control_request(
        stream,
        15,
        ClientControlRequest::RouteOpen {
            scope: None,
            role_versions: None,
            target: RouteTarget::ToolProvider {
                module_id: MODULE_ID.to_string(),
            },
            identity: BindIdentity::new(
                "/tmp",
                "conformance".to_string(),
                "live-session".to_string(),
            ),
            consumer_identity: None,
            consumer_capabilities: None,
            admission_facts: None,
        },
    )
    .await;
    assert_eq!(
        frame.header.ty,
        FrameType::Response,
        "route open failed: {}",
        String::from_utf8_lossy(&frame.body)
    );
    match serde_json::from_slice::<ClientControlResponse>(&frame.body).expect("route open response")
    {
        ClientControlResponse::RouteOpen {
            route_channel,
            route_epoch,
        } => (route_channel, route_epoch),
        response => panic!("expected route open response, got {response:?}"),
    }
}

/// Open a route to the PRIVILEGED surface. A ToolProvider target would be
/// refused for these ops by the daemon's role match, which is the structural
/// separation the ceremony relies on.
async fn open_management_route(stream: &mut TcpStream) -> (u16, u32) {
    let frame = send_control_request(
        stream,
        16,
        ClientControlRequest::RouteOpen {
            scope: None,
            role_versions: None,
            target: RouteTarget::ManagementSurface {
                module_id: MODULE_ID.to_string(),
            },
            identity: BindIdentity::new(
                "/tmp",
                "conformance".to_string(),
                "live-session".to_string(),
            ),
            consumer_identity: None,
            consumer_capabilities: None,
            admission_facts: None,
        },
    )
    .await;
    assert_eq!(
        frame.header.ty,
        FrameType::Response,
        "management route open failed: {}",
        String::from_utf8_lossy(&frame.body)
    );
    let route = match serde_json::from_slice::<ClientControlResponse>(&frame.body)
        .expect("management route open response")
    {
        ClientControlResponse::RouteOpen {
            route_channel,
            route_epoch,
        } => (route_channel, route_epoch),
        response => panic!("expected route open response, got {response:?}"),
    };
    wait_for_connector_home_held(stream, route).await;
    route
}

/// Wait until plexus reports the fixture's connector-home claim as held, over
/// an open management `route`.
///
/// Plexus refuses every connector effect (a vendor call, a ticket, a consent
/// card) as `connector_home_not_held` until a successful `role.read` from
/// entorhinal says this machine holds the role, and it starts every boot
/// `unknown`. Its own first read runs on a background task at startup, so a
/// test that issues an effect straight after plexus registers races that
/// read: on a Linux CI runner a ticket was refused 7 ms before the read
/// landed. Every live test that issues an effect must therefore come through
/// here first (`open_management_route` and `open_live_route` do).
///
/// The status operation performs a fresh read each time it is asked, so this
/// does not wait for plexus's 30 s background reader. A read that cannot reach
/// entorhinal leaves the state `unknown`, which is worth asking again; `not_held`
/// is a real answer the fixture never gives, so it fails at once. The bound is
/// elapsed time, for the reasons given on `wait_for_module_catalog`.
async fn wait_for_connector_home_held(stream: &mut TcpStream, route: (u16, u32)) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut correlation = 17;
    loop {
        let now = std::time::Instant::now();
        // The role reader reconnects to Entorhinal on each request, then has a
        // 3 s call timeout. Allow the rest of the overall bound rather than
        // 5 s so a late status reply cannot remain unread on this connection.
        let status = send_management_request_within(
            stream,
            route,
            correlation,
            plexus_module::connector_home::STATUS_OP,
            json!({}),
            deadline.saturating_duration_since(now),
        )
        .await;
        let value: Value = serde_json::from_slice(&status.body).expect("connector-home status");
        // A failed read puts the local connectorHome gate beside the error;
        // a successful read nests the gate and raw role reply inside result.
        let state = if value["result"].is_null() {
            &value["connectorHome"]["state"]
        } else {
            &value["result"]["connectorHome"]["state"]
        };
        match state.as_str() {
            Some("held") => return,
            Some("unknown") => {}
            _ => panic!("plexus reported the connector-home claim not held: {value}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "plexus did not report the connector-home claim held within 60s; last status: {value}"
        );
        correlation += 1;
        sleep(Duration::from_millis(10)).await;
    }
}

async fn send_management_request(
    stream: &mut TcpStream,
    route: (u16, u32),
    correlation: u64,
    method: &str,
    params: Value,
) -> Frame {
    send_management_request_within(
        stream,
        route,
        correlation,
        method,
        params,
        Duration::from_secs(5),
    )
    .await
}

/// [`send_management_request`] with its own answer deadline.
async fn send_management_request_within(
    stream: &mut TcpStream,
    (channel, epoch): (u16, u32),
    correlation: u64,
    method: &str,
    params: Value,
    deadline: Duration,
) -> Frame {
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        correlation,
        serde_json::to_vec(&json!({"method": method, "params": params}))
            .expect("serialize management request"),
    )
    .expect("build management request");
    write_frame(stream, &frame)
        .await
        .expect("write management request");
    timeout(deadline, read_frame(stream))
        .await
        .unwrap_or_else(|_| {
            panic!("management response deadline: no answer within {deadline:?} to {method}")
        })
        .expect("read management response")
        .expect("daemon connection remains open")
}

async fn send_tool_request(
    stream: &mut TcpStream,
    (channel, epoch): (u16, u32),
    correlation: u64,
    name: &str,
    arguments: Value,
) -> Frame {
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        correlation,
        serde_json::to_vec(&json!({"name": name, "arguments": arguments}))
            .expect("serialize tool request"),
    )
    .expect("build tool request");
    write_frame(stream, &frame)
        .await
        .expect("write tool request");
    timeout(Duration::from_secs(5), read_frame(stream))
        .await
        .expect("tool response deadline")
        .expect("read tool response")
        .expect("daemon connection remains open")
}

/// Every operation the HELLO manifest advertises must reach a dispatch arm.
///
/// Credential material in a tool argument must be REFUSED AT THE FACADE, and
/// the refusal must happen before the argument reaches anything that acts on
/// it.
///
/// The unit tests for `contains_secret_input` fence the DECISION: given a map
/// containing a handle, the predicate answers true. They say nothing about
/// whether any caller consults it. That gap is not hypothetical — neutering the
/// call site (`if false && contains_secret_input(..)`) leaves the entire
/// workspace suite green, because a predicate can be perfectly tested and never
/// invoked. A guard is only a guard where it is CALLED.
///
/// This asserts over the wire, at the surface an agent actually reaches, and it
/// asserts the two things separately:
///
/// 1. the call is refused with `secret_input_rejected`, which fails if the
///    enforcement is removed or moved after dispatch; and
/// 2. the secret bytes do not appear ANYWHERE in the response, which is the
///    property the guard exists for. A guard whose job is to prevent something
///    should be tested by asserting the thing does not happen, rather than by
///    asserting an error came back — an error can be returned while the secret
///    is still echoed in a message, logged, or reflected in a detail field.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_material_in_a_tool_argument_is_refused_at_the_facade() {
    let (mut daemon, connection) = start_live_daemon().await;
    let mut client = connect_client(&connection).await;
    wait_for_module_catalog(&mut client).await;
    let route = open_live_route(&mut client).await;

    // A distinctive value so its presence anywhere in the response is
    // unambiguous rather than a coincidental substring.
    const SECRET: &str = "ckh_conformance_canary_9f3a2b71";

    // Each vector places the handle where a caller might plausibly put it:
    // top level, nested one level down, and inside an array. The nested cases
    // matter because a top-level-only guard is bypassed by wrapping.
    let vectors = [
        json!({"op": "connect", "handle": SECRET}),
        json!({"op": "connect", "binding": {"credential": SECRET}}),
        json!({"op": "connect", "items": [{"token": SECRET}]}),
        json!({"op": "subscribe", "fixed_args": {"credential_handle": SECRET}}),
    ];

    let before = send_tool_request(
        &mut client,
        route,
        959,
        manifest::CONNECTIONS_TOOL,
        json!({"op": "list"}),
    )
    .await;
    let mut correlation = 960;
    for arguments in vectors {
        correlation += 1;
        let frame = send_tool_request(
            &mut client,
            route,
            correlation,
            manifest::CONNECTIONS_TOOL,
            arguments.clone(),
        )
        .await;

        let body: Value = serde_json::from_slice(&frame.body).expect("tool response");
        assert_eq!(
            body["error"]["code"],
            if arguments.get("op") == Some(&json!("connect")) && arguments.get("handle").is_some() {
                "handle_bindings_removed"
            } else {
                "secret_input_rejected"
            },
            "credential material must be refused at the facade, got {body} for {arguments}"
        );

        let raw = String::from_utf8_lossy(&frame.body);
        assert!(
            !raw.contains(SECRET),
            "the response echoed the credential back to the caller: {raw}"
        );
    }

    let after = send_tool_request(
        &mut client,
        route,
        969,
        manifest::CONNECTIONS_TOOL,
        json!({"op": "list"}),
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&before.body).unwrap(),
        serde_json::from_slice::<Value>(&after.body).unwrap(),
        "refused handles must not write connection rows"
    );

    drop(client);
    daemon.stop();
}

/// A validation error must report EVERY missing field it already knows about,
/// not the first one it happens to check.
///
/// This is not cosmetic. A caller who omits two fields and is told about one
/// corrects it, retries, and hits a refusal that is indistinguishable from the
/// previous one — so they cannot tell whether their correction made progress.
/// The validator held both failures at the moment it refused, so disclosing one
/// throws away information it had already computed, and charges the caller a
/// round trip to rediscover it. It costs most for callers with no access to
/// this source, which is every agent reaching the module through the facade.
///
/// The concrete case: an operator called invoke with `connection_id` and
/// `arguments` — the names anyone would reach for — and learned one wrong name
/// per attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_validation_error_reports_every_missing_field_at_once() {
    let (mut daemon, connection) = start_live_daemon().await;
    let mut client = connect_client(&connection).await;
    wait_for_module_catalog(&mut client).await;
    let route = open_live_route(&mut client).await;

    // Both required fields absent, using the names an operator naturally
    // reaches for rather than the ones the surface takes.
    let frame = send_tool_request(
        &mut client,
        route,
        980,
        manifest::INVOKE_TOOL,
        json!({"op": "call", "connection_id": "conn-exa", "arguments": {}}),
    )
    .await;
    let body: Value = serde_json::from_slice(&frame.body).expect("tool response");

    let missing = body["error"]["missing"]
        .as_array()
        .expect("error names the missing fields");
    assert_eq!(
        missing.len(),
        2,
        "both missing fields must be reported in one refusal, got {body}"
    );
    assert!(
        missing.iter().any(|value| value == "connection")
            && missing.iter().any(|value| value == "action"),
        "refusal must name connection and action, got {body}"
    );

    // Correcting only one field must produce a DIFFERENT refusal, so the
    // caller can tell they made progress.
    let frame = send_tool_request(
        &mut client,
        route,
        981,
        manifest::INVOKE_TOOL,
        json!({"op": "call", "connection": "conn-exa"}),
    )
    .await;
    let body: Value = serde_json::from_slice(&frame.body).expect("tool response");
    let missing = body["error"]["missing"]
        .as_array()
        .expect("error names the missing fields");
    assert_eq!(
        missing.len(),
        1,
        "a partially corrected call must narrow the refusal, got {body}"
    );
    assert_eq!(missing[0], "action", "got {body}");

    drop(client);
    daemon.stop();
}

/// A malformed fixed_args value is reported together with every missing
/// subscription field, so an agent can correct the whole request in one retry.
///
/// Mutation proved: removing the fixed_args shape check makes `invalid` empty
/// and fails the assertion while the missing-field validator still passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_fixed_args_is_reported_with_all_missing_subscription_fields() {
    let (mut daemon, connection) = start_live_daemon().await;
    let mut client = connect_client(&connection).await;
    wait_for_module_catalog(&mut client).await;
    let route = open_live_route(&mut client).await;

    let frame = send_tool_request(
        &mut client,
        route,
        982,
        manifest::EVENTS_TOOL,
        json!({"op": "subscribe", "fixed_args": ["not", "an", "object"]}),
    )
    .await;
    let body: Value = serde_json::from_slice(&frame.body).expect("tool response");
    assert_eq!(body["error"]["code"], "invalid_request");
    let missing = body["error"]["missing"]
        .as_array()
        .expect("missing fields are reported");
    assert_eq!(
        missing.len(),
        3,
        "connection, action, and cadence must be listed"
    );
    assert_eq!(body["error"]["invalid"][0], "fixed_args");
    assert_eq!(body["error"]["example"]["fixed_args"], json!({}));

    drop(client);
    daemon.stop();
}

/// The failure this closes is not a crash: a tool advertises an op, the agent
/// reads the manifest and calls it, and the module answers `invalid_operation`
/// because no match arm was ever written for it. Nothing errors at boot,
/// nothing errors in CI, and the capability is simply absent — which is how
/// `plexus.connections op=configure` shipped advertised-but-unhandled, leaving
/// every write permanently unreachable.
///
/// Fixture coverage cannot close this, because a fixture only exercises the
/// ops it happens to use. This asserts TOTALITY over the advertised surface,
/// so a new op cannot be added to the manifest without a dispatch arm.
///
/// The probe deliberately sends only `{"op": ...}` with no other arguments.
/// A registered arm rejects that with `invalid_request` (naming what it
/// needs) or acts; an unregistered one falls through to `invalid_operation`.
/// Distinguishing those two is the whole test, so it needs no connection,
/// no credential, and no vendor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_advertised_operation_reaches_a_dispatch_arm() {
    let (mut daemon, connection) = start_live_daemon().await;
    let mut client = connect_client(&connection).await;
    let catalog = wait_for_module_catalog(&mut client).await;
    let ClientControlResponse::CatalogList { modules, .. } = catalog else {
        panic!("expected catalog.list response");
    };
    let entry = modules
        .iter()
        .find(|module| module.module_id == MODULE_ID)
        .expect("plexus must register");
    let ProviderRole::ToolProvider { tools, .. } = entry
        .roles
        .iter()
        .find(|role| matches!(role, ProviderRole::ToolProvider { .. }))
        .expect("plexus must expose a tool provider role")
    else {
        unreachable!("filtered to ToolProvider above");
    };

    // Read the advertised op list out of the manifest the daemon actually
    // received, rather than from our own source, so the test tracks what a
    // consumer would see.
    let advertised: Vec<(String, String)> = tools
        .iter()
        .flat_map(|tool| {
            tool.schema["properties"]["op"]["enum"]
                .as_array()
                .map(|ops| {
                    ops.iter()
                        .filter_map(|op| op.as_str())
                        .map(|op| (tool.name.clone(), op.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .collect();
    assert!(
        advertised.len() >= 10,
        "expected the full facade surface, got {advertised:?}"
    );

    let route = open_live_route(&mut client).await;
    let mut correlation = 900;
    let mut unhandled = Vec::new();
    for (tool, op) in &advertised {
        correlation += 1;
        let frame =
            send_tool_request(&mut client, route, correlation, tool, json!({"op": op})).await;
        let body: Value = serde_json::from_slice(&frame.body).expect("tool response");
        if body["error"]["code"] == "invalid_operation" {
            unhandled.push(format!("{tool} op={op}"));
        }
    }
    assert!(
        unhandled.is_empty(),
        "these operations are advertised in the manifest but have no dispatch arm: {unhandled:?}"
    );

    drop(client);
    daemon.stop();
}

/// Every shipped manifest must admit the ticket shape selected by the shipped
/// operator CLI. Reaching a ticket result is the ceremony boundary: it proves
/// catalog discovery, manifest-derived credential handling, and the privileged
/// wire request without connecting to a vendor or making an external request.
///
/// The manifest list is discovered from `catalog/`, not copied into this test.
/// A future vendor therefore joins this proof merely by being shipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_shipped_manifest_is_reachable_through_the_operator_ceremony() {
    let catalog_directory = shipped_catalog_dir();
    let paths = catalog_manifests(&catalog_directory)
        .expect("the shipped catalog directory must be readable");
    assert!(
        paths.len() >= 10,
        "expected the full shipped catalog, found only {} manifest(s)",
        paths.len()
    );

    let (mut daemon, connection) = start_live_daemon_with_catalog(catalog_directory).await;
    let mut client = connect_client(&connection).await;
    wait_for_module_catalog(&mut client).await;
    // Ticket issuance is refused until a read confirms the connector-home
    // claim. Opening the management route waits until a read confirms it, so
    // the first ticket below can't race plexus's startup read.
    open_management_route(&mut client).await;
    drop(client);

    let admin_binary = ckdev_binary(
        std::env::var_os("CARGO_BIN_EXE_ck-plexus-admin")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/ck-plexus-admin")
            }),
    );
    assert_eq!(
        admin_binary.file_name().and_then(|name| name.to_str()),
        Some("ckdev-plexus-admin")
    );
    let mut failures = Vec::new();

    for path in paths {
        let source = fs::read_to_string(&path).expect("read shipped manifest");
        let normalized = subc_jsonc::jsonc_to_json(&source).expect("parse shipped JSONC");
        let value: Value = serde_json::from_str(&normalized).expect("parse shipped JSON");
        let ingested = ingest_value(value).expect("ingest shipped manifest");
        let app_key = ingested.manifest.key;
        // SearXNG permits anonymous enrollment, not the synthetic totality credential.
        let credential_free = matches!(
            ingested.manifest.auth.mode,
            plexus_core::manifest::AuthMode::None | plexus_core::manifest::AuthMode::OptionalApiKey
        );
        let binary = admin_binary.clone();
        let connection_file = daemon.connection_file_path.clone();
        let invoked_app = app_key.clone();
        let output = tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new(binary);
            command
                .arg("issue-ticket")
                .arg("--subc")
                .arg(connection_file)
                .arg("--app")
                .arg(&invoked_app)
                .arg("--actions")
                .arg("*");
            if !credential_free {
                command.arg("--credential-id").arg("test:operator_totality");
            }
            if invoked_app == "searxng_rest" {
                command
                    .arg("--instance-url")
                    .arg("https://searxng-fixture.invalid");
            }
            bounded::child_output(
                &mut command,
                std::time::Duration::from_secs(60),
                "test binary command",
            )
        })
        .await
        .expect("join operator CLI")
        .expect("run operator CLI");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() || !stdout.contains("ticket_id:") {
            failures.push(format!(
                "{app_key} (credential_free={credential_free}): status={} stdout={stdout:?} stderr={stderr:?}",
                output.status
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "operator ceremony could not issue a ticket for every shipped manifest:\n{}",
        failures.join("\n")
    );
    assert!(daemon.operator_peer.approvals() >= 10);
    daemon.stop();
}

/// Plexus reads its launch nonce from the descriptor the daemon hands over,
/// with no `SUBC_LAUNCH_NONCE` in its environment, and both of its readers get
/// it: HELLO, and the subc client's route open to the vault afterwards.
///
/// Each step fails for its own reason. Plexus is configured `reserved`, so the
/// daemon admits its HELLO only with the nonce it spawned it with, and
/// `wait_for_module_catalog` would time out. The vault read happens after HELLO
/// has read the nonce; a reader that consumed the pipe for itself would leave
/// the route open without an identity, and the test vault refuses a read that
/// is not attested as `reserved:plexus`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn descriptor_nonce_reaches_hello_provenance_and_a_later_vault_read() {
    let (mut daemon, connection) =
        start_live_daemon_with(conformance_catalog_dir(), NonceHandoff::DescriptorOnly).await;
    let mut client = connect_client(&connection).await;
    wait_for_module_catalog(&mut client).await;

    // A longer deadline than other control requests, because on Linux this
    // request is slow for a reason in the harness, not in plexus. Every
    // supervisor.provenance answer includes evidence of which executable the
    // daemon itself is running, whatever `module_id` asks for, and on Linux
    // subc-daemon gathers it by computing a SHA-256 of `/proc/<daemon
    // pid>/exe`. This daemon runs inside the test process, so that file is
    // this test binary: a debug build, which on Linux embeds its debug info
    // (macOS leaves it in the object files), hashed by a `sha2` compiled without
    // optimization, on a two-CPU CI runner. That takes longer than the five
    // seconds `send_control_request` allows. On macOS the daemon compares file
    // inode numbers instead and hashes nothing, which is why this passed
    // there. The daemon caches the digest, so only the first such request is
    // slow.
    let frame = send_control_request_within(
        &mut client,
        90,
        ClientControlRequest::SupervisorProvenance {
            module_id: Some(MODULE_ID.to_string()),
        },
        Duration::from_secs(180),
    )
    .await;
    let response: ClientControlResponse =
        serde_json::from_slice(&frame.body).expect("provenance response");
    let ClientControlResponse::SupervisorProvenance { modules, .. } = response else {
        panic!("expected supervisor.provenance, got {response:?}");
    };
    let declared = &modules
        .iter()
        .find(|module| module.module_id == MODULE_ID)
        .expect("plexus provenance")
        .module_declared;
    let subc_control::ModuleDeclaredProvenance::Reported { build } = declared else {
        panic!("plexus must declare its provenance, got {declared:?}");
    };
    assert_eq!(
        build.launch_nonce_source,
        Some(subc_protocol::manifest::LaunchNonceSource::Fd),
        "{build:?}"
    );
    // The ticket below is a connector effect, refused until a read confirms
    // the connector-home claim; opening the management route waits for that.
    open_management_route(&mut client).await;
    drop(client);

    let admin_binary = ckdev_binary(
        std::env::var_os("CARGO_BIN_EXE_ck-plexus-admin")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/ck-plexus-admin")
            }),
    );
    assert_eq!(
        admin_binary.file_name().and_then(|name| name.to_str()),
        Some("ckdev-plexus-admin")
    );
    let binary = admin_binary;
    let connection_file = daemon.connection_file_path.clone();
    // Exa authenticates with an API key, so before issuing its ticket plexus
    // reads the named credential from the vault to prove it exists. That read
    // is a route open from plexus to the test vault.
    let output = tokio::task::spawn_blocking(move || {
        bounded::child_output(
            std::process::Command::new(binary)
                .arg("issue-ticket")
                .arg("--subc")
                .arg(connection_file)
                .arg("--app")
                .arg("exa")
                .arg("--actions")
                .arg("*")
                .arg("--credential-id")
                .arg("test:descriptor_nonce"),
            std::time::Duration::from_secs(60),
            "test binary command",
        )
    })
    .await
    .expect("join operator CLI")
    .expect("run operator CLI");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("ticket_id:"),
        "the vault read after HELLO must succeed: status={} stdout={stdout:?} stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(daemon.operator_peer.approvals() > 0);
    daemon.stop();
}

/// Grant visibility must be checked at the management handler, not merely by
/// querying the store: the handler chooses the principal used for both calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imported_github_grant_lists_and_revokes_through_direct_management() {
    use plexus_core::credentials::ResolvedCredential;
    use plexus_core::github::control::{
        self, AgentPermission, InstallationReader, Inventory, InventoryHandle,
    };
    use plexus_core::github::credential::HandleCredentialProvider;
    struct Credential;
    impl HandleCredentialProvider for Credential {
        fn prepare(&self, _: &str, _: i64, _: &str) -> Result<ResolvedCredential, &'static str> {
            Ok(ResolvedCredential::new(
                b"fixture-installation-token".to_vec(),
                Some(1_000_000),
                1,
            ))
        }
        fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
    }
    struct Repositories;
    impl InstallationReader for Repositories {
        fn repositories_page(
            &self,
            _: &ResolvedCredential,
            _: usize,
            _: usize,
        ) -> Result<Value, String> {
            Ok(json!({"repositories":[{"full_name":"org/one"}]}))
        }
    }
    let scratch = Scratch::database("github-management-grants");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "github-management-grants".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.path().to_str().unwrap().into(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).unwrap());
    let source = include_str!("../../../catalog/github_rest.jsonc");
    let reviewed: Value =
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap();
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &ingest_value(reviewed).unwrap())
        .unwrap();
    let inventory = Inventory {
        version: "github-grant-import.v1".into(),
        handles: vec![InventoryHandle {
            app_handle_id: "app-management".into(),
            agent_id: "agent-management".into(),
            app_id: 42,
            installation_id: None,
            credential_id: "github_app:app-management".into(),
            status: "enabled".into(),
            grants: vec![AgentPermission {
                action: "create_issue".into(),
                repository: "org/one".into(),
                provenance: "approved-source-row".into(),
                policy: "allow".into(),
            }],
        }],
    };
    control::import(
        &store,
        "direct",
        &inventory,
        &Credential,
        &Repositories,
        0,
        false,
    )
    .unwrap();
    let grant_id = "github-import:app-management:agent:0:approved-source-row";
    let runtime = || {
        ModuleRuntime::with_stub_credentials_and_mock_transport(
            Arc::clone(&store),
            Arc::new(StubCredentialSource::with_default_success(
                b"fixture".to_vec(),
            )),
            Arc::new(plexus_core::MockTransport::default()),
        )
    };
    async fn management(
        runtime: ModuleRuntime,
        principal: Principal,
        method: &str,
        params: Value,
    ) -> Value {
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            74,
            1,
            702,
            serde_json::to_vec(&json!({"method":method,"params":params})).unwrap(),
        )
        .unwrap();
        let (writer, mut responses) = tokio::sync::mpsc::channel(1);
        plexus_module::handle_tool_request_for_test(frame, &writer, runtime, principal)
            .await
            .unwrap();
        serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "expected reply",
            )
            .await
            .body,
        )
        .unwrap()
    }
    let listed = management(
        runtime(),
        Principal::Direct,
        manifest::ADMIN_LIST_GRANTS_OP,
        json!({}),
    )
    .await;
    assert!(
        listed["result"]["grants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["grant_id"] == grant_id && row["state"] == "until_revoked"),
        "{listed}"
    );
    let revoked = management(
        runtime(),
        Principal::Direct,
        manifest::ADMIN_REVOKE_GRANT_OP,
        json!({"grant_id":grant_id}),
    )
    .await;
    assert_eq!(revoked["result"]["revoked"], true, "{revoked}");
    let after = management(
        runtime(),
        Principal::Direct,
        manifest::ADMIN_LIST_GRANTS_OP,
        json!({}),
    )
    .await;
    assert!(
        after["result"]["grants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["grant_id"] == grant_id && row["state"] == "revoked"),
        "{after}"
    );
    let journal = fs::read_to_string(
        scratch
            .path()
            .parent()
            .unwrap()
            .join("grant-revocations.jsonl"),
    )
    .unwrap();
    let entries: Vec<Value> = journal
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(entries
        .iter()
        .any(|row| row["grant_id"] == grant_id && row["principal"] == "direct"));
}

/// Supervised test-only vault: enrollment must prove the reference over the same
/// management route as production, rather than bypassing proof in the harness.
#[tokio::test]
async fn vault_route_fixture() {
    let Ok(path) = std::env::var("TEST_VAULT_CONNECTION") else {
        return;
    };
    use subc_protocol::manifest::{ManagementOperation, ManagementOperationKind, ProviderRole};
    let connection = timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(connection) = connection_file::read(std::path::Path::new(&path)) {
                break connection;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("vault fixture connection file");
    let mut stream = connect_client(&connection).await;
    let roles = std::env::var_os("TEST_ROLE_SERVICE").is_some();
    let mut module_manifest = manifest::build(if roles { "entorhinal" } else { "test-vault" });
    module_manifest
        .provides
        .retain(|role| matches!(role, ProviderRole::ManagementSurface { .. }));
    for role in &mut module_manifest.provides {
        if let ProviderRole::ManagementSurface { operations, .. } = role {
            *operations = vec![ManagementOperation {
                name: if roles {
                    "role.read"
                } else {
                    "credential.get_scoped"
                }
                .into(),
                kind: ManagementOperationKind::Query,
                description: None,
            }];
        }
    }
    let hello = subc_protocol::ModuleHelloBody {
        manifest: module_manifest,
        protocol_ver: PROTOCOL_VERSION,
        control_ops: Some(vec!["route.bind".into()]),
        // Through the accessor, as plexus itself does: the daemon hands the
        // nonce to this supervised fixture on descriptor 3 as well, and under
        // `NonceHandoff::DescriptorOnly` there is no environment copy at all.
        launch_nonce: subc_client_rs::launch_nonce()
            .expect("vault fixture launch nonce")
            .map(|nonce| nonce.value().to_string()),
    };
    let hello = Frame::build(
        FrameType::Hello,
        plexus_module::wire::control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&hello).unwrap(),
    )
    .unwrap();
    write_frame(&mut stream, &hello).await.unwrap();
    let ack = read_frame(&mut stream).await.unwrap().unwrap();
    assert_eq!(ack.header.ty, FrameType::HelloAck);
    // The principal the daemon attested for each bound route. The real vault
    // serves a scoped read only to the module the credential is granted to,
    // and answers anyone else (a route opened without plexus's launch nonce
    // arrives as `direct`) as `not_found`. Doing the same here is what makes a
    // vault read in these tests prove that plexus presented its nonce.
    let mut bound = std::collections::HashMap::new();
    while let Some(frame) = read_frame(&mut stream).await.unwrap() {
        if frame.header.ty != FrameType::Request {
            continue;
        }
        let request: Value = serde_json::from_slice(&frame.body).unwrap();
        let body = if frame.header.channel == 0 {
            if let Ok(ModuleControlRequest::RouteBind {
                route_channel,
                epoch,
                principal,
                ..
            }) = serde_json::from_value(request)
            {
                bound.insert((route_channel, epoch), principal);
            }
            serde_json::to_value(subc_protocol::session::ModuleControlResponse::RouteBindAck {})
                .unwrap()
        } else if roles && request["method"] != "role.read" {
            // Plexus also asks Entorhinal about repository ownership
            // (`enumerate`, `resolve_remote`) on its hourly pass, which can
            // start while a test is still running. This fixture models only
            // the role, so it refuses those; plexus leaves ownership unchanged
            // when Entorhinal does not answer.
            json!({"error": {"code": "unsupported", "message": "this test fixture serves only role.read"}})
        } else {
            assert_eq!(
                request["method"],
                if roles {
                    "role.read"
                } else {
                    "credential.get_scoped"
                }
            );
            let plexus = Principal::Reserved {
                module_id: MODULE_ID.to_string(),
            };
            match bound.get(&(frame.header.channel, frame.header.epoch)) {
                Some(Some(principal)) if *principal == plexus => {
                    if roles {
                        assert_eq!(request["params"], json!({"role":"connector_home"}));
                        json!({"result":{"role":"connector_home","epoch":1,"known":true,"stale":false,"holder":"test-member","holder_name":"Test Mac","held_here":true,"source":"cloud"}})
                    } else {
                        json!({"result": {"credential_id": request["params"]["credential_id"], "payload": b"test-vendor-token".to_vec(), "record_version": 1}})
                    }
                }
                _ => {
                    json!({"error": {"code": "not_found", "message": "test vault serves scoped reads only to reserved:plexus"}})
                }
            }
        };
        let response = Frame::build(
            FrameType::Response,
            frame.header.flags,
            frame.header.channel,
            frame.header.epoch,
            frame.header.corr,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        write_frame(&mut stream, &response).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connector_home_live_management_route_attests_plexus_and_reads_role() {
    let (mut daemon, connection) = start_live_daemon().await;
    let mut client = connect_client(&connection).await;
    wait_for_module_catalog(&mut client).await;
    let route = open_management_route(&mut client).await;
    let status = send_management_request(
        &mut client,
        route,
        101,
        plexus_module::connector_home::STATUS_OP,
        json!({}),
    )
    .await;
    let status: Value = serde_json::from_slice(&status.body).unwrap();
    assert_eq!(status["result"]["role"]["role"], "connector_home");
    assert_eq!(status["result"]["role"]["holder_name"], "Test Mac");
    assert_eq!(status["result"]["connectorHome"]["state"], "held");
    let removed = send_management_request(
        &mut client,
        route,
        102,
        "plexus.admin.connector_home.claim",
        json!({}),
    )
    .await;
    let removed: Value = serde_json::from_slice(&removed.body).unwrap();
    assert_eq!(removed["error"]["code"], "unknown_method");
    assert!(removed["error"]["message"]
        .as_str()
        .unwrap()
        .contains("connector_home.claim"));
    daemon.stop();
}
