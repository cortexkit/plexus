//! `github_react` adds one reaction as the acting agent's bot by sending the
//! `github` tool's bot request down the same path. These tests drive both
//! tools through the module's tool-request handler against one governed
//! runtime: the bot request gates, grants, receipts and the mock transport.

use super::*;
use plexus_core::credentials::CredentialSource;
use plexus_core::github::credential::HandleCredentialProvider;
use plexus_core::governance::GovernanceEngine;
use plexus_core::storage::github_store::{GithubGovernanceSeams, GithubHandle};
use plexus_core::transport::Transport;
use rusqlite::{params, Connection};
use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};

struct Token;
impl HandleCredentialProvider for Token {
    fn prepare(
        &self,
        _: &str,
        _: i64,
        _: &str,
    ) -> Result<plexus_core::ResolvedCredential, &'static str> {
        Ok(plexus_core::ResolvedCredential::anonymous())
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

/// Stands in for the daemon's session-scope lookup. Just before a bot write is
/// sent, plexus asks the daemon whether the caller's session scope is still
/// live and delegating; this answers with the scope the route was opened
/// under, as the daemon does while that session is running.
struct Live(CallScope);
impl plexus_core::scope::ScopeReader for Live {
    fn describe(
        &self,
        _: &str,
        _: &str,
    ) -> Result<plexus_core::scope::ScopeDescription, plexus_core::scope::ScopeReadError> {
        Ok(plexus_core::scope::ScopeDescription {
            status: plexus_core::scope::ScopeStatus::Live,
            owner_synced: true,
            owner_configured: true,
            live: Some(self.0.clone()),
        })
    }
}

const AGENT: &str = "agent-fixture";

fn stamp(delegates: bool, flow: bool) -> ScopeStamp {
    let attributes = ScopeAttributes::new()
        .with_agent_id(Some(AGENT.into()))
        .with_delegates(delegates);
    let attributes = if flow {
        attributes.with_flow_id(Some("flow-1".into()))
    } else {
        attributes
    };
    ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        "react-session",
        1,
        if flow {
            ScopeKind::Worker
        } else {
            ScopeKind::Head
        },
    )
    .with_attributes(attributes)
    .with_owner_authorized(true)
}

/// A runtime whose agent has a bot bound to `org/repo`, and whose carrier
/// module and agent each hold a grant for `add_reaction` and
/// `add_issue_comment`, so a refused comment is refused by github_react
/// itself rather than by a missing grant.
fn runtime(label: &str, carrier: &str) -> (Arc<ModuleState>, Arc<MockTransport>, Scratch) {
    let path = Scratch::database(&format!("github-react-{label}"));
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: format!("github-react-{label}"),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    store
        .insert_connection(
            "operator",
            "conn-react",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    store
        .put_github_handle(&GithubHandle {
            app_handle_id: "app-fixture".into(),
            agent_id: AGENT.into(),
            app_id: 1,
            installation_id: None,
            credential_reference: "github_app:app-fixture".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: Some(1),
            connection_principal: "operator".into(),
            connection_id: "conn-react".into(),
        })
        .unwrap();
    store.bind_github_repo("org/repo", "app-fixture").unwrap();
    let db = Connection::open(path.as_ref() as &Path).unwrap();
    for action in ["add_reaction", "add_issue_comment"] {
        db.execute("INSERT INTO catalog_actions (connection_id,principal,name,schema_json,schema_hash,risk,severity,status,first_seen_at_ms,last_seen_at_ms,ask_first)
            VALUES ('conn-react','operator',?1,'{}','schema','write','S1','active',1,1,0)", params![action]).unwrap();
    }
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github_rest.jsonc"),
    )
    .unwrap();
    let ingested = plexus_core::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap(),
    )
    .unwrap();
    db.execute(
        "INSERT INTO app_manifests (principal,key,schema_version,content_hash,manifest_json,ingested_at_ms)
         VALUES ('system','github_rest',1,'fixture',?1,1)",
        params![serde_json::to_string(&ingested.manifest).unwrap()],
    )
    .unwrap();
    for (id, agent) in [("module", None), ("agent", Some(AGENT))] {
        db.execute("INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,authority_kind,created_at_ms,action_selectors,agent_id)
            VALUES (?1,'operator','conn-react',?2,'write','invoke',1,'[\"add_reaction\",\"add_issue_comment\"]',?3)",
            params![id, format!("reserved:{carrier}"), agent]).unwrap();
    }
    let transport = Arc::new(MockTransport::default());
    let mut runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
        store.clone(),
        Arc::new(StubCredentialSource::default()),
        transport.clone(),
    );
    runtime.engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(StubCredentialSource::default()) as Arc<dyn CredentialSource>,
        transport.clone() as Arc<dyn Transport>,
    )
    .with_governance_seams(Arc::new(GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(Arc::new(Token)),
    }))
    .with_scope_reader(Arc::new(Live(CallScope::from_stamp(&stamp(
        true,
        carrier == "basal",
    )))));
    (
        Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        }),
        transport,
        path,
    )
}

/// Send one tool call on a route bound with `carrier` and `scope`, and return
/// the reply frame's exact body bytes.
async fn send(
    state: &Arc<ModuleState>,
    carrier: &str,
    scope: Option<ScopeStamp>,
    name: &str,
    arguments: Value,
) -> Vec<u8> {
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        41,
        1,
        99,
        serde_json::to_vec(&json!({"name": name, "arguments": arguments})).unwrap(),
    )
    .unwrap();
    let routes = Arc::new(RouteBindings::new());
    routes
        .insert_bound(
            frame.header.channel,
            frame.header.epoch,
            Principal::Reserved {
                module_id: carrier.into(),
            },
            scope.as_ref().map(CallScope::from_stamp),
            derive_call_mode(scope.as_ref()),
            scope
                .as_ref()
                .and_then(|stamp| stamp.attributes.on_behalf_of_agent.clone()),
        )
        .unwrap();
    let (writer, mut responses) = mpsc::channel(1);
    handle_tool_request(frame, &writer, state, &routes)
        .await
        .unwrap();
    recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "github_react reply",
    )
    .await
    .body
    .to_vec()
}

async fn call(
    state: &Arc<ModuleState>,
    scope: Option<ScopeStamp>,
    name: &str,
    arguments: Value,
) -> Value {
    serde_json::from_slice(&send(state, "aft", scope, name, arguments).await).unwrap()
}

fn react(nonce: &str, reaction: &str) -> Value {
    json!({"repository":"org/repo","kind":"issue","target":{"number":42},"reaction":reaction,"request_nonce":nonce})
}

/// The `github` tool call that carries the same reaction as [`react`].
fn bot_request(nonce: &str, reaction: &str) -> Value {
    json!({"op":"bot_request","request_nonce":nonce,"request":{
        "action":"issue reaction","repository":"org/repo","target":{"number":42},"body":{"reaction":reaction}
    }})
}

fn receipts(scratch: &Scratch) -> i64 {
    Connection::open(scratch.as_ref() as &Path)
        .unwrap()
        .query_row("SELECT count(*) FROM github_bot_receipt", [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_react_adds_the_reaction_as_the_agents_bot() {
    for (kind, action) in [("issue", "issue reaction"), ("pr", "pr reaction")] {
        let (state, transport, _scratch) = runtime(&format!("success-{kind}"), "aft");
        let mut arguments = react("nonce-1", "eyes");
        arguments["kind"] = json!(kind);
        let reply = call(&state, Some(stamp(true, false)), "github_react", arguments).await;
        assert_eq!(reply["result"]["status"], "completed", "{action}: {reply}");
        assert_eq!(reply["isError"], false);
        let sent = transport.requests();
        assert_eq!(sent.len(), 1, "{action}");
        assert_eq!(sent[0].action, "add_reaction");
        assert_eq!(sent[0].args["content"], "eyes");
        assert_eq!(sent[0].args["issue_number"], 42);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_react_serves_basal_flows_acting_for_their_agent() {
    let (state, transport, _scratch) = runtime("flow", "basal");
    let reply: Value = serde_json::from_slice(
        &send(
            &state,
            "basal",
            Some(stamp(true, true)),
            "github_react",
            react("flow-nonce", "eyes"),
        )
        .await,
    )
    .unwrap();
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(transport.requests()[0].action, "add_reaction");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_react_replays_a_repeated_nonce_without_reacting_again() {
    let (state, transport, scratch) = runtime("replay", "aft");
    let first = send(
        &state,
        "aft",
        Some(stamp(true, false)),
        "github_react",
        react("nonce-r", "eyes"),
    )
    .await;
    let again = send(
        &state,
        "aft",
        Some(stamp(true, false)),
        "github_react",
        react("nonce-r", "eyes"),
    )
    .await;
    assert_eq!(
        String::from_utf8(again).unwrap(),
        String::from_utf8(first).unwrap(),
        "a replay returns the first reply"
    );
    assert_eq!(
        transport.requests().len(),
        1,
        "a replay must not contact GitHub"
    );
    assert_eq!(receipts(&scratch), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_react_refuses_a_nonce_reused_for_another_reaction() {
    let (state, transport, _scratch) = runtime("mismatch", "aft");
    let first = call(
        &state,
        Some(stamp(true, false)),
        "github_react",
        react("nonce-m", "eyes"),
    )
    .await;
    assert_eq!(first["result"]["status"], "completed", "{first}");
    let reply = call(
        &state,
        Some(stamp(true, false)),
        "github_react",
        react("nonce-m", "rocket"),
    )
    .await;
    assert_eq!(reply["result"]["status"], "refused", "{reply}");
    assert_eq!(reply["result"]["refusal_code"], "nonce_payload_mismatch");
    assert_eq!(transport.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_react_refuses_every_undeclared_field_by_name() {
    let (state, transport, scratch) = runtime("fields", "aft");
    let mut cases = Vec::new();
    for (field, value) in [
        ("op", json!("bot_request")),
        ("action", json!("issue comment")),
        ("request", json!({"action":"issue comment"})),
        ("body", json!({"comment":"hi"})),
        ("agent_id", json!("someone-else")),
        ("connection_id", json!("conn-react")),
    ] {
        let mut arguments = react("nonce-f", "eyes");
        arguments[field] = value;
        cases.push((arguments, field.to_string()));
    }
    for (field, value) in [("comment_id", json!(7)), ("repository", json!("org/other"))] {
        let mut arguments = react("nonce-f", "eyes");
        arguments["target"][field] = value;
        cases.push((arguments, format!("target.{field}")));
    }
    for field in ["repository", "kind", "target", "reaction", "request_nonce"] {
        let mut arguments = react("nonce-f", "eyes");
        arguments.as_object_mut().unwrap().remove(field);
        cases.push((arguments, field.to_string()));
    }
    for (field, value, named) in [
        ("target", json!({"number":0}), "target.number"),
        ("target", json!({"number":"42"}), "target.number"),
        ("target", json!({"number":4.5}), "target.number"),
        ("target", json!(42), "target"),
        ("repository", json!(""), "repository"),
        ("request_nonce", json!(""), "request_nonce"),
        ("request_nonce", json!(7), "request_nonce"),
    ] {
        let mut arguments = react("nonce-f", "eyes");
        arguments[field] = value;
        cases.push((arguments, named.to_string()));
    }
    for (arguments, field) in cases {
        let reply = call(
            &state,
            Some(stamp(true, false)),
            "github_react",
            arguments.clone(),
        )
        .await;
        assert_eq!(
            reply["error"]["code"], "invalid_request",
            "{arguments}: {reply}"
        );
        assert_eq!(reply["error"]["field"], field, "{arguments}: {reply}");
        assert_eq!(reply["error"]["transmission"], "not_sent");
    }
    assert!(
        transport.requests().is_empty(),
        "a refused shape contacted GitHub"
    );
    assert_eq!(receipts(&scratch), 0, "a refused shape claimed a receipt");
}

/// `github_react` can only add a reaction. The test grants both the agent and
/// the module that carries its call permission to post comments
/// (`add_issue_comment`), then tries every `kind`: none reaches anything but
/// `add_reaction`, so holding a broader grant never widens this tool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_react_reaches_no_action_but_add_reaction() {
    let (state, transport, scratch) = runtime("kinds", "aft");
    for kind in [
        json!("issue comment"),
        json!("pr comment"),
        json!("issue close"),
        json!("pr review"),
        json!("issue create"),
        json!("comment"),
        json!("Issue"),
        json!(null),
    ] {
        let mut arguments = react("nonce-k", "eyes");
        arguments["kind"] = kind.clone();
        let reply = call(&state, Some(stamp(true, false)), "github_react", arguments).await;
        assert_eq!(reply["error"]["code"], "invalid_request", "{kind}: {reply}");
        assert_eq!(reply["error"]["field"], "kind", "{kind}: {reply}");
    }
    assert!(
        transport.requests().is_empty(),
        "a non-reaction kind contacted GitHub"
    );
    assert_eq!(receipts(&scratch), 0);
    for kind in ["issue", "pr"] {
        let mut arguments = react(&format!("nonce-{kind}"), "heart");
        arguments["kind"] = json!(kind);
        call(&state, Some(stamp(true, false)), "github_react", arguments).await;
    }
    let actions: Vec<_> = transport
        .requests()
        .into_iter()
        .map(|sent| sent.action)
        .collect();
    assert_eq!(actions, ["add_reaction", "add_reaction"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_react_refuses_a_reaction_outside_githubs_set() {
    let (state, transport, scratch) = runtime("reaction", "aft");
    for reaction in [json!("thumbsup"), json!("EYES"), json!(""), json!(1)] {
        let mut arguments = react("nonce-x", "eyes");
        arguments["reaction"] = reaction.clone();
        let reply = call(&state, Some(stamp(true, false)), "github_react", arguments).await;
        assert_eq!(
            reply["error"]["code"], "invalid_request",
            "{reaction}: {reply}"
        );
        assert_eq!(reply["error"]["field"], "reaction");
    }
    assert!(transport.requests().is_empty());
    assert_eq!(receipts(&scratch), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_react_requires_a_delegating_stamp_before_sending() {
    let (state, transport, _scratch) = runtime("delegation", "aft");
    for scope in [Some(stamp(false, false)), None] {
        let reply = call(&state, scope, "github_react", react("nonce-d", "eyes")).await;
        assert_eq!(reply["result"]["status"], "refused", "{reply}");
        assert_eq!(reply["result"]["refusal_code"], "delegating_scope_required");
    }
    assert!(transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_react_is_refused_in_codemode() {
    let (state, transport, scratch) = runtime("codemode", "aft");
    let codemode = stamp(true, false).with_attributes(
        ScopeAttributes::new()
            .with_agent_id(Some(AGENT.into()))
            .with_delegates(true)
            .with_run_id(Some("run-1".into())),
    );
    let reply = call(
        &state,
        Some(codemode),
        "github_react",
        react("nonce-c", "eyes"),
    )
    .await;
    assert_eq!(reply["error"]["code"], "call_mode_unsupported", "{reply}");
    assert_eq!(
        reply["error"]["detail"],
        json!({"tool":"github_react","mode":"codemode"})
    );
    assert!(transport.requests().is_empty());
    assert_eq!(receipts(&scratch), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_react_stops_while_this_machine_does_not_hold_the_connector_home() {
    let (mut state, transport, scratch) = runtime("home", "aft");
    Arc::get_mut(&mut state).unwrap().runtime.connector_home =
        Arc::new(crate::connector_home::ConnectorHome::unavailable());
    let reply = call(
        &state,
        Some(stamp(true, false)),
        "github_react",
        react("nonce-h", "eyes"),
    )
    .await;
    assert_eq!(reply["error"]["code"], "connector_home_not_held", "{reply}");
    assert_eq!(reply["error"]["transmission"], "not_sent");
    assert!(transport.requests().is_empty());
    assert_eq!(receipts(&scratch), 0);
}

/// github_react and the equivalent github bot_request return the same bytes,
/// whether the reaction is sent or refused, because both run the one bot
/// request path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_react_replies_byte_for_byte_like_the_equivalent_bot_request() {
    // A reaction that is sent: each tool runs on its own freshly built test
    // runtime with the same grants, bot and fake GitHub, so the replies can be
    // compared byte for byte.
    let (react_state, react_transport, _a) = runtime("same-react", "aft");
    let (bot_state, bot_transport, _b) = runtime("same-bot", "aft");
    let reacted = send(
        &react_state,
        "aft",
        Some(stamp(true, false)),
        "github_react",
        react("same", "eyes"),
    )
    .await;
    let requested = send(
        &bot_state,
        "aft",
        Some(stamp(true, false)),
        "github",
        bot_request("same", "eyes"),
    )
    .await;
    assert_eq!(
        String::from_utf8(reacted.clone()).unwrap(),
        String::from_utf8(requested).unwrap()
    );
    let decoded: Value = serde_json::from_slice(&reacted).unwrap();
    assert_eq!(decoded["result"]["status"], "completed", "{decoded}");
    let sent = |transport: &MockTransport| {
        transport
            .requests()
            .into_iter()
            .map(|sent| (sent.connection_id, sent.action, sent.args))
            .collect::<Vec<_>>()
    };
    assert_eq!(sent(&react_transport), sent(&bot_transport));
    // One receipt serves both tools: the bot_request with the same nonce and
    // request is a replay of the github_react call, not a second reaction.
    let replayed = send(
        &react_state,
        "aft",
        Some(stamp(true, false)),
        "github",
        bot_request("same", "eyes"),
    )
    .await;
    assert_eq!(
        String::from_utf8(replayed).unwrap(),
        String::from_utf8(reacted).unwrap()
    );
    assert_eq!(react_transport.requests().len(), 1);
    // Refusals: a stamp that does not delegate, a nonce reused for another
    // reaction, and a repository with no bot binding.
    let mut unbound = react("unbound", "eyes");
    unbound["repository"] = json!("org/unbound");
    let mut unbound_request = bot_request("unbound", "eyes");
    unbound_request["request"]["repository"] = json!("org/unbound");
    for (label, scope, react_arguments, bot_arguments, code) in [
        (
            "delegation",
            stamp(false, false),
            react("refused", "eyes"),
            bot_request("refused", "eyes"),
            "delegating_scope_required",
        ),
        (
            "mismatch",
            stamp(true, false),
            react("same", "rocket"),
            bot_request("same", "rocket"),
            "nonce_payload_mismatch",
        ),
        (
            "unbound",
            stamp(true, false),
            unbound,
            unbound_request,
            "repository_unbound",
        ),
    ] {
        let reacted = send(
            &react_state,
            "aft",
            Some(scope.clone()),
            "github_react",
            react_arguments,
        )
        .await;
        let requested = send(&bot_state, "aft", Some(scope), "github", bot_arguments).await;
        assert_eq!(
            String::from_utf8(reacted.clone()).unwrap(),
            String::from_utf8(requested).unwrap(),
            "{label}"
        );
        let decoded: Value = serde_json::from_slice(&reacted).unwrap();
        assert_eq!(
            decoded["result"]["refusal_code"], code,
            "{label}: {decoded}"
        );
    }
    assert_eq!(react_transport.requests().len(), 1);
    assert_eq!(bot_transport.requests().len(), 1);
}

/// A worker scope that works on behalf of an agent, as the daemon stamps it:
/// no agent_id, no delegation, only `on_behalf_of_agent`.
fn on_behalf_of_worker() -> ScopeStamp {
    ScopeStamp::new(
        Principal::Reserved {
            module_id: "aft".into(),
        },
        "worker-session",
        1,
        ScopeKind::Worker,
    )
    .with_attributes(ScopeAttributes::new().with_on_behalf_of_agent(Some(AGENT.into())))
    .with_owner_authorized(true)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_working_on_behalf_of_an_agent_cannot_write_as_its_bot() {
    let (state, transport, _scratch) = runtime("on-behalf-of-write", "aft");
    let scope = Some(on_behalf_of_worker());
    let reaction = call(
        &state,
        scope.clone(),
        "github_react",
        react("nonce-w1", "eyes"),
    )
    .await;
    assert_eq!(
        reaction["result"]["refusal_code"], "delegating_scope_required",
        "{reaction}"
    );
    let request = call(
        &state,
        scope.clone(),
        "github",
        bot_request("nonce-w2", "eyes"),
    )
    .await;
    assert_eq!(
        request["result"]["refusal_code"], "delegating_scope_required",
        "{request}"
    );
    // Invoking the bot's write action directly is no way around the facade.
    let invoke = call(
        &state,
        scope,
        "invoke",
        json!({"op":"call","connection":"conn-react","action":"add_reaction",
            "args":{"owner":"org","repo":"repo","issue_number":42,"content":"eyes"}}),
    )
    .await;
    assert!(invoke.get("error").is_some(), "{invoke}");
    assert!(
        transport.requests().is_empty(),
        "nothing may be written for a worker that only works on behalf of an agent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spent_bot_read_budget_never_refuses_a_bot_write() {
    let (state, transport, _scratch) = runtime("read-budget-write", "aft");
    let now = plexus_core::now_ms();
    let store = state.store();
    for _ in 0..plexus_core::storage::github_bot_reads_store::BOT_READ_HOURLY_CAP {
        store
            .reserve_github_bot_read("app-fixture", 1, now)
            .unwrap();
    }
    store
        .record_github_bot_rate_limit(
            "app-fixture",
            plexus_core::storage::github_bot_reads_store::BotRateLimit {
                remaining: 0,
                reset_at_ms: now + 3_600_000,
            },
            now,
        )
        .unwrap();
    let reply = call(
        &state,
        Some(stamp(true, false)),
        "github_react",
        react("nonce-b1", "eyes"),
    )
    .await;
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(transport.requests().len(), 1);
}
