// Agent bot reads on `github_read`: `github.repo.get`, the two searches and
// AFT's byte-range job log, each sent with the stamped agent's own bot on a
// repository bound to it, and each charged to that bot's read budget.

use super::*;
use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};

const BOT_ACTIONS: &[&str] = &[
    "github.repo.get",
    "github.search.code",
    "github.search.issues",
    "github.actions.job.get",
    "github.actions.job_log",
];

fn bot_runtime() -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    imported_runtime_with_actions(BOT_ACTIONS)
}

pub(super) fn head(agent: Option<&str>) -> ScopeStamp {
    ScopeStamp::new(
        Principal::Reserved {
            module_id: "aft".into(),
        },
        "head-session",
        1,
        ScopeKind::Head,
    )
    .with_attributes(ScopeAttributes::new().with_agent_id(agent.map(str::to_owned)))
    .with_owner_authorized(true)
}

pub(super) fn worker(on_behalf_of: Option<&str>) -> ScopeStamp {
    ScopeStamp::new(
        Principal::Reserved {
            module_id: "aft".into(),
        },
        "worker-session",
        1,
        ScopeKind::Worker,
    )
    .with_attributes(
        ScopeAttributes::new().with_on_behalf_of_agent(on_behalf_of.map(str::to_owned)),
    )
    .with_owner_authorized(true)
}

/// Send one tool call on a route bound the way a daemon bind binds it: the
/// stamp's scope, plus its `on_behalf_of_agent` kept beside the scope. Returns
/// the reply frame's exact body bytes.
pub(super) async fn send_bound(
    runtime: &Arc<ModuleState>,
    carrier: &str,
    scope: Option<ScopeStamp>,
    body: &Value,
) -> Vec<u8> {
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        73,
        1,
        702,
        serde_json::to_vec(body).unwrap(),
    )
    .unwrap();
    let (writer, mut responses) = mpsc::channel(1);
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
    handle_tool_request(frame, &writer, runtime, &routes)
        .await
        .unwrap();
    recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "bot read reply",
    )
    .await
    .body
    .to_vec()
}

async fn read(
    runtime: &Arc<ModuleState>,
    scope: Option<ScopeStamp>,
    action: &str,
    repository: &str,
    args: Value,
) -> Value {
    let body = json!({"name": manifest::GITHUB_READ_TOOL,
        "arguments": {"action": action, "repository": repository, "args": args}});
    serde_json::from_slice(&send_bound(runtime, "aft", scope, &body).await).unwrap()
}

fn envelope(body: Value) -> MockResponse {
    MockResponse::Success(json!({
        "status": 200, "body": body, "next_page": null,
        "rate_limit": {"remaining": 4_000, "reset_at_ms": 4_102_444_800_000_i64},
    }))
}

fn not_sent(reply: &Value, code: &str) {
    assert_eq!(reply["error"]["code"], code, "{reply}");
    assert_eq!(reply["error"]["transmission"], "not_sent", "{reply}");
    assert_eq!(reply["isError"], true, "{reply}");
    assert!(reply.get("structuredContent").is_none(), "{reply}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repo_get_reads_through_the_head_agents_bot() {
    let (runtime, _store, transport, scratch) = bot_runtime();
    transport.set_response(MockResponse::Success(json!({
        "status": 200, "body": [{"number": 1}], "next_page": 2,
        "rate_limit": {"remaining": 4_000, "reset_at_ms": 4_102_444_800_000_i64},
    })));
    let reply = read(
        &runtime,
        Some(head(Some("agent-x"))),
        "github.repo.get",
        "O/X",
        json!({"path": "pulls", "query": {"state": "open"}}),
    )
    .await;
    let expected = json!({"status": 200, "body": [{"number": 1}], "next_page": 2});
    assert_eq!(reply["result"], expected, "{reply}");
    assert_eq!(reply["structuredContent"], expected);
    assert_eq!(reply["isError"], false);
    let sent = transport.requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].connection_id, "github-handle-app-x");
    assert_eq!(sent[0].action, "github.repo.get");
    assert_eq!(
        sent[0].args,
        json!({"owner":"o","repo":"x","path":"pulls","query":{"state":"open"},
            "accept":"application/vnd.github+json"})
    );
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    let (agent, on_behalf_of): (Option<String>, Option<String>) = db
        .query_row(
            "SELECT agent_id, scope_on_behalf_of_agent FROM audit_journal
             WHERE action='github.repo.get' AND gate='dispatch'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(agent.as_deref(), Some("agent-x"));
    assert_eq!(on_behalf_of, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_reads_with_the_bot_of_the_agent_it_works_for() {
    let (runtime, _store, transport, scratch) = bot_runtime();
    transport.set_response(envelope(json!({"full_name": "o/x"})));
    let reply = read(
        &runtime,
        Some(worker(Some("agent-x"))),
        "github.repo.get",
        "o/x",
        json!({"path": ""}),
    )
    .await;
    assert_eq!(reply["result"]["body"], json!({"full_name": "o/x"}), "{reply}");
    assert_eq!(transport.requests()[0].connection_id, "github-handle-app-x");
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    let rows: Vec<(Option<String>, Option<String>)> = db
        .prepare(
            "SELECT agent_id, scope_on_behalf_of_agent FROM audit_journal
             WHERE action='github.repo.get' ORDER BY journal_id",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(rows.len(), 2, "an authorization row and a dispatch row");
    for (agent, on_behalf_of) in rows {
        assert_eq!(agent, None, "the worker's agent is never the audit row's agent_id");
        assert_eq!(on_behalf_of.as_deref(), Some("agent-x"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stamp_naming_no_usable_agent_is_refused_agent_identity_required() {
    let delegating_worker = ScopeStamp::new(
        Principal::Reserved {
            module_id: "aft".into(),
        },
        "worker-session",
        1,
        ScopeKind::Worker,
    )
    .with_attributes(
        ScopeAttributes::new()
            .with_agent_id(Some("agent-x".into()))
            .with_delegates(true),
    )
    .with_owner_authorized(true);
    for scope in [
        None,
        Some(head(None)),
        Some(worker(None)),
        // A worker's own agent_id is not the worker-read identity.
        Some(delegating_worker),
    ] {
        let (runtime, _store, transport, _scratch) = bot_runtime();
        for action in plexus_core::github::reads::bot::ACTIONS {
            let args = if *action == "github.repo.get" {
                json!({"path": ""})
            } else {
                json!({"q": "x"})
            };
            let reply = read(&runtime, scope.clone(), action, "o/x", args).await;
            not_sent(&reply, "agent_identity_required");
        }
        let reply = read(&runtime, scope, "github.actions.job_log", "o/x", json!({"job_id": 1})).await;
        not_sent(&reply, "agent_identity_required");
        assert!(transport.requests().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_repositories_bound_to_the_agents_bot_are_visible() {
    for (scope, repository) in [
        (head(Some("agent-x")), "o/unbound"),
        (head(Some("agent-other")), "o/x"),
        (worker(Some("agent-other")), "o/x"),
        (head(Some("agent-x")), "not-a-repository"),
    ] {
        let (runtime, _store, transport, _scratch) = bot_runtime();
        let reply = read(&runtime, Some(scope), "github.repo.get", repository, json!({"path": ""})).await;
        not_sent(&reply, "repository_not_visible");
        assert!(transport.requests().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_paths_accept_values_and_queries_send_nothing() {
    for (args, field) in [
        (json!({"path": "/"}), "path"),
        (json!({"path": "/pulls"}), "path"),
        (json!({"path": "https://api.github.com/user"}), "path"),
        (json!({"path": "pulls/../../orgs/o"}), "path"),
        (json!({"path": "pulls//1"}), "path"),
        (json!({"path": "contents%2fsecret"}), "path"),
        (json!({"path": "pulls/%2e%2e/x"}), "path"),
        (json!({}), "path"),
        (json!({"path": "", "accept": "application/json"}), "accept"),
        (json!({"path": "", "query": {"page": 2}}), "query"),
        (json!({"path": "", "query": ["page"]}), "query"),
        (json!({"path": "", "method": "DELETE"}), "method"),
    ] {
        let (runtime, _store, transport, _scratch) = bot_runtime();
        let reply = read(&runtime, Some(head(Some("agent-x"))), "github.repo.get", "o/x", args.clone()).await;
        not_sent(&reply, "endpoint_not_allowed");
        assert_eq!(reply["error"]["field"], field, "{args}: {reply}");
        assert!(transport.requests().is_empty(), "{args}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_is_fenced_to_the_bound_repository() {
    for action in ["github.search.code", "github.search.issues"] {
        let (runtime, _store, transport, _scratch) = bot_runtime();
        transport.set_response(envelope(json!({
            "total_count": 1, "incomplete_results": false, "items": [{"name": "a.rs"}],
        })));
        let reply = read(
            &runtime,
            Some(head(Some("agent-x"))),
            action,
            "o/x",
            json!({"q": "parse_config", "per_page": 50, "page": 2}),
        )
        .await;
        assert_eq!(
            reply["result"],
            json!({"total_count": 1, "incomplete_results": false, "items": [{"name": "a.rs"}], "next_page": null}),
            "{reply}"
        );
        let sent = transport.requests();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].action, action);
        assert_eq!(
            sent[0].args,
            json!({"owner":"o","repo":"x","q":"parse_config repo:o/x","page":2,"per_page":50})
        );
        for q in ["x repo:o/y", "x Org:o", "USER:someone"] {
            let reply = read(&runtime, Some(head(Some("agent-x"))), action, "o/x", json!({"q": q})).await;
            not_sent(&reply, "endpoint_not_allowed");
            assert_eq!(reply["error"]["field"], "q");
        }
        let reply = read(&runtime, Some(head(Some("agent-x"))), action, "o/x", json!({"q": "x", "per_page": 101})).await;
        not_sent(&reply, "endpoint_not_allowed");
        assert_eq!(reply["error"]["field"], "per_page");
        assert_eq!(transport.requests().len(), 1, "refused searches send nothing");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spent_read_budget_refuses_before_anything_is_sent() {
    let (runtime, store, transport, scratch) = bot_runtime();
    let now = plexus_core::now_ms();
    for _ in 0..plexus_core::storage::github_bot_reads_store::BOT_READ_HOURLY_CAP {
        store.reserve_github_bot_read("app-x", 1, now).unwrap();
    }
    transport.set_response(envelope(json!({})));
    let reply = read(&runtime, Some(head(Some("agent-x"))), "github.repo.get", "o/x", json!({"path": ""})).await;
    not_sent(&reply, "read_budget_exhausted");
    let retry = reply["error"]["retry_after_ms"].as_i64().unwrap();
    assert!(retry > 0 && retry <= 3_600_000, "{reply}");
    assert!(transport.requests().is_empty());
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    let statuses: Vec<String> = db
        .prepare("SELECT status FROM reservations WHERE action='github.repo.get'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(statuses, ["invalidated"], "the unsent read's reservation is retired");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_reporting_under_a_thousand_remaining_stops_reads_until_reset() {
    let (runtime, _store, transport, _scratch) = bot_runtime();
    let reset = plexus_core::now_ms() + 600_000;
    transport.set_response(MockResponse::Success(json!({
        "status": 200, "body": {}, "next_page": null,
        "rate_limit": {"remaining": 999, "reset_at_ms": reset},
    })));
    let first = read(&runtime, Some(head(Some("agent-x"))), "github.repo.get", "o/x", json!({"path": ""})).await;
    assert!(first.get("result").is_some(), "{first}");
    let second = read(&runtime, Some(head(Some("agent-x"))), "github.repo.get", "o/x", json!({"path": ""})).await;
    not_sent(&second, "read_budget_exhausted");
    let retry = second["error"]["retry_after_ms"].as_i64().unwrap();
    assert!(retry > 590_000 && retry <= 600_000, "{second}");
    assert_eq!(transport.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_github_refusal_is_vendor_error_with_its_status() {
    for (code, status) in [("http_404", 404), ("http_403", 403), ("http_422", 422)] {
        let (runtime, _store, transport, _scratch) = bot_runtime();
        transport.set_response(MockResponse::VendorError {
            code: code.into(),
            message: String::new(),
        });
        let reply = read(&runtime, Some(head(Some("agent-x"))), "github.repo.get", "o/x", json!({"path": "pulls/9"})).await;
        assert_eq!(reply["error"]["code"], "vendor_error", "{reply}");
        assert_eq!(reply["error"]["status"], status);
        assert_eq!(reply["error"]["transmission"], "sent");
        assert!(reply.get("structuredContent").is_none());
    }
    let (runtime, _store, transport, _scratch) = bot_runtime();
    transport.set_response(MockResponse::VendorError {
        code: "response_too_large".into(),
        message: String::new(),
    });
    let reply = read(&runtime, Some(head(Some("agent-x"))), "github.repo.get", "o/x", json!({"path": "pulls/9.diff"})).await;
    assert_eq!(reply["error"]["code"], "response_too_large", "{reply}");
    assert_eq!(reply["error"]["transmission"], "sent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aft_job_log_reads_a_byte_range_with_the_agents_bot() {
    let (runtime, _store, transport, _scratch) = bot_runtime();
    transport.set_response_for_method(
        "github.actions.job.get",
        "",
        envelope(json!({"status": "completed"})),
    );
    transport.set_response_for_method(
        "github.actions.job_log",
        "",
        MockResponse::Success(json!({"body": "line\n", "offset": 0, "length": 5, "total_bytes": 5})),
    );
    let reply = read(&runtime, Some(head(Some("agent-x"))), "github.actions.job_log", "o/x", json!({"job_id": 42})).await;
    assert_eq!(
        reply["result"],
        json!({"body": "line\n", "offset": 0, "length": 5, "total_bytes": 5}),
        "{reply}"
    );
    let sent = transport.requests();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|request| request.connection_id == "github-handle-app-x"));
    assert_eq!(sent[0].action, "github.actions.job.get");
    assert_eq!(sent[1].args, json!({"owner":"o","repo":"x","job_id":42,"offset":0,"length":1_048_576}));
    // The log read is two HTTP requests: GitHub's redirect and the storage
    // download it points to. With the job check that is three units.
    assert_eq!(
        runtime
            .store()
            .github_bot_reads_in_window("app-x", plexus_core::now_ms())
            .unwrap(),
        3
    );
    for (args, field) in [
        (json!({"job_id": 42, "length": 1_048_577}), "length"),
        (json!({"job_id": 42, "length": 0}), "length"),
        (json!({"job_id": 42, "offset": -1}), "offset"),
        (json!({"job_id": 0}), "job_id"),
        (json!({"job_id": 42, "since": "x"}), "since"),
    ] {
        let reply = read(&runtime, Some(head(Some("agent-x"))), "github.actions.job_log", "o/x", args.clone()).await;
        not_sent(&reply, "endpoint_not_allowed");
        assert_eq!(reply["error"]["field"], field, "{args}");
    }
    assert_eq!(transport.requests().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unfinished_job_has_no_log_request() {
    let (runtime, _store, transport, _scratch) = bot_runtime();
    transport.set_response(envelope(json!({"status": "in_progress"})));
    let reply = read(&runtime, Some(head(Some("agent-x"))), "github.actions.job_log", "o/x", json!({"job_id": 42})).await;
    assert_eq!(reply["error"]["code"], "job_not_finished", "{reply}");
    assert_eq!(transport.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn job_log_with_max_bytes_keeps_the_tail_form_off_the_bot() {
    let (runtime, _store, transport, _scratch) = bot_runtime();
    let reply = read(
        &runtime,
        Some(head(Some("agent-x"))),
        "github.actions.job_log",
        "o/x",
        json!({"job_id": 42, "max_bytes": 1024}),
    )
    .await;
    // This runtime has no Actions connection, so the tail form is refused by
    // governance; the bot form would refuse max_bytes as an argument it does
    // not serve.
    assert!(reply.get("error").is_some(), "{reply}");
    assert_ne!(
        reply["error"]["code"], "endpoint_not_allowed",
        "a max_bytes job log read keeps the tail form: {reply}"
    );
    assert!(
        transport
            .requests()
            .iter()
            .all(|request| request.connection_id != "github-handle-app-x"),
        "the tail form never uses the bot's connection"
    );
}

/// Records every status the GitHub handle credential path reports to the
/// vault, which treats a reported 401 as a credential to refresh or revoke.
#[derive(Default)]
struct RecordingToken(std::sync::Mutex<Vec<u16>>);
impl plexus_core::github::credential::HandleCredentialProvider for RecordingToken {
    fn prepare(
        &self,
        _: &str,
        _: i64,
        _: &str,
    ) -> Result<plexus_core::ResolvedCredential, &'static str> {
        Ok(plexus_core::ResolvedCredential::anonymous())
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, status: u16) {
        self.0.lock().unwrap().push(status);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_403_on_a_bot_read_is_never_reported_to_the_vault_but_a_401_is() {
    for (code, reported) in [("http_403", Vec::<u16>::new()), ("http_401", vec![401])] {
        let token = Arc::new(RecordingToken::default());
        let (runtime, _store, transport, _scratch) =
            imported_runtime_with_provider(BOT_ACTIONS, token.clone());
        transport.set_response(MockResponse::VendorError {
            code: code.into(),
            message: String::new(),
        });
        let reply = read(&runtime, Some(head(Some("agent-x"))), "github.actions.job_log", "o/x", json!({"job_id": 42})).await;
        assert_eq!(reply["error"]["code"], "vendor_error", "{reply}");
        assert_eq!(reply["error"]["transmission"], "sent");
        assert_eq!(*token.0.lock().unwrap(), reported, "{code}");
    }
}
