use super::job_log_tests::{actions_runtime, flow};
use super::*;
use std::collections::BTreeMap;

const SUPERSEDED: &str = "github.actions.run.superseded";

fn run(id: u64, number: u64, created: &str) -> Value {
    json!({"id":id,"run_number":number,"created_at":created,"status":"completed","conclusion":"success",
        "workflow_id":7,"head_branch":"train/a b","html_url":format!("https://github.com/o/x/actions/runs/{id}")})
}

fn setup() -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    let setup = actions_runtime();
    setup.2.set_response_for_method(
        "get_workflow_run_metadata",
        "",
        MockResponse::Success(run(42, 10, "2026-10-12T00:00:00Z")),
    );
    setup.2.set_response_for_method(
        "list_workflow_runs_for_workflow",
        "",
        MockResponse::Success(json!({"workflow_runs":[run(43, 11, "2026-10-12T00:01:00Z")]})),
    );
    setup.2.set_response_for_method("list_workflow_run_artifacts", "", MockResponse::Success(json!({
        "total_count":1,"artifacts":[{"id":7,"name":"shard","created_at":"2026-10-12T00:00:00Z","expired":false,"size_in_bytes":123}]
    })));
    setup.2.set_response_for_method(
        "github.actions.artifact_file",
        "",
        MockResponse::Success(json!({"total_bytes":3,"truncated":false,"text":"log"})),
    );
    setup
}

async fn read(
    runtime: Arc<ModuleState>,
    action: &str,
    repository: &str,
    args: Value,
    agent: Option<&str>,
) -> Value {
    send_facade_frame(
        runtime,
        manifest::GITHUB_READ_TOOL,
        json!({"action":action,"repository":repository,"args":args}),
        "basal",
        Some(flow(agent)),
    )
    .await
}

fn reads() -> [(&'static str, Value, i64); 3] {
    [
        ("github.actions.job_log", json!({"job_id":42}), 2),
        (
            "github.actions.artifact_file",
            json!({"run_id":42,"artifact":"shard","path":"log"}),
            101,
        ),
        (SUPERSEDED, json!({"run_id":42}), 2),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ci_reads_reserve_the_whole_bound_once_in_the_ledger() {
    for (action, args, count) in reads() {
        let (runtime, _, transport, scratch) = setup();
        let reply = read(runtime, action, "o/x", args, Some("agent-x")).await;
        assert!(reply.get("result").is_some(), "{action}: {reply}");
        let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
        let ledger: (i64, i64) = db
            .query_row(
                "SELECT COUNT(*),SUM(requests) FROM github_actions_quota",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            ledger,
            (1, count),
            "{action} must reserve its entire bound only once"
        );
        assert_eq!(transport.requests().len(), 2);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ci_reads_quota_refusal_is_atomic_and_reports_millisecond_retry() {
    for (action, args, count) in reads() {
        let (runtime, _, transport, scratch) = setup();
        let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
        let reserved = plexus_core::storage::now_ms();
        db.execute(
            "INSERT INTO github_actions_quota VALUES ('used',?1,?2)",
            (reserved, 601 - count),
        )
        .unwrap();
        let before = plexus_core::storage::now_ms();
        let reply = read(runtime, action, "o/x", args, Some("agent-x")).await;
        let after = plexus_core::storage::now_ms();
        assert_eq!(
            reply["error"]["code"], "github_actions_quota_exhausted",
            "{action}: {reply}"
        );
        assert_eq!(reply["error"]["transmission"], "not_sent");
        let retry = reply["error"]["detail"]["retry_after_ms"].as_i64().unwrap();
        assert!(
            (reserved + 3_600_001 - after..=reserved + 3_600_001 - before).contains(&retry),
            "millisecond retry: {reply}"
        );
        assert!(
            transport.requests().is_empty(),
            "an insufficient whole-read budget must send nothing"
        );
        let rows: i64 = db
            .query_row("SELECT COUNT(*) FROM github_actions_quota", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(rows, 1, "refusal must not leave a partial reservation");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn superseded_comparison_uses_identity_timestamp_and_tie_break() {
    for (candidate, expected) in [
        (run(43, 11, "2026-10-12T00:01:00Z"), true),
        (run(43, 9, "2026-10-12T00:01:00Z"), true),
        (run(43, 11, "2026-10-12T00:00:00Z"), true),
        (run(43, 10, "2026-10-12T00:00:00Z"), false),
        (run(43, 9, "2026-10-12T00:00:00Z"), false),
        (run(43, 11, "2026-10-11T23:59:59Z"), false),
        (run(42, 11, "2026-10-12T00:01:00Z"), false),
        (run(42, 10, "2026-10-12T00:00:00Z"), false),
    ] {
        let (runtime, _, transport, _scratch) = setup();
        transport.set_response_for_method(
            "list_workflow_runs_for_workflow",
            "",
            MockResponse::Success(json!({"workflow_runs":[candidate]})),
        );
        let reply = read(
            runtime,
            SUPERSEDED,
            "O/X",
            json!({"run_id":42}),
            Some("agent-x"),
        )
        .await;
        assert_eq!(
            reply["result"]["superseded"], expected,
            "candidate {candidate}: {reply}"
        );
        assert_eq!(reply["result"]["repository"], "o/x");
        assert_eq!(
            reply["result"]["run"],
            json!({"id":42,"run_number":10,"created_at":"2026-10-12T00:00:00Z","status":"completed","conclusion":"success"})
        );
        if expected {
            assert_eq!(reply["result"]["newer"]["id"], candidate["id"]);
            assert_eq!(reply["result"]["newer"]["url"], candidate["html_url"]);
        } else {
            assert!(reply["result"]["newer"].is_null());
        }
        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].action, "get_workflow_run_metadata");
        assert_eq!(
            requests[0].args,
            json!({"owner":"o","repo":"x","run_id":42})
        );
        assert_eq!(requests[1].action, "list_workflow_runs_for_workflow");
        assert_eq!(
            requests[1].args,
            json!({"owner":"o","repo":"x","workflow_id":7,"branch":"train/a b"})
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn superseded_null_branch_refuses_without_a_second_request() {
    let (runtime, _, transport, _scratch) = setup();
    let mut tag = run(42, 10, "2026-10-12T00:00:00Z");
    tag["head_branch"] = Value::Null;
    transport.set_response_for_method("get_workflow_run_metadata", "", MockResponse::Success(tag));
    let reply = read(
        runtime,
        SUPERSEDED,
        "o/x",
        json!({"run_id":42}),
        Some("agent-x"),
    )
    .await;
    assert_eq!(reply["error"]["code"], "run_branch_unknown", "{reply}");
    assert_eq!(transport.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn superseded_arguments_are_closed_and_positive() {
    let (runtime, _, transport, _scratch) = setup();
    for args in [
        json!({}),
        json!({"run_id":0}),
        json!({"run_id":-1}),
        json!({"run_id":1.5}),
        json!({"run_id":"42"}),
        json!({"run_id":42,"branch":"main"}),
        Value::Null,
    ] {
        let reply = read(runtime.clone(), SUPERSEDED, "o/x", args, Some("agent-x")).await;
        assert_eq!(reply["error"]["code"], "run_arguments_invalid", "{reply}");
    }
    assert!(transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn superseded_agent_flow_cannot_read_outside_its_bot() {
    let (runtime, _, transport, _scratch) = setup();
    for (repository, agent) in [("o/unbound", "agent-x"), ("o/x", "agent-other")] {
        let reply = read(
            runtime.clone(),
            SUPERSEDED,
            repository,
            json!({"run_id":42}),
            Some(agent),
        )
        .await;
        assert_eq!(reply["error"]["code"], "repository_not_visible", "{reply}");
    }
    assert!(transport.requests().is_empty());
}

fn with_rest(runtime: &mut Arc<ModuleState>, store: Arc<PlexusStore>, url: String) {
    let source = include_str!("../../../catalog/github_actions.jsonc");
    let manifest =
        ingest_value(serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap())
            .unwrap();
    let config = plexus_core::RestConfig::new(url)
        .with_bindings(manifest.manifest.credential_bindings.clone())
        .with_actions(plexus_core::rest_api::actions_from_manifest(
            &manifest.manifest,
        ));
    Arc::get_mut(runtime).unwrap().runtime.engine = plexus_core::GovernanceEngine::new(
        store,
        Arc::new(StubCredentialSource::with_default_success(b"test".to_vec()))
            as Arc<dyn plexus_core::CredentialSource>,
        Arc::new(plexus_core::RestTransport::new(config)) as Arc<dyn plexus_core::Transport>,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn superseded_catalog_dispatches_the_two_reviewed_endpoints() {
    let (mut runtime, store, _, _scratch) = setup();
    let (url, server) =
        crate::test_http::FixedRequestServer::start(2, "run comparison", |index, request| {
            let body = if index == 0 {
                assert!(
                    request.starts_with("GET /repos/o/x/actions/runs/42 "),
                    "{request}"
                );
                run(42, 10, "2026-10-12T00:00:00Z")
            } else {
                let target = request.split_whitespace().nth(1).unwrap();
                let (path, query) = target.split_once('?').unwrap();
                assert_eq!(path, "/repos/o/x/actions/workflows/7/runs");
                let query: BTreeMap<_, _> = query
                    .split('&')
                    .map(|pair| {
                        let (key, value) = pair.split_once('=').unwrap();
                        (
                            key.to_owned(),
                            value
                                .replace("%2F", "/")
                                .replace("%20", " ")
                                .replace('+', " "),
                        )
                    })
                    .collect();
                assert_eq!(
                    query,
                    BTreeMap::from([
                        ("branch".to_owned(), "train/a b".to_owned()),
                        ("per_page".to_owned(), "1".to_owned())
                    ])
                );
                json!({"workflow_runs":[run(43, 11, "2026-10-12T00:01:00Z")]})
            }
            .to_string();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        });
    with_rest(&mut runtime, store, url);
    let reply = read(
        runtime,
        SUPERSEDED,
        "o/x",
        json!({"run_id":42}),
        Some("agent-x"),
    )
    .await;
    server.join().unwrap();
    assert_eq!(reply["result"]["superseded"], true, "{reply}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn superseded_missing_run_has_a_named_refusal() {
    let (mut runtime, store, _, _scratch) = setup();
    let (url, server) =
        crate::test_http::FixedRequestServer::start(1, "missing run", |_, request| {
            assert!(request.starts_with("GET /repos/o/x/actions/runs/42 "));
            "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".into()
        });
    with_rest(&mut runtime, store, url);
    let reply = read(
        runtime,
        SUPERSEDED,
        "o/x",
        json!({"run_id":42}),
        Some("agent-x"),
    )
    .await;
    server.join().unwrap();
    assert_eq!(reply["error"]["code"], "run_not_found", "{reply}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn superseded_both_legs_require_basals_invoke_grant() {
    for selector in [
        "get_workflow_run_metadata",
        "list_workflow_runs_for_workflow",
    ] {
        let (runtime, store, transport, _scratch) = setup();
        store.revoke_grant("direct", "basal-actions").unwrap();
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "one-leg".into(),
                principal: "direct".into(),
                connection_id: "conn-github-actions".into(),
                grantee_principal: "reserved:basal".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec![selector.into()],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
        let reply = read(runtime, SUPERSEDED, "o/x", json!({"run_id":42}), None).await;
        assert!(reply.get("error").is_some(), "{reply}");
        assert_eq!(
            transport.requests().len(),
            usize::from(selector == "get_workflow_run_metadata")
        );
    }
}
