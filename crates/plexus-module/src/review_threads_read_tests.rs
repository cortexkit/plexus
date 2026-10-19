use super::job_log_tests::flow;
use super::*;

const ACTION: &str = "github.pr.review_threads";

fn setup() -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    let setup = imported_runtime_with_actions(&[ACTION]);
    setup
        .1
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "basal-review-threads".into(),
            principal: "direct".into(),
            connection_id: "github-handle-app-x".into(),
            grantee_principal: "reserved:basal".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec![ACTION.into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    setup
}

fn page(index: usize, more: bool) -> Value {
    json!({"data":{"repository":{"pullRequest":{"reviewThreads":{
        "nodes":[{"id":format!("PRRT_{index}"),"isResolved":index == 1,"isOutdated":false,
            "path":"src/example.rs","line":17,"comments":{"nodes":[{
                "author":{"login":"synthetic-reviewer[bot]","__typename":"Bot"},
                "body":"é🦀".repeat(751),"url":"https://github.com/o/x/pull/7#discussion_r1"
            }]}}],"pageInfo":{"hasNextPage":more,"endCursor":format!("cursor-{index}")}
    }}}}})
}

async fn read(
    runtime: Arc<ModuleState>,
    repository: &str,
    args: Value,
    agent: Option<&str>,
) -> Value {
    send_facade_frame(
        runtime,
        manifest::GITHUB_READ_TOOL,
        json!({"action":ACTION,"repository":repository,"args":args}),
        "basal",
        Some(flow(agent)),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_threads_page_cap_never_requests_a_fourth_page() {
    let (runtime, _store, transport, scratch) = setup();
    transport.set_response_sequence_for_method(
        ACTION,
        "",
        (1..=4)
            .map(|index| MockResponse::Success(page(index, true)))
            .collect(),
    );
    let reply = read(runtime, "O/X", json!({"pr":7}), Some("agent-x")).await;
    assert_eq!(
        transport.requests().len(),
        3,
        "review thread reads must never request a fourth page"
    );
    assert_eq!(reply["result"]["incomplete"], true, "{reply}");
    let threads = reply["result"]["threads"].as_array().unwrap();
    assert_eq!(threads.len(), 3);
    assert_eq!(
        threads[0],
        json!({"thread_id":"PRRT_1","is_resolved":true,"is_outdated":false,
        "path":"src/example.rs","line":17,"author_login":"synthetic-reviewer[bot]","author_is_bot":true,
        "body_excerpt":"é🦀".repeat(750),"url":"https://github.com/o/x/pull/7#discussion_r1"})
    );
    for (index, request) in transport.requests().iter().enumerate() {
        assert_eq!(request.connection_id, "github-handle-app-x");
        assert_eq!(
            request.args,
            json!({"owner":"o","repo":"x","variables":{"owner":"o","repo":"x","pr":7,
            "after":if index == 0 {Value::Null} else {json!(format!("cursor-{index}"))}}})
        );
    }
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    let dispatched: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM audit_journal WHERE action=?1 AND outcome='completed'",
            [ACTION],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(dispatched, 3);
    let quota: i64 = db
        .query_row("SELECT COUNT(*) FROM github_actions_quota", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        quota, 0,
        "App GraphQL reads must not debit the personal-token Actions quota"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_threads_refuses_caller_graphql_and_pagination_arguments() {
    for field in [
        "query",
        "variables",
        "after",
        "page",
        "per_page",
        "owner",
        "repo",
        "repository",
    ] {
        let (runtime, _, transport, _scratch) = setup();
        transport.set_response(MockResponse::Success(page(1, false)));
        let reply = read(
            runtime,
            "o/x",
            json!({"pr":7,(field):"caller-supplied"}),
            None,
        )
        .await;
        assert_eq!(
            reply["error"]["code"], "review_threads_arguments_invalid",
            "caller GraphQL and pagination must be refused: {reply}"
        );
        assert!(transport.requests().is_empty());
    }
    for args in [
        json!({}),
        json!({"pr":0}),
        json!({"pr":-1}),
        json!({"pr":1.5}),
        json!({"pr":"7"}),
        json!({"pr":2147483648_u64}),
    ] {
        let (runtime, _, transport, _scratch) = setup();
        let reply = read(runtime, "o/x", args, None).await;
        assert_eq!(
            reply["error"]["code"], "review_threads_arguments_invalid",
            "{reply}"
        );
        assert!(transport.requests().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_threads_reuses_issue_read_visibility_and_grants_without_fallback() {
    for (repository, agent, grant, expected) in [
        ("o/x", Some("agent-x"), true, None),
        ("o/x", None, true, None),
        (
            "o/x",
            Some("other-agent"),
            true,
            Some("repository_not_visible"),
        ),
        ("o/missing", None, true, Some("repository_unbound")),
        ("o/x", None, false, Some("module_grant_absent")),
    ] {
        let (runtime, store, transport, _scratch) = setup();
        if !grant {
            store
                .revoke_grant("direct", "basal-review-threads")
                .unwrap();
        }
        transport.set_response(MockResponse::Success(page(1, false)));
        let reply = read(runtime, repository, json!({"pr":7}), agent).await;
        if let Some(expected) = expected {
            assert_eq!(reply["error"]["code"], expected, "{reply}");
            assert!(transport.requests().is_empty());
        } else {
            assert_eq!(reply["result"]["incomplete"], false, "{reply}");
            assert_eq!(transport.requests().len(), 1);
            assert_eq!(transport.requests()[0].connection_id, "github-handle-app-x");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_threads_refuses_partial_graphql_and_bad_page_shapes() {
    let mut partial = page(1, false);
    partial["errors"] = json!([{"message":"private vendor detail"}]);
    for response in [
        partial,
        json!({"data":{"repository":null}}),
        json!({"data":null}),
    ] {
        let (runtime, _, transport, _scratch) = setup();
        transport.set_response(MockResponse::Success(response));
        let reply = read(runtime, "o/x", json!({"pr":7}), None).await;
        assert!(reply.get("error").is_some(), "{reply}");
        assert!(!reply.to_string().contains("private vendor detail"));
    }
}
