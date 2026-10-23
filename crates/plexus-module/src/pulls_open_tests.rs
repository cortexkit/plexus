use super::*;

fn pr(number: u64, head: &str, mergeable: &str) -> Value {
    json!({"number":number,"headRefName":head,"headRefOid":"abcdef","updatedAt":"2026-10-23T09:00:00Z",
        "mergeable":mergeable,"isInMergeQueue":false,
        "reviewThreads":{"nodes":[{"isResolved":false},{"isResolved":true}],"pageInfo":{"hasNextPage":false}}})
}

fn response(nodes: Vec<Value>, more: bool) -> MockResponse {
    MockResponse::Success(json!({"data":{"repository":{"pullRequests":{
        "nodes":nodes,"pageInfo":{"hasNextPage":more}}}}}))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pulls_open_shape_filter_and_unknown_are_verbatim() {
    let (runtime, store, transport, _scratch) = bot_runtime();
    transport.set_response(response(
        vec![
            pr(1, "land/a", "CONFLICTING"),
            pr(2, "land/b", "UNKNOWN"),
            pr(3, "other", "MERGEABLE"),
        ],
        false,
    ));
    let reply = read(
        &runtime,
        Some(head(Some("agent-x"))),
        "github.pulls.open",
        "O/X",
        json!({"head_prefix":"land/"}),
    )
    .await;
    assert_eq!(
        reply["result"],
        json!({"repository":"o/x","truncated":false,"prs":[
        {"number":1,"headRefName":"land/a","headRefOid":"abcdef","updatedAt":"2026-10-23T09:00:00Z","mergeable":"CONFLICTING","isInMergeQueue":false,"unresolved_threads":1,"threads_truncated":false},
        {"number":2,"headRefName":"land/b","headRefOid":"abcdef","updatedAt":"2026-10-23T09:00:00Z","mergeable":"UNKNOWN","isInMergeQueue":false,"unresolved_threads":1,"threads_truncated":false}]})
    );
    let sent = transport.requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].connection_id, "github-handle-app-x");
    assert_eq!(
        sent[0].args,
        json!({"owner":"o","repo":"x","variables":{"owner":"o","repo":"x"}})
    );
    assert_eq!(
        store
            .github_bot_reads_in_window("app-x", plexus_core::now_ms())
            .unwrap(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pulls_open_reports_both_hundred_node_bounds() {
    let (runtime, _store, transport, _scratch) = bot_runtime();
    let nodes = (1..=100)
        .map(|n| {
            let mut node = pr(n, "land/a", "MERGEABLE");
            node["reviewThreads"]["nodes"] = json!(
                (0..100)
                    .map(|n| json!({"isResolved":n%2==0}))
                    .collect::<Vec<_>>()
            );
            node["reviewThreads"]["pageInfo"]["hasNextPage"] = json!(true);
            node["isInMergeQueue"] = json!(true);
            node
        })
        .collect();
    transport.set_response(response(nodes, true));
    let reply = read(
        &runtime,
        Some(worker(Some("agent-x"))),
        "github.pulls.open",
        "o/x",
        json!({}),
    )
    .await;
    assert_eq!(reply["result"]["prs"].as_array().unwrap().len(), 100);
    assert_eq!(reply["result"]["truncated"], true);
    for pr in reply["result"]["prs"].as_array().unwrap() {
        assert_eq!(pr["threads_truncated"], true);
        assert_eq!(pr["unresolved_threads"], 50);
        assert_eq!(pr["isInMergeQueue"], true);
    }
    assert_eq!(
        transport.requests().len(),
        1,
        "one snapshot, never a pagination walk"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pulls_open_refuses_identity_visibility_budget_and_caller_graphql() {
    let (runtime, store, transport, _scratch) = bot_runtime();
    for (scope, repo, args, code) in [
        (None, "o/x", json!({}), "agent_identity_required"),
        (
            Some(head(Some("agent-y"))),
            "o/x",
            json!({}),
            "repository_not_visible",
        ),
        (
            Some(head(Some("agent-x"))),
            "o/y",
            json!({}),
            "repository_not_visible",
        ),
        (
            Some(head(Some("agent-x"))),
            "o/x",
            json!({"head_prefix":""}),
            "endpoint_not_allowed",
        ),
        (
            Some(head(Some("agent-x"))),
            "o/x",
            json!({"query":"query { viewer { login } }"}),
            "endpoint_not_allowed",
        ),
        (
            Some(head(Some("agent-x"))),
            "o/x",
            json!({"variables":{"owner":"other"}}),
            "endpoint_not_allowed",
        ),
    ] {
        let reply = read(&runtime, scope, "github.pulls.open", repo, args.clone()).await;
        not_sent(&reply, code);
        if args.get("head_prefix").is_some() {
            assert_eq!(reply["error"]["field"], "head_prefix");
        }
    }
    let now = plexus_core::now_ms();
    for _ in 0..350 {
        store.reserve_github_bot_read("app-x", 10, now).unwrap();
    }
    let reply = read(
        &runtime,
        Some(head(Some("agent-x"))),
        "github.pulls.open",
        "o/x",
        json!({}),
    )
    .await;
    not_sent(&reply, "read_budget_exhausted");
    assert!(reply["error"]["retry_after_ms"].as_i64().unwrap() > 0);
    assert!(transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pulls_open_graphql_errors_refuse_even_with_partial_data() {
    let (runtime, _store, transport, _scratch) = bot_runtime();
    transport.set_response(MockResponse::Success(
        json!({"errors":[{"message":"private vendor detail"}],
        "data":{"repository":{"pullRequests":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}),
    ));
    let reply = read(
        &runtime,
        Some(head(Some("agent-x"))),
        "github.pulls.open",
        "o/x",
        json!({}),
    )
    .await;
    assert_eq!(reply["error"]["code"], "read_response_invalid");
    assert_eq!(reply["isError"], true);
    assert!(reply.get("structuredContent").is_none());
    assert!(!reply.to_string().contains("private vendor detail"));
    transport.set_response(MockResponse::VendorError {
        code: "http_403".into(),
        message: String::new(),
    });
    let reply = read(
        &runtime,
        Some(head(Some("agent-x"))),
        "github.pulls.open",
        "o/x",
        json!({}),
    )
    .await;
    assert_eq!(reply["error"]["code"], "vendor_error");
    assert_eq!(reply["error"]["status"], 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pulls_open_raw_invoke_cannot_bypass_bot_authority() {
    let (runtime, _store, transport, _scratch) = bot_runtime();
    let body = json!({"name":manifest::INVOKE_TOOL,"arguments":{"op":"call",
        "connection":"github-handle-app-x","action":"github.pulls.open",
        "args":{"owner":"o","repo":"x","variables":{"owner":"other","repo":"private"}}}});
    let reply: Value = serde_json::from_slice(
        &send_bound(&runtime, "aft", Some(head(Some("agent-x"))), &body).await,
    )
    .unwrap();
    assert_eq!(reply["error"]["code"], "github_read_required");
    assert!(transport.requests().is_empty());
}
