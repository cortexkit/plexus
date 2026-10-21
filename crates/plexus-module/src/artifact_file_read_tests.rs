use super::job_log_tests::{actions_runtime, flow};
use super::*;

fn runtime() -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    let setup = actions_runtime();
    setup.2.set_response_for_method("list_workflow_run_artifacts", "", MockResponse::Success(json!({
        "total_count":1,"artifacts":[{"id":7,"name":"shard-1","created_at":"2026-10-12T00:00:00Z","expired":false,"size_in_bytes":123}]
    })));
    setup.2.set_response_for_method(
        "github.actions.artifact_file",
        "",
        MockResponse::Success(
            json!({"total_bytes":17,"truncated":false,"text":"test NAME FAILED\n"}),
        ),
    );
    setup
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
        json!({"action":"github.actions.artifact_file","repository":repository,"args":args}),
        "basal",
        Some(flow(agent)),
    )
    .await
}

fn args() -> Value {
    json!({"run_id":42,"artifact":"shard-1","path":"logs/shard.log"})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn artifact_flow_visibility_uses_the_agents_bot_bindings() {
    let (runtime, _, transport, _scratch) = runtime();
    for (repository, agent) in [("o/unbound", "agent-x"), ("o/x", "agent-other")] {
        let reply = read(runtime.clone(), repository, args(), Some(agent)).await;
        assert_eq!(reply["error"]["code"], "repository_not_visible", "{reply}");
        assert!(transport.requests().is_empty());
    }
    let reply = read(runtime, "O/X", args(), Some("agent-x")).await;
    assert_eq!(reply["result"]["repository"], "o/x", "{reply}");
    assert_eq!(reply["result"]["run_id"], 42);
    let requests = transport.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|request| request.connection_id == "conn-github-actions"));
    assert_eq!(requests[1].args["max_bytes"], 65536);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn artifact_arguments_are_bounded_before_dispatch() {
    let (runtime, _, transport, _scratch) = runtime();
    for invalid in [
        json!({"run_id":42,"artifact":"shard-1","path":"log","max_bytes":262145}),
        json!({"run_id":0,"artifact":"shard-1","path":"log"}),
        json!({"run_id":42,"artifact":"shard-1","path":"../bad"}),
        json!({"run_id":42,"artifact":"shard-1","path":"log","owner":"other"}),
    ] {
        let reply = read(runtime.clone(), "o/x", invalid, Some("agent-x")).await;
        assert_eq!(
            reply["error"]["code"], "artifact_arguments_invalid",
            "{reply}"
        );
    }
    assert!(transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn artifact_legs_each_require_their_own_grant() {
    for selectors in [
        vec!["list_workflow_run_artifacts"],
        vec!["github.actions.artifact_file"],
    ] {
        let (runtime, store, transport, _scratch) = runtime();
        store.revoke_grant("direct", "basal-actions").unwrap();
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "one-leg".into(),
                principal: "direct".into(),
                connection_id: "conn-github-actions".into(),
                grantee_principal: "reserved:basal".into(),
                risk_ceiling: "read".into(),
                action_selectors: selectors.iter().map(|name| (*name).into()).collect(),
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
        let reply = read(runtime, "o/x", args(), Some("agent-x")).await;
        assert!(reply.get("error").is_some(), "{reply}");
        assert_eq!(
            transport.requests().len(),
            usize::from(selectors[0] == "list_workflow_run_artifacts")
        );
    }
}
