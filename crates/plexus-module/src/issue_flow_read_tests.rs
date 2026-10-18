use super::job_log_tests::flow;
use super::*;

fn setup() -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    let setup = imported_runtime();
    setup
        .1
        .import_github_handles(&[GithubImportRow {
            handle: GithubHandle {
                app_handle_id: "app-y".into(),
                agent_id: "agent-y".into(),
                app_id: 2,
                installation_id: None,
                credential_reference: "github_app:app-y".into(),
                credential_generation: 0,
                status: "enabled".into(),
                proven_at: None,
                connection_principal: "direct".into(),
                connection_id: "github-handle-app-y".into(),
            },
            repositories: vec!["o/y".into()],
            grants: vec![],
            module_actions: vec![
                "github.issue.get".into(),
                "github.issue_comments.list".into(),
                "github.issue.search".into(),
            ],
            policies: vec![],
        }])
        .unwrap();
    for app in ["x", "y"] {
        setup
            .1
            .insert_grant(&plexus_core::GrantInput {
                grant_id: format!("basal-issues-{app}"),
                principal: "direct".into(),
                connection_id: format!("github-handle-app-{app}"),
                grantee_principal: "reserved:basal".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec![
                    "github.issue.get".into(),
                    "github.issue_comments.list".into(),
                    "github.issue.search".into(),
                ],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
    }
    setup
}

fn cases() -> [(&'static str, Value, Value); 3] {
    [
        (
            "github.issue.get",
            json!({"issue_number":42}),
            json!({"number":42}),
        ),
        (
            "github.issue_comments.list",
            json!({"issue_number":42}),
            json!([{ "id":123 }]),
        ),
        (
            "github.issue.search",
            json!({"terms":"bug"}),
            json!({"items":[]}),
        ),
    ]
}

async fn read(
    runtime: Arc<ModuleState>,
    action: &str,
    repository: Value,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_flow_issue_reads_allow_own_repository() {
    for (action, args, response) in cases() {
        let (runtime, _, transport, _scratch) = setup();
        transport.set_response(MockResponse::Success(response.clone()));
        let repository = if action == "github.issue.search" {
            json!(["O/X"])
        } else {
            json!("O/X")
        };
        let reply = read(runtime, action, repository, args, Some("agent-x")).await;
        let expected = if action == "github.issue.search" {
            json!({"items":[],"total_count":0,"incomplete":true,"incomplete_results":true})
        } else { response };
        assert_eq!(reply["result"], expected, "{action}: {reply}");
        assert_eq!(transport.requests().len(), 1);
        assert_eq!(transport.requests()[0].connection_id, "github-handle-app-x");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_flow_issue_reads_refuse_foreign_repository_before_authority() {
    for grant_present in [true, false] {
        for (action, args, _) in cases() {
            let (runtime, store, transport, scratch) = setup();
            if !grant_present {
                store.revoke_grant("direct", "basal-issues-y").unwrap();
            }
            let repository = if action == "github.issue.search" {
                json!(["o/y"])
            } else {
                json!("o/y")
            };
            let reply = read(runtime, action, repository, args, Some("agent-x")).await;
            assert_eq!(
                reply["error"],
                json!({"code":"repository_not_visible", "message":"repository_not_visible", "transmission":"not_sent"}),
                "{action}, grant_present={grant_present}: {reply}"
            );
            assert!(transport.requests().is_empty());
            assert!(store.list_audit("reserved:basal").unwrap().is_empty());
            let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
            let reservations: i64 = db
                .query_row("SELECT COUNT(*) FROM reservations", [], |row| row.get(0))
                .unwrap();
            assert_eq!(reservations, 0);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_flow_issue_search_checks_every_repository() {
    let (runtime, store, transport, _scratch) = setup();
    let reply = read(
        runtime,
        "github.issue.search",
        json!(["o/x", "o/y"]),
        json!({"terms":"bug"}),
        Some("agent-x"),
    )
    .await;
    assert_eq!(reply["error"]["code"], "repository_not_visible", "{reply}");
    assert_eq!(reply["error"]["transmission"], "not_sent");
    assert!(transport.requests().is_empty());
    assert!(store.list_audit("reserved:basal").unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_flow_issue_reads_allow_any_bound_repository() {
    for (action, args, response) in cases() {
        let (runtime, _, transport, _scratch) = setup();
        transport.set_response(MockResponse::Success(response.clone()));
        let repository = if action == "github.issue.search" {
            json!(["o/y"])
        } else {
            json!("o/y")
        };
        let reply = read(runtime, action, repository, args, None).await;
        let expected = if action == "github.issue.search" {
            json!({"items":[],"total_count":0,"incomplete":true,"incomplete_results":true})
        } else { response };
        assert_eq!(reply["result"], expected, "{action}: {reply}");
        assert_eq!(transport.requests().len(), 1);
        assert_eq!(transport.requests()[0].connection_id, "github-handle-app-y");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_flow_own_repository_still_requires_module_grant() {
    let (runtime, store, transport, _scratch) = setup();
    store.revoke_grant("direct", "basal-issues-x").unwrap();
    let reply = read(
        runtime,
        "github.issue.get",
        json!("o/x"),
        json!({"issue_number":42}),
        Some("agent-x"),
    )
    .await;
    assert_eq!(reply["error"]["code"], "module_grant_absent", "{reply}");
    assert!(transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_flow_agent_stamp_does_not_restrict_issue_reads() {
    let (runtime, _, transport, _scratch) = setup();
    transport.set_response(MockResponse::Success(json!({"number":42})));
    let scope = subc_protocol::scope::ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        "head",
        1,
        subc_protocol::scope::ScopeKind::Head,
    )
    .with_attributes(
        subc_protocol::scope::ScopeAttributes::new().with_agent_id(Some("agent-y".into())),
    );
    let reply = send_facade_frame(
        runtime,
        manifest::GITHUB_READ_TOOL,
        json!({"action":"github.issue.get","repository":"o/x","args":{"issue_number":42}}),
        "prefrontal-core",
        Some(scope),
    )
    .await;
    assert_eq!(reply["result"]["number"], 42, "{reply}");
    assert_eq!(transport.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue_and_actions_visibility_refusals_have_identical_errors() {
    let (runtime, _, transport, _scratch) = super::job_log_tests::actions_runtime();
    let issue = read(
        runtime.clone(),
        "github.issue.get",
        json!("o/x"),
        json!({"issue_number":42}),
        Some("agent-y"),
    )
    .await;
    let actions = read(
        runtime,
        "github.actions.job_log",
        json!("o/x"),
        json!({"job_id":42}),
        Some("agent-y"),
    )
    .await;
    assert_eq!(issue["error"]["code"], "repository_not_visible", "{issue}");
    assert_eq!(issue["error"]["transmission"], "not_sent");
    assert_eq!(issue["error"], actions["error"]);
    assert!(transport.requests().is_empty());
}
