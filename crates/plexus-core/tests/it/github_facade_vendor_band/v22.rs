use super::*;
use plexus_core::governance::AuthorizationRequest;
use plexus_core::rest_api::{RestConfig, RestTransport};
use std::collections::BTreeSet;
use std::sync::Mutex;

const THREAD: &str = "PRRT_kwDOAbc123";
const THREAD_READ: &str = "query($threadId: ID!) { node(id: $threadId) { ... on PullRequestReviewThread { id pullRequest { number repository { nameWithOwner } } } } }";
const RESOLVE: &str = "mutation($threadId: ID!) { resolveReviewThread(input: {threadId: $threadId}) { thread { id isResolved } } }";
const UNRESOLVE: &str = "mutation($threadId: ID!) { unresolveReviewThread(input: {threadId: $threadId}) { thread { id isResolved } } }";

pub(super) struct Run {
    store: Arc<PlexusStore>,
    engine: GovernanceEngine<plexus_core::credentials::StubCredentialSource, RestTransport>,
    scope: CallScope,
    sent: Arc<Mutex<Vec<String>>>,
    pub(super) server: validation_http::FixedRequestServer,
    _scratch: plexus_core::test_scratch::Scratch,
}

impl Run {
    pub(super) fn new(responses: Vec<Value>) -> Self {
        Self::with_statuses(
            responses
                .into_iter()
                .map(|value| (if value.is_null() { 204 } else { 200 }, value))
                .collect(),
        )
    }

    fn with_statuses(responses: Vec<(u16, Value)>) -> Self {
        Self::with_headers(responses, "")
    }

    pub(super) fn with_headers(responses: Vec<(u16, Value)>, headers: &'static str) -> Self {
        let (scratch, store, _, _, scope) = setup(
            "v22",
            &[
                ("github.issue_comment.get", "read"),
                ("update_issue_comment", "write"),
                ("github.pull_request.get", "read"),
                ("github.review_thread.get", "read"),
                ("github.stack.get", "read"),
                ("edit_pull_request", "write"),
                ("reply_to_review_comment", "write"),
                ("resolve_review_thread", "write"),
                ("unresolve_review_thread", "write"),
                ("create_pull_request_stack", "write"),
                ("add_to_pull_request_stack", "write"),
                ("unstack_pull_requests", "write"),
                ("mark_pull_request_ready", "write"),
                ("convert_pull_request_to_draft", "write"),
                ("github.pull_request.queue_state.get", "read"),
                ("enqueue_pull_request", "write"),
                ("dequeue_pull_request", "write"),
            ],
        );
        let sent = Arc::new(Mutex::new(Vec::new()));
        let capture = sent.clone();
        let (endpoint, server) = validation_http::FixedRequestServer::start(
            responses.len(),
            "v22",
            move |index, raw| {
                capture.lock().unwrap().push(raw.to_owned());
                let (status, value) = &responses[index];
                if *status == 204 {
                    return "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into();
                }
                let body = value.to_string();
                format!("HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n{body}", body.len())
            },
        );
        let manifest = github_manifest();
        let config = RestConfig::new(endpoint)
            .with_bindings(manifest.credential_bindings)
            .with_actions(
                manifest
                    .actions_baseline
                    .into_iter()
                    .map(|a| (a.name, a.http.unwrap()))
                    .collect(),
            );
        let engine = GovernanceEngine::new(
            store.clone(),
            Arc::new(
                plexus_core::credentials::StubCredentialSource::with_default_success(
                    b"test".to_vec(),
                ),
            ),
            Arc::new(RestTransport::new(config)),
        )
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: Some(Arc::new(Token)),
        }))
        .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
        Self {
            store,
            engine,
            scope,
            sent,
            server,
            _scratch: scratch,
        }
    }

    pub(super) fn call(&self, request: &Value) -> Value {
        bot_request_scoped(
            &self.store,
            &self.engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&self.scope),
            request,
            "v22-nonce",
            "v22-id",
            "worker",
            plexus_core::storage::now_ms(),
        )
    }

    pub(super) fn wire(&self) -> Vec<(String, Value)> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|raw| {
                let (head, body) = raw.split_once("\r\n\r\n").unwrap();
                (
                    head.lines().next().unwrap().to_owned(),
                    if body.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_str(body).unwrap()
                    },
                )
            })
            .collect()
    }
}

/// Every request carries the envelope the real gh shim stamps on each
/// `gh.route` call, so these cases exercise the wire AFT sends, not a
/// payload-only shape that production never receives.
fn request(action: &str, target: Value, body: Value) -> Value {
    let mut value = json!({"operation":"gh.route", "gh_route_schema":1, "action":action,
        "repository":"org/repo", "manifest_version":22, "rung_as_of_unix_secs":1793066213,
        "metadata":{"agent_id":"alfonso-aft", "pid":4242}, "target":target, "body":body});
    if action == "pr edit" {
        value["author_scope"] = json!("own");
    }
    value
}

fn pr(number: u64) -> Value {
    json!({"number":number, "html_url":format!("https://github.com/org/repo/pull/{number}"),
        "user":{"login":"app-fixture[bot]", "type":"Bot"}, "base":{"repo":{"url":"https://api.github.com/repos/org/repo"}}})
}

fn stack() -> Value {
    json!({"number":3, "url":"https://api.github.com/repos/org/repo/stacks/3", "pull_requests":[pr(7),pr(8)]})
}

fn thread_read(repo: &str) -> Value {
    json!({"data":{"node":{"id":THREAD, "pullRequest":{"number":7, "repository":{"nameWithOwner":repo}}}}})
}

type Case = (Value, Vec<Value>, Vec<(String, Value)>, Value);

fn cases() -> Vec<Case> {
    let mut result = vec![
        (
            request(
                "pr edit",
                json!({"number":"7"}),
                json!({"title":"T", "body":"B"}),
            ),
            vec![pr(7), pr(7)],
            vec![
                ("GET /repos/org/repo/pulls/7 HTTP/1.1".into(), Value::Null),
                (
                    "PATCH /repos/org/repo/pulls/7 HTTP/1.1".into(),
                    json!({"title":"T", "body":"B"}),
                ),
            ],
            json!({"url":"https://github.com/org/repo/pull/7", "number":7}),
        ),
        (
            request(
                "api:POST:/repos/*/*/pulls/*/comments/*/replies",
                json!({"number":"7", "comment_id":"99"}),
                json!({"body":"Fixed in the next push"}),
            ),
            vec![
                json!({"id":100, "html_url":"https://github.com/org/repo/pull/7#discussion_r100"}),
            ],
            vec![(
                "POST /repos/org/repo/pulls/7/comments/99/replies HTTP/1.1".into(),
                json!({"body":"Fixed in the next push"}),
            )],
            json!({"id":100, "url":"https://github.com/org/repo/pull/7#discussion_r100"}),
        ),
    ];
    for (action, name, query, resolved) in [
        (
            "graphql resolvereviewthread",
            "resolveReviewThread",
            RESOLVE,
            true,
        ),
        (
            "graphql unresolvereviewthread",
            "unresolveReviewThread",
            UNRESOLVE,
            false,
        ),
    ] {
        let mut responses = vec![thread_read("org/repo")];
        let mut expected = vec![(
            "POST /graphql HTTP/1.1".into(),
            json!({"query":THREAD_READ, "variables":{"threadId":THREAD}}),
        )];
        if resolved {
            responses.push(pr(7));
            expected.push(("GET /repos/org/repo/pulls/7 HTTP/1.1".into(), Value::Null));
        }
        responses.push(json!({"data":{name:{"thread":{"id":THREAD,"isResolved":resolved}}}}));
        expected.push((
            "POST /graphql HTTP/1.1".into(),
            json!({"query":query, "variables":{"threadId":THREAD}}),
        ));
        result.push((
            request(action, json!({"thread_id":THREAD}), json!({})),
            responses,
            expected,
            json!({"id":THREAD,"resolved":resolved}),
        ));
    }
    for (action, target, path) in [
        (
            "api:POST:/repos/*/*/stacks",
            json!({}),
            "/repos/org/repo/stacks",
        ),
        (
            "api:POST:/repos/*/*/stacks/*/add",
            json!({"stack_number":"3"}),
            "/repos/org/repo/stacks/3/add",
        ),
    ] {
        result.push((
            request(action, target, json!({"pull_requests":[7,8]})),
            vec![pr(7), pr(8), stack()],
            vec![
                ("GET /repos/org/repo/pulls/7 HTTP/1.1".into(), Value::Null),
                ("GET /repos/org/repo/pulls/8 HTTP/1.1".into(), Value::Null),
                (
                    format!("POST {path} HTTP/1.1"),
                    json!({"pull_requests":[7,8]}),
                ),
            ],
            json!({"url":"https://api.github.com/repos/org/repo/stacks/3", "number":3}),
        ));
    }
    for response in [stack(), Value::Null] {
        let projection = if response.is_null() {
            json!({"dissolved":true})
        } else {
            json!({"url":"https://api.github.com/repos/org/repo/stacks/3", "number":3, "dissolved":false})
        };
        result.push((
            request(
                "api:POST:/repos/*/*/stacks/*/unstack",
                json!({"stack_number":"3"}),
                json!({}),
            ),
            vec![stack(), response],
            vec![
                ("GET /repos/org/repo/stacks/3 HTTP/1.1".into(), Value::Null),
                (
                    "POST /repos/org/repo/stacks/3/unstack HTTP/1.1".into(),
                    Value::Null,
                ),
            ],
            projection,
        ));
    }
    result
}

#[test]
fn every_v22_kind_sends_exactly_its_reviewed_requests_and_replays() {
    for (request, responses, expected, projection) in cases() {
        let last = responses.len() - 1;
        let run = Run::with_statuses(
            responses
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let status = if value.is_null() {
                        204
                    } else if index == last && request["action"] == "api:POST:/repos/*/*/stacks" {
                        201
                    } else {
                        200
                    };
                    (status, value)
                })
                .collect(),
        );
        let first = run.call(&request);
        assert_eq!(
            first["result"],
            json!({"status":"completed","result":projection}),
            "{request}: {first}"
        );
        assert_eq!(run.wire(), expected, "{request}");
        assert_eq!(run.call(&request)["result"], first["result"]);
        assert_eq!(
            run.wire(),
            expected,
            "nonce replay contacted GitHub: {request}"
        );
        for raw in run
            .sent
            .lock()
            .unwrap()
            .iter()
            .filter(|raw| raw.lines().next().unwrap().contains("/stacks"))
        {
            assert!(
                raw.to_ascii_lowercase()
                    .contains("accept: application/vnd.github+json\r\n"),
                "{raw}"
            );
            assert!(raw
                .to_ascii_lowercase()
                .contains("x-github-api-version: 2026-03-10\r\n"));
        }
        run.server.join().unwrap();
    }
}

#[test]
fn every_v22_kind_refuses_extra_body_fields_by_name_without_contact() {
    for (mut request, _, _, _) in cases() {
        request["body"]["unexpected"] = json!("never sent");
        let run = Run::new(vec![]);
        let reply = run.call(&request);
        assert_eq!(
            reply["result"]["refusal_code"], "request_field_forbidden{field: unexpected}",
            "{reply}"
        );
        assert!(run.wire().is_empty());
        run.server.join().unwrap();
    }
}

#[test]
fn v22_thread_repository_pre_read_refuses_ordinary_invoke_even_with_matching_grants() {
    let run = Run::new(vec![]);
    let request = AuthorizationRequest::new(
        plexus_core::github::AFT_PRINCIPAL,
        "conn-fixture",
        "github.review_thread.get",
        json!({"repository":"org/repo", "owner":"org", "repo":"repo", "variables":{"threadId":THREAD}}),
    ).with_bound_agent("agent-fixture", "app-fixture");
    assert_eq!(
        run.engine.authorize(request),
        Err(plexus_core::governance::Denial::BotActionRequiresFacade)
    );
    assert!(run.wire().is_empty());
    assert!(run
        .store
        .list_action_requests(plexus_core::github::AFT_PRINCIPAL)
        .unwrap()
        .is_empty());
    run.server.join().unwrap();
}

#[test]
fn v22_ownership_and_repository_refusals_send_no_mutation_and_replay() {
    for human_type in ["User", "Bot"] {
        let mut human = pr(7);
        human["user"] = json!({"login":if human_type == "Bot" {"another[bot]"} else {"app-fixture[bot]"}, "type":human_type});
        for (request, responses) in [
            (
                request("pr edit", json!({"number":"7"}), json!({"title":"T"})),
                vec![human.clone()],
            ),
            (
                request(
                    "api:POST:/repos/*/*/stacks",
                    json!({}),
                    json!({"pull_requests":[7,8]}),
                ),
                vec![human.clone()],
            ),
            (
                request(
                    "api:POST:/repos/*/*/stacks/*/add",
                    json!({"stack_number":"3"}),
                    json!({"pull_requests":[7,8]}),
                ),
                vec![human.clone()],
            ),
            (
                request(
                    "api:POST:/repos/*/*/stacks/*/unstack",
                    json!({"stack_number":"3"}),
                    json!({}),
                ),
                vec![
                    json!({"number":3,"url":"https://api.github.com/repos/org/repo/stacks/3", "pull_requests":[pr(8),human.clone()]}),
                ],
            ),
        ] {
            let run = Run::new(responses);
            let first = run.call(&request);
            assert_eq!(
                first["result"]["refusal_code"],
                if request["action"] == "pr edit" {
                    "pr_edit_not_own"
                } else {
                    "stack_pr_not_own"
                },
                "{first}"
            );
            if request["action"] == "pr edit" {
                let message = first["result"]["detail"]["message"].as_str().unwrap();
                assert!(message.contains("#7 was opened by "));
                assert!(message.contains("GH_SHIM_BYPASS=operator"));
            } else {
                assert_eq!(first["result"]["detail"]["number"], 7);
                assert_eq!(
                    first["result"]["detail"]["author_login"],
                    human["user"]["login"]
                );
            }
            assert_eq!(run.call(&request)["result"], first["result"]);
            assert_eq!(run.wire().len(), 1);
            assert!(run.wire()[0].0.starts_with("GET "));
            run.server.join().unwrap();
        }
    }
    for action in [
        "graphql resolvereviewthread",
        "graphql unresolvereviewthread",
    ] {
        for (response, code) in [
            (thread_read("foreign/repo"), "agent_repository_conflict"),
            (json!({"data":{"node":null}}), "not_present"),
            (json!({"data":{"node":{"id":THREAD}}}), "not_present"),
        ] {
            let run = Run::new(vec![response]);
            let request = request(action, json!({"thread_id":THREAD}), json!({}));
            let first = run.call(&request);
            assert_eq!(first["result"]["refusal_code"], code, "{first}");
            assert!(!first.to_string().contains("private vendor canary"));
            assert_eq!(run.call(&request)["result"], first["result"]);
            assert_eq!(
                run.wire(),
                vec![(
                    "POST /graphql HTTP/1.1".into(),
                    json!({"query":THREAD_READ,"variables":{"threadId":THREAD}})
                )]
            );
            run.server.join().unwrap();
        }
    }
    for foreign_member in [false, true] {
        let mut response = stack();
        if foreign_member {
            response["pull_requests"][0]["base"]["repo"]["url"] =
                json!("https://api.github.com/repos/foreign/repo");
        } else {
            response["url"] = json!("https://api.github.com/repos/foreign/repo/stacks/3");
        }
        let run = Run::new(vec![response]);
        let request = request(
            "api:POST:/repos/*/*/stacks/*/unstack",
            json!({"stack_number":"3"}),
            json!({}),
        );
        let first = run.call(&request);
        assert_eq!(
            first["result"]["refusal_code"], "agent_repository_conflict",
            "{first}"
        );
        assert_eq!(run.call(&request)["result"], first["result"]);
        assert_eq!(run.wire().len(), 1);
        run.server.join().unwrap();
    }
}

#[test]
fn v22_graphql_pre_read_errors_release_claim_and_retry_without_mutation() {
    let error = json!({"errors":[{"message":"private vendor canary"}]});
    for action in [
        "graphql resolvereviewthread",
        "graphql unresolvereviewthread",
    ] {
        let run = Run::new(vec![error.clone(), error.clone()]);
        let request = request(action, json!({"thread_id":THREAD}), json!({}));
        let first = run.call(&request);
        assert_eq!(
            first["result"],
            json!({"status":"refused", "refusal_code":"vendor_rejected{status: 422}", "retry_same_nonce":true, "transmission":"not_sent"})
        );
        assert!(!first.to_string().contains("private vendor canary"));
        let row = run
            .store
            .github_receipt("agent-fixture", "v22-nonce")
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "pending");
        assert!(row.claim_owner.is_none());
        assert_eq!(run.call(&request)["result"], first["result"]);
        assert_eq!(
            run.wire(),
            vec![
                (
                    "POST /graphql HTTP/1.1".into(),
                    json!({"query":THREAD_READ,"variables":{"threadId":THREAD}})
                );
                2
            ]
        );
        run.server.join().unwrap();
    }
}

#[test]
fn v22_resolve_thread_refuses_non_owned_pr_without_mutation_and_replays() {
    for (author, user_type) in [
        ("outside-contributor", "User"),
        ("another[bot]", "Bot"),
        ("app-fixture[bot]", "User"),
    ] {
        let mut pull_request = pr(7);
        pull_request["user"] = json!({"login":author, "type":user_type});
        let run = Run::new(vec![thread_read("org/repo"), pull_request]);
        let request = request(
            "graphql resolvereviewthread",
            json!({"thread_id":THREAD}),
            json!({}),
        );
        let first = run.call(&request);
        assert_eq!(
            first["result"],
            json!({
                "status":"refused", "refusal_code":"review_thread_not_own",
                "code":"review_thread_not_own", "retry_same_nonce":false,
                "transmission":"not_sent",
                "detail":{
                    "number":7, "author_login":author,
                    "message":format!("'resolveReviewThread' works only on pull requests this repository's bot opened (app-fixture[bot]); #7 was opened by {author}. Reply to the finding as the bot, then resolve the thread as the operator.")
                }
            })
        );
        assert_eq!(run.call(&request)["result"], first["result"]);
        assert_eq!(
            run.wire(),
            vec![
                (
                    "POST /graphql HTTP/1.1".into(),
                    json!({"query":THREAD_READ,"variables":{"threadId":THREAD}})
                ),
                ("GET /repos/org/repo/pulls/7 HTTP/1.1".into(), Value::Null),
            ]
        );
        run.server.join().unwrap();
    }
}

#[test]
fn v22_resolve_thread_requires_parent_pr_number_before_pr_read() {
    for number in [Value::Null, json!(0), json!(-1), json!("7")] {
        let mut thread = thread_read("org/repo");
        thread["data"]["node"]["pullRequest"]["number"] = number;
        let run = Run::new(vec![thread]);
        let request = request(
            "graphql resolvereviewthread",
            json!({"thread_id":THREAD}),
            json!({}),
        );
        let reply = run.call(&request);
        assert_eq!(
            reply["result"]["refusal_code"],
            "pre_dispatch_read_incomplete{reason: invalid_response}",
            "{reply}"
        );
        assert_eq!(reply["result"]["retry_same_nonce"], true);
        assert_eq!(
            run.wire(),
            vec![(
                "POST /graphql HTTP/1.1".into(),
                json!({"query":THREAD_READ,"variables":{"threadId":THREAD}}),
            )]
        );
        run.server.join().unwrap();
    }
}

#[test]
fn v22_refuses_bad_ids_lists_empty_edits_and_caller_queries_without_contact() {
    let mut invalid = vec![(request("pr edit", json!({"number":"7"}), json!({})), "body")];
    for field in ["state", "maintainer_can_modify", "title_typo"] {
        invalid.push((
            request("pr edit", json!({"number":"7"}), json!({field:true})),
            field,
        ));
    }
    for action in [
        "api:POST:/repos/*/*/stacks",
        "api:POST:/repos/*/*/stacks/*/add",
    ] {
        for list in [
            json!([]),
            json!([7, 7]),
            json!([0]),
            json!([-1]),
            json!(["7"]),
            json!(vec![1; 51]),
        ] {
            let target = if action.ends_with("/add") {
                json!({"stack_number":"3"})
            } else {
                json!({})
            };
            invalid.push((
                request(action, target, json!({"pull_requests":list})),
                "pull_requests",
            ));
        }
    }
    for (action, target, body, field) in [
        (
            "pr edit",
            json!({"number":"0"}),
            json!({"title":"T"}),
            "number",
        ),
        (
            "api:POST:/repos/*/*/pulls/*/comments/*/replies",
            json!({"number":"7","comment_id":"0"}),
            json!({"body":"B"}),
            "comment_id",
        ),
        (
            "api:POST:/repos/*/*/pulls/*/comments/*/replies",
            json!({"number":"-1","comment_id":"99"}),
            json!({"body":"B"}),
            "number",
        ),
        (
            "api:POST:/repos/*/*/stacks/*/unstack",
            json!({"stack_number":0}),
            json!({}),
            "stack_number",
        ),
        (
            "graphql resolvereviewthread",
            json!({"thread_id":""}),
            json!({}),
            "thread_id",
        ),
    ] {
        invalid.push((request(action, target, body), field));
    }
    for action in [
        "graphql resolvereviewthread",
        "graphql unresolvereviewthread",
    ] {
        let mut value = request(action, json!({"thread_id":THREAD}), json!({}));
        value["query"] = json!("mutation { arbitrary }");
        invalid.push((value, "query"));
        invalid.push((
            request(
                action,
                json!({"thread_id":THREAD}),
                json!({"query":"arbitrary"}),
            ),
            "query",
        ));
    }
    // Retargeting a PR's base changes what it merges into, so pr edit refuses
    // it by name even alongside fields it does admit.
    invalid.push((
        request(
            "pr edit",
            json!({"number":"7"}),
            json!({"title":"T", "base":"stack/parent"}),
        ),
        "base",
    ));
    for (request, field) in invalid {
        let run = Run::new(vec![]);
        let reply = run.call(&request);
        assert_eq!(
            reply["result"]["refusal_code"],
            format!("request_field_forbidden{{field: {field}}}"),
            "{request}: {reply}"
        );
        assert!(run.wire().is_empty());
        run.server.join().unwrap();
    }
}

#[test]
fn v22_graphql_mutation_errors_are_sanitized_and_bad_preview_replies_are_unknown() {
    for action in [
        "graphql resolvereviewthread",
        "graphql unresolvereviewthread",
    ] {
        let mut responses = vec![thread_read("org/repo")];
        if action == "graphql resolvereviewthread" {
            responses.push(pr(7));
        }
        responses.push(json!({"errors":[{"message":"secret"}]}));
        let expected_requests = responses.len();
        let run = Run::new(responses);
        let request = request(action, json!({"thread_id":THREAD}), json!({}));
        let reply = run.call(&request);
        assert_eq!(
            reply["result"]["refusal_code"], "vendor_rejected{status: 422}",
            "{reply}"
        );
        assert!(!reply.to_string().contains("secret"));
        assert_eq!(run.call(&request)["result"], reply["result"]);
        assert_eq!(run.wire().len(), expected_requests);
        run.server.join().unwrap();
    }
    let run = Run::new(vec![pr(7), json!({"unexpected":"preview change"})]);
    let request = request(
        "api:POST:/repos/*/*/stacks",
        json!({}),
        json!({"pull_requests":[7]}),
    );
    let reply = run.call(&request);
    assert_eq!(reply["result"]["status"], "outcome_unknown", "{reply}");
    assert_eq!(run.call(&request)["result"], reply["result"]);
    assert_eq!(run.wire().len(), 2);
    run.server.join().unwrap();
}

#[test]
fn v22_preview_requires_documented_status_and_body_pairs() {
    for (action, target, body, read, status, response) in [
        (
            "api:POST:/repos/*/*/stacks/*/unstack",
            json!({"stack_number":"3"}),
            json!({}),
            stack(),
            200,
            Value::Null,
        ),
        (
            "api:POST:/repos/*/*/stacks/*/unstack",
            json!({"stack_number":"3"}),
            json!({}),
            stack(),
            201,
            stack(),
        ),
        (
            "api:POST:/repos/*/*/stacks",
            json!({}),
            json!({"pull_requests":[7]}),
            pr(7),
            200,
            stack(),
        ),
        (
            "api:POST:/repos/*/*/stacks",
            json!({}),
            json!({"pull_requests":[7]}),
            pr(7),
            201,
            json!({"unexpected":true}),
        ),
        (
            "api:POST:/repos/*/*/stacks/*/add",
            json!({"stack_number":"3"}),
            json!({"pull_requests":[7]}),
            pr(7),
            204,
            Value::Null,
        ),
    ] {
        let run = Run::with_statuses(vec![(200, read), (status, response)]);
        let request = request(action, target, body);
        let reply = run.call(&request);
        assert_eq!(
            reply["result"]["status"], "outcome_unknown",
            "{request}: {reply}"
        );
        assert_eq!(run.call(&request)["result"], reply["result"]);
        assert_eq!(run.wire().len(), 2);
        run.server.join().unwrap();
    }
}

#[test]
fn v22_stack_create_and_add_stop_at_first_non_bot_pr() {
    for action in [
        "api:POST:/repos/*/*/stacks",
        "api:POST:/repos/*/*/stacks/*/add",
    ] {
        let mut human = pr(8);
        human["user"] = json!({"login":"human","type":"User"});
        let run = Run::new(vec![pr(7), human]);
        let target = if action.ends_with("/add") {
            json!({"stack_number":"3"})
        } else {
            json!({})
        };
        let request = request(action, target, json!({"pull_requests":[7,8,9]}));
        let reply = run.call(&request);
        assert_eq!(
            reply["result"]["refusal_code"], "stack_pr_not_own",
            "{reply}"
        );
        assert_eq!(reply["result"]["detail"]["number"], 8);
        assert_eq!(reply["result"]["detail"]["author_login"], "human");
        assert!(!reply["result"]["detail"]["message"]
            .as_str()
            .unwrap()
            .contains("pr edit"));
        assert_eq!(
            run.wire(),
            vec![
                ("GET /repos/org/repo/pulls/7 HTTP/1.1".into(), Value::Null),
                ("GET /repos/org/repo/pulls/8 HTTP/1.1".into(), Value::Null)
            ]
        );
        run.server.join().unwrap();
    }
}

#[test]
fn v22_pr_edit_accepts_each_nonempty_subset_of_edit_fields() {
    for mask in 1..4 {
        let mut body = json!({});
        for (bit, field, value) in [(1, "title", "T"), (2, "body", "B")] {
            if mask & bit != 0 {
                body[field] = json!(value);
            }
        }
        let run = Run::new(vec![pr(7), pr(7)]);
        let request = request("pr edit", json!({"number":"7"}), body.clone());
        let reply = run.call(&request);
        assert_eq!(reply["result"]["status"], "completed", "{reply}");
        assert_eq!(
            run.wire()[1],
            ("PATCH /repos/org/repo/pulls/7 HTTP/1.1".into(), body)
        );
        run.server.join().unwrap();
    }
}

#[test]
fn v22_unstack_names_the_first_non_bot_member_and_replays_without_writing() {
    let mut first = pr(8);
    first["user"] = json!({"login":"first-author", "type":"User"});
    let mut second = pr(9);
    second["user"] = json!({"login":"second-author", "type":"User"});
    let mut response = stack();
    response["pull_requests"] = json!([pr(7), first, second]);
    let run = Run::new(vec![response]);
    let request = request(
        "api:POST:/repos/*/*/stacks/*/unstack",
        json!({"stack_number":"3"}),
        json!({}),
    );
    let reply = run.call(&request);
    assert_eq!(
        reply["result"]["refusal_code"], "stack_pr_not_own",
        "{reply}"
    );
    assert_eq!(reply["result"]["detail"]["number"], 8);
    assert_eq!(reply["result"]["detail"]["author_login"], "first-author");
    assert!(!reply["result"]["detail"]["message"]
        .as_str()
        .unwrap()
        .contains("pr edit"));
    assert_eq!(run.call(&request)["result"], reply["result"]);
    assert_eq!(
        run.wire(),
        vec![("GET /repos/org/repo/stacks/3 HTTP/1.1".into(), Value::Null)]
    );
    run.server.join().unwrap();
}

/// Set to `1` to rewrite the reply contract files from the facade's current
/// replies instead of comparing against them.
const REGENERATE_REPLIES: &str = "PLEXUS_REGENERATE_GH_ROUTE_REPLIES";

/// A pull request read whose author is a person, not this repository's bot.
fn human_pr(number: u64) -> Value {
    let mut value = pr(number);
    value["user"] = json!({"login":"octocat", "type":"User"});
    value
}

/// `pr ready` uses the shim's flat thread-state shape, not `action`/`target`.
fn pr_ready_request(undo: bool) -> Value {
    json!({"operation":"gh.route", "gh_route_schema":1, "verb":"pr ready",
        "repository":"org/repo", "number":"7", "undo":undo, "manifest_version":22,
        "rung_as_of_unix_secs":1793066213, "metadata":{"agent_id":"alfonso-aft", "pid":4242}})
}

/// One reply contract case: file name, request, and GitHub's answers (status
/// and body) to the facade's reads in the order it makes them.
type ReplyCase = (&'static str, Value, Vec<(u16, Value)>);

fn reply_contract_cases() -> Vec<ReplyCase> {
    let pr_edit = request("pr edit", json!({"number":"7"}), json!({"title":"T"}));
    let stack_create = request(
        "api:POST:/repos/*/*/stacks",
        json!({}),
        json!({"pull_requests":[7,8]}),
    );
    let stack_add = request(
        "api:POST:/repos/*/*/stacks/*/add",
        json!({"stack_number":"3"}),
        json!({"pull_requests":[7,8]}),
    );
    let unstack = request(
        "api:POST:/repos/*/*/stacks/*/unstack",
        json!({"stack_number":"3"}),
        json!({}),
    );
    let resolve = request(
        "graphql resolvereviewthread",
        json!({"thread_id":THREAD}),
        json!({}),
    );
    let unresolve = request(
        "graphql unresolvereviewthread",
        json!({"thread_id":THREAD}),
        json!({}),
    );
    let mut foreign_stack = stack();
    foreign_stack["url"] = json!("https://api.github.com/repos/foreign/repo/stacks/3");
    let mut foreign_member = stack();
    foreign_member["pull_requests"][1]["base"]["repo"]["url"] =
        json!("https://api.github.com/repos/foreign/repo");
    let mut memberless = stack();
    memberless.as_object_mut().unwrap().remove("pull_requests");
    let mut unowned_stack = stack();
    unowned_stack["pull_requests"] = json!([pr(7), human_pr(8)]);
    vec![
        (
            "comment-edit-pre-read-unknown",
            request(
                "api:PATCH:/repos/*/*/issues/comments/*",
                json!({"comment_id":"101"}),
                json!({"body":"replacement"}),
            ),
            vec![(500, json!({"message":"upstream unavailable"}))],
        ),
        (
            "resolve-thread-own",
            resolve.clone(),
            vec![
                (200, thread_read("org/repo")),
                (200, pr(7)),
                (
                    200,
                    json!({"data":{"resolveReviewThread":{"thread":{"id":THREAD,"isResolved":true}}}}),
                ),
            ],
        ),
        (
            "resolve-thread-not-own",
            resolve.clone(),
            vec![(200, thread_read("org/repo")), (200, human_pr(7))],
        ),
        ("pr-edit-not-own", pr_edit.clone(), vec![(200, human_pr(7))]),
        (
            "pr-edit-pull-request-not-found",
            pr_edit,
            vec![(404, json!({"message":"Not Found"}))],
        ),
        (
            "pr-ready-not-own",
            pr_ready_request(false),
            vec![(200, human_pr(7))],
        ),
        (
            "pr-draft-not-own",
            pr_ready_request(true),
            vec![(200, human_pr(7))],
        ),
        (
            "pr-ready-pull-request-read-incomplete",
            pr_ready_request(false),
            vec![(200, pr(7))],
        ),
        (
            "stack-create-pr-not-own",
            stack_create,
            vec![(200, pr(7)), (200, human_pr(8))],
        ),
        (
            "stack-add-pr-not-own",
            stack_add,
            vec![(200, pr(7)), (200, human_pr(8))],
        ),
        (
            "stack-unstack-pr-not-own",
            unstack.clone(),
            vec![(200, unowned_stack)],
        ),
        (
            "stack-unstack-foreign-stack",
            unstack.clone(),
            vec![(200, foreign_stack)],
        ),
        (
            "stack-unstack-foreign-member",
            unstack.clone(),
            vec![(200, foreign_member)],
        ),
        (
            "stack-unstack-stack-read-incomplete",
            unstack,
            vec![(200, memberless)],
        ),
        (
            "resolve-thread-repository-mismatch",
            resolve.clone(),
            vec![(200, thread_read("foreign/repo"))],
        ),
        (
            "unresolve-thread-repository-mismatch",
            unresolve,
            vec![(200, thread_read("foreign/repo"))],
        ),
        (
            "resolve-thread-not-present",
            resolve.clone(),
            vec![(200, json!({"data":{"node":null}}))],
        ),
        (
            "resolve-thread-graphql-errors",
            resolve,
            vec![(
                200,
                json!({"errors":[{"type":"NOT_FOUND", "message":"Could not resolve to a node"}]}),
            )],
        ),
    ]
}

/// The refusal codes vendor_band.rs writes as string literals: a literal
/// turned into a refusal with `.into()`, `.to_string()` or `.to_owned()`,
/// passed to `ok_or(...)`, or named as a typed refusal's `"code"`. Reading the
/// source means a new literal refusal fails the reply contract test until it
/// gets a reply file or a stated reason in `NOT_V22_REPLIES`.
fn vendor_band_refusal_literals() -> BTreeSet<String> {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/github/facade/vendor_band.rs");
    let source = std::fs::read_to_string(&path).unwrap();
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut found = BTreeSet::new();
    let mut rest = code.as_str();
    let mut before = String::new();
    while let Some(start) = rest.find('"') {
        before.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        let mut end = 0;
        let bytes = tail.as_bytes();
        while end < bytes.len() && bytes[end] != b'"' {
            end += if bytes[end] == b'\\' { 2 } else { 1 };
        }
        let literal = &tail[..end];
        let after = &tail[(end + 1).min(tail.len())..];
        let refusal_shape = literal.split('{').next().is_some_and(|name| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        });
        if refusal_shape
            && ([".into()", ".to_string()", ".to_owned()"]
                .iter()
                .any(|call| after.starts_with(call))
                || before.ends_with("ok_or(")
                || before.ends_with("\"code\":"))
        {
            found.insert(literal.to_owned());
        }
        before.push('"');
        before.push_str(literal);
        before.push('"');
        rest = after;
    }
    found
}

/// Literal codes in vendor_band.rs that no v22 request or pr ready request
/// can produce from GitHub's answers, each with the reason.
const NOT_V22_REPLIES: &[(&str, &str)] = &[
    (
        "store_failure",
        "local storage or receipt state fault, not reachable from a request and GitHub's answers",
    ),
    (
        "repository_unbound",
        "a claimed receipt whose mapped request lost its repository; admission refuses first",
    ),
    (
        "pre_dispatch_read_incomplete{reason: page_bound}",
        "only the comment --edit-last newest-comment walk",
    ),
    (
        "pre_dispatch_read_incomplete{reason: lease_expired}",
        "only the comment --edit-last newest-comment walk",
    ),
    (
        "issue_edit_not_own",
        "issue edit only; AFT's v14 captures already pin it",
    ),
    (
        "outcome_unknown",
        "not a refusal: the reply is {\"status\":\"outcome_unknown\"} after a write",
    ),
];

/// One reply contract file, rendered with sorted keys so its bytes do not
/// depend on whether serde_json's preserve_order feature is on in a build.
fn reply_contract_file(
    name: &str,
    request: &Value,
    reads: Value,
    writes: Vec<Value>,
    reply: &Value,
) -> String {
    let mut file = json!({"name":name, "request":request, "github_reads":reads, "reply":reply});
    if !writes.is_empty() {
        file["github_writes"] = json!(writes);
    }
    file.sort_all_objects();
    serde_json::to_string_pretty(&file).unwrap() + "\n"
}

#[test]
fn v22_reply_contract_files_match_the_facade() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/gh_shim_wire/replies-contract");
    let regenerate = std::env::var(REGENERATE_REPLIES).as_deref() == Ok("1");
    if regenerate {
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
    }
    let mut names = BTreeSet::new();
    let mut covered = BTreeSet::new();
    for (name, request, responses) in reply_contract_cases()
        .into_iter()
        .chain(super::merge_queue::reply_cases())
    {
        assert!(
            names.insert(format!("{name}.json")),
            "duplicate case {name}"
        );
        let run = Run::with_statuses(responses.clone());
        let reply = run.call(&request);
        let wire = run.wire();
        assert_eq!(wire.len(), responses.len(), "{name}: {reply}");
        run.server.join().unwrap();
        let mut reads: Vec<Value> = wire
            .into_iter()
            .zip(responses)
            .map(|((line, body), (status, response))| {
                json!({"request_line":line, "request_body":body, "status":status, "response":response})
            })
            .collect();
        let writes = if name == "pr-enqueue-own" || name == "pr-dequeue-own" {
            assert_eq!(reply["result"]["status"], "completed", "{name}: {reply}");
            assert_eq!(
                reply["result"]["result"]["queued"],
                name == "pr-enqueue-own",
                "{name}: {reply}"
            );
            vec![reads.pop().unwrap()]
        } else if name == "resolve-thread-own" {
            assert_eq!(
                reply["result"],
                json!({"status":"completed", "result":{"id":THREAD,"resolved":true}})
            );
            vec![reads.pop().unwrap()]
        } else {
            assert_eq!(reply["result"]["status"], "refused", "{name}: {reply}");
            covered.insert(
                reply["result"]["refusal_code"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{name}: {reply}"))
                    .to_owned(),
            );
            Vec::new()
        };
        let rendered = reply_contract_file(name, &request, Value::Array(reads), writes, &reply);
        let path = directory.join(format!("{name}.json"));
        if regenerate {
            std::fs::write(&path, rendered).unwrap();
        } else {
            let stored = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            assert_eq!(
                stored, rendered,
                "{name}: the facade's reply changed; rerun with {REGENERATE_REPLIES}=1 and review the diff"
            );
        }
    }
    let on_disk: BTreeSet<String> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        on_disk,
        names,
        "files in {} without a case, or the reverse",
        directory.display()
    );

    let literals = vendor_band_refusal_literals();
    for (code, _) in NOT_V22_REPLIES {
        assert!(
            literals.contains(*code),
            "{code} is listed as unreachable but is no longer in vendor_band.rs"
        );
    }
    let missing: Vec<_> = literals
        .iter()
        .filter(|code| !covered.contains(*code))
        .filter(|code| !NOT_V22_REPLIES.iter().any(|(listed, _)| listed == code))
        .collect();
    assert!(
        missing.is_empty(),
        "vendor_band.rs refusal codes with no reply contract file: {missing:?}"
    );
}
