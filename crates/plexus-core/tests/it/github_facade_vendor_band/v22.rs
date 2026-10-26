use super::*;
use plexus_core::governance::AuthorizationRequest;
use plexus_core::rest_api::{RestConfig, RestTransport};
use std::sync::Mutex;

const THREAD: &str = "PRRT_kwDOAbc123";
const THREAD_READ: &str = "query($threadId: ID!) { node(id: $threadId) { ... on PullRequestReviewThread { id pullRequest { repository { nameWithOwner } } } } }";
const RESOLVE: &str = "mutation($threadId: ID!) { resolveReviewThread(input: {threadId: $threadId}) { thread { id isResolved } } }";
const UNRESOLVE: &str = "mutation($threadId: ID!) { unresolveReviewThread(input: {threadId: $threadId}) { thread { id isResolved } } }";

struct Run {
    store: Arc<PlexusStore>,
    engine: GovernanceEngine<plexus_core::credentials::StubCredentialSource, RestTransport>,
    scope: CallScope,
    sent: Arc<Mutex<Vec<String>>>,
    server: validation_http::FixedRequestServer,
    _scratch: plexus_core::test_scratch::Scratch,
}

impl Run {
    fn new(responses: Vec<Value>) -> Self {
        Self::with_statuses(
            responses
                .into_iter()
                .map(|value| (if value.is_null() { 204 } else { 200 }, value))
                .collect(),
        )
    }

    fn with_statuses(responses: Vec<(u16, Value)>) -> Self {
        let (scratch, store, _, _, scope) = setup(
            "v22",
            &[
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
                format!("HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
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

    fn call(&self, request: &Value) -> Value {
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

    fn wire(&self) -> Vec<(String, Value)> {
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

fn request(action: &str, target: Value, body: Value) -> Value {
    let mut value = json!({"action":action, "repository":"org/repo", "manifest_version":22, "target":target, "body":body});
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
    json!({"data":{"node":{"id":THREAD, "pullRequest":{"repository":{"nameWithOwner":repo}}}}})
}

type Case = (Value, Vec<Value>, Vec<(String, Value)>, Value);

fn cases() -> Vec<Case> {
    let mut result = vec![
        (
            request(
                "pr edit",
                json!({"number":"7"}),
                json!({"title":"T", "body":"B", "base":"stack/parent"}),
            ),
            vec![pr(7), pr(7)],
            vec![
                ("GET /repos/org/repo/pulls/7 HTTP/1.1".into(), Value::Null),
                (
                    "PATCH /repos/org/repo/pulls/7 HTTP/1.1".into(),
                    json!({"title":"T", "body":"B", "base":"stack/parent"}),
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
        result.push((
            request(action, json!({"thread_id":THREAD}), json!({})),
            vec![
                thread_read("org/repo"),
                json!({"data":{name:{"thread":{"id":THREAD,"isResolved":resolved}}}}),
            ],
            vec![
                (
                    "POST /graphql HTTP/1.1".into(),
                    json!({"query":THREAD_READ, "variables":{"threadId":THREAD}}),
                ),
                (
                    "POST /graphql HTTP/1.1".into(),
                    json!({"query":query, "variables":{"threadId":THREAD}}),
                ),
            ],
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
                first["result"]["refusal_code"], "pr_edit_not_own",
                "{first}"
            );
            if request["action"] == "pr edit" {
                let message = first["result"]["detail"]["message"].as_str().unwrap();
                assert!(message.contains("#7 was opened by "));
                assert!(message.contains("GH_SHIM_BYPASS=operator"));
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
            (
                json!({"errors":[{"message":"private vendor canary"}]}),
                "vendor_rejected{status: 422}",
            ),
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
        let run = Run::new(vec![
            thread_read("org/repo"),
            json!({"errors":[{"message":"secret"}]}),
        ]);
        let request = request(action, json!({"thread_id":THREAD}), json!({}));
        let reply = run.call(&request);
        assert_eq!(
            reply["result"]["refusal_code"], "vendor_rejected{status: 422}",
            "{reply}"
        );
        assert!(!reply.to_string().contains("secret"));
        assert_eq!(run.call(&request)["result"], reply["result"]);
        assert_eq!(run.wire().len(), 2);
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
            reply["result"]["refusal_code"], "pr_edit_not_own",
            "{reply}"
        );
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
    for mask in 1..8 {
        let mut body = json!({});
        for (bit, field, value) in [
            (1, "title", "T"),
            (2, "body", "B"),
            (4, "base", "stack/parent"),
        ] {
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
