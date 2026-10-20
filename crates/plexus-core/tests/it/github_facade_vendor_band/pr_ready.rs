use super::*;
use plexus_core::rest_api::{RestConfig, RestTransport};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const READY_QUERY: &str = "mutation($pullRequestId: ID!) { markPullRequestReadyForReview(input: {pullRequestId: $pullRequestId}) { pullRequest { url number isDraft } } }";
const DRAFT_QUERY: &str = "mutation($pullRequestId: ID!) { convertPullRequestToDraft(input: {pullRequestId: $pullRequestId}) { pullRequest { url number isDraft } } }";
const URL: &str = "https://github.com/org/repo/pull/7";

struct BotToken;
impl HandleCredentialProvider for BotToken {
    fn prepare(&self, _: &str, _: i64, _: &str) -> Result<ResolvedCredential, &'static str> {
        Ok(ResolvedCredential::new(
            b"bot-token-canary".to_vec(),
            None,
            1,
        ))
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

fn request(undo: bool) -> Value {
    json!({"operation":"gh.route","gh_route_schema":1,"verb":"pr ready",
        "repository":"org/repo","number":"7","undo":undo,"manifest_version":19,
        "rung_as_of_unix_secs":1790209661,"metadata":{"agent_id":"agent-fixture"}})
}

fn pull(draft: bool) -> Value {
    json!({"user":{"login":"app-fixture[bot]","type":"Bot"},"draft":draft,
        "node_id":"PR_node_7","html_url":URL,"number":7})
}

fn mutation(undo: bool, draft: bool) -> Value {
    let name = if undo {
        "convertPullRequestToDraft"
    } else {
        "markPullRequestReadyForReview"
    };
    json!({"data":{name:{"pullRequest":{"url":URL,"number":7,"isDraft":draft,
        "body":"not projected"}}}})
}

struct ReadyRun {
    _scratch: plexus_core::test_scratch::Scratch,
    store: Arc<PlexusStore>,
    engine: GovernanceEngine<plexus_core::credentials::StubCredentialSource, RestTransport>,
    scope: CallScope,
    sent: Arc<Mutex<Vec<String>>>,
    server: validation_http::FixedRequestServer,
}

impl ReadyRun {
    fn new(label: &str, responses: Vec<Value>) -> Self {
        Self::with_token(label, responses, Arc::new(BotToken))
    }

    fn with_token(
        label: &str,
        responses: Vec<Value>,
        token: Arc<dyn HandleCredentialProvider>,
    ) -> Self {
        let (scratch, store, _, _, scope) = setup(
            label,
            &[
                ("github.pull_request.get", "read"),
                ("mark_pull_request_ready", "write"),
                ("convert_pull_request_to_draft", "write"),
            ],
        );
        let sent = Arc::new(Mutex::new(Vec::new()));
        let captured = sent.clone();
        let (endpoint, server) = validation_http::FixedRequestServer::start(
            responses.len(),
            "PR ready",
            move |index, raw| {
                captured.lock().unwrap().push(raw.to_owned());
                let body = responses[index].to_string();
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
            },
        );
        let manifest = github_manifest();
        assert_eq!(manifest.transport.url, "https://api.github.com");
        let config = RestConfig::new(endpoint)
            .with_bindings(manifest.credential_bindings.clone())
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
            credential_provider: Some(token),
        }))
        .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
        Self {
            _scratch: scratch,
            store,
            engine,
            scope,
            sent,
            server,
        }
    }

    fn call_raw(&self, request: &Value, nonce: &str) -> Value {
        bot_request_scoped(
            &self.store,
            &self.engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&self.scope),
            request,
            nonce,
            "pr-ready-id",
            "worker",
            plexus_core::storage::now_ms(),
        )
    }

    fn call(&self, request: &Value, nonce: &str) -> Value {
        let reply = self.call_raw(request, nonce);
        if reply["result"]["refusal_code"] == "transport_not_sent" {
            let db = Connection::open(self._scratch.path()).unwrap();
            let mut statement = db
                .prepare("SELECT action, response_class FROM audit_journal")
                .unwrap();
            let rows: Vec<_> = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            panic!(
                "unexpected transport refusal: {reply}; audit: {rows:?}; received {} HTTP requests",
                self.sent.lock().unwrap().len()
            );
        }
        reply
    }
}

#[test]
fn pr_ready_fixture_waits_for_credential_preparation_before_each_http_leg() {
    struct DelayedToken {
        delayed_leg: usize,
        calls: AtomicUsize,
    }
    impl HandleCredentialProvider for DelayedToken {
        fn prepare(
            &self,
            handle: &str,
            generation: i64,
            reference: &str,
        ) -> Result<ResolvedCredential, &'static str> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == self.delayed_leg {
                // Model a slow vault reply without consuming CPU. It exceeds
                // the former two-second accept deadline, so
                // the fixture must keep listening during credential preparation.
                std::thread::sleep(crate::bounded::WAIT + Duration::from_millis(500));
            }
            BotToken.prepare(handle, generation, reference)
        }
        fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
    }
    let mut failures = Vec::new();
    for delayed_leg in [0, 1] {
        let token = Arc::new(DelayedToken {
            delayed_leg,
            calls: AtomicUsize::new(0),
        });
        let run = ReadyRun::with_token(
            "pr-ready-slow-credential",
            vec![pull(true), mutation(false, false)],
            token,
        );
        let reply = run.call_raw(&request(false), "slow-credential");
        let received = run.sent.lock().unwrap().len();
        let server = run.server.join();
        if reply["result"]["status"] != "completed" || received != 2 || server.is_err() {
            failures.push(format!(
                "delayed leg {delayed_leg}: {reply}; received {received}; server: {server:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn pr_ready_and_undo_send_only_reviewed_query_and_node_variables_and_replay() {
    for undo in [false, true] {
        let run = ReadyRun::new("pr-ready-wire", vec![pull(!undo), mutation(undo, undo)]);
        let first = run.call(&request(undo), "ready-wire");
        assert_eq!(
            first["result"],
            json!({"status":"completed",
            "result":{"url":URL,"number":7,"draft":undo}}),
            "{first}"
        );
        let second = run.call(&request(undo), "ready-wire");
        assert_eq!(second["result"], first["result"]);
        let sent = run.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert!(sent[0].starts_with("GET /repos/org/repo/pulls/7 HTTP/1.1\r\n"));
        assert!(sent[1].starts_with("POST /graphql HTTP/1.1\r\n"));
        assert!(sent.iter().all(|raw| raw
            .to_ascii_lowercase()
            .contains("authorization: bearer bot-token-canary\r\n")));
        let body: Value = serde_json::from_str(sent[1].split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(
            body,
            json!({"query":if undo {DRAFT_QUERY} else {READY_QUERY},
            "variables":{"pullRequestId":"PR_node_7"}})
        );
        drop(sent);
        let receipt = run
            .store
            .github_receipt("agent-fixture", "ready-wire")
            .unwrap()
            .unwrap();
        assert_eq!(receipt.effects.len(), 1);
        assert_eq!(receipt.state, "completed");
        run.server.join().unwrap();
    }
}

#[test]
fn pr_ready_not_own_refuses_before_mutation() {
    for undo in [false, true] {
        for user in [
            json!({"login":"someone-else[bot]","type":"Bot"}),
            json!({"login":"app-fixture[bot]","type":"User"}),
        ] {
            let mut pr = pull(!undo);
            pr["user"] = user;
            let run = ReadyRun::new("pr-ready-not-own", vec![pr]);
            let reply = run.call(&request(undo), "not-own");
            assert_eq!(
                reply["result"]["refusal_code"], "pr_edit_not_own",
                "{reply}"
            );
            assert_eq!(run.sent.lock().unwrap().len(), 1);
            run.server.join().unwrap();
        }
    }
}

#[test]
fn pr_ready_noop_in_both_directions_sends_no_mutation_and_replays() {
    for undo in [false, true] {
        let run = ReadyRun::new("pr-ready-noop", vec![pull(undo)]);
        let reply = run.call(&request(undo), "noop");
        assert_eq!(
            reply["result"],
            json!({"status":"completed",
            "result":{"url":URL,"number":7,"draft":undo}}),
            "{reply}"
        );
        assert_eq!(run.call(&request(undo), "noop")["result"], reply["result"]);
        assert_eq!(run.sent.lock().unwrap().len(), 1);
        assert!(run
            .store
            .github_receipt("agent-fixture", "noop")
            .unwrap()
            .unwrap()
            .effects
            .iter()
            .all(|effect| effect.dispatch_attempted_at.is_none()));
        run.server.join().unwrap();
    }
}

#[test]
fn pr_ready_graphql_errors_at_http_200_are_sanitized_refusals() {
    for undo in [false, true] {
        // Null data proves no mutation result was produced; vendor messages
        // remain private even for a definite application refusal.
        let mut response = json!({"data":null});
        response["errors"] = json!([
            {"message":"bot-token-canary free vendor text", "path":["mutation"]},
            {"resource":"PullRequest","field":"draft","code":"invalid","message":"secret text"}
        ]);
        let run = ReadyRun::new("pr-ready-errors", vec![pull(!undo), response]);
        let reply = run.call(&request(undo), "errors");
        assert_eq!(reply["result"]["status"], "refused", "{reply}");
        assert_eq!(reply["result"]["refusal_code"], "vendor_rejected{status: 422, errors: [{\"code\":\"invalid\",\"field\":\"draft\",\"resource\":\"PullRequest\"}]}");
        assert!(!reply.to_string().contains("secret text"));
        assert!(!reply.to_string().contains("bot-token-canary"));
        assert_eq!(
            run.call(&request(undo), "errors")["result"],
            reply["result"]
        );
        assert_eq!(run.sent.lock().unwrap().len(), 2);
        run.server.join().unwrap();
    }
}

#[test]
fn pr_ready_ambiguous_graphql_success_is_unknown_and_never_retried() {
    for undo in [false, true] {
        for response in [
            json!({"data":{}}),
            json!({"data":null}),
            json!({"errors":[{"message":"secret"}]}),
            json!({"data":{"markPullRequestReadyForReview":{"pullRequest":{"number":7,"url":URL,"isDraft":false}}},"errors":[{"message":"partial"}]}),
        ] {
            let run = ReadyRun::new("pr-ready-missing-data", vec![pull(!undo), response.clone()]);
            let reply = run.call(&request(undo), "missing-data");
            let expected = if response.get("errors").is_some()
                && response.get("data").is_none_or(Value::is_null)
            {
                "refused"
            } else {
                "outcome_unknown"
            };
            assert_eq!(reply["result"]["status"], expected, "{reply}");
            assert_eq!(
                run.call(&request(undo), "missing-data")["result"],
                reply["result"]
            );
            run.server.join().unwrap();
        }
    }
}

#[test]
fn pr_ready_undo_and_top_level_allowlist_are_required_before_any_read() {
    let (_scratch, store, engine, transport, scope) = setup(
        "pr-ready-allowlist",
        &[
            ("github.pull_request.get", "read"),
            ("mark_pull_request_ready", "write"),
            ("convert_pull_request_to_draft", "write"),
        ],
    );
    let mut cases = Vec::new();
    let mut missing = request(false);
    missing.as_object_mut().unwrap().remove("undo");
    cases.push((missing, "undo"));
    for value in [Value::Null, json!("false"), json!(0), json!({})] {
        let mut invalid = request(false);
        invalid["undo"] = value;
        cases.push((invalid, "undo"));
    }
    for undo in [false, true] {
        for field in [
            "action",
            "target",
            "body",
            "comment",
            "title",
            "reason",
            "query",
            "variables",
            "pullRequestId",
            "unexpected",
        ] {
            let mut extra = request(undo);
            extra[field] = json!("caller value");
            cases.push((extra, field));
        }
    }
    for (index, (request, field)) in cases.into_iter().enumerate() {
        let reply = bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            &format!("bad-{index}"),
            "bad-id",
            "worker",
            plexus_core::storage::now_ms(),
        );
        assert_eq!(
            reply["result"]["refusal_code"],
            format!("request_field_forbidden{{field: {field}}}"),
            "{reply}"
        );
    }
    assert!(transport.requests().is_empty());
}
