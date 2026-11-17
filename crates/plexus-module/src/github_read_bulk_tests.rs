//! Bulk-operation vectors share the bot-read fake GitHub and real frame handler.

use super::super::bot_read_tests::{head, worker};
use super::*;
use plexus_core::github::reads::bot::{BULK_ACTIONS, BULK_METHOD};

const BULK_REGENERATE: &str = "PLEXUS_REGENERATE_GITHUB_READ_BULK_VECTORS";
const VECTOR_NAMES: &[&str] = &[
    "repo-get-diff",
    "search-code",
    "search-issues",
    "job-log-range",
    "refused-response-too-large",
    "refused-endpoint-not-allowed-path",
    "refused-vendor-error",
    "refused-job-not-finished",
    "refused-job-log-unavailable",
    "refused-job-log-redirect-refused",
    "refused-job-log-read-limit",
    "refused-job-log-download-failed",
    "refused-read-dispatch-failed-unknown",
    "refused-read-dispatch-failed-not-sent",
    "refused-read-response-invalid",
    "refused-invalid-request",
    "refused-denied",
];

fn bulk_dir(kind: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../plexus-core/tests/fixtures/gh_shim_wire")
        .join(format!("read-bulk-{kind}-contract"))
}

fn bulk_call(params: Value) -> Value {
    json!({"method": BULK_METHOD, "params": params})
}

fn setup(
    github: &Value,
) -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    let actions = [
        "github.repo.get",
        "github.search.code",
        "github.search.issues",
        "github.actions.job.get",
        "github.actions.job_log",
    ];
    let (runtime, store, transport, scratch) =
        imported_runtime_with_actions(if github["setup"]["deny_module_grants"] == true {
            &[]
        } else {
            &actions
        });
    for (action, reply) in github["replies"].as_object().unwrap() {
        let response = match reply["transport"].as_str() {
            Some("unknown") => MockResponse::OutcomeUnknown,
            Some("not_sent") => MockResponse::TransientNotSent {
                message: "private transport diagnostic".into(),
            },
            None => mock(reply),
            Some(other) => panic!("unknown vector transport outcome {other}"),
        };
        transport.set_response_for_method(action, "", response);
    }
    if let Some(spent) = github["setup"]["reads_spent"].as_i64() {
        let now = plexus_core::now_ms();
        let mut remaining = spent;
        while remaining > 0 {
            let units = remaining.min(16);
            store.reserve_github_bot_read("app-x", units, now).unwrap();
            remaining -= units;
        }
    }
    (runtime, store, transport, scratch)
}

fn source_vector(name: &str) -> Value {
    let base = match name {
        "refused-job-not-finished"
        | "refused-job-log-unavailable"
        | "refused-job-log-redirect-refused"
        | "refused-job-log-read-limit"
        | "refused-job-log-download-failed" => "job-log-range",
        "refused-read-dispatch-failed-unknown"
        | "refused-read-dispatch-failed-not-sent"
        | "refused-invalid-request"
        | "refused-denied" => "repo-get-diff",
        "refused-read-response-invalid" => "search-code",
        _ => return legacy_source_vector(name),
    };
    let mut source = legacy_source_vector(base);
    source["name"] = json!(name);
    let github = &mut source["github"];
    match name {
        "refused-job-not-finished" => {
            github["replies"]["github.actions.job.get"]["success"]["body"]["status"] =
                json!("in_progress");
            github["replies"]
                .as_object_mut()
                .unwrap()
                .remove("github.actions.job_log");
            github["expected_requests"]
                .as_array_mut()
                .unwrap()
                .truncate(1);
        }
        "refused-job-log-unavailable"
        | "refused-job-log-redirect-refused"
        | "refused-job-log-read-limit"
        | "refused-job-log-download-failed" => {
            let code = name.strip_prefix("refused-").unwrap().replace('-', "_");
            github["replies"]["github.actions.job_log"] = json!({"vendor_error":code});
        }
        "refused-read-dispatch-failed-unknown" | "refused-read-dispatch-failed-not-sent" => {
            let transmission = if name.ends_with("unknown") {
                "unknown"
            } else {
                "not_sent"
            };
            github["replies"]["github.repo.get"] = json!({"transport":transmission});
        }
        "refused-read-response-invalid" => {
            github["replies"]["github.search.code"]["success"]["body"] = json!({});
        }
        "refused-denied" => {
            github["setup"] = json!({"deny_module_grants":true});
            github["expected_requests"] = json!([]);
        }
        "refused-invalid-request" => {
            github["expected_requests"] = json!([]);
            source["request"]["params"]["args"] = json!([]);
        }
        _ => unreachable!(),
    }
    source
}

fn legacy_source_vector(name: &str) -> Value {
    let source = read_json(&vector_dir().join(format!("{name}.request.json")));
    json!({
        "name": name,
        "scope": source["scope"],
        "request": bulk_call(source["call"]["arguments"].clone()),
        "github": read_json(&vector_dir().join(format!("{name}.github.json"))),
    })
}

fn pretty(value: &Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(value).unwrap())
}

fn facade_only(bytes: &[u8]) -> Value {
    let mut reply: Value = serde_json::from_slice(bytes).unwrap();
    let fields = reply.as_object_mut().unwrap();
    for key in ["content", "structuredContent", "isError"] {
        fields.remove(key);
    }
    reply
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_vectors_replay_byte_for_byte_and_match_tool_payloads() {
    let regenerate = std::env::var(BULK_REGENERATE).as_deref() == Ok("1");
    if regenerate {
        std::fs::create_dir_all(bulk_dir("requests")).unwrap();
        std::fs::create_dir_all(bulk_dir("replies")).unwrap();
    }
    let mut covered = std::collections::BTreeSet::new();
    for name in VECTOR_NAMES {
        let source = source_vector(name);
        let request_path = bulk_dir("requests").join(format!("{name}.json"));
        if regenerate {
            std::fs::write(&request_path, pretty(&source)).unwrap();
        }
        let vector = read_json(&request_path);
        assert_eq!(
            std::fs::read_to_string(&request_path).unwrap(),
            pretty(&source)
        );
        let (runtime, store, transport, _scratch) = setup(&vector["github"]);
        let request = &vector["request"];
        let scope = stamp(&vector["scope"]);
        let body = send_bound(&runtime, "aft", scope.clone(), request).await;
        let reply: Value = serde_json::from_slice(&body).unwrap();
        let tool = json!({"name": manifest::GITHUB_READ_TOOL, "arguments": request["params"]});
        let tool_body = send_bound(&runtime, "aft", scope, &tool).await;
        assert_eq!(
            facade_only(&body),
            facade_only(&tool_body),
            "{name}: op and tool payloads differ"
        );
        assert!(serde_json::from_slice::<Value>(&tool_body)
            .unwrap()
            .get("content")
            .is_none());
        if matches!(
            *name,
            "repo-get-diff"
                | "search-code"
                | "search-issues"
                | "job-log-range"
                | "refused-response-too-large"
                | "refused-endpoint-not-allowed-path"
                | "refused-vendor-error"
        ) {
            let old_reply = read_json(&vector_dir().join(format!("{name}.reply.json")));
            assert_eq!(
                tool_body,
                serde_json::to_vec(&old_reply).unwrap(),
                "{name}: lean tool bytes changed"
            );
        }
        let sent: Vec<Value> = transport.requests().iter().map(|sent| {
            json!({"connection_id": sent.connection_id, "action": sent.action, "args": sent.args})
        }).collect();
        let expected = vector["github"]["expected_requests"].as_array().unwrap();
        let twice: Vec<_> = expected.iter().chain(expected).cloned().collect();
        assert_eq!(sent, twice, "{name}: governed requests differ");
        let units: i64 = expected
            .iter()
            .map(|sent| {
                if sent["action"] == "github.actions.job_log" {
                    2
                } else {
                    1
                }
            })
            .sum();
        assert_eq!(
            store
                .github_bot_reads_in_window("app-x", plexus_core::now_ms())
                .unwrap(),
            units * 2
        );
        covered.insert(
            reply["error"]["code"]
                .as_str()
                .unwrap_or_else(|| request["params"]["action"].as_str().unwrap())
                .to_owned(),
        );
        if reply.get("error").is_some() {
            assert!(
                reply["error"]["transmission"].is_string(),
                "{name}: {reply}"
            );
        }
        if reply["error"]["code"] == "read_dispatch_failed" {
            let expected = if name.ends_with("unknown") {
                "unknown"
            } else {
                "not_sent"
            };
            assert_eq!(reply["error"]["transmission"], expected, "{name}");
            assert_eq!(
                reply["error"]["outcome"]["transmission"], expected,
                "{name}"
            );
            covered.insert(format!("read_dispatch_failed:{expected}"));
        }
        let reply_path = bulk_dir("replies").join(format!("{name}.json"));
        let rendered = pretty(&json!({"name": name, "reply": reply}));
        if regenerate {
            std::fs::write(reply_path, rendered).unwrap();
        } else {
            let fixture = read_json(&reply_path);
            assert_eq!(
                body,
                serde_json::to_vec(&fixture["reply"]).unwrap(),
                "{name}: pinned reply differs"
            );
            assert_eq!(std::fs::read_to_string(reply_path).unwrap(), rendered);
        }
    }
    for required in BULK_ACTIONS.iter().copied().chain([
        "response_too_large",
        "endpoint_not_allowed",
        "vendor_error",
        "job_not_finished",
        "job_log_unavailable",
        "job_log_redirect_refused",
        "job_log_read_limit",
        "job_log_download_failed",
        "read_dispatch_failed:unknown",
        "read_dispatch_failed:not_sent",
        "read_response_invalid",
        "invalid_request",
        "grant_action_selector",
    ]) {
        assert!(
            covered.contains(required),
            "no bulk vector covers {required}"
        );
    }
    for kind in ["requests", "replies"] {
        assert_eq!(
            std::fs::read_dir(bulk_dir(kind)).unwrap().count(),
            VECTOR_NAMES.len()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_read_admission_transmission_is_scoped_to_bot_forms() {
    for (carrier, action, args, transmission) in [
        ("aft", "github.repo.get", json!({}), Some("not_sent")),
        ("other", "github.search.code", json!({}), Some("not_sent")),
        (
            "aft",
            "github.actions.job_log",
            json!({"job_id":42}),
            Some("not_sent"),
        ),
        (
            "aft",
            "github.actions.job_log",
            json!({"job_id":42,"max_bytes":100}),
            None,
        ),
        (
            "other",
            "github.actions.job_log",
            json!({"job_id":42}),
            None,
        ),
    ] {
        let vector = source_vector("repo-get-diff");
        let (runtime, _store, transport, _scratch) = setup(&vector["github"]);
        let body = send_bound(
            &runtime,
            carrier,
            Some(head(Some("agent-x"))),
            &json!({"name":manifest::GITHUB_READ_TOOL,"arguments":{
                "action":action,"repository":"o/x","args":args,"unexpected":true,
            }}),
        )
        .await;
        let reply: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            reply["error"]["code"], "invalid_request",
            "{carrier}: {reply}"
        );
        assert_eq!(
            reply["error"]["transmission"].as_str(),
            transmission,
            "{carrier}: {reply}"
        );
        assert!(transport.requests().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ask_first_bot_reads_return_approval_refusals_not_access_pending() {
    for bulk in [false, true] {
        let vector = source_vector("repo-get-diff");
        let (mut runtime, store, transport, _scratch) = setup(&vector["github"]);
        let engine = &mut Arc::get_mut(&mut runtime).unwrap().runtime.engine;
        *engine = engine
            .clone()
            .with_consent_cards(crate::consent_test_support::pending_cards());
        store
            .set_policy(
                "direct",
                "github-handle-app-x",
                "github.repo.get",
                "ask_first",
                None,
            )
            .unwrap();
        let call = if bulk {
            vector["request"].clone()
        } else {
            json!({"name":manifest::GITHUB_READ_TOOL,"arguments":vector["request"]["params"]})
        };
        let mut scope = head(Some("agent-x"));
        scope.attributes.delegates = true;
        let body = send_bound(&runtime, "aft", Some(scope), &call).await;
        let reply: Value = serde_json::from_slice(&body).unwrap();
        // Bot reads authorize without entering the held-call wait path that
        // turns a pending consent card into an access_pending reply.
        assert_eq!(reply["error"]["code"], "action_request_created", "{reply}");
        assert_eq!(reply["error"]["transmission"], "not_sent", "{reply}");
        let requests = store.list_action_requests("direct").unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].elicitation_id.is_some());
        assert!(transport.requests().is_empty());
        assert_eq!(
            store
                .github_bot_reads_in_window("app-x", plexus_core::now_ms())
                .unwrap(),
            0
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_four_actions_keep_head_and_worker_identity_and_payloads() {
    for name in &VECTOR_NAMES[..4] {
        let vector = source_vector(name);
        for scope in [head(Some("agent-x")), worker(Some("agent-x"))] {
            let (runtime, _store, _transport, scratch) = setup(&vector["github"]);
            let request = &vector["request"];
            let body = send_bound(&runtime, "aft", Some(scope.clone()), request).await;
            let tool = json!({"name": manifest::GITHUB_READ_TOOL, "arguments": request["params"]});
            assert_eq!(
                facade_only(&body),
                facade_only(&send_bound(&runtime, "aft", Some(scope.clone()), &tool).await),
                "{name}"
            );
            let reply: Value = serde_json::from_slice(&body).unwrap();
            assert!(reply.get("result").is_some(), "{name}: {reply}");
            let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
            let mut statement = db.prepare("SELECT agent_id, scope_on_behalf_of_agent FROM audit_journal WHERE gate='dispatch'").unwrap();
            let rows: Vec<(Option<String>, Option<String>)> = statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert_eq!(rows.len(), if *name == "job-log-range" { 4 } else { 2 });
            for row in rows {
                let expected = if scope.attributes.agent_id.is_some() {
                    (Some("agent-x".to_owned()), None)
                } else {
                    (None, Some("agent-x".to_owned()))
                };
                assert_eq!(row, expected, "{name}: stamped identity changed");
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_only_reserved_aft_is_admitted() {
    let vector = source_vector("repo-get-diff");
    for caller in ["prefrontal-core", "basal", "other"] {
        let (runtime, _store, transport, _scratch) = setup(&vector["github"]);
        let body = send_bound(
            &runtime,
            caller,
            Some(head(Some("agent-x"))),
            &vector["request"],
        )
        .await;
        let reply: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            reply["error"]["code"], "caller_not_allowed",
            "{caller}: {reply}"
        );
        assert_eq!(reply["error"]["transmission"], "not_sent");
        assert!(transport.requests().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_without_stamped_agent_refuses_without_sending() {
    let vector = source_vector("repo-get-diff");
    for scope in [None, Some(head(None)), Some(worker(None))] {
        let (runtime, _store, transport, _scratch) = setup(&vector["github"]);
        let body = send_bound(&runtime, "aft", scope, &vector["request"]).await;
        let reply: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(reply["error"]["code"], "agent_identity_required", "{reply}");
        assert_eq!(reply["error"]["transmission"], "not_sent");
        assert!(transport.requests().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_refuses_other_read_actions_by_name_and_is_not_a_tool() {
    let (runtime, _store, transport, _scratch) = setup(&json!({"replies": {}}));
    for action in plexus_core::github::reads::ACTIONS
        .iter()
        .copied()
        .filter(|action| !BULK_ACTIONS.contains(action))
    {
        let body = send_bound(
            &runtime,
            "aft",
            Some(head(Some("agent-x"))),
            &bulk_call(json!({"action": action})),
        )
        .await;
        let reply: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(reply["error"]["code"], "read_action_unsupported", "{reply}");
        assert_eq!(reply["error"]["action"], action);
    }
    let body = send_bound(
        &runtime,
        "aft",
        Some(head(Some("agent-x"))),
        &json!({"name": BULK_METHOD, "arguments": {}}),
    )
    .await;
    let reply: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(reply["error"]["code"], "unknown_method");
    assert!(transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_closed_fields_and_refusal_echoes_are_preserved() {
    let (runtime, _store, transport, _scratch) = setup(&json!({"replies": {}}));
    let params = json!({"action": "github.repo.get", "repository": "o/x", "args": {"path": ""}});
    for field in ["agent_id".to_owned(), "x".repeat(4096)] {
        let mut request = bulk_call(params.clone());
        request[&field] = json!("untrusted");
        let body = send_bound(&runtime, "aft", Some(head(Some("agent-x"))), &request).await;
        let reply: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(reply["error"]["code"], "invalid_request");
        assert_eq!(
            reply["error"]["field"],
            plexus_core::text::refusal_echo(&field).as_ref()
        );
    }
    for field in ["agent_id", "assertion", "agent_assertion"] {
        let mut bad_params = params.clone();
        bad_params[field] = json!("agent-x");
        let op = send_bound(&runtime, "aft", None, &bulk_call(bad_params.clone())).await;
        let tool = send_bound(
            &runtime,
            "aft",
            None,
            &json!({"name": manifest::GITHUB_READ_TOOL, "arguments": bad_params}),
        )
        .await;
        assert_eq!(facade_only(&op), facade_only(&tool));
        let reply: Value = serde_json::from_slice(&op).unwrap();
        assert_eq!(
            reply["error"]["code"],
            if field == "agent_id" {
                "invalid_request"
            } else {
                "argument_undeclared"
            }
        );
    }
    let action = "unknown".repeat(1024);
    let body = send_bound(
        &runtime,
        "aft",
        Some(head(Some("agent-x"))),
        &bulk_call(json!({"action": action})),
    )
    .await;
    let reply: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        reply["error"]["action"],
        plexus_core::text::refusal_echo(&action).as_ref()
    );
    assert!(transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_keeps_one_mib_replies_and_job_log_length_cap() {
    let (runtime, _store, transport, _scratch) = setup(&source_vector("job-log-range")["github"]);
    let text = "x".repeat(1_048_576);
    transport.set_response_for_method(
        "github.repo.get",
        "",
        MockResponse::Success(json!({"status":200, "body":text, "next_page":null})),
    );
    let params = json!({"action":"github.repo.get", "repository":"o/x", "args":{"path":""}});
    let op = send_bound(
        &runtime,
        "aft",
        Some(head(Some("agent-x"))),
        &bulk_call(params.clone()),
    )
    .await;
    let tool = send_bound(
        &runtime,
        "aft",
        Some(head(Some("agent-x"))),
        &json!({"name":manifest::GITHUB_READ_TOOL,"arguments":params}),
    )
    .await;
    let tool_reply: Value = serde_json::from_slice(&tool).unwrap();
    assert_eq!(tool_reply["error"]["code"], "response_too_large");
    assert_eq!(tool_reply["error"]["transmission"], "sent");
    let reply: Value = serde_json::from_slice(&op).unwrap();
    assert_eq!(reply["result"]["body"].as_str().unwrap().len(), 1_048_576);
    for length in [1_048_576_u64, 1_048_577] {
        let params = json!({"action":"github.actions.job_log", "repository":"o/x", "args":{"job_id":42,"offset":1024,"length":length}});
        let before = transport.requests().len();
        let op = send_bound(
            &runtime,
            "aft",
            Some(head(Some("agent-x"))),
            &bulk_call(params.clone()),
        )
        .await;
        let tool = send_bound(
            &runtime,
            "aft",
            Some(head(Some("agent-x"))),
            &json!({"name":manifest::GITHUB_READ_TOOL,"arguments":params}),
        )
        .await;
        let tool_reply: Value = serde_json::from_slice(&tool).unwrap();
        assert!(tool_reply.get("result").is_some(), "{tool_reply}");
        let sent = transport.requests();
        assert_eq!(sent.last().unwrap().args["length"], 10_000);
        let reply: Value = serde_json::from_slice(&op).unwrap();
        if length == 1_048_576 {
            assert!(reply.get("result").is_some(), "{reply}");
            assert_eq!(transport.requests()[before + 1].args["length"], length);
        } else {
            assert_eq!(reply["error"]["code"], "endpoint_not_allowed");
            assert_eq!(reply["error"]["field"], "length");
            assert_eq!(transport.requests().len(), before + 2);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_existing_refusals_keep_tool_codes_and_fields() {
    for name in [
        "refused-agent-identity-required",
        "refused-repository-not-visible",
        "refused-vendor-error",
        "refused-endpoint-not-allowed-accept",
        "refused-endpoint-not-allowed-q",
        "refused-endpoint-not-allowed-query",
        "refused-read-budget-exhausted",
    ] {
        let vector = source_vector(name);
        let (runtime, _store, _transport, _scratch) = setup(&vector["github"]);
        let request = &vector["request"];
        let scope = stamp(&vector["scope"]);
        let op = send_bound(&runtime, "aft", scope.clone(), request).await;
        let tool = send_bound(
            &runtime,
            "aft",
            scope,
            &json!({"name":manifest::GITHUB_READ_TOOL,"arguments":request["params"]}),
        )
        .await;
        let expected = read_json(&vector_dir().join(format!("{name}.reply.json")));
        let mut op_reply: Value = serde_json::from_slice(&op).unwrap();
        let mut tool_reply: Value = serde_json::from_slice(&tool).unwrap();
        if name == "refused-read-budget-exhausted" {
            // Only the wall-clock retry delay varies between sequential calls.
            normalize_clock(&mut op_reply, &expected);
            normalize_clock(&mut tool_reply, &expected);
        }
        assert_eq!(op_reply["error"], tool_reply["error"], "{name}");
        assert_eq!(tool_reply, expected, "{name}: lean refusal changed");
    }
    let (runtime, _store, transport, _scratch) = imported_runtime_with_actions(&[]);
    let params = json!({"action":"github.repo.get", "repository":"o/x", "args":{"path":""}});
    let op = send_bound(
        &runtime,
        "aft",
        Some(head(Some("agent-x"))),
        &bulk_call(params.clone()),
    )
    .await;
    let tool = send_bound(
        &runtime,
        "aft",
        Some(head(Some("agent-x"))),
        &json!({"name":manifest::GITHUB_READ_TOOL,"arguments":params}),
    )
    .await;
    assert_eq!(
        facade_only(&op),
        facade_only(&tool),
        "module-grant refusal changed"
    );
    let reply: Value = serde_json::from_slice(&op).unwrap();
    assert!(reply.get("error").is_some(), "{reply}");
    assert!(transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_and_tool_bound_unknown_argument_echoes() {
    let (runtime, _store, transport, _scratch) = setup(&json!({"replies": {}}));
    for length in [256, 4096] {
        let key = "x".repeat(length);
        let mut args = json!({"path": ""});
        args[&key] = json!(true);
        let params = json!({"action":"github.repo.get", "repository":"o/x", "args":args});
        let op = send_bound(
            &runtime,
            "aft",
            Some(head(Some("agent-x"))),
            &bulk_call(params.clone()),
        )
        .await;
        let tool = send_bound(
            &runtime,
            "aft",
            Some(head(Some("agent-x"))),
            &json!({"name":manifest::GITHUB_READ_TOOL,"arguments":params}),
        )
        .await;
        assert_eq!(facade_only(&op), facade_only(&tool));
        let reply: Value = serde_json::from_slice(&op).unwrap();
        assert_eq!(reply["error"]["code"], "endpoint_not_allowed");
        let echoed = reply["error"]["field"].as_str().unwrap();
        assert_eq!(
            echoed.len(),
            256,
            "unknown argument echo must fit 256 bytes"
        );
        if length == 256 {
            assert_eq!(echoed, key);
        } else {
            assert!(echoed.ends_with("[shortened]"));
        }
    }
    assert!(transport.requests().is_empty());
}
