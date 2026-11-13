use super::bot_read_tests::{head, send_bound};
use super::job_log_tests::{actions_runtime, flow};
use super::*;
use cortexkit_role_tool_provider::result::{legacy_model_visible_bytes, MAX_MODEL_VISIBLE_BYTES};

fn assert_bounded(reply: &Value) {
    assert!(legacy_model_visible_bytes(reply) <= MAX_MODEL_VISIBLE_BYTES);
}

#[test]
fn tail_shape_vectors_pin_short_and_escaped_lengths() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/github-read-tails");
    let regenerate =
        std::env::var("PLEXUS_REGENERATE_GITHUB_READ_TAIL_VECTORS").as_deref() == Ok("1");
    for (name, action) in [
        ("job-log", "github.actions.job_log"),
        ("artifact-file", "github.actions.artifact_file"),
    ] {
        for (case, text) in [
            ("short", "test NAME FAILED\n".to_owned()),
            ("escaped", format!("{}end", "\u{0001}".repeat(59_997))),
        ] {
            let mut result = json!({"repository":"o/x","total_bytes":text.len(),
                "truncated":false,"text":text,"max_bytes":60_000});
            if name == "job-log" {
                result["job_id"] = json!(42);
            } else {
                result["run_id"] = json!(42);
                result["artifact"] = json!("shard-1");
                result["path"] = json!("logs/shard.log");
            }
            let reply = github_read_tool::shape_tail(action, json!({"result":result}));
            for reads_tool_result_v1 in [false, true] {
                assert_eq!(
                    github_read_tool::guard(action, reply.clone(), reads_tool_result_v1),
                    reply
                );
            }
            assert_eq!(reply["result"]["max_bytes"], 60_000);
            let length = reply["result"]["length"].as_u64().unwrap();
            assert!(length < 60_000);
            assert_eq!(
                length,
                reply["result"]["text"].as_str().unwrap().len() as u64
            );
            if case == "short" {
                assert_eq!(length, 17);
                assert_eq!(reply["result"]["truncated"], false);
            } else {
                assert_eq!(reply["result"]["truncated"], true);
            }
            assert_bounded(&reply);
            let rendered = format!("{}\n", serde_json::to_string_pretty(&reply).unwrap());
            let path = dir.join(format!("{name}-{case}.reply.json"));
            if regenerate {
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(&path, &rendered).unwrap();
            }
            assert_eq!(std::fs::read_to_string(path).unwrap(), rendered);
        }
    }
}

#[test]
fn tail_trimming_keeps_utf8_suffixes_and_guard_limit_is_inclusive() {
    for text in [
        "🦀".repeat(20_000),
        format!("{}🦀end", "\u{0001}".repeat(59_993)),
    ] {
        let reply = github_read_tool::shape_tail(
            "github.actions.job_log",
            json!({"result":{
                "job_id":42,"repository":"o/x","max_bytes":60_000,
                "total_bytes":text.len(),"truncated":false,"text":text
            }}),
        );
        let kept = reply["result"]["text"].as_str().unwrap();
        assert!(text.ends_with(kept));
        assert!(kept.ends_with(if text.ends_with("end") {
            "🦀end"
        } else {
            "🦀"
        }));
        assert!(kept.len() <= 60_000);
        assert_bounded(&reply);
    }
    let exact = json!({"result":"x".repeat(65_523)});
    assert_eq!(legacy_model_visible_bytes(&exact), 65_536);
    assert_eq!(
        github_read_tool::guard("github.issue.get", exact.clone(), false),
        exact
    );
    let over = json!({"result":"x".repeat(65_524)});
    assert_eq!(
        github_read_tool::guard("github.issue.get", over, false)["error"]["code"],
        "response_too_large"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tails_clamp_installed_router_requests_and_bound_six_byte_escapes() {
    for action in ["github.actions.job_log", "github.actions.artifact_file"] {
        for requested in [None, Some(65_536), Some(u64::MAX)] {
            let (runtime, _store, transport, _scratch) = actions_runtime();
            transport.set_response_for_method("list_workflow_run_artifacts", "", MockResponse::Success(json!({
                "total_count":1,"artifacts":[{"id":7,"name":"shard-1","created_at":"2026-10-12T00:00:00Z","expired":false,"size_in_bytes":123}]
            })));
            let text = format!("{}end", "\u{0001}".repeat(59_997));
            transport.set_response_for_method(
                action,
                "",
                MockResponse::Success(json!({
                    "total_bytes":u64::MAX,"truncated":true,"text":text
                })),
            );
            let mut args = if action == "github.actions.job_log" {
                json!({"job_id":u64::MAX})
            } else {
                json!({"run_id":u64::MAX,"artifact":"shard-1","path":"logs/shard.log"})
            };
            if let Some(requested) = requested {
                args["max_bytes"] = json!(requested);
            }
            let reply = send_facade_frame(
                runtime,
                manifest::GITHUB_READ_TOOL,
                json!({"action":action,"repository":"o/x","args":args}),
                "basal",
                Some(flow(Some("agent-x"))),
            )
            .await;
            assert_eq!(reply["result"]["max_bytes"], 60_000, "{action}: {reply}");
            let kept = reply["result"]["text"].as_str().unwrap();
            assert!(text.ends_with(kept));
            assert!(kept.ends_with("end"));
            assert!(kept.len() < 60_000);
            assert_eq!(reply["result"]["length"], kept.len());
            assert_eq!(reply["result"]["truncated"], true);
            assert_eq!(
                transport.requests().last().unwrap().args["max_bytes"],
                60_000
            );
            assert_bounded(&reply);
            // One more old control byte must no longer fit: shaping keeps
            // the longest suffix rather than an arbitrary small tail.
            let mut larger = reply.clone();
            larger["result"]["text"] = json!(format!("\u{0001}{kept}"));
            larger["result"]["length"] = json!(kept.len() + 1);
            assert!(legacy_model_visible_bytes(&larger) > MAX_MODEL_VISIBLE_BYTES);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_range_clamps_one_mib_and_pages_from_returned_length() {
    let (runtime, _store, transport, _scratch) = bot_read_tests::bot_runtime();
    transport.set_response_for_method(
        "github.actions.job.get",
        "",
        MockResponse::Success(json!({
            "status":200,"body":{"status":"completed"},"next_page":null
        })),
    );
    let mut offset = 0;
    for length in [1_048_576, u64::MAX] {
        let body = "\u{0001}".repeat(10_000);
        transport.set_response_for_method(
            "github.actions.job_log",
            "",
            MockResponse::Success(json!({
                "body":body,"offset":offset,"length":10_000,"total_bytes":30_000
            })),
        );
        let bytes = send_bound(
            &runtime,
            "aft",
            Some(head(Some("agent-x"))),
            &json!({
                "name":manifest::GITHUB_READ_TOOL,"arguments":{
                    "action":"github.actions.job_log","repository":"o/x",
                    "args":{"job_id":42,"offset":offset,"length":length}
                }
            }),
        )
        .await;
        let reply: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reply["result"]["body"], body);
        assert_eq!(reply["result"]["offset"], offset);
        assert_eq!(reply["result"]["length"], 10_000);
        assert_eq!(reply["result"]["total_bytes"], 30_000);
        let sent = transport.requests();
        assert_eq!(sent.last().unwrap().args["offset"], offset);
        assert_eq!(sent.last().unwrap().args["length"], 10_000);
        assert_bounded(&reply);
        offset = reply["result"]["offset"].as_u64().unwrap()
            + reply["result"]["length"].as_u64().unwrap();
    }
    assert_eq!(offset, 20_000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_repo_and_search_bodies_are_refused_whole_after_send() {
    for (action, args, body) in [
        (
            "github.repo.get",
            json!({"path":"contents/large.txt"}),
            json!("x".repeat(65536)),
        ),
        (
            "github.search.code",
            json!({"q":"needle"}),
            json!({"total_count":1,"incomplete_results":false,"items":[{"path":"x".repeat(65536)}]}),
        ),
        (
            "github.search.issues",
            json!({"q":"needle"}),
            json!({"total_count":1,"incomplete_results":false,"items":[{"body":"x".repeat(65536)}]}),
        ),
    ] {
        let (runtime, _store, transport, _scratch) = bot_read_tests::bot_runtime();
        transport.set_response(MockResponse::Success(
            json!({"status":200,"body":body,"next_page":null}),
        ));
        let bytes = send_bound(
            &runtime,
            "aft",
            Some(head(Some("agent-x"))),
            &json!({
                "name":manifest::GITHUB_READ_TOOL,
                "arguments":{"action":action,"repository":"o/x","args":args}
            }),
        )
        .await;
        let reply: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            reply["error"]["code"], "response_too_large",
            "{action}: {reply}"
        );
        assert_eq!(reply["error"]["transmission"], "sent");
        assert!(reply.get("content").is_none());
        assert!(reply.get("result").is_none());
        assert!(reply.get("structuredContent").is_none());
        let message = reply["error"]["message"].as_str().unwrap();
        for hint in ["path", "per_page", "page"] {
            assert!(message.contains(hint));
        }
        assert_eq!(transport.requests().len(), 1);
        assert_bounded(&reply);
    }
}

#[test]
fn final_guard_replaces_oversize_other_actions_and_preserves_transmission() {
    let rendered = json!({"result":{"items":["x".repeat(65536)]}});
    assert!(legacy_model_visible_bytes(&rendered) > MAX_MODEL_VISIBLE_BYTES);
    let reply = github_read_tool::guard("github.pulls.open", rendered.clone(), false);
    assert_eq!(reply["error"]["code"], "response_too_large");
    assert_eq!(reply["error"]["transmission"], "sent");
    assert!(reply.get("result").is_none());
    assert_bounded(&reply);
    let local = github_read_tool::guard("github.bindings.list", rendered, false);
    assert_eq!(local["error"]["transmission"], "not_sent");
    for transmission in ["sent", "not_sent", "unknown", "failed"] {
        let refusal = json!({"error":{"transmission":transmission,"detail":"x".repeat(65536)}});
        let reply = github_read_tool::guard("github.issue.get", refusal, false);
        assert_eq!(reply["error"]["transmission"], transmission);
        assert_bounded(&reply);
    }
}

#[test]
fn extracted_guard_keeps_existing_fallback_bytes_for_both_bind_formats() {
    for (action, original, transmission) in [
        (
            "github.issue.get",
            json!({"result":"x".repeat(65_536)}),
            "sent",
        ),
        (
            "github.bindings.list",
            json!({"result":"x".repeat(65_536)}),
            "not_sent",
        ),
        (
            "github.issue.get",
            json!({"error":{"detail":"x".repeat(65_536)}}),
            "not_sent",
        ),
        (
            "github.issue.get",
            json!({"error":{"outcome":{"transmission":"unknown"},"detail":"x".repeat(65_536)}}),
            "unknown",
        ),
        (
            "github.issue.get",
            json!({"error":{"transmission":"failed","outcome":{"transmission":"sent"},"detail":"x".repeat(65_536)}}),
            "failed",
        ),
    ] {
        let expected = format!(
            r#"{{"error":{{"code":"response_too_large","message":"GitHub read reply exceeds the tool's 65536-byte limit and was not returned; narrow the request with a smaller path, per_page, or page","transmission":"{transmission}"}}}}"#
        );
        for capability in [false, true] {
            let body = github_read_tool::guard(action, original.clone(), capability);
            assert_eq!(serde_json::to_vec(&body).unwrap(), expected.as_bytes());
            assert_bounded(&body);
        }
    }
}
