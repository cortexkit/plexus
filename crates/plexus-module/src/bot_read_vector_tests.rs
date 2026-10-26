// Replays every vector under tests/fixtures/github-read-bot through the real
// tool-call handler and compares the reply frame's body byte for byte with the
// vector's `.reply.json`. AFT's `gh` shim is built against these replies, so a
// change here is a change to that contract. See the README beside the vectors.

use super::bot_read_tests::send_bound;
use super::*;
use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};

const REGENERATE: &str = "PLEXUS_REGENERATE_BOT_READ_VECTORS";

fn vector_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/github-read-bot")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap())
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The scope stamp a vector names, as the daemon would stamp the route.
fn stamp(scope: &Value) -> Option<ScopeStamp> {
    let kind = match scope.get("kind")?.as_str()? {
        "head" => ScopeKind::Head,
        "worker" => ScopeKind::Worker,
        other => panic!("unknown vector scope kind {other}"),
    };
    let text = |field: &str| scope.get(field).and_then(Value::as_str).map(str::to_owned);
    Some(
        ScopeStamp::new(
            Principal::Reserved {
                module_id: "aft".into(),
            },
            "vector-session",
            1,
            kind,
        )
        .with_attributes(
            ScopeAttributes::new()
                .with_agent_id(text("agent_id"))
                .with_on_behalf_of_agent(text("on_behalf_of_agent")),
        )
        .with_owner_authorized(true),
    )
}

fn mock(reply: &Value) -> MockResponse {
    if let Some(success) = reply.get("success") {
        return MockResponse::Success(success.clone());
    }
    MockResponse::VendorError {
        code: reply["vendor_error"].as_str().unwrap().to_owned(),
        message: String::new(),
    }
}

/// A budget refusal's delay depends on the clock, so it is checked for range
/// and then replaced by the vector's value, in the error and in the text.
fn normalize_clock(actual: &mut Value, expected: &Value) {
    if actual["error"]["code"] != "read_budget_exhausted" {
        return;
    }
    let retry = actual["error"]["retry_after_ms"].as_i64().unwrap();
    assert!(retry > 0 && retry <= 3_600_000, "{actual}");
    if expected.get("error").is_some() {
        actual["error"]["retry_after_ms"] = expected["error"]["retry_after_ms"].clone();
        actual["content"] = expected["content"].clone();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_bot_read_vector_replays_byte_for_byte() {
    let regenerate = std::env::var(REGENERATE).as_deref() == Ok("1");
    let mut names: Vec<String> = std::fs::read_dir(vector_dir())
        .unwrap()
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            name.strip_suffix(".request.json").map(str::to_owned)
        })
        .collect();
    names.sort();
    let mut covered = std::collections::BTreeSet::new();
    for name in &names {
        let dir = vector_dir();
        let request = read_json(&dir.join(format!("{name}.request.json")));
        let github = read_json(&dir.join(format!("{name}.github.json")));
        let reply_path = dir.join(format!("{name}.reply.json"));
        let (runtime, store, transport, _scratch) = imported_runtime_with_actions(&[
            "github.repo.get",
            "github.search.code",
            "github.search.issues",
            "github.pulls.open",
            "github.actions.job.get",
            "github.actions.job_log",
        ]);
        if let Some(spent) = github["setup"]["reads_spent"].as_i64() {
            let now = plexus_core::now_ms();
            for _ in 0..spent / 16 {
                store.reserve_github_bot_read("app-x", 16, now).unwrap();
            }
            if spent % 16 != 0 {
                store
                    .reserve_github_bot_read("app-x", spent % 16, now)
                    .unwrap();
            }
            assert_eq!(
                store.github_bot_reads_in_window("app-x", now).unwrap(),
                3_500,
                "{name}: the hourly read budget must be fully spent"
            );
        }
        for (action, reply) in github["replies"].as_object().unwrap() {
            transport.set_response_for_method(action, "", mock(reply));
        }
        let body = send_bound(&runtime, "aft", stamp(&request["scope"]), &request["call"]).await;
        let mut actual: Value = serde_json::from_slice(&body).unwrap();
        let sent: Vec<Value> = transport
            .requests()
            .iter()
            .map(|sent| json!({"connection_id": sent.connection_id, "action": sent.action, "args": sent.args}))
            .collect();
        assert_eq!(
            Value::Array(sent),
            github["expected_requests"],
            "{name}: the GitHub requests plexus sent"
        );
        let action = request["call"]["arguments"]["action"].as_str().unwrap();
        covered.insert(match actual["error"]["code"].as_str() {
            None => action.to_owned(),
            Some("endpoint_not_allowed") => {
                format!(
                    "endpoint_not_allowed:{}",
                    actual["error"]["field"].as_str().unwrap()
                )
            }
            Some(code) => code.to_owned(),
        });
        if regenerate {
            normalize_clock(&mut actual, &json!({}));
            let mut text = serde_json::to_string_pretty(&actual).unwrap();
            text.push('\n');
            std::fs::write(&reply_path, text).unwrap();
            continue;
        }
        let expected = read_json(&reply_path);
        if actual["error"]["code"] == "read_budget_exhausted" {
            normalize_clock(&mut actual, &expected);
            assert_eq!(
                serde_json::to_vec(&actual).unwrap(),
                serde_json::to_vec(&expected).unwrap(),
                "{name}: reply differs from {}",
                reply_path.display()
            );
        } else {
            assert_eq!(
                String::from_utf8(body).unwrap(),
                serde_json::to_string(&expected).unwrap(),
                "{name}: reply differs from {}",
                reply_path.display()
            );
        }
    }
    let required = [
        "github.repo.get",
        "github.search.code",
        "github.search.issues",
        "github.pulls.open",
        "github.actions.job_log",
        "read_budget_exhausted",
        "repository_not_visible",
        "endpoint_not_allowed:path",
        "endpoint_not_allowed:accept",
        "endpoint_not_allowed:q",
        "endpoint_not_allowed:query",
        "response_too_large",
        "agent_identity_required",
        "vendor_error",
    ];
    for vector in required {
        assert!(
            covered.contains(vector),
            "no vector covers {vector}: {covered:?}"
        );
    }
}
