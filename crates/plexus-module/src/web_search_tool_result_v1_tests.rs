use super::*;
use cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY;
use plexus_core::web_search::{
    backend::ReplyShapeError, capability::WebSearchCapability, query::WebSearchQuery,
    WebSearchBackend, WebSearchResult,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use subc_protocol::{BindIdentity, RouteTarget};

fn render(reply: Value, reads_tool_result_v1: bool, core_reader_ready: bool) -> Value {
    with_call_tool_result_for_route(
        Some(manifest::WEB_SEARCH_TOOL),
        reply,
        None,
        reads_tool_result_v1,
        core_reader_ready,
    )
}

#[test]
fn core_reader_gate_only_changes_negotiated_web_search_replies() {
    let found =
        json!({"cached": false, "results": [{"title": "T", "url": "https://example.com/"}]});
    let error = json!({"code": "rate_limited", "message": "slow down", "retry_after_ms": 41_200});
    let cases = [
        (
            json!({"result": found}),
            json!({
                "content": [{"type": "text", "text": "1 web result:\n\n1. T\n   https://example.com/"}],
                "isError": false,
                "structuredContent": found,
                "result": found,
            }),
            json!({
                "content": [{"type": "text", "text": "1 web result:\n\n1. T\n   https://example.com/"}],
                "isError": false,
                "structuredContent": found,
            }),
        ),
        (
            json!({"error": error}),
            json!({
                "content": [{"type": "text", "text": "web_search was refused (rate_limited): the web search rate limit is reached. Retry in 42 seconds (retry_after_ms 41200)."}],
                "isError": true,
                "errorCode": "rate_limited",
                "error": error,
            }),
            json!({
                "content": [{"type": "text", "text": "web_search was refused (rate_limited): the web search rate limit is reached. Retry in 42 seconds (retry_after_ms 41200)."}],
                "isError": true,
                "errorCode": "rate_limited",
                "structuredContent": error,
            }),
        ),
    ];
    for (facade, legacy, pure) in cases {
        let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
        // The shipped gate must keep even negotiated routes byte-identical.
        assert_eq!(
            serde_json::to_vec(&with_call_tool_result_with_repo(
                Some(manifest::WEB_SEARCH_TOOL),
                facade.clone(),
                None,
                true,
            ))
            .unwrap(),
            legacy_bytes
        );
        for (reads, ready) in [(false, false), (true, false), (false, true)] {
            assert_eq!(
                serde_json::to_vec(&render(facade.clone(), reads, ready)).unwrap(),
                legacy_bytes
            );
        }
        let actual = render(facade, true, true);
        assert_eq!(actual, pure);
        assert!(reply_guard::EffectiveFormat::ToolResultV1.fits(&actual));
    }
}

#[test]
fn negotiated_refusals_preserve_all_error_members_and_codes() {
    for code in [
        "module_grant_absent",
        "rate_limited",
        "custom_refusal",
        "access_pending",
    ] {
        let error = json!({
            "code": code,
            "message": "not allowed",
            "detail": {"nested": [1, "kept", {"retry": false}]},
            "retry_after_ms": 90_000,
            "field": "query",
            "retryable": false,
        });
        let actual = render(json!({"error": error}), true, true);
        assert_eq!(actual["structuredContent"], error);
        assert_eq!(actual["errorCode"], code);
        assert_eq!(actual["isError"], true);
        assert_eq!(actual.as_object().unwrap().len(), 4);
        assert!(actual.get("error").is_none());
        assert!(actual.get("result").is_none());
        assert!(reply_guard::EffectiveFormat::ToolResultV1.fits(&actual));
    }
}

#[test]
fn negotiated_web_search_guards_both_content_and_structured_bytes() {
    for facade in [
        json!({"error": {"code": "custom", "message": "x".repeat(65_536)}}),
        json!({"error": {"code": "rate_limited", "message": "slow down", "detail": "x".repeat(3 * 1024 * 1024)}}),
        json!({"result": {"results": [], "extra": "x".repeat(3 * 1024 * 1024)}}),
    ] {
        let actual = render(facade, true, true);
        assert_eq!(actual["errorCode"], "invalid_answer");
        assert_eq!(actual["structuredContent"]["code"], "invalid_answer");
        assert_eq!(actual["isError"], true);
        assert!(actual.get("error").is_none());
        assert!(reply_guard::EffectiveFormat::ToolResultV1.fits(&actual));
    }
}

// The service's clock fixes rate/cache time, not fetched_at. Delegate every Exa
// operation unchanged except the event timestamp so response bytes are stable.
struct FixedFetchedAtExa;

impl WebSearchBackend for FixedFetchedAtExa {
    fn name(&self) -> &'static str {
        ExaRestBackend.name()
    }

    fn app_key(&self) -> &'static str {
        ExaRestBackend.app_key()
    }

    fn action(&self) -> &'static str {
        ExaRestBackend.action()
    }

    fn capability(&self) -> WebSearchCapability {
        ExaRestBackend.capability()
    }

    fn vendor_args(&self, query: &WebSearchQuery, now_ms: i64) -> Value {
        ExaRestBackend.vendor_args(query, now_ms)
    }

    fn map_reply(
        &self,
        reply: &Value,
        max_results: usize,
        _fetched_at_ms: i64,
    ) -> Result<Vec<WebSearchResult>, ReplyShapeError> {
        ExaRestBackend.map_reply(reply, max_results, NOW_MS)
    }
}

fn fixture(label: &str, provider_reply: Value) -> Fixture {
    let mut fixture = Fixture::new(label);
    fixture
        .transport
        .set_response(MockResponse::Success(provider_reply));
    fixture.web_search = Arc::new(WebSearchService::with_clock(
        Arc::new(FixedFetchedAtExa),
        Arc::new(|| NOW_MS),
    ));
    fixture
}

fn two_results() -> Value {
    json!({"results": [
        {
            "title": "Rust release notes",
            "url": "https://blog.rust-lang.org/releases/",
            "text": "The Rust team announces a new release.",
            "publishedDate": "2026-09-18T00:00:00Z",
        },
        {
            "title": "Cargo book",
            "url": "https://doc.rust-lang.org/cargo/",
            "text": "Cargo is the Rust package manager.",
        },
    ]})
}

async fn handler_body(
    fixture: &Fixture,
    arguments: Value,
    negotiated: bool,
    core_reader_ready: bool,
) -> Vec<u8> {
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: fixture.runtime(),
    });
    let routes = Arc::new(RouteBindings::new());
    let bind = ModuleControlRequest::RouteBind {
        route_channel: 41,
        epoch: 1,
        target: RouteTarget::ToolProvider {
            module_id: DEFAULT_MODULE_ID.into(),
        },
        identity: BindIdentity::new("web-search-reply-fixtures", "session"),
        principal: Some(aft()),
        scope: None,
        call_mode: None,
        role_versions: None,
        consumer_capabilities: negotiated.then(|| vec![TOOL_RESULT_V1_CAPABILITY.into()]),
        admission_facts: None,
    };
    let (writer, mut responses) = mpsc::channel(1);
    handle_control_request(
        Frame::build(
            FrameType::Request,
            wire::control_flags(),
            0,
            0,
            1,
            serde_json::to_vec(&bind).unwrap(),
        )
        .unwrap(),
        &writer,
        &state,
        &routes,
    )
    .await
    .unwrap();
    let ack = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "web search fixture bind",
    )
    .await;
    assert_eq!(ack.header.ty, FrameType::Response);
    assert_eq!(
        routes.binding(41, 1).unwrap().unwrap().reads_tool_result_v1,
        negotiated
    );
    handle_tool_request_with_web_search_reader(
        Frame::build(
            FrameType::Request,
            wire::control_flags(),
            41,
            1,
            7,
            serde_json::to_vec(&json!({"name": manifest::WEB_SEARCH_TOOL, "arguments": arguments}))
                .unwrap(),
        )
        .unwrap(),
        &writer,
        &state,
        &routes,
        request_execution::RequestBudget::new(),
        core_reader_ready,
    )
    .await
    .unwrap();
    let response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "web search fixture response",
    )
    .await;
    assert_eq!(response.header.ty, FrameType::Response);
    response.body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_reply_fixtures_match_bytes() {
    const REGENERATE: &str = "PLEXUS_REGENERATE_WEB_SEARCH_TOOL_RESULT_V1";
    let query = json!({"query": "rust release notes"});
    let success = handler_body(
        &fixture("pure-reply", two_results()),
        query.clone(),
        true,
        true,
    )
    .await;
    let legacy = handler_body(
        &fixture("legacy-reply", two_results()),
        query.clone(),
        false,
        true,
    )
    .await;
    let gate_off = handler_body(
        &fixture("gated-reply", two_results()),
        query,
        true,
        CORE_WEB_SEARCH_TOOL_RESULT_V1_READER_READY,
    )
    .await;
    assert_eq!(gate_off, legacy, "the shipped gate preserves today's bytes");
    let parsed: Value = serde_json::from_slice(&success).unwrap();
    let legacy_parsed: Value = serde_json::from_slice(&legacy).unwrap();
    assert_eq!(parsed["isError"], false);
    assert_eq!(parsed["structuredContent"]["cached"], false);
    assert_eq!(
        parsed["structuredContent"]["results"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(parsed["structuredContent"]["results"][0]
        .get("published_at")
        .is_some());
    assert!(parsed["structuredContent"]["results"][1]
        .get("published_at")
        .is_none());
    assert_eq!(parsed["structuredContent"], legacy_parsed["result"]);
    assert_eq!(parsed["content"], legacy_parsed["content"]);

    let results: Vec<_> = (0..20)
        .map(|index| {
            let prefix = format!("https://example.com/{index}/");
            json!({
                "title": "🦀".repeat(300),
                "text": "🦀".repeat(600),
                "url": format!("{prefix}{}", "u".repeat(2048 - prefix.len())),
                "publishedDate": "2026-09-18T00:00:00Z",
            })
        })
        .collect();
    let subset = handler_body(
        &fixture("subset-reply", json!({"results": results})),
        json!({"query": "large web result fixture", "max_results": 20}),
        true,
        true,
    )
    .await;
    let parsed: Value = serde_json::from_slice(&subset).unwrap();
    let structured = &parsed["structuredContent"];
    let shown = structured["results_shown"].as_u64().unwrap();
    assert!(shown > 0 && shown < 20);
    assert_eq!(structured["results_found"], 20);
    assert_eq!(structured["results_omitted"], 20 - shown);
    assert_eq!(
        structured["results"].as_array().unwrap().len(),
        shown as usize
    );
    assert!(parsed["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains(&format!("Shown {shown} of 20 results found")));
    for result in structured["results"].as_array().unwrap() {
        assert_eq!(result["title"], "🦀".repeat(300));
        assert_eq!(result["excerpt"], "🦀".repeat(600));
        assert_eq!(result["url"].as_str().unwrap().len(), 2048);
    }

    let limited = fixture("limited-reply", two_results());
    limited
        .store
        .set_web_search_limits(
            "exa",
            WebSearchLimits {
                per_caller_per_minute: 1,
                per_backend_per_minute: 120,
            },
        )
        .unwrap();
    let first = handler_body(&limited, json!({"query": "first search"}), true, true).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&first).unwrap()["isError"],
        false
    );
    let rate_limited = handler_body(&limited, json!({"query": "second search"}), true, true).await;
    let parsed: Value = serde_json::from_slice(&rate_limited).unwrap();
    assert_eq!(parsed["errorCode"], "rate_limited");
    assert_eq!(parsed["structuredContent"]["code"], "rate_limited");
    assert!(
        parsed["structuredContent"]["retry_after_ms"]
            .as_u64()
            .unwrap()
            > 0
    );

    let other = handler_body(
        &fixture("code-lookup-reply", two_results()),
        json!({"query": "site:github.com/owner/repo/blob/main/lib.rs"}),
        true,
        true,
    )
    .await;
    let parsed: Value = serde_json::from_slice(&other).unwrap();
    assert_eq!(parsed["errorCode"], "web_search_code_lookup");
    assert_eq!(
        parsed["structuredContent"],
        plexus_core::web_search::WebSearchRefusal::CodeLookup.to_wire()["error"]
    );

    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/web-search-tool-result-v1");
    let regenerate = std::env::var(REGENERATE).as_deref() == Ok("1");
    let mut sums = String::new();
    for (name, bytes) in [
        ("legacy-result.json", legacy),
        ("refusal-other.json", other),
        ("refusal-rate-limited.json", rate_limited),
        ("result-shown-subset.json", subset),
        ("result.json", success),
    ] {
        let reply: Value = serde_json::from_slice(&bytes).unwrap();
        if name != "legacy-result.json" {
            assert!(reply.get("result").is_none(), "{name}");
            assert!(reply.get("error").is_none(), "{name}");
            assert!(
                reply_guard::EffectiveFormat::ToolResultV1.fits(&reply),
                "{name}"
            );
        }
        sums.push_str(&format!("{:x}  {name}\n", Sha256::digest(&bytes)));
        let path = directory.join(name);
        if regenerate {
            std::fs::write(path, &bytes).unwrap();
        } else {
            assert_eq!(
                std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
                bytes,
                "{name}: handler reply changed; rerun with {REGENERATE}=1 and review the diff"
            );
        }
    }
    let path = directory.join("SHA256SUMS");
    if regenerate {
        std::fs::write(path, sums).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(path).unwrap(), sums);
    }
}
