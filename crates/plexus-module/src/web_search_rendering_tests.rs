use super::with_call_tool_result;
use crate::manifest::WEB_SEARCH_TOOL;
use serde_json::{json, Value};

// These inputs and expected strings are the web search text models already
// receive, copied from the tests of Prefrontal (the agent runtime), which
// rendered it before plexus served the tool itself. They keep the text from
// drifting when the provider changes. The fixture README
// (tests/fixtures/core-web-search/README.md) names the Prefrontal revision and
// source lines they came from.
fn live_reply() -> Value {
    json!({"result": {
        "backend": "exa",
        "cached": false,
        "results": [
            {
                "title": "Rust 1.90 released",
                "url": "https://blog.rust-lang.org/2026/09/18/Rust-1.90.0/",
                "excerpt": "The Rust team is happy\nto announce   a new version.",
                "fetched_at": "2026-09-28T17:02:21.097Z",
                "published_at": "2026-09-18T00:00:00.000Z"
            },
            {
                "title": "Cargo book",
                "url": "https://doc.rust-lang.org/cargo/",
                "excerpt": "Cargo is the Rust package manager.",
                "fetched_at": "2026-09-28T17:02:21.097Z"
            }
        ]
    }})
}

fn rendered(reply: Value) -> String {
    let original = reply.clone();
    let reply = with_call_tool_result(Some(WEB_SEARCH_TOOL), reply);
    let result: cortexkit_role_tool_provider::result::ToolResult =
        serde_json::from_value(reply.clone()).unwrap();
    cortexkit_role_tool_provider::result::validate(&result).unwrap();
    if let Some(result) = original.get("result") {
        assert_eq!(&reply["result"], result);
        assert_eq!(&reply["structuredContent"], result);
        assert_eq!(reply["isError"], false);
    } else {
        assert_eq!(reply["error"], original["error"]);
        assert_eq!(reply["isError"], true);
        let code = original["error"]["code"].as_str().unwrap().trim();
        assert_eq!(
            reply["errorCode"],
            if code.is_empty() { "unknown" } else { code }
        );
        assert!(reply.get("structuredContent").is_none());
    }
    assert_eq!(reply["content"].as_array().unwrap().len(), 1);
    assert_eq!(reply["content"][0]["type"], "text");
    reply["content"][0]["text"].as_str().unwrap().to_string()
}

fn refused(error: Value) -> String {
    rendered(json!({"error": error}))
}

#[test]
fn results_render_numbered_with_url_published_day_and_excerpt() {
    assert_eq!(
        rendered(live_reply()),
        concat!(
            "2 web results:\n\n",
            "1. Rust 1.90 released\n",
            "   https://blog.rust-lang.org/2026/09/18/Rust-1.90.0/\n",
            "   Published 2026-09-18\n",
            "   The Rust team is happy to announce a new version.\n\n",
            "2. Cargo book\n",
            "   https://doc.rust-lang.org/cargo/\n",
            "   Cargo is the Rust package manager."
        ),
        "web_search must render the published day, not the full timestamp"
    );
}

#[test]
fn cached_results_say_cached_once() {
    let mut reply = live_reply();
    reply["result"]["cached"] = json!(true);
    let text = rendered(reply);
    assert!(text.starts_with("2 web results (cached):"), "{text}");
    assert_eq!(text.matches("cached").count(), 1, "{text}");
    assert_eq!(
        rendered(json!({"result": {"cached": true, "results": []}})),
        "No web results (cached)."
    );
    assert_eq!(
        rendered(json!({"result": {"results": []}})),
        "No web results."
    );
}

#[test]
fn rate_limited_refusal_renders_when_to_retry_mutation_proof() {
    assert_eq!(
        refused(json!({"code": "rate_limited", "retry_after_ms": 41_200})),
        "web_search was refused (rate_limited): the web search rate limit is reached. Retry in 42 seconds (retry_after_ms 41200)."
    );
    let text = refused(json!({"code": "rate_limited", "retry_after_ms": 90_000}));
    assert!(text.contains("Retry in 1 minute 30 seconds"), "{text}");
}

#[test]
fn refusals_name_their_code_and_what_to_do() {
    assert_eq!(
        refused(json!({
            "code": "invalid_query", "message": "a web search argument is invalid; see field", "field": "recency"
        })),
        "web_search was refused (invalid_query): the `recency` argument is not valid. Correct it and search again."
    );
    assert_eq!(
        refused(json!({
            "code": "backend_unavailable", "message": "the web search backend is unavailable", "backend": "exa"
        })),
        "web_search was refused (backend_unavailable): exa is unavailable right now. Retry in a little while."
    );
    assert_eq!(
        refused(json!({"code": "agent_not_granted", "message": "x"})),
        "web_search was refused (agent_not_granted): plexus holds no web search grant for this agent. An operator must grant it; retrying fails the same way until then."
    );
}

#[test]
fn code_lookup_refusal_renders_the_source_search_alternatives() {
    assert_eq!(
        rendered(plexus_core::web_search::WebSearchRefusal::CodeLookup.to_wire()),
        "web_search was refused (web_search_code_lookup): web_search doesn't look up source code. For public repositories use code_search. For a dependency, read its source on disk (for Rust, ~/.cargo/registry/src). For a commit, use git."
    );
}

#[test]
fn rendering_trims_fields_collapses_text_and_handles_missing_results() {
    assert_eq!(
        rendered(json!({"result": {"results": [{
            "title": "  A\n  title  ", "url": " https://example.com/ ",
            "published_at": " 2026-09-18 ", "excerpt": " an\n excerpt "
        }]}})),
        "1 web result:\n\n1. A title\n   https://example.com/\n   Published 2026-09-18\n   an excerpt"
    );
    assert_eq!(
        rendered(json!({"result": {"results": [{"title": "  ", "url": null, "excerpt": 1}]}})),
        "1 web result:\n\n1. (untitled)"
    );
    for result in [json!({}), json!({"results": null}), json!({"results": {}})] {
        assert_eq!(rendered(json!({"result": result})), "No web results.");
    }
}

#[test]
fn refusal_fallbacks_and_backend_states_match_core_wording() {
    for (error, expected) in [
        (
            json!({"code": "web_search_not_granted", "detail": {"kept": true}}),
            "web_search was refused (web_search_not_granted): plexus grants no web search backend to the calling module. An operator must grant it; retrying fails the same way until then.",
        ),
        (
            json!({"code": "backend_quarantined", "backend": "exa"}),
            "web_search was refused (backend_quarantined): exa is quarantined pending operator review; retrying fails the same way until an operator clears it.",
        ),
        (
            json!({"code": "backend_ambiguous"}),
            "web_search was refused (backend_ambiguous): more than one plexus connection could serve this search, and plexus will not pick whose account pays. An operator must leave one; retrying fails the same way until then.",
        ),
        (
            json!({"code": "backend_unavailable"}),
            "web_search was refused (backend_unavailable): the search backend is unavailable right now. Retry in a little while.",
        ),
        (
            json!({"code": "rate_limited"}),
            "web_search was refused (rate_limited): the web search rate limit is reached. Retry in a minute.",
        ),
        (
            json!({"code": "invalid_query"}),
            "web_search was refused (invalid_query): the `an argument` argument is not valid. Correct it and search again.",
        ),
        (
            json!({"code": "  custom  ", "message": "  detail  ", "retryable": true}),
            "web_search was refused (custom): detail. Retry shortly.",
        ),
        (
            json!({"code": " ", "message": null}),
            "web_search was refused (unknown): no detail given.",
        ),
    ] {
        assert_eq!(refused(error), expected);
    }
}

#[test]
fn retry_words_round_up_and_keep_singular_units() {
    for (milliseconds, expected) in [
        (0, "1 second"),
        (1, "1 second"),
        (1_001, "2 seconds"),
        (60_000, "1 minute"),
        (60_001, "1 minute 1 second"),
        (120_000, "2 minutes"),
    ] {
        assert_eq!(super::web_search_wait_words(milliseconds), expected);
    }
}

#[test]
fn tool_result_v1_search_refusals_keep_every_code() {
    use cortexkit_role_tool_provider::result::{validate, ToolResult};
    for tool in [WEB_SEARCH_TOOL, crate::manifest::CODE_SEARCH_TOOL] {
        for code in [
            "web_search_code_lookup",
            "rate_limited",
            "invalid_query",
            "web_search_not_granted",
            "code_search_not_granted",
            "agent_not_granted",
            "backend_unavailable",
            "backend_quarantined",
            "backend_ambiguous",
            "backend_invalid_response",
            "store_failure",
            "argument_undeclared",
            "module_grant_absent",
            "agent_grant_absent",
            "secret_input_rejected",
            "invalid_request",
            "route_not_bound",
            "flow_carrier_not_admitted",
            "flow_scope_required",
            "consent_unavailable",
            "call_mode_unsupported",
        ] {
            let original = json!({"error":{"code":code,"message":"the search was refused"}});
            let reply = with_call_tool_result(Some(tool), original.clone());
            assert_eq!(
                reply["errorCode"], code,
                "tool-result/v1 must preserve every search refusal code: {tool}/{code}"
            );
            assert_eq!(reply["isError"], true);
            let typed: ToolResult = serde_json::from_value(reply.clone()).unwrap();
            validate(&typed).unwrap();
            assert_eq!(typed.content.len(), 1);
            assert_eq!(reply["content"][0]["type"], "text");
            assert!(reply.get("structuredContent").is_none());
            if tool == WEB_SEARCH_TOOL {
                assert_eq!(reply["error"], original["error"]);
            } else {
                assert!(reply.get("error").is_none());
            }
        }
    }
}

#[test]
fn oversized_search_content_is_refused_without_invalid_content_or_truncation() {
    use cortexkit_role_tool_provider::result::{validate, ToolResult};
    let message = "plexus could not produce a valid tool-result/v1 result";
    for tool in [WEB_SEARCH_TOOL, crate::manifest::CODE_SEARCH_TOOL] {
        let reply = with_call_tool_result(
            Some(tool),
            json!({"error":{"code":"invalid_request","message":"x".repeat(3 * 1024 * 1024)}}),
        );
        assert_eq!(reply["isError"], true);
        assert_eq!(reply["errorCode"], "invalid_answer");
        assert_eq!(reply["content"], json!([{"type": "text", "text": message}]));
        if tool == WEB_SEARCH_TOOL {
            assert_eq!(
                reply["error"],
                json!({"code": "invalid_answer", "message": message})
            );
        }
        validate(&serde_json::from_value::<ToolResult>(reply).unwrap()).unwrap();
    }
}

// The whole reply, member by member, for both search tools. A head renders
// content parts only from a tool-result/v1 body: `content` as a list of typed
// parts with `isError`, `errorCode` and `structuredContent` beside it. A reply
// that drops back to the plain legacy envelope is shown to the model as JSON.
#[test]
fn search_replies_have_the_exact_tool_result_v1_shape() {
    let found = json!({"results": [{"title": "T", "url": "https://example.com/"}]});
    assert_eq!(
        with_call_tool_result(Some(WEB_SEARCH_TOOL), json!({"result": found.clone()})),
        json!({
            "content": [{"type": "text", "text": "1 web result:\n\n1. T\n   https://example.com/"}],
            "isError": false,
            "structuredContent": found,
            "result": found,
        }),
        "a web_search success must be a tool-result/v1 body beside its legacy result"
    );
    let error = json!({"code": "rate_limited", "message": "slow down"});
    assert_eq!(
        with_call_tool_result(Some(WEB_SEARCH_TOOL), json!({"error": error.clone()})),
        json!({
            "content": [{"type": "text", "text": "web_search was refused (rate_limited): the web search rate limit is reached. Retry in a minute."}],
            "isError": true,
            "errorCode": "rate_limited",
            "error": error,
        }),
        "a web_search refusal must be a tool-result/v1 body beside its legacy error"
    );
    assert_eq!(
        with_call_tool_result(
            Some(crate::manifest::CODE_SEARCH_TOOL),
            json!({"error": {"code": "rate_limited", "message": "slow down"}}),
        ),
        json!({
            "content": [{"type": "text", "text": "rate_limited: slow down"}],
            "isError": true,
            "errorCode": "rate_limited",
        }),
        "a code_search refusal must be a bare tool-result/v1 body"
    );
}
