use serde_json::{json, Value};

use super::*;
use crate::manifest::{HttpMethod, Risk, TransportKind};
use crate::web_search::capability::{CapabilityFailure, CapabilitySkip, CapabilitySkipReason};
use crate::web_search::query::{Recency, MAX_RESULTS_LIMIT};

const NOW: i64 = 1_790_596_800_000; // 2026-09-28T12:00:00Z

/// The recorded vendor reply `name` from `fixtures.json`, parsed.
fn recorded_body(name: &str) -> Value {
    let recordings: Value = serde_json::from_str(include_str!("fixtures.json")).unwrap();
    let body = recordings[name]["body"]
        .as_str()
        .unwrap_or_else(|| panic!("missing recorded Kimi reply {name}"));
    serde_json::from_str(body).unwrap()
}

fn query(text: &str, domains: &[&str], recency: Option<Recency>) -> WebSearchQuery {
    WebSearchQuery {
        query: text.to_string(),
        max_results: 5,
        include_domains: domains.iter().map(|domain| domain.to_string()).collect(),
        recency,
    }
}

fn shipped_manifest() -> crate::manifest::AppManifest {
    let source = include_str!("../../../../../../catalog/kimi_rest.jsonc");
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

fn skip(failed: CapabilityFailure) -> CapabilitySkip {
    CapabilitySkip {
        provider: "kimi",
        reason: CapabilitySkipReason::Capability,
        failed,
    }
}

#[test]
fn vendor_args_send_only_text_query_and_limit() {
    let prepared = KimiRestBackend
        .prepare(&query("Kimi K2 model release", &[], None), NOW)
        .unwrap();
    assert_eq!(
        prepared.vendor_args,
        json!({"text_query": "Kimi K2 model release", "limit": 5}),
        "the query travels as text_query with the result count as limit"
    );
    assert_eq!(prepared.query.query, "Kimi K2 model release");
}

#[test]
fn the_shipped_manifest_pins_kimis_bearer_post_to_coding_v1_search() {
    let manifest = shipped_manifest();
    assert_eq!(manifest.key, KimiRestBackend.app_key());
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://api.kimi.com");
    assert_eq!(manifest.credential_bindings.len(), 1);
    let binding = &manifest.credential_bindings[0];
    assert_eq!(
        (
            binding.placement.as_str(),
            binding.key.as_str(),
            binding.prefix.as_str()
        ),
        ("header", "Authorization", "Bearer ")
    );
    assert!(binding.required);
    assert_eq!(manifest.actions_baseline.len(), 1);
    let search = &manifest.actions_baseline[0];
    assert_eq!(search.name, KimiRestBackend.action());
    assert_eq!(search.risk, Risk::Read);
    let http = search.http.as_ref().unwrap();
    assert_eq!(
        (http.method, http.path.as_str()),
        (HttpMethod::Post, "/coding/v1/search")
    );
    assert!(
        http.request_constants.is_none(),
        "nothing beyond the caller's query and count is sent"
    );
    let properties = &http.args_schema["properties"];
    assert_eq!(
        (
            &properties["limit"]["minimum"],
            &properties["limit"]["maximum"]
        ),
        (&json!(1), &json!(20)),
        "limit is reviewed as Kimi's documented 1 to 20"
    );
}

/// Every argument the backend can send is declared by the reviewed closed
/// schema and within its bounds.
#[test]
fn every_vendor_argument_fits_the_reviewed_closed_schema() {
    let manifest = shipped_manifest();
    let schema = &manifest.actions_baseline[0]
        .http
        .as_ref()
        .unwrap()
        .args_schema;
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], json!(["text_query"]));
    let properties = schema["properties"].as_object().unwrap();
    for (text, count) in [
        ("q".to_string(), 1),
        ("é".repeat(MAX_QUERY_CHARS), MAX_RESULTS_LIMIT),
    ] {
        let mut search = query(&text, &[], None);
        search.max_results = count;
        let prepared = KimiRestBackend.prepare(&search, NOW).unwrap();
        let args = prepared.vendor_args.as_object().unwrap();
        for key in args.keys() {
            assert!(properties.contains_key(key), "{key} is not declared");
        }
        let sent = args["text_query"].as_str().unwrap().chars().count() as u64;
        assert!(sent >= properties["text_query"]["minLength"].as_u64().unwrap());
        assert!(sent <= properties["text_query"]["maxLength"].as_u64().unwrap());
        let limit = args["limit"].as_u64().unwrap();
        assert!(limit >= properties["limit"]["minimum"].as_u64().unwrap());
        assert!(limit <= properties["limit"]["maximum"].as_u64().unwrap());
    }
}

#[test]
fn a_documented_reply_maps_search_results_title_url_snippet_and_date() {
    let results = KimiRestBackend
        .map_reply(&recorded_body("success"), 5, NOW)
        .unwrap();
    assert_eq!(
        results,
        vec![
            WebSearchResult {
                url: "https://platform.kimi.ai/docs/api/overview".into(),
                title: "API Overview - Kimi API Open Platform".into(),
                excerpt: "Documentation entry of the Kimi API open platform.".into(),
                published_at: Some("2026-06-01T00:00:00.000Z".into()),
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
            WebSearchResult {
                url: "https://github.com/MoonshotAI/kimi-cli".into(),
                title: "MoonshotAI/kimi-cli - GitHub".into(),
                excerpt: "Kimi Code CLI is an AI agent that runs in the terminal.".into(),
                published_at: None,
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
        ],
        "each result is its title, url, snippet and date; an empty date reports none"
    );
    assert_eq!(
        KimiRestBackend
            .map_reply(&recorded_body("success"), 1, NOW)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_documented_empty_reply_is_an_empty_success() {
    assert_eq!(
        KimiRestBackend.map_reply(&recorded_body("empty"), 5, NOW),
        Ok(Vec::new())
    );
}

#[test]
fn a_reply_without_a_search_results_array_is_a_shape_error() {
    for record in [
        "malformed",
        "bad_request",
        "client_canceled",
        "rate_limited",
        "server_error",
        "upstream_failed",
        "timeout",
    ] {
        assert!(
            KimiRestBackend
                .map_reply(&recorded_body(record), 5, NOW)
                .is_err(),
            "{record}"
        );
    }
    assert!(
        KimiRestBackend
            .map_reply(
                &json!({"search_results": {"url": "https://a.example/"}}),
                5,
                NOW
            )
            .is_err(),
        "search_results that is not an array is a shape error"
    );
}

#[test]
fn mapping_drops_results_without_a_url_bounds_excerpts_and_reads_only_valid_dates() {
    let reply = json!({"search_results": [
        {"url": "https://a.example/", "title": " A ", "snippet": "é".repeat(700), "date": "2024-02-29T08:30:00+02:00"},
        {"url": "", "title": "an empty url is dropped", "snippet": "x", "date": ""},
        {"title": "no url is dropped", "snippet": "x"},
        {"url": "https://b.example/", "title": "B", "date": "yesterday"},
        {"url": "https://c.example/", "title": "C", "date": null}
    ]});
    let results = KimiRestBackend.map_reply(&reply, 10, 0).unwrap();
    assert_eq!(
        results
            .iter()
            .map(|result| result.url.as_str())
            .collect::<Vec<_>>(),
        [
            "https://a.example/",
            "https://b.example/",
            "https://c.example/"
        ],
        "a result whose url is missing or empty is dropped"
    );
    assert_eq!(results[0].title, "A");
    assert_eq!(results[0].excerpt.chars().count(), EXCERPT_MAX_CHARS);
    assert_eq!(
        results[0].published_at.as_deref(),
        Some("2024-02-29T06:30:00.000Z"),
        "an offset time is normalized to UTC"
    );
    assert_eq!(
        (results[1].excerpt.as_str(), &results[1].published_at),
        ("", &None),
        "a missing snippet is an empty excerpt and an unparseable date is dropped"
    );
    assert_eq!(results[2].published_at, None);
    assert_eq!(results[0].fetched_at, "1970-01-01T00:00:00.000Z");
}

/// Kimi documents no domain filter and no date filter, so any requested
/// domain or recency window skips it rather than widening the search.
#[test]
fn capability_skips_any_domain_or_recency_window() {
    assert_eq!(
        KimiRestBackend.prepare(&query("q", &["kimi.com"], None), NOW),
        Err(skip(CapabilityFailure::DomainFilter)),
        "a single requested domain must skip Kimi"
    );
    for recency in [Recency::Day, Recency::Week, Recency::Month, Recency::Year] {
        assert_eq!(
            KimiRestBackend.prepare(&query("q", &[], Some(recency)), NOW),
            Err(skip(CapabilityFailure::Recency)),
            "a {recency:?} recency window must skip Kimi"
        );
    }
}

/// Kimi documents no query limit, so the tool's 500 characters is the
/// declared envelope: the limit is served and one more character skips. The
/// tool never sends a longer query, so it is built directly here.
#[test]
fn capability_skips_a_query_beyond_the_declared_envelope() {
    assert!(KimiRestBackend
        .prepare(&query(&"é".repeat(MAX_QUERY_CHARS), &[], None), NOW)
        .is_ok());
    assert_eq!(
        KimiRestBackend.prepare(&query(&"é".repeat(MAX_QUERY_CHARS + 1), &[], None), NOW),
        Err(skip(CapabilityFailure::Length)),
        "a query over the declared 500-character envelope must skip"
    );
}

#[test]
fn capability_clamps_limit_to_20() {
    let mut many = query("news", &[], None);
    many.max_results = 60;
    let prepared = KimiRestBackend.prepare(&many, NOW).unwrap();
    assert_eq!(
        (prepared.query.max_results, &prepared.vendor_args["limit"]),
        (KIMI_MAX_LIMIT, &json!(20)),
        "limit is clamped to Kimi's documented maximum of 20"
    );
}
