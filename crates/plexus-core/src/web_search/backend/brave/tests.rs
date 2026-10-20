use serde_json::{json, Value};

use super::*;
use crate::manifest::{HttpMethod, RestParameterLocation, Risk, TransportKind};
use crate::web_search::capability::{CapabilityFailure, CapabilitySkip, CapabilitySkipReason};
use crate::web_search::query::MAX_QUERY_CHARS;

const NOW: i64 = 1_790_596_800_000; // 2026-09-28T12:00:00Z

/// The recorded vendor reply `name` from `fixtures.json`, parsed.
fn recorded_body(name: &str) -> Value {
    let recordings: Value = serde_json::from_str(include_str!("fixtures.json")).unwrap();
    let body = recordings[name]["body"]
        .as_str()
        .unwrap_or_else(|| panic!("missing recorded Brave reply {name}"));
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
    let source = include_str!("../../../../../../catalog/brave_rest.jsonc");
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

fn skip(failed: CapabilityFailure) -> CapabilitySkip {
    CapabilitySkip {
        provider: "brave",
        reason: CapabilitySkipReason::Capability,
        failed,
    }
}

#[test]
fn vendor_args_use_braves_documented_parameter_names() {
    let prepared = BraveRestBackend
        .prepare(
            &query(
                "python web frameworks",
                &["docs.python.org", "realpython.com"],
                Some(Recency::Week),
            ),
            NOW,
        )
        .unwrap();
    assert_eq!(
        prepared.vendor_args,
        json!({
            "q": "python web frameworks site:docs.python.org OR site:realpython.com",
            "count": 5,
            "freshness": "pw",
            "extra_snippets": true,
            "text_decorations": false
        }),
        "a filtered search maps domains to site: operators and recency to freshness"
    );
    let bare = BraveRestBackend
        .prepare(&query("python web frameworks", &[], None), NOW)
        .unwrap();
    assert_eq!(
        bare.vendor_args,
        json!({
            "q": "python web frameworks",
            "count": 5,
            "extra_snippets": true,
            "text_decorations": false
        }),
        "no filter is sent unless the caller asked for it"
    );
    for (recency, freshness) in [
        (Recency::Day, "pd"),
        (Recency::Week, "pw"),
        (Recency::Month, "pm"),
        (Recency::Year, "py"),
    ] {
        assert_eq!(
            BraveRestBackend.vendor_args(&query("news", &[], Some(recency)), NOW)["freshness"],
            freshness
        );
    }
}

#[test]
fn the_shipped_manifest_pins_braves_get_search_and_subscription_token_header() {
    let manifest = shipped_manifest();
    assert_eq!(manifest.key, BraveRestBackend.app_key());
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://api.search.brave.com");
    assert_eq!(manifest.credential_bindings.len(), 1);
    let binding = &manifest.credential_bindings[0];
    assert_eq!(
        (
            binding.placement.as_str(),
            binding.key.as_str(),
            binding.prefix.as_str()
        ),
        ("header", "X-Subscription-Token", "")
    );
    assert!(binding.required);
    assert_eq!(manifest.actions_baseline.len(), 1);
    let search = &manifest.actions_baseline[0];
    assert_eq!(search.name, BraveRestBackend.action());
    assert_eq!(search.risk, Risk::Read);
    let http = search.http.as_ref().unwrap();
    assert_eq!(
        (http.method, http.path.as_str(), http.parameters),
        (
            HttpMethod::Get,
            "/res/v1/web/search",
            Some(RestParameterLocation::Query)
        )
    );
}

#[test]
fn every_vendor_argument_fits_the_reviewed_closed_schema() {
    let manifest = shipped_manifest();
    let schema = &manifest.actions_baseline[0]
        .http
        .as_ref()
        .unwrap()
        .args_schema;
    assert_eq!(schema["additionalProperties"], false);
    let properties = schema["properties"].as_object().unwrap();
    let domains: Vec<String> = (0..3).map(|index| format!("d{index}.example")).collect();
    let domains: Vec<&str> = domains.iter().map(String::as_str).collect();
    for recency in [None, Some(Recency::Day), Some(Recency::Year)] {
        for domains in [&[][..], &domains[..]] {
            let mut search = query(&"q".repeat(400), domains, recency);
            search.max_results = 20;
            let prepared = BraveRestBackend.prepare(&search, NOW).unwrap();
            let args = prepared.vendor_args.as_object().unwrap();
            for (field, value) in args {
                let property = properties
                    .get(field)
                    .unwrap_or_else(|| panic!("{field} is not in the reviewed schema"));
                match property["type"].as_str().unwrap() {
                    "string" => {
                        let text = value.as_str().unwrap();
                        if let Some(allowed) = property.get("enum") {
                            assert!(allowed.as_array().unwrap().contains(value), "{value}");
                        }
                        if let Some(max) = property.get("maxLength") {
                            assert!(text.chars().count() as u64 <= max.as_u64().unwrap());
                        }
                    }
                    "integer" => {
                        let count = value.as_u64().unwrap();
                        assert!(count >= property["minimum"].as_u64().unwrap());
                        assert!(count <= property["maximum"].as_u64().unwrap());
                    }
                    "boolean" => assert!(value.is_boolean()),
                    other => panic!("unexpected schema type {other}"),
                }
            }
            assert!(args.contains_key("q"));
        }
    }
}

#[test]
fn a_documented_reply_maps_title_url_description_snippets_and_dates() {
    let results = BraveRestBackend
        .map_reply(&recorded_body("success"), 5, NOW)
        .unwrap();
    assert_eq!(
        results,
        vec![
            WebSearchResult {
                url: "https://example.com/python-frameworks".into(),
                title: "Python Web Frameworks".into(),
                excerpt: "Main snippet text... … First additional excerpt from the page... … Second additional excerpt from the page... … Third additional excerpt from the page...".into(),
                published_at: Some("2025-03-11T17:00:00.000Z".into()),
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
            WebSearchResult {
                url: "https://example.org/compare".into(),
                title: "Comparing Python web frameworks".into(),
                excerpt: "A comparison of Django, Flask and FastAPI.".into(),
                published_at: None,
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
        ],
        "Brave results map title, url, description with extra_snippets, and page_age"
    );
    assert_eq!(
        BraveRestBackend
            .map_reply(&recorded_body("success"), 1, NOW)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_search_reply_without_web_results_is_an_empty_success() {
    for record in ["empty", "empty_web"] {
        assert_eq!(
            BraveRestBackend.map_reply(&recorded_body(record), 5, NOW),
            Ok(Vec::new()),
            "{record}: a search that found no web pages is empty, not malformed"
        );
    }
}

#[test]
fn a_reply_without_a_web_results_array_is_a_shape_error() {
    for record in ["malformed", "token_invalid", "rate_limited", "server_error"] {
        assert!(
            BraveRestBackend
                .map_reply(&recorded_body(record), 5, NOW)
                .is_err(),
            "{record}"
        );
    }
}

#[test]
fn mapping_bounds_excerpts_and_reads_only_absolute_dates() {
    let reply = json!({"type": "search", "web": {"type": "search", "results": [
        {"url": "https://a.example/", "title": " <strong>A</strong> ", "description": "é".repeat(700)},
        {"title": "no url is dropped", "description": "x"},
        {"url": "https://b.example/", "page_age": "2024-02-29T08:30:00Z", "age": "March 1, 2024"},
        {"url": "https://c.example/", "age": "August 4, 2023"},
        {"url": "https://d.example/", "page_age": "2024-02-29"},
        {"url": "https://e.example/", "page_age": "yesterday", "age": "3 hours ago"},
        {"url": "https://f.example/", "description": " ", "extra_snippets": ["", " <strong>only</strong> snippet "]}
    ]}});
    let results = BraveRestBackend.map_reply(&reply, 10, 0).unwrap();
    assert_eq!(results.len(), 6);
    assert_eq!(results[0].title, "A", "highlight markup is removed");
    assert_eq!(results[0].excerpt.chars().count(), EXCERPT_MAX_CHARS);
    assert_eq!(results[0].published_at, None);
    assert_eq!(
        (results[1].title.as_str(), results[1].excerpt.as_str()),
        ("", "")
    );
    assert_eq!(
        results[1].published_at.as_deref(),
        Some("2024-02-29T08:30:00.000Z"),
        "page_age wins over age"
    );
    assert_eq!(
        results[2].published_at.as_deref(),
        Some("2023-08-04T00:00:00.000Z"),
        "an absolute age is used when page_age is missing"
    );
    assert_eq!(
        results[3].published_at.as_deref(),
        Some("2024-02-29T00:00:00.000Z")
    );
    assert_eq!(
        results[4].published_at, None,
        "a relative age is never turned into a guessed date"
    );
    assert_eq!(results[5].excerpt, "only snippet");
    assert_eq!(results[0].fetched_at, "1970-01-01T00:00:00.000Z");
}

#[test]
fn capability_serves_the_tool_envelope_with_domains_as_site_operators() {
    for recency in [
        None,
        Some(Recency::Day),
        Some(Recency::Week),
        Some(Recency::Month),
        Some(Recency::Year),
    ] {
        let mut search = query(&"é".repeat(MAX_QUERY_CHARS), &[], recency);
        search.max_results = 20;
        let prepared = BraveRestBackend.prepare(&search, NOW).unwrap();
        assert_eq!(
            prepared.query, search,
            "native recency leaves the query untouched"
        );
        assert_eq!(prepared.vendor_args["count"], 20);
    }
    let prepared = BraveRestBackend
        .prepare(&query("news", &["a.example"], None), NOW)
        .unwrap();
    assert_eq!(prepared.query.query, "news site:a.example");
    assert_eq!(prepared.vendor_args["q"], "news site:a.example");
    let mut many = query("news", &[], None);
    many.max_results = 50;
    let prepared = BraveRestBackend.prepare(&many, NOW).unwrap();
    assert_eq!(
        (prepared.query.max_results, &prepared.vendor_args["count"]),
        (BRAVE_MAX_COUNT, &json!(20)),
        "count is clamped to Brave's maximum of 20"
    );
}

#[test]
fn capability_checks_the_final_query_after_site_operators() {
    // The two site: operators and the OR between them lengthen the query.
    let operators = " site:a.example OR site:b.example".chars().count();
    let fits = query(
        &"x".repeat(BRAVE_MAX_QUERY_CHARS - operators),
        &["a.example", "b.example"],
        None,
    );
    let prepared = BraveRestBackend.prepare(&fits, NOW).unwrap();
    assert_eq!(
        prepared.query.query.chars().count(),
        BRAVE_MAX_QUERY_CHARS,
        "the exact limit after operators is served"
    );
    let over = query(
        &"x".repeat(BRAVE_MAX_QUERY_CHARS - operators + 1),
        &["a.example", "b.example"],
        None,
    );
    assert_eq!(
        BraveRestBackend.prepare(&over, NOW),
        Err(skip(CapabilityFailure::Length)),
        "a query that only exceeds 500 characters once its operators are added must skip"
    );
    assert_eq!(
        BraveRestBackend.prepare(&query(&"x".repeat(MAX_QUERY_CHARS + 1), &[], None), NOW),
        Err(skip(CapabilityFailure::Length))
    );
}

#[test]
fn capability_skips_a_final_query_over_brave_word_limit() {
    let words = |count: usize| vec!["w"; count].join(" ");
    assert!(BraveRestBackend
        .prepare(&query(&words(BRAVE_MAX_QUERY_WORDS), &[], None), NOW)
        .is_ok());
    assert_eq!(
        BraveRestBackend.prepare(&query(&words(BRAVE_MAX_QUERY_WORDS + 1), &[], None), NOW),
        Err(skip(CapabilityFailure::Length)),
        "more than 75 words must skip"
    );
    // 72 words plus "site:a OR site:b" is 75 words; one more domain adds two.
    assert!(BraveRestBackend
        .prepare(&query(&words(72), &["a.example", "b.example"], None), NOW)
        .is_ok());
    assert_eq!(
        BraveRestBackend.prepare(
            &query(&words(72), &["a.example", "b.example", "c.example"], None),
            NOW
        ),
        Err(skip(CapabilityFailure::Length)),
        "operator words count toward the word limit"
    );
}
