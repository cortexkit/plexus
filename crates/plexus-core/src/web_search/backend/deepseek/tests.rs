use serde_json::{json, Value};

use super::*;
use crate::manifest::{HttpMethod, Risk, TransportKind};
use crate::web_search::capability::{CapabilityFailure, CapabilitySkip, CapabilitySkipReason};
use crate::web_search::query::{Recency, MAX_QUERY_CHARS};

const NOW: i64 = 1_790_596_800_000; // 2026-09-28T12:00:00Z

/// The recorded vendor reply `name` from `fixtures.json`, parsed.
fn recorded_body(name: &str) -> Value {
    let recordings: Value = serde_json::from_str(include_str!("fixtures.json")).unwrap();
    let body = recordings[name]["body"]
        .as_str()
        .unwrap_or_else(|| panic!("missing recorded DeepSeek reply {name}"));
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
    let source = include_str!("../../../../../../catalog/deepseek_rest.jsonc");
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

fn skip(failed: CapabilityFailure) -> CapabilitySkip {
    CapabilitySkip {
        provider: "deepseek",
        reason: CapabilitySkipReason::Capability,
        failed,
    }
}

#[test]
fn vendor_args_compose_domains_and_recency_as_documented_operators() {
    let prepared = DeepSeekRestBackend
        .prepare(
            &query(
                "DeepSeek",
                &["github.com", "huggingface.co"],
                Some(Recency::Week),
            ),
            NOW,
        )
        .unwrap();
    assert_eq!(
        prepared.vendor_args,
        json!({
            "query": "DeepSeek site:github.com OR site:huggingface.co after:2026-09-21",
            "count": 5
        }),
        "domains become site:a OR site:b and recency becomes after:YYYY-MM-DD"
    );
    let bare = DeepSeekRestBackend
        .prepare(&query("DeepSeek", &[], None), NOW)
        .unwrap();
    assert_eq!(
        bare.vendor_args,
        json!({"query": "DeepSeek", "count": 5}),
        "no operator is added unless the caller asked for a filter"
    );
    for (recency, day) in [
        (Recency::Day, "2026-09-27"),
        (Recency::Week, "2026-09-21"),
        (Recency::Month, "2026-08-29"),
        (Recency::Year, "2025-09-28"),
    ] {
        assert_eq!(
            DeepSeekRestBackend
                .prepare(&query("news", &[], Some(recency)), NOW)
                .unwrap()
                .vendor_args["query"],
            format!("news after:{day}")
        );
    }
    assert_eq!(
        DeepSeekRestBackend
            .prepare(&query("news", &["a.example"], None), NOW)
            .unwrap()
            .vendor_args["query"],
        "news site:a.example"
    );
}

#[test]
fn the_shipped_manifest_pins_deepseeks_bearer_post_to_tools_search() {
    let manifest = shipped_manifest();
    assert_eq!(manifest.key, DeepSeekRestBackend.app_key());
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://api.deepseek.com");
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
    assert_eq!(search.name, DeepSeekRestBackend.action());
    assert_eq!(search.risk, Risk::Read);
    let http = search.http.as_ref().unwrap();
    assert_eq!(
        (http.method, http.path.as_str()),
        (HttpMethod::Post, "/v1/tools/search")
    );
    let properties = &http.args_schema["properties"];
    assert_eq!(
        (
            &properties["query"]["minLength"],
            &properties["query"]["maxLength"]
        ),
        (&json!(1), &json!(128))
    );
    assert_eq!(
        (
            &properties["count"]["minimum"],
            &properties["count"]["maximum"]
        ),
        (&json!(1), &json!(50))
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
    for recency in [None, Some(Recency::Day), Some(Recency::Year)] {
        for domains in [&[][..], &["a.example", "b.example"][..]] {
            let mut search = query(&"q".repeat(60), domains, recency);
            search.max_results = 20;
            let prepared = DeepSeekRestBackend.prepare(&search, NOW).unwrap();
            let args = prepared.vendor_args.as_object().unwrap();
            assert_eq!(args.len(), 2, "{args:?}");
            let text = args["query"].as_str().unwrap();
            let length = text.chars().count() as u64;
            assert!(length >= properties["query"]["minLength"].as_u64().unwrap());
            assert!(length <= properties["query"]["maxLength"].as_u64().unwrap());
            let count = args["count"].as_u64().unwrap();
            assert!(count >= properties["count"]["minimum"].as_u64().unwrap());
            assert!(count <= properties["count"]["maximum"].as_u64().unwrap());
        }
    }
}

#[test]
fn a_documented_reply_maps_title_url_summary_and_date() {
    let results = DeepSeekRestBackend
        .map_reply(&recorded_body("success"), 5, NOW)
        .unwrap();
    assert_eq!(
        results,
        vec![
            WebSearchResult {
                url: "https://example.com/deepseek-v4".into(),
                title: "DeepSeek V4 model released".into(),
                excerpt: "DeepSeek has released the V4 model. The release adds improved tool calling and long-context support for agent workflows.".into(),
                published_at: Some("2026-06-01T00:00:00.000Z".into()),
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
            WebSearchResult {
                url: "https://github.com/deepseek-ai".into(),
                title: "DeepSeek on GitHub".into(),
                excerpt: "DeepSeek's open-source repositories.".into(),
                published_at: None,
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
        ],
        "DeepSeek results map title, url, summary (snippet when empty) and an RFC 3339 or null date"
    );
    assert_eq!(
        DeepSeekRestBackend
            .map_reply(&recorded_body("success"), 1, NOW)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn an_empty_results_array_is_an_empty_success() {
    assert_eq!(
        DeepSeekRestBackend.map_reply(&recorded_body("empty"), 5, NOW),
        Ok(Vec::new())
    );
}

#[test]
fn a_reply_without_a_results_array_is_a_shape_error() {
    for record in [
        "malformed",
        "bad_request",
        "insufficient_balance",
        "qps_exceeded",
        "server_error",
    ] {
        assert!(
            DeepSeekRestBackend
                .map_reply(&recorded_body(record), 5, NOW)
                .is_err(),
            "{record}"
        );
    }
}

#[test]
fn mapping_bounds_excerpts_and_reads_only_valid_dates() {
    let reply = json!({"results": [
        {"url": "https://a.example/", "title": " A ", "summary": "é".repeat(700), "date": "2024-02-29T08:30:00+02:00"},
        {"title": "no url is dropped", "summary": "x"},
        {"url": "https://b.example/", "date": "not a date", "summary": " ", "snippet": " "},
        {"url": "https://c.example/", "date": null}
    ]});
    let results = DeepSeekRestBackend.map_reply(&reply, 10, 0).unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].title, "A");
    assert_eq!(results[0].excerpt.chars().count(), EXCERPT_MAX_CHARS);
    assert_eq!(
        results[0].published_at.as_deref(),
        Some("2024-02-29T06:30:00.000Z"),
        "an offset date is normalized to UTC"
    );
    assert_eq!(
        (
            results[1].title.as_str(),
            results[1].excerpt.as_str(),
            &results[1].published_at
        ),
        ("", "", &None)
    );
    assert_eq!(results[2].published_at, None);
    assert_eq!(results[0].fetched_at, "1970-01-01T00:00:00.000Z");
}

#[test]
fn capability_skips_a_200_character_query() {
    assert_eq!(
        DeepSeekRestBackend.prepare(&query(&"x".repeat(200), &[], None), NOW),
        Err(skip(CapabilityFailure::Length)),
        "a query over DeepSeek's 128-character limit must skip"
    );
    assert!(DeepSeekRestBackend
        .prepare(
            &query(&"é".repeat(DEEPSEEK_MAX_QUERY_CHARS), &[], None),
            NOW
        )
        .is_ok());
    assert_eq!(
        DeepSeekRestBackend.prepare(
            &query(&"é".repeat(DEEPSEEK_MAX_QUERY_CHARS + 1), &[], None),
            NOW
        ),
        Err(skip(CapabilityFailure::Length))
    );
    assert_eq!(
        DeepSeekRestBackend.prepare(&query(&"x".repeat(MAX_QUERY_CHARS), &[], None), NOW),
        Err(skip(CapabilityFailure::Length))
    );
}

#[test]
fn capability_checks_the_final_query_after_operators() {
    // 100 characters fit alone, but not with three site: operators.
    assert!(DeepSeekRestBackend
        .prepare(&query(&"x".repeat(100), &[], None), NOW)
        .is_ok());
    assert_eq!(
        DeepSeekRestBackend.prepare(
            &query(&"x".repeat(100), &["a.com", "b.com", "c.com"], None),
            NOW
        ),
        Err(skip(CapabilityFailure::Length)),
        "a query that only exceeds 128 characters once its operators are added must skip"
    );
    let operators = " site:a.com OR site:b.com after:2026-09-21".chars().count();
    let fits = query(
        &"x".repeat(DEEPSEEK_MAX_QUERY_CHARS - operators),
        &["a.com", "b.com"],
        Some(Recency::Week),
    );
    let prepared = DeepSeekRestBackend.prepare(&fits, NOW).unwrap();
    assert_eq!(
        prepared.query.query.chars().count(),
        DEEPSEEK_MAX_QUERY_CHARS,
        "the exact limit after operators is served"
    );
    let over = query(
        &"x".repeat(DEEPSEEK_MAX_QUERY_CHARS - operators + 1),
        &["a.com", "b.com"],
        Some(Recency::Week),
    );
    assert_eq!(
        DeepSeekRestBackend.prepare(&over, NOW),
        Err(skip(CapabilityFailure::Length))
    );
}

#[test]
fn capability_clamps_count_and_accepts_every_recency_and_domain_count() {
    let mut many = query("news", &[], None);
    many.max_results = 20;
    let prepared = DeepSeekRestBackend.prepare(&many, NOW).unwrap();
    assert_eq!(prepared.vendor_args["count"], 20);
    // The tool never asks for more than 20; DeepSeek's maximum is 50.
    many.max_results = 60;
    let prepared = DeepSeekRestBackend.prepare(&many, NOW).unwrap();
    assert_eq!(
        (prepared.query.max_results, &prepared.vendor_args["count"]),
        (DEEPSEEK_MAX_COUNT, &json!(50)),
        "count is clamped to DeepSeek's maximum of 50"
    );
    let capability = DeepSeekRestBackend.capability();
    assert_eq!(capability.recency.supported, ALL_RECENCIES);
    assert_eq!(capability.domains.max_domains, MAX_INCLUDE_DOMAINS);
    let too_many: Vec<String> = (0..=MAX_INCLUDE_DOMAINS)
        .map(|index| format!("d{index}.example"))
        .collect();
    let too_many: Vec<&str> = too_many.iter().map(String::as_str).collect();
    assert_eq!(
        DeepSeekRestBackend.prepare(&query("q", &too_many, None), NOW),
        Err(skip(CapabilityFailure::DomainFilter))
    );
}
