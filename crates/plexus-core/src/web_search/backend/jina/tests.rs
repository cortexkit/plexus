use serde_json::{json, Value};

use super::*;
use crate::manifest::{HttpMethod, Risk, TransportKind};
use crate::web_search::capability::{CapabilityFailure, CapabilitySkip, CapabilitySkipReason};
use crate::web_search::query::Recency;

const NOW: i64 = 1_790_596_800_000; // 2026-09-28T12:00:00Z

/// The recorded vendor reply `name` from `fixtures.json`, parsed.
fn recorded_body(name: &str) -> Value {
    let recordings: Value = serde_json::from_str(include_str!("fixtures.json")).unwrap();
    let body = recordings[name]["body"]
        .as_str()
        .unwrap_or_else(|| panic!("missing recorded Jina reply {name}"));
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
    let source = include_str!("../../../../../../catalog/jina_rest.jsonc");
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

fn skip(failed: CapabilityFailure) -> CapabilitySkip {
    CapabilitySkip {
        provider: "jina",
        reason: CapabilitySkipReason::Capability,
        failed,
    }
}

#[test]
fn vendor_args_send_the_query_count_and_one_site() {
    let prepared = JinaRestBackend
        .prepare(&query("jina reader", &["jina.ai"], None), NOW)
        .unwrap();
    assert_eq!(
        prepared.vendor_args,
        json!({"q": "jina reader", "count": 5, "site": "jina.ai"}),
        "a one-domain search sends that domain as the site filter"
    );
    let bare = JinaRestBackend
        .prepare(&query("jina reader", &[], None), NOW)
        .unwrap();
    assert_eq!(
        bare.vendor_args,
        json!({"q": "jina reader", "count": 5}),
        "no site filter is sent unless the caller asked for a domain"
    );
}

#[test]
fn the_shipped_manifest_pins_jinas_bearer_get_with_the_query_as_the_path() {
    let manifest = shipped_manifest();
    assert_eq!(manifest.key, JinaRestBackend.app_key());
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://s.jina.ai");
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
    assert_eq!(search.name, JinaRestBackend.action());
    assert_eq!(search.risk, Risk::Read);
    let http = search.http.as_ref().unwrap();
    assert_eq!((http.method, http.path.as_str()), (HttpMethod::Get, "/{q}"));
    assert_eq!(http.text_path_parameters, Some(vec!["q".to_string()]));
    assert_eq!(
        http.header_parameters
            .as_ref()
            .and_then(|headers| headers.get("site"))
            .map(String::as_str),
        Some("X-Site")
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
    for domains in [&[][..], &["a-very-long-subdomain.example.com"][..]] {
        let mut search = query(&"é".repeat(MAX_QUERY_CHARS), domains, None);
        search.max_results = u8::MAX;
        let prepared = JinaRestBackend.prepare(&search, NOW).unwrap();
        let args = prepared.vendor_args.as_object().unwrap();
        for field in args.keys() {
            assert!(
                properties.contains_key(field),
                "{field} is not in the reviewed schema"
            );
        }
        let text = args["q"].as_str().unwrap();
        assert!(text.chars().count() as u64 <= properties["q"]["maxLength"].as_u64().unwrap());
        let count = args["count"].as_u64().unwrap();
        assert!(count >= properties["count"]["minimum"].as_u64().unwrap());
        assert!(count <= properties["count"]["maximum"].as_u64().unwrap());
    }
}

#[test]
fn a_documented_reply_maps_title_url_description_and_date() {
    let results = JinaRestBackend
        .map_reply(&recorded_body("success"), 5, NOW)
        .unwrap();
    assert_eq!(
        results,
        vec![
            WebSearchResult {
                url: "https://jina.ai/reader/".into(),
                title: "Reader API - Jina AI".into(),
                excerpt: "Convert a URL to LLM-friendly input, by simply adding r.jina.ai in front."
                    .into(),
                published_at: None,
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
            WebSearchResult {
                url: "https://github.com/jina-ai/reader".into(),
                title: "jina-ai/reader: Convert any URL to an LLM-friendly input".into(),
                excerpt: "Convert any URL to an LLM-friendly input with a simple prefix https://r.jina.ai/".into(),
                published_at: Some("2024-04-11T00:00:00.000Z".into()),
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
        ],
        "Jina results map title, url, description and date"
    );
    assert_eq!(
        JinaRestBackend
            .map_reply(&recorded_body("success"), 1, NOW)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn content_fills_in_when_a_result_has_no_description() {
    let results = JinaRestBackend
        .map_reply(&recorded_body("content_only"), 5, NOW)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].excerpt, "Your Search Foundation, Supercharged.",
        "content fills in when description is empty"
    );
    assert_eq!(
        results[0].published_at.as_deref(),
        Some("2024-05-01T00:00:00.000Z"),
        "publishedTime is read when there is no date"
    );
}

#[test]
fn an_empty_data_array_is_an_empty_success() {
    assert_eq!(
        JinaRestBackend.map_reply(&recorded_body("empty"), 5, NOW),
        Ok(Vec::new())
    );
}

#[test]
fn a_reply_without_a_data_array_is_a_shape_error() {
    for record in [
        "malformed",
        "no_results",
        "payment_required",
        "rate_limited_retry",
        "server_error",
    ] {
        assert!(
            JinaRestBackend
                .map_reply(&recorded_body(record), 5, NOW)
                .is_err(),
            "{record}"
        );
    }
}

#[test]
fn mapping_bounds_excerpts_drops_results_without_a_url_and_unparseable_dates() {
    let reply = json!({"code": 200, "data": [
        {"url": "https://a.example/", "title": " A ", "description": "é".repeat(700)},
        {"title": "no url is dropped", "description": "x"},
        {"url": "https://b.example/", "description": " ", "content": " from content ", "date": "3 days ago"},
        {"url": "https://c.example/"}
    ]});
    let results = JinaRestBackend.map_reply(&reply, 10, 0).unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].title, "A");
    assert_eq!(results[0].excerpt.chars().count(), EXCERPT_MAX_CHARS);
    assert_eq!(results[1].excerpt, "from content");
    assert_eq!(
        results[1].published_at, None,
        "a relative date is not a date"
    );
    assert_eq!(
        (results[2].title.as_str(), results[2].excerpt.as_str()),
        ("", "")
    );
    assert_eq!(results[0].fetched_at, "1970-01-01T00:00:00.000Z");
}

#[test]
fn capability_clamps_count_to_20() {
    let mut many = query("news", &[], None);
    many.max_results = 50;
    let prepared = JinaRestBackend.prepare(&many, NOW).unwrap();
    assert_eq!(
        (prepared.query.max_results, &prepared.vendor_args["count"]),
        (JINA_MAX_COUNT, &json!(20)),
        "count is clamped to Jina's maximum of 20"
    );
    assert_eq!(prepared.query.query, "news", "the query is sent unchanged");
}

#[test]
fn capability_takes_one_domain_and_skips_two() {
    assert!(JinaRestBackend
        .prepare(&query("news", &["jina.ai"], None), NOW)
        .is_ok());
    assert_eq!(
        JinaRestBackend.prepare(&query("news", &["jina.ai", "github.com"], None), NOW),
        Err(skip(CapabilityFailure::DomainFilter)),
        "two domains must skip Jina, which takes one site filter"
    );
}

#[test]
fn capability_skips_every_recency_window() {
    for recency in [Recency::Day, Recency::Week, Recency::Month, Recency::Year] {
        assert_eq!(
            JinaRestBackend.prepare(&query("news", &[], Some(recency)), NOW),
            Err(skip(CapabilityFailure::Recency)),
            "Jina has no date filter, so a recency window must skip it"
        );
    }
}
