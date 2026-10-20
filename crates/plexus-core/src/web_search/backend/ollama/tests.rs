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
        .unwrap_or_else(|| panic!("missing recorded Ollama reply {name}"));
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
    let source = include_str!("../../../../../../catalog/ollama_rest.jsonc");
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

fn skip(failed: CapabilityFailure) -> CapabilitySkip {
    CapabilitySkip {
        provider: "ollama",
        reason: CapabilitySkipReason::Capability,
        failed,
    }
}

#[test]
fn vendor_args_send_only_query_and_max_results() {
    let prepared = OllamaRestBackend
        .prepare(&query("what is ollama?", &[], None), NOW)
        .unwrap();
    assert_eq!(
        prepared.vendor_args,
        json!({"query": "what is ollama?", "max_results": 5}),
        "the query travels as query with the result count as max_results"
    );
    assert_eq!(prepared.query.query, "what is ollama?");
}

#[test]
fn the_shipped_manifest_pins_ollamas_bearer_post_to_api_web_search() {
    let manifest = shipped_manifest();
    assert_eq!(manifest.key, OllamaRestBackend.app_key());
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://ollama.com");
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
    assert_eq!(search.name, OllamaRestBackend.action());
    assert_eq!(search.risk, Risk::Read);
    let http = search.http.as_ref().unwrap();
    assert_eq!(
        (http.method, http.path.as_str()),
        (HttpMethod::Post, "/api/web_search")
    );
    assert!(
        http.request_constants.is_none(),
        "nothing beyond the caller's query and count is sent"
    );
    let properties = &http.args_schema["properties"];
    assert_eq!(
        (
            &properties["max_results"]["minimum"],
            &properties["max_results"]["maximum"]
        ),
        (&json!(1), &json!(10)),
        "max_results is reviewed as Ollama's documented maximum of 10"
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
    assert_eq!(schema["required"], json!(["query"]));
    let properties = schema["properties"].as_object().unwrap();
    for (text, count) in [
        ("q".to_string(), 1),
        ("é".repeat(OLLAMA_MAX_QUERY_CHARS), MAX_RESULTS_LIMIT),
    ] {
        let mut search = query(&text, &[], None);
        search.max_results = count;
        let prepared = OllamaRestBackend.prepare(&search, NOW).unwrap();
        let args = prepared.vendor_args.as_object().unwrap();
        for key in args.keys() {
            assert!(properties.contains_key(key), "{key} is not declared");
        }
        let sent = args["query"].as_str().unwrap().chars().count() as u64;
        assert!(sent >= properties["query"]["minLength"].as_u64().unwrap());
        assert!(sent <= properties["query"]["maxLength"].as_u64().unwrap());
        let limit = args["max_results"].as_u64().unwrap();
        assert!(limit >= properties["max_results"]["minimum"].as_u64().unwrap());
        assert!(limit <= properties["max_results"]["maximum"].as_u64().unwrap());
    }
}

#[test]
fn a_documented_reply_maps_results_title_url_and_content() {
    let results = OllamaRestBackend
        .map_reply(&recorded_body("success"), 5, NOW)
        .unwrap();
    let fetched_at = "2026-09-28T12:00:00.000Z".to_string();
    assert_eq!(
        results,
        vec![
            WebSearchResult {
                url: "https://ollama.com/".into(),
                title: "Ollama".into(),
                excerpt: "Cloud models are now available...".into(),
                published_at: None,
                fetched_at: fetched_at.clone(),
            },
            WebSearchResult {
                url: "https://www.hostinger.com/tutorials/what-is-ollama".into(),
                title: "What is Ollama? Introduction to the AI model management tool".into(),
                excerpt: "Ariffud M. 6min Read...".into(),
                published_at: None,
                fetched_at: fetched_at.clone(),
            },
            WebSearchResult {
                url: "https://www.geeksforgeeks.org/artificial-intelligence/ollama-explained-transforming-ai-accessibility-and-language-processing/".into(),
                title: "Ollama Explained: Transforming AI Accessibility and Language ...".into(),
                excerpt: "Data Science Data Science Projects Data Analysis...".into(),
                published_at: None,
                fetched_at,
            },
        ],
        "each result is its title, url and content; Ollama reports no date"
    );
    assert_eq!(
        OllamaRestBackend
            .map_reply(&recorded_body("success"), 1, NOW)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn an_empty_results_array_is_an_empty_success() {
    assert_eq!(
        OllamaRestBackend.map_reply(&recorded_body("empty"), 5, NOW),
        Ok(Vec::new())
    );
}

#[test]
fn a_reply_without_a_results_array_is_a_shape_error() {
    for record in [
        "malformed",
        "bad_request",
        "unauthorized",
        "forbidden",
        "not_found",
        "rate_limited",
        "server_error",
        "bad_gateway",
    ] {
        assert!(
            OllamaRestBackend
                .map_reply(&recorded_body(record), 5, NOW)
                .is_err(),
            "{record}"
        );
    }
    assert!(
        OllamaRestBackend
            .map_reply(&json!({"results": {"url": "https://a.example/"}}), 5, NOW)
            .is_err(),
        "results that is not an array is a shape error"
    );
}

#[test]
fn mapping_drops_results_without_a_url_and_bounds_excerpts() {
    let reply = json!({"results": [
        {"url": " https://a.example/ ", "title": " A ", "content": "é".repeat(700)},
        {"url": "", "title": "an empty url is dropped", "content": "x"},
        {"title": "no url is dropped", "content": "x"},
        {"url": null, "title": "a null url is dropped"},
        {"url": "https://b.example/"}
    ]});
    let results = OllamaRestBackend.map_reply(&reply, 10, 0).unwrap();
    assert_eq!(
        results
            .iter()
            .map(|result| result.url.as_str())
            .collect::<Vec<_>>(),
        ["https://a.example/", "https://b.example/"],
        "a result whose url is missing, null or empty is dropped"
    );
    assert_eq!(results[0].title, "A");
    assert_eq!(results[0].excerpt.chars().count(), EXCERPT_MAX_CHARS);
    assert_eq!(
        (results[1].title.as_str(), results[1].excerpt.as_str()),
        ("", ""),
        "a missing title or content is empty text"
    );
    assert!(results.iter().all(|result| result.published_at.is_none()));
    assert_eq!(results[0].fetched_at, "1970-01-01T00:00:00.000Z");
}

/// Ollama documents no domain filter, no date filter and no query operator
/// for either, so any requested domain or recency window skips it rather than
/// being answered with unfiltered results.
#[test]
fn capability_skips_any_domain_or_recency_window() {
    assert_eq!(
        OllamaRestBackend.prepare(&query("q", &["ollama.com"], None), NOW),
        Err(skip(CapabilityFailure::DomainFilter)),
        "a single requested domain must skip Ollama"
    );
    for recency in [Recency::Day, Recency::Week, Recency::Month, Recency::Year] {
        assert_eq!(
            OllamaRestBackend.prepare(&query("q", &[], Some(recency)), NOW),
            Err(skip(CapabilityFailure::Recency)),
            "a {recency:?} recency window must skip Ollama"
        );
    }
}

/// The query is sent exactly as the caller wrote it, and the tool's
/// 500-character limit is the declared envelope since Ollama documents none:
/// the limit is served and one more character skips. The tool never sends a
/// longer query, so it is built directly here.
#[test]
fn capability_skips_a_query_beyond_the_declared_envelope() {
    let longest = "é".repeat(OLLAMA_MAX_QUERY_CHARS);
    let prepared = OllamaRestBackend
        .prepare(&query(&longest, &[], None), NOW)
        .unwrap();
    assert_eq!(
        prepared.vendor_args["query"],
        json!(longest),
        "the query is sent unchanged"
    );
    assert_eq!(
        OllamaRestBackend.prepare(
            &query(&"é".repeat(OLLAMA_MAX_QUERY_CHARS + 1), &[], None),
            NOW
        ),
        Err(skip(CapabilityFailure::Length)),
        "a query over the declared 500-character envelope must skip"
    );
}

#[test]
fn capability_clamps_max_results_to_10() {
    let mut many = query("news", &[], None);
    many.max_results = 60;
    let prepared = OllamaRestBackend.prepare(&many, NOW).unwrap();
    assert_eq!(
        (
            prepared.query.max_results,
            &prepared.vendor_args["max_results"]
        ),
        (OLLAMA_MAX_RESULTS, &json!(10)),
        "max_results is clamped to Ollama's documented maximum of 10"
    );
}
