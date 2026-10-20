use serde_json::{json, Value};

use super::*;
use crate::manifest::{HttpMethod, Risk, TransportKind};
use crate::web_search::capability::{CapabilityFailure, CapabilitySkip, CapabilitySkipReason};
use crate::web_search::query::MAX_QUERY_CHARS;

const NOW: i64 = 1_790_596_800_000; // 2026-09-28T12:00:00Z

/// The recorded vendor reply `name` from `fixtures.json`, parsed.
fn recorded_body(name: &str) -> Value {
    let recordings: Value = serde_json::from_str(include_str!("fixtures.json")).unwrap();
    let body = recordings[name]["body"]
        .as_str()
        .unwrap_or_else(|| panic!("missing recorded Firecrawl reply {name}"));
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

fn shipped_manifest(file: &str) -> crate::manifest::AppManifest {
    let source = match file {
        "firecrawl_rest.jsonc" => include_str!("../../../../../../catalog/firecrawl_rest.jsonc"),
        "firecrawl.jsonc" => include_str!("../../../../../../catalog/firecrawl.jsonc"),
        _ => unreachable!(),
    };
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

fn skip(failed: CapabilityFailure) -> CapabilitySkip {
    CapabilitySkip {
        provider: "firecrawl",
        reason: CapabilitySkipReason::Capability,
        failed,
    }
}

#[test]
fn vendor_args_use_firecrawls_documented_field_names() {
    let prepared = FirecrawlRestBackend
        .prepare(
            &query(
                "firecrawl",
                &["docs.firecrawl.dev", "github.com"],
                Some(Recency::Week),
            ),
            NOW,
        )
        .unwrap();
    assert_eq!(
        prepared.vendor_args,
        json!({
            "query": "firecrawl",
            "limit": 5,
            "sources": [{"type": "web"}],
            "includeDomains": ["docs.firecrawl.dev", "github.com"],
            "tbs": "qdr:w"
        }),
        "a filtered search maps every filter to Firecrawl's documented fields"
    );
    let bare = FirecrawlRestBackend
        .prepare(&query("firecrawl", &[], None), NOW)
        .unwrap();
    assert_eq!(
        bare.vendor_args,
        json!({"query": "firecrawl", "limit": 5, "sources": [{"type": "web"}]}),
        "no filter field is sent unless the caller asked for that filter"
    );
    for (recency, tbs) in [
        (Recency::Day, "qdr:d"),
        (Recency::Week, "qdr:w"),
        (Recency::Month, "qdr:m"),
        (Recency::Year, "qdr:y"),
    ] {
        assert_eq!(
            FirecrawlRestBackend
                .prepare(&query("news", &[], Some(recency)), NOW)
                .unwrap()
                .vendor_args["tbs"],
            tbs,
            "each recency window maps onto its tbs time filter"
        );
    }
}

#[test]
fn the_shipped_manifest_pins_firecrawls_bearer_post_to_v2_search() {
    let manifest = shipped_manifest("firecrawl_rest.jsonc");
    assert_eq!(manifest.key, FirecrawlRestBackend.app_key());
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://api.firecrawl.dev");
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
    assert_eq!(search.name, FirecrawlRestBackend.action());
    assert_eq!(search.risk, Risk::Read);
    let http = search.http.as_ref().unwrap();
    assert_eq!(
        (http.method, http.path.as_str()),
        (HttpMethod::Post, "/v2/search")
    );

    // The existing MCP manifest keeps its own key, transport and tools, so
    // its connections can never resolve as REST search connections.
    let mcp = shipped_manifest("firecrawl.jsonc");
    assert_eq!(mcp.key, "firecrawl");
    assert_eq!(mcp.transport.kind, TransportKind::McpRemote);
    assert_ne!(mcp.key, FirecrawlRestBackend.app_key());
    assert_eq!(
        mcp.actions_baseline
            .iter()
            .map(|action| action.name.as_str())
            .collect::<Vec<_>>(),
        ["firecrawl_scrape", "firecrawl_search", "firecrawl_parse"]
    );
}

#[test]
fn every_vendor_argument_fits_the_reviewed_closed_schema() {
    let manifest = shipped_manifest("firecrawl_rest.jsonc");
    let schema = &manifest.actions_baseline[0]
        .http
        .as_ref()
        .unwrap()
        .args_schema;
    assert_eq!(schema["additionalProperties"], false);
    let properties = schema["properties"].as_object().unwrap();
    let domains: Vec<String> = (0..20).map(|index| format!("d{index}.example")).collect();
    let domains: Vec<&str> = domains.iter().map(String::as_str).collect();
    for recency in [
        None,
        Some(Recency::Day),
        Some(Recency::Week),
        Some(Recency::Month),
        Some(Recency::Year),
    ] {
        for domains in [&[][..], &domains[..]] {
            let mut search = query(&"q".repeat(MAX_QUERY_CHARS), domains, recency);
            search.max_results = 20;
            let prepared = FirecrawlRestBackend.prepare(&search, NOW).unwrap();
            let args = prepared.vendor_args.as_object().unwrap();
            for field in args.keys() {
                assert!(
                    properties.contains_key(field),
                    "{field} is not in the reviewed schema"
                );
            }
            let text = args["query"].as_str().unwrap();
            assert!(
                text.encode_utf16().count() as u64
                    <= properties["query"]["maxLength"].as_u64().unwrap()
            );
            let limit = args["limit"].as_u64().unwrap();
            assert!(limit >= properties["limit"]["minimum"].as_u64().unwrap());
            assert!(limit <= properties["limit"]["maximum"].as_u64().unwrap());
            assert_eq!(args["sources"], json!([{"type": "web"}]));
            assert_eq!(
                properties["sources"]["items"]["properties"]["type"]["enum"],
                json!(["web"])
            );
            if let Some(sent) = args.get("includeDomains") {
                assert!(
                    sent.as_array().unwrap().len() as u64
                        <= properties["includeDomains"]["maxItems"].as_u64().unwrap()
                );
            }
            if let Some(tbs) = args.get("tbs") {
                assert!(properties["tbs"]["enum"].as_array().unwrap().contains(tbs));
            }
        }
    }
}

#[test]
fn a_documented_reply_maps_title_url_and_description() {
    let results = FirecrawlRestBackend
        .map_reply(&recorded_body("success"), 5, NOW)
        .unwrap();
    assert_eq!(
        results,
        vec![
            WebSearchResult {
                url: "https://www.firecrawl.dev/".into(),
                title: "Firecrawl - The Web Data API for AI".into(),
                excerpt: "The web crawling, scraping, and search API for AI. Built for scale.".into(),
                published_at: None,
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
            WebSearchResult {
                url: "https://github.com/firecrawl/firecrawl".into(),
                title: "firecrawl/firecrawl: Turn entire websites into LLM-ready markdown".into(),
                excerpt: "Firecrawl is an API service that takes a URL, crawls it, and converts it into clean markdown or structured data.".into(),
                published_at: None,
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
        ],
        "Firecrawl web results map title, url and description"
    );
    assert_eq!(
        FirecrawlRestBackend
            .map_reply(&recorded_body("success"), 1, NOW)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_reply_without_web_results_is_an_empty_success() {
    for record in ["empty", "empty_array"] {
        assert_eq!(
            FirecrawlRestBackend.map_reply(&recorded_body(record), 5, NOW),
            Ok(Vec::new()),
            "{record}: a data object without web results found nothing"
        );
    }
}

#[test]
fn a_reply_without_a_data_object_is_a_shape_error() {
    for record in [
        "malformed",
        "bad_request",
        "payment_required",
        "rate_limited_retry",
        "server_error",
    ] {
        assert!(
            FirecrawlRestBackend
                .map_reply(&recorded_body(record), 5, NOW)
                .is_err(),
            "{record}"
        );
    }
    assert!(
        FirecrawlRestBackend
            .map_reply(&json!({"success": true, "data": {"web": {}}}), 5, NOW)
            .is_err(),
        "a web section that is not an array has the wrong shape"
    );
}

#[test]
fn mapping_falls_back_to_snippet_bounds_excerpts_and_drops_results_without_a_url() {
    let reply = json!({"success": true, "data": {"web": [
        {"url": "https://a.example/", "title": " A ", "description": "é".repeat(700)},
        {"title": "no url is dropped", "description": "x"},
        {"url": "https://b.example/", "description": " ", "snippet": " from snippet "},
        {"url": "https://c.example/"}
    ]}});
    let results = FirecrawlRestBackend.map_reply(&reply, 10, 0).unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].title, "A");
    assert_eq!(results[0].excerpt.chars().count(), EXCERPT_MAX_CHARS);
    assert_eq!(
        results[1].excerpt, "from snippet",
        "snippet fills in when description is empty"
    );
    assert_eq!(
        (results[2].title.as_str(), results[2].excerpt.as_str()),
        ("", "")
    );
    assert!(results.iter().all(|result| result.published_at.is_none()));
    assert_eq!(results[0].fetched_at, "1970-01-01T00:00:00.000Z");
}

#[test]
fn capability_serves_the_whole_tool_envelope_natively() {
    let domains: Vec<String> = (0..20).map(|index| format!("d{index}.example")).collect();
    let domains: Vec<&str> = domains.iter().map(String::as_str).collect();
    for recency in [None, Some(Recency::Day), Some(Recency::Year)] {
        let mut search = query(&"é".repeat(MAX_QUERY_CHARS), &domains, recency);
        search.max_results = 20;
        let prepared = FirecrawlRestBackend.prepare(&search, NOW).unwrap();
        assert_eq!(
            prepared.query, search,
            "native filters leave the query untouched"
        );
        assert_eq!(prepared.vendor_args["limit"], 20);
    }
    let mut many = query("news", &[], None);
    many.max_results = 150;
    let prepared = FirecrawlRestBackend.prepare(&many, NOW).unwrap();
    assert_eq!(
        (prepared.query.max_results, &prepared.vendor_args["limit"]),
        (FIRECRAWL_MAX_LIMIT, &json!(100)),
        "limit is clamped to Firecrawl's maximum of 100"
    );
}

#[test]
fn capability_skips_a_query_over_500_utf16_code_units() {
    // 250 emoji are 250 characters but 500 UTF-16 code units: the limit.
    assert!(FirecrawlRestBackend
        .prepare(&query(&"😀".repeat(250), &[], None), NOW)
        .is_ok());
    assert_eq!(
        FirecrawlRestBackend.prepare(&query(&"😀".repeat(251), &[], None), NOW),
        Err(skip(CapabilityFailure::Length)),
        "a query over Firecrawl's 500-unit limit must skip"
    );
    assert_eq!(
        FirecrawlRestBackend.prepare(&query(&"x".repeat(MAX_QUERY_CHARS + 1), &[], None), NOW),
        Err(skip(CapabilityFailure::Length))
    );
}

#[test]
fn capability_skips_more_domains_than_the_reviewed_schema_takes() {
    let domains: Vec<String> = (0..=MAX_INCLUDE_DOMAINS)
        .map(|index| format!("d{index}.example"))
        .collect();
    let domains: Vec<&str> = domains.iter().map(String::as_str).collect();
    assert_eq!(
        FirecrawlRestBackend.prepare(&query("news", &domains, None), NOW),
        Err(skip(CapabilityFailure::DomainFilter)),
        "more domains than the reviewed schema takes must skip"
    );
    assert!(FirecrawlRestBackend
        .prepare(&query("news", &domains[1..], None), NOW)
        .is_ok());
}
