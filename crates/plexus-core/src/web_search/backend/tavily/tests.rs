use serde_json::{json, Value};

use super::*;
use crate::manifest::{HttpMethod, Risk, TransportKind};
use crate::web_search::capability::{CapabilityFailure, CapabilitySkip, CapabilitySkipReason};

const NOW: i64 = 1_790_596_800_000; // 2026-09-28T12:00:00Z

/// The recorded vendor reply `name` from `fixtures.json`, parsed.
pub(crate) fn recorded_body(name: &str) -> Value {
    let recordings: Value = serde_json::from_str(include_str!("fixtures.json")).unwrap();
    let body = recordings[name]["body"]
        .as_str()
        .unwrap_or_else(|| panic!("missing recorded Tavily reply {name}"));
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
        "tavily_rest.jsonc" => include_str!("../../../../../../catalog/tavily_rest.jsonc"),
        "tavily.jsonc" => include_str!("../../../../../../catalog/tavily.jsonc"),
        _ => unreachable!(),
    };
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

#[test]
fn vendor_args_use_tavilys_documented_field_names() {
    let args = TavilyRestBackend.vendor_args(
        &query(
            "Who is Leo Messi?",
            &["britannica.com", "fifa.com"],
            Some(Recency::Week),
        ),
        NOW,
    );
    assert_eq!(
        args,
        json!({
            "query": "Who is Leo Messi?",
            "max_results": 5,
            "include_domains": ["britannica.com", "fifa.com"],
            "time_range": "week",
            "include_published_date": true,
            "filter_by_published_date": true
        })
    );
    let bare = TavilyRestBackend.vendor_args(&query("Who is Leo Messi?", &[], None), NOW);
    assert_eq!(
        bare,
        json!({"query": "Who is Leo Messi?", "max_results": 5, "include_published_date": true}),
        "no filter field is sent unless the caller asked for that filter"
    );
    for (recency, range) in [
        (Recency::Day, "day"),
        (Recency::Week, "week"),
        (Recency::Month, "month"),
        (Recency::Year, "year"),
    ] {
        assert_eq!(
            TavilyRestBackend.vendor_args(&query("news", &[], Some(recency)), NOW)["time_range"],
            range
        );
    }
}

#[test]
fn the_shipped_manifest_pins_tavilys_search_endpoint_and_bearer_key() {
    let manifest = shipped_manifest("tavily_rest.jsonc");
    assert_eq!(manifest.key, TavilyRestBackend.app_key());
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://api.tavily.com");
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
    assert_eq!(search.name, TavilyRestBackend.action());
    assert_eq!(search.risk, Risk::Read);
    let http = search.http.as_ref().unwrap();
    assert_eq!(
        (http.method, http.path.as_str()),
        (HttpMethod::Post, "/search")
    );

    // The existing MCP manifest keeps its own key and transport, so its
    // connections can never resolve as REST search connections.
    let mcp = shipped_manifest("tavily.jsonc");
    assert_eq!(mcp.key, "tavily");
    assert_eq!(mcp.transport.kind, TransportKind::McpRemote);
    assert_ne!(mcp.key, TavilyRestBackend.app_key());
}

#[test]
fn every_vendor_argument_fits_the_reviewed_closed_schema() {
    let manifest = shipped_manifest("tavily_rest.jsonc");
    let schema = &manifest.actions_baseline[0]
        .http
        .as_ref()
        .unwrap()
        .args_schema;
    assert_eq!(schema["additionalProperties"], false);
    let properties = schema["properties"].as_object().unwrap();
    let domains: Vec<String> = (0..20).map(|index| format!("d{index}.example")).collect();
    let domains: Vec<&str> = domains.iter().map(String::as_str).collect();
    for recency in [None, Some(Recency::Day), Some(Recency::Year)] {
        for domains in [&[][..], &domains[..]] {
            let mut search = query(&"q".repeat(500), domains, recency);
            search.max_results = 20;
            let prepared = TavilyRestBackend.prepare(&search, NOW).unwrap();
            let args = prepared.vendor_args.as_object().unwrap();
            for (field, value) in args {
                let property = properties
                    .get(field)
                    .unwrap_or_else(|| panic!("{field} is not in the reviewed schema"));
                match property["type"].as_str().unwrap() {
                    "string" => {
                        assert!(value.is_string());
                        if let Some(allowed) = property.get("enum") {
                            assert!(allowed.as_array().unwrap().contains(value), "{value}");
                        }
                    }
                    "integer" => {
                        let count = value.as_u64().unwrap();
                        assert!(count <= property["maximum"].as_u64().unwrap());
                    }
                    "array" => {
                        let items = value.as_array().unwrap();
                        assert!(items.iter().all(Value::is_string));
                        assert!(items.len() as u64 <= property["maxItems"].as_u64().unwrap());
                    }
                    "boolean" => assert!(value.is_boolean()),
                    other => panic!("unexpected schema type {other}"),
                }
            }
            assert!(args.contains_key("query"));
        }
    }
}

#[test]
fn a_documented_reply_maps_title_url_content_and_date_and_drops_the_answer() {
    let reply = recorded_body("success");
    let results = TavilyRestBackend.map_reply(&reply, 5, NOW).unwrap();
    assert_eq!(
        results,
        vec![WebSearchResult {
            url: "https://www.britannica.com/facts/Lionel-Messi".into(),
            title: "Lionel Messi Facts | Britannica".into(),
            excerpt: "Lionel Messi, an Argentine footballer, is widely regarded as one of the greatest football players of his generation.".into(),
            published_at: Some("2025-03-11T17:00:00.000Z".into()),
            fetched_at: "2026-09-28T12:00:00.000Z".into(),
        }]
    );
    let answer = reply["answer"].as_str().unwrap();
    assert!(!serde_json::to_string(&results).unwrap().contains(answer));
}

#[test]
fn a_documented_reply_with_no_results_is_an_empty_success() {
    assert_eq!(
        TavilyRestBackend.map_reply(&recorded_body("empty"), 5, NOW),
        Ok(Vec::new()),
        "an answer without results contributes nothing"
    );
}

#[test]
fn a_reply_without_a_results_array_is_a_shape_error() {
    assert!(TavilyRestBackend
        .map_reply(&recorded_body("malformed"), 5, NOW)
        .is_err());
    assert!(TavilyRestBackend
        .map_reply(&recorded_body("unauthorized"), 5, NOW)
        .is_err());
}

#[test]
fn mapping_bounds_excerpts_and_drops_unusable_results_and_dates() {
    let reply = json!({"answer": "summary", "results": [
        {"url": "https://a.example/", "title": " A ", "content": "é".repeat(700), "published_date": null},
        {"title": "no url is dropped", "content": "x"},
        {"url": "https://b.example/", "published_date": "2024-02-29"},
        {"url": "https://c.example/", "published_date": "11/03/2025"},
        {"url": "https://d.example/"}
    ]});
    let results = TavilyRestBackend.map_reply(&reply, 10, 0).unwrap();
    assert_eq!(results.len(), 4);
    assert_eq!(results[0].title, "A");
    assert_eq!(results[0].excerpt.chars().count(), EXCERPT_MAX_CHARS);
    assert_eq!(results[0].published_at, None);
    assert_eq!(results[1].url, "https://b.example/");
    assert_eq!(
        (results[1].title.as_str(), results[1].excerpt.as_str()),
        ("", "")
    );
    assert_eq!(
        results[1].published_at.as_deref(),
        Some("2024-02-29T00:00:00.000Z")
    );
    assert_eq!(results[2].published_at, None);
    assert_eq!(results[0].fetched_at, "1970-01-01T00:00:00.000Z");
    assert_eq!(TavilyRestBackend.map_reply(&reply, 2, 0).unwrap().len(), 2);
}

#[test]
fn capability_serves_the_whole_tool_envelope_natively() {
    let domains: Vec<String> = (0..20).map(|index| format!("d{index}.example")).collect();
    let domains: Vec<&str> = domains.iter().map(String::as_str).collect();
    for recency in [
        None,
        Some(Recency::Day),
        Some(Recency::Week),
        Some(Recency::Month),
        Some(Recency::Year),
    ] {
        let mut search = query(&"é".repeat(MAX_QUERY_CHARS), &domains, recency);
        search.max_results = 20;
        let prepared = TavilyRestBackend.prepare(&search, NOW).unwrap();
        assert_eq!(
            prepared.query, search,
            "native filters leave the query untouched"
        );
        assert_eq!(
            prepared.vendor_args,
            TavilyRestBackend.vendor_args(&search, NOW)
        );
        assert_eq!(prepared.vendor_args["max_results"], 20);
    }
}

#[test]
fn capability_skips_what_tavily_cannot_take_before_mapping() {
    let skip = |failed| CapabilitySkip {
        provider: "tavily",
        reason: CapabilitySkipReason::Capability,
        failed,
    };
    let long = query(&"x".repeat(MAX_QUERY_CHARS + 1), &[], None);
    assert_eq!(
        TavilyRestBackend.prepare(&long, NOW),
        Err(skip(CapabilityFailure::Length))
    );
    let domains: Vec<String> = (0..=TAVILY_MAX_INCLUDE_DOMAINS)
        .map(|index| format!("d{index}.example"))
        .collect();
    let domains: Vec<&str> = domains.iter().map(String::as_str).collect();
    assert_eq!(
        TavilyRestBackend.prepare(&query("news", &domains, None), NOW),
        Err(skip(CapabilityFailure::DomainFilter))
    );
    assert!(TavilyRestBackend
        .prepare(&query("news", &domains[1..], None), NOW)
        .is_ok());
}
