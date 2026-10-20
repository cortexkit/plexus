use super::*;
use crate::manifest::{HttpMethod, Risk, TransportKind};
use crate::web_search::capability::{CapabilityFailure, CapabilitySkip, CapabilitySkipReason};
use crate::web_search::query::Recency;

const NOW: i64 = 1_790_596_800_000; // 2026-09-28T12:00:00Z

fn query(text: &str, domains: &[&str], recency: Option<Recency>) -> WebSearchQuery {
    WebSearchQuery {
        query: text.into(),
        max_results: 5,
        include_domains: domains.iter().map(|domain| domain.to_string()).collect(),
        recency,
    }
}

fn body(record: &str) -> Value {
    let fixtures: Value = serde_json::from_str(include_str!("fixtures.json")).unwrap();
    serde_json::from_str(fixtures[record]["body"].as_str().unwrap()).unwrap()
}

fn manifest() -> crate::manifest::AppManifest {
    crate::manifest::ingest_value(
        serde_json::from_str(
            &subc_jsonc::jsonc_to_json(include_str!(
                "../../../../../../catalog/parallel_rest.jsonc"
            ))
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
    .manifest
}

#[test]
fn native_fields_preserve_query_domains_and_each_recency_window() {
    for (recency, date) in [
        (Recency::Day, "2026-09-27"),
        (Recency::Week, "2026-09-21"),
        (Recency::Month, "2026-08-29"),
        (Recency::Year, "2025-09-28"),
    ] {
        let prepared = ParallelRestBackend
            .prepare(
                &query(
                    "weather report",
                    &["example.com", "example.org"],
                    Some(recency),
                ),
                NOW,
            )
            .unwrap();
        assert_eq!(
            prepared.vendor_args,
            json!({
                "search_queries": ["weather report"], "advanced_settings": {"max_results": 5,
                "source_policy": {"include_domains": ["example.com", "example.org"], "after_date": date}}
            }),
            "native filters must not be dropped or composed into the query"
        );
    }
    assert_eq!(
        ParallelRestBackend
            .prepare(&query("q", &[], None), NOW)
            .unwrap()
            .vendor_args,
        json!({"search_queries": ["q"], "advanced_settings": {"max_results": 5}})
    );
}

#[test]
fn shipped_manifest_pins_keyed_ga_search_and_closed_schema() {
    let manifest = manifest();
    assert_eq!(manifest.key, "parallel_rest");
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://api.parallel.ai");
    let binding = &manifest.credential_bindings[0];
    assert_eq!(
        (
            binding.ref_role.as_str(),
            binding.placement.as_str(),
            binding.key.as_str(),
            binding.prefix.as_str()
        ),
        ("api_key", "header", "x-api-key", "")
    );
    assert!(binding.required);
    let action = &manifest.actions_baseline[0];
    assert_eq!(action.name, "search");
    assert_eq!(action.risk, Risk::Read);
    assert!(
        action.idempotency.is_none(),
        "read-risk search needs no deprecated write-idempotency metadata"
    );
    let http = action.http.as_ref().unwrap();
    assert_eq!(
        (http.method, http.path.as_str()),
        (HttpMethod::Post, "/v1/search")
    );
    assert!(http.request_constants.is_none());
    assert!(
        http.header_parameters.is_none(),
        "GA requires no beta header"
    );
    assert_eq!(http.args_schema["additionalProperties"], false);
    let settings = &http.args_schema["properties"]["advanced_settings"];
    assert_eq!(settings["properties"]["max_results"]["maximum"], 20);
    assert_eq!(
        settings["properties"]["source_policy"]["additionalProperties"],
        false
    );
    assert_eq!(
        http.args_schema["properties"]["search_queries"]["items"]["maxLength"],
        200
    );
    assert_eq!(
        http.args_schema["required"],
        json!(["search_queries", "advanced_settings"])
    );
}

#[test]
fn documented_sources_map_only_links_excerpts_and_publication_dates() {
    let results = ParallelRestBackend
        .map_reply(&body("success"), 5, NOW)
        .unwrap();
    assert_eq!(
        results,
        vec![
            WebSearchResult {
                url: "https://example.com/news".into(),
                title: "Example news".into(),
                excerpt: "First excerpt.\nSecond excerpt.".into(),
                published_at: Some("2026-09-27T00:00:00.000Z".into()),
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
            WebSearchResult {
                url: "https://example.org/".into(),
                title: "Another source".into(),
                excerpt: "Another excerpt.".into(),
                published_at: None,
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            }
        ]
    );
    assert_eq!(
        ParallelRestBackend
            .map_reply(&body("success"), 1, NOW)
            .unwrap()
            .len(),
        1
    );
    assert!(ParallelRestBackend
        .map_reply(&body("success"), 0, NOW)
        .unwrap()
        .is_empty());
    assert_eq!(
        ParallelRestBackend.map_reply(&body("empty"), 5, NOW),
        Ok(vec![])
    );
    for reply in [
        body("malformed"),
        json!({"results": null}),
        json!({"results": {}}),
    ] {
        assert!(ParallelRestBackend.map_reply(&reply, 5, NOW).is_err());
    }
}

#[test]
fn missing_urls_are_dropped_excerpts_bounded_and_invalid_dates_omitted() {
    let reply = json!({"results": [
        {"title": "no URL"}, {"url": " "}, {"url": null},
        {"url": " https://a.example/ ", "title": " A ", "excerpts": [null, "", "é".repeat(700)], "publish_date": "invalid"},
        {"url": "https://b.example/"}
    ]});
    let results = ParallelRestBackend.map_reply(&reply, 5, 0).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].url, "https://a.example/");
    assert_eq!(results[0].title, "A");
    assert_eq!(results[0].excerpt, "é".repeat(EXCERPT_MAX_CHARS));
    assert!(results.iter().all(|result| result.published_at.is_none()));
    assert_eq!(results[1].excerpt, "");
    assert_eq!(results[1].title, "");
}

#[test]
fn capability_serves_the_declared_envelope_and_clamps_result_count() {
    let mut search = query(
        &"é".repeat(PARALLEL_MAX_QUERY_CHARS),
        &["example.com"; MAX_INCLUDE_DOMAINS],
        Some(Recency::Day),
    );
    search.max_results = 60;
    let prepared = ParallelRestBackend.prepare(&search, NOW).unwrap();
    assert_eq!(prepared.query.max_results, 20);
    assert_eq!(prepared.vendor_args["advanced_settings"]["max_results"], 20);
    assert_eq!(
        prepared.vendor_args["search_queries"],
        json!([search.query])
    );
    assert_eq!(
        prepared.vendor_args["advanced_settings"]["source_policy"]["include_domains"]
            .as_array()
            .unwrap()
            .len(),
        MAX_INCLUDE_DOMAINS
    );
}

#[test]
fn capability_skips_outside_the_declared_query_and_domain_envelope() {
    // Exercise a vendor query limit smaller than the tool's public envelope,
    // plus the tool's domain limit via direct preparation.
    for (search, failed) in [
        (
            query(&"é".repeat(PARALLEL_MAX_QUERY_CHARS + 1), &[], None),
            CapabilityFailure::Length,
        ),
        (
            query("q", &["example.com"; MAX_INCLUDE_DOMAINS + 1], None),
            CapabilityFailure::DomainFilter,
        ),
    ] {
        assert_eq!(
            ParallelRestBackend.prepare(&search, NOW),
            Err(CapabilitySkip {
                provider: "parallel",
                reason: CapabilitySkipReason::Capability,
                failed,
            }),
            "requests beyond the declared envelope must skip Parallel"
        );
    }
}

#[test]
fn production_registry_uses_parallel_backend_and_named_vault_credential() {
    let provider = crate::web_search::providers::provider_named("parallel").unwrap();
    let backend = crate::web_search::registered_backend(provider).unwrap();
    assert_eq!(
        (backend.name(), backend.app_key(), backend.action()),
        ("parallel", "parallel_rest", "search")
    );
    assert_eq!(
        provider.credential,
        crate::web_search::providers::VaultCredential::Required("apikey:parallel")
    );
}
