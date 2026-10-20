use super::*;
use crate::manifest::{HttpMethod, Risk, TransportKind};
use crate::web_search::capability::{CapabilityFailure, CapabilitySkip, CapabilitySkipReason};

const NOW: i64 = 1_790_596_800_000;

fn query(text: &str, domains: &[&str], recency: Option<Recency>) -> WebSearchQuery {
    WebSearchQuery {
        query: text.into(),
        max_results: 5,
        include_domains: domains.iter().map(|domain| domain.to_string()).collect(),
        recency,
    }
}

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures.json")).unwrap()
}

fn body(record: &str) -> Value {
    serde_json::from_str(fixtures()[record]["body"].as_str().unwrap()).unwrap()
}

fn manifest() -> crate::manifest::AppManifest {
    crate::manifest::ingest_value(
        serde_json::from_str(
            &subc_jsonc::jsonc_to_json(include_str!(
                "../../../../../../catalog/perplexity_rest.jsonc"
            ))
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
    .manifest
}

#[test]
fn native_fields_preserve_literal_query_count_domains_and_each_recency() {
    for (recency, value) in [
        (Recency::Day, "day"),
        (Recency::Week, "week"),
        (Recency::Month, "month"),
        (Recency::Year, "year"),
    ] {
        let prepared = PerplexityRestBackend
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
            json!({"query": "weather report", "max_results": 5,
                "search_domain_filter": ["example.com", "example.org"], "search_recency_filter": value}),
            "native query, count, domain and recency fields must be preserved"
        );
    }
    assert_eq!(
        PerplexityRestBackend
            .prepare(&query("q", &[], None), NOW)
            .unwrap()
            .vendor_args,
        json!({"query": "q", "max_results": 5}),
        "unrequested filters must be omitted"
    );
}

#[test]
fn shipped_manifest_pins_bearer_search_not_completions_and_closed_schema() {
    let manifest = manifest();
    assert_eq!(manifest.key, "perplexity_rest");
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://api.perplexity.ai");
    assert_eq!(manifest.actions_baseline.len(), 1);
    assert_eq!(manifest.credential_bindings.len(), 1);
    let binding = &manifest.credential_bindings[0];
    assert_eq!(
        (
            binding.ref_role.as_str(),
            binding.placement.as_str(),
            binding.key.as_str(),
            binding.prefix.as_str()
        ),
        ("api_key", "header", "Authorization", "Bearer ")
    );
    assert!(binding.required);
    let action = &manifest.actions_baseline[0];
    assert_eq!(action.name, "search");
    assert_eq!(action.risk, Risk::Read);
    assert!(action.idempotency.is_none());
    let http = action.http.as_ref().unwrap();
    assert_eq!(
        (http.method, http.path.as_str()),
        (HttpMethod::Post, "/search")
    );
    assert_eq!(http.args_schema["additionalProperties"], false);
    assert_eq!(
        http.args_schema["required"],
        json!(["query", "max_results"])
    );
    let fields = &http.args_schema["properties"];
    assert_eq!(fields.as_object().unwrap().len(), 4);
    assert_eq!(fields["query"]["maxLength"], 500);
    assert_eq!(fields["max_results"]["maximum"], 20);
    assert_eq!(fields["search_domain_filter"]["maxItems"], 20);
    assert_eq!(fields["search_domain_filter"]["items"]["maxLength"], 253);
    assert_eq!(
        fields["search_recency_filter"]["enum"],
        json!(["day", "week", "month", "year"])
    );
}

#[test]
fn documented_results_map_links_and_source_metadata_never_generated_answers() {
    let results = PerplexityRestBackend
        .map_reply(&body("success"), 5, NOW)
        .unwrap();
    assert_eq!(
        results,
        vec![
            WebSearchResult {
                url: "https://example.com/article".into(),
                title: "Example Article Title".into(),
                excerpt: "A short excerpt from the article relevant to the query...".into(),
                published_at: Some("2025-01-23T00:00:00.000Z".into()),
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
            WebSearchResult {
                url: "https://example.org/source".into(),
                title: "Another Relevant Source".into(),
                excerpt: "Another excerpt showing the structured result format.".into(),
                published_at: None,
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            }
        ],
        "only linked sources, never generated answer text or last_updated, may become results"
    );
    assert_eq!(
        PerplexityRestBackend
            .map_reply(&body("success"), 1, NOW)
            .unwrap()
            .len(),
        1
    );
    assert!(PerplexityRestBackend
        .map_reply(&body("success"), 0, NOW)
        .unwrap()
        .is_empty());
    assert_eq!(
        PerplexityRestBackend.map_reply(&body("empty"), 5, NOW),
        Ok(vec![])
    );
    for reply in [
        body("malformed"),
        json!({"results": null}),
        json!({"results": {}}),
    ] {
        assert!(PerplexityRestBackend.map_reply(&reply, 5, NOW).is_err());
    }
}

#[test]
fn unlinked_items_are_dropped_snippets_bounded_and_invalid_dates_omitted() {
    let results = PerplexityRestBackend.map_reply(&json!({"results": [
        {"title": "no URL", "snippet": "not a result"}, {"url": " "}, {"url": null},
        {"url": " https://a.example/ ", "title": " A ", "snippet": "é".repeat(700), "date": "invalid"},
        {"url": "https://b.example/", "answer": "never use this as a snippet", "last_updated": "2025-09-25"}
    ]}), 5, 0).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].url, "https://a.example/");
    assert_eq!(results[0].title, "A");
    assert_eq!(results[0].excerpt, "é".repeat(EXCERPT_MAX_CHARS));
    assert!(results.iter().all(|result| result.published_at.is_none()));
    assert_eq!(results[1].title, "");
    assert_eq!(results[1].excerpt, "");
}

#[test]
fn capability_serves_full_tool_envelope_and_clamps_to_twenty_web_results() {
    let mut search = query(&"é".repeat(500), &["example.com"; 20], Some(Recency::Year));
    search.max_results = 60;
    let prepared = PerplexityRestBackend.prepare(&search, NOW).unwrap();
    assert_eq!(
        prepared.query.max_results, 20,
        "web search must clamp to twenty results"
    );
    assert_eq!(prepared.vendor_args["max_results"], 20);
    assert_eq!(prepared.vendor_args["query"], search.query);
    assert_eq!(
        prepared.vendor_args["search_domain_filter"]
            .as_array()
            .unwrap()
            .len(),
        20
    );
    assert_eq!(prepared.vendor_args["search_recency_filter"], "year");
}

#[test]
fn capability_skips_direct_preparation_beyond_query_and_domain_envelopes() {
    // All validated tool requests fit the vendor's documented filter limits.
    // Exercise defensive preparation directly, without weakening that support.
    let records = fixtures();
    let query_chars = records["capability_skip"]["query_chars"].as_u64().unwrap() as usize;
    let domain_count = records["capability_skip"]["domain_count"].as_u64().unwrap() as usize;
    for (search, failed) in [
        (
            query(&"é".repeat(query_chars), &[], None),
            CapabilityFailure::Length,
        ),
        (
            query("q", &vec!["example.com"; domain_count], None),
            CapabilityFailure::DomainFilter,
        ),
    ] {
        assert_eq!(
            PerplexityRestBackend.prepare(&search, NOW),
            Err(CapabilitySkip {
                provider: "perplexity",
                reason: CapabilitySkipReason::Capability,
                failed,
            }),
            "requests beyond the declared envelope must skip Perplexity"
        );
    }
}

#[test]
fn production_registry_uses_perplexity_backend_and_named_vault_credential() {
    let provider = crate::web_search::providers::provider_named("perplexity").unwrap();
    let backend = crate::web_search::registered_backend(provider).unwrap();
    assert_eq!(
        (backend.name(), backend.app_key(), backend.action()),
        ("perplexity", "perplexity_rest", "search")
    );
    assert_eq!(
        provider.credential,
        crate::web_search::providers::VaultCredential::Required("apikey:perplexity")
    );
}
