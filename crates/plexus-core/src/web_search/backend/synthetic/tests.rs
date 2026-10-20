use super::*;
use crate::manifest::{HttpMethod, Risk, TransportKind};
use crate::web_search::query::Recency;

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
                "../../../../../../catalog/synthetic_rest.jsonc"
            ))
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
    .manifest
}

#[test]
fn capability_serves_unfiltered_queries_with_query_only_and_local_count() {
    let search = query(&"é".repeat(500), &[], None);
    let prepared = SyntheticRestBackend.prepare(&search, NOW).unwrap();
    assert_eq!(prepared.query, search);
    assert_eq!(
        prepared.vendor_args,
        json!({"query": search.query}),
        "Synthetic must receive only the literal query"
    );
    let mut search = query("weather report", &[], None);
    search.max_results = 60;
    let prepared = SyntheticRestBackend.prepare(&search, NOW).unwrap();
    assert_eq!(prepared.query.max_results, MAX_RESULTS_LIMIT);
    assert_eq!(prepared.vendor_args, json!({"query": "weather report"}));
}

#[test]
fn capability_skips_domains_and_every_recency_instead_of_dropping_filters() {
    let records = fixtures();
    let domain = records["capability_skip"]["include_domains"][0]
        .as_str()
        .unwrap();
    let mut cases = vec![(query("q", &[domain], None), CapabilityFailure::DomainFilter)];
    for recency in [Recency::Day, Recency::Week, Recency::Month, Recency::Year] {
        cases.push((query("q", &[], Some(recency)), CapabilityFailure::Recency));
    }
    cases.push((
        query(&"é".repeat(501), &[], None),
        CapabilityFailure::Length,
    ));
    for (search, failed) in cases {
        assert_eq!(
            SyntheticRestBackend.prepare(&search, NOW),
            Err(CapabilitySkip {
                provider: "synthetic",
                reason: CapabilitySkipReason::Capability,
                failed,
            }),
            "unsupported requests must skip Synthetic before dispatch"
        );
    }
}

#[test]
fn shipped_manifest_pins_bearer_query_only_search_and_closed_schema() {
    let manifest = manifest();
    assert_eq!(manifest.key, "synthetic_rest");
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://api.synthetic.new");
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
        (HttpMethod::Post, "/v2/search")
    );
    assert_eq!(http.args_schema["additionalProperties"], false);
    assert_eq!(http.args_schema["required"], json!(["query"]));
    let fields = &http.args_schema["properties"];
    assert_eq!(fields.as_object().unwrap().len(), 1);
    assert_eq!(fields["query"]["minLength"], 1);
    assert_eq!(fields["query"]["maxLength"], 500);
}

#[test]
fn documented_results_map_title_url_text_and_published() {
    assert_eq!(
        SyntheticRestBackend.map_reply(&body("success"), 5, NOW),
        Ok(vec![
            WebSearchResult {
                url: "https://example.com/article".into(),
                title: "Example Article".into(),
                excerpt: "A relevant excerpt from the page.".into(),
                published_at: Some("2025-01-23T12:30:00.000Z".into()),
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
            WebSearchResult {
                url: "https://example.org/source".into(),
                title: "Another Source".into(),
                excerpt: "Another page excerpt.".into(),
                published_at: None,
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            }
        ]),
        "Synthetic results must map title, url, text and published"
    );
    assert_eq!(
        SyntheticRestBackend.map_reply(&body("empty"), 5, NOW),
        Ok(vec![])
    );
    for reply in [
        body("malformed"),
        json!({"results": null}),
        json!({"results": {}}),
    ] {
        assert!(SyntheticRestBackend.map_reply(&reply, 5, NOW).is_err());
    }
}

#[test]
fn mapping_bounds_count_and_unicode_excerpts_and_drops_unlinked_items() {
    let reply = json!({"results": [
        {"title": "no URL", "text": "not a result"}, {"url": " "}, {"url": null},
        {"url": " https://a.example/ ", "title": " A ", "text": "é".repeat(700), "published": "invalid"},
        {"url": "https://b.example/", "published": "2025-01-23"}
    ]});
    let results = SyntheticRestBackend.map_reply(&reply, 5, 0).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].url, "https://a.example/");
    assert_eq!(results[0].title, "A");
    assert_eq!(results[0].excerpt, "é".repeat(EXCERPT_MAX_CHARS));
    assert!(results[0].published_at.is_none());
    assert_eq!(
        results[1].published_at.as_deref(),
        Some("2025-01-23T00:00:00.000Z")
    );
    assert_eq!(results[1].title, "");
    assert_eq!(results[1].excerpt, "");
    assert_eq!(
        SyntheticRestBackend.map_reply(&reply, 1, 0).unwrap().len(),
        1
    );
    assert!(SyntheticRestBackend
        .map_reply(&reply, 0, 0)
        .unwrap()
        .is_empty());
}

#[test]
fn production_registry_uses_synthetic_backend_and_named_vault_credential() {
    let provider = crate::web_search::providers::provider_named("synthetic").unwrap();
    let backend = crate::web_search::registered_backend(provider).unwrap();
    assert_eq!(
        (backend.name(), backend.app_key(), backend.action()),
        ("synthetic", "synthetic_rest", "search")
    );
    assert_eq!(
        provider.credential,
        crate::web_search::providers::VaultCredential::Required("apikey:synthetic")
    );
}
