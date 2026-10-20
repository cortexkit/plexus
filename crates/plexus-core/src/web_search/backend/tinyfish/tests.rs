use super::*;
use crate::manifest::{HttpMethod, RestParameterLocation, Risk, TransportKind};
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
                "../../../../../../catalog/tinyfish_rest.jsonc"
            ))
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
    .manifest
}

#[test]
fn capability_serves_native_domains_and_every_recency_without_changing_query() {
    for (recency, minutes) in [
        (Recency::Day, 1440),
        (Recency::Week, 10080),
        (Recency::Month, 43200),
        (Recency::Year, 525600),
    ] {
        let search = query(
            &"é".repeat(2000),
            &["example.com", "example.org"],
            Some(recency),
        );
        let prepared = TinyFishRestBackend.prepare(&search, NOW).unwrap();
        assert_eq!(prepared.query, search);
        assert_eq!(
            prepared.vendor_args,
            json!({
                "query": search.query,
                "include_domains": "example.com,example.org",
                "recency_minutes": minutes
            }),
            "native domains and recency must survive unchanged query preparation"
        );
    }
    assert_eq!(
        TinyFishRestBackend
            .prepare(&query("q", &[], None), NOW)
            .unwrap()
            .vendor_args,
        json!({"query": "q"}),
        "absent filters and undocumented count fields must not be sent"
    );
}

#[test]
fn capability_skips_queries_beyond_2000_characters_and_tool_domain_envelope() {
    let records = fixtures();
    let too_long = records["capability_skip"]["query_chars"].as_u64().unwrap() as usize;
    let mut cases = vec![(
        query(&"é".repeat(too_long), &[], None),
        CapabilityFailure::Length,
    )];
    let mut domains = query("q", &[], None);
    domains.include_domains = (0..21).map(|n| format!("d{n}.example")).collect();
    cases.push((domains, CapabilityFailure::DomainFilter));
    for (search, failed) in cases {
        assert_eq!(
            TinyFishRestBackend.prepare(&search, NOW),
            Err(CapabilitySkip {
                provider: "tinyfish",
                reason: CapabilitySkipReason::Capability,
                failed
            }),
            "requests beyond the declared envelope must skip TinyFish"
        );
    }
}

#[test]
fn capability_clamps_result_count_locally_to_20() {
    let mut search = query("q", &[], None);
    search.max_results = 60;
    search.include_domains = (0..20).map(|n| format!("d{n}.example")).collect();
    let prepared = TinyFishRestBackend.prepare(&search, NOW).unwrap();
    assert_eq!(
        prepared.query.max_results, 20,
        "local result count must clamp to 20"
    );
    assert_eq!(prepared.query.include_domains, search.include_domains);
    assert!(prepared.vendor_args.get("num_results").is_none());
}

#[test]
fn shipped_manifest_pins_keyed_get_root_query_transport_and_closed_schema() {
    let manifest = manifest();
    assert_eq!(manifest.key, "tinyfish_rest");
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://api.search.tinyfish.ai");
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
        ("api_key", "header", "X-API-Key", "")
    );
    assert!(binding.required);
    let action = &manifest.actions_baseline[0];
    assert_eq!(action.name, "search");
    assert_eq!(action.risk, Risk::Read);
    assert!(action.idempotency.is_none(), "a GET search is Pure");
    let http = action.http.as_ref().unwrap();
    assert_eq!((http.method, http.path.as_str()), (HttpMethod::Get, "/"));
    assert_eq!(http.parameters, Some(RestParameterLocation::Query));
    assert_eq!(http.args_schema["additionalProperties"], false);
    assert_eq!(http.args_schema["required"], json!(["query"]));
    let fields = &http.args_schema["properties"];
    assert_eq!(fields.as_object().unwrap().len(), 3);
    assert_eq!(fields["query"]["minLength"], 1);
    assert_eq!(fields["query"]["maxLength"], 2000);
    assert_eq!(fields["include_domains"]["type"], "string");
    assert_eq!(fields["recency_minutes"]["minimum"], 1);
    assert_eq!(fields["recency_minutes"]["maximum"], 5256000);
}

#[test]
fn documented_results_map_title_url_snippet_and_optional_date() {
    assert_eq!(
        TinyFishRestBackend.map_reply(&body("success"), 5, NOW),
        Ok(vec![
            WebSearchResult {
                url: "https://example.com/web-automation-tools".into(),
                title: "Best Web Automation Tools".into(),
                excerpt: "Top web automation tools for 2026...".into(),
                published_at: Some("2026-06-18T00:00:00.000Z".into()),
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
        "TinyFish results must map title, url, snippet and optional date"
    );
    assert_eq!(
        TinyFishRestBackend.map_reply(&body("empty"), 5, NOW),
        Ok(vec![])
    );
    for reply in [
        body("malformed"),
        json!({"results": null}),
        json!({"results": {}}),
    ] {
        assert!(TinyFishRestBackend.map_reply(&reply, 5, NOW).is_err());
    }
}

#[test]
fn mapping_bounds_count_and_unicode_excerpts_and_drops_unlinked_items() {
    let reply = json!({"results": [
        {"title": "no URL", "snippet": "not a result"}, {"url": " "}, {"url": null},
        {"url": " https://a.example/ ", "title": " A ", "snippet": "é".repeat(700), "date": "invalid"},
        {"url": "https://b.example/", "date": "2025-01-23T12:30:00Z"}
    ]});
    let results = TinyFishRestBackend.map_reply(&reply, 5, 0).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].url, "https://a.example/");
    assert_eq!(results[0].title, "A");
    assert_eq!(results[0].excerpt, "é".repeat(EXCERPT_MAX_CHARS));
    assert!(results[0].published_at.is_none());
    assert_eq!(
        results[1].published_at.as_deref(),
        Some("2025-01-23T12:30:00.000Z")
    );
    assert_eq!(results[1].title, "");
    assert_eq!(results[1].excerpt, "");
    assert_eq!(
        TinyFishRestBackend.map_reply(&reply, 1, 0).unwrap().len(),
        1,
        "mapping must respect the caller's local result count"
    );
    assert!(TinyFishRestBackend
        .map_reply(&reply, 0, 0)
        .unwrap()
        .is_empty());
    let many = json!({"results": vec![json!({"url": "https://a.example/"}); 25]});
    assert_eq!(
        TinyFishRestBackend.map_reply(&many, 25, 0).unwrap().len(),
        20,
        "mapping enforces the local cap even without a vendor count field"
    );
}

#[test]
fn production_registry_uses_tinyfish_backend_and_named_vault_credential() {
    let provider = crate::web_search::providers::provider_named("tinyfish").unwrap();
    let backend = crate::web_search::registered_backend(provider).unwrap();
    assert_eq!(
        (backend.name(), backend.app_key(), backend.action()),
        ("tinyfish", "tinyfish_rest", "search")
    );
    assert_eq!(
        provider.credential,
        crate::web_search::providers::VaultCredential::Required("apikey:tinyfish")
    );
}
