use super::*;
use crate::manifest::{AuthMode, HttpMethod, RestParameterLocation, Risk};

pub(crate) fn manifest() -> crate::manifest::AppManifest {
    crate::manifest::ingest_value(
        serde_json::from_str(
            &subc_jsonc::jsonc_to_json(include_str!(
                "../../../../../../catalog/searxng_rest.jsonc"
            ))
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
    .manifest
}

fn query(domains: &[&str], recency: Option<Recency>) -> WebSearchQuery {
    WebSearchQuery {
        query: "weather & climate?".into(),
        max_results: 5,
        include_domains: domains.iter().map(|s| s.to_string()).collect(),
        recency,
    }
}

#[test]
fn capability_serves_exact_native_time_ranges_and_language() {
    for (recency, time_range) in [
        (Recency::Day, "day"),
        (Recency::Month, "month"),
        (Recency::Year, "year"),
    ] {
        let prepared = SearxngRestBackend
            .prepare(&query(&[], Some(recency)), 0)
            .unwrap();
        assert_eq!(
            prepared.vendor_args,
            json!({"q":"weather & climate?", "format":"json", "language":"all", "time_range":time_range})
        );
    }
    let mut search = query(&[], None);
    search.max_results = 50;
    let prepared = SearxngRestBackend.prepare(&search, 0).unwrap();
    assert_eq!(prepared.query.max_results, 20);
    assert_eq!(
        prepared.vendor_args,
        json!({"q":search.query, "format":"json", "language":"all"})
    );
}

#[test]
fn capability_skips_domains_week_and_oversized_queries() {
    let mut large = query(&[], None);
    large.query = "é".repeat(501);
    for (search, failed) in [
        (
            query(&["example.org"], None),
            CapabilityFailure::DomainFilter,
        ),
        (query(&[], Some(Recency::Week)), CapabilityFailure::Recency),
        (large, CapabilityFailure::Length),
    ] {
        assert_eq!(
            SearxngRestBackend.prepare(&search, 0),
            Err(CapabilitySkip {
                provider: "searxng",
                reason: CapabilitySkipReason::Capability,
                failed
            })
        );
    }
}

#[test]
fn shipped_manifest_pins_private_instance_optional_bearer_get_and_pure_read() {
    let m = manifest();
    assert_eq!(m.key, "searxng_rest");
    assert!(m.transport.url_from_connection);
    assert!(m.transport.url.is_empty());
    assert_eq!(m.auth.mode, AuthMode::OptionalApiKey);
    assert_eq!(m.credential_bindings.len(), 1);
    let b = &m.credential_bindings[0];
    assert_eq!(
        (b.key.as_str(), b.prefix.as_str(), b.placement.as_str()),
        ("Authorization", "Bearer ", "header")
    );
    let a = &m.actions_baseline[0];
    assert_eq!((a.name.as_str(), a.risk), ("search", Risk::Read));
    assert!(a.idempotency.is_none());
    let http = a.http.as_ref().unwrap();
    assert_eq!(
        (http.method, http.path.as_str(), http.parameters),
        (
            HttpMethod::Get,
            "/search",
            Some(RestParameterLocation::Query)
        )
    );
    assert_eq!(http.args_schema["additionalProperties"], false);
    let provider = crate::web_search::providers::provider_named("searxng").unwrap();
    assert_eq!(
        crate::web_search::registered_backend(provider)
            .unwrap()
            .app_key(),
        "searxng_rest"
    );
    assert_eq!(
        provider.credential,
        crate::web_search::providers::VaultCredential::Optional("apikey:searxng")
    );
}

#[test]
fn documented_results_map_and_bound_content_and_published_date() {
    assert_eq!(
        published_date("Mon, 19 Oct 2026 12:30:00 GMT").as_deref(),
        Some("2026-10-19T12:30:00.000Z")
    );
    let records: Value = serde_json::from_str(include_str!("fixtures.json")).unwrap();
    let body =
        |key: &str| serde_json::from_str::<Value>(records[key]["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        SearxngRestBackend
            .map_reply(&body("success"), 5, 0)
            .unwrap(),
        vec![WebSearchResult {
            url: "https://example.org/weather".into(),
            title: "Weather report".into(),
            excerpt: "Forecast summary".into(),
            published_at: Some("2026-10-19T12:30:00.000Z".into()),
            fetched_at: "1970-01-01T00:00:00.000Z".into()
        }]
    );
    assert!(SearxngRestBackend
        .map_reply(&body("empty"), 5, 0)
        .unwrap()
        .is_empty());
    assert!(SearxngRestBackend
        .map_reply(&body("malformed"), 5, 0)
        .is_err());
    let body = json!({"results":[{"title":"unlinked"},{"url":" "},{"url":"https://a.example", "content":"é".repeat(900), "publishedDate":"invalid"},{"url":"https://b.example"}]});
    let mapped = SearxngRestBackend.map_reply(&body, 1, 0).unwrap();
    assert_eq!(mapped.len(), 1);
    assert_eq!(mapped[0].excerpt, "é".repeat(EXCERPT_MAX_CHARS));
    assert_eq!(mapped[0].published_at, None);
}

#[test]
fn manifest_refuses_fixed_urls_basic_auth_and_unknown_fields() {
    let base = serde_json::to_value(manifest()).unwrap();
    for (field, value) in [
        ("url", json!("https://private.invalid")),
        ("unknown", json!(true)),
    ] {
        let mut doc = base.clone();
        doc["transport"][field] = value;
        assert!(crate::manifest::ingest_value(doc).is_err());
    }
    let mut doc = base;
    doc["credential_bindings"][0]["prefix"] = json!("Basic ");
    assert!(crate::manifest::ingest_value(doc).is_err());
}
