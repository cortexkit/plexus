use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

use super::*;
use crate::web_search::backend::ReplyShapeError;
use crate::web_search::{ExaRestBackend, WebSearchBackend, WebSearchResult};

const NOW: i64 = 1_790_596_800_000; // 2026-09-28T12:00:00Z

struct FixtureBackend {
    name: &'static str,
    capability: WebSearchCapability,
    mappings: AtomicUsize,
}

impl FixtureBackend {
    fn new(name: &'static str, max_length: usize) -> Self {
        Self {
            name,
            capability: WebSearchCapability {
                query_length: QueryLengthLimit {
                    max: max_length,
                    unit: QueryLengthUnit::UnicodeScalars,
                },
                max_results: 20,
                domains: DomainCapability {
                    max_domains: 20,
                    encoding: FilterEncoding::Native,
                },
                recency: RecencyCapability {
                    supported: ALL_RECENCIES,
                    encoding: FilterEncoding::Native,
                },
            },
            mappings: AtomicUsize::new(0),
        }
    }
}

impl WebSearchBackend for FixtureBackend {
    fn name(&self) -> &'static str {
        self.name
    }
    fn app_key(&self) -> &'static str {
        "fixture_rest"
    }
    fn action(&self) -> &'static str {
        "search"
    }
    fn capability(&self) -> WebSearchCapability {
        self.capability
    }
    fn vendor_args(&self, query: &WebSearchQuery, _: i64) -> Value {
        self.mappings.fetch_add(1, Ordering::SeqCst);
        json!({"query":query.query, "count":query.max_results, "domains":query.include_domains,
            "recency_days":query.recency.map(Recency::days)})
    }
    fn map_reply(
        &self,
        reply: &Value,
        max_results: usize,
        fetched_at_ms: i64,
    ) -> Result<Vec<WebSearchResult>, ReplyShapeError> {
        ExaRestBackend.map_reply(reply, max_results, fetched_at_ms)
    }
}

fn query(text: &str, domains: &[&str], recency: Option<Recency>) -> WebSearchQuery {
    WebSearchQuery {
        query: text.into(),
        max_results: 20,
        include_domains: domains.iter().map(|domain| (*domain).into()).collect(),
        recency,
    }
}

fn assert_skip(backend: &FixtureBackend, query: &WebSearchQuery, failed: CapabilityFailure) {
    let skip = backend
        .prepare(query, NOW)
        .expect_err("unsupported capability must skip before vendor mapping");
    assert_eq!(
        skip,
        CapabilitySkip {
            provider: backend.name,
            reason: CapabilitySkipReason::Capability,
            failed
        }
    );
    assert_eq!(
        backend.mappings.load(Ordering::SeqCst),
        0,
        "capability rejection must precede vendor mapping"
    );
    let encoded = serde_json::to_value(skip).unwrap();
    assert_eq!(encoded["provider"], backend.name);
    assert_eq!(encoded["reason"], "capability");
    assert_eq!(encoded.as_object().unwrap().len(), 3);
}

#[test]
fn final_query_length_includes_domain_and_recency_operators() {
    // DeepSeek's documented 128-character envelope, without a live provider.
    let mut backend = FixtureBackend::new("deepseek", 128);
    backend.capability.domains.encoding = FilterEncoding::QueryOperators;
    backend.capability.recency.encoding = FilterEncoding::QueryOperators;
    assert_skip(
        &backend,
        &query(&"x".repeat(200), &[], None),
        CapabilityFailure::Length,
    );
    assert_skip(
        &backend,
        &query(&"x".repeat(100), &["a.com", "b.com", "c.com"], None),
        CapabilityFailure::Length,
    );
    assert_skip(
        &backend,
        &query(&"x".repeat(115), &[], Some(Recency::Week)),
        CapabilityFailure::Length,
    );
    // The exact composed boundary passes, while one extra character skips.
    let composed = "((news) (site:a.com OR site:b.com)) after:2026-09-21";
    backend.capability.query_length.max = composed.chars().count() - 1;
    assert_skip(
        &backend,
        &query("news", &["a.com", "b.com"], Some(Recency::Week)),
        CapabilityFailure::Length,
    );
    backend.capability.query_length.max += 1;
    let prepared = backend
        .prepare(
            &query("news", &["a.com", "b.com"], Some(Recency::Week)),
            NOW,
        )
        .unwrap();
    assert_eq!(
        prepared.vendor_args["query"], composed,
        "final vendor query must retain both kinds of filter"
    );
    assert_eq!(backend.mappings.load(Ordering::SeqCst), 1);
}

#[test]
fn domain_capacity_rejects_zero_or_one_domain_overflow() {
    let mut backend = FixtureBackend::new("jina", 500);
    backend.capability.domains.max_domains = 1;
    assert_skip(
        &backend,
        &query("news", &["a.com", "b.com"], None),
        CapabilityFailure::DomainFilter,
    );
    assert_eq!(
        serde_json::to_value(
            backend
                .prepare(&query("news", &["a.com", "b.com"], None), NOW)
                .unwrap_err()
        )
        .unwrap()["failed"],
        "domain_filter"
    );
    let prepared = backend
        .prepare(&query("news", &["a.com"], None), NOW)
        .unwrap();
    assert_eq!(prepared.vendor_args["domains"], json!(["a.com"]));

    let mut unsupported = FixtureBackend::new("zai", 500);
    unsupported.capability.domains.max_domains = 0;
    assert_skip(
        &unsupported,
        &query("news", &["a.com"], None),
        CapabilityFailure::DomainFilter,
    );
    assert!(unsupported.prepare(&query("news", &[], None), NOW).is_ok());
}

#[test]
fn unsupported_recency_is_recorded_instead_of_dropped() {
    let mut backend = FixtureBackend::new("fixture", 500);
    backend.capability.recency.supported = &[Recency::Day];
    for recency in [Recency::Week, Recency::Month, Recency::Year] {
        assert_skip(
            &backend,
            &query("news", &[], Some(recency)),
            CapabilityFailure::Recency,
        );
    }
    let skip = backend
        .prepare(&query("news", &[], Some(Recency::Week)), NOW)
        .unwrap_err();
    assert_eq!(serde_json::to_value(skip).unwrap()["failed"], "recency");
    assert_eq!(
        backend
            .prepare(&query("news", &[], Some(Recency::Day)), NOW)
            .unwrap()
            .vendor_args["recency_days"],
        1
    );
    backend.capability.recency.supported = &[];
    assert!(backend.prepare(&query("news", &[], None), NOW).is_ok());
}

#[test]
fn operator_composition_preserves_every_requested_filter() {
    let mut backend = FixtureBackend::new("fixture", 500);
    backend.capability.domains.encoding = FilterEncoding::QueryOperators;
    backend.capability.recency.encoding = FilterEncoding::QueryOperators;
    let original = query(
        "news OR weather",
        &["a.com", "b.com", "c.com"],
        Some(Recency::Week),
    );
    let prepared = backend.prepare(&original, NOW).unwrap();
    assert_eq!(
        prepared.vendor_args["query"],
        "((news OR weather) (site:a.com OR site:b.com OR site:c.com)) after:2026-09-21",
        "composition must preserve every domain and the recency bound"
    );
    assert_eq!(prepared.query.include_domains, original.include_domains);
    assert_eq!(prepared.query.recency, original.recency);
    assert_eq!(original.query, "news OR weather");
    assert_eq!(
        backend
            .prepare(&query("bare", &[], None), NOW)
            .unwrap()
            .vendor_args["query"],
        "bare"
    );
}

#[test]
fn vendor_length_units_are_not_interchangeable() {
    let mut backend = FixtureBackend::new("fixture", 2);
    assert!(backend.prepare(&query("é🦀", &[], None), NOW).is_ok());
    backend.mappings.store(0, Ordering::SeqCst);
    backend.capability.query_length.unit = QueryLengthUnit::Utf8Bytes;
    assert_skip(
        &backend,
        &query("é🦀", &[], None),
        CapabilityFailure::Length,
    );
    backend.capability.query_length.max = 6;
    assert!(backend.prepare(&query("é🦀", &[], None), NOW).is_ok());
    backend.mappings.store(0, Ordering::SeqCst);
    backend.capability.query_length.unit = QueryLengthUnit::Utf16CodeUnits;
    backend.capability.query_length.max = 2;
    assert_skip(
        &backend,
        &query("é🦀", &[], None),
        CapabilityFailure::Length,
    );
    backend.capability.query_length.max = 3;
    assert!(backend.prepare(&query("é🦀", &[], None), NOW).is_ok());
}

#[test]
fn result_count_is_clamped_for_request_and_reply() {
    let mut backend = FixtureBackend::new("fixture", 500);
    backend.capability.max_results = 3;
    let prepared = backend.prepare(&query("news", &[], None), NOW).unwrap();
    assert_eq!(
        prepared.vendor_args["count"], 3,
        "provider result maximum must clamp vendor arguments"
    );
    assert_eq!(prepared.query.max_results, 3);
    let reply = json!({"results": [{"url":"https://a.com"}, {"url":"https://b.com"}, {"url":"https://c.com"}, {"url":"https://d.com"}]});
    assert_eq!(
        backend
            .map_reply(&reply, usize::from(prepared.query.max_results), NOW)
            .unwrap()
            .len(),
        3
    );
    let mut smaller = query("news", &[], None);
    smaller.max_results = 1;
    assert_eq!(
        backend.prepare(&smaller, NOW).unwrap().vendor_args["count"],
        1
    );
}

#[test]
fn exa_preparation_preserves_legacy_vendor_arguments() {
    let domains: Vec<String> = (0..20).map(|index| format!("domain{index}.com")).collect();
    for recency in [
        None,
        Some(Recency::Day),
        Some(Recency::Week),
        Some(Recency::Month),
        Some(Recency::Year),
    ] {
        let query = WebSearchQuery {
            query: "é".repeat(500),
            max_results: 20,
            include_domains: domains.clone(),
            recency,
        };
        let prepared = ExaRestBackend.prepare(&query, NOW).unwrap();
        assert_eq!(prepared.query, query);
        assert_eq!(
            prepared.vendor_args,
            ExaRestBackend.vendor_args(&query, NOW)
        );
    }
}
