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
        .unwrap_or_else(|| panic!("missing recorded Kagi reply {name}"));
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
    let source = include_str!("../../../../../../catalog/kagi_rest.jsonc");
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

fn skip(failed: CapabilityFailure) -> CapabilitySkip {
    CapabilitySkip {
        provider: "kagi",
        reason: CapabilitySkipReason::Capability,
        failed,
    }
}

#[test]
fn vendor_args_send_the_query_limit_sites_and_after_day() {
    let prepared = KagiRestBackend
        .prepare(
            &query(
                "steve jobs",
                &["wikipedia.org", "apple.com"],
                Some(Recency::Week),
            ),
            NOW,
        )
        .unwrap();
    assert_eq!(
        prepared.vendor_args,
        json!({
            "query": "steve jobs",
            "limit": 5,
            "lens": {"sites_included": ["wikipedia.org", "apple.com"]},
            "filters": {"after": "2026-09-21"}
        }),
        "domains travel in lens.sites_included and recency in filters.after"
    );
    assert_eq!(
        prepared.query.query, "steve jobs",
        "native filters add nothing to the query text"
    );
    let bare = KagiRestBackend
        .prepare(&query("steve jobs", &[], None), NOW)
        .unwrap();
    assert_eq!(
        bare.vendor_args,
        json!({"query": "steve jobs", "limit": 5}),
        "no lens or filters object is sent unless the caller asked for a filter"
    );
    for (recency, day) in [
        (Recency::Day, "2026-09-27"),
        (Recency::Week, "2026-09-21"),
        (Recency::Month, "2026-08-29"),
        (Recency::Year, "2025-09-28"),
    ] {
        assert_eq!(
            KagiRestBackend
                .prepare(&query("news", &[], Some(recency)), NOW)
                .unwrap()
                .vendor_args["filters"],
            json!({"after": day}),
            "{recency:?}"
        );
    }
}

#[test]
fn the_shipped_manifest_pins_kagis_bearer_post_to_api_v1_search() {
    let manifest = shipped_manifest();
    assert_eq!(manifest.key, KagiRestBackend.app_key());
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://kagi.com");
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
    assert_eq!(search.name, KagiRestBackend.action());
    assert_eq!(search.risk, Risk::Read);
    let http = search.http.as_ref().unwrap();
    assert_eq!(
        (http.method, http.path.as_str()),
        (HttpMethod::Post, "/api/v1/search")
    );
    assert_eq!(
        http.request_constants.as_ref().unwrap()["workflow"],
        "search",
        "only web results are asked for"
    );
    let properties = &http.args_schema["properties"];
    assert_eq!(
        (
            &properties["limit"]["minimum"],
            &properties["limit"]["maximum"]
        ),
        (&json!(1), &json!(20))
    );
}

/// Every argument the backend can send is declared by the reviewed schema,
/// at the top level and inside `lens` and `filters`, and within its bounds.
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
    let domains: Vec<String> = (0..MAX_INCLUDE_DOMAINS)
        .map(|index| format!("d{index}.example"))
        .collect();
    let domains: Vec<&str> = domains.iter().map(String::as_str).collect();
    for recency in [None, Some(Recency::Day), Some(Recency::Year)] {
        for domains in [&[][..], &["a.example"][..], &domains[..]] {
            let mut search = query(&"q".repeat(MAX_QUERY_CHARS), domains, recency);
            search.max_results = MAX_RESULTS_LIMIT;
            let prepared = KagiRestBackend.prepare(&search, NOW).unwrap();
            let args = prepared.vendor_args.as_object().unwrap();
            for (key, value) in args {
                let declared = properties
                    .get(key)
                    .unwrap_or_else(|| panic!("{key} is not declared"));
                if let Some(nested) = value.as_object() {
                    assert_eq!(declared["additionalProperties"], false, "{key}");
                    for inner in nested.keys() {
                        assert!(
                            declared["properties"].get(inner).is_some(),
                            "{key}.{inner} is not declared"
                        );
                    }
                }
            }
            let text = args["query"].as_str().unwrap().chars().count() as u64;
            assert!(text <= properties["query"]["maxLength"].as_u64().unwrap());
            let limit = args["limit"].as_u64().unwrap();
            assert!(limit >= properties["limit"]["minimum"].as_u64().unwrap());
            assert!(limit <= properties["limit"]["maximum"].as_u64().unwrap());
            if let Some(lens) = args.get("lens") {
                let sites = lens["sites_included"].as_array().unwrap();
                let bounds = &properties["lens"]["properties"]["sites_included"];
                assert!(sites.len() as u64 >= bounds["minItems"].as_u64().unwrap());
                assert!(sites.len() as u64 <= bounds["maxItems"].as_u64().unwrap());
            }
            if let Some(filters) = args.get("filters") {
                let after = filters["after"].as_str().unwrap();
                assert_eq!(after.len(), 10, "{after}");
                assert!(after
                    .chars()
                    .enumerate()
                    .all(|(index, c)| if index == 4 || index == 7 {
                        c == '-'
                    } else {
                        c.is_ascii_digit()
                    }));
            }
        }
    }
}

#[test]
fn a_documented_reply_maps_only_search_results_title_url_snippet_and_time() {
    let results = KagiRestBackend
        .map_reply(&recorded_body("success"), 5, NOW)
        .unwrap();
    assert_eq!(
        results,
        vec![
            WebSearchResult {
                url: "https://en.wikipedia.org/wiki/Steve_Jobs".into(),
                title: "Steve Jobs - Wikipedia".into(),
                excerpt: "Steven Paul Jobs (February 24, 1955 – October 5, 2011) was an American businessman, inventor, and investor best known for co-founding the ...".into(),
                published_at: Some("2012-02-23T07:00:59.000Z".into()),
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
            WebSearchResult {
                url: "https://www.apple.com/stevejobs/".into(),
                title: "Remembering Steve Jobs - Apple".into(),
                excerpt: "Apple has lost a visionary and creative genius, and the world has lost an amazing human being.".into(),
                published_at: None,
                fetched_at: "2026-09-28T12:00:00.000Z".into(),
            },
        ],
        "only data.search items are results; direct_answer, infobox and related_search are dropped"
    );
    assert_eq!(
        KagiRestBackend
            .map_reply(&recorded_body("success"), 1, NOW)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn an_empty_search_bucket_or_an_answer_without_one_is_an_empty_success() {
    for record in ["empty", "answer_only"] {
        assert_eq!(
            KagiRestBackend.map_reply(&recorded_body(record), 5, NOW),
            Ok(Vec::new()),
            "{record}: an answer bucket is never served as a result"
        );
    }
}

#[test]
fn a_reply_without_a_data_object_is_a_shape_error() {
    for record in [
        "malformed",
        "bad_request",
        "unauthorized",
        "forbidden",
        "rate_limited_no_retry",
        "server_error",
    ] {
        assert!(
            KagiRestBackend
                .map_reply(&recorded_body(record), 5, NOW)
                .is_err(),
            "{record}"
        );
    }
    assert!(
        KagiRestBackend
            .map_reply(
                &json!({"data": {"search": {"url": "https://a.example/"}}}),
                5,
                NOW
            )
            .is_err(),
        "a search bucket that is not an array is a shape error"
    );
}

#[test]
fn mapping_bounds_excerpts_and_reads_only_valid_times() {
    let reply = json!({"data": {"search": [
        {"url": "https://a.example/", "title": " A ", "snippet": "é".repeat(700), "time": "2024-02-29T08:30:00+02:00"},
        {"title": "no url is dropped", "snippet": "x"},
        {"url": "https://b.example/", "title": "B", "time": "not a date"},
        {"url": "https://c.example/", "title": "C", "time": null}
    ]}});
    let results = KagiRestBackend.map_reply(&reply, 10, 0).unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].title, "A");
    assert_eq!(results[0].excerpt.chars().count(), EXCERPT_MAX_CHARS);
    assert_eq!(
        results[0].published_at.as_deref(),
        Some("2024-02-29T06:30:00.000Z"),
        "an offset time is normalized to UTC"
    );
    assert_eq!(
        (results[1].excerpt.as_str(), &results[1].published_at),
        ("", &None),
        "a missing snippet is an empty excerpt and an unparseable time is dropped"
    );
    assert_eq!(results[2].published_at, None);
    assert_eq!(results[0].fetched_at, "1970-01-01T00:00:00.000Z");
}

/// Kagi documents no query limit, so the tool's 500 characters is the
/// declared envelope: the limit is served and one more character skips.
/// The tool itself never sends a longer query or more than 20 domains, so
/// these queries are built directly rather than parsed from tool arguments.
#[test]
fn capability_skips_a_query_or_domain_list_beyond_the_declared_envelope() {
    assert!(KagiRestBackend
        .prepare(&query(&"é".repeat(MAX_QUERY_CHARS), &[], None), NOW)
        .is_ok());
    assert_eq!(
        KagiRestBackend.prepare(&query(&"é".repeat(MAX_QUERY_CHARS + 1), &[], None), NOW),
        Err(skip(CapabilityFailure::Length)),
        "a query over the declared 500-character envelope must skip"
    );
    let too_many: Vec<String> = (0..=MAX_INCLUDE_DOMAINS)
        .map(|index| format!("d{index}.example"))
        .collect();
    let too_many: Vec<&str> = too_many.iter().map(String::as_str).collect();
    assert_eq!(
        KagiRestBackend.prepare(&query("q", &too_many, None), NOW),
        Err(skip(CapabilityFailure::DomainFilter)),
        "more domains than declared must skip"
    );
    assert!(KagiRestBackend
        .prepare(&query("q", &too_many[..MAX_INCLUDE_DOMAINS], None), NOW)
        .is_ok());
}

#[test]
fn capability_clamps_limit_to_20_and_accepts_every_recency() {
    let mut many = query("news", &[], None);
    many.max_results = 60;
    let prepared = KagiRestBackend.prepare(&many, NOW).unwrap();
    assert_eq!(
        (prepared.query.max_results, &prepared.vendor_args["limit"]),
        (KAGI_MAX_LIMIT, &json!(20)),
        "limit is clamped to the reviewed maximum of 20"
    );
    assert_eq!(
        KagiRestBackend.capability().recency.supported,
        ALL_RECENCIES
    );
    for recency in ALL_RECENCIES {
        assert!(
            KagiRestBackend
                .prepare(&query("news", &[], Some(*recency)), NOW)
                .is_ok(),
            "{recency:?}"
        );
    }
}
