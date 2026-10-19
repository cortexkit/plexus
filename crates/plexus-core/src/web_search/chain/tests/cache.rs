//! The chain-mode result cache: one key for whichever provider served, and a
//! hit only for a caller who could be served by that provider right now. The
//! hit charges the provider's rate buckets last, so a hit that turns into a
//! miss costs no more than a plain miss.

use super::*;
use crate::storage::web_search_store::WebSearchLimits;
use crate::transport::MockResponse;
use std::collections::HashMap;
use std::sync::atomic::AtomicI64;

/// A SearXNG stand-in whose instance address is looked up per connection,
/// the way the real backend reads it from the connection record.
struct InstanceBackend {
    instances: HashMap<&'static str, &'static str>,
}

impl WebSearchBackend for InstanceBackend {
    fn name(&self) -> &'static str {
        "searxng"
    }
    fn app_key(&self) -> &'static str {
        "searxng_rest"
    }
    fn action(&self) -> &'static str {
        "search"
    }
    fn capability(&self) -> capability::WebSearchCapability {
        ExaRestBackend.capability()
    }
    fn vendor_args(&self, query: &WebSearchQuery, now_ms: i64) -> Value {
        ExaRestBackend.vendor_args(query, now_ms)
    }
    fn map_reply(
        &self,
        reply: &Value,
        max_results: usize,
        at: i64,
    ) -> Result<Vec<WebSearchResult>, backend::ReplyShapeError> {
        ExaRestBackend.map_reply(reply, max_results, at)
    }
    fn instance_url(&self, connection: &ConnectionRecord) -> Option<String> {
        self.instances
            .get(connection.connection_id.as_str())
            .map(|address| address.to_string())
    }
}

fn cache_service(now: &Arc<AtomicI64>) -> WebSearchService {
    let clock = now.clone();
    let mut service = WebSearchService::with_clock(
        Arc::new(ExaRestBackend),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    for name in ["tavily", "brave"] {
        service = service.with_chain_backend(Arc::new(TestBackend {
            name,
            preparations: Arc::new(AtomicUsize::new(0)),
        }));
    }
    service.with_chain_backend(Arc::new(InstanceBackend {
        instances: [
            ("sx-a", "https://search-a.example/"),
            // The same instance as sx-a, spelled differently.
            ("sx-a-again", "HTTPS://Search-A.example:443"),
            ("sx-b", "https://search-b.example/"),
        ]
        .into(),
    }))
}

fn search_as(
    service: &WebSearchService,
    engine: &Engine,
    caller: &str,
    query: &str,
) -> Result<WebSearchResponse, WebSearchRefusal> {
    service.search(
        engine,
        caller,
        json!({ "query": query }).as_object().unwrap(),
    )
}

fn limit(engine: &Engine, provider: &str, per_caller: u32, per_backend: u32) {
    engine
        .store()
        .set_web_search_limits(
            provider,
            WebSearchLimits {
                per_caller_per_minute: per_caller,
                per_backend_per_minute: per_backend,
            },
        )
        .unwrap();
}

fn one_result() -> MockResponse {
    MockResponse::Success(
        json!({"results":[{"url":"https://example.org/", "title":"Report", "text":"Weather"}]}),
    )
}

fn connection_ids(transport: &MockTransport) -> Vec<String> {
    transport
        .requests()
        .into_iter()
        .map(|request| request.connection_id)
        .collect()
}

fn web_search_rows(engine: &Engine, principal: &str) -> Vec<crate::storage::AuditRow> {
    engine
        .store()
        .list_audit(principal)
        .unwrap()
        .into_iter()
        .filter(|row| row.gate.as_deref() == Some("web_search"))
        .collect()
}

fn summary(row: &crate::storage::AuditRow) -> Value {
    serde_json::from_str(row.args_redaction_summary.as_deref().unwrap()).unwrap()
}

#[test]
fn searxng_instances_do_not_share_entries() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("cache-searxng");
    add_connection(&engine, "sx-a", "searxng", Some("direct"));
    add_connection(&engine, "sx-a-again", "searxng", Some("third"));
    add_connection(&engine, "sx-b", "searxng", Some("other"));
    order(&engine, &["searxng"]);
    // One search per caller per minute: a hit that charged before its
    // instance check would leave the caller nothing for the walk.
    limit(&engine, "searxng", 1, 3);
    transport.set_response(one_result());
    let now = Arc::new(AtomicI64::new(NOW));
    let service = cache_service(&now);

    let first = search_as(&service, &engine, "direct", "weather report").unwrap();
    assert_eq!((first.backend.as_str(), first.cached), ("searxng", false));
    let same_instance = search_as(&service, &engine, "third", "weather report").unwrap();
    assert_eq!(
        (same_instance.backend.as_str(), same_instance.cached),
        ("searxng", true),
        "two spellings of one instance address share entries"
    );
    let other_instance = search_as(&service, &engine, "other", "weather report").unwrap();
    assert!(
        !other_instance.cached,
        "an entry from one SearXNG instance must not answer a caller on another"
    );
    assert_eq!(connection_ids(&transport), ["sx-a", "sx-b"]);

    // The instance address and its digest stay out of the audit trail.
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        b"https://search-a.example",
    ));
    for principal in ["direct", "third", "other"] {
        let rows = serde_json::to_string(&engine.store().list_audit(principal).unwrap()).unwrap();
        assert!(!rows.contains("search-a.example") && !rows.contains("search-b.example"));
        assert!(!rows.contains(&digest));
    }
}

#[test]
fn a_searxng_connection_without_an_instance_is_never_cached() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("cache-searxng-none");
    add_connection(&engine, "sx-unknown", "searxng", Some("direct"));
    order(&engine, &["searxng"]);
    transport.set_response(one_result());
    let service = cache_service(&Arc::new(AtomicI64::new(NOW)));
    for _ in 0..2 {
        assert!(
            !search_as(&service, &engine, "direct", "weather report")
                .unwrap()
                .cached
        );
    }
    assert_eq!(transport.requests().len(), 2);
}

#[test]
fn failed_cached_read_policy_then_walk_charges_no_more_than_a_miss() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("cache-read-policy");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    order(&engine, &["exa", "tavily"]);
    limit(&engine, "exa", 2, 2);
    limit(&engine, "tavily", 2, 2);
    transport.set_response(one_result());
    let service = cache_service(&Arc::new(AtomicI64::new(NOW)));
    assert_eq!(
        search_as(&service, &engine, "direct", "weather report")
            .unwrap()
            .backend,
        "exa"
    );

    engine
        .store()
        .set_policy("direct", "exa", "search", "block", None)
        .unwrap();
    let walked = search_as(&service, &engine, "direct", "weather report").unwrap();
    assert_eq!((walked.backend.as_str(), walked.cached), ("tavily", false));
    assert_eq!(connection_ids(&transport), ["exa", "tavily"]);

    // The refused hit spent none of Exa's tokens: one is still left for a
    // new query once policy allows Exa again.
    engine
        .store()
        .set_policy("direct", "exa", "search", "allow", None)
        .unwrap();
    assert_eq!(
        search_as(&service, &engine, "direct", "another report")
            .unwrap()
            .backend,
        "exa"
    );
    // The walk charged Tavily exactly once, as a plain miss would: one of
    // its two tokens is left.
    let key = CallerKey {
        principal: "direct".into(),
        agent_id: None,
    };
    assert!(service
        .limiter
        .try_acquire(
            "tavily",
            &key,
            WebSearchLimits {
                per_caller_per_minute: 2,
                per_backend_per_minute: 2,
            },
            NOW
        )
        .is_ok());
    assert!(service
        .limiter
        .try_acquire(
            "tavily",
            &key,
            WebSearchLimits {
                per_caller_per_minute: 2,
                per_backend_per_minute: 2,
            },
            NOW
        )
        .is_err());
}

#[test]
fn ask_first_on_the_serving_provider_makes_the_hit_a_miss() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("cache-ask-first");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    order(&engine, &["exa", "tavily"]);
    transport.set_response(one_result());
    let service = cache_service(&Arc::new(AtomicI64::new(NOW)));
    assert!(
        !search_as(&service, &engine, "direct", "weather report")
            .unwrap()
            .cached
    );
    engine
        .store()
        .set_policy("direct", "exa", "search", "ask_first", None)
        .unwrap();
    let walked = search_as(&service, &engine, "direct", "weather report").unwrap();
    assert_eq!((walked.backend.as_str(), walked.cached), ("tavily", false));
    assert_eq!(connection_ids(&transport), ["exa", "tavily"]);
    let rows = web_search_rows(&engine, "direct");
    assert_eq!(
        summary(rows.last().unwrap()),
        json!({"served_by":"tavily","skipped":[{"provider":"exa","reason":"policy"}]})
    );
}

#[test]
fn quarantined_or_unusable_serving_connection_makes_the_hit_a_miss() {
    for scenario in ["quarantined", "unusable"] {
        let (engine, transport, path) = super::super::super::tests::granted_exa_engine_with_path(
            &format!("cache-standing-{scenario}"),
        );
        let sql = rusqlite::Connection::open(&*path).unwrap();
        order(&engine, &["exa"]);
        transport.set_response(one_result());
        let service = cache_service(&Arc::new(AtomicI64::new(NOW)));
        assert!(search_as(&service, &engine, "direct", "weather report").is_ok());
        let reason = if scenario == "quarantined" {
            sql.execute(
                "UPDATE catalog_actions SET status = 'quarantined' WHERE connection_id = 'exa'",
                [],
            )
            .unwrap();
            SkipReason::Quarantined
        } else {
            engine
                .store()
                .set_connection_health("direct", "exa", "degraded", &json!({"healthy":false}))
                .unwrap();
            SkipReason::ConnectionUnusable
        };
        assert_eq!(
            search_as(&service, &engine, "direct", "weather report"),
            Err(unavailable(&[("exa", reason)])),
            "{scenario}"
        );
        assert_eq!(transport.requests().len(), 1);
    }
}

#[test]
fn provider_removed_from_the_order_makes_the_hit_a_miss() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("cache-order");
    add_connection(&engine, "brave", "brave", Some("direct"));
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    order(&engine, &["brave", "tavily"]);
    transport.set_response(one_result());
    let service = cache_service(&Arc::new(AtomicI64::new(NOW)));
    assert_eq!(
        search_as(&service, &engine, "direct", "weather report")
            .unwrap()
            .backend,
        "brave"
    );
    let hit = search_as(&service, &engine, "direct", "weather report").unwrap();
    assert_eq!((hit.backend.as_str(), hit.cached), ("brave", true));

    order(&engine, &["tavily"]);
    let walked = search_as(&service, &engine, "direct", "weather report").unwrap();
    assert_eq!((walked.backend.as_str(), walked.cached), ("tavily", false));
    assert_eq!(connection_ids(&transport), ["brave", "tavily"]);
}

#[test]
fn a_tavily_only_caller_on_an_exa_entry_misses_and_is_served_by_tavily() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("cache-tavily-only");
    add_connection(&engine, "tavily", "tavily", Some("other"));
    order(&engine, &["exa", "tavily"]);
    transport.set_response(one_result());
    let service = cache_service(&Arc::new(AtomicI64::new(NOW)));
    assert_eq!(
        search_as(&service, &engine, "direct", "weather report")
            .unwrap()
            .backend,
        "exa"
    );
    let walked = search_as(&service, &engine, "other", "weather report").unwrap();
    assert_eq!((walked.backend.as_str(), walked.cached), ("tavily", false));
    assert_eq!(connection_ids(&transport), ["exa", "tavily"]);
}

#[test]
fn an_ambiguous_caller_misses_the_hit() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("cache-ambiguous");
    order(&engine, &["exa"]);
    transport.set_response(one_result());
    let service = cache_service(&Arc::new(AtomicI64::new(NOW)));
    assert!(search_as(&service, &engine, "direct", "weather report").is_ok());
    add_connection(&engine, "exa-two", "exa", Some("direct"));
    assert_eq!(
        search_as(&service, &engine, "direct", "weather report"),
        Err(unavailable(&[("exa", SkipReason::Ambiguous)]))
    );
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn a_hit_reports_its_provider_ignores_cooldown_and_allowance_and_audits_its_connection() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("cache-hit");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    order(&engine, &["exa", "tavily"]);
    engine
        .store()
        .set_web_search_allowance("tavily", 1)
        .unwrap();
    transport.set_response_sequence_for_method(
        "search",
        "",
        vec![
            MockResponse::VendorError {
                code: "http_503".into(),
                message: "unavailable".into(),
            },
            one_result(),
        ],
    );
    let service = cache_service(&Arc::new(AtomicI64::new(NOW)));
    let served = search_as(&service, &engine, "direct", "weather report").unwrap();
    assert_eq!((served.backend.as_str(), served.cached), ("tavily", false));
    assert_eq!(
        engine
            .store()
            .web_search_allowance_used("tavily", "direct", NOW)
            .unwrap(),
        1
    );
    // Tavily's allowance is used up and its connection is cooling down, yet
    // neither stops a cached read.
    service
        .chain_cooldowns
        .lock()
        .unwrap()
        .insert("tavily".into(), NOW + 60_000);
    let hit = search_as(&service, &engine, "direct", "weather report").unwrap();
    assert_eq!(
        hit,
        WebSearchResponse {
            results: served.results,
            backend: "tavily".into(),
            cached: true,
        }
    );
    assert_eq!(connection_ids(&transport), ["exa", "tavily"]);
    assert_eq!(
        engine
            .store()
            .web_search_allowance_used("tavily", "direct", NOW)
            .unwrap(),
        1,
        "a cache hit counts no allowance"
    );
    let rows = web_search_rows(&engine, "direct");
    let row = rows
        .iter()
        .find(|row| row.reason_code == "web_search_cache_hit")
        .unwrap();
    assert_eq!(row.connection_id.as_deref(), Some("tavily"));
    assert_eq!(row.app_key.as_deref(), Some("tavily_rest"));
    assert_eq!(row.outcome.as_deref(), Some("cached"));
    assert_eq!(summary(row), json!({"served_by":"tavily","skipped":[]}));
}

#[test]
fn a_rate_refused_hit_is_a_miss_and_the_walk_charges_once() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("cache-rate");
    order(&engine, &["exa"]);
    limit(&engine, "exa", 1, 10);
    transport.set_response(one_result());
    let now = Arc::new(AtomicI64::new(NOW));
    let service = cache_service(&now);
    assert!(search_as(&service, &engine, "direct", "weather report").is_ok());
    assert_eq!(
        search_as(&service, &engine, "direct", "weather report"),
        Err(WebSearchRefusal::RateLimited {
            retry_after_ms: 60_000
        })
    );
    // Neither the refused hit nor the refused walk took a token: exactly one
    // refills in a minute, and the hit spends it.
    now.store(NOW + 60_000, Ordering::SeqCst);
    assert!(
        search_as(&service, &engine, "direct", "weather report")
            .unwrap()
            .cached
    );
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn each_attempt_writes_its_own_row_pair_and_the_call_row_names_the_right_connection() {
    let rows_for = |engine: &Engine, connection: &str| {
        engine
            .store()
            .list_audit("direct")
            .unwrap()
            .into_iter()
            .filter(|row| {
                row.gate.as_deref() != Some("web_search")
                    && row.connection_id.as_deref() == Some(connection)
            })
            .count()
    };

    // Exa fails and Tavily serves: two governed pairs, the call row on Tavily.
    let (engine, transport) = super::super::super::tests::granted_exa_engine("cache-audit-served");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    order(&engine, &["exa", "tavily"]);
    transport.set_response_sequence_for_method(
        "search",
        "",
        vec![
            MockResponse::VendorError {
                code: "http_503".into(),
                message: "unavailable".into(),
            },
            one_result(),
        ],
    );
    let service = cache_service(&Arc::new(AtomicI64::new(NOW)));
    assert!(search_as(&service, &engine, "direct", "weather report").is_ok());
    assert_eq!(
        (rows_for(&engine, "exa"), rows_for(&engine, "tavily")),
        (2, 2)
    );
    let row = web_search_rows(&engine, "direct").pop().unwrap();
    assert_eq!(row.connection_id.as_deref(), Some("tavily"));
    assert_eq!(row.principal, "direct");
    assert_eq!(
        (row.risk.as_deref(), row.severity.as_deref()),
        (Some("read"), Some("S1"))
    );
    assert_eq!(
        summary(&row),
        json!({"served_by":"tavily","skipped":[{"provider":"exa","reason":"unavailable"}]})
    );

    // Both fail: the call row takes the last attempted provider's connection.
    let (engine, transport) = super::super::super::tests::granted_exa_engine("cache-audit-failed");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    order(&engine, &["exa", "tavily"]);
    transport.set_response(MockResponse::VendorError {
        code: "http_503".into(),
        message: "unavailable".into(),
    });
    let service = cache_service(&Arc::new(AtomicI64::new(NOW)));
    assert!(search_as(&service, &engine, "direct", "weather report").is_err());
    assert_eq!(
        (rows_for(&engine, "exa"), rows_for(&engine, "tavily")),
        (2, 2)
    );
    let row = web_search_rows(&engine, "direct").pop().unwrap();
    assert_eq!(row.connection_id.as_deref(), Some("tavily"));
    assert_eq!(row.app_key.as_deref(), Some("tavily_rest"));
    assert_eq!(
        summary(&row),
        json!({"served_by":null,"skipped":[
            {"provider":"exa","reason":"unavailable"},
            {"provider":"tavily","reason":"unavailable"}
        ]})
    );

    // Nothing attempted: the call row is the caller's, with no connection.
    assert_eq!(
        search_as(&service, &engine, "stranger", "weather report"),
        Err(WebSearchRefusal::NotGranted)
    );
    let row = web_search_rows(&engine, "stranger").pop().unwrap();
    assert_eq!(row.principal, "stranger");
    assert_eq!(row.connection_id, None);
    assert_eq!((row.risk.as_deref(), row.severity.as_deref()), (None, None));
}
