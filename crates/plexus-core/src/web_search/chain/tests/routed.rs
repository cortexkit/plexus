//! Provider choice through routing: what plexus offers a router, how it acts
//! on the answer, and what it reports back.

use super::*;
use crate::transport::MockResponse;
use crate::web_search::routing::fake::{FakeMode, FakeRouter};
use crate::web_search::routing::RouteRef;
use std::sync::atomic::AtomicI64;

fn route(provider: &str) -> Value {
    json!({"model": "search", "provider": provider})
}

/// Exa and Tavily services choosing through `router` on a movable clock.
fn routed_service(router: &Arc<FakeRouter>, now: &Arc<AtomicI64>) -> WebSearchService {
    let clock = now.clone();
    WebSearchService::with_clock(
        Arc::new(ExaRestBackend),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    )
    .with_chain_backend(Arc::new(TestBackend {
        name: "tavily",
        preparations: Arc::new(AtomicUsize::new(0)),
    }))
    .with_router(router.clone())
}

fn router(ranking: &[&str]) -> Arc<FakeRouter> {
    Arc::new(FakeRouter::ranked(
        ranking
            .iter()
            .map(|provider| RouteRef::new(*provider, "search"))
            .collect(),
    ))
}

fn hit() -> MockResponse {
    MockResponse::Success(
        json!({"results":[{"url":"https://example.org", "title":"Report", "text":"Weather"}]}),
    )
}

#[test]
fn allowance_left_offers_routes_with_searches_left_and_drops_spent_ones() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("routed-allowance");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    transport.set_response(hit());
    let router = router(&["tavily", "exa"]);
    let service = routed_service(&router, &Arc::new(AtomicI64::new(NOW)));
    engine
        .store()
        .set_web_search_allowance("tavily", 2)
        .unwrap();
    assert_eq!(
        search(&service, &engine, "direct").unwrap().backend,
        "tavily"
    );
    assert_eq!(
        router.params("route.select")[0],
        json!({
            "allowance_left": [route("tavily")],
            "consumer": "plexus.web_search",
            "eligible_routes": [route("exa"), route("tavily")],
            "kind": "search",
            "privacy": "remote_allowed",
            "requirements": {"iq": 75},
        })
    );
    // The second search spends Tavily's allowance; from then on it is not
    // offered at all, so routing cannot choose it.
    service
        .search(
            &engine,
            "direct",
            json!({"query":"second report"}).as_object().unwrap(),
        )
        .unwrap();
    let third = service
        .search(
            &engine,
            "direct",
            json!({"query":"third report"}).as_object().unwrap(),
        )
        .unwrap();
    assert_eq!(third.backend, "exa");
    let selects = router.params("route.select");
    assert_eq!(selects[2]["eligible_routes"], json!([route("exa")]));
    assert_eq!(selects[2]["allowance_left"], json!([]));
    assert_eq!(
        engine
            .store()
            .web_search_allowance_used("tavily", "direct", NOW)
            .unwrap(),
        2
    );
}

#[test]
fn failed_attempt_selects_again_without_the_failed_route() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("routed-failover");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    transport.set_response_sequence_for_method(
        "search",
        "",
        vec![
            MockResponse::VendorError {
                code: "http_503".into(),
                message: "down".into(),
            },
            hit(),
        ],
    );
    let router = router(&["exa", "tavily"]);
    let service = routed_service(&router, &Arc::new(AtomicI64::new(NOW)));
    let response = search(&service, &engine, "direct").unwrap();
    assert_eq!(response.backend, "tavily");
    let selects = router.params("route.select");
    assert_eq!(selects.len(), 2);
    assert_eq!(
        selects[0]["eligible_routes"],
        json!([route("exa"), route("tavily")])
    );
    assert_eq!(selects[1]["eligible_routes"], json!([route("tavily")]));
    assert_eq!(
        router.params("route.report"),
        [
            json!({"decision_id": "dec_000000000000", "outcome": "failed",
                "attempt_outcome": {"status": "unavailable"}}),
            json!({"decision_id": "dec_000000000001", "outcome": "completed",
                "attempt_outcome": {"status": "served"}}),
        ]
    );
    assert_eq!(transport.requests().len(), 2);
}

#[test]
fn zero_results_are_served_and_end_the_walk() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("routed-empty");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    transport.set_response(MockResponse::Success(json!({"results": []})));
    let router = router(&["exa", "tavily"]);
    let service = routed_service(&router, &Arc::new(AtomicI64::new(NOW)));
    let response = search(&service, &engine, "direct").unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("exa", 0)
    );
    assert_eq!(router.params("route.select").len(), 1);
    assert_eq!(
        router.params("route.report"),
        [
            json!({"decision_id": "dec_000000000000", "outcome": "completed",
            "attempt_outcome": {"status": "served_empty"}})
        ]
    );
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn unreachable_routing_refuses_retryably_without_vendor_contact_but_cache_answers() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("routed-unreachable");
    transport.set_response(hit());
    let router = router(&["exa"]);
    let service = routed_service(&router, &Arc::new(AtomicI64::new(NOW)));
    assert!(!search(&service, &engine, "direct").unwrap().cached);
    router.set_mode(FakeMode::Unreachable);
    let calls = router.methods().len();
    let cached = search(&service, &engine, "direct").unwrap();
    assert!(cached.cached, "a cache hit answers while routing is down");
    assert_eq!(
        router.methods().len(),
        calls,
        "a cache hit sends no select or report"
    );
    let refusal = service
        .search(
            &engine,
            "direct",
            json!({"query":"uncached"}).as_object().unwrap(),
        )
        .unwrap_err();
    assert_eq!(refusal, WebSearchRefusal::RoutingUnavailable);
    assert_eq!(
        refusal.to_wire(),
        json!({"error": {
            "code": "backend_unavailable",
            "backend": "routing",
            "message": "web search provider selection is unavailable right now; retry shortly",
        }})
    );
    assert_eq!(transport.requests().len(), 1, "no vendor was contacted");

    // A service with no router at all refuses the same way.
    let unrouted = WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW));
    assert_eq!(
        search(&unrouted, &engine, "direct"),
        Err(WebSearchRefusal::RoutingUnavailable)
    );
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn routing_that_does_not_serve_search_is_unavailable() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("routed-describe");
    let router = router(&["exa"]);
    let mut describe = FakeRouter::serving_search_describe();
    describe["capabilities"] = json!(["select_kind", "select_media", "select_eligible_routes"]);
    router.set_describe(describe);
    let service = routed_service(&router, &Arc::new(AtomicI64::new(NOW)));
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(WebSearchRefusal::RoutingUnavailable)
    );
    assert_eq!(router.methods(), ["role.describe"]);
    assert!(transport.requests().is_empty());
}

#[test]
fn a_select_refusal_other_than_no_route_is_routing_unavailable() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("routed-refused");
    let router = router(&["exa"]);
    router.set_mode(FakeMode::RefuseSelect("consumer_not_owned".into()));
    let service = routed_service(&router, &Arc::new(AtomicI64::new(NOW)));
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(WebSearchRefusal::RoutingUnavailable)
    );
    assert!(transport.requests().is_empty());
}

#[test]
fn no_route_just_after_adding_a_route_is_routing_unavailable() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("routed-grace");
    let router = router(&["exa"]);
    router.set_mode(FakeMode::RefuseSelect("no_route".into()));
    let now = Arc::new(AtomicI64::new(NOW));
    let service = routed_service(&router, &now);
    // Before any route was added, no_route means no provider could serve.
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(unavailable(&[("tavily", SkipReason::NotGranted)]))
    );
    service.note_routes_added();
    now.store(NOW + routing::DECLARATION_GRACE_MS - 1, Ordering::SeqCst);
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(WebSearchRefusal::RoutingUnavailable)
    );
    now.store(NOW + routing::DECLARATION_GRACE_MS, Ordering::SeqCst);
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(unavailable(&[("tavily", SkipReason::NotGranted)]))
    );
    assert!(transport.requests().is_empty());
}

#[test]
fn forbidden_reply_reports_unavailable_never_credential() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("routed-forbidden");
    transport.set_response(MockResponse::VendorError {
        code: "http_403".into(),
        message: "forbidden".into(),
    });
    let router = router(&["exa"]);
    let service = routed_service(&router, &Arc::new(AtomicI64::new(NOW)));
    assert!(search(&service, &engine, "direct").is_err());
    assert_eq!(
        router.params("route.report"),
        [
            json!({"decision_id": "dec_000000000000", "outcome": "failed",
            "attempt_outcome": {"status": "unavailable"}})
        ]
    );
}

#[test]
fn an_answer_naming_a_route_plexus_did_not_offer_is_refused() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("routed-unoffered");
    let router = router(&["exa"]);
    router.set_mode(FakeMode::Answer(RouteRef::new("brave", "web-search")));
    let service = routed_service(&router, &Arc::new(AtomicI64::new(NOW)));
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(WebSearchRefusal::RoutingUnavailable)
    );
    assert!(transport.requests().is_empty());
}
