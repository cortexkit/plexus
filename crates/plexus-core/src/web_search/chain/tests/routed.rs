//! Provider choice through routing: what plexus offers a router, how it acts
//! on the answer, and what it reports back.

use super::*;
use crate::transport::MockResponse;
use crate::web_search::routing::fake::{FakeMode, FakeRouter};
use crate::web_search::routing::RouteRef;
use std::sync::atomic::AtomicI64;

#[derive(Default)]
struct BodyPublisher(std::sync::Mutex<Vec<(String, Value)>>);
impl routing::RouteFactPublisher for BodyPublisher {
    fn publish_event<'a>(
        &'a self,
        event: &'a str,
        version: u32,
        reader: Option<&'a str>,
        msg_id: &'a str,
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            assert_eq!((event, version, reader), ("route_fact", 1, None));
            self.0
                .lock()
                .unwrap()
                .push((msg_id.into(), serde_json::from_slice(body).unwrap()));
            Ok(())
        })
    }
}

#[test]
fn search_returns_while_route_fact_publisher_is_stuck() {
    struct StuckPublisher;
    impl routing::RouteFactPublisher for StuckPublisher {
        fn publish_event<'a>(
            &'a self,
            _: &'a str,
            _: u32,
            _: Option<&'a str>,
            _: &'a str,
            _: &'a [u8],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>
        {
            Box::pin(std::future::pending())
        }
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let (engine, transport) =
            super::super::super::tests::granted_exa_engine("routed-stuck-publisher");
        transport.set_response(hit());
        let router = router(&["exa"]);
        let mut describe = FakeRouter::serving_search_describe();
        describe["capabilities"]
            .as_array_mut()
            .unwrap()
            .push(json!("route_fact_stream"));
        router.set_describe(describe);
        let service = routed_service(&router, &Arc::new(AtomicI64::new(NOW)))
            .with_route_fact_publisher(Arc::new(StuckPublisher));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut drain = Box::pin(service.drain_route_facts(engine.store(), 1));
        engine
            .store()
            .enqueue_route_fact(
                "old:outcome",
                &json!({"decision_id":"old","outcome":"completed"}),
                NOW,
            )
            .unwrap();
        // Poll an actual drain to its blocked publication, not just a publisher
        // that would block if some later caller invoked it.
        assert!(runtime
            .block_on(async {
                tokio::time::timeout(Duration::from_millis(20), drain.as_mut()).await
            })
            .is_err());
        let result = search(&service, &engine, "direct");
        tx.send((
            result.is_ok(),
            engine.store().pending_route_facts(10).unwrap().len(),
            router.params("route.report").len(),
        ))
        .unwrap();
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(10))
            .expect("search must not wait for publish"),
        (true, 2, 0)
    );
    worker.join().unwrap();
}

#[test]
fn route_reports_call_until_advertised_then_return_to_dual_delivery() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("routed-stream");
    transport.set_response(hit());
    let router = router(&["exa"]);
    let clock = Arc::new(AtomicI64::new(NOW));
    let publisher = Arc::new(BodyPublisher::default());
    let service = routed_service(&router, &clock).with_route_fact_publisher(publisher.clone());
    search(&service, &engine, "direct").unwrap();
    assert_eq!(router.params("route.report").len(), 1);
    let row = engine.store().pending_route_facts(10).unwrap().remove(0);
    assert_eq!(row.msg_id, "dec_000000000000:outcome");
    assert_eq!(
        serde_json::from_str::<Value>(&row.body).unwrap(),
        json!({"op":"route.report", "params":router.params("route.report")[0]})
    );

    let mut describe = FakeRouter::serving_search_describe();
    describe["capabilities"]
        .as_array_mut()
        .unwrap()
        .push(json!("route_fact_stream"));
    router.set_describe(describe);
    clock.store(NOW + routing::DESCRIBE_TTL_MS, Ordering::SeqCst);
    service
        .search(
            &engine,
            "direct",
            json!({"query":"different query"}).as_object().unwrap(),
        )
        .unwrap();
    assert_eq!(router.params("route.report").len(), 1);
    assert_eq!(engine.store().pending_route_facts(10).unwrap().len(), 2);
    assert!(
        publisher.0.lock().unwrap().is_empty(),
        "search waited on publication"
    );

    router.set_describe(FakeRouter::serving_search_describe());
    clock.store(NOW + 2 * routing::DESCRIBE_TTL_MS, Ordering::SeqCst);
    service
        .search(
            &engine,
            "direct",
            json!({"query":"third query"}).as_object().unwrap(),
        )
        .unwrap();
    assert_eq!(router.params("route.report").len(), 2);
    assert_eq!(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(service.drain_route_facts(engine.store(), 10))
            .unwrap(),
        3
    );
    assert!(engine.store().pending_route_facts(1).unwrap().is_empty());
    assert_eq!(publisher.0.lock().unwrap().len(), 3);
}

#[test]
fn missing_publisher_and_failed_insert_keep_reports_call_only() {
    let (engine, _) = super::super::super::tests::granted_exa_engine("routed-stream-fallback");
    let router = router(&["exa"]);
    let clock = Arc::new(AtomicI64::new(NOW));
    let service = routed_service(&router, &clock);
    let facts = routing::DescribeFacts {
        attempt_outcomes: true,
        route_fact_stream: true,
    };
    service.report_attempt(
        engine.store(),
        router.as_ref(),
        "no-publisher",
        routing::AttemptStatus::Served,
        facts,
        None,
    );
    assert_eq!(router.params("route.report").len(), 1);
    assert!(engine.store().pending_route_facts(1).unwrap().is_empty());

    engine.store().fail_route_fact_insert_for_test();
    let service = service.with_route_fact_publisher(Arc::new(BodyPublisher::default()));
    service.report_attempt(
        engine.store(),
        router.as_ref(),
        "failed-insert",
        routing::AttemptStatus::Served,
        facts,
        None,
    );
    assert_eq!(router.params("route.report").len(), 2);
    assert!(engine.store().pending_route_facts(1).unwrap().is_empty());
}

#[test]
fn failed_routing_describe_is_shared_until_retry_is_due() {
    let router = router(&["exa"]);
    router.set_mode(FakeMode::Unreachable);
    let clock = Arc::new(AtomicI64::new(NOW));
    let service = routed_service(&router, &clock);
    for at in [NOW, NOW + 4_999] {
        clock.store(at, Ordering::SeqCst);
        assert!(service
            .routing_facts(router.as_ref(), Duration::from_secs(1))
            .is_err());
    }
    assert_eq!(
        router.params("role.describe").len(),
        1,
        "the second call must reuse the failed refresh"
    );
    router.set_mode(FakeMode::Serve);
    clock.store(NOW + 5_000, Ordering::SeqCst);
    assert!(service
        .routing_facts(router.as_ref(), Duration::from_secs(1))
        .is_ok());
    assert_eq!(router.params("role.describe").len(), 2);
}

#[test]
fn in_flight_describe_does_not_block_stale_reads_or_overrun_a_cold_wait() {
    use std::sync::mpsc;
    use std::sync::Mutex;

    struct GatedDescribe {
        started: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl routing::RoutingPeer for GatedDescribe {
        fn call(
            &self,
            method: &str,
            _: Value,
            _: Option<&crate::scope::CallScope>,
            _: Duration,
        ) -> Result<Value, routing::RoutingCallError> {
            assert_eq!(method, "role.describe");
            self.started.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            Ok(json!({"result": FakeRouter::serving_search_describe()}))
        }
    }

    for seed_stale in [false, true] {
        let router = router(&["exa"]);
        let clock = Arc::new(AtomicI64::new(NOW));
        let service = routed_service(&router, &clock);
        if seed_stale {
            service
                .routing_facts(router.as_ref(), Duration::from_secs(1))
                .unwrap();
            clock.store(NOW + routing::DESCRIBE_TTL_MS, Ordering::SeqCst);
        }
        let (started, arrived) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let gated = GatedDescribe {
            started,
            release: Mutex::new(released),
        };
        std::thread::scope(|threads| {
            let refresh = threads.spawn(|| service.routing_facts(&gated, Duration::from_secs(3)));
            arrived.recv_timeout(Duration::from_secs(2)).unwrap();
            let (done, answer) = mpsc::channel();
            let service = &service;
            let gated = &gated;
            threads.spawn(move || {
                let result = service.routing_facts(gated, Duration::from_millis(30));
                let _ = done.send(result);
            });
            let concurrent = answer.recv_timeout(Duration::from_secs(2));
            release.send(()).unwrap();
            assert!(refresh.join().unwrap().is_ok());
            let concurrent = concurrent.expect("a concurrent search must not wait for the peer");
            assert_eq!(concurrent.is_ok(), seed_stale);
            assert!(
                arrived.try_recv().is_err(),
                "only one refresh should enter the peer"
            );
        });
    }
}

#[test]
fn unreachable_describe_preserves_last_stream_advertisement() {
    let router = router(&["exa"]);
    let mut describe = FakeRouter::serving_search_describe();
    describe["capabilities"]
        .as_array_mut()
        .unwrap()
        .push(json!("route_fact_stream"));
    router.set_describe(describe);
    let clock = Arc::new(AtomicI64::new(NOW));
    let service = routed_service(&router, &clock);
    assert!(
        service
            .routing_facts(router.as_ref(), Duration::from_secs(1))
            .unwrap()
            .route_fact_stream
    );
    router.set_mode(FakeMode::Unreachable);
    clock.store(NOW + routing::DESCRIBE_TTL_MS, Ordering::SeqCst);
    assert!(
        service
            .routing_facts(router.as_ref(), Duration::from_secs(1))
            .unwrap()
            .route_fact_stream
    );
}

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
fn local_search_carries_session_scope_on_select_and_report() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("routed-scope");
    transport.set_response(hit());
    let router = router(&["exa"]);
    let service = routed_service(&router, &Arc::new(AtomicI64::new(NOW)));
    let scope = CallScope {
        owner: "direct".into(),
        scope_ref: "head".into(),
        scope_epoch: 1,
        kind: None,
        parent: None,
        parent_state: None,
        agent_id: None,
        flow_id: Some("flow".into()),
        delegates: false,
        owner_authorized: true,
    };
    let args = json!({"query":"weather report"});
    let response = service
        .search_scoped(
            &engine,
            "direct",
            args.as_object().unwrap(),
            Some(&scope),
            None,
        )
        .unwrap();
    assert_eq!(response.backend, "exa");
    for method in ["route.select", "route.report"] {
        assert_eq!(router.scopes(method), [Some(scope.clone())], "{method}");
    }
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
