//! Monthly allowance admission in the ordered walk: a count is reserved after
//! the deadline gate and before rate charging, kept when the request may have
//! reached the vendor, and handed back on every exit that sent nothing.

use super::*;
use crate::credentials::ResolvedCredential;
use crate::storage::web_search_store::WebSearchLimits;
use crate::transport::{MockResponse, TransportRequest, TransportResponse};
use std::sync::atomic::AtomicI64;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// 2026-10-01T00:00:00Z, the first instant of the month after `NOW`.
const OCTOBER: i64 = 1_790_812_800_000;

fn used(engine: &Engine, provider: &str, at_ms: i64) -> u32 {
    engine
        .store()
        .web_search_allowance_used(provider, "direct", at_ms)
        .unwrap()
}

fn search_query(
    service: &WebSearchService,
    engine: &Engine,
    query: &str,
) -> Result<WebSearchResponse, WebSearchRefusal> {
    service.search(
        engine,
        "direct",
        json!({ "query": query }).as_object().unwrap(),
    )
}

fn clocked_service(now: &Arc<AtomicI64>) -> WebSearchService {
    let clock = now.clone();
    WebSearchService::with_clock(
        Arc::new(ExaRestBackend),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    )
    .with_chain_backend(Arc::new(TestBackend {
        name: "tavily",
        preparations: Arc::new(AtomicUsize::new(0)),
    }))
}

fn connection_ids(transport: &MockTransport) -> Vec<String> {
    transport
        .requests()
        .into_iter()
        .map(|request| request.connection_id)
        .collect()
}

#[test]
fn third_distinct_query_moves_past_a_used_up_allowance() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("allowance-third");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    order(&engine, &["exa", "tavily"]);
    engine.store().set_web_search_allowance("exa", 2).unwrap();
    transport.set_response(MockResponse::Success(json!({"results":[]})));
    let service = service();
    let backends = ["first query", "second query", "third query"]
        .map(|query| search_query(&service, &engine, query).unwrap().backend);
    assert_eq!(
        backends,
        ["exa", "exa", "tavily"],
        "a used-up allowance must hand the search to the next provider"
    );
    assert_eq!(connection_ids(&transport), ["exa", "exa", "tavily"]);
    assert_eq!(used(&engine, "exa", NOW), 2);
    // Tavily has no allowance set, so its search is not counted at all.
    assert_eq!(used(&engine, "tavily", NOW), 0);
    let summaries: Vec<Value> = engine
        .store()
        .list_audit("direct")
        .unwrap()
        .iter()
        .filter(|row| row.gate.as_deref() == Some("web_search"))
        .map(|row| serde_json::from_str(row.args_redaction_summary.as_deref().unwrap()).unwrap())
        .collect();
    assert!(
        summaries.contains(
            &json!({"served_by":"tavily","skipped":[{"provider":"exa","reason":"allowance"}]})
        ),
        "audit: {summaries:?}"
    );
}

#[test]
fn used_up_allowance_is_a_skip_until_the_utc_month_rolls_over() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("allowance-month");
    order(&engine, &["exa"]);
    engine.store().set_web_search_allowance("exa", 1).unwrap();
    transport.set_response(MockResponse::Success(json!({"results":[]})));
    let now = Arc::new(AtomicI64::new(OCTOBER - 1_000));
    let service = clocked_service(&now);
    assert_eq!(
        search_query(&service, &engine, "first").unwrap().backend,
        "exa"
    );
    assert_eq!(
        search_query(&service, &engine, "second"),
        Err(unavailable(&[("exa", SkipReason::Allowance)]))
    );
    now.store(OCTOBER, Ordering::SeqCst);
    assert_eq!(
        search_query(&service, &engine, "third").map(|response| response.backend),
        Ok("exa".to_string()),
        "a new UTC month must start a fresh allowance count"
    );
    assert_eq!(transport.requests().len(), 2);
    assert_eq!(used(&engine, "exa", OCTOBER - 1_000), 1);
    assert_eq!(used(&engine, "exa", OCTOBER), 1);
}

#[test]
fn not_sent_dispatch_releases_its_count() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("allowance-not-sent");
    order(&engine, &["exa"]);
    engine.store().set_web_search_allowance("exa", 1).unwrap();
    transport.set_response(MockResponse::TransientNotSent {
        message: "connection refused".into(),
    });
    let service = service();
    assert_eq!(
        search_query(&service, &engine, "first"),
        Err(unavailable(&[("exa", SkipReason::Unavailable)]))
    );
    assert_eq!(
        used(&engine, "exa", NOW),
        0,
        "a NotSent dispatch must release its allowance count"
    );
    // The NotSent attempt cooled the connection; clear it to show the
    // released unit is spendable again.
    service.chain_cooldowns.lock().unwrap().clear();
    transport.set_response(MockResponse::Success(json!({"results":[]})));
    assert_eq!(
        search_query(&service, &engine, "second").unwrap().backend,
        "exa"
    );
    assert_eq!(used(&engine, "exa", NOW), 1);
}

#[test]
fn sent_and_outcome_unknown_dispatches_keep_their_count() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("allowance-kept");
    order(&engine, &["exa"]);
    engine.store().set_web_search_allowance("exa", 5).unwrap();
    let service = service();
    for (expected, response) in [
        (1, MockResponse::OutcomeUnknown),
        (
            2,
            MockResponse::VendorError {
                code: "http_503".into(),
                message: "vendor down".into(),
            },
        ),
        (3, MockResponse::Success(json!({"results":[]}))),
    ] {
        service.chain_cooldowns.lock().unwrap().clear();
        transport.set_response(response);
        let _ = search_query(&service, &engine, &format!("query {expected}"));
        assert_eq!(
            used(&engine, "exa", NOW),
            expected,
            "a dispatch that may have reached the vendor keeps its count"
        );
    }
    assert_eq!(transport.requests().len(), 3);
}

#[test]
fn authorize_and_revalidate_denials_release_their_count() {
    let (engine, transport) =
        super::super::super::tests::granted_exa_engine("allowance-authorize-denial");
    order(&engine, &["exa"]);
    engine.store().set_web_search_allowance("exa", 1).unwrap();
    // The connector-home gate runs in authorize and again in revalidate. Let
    // the first check pass, so the first search is refused at revalidation,
    // and every later check deny, so the second is refused at authorize.
    let checks = Arc::new(AtomicUsize::new(0));
    let observed = checks.clone();
    let engine = engine.with_connector_home_guard(Arc::new(move || {
        (observed.fetch_add(1, Ordering::SeqCst) > 0).then(|| json!({"state":"not held"}))
    }));
    let service = service();
    for query in ["revalidate denial", "authorize denial"] {
        // A revalidation refusal is NotSent and cools the connection; clear
        // it so the next search reaches authorize.
        service.chain_cooldowns.lock().unwrap().clear();
        assert_eq!(
            search_query(&service, &engine, query),
            Err(unavailable(&[("exa", SkipReason::Unavailable)])),
            "{query}: a held count would turn this into an allowance skip"
        );
        assert_eq!(
            used(&engine, "exa", NOW),
            0,
            "{query} must release its allowance count"
        );
    }
    assert_eq!(checks.load(Ordering::SeqCst), 3);
    assert!(transport.requests().is_empty());
}

#[test]
fn rate_limited_skips_release_until_the_bucket_refills() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("allowance-rate");
    order(&engine, &["exa"]);
    engine.store().set_web_search_allowance("exa", 2).unwrap();
    let held = engine
        .store()
        .reserve_web_search_allowance("exa", "direct", NOW)
        .unwrap();
    assert!(matches!(held, WebSearchAllowanceAdmission::Reserved(_)));
    let limits = WebSearchLimits {
        per_caller_per_minute: 1,
        per_backend_per_minute: 100,
    };
    engine.store().set_web_search_limits("exa", limits).unwrap();
    transport.set_response(MockResponse::Success(json!({"results":[]})));
    let now = Arc::new(AtomicI64::new(NOW));
    let service = clocked_service(&now);
    let key = CallerKey {
        principal: "direct".into(),
        agent_id: None,
    };
    service
        .limiter
        .try_acquire("exa", &key, limits, NOW)
        .unwrap();
    for query in ["first", "second", "third"] {
        assert_eq!(
            search_query(&service, &engine, query),
            Err(WebSearchRefusal::RateLimited {
                retry_after_ms: 60_000
            })
        );
        assert_eq!(
            used(&engine, "exa", NOW),
            1,
            "a rate_limited skip must release its allowance count"
        );
    }
    now.store(NOW + 60_000, Ordering::SeqCst);
    assert_eq!(
        search_query(&service, &engine, "refilled").unwrap().backend,
        "exa"
    );
    assert_eq!(used(&engine, "exa", NOW), 2);
    assert_eq!(transport.requests().len(), 1);
}

/// Serves Tavily at once. Holds an Exa request until another search has
/// returned (or a bound passes), so two searches that both reached Exa would
/// be in flight together. Records the Exa count it sees while dispatching.
struct GateTransport {
    store: Arc<PlexusStore>,
    requests: Mutex<Vec<String>>,
    used_during_dispatch: Mutex<Vec<u32>>,
    finished: Arc<(Mutex<usize>, Condvar)>,
}

impl Transport for GateTransport {
    fn dispatch(&self, request: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
        self.requests
            .lock()
            .unwrap()
            .push(request.connection_id.clone());
        if request.connection_id == "exa" {
            self.used_during_dispatch.lock().unwrap().push(
                self.store
                    .web_search_allowance_used("exa", "direct", NOW)
                    .unwrap(),
            );
            let (finished, signal) = &*self.finished;
            let guard = finished.lock().unwrap();
            let _ = signal
                .wait_timeout_while(guard, Duration::from_secs(5), |done| *done == 0)
                .unwrap();
        }
        TransportResponse::success(json!({"results":[]}))
    }
}

#[test]
fn concurrent_searches_at_the_last_unit_do_not_both_reach_exa() {
    // Keep the scratch database: two searches in flight need a second pooled
    // reader, which opens the database file again.
    let (fixture, _, _path) =
        super::super::super::tests::granted_exa_engine_with_path("allowance-concurrent");
    add_connection(&fixture, "tavily", "tavily", Some("direct"));
    order(&fixture, &["exa", "tavily"]);
    fixture.store().set_web_search_allowance("exa", 2).unwrap();
    let held = fixture
        .store()
        .reserve_web_search_allowance("exa", "direct", NOW)
        .unwrap();
    assert!(matches!(held, WebSearchAllowanceAdmission::Reserved(_)));
    let finished = Arc::new((Mutex::new(0), Condvar::new()));
    let transport = Arc::new(GateTransport {
        store: fixture.store().clone(),
        requests: Mutex::new(Vec::new()),
        used_during_dispatch: Mutex::new(Vec::new()),
        finished: finished.clone(),
    });
    let engine = GovernanceEngine::new(
        fixture.store().clone(),
        Arc::new(crate::StubCredentialSource::with_default_success(
            b"test-credential".to_vec(),
        )),
        transport.clone(),
    );
    let service = service();
    let mut backends = std::thread::scope(|scope| {
        let searches = ["first concurrent", "second concurrent"].map(|query| {
            let (engine, service, finished) = (&engine, &service, &finished);
            scope.spawn(move || {
                let result = service.search(
                    engine,
                    "direct",
                    json!({ "query": query }).as_object().unwrap(),
                );
                let (done, signal) = &**finished;
                *done.lock().unwrap() += 1;
                signal.notify_all();
                result.unwrap().backend
            })
        });
        searches.map(|search| search.join().unwrap())
    });
    backends.sort();
    let mut requests = transport.requests.lock().unwrap().clone();
    requests.sort();
    assert_eq!(
        requests,
        ["exa", "tavily"],
        "two searches at count 1 of 2 must not both reach Exa"
    );
    assert_eq!(backends, ["exa", "tavily"]);
    // The reserving transaction committed before the vendor call, so a
    // process that died mid-dispatch would still have spent the unit.
    assert_eq!(*transport.used_during_dispatch.lock().unwrap(), [2]);
    assert_eq!(
        fixture
            .store()
            .web_search_allowance_used("exa", "direct", NOW)
            .unwrap(),
        2
    );
}
