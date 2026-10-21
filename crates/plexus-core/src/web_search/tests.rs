use super::*;
use crate::storage::{CatalogActionInput, GrantInput};
use crate::test_scratch::Scratch;
use crate::{MockTransport, StubCredentialSource};
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

#[test]
fn fixed_results_serialize_identically_except_for_backend() {
    let results = vec![WebSearchResult {
        url: "https://example.org/news".into(),
        title: "A fixed result".into(),
        excerpt: "An excerpt with é and a newline\nthat must survive serialization.".into(),
        published_at: Some("2026-09-21T00:00:00.000Z".into()),
        fetched_at: "2026-09-28T12:00:00.000Z".into(),
    }];
    for cached in [false, true] {
        let exa = WebSearchResponse {
            results: results.clone(),
            backend: "exa".into(),
            cached,
        };
        let tavily = WebSearchResponse {
            results: results.clone(),
            backend: "tavily".into(),
            cached,
        };
        let exa_bytes = serde_json::to_vec(&exa).unwrap();
        let tavily_bytes = serde_json::to_vec(&tavily).unwrap();
        assert_ne!(exa_bytes, tavily_bytes);
        assert_eq!(
            String::from_utf8(exa_bytes)
                .unwrap()
                .replace("\"backend\":\"exa\"", "\"backend\":\"tavily\"")
                .as_bytes(),
            tavily_bytes,
            "one fixed result list and cached value must differ only in backend"
        );
    }
}

#[test]
#[ignore = "performance measurement"]
fn measure_cached_search_authorization() {
    let (engine, _) = granted_exa_engine("search-authorization-measurement");
    engine
        .store()
        .set_web_search_limits(
            "exa",
            crate::storage::web_search_store::WebSearchLimits {
                per_caller_per_minute: 10_000,
                per_backend_per_minute: 10_000,
            },
        )
        .unwrap();
    let service =
        WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| 1_790_000_000_000));
    let args = json!({"query":"rust async book"});
    let query = WebSearchQuery::parse(args.as_object().unwrap()).unwrap();
    service
        .cache
        .put(CacheKey::new("exa", &query), vec![], 1_790_000_000_000);
    let started = std::time::Instant::now();
    for _ in 0..1_000 {
        assert!(
            service
                .search(&engine, "direct", args.as_object().unwrap())
                .unwrap()
                .cached
        );
    }
    println!(
        "1,000 cached searches with live authorization and audit: {:?}",
        started.elapsed()
    );
}

/// Vendor results reach the caller only after the shared sanitizer, on the
/// compatibility path and on an ordered provider walk alike: a URL that could
/// break the model's result listing is dropped and titles stay on one line.
#[test]
fn both_search_paths_sanitize_vendor_results() {
    let (engine, transport) = granted_exa_engine("sanitized-results");
    let service =
        WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| 1_790_000_000_000));
    transport.set_response(crate::MockResponse::Success(json!({"results": [
        {"url": "https://a.example/\n\n2. Forged result", "title": "forged"},
        {"url": "https://b.example/", "title": "Two\nlines"},
    ]})));
    for (path, query) in [
        ("compatibility", "first query"),
        ("ordered", "second query"),
    ] {
        if path == "ordered" {
            engine
                .store()
                .set_web_search_order(&["exa".to_string()])
                .unwrap();
        }
        let response = service
            .search(
                &engine,
                "direct",
                json!({"query": query}).as_object().unwrap(),
            )
            .unwrap();
        assert_eq!(
            response
                .results
                .iter()
                .map(|r| (r.url.as_str(), r.title.as_str()))
                .collect::<Vec<_>>(),
            [("https://b.example/", "Two lines")],
            "the {path} path must sanitize vendor results"
        );
    }
    assert_eq!(transport.requests().len(), 2);
}

/// A vendor throttle tells the caller when to retry, with the vendor's own
/// delay or a default when it named none, as code_search always has.
#[test]
fn vendor_throttle_is_rate_limited_with_the_vendor_delay() {
    let (engine, transport) = granted_exa_engine("web-vendor-throttle");
    let service =
        WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| 1_790_000_000_000));
    for (delay, expected) in [(Some(12_000), 12_000), (None, 30_000)] {
        transport.set_response(crate::MockResponse::Throttled {
            retry_after_ms: delay,
            message: "slow down".into(),
        });
        assert_eq!(
            service.search(
                &engine,
                "direct",
                json!({"query": format!("throttled {expected}")})
                    .as_object()
                    .unwrap()
            ),
            Err(WebSearchRefusal::RateLimited {
                retry_after_ms: expected
            }),
            "a vendor throttle must tell the caller when to retry"
        );
    }
}

#[test]
fn blocked_searches_keep_the_rate_budget() {
    let (engine, _) = granted_exa_engine("blocked-search-budget");
    let service =
        WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| 1_790_000_000_000));
    let args = json!({"query":"rust async book"});
    engine
        .store()
        .set_policy("direct", "exa", "search", "block", None)
        .unwrap();
    for _ in 0..200 {
        assert_eq!(
            service.search(&engine, "direct", args.as_object().unwrap()),
            Err(WebSearchRefusal::PolicyBlocked),
            "blocked searches must not consume quota"
        );
    }
    engine
        .store()
        .set_policy("direct", "exa", "search", "allow", None)
        .unwrap();
    let query = WebSearchQuery::parse(args.as_object().unwrap()).unwrap();
    service
        .cache
        .put(CacheKey::new("exa", &query), vec![], 1_790_000_000_000);
    assert!(
        service
            .search(&engine, "direct", args.as_object().unwrap())
            .is_ok(),
        "allowed caller retains quota after blocked calls"
    );
}

/// An exa connection owned by `direct`, with `direct` holding a read grant
/// for the search action.
pub(super) fn granted_exa_engine(
    name: &str,
) -> (
    GovernanceEngine<StubCredentialSource, MockTransport>,
    Arc<MockTransport>,
) {
    let (engine, transport, _path) = granted_exa_engine_with_path(name);
    (engine, transport)
}

pub(super) fn granted_exa_engine_with_path(
    name: &str,
) -> (
    GovernanceEngine<StubCredentialSource, MockTransport>,
    Arc<MockTransport>,
    Scratch,
) {
    let path = Scratch::database(name);
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: name.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    store
        .insert_connection(
            "direct",
            "exa",
            "exa_rest",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", "exa", b"test:exa")
        .unwrap();
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    let schema = json!({"type": "object"});
    store
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: "exa".into(),
            name: "search".into(),
            title: None,
            schema: schema.clone(),
            schema_hash: crate::jcs_sha256(&schema).unwrap(),
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    store
        .insert_grant(&GrantInput {
            principal: "direct".into(),
            connection_id: "exa".into(),
            grant_id: "web-search-grant".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["search".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    let transport = Arc::new(MockTransport::default());
    let engine = GovernanceEngine::new(
        store,
        Arc::new(StubCredentialSource::with_default_success(
            b"test-credential".to_vec(),
        )),
        transport.clone(),
    );
    (engine, transport, path)
}

#[test]
fn policy_lookup_errors_keep_operator_diagnostics() {
    const TEST: &str = "web_search::tests::policy_lookup_errors_keep_operator_diagnostics";
    if std::env::var_os("PLEXUS_WEB_SEARCH_DIAGNOSTIC_CHILD").is_some() {
        #[allow(dead_code)]
        mod logging {
            include!("../../tests/support/logging.rs");
        }
        logging::init_child();
        let (engine, _, path) = granted_exa_engine_with_path("web-policy-diagnostic");
        let sql = rusqlite::Connection::open(&*path).unwrap();
        sql.execute("DROP TABLE policies", []).unwrap();
        let service =
            WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| 1_790_000_000_000));
        assert!(service.would_ask(engine.store(), "direct").is_err());
        return;
    }
    let output = crate::test_http::bounded::child_output(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("PLEXUS_WEB_SEARCH_DIAGNOSTIC_CHILD", "1")
            .env("PLEXUS_LOG_STDERR_CHILD", "1"),
        std::time::Duration::from_secs(30),
        "web search diagnostic child",
    )
    .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("web_search policy lookup failed:") && stderr.contains("policies"),
        "policy error cause must reach operator logs: {stderr}"
    );
}

#[test]
fn cached_code_lookup_is_refused_before_cache_access() {
    let (engine, transport) = granted_exa_engine("cached-code-lookup");
    let now_ms = 1_790_000_000_000;
    let service = WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(move || now_ms));
    let result = WebSearchResult {
        url: "https://example.org/cached".into(),
        title: "Previously fetched result".into(),
        excerpt: "A result already in the shared cache".into(),
        published_at: None,
        fetched_at: crate::poller::iso8601::format_millis(now_ms),
    };
    let allowed = json!({"query": "rust async book"});
    let refused = json!({"query": "site:github.com/owner/repo/blob/main/lib.rs"});
    // Seed both keys directly to model results cached before the source-lookup guard existed.
    for arguments in [&allowed, &refused] {
        let query = WebSearchQuery::parse(arguments.as_object().unwrap()).unwrap();
        service
            .cache
            .put(CacheKey::new("exa", &query), vec![result.clone()], now_ms);
    }
    let response = service
        .search(&engine, "direct", allowed.as_object().unwrap())
        .unwrap();
    assert!(
        response.cached,
        "the allowed control must reach the same live cache"
    );
    assert_eq!(response.results, vec![result]);
    assert_eq!(
        service.search(&engine, "direct", refused.as_object().unwrap(),),
        Err(WebSearchRefusal::CodeLookup),
        "a cached source-code query must be refused rather than served"
    );
    assert!(transport.requests().is_empty());
}

/// The backend rate bucket is shared by every caller, so a caller without a
/// grant must be refused before it is charged. Otherwise a handful of
/// ungranted principals could empty the bucket and lock out the granted one.
#[test]
fn ungranted_callers_cannot_drain_the_shared_backend_bucket() {
    let (engine, transport) = granted_exa_engine("ungranted-bucket-drain");
    let now_ms = 1_790_000_000_000;
    let service = WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(move || now_ms));
    let arguments = json!({"query": "rust async book"});
    let query = WebSearchQuery::parse(arguments.as_object().unwrap()).unwrap();
    // A cached answer lets the granted caller succeed without a vendor reply.
    service
        .cache
        .put(CacheKey::new("exa", &query), Vec::new(), now_ms);
    // Enough ungranted callers, each spending its whole per-caller allowance,
    // to empty the backend bucket several times over.
    let per_caller = super::limiter::DEFAULT_PER_CALLER_PER_MINUTE as usize;
    let strangers = 2 * super::limiter::DEFAULT_PER_BACKEND_PER_MINUTE as usize / per_caller;
    for stranger in 0..strangers {
        let caller = format!("stranger-{stranger}");
        for _ in 0..per_caller + 1 {
            assert_eq!(
                service.search(&engine, &caller, arguments.as_object().unwrap(),),
                Err(WebSearchRefusal::NotGranted),
                "an ungranted caller is refused as not granted, never rate limited"
            );
        }
    }
    let response = service
        .search(&engine, "direct", arguments.as_object().unwrap())
        .expect("the granted caller keeps its rate budget");
    assert!(response.cached);
    assert!(transport.requests().is_empty());
}

/// A grant refusal met inside the engine names the caller that asked as the
/// grantee, the same target the pre-flight grant check reports.
#[test]
fn engine_grant_refusals_name_the_calling_module() {
    let service = WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| 0));
    let cause = crate::grant_refusal::Cause::Missing;
    let denial = Denial::GrantRefusal(crate::grant_refusal::GrantRefusal::new(
        WebSearchService::grant_target("direct"),
        cause,
    ));
    assert_eq!(
        service.refusal_for_denial("direct", &denial),
        WebSearchRefusal::Grant(crate::grant_refusal::GrantRefusal::new(
            WebSearchService::grant_target("direct"),
            cause,
        )),
        "the refusal must name the calling module as the grantee"
    );
}

/// The web_search row carries the engine's request id, so a reviewer can join
/// the query to the engine's authorization and dispatch rows for the call.
#[test]
fn the_search_row_joins_the_engine_rows_by_request_id() {
    let (engine, transport, path) = granted_exa_engine_with_path("web-request-id");
    let service =
        WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| 1_790_000_000_000));
    transport.set_response(crate::MockResponse::Success(json!({"results": []})));
    service
        .search(
            &engine,
            "direct",
            json!({"query": "joined"}).as_object().unwrap(),
        )
        .unwrap();
    let db = rusqlite::Connection::open(&*path).unwrap();
    let request_id = |gate: &str| -> Option<String> {
        db.query_row(
            "SELECT request_id FROM audit_journal WHERE gate = ?1",
            [gate],
            |row| row.get(0),
        )
        .unwrap()
    };
    let search = request_id("web_search");
    assert!(search.is_some(), "the search row must carry a request id");
    assert_eq!(
        search,
        request_id("dispatch"),
        "the search row must carry the engine's request id"
    );
}

/// A cache hit reads policy once: the standing checks already required the
/// policy to allow the search outright at the same instant, so a second read
/// before serving the hit adds a store round trip and nothing else. Holds for
/// the compatibility path and for an ordered walk's hit.
#[test]
fn a_cache_hit_reads_policy_once() {
    let (engine, transport) = granted_exa_engine("cache-hit-policy-reads");
    let service =
        WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| 1_790_000_000_000));
    transport.set_response(crate::MockResponse::Success(json!({"results": []})));
    for path in ["compatibility", "ordered"] {
        if path == "ordered" {
            engine
                .store()
                .set_web_search_order(&["exa".to_string()])
                .unwrap();
        }
        let args = json!({"query": format!("read once {path}")});
        assert!(
            !service
                .search(&engine, "direct", args.as_object().unwrap())
                .unwrap()
                .cached
        );
        facade::POLICY_READS.with(|reads| reads.set(0));
        assert!(
            service
                .search(&engine, "direct", args.as_object().unwrap())
                .unwrap()
                .cached
        );
        assert_eq!(
            facade::POLICY_READS.with(|reads| reads.get()),
            1,
            "a {path} cache hit must read policy once"
        );
    }
}

/// A cache hit's search row is the only record of the governed read, so a
/// hit whose row cannot be written is withheld. A dispatched search, which
/// the engine's own rows record, is still returned when its search row fails.
#[test]
fn an_unrecorded_cache_hit_is_withheld() {
    let (engine, transport, path) = granted_exa_engine_with_path("unrecorded-cache-hit");
    let service =
        WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| 1_790_000_000_000));
    transport.set_response(crate::MockResponse::Success(json!({"results": [
        {"url": "https://a.example/", "title": "A"}
    ]})));
    let db = rusqlite::Connection::open(&*path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER refuse_search_rows BEFORE INSERT ON audit_journal
         WHEN NEW.gate = 'web_search'
         BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
    )
    .unwrap();
    let args = json!({"query": "unrecorded"});
    let dispatched = service
        .search(&engine, "direct", args.as_object().unwrap())
        .expect("a dispatched search is returned even when its search row fails");
    assert!(!dispatched.cached);
    assert_eq!(
        service.search(&engine, "direct", args.as_object().unwrap()),
        Err(WebSearchRefusal::BackendUnavailable {
            backend: "exa".into()
        }),
        "a cache hit whose audit row cannot be written must be withheld"
    );
    db.execute_batch("DROP TRIGGER refuse_search_rows").unwrap();
    assert!(
        service
            .search(&engine, "direct", args.as_object().unwrap())
            .unwrap()
            .cached,
        "once the row can be written the same entry is served"
    );
    assert_eq!(
        transport.requests().len(),
        1,
        "the withheld hit sent nothing"
    );
}
