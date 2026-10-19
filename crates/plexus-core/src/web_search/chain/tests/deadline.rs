use super::*;
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::transport::{TransportRequest, TransportResponse};
use std::sync::atomic::AtomicI64;
use std::sync::Mutex;

struct DelayedVault {
    now: Arc<AtomicI64>,
    delay_ms: i64,
    reads: AtomicUsize,
}

impl CredentialSource for DelayedVault {
    fn get_by_id(&self, _: &str) -> Result<ResolvedCredential, CredentialError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.now.fetch_add(self.delay_ms, Ordering::SeqCst);
        Ok(ResolvedCredential::new(b"test-key".to_vec(), None, 1))
    }
}

struct TimeoutTransport {
    now: Arc<AtomicI64>,
    requests: Mutex<Vec<String>>,
}

impl Transport for TimeoutTransport {
    fn dispatch(&self, request: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
        self.requests
            .lock()
            .unwrap()
            .push(request.connection_id.clone());
        if request.connection_id == "exa" {
            self.now.fetch_add(30_000, Ordering::SeqCst);
            TransportResponse::timeout("REST")
        } else {
            TransportResponse::success(json!({"results":[]}))
        }
    }
}

fn clocked_service(now: &Arc<AtomicI64>) -> WebSearchService {
    let clock = now.clone();
    let mut service = WebSearchService::with_clock(
        Arc::new(ExaRestBackend),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    for name in ["tavily", "brave", "deepseek", "jina", "kagi"] {
        service = service.with_chain_backend(Arc::new(TestBackend {
            name,
            preparations: Arc::new(AtomicUsize::new(0)),
        }));
    }
    service
}

fn delayed_engine(
    fixture: &Engine,
    now: &Arc<AtomicI64>,
    vault_ms: i64,
) -> (
    GovernanceEngine<DelayedVault, TimeoutTransport>,
    Arc<DelayedVault>,
    Arc<TimeoutTransport>,
) {
    let vault = Arc::new(DelayedVault {
        now: now.clone(),
        delay_ms: vault_ms,
        reads: AtomicUsize::new(0),
    });
    let transport = Arc::new(TimeoutTransport {
        now: now.clone(),
        requests: Mutex::new(Vec::new()),
    });
    (
        GovernanceEngine::new(fixture.store().clone(), vault.clone(), transport.clone()),
        vault,
        transport,
    )
}

#[test]
fn fast_vault_and_thirty_second_timeout_admit_tavily() {
    let (fixture, _) = super::super::super::tests::granted_exa_engine("deadline-fast-vault");
    add_connection(&fixture, "tavily", "tavily", Some("direct"));
    order(&fixture, &["exa", "tavily"]);
    let now = Arc::new(AtomicI64::new(NOW));
    let service = clocked_service(&now);
    let (engine, vault, transport) = delayed_engine(&fixture, &now, 1);
    let response = service
        .search(
            &engine,
            "direct",
            json!({"query":"weather report"}).as_object().unwrap(),
        )
        .unwrap();
    assert_eq!(response.backend, "tavily");
    assert_eq!(*transport.requests.lock().unwrap(), ["exa", "tavily"]);
    assert_eq!(vault.reads.load(Ordering::SeqCst), 2);
    assert_eq!(now.load(Ordering::SeqCst) - NOW, 30_002);
}

#[test]
fn slow_vault_and_timeout_stop_later_providers_without_spending() {
    let (fixture, _) = super::super::super::tests::granted_exa_engine("deadline-slow-vault");
    for name in ["tavily", "brave"] {
        add_connection(&fixture, name, name, Some("direct"));
        fixture.store().set_web_search_allowance(name, 1).unwrap();
        fixture
            .store()
            .set_web_search_limits(
                name,
                crate::storage::web_search_store::WebSearchLimits {
                    per_caller_per_minute: 1,
                    per_backend_per_minute: 1,
                },
            )
            .unwrap();
    }
    order(&fixture, &["exa", "tavily", "brave"]);
    let now = Arc::new(AtomicI64::new(NOW));
    let service = clocked_service(&now);
    let (engine, vault, transport) = delayed_engine(&fixture, &now, 30_000);
    let result = service.search(
        &engine,
        "direct",
        json!({"query":"weather report"}).as_object().unwrap(),
    );
    assert_eq!(
        result,
        Err(unavailable(&[
            ("exa", SkipReason::Unavailable),
            ("tavily", SkipReason::Deadline),
            ("brave", SkipReason::Deadline),
        ])),
        "deadline admission must refuse providers with less than 65 seconds left"
    );
    let refusal = result.unwrap_err();
    assert_eq!(
        refusal.to_wire()["error"]["detail"],
        json!([
            {"provider":"exa", "reason":"unavailable"},
            {"provider":"tavily", "reason":"deadline"},
            {"provider":"brave", "reason":"deadline"},
        ])
    );
    assert_eq!(*transport.requests.lock().unwrap(), ["exa"]);
    assert_eq!(vault.reads.load(Ordering::SeqCst), 1);
    let elapsed_ms = now.load(Ordering::SeqCst) - NOW;
    assert_eq!(elapsed_ms, 60_000);
    assert!(elapsed_ms <= 120_000);
    for name in ["tavily", "brave"] {
        assert_eq!(
            engine
                .store()
                .web_search_allowance_used(name, "direct", NOW)
                .unwrap(),
            0
        );
        assert!(!service.chain_cooldowns.lock().unwrap().contains_key(name));
        let key = CallerKey {
            principal: "direct".into(),
            agent_id: None,
        };
        let limits = engine.store().web_search_limits(name).unwrap().unwrap();
        assert!(service.limiter.try_acquire(name, &key, limits, NOW).is_ok());
    }
    let rows = engine.store().list_audit("direct").unwrap();
    let row = rows
        .iter()
        .find(|row| row.gate.as_deref() == Some("web_search"))
        .unwrap();
    assert_eq!(row.connection_id.as_deref(), Some("exa"));
    let detail: Value =
        serde_json::from_str(row.args_redaction_summary.as_deref().unwrap()).unwrap();
    assert_eq!(detail["skipped"], refusal.to_wire()["error"]["detail"]);
}

#[test]
fn exactly_sixty_five_seconds_remaining_is_admitted() {
    assert_eq!(
        WEB_SEARCH_CHAIN_DEADLINE,
        std::time::Duration::from_secs(120)
    );
    assert_eq!(WEB_SEARCH_ATTEMPT_BOUND, std::time::Duration::from_secs(65));
    for vault_ms in [24_999, 25_000, 25_001] {
        let (fixture, _) = super::super::super::tests::granted_exa_engine("deadline-boundary");
        add_connection(&fixture, "tavily", "tavily", Some("direct"));
        order(&fixture, &["exa", "tavily"]);
        let now = Arc::new(AtomicI64::new(NOW));
        let service = clocked_service(&now);
        let (engine, _, transport) = delayed_engine(&fixture, &now, vault_ms);
        let result = service.search(
            &engine,
            "direct",
            json!({"query":"weather report"}).as_object().unwrap(),
        );
        if vault_ms <= 25_000 {
            assert_eq!(result.unwrap().backend, "tavily");
            assert_eq!(*transport.requests.lock().unwrap(), ["exa", "tavily"]);
        } else {
            assert_eq!(
                result,
                Err(unavailable(&[
                    ("exa", SkipReason::Unavailable),
                    ("tavily", SkipReason::Deadline),
                ]))
            );
            assert_eq!(*transport.requests.lock().unwrap(), ["exa"]);
        }
    }
}

#[test]
fn after_deadline_only_capability_and_grant_checks_run() {
    let (fixture, _, path) =
        super::super::super::tests::granted_exa_engine_with_path("deadline-narrowing");
    for name in ["tavily", "brave", "kagi"] {
        add_connection(&fixture, name, name, Some("direct"));
    }
    add_connection(&fixture, "kagi-two", "kagi", Some("direct"));
    fixture
        .store()
        .set_policy("direct", "brave", "search", "ask_first", None)
        .unwrap();
    let sql = rusqlite::Connection::open(&*path).unwrap();
    sql.execute(
        "UPDATE catalog_actions SET status = 'quarantined' WHERE connection_id = 'brave'",
        [],
    )
    .unwrap();
    sql.execute(
        "UPDATE connections SET status = 'auth_required' WHERE connection_id = 'brave'",
        [],
    )
    .unwrap();
    order(
        &fixture,
        &["exa", "tavily", "brave", "deepseek", "jina", "kagi"],
    );
    let now = Arc::new(AtomicI64::new(NOW));
    let service = clocked_service(&now);
    service
        .chain_cooldowns
        .lock()
        .unwrap()
        .insert("brave".into(), NOW + 200_000);
    let (engine, vault, transport) = delayed_engine(&fixture, &now, 30_000);
    assert_eq!(
        service.search(
            &engine,
            "direct",
            json!({"query":"x".repeat(200)}).as_object().unwrap(),
        ),
        Err(unavailable(&[
            ("exa", SkipReason::Unavailable),
            ("tavily", SkipReason::Deadline),
            ("brave", SkipReason::Deadline),
            ("deepseek", SkipReason::Capability),
            ("jina", SkipReason::NotGranted),
            ("kagi", SkipReason::Ambiguous),
        ])),
        "after a deadline stop, policy and approval must not replace the deadline reason"
    );
    assert_eq!(*transport.requests.lock().unwrap(), ["exa"]);
    assert_eq!(vault.reads.load(Ordering::SeqCst), 1);
}

#[test]
fn budget_starts_at_walk_entry_not_the_earlier_search_timestamp() {
    let (fixture, _) = super::super::super::tests::granted_exa_engine("deadline-entry-clock");
    add_connection(&fixture, "tavily", "tavily", Some("direct"));
    order(&fixture, &["exa", "tavily"]);
    let now = Arc::new(AtomicI64::new(NOW));
    let clock = now.clone();
    let reads = AtomicUsize::new(0);
    let service = WebSearchService::with_clock(
        Arc::new(ExaRestBackend),
        Arc::new(move || {
            // Model time spent in once-only checks before entering the walk.
            if reads.fetch_add(1, Ordering::SeqCst) == 1 {
                clock.fetch_add(90_000, Ordering::SeqCst);
            }
            clock.load(Ordering::SeqCst)
        }),
    )
    .with_chain_backend(Arc::new(TestBackend {
        name: "tavily",
        preparations: Arc::new(AtomicUsize::new(0)),
    }));
    let (engine, _, transport) = delayed_engine(&fixture, &now, 1);
    assert_eq!(
        service
            .search(
                &engine,
                "direct",
                json!({"query":"weather report"}).as_object().unwrap(),
            )
            .unwrap()
            .backend,
        "tavily"
    );
    assert_eq!(*transport.requests.lock().unwrap(), ["exa", "tavily"]);
    assert_eq!(now.load(Ordering::SeqCst) - (NOW + 90_000), 30_002);
}

#[test]
fn policy_and_cooldown_precede_the_first_deadline_stop() {
    let (fixture, _) = super::super::super::tests::granted_exa_engine("deadline-check-order");
    for name in ["tavily", "brave", "jina"] {
        add_connection(&fixture, name, name, Some("direct"));
    }
    fixture
        .store()
        .set_policy("direct", "tavily", "search", "ask_first", None)
        .unwrap();
    order(&fixture, &["exa", "tavily", "brave", "jina"]);
    let now = Arc::new(AtomicI64::new(NOW));
    let service = clocked_service(&now);
    service
        .chain_cooldowns
        .lock()
        .unwrap()
        .insert("brave".into(), NOW + 200_000);
    let (engine, vault, transport) = delayed_engine(&fixture, &now, 30_000);
    assert_eq!(
        service.search(
            &engine,
            "direct",
            json!({"query":"weather report"}).as_object().unwrap(),
        ),
        Err(unavailable(&[
            ("exa", SkipReason::Unavailable),
            ("tavily", SkipReason::Policy),
            ("brave", SkipReason::Cooldown),
            ("jina", SkipReason::Deadline),
        ]))
    );
    assert_eq!(*transport.requests.lock().unwrap(), ["exa"]);
    assert_eq!(vault.reads.load(Ordering::SeqCst), 1);
}
