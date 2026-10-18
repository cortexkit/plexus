use super::*;
use crate::storage::{CatalogActionInput, GrantInput};
use crate::{MockTransport, StubCredentialSource};
use std::sync::atomic::{AtomicUsize, Ordering};

mod outcomes;

const NOW: i64 = 1_790_000_000_000;
type Engine = GovernanceEngine<StubCredentialSource, MockTransport>;

struct TestBackend {
    name: &'static str,
    preparations: Arc<AtomicUsize>,
}

impl WebSearchBackend for TestBackend {
    fn name(&self) -> &'static str {
        self.name
    }
    fn app_key(&self) -> &'static str {
        providers::provider_named(self.name).unwrap().app_key
    }
    fn action(&self) -> &'static str {
        "search"
    }
    fn capability(&self) -> capability::WebSearchCapability {
        let mut capability = ExaRestBackend.capability();
        if self.name == "deepseek" {
            capability.query_length.max = 128;
        }
        capability
    }
    fn vendor_args(&self, query: &WebSearchQuery, now_ms: i64) -> Value {
        self.preparations.fetch_add(1, Ordering::SeqCst);
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
}

fn service() -> WebSearchService {
    let mut service = WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW));
    for name in ["tavily", "deepseek"] {
        service = service.with_chain_backend(Arc::new(TestBackend {
            name,
            preparations: Arc::new(AtomicUsize::new(0)),
        }));
    }
    service
}

fn order(engine: &Engine, names: &[&str]) {
    engine
        .store()
        .set_web_search_order(
            &names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
}

fn add_connection(engine: &Engine, id: &str, provider: &str, caller: Option<&str>) {
    let store = engine.store();
    store
        .insert_connection(
            "direct",
            id,
            providers::provider_named(provider).unwrap().app_key,
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", id, b"test:search")
        .unwrap();
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    let schema = json!({"type":"object"});
    store
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: id.into(),
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
    if let Some(caller) = caller {
        store
            .insert_grant(&GrantInput {
                principal: "direct".into(),
                connection_id: id.into(),
                grant_id: format!("{id}-{caller}"),
                grantee_principal: caller.into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["search".into()],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
    }
}

fn search(
    service: &WebSearchService,
    engine: &Engine,
    caller: &str,
) -> Result<WebSearchResponse, WebSearchRefusal> {
    service.search(
        engine,
        caller,
        json!({"query":"weather report"}).as_object().unwrap(),
    )
}

fn unavailable(names: &[(&str, SkipReason)]) -> WebSearchRefusal {
    WebSearchRefusal::WebSearchUnavailable {
        providers: names
            .iter()
            .map(|(name, reason)| ProviderSkip {
                provider: name.to_string(),
                reason: *reason,
            })
            .collect(),
    }
}

#[test]
fn capability_precedes_grant_but_every_check_two_counts() {
    let (engine, transport) = super::super::tests::granted_exa_engine("chain-capability-order");
    order(&engine, &["deepseek", "exa"]);
    let service = service();
    let args = json!({"query":"x".repeat(200)});
    assert_eq!(
        service.search(&engine, "stranger", args.as_object().unwrap()),
        Err(WebSearchRefusal::NotGranted)
    );
    // Exa has an admitting grant, so the capability reason must now be visible.
    assert_eq!(
        service.search(&engine, "direct", args.as_object().unwrap()),
        Err(unavailable(&[
            ("deepseek", SkipReason::Capability),
            ("exa", SkipReason::Unavailable)
        ]))
    );
    assert_eq!(
        transport.requests().len(),
        1,
        "audit: {:?}",
        engine.store().list_audit("direct").unwrap()
    );
}

#[test]
fn all_ungranted_flow_uses_first_provider_and_its_own_cause() {
    let (engine, transport, path) =
        super::super::tests::granted_exa_engine_with_path("chain-first-grant-cause");
    let sql = rusqlite::Connection::open(&*path).unwrap();
    sql.execute(
        "UPDATE grants SET expires_at = 1 WHERE connection_id = 'exa'",
        [],
    )
    .unwrap();
    order(&engine, &["exa", "deepseek"]);
    let scope = CallScope {
        flow_id: Some("flow".into()),
        owner: "direct".into(),
        scope_ref: "head".into(),
        scope_epoch: 1,
        kind: None,
        parent: None,
        parent_state: None,
        agent_id: None,
        delegates: false,
        owner_authorized: true,
    };
    let result = service().search_scoped(
        &engine,
        "direct",
        json!({"query":"x".repeat(200)}).as_object().unwrap(),
        Some(&scope),
        None,
    );
    let Err(WebSearchRefusal::Grant(refusal)) = result else {
        panic!("expected first provider grant refusal: {result:?}")
    };
    let target = crate::grant_refusal::GrantTarget::decode(&refusal.detail().grant).unwrap();
    assert_eq!(target.tool, "web_search");
    assert_eq!(target.connection.as_deref(), Some("exa"));
    assert_eq!(target.grantee, "direct");
    assert_eq!(refusal.detail().cause, crate::grant_refusal::Cause::Expired);
    assert!(transport.requests().is_empty());
}

#[test]
fn ambiguous_alone_and_mixed_with_not_granted_are_unavailable() {
    let (engine, transport) = super::super::tests::granted_exa_engine("chain-ambiguous");
    add_connection(&engine, "exa-two", "exa", Some("direct"));
    let service = service();
    for name in ["exa", "tavily"] {
        engine.store().set_web_search_allowance(name, 1).unwrap();
    }
    for names in [&["exa"][..], &["exa", "tavily"][..]] {
        order(&engine, names);
        let mut expected = vec![("exa", SkipReason::Ambiguous)];
        if names.len() == 2 {
            expected.push(("tavily", SkipReason::NotGranted));
        }
        assert_eq!(
            search(&service, &engine, "direct"),
            Err(unavailable(&expected))
        );
        for name in names {
            assert_eq!(
                engine
                    .store()
                    .web_search_allowance_used(name, "direct", NOW)
                    .unwrap(),
                0
            );
        }
    }
    assert!(transport.requests().is_empty());
}

#[test]
fn grant_before_charge_preserves_every_provider_bucket() {
    let (engine, transport) = super::super::tests::granted_exa_engine("chain-grant-before-charge");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    order(&engine, &["exa", "tavily"]);
    let service = service();
    for name in ["exa", "tavily"] {
        engine
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
    for _ in 0..4 {
        assert_eq!(
            search(&service, &engine, "stranger"),
            Err(WebSearchRefusal::NotGranted)
        );
    }
    // The default mock reply has no search results array. Both providers
    // must dispatch before mapping fails: an ungranted caller must not have
    // spent either provider's shared bucket.
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(unavailable(&[
            ("exa", SkipReason::Unavailable),
            ("tavily", SkipReason::Unavailable),
        ]))
    );
    assert_eq!(
        transport.requests().len(),
        2,
        "audit: {:?}",
        engine.store().list_audit("direct").unwrap()
    );
}

#[test]
fn policy_status_connection_cooldown_then_rate_is_the_failure_order() {
    let (engine, transport, path) =
        super::super::tests::granted_exa_engine_with_path("chain-check-order");
    let sql = rusqlite::Connection::open(&*path).unwrap();
    order(&engine, &["exa"]);
    let service = service();
    let key = CallerKey {
        principal: "direct".into(),
        agent_id: None,
    };
    let limits = crate::storage::web_search_store::WebSearchLimits {
        per_caller_per_minute: 1,
        per_backend_per_minute: 1,
    };
    engine.store().set_web_search_limits("exa", limits).unwrap();
    service
        .limiter
        .try_acquire("exa", &key, limits, NOW)
        .unwrap();
    service
        .chain_cooldowns
        .lock()
        .unwrap()
        .insert("exa".into(), NOW + 60_000);
    sql.execute(
        "UPDATE connections SET status = 'auth_required' WHERE connection_id = 'exa'",
        [],
    )
    .unwrap();
    sql.execute(
        "UPDATE catalog_actions SET status = 'quarantined' WHERE connection_id = 'exa'",
        [],
    )
    .unwrap();
    engine
        .store()
        .set_policy("direct", "exa", "search", "block", None)
        .unwrap();
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(unavailable(&[("exa", SkipReason::Policy)]))
    );
    engine
        .store()
        .set_policy("direct", "exa", "search", "ask_first", None)
        .unwrap();
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(unavailable(&[("exa", SkipReason::Policy)]))
    );
    engine
        .store()
        .set_policy("direct", "exa", "search", "allow", None)
        .unwrap();
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(unavailable(&[("exa", SkipReason::Quarantined)]))
    );
    sql.execute(
        "UPDATE catalog_actions SET status = 'active' WHERE connection_id = 'exa'",
        [],
    )
    .unwrap();
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(unavailable(&[("exa", SkipReason::ConnectionUnusable)]))
    );
    sql.execute(
        "UPDATE connections SET status = 'active' WHERE connection_id = 'exa'",
        [],
    )
    .unwrap();
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(unavailable(&[("exa", SkipReason::Cooldown)]))
    );
    service.chain_cooldowns.lock().unwrap().clear();
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(WebSearchRefusal::RateLimited {
            retry_after_ms: 60_000
        })
    );
    assert!(transport.requests().is_empty());
}

#[test]
fn all_rate_limited_returns_smallest_retry() {
    let (engine, transport) = super::super::tests::granted_exa_engine("chain-rate-terminal");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    order(&engine, &["exa", "tavily"]);
    let service = service();
    let key = CallerKey {
        principal: "direct".into(),
        agent_id: None,
    };
    let limits = crate::storage::web_search_store::WebSearchLimits {
        per_caller_per_minute: 1,
        per_backend_per_minute: 1,
    };
    for (name, at) in [("exa", NOW - 30_000), ("tavily", NOW - 10_000)] {
        engine.store().set_web_search_limits(name, limits).unwrap();
        service.limiter.try_acquire(name, &key, limits, at).unwrap();
    }
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(WebSearchRefusal::RateLimited {
            retry_after_ms: 30_000
        })
    );
    assert!(transport.requests().is_empty());
}

#[test]
fn unheld_connector_home_is_authorize_unavailable_without_dispatch() {
    let (engine, transport) = super::super::tests::granted_exa_engine("chain-home");
    order(&engine, &["exa"]);
    let checks = Arc::new(AtomicUsize::new(0));
    let observed = checks.clone();
    let engine = engine.with_connector_home_guard(Arc::new(move || {
        observed.fetch_add(1, Ordering::SeqCst);
        Some(json!({"secret":"not held"}))
    }));
    let refusal = search(&service(), &engine, "direct").unwrap_err();
    assert_eq!(refusal, unavailable(&[("exa", SkipReason::Unavailable)]));
    assert_eq!(
        refusal.to_wire()["error"]["detail"],
        json!([{"provider":"exa", "reason":"unavailable"}])
    );
    assert!(transport.requests().is_empty());
    assert_eq!(
        checks.load(Ordering::SeqCst),
        1,
        "home gate must run once inside authorize"
    );
}

#[test]
fn validation_and_code_lookup_precede_all_provider_work() {
    let (engine, transport) = super::super::tests::granted_exa_engine("chain-once-only");
    order(&engine, &["exa", "tavily"]);
    let count = Arc::new(AtomicUsize::new(0));
    let service = service()
        .with_chain_backend(Arc::new(TestBackend {
            name: "exa",
            preparations: count.clone(),
        }))
        .with_chain_backend(Arc::new(TestBackend {
            name: "tavily",
            preparations: count.clone(),
        }));
    assert!(matches!(
        service.search(&engine, "direct", json!({"query":""}).as_object().unwrap()),
        Err(WebSearchRefusal::InvalidQuery { .. })
    ));
    assert_eq!(
        service.search(
            &engine,
            "direct",
            json!({"query":"site:github.com/a/b/blob/main/lib.rs"})
                .as_object()
                .unwrap()
        ),
        Err(WebSearchRefusal::CodeLookup)
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert!(transport.requests().is_empty());
}

#[test]
fn compatibility_refusals_survive_set_then_clear() {
    for scenario in [
        "not_granted",
        "flow_grant",
        "ambiguous",
        "quarantined",
        "ask_first",
        "blocked",
        "vendor_5xx",
        "unusable",
    ] {
        let (engine, transport, path) =
            super::super::tests::granted_exa_engine_with_path(&format!("compatibility-{scenario}"));
        let sql = rusqlite::Connection::open(&*path).unwrap();
        let service = service();
        let caller = if scenario == "not_granted" || scenario == "flow_grant" {
            "stranger"
        } else {
            "direct"
        };
        let scope = (scenario == "flow_grant").then(|| CallScope {
            flow_id: Some("flow".into()),
            owner: "direct".into(),
            scope_ref: "head".into(),
            scope_epoch: 1,
            kind: None,
            parent: None,
            parent_state: None,
            agent_id: None,
            delegates: false,
            owner_authorized: true,
        });
        let expected = match scenario {
            "not_granted" => WebSearchRefusal::NotGranted,
            "flow_grant" => WebSearchRefusal::Grant(crate::grant_refusal::GrantRefusal::new(
                WebSearchService::grant_target(caller),
                crate::grant_refusal::Cause::Missing,
            )),
            "ambiguous" => {
                add_connection(&engine, "exa-two", "exa", Some("direct"));
                WebSearchRefusal::BackendAmbiguous
            }
            "quarantined" => {
                sql.execute("UPDATE catalog_actions SET status = 'quarantined'", [])
                    .unwrap();
                WebSearchRefusal::BackendQuarantined {
                    backend: "exa".into(),
                }
            }
            "ask_first" => {
                engine
                    .store()
                    .set_policy("direct", "exa", "search", "ask_first", None)
                    .unwrap();
                WebSearchRefusal::PerCallApprovalUnsupported
            }
            "blocked" => {
                engine
                    .store()
                    .set_policy("direct", "exa", "search", "block", None)
                    .unwrap();
                WebSearchRefusal::NotGranted
            }
            "unusable" => {
                engine
                    .store()
                    .set_connection_health("direct", "exa", "degraded", &json!({"healthy":false}))
                    .unwrap();
                WebSearchRefusal::BackendUnavailable {
                    backend: "exa".into(),
                }
            }
            "vendor_5xx" => {
                transport.set_response(crate::transport::MockResponse::VendorError {
                    code: "http_503".into(),
                    message: "vendor diagnostic must stay private".into(),
                });
                WebSearchRefusal::BackendUnavailable {
                    backend: "exa".into(),
                }
            }
            _ => unreachable!(),
        };
        let args = json!({"query":"weather report"});
        let before = service.search_scoped(
            &engine,
            caller,
            args.as_object().unwrap(),
            scope.as_ref(),
            None,
        );
        assert_eq!(before, Err(expected.clone()), "never-set: {scenario}");
        order(&engine, &["exa", "tavily"]);
        engine.store().clear_web_search_order().unwrap();
        assert_eq!(
            service.search_scoped(
                &engine,
                caller,
                args.as_object().unwrap(),
                scope.as_ref(),
                None
            ),
            before,
            "set-then-clear: {scenario}"
        );
        let wire = expected.to_wire().to_string();
        assert!(!wire.contains("web_search_unavailable"));
        assert!(!wire.contains("vendor diagnostic"));
        assert_eq!(
            transport.requests().len(),
            if scenario == "vendor_5xx" { 2 } else { 0 },
            "dispatch count: {scenario}"
        );
    }
}

#[test]
fn compatibility_keeps_exa_cache_bucket_and_audit_without_chain_state() {
    let (engine, transport) = super::super::tests::granted_exa_engine("compatibility-state");
    let service = service();
    engine.store().set_web_search_allowance("exa", 1).unwrap();
    service
        .chain_cooldowns
        .lock()
        .unwrap()
        .insert("exa".into(), NOW + 60_000);
    let args = json!({"query":"weather report"});
    let query = WebSearchQuery::parse(args.as_object().unwrap()).unwrap();
    service.cache.put(CacheKey::new("exa", &query), vec![], NOW);
    engine
        .store()
        .set_web_search_limits(
            "exa",
            crate::storage::web_search_store::WebSearchLimits {
                per_caller_per_minute: 2,
                per_backend_per_minute: 2,
            },
        )
        .unwrap();
    let before = search(&service, &engine, "direct").unwrap();
    assert!(before.cached);
    assert_eq!(before.backend, "exa");
    order(&engine, &["exa", "tavily"]);
    engine.store().clear_web_search_order().unwrap();
    assert_eq!(search(&service, &engine, "direct"), Ok(before));
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(WebSearchRefusal::RateLimited {
            retry_after_ms: 30_000
        })
    );
    let rows = engine.store().list_audit("direct").unwrap();
    for row in rows
        .iter()
        .filter(|row| row.gate.as_deref() == Some("web_search"))
    {
        assert_eq!(row.app_key.as_deref(), Some("exa_rest"));
        assert_eq!(row.connection_id.as_deref(), Some("exa"));
        assert_eq!(
            row.args_redaction_summary.as_deref(),
            Some("web_search query recorded in query_text; assertion and other arguments omitted")
        );
    }
    assert!(transport.requests().is_empty());
}

#[test]
fn authorize_denial_reasons_follow_legacy_mapping() {
    use crate::governance::{GrantDenial, PolicyDenial};
    let service = service();
    for (denial, reason) in [
        (Denial::Grant(GrantDenial::Missing), SkipReason::NotGranted),
        (Denial::Policy(PolicyDenial::AskFirst), SkipReason::Policy),
        (
            Denial::Catalog(CatalogDenial::Quarantined),
            SkipReason::Quarantined,
        ),
        (
            Denial::ConnectorHomeNotHeld {
                state: json!({"secret":"redacted"}),
            },
            SkipReason::Unavailable,
        ),
    ] {
        assert_eq!(
            SkipReason::for_refusal(&service.refusal_for_denial("direct", &denial)),
            reason
        );
    }
}

#[test]
fn first_serving_provider_stops_the_walk_even_when_empty() {
    let (engine, transport) = super::super::tests::granted_exa_engine("chain-first-serve");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    order(&engine, &["exa", "tavily"]);
    transport.set_response(crate::transport::MockResponse::Success(
        json!({"results":[]}),
    ));
    assert_eq!(
        search(&service(), &engine, "direct"),
        Ok(WebSearchResponse {
            results: vec![],
            backend: "exa".into(),
            cached: false,
        })
    );
    assert_eq!(transport.requests().len(), 1);
    let rows = engine.store().list_audit("direct").unwrap();
    let row = rows
        .iter()
        .find(|row| row.gate.as_deref() == Some("web_search"))
        .unwrap();
    assert_eq!(row.connection_id.as_deref(), Some("exa"));
    assert_eq!(
        serde_json::from_str::<Value>(row.args_redaction_summary.as_deref().unwrap()).unwrap(),
        json!({"served_by":"exa","skipped":[]})
    );
}

#[test]
fn connection_resolution_is_per_caller_not_per_provider() {
    let (engine, transport) = super::super::tests::granted_exa_engine("chain-per-caller");
    add_connection(&engine, "exa-two", "exa", Some("other"));
    order(&engine, &["exa"]);
    transport.set_response(crate::transport::MockResponse::Success(
        json!({"results":[]}),
    ));
    let service = service();
    assert!(search(&service, &engine, "direct").is_ok());
    assert!(search(&service, &engine, "other").is_ok());
    let requests = transport.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].connection_id, "exa");
    assert_eq!(requests[1].connection_id, "exa-two");
}

#[test]
fn compatibility_dispatch_ignores_exhausted_allowance_and_cooldown() {
    let (engine, transport) =
        super::super::tests::granted_exa_engine("compatibility-dormant-admission");
    engine.store().set_web_search_allowance("exa", 1).unwrap();
    let _reservation = engine
        .store()
        .reserve_web_search_allowance("exa", "direct", NOW)
        .unwrap();
    let service = service();
    service
        .chain_cooldowns
        .lock()
        .unwrap()
        .insert("exa".into(), NOW + 60_000);
    transport.set_response(crate::transport::MockResponse::Success(
        json!({"results":[]}),
    ));
    let before = search(&service, &engine, "direct").unwrap();
    assert!(!before.cached);
    order(&engine, &["exa", "tavily"]);
    engine.store().clear_web_search_order().unwrap();
    let after = service
        .search(
            &engine,
            "direct",
            json!({"query":"different weather report"})
                .as_object()
                .unwrap(),
        )
        .unwrap();
    assert!(!after.cached);
    assert_eq!(after.backend, "exa");
    assert_eq!(transport.requests().len(), 2);
    assert_eq!(
        engine
            .store()
            .web_search_allowance_used("exa", "direct", NOW)
            .unwrap(),
        1
    );
}
