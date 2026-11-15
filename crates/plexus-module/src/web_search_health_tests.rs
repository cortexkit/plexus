//! The health report's `webSearch` section, and the search service the module
//! composes for production.

use super::*;
use plexus_core::storage::ConnectionRecord;
use plexus_core::web_search::backend::ReplyShapeError;
use plexus_core::web_search::capability::WebSearchCapability;
use plexus_core::web_search::{WebSearchBackend, WebSearchQuery, WebSearchResult};

/// Captures the real fleet log renderer's stderr in an isolated child process.
use crate::test_logging as logging;

/// A SearXNG instance address, planted where a connection could carry one.
const INSTANCE_HOST: &str = "searx.internal.example";
const INSTANCE: &str = "https://searx.internal.example:8443/";
/// Text a vendor's error reply could carry; it must never be surfaced.
const VENDOR_TEXT: &str = "VENDOR-ERROR-BODY-7f3a";

fn state_of(runtime: ModuleRuntime) -> ModuleState {
    ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    }
}

/// The `webSearch` metric after one store refresh, as the control lane
/// answers a health check.
fn web_search_health(state: &ModuleState) -> Value {
    refresh_store_health(state, &health_probe_principals(state));
    let report = serde_json::to_value(connector_home_health(state)).unwrap();
    report["metrics"]["webSearch"].clone()
}

/// One column of the health rows, in row order.
fn column(health: &Value, name: &str) -> Vec<Value> {
    health["providers"]
        .as_array()
        .unwrap_or_else(|| panic!("webSearch has provider rows: {health}"))
        .iter()
        .map(|row| row[name].clone())
        .collect()
}

/// The rows of one provider, in row order.
fn rows_of(health: &Value, provider: &str) -> Vec<Value> {
    health["providers"]
        .as_array()
        .unwrap_or_else(|| panic!("webSearch has provider rows: {health}"))
        .iter()
        .filter(|row| row["provider"] == provider)
        .cloned()
        .collect()
}

/// One column of one provider's rows.
fn provider_column(health: &Value, provider: &str, name: &str) -> Vec<Value> {
    rows_of(health, provider)
        .iter()
        .map(|row| row[name].clone())
        .collect()
}

fn order(fixture: &Fixture, names: &[&str]) {
    fixture
        .store
        .set_web_search_order(
            &names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
}

/// A live connection to `app_key` owned by `owner`, with an active `search`
/// action and no grant to anyone. `resource_filters` is stored as given.
fn add_owned_connection(
    fixture: &Fixture,
    owner: &str,
    connection_id: &str,
    app_key: &str,
    resource_filters: Value,
) {
    let store = &fixture.store;
    store
        .insert_connection(owner, connection_id, app_key, "pending", &resource_filters)
        .unwrap();
    let instance = (app_key == "searxng_rest")
        .then(|| plexus_core::instance_url::InstanceUrl::parse(INSTANCE).unwrap());
    if instance.is_some() {
        let manifest = plexus_core::ingest_value(
            serde_json::from_str(
                &subc_jsonc::jsonc_to_json(include_str!("../../../catalog/searxng_rest.jsonc"))
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        store.upsert_manifest("system", &manifest).unwrap();
    }
    let ticket = store
        .create_binding_ticket_with_instance(
            owner,
            connection_id,
            "credential_reference",
            HANDLE,
            instance.as_ref(),
        )
        .unwrap();
    store
        .connect_with_ticket(owner, &ticket.ticket_id)
        .unwrap()
        .unwrap();
    let schema = json!({"type": "object"});
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: connection_id.to_string(),
            principal: owner.to_string(),
            name: "search".to_string(),
            title: None,
            schema: schema.clone(),
            schema_hash: jcs_sha256(&schema).unwrap(),
            risk: "read".to_string(),
            severity: "S1".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_lists_every_routed_provider_with_its_route_presence_and_connections() {
    let fixture = Fixture::new("health-rows");
    add_owned_connection(&fixture, "other", "conn-exa-other", "exa_rest", json!({}));
    // Connected, but with no routing catalog row, so never searched.
    add_owned_connection(&fixture, "direct", "conn-jina", "jina_rest", json!({}));
    // A stored order changes nothing and is not reported.
    order(&fixture, &["tavily", "exa"]);
    let health = web_search_health(&state_of(fixture.runtime()));

    assert!(health.get("order").is_none(), "{health}");
    assert_eq!(
        column(&health, "provider"),
        ["exa", "exa", "tavily", "brave", "deepseek", "kimi", "ollama", "jina"]
            .map(|name| json!(name)),
        "every routed provider in table order, then connected unrouted ones: {health}"
    );
    assert_eq!(
        column(&health, "connection_id"),
        [
            json!(CONNECTION),
            json!("conn-exa-other"),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            json!("conn-jina")
        ],
        "a provider with several connections gets one row per connection, across principals: {health}"
    );
    assert_eq!(
        provider_column(&health, "exa", "principal"),
        [json!("direct"), json!("other")]
    );
    assert_eq!(
        column(&health, "route")[..3],
        [
            json!({"provider": "exa", "model": "search"}),
            json!({"provider": "exa", "model": "search"}),
            json!({"provider": "tavily", "model": "search"}),
        ]
    );
    assert_eq!(
        provider_column(&health, "kimi", "route"),
        [json!({"provider": "kimi-for-coding", "model": "search"})]
    );
    assert_eq!(provider_column(&health, "jina", "route"), [Value::Null]);
    assert_eq!(
        column(&health, "connection_present"),
        [true, true, false, false, false, false, false, true].map(|present| json!(present)),
        "connection_present says whether the provider has a live connection"
    );
    assert!(
        column(&health, "order_position").iter().all(Value::is_null),
        "rows no longer carry an order position: {health}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_reports_each_owners_allowance_use_against_the_providers_limit() {
    let fixture = Fixture::new("health-allowance");
    add_owned_connection(&fixture, "other", "conn-exa-other", "exa_rest", json!({}));
    fixture.store.set_web_search_allowance("exa", 5).unwrap();
    let reply = fixture
        .search(Principal::Direct, json!({"query": "allowance"}))
        .await;
    assert_eq!(reply["result"]["backend"], "exa", "{reply}");
    let health = web_search_health(&state_of(fixture.runtime()));

    assert_eq!(
        column(&health, "allowance_limit")[..3],
        [json!(5), json!(5), Value::Null],
        "allowance_limit is the provider's monthly allowance, or null when none is set: {health}"
    );
    assert_eq!(
        column(&health, "allowance_used")[..3],
        [json!(1), json!(0), Value::Null],
        "allowance_used is this month's count for the connection's owner: {health}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_reports_live_cooldowns_per_connection_and_zero_after_a_restart() {
    let fixture = Fixture::new("health-cooldown");
    add_owned_connection(&fixture, "other", "conn-exa-other", "exa_rest", json!({}));
    fixture.transport.set_response(MockResponse::VendorError {
        code: "http_503".to_string(),
        message: "outage".to_string(),
    });
    let reply = fixture
        .search(Principal::Direct, json!({"query": "cooldown"}))
        .await;
    assert_eq!(code(&reply), "web_search_unavailable", "{reply}");
    let health = web_search_health(&state_of(fixture.runtime()));
    assert_eq!(
        provider_column(&health, "exa", "cooldown_remaining_ms"),
        [json!(60_000), json!(0)],
        "cooldown_remaining_ms counts down the failed connection's cooldown only: {health}"
    );

    // A restarted module builds a new search service over the same store.
    let mut restarted = fixture.runtime();
    restarted.web_search = Arc::new(WebSearchService::with_clock(
        Arc::new(ExaRestBackend),
        Arc::new(|| NOW_MS),
    ));
    let health = web_search_health(&state_of(restarted));
    assert_eq!(
        provider_column(&health, "exa", "cooldown_remaining_ms"),
        [json!(0), json!(0)],
        "cooldowns are held in memory, so a restarted module reports 0: {health}"
    );
}

/// Exa's health rows with its only connection moved to `status`.
fn health_with_only_connection(label: &str, status: &str) -> Vec<Value> {
    let fixture = Fixture::new(label);
    let updated = Connection::open(fixture.path.as_ref() as &Path)
        .unwrap()
        .execute(
            "UPDATE connections SET status = ?1 WHERE connection_id = ?2",
            params![status, CONNECTION],
        )
        .unwrap();
    assert_eq!(updated, 1);
    rows_of(&web_search_health(&state_of(fixture.runtime())), "exa")
}

/// The single row of a provider with no connection that can serve a search.
fn absent_exa_row() -> Vec<Value> {
    vec![json!({
        "provider": "exa",
        "route": {"provider": "exa", "model": "search"},
        "connection_id": null,
        "principal": null,
        "connection_present": false,
        "cooldown_remaining_ms": 0,
        "allowance_used": null,
        "allowance_limit": null,
    })]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_whose_only_connection_is_revoked_has_no_connection_present() {
    assert_eq!(
        health_with_only_connection("health-revoked", "revoked"),
        absent_exa_row(),
        "a revoked connection cannot serve a search, so health reports none present"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_whose_only_connection_is_disabled_has_no_connection_present() {
    assert_eq!(
        health_with_only_connection("health-disabled", "disabled"),
        absent_exa_row(),
        "a disabled connection cannot serve a search, so health reports none present"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_is_null_until_the_store_is_read() {
    let fixture = Fixture::new("health-unread");
    let state = state_of(fixture.runtime());
    let before_refresh = serde_json::to_value(connector_home_health(&state)).unwrap();
    assert_eq!(before_refresh["metrics"]["webSearch"], Value::Null);
    assert!(web_search_health(&state)["providers"].is_array());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_reports_the_routing_look_and_the_declared_routes() {
    use plexus_core::web_search::routing::fake::FakeRouter;
    use plexus_core::web_search::routing::{Discovery, DiscoveryOutcome, RouteRef};
    let all_routes = json!([
        {"provider": "brave", "model": "web-search"},
        {"provider": "deepseek", "model": "search"},
        {"provider": "exa", "model": "search"},
        {"provider": "kimi-for-coding", "model": "search"},
        {"provider": "ollama-cloud", "model": "web-search"},
        {"provider": "tavily", "model": "search"},
    ]);

    // A module that could not open its daemon route has nothing to look over.
    let mut fixture = Fixture::new("health-routing");
    fixture.web_search = Arc::new(WebSearchService::production());
    let health = web_search_health(&state_of(fixture.runtime()));
    assert_eq!(
        health["routing"],
        json!({"discovery": "unreachable", "provider": null, "at_ms": null})
    );
    // Without a declaration update, HELLO's declaration of every row stands.
    assert_eq!(
        health["routes"],
        json!({"declared": all_routes, "updated_at_ms": null})
    );

    let router = Arc::new(FakeRouter::ranked(Vec::new()));
    fixture.web_search = Arc::new(WebSearchService::production().with_router(router.clone()));
    let health = web_search_health(&state_of(fixture.runtime()));
    assert_eq!(
        health["routing"],
        json!({"discovery": null, "provider": null, "at_ms": null}),
        "no look has been made before the first search that needs routing"
    );
    for (outcome, provider, name) in [
        (DiscoveryOutcome::Found, Some("striatum"), "found"),
        (DiscoveryOutcome::None, None, "none"),
        (DiscoveryOutcome::Several, None, "several"),
        (DiscoveryOutcome::Unreachable, None, "unreachable"),
    ] {
        router.set_discovery(Some(Discovery {
            outcome,
            provider: provider.map(str::to_owned),
            at_ms: NOW_MS,
        }));
        let health = web_search_health(&state_of(fixture.runtime()));
        assert_eq!(
            health["routing"],
            json!({"discovery": name, "provider": provider, "at_ms": NOW_MS})
        );
    }

    // An accepted update replaces the declared set and stamps its time.
    let snapshot =
        crate::web_search_health::snapshot(&fixture.store, &["direct".to_string()], NOW_MS)
            .unwrap();
    let rendered = crate::web_search_health::render(
        Some(&snapshot),
        &fixture.web_search,
        Some(&crate::search_declarations::DeclarationStatus {
            routes: vec![RouteRef::new("exa", "search")],
            updated_at_ms: Some(NOW_MS + 1),
        }),
    );
    assert_eq!(
        rendered["routes"],
        json!({"declared": [{"provider": "exa", "model": "search"}], "updated_at_ms": NOW_MS + 1})
    );
}

/// A SearXNG stand-in whose instance address is the planted one, so a chain
/// search over it has an address in hand.
struct SearxngBackend;

impl WebSearchBackend for SearxngBackend {
    fn name(&self) -> &'static str {
        "searxng"
    }
    fn app_key(&self) -> &'static str {
        "searxng_rest"
    }
    fn action(&self) -> &'static str {
        "search"
    }
    fn capability(&self) -> WebSearchCapability {
        ExaRestBackend.capability()
    }
    fn vendor_args(&self, query: &WebSearchQuery, now_ms: i64) -> Value {
        ExaRestBackend.vendor_args(query, now_ms)
    }
    fn map_reply(
        &self,
        reply: &Value,
        max_results: usize,
        fetched_at_ms: i64,
    ) -> Result<Vec<WebSearchResult>, ReplyShapeError> {
        ExaRestBackend.map_reply(reply, max_results, fetched_at_ms)
    }
    fn instance_url(&self, _connection: &ConnectionRecord) -> Option<String> {
        Some(INSTANCE.to_string())
    }
}

/// Run a failing SearXNG chain search, then report health; return the tool
/// reply and the health value. In the diagnostics child the same run also
/// writes whatever it logs to stderr.
async fn failing_searxng_search(label: &str) -> (Value, Value) {
    logging::init_child();
    let mut fixture = Fixture::new(label);
    fixture.web_search = Arc::new(
        WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW_MS))
            .with_stored_order_router_for_test()
            .with_chain_backend(Arc::new(SearxngBackend)),
    );
    add_owned_connection(
        &fixture,
        "direct",
        "conn-searxng",
        "searxng_rest",
        json!({"required": [], "optional": [], "write_enabling": [], "instance": INSTANCE}),
    );
    fixture.grant("grant-searxng", "conn-searxng", &Principal::Direct);
    order(&fixture, &["searxng"]);
    fixture.transport.set_response(MockResponse::VendorError {
        code: "http_502".to_string(),
        message: format!("{INSTANCE}search?q=leak answered: {VENDOR_TEXT}"),
    });
    let reply = fixture
        .search(Principal::Direct, json!({"query": "private instance"}))
        .await;
    let health = web_search_health(&state_of(fixture.runtime()));
    (reply, health)
}

fn assert_no_instance_or_vendor_text(rendered: &str, what: &str) {
    for leak in [INSTANCE_HOST, VENDOR_TEXT, "http_502"] {
        assert!(
            !rendered.contains(leak),
            "{what} must not print {leak:?}: {rendered}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_and_the_unavailable_detail_never_print_an_instance_address_or_vendor_text() {
    let (reply, health) = failing_searxng_search("health-searxng").await;
    assert_eq!(code(&reply), "web_search_unavailable", "{reply}");
    assert_eq!(
        reply["error"]["detail"],
        json!([{"provider": "searxng", "reason": "unavailable"}])
    );
    assert_no_instance_or_vendor_text(&reply.to_string(), "the web_search_unavailable reply");
    assert_eq!(
        provider_column(&health, "searxng", "connection_id"),
        [json!("conn-searxng")],
        "{health}"
    );
    assert_eq!(
        provider_column(&health, "searxng", "cooldown_remaining_ms"),
        [json!(60_000)]
    );
    assert_no_instance_or_vendor_text(&health.to_string(), "health");
}

/// Run in a child process by the diagnostics test below; on its own it is
/// the same search with logging left uninstalled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn searxng_diagnostics_fixture() {
    let (reply, health) = failing_searxng_search("health-searxng-log").await;
    assert_eq!(code(&reply), "web_search_unavailable", "{reply}");
    assert_eq!(
        provider_column(&health, "searxng", "connection_id"),
        [json!("conn-searxng")]
    );
    // A known last line: the parent test finds it to show the child's stderr
    // really carries the module's log lines.
    eprintln!(warn health: "searxng diagnostics fixture finished");
}

#[test]
fn diagnostics_never_print_an_instance_address_or_vendor_text() {
    let output = bounded::child_output(
        std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "web_search_tests::health_report::searxng_diagnostics_fixture",
                "--nocapture",
            ])
            .env("PLEXUS_LOG_STDERR_CHILD", "1"),
        std::time::Duration::from_secs(60),
        "searxng diagnostics child",
    )
    .expect("run diagnostics fixture");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout} {stderr}");
    assert!(stdout.contains("1 passed"), "the fixture ran: {stdout}");
    assert!(
        stderr.contains("plexus.health: searxng diagnostics fixture finished"),
        "the child's stderr carries the module's log lines: {stderr}"
    );
    assert_no_instance_or_vendor_text(&stderr, "diagnostics");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exa_only_install_searches_through_routing() {
    use plexus_core::web_search::routing::{fake::FakeRouter, RouteRef};
    let router = Arc::new(FakeRouter::ranked(vec![RouteRef::new("exa", "search")]));
    let mut fixture = Fixture::new("exa-only-routed");
    fixture.web_search = Arc::new(WebSearchService::production().with_router(router.clone()));
    let served = fixture
        .search(Principal::Direct, json!({"query": "rust async runtimes"}))
        .await;
    assert_eq!(served["result"]["backend"], "exa", "{served}");
    assert_eq!(served["result"]["cached"], false, "{served}");
    // Exa is the only provider with a connection, so it is all plexus offers.
    assert_eq!(
        router.params("route.select"),
        [json!({
            "allowance_left": [],
            "consumer": "plexus.web_search",
            "eligible_routes": [{"model": "search", "provider": "exa"}],
            "kind": "search",
            "privacy": "remote_allowed",
            "requirements": {"iq": 75},
        })]
    );
    assert_eq!(fixture.transport.requests().len(), 1);
}
