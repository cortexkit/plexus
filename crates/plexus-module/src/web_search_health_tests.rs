//! The health report's `webSearch` section, and the search service the module
//! composes for production.

use super::*;
use plexus_core::storage::ConnectionRecord;
use plexus_core::web_search::backend::ReplyShapeError;
use plexus_core::web_search::capability::WebSearchCapability;
use plexus_core::web_search::{WebSearchBackend, WebSearchQuery, WebSearchResult};

/// Captures the real fleet log renderer's stderr in an isolated child process.
#[allow(dead_code)]
mod logging {
    include!("../../plexus-core/tests/support/logging.rs");
}

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
async fn health_lists_each_ordered_provider_with_its_position_presence_and_connections() {
    let fixture = Fixture::new("health-rows");
    add_owned_connection(&fixture, "other", "conn-exa-other", "exa_rest", json!({}));
    order(&fixture, &["exa", "tavily"]);
    let health = web_search_health(&state_of(fixture.runtime()));

    assert_eq!(health["order"], json!(["exa", "tavily"]), "{health}");
    assert_eq!(
        column(&health, "connection_id"),
        [json!(CONNECTION), json!("conn-exa-other"), Value::Null],
        "a provider with several connections gets one row per connection, across principals: {health}"
    );
    assert_eq!(
        column(&health, "principal"),
        [json!("direct"), json!("other"), Value::Null]
    );
    assert_eq!(
        column(&health, "provider"),
        [json!("exa"), json!("exa"), json!("tavily")]
    );
    assert_eq!(
        column(&health, "order_position"),
        [json!(1), json!(1), json!(2)],
        "order_position is the provider's place in the order, counting from 1"
    );
    assert_eq!(
        column(&health, "connection_present"),
        [json!(true), json!(true), json!(false)],
        "connection_present says whether the provider has a live connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_reports_each_owners_allowance_use_against_the_providers_limit() {
    let fixture = Fixture::new("health-allowance");
    add_owned_connection(&fixture, "other", "conn-exa-other", "exa_rest", json!({}));
    order(&fixture, &["exa", "tavily"]);
    fixture.store.set_web_search_allowance("exa", 5).unwrap();
    let reply = fixture
        .search(Principal::Direct, json!({"query": "allowance"}))
        .await;
    assert_eq!(reply["result"]["backend"], "exa", "{reply}");
    let health = web_search_health(&state_of(fixture.runtime()));

    assert_eq!(
        column(&health, "allowance_limit"),
        [json!(5), json!(5), Value::Null],
        "allowance_limit is the provider's monthly allowance, or null when none is set: {health}"
    );
    assert_eq!(
        column(&health, "allowance_used"),
        [json!(1), json!(0), Value::Null],
        "allowance_used is this month's count for the connection's owner: {health}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_reports_live_cooldowns_per_connection_and_zero_after_a_restart() {
    let fixture = Fixture::new("health-cooldown");
    add_owned_connection(&fixture, "other", "conn-exa-other", "exa_rest", json!({}));
    order(&fixture, &["exa"]);
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
        column(&health, "cooldown_remaining_ms"),
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
        column(&health, "cooldown_remaining_ms"),
        [json!(0), json!(0)],
        "cooldowns are held in memory, so a restarted module reports 0: {health}"
    );
}

/// Health with Exa ordered and its only connection moved to `status`.
fn health_with_only_connection(label: &str, status: &str) -> Value {
    let fixture = Fixture::new(label);
    order(&fixture, &["exa"]);
    let updated = Connection::open(fixture.path.as_ref() as &Path)
        .unwrap()
        .execute(
            "UPDATE connections SET status = ?1 WHERE connection_id = ?2",
            params![status, CONNECTION],
        )
        .unwrap();
    assert_eq!(updated, 1);
    web_search_health(&state_of(fixture.runtime()))
}

/// The single row of a provider with no connection that can serve a search.
fn absent_exa_row() -> Value {
    json!({"order": ["exa"], "providers": [{
        "provider": "exa",
        "order_position": 1,
        "connection_id": null,
        "principal": null,
        "connection_present": false,
        "cooldown_remaining_ms": 0,
        "allowance_used": null,
        "allowance_limit": null,
    }]})
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
async fn with_no_order_health_lists_no_providers() {
    let fixture = Fixture::new("health-no-order");
    let state = state_of(fixture.runtime());
    let before_refresh = serde_json::to_value(connector_home_health(&state)).unwrap();
    assert_eq!(before_refresh["metrics"]["webSearch"], Value::Null);
    assert_eq!(
        web_search_health(&state),
        json!({"order": null, "providers": []})
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
        column(&health, "connection_id"),
        [json!("conn-searxng")],
        "{health}"
    );
    assert_eq!(column(&health, "cooldown_remaining_ms"), [json!(60_000)]);
    assert_no_instance_or_vendor_text(&health.to_string(), "health");
}

/// Run in a child process by the diagnostics test below; on its own it is
/// the same search with logging left uninstalled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn searxng_diagnostics_fixture() {
    let (reply, health) = failing_searxng_search("health-searxng-log").await;
    assert_eq!(code(&reply), "web_search_unavailable", "{reply}");
    assert_eq!(column(&health, "connection_id"), [json!("conn-searxng")]);
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

/// Every `fetched_at` value in `value`, which records when the reply arrived
/// and so differs between otherwise identical runs.
fn fetched_at_values(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                match (key.as_str(), value) {
                    ("fetched_at", Value::String(at)) => found.push(at.clone()),
                    _ => fetched_at_values(value, found),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| fetched_at_values(item, found)),
        _ => {}
    }
}

/// `reply` serialized with every receipt time replaced by one placeholder.
fn without_receipt_times(reply: &Value) -> String {
    let mut found = Vec::new();
    fetched_at_values(reply, &mut found);
    let mut rendered = reply.to_string();
    for at in found {
        rendered = rendered.replace(&at, "<fetched_at>");
    }
    rendered
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_order_the_production_service_searches_as_exa_does() {
    let mut transcripts = Vec::new();
    for (label, service) in [
        ("compat-exa", WebSearchService::exa()),
        ("compat-production", WebSearchService::production()),
    ] {
        let mut fixture = Fixture::new(label);
        fixture.web_search = Arc::new(service);
        let mut replies = Vec::new();
        for _ in 0..2 {
            // The second search is answered from the cache.
            replies.push(
                fixture
                    .search(Principal::Direct, json!({"query": "rust async runtimes"}))
                    .await,
            );
        }
        let stranger = Principal::Reserved {
            module_id: "prefrontal-core".to_string(),
        };
        replies.push(fixture.search(stranger, json!({"query": "anything"})).await);
        fixture.transport.set_response(MockResponse::VendorError {
            code: "http_503".to_string(),
            message: "outage".to_string(),
        });
        replies.push(
            fixture
                .search(Principal::Direct, json!({"query": "outage"}))
                .await,
        );
        fixture.add_connection("conn-exa-second");
        fixture.grant("grant-second", "conn-exa-second", &Principal::Direct);
        replies.push(
            fixture
                .search(Principal::Direct, json!({"query": "ambiguous"}))
                .await,
        );
        let requests = fixture
            .transport
            .requests()
            .into_iter()
            .map(|request| (request.connection_id, request.action, request.args))
            .collect::<Vec<_>>();
        transcripts.push((
            replies
                .iter()
                .map(without_receipt_times)
                .collect::<Vec<_>>(),
            requests,
            format!("{:?}", fixture.audit()),
        ));
    }
    assert_eq!(
        transcripts[0]
            .0
            .iter()
            .map(|reply| reply.contains("\"error\""))
            .collect::<Vec<_>>(),
        [false, false, true, true, true],
        "the transcript covers a served search, a cache hit and three refusals"
    );
    assert_eq!(
        transcripts[0], transcripts[1],
        "with no order the production service must search exactly as WebSearchService::exa()"
    );
}
