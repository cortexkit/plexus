//! Synthetic MCP contract fixtures exercised through real remote transport and
//! governed dispatch. No live provider, key, or schema discovery is contacted.

use super::*;
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::mcp_remote::{McpRemoteConfig, McpRemoteTransport};
use crate::transport::{TransportRequest, TransportResponse};
use std::sync::Mutex;

const CONNECTION: &str = "zai-mcp";
const ACTION: &str = "web_search_prime";

#[derive(Default)]
struct Vault {
    reads: Mutex<Vec<String>>,
    failures: Mutex<Vec<u16>>,
}
impl CredentialSource for Vault {
    fn get_by_id(&self, id: &str) -> Result<ResolvedCredential, CredentialError> {
        self.reads.lock().unwrap().push(id.into());
        Ok(ResolvedCredential::new(b"zai-test-key".to_vec(), None, 1))
    }
    fn report_id_auth_failure(&self, _: &str, status: u16) {
        self.failures.lock().unwrap().push(status);
    }
}

fn fixtures() -> Value {
    serde_json::from_str(include_str!("../../backend/zai/fixtures.json")).unwrap()
}
fn schema(field: &str, count: bool) -> Value {
    let mut schema =
        json!({"type":"object", "properties":{}, "required":[field], "additionalProperties":false});
    schema["properties"][field] = json!({"type":"string"});
    if count {
        schema["properties"]["count"] = json!({"type":"integer"});
    }
    schema
}
fn connect(engine: &Engine, schema: Value) {
    let store = engine.store();
    store
        .insert_connection(
            "direct",
            CONNECTION,
            "zai",
            "pending",
            &json!({"required":[],"optional":[],"write_enabling":[]}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", CONNECTION, b"apikey:zai")
        .unwrap();
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    store
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: CONNECTION.into(),
            name: ACTION.into(),
            title: None,
            schema_hash: crate::jcs_sha256(&schema).unwrap(),
            schema,
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
            connection_id: CONNECTION.into(),
            grant_id: "zai-grant".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec![ACTION.into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    order(engine, &["zai"]);
    store.set_web_search_allowance("zai", 10).unwrap();
}
fn service() -> WebSearchService {
    WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(ZaiMcpBackend::default()))
}
fn run<C: CredentialSource, T: crate::transport::Transport>(
    service: &WebSearchService,
    engine: &GovernanceEngine<C, T>,
    args: Value,
) -> Result<WebSearchResponse, WebSearchRefusal> {
    service.search(engine, "direct", args.as_object().unwrap())
}

struct Recorded {
    result: Result<WebSearchResponse, WebSearchRefusal>,
    service: WebSearchService,
    requests: Vec<String>,
    vault: Arc<Vault>,
    used: u32,
}
fn recorded(record: &str, field: &str, count: bool) -> Recorded {
    recorded_with_setup_delay(record, field, count, std::time::Duration::ZERO)
}

fn recorded_with_setup_delay(
    record: &str,
    field: &str,
    count: bool,
    setup_delay: std::time::Duration,
) -> Recorded {
    let reply = fixtures()[record].clone();
    let calls = if record == "unauthorized" { 2 } else { 1 };
    // Auth rejection initializes a second session before the one permitted resend.
    let expected = if calls == 2 { 6 } else { 3 };
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let (endpoint, server) = crate::test_http::FixedRequestServer::start(
        expected,
        "zai",
        move |_, request| {
            captured.lock().unwrap().push(request.to_string());
            let input: Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            let (status, body, headers) = match input["method"].as_str().unwrap() {
            "initialize" => (200, json!({"jsonrpc":"2.0","id":input["id"],"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"zai-fixture","version":"1"}}}).to_string(), ""),
            "notifications/initialized" => (202, String::new(), ""),
            "tools/call" => {
                let status = reply["status"].as_u64().unwrap_or(200);
                let body = if let Some(raw) = reply["raw"].as_str() { raw.into() }
                    else if status != 200 { reply["body"].to_string() }
                    else {
                        let mut envelope = reply.clone();
                        envelope["jsonrpc"] = json!("2.0"); envelope["id"] = input["id"].clone(); envelope.to_string()
                    };
                (status, body, reply["headers"].as_str().unwrap_or(""))
            },
            method => panic!("unexpected MCP method {method}"),
        };
            format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        },
    );
    // The listener already exists while the durable store is being prepared.
    // Model a disk stall without consuming a CPU or changing MCP response timing.
    std::thread::sleep(setup_delay);
    let (fixture, _) = super::super::super::tests::granted_exa_engine(&format!("zai-{record}"));
    connect(&fixture, schema(field, count));
    let manifest = crate::manifest::ingest_value(
        serde_json::from_str(
            &subc_jsonc::jsonc_to_json(include_str!("../../../../../../catalog/zai.jsonc"))
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
    .manifest;
    let mut config = McpRemoteConfig::from_manifest(&manifest);
    config.endpoint = endpoint;
    let vault = Arc::new(Vault::default());
    let engine = GovernanceEngine::new(
        fixture.store().clone(),
        vault.clone(),
        Arc::new(McpRemoteTransport::new(config)),
    );
    let service = service();
    let result = run(
        &service,
        &engine,
        json!({"query":"weather report", "max_results":1}),
    );
    server
        .join()
        .unwrap_or_else(|error| panic!("{record}: {error}; {result:?}"));
    let requests = requests.lock().unwrap().clone();
    let used = engine
        .store()
        .web_search_allowance_used("zai", "direct", NOW)
        .unwrap();
    Recorded {
        result,
        service,
        requests,
        vault,
        used,
    }
}

#[test]
fn mcp_fixture_waits_for_durable_preparation_before_session_initialization() {
    let record = recorded_with_setup_delay(
        "success",
        "query",
        true,
        crate::bounded::WAIT + std::time::Duration::from_millis(500),
    );
    assert!(record.result.is_ok(), "{:?}", record.result);
    assert_eq!(record.requests.len(), 3);
}

#[test]
fn mcp_serve_uses_reviewed_fields_bearer_vault_and_one_search_call() {
    for (field, count) in [
        ("query", true),
        ("search_query", true),
        ("query", false),
        ("search_query", false),
    ] {
        let record = recorded("success", field, count);
        let response = record.result.unwrap();
        assert_eq!(response.backend, "zai");
        assert_eq!(
            response.results.len(),
            1,
            "count is always enforced locally"
        );
        assert_eq!(response.results[0].url, "https://example.com/search");
        assert_eq!(response.results[0].excerpt, "Source excerpt.");
        assert_eq!(record.used, 1);
        assert!(record.service.chain_cooldowns.lock().unwrap().is_empty());
        assert_eq!(*record.vault.reads.lock().unwrap(), ["apikey:zai"]);
        let calls: Vec<_> = record
            .requests
            .iter()
            .filter_map(|request| {
                assert!(request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("authorization: Bearer zai-test-key")));
                let body: Value =
                    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
                (body["method"] == "tools/call").then_some(body)
            })
            .collect();
        assert_eq!(
            calls.len(),
            1,
            "schema adaptation must not retry argument shapes"
        );
        assert_eq!(calls[0]["params"]["name"], ACTION);
        let mut expected = json!({});
        expected[field] = json!("weather report");
        if count {
            expected["count"] = json!(1);
        }
        assert_eq!(calls[0]["params"]["arguments"], expected);
    }
}

#[test]
fn mcp_empty_serves_and_invalid_requests_are_terminal() {
    let record = recorded("empty", "query", true);
    assert!(record.result.unwrap().results.is_empty());
    assert!(record.service.chain_cooldowns.lock().unwrap().is_empty());
    for name in ["bad_request", "unprocessable"] {
        let record = recorded(name, "query", true);
        assert_eq!(
            record.result,
            Err(WebSearchRefusal::RequestRejected {
                backend: "zai".into()
            })
        );
        assert!(record.service.chain_cooldowns.lock().unwrap().is_empty());
        assert!(record.vault.failures.lock().unwrap().is_empty());
    }
}

#[test]
fn mcp_other_errors_have_closed_outcomes_and_cooldowns() {
    for (name, reason, cooldown) in [
        ("rpc_quota", SkipReason::Unavailable, 60_000),
        ("rpc_credits", SkipReason::Unavailable, 60_000),
        ("rpc_balance", SkipReason::Unavailable, 60_000),
        ("tool_quota", SkipReason::Unavailable, 60_000),
        ("rpc_unavailable", SkipReason::Unavailable, 60_000),
        ("tool_unavailable", SkipReason::Unavailable, 60_000),
        ("payment_required", SkipReason::Quota, 3_600_000),
        ("unauthorized", SkipReason::Credential, 60_000),
        ("forbidden", SkipReason::Unavailable, 60_000),
        ("rate_limited", SkipReason::Throttled, 60_000),
        ("rate_limited_retry", SkipReason::Throttled, 7_000),
        ("server_error", SkipReason::Unavailable, 60_000),
        ("malformed", SkipReason::Unavailable, 60_000),
        ("invalid_json", SkipReason::Unavailable, 60_000),
        ("no_body", SkipReason::Unavailable, 60_000),
        ("rpc_timeout", SkipReason::Unavailable, 60_000),
    ] {
        let record = recorded(name, "query", true);
        assert_eq!(
            record.result,
            Err(unavailable(&[("zai", reason)])),
            "{name}"
        );
        assert_eq!(
            record
                .service
                .chain_cooldowns
                .lock()
                .unwrap()
                .get(CONNECTION),
            Some(&(NOW + cooldown)),
            "{name}"
        );
        assert_eq!(
            *record.vault.failures.lock().unwrap(),
            if name == "unauthorized" {
                vec![401]
            } else {
                vec![]
            },
            "{name}"
        );
    }
}

#[test]
fn capability_skips_filters_and_missing_reviewed_query_without_side_effects() {
    let filter = fixtures()["capability_skip"].clone();
    for (name, schema, args) in [
        ("domain", schema("query", true), filter),
        (
            "recency",
            schema("query", true),
            json!({"query":"weather report", "recency":"day"}),
        ),
        (
            "schema",
            json!({"type":"object", "properties":{"count":{"type":"integer"}},"additionalProperties":false}),
            json!({"query":"weather report"}),
        ),
    ] {
        let (engine, transport) =
            super::super::super::tests::granted_exa_engine(&format!("zai-skip-{name}"));
        connect(&engine, schema);
        let service = service();
        assert_eq!(
            run(&service, &engine, args),
            Err(unavailable(&[("zai", SkipReason::Capability)])),
            "{name}"
        );
        assert!(transport.requests().is_empty(), "{name} must not dispatch");
        assert_eq!(
            engine
                .store()
                .web_search_allowance_used("zai", "direct", NOW)
                .unwrap(),
            0
        );
        assert!(service.chain_cooldowns.lock().unwrap().is_empty());
    }
}

struct HookTrap;
impl WebSearchBackend for HookTrap {
    fn name(&self) -> &'static str {
        "zai"
    }
    fn app_key(&self) -> &'static str {
        "zai"
    }
    fn action(&self) -> &'static str {
        ACTION
    }
    fn capability(&self) -> capability::WebSearchCapability {
        ZaiMcpBackend::default().capability()
    }
    fn vendor_args(&self, query: &WebSearchQuery, now: i64) -> Value {
        ZaiMcpBackend::default().vendor_args(query, now)
    }
    fn map_reply(
        &self,
        reply: &Value,
        count: usize,
        now: i64,
    ) -> Result<Vec<WebSearchResult>, backend::ReplyShapeError> {
        ZaiMcpBackend::default().map_reply(reply, count, now)
    }
    fn prepare_reviewed(
        &self,
        _: capability::PreparedSearch,
        _: Option<&Value>,
        _: &str,
    ) -> Result<capability::PreparedSearch, capability::CapabilitySkip> {
        panic!("quarantined Z.AI action reached schema hook")
    }
}

#[test]
fn quarantined_zai_never_reaches_schema_hook() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("zai-quarantined");
    connect(&engine, schema("query", true));
    let changed = schema("search_query", false);
    engine
        .store()
        .refresh_catalog_action(CatalogActionInput {
            principal: "direct".into(),
            connection_id: CONNECTION.into(),
            name: ACTION.into(),
            title: None,
            schema_hash: crate::jcs_sha256(&changed).unwrap(),
            schema: changed,
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    let action = engine
        .store()
        .catalog_action("direct", CONNECTION, ACTION)
        .unwrap()
        .unwrap();
    assert_eq!(action.status, "quarantined");
    assert_eq!(
        action.quarantine_reason.as_deref(),
        Some("schema_changed_requires_review")
    );
    let service = WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(HookTrap));
    assert_eq!(
        run(&service, &engine, json!({"query":"weather report"})),
        Err(unavailable(&[("zai", SkipReason::Quarantined)]))
    );
    assert!(transport.requests().is_empty());
    assert_eq!(
        engine
            .store()
            .web_search_allowance_used("zai", "direct", NOW)
            .unwrap(),
        0
    );
    assert!(service.chain_cooldowns.lock().unwrap().is_empty());
}

struct LocalOutcome(TransportResponse);
impl crate::transport::Transport for LocalOutcome {
    fn dispatch(&self, _: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
        self.0.clone()
    }
}

#[test]
fn local_outcomes_release_unsent_allowance_and_preserve_closed_reasons() {
    for record in fixtures()["local_outcomes"].as_array().unwrap() {
        let (fixture, _) = super::super::super::tests::granted_exa_engine("zai-local");
        connect(&fixture, schema("query", true));
        let mut response = TransportResponse::success(Value::Null);
        response.response = None;
        response.transmission = match record["transmission"].as_str().unwrap() {
            "not_sent" => crate::transport::TransmissionState::NotSent,
            "unknown" => crate::transport::TransmissionState::OutcomeUnknown,
            _ => crate::transport::TransmissionState::Sent,
        };
        response.retry_after_ms = record["retry"].as_u64();
        response.error_code = record["code"].as_str().map(str::to_string);
        let engine = GovernanceEngine::new(
            fixture.store().clone(),
            Arc::new(Vault::default()),
            Arc::new(LocalOutcome(response)),
        );
        let service = service();
        let reason = if record["reason"] == "throttled" {
            SkipReason::Throttled
        } else {
            SkipReason::Unavailable
        };
        assert_eq!(
            run(&service, &engine, json!({"query":"weather report"})),
            Err(unavailable(&[("zai", reason)])),
            "{}",
            record["name"]
        );
        assert_eq!(
            service.chain_cooldowns.lock().unwrap().get(CONNECTION),
            Some(&(NOW + record["cooldown"].as_i64().unwrap()))
        );
        assert_eq!(
            u64::from(
                engine
                    .store()
                    .web_search_allowance_used("zai", "direct", NOW)
                    .unwrap()
            ),
            record["used"].as_u64().unwrap()
        );
    }
}
