//! Firecrawl's documented replies, sent through the real REST transport built
//! from the shipped `catalog/firecrawl_rest.jsonc`, and how the chain treats
//! each; plus the capability skip that keeps a query Firecrawl cannot take
//! from counting its allowance or cooling it down, and the check that
//! connections of the existing MCP app `firecrawl` never serve REST search.

use super::*;
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::rest_api::{RestConfig, RestTransport};
use crate::web_search::backend::FirecrawlRestBackend;
use std::sync::Mutex;

const CONNECTION: &str = "firecrawl-rest";

/// Records which vault credential each dispatch asked for, and every
/// authentication failure reported back to the vault.
#[derive(Default)]
struct RecordingVault {
    requested: Mutex<Vec<String>>,
    auth_failures: Mutex<Vec<u16>>,
}

impl CredentialSource for RecordingVault {
    fn get_by_id(&self, id: &str) -> Result<ResolvedCredential, CredentialError> {
        self.requested.lock().unwrap().push(id.to_string());
        Ok(ResolvedCredential::new(
            b"test-credential".to_vec(),
            None,
            7,
        ))
    }
    fn report_id_auth_failure(&self, _: &str, status: u16) {
        self.auth_failures.lock().unwrap().push(status);
    }
}

fn shipped_manifest() -> crate::manifest::AppManifest {
    let source = include_str!("../../../../../../catalog/firecrawl_rest.jsonc");
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

/// Connect `connection` of `app_key` for the `direct` principal, which owns
/// it and is the caller every search in these tests runs as. The connection
/// is bound to the vault credential `credential`, with `action` reviewed under
/// `schema` and an invoke grant for `action` to `direct`.
fn connect(
    store: &PlexusStore,
    connection: &str,
    app_key: &str,
    credential: &[u8],
    action: &str,
    schema: Value,
) {
    store
        .insert_connection(
            "direct",
            connection,
            app_key,
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", connection, credential)
        .unwrap();
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    store
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: connection.into(),
            name: action.into(),
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
            connection_id: connection.into(),
            grant_id: format!("{connection}-direct"),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec![action.into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
}

fn firecrawl_service() -> WebSearchService {
    WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(FirecrawlRestBackend))
}

struct Recorded {
    result: Result<WebSearchResponse, WebSearchRefusal>,
    service: WebSearchService,
    /// The request sent in Firecrawl's attempt.
    request: String,
    vault: Arc<RecordingVault>,
    /// The chain fields of the call's `web_search` audit row.
    audit: Option<Value>,
}

impl Recorded {
    fn cooldown(&self) -> Option<i64> {
        self.service
            .chain_cooldowns
            .lock()
            .unwrap()
            .get(CONNECTION)
            .map(|until| until - NOW)
    }
}

/// One search with order `firecrawl`, answered by the recorded reply `record`.
fn recorded_search(record: &str) -> Recorded {
    recorded_walk(record, &["firecrawl"])
}

/// One search with `order`, which must start with `firecrawl`. Firecrawl's
/// attempt is answered by the recorded reply `record`; each later provider's
/// attempt, by an Exa-shaped success. The fake server expects one request per
/// provider.
fn recorded_walk(record: &str, providers: &[&str]) -> Recorded {
    assert_eq!(providers.first(), Some(&"firecrawl"));
    let recordings: Value =
        serde_json::from_str(include_str!("../../backend/firecrawl/fixtures.json")).unwrap();
    let response = recordings[record].clone();
    assert!(response.is_object(), "missing recorded response {record}");
    let manifest = shipped_manifest();
    let (fixture, _) = super::super::super::tests::granted_exa_engine(&format!(
        "chain-firecrawl-{record}-{}",
        providers.len()
    ));
    connect(
        fixture.store(),
        CONNECTION,
        "firecrawl_rest",
        b"apikey:firecrawl",
        "search",
        manifest.actions_baseline[0]
            .http
            .as_ref()
            .unwrap()
            .args_schema
            .clone(),
    );
    order(&fixture, providers);
    // The server starts only after the store is set up, and waits longer than
    // the default for the request: on a loaded test host the store writes
    // before dispatch can outlast the default two-second accept deadline, and
    // the search would then fail to connect rather than see the recorded reply.
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (endpoint, server) = crate::test_http::FixedRequestServer::start_with_deadline(
        providers.len(),
        "firecrawl",
        std::time::Duration::from_secs(30),
        {
            let requests = requests.clone();
            move |index, received| {
                requests.lock().unwrap().push(received.to_string());
                let (status, headers, body) = if index == 0 {
                    (
                        response["status"].as_u64().unwrap(),
                        response["headers"].as_str().unwrap(),
                        response["body"].as_str().unwrap(),
                    )
                } else {
                    (
                        200,
                        "",
                        r#"{"results":[{"url":"https://example.org","title":"Fallback","text":"Weather"}]}"#,
                    )
                };
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }
        },
    );
    let mut config = RestConfig::from_manifest(&manifest);
    config.base_url = endpoint;
    let vault = Arc::new(RecordingVault::default());
    let engine = GovernanceEngine::new(
        fixture.store().clone(),
        vault.clone(),
        Arc::new(RestTransport::new(config)),
    );
    let service = firecrawl_service();
    let result = service.search(
        &engine,
        "direct",
        json!({
            "query": "firecrawl",
            "max_results": 3,
            "include_domains": ["docs.firecrawl.dev", "github.com"],
            "recency": "month"
        })
        .as_object()
        .unwrap(),
    );
    if let Err(error) = server.join() {
        panic!(
            "{record}: the search did not reach the recorded endpoint once per provider ({error}): {result:?}"
        );
    }
    let request = requests.lock().unwrap().remove(0);
    let audit = engine
        .store()
        .list_audit("direct")
        .unwrap()
        .into_iter()
        .find(|row| row.gate.as_deref() == Some("web_search"))
        .and_then(|row| row.args_redaction_summary)
        .map(|summary| serde_json::from_str(&summary).unwrap());
    Recorded {
        result,
        service,
        request,
        vault,
        audit,
    }
}

fn assert_moved_on(record: &str, reason: SkipReason, cooldown_ms: i64) -> Recorded {
    let recorded = recorded_search(record);
    let refusal = recorded.result.clone().unwrap_err();
    assert_eq!(
        refusal,
        unavailable(&[("firecrawl", reason)]),
        "{record} must move on"
    );
    assert_eq!(recorded.cooldown(), Some(cooldown_ms), "{record} cooldown");
    let wire = refusal.to_wire().to_string();
    assert!(
        !wire.contains("\"success\"") && !wire.contains("credits") && !wire.contains("Rate limit"),
        "{record}: vendor text must not reach the caller: {wire}"
    );
    recorded
}

#[test]
fn a_documented_success_is_served_from_a_bearer_post_to_v2_search() {
    let recorded = recorded_search("success");
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(response.backend, "firecrawl");
    assert_eq!(
        response
            .results
            .iter()
            .map(|result| (result.url.as_str(), result.title.as_str()))
            .collect::<Vec<_>>(),
        [
            (
                "https://www.firecrawl.dev/",
                "Firecrawl - The Web Data API for AI"
            ),
            (
                "https://github.com/firecrawl/firecrawl",
                "firecrawl/firecrawl: Turn entire websites into LLM-ready markdown"
            )
        ]
    );
    assert_eq!(recorded.cooldown(), None);

    let (head, body) = recorded.request.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("POST /v2/search HTTP/1.1\r\n"), "{head}");
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("authorization: Bearer test-credential")),
        "the key travels as a bearer token: {head}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(body).unwrap(),
        json!({
            "query": "firecrawl",
            "limit": 3,
            "sources": [{"type": "web"}],
            "includeDomains": ["docs.firecrawl.dev", "github.com"],
            "tbs": "qdr:m"
        }),
        "query, limit, web sources, domains and the tbs recency filter travel in the body"
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        ["apikey:firecrawl"],
        "the credential is read from the vault by name at dispatch"
    );
}

#[test]
fn a_documented_empty_reply_is_served_empty() {
    for record in ["empty", "empty_array"] {
        let recorded = recorded_search(record);
        let response = recorded.result.unwrap();
        assert_eq!(
            (response.backend.as_str(), response.results.len()),
            ("firecrawl", 0),
            "{record}"
        );
        assert!(recorded.service.chain_cooldowns.lock().unwrap().is_empty());
    }
}

#[test]
fn a_documented_bad_request_rejects_without_a_cooldown() {
    let recorded = recorded_search("bad_request");
    assert_eq!(
        recorded.result,
        Err(WebSearchRefusal::RequestRejected {
            backend: "firecrawl".into()
        })
    );
    assert_eq!(recorded.cooldown(), None);
    assert!(recorded.vault.auth_failures.lock().unwrap().is_empty());
}

#[test]
fn a_documented_unauthorized_reply_cools_the_credential_and_reports_it() {
    let recorded = assert_moved_on("unauthorized", SkipReason::Credential, 60_000);
    assert_eq!(*recorded.vault.auth_failures.lock().unwrap(), [401]);
}

#[test]
fn payment_required_is_quota_and_falls_through() {
    let recorded = recorded_walk("payment_required", &["firecrawl", "exa"]);
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("exa", 1),
        "a 402 falls through to the next provider"
    );
    assert_eq!(recorded.cooldown(), Some(3_600_000));
    assert_eq!(
        recorded.audit,
        Some(
            json!({"served_by": "exa", "skipped": [{"provider": "firecrawl", "reason": "quota"}]})
        )
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        ["apikey:firecrawl", "test:exa"]
    );
    assert!(recorded.vault.auth_failures.lock().unwrap().is_empty());

    let alone = assert_moved_on("payment_required", SkipReason::Quota, 3_600_000);
    assert!(alone.vault.auth_failures.lock().unwrap().is_empty());
}

#[test]
fn documented_rate_limits_are_throttled_for_the_retry_after_or_a_minute() {
    assert_moved_on("rate_limited_retry", SkipReason::Throttled, 7_000);
    assert_moved_on("rate_limited_no_retry", SkipReason::Throttled, 60_000);
}

#[test]
fn timeouts_server_errors_and_replies_without_data_are_unavailable() {
    for record in ["request_timeout", "server_error", "malformed"] {
        let recorded = assert_moved_on(record, SkipReason::Unavailable, 60_000);
        assert!(
            recorded.vault.auth_failures.lock().unwrap().is_empty(),
            "{record}"
        );
    }
}

#[test]
fn firecrawl_mcp_connections_are_not_chain_candidates() {
    let refusal_with_mcp = |with_mcp: bool| {
        let (engine, transport) = super::super::super::tests::granted_exa_engine(&format!(
            "chain-firecrawl-mcp-{with_mcp}"
        ));
        if with_mcp {
            // A live MCP Firecrawl connection, granted to the caller for both
            // its own search tool and an action named like the REST search.
            connect(
                engine.store(),
                "firecrawl-mcp",
                "firecrawl",
                b"apikey:firecrawl",
                "firecrawl_search",
                json!({"type": "object"}),
            );
            engine
                .store()
                .insert_grant(&GrantInput {
                    principal: "direct".into(),
                    connection_id: "firecrawl-mcp".into(),
                    grant_id: "firecrawl-mcp-search".into(),
                    grantee_principal: "direct".into(),
                    risk_ceiling: "read".into(),
                    action_selectors: vec!["search".into()],
                    authority_kind: "invoke".into(),
                    expires_at: None,
                })
                .unwrap();
        }
        order(&engine, &["firecrawl"]);
        let refusal = search(&firecrawl_service(), &engine, "direct").unwrap_err();
        assert!(transport.requests().is_empty(), "nothing is dispatched");
        refusal
    };
    let refusal = refusal_with_mcp(true);
    assert_eq!(refusal.code(), "web_search_not_granted");
    assert_eq!(
        refusal,
        refusal_with_mcp(false),
        "an MCP Firecrawl connection changes nothing for REST search"
    );
}

/// An engine whose only ordered provider is a granted Firecrawl connection
/// with a monthly allowance of 5, answered by the mock transport.
fn allowance_engine(name: &str) -> (Engine, Arc<MockTransport>, WebSearchService) {
    let (engine, transport) = super::super::super::tests::granted_exa_engine(name);
    add_connection(&engine, CONNECTION, "firecrawl", Some("direct"));
    order(&engine, &["firecrawl"]);
    engine
        .store()
        .set_web_search_allowance("firecrawl", 5)
        .unwrap();
    (engine, transport, firecrawl_service())
}

fn used(engine: &Engine) -> u32 {
    engine
        .store()
        .web_search_allowance_used("firecrawl", "direct", NOW)
        .unwrap()
}

/// 251 emoji are a valid tool query of 251 characters, but 502 UTF-16 code
/// units: over Firecrawl's 500, so Firecrawl is skipped for capability before
/// any connection, allowance, cooldown or dispatch work.
#[test]
fn a_query_over_500_utf16_units_skips_firecrawl_without_counting_or_cooling_it() {
    let (engine, transport, service) = allowance_engine("chain-firecrawl-long-query");
    let refusal = service
        .search(
            &engine,
            "direct",
            json!({"query": "😀".repeat(251)}).as_object().unwrap(),
        )
        .unwrap_err();
    assert_eq!(
        refusal,
        unavailable(&[("firecrawl", SkipReason::Capability)])
    );
    assert!(transport.requests().is_empty(), "nothing is dispatched");
    assert_eq!(used(&engine), 0, "a capability skip counts no allowance");
    assert!(
        service.chain_cooldowns.lock().unwrap().is_empty(),
        "a capability skip starts no cooldown"
    );
}

/// 250 emoji are exactly 500 UTF-16 code units, so they are dispatched and
/// counted: the skip above comes from the length, not from the setup.
#[test]
fn a_query_of_exactly_500_utf16_units_is_dispatched_and_counted() {
    let (engine, transport, service) = allowance_engine("chain-firecrawl-fits");
    let _ = service.search(
        &engine,
        "direct",
        json!({"query": "😀".repeat(250)}).as_object().unwrap(),
    );
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(used(&engine), 1);
}
