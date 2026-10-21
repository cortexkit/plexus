//! DeepSeek's documented replies, sent through the real REST transport built
//! from the shipped `catalog/deepseek_rest.jsonc`, and how the chain treats
//! each; plus the capability skips that keep a query DeepSeek cannot take from
//! counting its allowance or cooling it down.

use super::*;
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::rest_api::{RestConfig, RestTransport};
use crate::web_search::backend::DeepSeekRestBackend;
use std::sync::Mutex;

const CONNECTION: &str = "deepseek-rest";

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
    let source = include_str!("../../../../../../catalog/deepseek_rest.jsonc");
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

/// Connect `CONNECTION` of `deepseek_rest` for the `direct` principal, which
/// owns it and is the caller every search in these tests runs as. The
/// connection is bound to the vault credential `apikey:deepseek`, with
/// `search` reviewed under the shipped schema and an invoke grant for `search`
/// to `direct`.
fn connect_deepseek(store: &PlexusStore, schema: Value) {
    store
        .insert_connection(
            "direct",
            CONNECTION,
            "deepseek_rest",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", CONNECTION, b"apikey:deepseek")
        .unwrap();
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    store
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: CONNECTION.into(),
            name: "search".into(),
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
            grant_id: format!("{CONNECTION}-direct"),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["search".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
}

fn deepseek_service() -> WebSearchService {
    WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(DeepSeekRestBackend))
}

struct Recorded {
    result: Result<WebSearchResponse, WebSearchRefusal>,
    service: WebSearchService,
    /// The request sent in DeepSeek's attempt.
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

/// One search with order `deepseek`, answered by the recorded reply `record`.
fn recorded_search(record: &str) -> Recorded {
    recorded_walk(record, &["deepseek"])
}

/// One search with `order`, which must start with `deepseek`. DeepSeek's
/// attempt is answered by the recorded reply `record`; each later provider's
/// attempt, by an Exa-shaped success. The fake server expects one request per
/// provider.
fn recorded_walk(record: &str, providers: &[&str]) -> Recorded {
    assert_eq!(providers.first(), Some(&"deepseek"));
    let recordings: Value =
        serde_json::from_str(include_str!("../../backend/deepseek/fixtures.json")).unwrap();
    let response = recordings[record].clone();
    assert!(response.is_object(), "missing recorded response {record}");
    let manifest = shipped_manifest();
    let (fixture, _) = super::super::super::tests::granted_exa_engine(&format!(
        "chain-deepseek-{record}-{}",
        providers.len()
    ));
    connect_deepseek(
        fixture.store(),
        manifest.actions_baseline[0]
            .http
            .as_ref()
            .unwrap()
            .args_schema
            .clone(),
    );
    order(&fixture, providers);
    // Complete durable setup first. Admission then follows the server's lifetime,
    // so preparation before dispatch cannot expire its listener.
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (endpoint, server) = crate::test_http::FixedRequestServer::start_with_deadline(
        providers.len(),
        "deepseek",
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
    let service = deepseek_service();
    let result = service.search(
        &engine,
        "direct",
        json!({
            "query": "DeepSeek",
            "max_results": 3,
            "include_domains": ["github.com", "huggingface.co"],
            "recency": "week"
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
        unavailable(&[("deepseek", reason)]),
        "{record} must move on"
    );
    assert_eq!(recorded.cooldown(), Some(cooldown_ms), "{record} cooldown");
    let wire = refusal.to_wire().to_string();
    assert!(
        !wire.contains("_error") && !wire.contains("Balance"),
        "{record}: vendor text must not reach the caller: {wire}"
    );
    recorded
}

#[test]
fn a_documented_success_is_served_from_a_bearer_post_to_tools_search() {
    let recorded = recorded_search("success");
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(response.backend, "deepseek");
    assert_eq!(
        response
            .results
            .iter()
            .map(|result| (
                result.url.as_str(),
                result.title.as_str(),
                result.published_at.as_deref()
            ))
            .collect::<Vec<_>>(),
        [
            (
                "https://example.com/deepseek-v4",
                "DeepSeek V4 model released",
                Some("2026-06-01T00:00:00.000Z")
            ),
            ("https://github.com/deepseek-ai", "DeepSeek on GitHub", None)
        ]
    );
    assert_eq!(recorded.cooldown(), None);

    let (head, body) = recorded.request.split_once("\r\n\r\n").unwrap();
    assert!(
        head.starts_with("POST /v1/tools/search HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("authorization: Bearer test-credential")),
        "the key travels as a bearer token: {head}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(body).unwrap(),
        json!({
            "query": "DeepSeek site:github.com OR site:huggingface.co after:2026-09-14",
            "count": 3
        }),
        "domains and recency travel as operators inside query"
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        ["apikey:deepseek"],
        "the credential is read from the vault by name at dispatch"
    );
}

#[test]
fn a_documented_empty_reply_is_served_empty() {
    let recorded = recorded_search("empty");
    let response = recorded.result.unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("deepseek", 0)
    );
    assert!(recorded.service.chain_cooldowns.lock().unwrap().is_empty());
}

#[test]
fn a_documented_bad_request_rejects_without_a_cooldown() {
    let recorded = recorded_search("bad_request");
    assert_eq!(
        recorded.result,
        Err(WebSearchRefusal::RequestRejected {
            backend: "deepseek".into()
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
fn insufficient_balance_is_quota_and_falls_through() {
    let recorded = recorded_walk("insufficient_balance", &["deepseek", "exa"]);
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
            json!({"filters": {"include_domains": ["github.com", "huggingface.co"], "max_results": 3, "recency": "week"}, "served_by": "exa", "skipped": [{"provider": "deepseek", "reason": "quota"}]})
        )
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        ["apikey:deepseek", "test:exa"]
    );
    assert!(recorded.vault.auth_failures.lock().unwrap().is_empty());

    let alone = assert_moved_on("insufficient_balance", SkipReason::Quota, 3_600_000);
    assert!(alone.vault.auth_failures.lock().unwrap().is_empty());
}

#[test]
fn an_exceeded_qps_limit_is_throttled_for_a_minute() {
    // DeepSeek documents no Retry-After, so a 429 takes the one-minute default.
    let recorded = assert_moved_on("qps_exceeded", SkipReason::Throttled, 60_000);
    assert!(recorded.vault.auth_failures.lock().unwrap().is_empty());
}

#[test]
fn timeouts_server_errors_and_replies_without_results_are_unavailable() {
    for record in [
        "request_timeout",
        "server_error",
        "gateway_timeout",
        "malformed",
    ] {
        let recorded = assert_moved_on(record, SkipReason::Unavailable, 60_000);
        assert!(
            recorded.vault.auth_failures.lock().unwrap().is_empty(),
            "{record}"
        );
    }
}

/// An engine whose only ordered provider is a granted DeepSeek connection
/// with a monthly allowance of 5, answered by the mock transport.
fn allowance_engine(name: &str) -> (Engine, Arc<MockTransport>, WebSearchService) {
    let (engine, transport) = super::super::super::tests::granted_exa_engine(name);
    add_connection(&engine, CONNECTION, "deepseek", Some("direct"));
    order(&engine, &["deepseek"]);
    engine
        .store()
        .set_web_search_allowance("deepseek", 5)
        .unwrap();
    (engine, transport, deepseek_service())
}

fn used(engine: &Engine) -> u32 {
    engine
        .store()
        .web_search_allowance_used("deepseek", "direct", NOW)
        .unwrap()
}

/// Asserts that `arguments` skip DeepSeek for capability before any
/// connection, allowance, cooldown or dispatch work.
fn assert_capability_skip(name: &str, arguments: Value) {
    let (engine, transport, service) = allowance_engine(name);
    let refusal = service
        .search(&engine, "direct", arguments.as_object().unwrap())
        .unwrap_err();
    assert_eq!(
        refusal,
        unavailable(&[("deepseek", SkipReason::Capability)])
    );
    assert!(transport.requests().is_empty(), "nothing is dispatched");
    assert_eq!(used(&engine), 0, "a capability skip counts no allowance");
    assert!(
        service.chain_cooldowns.lock().unwrap().is_empty(),
        "a capability skip starts no cooldown"
    );
}

#[test]
fn a_200_character_query_skips_deepseek_without_counting_or_cooling_it() {
    assert_capability_skip(
        "chain-deepseek-long-query",
        json!({"query": "x".repeat(200)}),
    );
}

#[test]
fn a_100_character_query_with_three_domains_skips_deepseek_once_operators_are_added() {
    assert_capability_skip(
        "chain-deepseek-long-operators",
        json!({
            "query": "x".repeat(100),
            "include_domains": ["a.com", "b.com", "c.com"]
        }),
    );
}

/// The same 100-character query without domains fits, so it is dispatched and
/// counted: the skips above come from the operators, not from the setup.
#[test]
fn a_100_character_query_without_domains_is_dispatched_and_counted() {
    let (engine, transport, service) = allowance_engine("chain-deepseek-fits");
    let _ = service.search(
        &engine,
        "direct",
        json!({"query": "x".repeat(100)}).as_object().unwrap(),
    );
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(used(&engine), 1);
}
