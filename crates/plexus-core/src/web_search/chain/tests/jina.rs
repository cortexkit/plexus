//! Jina's documented replies, sent through the real REST transport built from
//! the shipped `catalog/jina_rest.jsonc`, and how the chain treats each; plus
//! the capability declaration of one domain: two domains skip Jina without
//! counting its allowance or cooling it down, and one domain is served.

use super::*;
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::rest_api::{RestConfig, RestTransport};
use crate::transport::{Transport, TransportRequest, TransportResponse};
use crate::web_search::backend::JinaRestBackend;
use std::sync::Mutex;

const CONNECTION: &str = "jina-rest";

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
    let source = include_str!("../../../../../../catalog/jina_rest.jsonc");
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

/// Connect the Jina REST connection for the `direct` principal, which owns it
/// and is the caller every search in these tests runs as. It is bound to the
/// vault credential `apikey:jina`, with `search` reviewed under the shipped
/// schema and an invoke grant for `search` to `direct`.
fn connect(store: &PlexusStore, schema: Value) {
    store
        .insert_connection(
            "direct",
            CONNECTION,
            "jina_rest",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", CONNECTION, b"apikey:jina")
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

fn exa_manifest() -> crate::manifest::AppManifest {
    let source = include_str!("../../../../../../catalog/exa_rest.jsonc");
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

/// Sends the Jina connection's requests through a transport built from the
/// Jina manifest, and every other connection's through one built from the Exa
/// manifest. Both actions are named `search`, so one transport cannot carry
/// both: Jina's GET with the query as its path cannot send Exa's arguments.
struct ByConnection {
    jina: RestTransport,
    exa: RestTransport,
}

impl Transport for ByConnection {
    fn dispatch(
        &self,
        request: TransportRequest,
        credential: &ResolvedCredential,
    ) -> TransportResponse {
        if request.connection_id == CONNECTION {
            self.jina.dispatch(request, credential)
        } else {
            self.exa.dispatch(request, credential)
        }
    }
}

fn jina_service() -> WebSearchService {
    WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(JinaRestBackend))
}

struct Recorded {
    result: Result<WebSearchResponse, WebSearchRefusal>,
    service: WebSearchService,
    /// The request sent in Jina's attempt.
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

/// One search for `query` with order `jina`, answered by the recorded reply
/// `record`.
fn recorded_search(record: &str) -> Recorded {
    recorded_walk(record, &["jina"], "jina reader")
}

/// One search for `query`, restricted to `jina.ai`, with `order`, which must
/// start with `jina`. Jina's attempt is answered by the recorded reply
/// `record`; each later provider's attempt, by an Exa-shaped success. The
/// fake server expects one request per provider.
fn recorded_walk(record: &str, providers: &[&str], query: &str) -> Recorded {
    assert_eq!(providers.first(), Some(&"jina"));
    let recordings: Value =
        serde_json::from_str(include_str!("../../backend/jina/fixtures.json")).unwrap();
    let response = recordings[record].clone();
    assert!(response.is_object(), "missing recorded response {record}");
    let manifest = shipped_manifest();
    let (fixture, _) = super::super::super::tests::granted_exa_engine(&format!(
        "chain-jina-{record}-{}",
        providers.len()
    ));
    connect(
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
        "jina",
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
    config.base_url = endpoint.clone();
    let mut exa_config = RestConfig::from_manifest(&exa_manifest());
    exa_config.base_url = endpoint;
    let vault = Arc::new(RecordingVault::default());
    let engine = GovernanceEngine::new(
        fixture.store().clone(),
        vault.clone(),
        Arc::new(ByConnection {
            jina: RestTransport::new(config),
            exa: RestTransport::new(exa_config),
        }),
    );
    let service = jina_service();
    let result = service.search(
        &engine,
        "direct",
        json!({
            "query": query,
            "max_results": 3,
            "include_domains": ["jina.ai"]
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
        unavailable(&[("jina", reason)]),
        "{record} must move on"
    );
    assert_eq!(recorded.cooldown(), Some(cooldown_ms), "{record} cooldown");
    let wire = refusal.to_wire().to_string();
    assert!(
        !wire.contains("readableMessage") && !wire.contains("Error:") && !wire.contains("balance"),
        "{record}: vendor text must not reach the caller: {wire}"
    );
    recorded
}

/// The request head's lines, without the request line.
fn header_lines(head: &str) -> Vec<String> {
    head.lines().skip(1).map(str::to_ascii_lowercase).collect()
}

#[test]
fn a_documented_success_is_served_from_a_bearer_get_with_the_query_as_the_path() {
    let recorded = recorded_search("success");
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(response.backend, "jina");
    assert_eq!(
        response
            .results
            .iter()
            .map(|result| (result.url.as_str(), result.title.as_str()))
            .collect::<Vec<_>>(),
        [
            ("https://jina.ai/reader/", "Reader API - Jina AI"),
            (
                "https://github.com/jina-ai/reader",
                "jina-ai/reader: Convert any URL to an LLM-friendly input"
            )
        ]
    );
    assert_eq!(recorded.cooldown(), None);

    let (head, body) = recorded.request.split_once("\r\n\r\n").unwrap();
    assert!(
        head.starts_with("GET /jina%20reader?count=3 HTTP/1.1\r\n"),
        "the query is the whole path and count a query parameter: {head}"
    );
    assert_eq!(body, "", "a GET sends no body");
    let headers = header_lines(head);
    assert!(
        headers.contains(&"authorization: bearer test-credential".to_string()),
        "the key travels as a bearer token: {head}"
    );
    assert!(
        headers.contains(&"x-site: jina.ai".to_string()),
        "the one requested domain travels in X-Site: {head}"
    );
    assert!(
        headers.contains(&"x-respond-with: no-content".to_string()),
        "Jina is asked not to fetch each result page: {head}"
    );
    assert!(headers.contains(&"accept: application/json".to_string()));
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        ["apikey:jina"],
        "the credential is read from the vault by name at dispatch"
    );
}

#[test]
fn a_query_with_path_and_query_characters_stays_one_path_segment() {
    let recorded = recorded_walk("success", &["jina"], "a/b?c=d#e %");
    assert_eq!(recorded.result.unwrap().backend, "jina");
    assert!(
        recorded
            .request
            .starts_with("GET /a%2Fb%3Fc%3Dd%23e%20%25?count=3 HTTP/1.1\r\n"),
        "every reserved character is escaped: {}",
        recorded.request
    );
}

#[test]
fn a_documented_empty_reply_is_served_empty() {
    let recorded = recorded_search("empty");
    let response = recorded.result.unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("jina", 0)
    );
    assert!(recorded.service.chain_cooldowns.lock().unwrap().is_empty());
}

#[test]
fn a_reply_with_only_content_is_served_from_content() {
    let recorded = recorded_search("content_only");
    let response = recorded.result.unwrap();
    assert_eq!(response.results.len(), 1);
    assert_eq!(
        response.results[0].excerpt,
        "Your Search Foundation, Supercharged."
    );
}

#[test]
fn documented_bad_requests_reject_without_a_cooldown() {
    // Jina answers a search that finds nothing with a 422; like every 400 and
    // 422, it is refused without reading the body and never retried elsewhere.
    for record in ["bad_request", "no_results"] {
        let recorded = recorded_search(record);
        assert_eq!(
            recorded.result,
            Err(WebSearchRefusal::RequestRejected {
                backend: "jina".into()
            }),
            "{record}"
        );
        assert_eq!(recorded.cooldown(), None, "{record}");
        assert!(recorded.vault.auth_failures.lock().unwrap().is_empty());
    }
}

#[test]
fn a_documented_unauthorized_reply_cools_the_credential_and_reports_it() {
    let recorded = assert_moved_on("unauthorized", SkipReason::Credential, 60_000);
    assert_eq!(*recorded.vault.auth_failures.lock().unwrap(), [401]);
}

#[test]
fn payment_required_is_quota_and_falls_through() {
    let recorded = recorded_walk("payment_required", &["jina", "exa"], "jina reader");
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("exa", 1),
        "a 402 falls through to the next provider"
    );
    assert_eq!(recorded.cooldown(), Some(3_600_000));
    assert_eq!(
        recorded.audit,
        Some(json!({"served_by": "exa", "skipped": [{"provider": "jina", "reason": "quota"}]}))
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        ["apikey:jina", "test:exa"]
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
fn forbidden_server_errors_and_replies_without_data_are_unavailable() {
    for record in [
        "forbidden",
        "server_error",
        "service_unavailable",
        "malformed",
    ] {
        let recorded = assert_moved_on(record, SkipReason::Unavailable, 60_000);
        assert!(
            recorded.vault.auth_failures.lock().unwrap().is_empty(),
            "{record}"
        );
    }
}

/// An engine whose only ordered provider is a granted Jina connection with a
/// monthly allowance of 5, answered by the mock transport.
fn allowance_engine(name: &str) -> (Engine, Arc<MockTransport>, WebSearchService) {
    let (engine, transport) = super::super::super::tests::granted_exa_engine(name);
    add_connection(&engine, CONNECTION, "jina", Some("direct"));
    order(&engine, &["jina"]);
    engine.store().set_web_search_allowance("jina", 5).unwrap();
    (engine, transport, jina_service())
}

fn used(engine: &Engine) -> u32 {
    engine
        .store()
        .web_search_allowance_used("jina", "direct", NOW)
        .unwrap()
}

/// Jina takes one site filter, so two domains skip it for capability before
/// any connection, allowance, cooldown or dispatch work.
#[test]
fn two_domains_skip_jina_without_counting_or_cooling_it() {
    let (engine, transport, service) = allowance_engine("chain-jina-two-domains");
    let refusal = service
        .search(
            &engine,
            "direct",
            json!({"query": "news", "include_domains": ["jina.ai", "github.com"]})
                .as_object()
                .unwrap(),
        )
        .unwrap_err();
    assert_eq!(refusal, unavailable(&[("jina", SkipReason::Capability)]));
    assert!(transport.requests().is_empty(), "nothing is dispatched");
    assert_eq!(used(&engine), 0, "a capability skip counts no allowance");
    assert!(
        service.chain_cooldowns.lock().unwrap().is_empty(),
        "a capability skip starts no cooldown"
    );
}

/// One domain is dispatched to Jina and counted, with the domain as its site
/// filter: the skip above comes from the domain count, not from the setup.
#[test]
fn one_domain_is_served_by_jina() {
    let (engine, transport, service) = allowance_engine("chain-jina-one-domain");
    let _ = service.search(
        &engine,
        "direct",
        json!({"query": "news", "include_domains": ["jina.ai"]})
            .as_object()
            .unwrap(),
    );
    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].args["site"], "jina.ai");
    assert_eq!(used(&engine), 1);
}
