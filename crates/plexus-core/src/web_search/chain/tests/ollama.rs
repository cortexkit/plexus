//! Ollama's documented replies, sent through the real REST transport built
//! from the shipped `catalog/ollama_rest.jsonc`, and how the chain treats
//! each; plus the capability declaration: Ollama takes domains only as `site:`
//! operators and no date filter, so a recency window, or a query too long once
//! its operators are added, skips it without dispatch, allowance or cooldown,
//! while the same search that fits is dispatched and counted.

use super::*;
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::rest_api::{RestConfig, RestTransport};
use crate::transport::{Transport, TransportRequest, TransportResponse};
use crate::web_search::backend::OllamaRestBackend;
use std::sync::Mutex;

const CONNECTION: &str = "ollama-rest";
/// The vault credential the Ollama connection is bound to: an ollama.com
/// account key, as `crate::web_search::providers` names it.
const CREDENTIAL: &str = "apikey:ollama-cloud";

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

fn manifest(source: &str) -> crate::manifest::AppManifest {
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

fn shipped_manifest() -> crate::manifest::AppManifest {
    manifest(include_str!("../../../../../../catalog/ollama_rest.jsonc"))
}

/// Connect the Ollama REST connection for the `direct` principal, which owns
/// it and is the caller every search in these tests runs as. It is bound to
/// the vault credential `apikey:ollama-cloud`, with `search` reviewed under
/// the shipped schema and an invoke grant for `search` to `direct`.
fn connect(store: &PlexusStore, schema: Value) {
    store
        .insert_connection(
            "direct",
            CONNECTION,
            "ollama_rest",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", CONNECTION, CREDENTIAL.as_bytes())
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

/// Sends the Ollama connection's requests through a transport built from the
/// Ollama manifest, and every other connection's through one built from the
/// Exa manifest. Both actions are named `search`, so one transport cannot
/// carry both: Ollama's path would reach Exa's request.
struct ByConnection {
    ollama: RestTransport,
    exa: RestTransport,
}

impl Transport for ByConnection {
    fn dispatch(
        &self,
        request: TransportRequest,
        credential: &ResolvedCredential,
    ) -> TransportResponse {
        if request.connection_id == CONNECTION {
            self.ollama.dispatch(request, credential)
        } else {
            self.exa.dispatch(request, credential)
        }
    }
}

fn ollama_service() -> WebSearchService {
    WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(OllamaRestBackend))
}

struct Recorded {
    result: Result<WebSearchResponse, WebSearchRefusal>,
    service: WebSearchService,
    /// The request sent in Ollama's attempt.
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

/// One search with order `ollama`, answered by the recorded reply `record`.
fn recorded_search(record: &str) -> Recorded {
    recorded_walk(record, &["ollama"])
}

/// One search for "what is ollama?" with no domain or recency filter, with
/// `order`, which must start with `ollama`. Ollama's attempt is answered by
/// the recorded reply `record`; each later provider's attempt, by an
/// Exa-shaped success. The fake server expects one request per provider.
fn recorded_walk(record: &str, providers: &[&str]) -> Recorded {
    recorded_walk_with(
        "plain",
        record,
        providers,
        json!({"query": "what is ollama?", "max_results": 3}),
    )
}

/// As [`recorded_walk`], with the tool arguments `arguments`. `tag` keeps the
/// store of each distinct call apart.
fn recorded_walk_with(tag: &str, record: &str, providers: &[&str], arguments: Value) -> Recorded {
    assert_eq!(providers.first(), Some(&"ollama"));
    let recordings: Value =
        serde_json::from_str(include_str!("../../backend/ollama/fixtures.json")).unwrap();
    let response = recordings[record].clone();
    assert!(response.is_object(), "missing recorded response {record}");
    let ollama_manifest = shipped_manifest();
    let (fixture, _) = super::super::super::tests::granted_exa_engine(&format!(
        "chain-ollama-{tag}-{record}-{}",
        providers.len()
    ));
    connect(
        fixture.store(),
        ollama_manifest.actions_baseline[0]
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
        "ollama",
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
    let mut config = RestConfig::from_manifest(&ollama_manifest);
    config.base_url = endpoint.clone();
    let mut exa_config = RestConfig::from_manifest(&manifest(include_str!(
        "../../../../../../catalog/exa_rest.jsonc"
    )));
    exa_config.base_url = endpoint;
    let vault = Arc::new(RecordingVault::default());
    let engine = GovernanceEngine::new(
        fixture.store().clone(),
        vault.clone(),
        Arc::new(ByConnection {
            ollama: RestTransport::new(config),
            exa: RestTransport::new(exa_config),
        }),
    );
    let service = ollama_service();
    let result = service.search(&engine, "direct", arguments.as_object().unwrap());
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
        unavailable(&[("ollama", reason)]),
        "{record} must move on"
    );
    assert_eq!(recorded.cooldown(), Some(cooldown_ms), "{record} cooldown");
    let wire = refusal.to_wire().to_string();
    assert!(
        !wire.contains("too many requests")
            && !wire.contains("account suspended")
            && !wire.contains("not found")
            && !wire.contains("internal server error")
            && !wire.contains("bad gateway"),
        "{record}: vendor text must not reach the caller: {wire}"
    );
    recorded
}

#[test]
fn a_documented_success_is_served_from_a_bearer_post_to_api_web_search() {
    let recorded = recorded_search("success");
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(response.backend, "ollama");
    assert_eq!(
        response
            .results
            .iter()
            .map(|result| (
                result.url.as_str(),
                result.title.as_str(),
                result.excerpt.as_str(),
                result.published_at.as_deref()
            ))
            .collect::<Vec<_>>(),
        [
            (
                "https://ollama.com/",
                "Ollama",
                "Cloud models are now available...",
                None
            ),
            (
                "https://www.hostinger.com/tutorials/what-is-ollama",
                "What is Ollama? Introduction to the AI model management tool",
                "Ariffud M. 6min Read...",
                None
            ),
            (
                "https://www.geeksforgeeks.org/artificial-intelligence/ollama-explained-transforming-ai-accessibility-and-language-processing/",
                "Ollama Explained: Transforming AI Accessibility and Language ...",
                "Data Science Data Science Projects Data Analysis...",
                None
            )
        ],
        "results map to title, url and content"
    );
    assert_eq!(recorded.cooldown(), None);

    let (head, body) = recorded.request.split_once("\r\n\r\n").unwrap();
    assert!(
        head.starts_with("POST /api/web_search HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("authorization: Bearer test-credential")),
        "the key travels as a bearer token: {head}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(body).unwrap(),
        json!({"query": "what is ollama?", "max_results": 3}),
        "only query and max_results are sent"
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        [CREDENTIAL],
        "the credential is read from the vault by name at dispatch"
    );
}

/// Requested domains reach Ollama as `site:` operators inside `query`, sent
/// through the real transport, and the reply is served.
#[test]
fn requested_domains_travel_as_site_operators_in_the_sent_query() {
    let recorded = recorded_walk_with(
        "domains",
        "success",
        &["ollama"],
        json!({
            "query": "what is ollama?",
            "max_results": 3,
            "include_domains": ["github.com", "ollama.com"]
        }),
    );
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("ollama", 3)
    );
    let (_, body) = recorded.request.split_once("\r\n\r\n").unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(body).unwrap(),
        json!({
            "query": "what is ollama? site:github.com OR site:ollama.com",
            "max_results": 3
        }),
        "the domains are site: operators in query, with no domain field"
    );
}

#[test]
fn an_empty_results_array_is_served_empty() {
    let recorded = recorded_search("empty");
    let response = recorded.result.unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("ollama", 0)
    );
    assert!(recorded.service.chain_cooldowns.lock().unwrap().is_empty());
}

#[test]
fn a_bad_request_rejects_without_a_cooldown() {
    let recorded = recorded_search("bad_request");
    assert_eq!(
        recorded.result,
        Err(WebSearchRefusal::RequestRejected {
            backend: "ollama".into()
        })
    );
    assert_eq!(recorded.cooldown(), None);
    assert!(recorded.vault.auth_failures.lock().unwrap().is_empty());
}

#[test]
fn an_unauthorized_reply_cools_the_credential_and_reports_it() {
    let recorded = assert_moved_on("unauthorized", SkipReason::Credential, 60_000);
    assert_eq!(*recorded.vault.auth_failures.lock().unwrap(), [401]);
}

/// Ollama's 429 is its documented rate limit; the search moves on, here to
/// Exa. No Retry-After is documented for web search, so Ollama cools for a
/// minute, or for the Retry-After if one is sent.
#[test]
fn a_rate_limit_falls_through_throttled() {
    let recorded = recorded_walk("rate_limited", &["ollama", "exa"]);
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("exa", 1),
        "a 429 falls through to the next provider"
    );
    assert_eq!(recorded.cooldown(), Some(60_000));
    assert_eq!(
        recorded.audit,
        Some(
            json!({"served_by": "exa", "skipped": [{"provider": "ollama", "reason": "throttled"}]})
        )
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        [CREDENTIAL, "test:exa"]
    );
    assert!(recorded.vault.auth_failures.lock().unwrap().is_empty());

    assert_moved_on("rate_limited", SkipReason::Throttled, 60_000);
    assert_moved_on("rate_limited_retry", SkipReason::Throttled, 7_000);
}

#[test]
fn forbidden_not_found_server_errors_and_replies_without_results_are_unavailable() {
    for record in [
        "forbidden",
        "not_found",
        "server_error",
        "bad_gateway",
        "malformed",
    ] {
        let recorded = assert_moved_on(record, SkipReason::Unavailable, 60_000);
        assert!(
            recorded.vault.auth_failures.lock().unwrap().is_empty(),
            "{record}"
        );
    }
}

/// An engine whose only ordered provider is a granted Ollama connection with
/// a monthly allowance of 5, answered by the mock transport.
fn allowance_engine(name: &str) -> (Engine, Arc<MockTransport>, WebSearchService) {
    let (engine, transport) = super::super::super::tests::granted_exa_engine(name);
    add_connection(&engine, CONNECTION, "ollama", Some("direct"));
    order(&engine, &["ollama"]);
    engine
        .store()
        .set_web_search_allowance("ollama", 5)
        .unwrap();
    (engine, transport, ollama_service())
}

fn used(engine: &Engine) -> u32 {
    engine
        .store()
        .web_search_allowance_used("ollama", "direct", NOW)
        .unwrap()
}

/// Ollama takes no recency filter, and its 500-character envelope is counted
/// after the `site:` operators are added. A search with a recency window, or
/// a 495-character query with one domain (507 characters once composed),
/// skips Ollama for capability before any connection, allowance, cooldown or
/// dispatch work.
#[test]
fn recency_or_a_query_too_long_with_its_operators_skips_ollama_without_counting_or_cooling_it() {
    for (case, arguments) in [
        ("recency", json!({"query": "news", "recency": "day"})),
        (
            "too long with operators",
            json!({"query": "x".repeat(495), "include_domains": ["a.com"]}),
        ),
    ] {
        let (engine, transport, service) =
            allowance_engine(&format!("chain-ollama-skip-{}", case.replace(' ', "-")));
        let refusal = service
            .search(&engine, "direct", arguments.as_object().unwrap())
            .unwrap_err();
        assert_eq!(
            refusal,
            unavailable(&[("ollama", SkipReason::Capability)]),
            "{case}"
        );
        assert!(
            transport.requests().is_empty(),
            "{case}: nothing is dispatched"
        );
        assert_eq!(
            used(&engine),
            0,
            "{case}: a capability skip counts no allowance"
        );
        assert!(
            service.chain_cooldowns.lock().unwrap().is_empty(),
            "{case}: a capability skip starts no cooldown"
        );
    }
}

/// The same 495-character query with no domain, and a short query with one
/// domain, are each dispatched to Ollama and counted: the skips above come
/// from the filters and the composed length, not from the setup.
#[test]
fn a_query_that_fits_with_its_operators_is_served_by_ollama() {
    let text = "x".repeat(495);
    for (case, arguments, sent) in [
        (
            "long",
            json!({"query": text, "max_results": 20}),
            json!({"query": text, "max_results": 10}),
        ),
        (
            "domain",
            json!({"query": "news", "include_domains": ["a.com"], "max_results": 5}),
            json!({"query": "news site:a.com", "max_results": 5}),
        ),
    ] {
        let (engine, transport, service) = allowance_engine(&format!("chain-ollama-serve-{case}"));
        let _ = service.search(&engine, "direct", arguments.as_object().unwrap());
        let requests = transport.requests();
        assert_eq!(
            requests.len(),
            1,
            "{case}: the search is dispatched to Ollama"
        );
        assert_eq!(
            requests[0].args, sent,
            "{case}: the query keeps its terms, one domain becomes one site: operator, \
             and max_results is clamped to Ollama's 10"
        );
        assert_eq!(used(&engine), 1, "{case}");
    }
}
