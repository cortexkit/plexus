//! Kagi's documented replies, sent through the real REST transport built from
//! the shipped `catalog/kagi_rest.jsonc`, and how the chain treats each; plus
//! the capability declaration's serve side: the most domains the tool allows,
//! with a recency window, are dispatched to Kagi and counted. (No valid tool
//! query exceeds Kagi's declared envelope, so its capability skip is tested
//! on the backend directly.)

use super::*;
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::rest_api::{RestConfig, RestTransport};
use crate::transport::{Transport, TransportRequest, TransportResponse};
use crate::web_search::backend::KagiRestBackend;
use std::sync::Mutex;

const CONNECTION: &str = "kagi-rest";

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
    manifest(include_str!("../../../../../../catalog/kagi_rest.jsonc"))
}

/// Connect the Kagi REST connection for the `direct` principal, which owns it
/// and is the caller every search in these tests runs as. It is bound to the
/// vault credential `apikey:kagi`, with `search` reviewed under the shipped
/// schema and an invoke grant for `search` to `direct`.
fn connect(store: &PlexusStore, schema: Value) {
    store
        .insert_connection(
            "direct",
            CONNECTION,
            "kagi_rest",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", CONNECTION, b"apikey:kagi")
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

/// Sends the Kagi connection's requests through a transport built from the
/// Kagi manifest, and every other connection's through one built from the Exa
/// manifest. Both actions are named `search`, so one transport cannot carry
/// both: Kagi's path and its `workflow` constant would reach Exa's request.
struct ByConnection {
    kagi: RestTransport,
    exa: RestTransport,
}

impl Transport for ByConnection {
    fn dispatch(
        &self,
        request: TransportRequest,
        credential: &ResolvedCredential,
    ) -> TransportResponse {
        if request.connection_id == CONNECTION {
            self.kagi.dispatch(request, credential)
        } else {
            self.exa.dispatch(request, credential)
        }
    }
}

fn kagi_service() -> WebSearchService {
    WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(KagiRestBackend))
}

struct Recorded {
    result: Result<WebSearchResponse, WebSearchRefusal>,
    service: WebSearchService,
    /// The request sent in Kagi's attempt.
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

/// One search with order `kagi`, answered by the recorded reply `record`.
fn recorded_search(record: &str) -> Recorded {
    recorded_walk(record, &["kagi"])
}

/// One search for "steve jobs" on two domains within the last week, with
/// `order`, which must start with `kagi`. Kagi's attempt is answered by the
/// recorded reply `record`; each later provider's attempt, by an Exa-shaped
/// success. The fake server expects one request per provider.
fn recorded_walk(record: &str, providers: &[&str]) -> Recorded {
    assert_eq!(providers.first(), Some(&"kagi"));
    let recordings: Value =
        serde_json::from_str(include_str!("../../backend/kagi/fixtures.json")).unwrap();
    let response = recordings[record].clone();
    assert!(response.is_object(), "missing recorded response {record}");
    let kagi_manifest = shipped_manifest();
    let (fixture, _) = super::super::super::tests::granted_exa_engine(&format!(
        "chain-kagi-{record}-{}",
        providers.len()
    ));
    connect(
        fixture.store(),
        kagi_manifest.actions_baseline[0]
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
        "kagi",
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
    let mut config = RestConfig::from_manifest(&kagi_manifest);
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
            kagi: RestTransport::new(config),
            exa: RestTransport::new(exa_config),
        }),
    );
    let service = kagi_service();
    let result = service.search(
        &engine,
        "direct",
        json!({
            "query": "steve jobs",
            "max_results": 3,
            "include_domains": ["wikipedia.org", "apple.com"],
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
        unavailable(&[("kagi", reason)]),
        "{record} must move on"
    );
    assert_eq!(recorded.cooldown(), Some(cooldown_ms), "{record} cooldown");
    let wire = refusal.to_wire().to_string();
    assert!(
        !wire.contains("help.kagi.com")
            && !wire.contains("not authorized")
            && !wire.contains("Internal server error"),
        "{record}: vendor text must not reach the caller: {wire}"
    );
    recorded
}

#[test]
fn a_documented_success_is_served_from_a_bearer_post_to_api_v1_search() {
    let recorded = recorded_search("success");
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(response.backend, "kagi");
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
                "https://en.wikipedia.org/wiki/Steve_Jobs",
                "Steve Jobs - Wikipedia",
                Some("2012-02-23T07:00:59.000Z")
            ),
            (
                "https://www.apple.com/stevejobs/",
                "Remembering Steve Jobs - Apple",
                None
            )
        ],
        "only data.search results are served; the direct answer and infobox are dropped"
    );
    assert_eq!(recorded.cooldown(), None);

    let (head, body) = recorded.request.split_once("\r\n\r\n").unwrap();
    assert!(
        head.starts_with("POST /api/v1/search HTTP/1.1\r\n"),
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
            "query": "steve jobs",
            "workflow": "search",
            "limit": 3,
            "lens": {"sites_included": ["apple.com", "wikipedia.org"]},
            "filters": {"after": "2026-09-14"}
        }),
        "domains travel in lens.sites_included and recency in filters.after"
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        ["apikey:kagi"],
        "the credential is read from the vault by name at dispatch"
    );
}

#[test]
fn documented_empty_and_answer_only_replies_are_served_empty() {
    for record in ["empty", "answer_only"] {
        let recorded = recorded_search(record);
        let response = recorded.result.unwrap();
        assert_eq!(
            (response.backend.as_str(), response.results.len()),
            ("kagi", 0),
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
            backend: "kagi".into()
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

/// Kagi's 429 means "Rate limited or usage limit exhausted"; either way the
/// search moves on, here to Exa, and Kagi cools for the Retry-After.
#[test]
fn a_documented_rate_limit_falls_through_throttled() {
    let recorded = recorded_walk("rate_limited_retry", &["kagi", "exa"]);
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("exa", 1),
        "a 429 falls through to the next provider"
    );
    assert_eq!(recorded.cooldown(), Some(7_000));
    assert_eq!(
        recorded.audit,
        Some(
            json!({"filters": {"include_domains": ["apple.com", "wikipedia.org"], "max_results": 3, "recency": "week"}, "served_by": "exa", "skipped": [{"provider": "kagi", "reason": "throttled"}]})
        )
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        ["apikey:kagi", "test:exa"]
    );
    assert!(recorded.vault.auth_failures.lock().unwrap().is_empty());

    assert_moved_on("rate_limited_retry", SkipReason::Throttled, 7_000);
    assert_moved_on("rate_limited_no_retry", SkipReason::Throttled, 60_000);
}

#[test]
fn forbidden_server_errors_and_replies_without_a_data_object_are_unavailable() {
    for record in ["forbidden", "server_error", "malformed"] {
        let recorded = assert_moved_on(record, SkipReason::Unavailable, 60_000);
        assert!(
            recorded.vault.auth_failures.lock().unwrap().is_empty(),
            "{record}"
        );
    }
}

/// An engine whose only ordered provider is a granted Kagi connection with a
/// monthly allowance of 5, answered by the mock transport.
fn allowance_engine(name: &str) -> (Engine, Arc<MockTransport>, WebSearchService) {
    let (engine, transport) = super::super::super::tests::granted_exa_engine(name);
    add_connection(&engine, CONNECTION, "kagi", Some("direct"));
    order(&engine, &["kagi"]);
    engine.store().set_web_search_allowance("kagi", 5).unwrap();
    (engine, transport, kagi_service())
}

/// The longest query and the most domains the tool accepts, with a recency
/// window, are within Kagi's declared envelope: they are dispatched once and
/// counted, with every filter in its native field and the query unchanged.
#[test]
fn the_widest_tool_query_is_served_by_kagi_with_every_filter() {
    let (engine, transport, service) = allowance_engine("chain-kagi-widest");
    let domains: Vec<String> = (0..crate::web_search::query::MAX_INCLUDE_DOMAINS)
        .map(|index| format!("d{index}.example"))
        .collect();
    let text = "x".repeat(crate::web_search::query::MAX_QUERY_CHARS);
    let _ = service.search(
        &engine,
        "direct",
        json!({"query": text, "include_domains": domains, "recency": "year"})
            .as_object()
            .unwrap(),
    );
    let requests = transport.requests();
    assert_eq!(requests.len(), 1, "the search is dispatched to Kagi");
    assert_eq!(requests[0].args["query"], text.as_str());
    let mut sent = domains.clone();
    // The tool's argument parsing sorts the requested domains.
    sent.sort();
    assert_eq!(requests[0].args["lens"]["sites_included"], json!(sent));
    assert_eq!(requests[0].args["filters"]["after"], "2025-09-21");
    assert_eq!(
        engine
            .store()
            .web_search_allowance_used("kagi", "direct", NOW)
            .unwrap(),
        1
    );
}
