//! Kimi's documented replies, sent through the real REST transport built from
//! the shipped `catalog/kimi_rest.jsonc`, and how the chain treats each; plus
//! the capability declaration: Kimi takes no domain or date filter, so a
//! search with either skips it without dispatch, allowance or cooldown, and
//! the same search without them is dispatched and counted.

use super::*;
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::rest_api::{RestConfig, RestTransport};
use crate::transport::{Transport, TransportRequest, TransportResponse};
use crate::web_search::backend::KimiRestBackend;
use std::sync::Mutex;

const CONNECTION: &str = "kimi-rest";
/// The vault credential the Kimi connection is bound to: a Kimi Code console
/// key, as `crate::web_search::providers` names it.
const CREDENTIAL: &str = "apikey:kimi-for-coding";

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
    manifest(include_str!("../../../../../../catalog/kimi_rest.jsonc"))
}

/// Connect the Kimi REST connection for the `direct` principal, which owns it
/// and is the caller every search in these tests runs as. It is bound to the
/// vault credential `apikey:kimi-for-coding`, with `search` reviewed under
/// the shipped schema and an invoke grant for `search` to `direct`.
fn connect(store: &PlexusStore, schema: Value) {
    store
        .insert_connection(
            "direct",
            CONNECTION,
            "kimi_rest",
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

/// Sends the Kimi connection's requests through a transport built from the
/// Kimi manifest, and every other connection's through one built from the Exa
/// manifest. Both actions are named `search`, so one transport cannot carry
/// both: Kimi's path would reach Exa's request.
struct ByConnection {
    kimi: RestTransport,
    exa: RestTransport,
}

impl Transport for ByConnection {
    fn dispatch(
        &self,
        request: TransportRequest,
        credential: &ResolvedCredential,
    ) -> TransportResponse {
        if request.connection_id == CONNECTION {
            self.kimi.dispatch(request, credential)
        } else {
            self.exa.dispatch(request, credential)
        }
    }
}

fn kimi_service() -> WebSearchService {
    WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(KimiRestBackend))
}

struct Recorded {
    result: Result<WebSearchResponse, WebSearchRefusal>,
    service: WebSearchService,
    /// The request sent in Kimi's attempt.
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

/// One search with order `kimi`, answered by the recorded reply `record`.
fn recorded_search(record: &str) -> Recorded {
    recorded_walk(record, &["kimi"])
}

/// One search for "Kimi K2 model release" with no domain or recency filter,
/// with `order`, which must start with `kimi`. Kimi's attempt is answered by
/// the recorded reply `record`; each later provider's attempt, by an
/// Exa-shaped success. The fake server expects one request per provider.
fn recorded_walk(record: &str, providers: &[&str]) -> Recorded {
    assert_eq!(providers.first(), Some(&"kimi"));
    let recordings: Value =
        serde_json::from_str(include_str!("../../backend/kimi/fixtures.json")).unwrap();
    let response = recordings[record].clone();
    assert!(response.is_object(), "missing recorded response {record}");
    let kimi_manifest = shipped_manifest();
    let (fixture, _) = super::super::super::tests::granted_exa_engine(&format!(
        "chain-kimi-{record}-{}",
        providers.len()
    ));
    connect(
        fixture.store(),
        kimi_manifest.actions_baseline[0]
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
        "kimi",
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
    let mut config = RestConfig::from_manifest(&kimi_manifest);
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
            kimi: RestTransport::new(config),
            exa: RestTransport::new(exa_config),
        }),
    );
    let service = kimi_service();
    let result = service.search(
        &engine,
        "direct",
        json!({"query": "Kimi K2 model release", "max_results": 3})
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
        unavailable(&[("kimi", reason)]),
        "{record} must move on"
    );
    assert_eq!(recorded.cooldown(), Some(cooldown_ms), "{record} cooldown");
    let wire = refusal.to_wire().to_string();
    assert!(
        !wire.contains("qps")
            && !wire.contains("upstream service failed")
            && !wire.contains("internal error")
            && !wire.contains("request timeout")
            && !wire.contains("client canceled"),
        "{record}: vendor text must not reach the caller: {wire}"
    );
    recorded
}

#[test]
fn a_documented_success_is_served_from_a_bearer_post_to_coding_v1_search() {
    let recorded = recorded_search("success");
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(response.backend, "kimi");
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
                "https://platform.kimi.ai/docs/api/overview",
                "API Overview - Kimi API Open Platform",
                "Documentation entry of the Kimi API open platform.",
                Some("2026-06-01T00:00:00.000Z")
            ),
            (
                "https://github.com/MoonshotAI/kimi-cli",
                "MoonshotAI/kimi-cli - GitHub",
                "Kimi Code CLI is an AI agent that runs in the terminal.",
                None
            )
        ],
        "search_results map to title, url, snippet and date"
    );
    assert_eq!(recorded.cooldown(), None);

    let (head, body) = recorded.request.split_once("\r\n\r\n").unwrap();
    assert!(
        head.starts_with("POST /coding/v1/search HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("authorization: Bearer test-credential")),
        "the key travels as a bearer token: {head}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(body).unwrap(),
        json!({"text_query": "Kimi K2 model release", "limit": 3}),
        "only text_query and limit are sent"
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        [CREDENTIAL],
        "the credential is read from the vault by name at dispatch"
    );
}

#[test]
fn a_documented_empty_reply_is_served_empty() {
    let recorded = recorded_search("empty");
    let response = recorded.result.unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("kimi", 0)
    );
    assert!(recorded.service.chain_cooldowns.lock().unwrap().is_empty());
}

#[test]
fn a_documented_bad_request_rejects_without_a_cooldown() {
    let recorded = recorded_search("bad_request");
    assert_eq!(
        recorded.result,
        Err(WebSearchRefusal::RequestRejected {
            backend: "kimi".into()
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

/// Kimi's 429 is a rate or concurrency limit; the search moves on, here to
/// Exa. Kimi documents no Retry-After, so it cools for a minute, or for the
/// Retry-After if one is ever sent.
#[test]
fn a_documented_rate_limit_falls_through_throttled() {
    let recorded = recorded_walk("rate_limited", &["kimi", "exa"]);
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
            json!({"filters": {"max_results": 3}, "served_by": "exa", "skipped": [{"provider": "kimi", "reason": "throttled"}]})
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
fn forbidden_other_errors_and_replies_without_search_results_are_unavailable() {
    for record in [
        "forbidden",
        "client_canceled",
        "server_error",
        "upstream_failed",
        "timeout",
        "malformed",
    ] {
        let recorded = assert_moved_on(record, SkipReason::Unavailable, 60_000);
        assert!(
            recorded.vault.auth_failures.lock().unwrap().is_empty(),
            "{record}"
        );
    }
}

/// An engine whose only ordered provider is a granted Kimi connection with a
/// monthly allowance of 5, answered by the mock transport.
fn allowance_engine(name: &str) -> (Engine, Arc<MockTransport>, WebSearchService) {
    let (engine, transport) = super::super::super::tests::granted_exa_engine(name);
    add_connection(&engine, CONNECTION, "kimi", Some("direct"));
    order(&engine, &["kimi"]);
    engine.store().set_web_search_allowance("kimi", 5).unwrap();
    (engine, transport, kimi_service())
}

fn used(engine: &Engine) -> u32 {
    engine
        .store()
        .web_search_allowance_used("kimi", "direct", NOW)
        .unwrap()
}

/// Kimi takes no domain filter and no recency filter, so a search with one
/// domain, or with a recency window, skips it for capability before any
/// connection, allowance, cooldown or dispatch work.
#[test]
fn a_domain_or_recency_window_skips_kimi_without_counting_or_cooling_it() {
    for (case, arguments) in [
        (
            "one domain",
            json!({"query": "news", "include_domains": ["kimi.com"]}),
        ),
        ("recency", json!({"query": "news", "recency": "day"})),
    ] {
        let (engine, transport, service) =
            allowance_engine(&format!("chain-kimi-skip-{}", case.replace(' ', "-")));
        let refusal = service
            .search(&engine, "direct", arguments.as_object().unwrap())
            .unwrap_err();
        assert_eq!(
            refusal,
            unavailable(&[("kimi", SkipReason::Capability)]),
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

/// The longest query the tool accepts, without filters, is dispatched to Kimi
/// and counted: the skips above come from the filters, not from the setup.
#[test]
fn the_longest_unfiltered_tool_query_is_served_by_kimi() {
    let (engine, transport, service) = allowance_engine("chain-kimi-serve");
    let text = "x".repeat(crate::web_search::query::MAX_QUERY_CHARS);
    let _ = service.search(
        &engine,
        "direct",
        json!({"query": text, "max_results": 20})
            .as_object()
            .unwrap(),
    );
    let requests = transport.requests();
    assert_eq!(requests.len(), 1, "the search is dispatched to Kimi");
    assert_eq!(
        requests[0].args,
        json!({"text_query": text, "limit": 20}),
        "the query is unchanged and limit is the tool's maximum of 20"
    );
    assert_eq!(used(&engine), 1);
}
