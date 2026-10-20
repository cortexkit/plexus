//! Shipped Perplexity Search manifest exercised through governed dispatch and
//! the real REST response path. No live provider or vault is contacted.

use super::*;
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::rest_api::{RestConfig, RestTransport};
use crate::transport::{TransportRequest, TransportResponse};
use std::sync::Mutex;

const CONNECTION: &str = "perplexity-rest";
const CREDENTIAL: &str = "apikey:perplexity";

#[derive(Default)]
struct RecordingVault {
    requested: Mutex<Vec<String>>,
    failures: Mutex<Vec<u16>>,
}

impl CredentialSource for RecordingVault {
    fn get_by_id(&self, id: &str) -> Result<ResolvedCredential, CredentialError> {
        self.requested.lock().unwrap().push(id.into());
        Ok(ResolvedCredential::new(
            b"test-credential".to_vec(),
            None,
            7,
        ))
    }
    fn report_id_auth_failure(&self, _: &str, status: u16) {
        self.failures.lock().unwrap().push(status);
    }
}

fn manifest() -> crate::manifest::AppManifest {
    crate::manifest::ingest_value(
        serde_json::from_str(
            &subc_jsonc::jsonc_to_json(include_str!(
                "../../../../../../catalog/perplexity_rest.jsonc"
            ))
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
    .manifest
}

fn connect(engine: &Engine) {
    let store = engine.store();
    store
        .insert_connection(
            "direct",
            CONNECTION,
            "perplexity_rest",
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
    let schema = manifest().actions_baseline[0]
        .http
        .as_ref()
        .unwrap()
        .args_schema
        .clone();
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
            grant_id: "perplexity-direct".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["search".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    order(engine, &["perplexity", "exa"]);
}

fn service() -> WebSearchService {
    WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(PerplexityRestBackend))
}

struct Recorded {
    result: Result<WebSearchResponse, WebSearchRefusal>,
    service: WebSearchService,
    request: String,
    vault: Arc<RecordingVault>,
}

fn recorded_search(record: &str) -> Recorded {
    let records: Value =
        serde_json::from_str(include_str!("../../backend/perplexity/fixtures.json")).unwrap();
    let response = records[record].clone();
    let (fixture, _) =
        super::super::super::tests::granted_exa_engine(&format!("chain-perplexity-{record}"));
    connect(&fixture);
    fixture
        .store()
        .set_web_search_order(&["perplexity".into()])
        .unwrap();
    let received = Arc::new(Mutex::new(String::new()));
    let (endpoint, server) = crate::test_http::FixedRequestServer::start_with_deadline(
        1,
        "perplexity",
        std::time::Duration::from_secs(30),
        {
            let received = received.clone();
            move |_, request| {
                *received.lock().unwrap() = request.to_string();
                let body = response["body"].as_str().unwrap();
                format!("HTTP/1.1 {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    response["status"].as_u64().unwrap(), response["headers"].as_str().unwrap(), body.len())
            }
        },
    );
    let mut config = RestConfig::from_manifest(&manifest());
    config.base_url = endpoint;
    let vault = Arc::new(RecordingVault::default());
    let engine = GovernanceEngine::new(
        fixture.store().clone(),
        vault.clone(),
        Arc::new(RestTransport::new(config)),
    );
    let service = service();
    let result = service.search(
        &engine,
        "direct",
        json!({
            "query": "weather report", "max_results": 3,
            "include_domains": ["example.com", "example.org"], "recency": "week"
        })
        .as_object()
        .unwrap(),
    );
    server
        .join()
        .unwrap_or_else(|error| panic!("{record}: {error}; {result:?}"));
    let request = received.lock().unwrap().clone();
    Recorded {
        result,
        service,
        request,
        vault,
    }
}

#[test]
fn keyed_search_post_sends_bearer_query_count_domain_and_recency() {
    let recorded = recorded_search("success");
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(response.backend, "perplexity");
    assert_eq!(response.results.len(), 2);
    assert_eq!(response.results[0].url, "https://example.com/article");
    assert_eq!(
        response.results[0].excerpt,
        "A short excerpt from the article relevant to the query..."
    );
    let (head, body) = recorded.request.split_once("\r\n\r\n").unwrap();
    assert!(
        head.starts_with("POST /search HTTP/1.1\r\n"),
        "Search must use POST /search: {head}"
    );
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("authorization: Bearer test-credential")),
        "the vault key must travel as a bearer token: {head}"
    );
    let sent: Value = serde_json::from_str(body).unwrap();
    assert_eq!(
        sent,
        json!({"query": "weather report", "max_results": 3,
        "search_domain_filter": ["example.com", "example.org"], "search_recency_filter": "week"})
    );
    assert_eq!(*recorded.vault.requested.lock().unwrap(), [CREDENTIAL]);
    assert!(recorded.service.chain_cooldowns.lock().unwrap().is_empty());
}

#[test]
fn empty_is_served_and_bad_requests_are_terminal_without_cooldown() {
    let recorded = recorded_search("empty");
    let response = recorded.result.unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("perplexity", 0)
    );
    assert!(recorded.service.chain_cooldowns.lock().unwrap().is_empty());
    for record in ["bad_request", "unprocessable"] {
        let recorded = recorded_search(record);
        assert_eq!(
            recorded.result,
            Err(WebSearchRefusal::RequestRejected {
                backend: "perplexity".into()
            })
        );
        assert!(recorded.service.chain_cooldowns.lock().unwrap().is_empty());
        assert!(recorded.vault.failures.lock().unwrap().is_empty());
    }
}

#[test]
fn recorded_http_outcomes_have_closed_reasons_and_cooldowns() {
    for (record, reason, cooldown) in [
        ("payment_required", SkipReason::Quota, 3_600_000),
        // The shared REST transport drops vendor error bodies before classification;
        // without a quota signal the chain can only classify these as unavailable.
        ("quota_forbidden", SkipReason::Unavailable, 60_000),
        ("unauthorized", SkipReason::Credential, 60_000),
        ("forbidden", SkipReason::Unavailable, 60_000),
        ("not_found", SkipReason::Unavailable, 60_000),
        ("rate_limited", SkipReason::Throttled, 60_000),
        ("rate_limited_retry", SkipReason::Throttled, 7_000),
        ("server_error", SkipReason::Unavailable, 60_000),
        ("malformed", SkipReason::Unavailable, 60_000),
        ("invalid_json", SkipReason::Unavailable, 60_000),
        ("no_body", SkipReason::Unavailable, 60_000),
    ] {
        let recorded = recorded_search(record);
        assert_eq!(
            recorded.result,
            Err(unavailable(&[("perplexity", reason)])),
            "{record}"
        );
        assert_eq!(
            recorded
                .service
                .chain_cooldowns
                .lock()
                .unwrap()
                .get(CONNECTION)
                .copied(),
            Some(NOW + cooldown),
            "{record}"
        );
        assert_eq!(
            *recorded.vault.failures.lock().unwrap(),
            if record == "unauthorized" {
                vec![401]
            } else {
                vec![]
            },
            "{record}"
        );
    }
}

#[test]
fn full_tool_boundary_dispatches_and_uses_one_allowance() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("perplexity-boundary");
    connect(&engine);
    engine
        .store()
        .set_web_search_order(&["perplexity".into()])
        .unwrap();
    engine
        .store()
        .set_web_search_allowance("perplexity", 5)
        .unwrap();
    transport.set_response(crate::transport::MockResponse::Success(
        json!({"results": []}),
    ));
    let service = service();
    let response = service.search(&engine, "direct", json!({
        "query": "é".repeat(500), "max_results": 20,
        "include_domains": (0..20).map(|i| format!("host{i}.example")).collect::<Vec<_>>(), "recency": "year"
    }).as_object().unwrap()).unwrap();
    assert_eq!(response.backend, "perplexity");
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(
        engine
            .store()
            .web_search_allowance_used("perplexity", "direct", NOW)
            .unwrap(),
        1
    );
    assert!(service.chain_cooldowns.lock().unwrap().is_empty());
}

struct LocalOutcome {
    response: TransportResponse,
    dispatched: Mutex<Vec<String>>,
}

impl crate::transport::Transport for LocalOutcome {
    fn dispatch(&self, request: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
        self.dispatched
            .lock()
            .unwrap()
            .push(request.connection_id.clone());
        if request.connection_id == CONNECTION {
            self.response.clone()
        } else {
            TransportResponse::success(
                json!({"results": [{"url": "https://fallback.example/", "title": "Fallback", "text": "Fallback excerpt"}]}),
            )
        }
    }
}

#[test]
fn local_transmission_outcomes_move_on_and_not_sent_releases_allowance() {
    use crate::transport::TransmissionState::{NotSent, OutcomeUnknown, Sent};
    for (name, transmission, error, retry, reason, cooldown, used) in [
        (
            "not-sent",
            NotSent,
            None,
            None,
            SkipReason::Unavailable,
            60_000,
            0,
        ),
        (
            "local-throttle",
            NotSent,
            None,
            Some(9_000),
            SkipReason::Throttled,
            9_000,
            0,
        ),
        (
            "unknown",
            OutcomeUnknown,
            None,
            None,
            SkipReason::Unavailable,
            60_000,
            1,
        ),
        (
            "timeout",
            OutcomeUnknown,
            Some("timeout"),
            None,
            SkipReason::Unavailable,
            60_000,
            1,
        ),
        (
            "no-body",
            Sent,
            None,
            None,
            SkipReason::Unavailable,
            60_000,
            1,
        ),
    ] {
        let (fixture, _) =
            super::super::super::tests::granted_exa_engine(&format!("perplexity-local-{name}"));
        connect(&fixture);
        fixture
            .store()
            .set_web_search_allowance("perplexity", 5)
            .unwrap();
        let mut response = TransportResponse::success(Value::Null);
        response.response = None;
        response.transmission = transmission;
        response.error_code = error.map(str::to_string);
        response.retry_after_ms = retry;
        let transport = Arc::new(LocalOutcome {
            response,
            dispatched: Mutex::new(Vec::new()),
        });
        let engine = GovernanceEngine::new(
            fixture.store().clone(),
            Arc::new(RecordingVault::default()),
            transport.clone(),
        );
        let service = service();
        let result = service
            .search(
                &engine,
                "direct",
                json!({"query": "weather report"}).as_object().unwrap(),
            )
            .unwrap();
        assert_eq!(result.backend, "exa", "{name} must fall through");
        assert_eq!(*transport.dispatched.lock().unwrap(), [CONNECTION, "exa"]);
        assert_eq!(
            engine
                .store()
                .web_search_allowance_used("perplexity", "direct", NOW)
                .unwrap(),
            used,
            "{name}"
        );
        assert_eq!(
            service
                .chain_cooldowns
                .lock()
                .unwrap()
                .get(CONNECTION)
                .copied(),
            Some(NOW + cooldown)
        );
        let audit = engine
            .store()
            .list_audit("direct")
            .unwrap()
            .into_iter()
            .find(|row| row.gate.as_deref() == Some("web_search"))
            .unwrap();
        let summary: Value =
            serde_json::from_str(audit.args_redaction_summary.as_ref().unwrap()).unwrap();
        assert_eq!(
            summary["skipped"],
            json!([{"provider": "perplexity", "reason": reason}])
        );
    }
}

#[test]
fn authorization_denial_does_not_dispatch_or_cool_perplexity() {
    let (fixture, _) = super::super::super::tests::granted_exa_engine("perplexity-denial");
    connect(&fixture);
    let vault = Arc::new(RecordingVault::default());
    let transport = Arc::new(LocalOutcome {
        response: TransportResponse::success(json!({"results": []})),
        dispatched: Mutex::new(Vec::new()),
    });
    let engine = GovernanceEngine::new(fixture.store().clone(), vault.clone(), transport.clone());
    let service = service();
    let result = service.search(
        &engine,
        "ungranted-caller",
        json!({"query": "weather report"}).as_object().unwrap(),
    );
    assert!(
        matches!(
            result,
            Err(WebSearchRefusal::NotGranted | WebSearchRefusal::Grant(_))
        ),
        "{result:?}"
    );
    assert!(vault.requested.lock().unwrap().is_empty());
    assert!(transport.dispatched.lock().unwrap().is_empty());
    assert!(service.chain_cooldowns.lock().unwrap().is_empty());
}
