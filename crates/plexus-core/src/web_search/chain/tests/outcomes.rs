use super::*;
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::transport::{MockResponse, TransportRequest, TransportResponse};
use std::sync::atomic::AtomicI64;
use std::sync::Mutex;

fn clocked_service(now: &Arc<AtomicI64>) -> WebSearchService {
    let clock = now.clone();
    WebSearchService::with_clock(
        Arc::new(ExaRestBackend),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    )
    .with_chain_backend(Arc::new(TestBackend {
        name: "tavily",
        preparations: Arc::new(AtomicUsize::new(0)),
    }))
}

#[test]
fn request_rejected_is_audited_without_retry_or_vendor_text() {
    for status in [400, 422] {
        let (engine, transport) = super::super::super::tests::granted_exa_engine("chain-rejected");
        add_connection(&engine, "tavily", "tavily", Some("direct"));
        order(&engine, &["exa", "tavily"]);
        transport.set_response(MockResponse::VendorError {
            code: format!("http_{status}"),
            message: "quota secret-vendor-body".into(),
        });
        let service = service();
        let refusal = search(&service, &engine, "direct").unwrap_err();
        assert_eq!(
            refusal.to_wire(),
            json!({"error": {
                "code":"web_search_request_rejected", "backend":"exa",
                "message":"the web search provider rejected the request"
            }})
        );
        assert_eq!(transport.requests().len(), 1);
        assert!(service.chain_cooldowns.lock().unwrap().is_empty());
        let rows = engine.store().list_audit("direct").unwrap();
        assert!(rows
            .iter()
            .any(|row| row.gate.as_deref() == Some("web_search")
                && row.reason_code == "web_search_request_rejected"
                && row.connection_id.as_deref() == Some("exa")));
        assert!(!serde_json::to_string(&rows)
            .unwrap()
            .contains("secret-vendor-body"));
    }
}

#[test]
fn completed_results_stop_before_next_provider() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("chain-results");
    add_connection(&engine, "tavily", "tavily", Some("direct"));
    order(&engine, &["exa", "tavily"]);
    transport.set_response(MockResponse::Success(
        json!({"results":[{"url":"https://example.org", "title":"Report", "text":"Weather"}]}),
    ));
    let response = search(&service(), &engine, "direct").unwrap();
    assert_eq!(response.backend, "exa");
    assert_eq!(response.results.len(), 1);
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn unavailable_cooldown_expires_and_restart_resets_memory() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("chain-expiry");
    order(&engine, &["exa"]);
    let now = Arc::new(AtomicI64::new(NOW));
    let service = clocked_service(&now);
    transport.set_response(MockResponse::VendorError {
        code: "http_503".into(),
        message: "quota is not meaningful in a 5xx".into(),
    });
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(unavailable(&[("exa", SkipReason::Unavailable)]))
    );
    transport.set_response(MockResponse::Success(json!({"results":[]})));
    now.store(NOW + 59_999, Ordering::SeqCst);
    assert_eq!(
        search(&service, &engine, "direct"),
        Err(unavailable(&[("exa", SkipReason::Cooldown)]))
    );
    assert_eq!(transport.requests().len(), 1);
    assert!(
        search(&clocked_service(&now), &engine, "direct").is_ok(),
        "a restarted service has no in-memory cooldown"
    );
    now.store(NOW + 60_000, Ordering::SeqCst);
    assert!(search(&service, &engine, "direct").is_ok());
    assert_eq!(transport.requests().len(), 3);
}

#[test]
fn quota_cooldown_is_connection_local() {
    let (engine, transport) =
        super::super::super::tests::granted_exa_engine("chain-local-cooldown");
    add_connection(&engine, "exa-two", "exa", Some("other"));
    order(&engine, &["exa"]);
    let service = service();
    transport.set_response(MockResponse::VendorError {
        code: "http_402".into(),
        message: "payment".into(),
    });
    assert_eq!(
        search(&service, &engine, "other"),
        Err(unavailable(&[("exa", SkipReason::Quota)]))
    );
    transport.set_response(MockResponse::Success(json!({"results":[]})));
    assert!(search(&service, &engine, "direct").is_ok());
    assert_eq!(
        search(&service, &engine, "other"),
        Err(unavailable(&[("exa", SkipReason::Cooldown)]))
    );
    assert_eq!(transport.requests().len(), 2);
    assert_eq!(transport.requests()[1].connection_id, "exa");
}

#[derive(Default)]
struct ReportingCredentials(Mutex<Vec<u16>>);

impl CredentialSource for ReportingCredentials {
    fn get(&self, _: &[u8]) -> Result<ResolvedCredential, CredentialError> {
        Ok(ResolvedCredential::new(
            b"test-credential".to_vec(),
            None,
            7,
        ))
    }
    fn get_by_id(&self, _: &str) -> Result<ResolvedCredential, CredentialError> {
        self.get(&[])
    }
    fn report_id_auth_failure(&self, _: &str, status: u16) {
        self.0.lock().unwrap().push(status);
    }
}

struct FixedTransport(TransportResponse);

impl Transport for FixedTransport {
    fn dispatch(&self, _: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
        self.0.clone()
    }
}

#[test]
fn credential_cooldown_and_vault_reporting_exclude_forbidden() {
    for (status, reason) in [
        (401, SkipReason::Credential),
        (403, SkipReason::Unavailable),
    ] {
        let (fixture, _) = super::super::super::tests::granted_exa_engine("chain-auth-cooldown");
        order(&fixture, &["exa"]);
        let credentials = Arc::new(ReportingCredentials::default());
        let engine = GovernanceEngine::new(
            fixture.store().clone(),
            credentials.clone(),
            Arc::new(FixedTransport(TransportResponse::vendor_error(
                &format!("http_{status}"),
                "permission denied",
            ))),
        );
        let now = Arc::new(AtomicI64::new(NOW));
        let service = clocked_service(&now);
        let args = json!({"query":"weather report"});
        assert_eq!(
            service.search(&engine, "direct", args.as_object().unwrap()),
            Err(unavailable(&[("exa", reason)]))
        );
        assert_eq!(
            *credentials.0.lock().unwrap(),
            if status == 401 { vec![401] } else { vec![] }
        );
        now.store(NOW + 59_999, Ordering::SeqCst);
        assert_eq!(
            service.search(&engine, "direct", args.as_object().unwrap()),
            Err(unavailable(&[("exa", SkipReason::Cooldown)]))
        );
        engine
            .store()
            .set_connection_health("direct", "exa", "degraded", &json!({"healthy":false}))
            .unwrap();
        now.store(NOW + 60_000, Ordering::SeqCst);
        assert_eq!(
            service.search(&engine, "direct", args.as_object().unwrap()),
            Err(unavailable(&[("exa", SkipReason::ConnectionUnusable)]))
        );
        engine
            .store()
            .set_connection_health("direct", "exa", "active", &json!({"healthy":true}))
            .unwrap();
        assert_eq!(
            service.search(&engine, "direct", args.as_object().unwrap()),
            Err(unavailable(&[("exa", reason)]))
        );
    }
}

fn recorded_rest_attempt(record: &str, reason: SkipReason, cooldown_ms: i64) {
    use crate::manifest::{HttpMethod, HttpOperation};
    use crate::rest_api::{RestConfig, RestTransport};

    let recordings: Value =
        serde_json::from_str(include_str!("fixtures/rest_outcomes.json")).unwrap();
    let response = recordings[record].clone();
    assert!(response.is_object(), "missing recorded response {record}");
    let (endpoint, server) = crate::test_http::FixedRequestServer::start(
        2,
        "web-search-outcomes",
        move |index, received| {
            assert!(received.starts_with("POST /search HTTP/1.1"));
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
            format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        },
    );
    let (fixture, _) = super::super::super::tests::granted_exa_engine("chain-recorded-rest");
    add_connection(&fixture, "tavily", "tavily", Some("direct"));
    order(&fixture, &["exa", "tavily"]);
    let transport = RestTransport::new(
        RestConfig::new(endpoint).with_actions(
            [(
                "search".into(),
                HttpOperation {
                    method: HttpMethod::Post,
                    path: "/search".into(),
                    args_schema: json!({"type":"object"}),
                    request_constants: None,
                    credentialless_tail: None,
                },
            )]
            .into(),
        ),
    );
    let engine = GovernanceEngine::new(
        fixture.store().clone(),
        Arc::new(StubCredentialSource::with_default_success(
            b"test-credential".to_vec(),
        )),
        Arc::new(transport),
    );
    let service = service();
    let result = service
        .search(
            &engine,
            "direct",
            json!({"query":"weather report"}).as_object().unwrap(),
        )
        .unwrap();
    server
        .join()
        .expect("both provider attempts reached the recorded REST endpoint");
    assert_eq!(result.backend, "tavily");
    assert_eq!(result.results.len(), 1);
    assert_eq!(
        service.chain_cooldowns.lock().unwrap().get("exa"),
        Some(&(NOW + cooldown_ms))
    );
    let rows = engine.store().list_audit("direct").unwrap();
    let row = rows
        .iter()
        .find(|row| row.gate.as_deref() == Some("web_search"))
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(row.args_redaction_summary.as_deref().unwrap()).unwrap(),
        json!({"served_by":"tavily", "skipped":[{"provider":"exa", "reason":reason}]})
    );
}

#[test]
fn recorded_rest_payment_required_is_quota() {
    recorded_rest_attempt("payment_required", SkipReason::Quota, 3_600_000);
}

#[test]
fn recorded_rest_throttled_with_retry_is_capped() {
    recorded_rest_attempt("throttled_retry", SkipReason::Throttled, 7_000);
    recorded_rest_attempt("throttled_long_retry", SkipReason::Throttled, 3_600_000);
}

#[test]
fn recorded_rest_throttled_without_retry_uses_one_minute() {
    recorded_rest_attempt("throttled_no_retry", SkipReason::Throttled, 60_000);
}

#[test]
fn recorded_rest_redacted_quota_body_has_no_private_signal_yet() {
    recorded_rest_attempt("forbidden_quota", SkipReason::Unavailable, 60_000);
}
