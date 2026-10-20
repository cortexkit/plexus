use super::*;
use crate::manifest::{ingest_value, ErrorSignal};
use crate::rest_api::{RestConfig, RestTransport};

fn declared_rest_attempt(status: u16, signal: ErrorSignal) {
    let (fixture, _) =
        super::super::super::super::tests::granted_exa_engine("declared-rest-signal");
    order(&fixture, &["exa"]);
    let body = r#"{"error":{"code":"REVIEWED"},"detail":"private vendor wording"}"#;
    let (endpoint, server) = crate::test_http::FixedRequestServer::start_with_deadline(
        1,
        "declared-rest-signal",
        std::time::Duration::from_secs(30),
        move |_, _| {
            format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nRetry-After: 2\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        },
    );
    let mut manifest = crate::manifest::catalog_fixture("exa_rest.jsonc");
    manifest["actions_baseline"][0]["error_signals"] = json!([{
        "status":status,"signal":signal,"matches":{"kind":"json","pointer":"/error/code","value":"REVIEWED"}
    }]);
    let manifest = ingest_value(manifest).unwrap().manifest;
    let mut config = RestConfig::from_manifest(&manifest);
    config.base_url = endpoint;
    let credentials = Arc::new(ReportingCredentials::default());
    let engine = GovernanceEngine::new(
        fixture.store().clone(),
        credentials.clone(),
        Arc::new(RestTransport::new(config)),
    );
    let service = service();
    let result = service.search(
        &engine,
        "direct",
        json!({"query":"weather report"}).as_object().unwrap(),
    );
    server.join().unwrap();
    if status == 401 || signal == ErrorSignal::CredentialRejected {
        assert_eq!(
            result,
            Err(unavailable(&[("exa", SkipReason::Credential)])),
            "declared credential rejection must skip as a bad key"
        );
        assert_eq!(
            *credentials.0.lock().unwrap(),
            vec![401],
            "declared credential rejection must report exactly the same vault status as 401"
        );
        assert_eq!(
            service.chain_cooldowns.lock().unwrap().get("exa"),
            Some(&(NOW + 60_000))
        );
    } else if signal == ErrorSignal::QuotaExhausted {
        assert_eq!(
            result,
            Err(unavailable(&[("exa", SkipReason::Quota)])),
            "declared quota must reach the chain through transport and governance"
        );
        assert_eq!(
            service.chain_cooldowns.lock().unwrap().get("exa"),
            Some(&(NOW + 3_600_000))
        );
        assert!(credentials.0.lock().unwrap().is_empty());
    } else {
        let result = result.expect("declared no_results must serve an empty search");
        assert!(
            result.results.is_empty(),
            "declared no_results must be empty"
        );
        assert_eq!(result.backend, "exa");
        assert!(service.chain_cooldowns.lock().unwrap().is_empty());
        assert!(credentials.0.lock().unwrap().is_empty());
    }
    let rows = engine.store().list_audit("direct").unwrap();
    assert!(
        !format!("{rows:?}").contains("private vendor wording"),
        "vendor text must not escape transport"
    );
}

#[test]
fn declared_rest_quota_overrides_429_retry() {
    declared_rest_attempt(429, ErrorSignal::QuotaExhausted);
}

#[test]
fn declared_rest_bad_key_reports_401_to_vault() {
    declared_rest_attempt(422, ErrorSignal::CredentialRejected);
}

#[test]
fn declared_rest_no_results_serves_empty_instead_of_rejecting_422() {
    declared_rest_attempt(422, ErrorSignal::NoResults);
}

#[test]
fn declared_rest_401_never_becomes_empty_or_quota() {
    declared_rest_attempt(401, ErrorSignal::NoResults);
    declared_rest_attempt(401, ErrorSignal::QuotaExhausted);
}

#[test]
fn declared_rest_success_cannot_emit_error_signals_and_serves_results() {
    for signal in [
        ErrorSignal::QuotaExhausted,
        ErrorSignal::CredentialRejected,
        ErrorSignal::NoResults,
    ] {
        let (fixture, _) =
            super::super::super::super::tests::granted_exa_engine("declared-rest-success-signal");
        order(&fixture, &["exa"]);
        let body = json!({"results":[{
            "url":"https://example.org/weather", "title":"Weather", "text":"Forecast"
        }]});
        let wire_body = body.to_string();
        let (endpoint, server) = crate::test_http::FixedRequestServer::start_with_deadline(
            2,
            "declared-rest-success-signal",
            std::time::Duration::from_secs(30),
            move |_, received| {
                assert!(received.starts_with("POST /search HTTP/1.1"));
                format!("HTTP/1.1 200\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{wire_body}", wire_body.len())
            },
        );
        let mut manifest = crate::manifest::catalog_fixture("exa_rest.jsonc");
        manifest["actions_baseline"][0]["error_signals"] = json!([{
            "status":200,"signal":signal,"matches":{
                "kind":"json","pointer":"/results/0/title","value":"Weather"
            }
        }]);
        let manifest = ingest_value(manifest).unwrap().manifest;
        let mut config = RestConfig::from_manifest(&manifest);
        config.base_url = endpoint;
        let transport = Arc::new(RestTransport::new(config));
        let dispatched = transport.dispatch(
            TransportRequest {
                request_id: "rest-success-signal".into(),
                connection_id: "exa".into(),
                action: "search".into(),
                args: json!({"query":"weather report","numResults":5}),
                credential_fingerprint: "fixture".into(),
            },
            &ResolvedCredential::new(b"test-credential".to_vec(), None, 7),
        );
        let credentials = Arc::new(ReportingCredentials::default());
        let engine = GovernanceEngine::new(fixture.store().clone(), credentials.clone(), transport);
        let service = service();
        let result = service.search(
            &engine,
            "direct",
            json!({"query":"weather report"}).as_object().unwrap(),
        );
        server.join().unwrap();
        let result = result.expect("a matching 200 body must still serve its search results");
        assert_eq!(result.backend, "exa");
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].url, "https://example.org/weather");
        assert_eq!(result.results[0].title, "Weather");
        assert_eq!(
            dispatched.error_signal, None,
            "successful REST data must never carry an error signal"
        );
        assert_eq!(dispatched, TransportResponse::success(body));
        assert!(service.chain_cooldowns.lock().unwrap().is_empty());
        assert!(credentials.0.lock().unwrap().is_empty());
    }
}
