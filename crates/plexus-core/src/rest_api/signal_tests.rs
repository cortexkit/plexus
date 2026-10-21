use super::*;
use crate::manifest::{catalog_fixture, ingest_value, ErrorSignal};
use serde_json::json;

fn dispatch(
    manifest: &crate::manifest::AppManifest,
    status: u16,
    headers: &str,
    body: &str,
) -> TransportResponse {
    let headers = headers.to_owned();
    let body = body.to_owned();
    let (endpoint, server) = crate::test_http::FixedRequestServer::start_with_deadline(
        1,
        "rest-signals",
        Duration::from_secs(30),
        move |_, _| {
            format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
        },
    );
    let mut config = RestConfig::from_manifest(manifest);
    config.base_url = endpoint;
    let result = RestTransport::new(config).dispatch(
        TransportRequest {
            request_id: "signal-test".into(),
            connection_id: "fixture".into(),
            action: "search".into(),
            args: json!({"q":"weather report"}),
            credential_fingerprint: "fixture".into(),
        },
        &ResolvedCredential::new(b"fixture".to_vec(), None, 0),
    );
    server.join().unwrap();
    result
}

#[test]
fn brave_monthly_header_distinguishes_quota_from_short_throttle() {
    let brave = ingest_value(catalog_fixture("brave_rest.jsonc"))
        .unwrap()
        .manifest;
    for (remaining, expected) in [
        ("1, 0", Some(ErrorSignal::QuotaExhausted)),
        ("0, 50", None),
        ("0", None),
    ] {
        let result = dispatch(
            &brave,
            429,
            &format!("X-RateLimit-Remaining: {remaining}\r\nRetry-After: 7\r\n"),
            r#"{"detail":"vendor wording"}"#,
        );
        assert_eq!(
            result.error_signal, expected,
            "Brave monthly quota must survive the throttle path"
        );
        assert_eq!(result.retry_after_ms, Some(7_000));
        assert_eq!(
            result.error_message.as_deref(),
            Some("REST vendor throttled the request; retry after 7000ms")
        );
        assert!(result.response.is_none());
    }
}

#[test]
fn exa_without_declarations_is_byte_for_byte_unchanged() {
    let exa = ingest_value(catalog_fixture("exa_rest.jsonc"))
        .unwrap()
        .manifest;
    assert!(RestConfig::from_manifest(&exa).error_signals.is_empty());
    for status in [400, 401, 402, 403, 422, 429, 500] {
        let result = dispatch(
            &exa,
            status,
            "",
            r#"{"error":{"code":"EMPTY"},"quota":"exhausted","token":"private"}"#,
        );
        let expected = match status {
            401 => {
                let mut response = TransportResponse::vendor_error("http_401");
                response.error_message = Some("REST authentication was rejected".into());
                response
            }
            429 => crate::http_support::throttled_response("REST", Duration::from_secs(60)),
            500 => TransportResponse::unknown_with_error("http_500"),
            _ => TransportResponse::vendor_error(&format!("http_{status}")),
        };
        assert_eq!(
            result, expected,
            "undeclared Exa errors must remain byte-for-byte unchanged"
        );
    }
    let payload = json!({"results":[],"token":"ordinary result data"});
    assert_eq!(
        dispatch(&exa, 200, "", &payload.to_string()),
        TransportResponse::success(payload)
    );
}
