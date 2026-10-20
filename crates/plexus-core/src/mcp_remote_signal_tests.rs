use super::*;
use crate::manifest::{catalog_fixture, ingest_value, ErrorSignal};

fn dispatch(rule: Option<Value>, status: u16, headers: &str, error: Value) -> TransportResponse {
    dispatch_action(rule, status, headers, error, false)
}

fn dispatch_action(
    rule: Option<Value>,
    status: u16,
    headers: &str,
    error: Value,
    other_action: bool,
) -> TransportResponse {
    let mut manifest = catalog_fixture("github.jsonc");
    let action = manifest["actions_baseline"][usize::from(other_action)]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    if let Some(rule) = rule {
        manifest["actions_baseline"][0]["error_signals"] = json!([rule]);
    }
    let manifest = ingest_value(manifest).unwrap().manifest;
    let headers = headers.to_owned();
    let (endpoint, server) = crate::test_http::FixedRequestServer::start_with_deadline(
        3,
        "mcp-signals",
        Duration::from_secs(30),
        move |_, received| {
            let rpc: Value =
                serde_json::from_str(received.split_once("\r\n\r\n").unwrap().1).unwrap();
            let (status, body, headers) = match rpc["method"].as_str().unwrap() {
                "initialize" => (
                    200,
                    json!({"jsonrpc":"2.0","id":rpc["id"],"result":{}}).to_string(),
                    "",
                ),
                "notifications/initialized" => (202, String::new(), ""),
                "tools/call" => {
                    let mut body = error.clone();
                    if status == 200 {
                        body["id"] = rpc["id"].clone();
                    }
                    (status, body.to_string(), headers.as_str())
                }
                other => panic!("unexpected method {other}"),
            };
            format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
        },
    );
    let mut config = McpRemoteConfig::from_manifest(&manifest);
    config.endpoint = endpoint;
    let result = McpRemoteTransport::new(config).dispatch(
        TransportRequest {
            request_id: "signals".into(),
            connection_id: "fixture".into(),
            action,
            args: json!({}),
            credential_fingerprint: "fixture".into(),
        },
        &ResolvedCredential::new(b"fixture".to_vec(), None, 0),
    );
    server.join().unwrap();
    result
}

fn rule(status: u16, signal: ErrorSignal, pointer: &str) -> Value {
    json!({"status":status,"signal":signal,"matches":{"kind":"json","pointer":pointer,"value":"REVIEWED"}})
}

#[test]
fn declared_mcp_tool_errors_carry_only_fixed_signals() {
    for signal in [
        ErrorSignal::QuotaExhausted,
        ErrorSignal::CredentialRejected,
        ErrorSignal::NoResults,
    ] {
        let error = json!({"jsonrpc":"2.0","result":{"isError":true,"structuredContent":{"code":"REVIEWED"},
            "content":[{"type":"text","text":"private vendor wording"}]}});
        let result = dispatch(
            Some(rule(200, signal, "/result/structuredContent/code")),
            200,
            "",
            error,
        );
        assert_eq!(
            result,
            TransportResponse::vendor_error("mcp_tool_error", "MCP vendor request failed")
                .with_error_signal(Some(signal)),
            "MCP tool error must retain only the fixed declared signal"
        );
        assert_eq!(
            result.provider_auth_status(),
            (signal == ErrorSignal::CredentialRejected).then_some(401)
        );
    }
}

#[test]
fn declared_mcp_rpc_errors_carry_only_fixed_signals() {
    for signal in [
        ErrorSignal::QuotaExhausted,
        ErrorSignal::CredentialRejected,
        ErrorSignal::NoResults,
    ] {
        let error =
            json!({"jsonrpc":"2.0","error":{"code":"REVIEWED","message":"private vendor wording"}});
        assert_eq!(
            dispatch(Some(rule(200, signal, "/error/code")), 200, "", error),
            TransportResponse::vendor_error("mcp_request_failed", "MCP vendor request failed")
                .with_error_signal(Some(signal)),
            "MCP RPC error must retain only the fixed declared signal"
        );
    }
}

#[test]
fn declared_mcp_http_errors_match_raw_body_and_headers_before_throttling() {
    let error = json!({"error":{"code":"REVIEWED","message":"private vendor wording"}});
    let signal = ErrorSignal::QuotaExhausted;
    let expected = crate::http_support::throttled_response("MCP", Duration::from_secs(7))
        .with_error_signal(Some(signal));
    assert_eq!(
        dispatch(
            Some(rule(429, signal, "/error/code")),
            429,
            "Retry-After: 7\r\n",
            error.clone()
        ),
        expected,
        "MCP HTTP error body signal must survive throttling"
    );
    let header_rule = json!({"status":429,"signal":signal,"matches":{"kind":"header","name":"X-Remaining",
        "condition":{"kind":"exact","value":"0"}}});
    assert_eq!(
        dispatch(
            Some(header_rule),
            429,
            "Retry-After: 7\r\nX-Remaining: 0\r\n",
            error
        ),
        expected,
        "MCP HTTP header signal must survive throttling"
    );
}

#[test]
fn github_without_declarations_is_byte_for_byte_unchanged() {
    let tool_error = json!({"result":{"isError":true,"structuredContent":{"code":"REVIEWED"},
        "content":[{"type":"text","text":"quota exhausted private wording"}]}});
    assert_eq!(
        dispatch(None, 200, "", tool_error),
        TransportResponse::vendor_error("mcp_tool_error", "MCP vendor request failed"),
        "undeclared GitHub tool errors must remain byte-for-byte unchanged"
    );
    let rpc_error =
        json!({"error":{"code":"REVIEWED","message":"quota exhausted private wording"}});
    assert_eq!(
        dispatch(None, 200, "", rpc_error.clone()),
        TransportResponse::vendor_error("mcp_request_failed", "MCP vendor request failed")
    );
    assert_eq!(
        dispatch(None, 422, "", rpc_error.clone()),
        TransportResponse::vendor_error("http_422", "MCP vendor request failed")
    );
    assert_eq!(
        dispatch(None, 429, "Retry-After: 7\r\n", rpc_error),
        crate::http_support::throttled_response("MCP", Duration::from_secs(7))
    );
}

#[test]
fn mcp_success_and_other_actions_cannot_emit_error_signals() {
    let success =
        json!({"result":{"isError":false,"structuredContent":{"code":"REVIEWED"},"content":[]}});
    let result = dispatch(
        Some(rule(
            200,
            ErrorSignal::QuotaExhausted,
            "/result/structuredContent/code",
        )),
        200,
        "",
        success,
    );
    assert_eq!(
        result.error_signal, None,
        "matching successful data is not an error signal"
    );
    assert!(result.error_code.is_none());
    let body = json!({"result":{"isError":true,"structuredContent":{"code":"REVIEWED"}}});
    assert_eq!(
        dispatch(
            Some(rule(
                422,
                ErrorSignal::QuotaExhausted,
                "/result/structuredContent/code"
            )),
            200,
            "",
            body
        )
        .error_signal,
        None
    );
    let body = json!({"result":{"isError":true,"structuredContent":{"code":"REVIEWED"}}});
    assert_eq!(
        dispatch_action(
            Some(rule(
                200,
                ErrorSignal::QuotaExhausted,
                "/result/structuredContent/code"
            )),
            200,
            "",
            body,
            true
        )
        .error_signal,
        None,
        "only the dispatched action may supply error signals"
    );
}
