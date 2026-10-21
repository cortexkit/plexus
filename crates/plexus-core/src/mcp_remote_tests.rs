use super::*;

/// The vendor's own explanation is recovered from a failed tool call.
///
/// MCP reports a tool failure as an ordinary result carrying `isError:
/// true`, with the reason in the content blocks -- so the text naming the
/// cause sits inside a structure that otherwise looks like success, and
/// dropping it leaves one fixed sentence as the only evidence anywhere.
/// Narrowing one real failure without it took five separate probes.
///
/// Every text block is joined rather than the first taken, because a
/// truncated reason reads as a complete one -- the failure mode is a
/// confident half-answer, not an obvious gap.
///
/// The two empty cases are kept DISTINCT: a vendor that sent no content and
/// a response we could not read are both quiet, and only one of them is the
/// vendor's fault.
///
/// Mutation-proved: taking only the first block fails the join assertion,
/// and returning a constant fails the distinctness assertions.
#[test]
fn a_tool_error_recovers_the_vendor_text() {
    let split = serde_json::json!({
        "content": [
            {"type": "text", "text": "resource not accessible"},
            {"type": "text", "text": "by personal access token"}
        ]
    });
    assert_eq!(
        tool_error_text(&split),
        "resource not accessible by personal access token",
        "every text block must survive: a partial reason reads as a whole one"
    );

    assert_eq!(
        tool_error_text(&serde_json::json!({})),
        "<no content blocks>",
        "an unreadable response must not be reported as a silent vendor"
    );
    assert_eq!(
        tool_error_text(&serde_json::json!({"content": [{"type": "image"}]})),
        "<content carried no text>",
        "a vendor that sent no text is a different fact from an unreadable response"
    );
}

#[test]
fn grep_app_no_results_tool_error_is_recognized_narrowly() {
    let prefix = include_str!("../tests/fixtures/grep_app/no_results_tool_error.txt").trim_end();
    let with_usage_advice = format!("{prefix} Add a repository or language filter.");
    let (kind, response) = grep_app_tool_error_response(
        Some(GREP_APP_APP_KEY),
        GREP_APP_SEARCH_ACTION,
        &with_usage_advice,
    )
    .expect("the no-match sentence is recognized");
    assert_eq!(kind, GrepAppToolError::NoResults);
    assert_eq!(
        response.response,
        Some(serde_json::json!({
            "content": [{"type": "text", "text": GREP_APP_NO_RESULTS}]
        })),
        "a tool error becomes the ordinary empty-result shape"
    );
    assert_eq!(response.retryability, Retryability::Terminal);
    assert!(
        grep_app_tool_error_response(
            Some(GREP_APP_APP_KEY),
            GREP_APP_SEARCH_ACTION,
            "No results found for your query"
        )
        .is_none(),
        "the complete sentence, including its period, is required"
    );
    assert!(
        grep_app_tool_error_response(
            Some("other_app"),
            GREP_APP_SEARCH_ACTION,
            &with_usage_advice
        )
        .is_none(),
        "other MCP endpoints keep their vendor errors"
    );
}

#[test]
fn grep_app_upstream_rate_limit_tool_error_is_recognized_narrowly() {
    let text = include_str!("../tests/fixtures/grep_app/rate_limit_tool_error.txt").trim();
    let (kind, response) =
        grep_app_tool_error_response(Some(GREP_APP_APP_KEY), GREP_APP_SEARCH_ACTION, text)
            .expect("the upstream rate-limit parser error is recognized");
    assert_eq!(kind, GrepAppToolError::RateLimited);
    assert_eq!(response.retryability, Retryability::Throttle);
    assert_eq!(response.error_code.as_deref(), Some("throttled"));
    assert_eq!(response.retry_after_ms, Some(30_000));
    assert!(
        grep_app_tool_error_response(
            Some(GREP_APP_APP_KEY),
            GREP_APP_SEARCH_ACTION,
            "Unexpected token 'T', \"Too Many Tokens\" is not valid JSON"
        )
        .is_none(),
        "a different JSON parse failure is not a grep.app rate limit"
    );
    assert!(
        grep_app_tool_error_response(Some(GREP_APP_APP_KEY), "otherAction", text).is_none(),
        "only searchGitHub's response uses this vendor-specific hint"
    );
}

#[test]
fn catalog_app_key_is_carried_into_mcp_connection_config() {
    let source = include_str!("../../../catalog/grep_app.jsonc");
    let source = subc_jsonc::jsonc_to_json(source).expect("shipped catalog is valid JSONC");
    let manifest: crate::manifest::AppManifest =
        serde_json::from_str(&source).expect("reviewed grep.app manifest");

    let connection = McpConnection::from_manifest("grep", &manifest);
    assert_eq!(manifest.key, GREP_APP_APP_KEY);
    assert!(manifest
        .actions_baseline
        .iter()
        .any(|action| action.name == GREP_APP_SEARCH_ACTION));
    assert_eq!(
        connection.config.app_key.as_deref(),
        Some(manifest.key.as_str())
    );
}

use std::net::TcpListener;

pub(super) fn start_server<F>(
    requests: usize,
    handler: F,
) -> (String, crate::test_http::FixedRequestServer)
where
    F: Fn(usize, &str) -> String + Send + 'static,
{
    let (base, task) =
        crate::test_http::FixedRequestServer::start(requests, "MCP", move |index, wire| {
            let reply = handler(index, wire);
            // Canned JSON fixtures describe the result, not the request counter.
            // Echo the actual RPC id just as a conforming server does. Protocol
            // mismatch tests use FixedRequestServer directly, without this helper.
            let Some((headers, body)) = reply.split_once("\r\n\r\n") else {
                return reply;
            };
            if !headers.contains("Content-Type: application/json") {
                return reply;
            }
            let Some(request) = wire
                .split_once("\r\n\r\n")
                .and_then(|(_, body)| serde_json::from_str::<Value>(body).ok())
            else {
                return reply;
            };
            let Ok(mut envelope) = serde_json::from_str::<Value>(body) else {
                return reply;
            };
            if request.get("id").is_none()
                || (!envelope.get("result").is_some() && !envelope.get("error").is_some())
            {
                return reply;
            }
            envelope["id"] = request["id"].clone();
            let encoded = envelope.to_string();
            let headers = headers.replace(
                &format!("Content-Length: {}", body.len()),
                &format!("Content-Length: {}", encoded.len()),
            );
            format!("{headers}\r\n\r\n{encoded}")
        });
    (format!("{base}/mcp"), task)
}

pub(super) fn response(status: u16, body: &str, extra_headers: &str) -> String {
    let crlf = [char::from(13), char::from(10)]
        .into_iter()
        .collect::<String>();
    let extra = if extra_headers.is_empty() {
        String::new()
    } else {
        format!("{extra_headers}{crlf}")
    };
    format!(
            "HTTP/1.1 {status}{crlf}Content-Type: application/json{crlf}Content-Length: {}{crlf}Connection: close{crlf}{extra}{crlf}{body}",
            body.len()
        )
}

pub(super) fn notification_response() -> String {
    let crlf = [char::from(13), char::from(10)]
        .into_iter()
        .collect::<String>();
    format!("HTTP/1.1 202 Accepted{crlf}Content-Length: 0{crlf}Connection: close{crlf}{crlf}")
}

pub(super) fn request(connection_id: &str, action: &str) -> TransportRequest {
    TransportRequest {
        request_id: "request-1".to_string(),
        connection_id: connection_id.to_string(),
        action: action.to_string(),
        args: json!({"value": "ordinary"}),
        credential_fingerprint: "fp".to_string(),
    }
}

pub(super) fn config(endpoint: String) -> McpRemoteConfig {
    McpRemoteConfig::new(endpoint).with_bindings(vec![CredentialBinding {
        ref_role: "credential".to_string(),
        placement: "header".to_string(),
        key: "authorization".to_string(),
        prefix: "Bearer ".to_string(),
        required: true,
    }])
}

fn poisoned_entry_response() -> TransportResponse {
    let config = config("http://127.0.0.1:0/mcp".to_string());
    let transport = McpRemoteTransport::new(config.clone());
    let entry = transport
        .entry_for("poisoned", &config)
        .expect("create pooled MCP entry");
    let poisoned_entry = Arc::clone(&entry.entry);
    let poisoner = std::thread::spawn(move || {
        let _guard = poisoned_entry
            .lock()
            .expect("entry must be healthy before the poison is induced");
        panic!("poison the real pooled MCP entry while holding its guard");
    });
    assert!(
        poisoner.join().is_err(),
        "the poisoner must panic while holding the real entry guard"
    );

    transport.dispatch(
        request("poisoned", "read_tool"),
        &ResolvedCredential::new(b"CANARY".to_vec(), None, 1),
    )
}

fn connect_failure_response() -> TransportResponse {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve refused TCP endpoint");
    let address = listener.local_addr().expect("read refused TCP endpoint");
    drop(listener);

    McpRemoteTransport::new(config(format!("http://{address}/mcp"))).dispatch(
        request("refused", "read_tool"),
        &ResolvedCredential::new(b"CANARY".to_vec(), None, 1),
    )
}

#[test]
fn invalid_request_diagnostic_is_not_sent_through_mcp() {
    let cfg = config("not a valid URL".to_string());
    let transport = McpRemoteTransport::new(cfg.clone());
    // Exercise the tool-post path, not a failed initialize. Initialization
    // failures now explicitly report that the tool was never sent.
    transport
        .entry_for("invalid", &cfg)
        .unwrap()
        .lock()
        .unwrap()
        .initialized = true;
    let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
    let result = transport.dispatch(request("invalid", "read_tool"), &credential);

    assert_eq!(
        (result.transmission, result.error_code.as_deref()),
        (TransmissionState::NotSent, Some("http_request_invalid"))
    );
}

#[test]
fn poisoned_lock_and_connect_failure_have_distinct_wire_codes() {
    let poisoned = poisoned_entry_response();
    let refused = connect_failure_response();

    assert_eq!(
        poisoned.error_code.as_deref(),
        Some("transport_restart_required")
    );
    assert_eq!(refused.error_code.as_deref(), Some("transport_transient"));
    assert_ne!(poisoned.error_code, refused.error_code);
    assert_eq!(refused.transmission, TransmissionState::NotSent);
    assert_eq!(refused.retryability, Retryability::AutoRetryable);
}

#[test]
fn poisoned_lock_is_terminal_without_claiming_transmission() {
    let response = poisoned_entry_response();

    assert_eq!(response.transmission, TransmissionState::NotSent);
    assert_eq!(response.retryability, Retryability::Terminal);
}

#[test]
fn debug_projection_does_not_include_credential_binding_values() {
    let mut config = McpRemoteConfig::new("https://vendor.invalid/mcp?token=CANARY");
    config.credential_bindings.push(CredentialBinding {
        ref_role: "credential".to_string(),
        placement: "header".to_string(),
        key: "authorization".to_string(),
        prefix: "Bearer ".to_string(),
        required: true,
    });
    let transport = McpRemoteTransport::new(config);
    let rendered = format!("{transport:?}");
    assert!(!rendered.contains("CANARY"));

    // An empty projection satisfies the absence assertion above perfectly,
    // so it cannot stand alone: a debug projection is read during an
    // incident, and one that renders nothing leaks nothing and diagnoses
    // nothing. Assert the non-secret fields survive redaction.
    assert!(
        rendered.contains("vendor.invalid"),
        "the projection dropped the vendor host, leaving nothing to diagnose: {rendered}"
    );
    assert!(
        rendered.contains("credential_binding_count"),
        "the projection dropped the binding count: {rendered}"
    );
}
