use super::tests::{config, notification_response, request, response, start_server};
use super::*;
use crate::test_scratch::Scratch;
use crate::CredentialSource;
use std::thread;

#[test]
fn mcp_lookup_reserves_lease_before_releasing_the_pool_map() {
    for discovery in [false, true] {
        let (endpoint, server) = start_server(3, move |index, _| match index {
            0 => response(200, r#"{"id":1,"result":{}}"#, ""),
            1 => notification_response(),
            _ if discovery => response(
                200,
                r#"{"id":2,"result":{"tools":[{"name":"read_tool","inputSchema":{}}]}}"#,
                "",
            ),
            _ => response(200, r#"{"id":2,"result":{"ok":true}}"#, ""),
        });
        let cfg = config(endpoint);
        let transport = Arc::new(McpRemoteTransport::new(cfg.clone()));
        // Seed the zero reservations of an idle connection directly, so
        // fixture setup does not acquire/release the lease being tested.
        transport.entries.lock().unwrap().insert(
            "lease-gap".into(),
            Arc::new(PooledEntry {
                state: Mutex::new(ConnectionEntry::build(&cfg, transport.clock.clone()).unwrap()),
                leases: AtomicUsize::new(0),
            }),
        );
        assert!(transport.age_entry_for_test("lease-gap", Duration::from_secs(600)));
        let (reached, paused) = std::sync::mpsc::sync_channel(1);
        let (resume, released) = std::sync::mpsc::sync_channel(1);
        *transport.lookup_pause.lock().unwrap() = Some(LookupPause {
            connection_id: "lease-gap".into(),
            reached,
            resume: released,
        });
        let caller = Arc::clone(&transport);
        let worker = thread::spawn(move || {
            if discovery {
                assert_eq!(
                    caller
                        .discover(
                            &McpConnection {
                                connection_id: "lease-gap".into(),
                                config: cfg
                            },
                            &ResolvedCredential::anonymous()
                        )
                        .unwrap()[0]
                        .name,
                    "read_tool"
                );
            } else {
                assert_eq!(
                    caller
                        .dispatch(
                            request("lease-gap", "read_tool"),
                            &ResolvedCredential::anonymous()
                        )
                        .response
                        .unwrap()["ok"],
                    true
                );
            }
        });
        let borrowed = paused
            .recv_timeout(Duration::from_secs(5))
            .expect("caller paused after pool lookup");
        // Sweep in the exact lookup-to-entry-lock gap, without sleeps. The
        // caller must already own a lease even though it has not sent yet.
        let removed = transport.sweep_idle();
        let pooled = transport
            .entries
            .lock()
            .unwrap()
            .get("lease-gap")
            .map(|entry| Arc::as_ptr(entry) as usize);
        resume.send(()).unwrap();
        worker.join().unwrap();
        server.join().unwrap();
        assert_eq!(
            removed, 0,
            "lookup must reserve a lease before the pool map is released (discovery={discovery})"
        );
        assert_eq!(
            pooled,
            Some(borrowed),
            "the paused caller must retain the same pooled entry"
        );
    }
}

// Keep serving after the first error: a duplicate call must reach the mock
// vendor and increment its counter, not fail against a closed test socket.
fn rpc_error_vendor(error: Value) -> (String, Arc<AtomicU64>, crate::test_http::KeepAliveServer) {
    let calls = Arc::new(AtomicU64::new(0));
    let observed = Arc::clone(&calls);
    let vendor = crate::test_http::KeepAliveServer::start(Duration::from_secs(2), move |wire| {
        let rpc: Value = serde_json::from_str(wire.split_once("\r\n\r\n").unwrap().1).unwrap();
        if rpc["method"] == "notifications/initialized" {
            return notification_response().replace("Connection: close\r\n", "");
        }
        let body = if rpc["method"] == "initialize" {
            json!({"jsonrpc":"2.0","id":rpc["id"],"result":{}})
        } else {
            assert_eq!(rpc["method"], "tools/call");
            observed.fetch_add(1, Ordering::Relaxed);
            json!({"jsonrpc":"2.0","id":rpc["id"],"error":error})
        };
        response(200, &body.to_string(), "").replace("Connection: close\r\n", "")
    });
    (format!("http://{}/mcp", vendor.address()), calls, vendor)
}

#[test]
fn vendor_error_diagnostics_are_bounded() {
    const TEST: &str =
        "mcp_remote::transport_integration_tests::vendor_error_diagnostics_are_bounded";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
        use crate::test_logging as logging;
        logging::init_child();
        for tool in [false, true] {
            let (endpoint, task) = start_server(3, move |index, _| match index {
                0 => response(200, r#"{"id":1,"result":{}}"#, ""),
                1 => notification_response(),
                _ => {
                    let text = "界".repeat(1024 * 1024 / 3);
                    let envelope = if tool {
                        json!({"id":2,"result":{"isError":true,"content":[{"text":text}]}})
                    } else {
                        json!({"id":2,"error":{"code":"vendor_failure","message":text}})
                    };
                    response(200, &envelope.to_string(), "")
                }
            });
            let result = McpRemoteTransport::new(config(endpoint)).dispatch(
                request("logs", "read_tool"),
                &ResolvedCredential::anonymous(),
            );
            assert!(result.error_code.is_some());
            task.join().unwrap();
        }
        return;
    }
    let output = crate::test_http::bounded::child_test_output(
        TEST,
        &[("PLEXUS_LOG_STDERR_CHILD", "1")],
        Duration::from_secs(30),
        "MCP bounded vendor diagnostic child",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    let lines: Vec<_> = stderr
        .lines()
        .filter(|line| line.contains("vendor rpc error:") || line.contains("vendor tool error on"))
        .collect();
    assert_eq!(lines.len(), 2);
    println!(
        "vendor diagnostic bytes: rpc={} tool={}",
        lines[0].len(),
        lines[1].len()
    );
    assert!(
        lines.iter().all(|line| line.len() <= 4352),
        "vendor diagnostics must be capped near 4096 bytes"
    );
}

#[test]
fn negotiated_protocol_accepts_capture_defaults_omission_and_refuses_unsupported() {
    let captured = parse_sse_reply(
        include_str!("../tests/fixtures/grep_app/initialize.sse"),
        Some(&json!(1)),
    )
    .unwrap();
    for version in [
        Some(MCP_PROTOCOL_VERSION),
        Some(MCP_PROTOCOL_VERSION_JUNE),
        None,
        Some("2099-01-01"),
    ] {
        let mut initialize = captured.clone();
        if let Some(version) = version {
            initialize["result"]["protocolVersion"] = json!(version);
        } else {
            initialize["result"]
                .as_object_mut()
                .unwrap()
                .remove("protocolVersion");
        }
        let supported = version != Some("2099-01-01");
        let (endpoint, task) = start_server(if supported { 3 } else { 1 }, move |index, wire| {
            if index == 0 {
                let initialize_request: Value =
                    serde_json::from_str(wire.split_once("\r\n\r\n").unwrap().1).unwrap();
                assert_eq!(
                    initialize_request["params"]["clientInfo"]["version"],
                    env!("CARGO_PKG_VERSION"),
                    "clientInfo must name the package version, not just User-Agent"
                );
                return response(200, &initialize.to_string(), "");
            }
            let expected = version.unwrap_or(MCP_PROTOCOL_VERSION);
            assert!(wire
                .to_ascii_lowercase()
                .contains(&format!("mcp-protocol-version: {expected}")));
            if index == 1 {
                notification_response()
            } else {
                response(200, r#"{"id":2,"result":{"ok":true}}"#, "")
            }
        });
        let result = McpRemoteTransport::new(config(endpoint)).dispatch(
            request("protocol", "read_tool"),
            &ResolvedCredential::anonymous(),
        );
        task.join().unwrap();
        if supported {
            assert_eq!(result.response.unwrap()["ok"], true);
        } else {
            assert_eq!(result.transmission, TransmissionState::NotSent);
            assert_eq!(
                result.error_code.as_deref(),
                Some("mcp_unsupported_protocol_version")
            );
        }
    }
}

#[test]
fn sse_matching_answer_finishes_without_waiting_for_stream_eof() {
    use std::io::Write;
    let (release, wait) = std::sync::mpsc::channel::<()>();
    // The shared fixture bounds every accept and read, so a client that
    // sends fewer than three requests fails at join instead of hanging.
    let (base, server) = crate::test_http::FixedRequestServer::start_writing(
        3,
        "MCP SSE",
        Duration::from_secs(6),
        move |index, wire, socket| {
            let body: Value = serde_json::from_str(wire.split_once("\r\n\r\n").unwrap().1).unwrap();
            if index == 0 {
                let _ = socket.write_all(
                    response(200, &json!({"id":body["id"],"result":{}}).to_string(), "").as_bytes(),
                );
                return;
            }
            if index == 1 {
                let _ = socket.write_all(notification_response().as_bytes());
                return;
            }
            let event = format!("data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}}\n\ndata: {}\n\n", json!({"id":body["id"],"result":{"ok":true}}));
            let _ = socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{event}\r\n", event.len()).as_bytes());
            let _ = socket.flush();
            // Hold the stream open, with no terminating chunk, until the
            // client has its answer: a client that waited for end of
            // stream would hit its request timeout first.
            let _ = wait.recv_timeout(Duration::from_secs(3));
        },
    );
    let mut cfg = config(format!("{base}/mcp"));
    cfg.request_timeout = Duration::from_millis(500);
    let result = McpRemoteTransport::new(cfg).dispatch(
        request("stream", "read_tool"),
        &ResolvedCredential::anonymous(),
    );
    let _ = release.send(());
    server.join().unwrap();
    assert_eq!(
        result
            .response
            .expect("matching SSE answer must not await EOF")["ok"],
        true
    );
}

#[test]
fn initialize_timeout_is_not_sent_with_zero_tool_calls() {
    let calls = Arc::new(AtomicU64::new(0));
    let observed = Arc::clone(&calls);
    let (endpoint, task) = start_server(1, move |_, wire| {
        if wire.contains("tools/call") {
            observed.fetch_add(1, Ordering::Relaxed);
        }
        assert!(wire.contains("initialize"));
        thread::sleep(Duration::from_millis(150));
        response(200, r#"{"id":1,"result":{}}"#, "")
    });
    let mut cfg = config(endpoint);
    cfg.request_timeout = Duration::from_millis(40);
    let result = McpRemoteTransport::new(cfg).dispatch(
        request("init-timeout", "write_tool"),
        &ResolvedCredential::anonymous(),
    );
    task.join().unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(result.transmission, TransmissionState::NotSent);
    assert_eq!(result.retryability, Retryability::AutoRetryable);
    assert_eq!(result.error_code.as_deref(), Some("timeout"));
}

#[test]
fn initialize_and_notification_refusals_are_not_tool_failures() {
    for status in [403, 500, 429] {
        for notification in [false, true] {
            let (endpoint, task) =
                start_server(if notification { 2 } else { 1 }, move |index, wire| {
                    assert!(!wire.contains("tools/call"));
                    if notification && index == 0 {
                        response(200, r#"{"id":1,"result":{}}"#, "")
                    } else {
                        response(
                            status,
                            r#"{"error":{"code":"vendor_failed"}}"#,
                            "Retry-After: 1",
                        )
                    }
                });
            let result = McpRemoteTransport::new(config(endpoint)).dispatch(
                request("init-refusal", "write_tool"),
                &ResolvedCredential::anonymous(),
            );
            task.join().unwrap();
            assert_eq!(
                result.transmission,
                TransmissionState::NotSent,
                "{status} notification={notification}"
            );
            assert_eq!(
                result.retryability,
                if matches!(status, 403 | 429) {
                    Retryability::Throttle
                } else {
                    Retryability::Terminal
                }
            );
        }
    }
}

#[test]
fn json_response_id_must_match_the_posted_tool_call() {
    let (base, task) =
        crate::test_http::FixedRequestServer::start(3, "MCP mismatched id", |index, wire| {
            if index == 1 {
                return notification_response();
            }
            let body: Value = serde_json::from_str(wire.split_once("\r\n\r\n").unwrap().1).unwrap();
            let id = if index == 0 {
                body["id"].clone()
            } else {
                json!(99999)
            };
            response(
                200,
                &json!({"jsonrpc":"2.0", "id":id, "result":{"ok":true}}).to_string(),
                "",
            )
        });
    let result = McpRemoteTransport::new(config(format!("{base}/mcp"))).dispatch(
        request("mismatch", "write_tool"),
        &ResolvedCredential::anonymous(),
    );
    task.join().unwrap();
    assert!(
        result.response.is_none(),
        "a mismatched id is not this call's response"
    );
    assert_eq!(result.error_code.as_deref(), Some("mcp_protocol_error"));
}

#[test]
fn remote_discovery_reads_all_tool_pages_and_rejects_repeated_cursors() {
    for repeat in [false, true] {
        let (endpoint, task) = start_server(4, move |index, wire| match index {
            0 => response(200, r#"{"id":1,"result":{}}"#, ""),
            1 => notification_response(),
            2 => response(
                200,
                r#"{"id":2,"result":{"tools":[{"name":"first","inputSchema":{}}],"nextCursor":"page2"}}"#,
                "",
            ),
            _ => {
                assert!(wire.contains(r#""cursor":"page2""#));
                let mut result = json!({"tools":[{"name":"second", "inputSchema":{}}]});
                if repeat {
                    result["nextCursor"] = json!("page2");
                }
                response(200, &json!({"id":3,"result":result}).to_string(), "")
            }
        });
        let transport = McpRemoteTransport::new(config(endpoint.clone()));
        let result = transport.discover(
            &McpConnection::new("pages", endpoint),
            &ResolvedCredential::anonymous(),
        );
        task.join().unwrap();
        if repeat {
            assert_eq!(result.unwrap_err(), McpRemoteError::Protocol);
        } else {
            assert_eq!(
                result
                    .unwrap()
                    .iter()
                    .map(|action| action.name.as_str())
                    .collect::<Vec<_>>(),
                ["first", "second"]
            );
        }
    }
}

#[test]
fn pooled_mcp_throttle_survives_idle_sweep() {
    let transport = McpRemoteTransport::default();
    let cfg = config("http://127.0.0.1:1".into());
    let entry = transport.entry_for("throttled", &cfg).unwrap();
    {
        let mut state = entry.lock().unwrap();
        state.throttle_until = Some(Instant::now() + Duration::from_secs(3600));
    }
    drop(entry);
    assert!(transport.age_entry_for_test("throttled", Duration::from_secs(600)));
    assert_eq!(
        transport.sweep_idle(),
        0,
        "an active throttle must survive idle eviction"
    );
    assert_eq!(transport.connection_count(), 1);
}

#[test]
fn unregister_mcp_removes_configuration_and_pooled_entry() {
    let transport = McpRemoteTransport::default();
    let connection = McpConnection::new("removed", "http://127.0.0.1:1");
    transport.register_connection(connection.clone());
    transport.entry_for("removed", &connection.config).unwrap();
    assert!(transport.has_connection("removed"));
    transport.unregister_connection("removed");
    assert!(!transport.has_connection("removed"));
    assert!(transport.configs.lock().unwrap().is_empty());
    assert_eq!(transport.connection_count(), 0);
}

#[test]
fn debug_mcp_transport_does_not_wait_for_its_entries_lock() {
    let transport = Arc::new(McpRemoteTransport::default());
    let lock = transport.entries.lock().unwrap();
    let worker_transport = Arc::clone(&transport);
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || tx.send(format!("{worker_transport:?}")).unwrap());
    let formatted = rx.recv_timeout(Duration::from_millis(250));
    drop(lock);
    worker.join().unwrap();
    assert!(formatted.is_ok(), "Debug must not wait for the pool lock");
}

#[test]
fn rpc_request_timeout_is_outcome_unknown_without_resending_the_write() {
    let (endpoint, calls, _vendor) =
        rpc_error_vendor(json!({"code":-32001,"message":"Request timed out"}));
    let result = McpRemoteTransport::new(config(endpoint)).dispatch(
        request("rpc-timeout", "write_tool"),
        &ResolvedCredential::anonymous(),
    );
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "a timed-out write must not be resent"
    );
    assert_eq!(result.transmission, TransmissionState::OutcomeUnknown);
    assert_eq!(result.retryability, Retryability::Terminal);
    assert_eq!(result.error_code.as_deref(), Some("timeout"));
}

#[test]
fn rpc_auth_or_session_words_are_vendor_errors_without_resending() {
    for code in ["session_timeout", "auth_backend_failed", "stale_data"] {
        let (endpoint, calls, _vendor) = rpc_error_vendor(
            json!({"code":code,"message":"session auth failed after applying write"}),
        );
        let result = McpRemoteTransport::new(config(endpoint)).dispatch(
            request("rpc-vendor", "write_tool"),
            &ResolvedCredential::anonymous(),
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "RPC prose must not resend {code}"
        );
        assert_eq!(result.transmission, TransmissionState::Sent, "{code}");
        assert_eq!(result.retryability, Retryability::Terminal, "{code}");
        assert_eq!(
            result.error_code.as_deref(),
            Some("mcp_request_failed"),
            "{code}"
        );
    }
}

#[test]
fn http_401_on_tool_call_reconnects_and_resends_once() {
    let calls = Arc::new(AtomicU64::new(0));
    let observed = Arc::clone(&calls);
    let (endpoint, task) = start_server(6, move |index, wire| match index {
        0 | 3 => response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, ""),
        1 | 4 => notification_response(),
        2 => {
            assert!(wire.contains("tools/call"));
            observed.fetch_add(1, Ordering::Relaxed);
            response(401, "", "")
        }
        _ => {
            assert!(wire.contains("tools/call"));
            observed.fetch_add(1, Ordering::Relaxed);
            response(200, r#"{"jsonrpc":"2.0","id":0,"result":{"ok":true}}"#, "")
        }
    });
    let result = McpRemoteTransport::new(config(endpoint)).dispatch(
        request("http-auth", "write_tool"),
        &ResolvedCredential::anonymous(),
    );
    task.join().expect("server exits after one reconnect");
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(result.response.expect("successful retry")["ok"], true);
}

#[test]
fn auth_rejection_reconnects_and_retries_exactly_once() {
    let (seen, task) = start_server(4, |index, request| {
        if index == 0 {
            assert!(request
                .to_ascii_lowercase()
                .contains("authorization: bearer canary"));
            return response(401, r#"{"error":{"code":"unauthorized"}}"#, "");
        }
        if index == 2 {
            return notification_response();
        }
        if index == 1 {
            return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
        }
        response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, "")
    });
    let transport = McpRemoteTransport::new(config(seen));
    let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
    let result = transport.dispatch(request("auth", "read_tool"), &credential);
    assert_eq!(result.retryability, Retryability::Terminal);
    assert_eq!(result.response.expect("successful MCP call")["ok"], true);
    task.join().expect("auth retry server exits");
}

#[test]
fn forbidden_response_is_a_terminal_vendor_failure_without_auth_reporting() {
    let (endpoint, task) = start_server(3, |index, _request| match index {
        0 => response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, ""),
        1 => notification_response(),
        2 => response(
            403,
            r#"{"error":{"code":"forbidden","message":"missing permission"}}"#,
            "",
        ),
        _ => unreachable!("a 403 must not reconnect the MCP session"),
    });
    let transport = McpRemoteTransport::new(config(endpoint));
    let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);

    let result = transport.dispatch(request("forbidden", "read_tool"), &credential);
    task.join().expect("server exits");

    assert_eq!(
        result.transmission,
        TransmissionState::Sent,
        "forbidden response must be sent and terminal: {result:?}"
    );
    assert_eq!(result.retryability, Retryability::Terminal);
    assert_eq!(result.error_code.as_deref(), Some("http_403"));
    assert_eq!(result.provider_auth_status(), None);
    assert!(result.response.is_none());
}

/// An MCP tool result reaches the caller BYTE-FOR-BYTE, with no field
/// rewritten in transit.
///
/// Both transports once passed vendor responses through
/// `http_support::redact_value`, which replaces the value of any field
/// whose NAME contains "token", "payload", "secret" and similar with a
/// fingerprint. On a vendor response those are names we do not control, so
/// it destroyed ordinary data: `payload` is an ordinary field name in tool
/// results, and the whole nested object was replaced with nothing marking
/// the value as redacted. The REST transport carries the equivalent test;
/// this covers the MCP path, since a guard on only one dispatch path
/// leaves the other free to reacquire the behaviour.
///
/// The assertion is non-vacuous: re-adding the `redact_value` call to this
/// function makes this test fail.
#[test]
fn an_mcp_tool_result_reaches_the_caller_verbatim() {
    let (endpoint, task) = start_server(3, |index, _request| {
        if index == 0 {
            return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
        }
        if index == 1 {
            return notification_response();
        }
        response(
            200,
            r#"{"jsonrpc":"2.0","id":2,"result":{"payload":{"summary":"Standup"},"next_cursor":"tok-2"}}"#,
            "",
        )
    });
    let transport = McpRemoteTransport::new(config(endpoint));
    let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
    let result = transport.dispatch(request("verbatim", "read_tool"), &credential);
    task.join().expect("server exits");

    let body = result.response.expect("successful MCP call");
    assert_eq!(
        body["payload"]["summary"], "Standup",
        "a nested tool-result field was rewritten in transit: {body}"
    );
    assert_eq!(
        body["next_cursor"], "tok-2",
        "the cursor field was rewritten in transit: {body}"
    );
}

/// A JSON payload inside MCP's text content block is decoded, and everything
/// the decoding does not understand keeps its envelope.
///
/// Driven through the real dispatch path rather than by calling the decoder,
/// because the defect was that no caller decoded at all: the poller looked
/// for its manifest-declared items field at the top level, found `content`,
/// and reported a successful poll with zero events against a repository with
/// eleven issues. Nothing failed, because an absent items field is
/// indistinguishable from a quiet period.
///
/// All four arms matter, and three of them are the reason this is a widening
/// rather than a rewrite: prose must not be mangled, a bare scalar must not
/// replace an indexable result, and a multi-block result has no single
/// payload to choose.
///
/// Mutation-proved: returning `result` unchanged from `decode_tool_result`
/// fails the first arm; returning the parsed value unconditionally fails the
/// scalar arm.
#[test]
fn a_json_payload_in_an_mcp_text_block_is_decoded() {
    // What GitHub actually sends: the array serialized into a text block,
    // with no structuredContent alongside it.
    let wrapped = r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"issues\":[{\"number\":4,\"title\":\"Seam\"}]}"}]}}"#;
    let (endpoint, task) = start_server(3, move |index, _request| {
        if index == 0 {
            return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
        }
        if index == 1 {
            return notification_response();
        }
        response(200, wrapped, "")
    });
    let transport = McpRemoteTransport::new(config(endpoint));
    let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
    let body = transport
        .dispatch(request("decode", "list_issues"), &credential)
        .response
        .expect("successful MCP call");
    task.join().expect("server exits");
    assert_eq!(
        body["issues"][0]["number"], 4,
        "the declared items field must be reachable at the top level: {body}"
    );

    // Prose in a text block is not a payload and must survive untouched.
    let prose = decode_tool_result(serde_json::json!({
        "content": [{"type": "text", "text": "stub-ok:read_item"}]
    }));
    assert_eq!(
        prose["content"][0]["text"], "stub-ok:read_item",
        "a non-JSON text block must keep its envelope: {prose}"
    );

    // A bare JSON scalar parses, and replacing a result with it would leave
    // callers nothing to index.
    let scalar = decode_tool_result(serde_json::json!({
        "content": [{"type": "text", "text": "4"}]
    }));
    assert!(
        scalar.get("content").is_some(),
        "a scalar must not replace the result: {scalar}"
    );

    // structuredContent is the protocol's own answer and outranks the text
    // block when a vendor sends it.
    let structured = decode_tool_result(serde_json::json!({
        "structuredContent": {"issues": []},
        "content": [{"type": "text", "text": "{\"issues\":[{\"number\":9}]}"}]
    }));
    assert!(
        structured["issues"]
            .as_array()
            .is_some_and(|a| a.is_empty()),
        "structuredContent must win over the text block: {structured}"
    );
}

#[test]
fn request_timeout_is_outcome_unknown_and_is_not_retried() {
    let (endpoint, task) = start_server(3, |index, _request| {
        if index == 0 {
            return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
        }
        if index == 1 {
            return notification_response();
        }
        std::thread::sleep(Duration::from_millis(150));
        response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, "")
    });
    let mut remote_config = config(endpoint);
    remote_config.request_timeout = Duration::from_millis(40);
    let transport = McpRemoteTransport::new(remote_config);
    let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
    let result = transport.dispatch(request("timeout", "read_tool"), &credential);
    assert_eq!(result.transmission, TransmissionState::OutcomeUnknown);
    assert_eq!(result.retryability, Retryability::Terminal);
    task.join().expect("timeout server exits after one request");
}

#[test]
fn retry_after_is_returned_as_throttle_and_honored_before_next_call() {
    let (endpoint, task) = start_server(4, |index, request| {
        if request.contains("notifications/initialized") {
            return notification_response();
        }
        if request.contains("initialize") {
            return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
        }
        if index == 2 {
            return response(
                429,
                r#"{"error":{"code":"rate_limited"}}"#,
                "Retry-After: 1",
            );
        }
        response(200, r#"{"jsonrpc":"2.0","id":3,"result":{"ok":true}}"#, "")
    });
    let clock = TransportClock::manual();
    let transport = McpRemoteTransport::new(config(endpoint)).with_clock(clock.clone());
    let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
    let first = transport.dispatch(request("throttle", "read_tool"), &credential);
    assert_eq!(first.retryability, Retryability::Throttle);
    assert_eq!(
        first.retry_after_ms,
        Some(1_000),
        "the vendor's delay reaches the caller as a number, not only as prose"
    );
    // The transport waits on the manual clock, which moves only when slept
    // on: the time it shows passing is the wait the transport made.
    let started = clock.now();
    let second = transport.dispatch(request("throttle", "read_tool"), &credential);
    assert!(
        clock.now().duration_since(started) >= Duration::from_millis(900),
        "retry-after must be honored before the next call"
    );
    assert!(second.response.is_some());
    task.join().expect("throttle server exits");
}

/// A transport built for production reads the real clock: a manual or frozen
/// one would make every throttle wait pass instantly.
#[test]
fn a_new_mcp_transport_reads_the_real_clock() {
    let transport = McpRemoteTransport::default();
    let before = Instant::now();
    thread::sleep(Duration::from_millis(5));
    let read = transport.clock.now();
    assert!(
        read >= before + Duration::from_millis(5) && read <= Instant::now(),
        "the transport clock must be the real one"
    );
}

#[test]
fn tools_list_discovery_accepts_streamable_http_json() {
    let (endpoint, task) = start_server(3, |_index, request| {
        if request.contains("notifications/initialized") {
            return notification_response();
        }
        if request.contains("initialize") {
            return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
        }
        response(
            200,
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_tool","title":"Read","inputSchema":{"type":"object"}}]}}"#,
            "",
        )
    });
    let transport = McpRemoteTransport::new(config(endpoint.clone()));
    let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
    let connection = McpConnection {
        connection_id: "discover".to_string(),
        config: config(endpoint),
    };
    let actions = transport
        .discover(&connection, &credential)
        .expect("tools/list discovery");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].name, "read_tool");
    assert!(crate::jcs::jcs_sha256(&actions[0].input_schema)
        .expect("test schema is JCS-compatible")
        .starts_with("sha256:"));
    task.join().expect("discovery server exits");
}

struct IntegrationCkcredPeer {
    calls: std::sync::Mutex<Vec<(String, Value)>>,
}

impl IntegrationCkcredPeer {
    fn new() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl crate::CkcredRoutePeer for IntegrationCkcredPeer {
    fn call(&self, operation: &str, params: Value) -> Result<Value, crate::CkcredRouteError> {
        self.calls
            .lock()
            .map_err(|_| crate::CkcredRouteError::Transport)?
            .push((operation.to_string(), params));
        if operation == "credential.get_scoped" {
            Ok(json!({
                "result": {
                    "payload": [67, 65, 78, 65, 82, 89, 45, 80, 65, 89, 76, 79, 65, 68],
                    "record_version": 11, "credential_id": "test:CANARY-HANDLE"
                }
            }))
        } else {
            Err(crate::CkcredRouteError::Transport)
        }
    }
}

fn integration_manifest() -> crate::AppManifest {
    serde_json::from_value(json!({
        "schema_version": 1,
        "key": "mock",
        "name": "Mock",
        "description": "HTTP integration manifest",
        "reuse_path": "mcp_direct",
        "reuse_rationale": "in-process test server",
        "tier": "S1",
        "transport": {"kind": "mcp_remote", "url": "https://unused.invalid/mcp"},
        "auth": {"mode": "api_key"},
        "credential_bindings": [{
            "ref_role": "primary", "placement": "header", "key": "Authorization",
            "prefix": "Bearer ", "required": true
        }],
        "resource_filters": {"required": [], "optional": [], "write_enabling": []},
        "actions_baseline": [
            {"name": "read_tool", "risk": "read"},
            {"name": "write_tool", "risk": "write"}
        ],
        "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 30}},
        "availability": "ga"
    }))
    .expect("integration manifest")
}

#[test]
fn full_http_catalog_governance_path_quarantines_schema_drift() {
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    use std::sync::atomic::{AtomicBool, Ordering};

    let schema_changed = std::sync::Arc::new(AtomicBool::new(false));
    let schema_changed_for_server = std::sync::Arc::clone(&schema_changed);
    let wire_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let wire_requests_for_server = std::sync::Arc::clone(&wire_requests);
    // The macOS clock ticks in microseconds, so the counter prevents same-tick test nonce collisions.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let path = Scratch::database("http-e2e");
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("http-e2e-{unique}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    let store = std::sync::Arc::new(crate::PlexusStore::open(&descriptor).expect("e2e store"));
    store
        .insert_connection(
            "direct",
            "connection",
            "mock",
            "pending",
            &json!({"required": [], "write_enabling": []}),
        )
        .expect("e2e connection");
    let handle = b"test:CANARY-HANDLE";
    let ticket = store
        .create_binding_ticket("direct", "connection", handle)
        .expect("e2e binding ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume e2e ticket")
        .expect("active e2e connection");

    let manifest = integration_manifest();
    let ingested = crate::ingest_value(serde_json::to_value(&manifest).expect("manifest JSON"))
        .expect("ingest integration manifest");
    store
        .upsert_manifest("system", &ingested)
        .expect("store integration manifest");
    store
        .seed_catalog_from_manifest("direct", "connection", "mock")
        .expect("seed baseline catalog");
    store
        .insert_grant(&crate::GrantInput {
            grant_id: "read-grant".to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["read_tool".to_string()],
            authority_kind: "invoke".to_string(),
            expires_at: None,
        })
        .expect("read grant");
    store
        .insert_policy(&crate::PolicyInput {
            policy_id: "read-policy".to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            action_selector: "read_tool".to_string(),
            effect: "allow".to_string(),
            expires_at: None,
        })
        .expect("read policy");

    let route_peer = std::sync::Arc::new(IntegrationCkcredPeer::new());
    let credentials = crate::CkcredCredentialSource::new(route_peer);
    let resolved = credentials
        .get_by_id(std::str::from_utf8(handle).unwrap())
        .expect("resolve canary credential");

    // Start the vendor only after database and credential setup: its bounded
    // accept wait measures missing HTTP requests, not unrelated fixture work.
    let catalog_server_started = std::time::Instant::now();
    let (endpoint, task) = start_server(5, move |_index, request| {
        wire_requests_for_server
            .lock()
            .expect("wire request log")
            .push(request.to_string());
        if request.contains("\"method\":\"initialize\"") {
            return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
        }
        if request.contains("\"method\":\"notifications/initialized\"") {
            return notification_response();
        }
        if request.contains("\"method\":\"tools/list\"") {
            let write_type = if schema_changed_for_server.load(Ordering::Acquire) {
                "number"
            } else {
                "string"
            };
            let body = json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "tools": [
                        {
                            "name": "read_tool",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"q": {"type": "string"}}
                            }
                        },
                        {
                            "name": "write_tool",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"title": {"type": write_type}}
                            }
                        }
                    ]
                }
            });
            return response(200, &body.to_string(), "");
        }
        response(
            200,
            r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"read-ok"}]}}"#,
            "",
        )
    });

    let connection = McpConnection {
        connection_id: "connection".to_string(),
        config: config(endpoint.clone()),
    };
    let transport = std::sync::Arc::new(McpRemoteTransport::new(config(endpoint)));
    let reconciler = crate::CatalogReconciler::new(
        std::sync::Arc::clone(&store),
        std::sync::Arc::clone(&transport),
        Default::default(),
    );
    reconciler
        .refresh("direct", &connection, &manifest, &resolved)
        .unwrap_or_else(|error| {
            panic!(
                "HTTP catalog discovery: {error:?}; server age {:?}; completed requests {}",
                catalog_server_started.elapsed(),
                wire_requests.lock().expect("wire request log").len(),
            )
        });
    let first_rows = store
        .list_catalog_actions_all("direct", "connection")
        .expect("first catalog rows");
    assert!(first_rows
        .iter()
        .all(|row| row.schema_hash.starts_with("sha256:")));
    assert_eq!(
        first_rows
            .iter()
            .find(|row| row.name == "write_tool")
            .map(|row| row.status.as_str()),
        Some("active")
    );

    let engine = crate::GovernanceEngine::new(
        std::sync::Arc::clone(&store),
        std::sync::Arc::new(credentials.clone()),
        std::sync::Arc::clone(&transport),
    );
    let reservation = engine
        .authorize(crate::AuthorizationRequest::new(
            "direct",
            "connection",
            "read_tool",
            json!({"q": "hello"}),
        ))
        .expect("authorized read reservation");
    let read_outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(
        read_outcome.outcome,
        crate::TransportOutcome::Completed { response: Some(_) }
    ));

    schema_changed.store(true, Ordering::Release);
    reconciler
        .refresh("direct", &connection, &manifest, &resolved)
        .expect("HTTP rediscovery after schema mutation");
    let changed_rows = store
        .list_catalog_actions_all("direct", "connection")
        .expect("changed catalog rows");
    assert_eq!(
        changed_rows
            .iter()
            .find(|row| row.name == "write_tool")
            .map(|row| (row.status.as_str(), row.quarantine_reason.as_deref())),
        Some(("quarantined", Some("schema_changed_requires_review")))
    );
    assert!(matches!(
        engine.authorize(crate::AuthorizationRequest::new(
            "direct",
            "connection",
            "write_tool",
            json!({"title": "new"}),
        )),
        Err(crate::Denial::Catalog(crate::CatalogDenial::Quarantined))
    ));

    let rendered_transport = format!("{transport:?}");
    let rendered_outcome = format!("{read_outcome:?}");
    assert!(!rendered_transport.contains("test:CANARY-HANDLE"));
    assert!(!rendered_transport.contains("CANARY-PAYLOAD"));
    assert!(!rendered_outcome.contains("test:CANARY-HANDLE"));
    assert!(!rendered_outcome.contains("CANARY-PAYLOAD"));
    for row in store.list_audit("direct").expect("audit rows") {
        let rendered = serde_json::to_string(&row).expect("audit JSON");
        assert!(!rendered.contains("test:CANARY-HANDLE"));
        assert!(!rendered.contains("CANARY-PAYLOAD"));
    }
    let requests = wire_requests.lock().expect("wire request log");
    assert!(requests.iter().any(|request| request
        .to_ascii_lowercase()
        .contains("authorization: bearer canary-payload")));
    for request in requests.iter() {
        assert!(!request.contains("test:CANARY-HANDLE"));
        if request.contains("CANARY-PAYLOAD") {
            assert!(request
                .lines()
                .any(|line| line.to_ascii_lowercase().contains("authorization:")));
        }
    }
    task.join().expect("HTTP e2e server");
}

#[test]
fn mcp_http_failure_writes_mcp_operator_diagnostic() {
    const TEST: &str =
        "mcp_remote::transport_integration_tests::mcp_http_failure_writes_mcp_operator_diagnostic";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
        use crate::test_logging as logging;
        logging::init_child();
        let (endpoint, task) = start_server(3, |_index, request| {
            if request.contains("notifications/initialized") {
                return notification_response();
            }
            if request.contains("initialize") {
                return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
            }
            response(503, r#"{"error":"ghs_SECRET123"}"#, "")
        });
        let transport = McpRemoteTransport::new(config(format!("{endpoint}?token=abc")));
        let result = transport.dispatch(
            request("canary", "read_tool"),
            &ResolvedCredential::new(b"credential".to_vec(), None, 1),
        );
        assert_eq!(result.error_code.as_deref(), Some("http_503"));
        task.join().expect("server exits");
        return;
    }
    let output = crate::test_http::bounded::child_test_output(
        TEST,
        &[("PLEXUS_LOG_STDERR_CHILD", "1")],
        std::time::Duration::from_secs(30),
        "MCP diagnostic test child",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let line = stderr
        .lines()
        .find(|line| line.contains("vendor error on"))
        .expect("operator diagnostic on stderr");
    let parsed = cortexkit_log::parse_line(line).expect("fleet log line");
    assert_eq!(parsed.level, cortexkit_log::ParsedLevel::Warn);
    assert_eq!(parsed.logger, "plexus.transport");
    assert!(line.contains("MCP vendor error on POST /mcp"), "{stderr}");
    assert!(!line.contains("REST vendor error on"), "{stderr}");
    assert!(line.contains("status=503"), "{stderr}");
    assert!(!line.contains("?token=abc"), "{stderr}");
}

/// Drive one MCP call at a server that reads the request and hangs up
/// without answering, and return the endpoint it served.
///
/// Runs only inside the stderr-capturing child, where the fleet renderer is
/// installed; the parent reads the resulting line off the child's stderr.
fn dispatch_against_hang_up(query: &str) -> String {
    // An empty response closes the stream without answering the request.
    let (base, task) =
        crate::test_http::FixedRequestServer::start(1, "hang-up", |_, _| String::new());
    let endpoint = format!("{base}/mcp{query}");
    let result = McpRemoteTransport::new(config(endpoint.clone())).dispatch(
        request("hang-up", "read_tool"),
        &ResolvedCredential::new(b"credential".to_vec(), None, 1),
    );
    // The connection closed during initialize, before any tools/call was
    // posted. Keep the diagnostic category, but do not claim a tool was sent.
    assert_eq!(
        (result.transmission, result.error_code.as_deref()),
        (TransmissionState::NotSent, Some("http_request_failed"))
    );
    task.join().expect("hang-up server exits");
    endpoint
}

/// Re-run `test` in a child with the fleet renderer installed and return
/// the child's stdout, its stderr, and the one `MCP HTTP transport failed`
/// line on that stderr.
fn hang_up_diagnostic(test: &str) -> (String, String, String) {
    let output = crate::test_http::bounded::child_test_output(
        test,
        &[("PLEXUS_LOG_STDERR_CHILD", "1")],
        std::time::Duration::from_secs(30),
        "MCP diagnostic test child",
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    let lines: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("MCP HTTP transport failed"))
        .collect();
    assert_eq!(lines.len(), 1, "one line per failure: {stderr}");
    let line = lines[0].to_string();
    let parsed = cortexkit_log::parse_line(&line).expect("fleet log line");
    assert_eq!(parsed.level, cortexkit_log::ParsedLevel::Warn);
    assert_eq!(parsed.logger, "plexus.transport");
    (stdout, stderr, line)
}

#[test]
fn a_transport_failure_logs_its_cause_without_the_url() {
    const TEST: &str =
            "mcp_remote::transport_integration_tests::a_transport_failure_logs_its_cause_without_the_url";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
        use crate::test_logging as logging;
        logging::init_child();
        let endpoint = dispatch_against_hang_up("");
        // Hand the endpoint to the parent so it knows which port to look
        // for; this goes to stdout, never into the diagnostic line.
        println!("HANG-UP-ENDPOINT {endpoint}");
        return;
    }
    let (stdout, stderr, line) = hang_up_diagnostic(TEST);
    let endpoint = stdout
        .lines()
        .find_map(|line| line.strip_prefix("HANG-UP-ENDPOINT "))
        .expect("child reports its endpoint");
    let port = endpoint
        .trim_start_matches("http://127.0.0.1:")
        .trim_end_matches("/mcp");
    assert!(port.parse::<u16>().is_ok(), "port from {endpoint}");

    let message = line
        .split_once("MCP HTTP transport failed: ")
        .map(|(_, message)| message)
        .expect("diagnostic message");
    let (category, cause) = message.split_once(": ").expect("category then cause");
    assert_eq!(category, "Request", "{stderr}");
    // The cause must say more than the category: the error and the
    // chain beneath it, here the connection the server dropped.
    assert!(cause.len() > "Request".len(), "{stderr}");
    assert!(cause.contains("error sending request"), "{stderr}");
    assert!(
        cause.contains(": "),
        "the source chain is missing: {stderr}"
    );
    assert!(!line.contains(endpoint), "{stderr}");
    assert!(!line.contains("127.0.0.1"), "{stderr}");
    assert!(!line.contains(port), "{stderr}");
}

#[test]
fn a_transport_failure_never_logs_a_query_credential() {
    const TEST: &str =
            "mcp_remote::transport_integration_tests::a_transport_failure_never_logs_a_query_credential";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
        use crate::test_logging as logging;
        logging::init_child();
        // A vendor-specific parameter name on purpose. The fleet renderer
        // already masks the value of well-known names such as `token`, so
        // a test using one would still pass if this transport logged the
        // full URL; only a name the renderer does not know proves the
        // URL never reaches the line.
        dispatch_against_hang_up("?exaApiKey=SENTINEL");
        return;
    }
    let (_, stderr, line) = hang_up_diagnostic(TEST);
    assert!(
        line.contains("MCP HTTP transport failed: Request: "),
        "{stderr}"
    );
    assert!(!line.contains("SENTINEL"), "{stderr}");
    assert!(!stderr.contains("SENTINEL"), "{stderr}");
}

#[test]
fn vendor_error_body_and_debug_output_never_carry_canary() {
    let (endpoint, task) = start_server(3, |_index, request| {
        if request.contains("notifications/initialized") {
            return notification_response();
        }
        if request.contains("initialize") {
            return response(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, "");
        }
        response(
            500,
            r#"{"error":{"code":"vendor_failure","message":"ghs_SECRET123 https://example.test/?token=abc"}}"#,
            "",
        )
    });
    let transport = McpRemoteTransport::new(config(endpoint));
    let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
    let result = transport.dispatch(request("canary", "read_tool"), &credential);
    let rendered = format!("{transport:?} {result:?}");
    let message = result.error_message.as_deref().expect("agent error text");
    assert!(message.contains("ck module logs plexus"), "{message}");
    assert!(!rendered.contains("ghs_SECRET123"), "{rendered}");
    assert!(!rendered.contains("?token=abc"), "{rendered}");
    assert!(!rendered.contains("CANARY"));
    task.join().expect("canary server exits");
}

/// The session id from `initialize` is replayed on every later request.
///
/// The MCP streamable-HTTP transport lets a server assign a session in the
/// `mcp-session-id` RESPONSE header of `initialize` and then require it on
/// everything that follows. Dropping it is silent at the transport layer
/// and fatal one call later, and it does NOT look like a transport bug from
/// outside: the servers that do this answer 400 `Missing mcp-session-id`,
/// which reads as a protocol quirk or, worse, as a credential problem.
/// Three vendors in the catalog behave this way (context7, huggingface and
/// browserbase), and none of them can be reached at all without it.
///
/// The server here REQUIRES the header exactly as those vendors do, so the
/// assertion is the tools/list succeeding rather than a header inspection:
/// a test that only checked the header was present would still pass if the
/// value were wrong.
///
/// Mutation-proved: not storing the id from the reply, and omitting the
/// header from post_json, each fail this with a protocol error.
#[test]
fn a_server_assigned_session_id_is_replayed_on_later_requests() {
    let (seen, task) = start_server(3, |index, request| {
        if index == 0 {
            // initialize: assign a session.
            return response(
                200,
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
                "mcp-session-id: sess-abc123",
            );
        }
        // Everything after initialize must carry the session back, exactly
        // as context7/huggingface/browserbase require.
        if !request
            .to_ascii_lowercase()
            .contains("mcp-session-id: sess-abc123")
        {
            return response(
                400,
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Missing mcp-session-id"}}"#,
                "",
            );
        }
        response(
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_tool","inputSchema":{"type":"object"}}]}}"#,
            "",
        )
    });
    let transport = McpRemoteTransport::new(config(seen.clone()));
    let connection = McpConnection {
        connection_id: "sessioned".to_string(),
        config: config(seen),
    };
    let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);

    let discovered = transport
        .discover(&connection, &credential)
        .expect("discovery must succeed when the session is replayed");
    assert_eq!(
        discovered
            .iter()
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>(),
        vec!["read_tool"],
        "the vendor rejected the follow-up request, so the session was not carried"
    );

    task.join().expect("session server exits");
}

/// A reconnect must not replay the session it is reconnecting away from,
/// INCLUDING when the new `initialize` assigns no session at all.
///
/// That last clause is the whole test, and the first version of it did not
/// have it. Written the obvious way — re-initialize hands out a second
/// session — the mutation that stops `reset_session` clearing the id STILL
/// PASSED, because adopting the new id overwrites the stale one regardless.
/// The clear only becomes observable when there is nothing to overwrite it
/// with, which is exactly the case a server hits when it stops issuing
/// sessions: adoption is guarded on the reply carrying an id, so a stale
/// value would survive and be replayed forever.
///
/// Mutation-proved: making `reset_session` clear only `initialized` fails
/// this, while every other test in the file stays green.
#[test]
fn a_reconnect_does_not_carry_the_stale_session() {
    let (seen, task) = start_server(6, |index, request| {
        let lowered = request.to_ascii_lowercase();
        match index {
            // First session.
            0 => response(
                200,
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
                "mcp-session-id: sess-first",
            ),
            1 => response(200, r#"{"jsonrpc":"2.0","result":{}}"#, ""),
            // The server forgets the session and rejects the call, which is
            // what drives the reconnect.
            2 => response(
                401,
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"session expired"}}"#,
                "",
            ),
            // Re-initialize, assigning NO session this time. Nothing here
            // can overwrite a stale id, so the clear is the only thing that
            // can remove it.
            3 => response(
                200,
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
                "",
            ),
            4 => response(200, r#"{"jsonrpc":"2.0","result":{}}"#, ""),
            // The retried call must carry NO session header at all.
            _ => {
                if lowered.contains("mcp-session-id") {
                    return response(
                        400,
                        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"stale session replayed"}}"#,
                        "",
                    );
                }
                response(
                    200,
                    r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_tool","inputSchema":{"type":"object"}}]}}"#,
                    "",
                )
            }
        }
    });
    let transport = McpRemoteTransport::new(config(seen.clone()));
    let connection = McpConnection {
        connection_id: "reconnecting".to_string(),
        config: config(seen),
    };
    let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);

    let discovered = transport
        .discover(&connection, &credential)
        .expect("the retry after an auth response must succeed with a fresh session");
    assert_eq!(
        discovered
            .iter()
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>(),
        vec!["read_tool"],
        "the reconnect replayed the stale session instead of the new one"
    );

    task.join().expect("reconnect server exits");
}

/// An idle pooled connection is evicted, and a LEASED one is not.
///
/// Both halves are required and the second is the one that matters: a
/// removal-only test cannot distinguish a correct sweep from one that
/// evicts everything, and evicting a leased entry would drop the client
/// out from under a vendor call that is still in flight.
///
/// The test makes the entry idle by moving its real `last_used` time back
/// rather than by configuring a tiny idle timeout, so the sweep is checked
/// against the idle timeout production actually uses.
#[test]
fn the_sweep_evicts_an_idle_entry_and_spares_a_leased_one() {
    let (seen, task) = start_server(2, |_, _| {
        response(200, r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#, "")
    });
    let config = config(seen);
    let idle_timeout = config.idle_timeout;
    let transport = McpRemoteTransport::new(config);
    let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);

    let _ = transport.dispatch(request("pooled", "read_tool"), &credential);
    assert_eq!(
        transport.connection_count(),
        1,
        "the dispatch must have pooled an entry, or the sweep below has \
             nothing to act on and would pass vacuously"
    );

    // Still fresh: a sweep now must keep it.
    assert_eq!(transport.sweep_idle(), 0);
    assert_eq!(transport.connection_count(), 1);

    // Older than the real idle timeout: now it must go.
    assert!(transport.age_entry_for_test("pooled", idle_timeout + Duration::from_secs(1)));
    assert_eq!(transport.sweep_idle(), 1, "an idle entry must be evicted");
    assert_eq!(transport.connection_count(), 0);

    // A leased entry is exempt even when its idle deadline has passed,
    // because a lease means a vendor call is using the client right now.
    let _ = transport.dispatch(request("leased", "read_tool"), &credential);
    let lease = transport
        .lease_for_test("leased")
        .expect("lease pooled entry");
    assert!(transport.age_entry_for_test("leased", idle_timeout + Duration::from_secs(1)));
    assert_eq!(
        transport.sweep_idle(),
        0,
        "a leased entry must survive its idle deadline"
    );
    assert_eq!(transport.connection_count(), 1);
    drop(lease);

    task.join().expect("sweep server exits");
}

/// The mock vendor's keep-alive timeout in the pooled-connection tests.
const VENDOR_KEEP_ALIVE: Duration = Duration::from_millis(1000);
/// The idle gap between the two calls: longer than the vendor keeps an idle
/// connection open, so any connection reused across it loses the race.
const IDLE_GAP: Duration = Duration::from_millis(1300);

/// A keep-alive MCP vendor: answers initialize, the initialized
/// notification and any tool call, without ever asking to close.
fn keep_alive_mcp_vendor() -> crate::test_http::KeepAliveServer {
    crate::test_http::KeepAliveServer::start(VENDOR_KEEP_ALIVE, |request| {
        let rpc: Value = serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        let (status, body) = if request.contains("notifications/initialized") {
            ("202 Accepted", String::new())
        } else if request.contains("\"initialize\"") {
            (
                "200 OK",
                json!({"jsonrpc":"2.0", "id":rpc["id"], "result":{}}).to_string(),
            )
        } else {
            (
                "200 OK",
                json!({"jsonrpc":"2.0", "id":rpc["id"], "result":{"ok":true}}).to_string(),
            )
        };
        format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
    })
}

/// Two tool calls through one transport, `IDLE_GAP` apart, with the HTTP
/// client's keep-alive pool limited to `pool_limit`. Returns both results
/// and the vendor's accepted-connection count before and after the second
/// call.
fn two_calls_across_an_idle_gap(
    pool_limit: Duration,
) -> (TransportResponse, TransportResponse, usize, usize) {
    let vendor = keep_alive_mcp_vendor();
    let mut config = config(format!("http://{}/mcp", vendor.address()));
    config.pooled_connection_idle_limit = pool_limit;
    let transport = McpRemoteTransport::new(config);
    let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);

    let first = transport.dispatch(request("keep-alive", "read_tool"), &credential);
    let before = vendor.connections();
    std::thread::sleep(IDLE_GAP);
    let second = transport.dispatch(request("keep-alive", "read_tool"), &credential);
    let after = vendor.connections();
    (first, second, before, after)
}

/// A pooled connection idle past the client's pool limit is replaced, not
/// reused, so a vendor that already closed it at its keep-alive timeout
/// never sees a request on it.
///
/// This is the DeepWiki probe failure ("connection closed before message
/// completed"): the vendor drops idle connections
/// at about 60 seconds, probes run every 60, and the client kept idle
/// connections for 90. Here the pool limit is below the gap and the
/// vendor's keep-alive is shorter than the gap, the same ordering
/// production has with `POOLED_CONNECTION_IDLE_LIMIT`.
///
/// Asserted as a connection-count delta across the second call rather than
/// an absolute count: the first call is three requests, and the client is
/// free to open more than one connection for them.
///
/// `a_connection_reused_past_the_vendor_keep_alive_fails_as_production_did`
/// proves the mock vendor really does break a reused connection, so this
/// success is not the mock being lenient.
#[test]
fn a_connection_idle_past_the_pool_limit_is_replaced_not_reused() {
    let (first, second, before, after) = two_calls_across_an_idle_gap(Duration::from_millis(250));
    assert_eq!(first.response.expect("first MCP call succeeds")["ok"], true);
    assert_eq!(
        second
            .response
            .as_ref()
            .map(|response| response["ok"].clone()),
        Some(Value::Bool(true)),
        "the second call was sent on a connection the vendor had closed: {second:?}"
    );
    assert_eq!(
        after - before,
        1,
        "the second call must have opened exactly one fresh connection"
    );
}

/// The control for `a_connection_idle_past_the_pool_limit_is_replaced_not_reused`:
/// with the pool limit ABOVE the idle gap, the second call reuses the idle
/// connection and fails with hyper's "connection closed before message
/// completed", the same cause a real DeepWiki probe logs when it loses
/// this race. Without this, a mock vendor that answered a reused
/// connection would let that test pass for the wrong reason.
///
/// The cause is not in the transport's response, only in the operator log
/// line, so the calls run in a child process with the fleet log renderer
/// installed and this test reads the line off the child's stderr.
#[test]
fn a_connection_reused_past_the_vendor_keep_alive_fails_as_production_did() {
    const TEST: &str = "mcp_remote::transport_integration_tests::a_connection_reused_past_the_vendor_keep_alive_fails_as_production_did";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
        use crate::test_logging as logging;
        logging::init_child();
        let (first, second, before, after) = two_calls_across_an_idle_gap(Duration::from_secs(60));
        assert_eq!(first.response.expect("first MCP call succeeds")["ok"], true);
        assert_eq!(
            (second.transmission, second.error_code.as_deref()),
            (
                TransmissionState::OutcomeUnknown,
                Some("http_request_failed")
            ),
            "the reused connection must fail: {second:?}"
        );
        assert_eq!(
            after, before,
            "the failing call must have reused a connection"
        );
        return;
    }
    let (_, stderr, line) = hang_up_diagnostic(TEST);
    assert!(
        line.contains("connection closed before message completed"),
        "{stderr}"
    );
}

const INITIALIZED: &str = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;

/// A response with a non-JSON body and the given headers.
fn text_response(status: &str, body: &str, extra_headers: &str) -> String {
    format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}",
            body.len()
        )
}

/// The JSON-RPC id of the request a mock vendor received.
fn request_id(request: &str) -> Value {
    let body = request.split_once("\r\n\r\n").expect("request body").1;
    serde_json::from_str::<Value>(body).expect("JSON-RPC request")["id"].clone()
}

/// A `Retry-After` of any size is reported to the caller as a number, and
/// one longer than a request may wait refuses the next request locally
/// instead of sleeping under the connection lock.
///
/// `u64::MAX` seconds is the value that used to panic while the lock was
/// held (`Instant + Duration` overflow), poisoning the connection until
/// restart; any value over a few seconds parked the next request's thread
/// for as long as the vendor asked.
#[test]
fn an_over_long_retry_after_refuses_locally_instead_of_sleeping() {
    let (endpoint, task) = start_server(3, |index, _request| match index {
        0 => response(200, INITIALIZED, ""),
        1 => notification_response(),
        _ => response(429, "{}", "Retry-After: 18446744073709551615"),
    });
    let transport = McpRemoteTransport::new(config(endpoint));
    let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
    let first = transport.dispatch(request("throttle", "read_tool"), &credential);
    assert_eq!(first.retryability, Retryability::Throttle, "{first:?}");
    assert_eq!(first.retry_after_ms, Some(3_600_000), "{first:?}");

    let started = Instant::now();
    let second = transport.dispatch(request("throttle", "read_tool"), &credential);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "an hour-long throttle must not be slept through"
    );
    assert_eq!(
        second.transmission,
        TransmissionState::NotSent,
        "{second:?}"
    );
    assert_eq!(second.retryability, Retryability::Throttle);
    let remaining = second.retry_after_ms.expect("the refusal names the delay");
    assert!(
        remaining > 3_590_000 && remaining <= 3_600_000,
        "{remaining}"
    );
    task.join()
        .expect("only the throttled call reached the vendor");
}

/// A refusal is classified by its status even when its body is not JSON.
///
/// Vendors and proxies send 401 and 429 with an HTML page or nothing at
/// all. Parsing the body first made both a protocol error, so the 401
/// never reconnected and the 429 never reported its throttle.
#[test]
fn a_refusal_with_a_non_json_body_is_classified_by_its_status() {
    let (endpoint, task) = start_server(7, |index, _request| match index {
        0 | 3 => response(200, INITIALIZED, ""),
        1 | 4 => notification_response(),
        2 => text_response("401 Unauthorized", "<html>login</html>", ""),
        5 => response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, ""),
        _ => text_response("429 Too Many Requests", "", "Retry-After: 1\r\n"),
    });
    let transport = McpRemoteTransport::new(config(endpoint));
    let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
    let reconnected = transport.dispatch(request("html", "read_tool"), &credential);
    assert_eq!(
        reconnected
            .response
            .expect("a 401 page reconnects and retries")["ok"],
        true
    );
    let throttled = transport.dispatch(request("html", "read_tool"), &credential);
    assert_eq!(
        throttled.retryability,
        Retryability::Throttle,
        "{throttled:?}"
    );
    assert_eq!(throttled.retry_after_ms, Some(1_000));
    task.join().expect("server exits");
}

/// A 404 to a request that carried a session means the server forgot the
/// session, and the client starts a new one (the MCP spec requires it).
/// The new initialize carries no session id, and the retried call carries
/// the new one.
#[test]
fn an_expired_session_is_reinitialized_once() {
    let (endpoint, task) = start_server(6, |index, request| {
        let lowered = request.to_ascii_lowercase();
        match index {
            0 => response(200, INITIALIZED, "mcp-session-id: sess-old"),
            1 => notification_response(),
            2 => {
                assert!(lowered.contains("mcp-session-id: sess-old"));
                text_response("404 Not Found", "Session not found", "")
            }
            3 => {
                assert!(lowered.contains("\"initialize\""), "{request}");
                assert!(
                    !lowered.contains("mcp-session-id:"),
                    "a new initialize must not carry the forgotten session"
                );
                response(200, INITIALIZED, "mcp-session-id: sess-new")
            }
            4 => notification_response(),
            _ => {
                assert!(lowered.contains("mcp-session-id: sess-new"), "{request}");
                response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, "")
            }
        }
    });
    let transport = McpRemoteTransport::new(config(endpoint));
    let result = transport.dispatch(
        request("expired", "read_tool"),
        &ResolvedCredential::new(b"token".to_vec(), None, 1),
    );
    task.join().expect("server exits");
    assert_eq!(
        result.response.expect("the call succeeds on a new session")["ok"],
        true
    );
}

/// A 404 to a request that carried no session is an ordinary vendor
/// failure, not an expired session, and is not retried.
#[test]
fn a_404_without_a_session_is_not_retried() {
    let (endpoint, task) = start_server(3, |index, _request| match index {
        0 => response(200, INITIALIZED, ""),
        1 => notification_response(),
        _ => text_response("404 Not Found", "no such tool", ""),
    });
    let transport = McpRemoteTransport::new(config(endpoint));
    let result = transport.dispatch(
        request("plain", "read_tool"),
        &ResolvedCredential::new(b"token".to_vec(), None, 1),
    );
    task.join().expect("exactly three requests");
    assert_eq!(result.transmission, TransmissionState::Sent, "{result:?}");
    assert!(result.response.is_none());
}

/// A refused `notifications/initialized` leaves the session unready, so
/// the next call initializes again instead of sending a tool call on a
/// session the server never confirmed.
#[test]
fn a_refused_initialized_notification_does_not_mark_the_session_ready() {
    let (endpoint, task) = start_server(5, |index, request| match index {
        0 => response(200, INITIALIZED, ""),
        1 => text_response("500 Internal Server Error", "boom", ""),
        2 => {
            assert!(request.contains("\"initialize\""), "{request}");
            response(200, INITIALIZED, "")
        }
        3 => notification_response(),
        _ => response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, ""),
    });
    let transport = McpRemoteTransport::new(config(endpoint));
    let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
    let refused = transport.dispatch(request("notify", "read_tool"), &credential);
    assert!(refused.response.is_none(), "{refused:?}");
    let retried = transport.dispatch(request("notify", "read_tool"), &credential);
    task.join().expect("server exits");
    assert_eq!(
        retried.response.expect("the second call re-initializes")["ok"],
        true
    );
}

/// The answer in a server-sent-event body is the response to THIS request:
/// progress notifications and other messages before it are skipped, and
/// an event's data split across several `data:` lines is joined.
#[test]
fn an_sse_reply_is_the_response_matching_the_request_id() {
    let (endpoint, task) = start_server(3, |index, request| match index {
        0 => response(200, INITIALIZED, ""),
        1 => notification_response(),
        _ => {
            let id = request_id(request);
            let body = format!(
                    concat!(
                        ": keep-alive comment\r\n\r\n",
                        "event: message\r\n",
                        "data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progress\":1}}}}\r\n\r\n",
                        "data: {{\"jsonrpc\":\"2.0\",\"id\":\"other\",\"result\":{{\"stale\":true}}}}\r\n\r\n",
                        "data: {{\"jsonrpc\":\"2.0\",\"id\":{id},\r\n",
                        "data: \"result\":{{\"ok\":true}}}}\r\n\r\n"
                    ),
                    id = id
                );
            format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
        }
    });
    let transport = McpRemoteTransport::new(config(endpoint));
    let result = transport.dispatch(
        request("sse", "read_tool"),
        &ResolvedCredential::new(b"token".to_vec(), None, 1),
    );
    task.join().expect("server exits");
    let body = result.response.expect("the matching response is found");
    assert_eq!(body["ok"], true, "{body}");
}

/// Re-registering a connection with a new endpoint starts a new session
/// there: the new server sees initialize first, never the old server's
/// session id.
#[test]
fn a_changed_endpoint_starts_a_new_session() {
    let (old_endpoint, old_task) = start_server(3, |index, _request| match index {
        0 => response(200, INITIALIZED, "mcp-session-id: sess-old"),
        1 => notification_response(),
        _ => response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, ""),
    });
    let (new_endpoint, new_task) = start_server(3, |index, request| {
        assert!(
            !request.to_ascii_lowercase().contains("sess-old"),
            "the old server's session reached the new server: {request}"
        );
        match index {
            0 => {
                assert!(request.contains("\"initialize\""), "{request}");
                response(200, INITIALIZED, "")
            }
            1 => notification_response(),
            _ => response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, ""),
        }
    });
    let transport = McpRemoteTransport::default();
    let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
    transport.register_config("moved", config(old_endpoint));
    assert!(transport
        .dispatch(request("moved", "read_tool"), &credential)
        .response
        .is_some());
    transport.register_config("moved", config(new_endpoint));
    let moved = transport.dispatch(request("moved", "read_tool"), &credential);
    old_task.join().expect("old server exits");
    new_task.join().expect("new server exits");
    assert_eq!(
        moved.response.expect("the new endpoint answers")["ok"],
        true
    );
}

/// An MCP POST never follows a redirect to another origin, even a 307
/// that would keep the method: the credential stays on the endpoint the
/// manifest names, and the caller sees only the status.
#[test]
fn a_cross_origin_redirect_is_not_followed() {
    let elsewhere = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    elsewhere.set_nonblocking(true).expect("nonblocking");
    let location = format!("http://{}/mcp", elsewhere.local_addr().expect("address"));
    let (endpoint, task) = start_server(3, move |index, _request| match index {
        0 => response(200, INITIALIZED, ""),
        1 => notification_response(),
        _ => text_response(
            "307 Temporary Redirect",
            "",
            &format!("Location: {location}\r\n"),
        ),
    });
    let mut remote_config = config(endpoint);
    // Bounds the test if a regression follows into the listener, which
    // accepts the connection but never answers.
    remote_config.request_timeout = Duration::from_secs(2);
    let transport = McpRemoteTransport::new(remote_config);
    let result = transport.dispatch(
        request("redirect", "read_tool"),
        &ResolvedCredential::new(b"CANARY".to_vec(), None, 1),
    );
    task.join().expect("server exits");
    assert!(
        matches!(elsewhere.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "the request was sent to another origin"
    );
    assert_eq!(result.error_code.as_deref(), Some("http_307"), "{result:?}");
}

/// A success body larger than the transport reads into memory is
/// outcome-unknown rather than read whole.
#[test]
fn an_oversized_success_body_is_outcome_unknown() {
    let (endpoint, task) = start_server(3, |index, _request| match index {
        0 => response(200, INITIALIZED, ""),
        1 => notification_response(),
        _ => response(200, &" ".repeat(MAX_RESPONSE_BODY_BYTES + 1), ""),
    });
    let transport = McpRemoteTransport::new(config(endpoint));
    let result = transport.dispatch(
        request("large", "read_tool"),
        &ResolvedCredential::new(b"token".to_vec(), None, 1),
    );
    drop(task);
    assert_eq!(
        (result.transmission, result.error_code.as_deref()),
        (
            TransmissionState::OutcomeUnknown,
            Some("response_too_large")
        ),
        "{:?}",
        result.error_code
    );
}

/// A panic while a tool call holds its connection reaches the caller as
/// outcome unknown (the call was already on the wire), the session is
/// discarded, and the connection keeps working.
#[test]
fn a_panic_mid_request_reports_outcome_unknown_and_keeps_the_connection() {
    let (endpoint, task) = start_server(7, |index, request| match index {
        0 | 4 => {
            assert!(request.contains("\"initialize\""), "{request}");
            response(200, INITIALIZED, "")
        }
        1 | 5 => notification_response(),
        _ => response(200, r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#, ""),
    });
    let transport = McpRemoteTransport::new(config(endpoint));
    let credential = ResolvedCredential::new(b"token".to_vec(), None, 1);
    let call = || transport.dispatch(request("panics", "write_tool"), &credential);
    assert_eq!(call().response.expect("warm-up call")["ok"], true);
    assert!(transport.panic_after_next_send_for_test("panics"));

    let panicked = call();
    assert_eq!(
        (panicked.transmission, panicked.error_code.as_deref()),
        (
            TransmissionState::OutcomeUnknown,
            Some("transport_panicked")
        ),
        "{panicked:?}"
    );
    assert_eq!(transport.panic_recoveries(), 1);
    assert_eq!(
        call()
            .response
            .expect("the connection re-initializes and works")["ok"],
        true
    );
    task.join().expect("server exits");
}
