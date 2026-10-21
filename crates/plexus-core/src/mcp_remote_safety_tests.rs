use super::*;

fn reply(status: u16, headers: &str, body: Value) -> String {
    let text = body.to_string();
    format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{text}", text.len())
}
fn rpc(wire: &str) -> Value {
    serde_json::from_str(wire.split_once("\r\n\r\n").unwrap().1).unwrap()
}
fn request() -> TransportRequest {
    TransportRequest {
        request_id: "safety".into(),
        connection_id: "safety".into(),
        action: "write_tool".into(),
        args: json!({}),
        credential_fingerprint: String::new(),
    }
}

#[test]
fn rejected_initialized_notification_discards_the_provisional_session() {
    let (endpoint, server) =
        crate::test_http::FixedRequestServer::start(5, "session", |index, wire| {
            let message = rpc(wire);
            match index {
                0 => reply(
                    200,
                    "Mcp-Session-Id: stale\r\n",
                    json!({"id":message["id"],"result":{}}),
                ),
                1 => reply(403, "", Value::Null),
                2 => {
                    assert_eq!(message["method"], "initialize");
                    assert!(
                        !wire.to_ascii_lowercase().contains("mcp-session-id:"),
                        "fresh initialize must not replay the refused session"
                    );
                    reply(200, "", json!({"id":message["id"],"result":{}}))
                }
                3 => reply(202, "", Value::Null),
                _ => reply(200, "", json!({"id":message["id"],"result":{"ok":true}})),
            }
        });
    let transport = McpRemoteTransport::new(McpRemoteConfig::new(endpoint));
    assert_eq!(
        transport
            .dispatch(request(), &ResolvedCredential::anonymous())
            .transmission,
        TransmissionState::NotSent
    );
    assert!(transport
        .dispatch(request(), &ResolvedCredential::anonymous())
        .response
        .is_some());
    server.join().unwrap();
}

#[test]
fn accepted_but_invalid_tool_replies_remain_outcome_unknown() {
    for result in [json!({"isError":"true","content":[]}), Value::Null] {
        let (endpoint, server) =
            crate::test_http::FixedRequestServer::start(3, "invalid-result", move |index, wire| {
                let message = rpc(wire);
                match index {
                    0 => reply(200, "", json!({"id":message["id"],"result":{}})),
                    1 => reply(202, "", Value::Null),
                    _ if result.is_null() => {
                        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
                    }
                    _ => reply(200, "", json!({"id":message["id"],"result":result})),
                }
            });
        let transport = McpRemoteTransport::new(McpRemoteConfig::new(endpoint));
        let answer = transport.dispatch(request(), &ResolvedCredential::anonymous());
        server.join().unwrap();
        assert_eq!(
            answer.transmission,
            TransmissionState::OutcomeUnknown,
            "an accepted write without a valid result must be reconciled"
        );
        assert_eq!(answer.error_code.as_deref(), Some("mcp_protocol_error"));
    }
}

#[test]
fn mcp_throttles_and_gateway_statuses_keep_their_safe_posture() {
    for (status, headers, throttled) in [
        (403, "X-RateLimit-Remaining: 0\r\n", true),
        (429, "", true),
        (503, "Retry-After: 60\r\n", true),
        (502, "", false),
    ] {
        let (endpoint, server) =
            crate::test_http::FixedRequestServer::start(3, "statuses", move |index, wire| {
                let message = rpc(wire);
                match index {
                    0 => reply(200, "", json!({"id":message["id"],"result":{}})),
                    1 => reply(202, "", Value::Null),
                    _ => reply(status, headers, Value::Null),
                }
            });
        let transport = McpRemoteTransport::new(McpRemoteConfig::new(endpoint));
        let answer = transport.dispatch(request(), &ResolvedCredential::anonymous());
        server.join().unwrap();
        if throttled {
            assert_eq!(answer.retryability, Retryability::Throttle);
            assert!(answer.retry_after_ms.is_some_and(|delay| delay > 0));
            let next = transport.dispatch(request(), &ResolvedCredential::anonymous());
            assert_eq!(
                (next.transmission, next.retryability),
                (TransmissionState::NotSent, Retryability::Throttle)
            );
        } else {
            assert_eq!(answer.transmission, TransmissionState::OutcomeUnknown);
            assert_eq!(answer.error_code.as_deref(), Some("http_502"));
        }
    }
}

#[test]
fn discovery_rejects_duplicate_names() {
    let (endpoint, server) = crate::test_http::FixedRequestServer::start(
        3,
        "duplicates",
        |index, wire| {
            let message = rpc(wire);
            let result = if index == 0 {
                json!({})
            } else {
                json!({"tools":[{"name":"read","inputSchema":{}},{"name":"read","inputSchema":{"type":"string"}}]})
            };
            reply(
                if index == 1 { 202 } else { 200 },
                "",
                json!({"id":message["id"],"result":result}),
            )
        },
    );
    let connection = McpConnection::new("duplicates", endpoint);
    let transport = McpRemoteTransport::default();
    let result = transport.discover(&connection, &ResolvedCredential::anonymous());
    server.join().unwrap();
    assert_eq!(
        result.unwrap_err(),
        McpRemoteError::Protocol,
        "duplicate names must not mask schema drift"
    );
}

#[test]
fn discovery_has_an_aggregate_response_budget() {
    let (endpoint, server) = crate::test_http::FixedRequestServer::start(
        4,
        "aggregate",
        |index, wire| {
            let message = rpc(wire);
            let result = match index {
                0 | 1 => json!({}),
                _ => {
                    json!({"tools":[{"name":format!("tool-{index}"),"description":"x".repeat(9*1024*1024),"inputSchema":{}}],"nextCursor":if index==2 { json!("next") } else { Value::Null }})
                }
            };
            reply(
                if index == 1 { 202 } else { 200 },
                "",
                json!({"id":message["id"],"result":result}),
            )
        },
    );
    let transport = McpRemoteTransport::default();
    let result = transport.discover(
        &McpConnection::new("aggregate", endpoint),
        &ResolvedCredential::anonymous(),
    );
    server.join().unwrap();
    assert_eq!(
        result.unwrap_err(),
        McpRemoteError::ResponseTooLarge,
        "discovery must cap all pages together"
    );
}

#[test]
fn discovery_panic_is_contained_without_poisoning_the_connection() {
    let (endpoint, server) = crate::test_http::FixedRequestServer::start(1, "panic", |_, wire| {
        reply(200, "", json!({"id":rpc(wire)["id"],"result":{"tools":[]}}))
    });
    let config = McpRemoteConfig::new(endpoint);
    let transport = McpRemoteTransport::new(config.clone());
    let lease = transport.entry_for("panic", &config).unwrap();
    {
        let mut state = lease.lock().unwrap();
        state.initialized = true;
        state.panic_after_send = true;
    }
    let result = transport.discover(
        &McpConnection {
            connection_id: "panic".into(),
            config,
        },
        &ResolvedCredential::anonymous(),
    );
    server.join().unwrap();
    assert_eq!(result.unwrap_err(), McpRemoteError::OutcomeUnknown);
    assert!(
        lease.lock().is_ok(),
        "discovery must not poison the pooled entry"
    );
    assert_eq!(transport.panic_recoveries(), 1);
}

#[test]
fn dropping_a_finished_lease_never_waits_for_another_rpc() {
    let transport = McpRemoteTransport::new(McpRemoteConfig::new("http://127.0.0.1:1"));
    let lease = transport
        .entry_for("lease", &transport.default_config)
        .unwrap();
    let pooled = Arc::clone(&lease.entry);
    let guard = pooled.lock().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        drop(lease);
        tx.send(()).unwrap();
    });
    let dropped = rx.recv_timeout(Duration::from_millis(300)).is_ok();
    drop(guard);
    worker.join().unwrap();
    assert!(dropped, "finished lease drop must not wait for a busy RPC");
}

#[test]
fn unrenderable_credentials_on_a_live_session_are_not_sent() {
    let mut config = McpRemoteConfig::new("http://127.0.0.1:1");
    config.credential_bindings = vec![CredentialBinding {
        ref_role: "credential".into(),
        placement: "header".into(),
        key: "authorization".into(),
        prefix: "Bearer ".into(),
        required: true,
    }];
    let transport = McpRemoteTransport::new(config.clone());
    transport
        .entry_for("safety", &config)
        .unwrap()
        .lock()
        .unwrap()
        .initialized = true;
    let answer = transport.dispatch(
        request(),
        &ResolvedCredential::new(b"bad\nheader".to_vec(), None, 1),
    );
    assert_eq!(
        answer.transmission,
        TransmissionState::NotSent,
        "invalid credentials must fail before send on initialized sessions too"
    );
}

#[test]
fn cr_only_sse_requests_receive_an_error_before_the_tool_result() {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    // Not `FixedRequestServer`: this test keeps a three-second accept deadline
    // and two-second socket timeouts, tighter than the shared fixture's.
    let worker = thread::spawn(move || {
        let accept = || {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        return stream;
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::park_timeout(Duration::from_millis(2))
                    }
                    Err(error) => panic!("SSE accept: {error}"),
                }
            }
        };
        for index in 0..2 {
            let mut stream = accept();
            let message =
                rpc(&crate::test_http::read_mock_request(&mut stream, "SSE init").unwrap());
            stream
                .write_all(
                    reply(
                        if index == 0 { 200 } else { 202 },
                        "",
                        json!({"id":message["id"],"result":{}}),
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
        let mut stream = accept();
        let message = rpc(&crate::test_http::read_mock_request(&mut stream, "SSE tool").unwrap());
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"sampling/createMessage\",\"params\":{}}\r\r").unwrap();
        let mut answer_stream = accept();
        let answer =
            rpc(&crate::test_http::read_mock_request(&mut answer_stream, "SSE error").unwrap());
        assert_eq!(answer["id"], 77);
        assert_eq!(
            answer["error"]["code"], -32601,
            "unsupported server request must receive a JSON-RPC error"
        );
        answer_stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        stream
            .write_all(b"data: {\"jsonrpc\":\"2.0\",\"id\":78,\"method\":\"ping\"}\r\r")
            .unwrap();
        let mut ping_stream = accept();
        let ping = rpc(&crate::test_http::read_mock_request(&mut ping_stream, "SSE ping").unwrap());
        assert_eq!(ping["id"], 78);
        assert_eq!(
            ping["result"],
            json!({}),
            "server ping must receive an empty result"
        );
        ping_stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        stream
            .write_all(
                format!(
                    "data: {}\r\r",
                    json!({"jsonrpc":"2.0","id":message["id"],"result":{"ok":true}})
                )
                .as_bytes(),
            )
            .unwrap();
    });
    let mut config = McpRemoteConfig::new(endpoint);
    config.request_timeout = Duration::from_secs(1);
    let answer =
        McpRemoteTransport::new(config).dispatch(request(), &ResolvedCredential::anonymous());
    worker.join().unwrap();
    assert_eq!(
        answer.response.unwrap()["ok"],
        true,
        "CR-only stream must complete after refusing the server request"
    );
}

#[test]
fn sse_body_failures_have_an_operator_cause_and_path() {
    const TEST: &str =
        "mcp_remote::safety_tests::sse_body_failures_have_an_operator_cause_and_path";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
        use crate::test_logging as logging;
        logging::init_child();
        let (endpoint, server) = crate::test_http::FixedRequestServer::start(
            3,
            "SSE diagnostic",
            |index, wire| {
                match index {
                0 => reply(200,"",json!({"id":rpc(wire)["id"],"result":{}})),
                1 => reply(202,"",Value::Null),
                _ => "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 100\r\nConnection: close\r\n\r\n: ping\n\n".into(),
            }
            },
        );
        let answer = McpRemoteTransport::new(McpRemoteConfig::new(endpoint))
            .dispatch(request(), &ResolvedCredential::anonymous());
        server.join().unwrap();
        assert_eq!(answer.transmission, TransmissionState::OutcomeUnknown);
        return;
    }
    let output = crate::test_http::bounded::child_test_output(
        TEST,
        &[("PLEXUS_LOG_STDERR_CHILD", "1")],
        Duration::from_secs(10),
        "SSE diagnostic child",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("MCP SSE body read failed:"),
        "SSE read failure must name the cause: {stderr}"
    );
    assert!(
        stderr.contains("status=200 path=/"),
        "SSE read failure must name its endpoint path: {stderr}"
    );
}

#[test]
fn production_configuration_refuses_unregistered_ids_without_sending() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let transport = McpRemoteTransport::default();
    let mut config = McpRemoteConfig::new(format!("http://{}", listener.local_addr().unwrap()));
    config.request_timeout = Duration::from_millis(100);
    transport.register_connection(McpConnection {
        connection_id: "registered".into(),
        config,
    });
    let answer = transport.dispatch(
        request(),
        &ResolvedCredential::new(b"credential".to_vec(), None, 1),
    );
    assert_eq!(answer.transmission, TransmissionState::NotSent);
    assert_eq!(
        answer.error_code.as_deref(),
        Some("mcp_transport_error"),
        "unregistered id must refuse locally, not contact another endpoint"
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "unregistered id must send nothing"
    );
    assert_eq!(transport.connection_count(), 0);
}
