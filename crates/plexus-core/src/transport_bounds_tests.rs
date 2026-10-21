use crate::credentials::ResolvedCredential;
use crate::manifest::HttpOperation;
use crate::mcp_remote::{McpRemoteConfig, McpRemoteTransport};
use crate::rest_api::{RestConfig, RestTransport};
use crate::transport::{Retryability, TransmissionState, Transport, TransportRequest};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn request(action: &str, args: Value) -> TransportRequest {
    TransportRequest {
        request_id: "bounds".into(),
        connection_id: "bounds".into(),
        action: action.into(),
        args,
        credential_fingerprint: String::new(),
    }
}
fn operation(value: Value) -> HttpOperation {
    serde_json::from_value(value).unwrap()
}
/// Not `FixedRequestServer`: these bounds tests hold a three-second accept
/// deadline and two-second socket timeouts, tighter than the shared fixture's.
fn server(
    handler: impl FnOnce(String) -> String + Send + 'static,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let wire = crate::test_http::read_mock_request(&mut socket, "bounds").unwrap();
                    let response = handler(wire);
                    let _ = socket.write_all(response.as_bytes());
                    break;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
                {
                    std::thread::park_timeout(Duration::from_millis(2))
                }
                Err(error) => panic!("accept: {error}"),
            }
        }
    });
    (url, worker)
}
fn response(status: u16, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} Test\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn delete_assignees_uses_reviewed_body_without_changing_input_schema() {
    let mut manifest = crate::manifest::ingest_value(
        serde_json::from_str(
            &subc_jsonc::jsonc_to_json(include_str!("../../../catalog/github_rest.jsonc")).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
    .manifest;
    let action = manifest
        .actions_baseline
        .iter_mut()
        .find(|action| action.name == "remove_issue_assignees")
        .unwrap();
    let before = action.http.as_ref().unwrap().args_schema.clone();
    let serialized = serde_json::to_value(action.http.as_ref().unwrap()).unwrap();
    assert_eq!(
        serialized["parameters"],
        json!("body"),
        "shipped assignee removal must opt into a body"
    );
    let op = operation(serialized);
    assert_eq!(
        before, op.args_schema,
        "parameter placement must not change input schema"
    );
    let recorded = Arc::new(Mutex::new(String::new()));
    let observed = Arc::clone(&recorded);
    let (url, worker) = server(move |wire| {
        *observed.lock().unwrap() = wire;
        response(200, "", "{}")
    });
    let transport = RestTransport::new(
        RestConfig::new(url).with_actions(HashMap::from([("remove_issue_assignees".into(), op)])),
    );
    let reply = transport.dispatch(
        request(
            "remove_issue_assignees",
            json!({"owner":"org","repo":"repo","issue_number":7,"assignees":["alice"]}),
        ),
        &ResolvedCredential::anonymous(),
    );
    worker.join().unwrap();
    assert!(reply.response.is_some());
    let wire = recorded.lock().unwrap();
    assert_eq!(
        wire.lines().next().unwrap(),
        "DELETE /repos/org/repo/issues/7/assignees HTTP/1.1"
    );
    assert_eq!(
        serde_json::from_str::<Value>(wire.split_once("\r\n\r\n").unwrap().1).unwrap(),
        json!({"assignees":["alice"]}),
        "DELETE assignees must travel in the body"
    );
}

#[test]
fn facade_redirect_is_not_followed_outside_the_repository_binding() {
    let (url, worker) = server(|_| response(307, "Location: /repos/other/repo/issues\r\n", ""));
    let transport = RestTransport::new(RestConfig::new(url).with_actions(HashMap::from([(
        "read".into(),
        operation(json!({"method":"GET","path":"/repos/org/repo/issues","args_schema":{}})),
    )])));
    let reply = transport
        .dispatch_github_facade(request("read", json!({})), &ResolvedCredential::anonymous());
    worker.join().unwrap();
    assert_eq!(
        reply.error_code.as_deref(),
        Some("repository_redirected"),
        "facade redirects must be refused by name"
    );
}

#[test]
fn ambiguous_path_arguments_are_refused_before_send() {
    let op = operation(json!({"method":"GET","path":"/repos/{repo}","args_schema":{}}));
    let transport = RestTransport::new(
        RestConfig::new("http://127.0.0.1:1").with_actions(HashMap::from([("read".into(), op)])),
    );
    for value in ["a/b", "a\\b", "%2f", "%5C", "%2e%2e", "a/%2e%2e/b", "%252f"] {
        let reply = transport.dispatch(
            request("read", json!({"repo":value})),
            &ResolvedCredential::anonymous(),
        );
        assert_eq!(reply.transmission, TransmissionState::NotSent);
        assert_eq!(
            reply.error_code.as_deref(),
            Some("path_argument_invalid"),
            "ambiguous path must be refused: {value}"
        );
    }
}

#[test]
fn throttle_statuses_without_auth_poisoning() {
    for (status, headers) in [
        (403, "X-RateLimit-Remaining: 0\r\n"),
        (429, ""),
        (503, "Retry-After: 60\r\n"),
    ] {
        let (url, worker) = server(move |_| response(status, headers, "{}"));
        let transport = RestTransport::new(RestConfig::new(url).with_actions(HashMap::from([(
            "read".into(),
            operation(json!({"method":"GET","path":"/","args_schema":{}})),
        )])));
        let reply =
            transport.dispatch(request("read", json!({})), &ResolvedCredential::anonymous());
        worker.join().unwrap();
        assert_eq!(
            reply.retryability,
            Retryability::Throttle,
            "status {status} must be a throttle"
        );
        assert_eq!(reply.error_code.as_deref(), Some("throttled"));
        assert!(
            reply.retry_after_ms.is_some_and(|delay| delay > 0),
            "throttle needs a bounded fallback delay"
        );
        let next = transport.dispatch(request("read", json!({})), &ResolvedCredential::anonymous());
        assert_eq!(next.transmission, TransmissionState::NotSent);
        assert_eq!(
            next.retryability,
            Retryability::Throttle,
            "next call must honor the prior throttle"
        );
    }
}

/// Not `FixedRequestServer`: the reply is written in timed slices, under the
/// same tighter accept and socket deadlines as `server`.
fn trickle(mcp: bool) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(3);
        let mut index = 0;
        loop {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let wire = crate::test_http::read_mock_request(&mut socket, "trickle").unwrap();
                    if mcp && index < 2 {
                        let rpc: Value =
                            serde_json::from_str(wire.split_once("\r\n\r\n").unwrap().1).unwrap();
                        let reply = if index == 0 {
                            response(
                                200,
                                "",
                                &json!({"jsonrpc":"2.0","id":rpc["id"],"result":{}}).to_string(),
                            )
                        } else {
                            response(202, "", "")
                        };
                        socket.write_all(reply.as_bytes()).unwrap();
                        index += 1;
                        continue;
                    }
                    let kind = if mcp {
                        "text/event-stream"
                    } else {
                        "application/json"
                    };
                    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
                    let started = Instant::now();
                    while started.elapsed() < Duration::from_millis(900) {
                        if socket
                            .write_all(if mcp { b": ping\n\n" } else { b" " })
                            .is_err()
                        {
                            break;
                        }
                        std::thread::park_timeout(Duration::from_millis(20));
                    }
                    break;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
                {
                    std::thread::park_timeout(Duration::from_millis(2))
                }
                Err(error) => panic!("accept: {error}"),
            }
        }
    });
    (url, worker)
}

#[test]
fn rest_total_deadline_bounds_trickling_body_and_releases_connection() {
    let (url, worker) = trickle(false);
    let mut cfg = RestConfig::new(url).with_actions(HashMap::from([(
        "read".into(),
        operation(json!({"method":"GET","path":"/","args_schema":{}})),
    )]));
    cfg.request_timeout = Duration::from_millis(150);
    let transport = RestTransport::new(cfg);
    let started = Instant::now();
    let reply = transport.dispatch(request("read", json!({})), &ResolvedCredential::anonymous());
    let elapsed = started.elapsed();
    let next = transport.dispatch(request("read", json!({})), &ResolvedCredential::anonymous());
    worker.join().unwrap();
    assert!(
        elapsed < Duration::from_millis(650),
        "total deadline must stop a trickling body: {elapsed:?}"
    );
    assert_eq!(reply.error_code.as_deref(), Some("timeout"));
    assert_ne!(
        next.error_code.as_deref(),
        Some("transport_restart_required")
    );
}

#[test]
fn mcp_total_deadline_bounds_pings_and_releases_connection() {
    let (url, worker) = trickle(true);
    let mut cfg = McpRemoteConfig::new(url);
    cfg.request_timeout = Duration::from_millis(150);
    let transport = McpRemoteTransport::new(cfg);
    let started = Instant::now();
    let reply = transport.dispatch(request("read", json!({})), &ResolvedCredential::anonymous());
    let elapsed = started.elapsed();
    let next = transport.dispatch(request("read", json!({})), &ResolvedCredential::anonymous());
    worker.join().unwrap();
    assert!(
        elapsed < Duration::from_millis(650),
        "total deadline must stop endless pings: {elapsed:?}"
    );
    assert_eq!(reply.error_code.as_deref(), Some("timeout"));
    assert_ne!(
        next.error_code.as_deref(),
        Some("transport_restart_required")
    );
}

#[test]
fn parameter_placement_does_not_quarantine_an_active_catalog_action() {
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    let scratch = crate::test_scratch::Scratch::database("transport-schema-placement");
    let store = Arc::new(
        crate::PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "transport-placement-test".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    store
        .insert_connection(
            "direct",
            "bounds",
            "github_rest",
            "active",
            &json!({"required":[],"write_enabling":[]}),
        )
        .unwrap();
    let source: Value = serde_json::from_str(
        &subc_jsonc::jsonc_to_json(include_str!("../../../catalog/github_rest.jsonc")).unwrap(),
    )
    .unwrap();
    let mut before = crate::manifest::ingest_value(source).unwrap().manifest;
    before
        .actions_baseline
        .retain(|action| action.name == "remove_issue_assignees");
    before.actions_baseline[0].http.as_mut().unwrap().parameters = None;
    let reconciler = crate::catalog::CatalogReconciler::new(
        Arc::clone(&store),
        Arc::new(McpRemoteTransport::default()),
        Default::default(),
    );
    let connection = crate::rest_api::RestConnection::from_manifest("bounds", &before);
    reconciler
        .refresh_rest("direct", &connection, &before)
        .unwrap();
    let row = store
        .list_catalog_actions_all("direct", "bounds")
        .unwrap()
        .remove(0);
    store
        .upsert_catalog_action(&crate::CatalogActionInput {
            principal: "direct".into(),
            connection_id: "bounds".into(),
            name: row.name,
            title: row.title,
            schema: row.schema,
            schema_hash: row.schema_hash,
            risk: row.risk,
            severity: row.severity,
            ask_first: row.ask_first,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: row.reconciliation,
        })
        .unwrap();
    let baseline = store
        .list_catalog_actions_all("direct", "bounds")
        .unwrap()
        .remove(0);
    let mut after = before;
    after.actions_baseline[0].http.as_mut().unwrap().parameters =
        Some(crate::manifest::RestParameterLocation::Body);
    reconciler
        .refresh_rest(
            "direct",
            &crate::rest_api::RestConnection::from_manifest("bounds", &after),
            &after,
        )
        .unwrap();
    let current = store
        .list_catalog_actions_all("direct", "bounds")
        .unwrap()
        .remove(0);
    assert_eq!(
        current.schema_hash, baseline.schema_hash,
        "transport placement must not alter the input-schema pin"
    );
    assert_eq!(
        current.generation, baseline.generation,
        "transport placement must not invalidate an active action"
    );
    assert_eq!(
        current.status, "active",
        "transport placement must not quarantine a live write"
    );
}
