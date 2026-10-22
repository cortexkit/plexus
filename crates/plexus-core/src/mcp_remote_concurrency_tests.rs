//! Pool maintenance must not serialize RPCs on unrelated MCP connections.

use super::tests::{config, notification_response, request, response, start_server};
use super::*;
use crate::bounded::Task;
use std::sync::{mpsc, TryLockError};
use std::thread;

/// How long a step that must make progress while another connection's RPC is
/// held may take. The busy RPC stays blocked until the test releases it, so the
/// failure being caught is waiting forever, and a generous bound costs nothing
/// when the step proceeds at once; a tight one only turns a loaded host into a
/// false "serialized" verdict.
const MUST_PROGRESS: Duration = Duration::from_secs(5);

fn vendor(
    arrived: mpsc::Sender<()>,
    release: Option<mpsc::Receiver<()>>,
) -> (String, crate::test_http::FixedRequestServer) {
    start_server(3, move |_, raw| {
        let body: Value = serde_json::from_str(raw.split_once("\r\n\r\n").unwrap().1).unwrap();
        match body["method"].as_str().unwrap() {
            "initialize" => response(
                200,
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
                "mcp-session-id: vendor-session",
            ),
            "notifications/initialized" => {
                assert!(raw
                    .to_ascii_lowercase()
                    .contains("mcp-session-id: vendor-session"));
                notification_response()
            }
            "tools/call" => {
                assert!(raw
                    .to_ascii_lowercase()
                    .contains("mcp-session-id: vendor-session"));
                arrived.send(()).unwrap();
                if let Some(release) = &release {
                    // Longer than every MUST_PROGRESS wait a red run spends
                    // before releasing, and shorter than the client's 30 s
                    // request timeout, so a serialized pool fails on its own
                    // assertion rather than on this gate.
                    release
                        .recv_timeout(Duration::from_secs(25))
                        .expect("release gated MCP RPC");
                }
                response(
                    200,
                    r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"done"}]}}"#,
                    "",
                )
            }
            method => panic!("unexpected MCP method: {method}"),
        }
    })
}

fn dispatch(
    transport: Arc<McpRemoteTransport>,
    connection: &'static str,
) -> Task<TransportResponse> {
    Task::spawn(move || {
        transport.dispatch(
            request(connection, "read_tool"),
            &ResolvedCredential::new(b"test-key".to_vec(), None, 1),
        )
    })
}

struct BusyConnection {
    transport: Arc<McpRemoteTransport>,
    release: mpsc::Sender<()>,
    call: Task<TransportResponse>,
    vendor: crate::test_http::FixedRequestServer,
}

impl BusyConnection {
    fn start() -> Self {
        let (arrived, requests) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (endpoint, vendor) = vendor(arrived, Some(released));
        let transport = Arc::new(McpRemoteTransport::default());
        let mut config = config(endpoint);
        // Even an expired idle clock cannot make an in-flight client evictable.
        config.idle_timeout = Duration::ZERO;
        transport.register_config("busy", config);
        let call = dispatch(Arc::clone(&transport), "busy");
        requests
            .recv_timeout(Duration::from_secs(5))
            .expect("first vendor reached its gated tools/call");
        Self {
            transport,
            release,
            call,
            vendor,
        }
    }

    fn finish(self) {
        self.release.send(()).unwrap();
        let result = self.call.join_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            result.response.is_some(),
            "first RPC must complete: {result:?}"
        );
        self.vendor.join().unwrap();
    }
}

#[test]
fn mcp_sweep_and_other_connection_dispatch_progress_during_a_busy_rpc() {
    let busy = BusyConnection::start();
    let transport = Arc::clone(&busy.transport);
    let sweep_transport = Arc::clone(&transport);
    let (swept, sweeps) = mpsc::channel();
    let sweep = Task::spawn(move || {
        let removed = sweep_transport.sweep_idle();
        swept.send(removed).unwrap();
    });
    let sweep_result = sweeps.recv_timeout(MUST_PROGRESS);

    let (arrived, requests) = mpsc::channel();
    let (endpoint, other_vendor) = vendor(arrived, None);
    transport.register_config("other", config(endpoint));
    let other_call = dispatch(Arc::clone(&transport), "other");
    let other_started = requests.recv_timeout(MUST_PROGRESS);

    // Always release and join the gated vendor before reporting a red control.
    busy.finish();
    sweep.join_timeout(Duration::from_secs(5)).unwrap();
    let result = other_call.join_timeout(Duration::from_secs(5)).unwrap();
    other_vendor.join().unwrap();
    assert!(
        sweep_result.is_ok(),
        "MCP sweep must not wait for a busy RPC"
    );
    assert!(
        other_started.is_ok(),
        "another MCP connection must reach its vendor before the busy RPC is released"
    );
    assert!(
        result.response.is_some(),
        "second RPC must complete: {result:?}"
    );
    assert_eq!(
        sweep_result.unwrap(),
        0,
        "a busy MCP entry must not be evicted"
    );
    assert_eq!(
        transport.connection_count(),
        2,
        "both per-connection clients must remain pooled"
    );
}

#[test]
fn mcp_reconnect_waits_only_for_its_own_busy_connection() {
    let busy = BusyConnection::start();
    let transport = Arc::clone(&busy.transport);
    let entry = Arc::clone(transport.entries.lock().unwrap().get("busy").unwrap());
    let owners_before_reset = Arc::strong_count(&entry);
    let reconnect_transport = Arc::clone(&transport);
    let (reconnected, reconnects) = mpsc::channel();
    let reconnect = Task::spawn(move || {
        reconnect_transport.reconnect("busy");
        reconnected.send(()).unwrap();
    });

    // The gated RPC keeps its entry ownership stable. A new Arc owner proves
    // reconnect has looked up that entry; a held map detects the old lock order.
    // Either observation places reconnect at the busy entry before dispatching
    // the other connection, without a timing sleep or a production test hook.
    let deadline = Instant::now() + MUST_PROGRESS;
    let reconnect_started = loop {
        if Arc::strong_count(&entry) > owners_before_reset
            || matches!(transport.entries.try_lock(), Err(TryLockError::WouldBlock))
        {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::yield_now();
    };
    let reset_pending = matches!(reconnects.try_recv(), Err(mpsc::TryRecvError::Empty));
    let (arrived, requests) = mpsc::channel();
    let (endpoint, other_vendor) = vendor(arrived, None);
    transport.register_config("other", config(endpoint));
    let other_call = dispatch(Arc::clone(&transport), "other");
    let other_started = requests.recv_timeout(MUST_PROGRESS);

    busy.finish();
    reconnect.join_timeout(Duration::from_secs(5)).unwrap();
    let result = other_call.join_timeout(Duration::from_secs(5)).unwrap();
    other_vendor.join().unwrap();
    assert!(
        reconnect_started,
        "reconnect must reach the busy connection"
    );
    assert!(
        reset_pending,
        "reconnect must wait until its own RPC finishes"
    );
    assert!(
        other_started.is_ok(),
        "MCP reconnect must not block another connection's RPC"
    );
    assert!(
        result.response.is_some(),
        "second RPC must complete: {result:?}"
    );
    assert!(
        reconnects.recv_timeout(crate::bounded::WAIT).is_ok(),
        "reconnect must finish after its RPC is released"
    );
    let state = entry.lock().unwrap();
    assert!(!state.initialized, "reconnect must require a new handshake");
    assert!(
        state.session_id.is_none(),
        "reconnect must clear the vendor session"
    );
}

/// A poisoned entry is evicted, logged and counted, so the connection heals
/// on its next call instead of refusing every call until a restart.
///
/// A poisoned lock means a panic happened while a request held the
/// connection, so the eviction is not silent: it is logged at ERROR and
/// counted in `panic_recoveries`.
#[test]
fn mcp_sweep_evicts_a_poisoned_entry() {
    let transport = McpRemoteTransport::default();
    let config = config("http://127.0.0.1:1/mcp".into());
    let entry = transport.entry_for("poisoned", &config).unwrap();
    let poison = Task::spawn(move || {
        let _state = entry.lock().unwrap();
        panic!("poison the entry for eviction coverage");
    });
    assert!(
        poison.join().is_err(),
        "the entry must actually be poisoned"
    );
    assert_eq!(
        transport.sweep_idle(),
        1,
        "a poisoned MCP entry must be evicted"
    );
    assert_eq!(transport.connection_count(), 0);
    assert_eq!(transport.panic_recoveries(), 1);
}
