use super::*;
use plexus_core::{CredentialSource, GovernanceEngine, RestTransport, Transport};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use subc_protocol::session::{HealthStatus, ModuleControlCommand};
use subc_protocol::{BindIdentity, Principal, RouteTarget};
use subc_transport::write_frame;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tokio::sync::oneshot;

const RESPONSE_DEADLINE: Duration = Duration::from_secs(5);

struct ObservedReader {
    inner: tokio::io::DuplexStream,
    reads: mpsc::UnboundedSender<usize>,
}

impl AsyncRead for ObservedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let received = buf.filled().len() - before;
        if received > 0 {
            let _ = this.reads.send(received);
        }
        result
    }
}

fn frame(kind: FrameType, channel: u16, corr: u64, body: Value) -> Frame {
    Frame::build(
        kind,
        wire::control_flags(),
        channel,
        if channel == 0 { 0 } else { 1 },
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

fn bind(corr: u64) -> Frame {
    frame(
        FrameType::Request,
        0,
        corr,
        serde_json::to_value(ModuleControlRequest::RouteBind {
            route_channel: 2,
            epoch: 1,
            target: RouteTarget::ToolProvider {
                module_id: DEFAULT_MODULE_ID.into(),
            },
            identity: BindIdentity::new("startup-fixture", "test", "session"),
            principal: Some(Principal::Direct),
            consumer_capabilities: None,
            role_versions: None,
            admission_facts: None,
            scope: None,
            call_mode: None,
        })
        .unwrap(),
    )
}

fn stop_notice() -> Frame {
    frame(
        FrameType::Push,
        0,
        0,
        serde_json::to_value(ModuleControlCommand::Draining {
            reason: subc_protocol::RouteCloseReason::Restart,
            deadline_ms: (plexus_core::storage::now_ms() + 5_000) as u64,
        })
        .unwrap(),
    )
}

async fn reply(responses: &mut mpsc::Receiver<Frame>, corr: u64) -> Frame {
    let response = recv_within(responses.recv(), RESPONSE_DEADLINE, "startup response").await;
    assert_eq!(response.header.corr, corr);
    response
}

async fn hello(
    input: &mut tokio::io::DuplexStream,
    responses: &mut mpsc::Receiver<Frame>,
    namespace: &str,
) {
    let hello = reply(responses, HELLO_CORRELATION).await;
    assert_eq!(hello.header.ty, FrameType::Hello);
    let body: ModuleHelloBody = serde_json::from_slice(&hello.body).unwrap();
    assert_ne!(
        body.manifest.ready,
        Some(false),
        "HELLO readiness stays unchanged until the client can flip it"
    );
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.into(),
        storage_namespace: namespace.into(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".into(),
        },
    };
    write_frame(
        input,
        &frame(
            FrameType::HelloAck,
            0,
            HELLO_CORRELATION,
            serde_json::to_value(ModuleHelloAckBody {
                negotiated_ver: PROTOCOL_VERSION,
                subc_ops: vec![],
                subc_capabilities: vec![],
                machine_id: None,
                storage: Some(serde_json::to_value(descriptor).unwrap()),
            })
            .unwrap(),
        ),
    )
    .await
    .unwrap();
}

fn assert_warming(response: Frame) {
    assert_eq!(response.header.ty, FrameType::Error);
    let body: ErrorBody = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body.code, subc_protocol::error_codes::MODULE_WARMING);
    assert_eq!(body.detail.unwrap()["reason"], "module_initializing");
}

fn assert_unsampled(metrics: &Value) {
    for gauge in [
        "outboxDepth",
        "overlappingKeyRows",
        "droppedOnUnsubscribe",
        "droppedOnDelete",
        "orphanedMarkers",
        "effectiveCiCadenceS",
    ] {
        assert!(
            metrics.get(gauge).is_none(),
            "unsampled gauge {gauge} must not be zero"
        );
    }
}

struct FirstPoll {
    rest: Arc<RestTransport>,
    polled: mpsc::UnboundedSender<bool>,
}

impl Transport for FirstPoll {
    fn dispatch(
        &self,
        request: plexus_core::TransportRequest,
        _: &plexus_core::ResolvedCredential,
    ) -> plexus_core::TransportResponse {
        assert_eq!(request.connection_id, "poll-connection");
        assert_eq!(request.action, "poll");
        let _ = self
            .polled
            .send(self.rest.has_connection(&request.connection_id));
        plexus_core::TransportResponse::success(json!({"tag_name": "v1"}))
    }
}

fn config() -> ModuleConfig {
    ModuleConfig {
        module_id: DEFAULT_MODULE_ID.into(),
        connection_file_path: PathBuf::from("unused-startup-fixture-connection"),
        audit_retention_window_ms: DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_startup_serves_warming_then_registers_before_polling() {
    let health = Arc::new(health::HealthState::new());
    let lock_health = Arc::clone(&health);
    let (lock_ready, locked) = oneshot::channel();
    let (unlock, unlock_rx) = std::sync::mpsc::channel();
    let health_lock = tokio::task::spawn_blocking(move || {
        let _guard = lock_health.outbox_health.lock().unwrap();
        lock_ready.send(()).unwrap();
        let _ = unlock_rx.recv_timeout(Duration::from_secs(20));
    });
    locked.await.unwrap();

    let (composed, composing) = oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let (polls, mut polled) = mpsc::unbounded_channel();
    let (mut input, reader) = tokio::io::duplex(8192);
    let (read_steps, mut reads) = mpsc::unbounded_channel();
    let mut reader = ObservedReader {
        inner: reader,
        reads: read_steps,
    };
    let (writer, mut responses) = mpsc::channel(16);
    let loop_health = Arc::clone(&health);
    let module = tokio::spawn(async move {
        module_loop_with_composition(
            &mut reader,
            writer,
            &config(),
            loop_health,
            Arc::new(RouteBindings::new()),
            move |store, _| {
                crate::rest_pool_tests::seed_poll_store(&store);
                let mut runtime = runtime_for_test(Arc::clone(&store));
                runtime.engine = GovernanceEngine::new(
                    store,
                    Arc::new(StubCredentialSource::with_default_success(
                        b"poll-key".to_vec(),
                    )) as Arc<dyn CredentialSource>,
                    Arc::new(FirstPoll {
                        rest: Arc::clone(&runtime.rest_transport),
                        polled: polls,
                    }),
                );
                composed.send(()).unwrap();
                released
                    .recv_timeout(Duration::from_secs(20))
                    .expect("release composition");
                runtime
            },
        )
        .await
    });
    hello(&mut input, &mut responses, "delayed-startup").await;
    recv_within(
        async { composing.await.ok() },
        RESPONSE_DEADLINE,
        "composition delay reached",
    )
    .await;
    assert!(polled.try_recv().is_err(), "no polling during composition");

    write_frame(
        &mut input,
        &frame(FrameType::Request, 0, 77, json!({"op":"health.check"})),
    )
    .await
    .unwrap();
    let response = reply(&mut responses, 77).await;
    let ModuleControlResponse::HealthCheck {
        status,
        detail,
        metrics,
    } = serde_json::from_slice(&response.body).unwrap()
    else {
        panic!("expected warming health report");
    };
    assert_eq!(status, HealthStatus::Degraded);
    assert_eq!(detail.as_deref(), Some("module_warming"));
    let metrics = metrics.unwrap();
    assert_eq!(metrics["ready"], false);
    assert_eq!(metrics["connections"], Value::Null);
    assert_eq!(metrics["connectionsDegraded"], Value::Null);
    assert_unsampled(&metrics);

    write_frame(&mut input, &bind(78)).await.unwrap();
    assert_warming(reply(&mut responses, 78).await);
    let tool = |corr| {
        frame(
            FrameType::Request,
            2,
            corr,
            json!({"name":"connections", "arguments":{"op":"list"}}),
        )
    };
    write_frame(&mut input, &tool(79)).await.unwrap();
    assert_warming(reply(&mut responses, 79).await);

    // Keep a frame mid-read across readiness: completing initialization must
    // not drop read_frame's partial header and corrupt the daemon stream.
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &bind(80)).await.unwrap();
    while reads.try_recv().is_ok() {}
    input.write_all(&bytes[..10]).await.unwrap();
    // Each read is bounded on its own, so a stalled reader fails the test by
    // name instead of hanging it.
    let mut consumed = 0;
    while consumed < 10 {
        consumed += recv_within(reads.recv(), RESPONSE_DEADLINE, "partial frame consumed").await;
    }
    assert_eq!(consumed, 10);
    release.send(()).unwrap();
    assert!(
        recv_within(polled.recv(), RESPONSE_DEADLINE, "first scheduler poll").await,
        "the first poll must observe registered transport configuration"
    );
    input.write_all(&bytes[10..]).await.unwrap();
    let bound = reply(&mut responses, 80).await;
    assert_eq!(bound.header.ty, FrameType::Response);
    assert_eq!(
        serde_json::from_slice::<ModuleControlResponse>(&bound.body).unwrap(),
        ModuleControlResponse::RouteBindAck {}
    );
    write_frame(&mut input, &tool(81)).await.unwrap();
    let called = reply(&mut responses, 81).await;
    assert_eq!(called.header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&called.body).unwrap();
    assert!(
        body["result"]["connections"].is_array(),
        "tool call works after startup: {body}"
    );

    // The first scheduler health pass is blocked on the held outbox-cache
    // lock, but cached control health must remain responsive and unsampled.
    tokio::time::timeout(RESPONSE_DEADLINE, async {
        loop {
            let ModuleControlResponse::HealthCheck { metrics, .. } = health.report() else {
                unreachable!()
            };
            if !metrics.unwrap()["connections"].is_null() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first connection probe before store refresh");
    write_frame(
        &mut input,
        &frame(FrameType::Request, 0, 82, json!({"op":"health.check"})),
    )
    .await
    .unwrap();
    let response = reply(&mut responses, 82).await;
    let ModuleControlResponse::HealthCheck {
        status, metrics, ..
    } = serde_json::from_slice(&response.body).unwrap()
    else {
        panic!("expected ready health")
    };
    assert_eq!(status, HealthStatus::Ok);
    let metrics = metrics.unwrap();
    assert_eq!(metrics["ready"], true);
    assert_unsampled(&metrics);

    unlock.send(()).unwrap();
    health_lock.await.unwrap();
    write_frame(&mut input, &stop_notice()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), module)
        .await
        .expect("module stops")
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_notice_during_warmup_exits_without_waiting_for_startup() {
    let (composed, composing) = oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let (finished, finishing) = oneshot::channel();
    let (mut input, mut reader) = tokio::io::duplex(8192);
    let (writer, mut responses) = mpsc::channel(8);
    let module = tokio::spawn(async move {
        module_loop_with_composition(
            &mut reader,
            writer,
            &config(),
            Arc::new(health::HealthState::new()),
            Arc::new(RouteBindings::new()),
            move |store, _| {
                let runtime = runtime_for_test(store);
                composed.send(()).unwrap();
                let _ = released.recv_timeout(Duration::from_secs(20));
                let _ = finished.send(());
                runtime
            },
        )
        .await
    });
    hello(&mut input, &mut responses, "stopped-startup").await;
    recv_within(
        async { composing.await.ok() },
        RESPONSE_DEADLINE,
        "composition delay reached",
    )
    .await;
    write_frame(&mut input, &stop_notice()).await.unwrap();
    tokio::time::timeout(RESPONSE_DEADLINE, module)
        .await
        .expect("stop must not wait for composition")
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(RESPONSE_DEADLINE, responses.recv())
            .await
            .expect("writer closes on stop")
            .is_none(),
        "the daemon writer is released on stop"
    );
    release.send(()).unwrap();
    recv_within(
        async { finishing.await.ok() },
        RESPONSE_DEADLINE,
        "cancelled startup cleanup",
    )
    .await;
}
