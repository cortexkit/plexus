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

#[tokio::test]
async fn registration_channel_hello_omits_nonce_and_stays_warming() {
    let (writer, mut responses) = mpsc::channel(2);
    let mut config = config();
    config.registration_channel = true;
    let provides = send_hello(&writer, &config).await.unwrap();
    let frame = recv_within(responses.recv(), RESPONSE_DEADLINE, "channel HELLO").await;
    let body: Value = serde_json::from_slice(&frame.body).unwrap();
    assert!(body.get("launch_nonce").is_none(), "{body}");
    assert_eq!(body["manifest"]["registration_channel"], true);
    assert_eq!(body["manifest"]["ready"], false);
    assert_eq!(
        body["manifest"]["provides"],
        serde_json::to_value(provides).unwrap()
    );

    // Pin the old registration HELLO bytes. Build provenance changes with
    // the checkout and dependency pins, so mask just its value in the raw JSON.
    let body: ModuleHelloBody = serde_json::from_slice(&frame.body).unwrap();
    let raw = std::str::from_utf8(&frame.body).unwrap();
    let provenance = format!(
        "\"provenance\":{}",
        serde_json::to_string(&body.manifest.provenance).unwrap()
    );
    assert_eq!(raw.matches(&provenance).count(), 1);
    let comparable = raw.replacen(&provenance, "\"provenance\":null", 1);
    assert_eq!(
        plexus_core::jcs::sha256_hex(comparable.as_bytes()),
        "b353e9378196ae97a5e93af978b9d69b3a5f70bce862a35b74e420795dd32948",
        "registration HELLO bytes outside build provenance changed"
    );
}

#[tokio::test]
async fn warming_ignores_upgrade_and_unknown_control_pushes() {
    let (writer, mut responses) = mpsc::channel(2);
    let health = health::HealthState::new();
    let upgrade = frame(
        FrameType::Push,
        0,
        0,
        json!({"op": "module.upgrading", "reconnect_by_ms": 1000}),
    );
    assert_eq!(
        serde_json::from_slice::<ModuleControlCommand>(&upgrade.body).unwrap(),
        ModuleControlCommand::Upgrading {
            reconnect_by_ms: 1000,
        }
    );
    let unknown = frame(FrameType::Push, 0, 0, json!({"op": "module.future"}));
    for notice in [upgrade, unknown] {
        assert!(startup::handle_warming_frame(notice, &writer, &health)
            .await
            .unwrap());
        assert_eq!(responses.try_recv(), Err(mpsc::error::TryRecvError::Empty));
    }
    assert!(
        !startup::handle_warming_frame(stop_notice(), &writer, &health)
            .await
            .unwrap()
    );
}

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
            identity: BindIdentity::new("test", "session"),
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
) -> ModuleHelloBody {
    let hello = reply(responses, HELLO_CORRELATION).await;
    assert_eq!(hello.header.ty, FrameType::Hello);
    let body: ModuleHelloBody = serde_json::from_slice(&hello.body).unwrap();
    assert_eq!(body.manifest.ready, Some(false));
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.into(),
        storage_namespace: namespace.into(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: plexus_core::test_scratch::store_path(),
        },
    };
    hello_ack(input, Some(serde_json::to_value(descriptor).unwrap())).await;
    body
}

async fn hello_ack(input: &mut tokio::io::DuplexStream, storage: Option<Value>) {
    write_frame(
        input,
        &frame(
            FrameType::HelloAck,
            0,
            HELLO_CORRELATION,
            serde_json::to_value(ModuleHelloAckBody {
                negotiated_ver: PROTOCOL_VERSION,
                subc_ops: vec!["catalog.update".into()],
                subc_capabilities: vec![],
                machine_id: None,
                storage,
                resume_token: None,
            })
            .unwrap(),
        ),
    )
    .await
    .unwrap();
}

async fn ready_update(responses: &mut mpsc::Receiver<Frame>, hello: &ModuleHelloBody) -> Frame {
    let update = recv_within(responses.recv(), RESPONSE_DEADLINE, "ready update").await;
    assert_eq!(update.header.ty, FrameType::Request);
    assert_eq!(update.header.ver, PROTOCOL_VERSION);
    assert_eq!(update.header.channel, 0);
    assert_eq!(update.header.epoch, 0);
    assert_eq!(
        serde_json::from_slice::<Value>(&update.body).unwrap(),
        json!({
            "op": "catalog.update",
            "provides": hello.manifest.provides,
            "ready": true,
        }),
        "readiness must preserve the registered roles and omit capabilities"
    );
    update
}

async fn ready_ack(input: &mut tokio::io::DuplexStream, update: &Frame) {
    write_frame(
        input,
        &frame(
            FrameType::Response,
            0,
            update.header.corr,
            json!({"op":"catalog.update"}),
        ),
    )
    .await
    .unwrap();
}

async fn assert_writer_closed(responses: &mut mpsc::Receiver<Frame>) {
    assert!(
        tokio::time::timeout(RESPONSE_DEADLINE, responses.recv())
            .await
            .expect("daemon writer closes")
            .is_none(),
        "unexpected extra frame after startup or shutdown"
    );
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
        registration_channel: false,
        module_id: DEFAULT_MODULE_ID.into(),
        connection_file_path: PathBuf::from("unused-startup-fixture-connection"),
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
                // Only the mock vendor has a credential. A default success
                // would hand a bogus token to background relay tasks, which
                // connect to the real relay rather than the mock transport.
                let credentials = StubCredentialSource::default();
                credentials.set_success(
                    crate::rest_pool_tests::POLL_CREDENTIAL_HANDLE,
                    b"poll-key".to_vec(),
                    None,
                    1,
                );
                runtime.engine = GovernanceEngine::new(
                    store,
                    Arc::new(credentials) as Arc<dyn CredentialSource>,
                    Arc::new(FirstPoll {
                        rest: Arc::clone(&runtime.rest_transport),
                        polled: polls,
                    }),
                );
                for id in ["relay:github", "relay:github-apps"] {
                    assert!(
                        runtime.credential_source().get_by_id(id).is_err(),
                        "startup fixture must not supply a credential to the external relay"
                    );
                }
                composed.send(()).unwrap();
                released
                    .recv_timeout(Duration::from_secs(20))
                    .expect("release composition");
                runtime
            },
        )
        .await
    });
    let hello = hello(&mut input, &mut responses, "delayed-startup").await;
    recv_within(
        async { composing.await.ok() },
        RESPONSE_DEADLINE,
        "composition delay reached",
    )
    .await;
    assert!(polled.try_recv().is_err(), "no polling during composition");
    assert!(
        responses.try_recv().is_err(),
        "no ready flip during composition"
    );

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
    let update = ready_update(&mut responses, &hello).await;
    assert!(
        polled.try_recv().is_err(),
        "no polling before readiness ACK"
    );
    input.write_all(&bytes[10..]).await.unwrap();
    assert_warming(reply(&mut responses, 80).await);
    write_frame(
        &mut input,
        &frame(FrameType::Request, 0, 83, json!({"op":"health.check"})),
    )
    .await
    .unwrap();
    let warming: Value = serde_json::from_slice(&reply(&mut responses, 83).await.body).unwrap();
    assert_eq!(warming["detail"], "module_warming");
    assert_eq!(warming["metrics"]["ready"], false);
    ready_ack(&mut input, &update).await;
    assert!(
        recv_within(polled.recv(), RESPONSE_DEADLINE, "first scheduler poll").await,
        "the first poll must observe registered transport configuration"
    );
    write_frame(&mut input, &bind(84)).await.unwrap();
    let bound = reply(&mut responses, 84).await;
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
    tokio::time::timeout(
        RESPONSE_DEADLINE,
        health.connection_probe_observed.notified(),
    )
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
        status,
        detail,
        metrics,
    } = serde_json::from_slice(&response.body).unwrap()
    else {
        panic!("expected ready health")
    };
    assert_eq!(
        status,
        HealthStatus::Ok,
        "ready health degraded: {detail:?}; {metrics:?}"
    );
    let metrics = metrics.unwrap();
    assert_eq!(metrics["ready"], true);
    assert!(
        !metrics["connections"].is_null(),
        "connection probe must have published"
    );
    assert_unsampled(&metrics);

    unlock.send(()).unwrap();
    health_lock.await.unwrap();
    write_frame(&mut input, &stop_notice()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), module)
        .await
        .expect("module stops")
        .unwrap()
        .unwrap();
    assert_writer_closed(&mut responses).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_startup_never_sends_ready() {
    let (mut input, mut reader) = tokio::io::duplex(8192);
    let (writer, mut responses) = mpsc::channel(8);
    let module = tokio::spawn(async move {
        module_loop_with_composition(
            &mut reader,
            writer,
            &config(),
            Arc::new(health::HealthState::new()),
            Arc::new(RouteBindings::new()),
            |_, _| panic!("composition must not run without storage"),
        )
        .await
    });
    let sent = reply(&mut responses, HELLO_CORRELATION).await;
    let hello: ModuleHelloBody = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(hello.manifest.ready, Some(false));
    hello_ack(&mut input, None).await;
    let error = tokio::time::timeout(RESPONSE_DEADLINE, module)
        .await
        .expect("failed startup exits")
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("omitted the storage descriptor"));
    assert_writer_closed(&mut responses).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readiness_refusals_are_bounded_and_keep_health_warming_until_ack() {
    for accept_last in [true, false] {
        let (mut input, mut reader) = tokio::io::duplex(8192);
        let (writer, mut responses) = mpsc::channel(8);
        let module = tokio::spawn(async move {
            module_loop_with_composition(
                &mut reader,
                writer,
                &config(),
                Arc::new(health::HealthState::new()),
                Arc::new(RouteBindings::new()),
                |store, _| runtime_for_test(store),
            )
            .await
        });
        let hello = hello(&mut input, &mut responses, "refused-ready").await;
        for attempt in 1..=3 {
            let update = ready_update(&mut responses, &hello).await;
            write_frame(&mut input, &bind(90)).await.unwrap();
            assert_warming(reply(&mut responses, 90).await);
            write_frame(
                &mut input,
                &frame(FrameType::Request, 0, 91, json!({"op":"health.check"})),
            )
            .await
            .unwrap();
            let health: Value =
                serde_json::from_slice(&reply(&mut responses, 91).await.body).unwrap();
            assert_eq!(health["metrics"]["ready"], false);
            if attempt == 3 && accept_last {
                ready_ack(&mut input, &update).await;
            } else {
                write_frame(
                    &mut input,
                    &frame(
                        FrameType::Error,
                        0,
                        update.header.corr,
                        json!({"code":"temporarily_unavailable", "message":"retry"}),
                    ),
                )
                .await
                .unwrap();
            }
        }
        if accept_last {
            tokio::time::timeout(RESPONSE_DEADLINE, async {
                loop {
                    write_frame(
                        &mut input,
                        &frame(FrameType::Request, 0, 93, json!({"op":"health.check"})),
                    )
                    .await
                    .unwrap();
                    let health: Value =
                        serde_json::from_slice(&reply(&mut responses, 93).await.body).unwrap();
                    if health["metrics"]["ready"] == true {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("readiness ACK opens the health gate");
            write_frame(&mut input, &bind(92)).await.unwrap();
            assert_eq!(
                reply(&mut responses, 92).await.header.ty,
                FrameType::Response
            );
            write_frame(&mut input, &stop_notice()).await.unwrap();
        }
        let result = tokio::time::timeout(RESPONSE_DEADLINE, module)
            .await
            .expect("readiness attempts finish")
            .unwrap();
        assert_eq!(result.is_ok(), accept_last);
        assert_writer_closed(&mut responses).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_while_waiting_for_readiness_ack_closes_without_retry() {
    let (mut input, mut reader) = tokio::io::duplex(8192);
    let (writer, mut responses) = mpsc::channel(8);
    let module = tokio::spawn(async move {
        module_loop_with_composition(
            &mut reader,
            writer,
            &config(),
            Arc::new(health::HealthState::new()),
            Arc::new(RouteBindings::new()),
            |store, _| runtime_for_test(store),
        )
        .await
    });
    let hello = hello(&mut input, &mut responses, "stopped-ready").await;
    let _update = ready_update(&mut responses, &hello).await;
    write_frame(&mut input, &stop_notice()).await.unwrap();
    tokio::time::timeout(RESPONSE_DEADLINE, module)
        .await
        .expect("stop must not wait for readiness ACK")
        .unwrap()
        .unwrap();
    assert_writer_closed(&mut responses).await;
}

#[tokio::test]
async fn draining_fences_claim_mint_and_logs_racing_refusal_once_at_debug() {
    use subc_client_rs::registration::{ClaimError, ClaimMinter};
    use subc_protocol::claim::{ClaimMintRequest, ClaimPurpose};
    use subc_protocol::error_codes::CLAIM_UNREDEEMED_LIMIT;
    use tracing_subscriber::prelude::*;

    let logs = plexus_core::test_scratch::Scratch::directory("draining-claim-mint-log");
    let mut log_config = cortexkit_log::Config::in_dir("plexus", logs.path());
    log_config.spec = Some("debug".into());
    let (layer, handle) = crate::bus::safe_log_layer(log_config).unwrap();
    let _subscriber =
        tracing::subscriber::set_default(tracing_subscriber::Registry::default().with(layer));

    let (mut input, mut reader) = tokio::io::duplex(8192);
    let (writer, mut responses) = mpsc::channel(8);
    let bindings = Arc::new(RouteBindings::new());
    let pending = Arc::clone(&bindings.control_replies);
    let (minter, registration) = registration::Minter::new(&writer, PROTOCOL_VERSION, pending);
    let request = || ClaimMintRequest::new(ClaimPurpose::SelfConnection);
    let dispatcher = dispatch_loop_starting(
        &mut reader,
        writer.clone(),
        Arc::new(health::HealthState::new()),
        Arc::clone(&bindings),
        Arc::clone(&bindings.control_replies),
        std::future::pending(),
        Some(DispatchSettings {
            connection_file: Path::new("unused-startup-fixture-connection"),
            managed: None,
            registration: Some(&registration),
        }),
    );
    let daemon = async {
        let mint = recv_within(responses.recv(), RESPONSE_DEADLINE, "claim.mint request").await;
        assert_eq!(mint.header.ty, FrameType::Request);
        assert_eq!((mint.header.channel, mint.header.epoch), (0, 0));
        assert_eq!(
            serde_json::from_slice::<Value>(&mint.body).unwrap()["op"],
            "claim.mint"
        );
        let refusal = frame(
            FrameType::Error,
            0,
            mint.header.corr,
            json!({"code": CLAIM_UNREDEEMED_LIMIT, "message": "refused"}),
        );
        // Queue both frames together. The current-thread dispatch loop handles
        // Draining before the woken mint future can process its refusal.
        let mut incoming = Vec::new();
        write_frame(&mut incoming, &refusal).await.unwrap();
        write_frame(&mut incoming, &stop_notice()).await.unwrap();
        input.write_all(&incoming).await.unwrap();
    };
    let (stopped, (), raced) = tokio::time::timeout(RESPONSE_DEADLINE, async {
        tokio::join!(dispatcher, daemon, minter.mint(request()))
    })
    .await
    .expect("drain and racing mint finish");
    stopped.unwrap();

    // Keep the writer and lifetime alive, just as they can be while background
    // tasks unwind. A new mint must refuse locally rather than enqueue a frame.
    let fenced = tokio::select! {
        biased;
        result = minter.mint(request()) => matches!(result, Err(ClaimError::Unavailable)),
        _ = responses.recv() => false,
    };
    let no_extra_mints =
        fenced && matches!(responses.try_recv(), Err(mpsc::error::TryRecvError::Empty));

    let log = std::fs::read_to_string(handle.path()).unwrap();
    let mint_lines: Vec<_> = log
        .lines()
        .filter(|line| line.contains("registration claim.mint"))
        .collect();
    assert!(matches!(raced, Err(ClaimError::Unavailable)) && no_extra_mints && mint_lines.len() == 1,
        "Draining must stop retries and log the refusal once; racing result: {raced:?}; no extra mints: {no_extra_mints}; mint logs: {mint_lines:?}");
    test_logging::assert_diagnostic(
        mint_lines[0],
        cortexkit_log::ParsedLevel::Debug,
        "plexus.wire",
        &format!("registration claim.mint refused during shutdown: {CLAIM_UNREDEEMED_LIMIT}"),
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_settings_are_reviewed_while_warming_and_applied_before_readiness() {
    use subc_client_rs::config::*;

    let data = Scratch::directory("managed-startup");
    let catalog = data.join("catalog");
    std::fs::create_dir(&catalog).unwrap();
    std::fs::write(
        catalog.join("deepwiki.jsonc"),
        include_bytes!("../../../catalog/deepwiki.jsonc"),
    )
    .unwrap();
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.into(),
        storage_namespace: "managed-startup".into(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: data
                .join("plexus.db")
                .into_os_string()
                .into_string()
                .unwrap(),
        },
    };
    let (mut input, mut reader) = tokio::io::duplex(8192);
    let (writer, mut responses) = mpsc::channel(16);
    let module = tokio::spawn(async move {
        module_loop_with_composition(
            &mut reader,
            writer,
            &config(),
            Arc::new(health::HealthState::new()),
            Arc::new(RouteBindings::new()),
            |store, _| {
                let manifests = store.list_manifest_summaries("direct").unwrap();
                assert_eq!(manifests.len(), 1);
                assert_eq!(manifests[0].key, "deepwiki");
                runtime_for_test(store)
            },
        )
        .await
    });
    let hello: ModuleHelloBody =
        serde_json::from_slice(&reply(&mut responses, HELLO_CORRELATION).await.body).unwrap();
    assert!(hello
        .control_ops
        .as_ref()
        .unwrap()
        .iter()
        .any(|op| op == CONFIG_REVIEW_OP));
    let ack = ModuleHelloAckBody {
        negotiated_ver: PROTOCOL_VERSION,
        subc_ops: vec!["catalog.update".into()],
        subc_capabilities: vec![CONFIG_GATE_CAPABILITY.into()],
        machine_id: None,
        storage: Some(serde_json::to_value(descriptor).unwrap()),
        resume_token: None,
    };
    write_frame(
        &mut input,
        &frame(
            FrameType::HelloAck,
            0,
            HELLO_CORRELATION,
            serde_json::to_value(ack).unwrap(),
        ),
    )
    .await
    .unwrap();
    let control = |frame: &Frame, op| {
        assert_eq!(frame.header.ty, FrameType::Request);
        assert_eq!(frame.header.channel, 0);
        let body: Value = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(body["op"], op);
        body
    };
    let declare = recv_within(responses.recv(), RESPONSE_DEADLINE, "config declaration").await;
    let declaration = control(&declare, CONFIG_DECLARE_OP);
    write_frame(
        &mut input,
        &frame(
            FrameType::Response,
            0,
            declare.header.corr,
            json!({"op":CONFIG_DECLARE_OP}),
        ),
    )
    .await
    .unwrap();
    let get = recv_within(responses.recv(), RESPONSE_DEADLINE, "initial config fetch").await;
    control(&get, CONFIG_GET_OP);

    let review = ConfigReviewRequest::new(
        0,
        vec![ConfigLayerSnapshot::file(
            DEFAULT_MODULE_ID,
            ConfigLayer::User,
            declaration["user_file"].as_str().unwrap(),
            Some(br#"{"audit_retention_days":6}"#.to_vec()),
        )],
        None,
    );
    write_frame(
        &mut input,
        &frame(
            FrameType::Request,
            0,
            77,
            serde_json::to_value(review).unwrap(),
        ),
    )
    .await
    .unwrap();
    let response = reply(&mut responses, 77).await;
    assert_eq!(response.header.ty, FrameType::Response);
    let refused: ConfigReviewReply = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(refused.refusals[0].paths, ["/audit_retention_days"]);

    for (generation, get, catalog_dir, expected_result) in [
        (1, Some(get), "catalog", "ack"),
        (2, None, "catalog", "ack"),
        (3, None, "other-catalog", "nack"),
    ] {
        let get = if let Some(get) = get {
            get
        } else {
            let hint = ConfigChanged::new(generation, vec![]);
            write_frame(
                &mut input,
                &frame(FrameType::Push, 0, 0, serde_json::to_value(hint).unwrap()),
            )
            .await
            .unwrap();
            let get = recv_within(
                responses.recv(),
                RESPONSE_DEADLINE,
                "refreshed config fetch",
            )
            .await;
            control(&get, CONFIG_GET_OP);
            get
        };
        let mut view = ConfigView::new(
            generation,
            json!({"catalog_dir":catalog_dir,"audit_retention_days": 10 + generation}),
            Default::default(),
            vec![],
            ConfigStatus::Pending,
        );
        view.attempt = Some(generation + 50);
        let delivery = serde_json::to_value(ConfigGetReply::new(None, Some(view))).unwrap();
        write_frame(
            &mut input,
            &frame(FrameType::Response, 0, get.header.corr, delivery),
        )
        .await
        .unwrap();
        if generation == 1 {
            let ready = ready_update(&mut responses, &hello).await;
            ready_ack(&mut input, &ready).await;
        }
        let applied = recv_within(responses.recv(), RESPONSE_DEADLINE, "apply result").await;
        let body = control(&applied, CONFIG_APPLIED_OP);
        assert_eq!(body["result"], expected_result);
        assert_eq!(body["generation"], generation);
        assert_eq!(body["attempt"], generation + 50);
        write_frame(
            &mut input,
            &frame(
                FrameType::Response,
                0,
                applied.header.corr,
                json!({"op":CONFIG_APPLIED_OP}),
            ),
        )
        .await
        .unwrap();
    }

    write_frame(&mut input, &stop_notice()).await.unwrap();
    tokio::time::timeout(RESPONSE_DEADLINE, module)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_writer_closed(&mut responses).await;
}
