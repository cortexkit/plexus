use super::*;
use crate::connector_home::RolePeer;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::rest_api::RestConfig;
use plexus_core::test_scratch::Scratch;
use plexus_core::{
    McpRemoteTransport, RestTransport, TransmissionState, Transport, TransportRequest,
};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use subc_protocol::{Flags, Frame, FrameType};
use subc_transport::{
    authenticate_server, connection_file, generate_daemon_id, generate_key, read_frame,
    write_frame, ConnectionInfo, Endpoint, SCHEMA_VERSION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(5);
const CHANNEL: u16 = 33;
const EPOCH: u32 = 7;

fn samples(name: &str) -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/role-lease-v1")
        .join(format!("{name}.json"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[derive(Default)]
struct OldReader(AtomicUsize);
impl RolePeer for OldReader {
    fn call(&self, method: &str, params: Value) -> Result<Value, ErrorBody> {
        assert_eq!(method, "role.read");
        assert_eq!(params, json!({"role": ROLE}));
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(
            json!({"role":ROLE,"epoch":1,"known":true,"held_here":true,"stale":false,
            "holder":"local","holder_name":"Here","source":"engram"}),
        )
    }
}

struct Rig {
    _scratch: Scratch,
    now: Arc<AtomicU64>,
    home: Arc<ConnectorHome>,
    store: Arc<PlexusStore>,
    reader: Arc<OldReader>,
    socket: TcpStream,
    stream_corr: u64,
    stop: mpsc::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

async fn recv(socket: &mut TcpStream) -> Frame {
    timeout(LIMIT, read_frame(socket))
        .await
        .expect("request did not arrive")
        .unwrap()
        .expect("route closed before request")
}

async fn send(
    socket: &mut TcpStream,
    kind: FrameType,
    channel: u16,
    epoch: u32,
    corr: u64,
    body: Vec<u8>,
) {
    let frame = Frame::build(kind, Flags(0), channel, epoch, corr, body).unwrap();
    timeout(LIMIT, write_frame(socket, &frame))
        .await
        .unwrap()
        .unwrap();
}

impl Rig {
    async fn new(now: u64) -> Self {
        let scratch = Scratch::directory("connector-home-lease");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connection = ConnectionInfo {
            schema: SCHEMA_VERSION,
            wire_version: None,
            endpoints: vec![Endpoint {
                host: "127.0.0.1".into(),
                port: listener.local_addr().unwrap().port(),
            }],
            key: generate_key().unwrap(),
            daemon_id: generate_daemon_id().unwrap(),
            pid: std::process::id(),
            daemon_ver: "0.41.0".into(),
        };
        let path = scratch.join("connection.json");
        connection_file::write_atomic(&path, &connection).unwrap();
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "lease-test".into(),
                isolation: Isolation::Module,
                backend: StorageBackend::Sqlite {
                    path: scratch.join("store.db").to_string_lossy().into(),
                },
            })
            .unwrap(),
        );
        let now = Arc::new(AtomicU64::new(now));
        let clock = now.clone();
        let reader = Arc::new(OldReader::default());
        let home = Arc::new(ConnectorHome::with_gate(reader.clone(), false, move || {
            Some(clock.load(Ordering::SeqCst))
        }));
        let (stop, rx) = mpsc::channel(1);
        let task_home = home.clone();
        let task_store = store.clone();
        let task = tokio::spawn(async move { run(task_home, task_store, &path, rx).await });
        let (mut socket, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        authenticate_server(
            &mut socket,
            &connection.key,
            &connection.daemon_id,
            &connection.daemon_ver,
            LIMIT,
        )
        .await
        .unwrap();

        let describe = recv(&mut socket).await;
        assert_eq!(describe.body, br#"{"op":"server.describe"}"#);
        send(
            &mut socket, FrameType::Response, 0, 0, describe.header.corr,
            br#"{"op":"server.describe","protocol_ver":1,"subc_ops":[],"capabilities":[],"connected_clients":1}"#.to_vec(),
        ).await;
        let open = recv(&mut socket).await;
        assert_eq!(open.header.channel, 0);
        let request: Value = serde_json::from_slice(&open.body).unwrap();
        assert_eq!(request["op"], "route.open");
        assert_eq!(
            request["target"],
            serde_json::to_value(RouteTarget::ManagementSurface {
                module_id: "entorhinal".into()
            })
            .unwrap()
        );
        let body = json!({"op":"route.open","route_channel":CHANNEL,"route_epoch":EPOCH,"request_window":3,"watch_window":1});
        send(
            &mut socket,
            FrameType::Response,
            0,
            0,
            open.header.corr,
            serde_json::to_vec(&body).unwrap(),
        )
        .await;
        let watch = recv(&mut socket).await;
        assert_eq!((watch.header.channel, watch.header.epoch), (CHANNEL, EPOCH));
        assert_eq!(
            watch.body,
            br#"{"method":"role.lease","params":{"role":"connector_home"}}"#
        );
        Self {
            _scratch: scratch,
            now,
            home,
            store,
            reader,
            socket,
            stream_corr: watch.header.corr,
            stop,
            task,
        }
    }

    async fn notice(&mut self, body: &Value) {
        send(
            &mut self.socket,
            FrameType::StreamData,
            CHANNEL,
            EPOCH,
            self.stream_corr,
            serde_json::to_vec(body).unwrap(),
        )
        .await;
        let seq = body["seq"].as_u64().unwrap();
        let ack = self.unary(format!(r#"{{"method":"role.lease.ack","params":{{"role":"connector_home","seq":{seq}}}}}"#).as_bytes()).await;
        let response = samples("ack")[0]["frames"][0]["body"].clone();
        self.reply(&ack, FrameType::Response, &response).await;
    }

    async fn unary(&mut self, body: &[u8]) -> Frame {
        let request = recv(&mut self.socket).await;
        assert_eq!(request.header.ty, FrameType::Request);
        assert_eq!(
            (request.header.channel, request.header.epoch),
            (CHANNEL, EPOCH)
        );
        assert_ne!(request.header.corr, self.stream_corr);
        assert_eq!(request.body, body);
        request
    }

    async fn reply(&mut self, request: &Frame, kind: FrameType, body: &Value) {
        send(
            &mut self.socket,
            kind,
            CHANNEL,
            EPOCH,
            request.header.corr,
            serde_json::to_vec(body).unwrap(),
        )
        .await;
    }

    async fn terminal(&mut self, kind: FrameType, body: Vec<u8>) {
        send(
            &mut self.socket,
            kind,
            CHANNEL,
            EPOCH,
            self.stream_corr,
            body,
        )
        .await;
    }

    async fn decision(&self, held: bool) {
        let mut updates = self.home.decisions();
        timeout(LIMIT, updates.wait_for(|value| *value == held))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self.home.held(), held);
    }

    async fn finish(self) {
        drop(self.stop);
        timeout(LIMIT, self.task).await.unwrap().unwrap();
        assert!(!self.home.held() || self.home.gate.legacy());
    }
}

fn body(record: &Value, index: usize) -> &Value {
    &record["frames"][index]["body"]
}

#[tokio::test(flavor = "multi_thread")]
async fn serving_requires_a_live_notice_and_remaining_transport_budget() {
    let mut rig = Rig::new(100_000).await;
    let unchanged = br#"{"error":{"code":"connector_home_not_held","connectorHome":{"state":"unknown"},"message":"connector home not held: {\"state\":\"unknown\"}","transmission":"not_sent"}}"#;
    assert_eq!(
        serde_json::to_vec(&rig.home.refusal().unwrap()).unwrap(),
        unchanged
    );
    rig.home.refresh().unwrap();
    assert!(!rig.home.held(), "role.read only feeds diagnostics");
    rig.notice(body(&samples("holding")[0], 0)).await;
    rig.decision(true).await;
    assert_eq!(
        rig.home.health_status()["lease"],
        json!({
            "holding":true, "gen":7, "deadline_in_ms":45_000, "handback":false, "yield_pending":false,
        })
    );
    rig.now.store(140_000, Ordering::SeqCst);
    assert_eq!(
        rig.home.begin_act().unwrap().unwrap().1,
        Duration::from_secs(5)
    );
    rig.now.store(140_001, Ordering::SeqCst);
    assert!(rig.home.held());
    assert!(rig.home.begin_act().is_err());

    rig.now.store(144_999, Ordering::SeqCst);
    assert!(rig.home.held());
    let mut changes = rig.home.decisions();
    rig.now.store(145_000, Ordering::SeqCst);
    assert!(rig.home.begin_act().is_err());
    timeout(LIMIT, changes.wait_for(|holds| !*holds))
        .await
        .unwrap()
        .unwrap();
    assert!(
        rig.home.refusal().is_some(),
        "a live connection cannot extend the deadline"
    );
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn engram_renewal_and_non_holding_notices_ack_and_refuse_stale_generation() {
    let mut rig = Rig::new(140_000).await;
    let engram = samples("engram-sharing");
    rig.notice(body(&engram[0], 0)).await;
    rig.decision(true).await;
    rig.notice(body(&engram[0], 1)).await;
    rig.decision(false).await;
    let mut old = body(&samples("holding")[0], 0).clone();
    old["seq"] = json!(7);
    rig.notice(&old).await;
    // A fresh valid generation with a higher sequence is processed after the
    // replay. The replay itself is not eligible even though it has time left.
    let mut changes = rig.home.decisions();
    assert!(
        timeout(Duration::from_millis(100), changes.wait_for(|held| *held))
            .await
            .is_err()
    );
    assert!(!rig.home.held());
    assert!(!rig.store.observe_connector_home_generation(7).unwrap());
    let newer = samples("local-after-hub");
    rig.notice(body(&newer[0], 0)).await;
    rig.decision(true).await;
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn handback_waits_for_an_in_flight_leg_then_yields_on_the_watch_route() {
    for (file, transferred) in [("yield-transferred", true), ("yield-withdrawn", false)] {
        let mut rig = Rig::new(100_000).await;
        let shared = samples("sharing-disabled");
        rig.notice(body(&shared[0], 0)).await;
        rig.decision(true).await;
        let leg = rig.home.begin_act().unwrap();

        // The handback fixture is addressed to Magic Context. The notices do
        // not carry a role name; retarget its generation to the Plexus yield.
        let mut handback = body(&samples("handback")[0], 0).clone();
        handback["gen"] = json!(1);
        rig.notice(&handback).await;
        rig.decision(false).await;
        assert!(rig.home.begin_act().is_err());
        let mut peek = [0];
        assert!(
            timeout(Duration::from_millis(50), rig.socket.peek(&mut peek))
                .await
                .is_err(),
            "yield must wait for the admitted leg"
        );
        drop(leg);
        let request = rig
            .unary(br#"{"method":"role.lease.yield","params":{"gen":1,"role":"connector_home"}}"#)
            .await;
        assert_eq!(rig.home.health_status()["lease"]["yield_pending"], true);
        let mut renewal = body(&shared[0], 1).clone();
        renewal["seq"] = json!(4);
        rig.now.store(120_000, Ordering::SeqCst);
        rig.notice(&renewal).await;
        assert!(
            rig.home.begin_act().is_err(),
            "renewal cannot bypass an unsettled yield"
        );
        rig.reply(&request, FrameType::Response, body(&samples(file)[0], 0))
            .await;
        if transferred {
            let mut replay = renewal.clone();
            replay["seq"] = json!(5);
            rig.notice(&replay).await;
            assert!(
                rig.home.begin_act().is_err(),
                "transferred generation must never resume"
            );
            renewal["seq"] = json!(6);
            renewal["gen"] = json!(2);
            rig.notice(&renewal).await;
        }
        rig.decision(true).await;
        rig.finish().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lapse_and_stream_end_never_fall_back() {
    let mut rig = Rig::new(100_000).await;
    let lapse = samples("lapsed");
    rig.notice(body(&lapse[0], 0)).await;
    rig.decision(true).await;
    let mut changes = rig.home.decisions();
    rig.now.store(145_000, Ordering::SeqCst);
    timeout(LIMIT, changes.wait_for(|held| !*held))
        .await
        .unwrap()
        .unwrap();
    assert!(!rig.home.held());
    assert!(body(&lapse[0], 1).is_null());
    rig.terminal(FrameType::StreamEnd, vec![]).await;
    assert!(!rig.home.gate.legacy());
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn only_explicit_unsupported_watch_enables_legacy_reader() {
    let mut refusals = samples("refusals")
        .into_iter()
        .map(|record| body(&record, 0).clone())
        .collect::<Vec<_>>();
    refusals.extend([
        json!({"code":"unknown_method","message":"role.lease"}),
        json!({"code":"unsupported","message":"role.lease"}),
    ]);
    for error in refusals {
        let mut rig = Rig::new(100_000).await;
        rig.home.refresh().unwrap();
        assert!(!rig.home.held());
        rig.terminal(FrameType::Error, serde_json::to_vec(&error).unwrap())
            .await;
        // The real client must release its route on each terminal outcome.
        let goodbye = recv(&mut rig.socket).await;
        assert_eq!(goodbye.header.ty, FrameType::Goodbye);
        assert_eq!(
            (goodbye.header.channel, goodbye.header.epoch),
            (CHANNEL, EPOCH)
        );
        if matches!(
            error["code"].as_str(),
            Some("unknown_method" | "unsupported")
        ) {
            rig.decision(true).await;
            assert_eq!(rig.reader.0.load(Ordering::SeqCst), 2);
        } else {
            assert!(!rig.home.held());
            assert_eq!(rig.reader.0.load(Ordering::SeqCst), 1);
        }
        rig.finish().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn not_holding_is_acked_and_wrong_route_ack_never_grants() {
    let mut rig = Rig::new(100_000).await;
    rig.notice(body(&samples("not-holding")[0], 0)).await;
    rig.decision(false).await;
    let holding = samples("holding");
    let mut notice = body(&holding[0], 0).clone();
    notice["seq"] = json!(3);
    rig.terminal(FrameType::StreamData, serde_json::to_vec(&notice).unwrap())
        .await;
    let ack = rig
        .unary(br#"{"method":"role.lease.ack","params":{"role":"connector_home","seq":3}}"#)
        .await;
    rig.reply(&ack, FrameType::Error, body(&samples("ack")[1], 0))
        .await;
    assert!(!rig.home.held());
    assert!(!rig.home.gate.legacy());
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn insufficient_lease_refuses_at_real_rest_and_mcp_send_boundaries() {
    let mut rig = Rig::new(100_000).await;
    rig.notice(body(&samples("holding")[0], 0)).await;
    rig.decision(true).await;
    let vendor = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", vendor.local_addr().unwrap());
    let rest = rest_reader(&rig.home, &endpoint);
    let mcp = McpRemoteTransport::new(plexus_core::McpRemoteConfig::new(&endpoint))
        .with_vendor_leg_gate(rig.home.vendor_gate());

    let endpoint_task = tokio::spawn(async move {
        let (mut socket, request) = vendor_request(&vendor).await;
        assert!(request.starts_with(b"GET /read "));
        socket.write_all(VENDOR_OK).await.unwrap();
    });
    rig.now.store(141_000, Ordering::SeqCst);
    assert!(rig.home.held());
    for transport in [&rest as &dyn Transport, &mcp] {
        let reply = blocking_section(|| dispatch_read(transport));
        assert_eq!(reply.transmission, TransmissionState::NotSent);
        assert_eq!(reply.error_code.as_deref(), Some("connector_home_not_held"));
        assert_eq!(
            reply.error_message.as_deref(),
            Some(
                r#"connector home not held: {"checkedAt":null,"code":null,"epoch":null,"holder_name":null,"source":null,"state":"not_held"}"#
            )
        );
    }
    rig.now.store(119_000, Ordering::SeqCst);
    let reply = blocking_section(|| dispatch_read(&rest));
    assert_eq!(reply.response, Some(json!({})));
    timeout(LIMIT, endpoint_task).await.unwrap().unwrap();
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rest_leg_times_out_when_vendor_replies_after_lease_deadline() {
    let mut rig = Rig::new(100_000).await;
    rig.notice(body(&samples("holding")[0], 0)).await;
    rig.decision(true).await;
    rig.now.store(119_000, Ordering::SeqCst);

    let vendor = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rest = rest_reader(
        &rig.home,
        &format!("http://{}", vendor.local_addr().unwrap()),
    );
    let (seen, received) = tokio::sync::oneshot::channel();
    let endpoint_task = tokio::spawn(async move {
        let (mut socket, request) = vendor_request(&vendor).await;
        assert!(request.starts_with(b"GET /read "));
        seen.send(()).unwrap();
        // The reply fits within the configured 30 seconds, but not the lease's 26.
        tokio::time::sleep(Duration::from_secs(27)).await;
        let _ = socket.write_all(VENDOR_OK).await;
    });
    let reply = blocking_section(|| dispatch_read(&rest));
    assert_eq!(reply.error_code.as_deref(), Some("timeout"));
    assert_eq!(reply.response, None);
    timeout(LIMIT, received).await.unwrap().unwrap();
    timeout(LIMIT, endpoint_task).await.unwrap().unwrap();
    rig.finish().await;
}

const VENDOR_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

async fn vendor_request(vendor: &TcpListener) -> (TcpStream, Vec<u8>) {
    let (mut socket, _) = vendor.accept().await.unwrap();
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        request.push(socket.read_u8().await.unwrap());
    }
    (socket, request)
}

fn rest_reader(home: &Arc<ConnectorHome>, endpoint: &str) -> RestTransport {
    let mut config = RestConfig::new(endpoint);
    assert_eq!(config.request_timeout, Duration::from_secs(30));
    config.actions.insert(
        "read".into(),
        serde_json::from_value(json!({
            "method":"GET", "path":"/read", "args_schema":{"type":"object"}
        }))
        .unwrap(),
    );
    RestTransport::new(config).with_vendor_leg_gate(home.vendor_gate())
}

fn dispatch_read(transport: &dyn Transport) -> plexus_core::TransportResponse {
    transport.dispatch(
        TransportRequest {
            request_id: "lease-bound".into(),
            connection_id: "fixture".into(),
            action: "read".into(),
            args: json!({}),
            credential_fingerprint: String::new(),
        },
        &plexus_core::ResolvedCredential::anonymous(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn unsettled_yield_needs_another_fresh_notice() {
    let mut rig = Rig::new(100_000).await;
    let shared = samples("sharing-disabled");
    rig.notice(body(&shared[0], 0)).await;
    rig.decision(true).await;
    let mut handback = body(&samples("handback")[0], 0).clone();
    handback["gen"] = json!(1);
    rig.notice(&handback).await;
    let request = rig
        .unary(br#"{"method":"role.lease.yield","params":{"gen":1,"role":"connector_home"}}"#)
        .await;
    let mut renewal = body(&shared[0], 1).clone();
    renewal["seq"] = json!(4);
    rig.now.store(120_000, Ordering::SeqCst);
    rig.notice(&renewal).await;
    rig.reply(
        &request,
        FrameType::Error,
        &json!({"code":"outcome_unknown","message":"yield unsettled"}),
    )
    .await;
    let mut changes = rig.home.decisions();
    assert!(
        timeout(Duration::from_millis(100), changes.wait_for(|held| *held))
            .await
            .is_err()
    );
    assert_eq!(rig.home.health_status()["lease"]["yield_pending"], true);
    renewal["seq"] = json!(5);
    rig.notice(&renewal).await;
    rig.decision(true).await;
    rig.finish().await;
}
