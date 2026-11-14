//! Compatibility probe for the published daemon using test-only module peers.

#[path = "support/daemon_client.rs"]
mod daemon_client;

use plexus_core::test_scratch::Scratch;
use serde_json::{json, Value};
use std::{fs, time::Duration};
use subc_protocol::{Frame, FrameType, PROTOCOL_VERSION};
use subc_transport::{connection_file, read_frame, write_frame};
use tokio::{net::TcpStream, time::timeout};

const OWNER: &str = "callosum";
const PROVIDER: &str = "protocol-probe";
const CONSENT: &str = "cingulate";

struct Daemon(tokio::task::JoinHandle<Result<(), subc_daemon::bootstrap::BootstrapError>>);

impl Drop for Daemon {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn receive(stream: &mut TcpStream) -> Frame {
    timeout(Duration::from_secs(10), read_frame(stream))
        .await
        .expect("probe reply deadline")
        .expect("read probe reply")
        .expect("probe connection remains open")
}

async fn request(stream: &mut TcpStream, corr: u64, body: Value) -> Value {
    let frame = Frame::build(
        FrameType::Request,
        plexus_module::wire::control_flags(),
        0,
        0,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    let reply = receive(stream).await;
    assert_eq!(reply.header.corr, corr);
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    serde_json::from_slice(&reply.body).unwrap()
}

async fn register(
    connection: &subc_transport::ConnectionInfo,
    module_id: &str,
    nonce: &str,
) -> TcpStream {
    let mut stream = daemon_client::connect_client(connection).await;
    let manifest = plexus_module::manifest::build(module_id);
    let hello = json!({
        "manifest": manifest,
        "protocol_ver": PROTOCOL_VERSION,
        "control_ops": ["route.bind"],
        "launch_nonce": nonce
    });
    let frame = Frame::build(
        FrameType::Hello,
        plexus_module::wire::control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&hello).unwrap(),
    )
    .unwrap();
    write_frame(&mut stream, &frame).await.unwrap();
    let reply = receive(&mut stream).await;
    assert_eq!(reply.header.ty, FrameType::HelloAck, "{:?}", reply.body);
    stream
}

async fn accept_bind(stream: &mut TcpStream) -> Value {
    let frame = receive(stream).await;
    let bind: Value = serde_json::from_slice(&frame.body).unwrap();
    assert_eq!(bind["op"], "route.bind");
    let ack = Frame::build(
        FrameType::Response,
        frame.header.flags,
        0,
        0,
        frame.header.corr,
        serde_json::to_vec(&json!({"op":"route.bind"})).unwrap(),
    )
    .unwrap();
    write_frame(stream, &ack).await.unwrap();
    bind
}

fn open(caller: &str, target: &str, nonce: &str, scope_ref: &str) -> Value {
    json!({
        "op":"route.open",
        "target":{"kind":"tool_provider","module_id":target},
        "identity":{"harness":"protocol-probe","session":"probe"},
        "consumer_identity":{"module_id":caller,"launch_nonce":nonce},
        "consumer_capabilities":["tool-result/v1","held-reply/v1"],
        "scope":{
            "owner":{"kind":"reserved","module_id":OWNER},
            "ref":scope_ref,"scope_epoch":1
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_daemon_supports_federated_scopes_stamps_carriers_and_describe() {
    let scratch = Scratch::directory("protocol-move-daemon");
    let connection_path = scratch.join("connection.json");
    let config_path = scratch.join("subc.jsonc");
    let mut modules = serde_json::Map::new();
    for module_id in [OWNER, PROVIDER, CONSENT] {
        // The supervised shell writes its descriptor-delivered launch nonce
        // to a file so this test can register the corresponding module double.
        // No production binary or operator data is used.
        let nonce_path = scratch.join(format!("{module_id}.nonce"));
        modules.insert(
            module_id.into(),
            json!({
                "program":"/bin/sh",
                "args":["-c", "dd status=none <&3 > \"$1\"; exec sleep 120", "probe", nonce_path],
                "reserved":true
            }),
        );
    }
    fs::write(
        &config_path,
        serde_json::to_vec(&json!({
            "version":1,
            "storage":{"backend":"sqlite","data_home":scratch.join("home")},
            "modules":modules
        }))
        .unwrap(),
    )
    .unwrap();
    let config = subc_daemon::bootstrap::BootstrapConfig::new(&connection_path, 0)
        .with_daemon_config_path(&config_path)
        .unwrap();
    let daemon = Daemon(tokio::spawn(subc_daemon::bootstrap::run_with_config(
        config,
    )));
    let (connection, nonces) = timeout(Duration::from_secs(10), async {
        loop {
            let nonces: Option<Vec<String>> = [OWNER, PROVIDER, CONSENT]
                .iter()
                .map(|id| {
                    fs::read_to_string(scratch.join(format!("{id}.nonce")))
                        .ok()
                        .filter(|s| !s.is_empty())
                })
                .collect();
            if let (Ok(connection), Some(nonces)) =
                (connection_file::read(&connection_path), nonces)
            {
                break (connection, nonces);
            }
            assert!(!daemon.0.is_finished(), "daemon stopped before publishing");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("daemon and supervised nonce publication");
    let mut owner = register(&connection, OWNER, &nonces[0]).await;
    let mut provider = register(&connection, PROVIDER, &nonces[1]).await;
    let mut consent = register(&connection, CONSENT, &nonces[2]).await;
    let mut owner_routes = daemon_client::connect_client(&connection).await;
    let mut provider_routes = daemon_client::connect_client(&connection).await;
    let sync = request(
        &mut owner,
        2,
        json!({"op":"scope.sync","generation":1,"scopes":[]}),
    )
    .await;
    assert_eq!(sync["generation"], 1);
    let scope_ref = format!("fed-base:{}:pair:1", "a".repeat(32));
    let apply = request(&mut owner, 3, json!({
        "op":"scope.apply","generation":2,"end":[],"upsert":[{
            "ref":scope_ref,"scope_epoch":1,"kind":"federated",
            "attributes":{"federated":{
                "peer_class":"computer","peer_fingerprint":"a".repeat(32),
                "pairing_id":"pair:1","peer_name":"Probe computer"
            }},
            "carriers":[{"principal":{"kind":"reserved","module_id":PROVIDER},"targets":[CONSENT]}]
        }]
    })).await;
    assert_eq!(apply["results"][0]["outcome"], "created", "{apply}");
    println!("apply reserved:callosum-owned federated scope: yes");
    let (opened, bind) = tokio::join!(
        request(
            &mut owner_routes,
            4,
            open(OWNER, PROVIDER, &nonces[0], &scope_ref)
        ),
        accept_bind(&mut provider)
    );
    assert_eq!(opened["op"], "route.open");
    assert_eq!(bind["scope"]["kind"], "federated");
    assert_eq!(bind["scope"]["owner"]["module_id"], OWNER);
    assert_eq!(bind["scope"]["owner_authorized"], false);
    assert_eq!(
        bind["consumer_capabilities"],
        json!(["tool-result/v1", "held-reply/v1"])
    );
    println!("stamp a declaring target, including held-reply bind member: yes");
    let (carried, bind) = tokio::join!(
        request(
            &mut provider_routes,
            5,
            open(PROVIDER, CONSENT, &nonces[1], &scope_ref)
        ),
        accept_bind(&mut consent)
    );
    assert_eq!(carried["op"], "route.open");
    assert_eq!(bind["principal"]["module_id"], PROVIDER);
    assert_eq!(bind["scope"]["ref"], scope_ref);
    println!("honour carrier to Cingulate stand-in: yes");
    let describe = request(
        &mut provider,
        6,
        json!({
            "op":"scope.describe","owner":{"kind":"reserved","module_id":OWNER},"ref":scope_ref
        }),
    )
    .await;
    assert_eq!(describe["status"], "live", "{describe}");
    assert_eq!(describe["owner_synced"], true);
    assert_eq!(describe["owner_configured"], true);
    println!("scope.describe fed-base ref: yes");
    daemon.0.abort();
}
