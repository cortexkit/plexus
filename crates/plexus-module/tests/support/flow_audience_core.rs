use plexus_core::{github_identity::SubcPrefrontalRoutePeer, test_scratch::Scratch};
use plexus_module::{flow_audience::FlowAudiences, manifest, wire};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use subc_protocol::{
    session::ModuleControlResponse, Frame, FrameType, ModuleHelloBody, PROTOCOL_VERSION,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

#[path = "fixture_launcher.rs"]
mod fixture_launcher;

const LIMIT: Duration = Duration::from_secs(60);
/// Bound for `flow.audience` calls the fixture answers. Generous on purpose:
/// it only has to catch a fixture that never answers, and the call travels
/// through a daemon and a re-executed child that reads its answer from disk.
pub(super) const ANSWERED_CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Each daemon boot re-executes this test binary twice. Concurrent boots
/// contend for the machine enough that a daemon can drop a client connection
/// mid-request (tests/conformance.rs serializes its daemons for the same
/// reason), so the fixtures here start their daemons one at a time.
static DAEMON_BOOT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn atomic_json(path: &Path, value: &Value) {
    let temporary = path.with_extension("partial");
    fs::write(&temporary, serde_json::to_vec(value).unwrap()).unwrap();
    fs::rename(temporary, path).unwrap();
}

pub(super) struct Core {
    pub(super) scratch: Scratch,
    task: tokio::task::JoinHandle<Result<(), subc_daemon::bootstrap::BootstrapError>>,
    peer: Option<SubcPrefrontalRoutePeer>,
}
impl Drop for Core {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Core {
    pub(super) async fn new(reply: Value) -> Self {
        Self::with_call_timeout(reply, ANSWERED_CALL_TIMEOUT).await
    }
    pub(super) async fn with_call_timeout(reply: Value, call_timeout: Duration) -> Self {
        Self::with_module("prefrontal", reply, call_timeout).await
    }
    pub(super) async fn with_module(
        core_module: &str,
        reply: Value,
        call_timeout: Duration,
    ) -> Self {
        let _boot = DAEMON_BOOT.lock().await;
        let scratch = Scratch::directory("flow-audience-core");
        let connection = scratch.join("connection.json");
        let home = scratch.join("home");
        fs::create_dir_all(&home).unwrap();
        let built = Path::new(env!("CARGO_BIN_EXE_ckdev-plexus-test-launcher"));
        let launcher = fixture_launcher::launcher(built);
        let executable = cortexkit_test_support::ckdev_binary(std::env::current_exe().unwrap());
        let module = |id| {
            json!({"program":launcher,"args":["test",executable,"core_fixture::core_module_fixture"],"reserved":true,
            "env":{"HOME":home,"XDG_DATA_HOME":home,"AUDIENCE_FIXTURE_CONNECTION":connection,
            "AUDIENCE_FIXTURE_ROOT":scratch.path(),"AUDIENCE_FIXTURE_MODULE":id}})
        };
        let config_path = scratch.join("daemon.jsonc");
        atomic_json(
            &config_path,
            &json!({"version":1,"storage":{"backend":"sqlite","data_home":home},
            "modules":{(core_module):module(core_module),"plexus":module("plexus")}}),
        );
        atomic_json(&scratch.join("behavior.json"), &json!({"reply":reply}));
        let logs = scratch.join("logs");
        let config = fixture_launcher::daemon_config(&connection, built)
            .with_capture_logs_dir(&logs)
            .with_daemon_config_path(&config_path)
            .unwrap();
        let mut task = tokio::spawn(subc_daemon::bootstrap::run_with_config(config));
        let core_ready = scratch.join(format!("{core_module}.ready.json"));
        let plexus_ready = scratch.join("plexus.ready.json");
        let ready = async {
            loop {
                if core_ready.exists() {
                    if let Ok(bytes) = fs::read(&plexus_ready) {
                        break bytes;
                    }
                }
                sleep(Duration::from_millis(20)).await;
            }
        };
        let result = tokio::select! {
            result = &mut task => Err(format!("daemon stopped before fixture registration: {result:?}")),
            result = timeout(LIMIT, ready) => result.map_err(|_| format!(
                "registration did not finish within {LIMIT:?} ({core_module} ready: {}, plexus ready: {})",
                core_ready.exists(), plexus_ready.exists()
            )),
        };
        let credentials = result.unwrap_or_else(|cause| {
            task.abort();
            let output = |id| {
                fs::read_to_string(logs.join(format!("{id}.stderr.log")))
                    .unwrap_or_else(|error| format!("could not read captured output: {error}"))
            };
            panic!(
                "core fixture startup failed: {cause}\n{core_module} output:\n{}\nplexus output:\n{}",
                output(core_module),
                output("plexus")
            );
        });
        let peer = SubcPrefrontalRoutePeer::connect(
            &connection,
            "prefrontal",
            subc_protocol::BindIdentity::new("plexus", "module"),
        )
        .unwrap()
        .with_call_options(subc_client_rs::CallOptions {
            consumer_identity: Some(serde_json::from_slice(&credentials).unwrap()),
            ..Default::default()
        })
        .with_call_timeout(call_timeout);
        Self {
            scratch,
            task,
            peer: Some(peer),
        }
    }
    pub(super) fn audiences(&mut self) -> FlowAudiences {
        FlowAudiences::new(self.peer.take())
    }
    pub(super) fn behavior(&self, value: Value) {
        atomic_json(&self.scratch.join("behavior.json"), &value);
    }
    pub(super) fn calls(&self) -> Vec<Value> {
        serde_json::from_slice(
            &fs::read(self.scratch.join("calls.json")).unwrap_or_else(|_| b"[]".to_vec()),
        )
        .unwrap()
    }
}

async fn receive(stream: &mut TcpStream) -> Option<Frame> {
    timeout(LIMIT, read_frame(stream))
        .await
        .expect("fixture read deadline")
        .unwrap()
}
async fn respond(stream: &mut TcpStream, request: &Frame, kind: FrameType, value: &Value) {
    let response = Frame::build(
        kind,
        request.header.flags,
        request.header.channel,
        request.header.epoch,
        request.header.corr,
        serde_json::to_vec(value).unwrap(),
    )
    .unwrap();
    write_frame(stream, &response).await.unwrap();
}

#[tokio::test]
async fn core_module_fixture() {
    let Ok(path) = std::env::var("AUDIENCE_FIXTURE_CONNECTION") else {
        return;
    };
    let root = PathBuf::from(std::env::var("AUDIENCE_FIXTURE_ROOT").unwrap());
    let id = std::env::var("AUDIENCE_FIXTURE_MODULE").unwrap();
    let info = connection_file::read(Path::new(&path)).unwrap();
    let endpoint = &info.endpoints[0];
    let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .unwrap();
    authenticate_client(&mut stream, &info, Duration::from_secs(5))
        .await
        .unwrap();
    let nonce = subc_client_rs::launch_nonce()
        .expect("read core fixture launch nonce")
        .expect("core fixture did not receive a launch nonce")
        .value()
        .to_string();
    let mut module_manifest = manifest::build(&id);
    module_manifest.provides.retain(|role| {
        matches!(
            role,
            subc_protocol::manifest::ProviderRole::ManagementSurface { .. }
        )
    });
    if id != "plexus" {
        if let subc_protocol::manifest::ProviderRole::ManagementSurface { operations, .. } =
            &mut module_manifest.provides[0]
        {
            *operations = vec![subc_protocol::manifest::ManagementOperation {
                name: "flow.audience".into(),
                kind: subc_protocol::manifest::ManagementOperationKind::Query,
                description: None,
            }];
        }
    } else {
        module_manifest.provides.clear();
    }
    let hello = ModuleHelloBody {
        manifest: module_manifest,
        protocol_ver: PROTOCOL_VERSION,
        control_ops: Some(vec!["route.bind".into()]),
        launch_nonce: Some(nonce.clone()),
        module_capabilities: None,
        resume_token: None,
    };
    let frame = Frame::build(
        FrameType::Hello,
        wire::control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&hello).unwrap(),
    )
    .unwrap();
    write_frame(&mut stream, &frame).await.unwrap();
    let ack = receive(&mut stream)
        .await
        .expect("core fixture HELLO reply");
    assert_eq!(
        ack.header.ty,
        FrameType::HelloAck,
        "{id} HELLO rejected: {}",
        String::from_utf8_lossy(&ack.body)
    );
    atomic_json(
        &root.join(format!("{id}.ready.json")),
        &json!({"module_id":id,"launch_nonce":nonce}),
    );
    let mut calls = Vec::<Value>::new();
    let mut binds = Vec::<Value>::new();
    while let Some(frame) = receive(&mut stream).await {
        if frame.header.ty != FrameType::Request {
            continue;
        }
        let value: Value = serde_json::from_slice(&frame.body).unwrap();
        if frame.header.channel == 0 {
            binds.push(value);
            atomic_json(&root.join("binds.json"), &json!(binds));
            respond(
                &mut stream,
                &frame,
                FrameType::Response,
                &serde_json::to_value(ModuleControlResponse::RouteBindAck {}).unwrap(),
            )
            .await;
            continue;
        }
        assert_ne!(id, "plexus");
        assert_eq!(value["method"], "flow.audience");
        assert_eq!(value["params"].as_object().unwrap().len(), 1);
        calls.push(value);
        atomic_json(&root.join("calls.json"), &json!(calls));
        let behavior: Value =
            serde_json::from_slice(&fs::read(root.join("behavior.json")).unwrap()).unwrap();
        if behavior["timeout"] == true {
            continue;
        }
        respond(
            &mut stream,
            &frame,
            if behavior["error_frame"] == true {
                FrameType::Error
            } else {
                FrameType::Response
            },
            &behavior["reply"],
        )
        .await;
    }
}
