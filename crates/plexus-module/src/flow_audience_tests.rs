use super::*;
use plexus_core::{test_scratch::Scratch, MockTransport};
use std::{
    fs,
    path::{Path, PathBuf},
};
use subc_protocol::{session::ModuleControlResponse, ModuleHelloBody, PROTOCOL_VERSION};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

const LIMIT: Duration = Duration::from_secs(60);
/// Bound for `flow.audience` calls the fixture answers. Generous on purpose:
/// it only has to catch a fixture that never answers, and the call travels
/// through a daemon and a re-executed child that reads its answer from disk.
const ANSWERED_CALL_TIMEOUT: Duration = Duration::from_secs(10);
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

struct Core {
    scratch: Scratch,
    task: tokio::task::JoinHandle<Result<(), subc_daemon::bootstrap::BootstrapError>>,
    peer: Option<SubcPrefrontalRoutePeer>,
}
impl Drop for Core {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Core {
    async fn new(reply: Value) -> Self {
        Self::with_call_timeout(reply, ANSWERED_CALL_TIMEOUT).await
    }
    async fn with_call_timeout(reply: Value, call_timeout: Duration) -> Self {
        let _boot = DAEMON_BOOT.lock().await;
        let scratch = Scratch::directory("flow-audience-core");
        let connection = scratch.join("connection.json");
        let home = scratch.join("home");
        fs::create_dir_all(&home).unwrap();
        let executable = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .replace('\'', "'\"'\"'");
        let launcher = scratch.join("module.sh");
        fs::write(&launcher, format!("exec '{executable}' --exact flow_audience::tests::core_module_fixture --nocapture\n")).unwrap();
        let module = |id| {
            json!({"program":"/bin/sh","args":[launcher],"reserved":true,
            "env":{"HOME":home,"XDG_DATA_HOME":home,"AUDIENCE_FIXTURE_CONNECTION":connection,
            "AUDIENCE_FIXTURE_ROOT":scratch.path(),"AUDIENCE_FIXTURE_MODULE":id}})
        };
        let config_path = scratch.join("daemon.jsonc");
        atomic_json(
            &config_path,
            &json!({"version":1,"storage":{"backend":"sqlite","data_home":home},
            "modules":{"prefrontal-core":module("prefrontal-core"),"plexus":module("plexus")}}),
        );
        atomic_json(&scratch.join("behavior.json"), &json!({"reply":reply}));
        let config = subc_daemon::bootstrap::BootstrapConfig::new(&connection, 0)
            .with_capture_logs_dir(scratch.join("logs"))
            .with_daemon_config_path(&config_path)
            .unwrap();
        let task = tokio::spawn(subc_daemon::bootstrap::run_with_config(config));
        let credentials = timeout(LIMIT, async {
            loop {
                if scratch.join("prefrontal-core.ready.json").exists() {
                    if let Ok(bytes) = fs::read(scratch.join("plexus.ready.json")) {
                        break serde_json::from_slice::<Value>(&bytes).unwrap();
                    }
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("core fixture startup failed: {:?}", scratch.path()));
        let peer = SubcPrefrontalRoutePeer::connect(
            &connection,
            "prefrontal-core",
            subc_protocol::BindIdentity::new("/", "plexus", "module"),
        )
        .unwrap()
        .with_call_options(subc_client_rs::CallOptions {
            consumer_identity: Some(serde_json::from_value(credentials).unwrap()),
            ..Default::default()
        })
        .with_call_timeout(call_timeout);
        Self {
            scratch,
            task,
            peer: Some(peer),
        }
    }
    fn audiences(&mut self) -> FlowAudiences {
        FlowAudiences::new(self.peer.take())
    }
    fn behavior(&self, value: Value) {
        atomic_json(&self.scratch.join("behavior.json"), &value);
    }
    fn calls(&self) -> Vec<Value> {
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
        .unwrap()
        .unwrap()
        .value()
        .to_string();
    let mut module_manifest = manifest::build(&id);
    module_manifest.provides.retain(|role| {
        matches!(
            role,
            subc_protocol::manifest::ProviderRole::ManagementSurface { .. }
        )
    });
    if id == "prefrontal-core" {
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
    assert_eq!(
        receive(&mut stream).await.unwrap().header.ty,
        FrameType::HelloAck
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
        assert_eq!(id, "prefrontal-core");
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

fn global() -> Value {
    json!({"flow_id":"flow-a","audience":{"kind":"global"},"revision":"r1"})
}
fn workspace() -> Value {
    json!({"flow_id":"flow-a","audience":{"kind":"workspace","workspace_id":"ws-a","project_ids":["pj-a"]},"revision":"r1"})
}
fn scope(agent: Option<&str>) -> CallScope {
    CallScope {
        owner: "reserved:prefrontal-core".into(),
        scope_ref: "flow-a".into(),
        scope_epoch: 1,
        kind: Some("head".into()),
        parent: None,
        parent_state: None,
        agent_id: agent.map(str::to_owned),
        delegates: agent.is_some(),
        owner_authorized: true,
        flow_id: Some("flow-a".into()),
    }
}
fn call(state: &Arc<ModuleState>, name: &str, args: Value, stamp: Option<CallScope>) -> Value {
    let bindings = Arc::new(RouteBindings::new());
    bindings
        .insert_mode(
            1,
            1,
            Principal::Reserved {
                module_id: "basal".into(),
            },
            stamp,
            CallMode::Flow,
        )
        .unwrap();
    let frame = Frame::build(FrameType::Request, wire::control_flags(), 1, 1, 7, vec![]).unwrap();
    blocking_section(|| {
        facade_tool_reply(
            &frame,
            json!({"name":name,"arguments":args}).as_object().unwrap(),
            state,
            &bindings,
        )
    })
    .unwrap()
}
fn read_args(repository: &str) -> Value {
    json!({"action":"github.issue.get","repository":repository,"args":{"issue_number":42}})
}

fn setup(
    audiences: FlowAudiences,
) -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    let (mut state, store, transport, scratch) = crate::github_read_frame_tests::imported_runtime();
    Arc::get_mut(&mut state).unwrap().runtime.flow_audiences = audiences;
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "basal-read".into(),
            principal: "direct".into(),
            connection_id: "github-handle-app-x".into(),
            grantee_principal: "reserved:basal".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["github.issue.get".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    db.execute("INSERT INTO trigger_subscriptions (subscription_id,principal,connection_id,action,cadence_s,cursor_kind,cursor_state,fixed_args,schema_hash,status,created_at_ms,project_id,project_source)
        VALUES ('watch','direct','github-handle-app-x','list_issues',300,'ordered_timestamp','{}','{\"owner\":\"o\",\"repo\":\"x\"}','hash','active',1,'pj-a','entorhinal')", []).unwrap();
    (state, store, transport, scratch)
}
fn snapshot(path: &Path) -> Vec<i64> {
    let db = rusqlite::Connection::open(path).unwrap();
    [
        "reservations",
        "action_requests",
        "github_bot_receipt",
        "audit_journal",
    ]
    .iter()
    .map(|table| {
        db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    })
    .collect()
}
fn quiet_refusal(
    state: &Arc<ModuleState>,
    transport: &MockTransport,
    scratch: &Scratch,
    name: &str,
    args: Value,
    code: &str,
) -> Value {
    let before = snapshot(scratch.as_ref());
    let sent = transport.requests().len();
    let reply = call(state, name, args, Some(scope(None)));
    assert_eq!(
        reply["error"]["code"], code,
        "audience guard must refuse: {reply}"
    );
    assert_eq!(transport.requests().len(), sent, "refusal contacted vendor");
    assert_eq!(
        snapshot(scratch.as_ref()),
        before,
        "refusal reserved, parked, claimed a receipt or audited dispatch"
    );
    reply
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agentless_routes_require_core_before_dispatch() {
    let mut core =
        Core::new(json!({"error":{"code":"flow_unknown","message":"unknown flow"}})).await;
    let (state, _, transport, scratch) = setup(core.audiences());
    let reply = quiet_refusal(
        &state,
        &transport,
        &scratch,
        "github_read",
        read_args("o/x"),
        "flow_unknown",
    );
    assert_eq!(reply["error"]["transmission"], "not_sent");
    assert_eq!(
        core.calls(),
        vec![json!({"method":"flow.audience","params":{"flow_id":"flow-a"}})]
    );
    let binds: Value =
        serde_json::from_slice(&fs::read(core.scratch.join("binds.json")).unwrap()).unwrap();
    assert_eq!(
        binds[0]["principal"],
        json!({"kind":"reserved","module_id":"plexus"})
    );
    assert!(
        binds[0].get("scope").is_none_or(Value::is_null),
        "audience lookup must be unscoped: {binds}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_answers_never_become_global() {
    let mut core = Core::new(
        json!({"error":{"code":"flow_audience_unavailable","message":"workspace storage offline"}}),
    )
    .await;
    let (state, _, transport, scratch) = setup(core.audiences());
    let reply = quiet_refusal(
        &state,
        &transport,
        &scratch,
        "github_read",
        read_args("o/x"),
        "flow_audience_unavailable",
    );
    assert!(reply["error"]["cause"]
        .as_str()
        .unwrap()
        .contains("workspace storage offline"));
    assert_eq!(reply["error"]["transmission"], "not_sent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn named_refusals_malformed_and_timeout_fail_closed_without_side_effects() {
    let mut core = Core::new(global()).await;
    let (state, _, transport, scratch) = setup(core.audiences());
    for code in [
        "flow_unknown",
        "flow_not_approved",
        "flow_audience_conflict",
        "flow_audience_unavailable",
        "unexpected_error",
    ] {
        for error_frame in [true, false] {
            let refusal = json!({"code":code,"message":"core refusal","detail":{"versions":[1,2]}});
            core.behavior(json!({"reply":if error_frame { refusal.clone() } else { json!({"error":refusal}) },"error_frame":error_frame}));
            let expected = if code == "unexpected_error" {
                "flow_audience_unavailable"
            } else {
                code
            };
            let reply = quiet_refusal(
                &state,
                &transport,
                &scratch,
                "github_read",
                read_args("o/x"),
                expected,
            );
            assert_eq!(reply["error"]["transmission"], "not_sent");
            if code == "flow_audience_conflict" {
                assert_eq!(reply["error"]["detail"]["versions"], json!([1, 2]));
            }
        }
    }
    for reply in [
        Value::Null,
        json!({"error":"bad"}),
        json!({"flow_id":"other","audience":{"kind":"global"},"revision":"r"}),
        json!({"flow_id":"flow-a","audience":{"kind":"workspace","workspace_id":"ws","project_ids":[]},"revision":"r"}),
        json!({"flow_id":"flow-a","audience":{"kind":"unknown"},"revision":"r"}),
    ] {
        core.behavior(json!({"reply":reply}));
        quiet_refusal(
            &state,
            &transport,
            &scratch,
            "github_read",
            read_args("o/x"),
            "flow_audience_unavailable",
        );
    }
    // The timeout case gets its own core with a short call timeout. The fixture
    // never answers it, so the call waits out the whole bound, and the answered
    // calls above keep their generous one.
    let mut silent = Core::with_call_timeout(global(), Duration::from_millis(250)).await;
    silent.behavior(json!({"timeout":true}));
    let (state, _, transport, scratch) = setup(silent.audiences());
    let reply = quiet_refusal(
        &state,
        &transport,
        &scratch,
        "github_read",
        read_args("o/x"),
        "flow_audience_unavailable",
    );
    assert!(reply["error"]["cause"]
        .as_str()
        .unwrap()
        .contains("timed out"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_get_audience_refusals_have_retryable_policy() {
    let mut core = Core::new(global()).await;
    let (state, _, _, _scratch) = setup(core.audiences());
    let args = json!({"event_key":"a".repeat(64),"event_name":"github_issue_changed"});
    for (upstream, expected, retryable) in [
        ("flow_unknown", "flow_unknown", false),
        ("flow_not_approved", "flow_not_approved", false),
        ("flow_audience_conflict", "flow_audience_conflict", false),
        (
            "flow_audience_unavailable",
            "flow_audience_unavailable",
            true,
        ),
        ("unexpected_error", "flow_audience_unavailable", true),
    ] {
        for error_frame in [true, false] {
            let error =
                json!({"code":upstream,"message":"core refusal","detail":{"versions":[1,2]}});
            core.behavior(json!({"reply":if error_frame { error } else { json!({"error":error}) },"error_frame":error_frame}));
            let reply = call(&state, "events_get", args.clone(), Some(scope(None)));
            assert_eq!(reply["error"]["code"], expected, "{reply}");
            assert_eq!(reply["error"]["retryable"], retryable, "{reply}");
            assert_eq!(reply["error"]["transmission"], "not_sent");
            if upstream == "flow_audience_conflict" {
                assert_eq!(reply["error"]["detail"]["versions"], json!([1, 2]));
            }
        }
    }
    for malformed in [
        Value::Null,
        json!({"error":"bad"}),
        json!({"flow_id":"other","audience":{"kind":"global"},"revision":"r"}),
        json!({"flow_id":"flow-a","audience":{"kind":"unknown"},"revision":"r"}),
    ] {
        core.behavior(json!({"reply":malformed}));
        let reply = call(&state, "events_get", args.clone(), Some(scope(None)));
        assert_eq!(reply["error"]["code"], "flow_audience_unavailable");
        assert_eq!(reply["error"]["retryable"], true, "{reply}");
    }
    core.behavior(json!({"reply":{"flow_id":"flow-a","audience":{"kind":"agent","agent_id":"agent-a"},"revision":"r"}}));
    let reply = call(&state, "events_get", args.clone(), Some(scope(None)));
    assert_eq!(reply["error"]["code"], "flow_audience_mismatch");
    assert_eq!(reply["error"]["retryable"], false);

    let (state, _, _, _scratch) = setup(FlowAudiences::new(None));
    let reply = call(&state, "events_get", args, Some(scope(None)));
    assert_eq!(reply["error"]["code"], "flow_audience_unavailable");
    assert_eq!(reply["error"]["retryable"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_workspace_and_agent_audiences_preserve_their_authority() {
    for answer in [
        global(),
        workspace(),
        json!({"flow_id":"flow-a","audience":{"kind":"agent","agent_id":"agent-x"},"revision":"r"}),
    ] {
        let mut core = Core::new(answer.clone()).await;
        let (state, _, transport, scratch) = setup(core.audiences());
        if answer["audience"]["kind"] == "agent" {
            quiet_refusal(
                &state,
                &transport,
                &scratch,
                "github_read",
                read_args("o/x"),
                "flow_audience_mismatch",
            );
        } else {
            let reply = call(&state, "github_read", read_args("O/X"), Some(scope(None)));
            assert!(
                reply.get("result").is_some(),
                "inside-audience repository should dispatch: {reply}"
            );
            assert_eq!(transport.requests().len(), 1);
        }
        let before = core.calls().len();
        let agent_reply = call(
            &state,
            "github_read",
            read_args("o/x"),
            Some(scope(Some("agent-x"))),
        );
        // A call refused before routing would also leave the audience
        // unconsulted, so the count below means something only if it ran.
        assert!(
            agent_reply.get("result").is_some(),
            "agent-stamped call should dispatch: {agent_reply}"
        );
        assert_eq!(
            core.calls().len(),
            before,
            "agent-stamped calls must not consult audience"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_filter_covers_every_repository_operation_class() {
    let mut core = Core::new(workspace()).await;
    let (state, _, transport, scratch) = setup(core.audiences());
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    db.execute(
        "UPDATE trigger_subscriptions SET project_id='pj-outside'",
        [],
    )
    .unwrap();
    for (name, args) in [
        ("github_read", read_args("o/x")),
        (
            "github_read",
            json!({"action":"github.actions.job_log","repository":"o/x","args":{"job_id":1}}),
        ),
        (
            "github_read",
            json!({"action":"github.actions.run.superseded","repository":"o/x","args":{"run_id":1}}),
        ),
        (
            "github_read",
            json!({"action":"github.actions.artifact_file","repository":"o/x","args":{"run_id":1,"artifact_name":"x","path":"log.txt"}}),
        ),
        (
            "invoke",
            json!({"op":"call","connection":"github-handle-app-x","action":"github.issue.get","args":{"owner":"o","repo":"x","issue_number":42}}),
        ),
        (
            "invoke",
            json!({"op":"call","connection":"github-handle-app-x","action":"github.issue.get","args":{"repository":"o/x","issue_number":42}}),
        ),
        (
            "invoke",
            json!({"op":"call","connection":"github-handle-app-x","action":"github.issue.search","args":{"repositories":["o/x"]}}),
        ),
        (
            "github",
            json!({"op":"bot_request","request_nonce":"n","request":{"repository":"o/x","action":"issue create","body":{"title":"x"}}}),
        ),
        (
            "github_react",
            json!({"repository":"o/x","kind":"issue","target":{"number":42},"reaction":"eyes","request_nonce":"n"}),
        ),
    ] {
        let reply = quiet_refusal(
            &state,
            &transport,
            &scratch,
            name,
            args,
            "flow_audience_excludes_repository",
        );
        assert_eq!(reply["error"]["repository"], "o/x");
        assert!(
            !reply.to_string().contains("pj-a"),
            "refusal must not expose workspace projects"
        );
        assert_eq!(reply["error"]["transmission"], "not_sent");
    }
    for app in ["github", "github_actions", "github_rest"] {
        db.execute(
            "UPDATE connections SET app_key=?1 WHERE connection_id='github-handle-app-x'",
            [app],
        )
        .unwrap();
        quiet_refusal(
            &state,
            &transport,
            &scratch,
            "invoke",
            json!({"op":"call","connection":"github-handle-app-x","action":"read","args":{"owner":"o","repo":"x"}}),
            "flow_audience_excludes_repository",
        );
    }
    for repository in [
        Value::Null,
        json!([]),
        json!("bad"),
        json!({"owner":"o","repo":"x"}),
        json!(["o/x", 4]),
    ] {
        quiet_refusal(
            &state,
            &transport,
            &scratch,
            "github_read",
            json!({"action":"github.issue.get","repository":repository,"args":{}}),
            "flow_audience_excludes_repository",
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_audience_refuses_agent_binding_enumeration() {
    let mut core = Core::new(workspace()).await;
    let (state, _, transport, scratch) = setup(core.audiences());
    let reply = quiet_refusal(
        &state,
        &transport,
        &scratch,
        "github",
        json!({"op":"bindings.read_for_agent","agent_id":"agent-x"}),
        "flow_audience_excludes_repository",
    );
    assert_eq!(reply["error"]["repository"], "<unresolved>");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hand_set_missing_and_conflicting_stamps_do_not_establish_reach() {
    let mut core = Core::new(workspace()).await;
    let (state, _, transport, scratch) = setup(core.audiences());
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    db.execute("UPDATE trigger_subscriptions SET project_source='hand'", [])
        .unwrap();
    quiet_refusal(
        &state,
        &transport,
        &scratch,
        "github_read",
        read_args("o/x"),
        "flow_audience_excludes_repository",
    );
    db.execute(
        "UPDATE trigger_subscriptions SET project_id=NULL,project_source=NULL",
        [],
    )
    .unwrap();
    quiet_refusal(
        &state,
        &transport,
        &scratch,
        "github_read",
        read_args("o/x"),
        "flow_audience_excludes_repository",
    );
    db.execute(
        "UPDATE trigger_subscriptions SET project_id='pj-a',project_source='entorhinal'",
        [],
    )
    .unwrap();
    db.execute("INSERT INTO trigger_subscriptions (subscription_id,principal,connection_id,action,cadence_s,cursor_kind,cursor_state,fixed_args,schema_hash,status,created_at_ms,project_id,project_source)
        VALUES ('conflict','direct','github-handle-app-x','list_pull_requests',300,'ordered_timestamp','{}','{\"owner\":\"O\",\"repo\":\"X\"}','hash','active',1,'pj-b','entorhinal')", []).unwrap();
    quiet_refusal(
        &state,
        &transport,
        &scratch,
        "github_read",
        read_args("o/x"),
        "flow_audience_excludes_repository",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_expires_and_observes_a_new_revision_and_project_set() {
    let mut core = Core::new(workspace()).await;
    let audiences = core.audiences();
    assert_eq!(audiences.lookup("flow-a").unwrap().revision, "r1");
    let mut changed = workspace();
    changed["revision"] = json!("r2");
    changed["audience"]["project_ids"] = json!(["pj-b"]);
    core.behavior(json!({"reply":changed}));
    assert_eq!(audiences.lookup("flow-a").unwrap().revision, "r1");
    assert_eq!(core.calls().len(), 1);
    audiences.cache.lock().unwrap().get_mut("flow-a").unwrap().0 =
        Instant::now() - Duration::from_secs(31);
    let refreshed = audiences.lookup("flow-a").unwrap();
    assert_eq!(
        refreshed.revision, "r2",
        "expired audience must be refreshed"
    );
    assert_eq!(core.calls().len(), 2);
    assert_eq!(
        refreshed.audience,
        Audience::Workspace {
            workspace_id: "ws-a".into(),
            project_ids: vec!["pj-b".into()]
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_use_stored_repository_and_hide_excluded_event_existence() {
    let mut core = Core::new(workspace()).await;
    let (state, store, transport, scratch) = setup(core.audiences());
    let (key, _) = crate::events_get_tests::seed_test_events(scratch.as_ref(), &store);
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "basal-consume".into(),
            principal: "direct".into(),
            connection_id: "conn-github".into(),
            grantee_principal: "reserved:basal".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["list_issues".into()],
            authority_kind: "events_consume".into(),
            expires_at: None,
        })
        .unwrap();
    for version in [1, 2] {
        let excluded = quiet_refusal(
            &state,
            &transport,
            &scratch,
            "events_get",
            json!({"event_key":key,"event_name":"wrong-name","version":version}),
            "event_not_visible",
        );
        let unknown = quiet_refusal(
            &state,
            &transport,
            &scratch,
            "events_get",
            json!({"event_key":"f".repeat(64),"event_name":"wrong-name","version":version}),
            "event_not_visible",
        );
        assert_eq!(excluded["error"]["retryable"], false);
        assert_eq!(
            excluded, unknown,
            "excluded and unknown events must be indistinguishable"
        );
    }
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    db.execute("UPDATE trigger_subscriptions SET project_id='pj-a',project_source='entorhinal',fixed_args='{\"owner\":\"owner\",\"repo\":\"repo\"}' WHERE subscription_id='issue-sub-1'", []).unwrap();
    let reply = call(
        &state,
        "events_get",
        json!({"event_key":key,"event_name":"github_issue_changed"}),
        Some(scope(None)),
    );
    assert!(
        reply.get("result").is_some(),
        "stored event repo, not stale event project, establishes reach: {reply}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn would_ask_keeps_grant_semantics_but_checks_audience_once() {
    let mut core = Core::new(workspace()).await;
    let (state, _, transport, _) = setup(core.audiences());
    let request = json!({"method":"grants.would_ask","params":{"flow_id":"flow-a","items":[{"tool":"invoke","connection":"github-handle-app-x","action":"github.issue.get"}]}});
    let run = || {
        blocking_section(|| {
            grants_would_ask::run(
                &state,
                "reserved:basal",
                Some(&scope(None)),
                request.as_object().unwrap(),
            )
        })
    };
    let reply = run();
    assert_eq!(
        reply["result"]["items"][0]["verdict"], "yes",
        "workspace grants should remain installable: {reply}"
    );
    let actual = call(&state, "github_read", read_args("o/x"), Some(scope(None)));
    assert!(
        actual.get("result").is_some(),
        "would_ask must agree for an inside-audience repository: {actual}"
    );
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(core.calls().len(), 1);
    for code in [
        "flow_unknown",
        "flow_not_approved",
        "flow_audience_conflict",
        "flow_audience_unavailable",
        "flow_audience_mismatch",
    ] {
        state.runtime.flow_audiences.cache.lock().unwrap().clear();
        core.behavior(json!({"reply":if code == "flow_audience_mismatch" {
            json!({"flow_id":"flow-a","audience":{"kind":"agent","agent_id":"agent-x"},"revision":"r"})
        } else { json!({"error":{"code":code,"message":"no audience","versions":[1,2]}}) }}));
        let before = transport.requests().len();
        let reply = run();
        assert_eq!(reply["result"]["items"][0]["verdict"], "no");
        assert_eq!(reply["result"]["items"][0]["reason"], code);
        assert_eq!(transport.requests().len(), before);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_flow_audience_vectors_decode_through_plexus() {
    let records: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/flow-audience-v1/records.json"
    ))
    .unwrap();
    assert_eq!(records["version"], 1);
    let cases = records["cases"].as_array().expect("upstream cases array");
    assert_eq!(cases.len(), 9, "every published v1 case must be exercised");
    let mut core = Core::new(Value::Null).await;
    let audiences = core.audiences();
    let mut names = std::collections::BTreeSet::new();
    for case in cases {
        let name = case["name"].as_str().expect("vector name");
        assert!(names.insert(name), "duplicate upstream case: {name}");
        let flow_id = case["request"]["params"]["flow_id"]
            .as_str()
            .expect("requested flow_id");
        core.behavior(json!({"reply":case["reply"]}));
        audiences.cache.lock().unwrap().clear();
        let parsed = audiences.lookup(flow_id);
        let calls = core.calls();
        let sent = calls.last().expect("Plexus request recorded by core");
        assert_eq!(sent["method"], case["request"]["method"], "{name}");
        assert_eq!(sent["params"], json!({"flow_id":flow_id}), "{name}");
        if name == "unknown-field" {
            // This negative vector describes a malformed core request, not a
            // request Plexus sends. Never copy its extra field into the lookup.
            assert_eq!(
                case["request"]["params"],
                json!({"flow_id":flow_id,"extra":true})
            );
            assert_ne!(sent["params"], case["request"]["params"]);
        } else {
            assert_eq!(sent["params"], case["request"]["params"], "{name}");
        }
        // caller is the identity upstream used to produce the recorded reply.
        // caller-refused simulates Basal asking core directly; replaying that
        // reply never makes Plexus impersonate Basal. Our real lookup always
        // authenticates with Plexus's own verified identity.
        assert_eq!(
            case["caller"],
            if name == "caller-refused" {
                "reserved:basal"
            } else {
                "reserved:plexus"
            }
        );
        match name {
            "global" | "workspace" | "agent" => {
                let answer =
                    parsed.unwrap_or_else(|error| panic!("{name} vector must parse: {error}"));
                let expected = match name {
                    "global" => Audience::Global,
                    "workspace" => Audience::Workspace {
                        workspace_id: "ws-a".into(),
                        project_ids: vec!["project-a".into(), "project-b".into()],
                    },
                    "agent" => Audience::Agent {
                        agent_id: "ag_b".into(),
                    },
                    _ => unreachable!(),
                };
                assert_eq!(answer.audience, expected, "{name}");
                assert_eq!(answer.flow_id, flow_id, "{name}");
                assert_eq!(
                    answer.revision,
                    case["reply"]["result"]["revision"].as_str().unwrap(),
                    "{name}"
                );
            }
            "flow-unknown" | "flow-not-approved" | "flow-audience-conflict" => {
                let expected = match name {
                    "flow-unknown" => "flow_unknown",
                    "flow-not-approved" => "flow_not_approved",
                    "flow-audience-conflict" => "flow_audience_conflict",
                    _ => unreachable!(),
                };
                let refusal = parsed.unwrap_err();
                assert_eq!(refusal["error"]["code"], expected, "{name}");
                assert_eq!(
                    refusal["error"]["message"], case["reply"]["error"]["message"],
                    "{name}"
                );
                assert_eq!(refusal["error"]["transmission"], "not_sent", "{name}");
            }
            "membership-unavailable" | "caller-refused" | "unknown-field" => {
                let refusal = parsed.unwrap_err();
                assert_eq!(
                    refusal["error"]["code"], "flow_audience_unavailable",
                    "{name}"
                );
                assert_eq!(refusal["error"]["transmission"], "not_sent", "{name}");
                assert!(
                    refusal["error"]["cause"]
                        .as_str()
                        .unwrap()
                        .contains(case["reply"]["error"]["code"].as_str().unwrap()),
                    "{name}: {refusal}"
                );
            }
            _ => panic!("upstream case requires an explicit expectation: {name}"),
        }
    }
    assert_eq!(core.calls().len(), cases.len());
    let binds: Value =
        serde_json::from_slice(&fs::read(core.scratch.join("binds.json")).unwrap()).unwrap();
    for bind in binds.as_array().unwrap() {
        assert_eq!(
            bind["principal"],
            json!({"kind":"reserved","module_id":"plexus"})
        );
        assert!(bind.get("scope").is_none_or(Value::is_null));
    }
}

#[test]
fn malformed_audience_contracts_fail_closed() {
    let mut malformed = Vec::new();
    let mut other_flow = workspace();
    other_flow["flow_id"] = json!("another-flow");
    malformed.push(other_flow);
    let mut absent_revision = workspace();
    absent_revision.as_object_mut().unwrap().remove("revision");
    malformed.push(absent_revision);
    let mut empty_revision = workspace();
    empty_revision["revision"] = json!("");
    malformed.push(empty_revision);
    for projects in [
        json!([]),
        json!(["pj-b", "pj-a"]),
        json!(["pj-a", "pj-a"]),
        json!([""]),
        json!([null]),
        json!([12]),
    ] {
        let mut reply = workspace();
        reply["audience"]["project_ids"] = projects;
        malformed.push(reply);
    }
    for reply in malformed {
        let parsed = parse("flow-a", reply);
        assert!(parsed.is_err(), "invalid audience reply must fail closed");
        assert_eq!(
            parsed.unwrap_err()["error"]["code"],
            "flow_audience_unavailable",
            "invalid audience reply must fail closed"
        );
    }
    assert_eq!(
        FlowAudiences::new(None).lookup("flow-a").unwrap_err()["error"]["code"],
        "flow_audience_unavailable"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inside_audience_still_requires_basal_grant() {
    let mut core = Core::new(workspace()).await;
    let (state, _, transport, scratch) = setup(core.audiences());
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    db.execute("DELETE FROM grants WHERE grant_id='basal-read'", [])
        .unwrap();
    let before = snapshot(scratch.as_ref());
    let reply = call(&state, "github_read", read_args("o/x"), Some(scope(None)));
    assert_eq!(
        reply["error"]["code"], "module_grant_absent",
        "workspace membership must not replace Basal's own grant: {reply}"
    );
    assert_eq!(reply["error"]["detail"]["cause"], "missing");
    assert!(transport.requests().is_empty());
    assert_eq!(
        &snapshot(scratch.as_ref())[..3],
        &before[..3],
        "ungranted call must not reserve, park or claim a receipt"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_watch_projects_do_not_shadow_live_membership() {
    let mut core = Core::new(workspace()).await;
    let (state, _, transport, scratch) = setup(core.audiences());
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    db.execute("INSERT INTO trigger_subscriptions (subscription_id,principal,connection_id,action,cadence_s,cursor_kind,cursor_state,fixed_args,schema_hash,status,created_at_ms,project_id,project_source)
        VALUES ('old-watch','direct','github-handle-app-x','list_issues',300,'ordered_timestamp','{}','{\"owner\":\"O\",\"repo\":\"X\"}','hash','retired',1,'pj-old','entorhinal')", []).unwrap();
    for status in ["active", "suspended"] {
        db.execute(
            "UPDATE trigger_subscriptions SET status=?1 WHERE subscription_id='watch'",
            [status],
        )
        .unwrap();
        let reply = call(&state, "github_read", read_args("o/x"), Some(scope(None)));
        assert!(
            reply.get("result").is_some(),
            "retired watch must not shadow live project: {reply}"
        );
    }
    assert_eq!(transport.requests().len(), 2);
    db.execute("UPDATE trigger_subscriptions SET project_id=CASE subscription_id WHEN 'watch' THEN 'pj-outside' ELSE 'pj-a' END", []).unwrap();
    quiet_refusal(
        &state,
        &transport,
        &scratch,
        "github_read",
        read_args("o/x"),
        "flow_audience_excludes_repository",
    );
}

fn grant_search(store: &PlexusStore) {
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "basal-search".into(),
            principal: "direct".into(),
            connection_id: "github-handle-app-x".into(),
            grantee_principal: "reserved:basal".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["github.issue.search".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_invoke_free_text_queries_are_unresolved() {
    let mut core = Core::new(workspace()).await;
    let (state, store, transport, scratch) = setup(core.audiences());
    grant_search(&store);
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    // Model a discovered search schema accepting the query aliases, so a
    // missing audience fence cannot be hidden by a vendor-schema refusal.
    let schema = json!({"type":"object","properties":{"repositories":{"type":"array","items":{"type":"string"}}},"required":["repositories"],"additionalProperties":true});
    db.execute("UPDATE catalog_actions SET schema_json=?1,schema_hash=?2 WHERE principal='direct' AND connection_id='github-handle-app-x' AND name='github.issue.search'",
        [schema.to_string(), plexus_core::jcs_sha256(&schema).unwrap()]).unwrap();
    let safe = json!({"op":"call","connection":"github-handle-app-x","action":"github.issue.search","args":{"repositories":["o/x"]}});
    let reply = call(&state, "invoke", safe.clone(), Some(scope(None)));
    assert!(
        reply.get("result").is_some(),
        "query-free invoke must reach its granted transport: {reply}"
    );
    assert_eq!(transport.requests().len(), 1);
    for field in ["q", "query", "terms"] {
        for value in [
            json!("repo:other/secret"),
            Value::Null,
            json!({"text":"repo:other/secret"}),
        ] {
            let mut request = safe.clone();
            request["args"][field] = value;
            let reply = quiet_refusal(
                &state,
                &transport,
                &scratch,
                "invoke",
                request,
                "flow_audience_excludes_repository",
            );
            assert_eq!(reply["error"]["repository"], "<unresolved>");
            assert_eq!(reply["error"]["transmission"], "not_sent");
        }
    }
    for app in ["github", "github_rest", "github_actions"] {
        db.execute(
            "UPDATE connections SET app_key=?1 WHERE connection_id='github-handle-app-x'",
            [app],
        )
        .unwrap();
        for field in ["query", "q", "terms"] {
            let mut request = json!({"op":"call","connection":"github-handle-app-x","action":"search_issues","args":{"owner":"o","repo":"x"}});
            request["args"][field] = json!("repo:other/secret");
            let reply = quiet_refusal(
                &state,
                &transport,
                &scratch,
                "invoke",
                request,
                "flow_audience_excludes_repository",
            );
            assert_eq!(reply["error"]["repository"], "<unresolved>");
        }
    }
    let mut nested = safe;
    nested["args"]["options"] = json!([{"query":"repo:other/secret"}]);
    quiet_refusal(
        &state,
        &transport,
        &scratch,
        "invoke",
        nested,
        "flow_audience_excludes_repository",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_read_search_free_text_is_unresolved() {
    let mut core = Core::new(workspace()).await;
    let (state, store, transport, scratch) = setup(core.audiences());
    grant_search(&store);
    let safe = json!({"action":"github.issue.search","repository":["o/x"],"args":{}});
    let reply = call(&state, "github_read", safe.clone(), Some(scope(None)));
    assert!(
        reply.get("result").is_some(),
        "repository-only search must remain available: {reply}"
    );
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(transport.requests()[0].args["q"], "repo:o/x");
    for (field, value) in [
        ("terms", json!("fix")),
        ("terms", json!("repo:other/secret")),
        ("terms", json!("\"repo:other/secret\"")),
        ("q", json!("repo:other/secret")),
        ("query", json!("repo:other/secret")),
        ("terms", Value::Null),
    ] {
        let mut request = safe.clone();
        request["args"][field] = value;
        let reply = quiet_refusal(
            &state,
            &transport,
            &scratch,
            "github_read",
            request,
            "flow_audience_excludes_repository",
        );
        assert_eq!(reply["error"]["repository"], "<unresolved>");
        assert_eq!(reply["error"]["transmission"], "not_sent");
    }
}

#[test]
fn explicit_null_audience_is_malformed() {
    let reply = json!({"flow_id":"flow-a","audience":null,"revision":"r1"});
    for reply in [reply.clone(), json!({"result":reply})] {
        let refusal = parse("flow-a", reply).expect_err("explicit null audience must be malformed");
        assert_eq!(refusal["error"]["code"], "flow_audience_unavailable");
        assert_eq!(refusal["error"]["transmission"], "not_sent");
        assert!(refusal["error"]["cause"]
            .as_str()
            .unwrap()
            .contains("malformed reply"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opaque_project_ids_require_exact_watch_membership() {
    let mut answer = workspace();
    answer["audience"]["project_ids"] = json!(["project-a", "project-b"]);
    let mut core = Core::new(answer).await;
    let (state, _, transport, scratch) = setup(core.audiences());
    quiet_refusal(
        &state,
        &transport,
        &scratch,
        "github_read",
        read_args("o/x"),
        "flow_audience_excludes_repository",
    );
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    db.execute(
        "UPDATE trigger_subscriptions SET project_id='project-a'",
        [],
    )
    .unwrap();
    let reply = call(&state, "github_read", read_args("o/x"), Some(scope(None)));
    assert!(
        reply.get("result").is_some(),
        "opaque project ID must authorize its exact watch stamp: {reply}"
    );
    assert_eq!(transport.requests().len(), 1);
    db.execute(
        "UPDATE trigger_subscriptions SET project_id='project-ab'",
        [],
    )
    .unwrap();
    quiet_refusal(
        &state,
        &transport,
        &scratch,
        "github_read",
        read_args("o/x"),
        "flow_audience_excludes_repository",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_capacity_evicts_one_entry_instead_of_all_audiences() {
    let mut core = Core::new(workspace()).await;
    let audiences = core.audiences();
    let now = Instant::now();
    let answer = parse("flow-a", workspace()).unwrap();
    {
        let mut cache = audiences.cache.lock().unwrap();
        for index in 0..1024 {
            cache.insert(format!("cached-{index}"), (now, answer.clone(), now));
        }
        cache.get_mut("cached-0").unwrap().2 = now - Duration::from_secs(1);
    }
    assert_eq!(audiences.lookup("flow-a").unwrap().revision, "r1");
    let cache = audiences.cache.lock().unwrap();
    assert_eq!(cache.len(), 1024);
    assert!(!cache.contains_key("cached-0"));
    assert!(cache.contains_key("cached-1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_audience_misses_share_one_lookup() {
    let mut core = Core::new(workspace()).await;
    let audiences = Arc::new(core.audiences());
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let audiences = audiences.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            barrier.wait();
            audiences.lookup("flow-a").unwrap()
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().revision, "r1");
    }
    assert_eq!(core.calls().len(), 1);
}
