//! Held approvals and re-calls, tested over a real in-process subc daemon (the
//! fleet supervisor that routes calls between modules) and a fake Cingulate,
//! the consent module that shows approval cards. The fake records each route
//! the daemon binds and the exact request bytes plexus sends. It can answer
//! with response bytes copied from Cingulate's published test vectors
//! (tests/fixtures/cingulate-consent-requester/) without re-encoding them.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::shell::single_quoted;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::consent_card::*;
use plexus_core::scope::{CallScope, ScopeDescription, ScopeReadError, ScopeReader, ScopeStatus};
use plexus_core::test_scratch::Scratch;
use plexus_core::{
    AuthorizationRequest, CatalogActionInput, ConsentCards, Denial, GovernanceEngine, GrantInput,
    MockTransport, PlexusStore, StubCredentialSource, SubcPrefrontalRoutePeer,
};
use plexus_module::{manifest, wire};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subc_protocol::session::{ModuleControlRequestFromModule, ModuleControlResponse};
use subc_protocol::{Frame, FrameType, ModuleHelloBody, PROTOCOL_VERSION};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const CARRIER: &str = "reserved:broca";
const ACTION: &str = "post_message";
const FIXTURE_LIMIT: Duration = Duration::from_secs(60);

type Engine = GovernanceEngine<StubCredentialSource, MockTransport>;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cingulate-consent-requester/vectors")
}
fn head() -> CallScope {
    CallScope {
        owner: "reserved:prefrontal-core".into(),
        scope_ref: "head".into(),
        scope_epoch: 3,
        kind: Some("head".into()),
        parent: None,
        parent_state: None,
        agent_id: Some("agent".into()),
        delegates: true,
        owner_authorized: true,
        flow_id: None,
    }
}

fn atomic_json(path: &Path, value: &Value) {
    let temporary = path.with_extension("partial");
    fs::write(&temporary, serde_json::to_vec(value).unwrap()).unwrap();
    fs::rename(temporary, path).unwrap();
}

struct Daemon {
    scratch: Scratch,
    task: tokio::task::JoinHandle<Result<(), subc_daemon::bootstrap::BootstrapError>>,
    route: Arc<SubcPrefrontalRoutePeer>,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Daemon {
    async fn new() -> Self {
        let scratch = Scratch::directory("cingulate-requester");
        let connection = scratch.join("connection.json");
        let home = scratch.join("home");
        fs::create_dir_all(&home).unwrap();
        let executable = single_quoted(std::env::current_exe().unwrap());
        let launcher = scratch.join("module.sh");
        fs::write(&launcher, format!("exec {executable} --exact consent_requester::cingulate_module_fixture --nocapture\n")).unwrap();
        let module = |id: &str| {
            json!({"program":"/bin/sh", "args":[launcher], "reserved":true,
            "env":{"HOME":home, "XDG_DATA_HOME":home, "CONSENT_FIXTURE_CONNECTION":connection, "CONSENT_FIXTURE_ROOT":scratch.path(), "CONSENT_FIXTURE_MODULE":id}})
        };
        let config_path = scratch.join("daemon.jsonc");
        atomic_json(
            &config_path,
            &json!({"version":1, "storage":{"backend":"sqlite","data_home":home},
            "modules":{"cingulate":module("cingulate"), "prefrontal-core":module("prefrontal-core"), "plexus":module("plexus")}}),
        );
        atomic_json(&scratch.join("behavior.json"), &json!({"answer":"pending"}));
        let config = subc_daemon::bootstrap::BootstrapConfig::new(&connection, 0)
            .with_capture_logs_dir(scratch.join("logs"))
            .with_daemon_config_path(&config_path)
            .unwrap();
        let task = tokio::spawn(subc_daemon::bootstrap::run_with_config(config));
        let credentials = timeout(FIXTURE_LIMIT, async {
            loop {
                if scratch.join("cingulate.ready.json").exists()
                    && scratch.join("prefrontal-core.ready.json").exists()
                {
                    if let Ok(bytes) = fs::read(scratch.join("plexus.ready.json")) {
                        break serde_json::from_slice::<Value>(&bytes).unwrap();
                    }
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "fixture modules failed to start; logs at {:?}",
                scratch.path()
            )
        });
        let options = subc_client_rs::CallOptions {
            consumer_identity: Some(serde_json::from_value(credentials).unwrap()),
            ..Default::default()
        };
        let route = SubcPrefrontalRoutePeer::connect(
            &connection,
            "cingulate",
            subc_protocol::BindIdentity::new("/", "plexus", "module"),
        )
        .unwrap()
        .with_call_options(options);
        Self {
            scratch,
            task,
            route: Arc::new(route),
        }
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
    fn binds(&self) -> Vec<Value> {
        serde_json::from_slice(
            &fs::read(self.scratch.join("binds.json")).unwrap_or_else(|_| b"[]".to_vec()),
        )
        .unwrap()
    }
}

async fn frame_read(stream: &mut TcpStream) -> Option<Frame> {
    timeout(FIXTURE_LIMIT, read_frame(stream))
        .await
        .expect("fixture read bound")
        .unwrap()
}
async fn respond(stream: &mut TcpStream, request: &Frame, kind: FrameType, bytes: Vec<u8>) {
    let response = Frame::build(
        kind,
        request.header.flags,
        request.header.channel,
        request.header.epoch,
        request.header.corr,
        bytes,
    )
    .unwrap();
    timeout(FIXTURE_LIMIT, write_frame(stream, &response))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn cingulate_module_fixture() {
    let Ok(path) = std::env::var("CONSENT_FIXTURE_CONNECTION") else {
        return;
    };
    let root = PathBuf::from(std::env::var("CONSENT_FIXTURE_ROOT").unwrap());
    let id = std::env::var("CONSENT_FIXTURE_MODULE").unwrap();
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
    if id == "cingulate" {
        module_manifest.provides.retain(|role| {
            matches!(
                role,
                subc_protocol::manifest::ProviderRole::ManagementSurface { .. }
            )
        });
        if let subc_protocol::manifest::ProviderRole::ManagementSurface { operations, .. } =
            &mut module_manifest.provides[0]
        {
            *operations = [
                CONSENT_REQUEST,
                CONSENT_GET,
                CONSENT_AWAIT,
                CONSENT_DETACH,
                CONSENT_WITHDRAW,
                CONSENT_REPORT_EXECUTION,
            ]
            .into_iter()
            .map(|name| subc_protocol::manifest::ManagementOperation {
                name: name.into(),
                kind: subc_protocol::manifest::ManagementOperationKind::Mutate,
                description: None,
            })
            .collect();
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
    let ack = frame_read(&mut stream).await.unwrap();
    assert_eq!(
        ack.header.ty,
        FrameType::HelloAck,
        "{}",
        String::from_utf8_lossy(&ack.body)
    );
    if id == "prefrontal-core" {
        let request = ModuleControlRequestFromModule::ScopeSync { generation: 1, scopes: vec![
            serde_json::from_value(json!({"ref":"head","scope_epoch":3,"kind":"head","carriers":[{"principal":{"kind":"reserved","module_id":"plexus"},"targets":["cingulate"]}],"attributes":{"agent_id":"agent","delegates":true}})).unwrap(),
            serde_json::from_value(json!({"ref":"worker","scope_epoch":2,"kind":"worker","carriers":[{"principal":{"kind":"reserved","module_id":"plexus"},"targets":["cingulate"]}],"parent":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"ref":"head","scope_epoch":3}})).unwrap()
        ] };
        let frame = Frame::build(
            FrameType::Request,
            wire::control_flags(),
            0,
            0,
            1 << 32,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        write_frame(&mut stream, &frame).await.unwrap();
        let answer = frame_read(&mut stream).await.unwrap();
        assert_eq!(
            answer.header.ty,
            FrameType::Response,
            "{}",
            String::from_utf8_lossy(&answer.body)
        );
    }
    atomic_json(
        &root.join(format!("{id}.ready.json")),
        &json!({"module_id":id,"launch_nonce":nonce}),
    );
    let mut cards = HashMap::<String, Value>::new();
    let mut calls = Vec::new();
    let mut binds = Vec::<Value>::new();
    while let Some(frame) = frame_read(&mut stream).await {
        if frame.header.ty != FrameType::Request {
            continue;
        }
        if frame.header.channel == 0 {
            let bind: Value = serde_json::from_slice(&frame.body).unwrap();
            if id == "cingulate" {
                binds.push(bind);
                atomic_json(&root.join("binds.json"), &json!(binds));
            }
            respond(
                &mut stream,
                &frame,
                FrameType::Response,
                serde_json::to_vec(&ModuleControlResponse::RouteBindAck {}).unwrap(),
            )
            .await;
            continue;
        }
        assert_eq!(id, "cingulate");
        let request: Value = serde_json::from_slice(&frame.body).unwrap();
        calls.push(request.clone());
        atomic_json(&root.join("calls.json"), &json!(calls));
        let behavior: Value =
            serde_json::from_slice(&fs::read(root.join("behavior.json")).unwrap()).unwrap();
        if let Some(prefix) = behavior["vector"].as_str() {
            let expected = fs::read(fixtures().join(format!("{prefix}-request.json"))).unwrap();
            assert_eq!(frame.body, expected, "vector request bytes");
            let refusal = behavior["refusal"].as_bool().unwrap_or(false);
            let bytes = fs::read(fixtures().join(format!(
                "{prefix}-{}.json",
                if refusal { "refusal" } else { "reply" }
            )))
            .unwrap();
            respond(
                &mut stream,
                &frame,
                if refusal {
                    FrameType::Error
                } else {
                    FrameType::Response
                },
                bytes,
            )
            .await;
            continue;
        }
        let op = request["method"].as_str().unwrap();
        let params = &request["params"];
        if op == CONSENT_REQUEST {
            let allowed = [
                "kind",
                "title",
                "prompt",
                "options",
                "default",
                "urgency",
                "on_expiry",
                "material_damage",
                "late_execution",
                "target",
                "expires_in_ms",
                "dedup_key",
                "requester_ref",
                "args_digest",
                "preview",
                "facts",
            ];
            assert!(
                params
                    .as_object()
                    .unwrap()
                    .keys()
                    .all(|field| allowed.contains(&field.as_str())),
                "closed consent.request body: {params}"
            );
            assert_eq!(params["kind"], "consent");
            assert_eq!(params["on_expiry"], "deny");
            assert_eq!(params["default"], "deny");
            assert_eq!(params["options"][1]["effect"], "decline");
            let id = format!("el_{}", cards.len() + 1);
            let mut record = params.clone();
            record["elicitation_id"] = json!(id);
            record["state"] = json!("pending");
            cards.insert(id.clone(), record);
            respond(
                &mut stream,
                &frame,
                FrameType::Response,
                serde_json::to_vec(&json!({"result":{"elicitation_id":id}})).unwrap(),
            )
            .await;
            continue;
        }
        let id = params["elicitation_id"].as_str().unwrap();
        if behavior["missing"] == true && op == CONSENT_GET {
            respond(
                &mut stream,
                &frame,
                FrameType::Error,
                serde_json::to_vec(
                    &json!({"code":"elicitation_not_found","message":"not retained"}),
                )
                .unwrap(),
            )
            .await;
            continue;
        }
        let record = cards.get_mut(id).expect("owned card id");
        let answer = if op == CONSENT_DETACH {
            behavior["detach_answer"]
                .as_str()
                .or(behavior["answer"].as_str())
        } else {
            behavior["answer"].as_str()
        }
        .unwrap_or("pending");
        if record["state"] == "pending" {
            match answer {
                "approve" | "deny" => {
                    record["state"] = json!("answered");
                    record["answered_choice_id"] = json!(answer);
                }
                "expired" => record["state"] = json!("expired"),
                "withdrawn" => record["state"] = json!("withdrawn"),
                _ => {}
            }
        }
        if op == CONSENT_WITHDRAW && record["state"] == "pending" {
            record["state"] = json!("withdrawn");
        }
        if op == CONSENT_REPORT_EXECUTION {
            record["execution"] = params["execution"].clone();
        }
        if op == CONSENT_AWAIT && record["state"] == "pending" {
            sleep(Duration::from_millis(
                params["timeout_ms"].as_u64().unwrap(),
            ))
            .await;
        }
        let mut reply = record.clone();
        if op == CONSENT_DETACH && reply["state"] == "pending" {
            reply["detached"] = json!(true);
        }
        respond(
            &mut stream,
            &frame,
            FrameType::Response,
            serde_json::to_vec(&json!({"result":reply})).unwrap(),
        )
        .await;
    }
}

struct Scopes(Mutex<CallScope>);
impl ScopeReader for Scopes {
    fn describe(&self, _: &str, _: &str) -> Result<ScopeDescription, ScopeReadError> {
        let scope = self.0.lock().unwrap().clone();
        Ok(ScopeDescription {
            status: ScopeStatus::Live,
            owner_synced: true,
            owner_configured: true,
            live: Some(scope),
        })
    }
}
struct Fixture {
    daemon: Daemon,
    database: Scratch,
    engine: Engine,
    scopes: Arc<Scopes>,
}
impl Fixture {
    async fn new() -> Self {
        let daemon = Daemon::new().await;
        let database = Scratch::database("consent-held-call");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "consent".into(),
                isolation: Isolation::Module,
                backend: StorageBackend::Sqlite {
                    path: database.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        store
            .insert_connection(
                "direct",
                "conn",
                "mock",
                "pending",
                &json!({"required":[],"optional":[],"write_enabling":["text"]}),
            )
            .unwrap();
        let schema = json!({"type":"object"});
        let handle = b"test:consent-cards-handle";
        let ticket = store
            .create_binding_ticket("direct", "conn", handle)
            .unwrap();
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .unwrap()
            .unwrap();
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "conn".into(),
                principal: "direct".into(),
                name: ACTION.into(),
                title: Some("Post a message".into()),
                schema: schema.clone(),
                schema_hash: plexus_core::jcs_sha256(&schema).unwrap(),
                risk: "write".into(),
                severity: "S1".into(),
                ask_first: true,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
        for (id, grantee, kind) in [
            ("module", CARRIER, "invoke"),
            ("agent", CARRIER, "invoke"),
            ("admin", "direct", "connection_admin"),
        ] {
            store
                .insert_grant(&GrantInput {
                    grant_id: id.into(),
                    principal: "direct".into(),
                    connection_id: "conn".into(),
                    grantee_principal: grantee.into(),
                    risk_ceiling: "write".into(),
                    action_selectors: vec![ACTION.into()],
                    authority_kind: kind.into(),
                    expires_at: None,
                })
                .unwrap();
        }
        let sql = rusqlite::Connection::open(database.path()).unwrap();
        sql.execute(
            "UPDATE grants SET agent_id='agent' WHERE grant_id='agent'",
            [],
        )
        .unwrap();
        let reviewed = plexus_core::ingest_value(json!({
            "schema_version":1,"key":"mock","name":"Mock Chat","description":"Consent requester fixture",
            "reuse_path":"mcp_direct","reuse_rationale":"Test fixture","tier":"S1",
            "transport":{"kind":"mcp_remote","url":"https://example.invalid/mcp"},
            "auth":{"mode":"none"},"credential_bindings":[],
            "resource_filters":{"required":[],"optional":[],"write_enabling":[]},
            "actions_baseline":[{"name":ACTION,"risk":"write","ask_first":true,"input_schema":schema}],
            "defaults":{"ask_first_risk":["write","destructive"],"rate_limit":{"calls_per_min":30}},
            "availability":"ga"
        })).unwrap();
        store.upsert_manifest("system", &reviewed).unwrap();
        let scopes = Arc::new(Scopes(Mutex::new(head())));
        let credentials = StubCredentialSource::default();
        credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
        let engine = GovernanceEngine::new(
            store,
            Arc::new(credentials),
            Arc::new(MockTransport::default()),
        )
        .with_scope_reader(scopes.clone())
        .with_consent_cards(Arc::new(ConsentCards::new(daemon.route.clone())));
        Self {
            daemon,
            database,
            engine,
            scopes,
        }
    }
    fn request(&self, key: &str, text: &str) -> AuthorizationRequest {
        AuthorizationRequest::new(CARRIER, "conn", ACTION, json!({"text":text}))
            .with_scope(head())
            .with_call_key(key)
    }
    fn call(&self, key: &str, text: &str) -> Result<plexus_core::DispatchOutcome, Denial> {
        self.engine.invoke_held(
            self.request(key, text),
            Instant::now() + CONTROL_RPC_TIMEOUT,
        )
    }
    fn rows(&self) -> Vec<plexus_core::ActionRequestRecord> {
        self.engine.store().list_action_requests("direct").unwrap()
    }
    fn sent(&self) -> usize {
        self.engine.transport().requests().len()
    }
    fn ops(&self, op: &str) -> Vec<Value> {
        self.daemon
            .calls()
            .into_iter()
            .filter(|call| call["method"] == op)
            .map(|call| call["params"].clone())
            .collect()
    }
    fn park(&self) -> String {
        match self.call("original", "hello") {
            Err(Denial::AccessPending { elicitation_id, .. }) => elicitation_id,
            other => panic!("must detach pending: {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn files_redacted_scoped_card_with_requester_ref_and_carrier_dedup_key() {
    let f = Fixture::new().await;
    let mut request = f.request("original", "hello");
    let token = format!("ghp_{}", "Z".repeat(36));
    request.args["note"] = json!(token);
    let held = f.engine.authorize(request);
    assert!(
        matches!(held, Err(Denial::ActionRequestCreated { .. })),
        "{held:?}"
    );
    let body = &f.ops(CONSENT_REQUEST)[0];
    let row = &f.rows()[0];
    assert_eq!(body["requester_ref"], row.request_id);
    assert_eq!(body["dedup_key"], format!("{CARRIER}:original"));
    assert_eq!(body["preview"]["text"], "note: [withheld]\ntext: hello");
    assert!(!body.to_string().contains(&token));
    for field in [
        "subject",
        "agent_id",
        "principal",
        "owner",
        "requester",
        "session_ref",
        "parent_session_ref",
    ] {
        assert!(body.get(field).is_none(), "identity field {field}");
    }
    assert!(row.elicitation_id.is_some());
    let binds = f.daemon.binds();
    let bind = &binds[0];
    assert_eq!(
        bind["principal"],
        json!({"kind":"reserved","module_id":"plexus"})
    );
    assert_eq!(
        bind["scope"]["owner"],
        json!({"kind":"reserved","module_id":"prefrontal-core"})
    );
    assert_eq!(bind["scope"]["ref"], "head");
    assert_eq!(bind["scope"]["scope_epoch"], 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deny_sends_nothing() {
    let f = Fixture::new().await;
    f.daemon.behavior(json!({"answer":"deny"}));
    let reply = f.call("original", "hello");
    assert!(
        matches!(
            reply,
            Err(Denial::ConsentRefused {
                code: "consent_denied",
                ..
            })
        ),
        "{reply:?}"
    );
    assert_eq!(f.sent(), 0);
    assert!(f.ops(CONSENT_REPORT_EXECUTION).is_empty());
    assert_eq!(f.rows()[0].status, "denied");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_sends_nothing() {
    let f = Fixture::new().await;
    f.daemon.behavior(json!({"answer":"expired"}));
    let reply = f.call("original", "hello");
    assert!(
        matches!(
            reply,
            Err(Denial::ConsentRefused {
                code: "consent_expired",
                ..
            })
        ),
        "{reply:?}"
    );
    assert_eq!(f.sent(), 0);
    assert!(f.ops(CONSENT_REPORT_EXECUTION).is_empty());
    assert_eq!(f.rows()[0].status, "expired");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settled_detach_executes_in_the_held_call() {
    let f = Fixture::new().await;
    f.daemon
        .behavior(json!({"answer":"pending", "detach_answer":"approve"}));
    assert!(f.call("original", "hello").is_ok());
    assert_eq!(f.sent(), 1);
    assert_eq!(f.rows()[0].status, "consumed");
    assert_eq!(f.ops(CONSENT_DETACH).len(), 1);
    assert_eq!(f.ops(CONSENT_REPORT_EXECUTION)[0]["execution"], "executed");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unscoped_caller_parks_nothing() {
    let f = Fixture::new().await;
    let request = AuthorizationRequest::new(CARRIER, "conn", ACTION, json!({"text":"hello"}))
        .with_attributed_agent("agent")
        .with_call_key("unscoped");
    let reply = f
        .engine
        .invoke_held(request, Instant::now() + CONTROL_RPC_TIMEOUT);
    assert!(
        matches!(reply, Err(Denial::ConsentUnavailable { .. })),
        "{reply:?}"
    );
    assert!(f.rows().is_empty());
    assert!(f.daemon.calls().is_empty());
    assert_eq!(f.sent(), 0);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_recall_never_dispatches_again() {
    let f = Fixture::new().await;
    let id = f.park();
    assert_eq!(f.sent(), 0);
    f.daemon.behavior(json!({"answer":"approve"}));
    assert!(f.call("recall-1", "hello").is_ok());
    assert_eq!(f.sent(), 1);
    assert_eq!(f.ops(CONSENT_GET)[0]["elicitation_id"], id);
    assert!(matches!(
        f.call("recall-2", "hello"),
        Err(Denial::Policy(plexus_core::PolicyDenial::ApprovalConsumed))
    ));
    assert_eq!(f.sent(), 1);
    assert_eq!(f.ops(CONSENT_REQUEST).len(), 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn different_arguments_with_a_new_key_file_a_fresh_card() {
    let f = Fixture::new().await;
    let id = f.park();
    f.daemon.behavior(json!({"answer":"approve"}));
    let reply = f.call("changed", "different");
    assert!(reply.is_ok(), "{reply:?}");
    assert_eq!(f.ops(CONSENT_REQUEST).len(), 2);
    assert!(f.ops(CONSENT_GET).is_empty());
    assert_ne!(
        f.rows()[0].elicitation_id.as_deref(),
        f.rows()[1].elicitation_id.as_deref()
    );
    assert_eq!(f.sent(), 1);
    assert_eq!(
        f.engine.transport().requests()[0].args,
        json!({"text":"different"})
    );
    assert_eq!(
        f.rows()
            .iter()
            .find(|row| row.call_key.as_deref() == Some("original"))
            .unwrap()
            .elicitation_id
            .as_deref(),
        Some(id.as_str())
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_recall_resumes_wait_and_can_be_withdrawn_by_its_new_key() {
    let f = Fixture::new().await;
    let id = f.park();
    let request = f.request("recall", "hello");
    let reply = f.engine.invoke_held(
        request,
        Instant::now() + CONTROL_RPC_TIMEOUT + Duration::from_millis(30),
    );
    assert!(
        matches!(reply, Err(Denial::AccessPending { .. })),
        "{reply:?}"
    );
    assert_eq!(f.ops(CONSENT_AWAIT).len(), 1);
    assert_eq!(f.ops(CONSENT_DETACH).len(), 2);
    assert_eq!(f.ops(CONSENT_REQUEST).len(), 1);
    let scope = head();
    let answer = f
        .engine
        .withdraw_call(&plexus_core::withdraw::WithdrawCall {
            caller: CARRIER,
            carrier: None,
            call_key: "recall",
            scope: Some(&scope),
        });
    assert!(
        matches!(answer, Ok(plexus_core::withdraw::WithdrawAnswer::Withdrawn)),
        "{answer:?}"
    );
    assert_eq!(f.ops(CONSENT_WITHDRAW)[0]["elicitation_id"], id);
    let reply = f.call("after-withdraw", "hello");
    assert!(
        matches!(
            reply,
            Err(Denial::ConsentRefused {
                code: "consent_withdrawn",
                ..
            })
        ),
        "{reply:?}"
    );
    assert_eq!(f.sent(), 0);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recall_deny_expiry_and_withdrawal_are_named_and_unsent() {
    for (answer, code) in [
        ("deny", "consent_denied"),
        ("expired", "consent_expired"),
        ("withdrawn", "consent_withdrawn"),
    ] {
        let f = Fixture::new().await;
        f.park();
        f.daemon.behavior(json!({"answer":answer}));
        let reply = f.call("recall", "hello");
        assert!(
            matches!(reply,Err(Denial::ConsentRefused { code:actual, .. }) if actual==code),
            "{reply:?}"
        );
        assert_eq!(f.sent(), 0);
        assert_eq!(f.ops(CONSENT_REQUEST).len(), 1);
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_card_files_a_fresh_card() {
    let f = Fixture::new().await;
    f.park();
    f.daemon
        .behavior(json!({"missing":true,"answer":"pending"}));
    assert!(matches!(
        f.call("recall", "hello"),
        Err(Denial::AccessPending { .. })
    ));
    assert_eq!(f.ops(CONSENT_REQUEST).len(), 2);
    assert_eq!(f.sent(), 0);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grant_and_scope_rechecks_refuse_and_report_approved_not_executed() {
    for revoked in [true, false] {
        let f = Fixture::new().await;
        f.park();
        f.daemon.behavior(json!({"answer":"approve"}));
        if revoked {
            rusqlite::Connection::open(f.database.path())
                .unwrap()
                .execute("DELETE FROM grants WHERE grant_id='module'", [])
                .unwrap();
        } else {
            f.scopes.0.lock().unwrap().scope_epoch = 4;
        }
        let reply = f.call("recall", "hello");
        if revoked {
            assert!(reply.is_err(), "revoked grant: {reply:?}");
        } else {
            assert!(
                matches!(reply, Ok(plexus_core::DispatchOutcome { outcome: plexus_core::TransportOutcome::NotSent { ref code, .. }, .. }) if code == "scope_ended"),
                "ended scope: {reply:?}"
            );
        }
        assert_eq!(f.sent(), 0);
        assert_eq!(
            f.ops(CONSENT_REPORT_EXECUTION)[0]["execution"],
            "approved_not_executed"
        );
    }
}

#[test]
fn all_vendored_cingulate_bytes_match_the_pinned_checksums() {
    let mut checked = 0;
    for directory in [
        "consent-requester-v1",
        "consent-requester-v2",
        "consent-late-answer-v1",
    ] {
        let root = fixtures().join(directory);
        for row in fs::read_to_string(root.join("SHA256SUMS")).unwrap().lines() {
            let (expected, file) = row.split_once("  ").unwrap();
            let bytes = fs::read(root.join(file)).unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(bytes)),
                expected,
                "{directory}/{file}"
            );
            checked += 1;
        }
    }
    assert!(checked > 90, "checked {checked} fixture files");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_adapter_preserves_vendored_request_reply_and_refusal_bytes() {
    let daemon = Daemon::new().await;
    for (prefix, refused) in [
        ("consent-requester-v2/plexus", false),
        ("consent-requester-v2/plexus-non-consent", true),
        ("consent-requester-v1/report-execution", false),
        ("consent-requester-v1/withdraw", false),
        ("consent-requester-v2/cerebellum-ref", false),
        ("consent-requester-v2/cerebellum-ref-get", false),
        ("consent-requester-v2/cerebellum-ref-await", false),
        ("consent-requester-v2/cerebellum-detach-pending", false),
        ("consent-requester-v2/cerebellum-detach-settled", false),
        ("consent-requester-v2/cerebellum-detach-wrong-owner", true),
    ] {
        daemon.behavior(json!({"vector":prefix,"refusal":refused}));
        let request: Value = serde_json::from_slice(
            &fs::read(fixtures().join(format!("{prefix}-request.json"))).unwrap(),
        )
        .unwrap();
        let reply = daemon.route.call_scoped(
            &head(),
            request["method"].as_str().unwrap(),
            request["params"].clone(),
            CONTROL_RPC_TIMEOUT,
        );
        let expected = fs::read(fixtures().join(format!(
            "{prefix}-{}.json",
            if refused { "refusal" } else { "reply" }
        )))
        .unwrap();
        if refused {
            let parsed: Value = serde_json::from_slice(&expected).unwrap();
            assert!(
                matches!(reply,Err(ElicitationCallError::Refused {code,message}) if code==parsed["code"] && message==parsed["message"])
            );
        } else {
            assert_eq!(
                serde_json::to_vec(&json!({"result":reply.unwrap()})).unwrap(),
                expected,
                "{prefix} reply bytes"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outcome_unknown_is_reported_and_the_approval_stays_single_use() {
    let f = Fixture::new().await;
    f.engine
        .transport()
        .set_response(plexus_core::MockResponse::OutcomeUnknown);
    f.daemon.behavior(json!({"answer":"approve"}));
    let reply = f.call("original", "hello").unwrap();
    assert!(matches!(
        reply.outcome,
        plexus_core::TransportOutcome::OutcomeUnknown
    ));
    assert_eq!(
        f.ops(CONSENT_REPORT_EXECUTION)[0]["execution"],
        "outcome_unknown"
    );
    assert!(matches!(
        f.call("recall", "hello"),
        Err(Denial::Policy(plexus_core::PolicyDenial::ApprovalConsumed))
    ));
    assert_eq!(f.sent(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_without_agent_uses_its_own_attested_scope_and_unkeyed_dedup_falls_back_to_row_id() {
    let f = Fixture::new().await;
    let mut worker = head();
    worker.scope_ref = "worker".into();
    worker.scope_epoch = 2;
    worker.kind = Some("worker".into());
    worker.parent = Some("reserved:prefrontal-core/head@3".into());
    worker.parent_state = Some("linked".into());
    worker.agent_id = None;
    worker.delegates = false;
    let request =
        AuthorizationRequest::new(CARRIER, "conn", ACTION, json!({"text":"worker message"}))
            .with_scope(worker);
    assert!(matches!(
        f.engine
            .invoke_held(request, Instant::now() + CONTROL_RPC_TIMEOUT),
        Err(Denial::AccessPending { .. })
    ));
    let row = &f.rows()[0];
    let body = &f.ops(CONSENT_REQUEST)[0];
    assert_eq!(body["dedup_key"], row.request_id);
    assert_eq!(body["requester_ref"], row.request_id);
    let bind = &f.daemon.binds()[0];
    assert_eq!(bind["scope"]["ref"], "worker");
    assert_eq!(bind["scope"]["scope_epoch"], 2);
    assert!(bind["scope"]["attributes"].get("agent_id").is_none());
    assert_eq!(bind["scope"]["parent"]["ref"], "head");
    assert_eq!(f.sent(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changed_arguments_under_the_same_key_remain_refused() {
    let f = Fixture::new().await;
    f.park();
    f.daemon.behavior(json!({"answer":"approve"}));
    assert!(matches!(
        f.call("original", "different"),
        Err(Denial::Policy(plexus_core::PolicyDenial::CallKeyReused))
    ));
    assert_eq!(f.sent(), 0);
    assert_eq!(f.ops(CONSENT_REQUEST).len(), 1);
    assert!(f.ops(CONSENT_GET).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_answer_does_not_execute_until_the_agent_recalls() {
    let f = Fixture::new().await;
    f.park();
    f.daemon.behavior(json!({"answer":"approve"}));
    assert_eq!(f.engine.retry_waiting_approvals(100), 0);
    assert_eq!(f.sent(), 0);
    assert!(f.ops(CONSENT_GET).is_empty());
    assert_eq!(f.rows()[0].status, "pending");
    assert!(f.call("recall", "hello").is_ok());
    assert_eq!(f.sent(), 1);
}
