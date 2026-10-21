//! Tests Plexus's `scope.describe` reader, `DaemonScopeReader`, against a
//! real subc daemon instead of a stub.
//!
//! The daemon runs in-process and supervises two fixture modules launched from
//! this test binary: `test-scope-owner`, which registers scopes with
//! `scope.sync`, and `test-scope-idle`, which is in the roster but never syncs.
//! This test then connects as a third, unsupervised module and asks the
//! daemon about those scopes through `DaemonScopeReader`, the reader the
//! engine uses before a stored approval runs, before each GitHub bot write
//! step, and for `tool.withdraw`.
//!
//! Each answer is checked three ways: the description the reader decoded; the
//! same reply decoded straight from the raw bytes with subc-protocol, so a
//! field the reader drops or misreads shows up; and what Plexus's two scope
//! checks decide from it. `recheck_call_scope` decides whether a running call
//! may still send a write under the scope its route was bound to, and
//! `approval_scope_verdict` decides whether a stored approval runs, is
//! refused, or waits.

#![cfg(test)]

#[path = "support/bounded.rs"]
mod bounded;
#[path = "support/daemon_client.rs"]
mod daemon_client;
#[path = "support/shell.rs"]
mod shell;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use daemon_client::connect_client;
use plexus_core::scope::{
    approval_scope_verdict, recheck_call_scope, ApprovalScope, ApprovalScopeVerdict, CallScope,
    ScopeDescription, ScopeReader, ScopeStatus, SCOPE_ENDED, SCOPE_NOT_SYNCED, SCOPE_UNVERIFIABLE,
};
use plexus_core::test_scratch::Scratch;
use plexus_module::scope_reader::{DaemonScopeReader, PendingControlReplies};
use plexus_module::{manifest, wire};
use serde_json::{json, Value};
use shell::single_quoted;
use subc_protocol::session::{ModuleControlRequestFromModule, ModuleControlResponseToModule};
use subc_protocol::{Frame, FrameType, ModuleHelloAckBody, PROTOCOL_VERSION};
use subc_transport::{connection_file, read_frame, write_frame};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

const OWNER: &str = "test-scope-owner";
const IDLE_OWNER: &str = "test-scope-idle";
const READER: &str = "plexus-scope-reader";

/// How long to wait for the `test-scope-owner` fixture to write its sync
/// replies. Generous on purpose: the bound only has to catch a fixture that
/// will never finish, and a tight one would fail on a loaded machine instead.
const FIXTURE_DEADLINE: Duration = Duration::from_secs(60);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plexus_reads_live_ended_unknown_and_unsynced_scopes_from_a_real_daemon() {
    let daemon = start_daemon().await;

    // The owner's own view of what it did: session-a and session-b created,
    // then session-b ended by leaving it out of the second sync.
    let syncs = wait_for_owner_results(&daemon.results_path).await;
    let first = &syncs[0]["ok"];
    assert_eq!(first["generation"], 1, "{syncs:?}");
    let outcomes = first["results"]
        .as_array()
        .expect("per-record results")
        .iter()
        .map(|result| (result["ref"].clone(), result["outcome"].clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes,
        vec![
            (json!("session-a"), json!("created")),
            (json!("session-b"), json!("created"))
        ],
        "{syncs:?}"
    );
    let second = &syncs[1]["ok"];
    assert_eq!(second["generation"], 2, "{syncs:?}");
    assert_eq!(
        second["ended"],
        json!([{"ref": "session-b", "scope_epoch": 1}]),
        "{syncs:?}"
    );

    let reader = ReaderModule::connect(&daemon.connection).await;
    let owner = format!("reserved:{OWNER}");

    // session-a is live at scope epoch 3. A running call whose route stamp
    // names session-a at epoch 3 may still send its write, and a stored
    // approval bound to session-a at epoch 3 runs. A stamp naming session-a at
    // epoch 2 came from an earlier session under the same ref, which has ended.
    let live = reader.describe(&owner, "session-a");
    assert_eq!(
        live,
        ScopeDescription {
            status: ScopeStatus::Live,

            owner_synced: true,
            owner_configured: true,
            live: Some(CallScope {
                owner: owner.clone(),
                scope_ref: "session-a".into(),
                scope_epoch: 3,
                kind: Some("head".into()),
                parent: None,
                parent_state: None,
                agent_id: None,
                flow_id: None,
                delegates: false,
                owner_authorized: false,
            }),
        }
    );
    assert_eq!(
        recheck_call_scope(&stamp(&owner, "session-a", 3), Ok(&live)),
        Ok(())
    );
    assert_eq!(
        approval_scope_verdict(&approval(&owner, "session-a", 3), Ok(&live)),
        ApprovalScopeVerdict::Run
    );
    assert_eq!(
        recheck_call_scope(&stamp(&owner, "session-a", 2), Ok(&live)),
        Err(SCOPE_ENDED),
        "a stamp from an earlier session under the same ref has ended"
    );

    // session-b was left out of the owner's second sync, so the daemon reports
    // it as ended at its last epoch, 1, rather than as unknown. Both checks
    // refuse with `SCOPE_ENDED`.
    let ended = reader.describe(&owner, "session-b");
    assert_eq!(
        ended,
        ScopeDescription {
            status: ScopeStatus::Ended,

            owner_synced: true,
            owner_configured: true,
            live: None,
        }
    );
    assert_eq!(
        recheck_call_scope(&stamp(&owner, "session-b", 1), Ok(&ended)),
        Err(SCOPE_ENDED)
    );
    assert_eq!(
        approval_scope_verdict(&approval(&owner, "session-b", 1), Ok(&ended)),
        ApprovalScopeVerdict::Refuse(SCOPE_ENDED)
    );

    // `never-synced` was in none of the owner's syncs. The daemon still
    // answers `scope.describe` for it (status not live) instead of refusing
    // the request. Each sync lists every scope the owner holds, so once the
    // owner has synced since the daemon started (`owner_synced`), a ref
    // missing from that list is gone, and `recheck_call_scope` refuses with
    // `SCOPE_ENDED`.
    let unknown = reader.describe(&owner, "never-synced");
    assert_eq!(
        unknown,
        ScopeDescription {
            status: ScopeStatus::NotLive,

            owner_synced: true,
            owner_configured: true,
            live: None,
        }
    );
    assert_eq!(
        recheck_call_scope(&stamp(&owner, "never-synced", 1), Ok(&unknown)),
        Err(SCOPE_ENDED)
    );

    // `test-scope-idle` is in the daemon's roster but has never synced, so
    // whether its session-a exists can still change. `recheck_call_scope`
    // gives a running call the retryable `SCOPE_NOT_SYNCED`, and
    // `approval_scope_verdict` holds a stored approval instead of refusing it.
    let idle_owner = format!("reserved:{IDLE_OWNER}");
    let not_synced = reader.describe(&idle_owner, "session-a");
    assert_eq!(
        not_synced,
        ScopeDescription {
            status: ScopeStatus::NotLive,

            owner_synced: false,
            owner_configured: true,
            live: None,
        }
    );
    assert_eq!(
        recheck_call_scope(&stamp(&idle_owner, "session-a", 1), Ok(&not_synced)),
        Err(SCOPE_NOT_SYNCED)
    );
    assert_eq!(
        approval_scope_verdict(&approval(&idle_owner, "session-a", 1), Ok(&not_synced)),
        ApprovalScopeVerdict::Hold(SCOPE_NOT_SYNCED)
    );

    // `no-such-owner` is not in the daemon's roster, and only roster modules
    // may sync, so it never will and its scopes can never be confirmed. Both
    // checks refuse with `SCOPE_UNVERIFIABLE`.
    let stranger = "reserved:no-such-owner";
    let unconfigured = reader.describe(stranger, "session-a");
    assert_eq!(
        unconfigured,
        ScopeDescription {
            status: ScopeStatus::NotLive,

            owner_synced: false,
            owner_configured: false,
            live: None,
        }
    );
    assert_eq!(
        recheck_call_scope(&stamp(stranger, "session-a", 1), Ok(&unconfigured)),
        Err(SCOPE_UNVERIFIABLE)
    );
    assert_eq!(
        approval_scope_verdict(&approval(stranger, "session-a", 1), Ok(&unconfigured)),
        ApprovalScopeVerdict::Refuse(SCOPE_UNVERIFIABLE)
    );
}

fn stamp(owner: &str, scope_ref: &str, scope_epoch: u64) -> CallScope {
    CallScope {
        owner: owner.into(),
        scope_ref: scope_ref.into(),
        scope_epoch,
        kind: Some("head".into()),
        parent: None,
        parent_state: None,
        agent_id: None,
        delegates: false,
        owner_authorized: false,
        flow_id: None,
    }
}

fn approval(owner: &str, scope_ref: &str, scope_epoch: u64) -> ApprovalScope {
    ApprovalScope {
        request_id: "req-1".into(),
        owner: owner.into(),
        scope_ref: scope_ref.into(),
        scope_epoch,
        agent_id: None,
        acted_as_agent: false,
        expires_at: i64::MAX,
    }
}

/// A module connection this test opens itself (the daemon did not launch it),
/// carrying Plexus's `DaemonScopeReader`. Every channel-0 RESPONSE or ERROR
/// frame is passed to `PendingControlReplies::complete`, which wakes the
/// `describe` call waiting on that frame's correlation id, as Plexus's own
/// dispatch loop does. The frame's raw body is also kept so each decoded
/// description can be compared with the bytes the daemon sent.
struct ReaderModule {
    reader: DaemonScopeReader,
    replies: Arc<Mutex<Vec<Vec<u8>>>>,
    _tasks: [AbortOnDrop; 2],
}

impl ReaderModule {
    async fn connect(connection: &subc_transport::ConnectionInfo) -> Self {
        let mut stream = connect_client(connection).await;
        let mut module_manifest = manifest::build(READER);
        module_manifest.provides.clear();
        let ack = hello(&mut stream, module_manifest, None).await;
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let (writer, mut outbound) = mpsc::channel::<Frame>(8);
        let writer_task = tokio::spawn(async move {
            while let Some(frame) = bounded::recv_option_within(
                outbound.recv(),
                std::time::Duration::from_secs(5),
                "scope-describe outbound frame",
            )
            .await
            {
                if write_frame(&mut write_half, &frame).await.is_err() {
                    break;
                }
            }
        });
        let pending = Arc::new(PendingControlReplies::default());
        let replies = Arc::new(Mutex::new(Vec::new()));
        let reader_task = tokio::spawn({
            let pending = Arc::clone(&pending);
            let replies = Arc::clone(&replies);
            async move {
                while let Ok(Some(frame)) = read_frame(&mut read_half).await {
                    if frame.header.channel == 0
                        && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
                    {
                        replies.lock().unwrap().push(frame.body.clone());
                        pending.complete(frame);
                    }
                }
            }
        });
        Self {
            reader: DaemonScopeReader::new(writer, ack.negotiated_ver, pending),
            replies,
            _tasks: [AbortOnDrop(writer_task), AbortOnDrop(reader_task)],
        }
    }

    /// Ask about `owner`/`scope_ref` through `DaemonScopeReader::describe`,
    /// then decode the raw reply it consumed with subc-protocol and check that
    /// both agree on every field `ScopeDescription` keeps: status, scope epoch,
    /// `owner_synced`, `owner_configured` and the live scope's stamp.
    fn describe(&self, owner: &str, scope_ref: &str) -> ScopeDescription {
        let described = self
            .reader
            .describe(owner, scope_ref)
            .unwrap_or_else(|error| panic!("describe {owner}/{scope_ref}: {error:?}"));
        let raw = self
            .replies
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("the reply the reader decoded");
        let Ok(ModuleControlResponseToModule::ScopeDescribe {
            status,
            scope_epoch: _,
            owner_synced,
            owner_configured,
            scope,
            ..
        }) = serde_json::from_slice(&raw)
        else {
            panic!(
                "not a scope.describe reply: {}",
                String::from_utf8_lossy(&raw)
            );
        };
        let decoded_status = match status {
            subc_protocol::scope::ScopeStatus::Live => ScopeStatus::Live,
            subc_protocol::scope::ScopeStatus::Ended => ScopeStatus::Ended,
            subc_protocol::scope::ScopeStatus::NotLive => ScopeStatus::NotLive,
        };
        assert_eq!(
            described,
            ScopeDescription {
                status: decoded_status,
                owner_synced,
                owner_configured,
                live: scope.as_ref().map(CallScope::from_stamp),
            },
            "the reader's decoding of {owner}/{scope_ref} differs from the raw reply: {}",
            String::from_utf8_lossy(&raw)
        );
        described
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Daemon {
    task: tokio::task::JoinHandle<Result<(), subc_daemon::bootstrap::BootstrapError>>,
    connection: subc_transport::ConnectionInfo,
    results_path: PathBuf,
    _directory: Scratch,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Start an in-process daemon whose roster holds the two fixture modules.
async fn start_daemon() -> Daemon {
    let directory = Scratch::directory("scope-describe-daemon");
    let home = directory.join("home");
    fs::create_dir_all(&home).expect("create isolated data home");
    let connection_file_path = directory.join("subc-connection.json");
    let results_path = directory.join("owner-results.json");
    let test_binary = single_quoted(std::env::current_exe().unwrap());
    // The supervisor launches each module with `--subc <connection file>`
    // appended to its configured arguments, and the Rust test runner would
    // reject `--subc` as an unknown flag. So each fixture runs this shell
    // script, which execs this test binary to run only `scope_owner_fixture`
    // and does not pass the appended arguments on.
    let launcher = directory.join("scope-owner-fixture.sh");
    fs::write(
        &launcher,
        format!("exec {test_binary} --exact scope_owner_fixture --nocapture\n"),
    )
    .unwrap();
    let fixture = |mode: &str| {
        json!({
            "program": "/bin/sh",
            "args": [launcher],
            "env": {
                "HOME": home,
                "XDG_DATA_HOME": home.join(".local/share"),
                "SCOPE_OWNER_CONNECTION": connection_file_path,
                "SCOPE_OWNER_RESULTS": results_path,
                "SCOPE_OWNER_MODE": mode,
            },
            "reserved": true
        })
    };
    let daemon_config_path = directory.join("subc.jsonc");
    fs::write(
        &daemon_config_path,
        serde_json::to_vec(&json!({
            "version": 1,
            "storage": {"backend": "sqlite", "data_home": home},
            "modules": {
                OWNER: fixture("sync"),
                IDLE_OWNER: fixture("idle"),
            }
        }))
        .unwrap(),
    )
    .unwrap();
    // Capture each fixture module's stderr into `run-logs/<module id>.stderr.log`
    // inside this test's scratch directory. With no capture directory,
    // subc-daemon 0.26 forwards module stderr to its own stderr; older
    // versions instead defaulted to the operator's live
    // `~/.local/share/cortexkit/run/logs/`, mixing fixture output into the
    // logs of real modules.
    let capture_logs = directory.join("run-logs");
    fs::create_dir_all(&capture_logs).unwrap();
    let config = subc_daemon::bootstrap::BootstrapConfig::new(&connection_file_path, 0)
        .with_capture_logs_dir(&capture_logs)
        .with_daemon_config_path(&daemon_config_path)
        .expect("load daemon config");
    let task = tokio::spawn(subc_daemon::bootstrap::run_with_config(config));
    let connection = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(connection) = connection_file::read(&connection_file_path) {
                break connection;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("daemon must publish its connection file");
    Daemon {
        task,
        connection,
        results_path,
        _directory: directory,
    }
}

/// Wait for the `test-scope-owner` fixture to write its two `scope.sync`
/// replies to `path`, and return them in order. The fixture writes a
/// temporary file and renames it into place, so once `path` exists it is
/// complete.
async fn wait_for_owner_results(path: &Path) -> Vec<Value> {
    timeout(FIXTURE_DEADLINE, async {
        loop {
            if let Ok(bytes) = fs::read(path) {
                break serde_json::from_slice::<Vec<Value>>(&bytes).expect("owner results JSON");
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the scope owner fixture must sync within the deadline")
}

async fn hello(
    stream: &mut TcpStream,
    manifest: subc_protocol::manifest::ModuleManifest,
    launch_nonce: Option<String>,
) -> ModuleHelloAckBody {
    let body = subc_protocol::ModuleHelloBody {
        manifest,
        protocol_ver: PROTOCOL_VERSION,
        control_ops: Some(vec!["route.bind".into()]),
        launch_nonce,
    };
    let frame = Frame::build(
        FrameType::Hello,
        wire::control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    let ack = read_frame(stream)
        .await
        .unwrap()
        .expect("daemon answers HELLO");
    assert_eq!(
        ack.header.ty,
        FrameType::HelloAck,
        "{}",
        String::from_utf8_lossy(&ack.body)
    );
    serde_json::from_slice(&ack.body).expect("HELLO_ACK body")
}

/// Send one module-originated control request and return the daemon's
/// answer: `{"ok": reply}` or `{"refused": error body}`. Channel-0 requests
/// the daemon sends meanwhile are acknowledged so it keeps the module up.
async fn control_request(
    stream: &mut TcpStream,
    correlation: u64,
    request: &ModuleControlRequestFromModule,
) -> Value {
    let frame = Frame::build(
        FrameType::Request,
        wire::control_flags(),
        0,
        0,
        correlation,
        serde_json::to_vec(request).unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame(stream)
            .await
            .unwrap()
            .expect("daemon connection stays open");
        if frame.header.channel != 0 {
            continue;
        }
        match frame.header.ty {
            FrameType::Request => acknowledge(stream, &frame).await,
            FrameType::Response if frame.header.corr == correlation => {
                return json!({"ok": serde_json::from_slice::<Value>(&frame.body).unwrap()});
            }
            FrameType::Error if frame.header.corr == correlation => {
                return json!({"refused": serde_json::from_slice::<Value>(&frame.body).unwrap()});
            }
            _ => {}
        }
    }
}

async fn acknowledge(stream: &mut TcpStream, request: &Frame) {
    let body = serde_json::to_vec(&subc_protocol::session::ModuleControlResponse::RouteBindAck {})
        .unwrap();
    let response = Frame::build(
        FrameType::Response,
        request.header.flags,
        0,
        request.header.epoch,
        request.header.corr,
        body,
    )
    .unwrap();
    write_frame(stream, &response).await.unwrap();
}

fn head_scope(scope_ref: &str, scope_epoch: u64) -> subc_protocol::scope::ScopeRecord {
    serde_json::from_value(json!({"ref": scope_ref, "scope_epoch": scope_epoch, "kind": "head"}))
        .expect("scope record")
}

/// The supervised scope owner. With `SCOPE_OWNER_MODE=sync` it syncs
/// session-a and session-b, then syncs again without session-b, which ends
/// it; it writes both replies to `SCOPE_OWNER_RESULTS`. With `idle` it
/// registers and never syncs. Either way it then stays connected until the
/// daemon goes away. Run on its own (no environment) it does nothing.
#[tokio::test]
async fn scope_owner_fixture() {
    let Ok(connection_path) = std::env::var("SCOPE_OWNER_CONNECTION") else {
        return;
    };
    let results_path = PathBuf::from(std::env::var("SCOPE_OWNER_RESULTS").unwrap());
    let mode = std::env::var("SCOPE_OWNER_MODE").unwrap();
    let connection = connection_file::read(Path::new(&connection_path)).expect("connection file");
    let mut stream = connect_client(&connection).await;
    let module_id = if mode == "sync" { OWNER } else { IDLE_OWNER };
    let mut module_manifest = manifest::build(module_id);
    module_manifest.provides.clear();
    let launch_nonce = subc_client_rs::launch_nonce()
        .expect("fixture launch nonce")
        .map(|nonce| nonce.value().to_string());
    hello(&mut stream, module_manifest, launch_nonce).await;
    if mode == "sync" {
        // Start at correlation id 1 << 32, as Plexus's reader does: far above
        // the id 1 the HELLO frame used, so a reply to these sync requests can
        // never be confused with the HELLO exchange.
        let first = control_request(
            &mut stream,
            1 << 32,
            &ModuleControlRequestFromModule::ScopeSync {
                generation: 1,
                scopes: vec![head_scope("session-a", 3), head_scope("session-b", 1)],
            },
        )
        .await;
        let second = control_request(
            &mut stream,
            (1 << 32) + 1,
            &ModuleControlRequestFromModule::ScopeSync {
                generation: 2,
                scopes: vec![head_scope("session-a", 3)],
            },
        )
        .await;
        // Write both replies to `owner-results.partial` first, then rename it
        // to the `SCOPE_OWNER_RESULTS` path. The rename is atomic, so
        // `wait_for_owner_results`, which polls that path, never reads a
        // half-written file.
        let partial = results_path.with_extension("partial");
        fs::write(
            &partial,
            serde_json::to_vec(&json!([first, second])).unwrap(),
        )
        .unwrap();
        fs::rename(&partial, &results_path).unwrap();
    }
    while let Ok(Some(frame)) = read_frame(&mut stream).await {
        if frame.header.channel == 0 && frame.header.ty == FrameType::Request {
            acknowledge(&mut stream, &frame).await;
        }
    }
}
