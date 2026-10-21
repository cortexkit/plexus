use super::*;
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{BindIdentity, RouteTarget};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn searxng_connect_stores_private_instance_and_allows_anonymous_or_named_bearer() {
    let (_scratch, store, state) = two_connection_fixture("searxng-connect");
    let manifest = plexus_core::ingest_value(
        serde_json::from_str(
            &subc_jsonc::jsonc_to_json(include_str!("../../../catalog/searxng_rest.jsonc"))
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    store.upsert_manifest("system", &manifest).unwrap();
    let address = "https://private-instance-canary.invalid/secret-instance-path";
    for bearer in [false, true] {
        let id = format!("searxng-{bearer}");
        let mut params =
            json!({"app_key":"searxng_rest", "connection_id":id, "instance_url":address});
        if bearer {
            params["credential_id"] = json!("apikey:searxng");
        }
        for invalid in [
            Value::Null,
            json!("http://localhost:80@evil.invalid"),
            json!("https://user:password@private-instance-canary.invalid"),
        ] {
            let mut bad = params.clone();
            bad["instance_url"] = invalid;
            let refused = ceremony::issue_ticket(&state, "direct", &bad);
            assert_eq!(refused["error"]["code"], "invalid_request");
            assert!(store.connection("direct", &id).unwrap().is_none());
            assert!(!refused.to_string().contains("private-instance-canary"));
            assert!(!refused.to_string().contains("evil.invalid"));
        }
        let issue = ceremony::issue_ticket(&state, "direct", &params);
        let ticket = issue["result"]["ticket_id"]
            .as_str()
            .expect("SearXNG enrollment");
        assert!(store
            .connection("direct", &id)
            .unwrap()
            .unwrap()
            .instance_url
            .is_none());
        assert!(!issue.to_string().contains("private-instance-canary"));
        let invoke = |args: &Value| {
            facade_connections_connect(&FacadeArguments {
                state: &state,
                arguments: args.as_object().unwrap(),
                principal_key: "direct",
                op: Some("connect"),
            })
            .unwrap()
        };
        let refused =
            invoke(&json!({"ticket_id":ticket,"instance_url":"https://attacker.invalid"}));
        assert_eq!(refused["error"]["code"], "argument_undeclared");
        assert_eq!(refused["error"]["field"], "instance_url");
        assert_eq!(
            store.connection("direct", &id).unwrap().unwrap().status,
            "pending"
        );
        let reply = invoke(&json!({"ticket_id":ticket}));
        assert_eq!(reply["result"]["discovery"], "complete", "{reply}");
        assert!(!reply.to_string().contains("private-instance-canary"));
        let record = store.connection("direct", &id).unwrap().unwrap();
        assert_eq!(record.instance_url.as_ref().unwrap().as_str(), address);
        assert_eq!(record.has_credential_binding, bearer);
    }
    for params in [
        json!({"app_key":"searxng_rest","credential_id":"apikey:other","instance_url":address}),
        json!({"app_key":"exa_rest","credential_id":"apikey:exa","instance_url":address}),
    ] {
        let rejected = ceremony::issue_ticket(&state, "direct", &params);
        assert_eq!(rejected["error"]["code"], "invalid_request");
    }
    store.set_web_search_order(&["searxng".into()]).unwrap();
    refresh_store_health(&state, &health_probe_principals(&state));
    let health = serde_json::to_value(connector_home_health(&state))
        .unwrap()
        .to_string();
    assert!(health.contains("searxng"));
    assert!(!health.contains("private-instance-canary"));
    assert!(!health.contains("secret-instance-path"));
}

#[test]
fn searxng_connections_schema_digest_stays_unchanged_and_excludes_instance_url() {
    let module = manifest::build("plexus");
    let subc_protocol::manifest::ProviderRole::ToolProvider { tools, .. } = &module.provides[0]
    else {
        panic!("tool provider")
    };
    let schema = &tools
        .iter()
        .find(|tool| tool.name == manifest::CONNECTIONS_TOOL)
        .unwrap()
        .schema;
    assert_eq!(
        plexus_core::jcs_sha256(schema).unwrap(),
        "sha256:bb9507643e8d6c3c7c45cce4699c7baa12311b8523b1b0fa04af676ae6cce895"
    );
    assert_eq!(schema["additionalProperties"], false);
    assert!(schema["properties"].get("instance_url").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn searxng_instance_catalog_and_ceremony_follow_the_reviewed_manifest() {
    let (_scratch, store, state) = two_connection_fixture("instance-manifest-rule");
    let mut manifest: Value = serde_json::from_str(
        &subc_jsonc::jsonc_to_json(include_str!("../../../catalog/searxng_rest.jsonc")).unwrap(),
    )
    .unwrap();
    manifest["key"] = json!("private_rest");
    store
        .upsert_manifest("system", &plexus_core::ingest_value(manifest).unwrap())
        .unwrap();
    let arguments = json!({});
    let catalog = facade_catalog_apps(&FacadeArguments {
        state: &state,
        arguments: arguments.as_object().unwrap(),
        principal_key: "direct",
        op: Some("apps"),
    })
    .unwrap();
    let apps = catalog["result"]["apps"].as_array().unwrap();
    assert_eq!(
        apps.iter()
            .find(|app| app["key"] == "private_rest")
            .unwrap()["takes_instance_url"],
        true
    );
    assert_eq!(
        apps.iter().find(|app| app["key"] == "exa_rest").unwrap()["takes_instance_url"],
        false
    );
    let missing = ceremony::issue_ticket(&state, "direct", &json!({"app_key":"private_rest"}));
    assert_eq!(
        missing["error"]["message"],
        "this provider requires instance_url"
    );
    let refused = ceremony::issue_ticket(
        &state,
        "direct",
        &json!({"app_key":"exa_rest","instance_url":"https://private.invalid"}),
    );
    assert_eq!(
        refused["error"]["message"],
        "this provider takes no instance_url"
    );
    let approved = ceremony::issue_ticket(
        &state,
        "direct",
        &json!({"app_key":"private_rest","instance_url":"https://private.invalid/base","action_selectors":["search"]}),
    );
    let ticket = approved["result"]["ticket_id"]
        .as_str()
        .expect("instance manifest ticket");
    let arguments = json!({"ticket_id":ticket});
    let connected = facade_connections_connect(&FacadeArguments {
        state: &state,
        arguments: arguments.as_object().unwrap(),
        principal_key: "direct",
        op: Some("connect"),
    })
    .unwrap();
    assert_eq!(connected["result"]["discovery"], "complete");
    assert_eq!(
        store
            .connection("direct", "conn-private_rest")
            .unwrap()
            .unwrap()
            .instance_url
            .as_ref()
            .unwrap()
            .as_str(),
        "https://private.invalid/base"
    );
}

#[tokio::test]
async fn undecodable_control_bind_refuses_only_that_request_and_loop_survives() {
    let scratch = Scratch::database("control-decode-loop");
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.into(),
            storage_namespace: "test".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(store),
    });
    let (mut input, mut reader) = tokio::io::duplex(8192);
    let (writer, mut replies) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        dispatch_loop(
            &mut reader,
            writer,
            state,
            Arc::new(RouteBindings::new()),
            Arc::new(PendingControlReplies::default()),
        )
        .await
    });
    let mut malformed: Value = serde_json::from_slice(
        &bind(Some(Principal::Reserved {
            module_id: "basal".into(),
        }))
        .body,
    )
    .unwrap();
    malformed["scope"] = serde_json::to_value(
        subc_protocol::scope::ScopeStamp::new(
            Principal::Reserved {
                module_id: "prefrontal".into(),
            },
            "flow",
            1,
            subc_protocol::scope::ScopeKind::Head,
        )
        .with_owner_authorized(true),
    )
    .unwrap();
    assert!(serde_json::from_value::<ModuleControlRequest>(malformed.clone()).is_ok());
    malformed["scope"]["attributes"] = json!({"future_unknown_field":true});
    let decode_error =
        serde_json::from_value::<ModuleControlRequest>(malformed.clone()).unwrap_err();
    assert!(decode_error.to_string().contains("future_unknown_field"));
    for (corr, body) in [
        (17, serde_json::to_vec(&malformed).unwrap()),
        (
            18,
            serde_json::to_vec(&ModuleControlRequest::HealthCheck {}).unwrap(),
        ),
    ] {
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            wire::control_flags(),
            0,
            0,
            corr,
            body,
        )
        .unwrap();
        write_frame(&mut input, &frame).await.unwrap();
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), replies.recv())
            .await
            .unwrap()
            .expect("loop must answer");
        assert_eq!(response.header.corr, corr);
        if corr == 17 {
            assert_eq!(response.header.ty, FrameType::Error);
            let body: subc_protocol::ErrorBody = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body.code, "invalid_request");
            assert!(body.message.contains("future_unknown_field"));
        } else {
            assert_eq!(response.header.ty, FrameType::Response);
            assert!(matches!(
                serde_json::from_slice::<subc_protocol::session::ModuleControlResponse>(
                    &response.body
                )
                .unwrap(),
                subc_protocol::session::ModuleControlResponse::HealthCheck { .. }
            ));
        }
        assert!(!task.is_finished(), "dispatch loop must remain live");
    }
    drop(input);
    task.await.unwrap().unwrap();
}

#[test]
fn a_refused_launch_nonce_names_its_kind() {
    let error = launch_nonce_refused(subc_os::LaunchNonceError::NotOpen { fd: 3, errno: 9 });
    let line = error.to_string();
    assert!(
        line.starts_with("read launch nonce: refused as NotOpen { fd: 3, errno: 9 }: "),
        "{line}"
    );
    assert!(line.contains("which is not open"), "{line}");
    assert!(!line.contains('\n'), "{line}");
}

fn prepare_selection_fixture() -> Scratch {
    let path = Scratch::database("selection");
    let _store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: path.to_string_lossy().into_owned(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    let conn = rusqlite::Connection::open(&path).unwrap();
    let now = plexus_core::storage::now_ms();
    conn.execute("INSERT INTO trigger_subscriptions (subscription_id, principal, connection_id, action, cadence_s, cursor_kind, cursor_state, schema_hash, status, last_polled_at_ms, consecutive_vendor_failures, created_at_ms) VALUES ('watch', 'selection-owner', 'unused', 'read', 300, 'sync_token', '{}', 'hash', 'active', ?1, 4, 0)", [now - 301_000]).unwrap();
    path
}

async fn selection_health_scenario(scenario: &str) {
    let path = diagnostic_store_path(prepare_selection_fixture);
    let store = open_diagnostic_store(&path);
    let conn = rusqlite::Connection::open(&path).unwrap();
    // Cadence-due but held in exponential backoff, so a valid selection polls nothing.
    if scenario != "backoff" {
        conn.execute(
            "UPDATE trigger_subscriptions SET cursor_state = 'broken-json'",
            [],
        )
        .unwrap();
    }
    let health = Arc::new(health::HealthState::new());
    let state = Arc::new(ModuleState {
        health: Arc::clone(&health),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    let (shutdown, stop) = mpsc::channel(1);
    let task = crate::test_support::spawn_test_scheduler(state, stop);
    assert!(
        crate::test_support::scheduler_passes(&health, 2).await,
        "the scheduler must run a pass over the selection fixture"
    );
    if scenario == "recovery" {
        conn.execute("UPDATE trigger_subscriptions SET cursor_state = '{}'", [])
            .unwrap();
        assert!(
            crate::test_support::scheduler_passes(&health, 2).await,
            "the scheduler must retry selection after the repair"
        );
    } else if scenario == "empty" {
        conn.execute("DELETE FROM trigger_subscriptions", [])
            .unwrap();
        assert!(
            crate::test_support::scheduler_passes(&health, 2).await,
            "the scheduler must select again after the watches are removed"
        );
    }
    health.backdate_scheduler_success(health::scheduler_stall_threshold_ms_for_test(300) + 1);
    health.stamp_heartbeat();
    let response = health.report();
    drop(shutdown);
    task.await.unwrap();
    let subc_protocol::session::ModuleControlResponse::HealthCheck {
        status, metrics, ..
    } = response
    else {
        panic!("health response")
    };
    let metrics = metrics.unwrap();
    assert_eq!(metrics["schedulerPollsAttempted"], json!(0));
    assert_eq!(metrics["schedulerPollsCompleted"], json!(0));
    assert_eq!(
        store
            .active_subscription_schedule()
            .unwrap()
            .map(|(count, _)| count)
            .unwrap_or(0),
        if scenario == "empty" { 0 } else { 1 }
    );
    if scenario != "log" {
        assert_eq!(
            status,
            if scenario == "failure" {
                subc_protocol::session::HealthStatus::Degraded
            } else {
                subc_protocol::session::HealthStatus::Ok
            },
            "{metrics}"
        );
    }
    drop(conn);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selection_failure_reaches_stall_verdict() {
    selection_health_scenario("failure").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selection_failure_clears_on_successful_retry() {
    selection_health_scenario("recovery").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_watches_deferred_in_backoff_are_healthy() {
    selection_health_scenario("backoff").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_active_set_after_selection_failure_never_stalls() {
    selection_health_scenario("empty").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selection_log_fixture() {
    if !diagnostic_child() {
        return;
    }
    selection_health_scenario("log").await;
}

#[test]
fn selection_failure_logs_principal_and_error_to_stderr() {
    let stderr = module_diagnostic_output("tests::selection_log_fixture");
    let prefix =
        " ERROR plexus.scheduler: scheduler selection failed for principal selection-owner:";
    let line = stderr
        .lines()
        .find(|line| line.contains(prefix))
        .unwrap_or_else(|| panic!("no selection failure line: {stderr}"));
    // The decoding error's own wording belongs to the SQLite and JSON
    // libraries; what matters here is that the line carries a cause.
    assert!(
        !cause_after(line, prefix).is_empty(),
        "missing decoding error: {line}"
    );
}

const PREPARED_DIAGNOSTIC_STORE: &str = "PLEXUS_PREPARED_DIAGNOSTIC_STORE";

// Directory cleanup belongs to the capturing parent. A child borrows its
// prepared database instead of creating a second fixture or seeding it again.
enum DiagnosticStorePath {
    Owned(Scratch),
    Prepared(PathBuf),
}

impl DiagnosticStorePath {
    fn new(label: &str) -> Self {
        match std::env::var_os(PREPARED_DIAGNOSTIC_STORE) {
            Some(path) => Self::Prepared(path.into()),
            None => Self::Owned(Scratch::database(label)),
        }
    }

    fn is_prepared(&self) -> bool {
        matches!(self, Self::Prepared(_))
    }

    fn path(&self) -> &Path {
        match self {
            Self::Owned(scratch) => scratch.path(),
            Self::Prepared(path) => path,
        }
    }
}

impl std::ops::Deref for DiagnosticStorePath {
    type Target = Path;
    fn deref(&self) -> &Path {
        self.path()
    }
}

impl AsRef<Path> for DiagnosticStorePath {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

fn open_diagnostic_store(path: &Path) -> Arc<PlexusStore> {
    Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: path.to_string_lossy().into_owned(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    )
}

fn diagnostic_store_path(prepare: fn() -> Scratch) -> DiagnosticStorePath {
    if let Some(path) = std::env::var_os(PREPARED_DIAGNOSTIC_STORE) {
        DiagnosticStorePath::Prepared(path.into())
    } else {
        DiagnosticStorePath::Owned(prepare())
    }
}

fn prepare_health_probe_fixture() -> Scratch {
    let path = Scratch::database("health-probe");
    let store = open_diagnostic_store(&path);
    // REST catalog refresh uses the manifest's actions, not a vendor request.
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/exa_rest.jsonc"),
    )
    .unwrap();
    let ingested = plexus_core::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap(),
    )
    .unwrap();
    store.upsert_manifest("system", &ingested).unwrap();
    let owners = ["direct", "probe-owner", "z-other-owner"];
    for principal in owners {
        for suffix in ["a", "b"] {
            let id = format!("{principal}-{suffix}");
            store
                .insert_connection(
                    principal,
                    &id,
                    &ingested.manifest.key,
                    "pending",
                    &json!({}),
                )
                .unwrap();
            let ticket = store
                .create_binding_ticket(principal, &id, b"test:probe-handle")
                .unwrap();
            store
                .connect_with_ticket(principal, &ticket.ticket_id)
                .unwrap()
                .unwrap();
            store
                .set_connection_health(principal, &id, "degraded", &json!({}))
                .unwrap();
        }
    }
    path
}

fn health_probe_scenario(scenario: &str) {
    logging::init_child();
    let path = diagnostic_store_path(prepare_health_probe_fixture);
    let store = open_diagnostic_store(&path);
    let owners = ["direct", "probe-owner", "z-other-owner"];
    let state = ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    };
    assert_eq!(health_probe_principals(&state), owners);
    let conn = rusqlite::Connection::open(&path).unwrap();
    match scenario {
        "listing" => {
            // Owner enumeration still succeeds; only this owner's summary cannot decode.
            conn.execute("UPDATE connections SET generation = 'broken-generation' WHERE principal = 'probe-owner'", []).unwrap();
        }
        "probe" => {
            // Summaries still decode, but loading this connection for refresh fails.
            conn.execute("UPDATE connections SET health_state = 'broken-json' WHERE connection_id = 'probe-owner-a'", []).unwrap();
        }
        "principals" => {
            conn.execute("DROP TABLE trigger_subscriptions", [])
                .unwrap();
            assert_eq!(health_probe_principals(&state), ["direct"]);
        }
        "happy" => {}
        _ => panic!("unknown probe scenario"),
    }
    if scenario != "principals" {
        run_health_probes(&state);
        for principal in owners {
            for suffix in ["a", "b"] {
                let id = format!("{principal}-{suffix}");
                let expected = if (scenario == "listing" && principal == "probe-owner")
                    || (scenario == "probe" && id == "probe-owner-a")
                {
                    "degraded"
                } else {
                    "active"
                };
                let status: String = conn
                    .query_row(
                        "SELECT status FROM connections WHERE connection_id = ?1",
                        [&id],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(status, expected, "{scenario}: {id}");
            }
        }
    }
    drop(conn);
    drop(state);
    drop(store);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn health_probe_listing_error_fixture() {
    if !diagnostic_child() {
        return;
    }
    health_probe_scenario("listing");
}

#[test]
fn health_probe_connection_error_fixture() {
    if !diagnostic_child() {
        return;
    }
    health_probe_scenario("probe");
}

#[test]
fn health_probe_principals_error_fixture() {
    if !diagnostic_child() {
        return;
    }
    health_probe_scenario("principals");
}

#[test]
fn health_probe_visits_every_connection_of_every_principal() {
    health_probe_scenario("happy");
}

/// A request whose handler fails before it can reply (here: the route
/// binding lock is poisoned, so the binding cannot be read) still gets an
/// `internal_error` answer, and the failure is logged. Run as a child so
/// the log line can be read back.
#[test]
fn failed_request_fixture() {
    if !diagnostic_child() {
        return;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("fixture runtime");
    runtime.block_on(async {
        let descriptor = StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.to_string(),
            storage_namespace: format!("failed-request-{}", plexus_core::now_ms()),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("open test store"));
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(store),
        });
        let bindings = Arc::new(RouteBindings::new());
        let poisoner = Arc::clone(&bindings.inner);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.write().unwrap();
            panic!("poison the route binding lock");
        })
        .join();
        let body = json!({"name":"connections","arguments":{"op":"list"}});
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            wire::control_flags(),
            3,
            1,
            77,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        let (writer, mut responses) = mpsc::channel(4);
        assert!(handle_frame(frame, &writer, &state, &bindings)
            .await
            .expect("dispatch"));
        let reply = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "a reply to a request whose handler failed",
        )
        .await;
        assert_eq!(reply.header.corr, 77);
        let reply: Value = serde_json::from_slice(&reply.body).expect("reply JSON");
        assert_eq!(reply["error"]["code"], "internal_error", "{reply}");
    });
}

#[test]
fn a_request_whose_handler_fails_is_answered_and_logged() {
    let stderr = module_diagnostic_output("tests::failed_request_fixture");
    assert!(
            stderr.contains("plexus.wire: request on channel 3 epoch 1 correlation 77 failed before its reply was sent: route binding state was poisoned"),
            "{stderr}"
        );
}

#[test]
fn health_probe_listing_failure_logs_principal_and_error_to_stderr() {
    let stderr = module_diagnostic_output("tests::health_probe_listing_error_fixture");
    assert!(
            stderr.contains(
                " WARN  plexus.health: health probe connection listing failed for principal probe-owner:"
            ),
            "{stderr}"
        );
    assert!(
        stderr.contains("generation"),
        "missing decoding error: {stderr}"
    );
}

#[test]
fn health_probe_principals_failure_logs_narrowing_and_error_to_stderr() {
    let stderr = module_diagnostic_output("tests::health_probe_principals_error_fixture");
    assert!(stderr.contains(" ERROR plexus.health: health probe principal enumeration failed for stored subscription and connection owners; falling back to principal direct only:"), "{stderr}");
    let prefix = "falling back to principal direct only:";
    let line = stderr
        .lines()
        .find(|line| line.contains(prefix))
        .unwrap_or_else(|| panic!("no enumeration failure line: {stderr}"));
    assert!(
        cause_after(line, prefix).contains("trigger_subscriptions"),
        "missing enumeration error naming the dropped table: {line}"
    );
}

/// A failed probe must say WHO and WHY. The fixture breaks one row's
/// `health_state` JSON so loading that connection fails in the store; the
/// warning names the principal and connection, and carries the store's
/// decoding error after the fixed summary, not only the summary.
#[test]
fn health_probe_store_failure_logs_the_underlying_cause() {
    let stderr = module_diagnostic_output("tests::health_probe_connection_error_fixture");
    let prefix = " WARN  plexus.health: health probe failed for principal probe-owner, connection probe-owner-a: catalog store operation failed: storage backend:";
    let line = stderr
        .lines()
        .find(|line| line.contains(prefix))
        .unwrap_or_else(|| panic!("no probe failure line: {stderr}"));
    // The decoding error's own wording belongs to the SQLite and JSON
    // libraries; what matters here is that the line carries one.
    assert!(
        !cause_after(line, prefix).is_empty(),
        "the probe failure must name the store error that caused it: {line}"
    );
}

/// The text a diagnostic line carries after `prefix`, trimmed.
fn cause_after<'a>(line: &'a str, prefix: &str) -> &'a str {
    line.split_once(prefix)
        .map_or("", |(_, cause)| cause.trim())
}

/// One imported GitHub handle connection in the production shape: the
/// reviewed github_rest manifest, a connection row created by the import
/// with NO stored credential binding, and the handle credential provider
/// installed later on the runtime. This prepares durable rows only; the
/// observer process runs the probe and checks the resulting status.
fn prepare_imported_handle_probe_fixture() -> Scratch {
    let path = Scratch::database("handle-probe");
    let store = open_diagnostic_store(&path);
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github_rest.jsonc"),
    )
    .unwrap();
    let ingested = plexus_core::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap(),
    )
    .unwrap();
    store.upsert_manifest("system", &ingested).unwrap();
    let connection_id = "github-handle-app-probe";
    store
        .import_github_handles(&[plexus_core::storage::github_store::GithubImportRow {
            handle: plexus_core::storage::github_store::GithubHandle {
                app_handle_id: "app-probe".into(),
                agent_id: "agent-probe".into(),
                app_id: 1,
                installation_id: None,
                credential_reference: "github_app:app-probe".into(),
                credential_generation: 0,
                status: "enabled".into(),
                proven_at: None,
                connection_principal: "direct".into(),
                connection_id: connection_id.into(),
            },
            repositories: vec!["o/probe".into()],
            grants: vec![],
            module_actions: vec!["github.issue.get".into()],
            policies: vec![],
        }])
        .unwrap();
    path
}

fn imported_handle_probe_scenario(status: &str) {
    logging::init_child();
    let path = diagnostic_store_path(prepare_imported_handle_probe_fixture);
    let store = open_diagnostic_store(&path);
    let connection_id = "github-handle-app-probe";
    let imported = store.connection("direct", connection_id).unwrap().unwrap();
    assert!(
        !imported.has_credential_binding,
        "an imported handle connection carries no stored credential binding"
    );
    if status != "active" {
        store
            .set_connection_health("direct", connection_id, status, &json!({"reason": "test"}))
            .unwrap();
    }
    let mut runtime = runtime_for_test(Arc::clone(&store));
    runtime.github_handle_credentials = Some(Arc::new(AnyHandleToken));
    let state = ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    };
    run_health_probes(&state);
    let subc_protocol::session::ModuleControlResponse::HealthCheck { metrics, .. } =
        state.health.report()
    else {
        panic!("expected probe health report");
    };
    assert_eq!(
        metrics.unwrap()["connections"],
        json!(1),
        "the imported handle must actually be probed"
    );
    let after = store.connection("direct", connection_id).unwrap().unwrap();
    assert_eq!(after.status, "active", "started {status}");
    drop(state);
    drop(store);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn health_probe_imported_handle_fixture() {
    if !diagnostic_child() {
        return;
    }
    imported_handle_probe_scenario("active");
}

#[test]
fn health_probe_imported_handle_degraded_fixture() {
    if !diagnostic_child() {
        return;
    }
    imported_handle_probe_scenario("degraded");
}

/// A probe over an imported GitHub handle connection succeeds and logs
/// nothing. Every such connection used to log a probe failure once a
/// minute, because the probe looked for a stored credential binding these
/// connections never have.
#[test]
fn health_probe_over_an_imported_handle_connection_logs_no_warning() {
    let stderr = module_diagnostic_output("tests::health_probe_imported_handle_fixture");
    assert!(
        !stderr.contains("health probe failed"),
        "a healthy handle connection must probe cleanly: {stderr}"
    );
}

/// A handle connection left `degraded` recovers on a successful probe, the
/// same as any other connection. The fixture asserts the recovered status;
/// this also checks the pass logged no failure.
#[test]
fn health_probe_recovers_a_degraded_handle_connection() {
    let fixture = "tests::health_probe_imported_handle_degraded_fixture";
    let stderr = module_diagnostic_output(fixture);
    assert!(
        !stderr.contains("health probe failed"),
        "{fixture}: {stderr}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invoke_connection_lookup_failure_is_refused_as_a_store_failure() {
    let (path, _store, state) = two_connection_fixture("invoke-lookup-error");
    rusqlite::Connection::open(path.path())
            .unwrap()
            .execute(
                "UPDATE connections SET generation = 'broken-generation' WHERE connection_id = 'conn-keep-rest'",
                [],
            )
            .unwrap();
    let object = json!({"name":"invoke","arguments":{"op":"call",
            "connection":"conn-keep-rest","action":"web_search_exa","args":{"query":"x"}}});
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        wire::control_flags(),
        2,
        1,
        8,
        serde_json::to_vec(&object).unwrap(),
    )
    .unwrap();
    let routes = Arc::new(RouteBindings::new());
    routes.insert(2, 1, Principal::Direct).unwrap();
    let reply =
        facade_tool_reply(&frame, object.as_object().unwrap(), &state, &routes).expect("a reply");
    assert_eq!(
        reply["error"]["code"], "store_failure",
        "a connection lookup failure must be refused as store_failure: {reply}"
    );
}

/// A credential-free MCP connection `conn-mcp` holding one catalogued
/// write, `held_write`, whose stored schema declares `team`. The engine
/// dispatches through a mock transport (counted), while the freshness
/// check's catalog refresh goes to `url` over real MCP.
struct McpWriteFixture {
    scratch: Scratch,
    state: Arc<ModuleState>,
    transport: Arc<plexus_core::MockTransport>,
}

fn write_schema() -> Value {
    json!({"type": "object", "properties": {"team": {"type": "string"}}})
}

fn mcp_write_fixture(label: &str, url: &str, ask_first: bool, granted: bool) -> McpWriteFixture {
    crate::test_support::assert_loopback_is_not_proxied();
    let scratch = Scratch::database(label);
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: scratch.to_string_lossy().into_owned(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    store
        .upsert_manifest("system", &crate::test_mcp_manifest("stubmcp", url))
        .unwrap();
    store
        .insert_connection(
            "direct",
            "conn-mcp",
            "stubmcp",
            "active",
            &json!({"required": [], "optional": [], "write_enabling": ["team"]}),
        )
        .unwrap();
    let schema = write_schema();
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: "conn-mcp".to_string(),
            principal: "direct".to_string(),
            name: "held_write".to_string(),
            title: None,
            schema: schema.clone(),
            schema_hash: plexus_core::jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
            risk: "write".to_string(),
            severity: "S2".to_string(),
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
            ask_first,
        })
        .unwrap();
    if granted {
        for (grant_id, kind) in [
            ("grant-invoke", "invoke"),
            ("grant-admin", "connection_admin"),
        ] {
            store
                .insert_grant(&plexus_core::GrantInput {
                    grant_id: grant_id.into(),
                    principal: "direct".into(),
                    connection_id: "conn-mcp".into(),
                    grantee_principal: "direct".into(),
                    risk_ceiling: "write".into(),
                    action_selectors: vec!["held_write".into()],
                    authority_kind: kind.into(),
                    expires_at: None,
                })
                .unwrap();
        }
    }
    let transport = Arc::new(plexus_core::MockTransport::default());
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: ModuleRuntime::with_stub_credentials_and_mock_transport(
            Arc::clone(&store),
            Arc::new(StubCredentialSource::with_default_success(
                b"unused".to_vec(),
            )),
            Arc::clone(&transport),
        ),
    });
    McpWriteFixture {
        scratch,
        state,
        transport,
    }
}

impl McpWriteFixture {
    /// Age the catalog past every staleness bound, so the next write's
    /// freshness check must refresh it from the vendor.
    fn age_catalog(&self) {
        rusqlite::Connection::open(self.scratch.path())
            .unwrap()
            .execute("UPDATE catalog_actions SET last_seen_at_ms = 0", [])
            .unwrap();
    }

    fn invoke(&self) -> Value {
        let object = json!({"name":"invoke","arguments":{"op":"call",
                "connection":"conn-mcp","action":"held_write","args":{"team":"plexus"}}});
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            wire::control_flags(),
            2,
            1,
            8,
            serde_json::to_vec(&object).unwrap(),
        )
        .unwrap();
        let routes = Arc::new(RouteBindings::new());
        routes.insert(2, 1, Principal::Direct).unwrap();
        facade_tool_reply(&frame, object.as_object().unwrap(), &self.state, &routes)
            .expect("a reply")
    }

    fn audit_rows(&self, gate: &str) -> i64 {
        rusqlite::Connection::open(self.scratch.path())
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM audit_journal WHERE gate = ?1 AND actor = 'direct'",
                [gate],
                |row| row.get(0),
            )
            .unwrap()
    }
}

/// A caller without a grant causes no vendor contact at all: the freshness
/// check, whose catalog refresh is an MCP `tools/list` call, runs only
/// after authorization. The vendor counts every connection it receives
/// and closes it at once, so a refresh fails fast instead of waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ungranted_write_causes_no_vendor_contact() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let vendor = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    vendor.set_nonblocking(true).unwrap();
    let url = format!("http://{}/mcp", vendor.local_addr().unwrap());
    let contacts = Arc::new(AtomicUsize::new(0));
    let running = Arc::new(AtomicBool::new(true));
    let counter = {
        let contacts = Arc::clone(&contacts);
        let running = Arc::clone(&running);
        std::thread::spawn(move || {
            while running.load(Ordering::Acquire) {
                match vendor.accept() {
                    Ok((stream, _)) => {
                        contacts.fetch_add(1, Ordering::SeqCst);
                        drop(stream);
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                }
            }
        })
    };
    let fixture = mcp_write_fixture("freshness-ungranted", &url, false, false);
    fixture.age_catalog();
    let reply = blocking_section(|| fixture.invoke());
    running.store(false, Ordering::Release);
    let _ = counter.join();
    let code = reply["error"]["code"].as_str().unwrap_or_default();
    assert!(
        !code.is_empty() && code != "freshness_check_failed" && code != "catalog_stale_write",
        "an ungranted write must get its authorization refusal: {reply}"
    );
    assert_eq!(
        contacts.load(Ordering::SeqCst),
        0,
        "an ungranted write must cause zero vendor requests"
    );
    assert_eq!(fixture.transport.requests().len(), 0);
}

/// A granted write whose tool schema changed at the vendor is caught by
/// the freshness refresh (run after authorization, audited under the
/// caller) and not sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_granted_write_whose_schema_changed_is_not_sent() {
    let mut changed = write_schema();
    changed["properties"]["title"] = json!({"type": "string"});
    let vendor = plexus_conformance::stub_server::StubMcpServer::start(vec![
        plexus_conformance::stub_server::StubTool::new("held_write", changed),
    ])
    .expect("stub MCP vendor");
    let fixture = mcp_write_fixture("freshness-schema-changed", vendor.endpoint(), false, true);
    fixture.age_catalog();
    let reply = blocking_section(|| fixture.invoke());
    assert_eq!(
        reply["result"]["transmission"], "not_sent",
        "a write whose schema changed must not be sent: {reply}"
    );
    assert_eq!(fixture.transport.requests().len(), 0, "{reply}");
    assert_eq!(
        fixture.audit_rows("freshness"),
        1,
        "the refresh that reached the vendor is audited under the caller"
    );
}

/// An approved request runs the same freshness check when it executes: a
/// schema that changed while the request waited for approval stops it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approved_write_whose_schema_changed_while_waiting_is_not_sent() {
    let mut changed = write_schema();
    changed["properties"]["title"] = json!({"type": "string"});
    let vendor = plexus_conformance::stub_server::StubMcpServer::start(vec![
        plexus_conformance::stub_server::StubTool::new("held_write", changed),
    ])
    .expect("stub MCP vendor");
    let fixture = mcp_write_fixture("freshness-approved", vendor.endpoint(), true, true);
    // A tool call over a route with no session scope cannot file a consent
    // card, so it can't create this held approval. Hold it through
    // internal authorization; only the operator can then approve it.
    let request_id = match fixture
        .state
        .runtime
        .engine
        .authorize(AuthorizationRequest::new(
            "direct",
            "conn-mcp",
            "held_write",
            json!({"team":"plexus"}),
        )) {
        Err(plexus_core::Denial::ActionRequestCreated { request_id }) => request_id,
        other => panic!("operator approval was not parked: {other:?}"),
    };
    // Time passes while it waits: the catalog is now past its bound.
    fixture.age_catalog();
    let outcome = blocking_section(|| {
        fixture
            .state
            .runtime
            .engine
            .approve_request("direct", &request_id, "direct")
    })
    .expect("approval is accepted");
    assert_eq!(
        outcome.transmission,
        plexus_core::TransmissionState::NotSent,
        "an approved write whose schema changed while it waited must not be sent: {outcome:?}"
    );
    assert_eq!(fixture.transport.requests().len(), 0);
}

/// When the ids still unacknowledged cannot be read, a partial ack is an
/// error naming the committed count, never `"unacked": []`, which would
/// claim every event was acknowledged.
#[test]
fn a_partial_ack_whose_unacked_read_fails_is_an_error() {
    let failed = partial_ack_reply(2, Err::<Vec<String>, _>("store unavailable"));
    assert_eq!(
        failed["error"]["code"], "store_failure",
        "an unreadable unacked list must be an error, not an empty list: {failed}"
    );
    assert_eq!(failed["error"]["acked"], 2, "{failed}");
    assert!(failed.get("result").is_none(), "{failed}");
    let read = partial_ack_reply(2, Ok::<_, String>(vec!["event-3".to_string()]));
    assert_eq!(read["result"]["unacked"], json!(["event-3"]), "{read}");
}

/// A write whose freshness check cannot run (here the connection's
/// credential cannot be resolved) is refused after authorization: a caller
/// without a grant gets its grant refusal and learns nothing about the
/// target, and a granted caller gets `freshness_check_failed` as not sent,
/// audited as a pre-dispatch refusal, with nothing dispatched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_whose_freshness_check_cannot_run_is_not_sent() {
    let path = Scratch::database("freshness-check-failed");
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: path.to_string_lossy().into_owned(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    // Authorize `held_write` with an ordinary grant: the manifest's lowest
    // app tier makes this write too low-severity to need the separate
    // approval service. The pre-write catalog check then stops because the
    // manifest requires a credential but the source resolves none. Report
    // a credential failure, not a stale catalog or missing transport.
    // Configure the `team` filter to permit writes within that team, and
    // redeem a binding ticket to attach the credential reference.
    store
        .upsert_manifest(
            "system",
            &crate::test_write_manifest("credentialed", "https://vendor.invalid/mcp"),
        )
        .unwrap();
    store
        .insert_connection(
            "direct",
            "conn-keep-rest",
            "credentialed",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": ["team"]}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", "conn-keep-rest", b"test:freshness-handle")
        .expect("ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("connect")
        .expect("connection activates");
    // A stub with no responses resolves no credential at all.
    let transport = Arc::new(plexus_core::MockTransport::default());
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: ModuleRuntime::with_stub_credentials_and_mock_transport(
            Arc::clone(&store),
            Arc::new(StubCredentialSource::default()),
            Arc::clone(&transport),
        ),
    });
    let schema = json!({"type": "object"});
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: "conn-keep-rest".to_string(),
            principal: "direct".to_string(),
            name: "held_write".to_string(),
            title: None,
            schema: schema.clone(),
            schema_hash: plexus_core::jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
            risk: "write".to_string(),
            // The column holds the app's tier, as the catalog seed writes it.
            severity: "S1".to_string(),
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
            ask_first: false,
        })
        .expect("seed write action");
    // Set the connection's catalog rows as last seen at time zero, so the
    // catalog is stale.
    // A stale catalog makes the pre-write check rediscover the vendor's
    // actions, which needs the credential this fixture cannot resolve, so
    // the write is refused as `catalog_stale_write`. With a fresh catalog
    // the check would pass without a credential, and the call would fail
    // later, at the credential lookup before dispatch, which is not what
    // this test is about.
    let db = rusqlite::Connection::open(path.path()).unwrap();
    assert!(
        db.execute(
            "UPDATE catalog_actions SET last_seen_at_ms=0 WHERE connection_id='conn-keep-rest'",
            []
        )
        .unwrap()
            > 0
    );
    let object = json!({"name":"invoke","arguments":{"op":"call",
            "connection":"conn-keep-rest","action":"held_write","args":{"team":"plexus"}}});
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        wire::control_flags(),
        2,
        1,
        8,
        serde_json::to_vec(&object).unwrap(),
    )
    .unwrap();
    let routes = Arc::new(RouteBindings::new());
    routes.insert(2, 1, Principal::Direct).unwrap();
    let invoke = || {
        facade_tool_reply(&frame, object.as_object().unwrap(), &state, &routes).expect("a reply")
    };

    let ungranted = invoke();
    let code = ungranted["error"]["code"].as_str().unwrap_or_default();
    assert!(
        !code.is_empty() && code != "catalog_stale_write",
        "an ungranted caller must get its authorization refusal: {ungranted}"
    );

    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "grant-held-write".into(),
            principal: "direct".into(),
            connection_id: "conn-keep-rest".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "write".into(),
            action_selectors: vec!["held_write".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .expect("grant");
    let granted = invoke();
    assert_eq!(
        granted["result"]["transmission"], "not_sent",
        "a write whose freshness check cannot run must not be sent: {granted}"
    );
    assert_eq!(
        granted["result"]["response"]["code"], "catalog_stale_write",
        "a write whose freshness check cannot run must not be sent: {granted}"
    );
    let db = rusqlite::Connection::open(path.path()).unwrap();
    let count = |reason: &str| -> i64 {
        db.query_row(
            "SELECT COUNT(*) FROM audit_journal WHERE action = 'held_write' AND reason_code = ?1",
            [reason],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert!(count("catalog_stale_write") >= 1, "the refusal is audited");
    assert_eq!(count("dispatched"), 0, "nothing was dispatched");
    assert_eq!(
        transport.requests().len(),
        0,
        "nothing reached the transport"
    );
}

/// A connect whose catalog seed fails reports degraded discovery with the
/// reason, never `complete`: the connection is active but its reviewed
/// actions were not stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_catalog_seed_is_reported_as_degraded_discovery() {
    let (path, store, state) = two_connection_fixture("connect-seed-error");
    let app_key = store
        .connection("direct", "conn-keep-rest")
        .unwrap()
        .expect("fixture connection")
        .app_key;
    store
        .insert_connection("direct", "conn-seed", &app_key, "pending", &json!({}))
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", "conn-seed", b"test:seed-handle")
        .expect("ticket");
    rusqlite::Connection::open(path.path())
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER refuse_seed BEFORE INSERT ON catalog_actions
                 WHEN NEW.connection_id = 'conn-seed'
                 BEGIN SELECT RAISE(ABORT, 'catalog table unavailable'); END;",
        )
        .unwrap();
    let object = json!({"name":"connections","arguments":{"op":"connect",
            "ticket_id": ticket.ticket_id}});
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        wire::control_flags(),
        2,
        1,
        8,
        serde_json::to_vec(&object).unwrap(),
    )
    .unwrap();
    let routes = Arc::new(RouteBindings::new());
    routes.insert(2, 1, Principal::Direct).unwrap();
    let reply =
        facade_tool_reply(&frame, object.as_object().unwrap(), &state, &routes).expect("a reply");
    assert_eq!(
        reply["result"]["discovery"], "degraded",
        "a failed seed must report degraded discovery: {reply}"
    );
    assert!(
        reply["result"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("seeded")),
        "a failed seed must report degraded discovery with the seed as its reason: {reply}"
    );
}

/// `blocking_section` must not panic on a current-thread runtime, where
/// `block_in_place` is unavailable; it runs the work inline there.
#[test]
fn blocking_section_runs_on_a_current_thread_runtime() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    let answer = runtime.block_on(async { blocking_section(|| 41 + 1) });
    assert_eq!(answer, 42);
    // Outside any runtime it runs inline too.
    assert_eq!(blocking_section(|| 7), 7);
}

/// Shutdown waits a bounded time for a signalled task, then aborts it, so
/// a task that never stops cannot hold the module open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_aborts_a_task_that_does_not_stop_within_its_grace() {
    let stuck = tokio::spawn(std::future::pending::<()>());
    let abort = stuck.abort_handle();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stop_task("stuck", stuck, std::time::Duration::from_millis(50)),
    )
    .await
    .expect("stop_task must return once the grace has passed");
    // Cancellation lands when the runtime next polls the task.
    for _ in 0..100 {
        if abort.is_finished() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(abort.is_finished(), "the stuck task must be aborted");
}

/// Send one management call bound as `principal` and return its response
/// body through the same management handler the admin client uses.
fn management_call(
    state: &Arc<ModuleState>,
    principal: Principal,
    method: &str,
    params: Value,
) -> Value {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("management test runtime");
    runtime.block_on(async {
        let (writer, mut responses) = mpsc::channel(4);
        let bindings = Arc::new(RouteBindings::new());
        let route = RouteFrameContext {
            version: PROTOCOL_VERSION,
            channel: 5,
            epoch: 2,
            correlation: 91,
        };
        bindings
            .insert(route.channel, route.epoch, principal)
            .expect("bind principal");
        confirmed_management_request(route, method, &params, &writer, state, &bindings)
            .await
            .expect("management request receives a response");
        let frame = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "management response",
        )
        .await;
        serde_json::from_slice(&frame.body).expect("management response JSON")
    })
}

async fn confirmed_management_request(
    route: RouteFrameContext,
    method: &str,
    params: &Value,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    let (proxy, requests) = mpsc::channel(4);
    let (result, ()) = tokio::join!(
        handle_management_request(route, method, params, &proxy, state, bindings),
        operator_confirmation::approving_test_peer(requests, writer, &bindings.control_replies),
    );
    result
}

/// Create a file-backed store with two active REST connections owned by
/// `direct` and no credential bindings. Credential checks cannot resolve
/// credentials for either connection and log a failure on each pass while
/// that connection remains active.
fn two_connection_fixture(
    label: &str,
) -> (DiagnosticStorePath, Arc<PlexusStore>, Arc<ModuleState>) {
    two_connection_fixture_with_retire_status(label, "active")
}

// `retire_status` is the status of `conn-retire-rest`; `conn-keep-rest` is
// always active. The credential-rebind tests pass "pending" because they
// redeem a binding ticket for `conn-retire-rest`, which needs a pending
// connection. The missing-credential health tests use the default, both
// connections active, through `two_connection_fixture`.
fn two_connection_fixture_with_retire_status(
    label: &str,
    retire_status: &str,
) -> (DiagnosticStorePath, Arc<PlexusStore>, Arc<ModuleState>) {
    let path = DiagnosticStorePath::new(label);
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: path.to_string_lossy().into_owned(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    if !path.is_prepared() {
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/exa_rest.jsonc"),
        )
        .unwrap();
        let ingested = plexus_core::ingest_value(
            serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap(),
        )
        .unwrap();
        store.upsert_manifest("system", &ingested).unwrap();
        for id in ["conn-retire-rest", "conn-keep-rest"] {
            store
                .insert_connection(
                    "direct",
                    id,
                    &ingested.manifest.key,
                    if id == "conn-retire-rest" {
                        retire_status
                    } else {
                        "active"
                    },
                    &json!({}),
                )
                .unwrap();
        }
    }
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    (path, store, state)
}

mod credential_rebind {
    include!("credential_rebind_tests.rs");
}

mod operator_confirmation_tests {
    include!("operator_confirmation_tests.rs");
}

fn delete_audit_rows(path: &Path, connection_id: &str) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM audit_journal
                 WHERE reason_code = 'ceremony_delete_connection' AND connection_id = ?1",
            [connection_id],
            |row| row.get(0),
        )
        .unwrap()
}

fn all_audit_rows(path: &Path, connection_id: &str) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM audit_journal WHERE connection_id = ?1",
            [connection_id],
            |row| row.get(0),
        )
        .unwrap()
}

fn connection_status(store: &PlexusStore, connection_id: &str) -> String {
    store
        .connection("direct", connection_id)
        .unwrap()
        .expect("connection row exists")
        .status
}

fn connection_exists(store: &PlexusStore, connection_id: &str) -> bool {
    store.connection("direct", connection_id).unwrap().is_some()
}

fn delete_params(connection_id: &str, apply: bool) -> Value {
    json!({"connection_id": connection_id, "dry_run": !apply})
}

/// Revokes one of the two fixture connections, then runs one
/// health-probe pass. Its stderr is read by
/// `a_revoked_connection_is_neither_probed_nor_logged`.
#[test]
fn revoke_then_probe_fixture() {
    if !diagnostic_child() {
        return;
    }
    let (path, store, state) = two_connection_fixture("revoke-probe");
    assert!(store
        .revoke_connection("direct", "conn-retire-rest")
        .unwrap());
    run_health_probes(&state);
    assert_eq!(
        connection_status(&store, "conn-retire-rest"),
        "revoked",
        "a probe pass must not bring a revoked connection back"
    );
    drop(state);
    drop(store);
    std::fs::remove_file(path).unwrap();
}

/// A revoked connection is neither probed nor logged by the next health
/// pass. The connection left active beside it IS logged in the same pass,
/// so a quiet stderr cannot come from a probe that never ran or a log
/// that was never captured.
#[test]
fn a_revoked_connection_is_neither_probed_nor_logged() {
    let stderr = module_diagnostic_output("tests::revoke_then_probe_fixture");
    assert!(
        stderr.contains("health probe failed for principal direct, connection conn-keep-rest"),
        "the active sibling must still be probed and logged: {stderr}"
    );
    assert!(
        !stderr.contains("conn-retire-rest"),
        "a revoked connection must not be probed or logged: {stderr}"
    );
}

/// A live grant makes the delete fail with `connection_has_live_grants`
/// and leaves the connection untouched; an expired grant does not count
/// and is deleted with the connection. Revoking the live grant first is
/// what lets the delete go through.
#[test]
fn delete_connection_refuses_while_a_grant_is_live_and_changes_nothing() {
    let (path, store, state) = two_connection_fixture("delete-live-grant");
    for (grant_id, expires_at) in [("g-live", None), ("g-expired", Some(1))] {
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: grant_id.into(),
                principal: "direct".into(),
                connection_id: "conn-retire-rest".into(),
                grantee_principal: "reserved:aft".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["*".into()],
                authority_kind: "invoke".into(),
                expires_at,
            })
            .unwrap();
    }
    let generation = store
        .connection("direct", "conn-retire-rest")
        .unwrap()
        .unwrap()
        .generation;
    let refused = management_call(
        &state,
        Principal::Direct,
        manifest::ADMIN_DELETE_CONNECTION_OP,
        delete_params("conn-retire-rest", true),
    );
    // The code is the fixed string `connection_has_live_grants`, so a
    // script can match it exactly; the number of grants is a separate field.
    assert_eq!(
        refused["error"]["code"], "connection_has_live_grants",
        "{refused}"
    );
    assert_eq!(refused["error"]["count"], 1, "{refused}");
    let after = store
        .connection("direct", "conn-retire-rest")
        .unwrap()
        .unwrap();
    assert_eq!(after.status, "active");
    assert_eq!(after.generation, generation);
    assert_eq!(delete_audit_rows(&path, "conn-retire-rest"), 0);

    let revoked = management_call(
        &state,
        Principal::Direct,
        manifest::ADMIN_REVOKE_GRANT_OP,
        json!({"grant_id": "g-live"}),
    );
    assert_eq!(revoked["result"]["revoked"], true, "{revoked}");
    let deleted = management_call(
        &state,
        Principal::Direct,
        manifest::ADMIN_DELETE_CONNECTION_OP,
        delete_params("conn-retire-rest", true),
    );
    assert_eq!(deleted["result"]["outcome"], "deleted", "{deleted}");
    assert_eq!(deleted["result"]["rows"]["grants"], 1, "{deleted}");
    assert!(!connection_exists(&store, "conn-retire-rest"));
    assert_eq!(delete_audit_rows(&path, "conn-retire-rest"), 1);
    drop(state);
    drop(store);
    std::fs::remove_file(path).unwrap();
}

/// `list_grants` honours `connection_id`, and the revoke and remove-policy
/// audit rows name what was removed: the connection, the grant's ceiling
/// or the policy's effect, and the id.
#[test]
fn list_grants_filters_by_connection_and_removals_audit_their_target() {
    let (path, store, state) = two_connection_fixture("grant-list-audit");
    for (grant_id, connection_id, risk) in [
        ("g-retire", "conn-retire-rest", "read"),
        ("g-keep", "conn-keep-rest", "write"),
    ] {
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: grant_id.into(),
                principal: "direct".into(),
                connection_id: connection_id.into(),
                grantee_principal: "reserved:aft".into(),
                risk_ceiling: risk.into(),
                action_selectors: vec!["*".into()],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
    }
    let listed = management_call(
        &state,
        Principal::Direct,
        manifest::ADMIN_LIST_GRANTS_OP,
        json!({"connection_id": "conn-keep-rest"}),
    );
    let ids: Vec<&str> = listed["result"]["grants"]
        .as_array()
        .expect("grants")
        .iter()
        .filter_map(|grant| grant["grant_id"].as_str())
        .collect();
    assert_eq!(
        ids,
        vec!["g-keep"],
        "list_grants must narrow to the named connection: {listed}"
    );

    let revoked = management_call(
        &state,
        Principal::Direct,
        manifest::ADMIN_REVOKE_GRANT_OP,
        json!({"grant_id": "g-keep"}),
    );
    assert_eq!(revoked["result"]["revoked"], true, "{revoked}");
    let policy = management_call(
        &state,
        Principal::Direct,
        manifest::ADMIN_SET_POLICY_OP,
        json!({"connection_id": "conn-keep-rest", "action_selector": "*", "effect": "block"}),
    );
    let policy_id = policy["result"]["policy"]["policy_id"]
        .as_str()
        .unwrap_or_else(|| panic!("policy id: {policy}"))
        .to_string();
    let removed = management_call(
        &state,
        Principal::Direct,
        manifest::ADMIN_REMOVE_POLICY_OP,
        json!({"policy_id": policy_id}),
    );
    assert_eq!(removed["result"]["removed"], true, "{removed}");

    let db = rusqlite::Connection::open(path.path()).unwrap();
    let row = |reason: &str| -> (Option<String>, Option<String>, Option<String>) {
        db.query_row(
            "SELECT connection_id, risk, args_redaction_summary FROM audit_journal
                 WHERE reason_code = ?1",
            [reason],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
    };
    assert_eq!(
        row("ceremony_revoke_grant"),
        (
            Some("conn-keep-rest".into()),
            Some("write".into()),
            Some("grant g-keep revoked".into())
        ),
        "the revoke audit row must name the grant"
    );
    assert_eq!(
        row("ceremony_remove_policy"),
        (
            Some("conn-keep-rest".into()),
            None,
            Some(format!("policy {policy_id} removed; effect=block"))
        ),
        "policy effects belong in the audit summary, never the risk column"
    );
}

/// The normal path: revoke the connection, then delete it. A dry run
/// reports the plan and writes nothing. The apply deletes the connection
/// and writes one audit row. It keeps the audit rows that already existed,
/// including one old enough for the audit delete trigger to allow
/// removing, so the test shows the delete itself skips audit rows. A
/// repeat finds nothing. An unknown connection is refused with
/// `connection_not_found`.
#[test]
fn delete_connection_dry_run_writes_nothing_and_the_apply_keeps_the_audit_trail() {
    let (path, store, state) = two_connection_fixture("delete-dry-run");
    assert!(store
        .revoke_connection("direct", "conn-retire-rest")
        .unwrap());
    rusqlite::Connection::open(&*path)
        .unwrap()
        .execute(
            "INSERT INTO audit_journal (ts, principal, actor, acting_principal,
                     connection_id, decision, reason_code)
                 VALUES (1, 'direct', 'agent', 'direct', 'conn-retire-rest', 'allow', 'invoke')",
            [],
        )
        .unwrap();
    let planned = management_call(
        &state,
        Principal::Direct,
        manifest::ADMIN_DELETE_CONNECTION_OP,
        json!({"connection_id": "conn-retire-rest"}),
    );
    assert_eq!(planned["result"]["outcome"], "would_delete", "{planned}");
    assert_eq!(planned["result"]["status"], "revoked", "{planned}");
    assert_eq!(planned["result"]["dry_run"], true, "{planned}");
    assert!(connection_exists(&store, "conn-retire-rest"));
    assert_eq!(all_audit_rows(&path, "conn-retire-rest"), 1);

    let applied = management_call(
        &state,
        Principal::Direct,
        manifest::ADMIN_DELETE_CONNECTION_OP,
        delete_params("conn-retire-rest", true),
    );
    assert_eq!(applied["result"]["outcome"], "deleted", "{applied}");
    assert!(!connection_exists(&store, "conn-retire-rest"));
    assert_eq!(delete_audit_rows(&path, "conn-retire-rest"), 1);
    assert_eq!(
        all_audit_rows(&path, "conn-retire-rest"),
        2,
        "the delete must keep the audit rows the connection already had"
    );
    assert_eq!(connection_status(&store, "conn-keep-rest"), "active");

    for connection in ["conn-retire-rest", "conn-missing-rest"] {
        let unknown = management_call(
            &state,
            Principal::Direct,
            manifest::ADMIN_DELETE_CONNECTION_OP,
            delete_params(connection, true),
        );
        assert_eq!(
            unknown["error"]["code"], "connection_not_found",
            "{connection}: {unknown}"
        );
    }
    assert_eq!(delete_audit_rows(&path, "conn-retire-rest"), 1);
    drop(state);
    drop(store);
    std::fs::remove_file(path).unwrap();
}

/// A GitHub App handle's connection is created and ended with its
/// handle, so the delete refuses it and writes nothing.
#[test]
fn delete_connection_refuses_a_github_handle_connection() {
    let (path, store, state) = two_connection_fixture("delete-handle");
    let app_key = store
        .connection("direct", "conn-retire-rest")
        .unwrap()
        .unwrap()
        .app_key;
    store
        .insert_connection("direct", "github-handle-h1", &app_key, "active", &json!({}))
        .unwrap();
    let refused = management_call(
        &state,
        Principal::Direct,
        manifest::ADMIN_DELETE_CONNECTION_OP,
        delete_params("github-handle-h1", true),
    );
    assert_eq!(
        refused["error"]["code"], "connection_is_github_handle",
        "{refused}"
    );
    assert!(connection_exists(&store, "github-handle-h1"));
    assert_eq!(delete_audit_rows(&path, "github-handle-h1"), 0);
    drop(state);
    drop(store);
    std::fs::remove_file(path).unwrap();
}

/// Only a direct principal may delete a connection; a supervised module
/// is refused before anything is read or written.
#[test]
fn delete_connection_refuses_a_non_direct_caller() {
    let (path, store, state) = two_connection_fixture("delete-non-direct");
    let denied = management_call(
        &state,
        Principal::Reserved {
            module_id: "aft".to_string(),
        },
        manifest::ADMIN_DELETE_CONNECTION_OP,
        delete_params("conn-retire-rest", true),
    );
    assert_eq!(
        denied["error"]["code"], "operator_authority_required",
        "{denied}"
    );
    assert!(connection_exists(&store, "conn-retire-rest"));
    assert_eq!(delete_audit_rows(&path, "conn-retire-rest"), 0);
    drop(state);
    drop(store);
    std::fs::remove_file(path).unwrap();
}

/// Capture the actual stderr of an isolated test process, not a formatting proxy.
use crate::test_logging as logging;

/// Whether this process is the child a diagnostic parent test spawned,
/// with its stderr logging set up. A `*_fixture` test exists to be run and
/// observed from its parent; in the ordinary run it returns at once rather
/// than repeat, unobserved, the scenario the child runs anyway.
fn diagnostic_child() -> bool {
    logging::init_child();
    std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some()
}

fn module_diagnostic_output(test: &str) -> String {
    // Cold migrations and fixture imports can stall on shared storage. They
    // are not log-observation work; prepare them before timing the child.
    // Keep the scratch owner alive until the child has closed the database.
    let prepared = match test {
            "tests::health_probe_listing_error_fixture"
            | "tests::health_probe_connection_error_fixture"
            | "tests::health_probe_principals_error_fixture" => {
                Some(DiagnosticStorePath::Owned(prepare_health_probe_fixture()))
            }
            "tests::health_probe_imported_handle_fixture"
            | "tests::health_probe_imported_handle_degraded_fixture" => {
                Some(DiagnosticStorePath::Owned(prepare_imported_handle_probe_fixture()))
            }
            "tests::selection_log_fixture" => Some(DiagnosticStorePath::Owned(prepare_selection_fixture())),
            "tests::revoke_then_probe_fixture" | "tests::route_capacity_log_fixture" => {
                let (path, store, state) = two_connection_fixture("diagnostic-connections");
                drop(state);
                drop(store);
                Some(path)
            }
            "tests::credential_rebind::reference_binding_log_fixture"
            | "tests::credential_rebind::reference_dispatch_rejects_mismatched_resolved_id_without_sending_or_leaking"
            | "tests::credential_rebind::rebind_rejects_mismatched_resolved_id_without_mutating_or_leaking" => Some(credential_rebind::prepare_log_fixture()),
            _ => None,
        };
    let mut command = std::process::Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", test, "--nocapture"])
        .env("PLEXUS_LOG_STDERR_CHILD", "1");
    if let Some(scratch) = &prepared {
        command.env(PREPARED_DIAGNOSTIC_STORE, scratch.path());
    }
    let output = bounded::child_output(
        &mut command,
        std::time::Duration::from_secs(30),
        "module diagnostic test child",
    )
    .expect("run diagnostic fixture");
    assert!(
        output.status.success(),
        "fixture {test} failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    crate::test_support::assert_exactly_one_test_passed(test, &output);
    String::from_utf8(output.stderr).expect("UTF-8 stderr")
}

#[test]
fn route_capacity_log_fixture() {
    if !diagnostic_child() {
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (_scratch, _store, state) = two_connection_fixture("route-capacity-log");
            let routes = Arc::new(RouteBindings::new());
            for channel in 10..(10 + MAX_ROUTE_BINDINGS as u16) {
                routes.insert(channel, 1, Principal::Direct).unwrap();
            }
            let (writer, mut responses) = mpsc::channel(4);
            for _ in 0..3 {
                handle_control_request(bind(Some(Principal::Direct)), &writer, &state, &routes)
                    .await
                    .unwrap();
                let reply = recv_within(
                    responses.recv(),
                    std::time::Duration::from_secs(5),
                    "route capacity refusal",
                )
                .await;
                assert_eq!(reply.header.ty, FrameType::Error);
                let body: Value = serde_json::from_slice(&reply.body).unwrap();
                assert_eq!(body["code"], "resource_exhausted");
            }
            assert_eq!(routes.inner.read().unwrap().len(), MAX_ROUTE_BINDINGS);
        });
}

#[test]
fn route_capacity_refusals_emit_one_warning_per_period() {
    let stderr = module_diagnostic_output("tests::route_capacity_log_fixture");
    assert_eq!(
        stderr.matches("route binding capacity exhausted").count(),
        1,
        "cap pressure must emit exactly one warning per minute: {stderr}"
    );
}

#[test]
fn diagnostic_shadow_fixture() {
    if !diagnostic_child() {
        return;
    }
    eprintln!(warn wire: "diagnostic_shadow_probe");
}

#[test]
fn diagnostic_shadow_writes_fleet_attribution_to_real_stderr() {
    let stderr = module_diagnostic_output("tests::diagnostic_shadow_fixture");
    let lines: Vec<_> = stderr
        .lines()
        .filter(|line| line.contains("diagnostic_shadow_probe"))
        .collect();
    assert_eq!(lines.len(), 1, "{stderr}");
    logging::assert_diagnostic(
        lines[0],
        cortexkit_log::ParsedLevel::Warn,
        "plexus.wire",
        "diagnostic_shadow_probe",
    );
}

fn bind(principal: Option<Principal>) -> Frame {
    let request = ModuleControlRequest::RouteBind {
        scope: None,
        call_mode: None,
        role_versions: None,
        route_channel: 4,
        epoch: 2,
        target: RouteTarget::ToolProvider {
            module_id: DEFAULT_MODULE_ID.to_string(),
        },
        identity: BindIdentity::new("/tmp/project", "test".to_string(), "session".to_string()),
        principal,
        consumer_capabilities: None,
        admission_facts: None,
    };
    Frame::build(
        FrameType::Request,
        wire::control_flags(),
        0,
        0,
        7,
        serde_json::to_vec(&request).expect("serialize bind"),
    )
    .expect("build bind frame")
}

/// The boot ingest retires a manifest whose file has been removed from the
/// catalog directory.
///
/// This is the CALL-SITE test for the retirement sweep. The store method has
/// its own tests in plexus-core, and those pass whether or not anything
/// invokes it -- a correct mechanism nobody calls is indistinguishable from
/// an absent one, and this sweep's whole purpose is to run on every boot.
///
/// Driven through two real ingests against a temporary directory with a file
/// deleted in between, because that is what a catalog sync actually does.
///
/// Mutation-proved: discarding the sweep's result at the call site, leaving
/// the store method itself untouched, fails this on the listing.
#[test]
fn the_boot_ingest_retires_a_withdrawn_manifest() {
    let unique = format!("{}-{}", std::process::id(), plexus_core::now_ms());
    let directory = Scratch::directory("retire");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
    for name in ["deepwiki.jsonc", "tavily.jsonc"] {
        std::fs::copy(source.join(name), directory.join(name)).expect("seed manifest");
    }

    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: format!("retire-{unique}"),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: directory.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).expect("test store");

    ingest_catalog_from(&store, &directory).expect("first ingest");
    let before: Vec<String> = store
        .list_manifest_summaries("direct")
        .expect("list manifests")
        .into_iter()
        .map(|summary| summary.key)
        .collect();
    assert_eq!(before, vec!["deepwiki".to_string(), "tavily".to_string()]);

    // What a catalog sync that drops a vendor looks like on disk.
    std::fs::remove_file(directory.join("tavily.jsonc")).expect("withdraw manifest");
    ingest_catalog_from(&store, &directory).expect("second ingest");

    let after: Vec<String> = store
        .list_manifest_summaries("direct")
        .expect("list manifests")
        .into_iter()
        .map(|summary| summary.key)
        .collect();
    assert_eq!(
        after,
        vec!["deepwiki".to_string()],
        "the withdrawn vendor must stop being offered after a boot ingest"
    );
}

/// The offline check counts each file once: an unreadable manifest is an
/// I/O error and not also a refusal.
#[test]
fn the_catalog_check_counts_an_unreadable_manifest_once() {
    let directory = Scratch::directory("check-tally");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
    std::fs::copy(
        source.join("deepwiki.jsonc"),
        directory.join("deepwiki.jsonc"),
    )
    .expect("seed manifest");
    std::fs::write(directory.join("broken.jsonc"), "{").expect("broken manifest");
    // A directory with the manifest extension cannot be read as a file.
    std::fs::create_dir(directory.join("unreadable.jsonc")).expect("unreadable entry");
    let paths = catalog_paths(&directory).expect("paths");
    assert_eq!(
        tally_catalog(&paths),
        (1, 1, 1),
        "an unreadable manifest is counted once, as an I/O error only"
    );
}

/// A catalog directory with no manifests refuses the boot and retires
/// nothing: an empty or wrong PLEXUS_CATALOG_DIR must not withdraw every
/// vendor the store already serves.
#[test]
fn an_empty_catalog_directory_refuses_the_boot_and_retires_nothing() {
    let unique = format!("{}-{}", std::process::id(), plexus_core::now_ms());
    let directory = Scratch::directory("empty-catalog");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
    std::fs::copy(
        source.join("deepwiki.jsonc"),
        directory.join("deepwiki.jsonc"),
    )
    .expect("seed manifest");
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: format!("empty-catalog-{unique}"),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: directory.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).expect("test store");
    ingest_catalog_from(&store, &directory).expect("first ingest");

    // Reject an existing directory with no manifests, such as one selected
    // by a mistyped `PLEXUS_CATALOG_DIR`. Preserve existing catalog entries
    // rather than retiring them because the selected directory is empty.
    let empty = Scratch::directory("empty-catalog-dir");
    let error = ingest_catalog_from(&store, &empty)
        .expect_err("an empty catalog directory must refuse the boot");
    assert!(error.to_string().contains("no .jsonc manifests"), "{error}");
    let after: Vec<String> = store
        .list_manifest_summaries("direct")
        .expect("list manifests")
        .into_iter()
        .map(|summary| summary.key)
        .collect();
    assert_eq!(
        after,
        vec!["deepwiki".to_string()],
        "nothing may be retired"
    );
}

/// The boot ingest pins reviewed argument schemas on GitHub handle rows
/// that still hold the open placeholder.
///
/// The CALL-SITE test for `pin_handle_placeholder_schemas`: the plexus-core
/// tests of the store method pass whether or not a boot ever calls it, so
/// only a test through the boot ingest proves the pass runs.
#[test]
fn the_boot_ingest_pins_reviewed_schemas_on_placeholder_handle_rows() {
    let unique = format!("{}-{}", std::process::id(), plexus_core::now_ms());
    let directory = Scratch::directory("handle-pin");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
    std::fs::copy(
        source.join("github_rest.jsonc"),
        directory.join("github_rest.jsonc"),
    )
    .expect("seed manifest");
    let path = directory.join("store.db");
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: format!("handle-pin-{unique}"),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).expect("test store");
    let connection = "github-handle-app-fixture";
    store
        .insert_connection("direct", connection, "github_rest", "active", &json!({}))
        .expect("handle connection");
    store
        .put_github_handle(&plexus_core::storage::github_store::GithubHandle {
            app_handle_id: "app-fixture".into(),
            agent_id: "agent-fixture".into(),
            app_id: 1,
            installation_id: None,
            credential_reference: "github_app:app-fixture".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: Some(1),
            connection_principal: "direct".into(),
            connection_id: connection.into(),
        })
        .expect("handle");
    // The first boot adds the handle's missing rows from the manifest.
    ingest_catalog_from(&store, &directory).expect("first ingest");
    let db = rusqlite::Connection::open(&path).expect("raw store");
    // Put every row back on the placeholder, as the old seeder left them.
    let rewound = db
        .execute(
            "UPDATE catalog_actions
                 SET schema_json = '{\"additionalProperties\":true,\"type\":\"object\"}'
                 WHERE connection_id = ?1",
            [connection],
        )
        .expect("rewind rows");
    assert!(rewound > 0);

    ingest_catalog_from(&store, &directory).expect("second ingest");

    let still_open: i64 = db
        .query_row(
            "SELECT count(*) FROM catalog_actions
                 WHERE connection_id = ?1 AND json_extract(schema_json, '$.properties') IS NULL",
            [connection],
            |row| row.get(0),
        )
        .expect("count open rows");
    assert_eq!(
        still_open, 0,
        "every placeholder handle row must hold its reviewed schema after a boot ingest"
    );
}

#[tokio::test]
async fn untrusted_bind_is_default_denied() {
    let (writer, mut responses) = mpsc::channel(4);
    let health = Arc::new(health::HealthState::new());
    let scratch = Scratch::database("untrusted-test");
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: "test-untrusted".to_string(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: scratch.to_string_lossy().into_owned(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));
    let state = Arc::new(ModuleState {
        health,
        runtime: runtime_for_test(store),
    });
    let bindings = Arc::new(RouteBindings::new());
    handle_control_request(
        bind(Some(Principal::Reserved {
            module_id: "subc-mcp".to_string(),
        })),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("handler succeeds");
    let response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "denial response",
    )
    .await;
    assert_eq!(response.header.ty, FrameType::Error);
    let body: ErrorBody = serde_json::from_slice(&response.body).expect("error body");
    assert_eq!(body.code, "principal_denied");
}

/// Schema review changes which catalog action may run, so it must remain on
/// the management route and require the same Direct-principal gate as the
/// other ceremony operations. A facade response alone would not prove either
/// boundary: this drives the management handler's denied and allowed arms,
/// then proves a facade-shaped call cannot name the operation.
#[tokio::test]
async fn review_action_is_management_only_and_requires_a_direct_principal() {
    let (writer, mut responses) = mpsc::channel(4);
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: format!("review-action-gate-{}", plexus_core::now_ms()),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).expect("open test store"));
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: "conn-review".to_string(),
            principal: "direct".to_string(),
            name: "list_issues".to_string(),
            title: Some("list_issues".to_string()),
            schema: json!({"type": "object", "properties": {"since": {"type": "string"}}}),
            schema_hash: "sha256:current".to_string(),
            risk: "read".to_string(),
            severity: "S2".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("seed catalog action");
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    let bindings = Arc::new(RouteBindings::new());
    let route = RouteFrameContext {
        version: PROTOCOL_VERSION,
        channel: 4,
        epoch: 2,
        correlation: 71,
    };
    bindings
        .insert(
            route.channel,
            route.epoch,
            Principal::Reserved {
                module_id: "another-module".to_string(),
            },
        )
        .expect("bind reserved principal");
    handle_management_request(
        route,
        manifest::ADMIN_REVIEW_ACTION_OP,
        &json!({"connection_id": "conn-review", "action": "list_issues"}),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("reserved request receives a response");
    let denied = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "reserved response",
    )
    .await;
    let denied: Value = serde_json::from_slice(&denied.body).expect("reserved response JSON");
    assert_eq!(denied["error"]["code"], "operator_authority_required");

    bindings
        .insert(route.channel, route.epoch, Principal::Direct)
        .expect("bind direct principal");
    handle_management_request(
        route,
        manifest::ADMIN_REVIEW_ACTION_OP,
        &json!({"connection_id": "conn-review", "action": "list_issues"}),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("direct request receives a response");
    let allowed = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "direct response",
    )
    .await;
    let allowed: Value = serde_json::from_slice(&allowed.body).expect("direct response JSON");
    assert_eq!(allowed["result"]["current_schema_hash"], "sha256:current");

    let facade = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route.channel,
        route.epoch,
        72,
        serde_json::to_vec(&json!({
            "name": manifest::ADMIN_REVIEW_ACTION_OP,
            "arguments": {"connection_id": "conn-review", "action": "list_issues"}
        }))
        .expect("serialize facade request"),
    )
    .expect("build facade request");
    handle_tool_request(facade, &writer, &state, &bindings)
        .await
        .expect("facade refusal response");
    let refused = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "facade response",
    )
    .await;
    let refused: Value = serde_json::from_slice(&refused.body).expect("facade response JSON");
    assert_eq!(refused["error"]["code"], "unknown_method");
}

#[tokio::test]
async fn widen_ceiling_is_management_only_and_requires_a_direct_principal() {
    let (writer, mut responses) = mpsc::channel(4);
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.into(),
            storage_namespace: "widen-ceiling-gate".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap(),
    );
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(store),
    });
    let bindings = Arc::new(RouteBindings::new());
    let route = RouteFrameContext {
        version: PROTOCOL_VERSION,
        channel: 4,
        epoch: 2,
        correlation: 71,
    };
    let params = json!({"connection_id":"ci","actions":["get_job"],"dry_run":false});
    for (principal, expected) in [
        (
            Principal::Reserved {
                module_id: "basal".into(),
            },
            "operator_authority_required",
        ),
        (Principal::Direct, "connection_not_found"),
    ] {
        bindings
            .insert(route.channel, route.epoch, principal)
            .unwrap();
        confirmed_management_request(
            route,
            manifest::ADMIN_WIDEN_CEILING_OP,
            &params,
            &writer,
            &state,
            &bindings,
        )
        .await
        .unwrap();
        let response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "widen ceiling response",
        )
        .await;
        let response: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(response["error"]["code"], expected);
    }
    for params in [
        json!({"connection_id":"ci","actions":["get_job"],"dry_run":"false"}),
        json!({"connection_id":"ci","actions":"get_job"}),
        json!({"connection_id":"ci","actions":[1]}),
        json!({"connection_id":"ci","actions":["get_job"],"risk":"write"}),
    ] {
        assert_eq!(
            ceremony::widen_ceiling(&state, "direct", &params)["error"]["code"],
            "invalid_request"
        );
    }
    let facade = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route.channel,
        route.epoch,
        72,
        serde_json::to_vec(&json!({"name":manifest::ADMIN_WIDEN_CEILING_OP,"arguments":params}))
            .unwrap(),
    )
    .unwrap();
    handle_tool_request(facade, &writer, &state, &bindings)
        .await
        .unwrap();
    let refused = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "facade refusal",
    )
    .await;
    let refused: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(refused["error"]["code"], "unknown_method");
}

/// `github.handle.grant` is routed on the management surface, refused for
/// a module principal, and for the operator reaches the grant itself: an
/// unknown handle comes back as the grant's own named refusal, not as an
/// unknown method or a decode failure. The parameters are the shape
/// `ck-plexus-admin handle-grant` sends.
#[tokio::test]
async fn handle_grant_is_a_direct_only_management_op_that_reaches_the_grant() {
    let (writer, mut responses) = mpsc::channel(4);
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: format!("handle-grant-gate-{}", plexus_core::now_ms()),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).expect("open test store"));
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    let bindings = Arc::new(RouteBindings::new());
    let route = RouteFrameContext {
        version: PROTOCOL_VERSION,
        channel: 5,
        epoch: 2,
        correlation: 81,
    };
    let params = json!({"app_handle_id":"app-unknown","actions":["create_issue"],
            "module":"reserved:aft","effect":"allow","dry_run":false});
    bindings
        .insert(
            route.channel,
            route.epoch,
            Principal::Reserved {
                module_id: "aft".to_string(),
            },
        )
        .expect("bind reserved principal");
    confirmed_management_request(
        route,
        manifest::GITHUB_GRANT_OP,
        &params,
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("reserved request receives a response");
    let denied = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "reserved response",
    )
    .await;
    let denied: Value = serde_json::from_slice(&denied.body).expect("reserved response JSON");
    assert_eq!(denied["error"]["code"], "operator_authority_required");

    bindings
        .insert(route.channel, route.epoch, Principal::Direct)
        .expect("bind direct principal");
    confirmed_management_request(
        route,
        manifest::GITHUB_GRANT_OP,
        &params,
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("direct request receives a response");
    let reached = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "direct response",
    )
    .await;
    let reached: Value = serde_json::from_slice(&reached.body).expect("direct response JSON");
    assert_eq!(reached["error"]["code"], "agent_handle_unknown");
    assert_eq!(reached["error"]["detail"]["app_handle_id"], "app-unknown");
}

#[test]
fn handle_poll_grant_unknown_handle_has_a_bare_code_and_detail() {
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: "poll-grant-unknown-handle-detail".into(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".into(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).unwrap());
    let state = ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(store),
    };
    let reply = github_handle_grant(
        &state,
        "direct",
        &json!({"kind":"poll","app_handle_id":"app-unknown",
                "actions":["github.issue.get"],"dry_run":false}),
    );
    assert_eq!(reply["error"]["code"], "agent_handle_unknown");
    assert_eq!(reply["error"]["detail"]["app_handle_id"], "app-unknown");
}

#[tokio::test(flavor = "multi_thread")]
async fn handle_unbind_is_direct_only_and_needs_no_credentials() {
    let (writer, mut responses) = mpsc::channel(4);
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: format!("handle-unbind-gate-{}", plexus_core::now_ms()),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).unwrap());
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(store),
    });
    let bindings = Arc::new(RouteBindings::new());
    let route = RouteFrameContext {
        version: PROTOCOL_VERSION,
        channel: 5,
        epoch: 2,
        correlation: 82,
    };
    let params = json!({"app_handle_id":"unknown", "repository":"org/repo"});
    for (principal, expected) in [
        (
            Principal::Reserved {
                module_id: "aft".into(),
            },
            "operator_authority_required",
        ),
        (Principal::Direct, "agent_handle_unknown"),
    ] {
        bindings
            .insert(route.channel, route.epoch, principal)
            .unwrap();
        handle_management_request(
            route,
            manifest::GITHUB_UNBIND_OP,
            &params,
            &writer,
            &state,
            &bindings,
        )
        .await
        .unwrap();
        let response = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "expected reply",
        )
        .await;
        let response: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(response["error"]["code"], expected);
        if expected == "agent_handle_unknown" {
            assert_eq!(response["error"]["detail"]["app_handle_id"], "unknown");
        }
    }
}

/// Hands out a token for any handle; the bind below refuses an unknown
/// handle before it would be used.
struct AnyHandleToken;
impl plexus_core::github::credential::HandleCredentialProvider for AnyHandleToken {
    fn prepare(
        &self,
        _: &str,
        _: i64,
        reference: &str,
    ) -> Result<plexus_core::credentials::ResolvedCredential, &'static str> {
        Ok(plexus_core::credentials::ResolvedCredential::new(
            reference.as_bytes().to_vec(),
            None,
            1,
        ))
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

/// `github.handle.bind` is routed on the management surface, refused for a
/// module principal, and for the operator reaches the bind itself: an
/// unknown handle comes back as the bind's own named refusal. The
/// parameters are the shape `ck-plexus-admin handle-bind` sends. Multi
/// threaded because the bind runs inside `block_in_place`.
#[tokio::test(flavor = "multi_thread")]
async fn handle_bind_is_a_direct_only_management_op_that_reaches_the_bind() {
    let (writer, mut responses) = mpsc::channel(4);
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: format!("handle-bind-gate-{}", plexus_core::now_ms()),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).expect("open test store"));
    let mut runtime = runtime_for_test(Arc::clone(&store));
    runtime.github_handle_credentials = Some(Arc::new(AnyHandleToken));
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    });
    let bindings = Arc::new(RouteBindings::new());
    let route = RouteFrameContext {
        version: PROTOCOL_VERSION,
        channel: 5,
        epoch: 2,
        correlation: 82,
    };
    let params = json!({"app_handle_id":"app-unknown","repositories":["org/second"],
            "dry_run":false});
    bindings
        .insert(
            route.channel,
            route.epoch,
            Principal::Reserved {
                module_id: "aft".to_string(),
            },
        )
        .expect("bind reserved principal");
    confirmed_management_request(
        route,
        manifest::GITHUB_BIND_OP,
        &params,
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("reserved request receives a response");
    let denied = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "reserved response",
    )
    .await;
    let denied: Value = serde_json::from_slice(&denied.body).expect("reserved response JSON");
    assert_eq!(denied["error"]["code"], "operator_authority_required");

    bindings
        .insert(route.channel, route.epoch, Principal::Direct)
        .expect("bind direct principal");
    confirmed_management_request(
        route,
        manifest::GITHUB_BIND_OP,
        &params,
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("direct request receives a response");
    let reached = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "direct response",
    )
    .await;
    let reached: Value = serde_json::from_slice(&reached.body).expect("direct response JSON");
    assert_eq!(reached["error"]["code"], "agent_handle_unknown");
    assert_eq!(reached["error"]["detail"]["app_handle_id"], "app-unknown");
}

/// Run each GitHub credential operation on a multi-threaded runtime, as the
/// module does, and require a reply. Operations that read the installation
/// must construct, use, and drop their blocking HTTP client in a blocking
/// section, not in an async runtime context. Reqwest can panic there,
/// especially when dropping the client's internal runtime, and end request
/// handling without replying to the operator.
#[tokio::test(flavor = "multi_thread")]
async fn github_handle_ops_answer_from_an_async_worker() {
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: format!("handle-ops-worker-{}", plexus_core::now_ms()),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).expect("open test store"));
    let mut runtime = runtime_for_test(Arc::clone(&store));
    runtime.github_handle_credentials = Some(Arc::new(AnyHandleToken));
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    });
    let bindings = Arc::new(RouteBindings::new());
    let route = RouteFrameContext {
        version: PROTOCOL_VERSION,
        channel: 5,
        epoch: 2,
        correlation: 83,
    };
    bindings
        .insert(route.channel, route.epoch, Principal::Direct)
        .expect("bind direct principal");
    for (method, params) in [
        (
            manifest::GITHUB_IMPORT_OP,
            json!({"inventory":{"version":"1","handles":[]},"dry_run":true}),
        ),
        (
            manifest::GITHUB_PROBE_OP,
            json!({"app_handle_id":"app-unknown"}),
        ),
        (
            manifest::GITHUB_BIND_OP,
            json!({"app_handle_id":"app-unknown","repositories":["org/a"]}),
        ),
    ] {
        let (writer, mut responses) = mpsc::channel(4);
        let served = tokio::spawn({
            let state = Arc::clone(&state);
            let bindings = Arc::clone(&bindings);
            async move {
                handle_management_request(route, method, &params, &writer, &state, &bindings).await
            }
        })
        .await;
        assert!(
            matches!(served, Ok(Ok(()))),
            "{method} must be served without a panic: {served:?}"
        );
        let reply = recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "github handle op response",
        )
        .await;
        let reply: Value = serde_json::from_slice(&reply.body).expect("response JSON");
        assert!(
            reply.get("result").is_some() || reply.get("error").is_some(),
            "{method} must answer: {reply}"
        );
    }
}
