//! Real broker coverage for the shared session. The fake ckbus serves throwaway
//! credentials to any principal; these tests do not cover vault authorization.

use super::*;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use cortexkit_bus_testkit::{
    trust::{box_root_id, signer_root_id, system_root_id, unix_now, TrustChain},
    BusOptions, BusServer, PreloadedAccount,
};
use plexus_core::{
    test_scratch::Scratch,
    web_search::{routing::RouteFactPublisher, WebSearchService},
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const LIMIT: Duration = Duration::from_secs(20);

#[test]
fn cingulate_card_vectors_match_upstream_checksums() {
    use sha2::{Digest, Sha256};
    let sums = include_bytes!("../tests/fixtures/card-settled-v1/SHA256SUMS");
    assert_eq!(
        format!("{:x}", Sha256::digest(sums)),
        "2718117337670cfccd3b5596cd921325ad614ed7347a4780c952fd8344cebc1d"
    );
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/card-settled-v1");
    for line in std::str::from_utf8(sums).unwrap().lines() {
        let (digest, name) = line.split_once("  ").unwrap();
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(std::fs::read(root.join(name)).unwrap())
            ),
            digest,
            "{name}"
        );
    }
}

struct FixtureCredential {
    user: Arc<nkeys::KeyPair>,
    jwt: String,
    url: String,
    ready: Arc<tokio::sync::Notify>,
    issues: Arc<AtomicUsize>,
}
#[async_trait]
impl subc_client_rs::ModuleHandler for FixtureCredential {
    async fn on_hello_ack(&self, _: &subc_protocol::ModuleHelloAckBody) {
        self.ready.notify_one();
    }
    async fn handle(
        &self,
        _: subc_client_rs::RequestCtx,
        body: Vec<u8>,
    ) -> subc_client_rs::HandlerOutcome {
        let body: Value = serde_json::from_slice(&body).unwrap();
        let result = match body["method"].as_str().unwrap() {
            "ckbus.credential" => {
                self.issues.fetch_add(1, Ordering::SeqCst);
                json!({"jwt":self.jwt,"exp":unix_now()+900,"credential_public":self.user.public_key(),"acct":"box_example","server_url":self.url,"inbox_prefix":format!("_INBOX.{}",self.user.public_key())})
            }
            "ckbus.nonce_sign" => {
                json!({"signature_b64":STANDARD.encode(self.user.sign(&STANDARD.decode(body["params"]["nonce_b64"].as_str().unwrap()).unwrap()).unwrap())})
            }
            other => panic!("unexpected credential operation: {other}"),
        };
        subc_client_rs::HandlerOutcome::Response(json!({"result":result}).to_string().into_bytes())
    }
}

struct LiveRig {
    _bus: BusServer,
    _scratch: Scratch,
    daemon: tokio::task::JoinHandle<()>,
    provider: tokio::task::JoinHandle<()>,
    path: PathBuf,
    admin: async_nats::jetstream::Context,
    issues: Arc<AtomicUsize>,
}
impl Drop for LiveRig {
    fn drop(&mut self) {
        self.provider.abort();
        self.daemon.abort();
    }
}

impl LiveRig {
    async fn start(durable: bool) -> Self {
        let scratch = Scratch::directory("shared-bus-live");
        let trust = TrustChain::generate();
        let account = trust.box_root_public();
        let bus = BusServer::start(BusOptions {
            directory: Some(scratch.join("nats")),
            preload: vec![PreloadedAccount {
                public_key: account.clone(),
                signing_keys: vec![account.clone()],
            }],
            trust: Some(trust),
            ..Default::default()
        })
        .await
        .expect("real testkit NATS is required");
        enable_jetstream(&bus, &account).await;
        let user = Arc::new(nkeys::KeyPair::new_user());
        let jwt = bus
            .trust
            .user_jwt(&box_root_id(), &account, &user, unix_now());
        let key = user.clone();
        let client = async_nats::ConnectOptions::with_jwt(jwt.clone(), move |nonce| {
            let key = key.clone();
            async move { key.sign(&nonce).map_err(async_nats::AuthError::new) }
        })
        .connect(&bus.url)
        .await
        .unwrap();
        let admin = async_nats::jetstream::new(client);
        let names = AccountNames::derive("box_example").unwrap();
        let stream = admin
            .create_stream(async_nats::jetstream::stream::Config {
                name: names.streams().event.clone(),
                subjects: vec![names.event_binding()],
                ..Default::default()
            })
            .await
            .unwrap();
        if durable {
            stream
                .create_consumer(async_nats::jetstream::consumer::pull::Config {
                    durable_name: Some(AccountNames::module_consumer_name("plexus").unwrap()),
                    filter_subjects: vec![names
                        .event_subject_with_reader("cingulate", "card_settled", 1, "plexus")
                        .unwrap()],
                    ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let path = scratch.join("connection.json");
        let config_path = scratch.join("daemon.jsonc");
        std::fs::write(&config_path,json!({"version":1,"storage":{"backend":"sqlite","data_home":scratch.join("home")},"modules":{}}).to_string()).unwrap();
        let config = subc_daemon::bootstrap::BootstrapConfig::new(&path, 0)
            .with_capture_logs_dir(scratch.join("logs"))
            .with_daemon_config_path(&config_path)
            .unwrap();
        let daemon = tokio::spawn(async move {
            subc_daemon::bootstrap::run_with_config(config)
                .await
                .unwrap();
        });
        tokio::time::timeout(LIMIT, async {
            while !path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let ready = Arc::new(tokio::sync::Notify::new());
        let issues = Arc::new(AtomicUsize::new(0));
        let credential = FixtureCredential {
            user,
            jwt,
            url: bus.url.clone(),
            ready: ready.clone(),
            issues: issues.clone(),
        };
        let mut manifest = crate::manifest::build("ckbus");
        manifest.provides.retain(|role| {
            matches!(
                role,
                subc_protocol::manifest::ProviderRole::ManagementSurface { .. }
            )
        });
        if let subc_protocol::manifest::ProviderRole::ManagementSurface { operations, .. } =
            &mut manifest.provides[0]
        {
            *operations = ["ckbus.credential", "ckbus.nonce_sign"]
                .into_iter()
                .map(|name| subc_protocol::manifest::ManagementOperation {
                    name: name.into(),
                    kind: subc_protocol::manifest::ManagementOperationKind::Query,
                    description: None,
                })
                .collect();
        }
        let serve_path = path.clone();
        let provider = tokio::spawn(async move {
            subc_client_rs::ServeOptions::default()
                .serve_with(&serve_path, manifest, credential)
                .await
                .unwrap();
        });
        tokio::time::timeout(LIMIT, ready.notified()).await.unwrap();
        Self {
            _scratch: scratch,
            _bus: bus,
            daemon,
            provider,
            path,
            admin,
            issues,
        }
    }
    async fn session(&self) -> BusSession {
        tokio::time::timeout(LIMIT, build_session(self.path.clone()))
            .await
            .unwrap()
            .unwrap()
    }
    async fn publish(&self, subject: String, id: &str, body: &[u8]) {
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("Nats-Msg-Id", id);
        self.admin
            .publish_with_headers(subject, headers, body.to_vec().into())
            .await
            .unwrap()
            .await
            .unwrap();
    }
}

async fn enable_jetstream(bus: &BusServer, account: &str) {
    let signer = bus.trust.signer.root(&signer_root_id());
    let claims = json!({"jti":"fixture","iat":unix_now(),"iss":signer.pair.public_key(),"sub":account,"name":"fixture-account","nats":{"type":"account","version":2,"limits":{"subs":-1,"data":-1,"payload":-1,"imports":-1,"exports":-1,"wildcards":true,"conn":-1,"leaf":-1,"mem_storage":-1,"disk_storage":-1,"streams":-1,"consumer":-1},"signing_keys":[account],"default_permissions":{"pub":{},"sub":{}}}});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"ed25519-nkey","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes())
    );
    let jwt = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signer.pair.sign(input.as_bytes()).unwrap())
    );
    let user = Arc::new(nkeys::KeyPair::new_user());
    let sys_jwt = bus
        .trust
        .user_jwt(&system_root_id(), &bus.system_account, &user, unix_now());
    let sys = async_nats::ConnectOptions::with_jwt(sys_jwt, move |nonce| {
        let user = user.clone();
        async move { user.sign(&nonce).map_err(async_nats::AuthError::new) }
    })
    .connect(&bus.url)
    .await
    .unwrap();
    let reply = sys
        .request("$SYS.REQ.CLAIMS.UPDATE", jwt.into())
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.payload).unwrap()["data"]["code"],
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_notice_matches_captured_030_publisher_bytes() {
    let _serial = LIVE.lock().await;
    let rig = LiveRig::start(false).await;
    let session = rig.session().await;
    let subject = "ck.box_example.event.plexus.github_issue_changed.v1";
    let receipt = session
        .publisher
        .publish(
            subject,
            "fixture-fact",
            ContentDigest::of_bytes(b"github-wire-fixture"),
            BTreeMap::from([
                ("kind".into(), "github_issue_changed".into()),
                ("repo".into(), "owner/repo".into()),
                ("project".into(), "project-a".into()),
            ]),
        )
        .await
        .unwrap();
    assert!(!receipt.duplicate());
    let stream = rig
        .admin
        .get_stream(&session.account.streams().event)
        .await
        .unwrap();
    let message = stream.get_raw_message(1).await.unwrap();
    let mut headers = BTreeMap::new();
    for (key, values) in message.headers.iter() {
        headers.insert(
            key.to_string(),
            values
                .iter()
                .map(|value| value.as_str())
                .collect::<Vec<_>>(),
        );
    }
    // The fixture was captured through bus-nats 0.3.0 against a real broker,
    // before replacing that backend. Only the account token differs here.
    let mut captured: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/github-notice-bus-nats-0.3.0.json"
    ))
    .unwrap();
    captured["subject"] = json!(subject);
    assert_eq!(
        json!({"subject":message.subject.as_str(),"payload":message.payload.to_vec(),"headers":headers}),
        captured
    );
    assert_eq!(
        rig.issues.load(Ordering::SeqCst),
        1,
        "one shared credential for all session paths"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_fact_exact_body_id_ack_and_duplicate_drain() {
    let _serial = LIVE.lock().await;
    let rig = LiveRig::start(false).await;
    let session = rig.session().await;
    let (_scratch, store) = tests::test_store("live-route-facts");
    let home = Arc::new(crate::connector_home::ConnectorHome::test_admitted());
    let publisher = Arc::new(RouteFactBus::default());
    publisher.bind(session.client.as_ref().unwrap(), &home);
    struct Gated {
        inner: Arc<RouteFactBus>,
        release: tokio::sync::Notify,
        entered: tokio::sync::Notify,
    }
    impl RouteFactPublisher for Gated {
        fn publish_event<'a>(
            &'a self,
            event: &'a str,
            version: u32,
            reader: Option<&'a str>,
            id: &'a str,
            body: &'a [u8],
        ) -> plexus_core::web_search::routing::RouteFactPublish<'a> {
            Box::pin(async move {
                self.entered.notify_one();
                self.release.notified().await;
                self.inner
                    .publish_event(event, version, reader, id, body)
                    .await
            })
        }
    }
    let gate = Arc::new(Gated {
        inner: publisher,
        release: Default::default(),
        entered: Default::default(),
    });
    let service = WebSearchService::production().with_route_fact_publisher(gate.clone());
    for (id, at) in [("z:outcome", 1), ("a:outcome", 2)] {
        store
            .enqueue_route_fact(id, &json!({"decision_id":id,"outcome":"completed"}), at)
            .unwrap();
    }
    let original = store.pending_route_facts(10).unwrap();
    let db = store.clone();
    let drain = tokio::spawn(async move { service.drain_route_facts(&db, 10).await });
    tokio::time::timeout(LIMIT, gate.entered.notified())
        .await
        .unwrap();
    assert_eq!(
        store.pending_route_facts(10).unwrap(),
        original,
        "no deletion before acceptance"
    );
    // Simulate a publish-before-delete crash: the first stored fact is already
    // accepted. Its duplicate receipt must still let the outbox delete the row.
    let row = &original[0];
    assert!(!session
        .client
        .as_ref()
        .unwrap()
        .publish_event("route_fact", 1, None, &row.msg_id, row.body.clone())
        .await
        .unwrap()
        .duplicate());
    gate.release.notify_one();
    tokio::time::timeout(LIMIT, gate.entered.notified())
        .await
        .unwrap();
    assert_eq!(store.pending_route_facts(10).unwrap(), original[1..]);
    gate.release.notify_one();
    assert_eq!(
        tokio::time::timeout(LIMIT, drain)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        2
    );
    assert!(store.pending_route_facts(10).unwrap().is_empty());
    let mut stream = rig
        .admin
        .get_stream(&session.account.streams().event)
        .await
        .unwrap();
    assert_eq!(stream.info().await.unwrap().state.messages, 2);
    for (seq, row) in (1..).zip(original) {
        let message = stream.get_raw_message(seq).await.unwrap();
        assert_eq!(
            message.subject.as_str(),
            "ck.box_example.event.plexus.route_fact.v1"
        );
        assert_eq!(message.payload.as_ref(), row.body.as_bytes());
        assert_eq!(
            message.headers.get("Nats-Msg-Id").unwrap().as_str(),
            row.msg_id
        );
    }
}

struct RegistryPeer(Mutex<Vec<(String, Value)>>);
impl plexus_core::github_identity::PrefrontalRoutePeer for RegistryPeer {
    fn call(
        &self,
        op: &str,
        params: Value,
    ) -> Result<Value, plexus_core::github_identity::PrefrontalRouteError> {
        self.0.lock().unwrap().push((op.into(), params.clone()));
        Ok(
            json!({"result":{"agent_id":params["agent_id"],"status":"live","gone":null,"merged_into":null,"generation":1,"incarnation":"first"}}),
        )
    }
}

fn state_with_registry(store: Arc<PlexusStore>, peer: Arc<RegistryPeer>) -> Arc<ModuleState> {
    let mut runtime = crate::runtime_for_test(store);
    runtime.agent_registry = Arc::new(plexus_core::agent_registry::EntorhinalAgentRegistry::new(
        peer,
    ));
    Arc::new(ModuleState {
        runtime,
        health: Arc::new(crate::health::HealthState::new()),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entorhinal_agents_bucket_reaches_full_retirement_sweep() {
    let _serial = LIVE.lock().await;
    let rig = LiveRig::start(true).await;
    let session = rig.session().await;
    let (_scratch, store) = tests::test_store("live-retirement");
    let peer = Arc::new(RegistryPeer(Mutex::new(vec![])));
    seed_pending_card(&store);
    let state = state_with_registry(store, peer.clone());
    let bucket = rig
        .admin
        .create_key_value(async_nats::jetstream::kv::Config {
            bucket: session
                .account
                .module_bucket_name("entorhinal", "changes")
                .unwrap(),
            ..Default::default()
        })
        .await
        .unwrap();
    let _watch = crate::bus_wakes::spawn_change_watch(
        state,
        session.client.as_ref().unwrap().connection(),
        &session.account,
    )
    .unwrap();
    bucket
        .put(
            "agents",
            br#"{"generation":1,"incarnation":"first"}"#.as_slice().into(),
        )
        .await
        .unwrap();
    until(|| peer.0.lock().unwrap().len() == 1).await;
    let calls = peer.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "agent.resolve");
    assert_eq!(calls[0].1, json!({"agent_id":"agent"}));
}

fn seed_pending_card(store: &PlexusStore) {
    store
        .put_github_handle(&plexus_core::storage::github_store::GithubHandle {
            app_handle_id: "app".into(),
            agent_id: "agent".into(),
            app_id: 7,
            installation_id: None,
            credential_reference: "github_app:app".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: None,
            connection_principal: "direct".into(),
            connection_id: "conn".into(),
        })
        .unwrap();
    assert!(store
        .save_github_manifest_binding(
            &plexus_core::storage::github_manifest_binding::BindingRecord {
                app_handle_id: "app".into(),
                repository: "org/repo".into(),
                agent_id: "agent".into(),
                proposal_id: Some("proposal".into()),
                manifest_version: Some(1),
                manifest_sha256: Some("a".repeat(64)),
                statement_b64url: Some("statement".into()),
                expires_at_ms: None,
                state: "pending".into(),
                card_id: Some("el_2".into()),
                present: true,
                revision: -1
            },
            None
        )
        .unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn durable_card_pointer_schedules_one_pending_manifest_pass_only() {
    use futures_util::FutureExt;
    let _serial = LIVE.lock().await;
    let rig = LiveRig::start(true).await;
    let session = rig.session().await;
    let (_scratch, store) = tests::test_store("live-card-pointer");
    seed_pending_card(&store);
    let state = state_with_registry(store, Arc::new(RegistryPeer(Mutex::new(vec![]))));
    let mut reader =
        crate::bus_wakes::session_reader(session.client.as_ref().unwrap().clone(), state.clone());
    let body = include_bytes!("../tests/fixtures/card-settled-v1/plexus.plexus.body.json");
    let subject = include_str!("../tests/fixtures/card-settled-v1/plexus.plexus.subject.txt");
    let headers: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/card-settled-v1/plexus.plexus.headers.json"
    ))
    .unwrap();
    for (id, bytes) in [
        (headers["Nats-Msg-Id"].as_str().unwrap(), body.as_slice()),
        ("el_2:plexus:3", body.as_slice()),
        (
            "unrelated",
            br#"{"elicitation_id":"other","feed":"answers","seq":4}"#.as_slice(),
        ),
    ] {
        rig.publish(subject.into(), id, bytes).await;
        assert!(tokio::time::timeout(
            LIMIT,
            crate::bus_wakes::read_module_event_once(reader.as_mut())
        )
        .await
        .unwrap()
        .unwrap());
    }
    assert!(state
        .runtime
        .manifest_binding_wake
        .notified()
        .now_or_never()
        .is_some());
    assert!(
        state
            .runtime
            .manifest_binding_wake
            .notified()
            .now_or_never()
            .is_none(),
        "burst coalesces into one scheduled pass"
    );
    rig.publish(
        subject.into(),
        "unrelated-2",
        br#"{"elicitation_id":"other","feed":"answers","seq":5}"#,
    )
    .await;
    assert!(tokio::time::timeout(
        LIMIT,
        crate::bus_wakes::read_module_event_once(reader.as_mut())
    )
    .await
    .unwrap()
    .unwrap());
    assert!(state
        .runtime
        .manifest_binding_wake
        .notified()
        .now_or_never()
        .is_none());
}

async fn until(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(LIMIT, async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_durable_keeps_publisher_and_outbox_wake_running() {
    let _serial = LIVE.lock().await;
    let rig = LiveRig::start(false).await;
    let (_scratch, store) = tests::test_store("live-missing-durable");
    let mut runtime = crate::runtime_for_test(store.clone());
    runtime.web_search = Arc::new(
        WebSearchService::production().with_route_fact_publisher(runtime.route_facts.clone()),
    );
    let state = Arc::new(ModuleState {
        runtime,
        health: Arc::new(crate::health::HealthState::new()),
    });
    let (stop, rx) = mpsc::channel(1);
    let task = spawn_outbox_drain(state.clone(), rx, session_factory(Some(rig.path.clone())));
    until(|| rig.issues.load(Ordering::SeqCst) == 1).await;
    // Retries to attach the durable must leave the outbox task running and
    // able to drain newly enqueued facts.
    tokio::time::sleep(Duration::from_millis(50)).await;
    store
        .enqueue_route_fact(
            "missing:outcome",
            &json!({"decision_id":"missing","outcome":"completed"}),
            1,
        )
        .unwrap();
    until(|| store.pending_route_facts(1).unwrap().is_empty()).await;
    assert!(!task.is_finished());
    assert!(state.health.last_publish_error().is_none());
    stop.send(()).await.unwrap();
    task.await.unwrap();
}

struct TrackedSessions {
    path: PathBuf,
    client: Arc<Mutex<Option<std::sync::Weak<BusClient>>>>,
}
#[async_trait]
impl SessionFactory for TrackedSessions {
    fn needs_idle_session(&self) -> bool {
        true
    }
    async fn open(&self) -> Result<BusSession, String> {
        let session = build_session(self.path.clone()).await?;
        *self.client.lock().unwrap() = session.client.as_ref().map(Arc::downgrade);
        Ok(session)
    }
}
struct Home(std::sync::atomic::AtomicBool);
impl crate::connector_home::RolePeer for Home {
    fn call(&self, _: &str, _: Value) -> Result<Value, subc_protocol::ErrorBody> {
        Ok(
            json!({"role":crate::connector_home::ROLE,"epoch":1,"known":true,"held_here":self.0.load(Ordering::SeqCst),"stale":false,"holder":null,"holder_name":null,"source":null}),
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_loss_destroys_shared_session_and_stops_all_paths() {
    use futures_util::FutureExt;
    let _serial = LIVE.lock().await;
    let rig = LiveRig::start(true).await;
    let (_scratch, store) = tests::test_store("live-claim-loss");
    let peer = Arc::new(RegistryPeer(Mutex::new(vec![])));
    let home = Arc::new(Home(std::sync::atomic::AtomicBool::new(true)));
    let mut runtime = crate::runtime_for_test(store.clone());
    runtime.connector_home = Arc::new(crate::connector_home::ConnectorHome::new(home.clone()));
    runtime.connector_home.refresh().unwrap();
    runtime.agent_registry = Arc::new(plexus_core::agent_registry::EntorhinalAgentRegistry::new(
        peer.clone(),
    ));
    runtime.web_search = Arc::new(
        WebSearchService::production().with_route_fact_publisher(runtime.route_facts.clone()),
    );
    let state = Arc::new(ModuleState {
        runtime,
        health: Arc::new(crate::health::HealthState::new()),
    });
    let client = Arc::new(Mutex::new(None));
    let (stop, rx) = mpsc::channel(1);
    let task = spawn_outbox_drain(
        state.clone(),
        rx,
        Arc::new(TrackedSessions {
            path: rig.path.clone(),
            client: client.clone(),
        }),
    );
    until(|| client.lock().unwrap().is_some()).await;
    let names = AccountNames::derive("box_example").unwrap();
    seed_pending_card(&store);
    let bucket = rig
        .admin
        .create_key_value(async_nats::jetstream::kv::Config {
            bucket: names.module_bucket_name("entorhinal", "changes").unwrap(),
            ..Default::default()
        })
        .await
        .unwrap();
    bucket
        .put(
            "agents",
            br#"{"generation":1,"incarnation":"first"}"#.as_slice().into(),
        )
        .await
        .unwrap();
    until(|| peer.0.lock().unwrap().len() == 1).await;
    home.0.store(false, Ordering::SeqCst);
    state.runtime.connector_home.refresh().unwrap();
    until(|| {
        client
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|client| client.upgrade().is_none())
    })
    .await;
    let sub = tests::seed_connection_and_subscription(&store, "conn-1");
    let key = "f".repeat(64);
    tests::insert_test_event(
        &store,
        &sub,
        &key,
        "github_issue_changed",
        "owner/repo",
        &json!({}),
    );
    store
        .enqueue_route_fact(
            "after:outcome",
            &json!({"decision_id":"after","outcome":"completed"}),
            1,
        )
        .unwrap();
    bucket
        .put(
            "agents",
            br#"{"generation":2,"incarnation":"first"}"#.as_slice().into(),
        )
        .await
        .unwrap();
    rig.publish(
        names
            .event_subject_with_reader("cingulate", "card_settled", 1, "plexus")
            .unwrap(),
        "after-card",
        include_bytes!("../tests/fixtures/card-settled-v1/plexus.plexus.body.json"),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(peer.0.lock().unwrap().len(), 1);
    assert!(state
        .runtime
        .manifest_binding_wake
        .notified()
        .now_or_never()
        .is_none());
    assert_eq!(store.pending_route_facts(10).unwrap().len(), 1);
    assert!(store
        .canonical_event_by_key(&key)
        .unwrap()
        .unwrap()
        .published_at_ms
        .is_none());
    assert_eq!(rig.issues.load(Ordering::SeqCst), 1);
    assert!(!task.is_finished());
    stop.send(()).await.unwrap();
    task.await.unwrap();
}
