use super::*;

const FRAMES: &str = include_str!("../tests/fixtures/webhook-relay/github-apps-frames.jsonl");

fn app_hello() -> String {
    vector(FRAMES, "app hello")
}

fn pending_hello(next: u64) -> String {
    let mut hello: Value = serde_json::from_str(&app_hello()).unwrap();
    hello["next_seq"] = json!(next);
    hello.to_string()
}

fn app_event(seq: u64, app_id: Value) -> String {
    let mut frame: Value = serde_json::from_str(&full_event()).unwrap();
    frame["seq"] = json!(seq);
    frame["app_id"] = app_id;
    frame["installation_id"] = Value::Null;
    frame.to_string()
}

fn seed_handle(scratch: &Scratch, bound: bool, enabled: bool) {
    let status = if enabled { "enabled" } else { "disabled" };
    sql(scratch, &format!("INSERT INTO github_app_handle
        (app_handle_id,agent_id,app_id,credential_reference,status,connection_principal,connection_id)
        VALUES ('demo','agent-demo',42,'github_app:demo','{status}','direct','conn-1')"));
    if bound {
        sql(
            scratch,
            "INSERT INTO github_repo_binding(repository,app_handle_id) VALUES ('org/repo','demo')",
        );
    }
}

fn counter(scratch: &Scratch, name: &str) -> i64 {
    Connection::open(scratch.path())
        .unwrap()
        .query_row(
            "SELECT coalesce((SELECT value FROM event_outbox_counters WHERE name=?1),0)",
            [name],
            |row| row.get(0),
        )
        .unwrap()
}

async fn exchange(store: Arc<PlexusStore>, status: &Status, frames: Vec<String>) {
    let (socket, mut peer) = memory_sockets().await;
    let home = ConnectorHome::test_admitted();
    let send = async {
        for frame in frames {
            let value: Value = serde_json::from_str(&frame).unwrap();
            peer.send(Message::Text(frame.into())).await.unwrap();
            if let Some(seq) = value["seq"].as_u64() {
                let reply = bounded(peer.next()).await.unwrap().unwrap();
                assert_eq!(
                    reply,
                    Message::Text(format!("{{\"type\":\"ack\",\"through_seq\":{seq}}}").into())
                );
            }
        }
        peer.close(None).await.unwrap();
    };
    let (failure, ()) = bounded(async {
        tokio::join!(
            consume_source(Source::Apps, socket, store, status, &home),
            send
        )
    })
    .await;
    assert_eq!(failure, Failure::Reconnecting);
}

#[tokio::test]
async fn pinned_frames_go_through_websocket_reader() {
    let (scratch, store, _) = fixture("apps-vectors");
    seed_handle(&scratch, true, true);
    let frames = FRAMES
        .lines()
        .map(|line| {
            let entry: Value = serde_json::from_str(line).unwrap();
            assert_eq!(entry["expect"], "emitted");
            vector(FRAMES, entry["name"].as_str().unwrap())
        })
        .collect();
    let status = Status::default();
    exchange(store.clone(), &status, frames).await;
    let cursor = store.relay_cursor("github-apps").unwrap().unwrap();
    assert_eq!(cursor.stream_id, ORIGINAL_STREAM);
    assert_eq!(cursor.committed_seq, 2);
    assert_eq!(
        counter(&scratch, "relay_drop_invalid_payload"),
        2,
        "both events carry the known App ID but neither has a repository"
    );
    assert!(store.relay_cursor("github").unwrap().is_none());
}

#[tokio::test]
async fn admitted_event_bytes_match_github_in_storage_and_on_publish() {
    let (_github_scratch, github, _) = fixture("apps-byte-equivalence-github");
    let (apps_scratch, apps, _) = fixture("apps-byte-equivalence-apps");
    seed_handle(&apps_scratch, true, true);
    replay(github.clone(), vec![hello(), full_event()], true).await;
    exchange(
        apps.clone(),
        &Status::default(),
        vec![app_hello(), app_event(1, json!("42"))],
    )
    .await;
    let accounts = cortexkit_bus_naming::AccountNames::derive("box_test").unwrap();
    let mut canonical = Vec::new();
    let mut notices = Vec::new();
    for store in [github, apps] {
        let rows = store.drain_event_outbox(64).unwrap();
        assert_eq!(rows.len(), 1);
        let event = &rows[0];
        canonical.push((
            event.event_key.clone(),
            event.body.as_bytes().to_vec(),
            event.envelope_v2.as_ref().unwrap().as_bytes().to_vec(),
        ));

        let publisher = MockPublisher::default();
        assert_eq!(
            crate::bus::drain_pass(&store, &accounts, &publisher, 64, &|| true)
                .await
                .unwrap(),
            2
        );
        notices.push(
            publisher
                .published
                .lock()
                .unwrap()
                .iter()
                .map(|message| {
                    serde_json::to_vec(&(
                        &message.subject,
                        &message.id,
                        message.digest.to_string(),
                        &message.headers,
                    ))
                    .unwrap()
                })
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(canonical[0], canonical[1]);
    assert_eq!(notices[0], notices[1]);
}

async fn assert_drop(app_id: Value, bound: bool, enabled: bool, reason: &str) {
    let (scratch, store, _) = fixture(reason);
    seed_handle(&scratch, bound, enabled);
    exchange(
        store.clone(),
        &Status::default(),
        vec![app_hello(), app_event(1, app_id)],
    )
    .await;
    assert_eq!(count(&scratch, "event_outbox"), 0);
    assert_eq!(counter(&scratch, reason), 1);
    assert_eq!(
        store
            .relay_cursor("github-apps")
            .unwrap()
            .unwrap()
            .committed_seq,
        1
    );
}

#[tokio::test]
async fn unknown_app_id_is_dropped_and_acked() {
    assert_drop(json!("99"), true, true, "relay_drop_unknown_app_id").await;
}

#[tokio::test]
async fn unbound_repository_is_dropped_and_acked() {
    assert_drop(
        json!("42"),
        false,
        true,
        "relay_drop_unbound_app_repository",
    )
    .await;
}

#[tokio::test]
async fn disabled_handle_is_dropped_and_acked() {
    assert_drop(json!("42"), true, false, "relay_drop_disabled_app_handle").await;
}

#[tokio::test]
async fn noncanonical_app_ids_are_dropped_and_acked() {
    let (scratch, store, _) = fixture("apps-invalid-id");
    seed_handle(&scratch, true, true);
    let ids = [
        json!(42),
        Value::Null,
        json!("042"),
        json!("+42"),
        json!("-42"),
        json!(" 42"),
        json!("9223372036854775808"),
        json!("0"),
    ];
    let frames = std::iter::once(app_hello())
        .chain(
            ids.into_iter()
                .enumerate()
                .map(|(i, id)| app_event(i as u64 + 1, id)),
        )
        .collect();
    exchange(store.clone(), &Status::default(), frames).await;
    assert_eq!(counter(&scratch, "relay_drop_invalid_app_id"), 8);
    assert_eq!(count(&scratch, "event_outbox"), 0);
}

#[tokio::test]
async fn duplicate_across_sources_is_stored_once_in_either_order() {
    for apps_first in [true, false] {
        let (scratch, store, _) = fixture("apps-cross-source-dedup");
        seed_handle(&scratch, true, true);
        let github = || replay(store.clone(), vec![hello(), full_event()], true);
        let status = Status::default();
        let apps = || {
            exchange(
                store.clone(),
                &status,
                vec![app_hello(), app_event(1, json!("42"))],
            )
        };
        if apps_first {
            apps().await;
            github().await;
        } else {
            github().await;
            apps().await;
        }
        assert_eq!(count(&scratch, "trigger_events WHERE kind='event'"), 1);
        assert_eq!(count(&scratch, "event_outbox"), 1);
        assert_eq!(counter(&scratch, "relay_drop_already_delivered"), 1);
        for source in ["github", "github-apps"] {
            assert_eq!(
                store.relay_cursor(source).unwrap().unwrap().committed_seq,
                1
            );
        }
    }
}

#[tokio::test]
async fn vault_id_disagreement_refuses_frames_without_overwriting_the_handle() {
    let (scratch, store, _) = fixture("apps-vault-cross-check");
    seed_handle(&scratch, true, true);
    let status = Status::default();
    let ids = |number| BTreeMap::from([("github_app:demo".into(), number)]);
    status.observe_app_ids(&store, ids(41)).unwrap();
    exchange(
        store.clone(),
        &status,
        vec![app_hello(), app_event(1, json!("42"))],
    )
    .await;
    assert_eq!(counter(&scratch, "relay_drop_app_id_mismatch"), 1);
    assert_eq!(count(&scratch, "event_outbox"), 0);
    assert_eq!(
        store
            .github_handle_for_repo("org/repo")
            .unwrap()
            .unwrap()
            .app_id,
        42
    );

    status.observe_app_ids(&store, ids(42)).unwrap();
    exchange(
        store.clone(),
        &status,
        vec![
            pending_hello(3),
            app_event(1, json!("42")),
            app_event(2, json!("42")),
        ],
    )
    .await;
    assert_eq!(counter(&scratch, "relay_drop_app_id_mismatch"), 1);
    assert_eq!(count(&scratch, "event_outbox"), 1);
}

#[tokio::test]
async fn overflow_replays_and_catches_up_only_bound_repositories() {
    let (scratch, store, _) = fixture("apps-overflow");
    seed_handle(&scratch, true, true);
    add_other_repository(&scratch);
    let status = Status::default();
    let overflow = json!({"type":"event","seq":1,"delivery_id":"overflow:01ARZ3NDEKTSV4RRFFQ69G5FAV:1","event":"cortexkit_overflow","installation_id":null,"app_id":"42","received_at":TIME,"stub":"overflow","body":{"overflow":true,"dropped":2}});
    exchange(
        store.clone(),
        &status,
        vec![pending_hello(2), overflow.to_string()],
    )
    .await;
    assert_eq!(
        due(&scratch),
        2,
        "only the two bound repository watches are due"
    );
    assert_eq!(status.polling_status()["last_clock_reset"], "overflow");
    assert!(store.relay_cursor("github").unwrap().is_none());

    sql(
        &scratch,
        "UPDATE trigger_subscriptions SET last_polled_at_ms=9999999999999",
    );
    exchange(
        store.clone(),
        &status,
        vec![pending_hello(2), overflow.to_string()],
    )
    .await;
    assert_eq!(
        due(&scratch),
        0,
        "replaying the committed marker must not requeue watches"
    );

    let mut unknown = overflow.clone();
    unknown["seq"] = json!(2);
    unknown["app_id"] = json!("99");
    exchange(
        store,
        &status,
        vec![pending_hello(3), overflow.to_string(), unknown.to_string()],
    )
    .await;
    assert_eq!(due(&scratch), 0);
    assert_eq!(counter(&scratch, "relay_drop_unknown_app_id"), 1);
}

struct TrackingCredentials {
    provider: StubCredentialSource,
    reads: mpsc::UnboundedSender<String>,
}

impl CredentialSource for TrackingCredentials {
    fn get_by_id(
        &self,
        id: &str,
    ) -> Result<plexus_core::ResolvedCredential, plexus_core::CredentialError> {
        let result = self.provider.get_by_id(id);
        let _ = self.reads.send(id.into());
        result
    }
}

#[tokio::test]
async fn absent_apps_credential_never_dials_and_health_is_disabled() {
    let (_scratch, store, _) = fixture("apps-disabled");
    let github = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let apps = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let github_url = format!("ws://{}/v1/relay/github/ws", github.local_addr().unwrap());
    let apps_url = format!(
        "ws://{}/v1/relay/github-apps/ws",
        apps.local_addr().unwrap()
    );
    let (reads, mut read) = mpsc::unbounded_channel();
    let provider = Arc::new(TrackingCredentials {
        provider: StubCredentialSource::default(),
        reads,
    });
    provider
        .provider
        .set_success(CREDENTIAL.as_bytes(), b"github-token".to_vec(), None, 1);
    let health = Arc::new(crate::health::HealthState::new());
    let (stop, rx) = mpsc::channel(1);
    let task = tokio::spawn({
        let health = health.clone();
        async move {
            run_sources(
                &github_url,
                Some(&apps_url),
                store,
                provider,
                Arc::new(ConnectorHome::test_admitted()),
                &health.relay,
                rx,
            )
            .await
        }
    });

    let (tcp, _) = bounded(github.accept()).await.unwrap();
    let mut github_socket =
        tokio_tungstenite::accept_hdr_async(tcp, ExpectedAuthorization(b"Bearer github-token"))
            .await
            .unwrap();
    github_socket
        .send(Message::Text(hello().into()))
        .await
        .unwrap();
    wait_state(&health.relay, State::Connected).await;
    let subc_protocol::session::ModuleControlResponse::HealthCheck {
        metrics: Some(metrics),
        ..
    } = health.report()
    else {
        panic!("expected module health metrics");
    };
    assert_eq!(metrics["githubAppsRelay"], "disabled");
    let reads = [
        bounded(read.recv()).await.unwrap(),
        bounded(read.recv()).await.unwrap(),
    ];
    assert!(reads.iter().any(|id| id == "relay:github-apps"));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), apps.accept())
            .await
            .is_err()
    );
    assert_eq!(
        health.relay.status()["sources"],
        json!([{"source":"github","state":"connected","last_event_at":null,"message":null}])
    );
    stop.send(()).await.unwrap();
    bounded(task).await.unwrap();
}

#[tokio::test]
async fn provisioned_apps_socket_uses_its_own_credential_and_rejection_backoff() {
    let (_scratch, store, _) = fixture("apps-revocation");
    let github = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let apps = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let github_url = format!("ws://{}/v1/relay/github/ws", github.local_addr().unwrap());
    let apps_url = format!(
        "ws://{}/v1/relay/github-apps/ws",
        apps.local_addr().unwrap()
    );
    let (reads, mut read) = mpsc::unbounded_channel();
    let provider = Arc::new(TrackingCredentials {
        provider: StubCredentialSource::default(),
        reads,
    });
    provider
        .provider
        .set_success(CREDENTIAL.as_bytes(), b"github-token".to_vec(), None, 1);
    provider
        .provider
        .set_success(APPS_CREDENTIAL.as_bytes(), b"apps-token".to_vec(), None, 1);
    let status = Arc::new(Status::default());
    let (stop, rx) = mpsc::channel(1);
    let task = tokio::spawn({
        let status = status.clone();
        async move {
            run_sources(
                &github_url,
                Some(&apps_url),
                store,
                provider,
                Arc::new(ConnectorHome::test_admitted()),
                &status,
                rx,
            )
            .await
        }
    });

    let (github_tcp, _) = bounded(github.accept()).await.unwrap();
    let (apps_tcp, _) = bounded(apps.accept()).await.unwrap();
    let mut github_socket = bounded(tokio_tungstenite::accept_hdr_async(
        github_tcp,
        ExpectedAuthorization(b"Bearer github-token"),
    ))
    .await
    .unwrap();
    let mut apps_socket = bounded(tokio_tungstenite::accept_hdr_async(
        apps_tcp,
        ExpectedAuthorization(b"Bearer apps-token"),
    ))
    .await
    .unwrap();
    github_socket
        .send(Message::Text(hello().into()))
        .await
        .unwrap();
    apps_socket
        .send(Message::Text(app_hello().into()))
        .await
        .unwrap();
    bounded(async {
        while status.apps_state() != "connected" {
            tokio::task::yield_now().await;
        }
    })
    .await;
    wait_state(&status, State::Connected).await;
    assert_eq!(
        status.status()["sources"][1],
        json!({"source":"github-apps","state":"connected","last_event_at":null,"message":null})
    );
    for _ in 0..2 {
        bounded(read.recv()).await.unwrap();
    }

    apps_socket
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Library(4001),
            reason: "revoked".into(),
        })))
        .await
        .unwrap();
    bounded(async {
        while status.apps_state() != "credential_rejected" {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(status.status()["sources"][0]["state"], "connected");
    tokio::time::pause();
    tokio::time::advance(INITIAL_CREDENTIAL_RECHECK + Duration::from_secs(1)).await;
    tokio::time::resume();
    assert_eq!(bounded(read.recv()).await.unwrap(), APPS_CREDENTIAL);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), apps.accept())
            .await
            .is_err(),
        "unchanged rejected credentials must not redial either source"
    );

    stop.send(()).await.unwrap();
    bounded(task).await.unwrap();
}

#[test]
fn either_source_supplies_the_shared_healthy_hour_but_neither_masks_a_failure() {
    let status = Status::default();
    let started = Instant::now() - HEALTHY_RELAY_WINDOW;
    status.source_connected_at(Source::Github, "github-stream".into(), None, started);
    status.source_connected_at(Source::Apps, "apps-stream".into(), None, started);
    {
        let mut s = status.0.lock().unwrap();
        for (i, minute) in (0..=60).step_by(10).enumerate() {
            let source = if i % 2 == 0 {
                Source::Apps
            } else {
                Source::Github
            };
            Status::source_delivered_at(&mut s, source, started + Duration::from_secs(minute * 60));
        }
        assert!(Status::slow_at(&s, started + HEALTHY_RELAY_WINDOW));
    }
    status.transition(
        Source::Apps,
        State::CredentialRejected,
        Some(RejectionCause::Close4001),
    );
    assert_eq!(status.polling_status()["mode"], "normal");
    assert_eq!(
        status.polling_status()["last_clock_reset"],
        "credential_rejected"
    );
    assert!(status.take_reconcile());
    assert_eq!(status.status()["sources"][0]["state"], "connected");
    assert_eq!(
        status.status()["sources"][1]["state"],
        "credential_rejected"
    );
}
