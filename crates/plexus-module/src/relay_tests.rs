use super::*;
use crate::bus::tests::{seed_connection_and_subscription, test_store, MockPublisher};
use plexus_core::storage::event_outbox::{EventLookupOutcome, EventReader};
use plexus_core::{now_ms, test_scratch::Scratch, StubCredentialSource};
use rusqlite::Connection;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_tungstenite::accept_async;

include!("review_event_tests.rs");

mod diagnostic_logging {
    include!("../../plexus-core/tests/support/logging.rs");
}

struct ExpectedAuthorization(&'static [u8]);
impl tungstenite::handshake::server::Callback for ExpectedAuthorization {
    fn on_request(
        self,
        request: &tungstenite::handshake::server::Request,
        response: tungstenite::handshake::server::Response,
    ) -> Result<
        tungstenite::handshake::server::Response,
        tungstenite::handshake::server::ErrorResponse,
    > {
        assert_eq!(request.headers()["Authorization"].as_bytes(), self.0);
        Ok(response)
    }
}

const ORIGINAL_STREAM: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const RECREATED_STREAM: &str = "AQEBAQEBAQEBAQEBAQEBAQE";
const TIME: &str = "2030-10-08T09:00:00.000Z";
const HELLOS: &str = include_str!("../tests/fixtures/webhook-relay/hello.jsonl");
const EVENTS: &str = include_str!("../tests/fixtures/webhook-relay/event.jsonl");
const ACKS: &str = include_str!("../tests/fixtures/webhook-relay/ack.jsonl");
fn vector(file: &str, name: &str) -> String {
    let line = file
        .lines()
        .find(|line| serde_json::from_str::<Value>(line).unwrap()["name"] == name)
        .unwrap();
    // Slice the pinned frame bytes rather than reserializing through a sorted JSON map.
    line.split_once("\"frame\":")
        .unwrap()
        .1
        .rsplit_once(",\"expect\":")
        .unwrap()
        .0
        .replace("<received_at>", TIME)
        .replace("<account_id>", "01ARZ3NDEKTSV4RRFFQ69G5FAV")
        .replace("<stream_id>", ORIGINAL_STREAM)
}
fn hello() -> String {
    vector(HELLOS, "buffered")
}

#[tokio::test(start_paused = true)]
async fn regression_silent_websocket_has_a_receive_deadline() {
    let (_scratch, store, _) = fixture("relay_silent_peer");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(tcp).await.unwrap();
        socket.send(Message::Text(hello().into())).await.unwrap();
        ready_tx.send(()).unwrap();
        let _ = release_rx.await;
        drop(socket);
    });
    let home = Arc::new(ConnectorHome::test_admitted());
    let socket = dial(&url, b"opaque-token", &home).await.unwrap();
    ready_rx.await.unwrap();
    let status = Status::default();
    let failure = tokio::time::timeout(
        Duration::from_secs(65),
        consume(socket, store, &status, &home),
    )
    .await;
    release_tx.send(()).unwrap();
    server.await.unwrap();
    assert_eq!(
        failure.expect("silent peer must time out before the outer deadline"),
        Failure::Reconnecting
    );
}

#[test]
fn regression_supersede_names_the_other_connector_home() {
    let status = Status::default();
    status.superseded();
    assert!(status.degraded_message().unwrap().contains("another"));
    assert!(status.status()["sources"][0]["message"]
        .as_str()
        .unwrap()
        .contains("another"));
}

#[tokio::test(start_paused = true)]
async fn received_pongs_keep_an_idle_relay_connection_alive() {
    let (_scratch, store, _) = fixture("relay-pong-progress");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(tcp).await.unwrap();
        socket.send(Message::Text(hello().into())).await.unwrap();
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            socket.send(Message::Pong(Vec::new().into())).await.unwrap();
        }
        socket.close(None).await.unwrap();
    });
    let home = Arc::new(ConnectorHome::test_admitted());
    let socket = dial(&url, b"opaque-token", &home).await.unwrap();
    let started = tokio::time::Instant::now();
    assert_eq!(
        consume(socket, store, &Status::default(), &home).await,
        Failure::Reconnecting
    );
    assert!(started.elapsed() >= Duration::from_secs(150));
    server.await.unwrap();
}

#[test]
fn regression_task_death_is_not_hidden_by_relay_failure() {
    let health = std::sync::Arc::new(crate::health::HealthState::new());
    health.relay.set(State::CredentialRejected);
    drop(crate::health::SchedulerLiveness::new(health.clone()));
    let subc_protocol::session::ModuleControlResponse::HealthCheck { detail, .. } = health.report()
    else {
        panic!("health reply")
    };
    let detail = detail.unwrap();
    assert!(detail.contains("scheduler task"));
    assert!(detail.contains("credential"));
}

#[test]
fn repeated_supersedes_keep_the_accumulated_backoff() {
    let mut failures = 7;
    reset_failure_count(State::Connected, Failure::Superseded, &mut failures);
    assert_eq!(
        failures, 7,
        "superseded sessions must retain backoff history"
    );
    assert_eq!(backoff(failures), Duration::from_secs(128));
    reset_failure_count(State::Connected, Failure::Reconnecting, &mut failures);
    assert_eq!(failures, 0);
}

#[test]
fn credential_transport_faults_are_not_missing_credentials() {
    use plexus_core::{CredentialError, PermanentCredentialError, TransientCredentialError};
    assert_eq!(
        credential_failure_state(&CredentialError::Permanent(
            PermanentCredentialError::NotFound
        )),
        State::NoCredential
    );
    for error in [
        CredentialError::AuthRequired,
        CredentialError::Transient(TransientCredentialError::VaultLocked),
        CredentialError::Permanent(PermanentCredentialError::Corrupt),
    ] {
        assert_eq!(
            credential_failure_state(&error),
            State::Reconnecting,
            "vault faults must not prescribe Connect GitHub"
        );
    }
    assert_eq!(State::NotHome.name(), "not_home");
    assert!(State::NotHome
        .message()
        .unwrap()
        .contains("deliberately stopped"));
}

#[tokio::test]
async fn local_hello_store_failure_does_not_blame_relay_protocol() {
    let (scratch, store, _) = fixture("local-relay-store-failure");
    sql(&scratch, "DROP TABLE relay_cursor");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (tcp, _) = bounded(listener.accept()).await.unwrap();
        let mut socket = accept_async(tcp).await.unwrap();
        socket.send(Message::Text(hello().into())).await.unwrap();
        let reply = bounded(socket.next()).await;
        assert!(
            !matches!(reply, Some(Ok(Message::Close(Some(frame)))) if u16::from(frame.code) == 4400),
            "local store failure must not send protocol close 4400"
        );
    });
    let home = Arc::new(ConnectorHome::test_admitted());
    let socket = bounded(dial(&url, b"opaque-token", &home)).await.unwrap();
    assert_eq!(
        bounded(consume(socket, store, &Status::default(), &home)).await,
        Failure::Reconnecting
    );
    bounded(server).await.unwrap();
}
fn sql(scratch: impl AsRef<std::path::Path>, statement: &str) {
    Connection::open(scratch.as_ref())
        .unwrap()
        .execute_batch(statement)
        .unwrap();
}
fn count(scratch: impl AsRef<std::path::Path>, table: &str) -> i64 {
    Connection::open(scratch.as_ref())
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}
fn fixture(name: &str) -> (Scratch, Arc<PlexusStore>, String) {
    let (scratch, store) = test_store(name);
    let sub = seed_connection_and_subscription(&store, "conn-1");
    sql(&scratch, &format!("UPDATE trigger_subscriptions SET fixed_args='{{\"owner\":\"org\",\"repo\":\"repo\"}}',project_id='p1',project_source='hand',last_polled_at_ms=9999999999999;
        INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,schema_hash,status,created_at_ms,fixed_args,project_id,project_source,last_polled_at_ms)
        SELECT 'pr-watch',principal,connection_id,'list_pull_requests',cadence_s,cursor_kind,schema_hash,status,created_at_ms,fixed_args,project_id,project_source,last_polled_at_ms FROM trigger_subscriptions WHERE subscription_id='{sub}';"));
    (scratch, store, sub)
}

const PREPARED_RELAY_LOG_STORE: &str = "PLEXUS_PREPARED_RELAY_LOG_STORE";

// Prepare the database before starting the diagnostic child so first-time schema
// migrations do not consume its execution deadline. The child still reopens the
// real store and performs the exchange or injected fault.
fn prepare_relay_log_fixture(label: &str) -> Scratch {
    let (scratch, store, _) = fixture(label);
    drop(store);
    scratch
}

fn relay_log_fixture(label: &str) -> (Option<Scratch>, Arc<PlexusStore>, std::path::PathBuf) {
    if let Some(path) = std::env::var_os(PREPARED_RELAY_LOG_STORE) {
        let path = std::path::PathBuf::from(path);
        let store = crate::bus::tests::open_test_store(&path);
        (None, store, path)
    } else {
        let (scratch, store, _) = fixture(label);
        let path = scratch.path().to_path_buf();
        (Some(scratch), store, path)
    }
}
fn kind_watch(store: &PlexusStore, action: &str) -> String {
    let (connection, app) = if action == "list_workflow_runs" {
        let source =
            subc_jsonc::jsonc_to_json(include_str!("../../../catalog/github_actions.jsonc"))
                .unwrap();
        let manifest = plexus_core::ingest_value(serde_json::from_str(&source).unwrap()).unwrap();
        store.upsert_manifest("system", &manifest).unwrap();
        store
            .insert_connection(
                "direct",
                "conn-github-actions",
                "github_actions",
                "active",
                &json!({}),
            )
            .unwrap();
        ("conn-github-actions", "github_actions")
    } else {
        ("conn-1", "github")
    };
    store
        .seed_catalog_from_manifest("direct", connection, app)
        .unwrap();
    if action == "get_latest_release" {
        store.upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: connection.into(), principal: "direct".into(), name: action.into(), title: None,
            schema: json!({"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"}},"required":["owner","repo"]}),
            schema_hash: "hash-release".into(), risk: "read".into(), severity: "S2".into(), ask_first: false,
            status: "active".into(), quarantine_reason: None, reconciliation: None,
        }).unwrap();
    }
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: format!("poll-{action}"),
            principal: "direct".into(),
            connection_id: connection.into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec![action.into()],
            authority_kind: "poll".into(),
            expires_at: None,
        })
        .unwrap();
    let cursor = if action == "list_workflow_runs" {
        json!({"scanned_through_ms":10})
    } else {
        json!({})
    };
    store
        .subscribe_with_cursor_state(
            "direct",
            connection,
            action,
            300,
            &cursor,
            &json!({"owner":"org","repo":"repo"}),
        )
        .unwrap()
        .unwrap()
        .subscription_id
}
fn kind_frame(event_name: &str) -> Value {
    json!({"type":"event","seq":1,"delivery_id":"kind-event","event":event_name,"action":"published","installation_id":42,"received_at":TIME,"stub":null,
        "body":{"repository":{"id":101,"full_name":"org/repo"},(event_name):{"id":7,"updated_at":TIME,"published_at":TIME,"completed_at":TIME,"status":"completed","run_attempt":2,"conclusion":"success"}}})
}
async fn bounded<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .expect("local relay deadline")
}
async fn replay(store: Arc<PlexusStore>, frames: Vec<String>, expected_ack: bool) -> Failure {
    replay_with_close(store, frames, expected_ack, None).await
}
async fn replay_with_close(
    store: Arc<PlexusStore>,
    frames: Vec<String>,
    expected_ack: bool,
    expected_close: Option<u16>,
) -> Failure {
    replay_using_status(
        store,
        frames,
        expected_ack,
        expected_close,
        &Status::default(),
    )
    .await
}
async fn replay_using_status(
    store: Arc<PlexusStore>,
    frames: Vec<String>,
    expected_ack: bool,
    expected_close: Option<u16>,
    status: &Status,
) -> Failure {
    // Each acknowledgement follows a durable commit. Bound individual replies
    // separately from the whole exchange, which may contain 64 such commits.
    let ack_deadline = Duration::from_secs(20);
    let exchange_deadline = ack_deadline * (frames.len() as u32 + 1);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (tcp, _) = bounded(listener.accept()).await.unwrap();
        let mut socket = bounded(accept_async(tcp)).await.unwrap();
        let hello_only = frames.len() == 1;
        let sequences: Vec<u64> = frames
            .iter()
            .filter_map(|frame| {
                let value: Value = serde_json::from_str(frame).unwrap();
                (value["type"] == "event").then(|| value["seq"].as_u64().unwrap())
            })
            .collect();
        for frame in frames {
            socket.send(Message::Text(frame.into())).await.unwrap();
        }
        if hello_only {
            let _ = socket.close(None).await;
            return;
        }
        let response = tokio::time::timeout(ack_deadline, socket.next())
            .await
            .expect("committed relay ack deadline");
        if expected_ack {
            let mut response = response;
            for (index, seq) in sequences.iter().enumerate() {
                if index > 0 {
                    response = tokio::time::timeout(ack_deadline, socket.next())
                        .await
                        .expect("committed relay ack deadline");
                }
                let text = response.take().unwrap().unwrap().into_text().unwrap();
                let expected = match *seq {
                    2 => vector(ACKS, "cumulative"),
                    plexus_core::storage::relay::MAX_SEQ => vector(ACKS, "max-safe-seq"),
                    _ => format!("{{\"type\":\"ack\",\"through_seq\":{seq}}}"),
                };
                assert_eq!(
                    text.as_str(),
                    expected,
                    "ack must cover exactly the committed received sequence"
                );
            }
        } else {
            assert!(
                !matches!(response.as_ref(), Some(Ok(Message::Text(_)))),
                "uncommitted event must not be acked"
            );
            if let Some(code) = expected_close {
                assert!(
                    matches!(response, Some(Ok(Message::Close(Some(frame)))) if u16::from(frame.code) == code),
                    "invalid relay frames must close 4400"
                );
            }
        }
        let _ = socket.close(None).await;
    });
    let home = Arc::new(ConnectorHome::test_admitted());
    let socket = bounded(dial(&url, b"opaque-relay-token", &home))
        .await
        .unwrap();
    let failure = tokio::time::timeout(exchange_deadline, consume(socket, store, status, &home))
        .await
        .expect("relay replay exchange deadline");
    bounded(server).await.unwrap();
    failure
}
fn full_event() -> String {
    json!({"type":"event","seq":1,"delivery_id":"full-event","event":"issues","action":"opened","installation_id":42,"received_at":TIME,"stub":null,
        "body":{"repository":{"id":101,"full_name":"org/repo"},"issue":{"id":7,"number":3,"created_at":TIME,"updated_at":TIME,"title":"opened"}}}).to_string()
}
const ISSUE_PR_WEBHOOKS: [&str; 5] = [
    "issues",
    "issue_comment",
    "pull_request",
    "pull_request_review",
    "pull_request_review_comment",
];

fn issue_pr_frame(event_name: &str, seq: u64, sender: Option<Value>) -> String {
    let mut frame: Value = serde_json::from_str(&full_event()).unwrap();
    frame["event"] = json!(event_name);
    frame["seq"] = json!(seq);
    frame["delivery_id"] = json!(format!("sender-{seq}"));
    frame["body"]["issue"]["user"] = json!({"login":"item-author"});
    if event_name.starts_with("pull_request") {
        let item = frame["body"]
            .as_object_mut()
            .unwrap()
            .remove("issue")
            .unwrap();
        frame["body"]["pull_request"] = item;
    }
    match event_name {
        "issue_comment" | "pull_request_review_comment" => {
            frame["body"]["comment"] = json!({"id":8,"user":{"login":"comment-author"}});
        }
        "pull_request_review" => {
            frame["body"]["review"] = json!({"id":9,"user":{"login":"review-author"}});
        }
        _ => {}
    }
    if let Some(sender) = sender {
        frame["body"]["sender"] = sender;
    }
    frame.to_string()
}

fn stored_actor_fields(scratch: &Scratch) -> (Option<String>, Option<String>) {
    Connection::open(scratch.path())
        .unwrap()
        .query_row(
            "SELECT actor_logins, actor_unknown_reason FROM trigger_events WHERE kind='event'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

#[tokio::test]
async fn webhook_sender_is_stored_for_all_five_issue_and_pr_events() {
    for event_name in ISSUE_PR_WEBHOOKS {
        let (scratch, store, _) = fixture("relay-sender");
        let frame = issue_pr_frame(
            event_name,
            1,
            Some(json!({"login":"acting-user","type":"User","id":1234})),
        );
        replay(store.clone(), vec![hello(), frame], true).await;
        assert_eq!(count(&scratch, "trigger_events"), 1, "{event_name}");
        assert_eq!(
            stored_actor_fields(&scratch),
            (Some(r#"["acting-user"]"#.to_owned()), None),
            "{event_name} must store sender.login, not the item's author"
        );
        let served = store.list_events("direct", None, None).unwrap();
        assert_eq!(served[0].actor_logins, Some(vec!["acting-user".to_owned()]));
        assert_eq!(served[0].actor_unknown, None);
    }
}

#[tokio::test]
async fn webhook_bot_sender_spelling_matches_poller() {
    let (poll_scratch, poll_store, poll_sub) = fixture("relay-poll-bot");
    let payload = json!({"id":7,"number":3,"updated_at":TIME});
    let actor = plexus_core::ActorAttribution::Known(vec!["magic-alfonso[bot]".to_owned()]);
    poll_store
        .commit_poll_success(
            "direct",
            "conn-1",
            &poll_sub,
            &json!({}),
            &[plexus_core::PollEventInput {
                vendor_event_id: "poll-bot",
                payload: &payload,
                observed_at_ms: now_ms(),
                item_kind: Some("issue"),
                activity_at_ms: Some(now_ms()),
                actor: &actor,
            }],
            now_ms(),
            None,
        )
        .unwrap();
    let expected = (Some(r#"["magic-alfonso[bot]"]"#.to_owned()), None);
    assert_eq!(stored_actor_fields(&poll_scratch), expected);
    for event_name in ISSUE_PR_WEBHOOKS {
        let (scratch, store, _) = fixture("relay-bot-sender");
        let frame = issue_pr_frame(
            event_name,
            1,
            Some(json!({"login":"magic-alfonso[bot]","type":"Bot","id":1234})),
        );
        replay(store, vec![hello(), frame], true).await;
        assert_eq!(
            stored_actor_fields(&scratch),
            expected,
            "{event_name} must preserve [bot] to match the poller and agent identity"
        );
    }
}

#[tokio::test]
async fn webhook_missing_or_malformed_sender_records_unknown() {
    for event_name in ISSUE_PR_WEBHOOKS {
        for sender in [
            None,
            Some(Value::Null),
            Some(json!("not an account")),
            Some(json!({"type":"Bot","id":1234})),
            Some(json!({"login":null})),
            Some(json!({"login":1234})),
            Some(json!({"login":[]})),
            Some(json!({"login":""})),
            Some(json!({"login":" "})),
            Some(json!({"login":"not a login"})),
        ] {
            let (scratch, store, _) = fixture("relay-unknown-sender");
            let frame = issue_pr_frame(event_name, 1, sender.clone());
            replay(store.clone(), vec![hello(), frame], true).await;
            assert_eq!(count(&scratch, "trigger_events"), 1);
            assert_eq!(
                stored_actor_fields(&scratch),
                (None, Some("unrecognized_response_shape".to_owned())),
                "{event_name} with sender {sender:?} must record why the actor is unknown"
            );
            let served = store.list_events("direct", None, None).unwrap();
            assert_eq!(served[0].actor_logins, None);
            assert_eq!(
                serde_json::to_value(served[0].actor_unknown.as_ref().unwrap()).unwrap(),
                json!({"reason":"unrecognized_response_shape","class":"unexpected"})
            );
        }
    }
}

#[tokio::test]
async fn same_second_webhooks_keep_the_first_sender_like_poll_duplicates() {
    let (scratch, store, _) = fixture("relay-same-second-senders");
    let first = issue_pr_frame(
        "issues",
        1,
        Some(json!({"login":"first-user","type":"User","id":1234})),
    );
    let second = issue_pr_frame(
        "issue_comment",
        2,
        Some(json!({"login":"second-user","type":"User","id":5678})),
    );
    replay(store, vec![hello(), first, second], true).await;
    assert_eq!(count(&scratch, "trigger_events"), 1);
    assert_eq!(count(&scratch, "event_outbox"), 1);
    assert_eq!(
        stored_actor_fields(&scratch),
        (Some(r#"["first-user"]"#.to_owned()), None)
    );
}

#[tokio::test]
async fn webhook_ci_and_release_actor_fields_remain_unenriched() {
    for (event_name, item) in [
        ("workflow_job", "workflow_job"),
        ("workflow_run", "workflow_run"),
        ("release", "release"),
    ] {
        for sender in [
            None,
            Some(json!({"login":"magic-alfonso[bot]","type":"Bot","id":1234})),
        ] {
            let (scratch, store, _) = fixture("relay-unenriched");
            kind_watch(
                &store,
                if event_name == "release" {
                    "get_latest_release"
                } else {
                    "list_workflow_runs"
                },
            );
            let mut frame = json!({"type":"event","seq":1,"delivery_id":"unenriched","event":event_name,"action":"published","installation_id":42,"received_at":TIME,"stub":null,
                "body":{"repository":{"id":101,"full_name":"org/repo"},(item):{"id":7,"updated_at":TIME,"published_at":TIME,"completed_at":TIME,"status":"completed","run_attempt":2,"conclusion":"success"}}});
            if let Some(sender) = sender {
                frame["body"]["sender"] = sender;
            }
            replay(store, vec![hello(), frame.to_string()], true).await;
            assert_eq!(count(&scratch, "trigger_events"), 1, "{event_name}");
            assert_eq!(stored_actor_fields(&scratch), (None, None), "{event_name}");
        }
    }
}

#[tokio::test]
async fn webhook_ci_on_circuit_breaker_watch_is_stored_and_published() {
    for event_name in ["workflow_job", "workflow_run"] {
        let (scratch, store, issue) = fixture("relay-suspended-ci");
        let ci = kind_watch(&store, "list_workflow_runs");
        store
            .suspend(
                "direct",
                &ci,
                plexus_core::storage::CIRCUIT_BREAKER_SUSPENSION_REASON,
            )
            .unwrap();
        let before = store.subscription("direct", &ci).unwrap().unwrap();
        let frame = kind_frame(event_name);
        replay(store.clone(), vec![hello(), frame.to_string()], true).await;

        let events = store.drain_event_outbox(64).unwrap();
        assert_eq!(
            events.len(),
            1,
            "a circuit-breaker pause must not drop CI webhooks"
        );
        let event = &events[0];
        assert_eq!(
            event.subscription_id, ci,
            "CI webhooks must use the CI watch"
        );
        assert_ne!(event.subscription_id, issue);
        assert_eq!(event.connection_id, "conn-github-actions");
        assert_eq!(
            event.event_name,
            if event_name == "workflow_job" {
                "github_ci_job_completed"
            } else {
                "github_ci_run_completed"
            }
        );
        let after = store.subscription("direct", &ci).unwrap().unwrap();
        assert_eq!(after.status, "suspended");
        assert_eq!(after.suspended_reason, before.suspended_reason);
        assert_eq!(after.cursor_state, before.cursor_state);
        assert_eq!(after.last_polled_at_ms, before.last_polled_at_ms);
        assert_eq!(after.generation, before.generation);

        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "issue-consumer".into(),
                principal: "direct".into(),
                connection_id: "conn-1".into(),
                grantee_principal: "reserved:prefrontal-core".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["*".into()],
                authority_kind: "events_consume".into(),
                expires_at: None,
            })
            .unwrap();
        assert_eq!(
            store
                .event_by_key(
                    &event.event_key,
                    EventReader::Consumer {
                        principal: "reserved:prefrontal-core"
                    },
                    now_ms()
                )
                .unwrap(),
            EventLookupOutcome::NotVisible
        );
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "ci-consumer".into(),
                principal: "direct".into(),
                connection_id: "conn-github-actions".into(),
                grantee_principal: "reserved:basal".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["list_workflow_runs".into()],
                authority_kind: "events_consume".into(),
                expires_at: None,
            })
            .unwrap();
        assert!(matches!(
            store
                .event_by_key(
                    &event.event_key,
                    EventReader::Consumer {
                        principal: "reserved:basal"
                    },
                    now_ms()
                )
                .unwrap(),
            EventLookupOutcome::Found(_)
        ));
        assert_eq!(
            store.prune("direct", &ci, 0, 0).unwrap(),
            0,
            "unpublished CI events must survive pruning"
        );

        let publisher = MockPublisher::default();
        assert_eq!(
            crate::bus::drain_pass(
                &store,
                &cortexkit_bus_naming::AccountNames::derive("box_test").unwrap(),
                &publisher,
                64,
                &|| true
            )
            .await
            .unwrap(),
            2
        );
        let messages = publisher.published.lock().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages
                .iter()
                .filter(|message| message.subject.ends_with(".v1"))
                .count(),
            1
        );
        assert_eq!(
            messages
                .iter()
                .filter(|message| message.subject.ends_with(".v2"))
                .count(),
            1
        );
        drop(messages);
        assert_eq!(*publisher.acks.lock().unwrap(), 2);
        assert!(store.drain_event_outbox(64).unwrap().is_empty());
        assert!(store.drain_event_outbox_version(64, 2).unwrap().is_empty());
        assert_eq!(
            store.prune("direct", &ci, 0, 0).unwrap(),
            0,
            "published CI bodies retain the seven-day floor"
        );

        let resumed = store.resume("direct", &ci).unwrap().unwrap();
        assert_eq!(resumed.status, "active");
        assert_eq!(resumed.cursor_state, before.cursor_state);
        // A resumed poll can see the same change; its key must deduplicate without
        // losing the cursor advance or publishing the webhook a second time.
        let actor = plexus_core::ActorAttribution::NotEnriched;
        let polled = plexus_core::KeyedPollEventInput {
            event: plexus_core::PollEventInput {
                vendor_event_id: "polled-copy",
                payload: &frame["body"][event_name],
                observed_at_ms: now_ms(),
                item_kind: Some(if event_name == "workflow_job" {
                    "ci_job"
                } else {
                    "ci_run"
                }),
                activity_at_ms: None,
                actor: &actor,
            },
            identity: Some(plexus_core::KeyedEventIdentity {
                event_key: &event.event_key,
                event_name: &event.event_name,
                repo_id: 101,
                change: None,
                headers: &event.headers,
            }),
            delivery_id: None,
            envelope_context: Default::default(),
        };
        let next_cursor = json!({"scanned_through_ms":20});
        store
            .commit_keyed_poll_success(
                "direct",
                "conn-github-actions",
                &ci,
                &next_cursor,
                &[polled],
                now_ms(),
                &[],
            )
            .unwrap();
        assert_eq!(
            store
                .subscription("direct", &ci)
                .unwrap()
                .unwrap()
                .cursor_state,
            next_cursor
        );
        assert_eq!(count(&scratch, "trigger_events WHERE kind='event'"), 1);
        assert_eq!(count(&scratch, "event_outbox"), 1);
        assert!(store.drain_event_outbox(64).unwrap().is_empty());
    }
}

#[tokio::test]
async fn webhook_ci_without_counting_watch_is_dropped() {
    for event_name in ["workflow_job", "workflow_run"] {
        for reason in [
            None,
            Some("repository_identity_changed"),
            Some("catalog_schema_mismatch"),
            Some("retired"),
        ] {
            let (scratch, store, _) = fixture("relay-unwatched-ci");
            if let Some(reason) = reason {
                let ci = kind_watch(&store, "list_workflow_runs");
                store.suspend("direct", &ci, reason).unwrap();
                if reason == "retired" {
                    sql(&scratch, "UPDATE trigger_subscriptions SET status='retired' WHERE action='list_workflow_runs'");
                }
            }
            replay(
                store.clone(),
                vec![hello(), kind_frame(event_name).to_string()],
                true,
            )
            .await;
            assert_unwatched_kind(&scratch, &store);
        }
    }
}

#[tokio::test]
async fn webhook_release_without_counting_watch_is_dropped() {
    for reason in [
        None,
        Some("repository_identity_changed"),
        Some("catalog_schema_mismatch"),
    ] {
        let (scratch, store, _) = fixture("relay-unwatched-release");
        if let Some(reason) = reason {
            let release = kind_watch(&store, "get_latest_release");
            store.suspend("direct", &release, reason).unwrap();
        }
        replay(
            store.clone(),
            vec![hello(), kind_frame("release").to_string()],
            true,
        )
        .await;
        assert_unwatched_kind(&scratch, &store);
    }
}

#[tokio::test]
async fn webhook_release_on_circuit_breaker_watch_is_stored() {
    let (_scratch, store, _) = fixture("relay-suspended-release");
    let release = kind_watch(&store, "get_latest_release");
    store
        .suspend(
            "direct",
            &release,
            plexus_core::storage::CIRCUIT_BREAKER_SUSPENSION_REASON,
        )
        .unwrap();
    replay(
        store.clone(),
        vec![hello(), kind_frame("release").to_string()],
        true,
    )
    .await;
    let events = store.drain_event_outbox(64).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].subscription_id, release);
    assert_eq!(events[0].event_name, "github_release_published");
}

fn assert_unwatched_kind(scratch: &Scratch, store: &PlexusStore) {
    assert_eq!(
        count(scratch, "trigger_events WHERE kind='event'"),
        0,
        "unwatched kinds must never fall back to the issue watch"
    );
    assert_eq!(count(scratch, "event_outbox"), 0);
    let ledger: i64 = Connection::open(scratch.path())
        .unwrap()
        .query_row(
            "SELECT value FROM event_outbox_counters WHERE name='relay_drop_unwatched_repository'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ledger, 1);
    assert_eq!(
        store.relay_cursor(SOURCE).unwrap().unwrap().committed_seq,
        1
    );
}

#[tokio::test]
async fn pr_conversation_comment_queues_only_pr_watch_without_publish_and_acks() {
    for pr_watch_only in [false, true] {
        let (scratch, store, _) = fixture("relay-pr-comment-reread");
        if pr_watch_only {
            sql(
                &scratch,
                "DELETE FROM trigger_subscriptions WHERE action='list_issues'",
            );
        }
        add_other_repository(&scratch);
        assert_eq!(due(&scratch), 0);
        let mut frame: Value = serde_json::from_str(&issue_pr_frame(
            "issue_comment",
            1,
            Some(json!({"login":"magic-alfonso[bot]","type":"Bot","id":1234})),
        ))
        .unwrap();
        frame["action"] = json!("created");
        frame["body"]["issue"]["number"] = json!(655);
        frame["body"]["issue"]["updated_at"] = json!("2030-10-08T09:00:08Z");
        frame["body"]["issue"]["html_url"] = json!("https://github.com/org/repo/pull/655");
        frame["body"]["issue"]["pull_request"] =
            json!({"url":"https://api.github.com/repos/org/repo/pulls/655"});
        replay(store.clone(), vec![hello(), frame.to_string()], true).await;
        assert_eq!(
            count(&scratch, "trigger_events"),
            0,
            "PR conversation comments must queue a canonical PR read, not publish an issue event"
        );
        assert_eq!(count(&scratch, "event_outbox"), 0);
        let conn = Connection::open(scratch.path()).unwrap();
        let queued: Vec<String> = conn
            .prepare("SELECT subscription_id FROM trigger_subscriptions WHERE last_polled_at_ms IS NULL ORDER BY subscription_id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(queued, vec!["pr-watch"]);
        let dropped: i64 = conn
            .query_row(
                "SELECT value FROM event_outbox_counters WHERE name='relay_drop_pr_comment_reread'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dropped, 1);
        assert_eq!(
            store.relay_cursor(SOURCE).unwrap().unwrap().committed_seq,
            1
        );
    }
}

#[tokio::test]
async fn plain_issue_comment_still_publishes_issue_changed_with_sender() {
    let (scratch, store, _) = fixture("relay-plain-issue-comment");
    let frame = issue_pr_frame(
        "issue_comment",
        1,
        Some(json!({"login":"acting-user","type":"User","id":1234})),
    );
    replay(store.clone(), vec![hello(), frame], true).await;
    assert_eq!(count(&scratch, "trigger_events"), 1);
    assert_eq!(due(&scratch), 0);
    let published = store.drain_event_outbox(64).unwrap();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].event_name, "github_issue_changed");
    assert_eq!(
        published[0].event_key,
        plexus_core::derive_event_key(
            "github_issue_changed",
            &json!({"repo_id":101,"number":3,"updated_at":TIME})
        )
        .unwrap()
    );
    assert_eq!(
        stored_actor_fields(&scratch),
        (Some(r#"["acting-user"]"#.to_owned()), None)
    );
}

fn due(scratch: impl AsRef<std::path::Path>) -> i64 {
    Connection::open(scratch.as_ref())
        .unwrap()
        .query_row(
            "SELECT count(*) FROM trigger_subscriptions WHERE last_polled_at_ms IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[tokio::test]
async fn hello_source_mismatch_refuses_before_events_or_ack() {
    let (scratch, store, _) = fixture("relay-source");
    let bad = vector(
        include_str!("../tests/fixtures/webhook-relay/hello-source-mismatch.jsonl"),
        "source-differs-from-dialled",
    );
    replay_with_close(store, vec![bad, full_event()], false, Some(4400)).await;
    assert_eq!(
        count(&scratch, "relay_cursor"),
        0,
        "source mismatch must not establish a cursor"
    );
    assert_eq!(count(&scratch, "event_outbox"), 0);
}

#[tokio::test]
async fn changed_stream_resets_cursor_and_queues_full_reconcile() {
    let (scratch, store, _) = fixture("relay-reset");
    replay(store.clone(), vec![vector(HELLOS, "empty")], false).await;
    sql(&scratch, "UPDATE relay_cursor SET committed_seq=8");
    // A cursor at or beyond next_seq is also reset even when the stream id matches.
    // Keep next_seq above the stored cursor to test the stream-id reset alone.
    let recreated = vector(HELLOS, "changed-stream-id")
        .replace(ORIGINAL_STREAM, RECREATED_STREAM)
        .replace("\"next_seq\":1", "\"next_seq\":10");
    assert_ne!(
        serde_json::from_str::<Hello>(&hello()).unwrap().stream_id,
        serde_json::from_str::<Hello>(&recreated).unwrap().stream_id,
        "the recreated relay must emit a different stream id than the original hello"
    );
    replay(store.clone(), vec![recreated, full_event()], true).await;
    assert_eq!(
        store.relay_cursor(SOURCE).unwrap().unwrap().committed_seq,
        1,
        "changed stream must restart its cursor"
    );
    assert_eq!(due(&scratch), 2);
    assert_eq!(count(&scratch, "event_outbox"), 1);
}

#[tokio::test]
async fn restored_older_store_is_a_gap_not_merely_behind() {
    let (scratch, store, _) = fixture("relay-gap");
    replay(
        store.clone(),
        vec![vector(HELLOS, "last-acked-ahead-of-client")],
        false,
    )
    .await;
    assert_eq!(
        due(&scratch),
        2,
        "last ack ahead of restored store must reconcile"
    );
    assert_eq!(
        store.relay_cursor(SOURCE).unwrap().unwrap().committed_seq,
        1
    );
    sql(&scratch, "UPDATE trigger_subscriptions SET last_polled_at_ms=9999999999999; UPDATE relay_cursor SET committed_seq=0;");
    let expired = hello().replace("\"oldest_seq\":1", "\"oldest_seq\":2");
    replay(store, vec![expired], false).await;
    assert_eq!(
        due(&scratch),
        2,
        "expired buffered sequences must reconcile"
    );
}

#[tokio::test]
async fn ack_only_after_commit_and_crash_redelivers() {
    let (scratch, store, _) = fixture("relay-commit");
    sql(&scratch, "CREATE TRIGGER fail_relay_commit BEFORE UPDATE ON relay_cursor BEGIN SELECT RAISE(ABORT,'crash before commit'); END;");
    replay(store.clone(), vec![hello(), full_event()], false).await;
    assert_eq!(
        count(&scratch, "event_outbox"),
        0,
        "failed cursor commit rolls back the event and marker"
    );
    assert_eq!(
        store.relay_cursor(SOURCE).unwrap().unwrap().committed_seq,
        0
    );
    sql(&scratch, "DROP TRIGGER fail_relay_commit");
    replay(store.clone(), vec![hello(), full_event()], true).await;
    // Model an ack lost after commit: the relay still sends the original frame on reconnect.
    replay(store, vec![hello(), full_event()], true).await;
    assert_eq!(
        count(&scratch, "event_outbox"),
        1,
        "redelivery must not lose or duplicate the event"
    );
}

#[tokio::test]
async fn webhook_and_polled_copy_share_one_outbox_row() {
    for poll_first in [true, false] {
        let (scratch, store, sub) = fixture("relay-dedup");
        let payload =
            serde_json::from_str::<Value>(&full_event()).unwrap()["body"]["issue"].clone();
        let key = plexus_core::derive_event_key(
            "github_issue_changed",
            &json!({"repo_id":101,"number":3,"updated_at":TIME}),
        )
        .unwrap();
        let poll = || {
            crate::bus::tests::insert_test_event(
                &store,
                &sub,
                &key,
                "github_issue_changed",
                "org/repo",
                &payload,
            )
        };
        if poll_first {
            poll();
        }
        replay(store.clone(), vec![hello(), full_event()], true).await;
        if !poll_first {
            poll();
        }
        assert_eq!(
            count(&scratch, "event_outbox"),
            1,
            "webhook and poll must yield one outbox row"
        );
        assert_eq!(count(&scratch, "trigger_events"), 1);
        let events = store.drain_event_outbox(64).unwrap();
        assert_eq!(events[0].headers.project.as_deref(), Some("p1"));
        assert_eq!(events[0].event_key, key);
    }
}

fn add_other_repository(scratch: impl AsRef<std::path::Path>) {
    sql(scratch, "INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,schema_hash,status,created_at_ms,fixed_args,project_id,project_source,last_polled_at_ms)
        SELECT subscription_id || '-other',principal,connection_id,action,cadence_s,cursor_kind,schema_hash,status,created_at_ms,'{\"owner\":\"org\",\"repo\":\"other\"}',project_id,project_source,last_polled_at_ms FROM trigger_subscriptions;");
}

async fn stub_case(name: &str) {
    let (scratch, store, _) = fixture("relay-stub");
    add_other_repository(&scratch);
    stub_reconciles_without_publish(store, &scratch, name).await;
}
/// Replay one stub or binding vector over a store whose watch set already has
/// the second repository, and check it queued a reconcile and published nothing.
async fn stub_reconciles_without_publish(
    store: Arc<PlexusStore>,
    scratch: impl AsRef<std::path::Path>,
    name: &str,
) {
    let scratch = scratch.as_ref();
    replay(store, vec![hello(), vector(EVENTS, name)], true).await;
    assert_eq!(
        due(scratch),
        if name == "rate-limited" { 2 } else { 4 },
        "stub or binding must queue reconcile before ack"
    );
    assert_eq!(
        count(scratch, "event_outbox"),
        0,
        "stubs and bindings publish nothing"
    );
}
#[tokio::test]
async fn oversized_stub_queues_reread_without_publish() {
    stub_case("oversized").await;
}
#[tokio::test]
async fn rate_limited_stub_queues_reread_without_publish() {
    stub_case("rate-limited").await;
}
/// An overflow marker means the relay dropped events: the gap is logged for
/// the operator, the whole watch set is queued for reconcile, and nothing is
/// published. Run as a child so the warning can be read back from stderr.
#[tokio::test]
async fn overflow_stub_logs_gap_and_reconciles() {
    const TEST: &str = "relay::tests::overflow_stub_logs_gap_and_reconciles";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_none() {
        let prepared = prepare_relay_log_fixture("relay-overflow-log");
        add_other_repository(&prepared);
        let output = crate::bounded::child_output(
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", TEST, "--nocapture"])
                .env("PLEXUS_LOG_STDERR_CHILD", "1")
                .env(PREPARED_RELAY_LOG_STORE, prepared.path()),
            Duration::from_secs(30),
            "relay overflow diagnostic child",
        )
        .expect("run relay overflow child");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        crate::test_support::assert_exactly_one_test_passed(TEST, &output);
        let gaps: Vec<_> = stderr
            .lines()
            .filter(|line| line.contains(" WARN  plexus.relay: relay overflow gap at seq="))
            .collect();
        assert_eq!(
            gaps.len(),
            1,
            "an overflow must log one gap warning: {stderr}"
        );
        assert!(
            gaps[0].ends_with("; full reconcile queued"),
            "the gap warning must say a full reconcile was queued: {}",
            gaps[0]
        );
        return;
    }
    diagnostic_logging::init_child();
    let (_scratch, store, path) = relay_log_fixture("relay-overflow-log");
    stub_reconciles_without_publish(store, &path, "overflow").await;
}
#[tokio::test]
async fn installation_bound_list_queues_only_matching_repositories() {
    let (scratch, store, _) = fixture("relay-bound-list");
    add_other_repository(&scratch);
    sql(
        &scratch,
        "INSERT INTO github_repo_id_cache VALUES ('org/repo',7,1,1)",
    );
    replay(
        store.clone(),
        vec![hello(), vector(EVENTS, "installation-bound-repositories")],
        true,
    )
    .await;
    assert_eq!(
        due(&scratch),
        2,
        "bound list must queue matching watches before ack"
    );
    sql(&scratch, "UPDATE trigger_subscriptions SET last_polled_at_ms=9999999999999; UPDATE relay_cursor SET committed_seq=0; UPDATE github_repo_id_cache SET repo_id=8");
    replay(
        store,
        vec![hello(), vector(EVENTS, "installation-bound-repositories")],
        true,
    )
    .await;
    assert_eq!(
        due(&scratch),
        0,
        "bound list must not poll a replacement repository id"
    );
}
#[tokio::test]
async fn installation_bound_null_reconciles_whole_watch_set() {
    stub_case("installation-bound-all-repositories").await;
}

#[tokio::test]
async fn all_pinned_event_and_sequence_boundary_bytes_are_consumed() {
    for name in ["github", "max-safe-seq"] {
        let (scratch, store, _) = fixture("relay-vector");
        let greet = if name == "max-safe-seq" {
            vector(HELLOS, "max-safe-seq")
        } else {
            hello()
        };
        replay(store.clone(), vec![greet, vector(EVENTS, name)], true).await;
        let seq = if name == "max-safe-seq" {
            plexus_core::storage::relay::MAX_SEQ
        } else {
            1
        };
        assert_eq!(
            store.relay_cursor(SOURCE).unwrap().unwrap().committed_seq,
            seq
        );
        assert_eq!(
            count(&scratch, "event_outbox"),
            0,
            "repository-less pinned events must be dropped"
        );
    }
    assert_eq!(
        vector(ACKS, "max-safe-seq"),
        "{\"type\":\"ack\",\"through_seq\":9007199254740991}"
    );
}

/// Relay states follow store work: `Connected` is set only after the hello
/// cursor commits on the blocking pool, which ordinary parallel runs can delay
/// for seconds. So this waits with the store-work watchdog; the short bound in
/// `bounded` is for local accept, dial and socket reads.
async fn wait_state(status: &Status, expected: State) {
    tokio::time::timeout(crate::bounded::STORE_WORK_WAIT, async {
        loop {
            if status.0.lock().unwrap().state == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("relay never reached {expected:?}"));
}

#[tokio::test]
async fn revoked_4001_never_reports_vault_auth_failure_or_retries_same_bytes() {
    let (_scratch, store, _) = fixture("relay-revoked");
    let credentials = Arc::new(StubCredentialSource::with_default_success(
        b"relay-secret".to_vec(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let status = Arc::new(Status::default());
    let task_status = status.clone();
    let task_credentials = credentials.clone();
    let (stop, rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        run(
            &url,
            store,
            task_credentials,
            Arc::new(ConnectorHome::test_admitted()),
            &task_status,
            rx,
        )
        .await;
    });
    let (tcp, _) = bounded(listener.accept()).await.unwrap();
    let mut socket = accept_async(tcp).await.unwrap();
    socket.send(Message::Text(hello().into())).await.unwrap();
    socket
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Library(4001),
            reason: "credential revoked".into(),
        })))
        .await
        .unwrap();
    wait_state(&status, State::CredentialRejected).await;
    assert!(
        credentials.auth_failure_reports().is_empty(),
        "relay 4001 must never report a vault auth failure"
    );
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(300)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        status.0.lock().unwrap().state,
        State::CredentialRejected,
        "same rejected bytes must not reconnect"
    );
    drop(stop);
    bounded(task).await.unwrap();
    tokio::time::resume();
}

struct Claim {
    held: std::sync::atomic::AtomicBool,
    reads: std::sync::atomic::AtomicUsize,
}
impl crate::connector_home::RolePeer for Claim {
    fn call(&self, _: &str, _: Value) -> Result<Value, subc_protocol::ErrorBody> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(
            json!({"role":"connector_home","epoch":1,"known":true,"stale":false,"holder":null,"holder_name":null,"source":"cloud","held_here":self.held.load(std::sync::atomic::Ordering::SeqCst)}),
        )
    }
}
#[tokio::test]
async fn connector_home_is_checked_before_dial_and_again_on_superseded() {
    use std::sync::atomic::Ordering::SeqCst;
    struct RetryCredentials {
        source: StubCredentialSource,
        reads: std::sync::atomic::AtomicUsize,
        retry_started: Arc<tokio::sync::Notify>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl CredentialSource for RetryCredentials {
        fn get_by_id(
            &self,
            id: &str,
        ) -> Result<plexus_core::ResolvedCredential, plexus_core::CredentialError> {
            if self.reads.fetch_add(1, SeqCst) > 0 {
                self.retry_started.notify_one();
                let _ = self
                    .release
                    .lock()
                    .unwrap()
                    .recv_timeout(crate::bounded::STORE_WORK_WAIT);
            }
            self.source.get_by_id(id)
        }
    }
    let (_scratch, store, _) = fixture("relay-home");
    let claim = Arc::new(Claim {
        held: false.into(),
        reads: 0.into(),
    });
    let home = Arc::new(ConnectorHome::new(claim.clone()));
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let initial_listener = listener.clone();
    let initial_server = tokio::spawn(async move {
        let (tcp, _) = initial_listener.accept().await.unwrap();
        let mut socket = accept_async(tcp).await.unwrap();
        let _ = socket.close(None).await;
    });
    let result = bounded(dial(&url, b"secret", &home)).await;
    initial_server.abort();
    assert!(
        matches!(result, Err(Failure::NotHome)),
        "connector home must fence dial before network contact"
    );
    assert_eq!(claim.reads.load(SeqCst), 1);
    claim.held.store(true, SeqCst);
    // Publish admission before run subscribes, so an unread admission change
    // cannot trigger a retry whose pre-dial refresh masks the 4009 recheck.
    home.refresh().unwrap();
    assert_eq!(claim.reads.load(SeqCst), 2);
    let mut home_changes = home.decisions();
    let retry_started = Arc::new(tokio::sync::Notify::new());
    let (release_retry, wait_retry) = std::sync::mpsc::channel();
    // The refresh triggered by a 4009 close also publishes a claim-change wake.
    // Gate the next credential lookup before its pre-dial refresh, so that later
    // refresh cannot satisfy the assertion about handling the close.
    let credentials = Arc::new(RetryCredentials {
        source: StubCredentialSource::with_default_success(b"secret".to_vec()),
        reads: 0.into(),
        retry_started: retry_started.clone(),
        release: std::sync::Mutex::new(wait_retry),
    });
    let status = Arc::new(Status::default());
    let task_status = status.clone();
    let (stop, rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        run(&url, store, credentials, home, &task_status, rx).await;
    });
    let (tcp, _) = bounded(listener.accept()).await.unwrap();
    let mut socket = accept_async(tcp).await.unwrap();
    socket.send(Message::Text(hello().into())).await.unwrap();
    wait_state(&status, State::Connected).await;
    claim.held.store(false, SeqCst);
    socket
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Library(4009),
            reason: "superseded".into(),
        })))
        .await
        .unwrap();
    let refreshed_before_retry = bounded(async {
        tokio::select! {
            biased;
            result = home_changes.changed() => { result.unwrap(); true }
            _ = retry_started.notified() => false,
        }
    })
    .await;
    // Pause only the test's observer after the home-change notification. The
    // exact count must remain stable while the next attempt waits at the
    // credential fence, even when the test does not assert promptly.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        refreshed_before_retry && !*home_changes.borrow(),
        "4009 must immediately recheck connector home"
    );
    assert_eq!(
        claim.reads.load(SeqCst),
        4,
        "4009 must immediately recheck connector home"
    );
    wait_state(&status, State::Reconnecting).await;
    assert_eq!(status.degraded_message(), Some(SUPERSEDED_MESSAGE));
    drop(stop);
    drop(release_retry);
    bounded(task).await.unwrap();
}

#[tokio::test]
async fn unknown_source_http_is_not_credential_rejection() {
    let vector: Value = serde_json::from_str(
        include_str!("../tests/fixtures/webhook-relay/unknown-source.jsonl")
            .lines()
            .find(|line| line.contains("/ws"))
            .unwrap(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = bounded(listener.accept()).await.unwrap();
        let body = vector["body"].as_str().unwrap();
        socket.write_all(format!("HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    });
    assert!(
        matches!(
            bounded(dial(
                &url,
                b"secret",
                &Arc::new(ConnectorHome::test_admitted())
            ))
            .await,
            Err(Failure::SourceNotServed)
        ),
        "unknown source must not be classified as a credential refusal"
    );
    bounded(server).await.unwrap();
}

#[tokio::test]
async fn unknown_frames_and_out_of_order_events_are_protocol_errors() {
    for line in include_str!("../tests/fixtures/webhook-relay/unknown-type.jsonl").lines() {
        let name: Value = serde_json::from_str(line).unwrap();
        let (_scratch, store, _) = fixture("relay-unknown");
        replay_with_close(
            store,
            vec![hello(), vector(line, name["name"].as_str().unwrap())],
            false,
            Some(4400),
        )
        .await;
    }
    let (scratch, store, _) = fixture("relay-order");
    replay_with_close(
        store,
        vec![hello(), full_event().replace("\"seq\":1", "\"seq\":2")],
        false,
        Some(4400),
    )
    .await;
    assert_eq!(count(&scratch, "event_outbox"), 0);
}

#[tokio::test]
async fn relay_4001_logs_one_redacted_rejection_transition() {
    const TEST: &str = "relay::tests::relay_4001_logs_one_redacted_rejection_transition";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_none() {
        let prepared = prepare_relay_log_fixture("relay-4001-log");
        let output = crate::bounded::child_output(
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", TEST, "--nocapture"])
                .env("PLEXUS_LOG_STDERR_CHILD", "1")
                .env(PREPARED_RELAY_LOG_STORE, prepared.path()),
            Duration::from_secs(30),
            "relay rejection diagnostic test child",
        )
        .expect("run relay diagnostic fixture");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        let lines: Vec<_> = stderr
            .lines()
            .filter(|line| line.contains("4001"))
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "expected one 4001 diagnostic line: {stderr}"
        );
        diagnostic_logging::assert_diagnostic(
            lines[0],
            cortexkit_log::ParsedLevel::Warn,
            "plexus.relay",
            "relay state changed: credential_rejected cause=close 4001",
        );
        assert!(
            !lines[0].contains("relay-log-secret"),
            "credential leaked: {stderr}"
        );
        return;
    }

    diagnostic_logging::init_child();
    let (_scratch, store, _path) = relay_log_fixture("relay-4001-log");
    let secret = b"relay-log-secret";
    let credentials = Arc::new(StubCredentialSource::with_default_success(secret.to_vec()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let status = Arc::new(Status::default());
    let task_status = status.clone();
    let (stop, rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        run(
            &url,
            store,
            credentials,
            Arc::new(ConnectorHome::test_admitted()),
            &task_status,
            rx,
        )
        .await;
    });
    let (tcp, _) = bounded(listener.accept()).await.unwrap();
    let mut socket = accept_async(tcp).await.unwrap();
    socket.send(Message::Text(hello().into())).await.unwrap();
    wait_state(&status, State::Connected).await;
    socket
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Library(4001),
            reason: "revoked".into(),
        })))
        .await
        .unwrap();
    wait_state(&status, State::CredentialRejected).await;
    drop(stop);
    bounded(task).await.unwrap();
}

#[tokio::test]
async fn relay_credential_never_appears_in_logs_even_with_transport_trace() {
    use tracing_subscriber::prelude::*;
    const CHILD: &str = "PLEXUS_RELAY_TRACE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "relay::tests::relay_credential_never_appears_in_logs_even_with_transport_trace",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("CK_LOG", "trace");
        let output = crate::bounded::child_output(
            &mut command,
            Duration::from_secs(30),
            "relay trace child",
        )
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        crate::test_support::assert_exactly_one_test_passed(
            "relay::tests::relay_credential_never_appears_in_logs_even_with_transport_trace",
            &output,
        );
        return;
    }
    let scratch = Scratch::database("relay-log");
    let logs = scratch.path().with_extension("logs");
    let (layer, handle) =
        crate::bus::safe_log_layer(cortexkit_log::Config::in_dir("plexus", &logs)).unwrap();
    // Initialize the upstream log facade as well as tracing, so transport logs
    // really reach this subscriber; a tracing-only positive control cannot prove that.
    tracing_subscriber::Registry::default().with(layer).init();
    let secret = "relay-log-secret-opaque-bytes";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (tcp, _) = bounded(listener.accept()).await.unwrap();
        let mut socket = tokio_tungstenite::accept_hdr_async(
            tcp,
            ExpectedAuthorization(b"Bearer relay-log-secret-opaque-bytes"),
        )
        .await
        .unwrap();
        let _ = socket.close(None).await;
    });
    let socket = bounded(dial(
        &url,
        secret.as_bytes(),
        &Arc::new(ConnectorHome::test_admitted()),
    ))
    .await
    .unwrap();
    drop(socket);
    bounded(server).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let echo_server = tokio::spawn(async move {
        let (mut tcp, _) = bounded(listener.accept()).await.unwrap();
        let mut bytes = [0; 4096];
        let mut read = 0;
        while !bytes[..read].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let n = tcp.read(&mut bytes[read..]).await.unwrap();
            assert!(
                n > 0,
                "peer echo server must receive the full upgrade request"
            );
            read += n;
        }
        let request = std::str::from_utf8(&bytes[..read]).unwrap();
        let echo = request
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("authorization")
                    .then(|| value.trim().to_owned())
            })
            .unwrap();
        tcp.write_all(format!("HTTP/1.1 401 Unauthorized\r\nX-Relay-Echo: {echo}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{echo}", echo.len()).as_bytes()).await.unwrap();
    });
    assert!(matches!(
        bounded(dial(
            &url,
            secret.as_bytes(),
            &Arc::new(ConnectorHome::test_admitted())
        ))
        .await,
        Err(Failure::Rejected(RejectionCause::Http401AtConnect))
    ));
    bounded(echo_server).await.unwrap();
    tracing::trace!("relay-trace-positive-control");
    let text = std::fs::read_to_string(handle.path()).unwrap();
    assert!(
        text.contains("relay-trace-positive-control"),
        "trace must actually be enabled"
    );
    let debug_bytes = format!("{:?}", secret.as_bytes());
    let byte_sequence = debug_bytes.trim_start_matches('[').trim_end_matches(']');
    assert!(
        !text.contains(byte_sequence),
        "relay credential leaked in logs or transport trace as byte integers: {text}"
    );
    use base64::Engine;
    for encoded in [
        base64::engine::general_purpose::STANDARD.encode(secret),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret),
        secret
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    ] {
        assert!(
            !text.contains(&encoded),
            "relay credential leaked in logs or transport trace as encoded bytes: {text}"
        );
    }
    assert!(
        !text.contains(secret),
        "relay credential leaked in logs or transport trace: {text}"
    );
}

#[test]
fn relay_status_messages_and_health_degradation_are_closed() {
    let health = crate::health::HealthState::new();
    for (state, name, message, degraded) in [
        (State::Connected, "connected", None, false),
        (
            State::Reconnecting,
            "reconnecting",
            Some("Plexus lost its connection to the relay and is reconnecting."),
            false,
        ),
        (
            State::NoCredential,
            "no_credential",
            Some("Plexus has no relay credential for GitHub. Use Connect GitHub."),
            false,
        ),
        (
            State::CredentialRejected,
            "credential_rejected",
            Some("The relay refused Plexus's credential. Use Connect GitHub again."),
            true,
        ),
        (
            State::SourceNotServed,
            "source_not_served",
            Some("The relay doesn't serve GitHub events for this account."),
            true,
        ),
    ] {
        health.relay.set(state);
        assert_eq!(
            health.relay.status(),
            json!({"sources":[{"source":"github","state":name,"last_event_at":null,"message":message}]})
        );
        match health.report() {
            subc_protocol::session::ModuleControlResponse::HealthCheck {
                status, detail, ..
            } => {
                assert_eq!(
                    status == subc_protocol::session::HealthStatus::Degraded,
                    degraded
                );
                if degraded {
                    assert_eq!(detail.as_deref(), message);
                }
            }
            _ => panic!("expected health check"),
        }
    }
}

#[tokio::test]
async fn relay_status_is_read_only_direct_management() {
    let (_scratch, store, _) = fixture("relay-management");
    let state = Arc::new(crate::ModuleState {
        health: Arc::new(crate::health::HealthState::new()),
        runtime: crate::composition::ModuleRuntime::with_stub_credentials_and_mock_transport(
            store,
            Arc::new(StubCredentialSource::with_default_success(vec![1])),
            Arc::new(plexus_core::MockTransport::default()),
        ),
    });
    for direct in [false, true] {
        let bindings = Arc::new(crate::RouteBindings::new());
        let principal = if direct {
            subc_protocol::Principal::Direct
        } else {
            subc_protocol::Principal::Reserved {
                module_id: "ck-account".into(),
            }
        };
        bindings.insert(1, 1, principal).unwrap();
        let (writer, mut reader) = mpsc::channel(1);
        crate::handle_management_request(
            crate::RouteFrameContext {
                version: subc_protocol::PROTOCOL_VERSION,
                channel: 1,
                epoch: 1,
                correlation: 1,
            },
            STATUS_OP,
            &json!({}),
            &writer,
            &state,
            &bindings,
        )
        .await
        .unwrap();
        let frame = crate::bounded::recv_within(
            reader.recv(),
            Duration::from_secs(5),
            "relay.status reply",
        )
        .await;
        let reply: Value = serde_json::from_slice(&frame.body).unwrap();
        if direct {
            assert_eq!(reply["result"], state.health.relay.status());
        } else {
            assert_eq!(reply["error"]["code"], "operator_authority_required");
        }
    }
}

#[tokio::test]
async fn sixty_four_in_flight_frames_ack_in_received_order() {
    let (scratch, store, _) = fixture("relay-window");
    let mut frames = vec![hello()];
    for seq in 1..=64 {
        let mut event: Value = serde_json::from_str(&full_event()).unwrap();
        event["seq"] = seq.into();
        event["delivery_id"] = format!("window-{seq}").into();
        event["body"]["issue"]["number"] = seq.into();
        frames.push(event.to_string());
    }
    replay(store.clone(), frames, true).await;
    assert_eq!(count(&scratch, "event_outbox"), 64);
    assert_eq!(
        store.relay_cursor(SOURCE).unwrap().unwrap().committed_seq,
        64
    );
}

#[tokio::test]
async fn all_six_webhook_kinds_share_the_polled_identity_fields() {
    for (event_name, item, kind, extra) in [
        ("issues", "issue", "github_issue_changed", json!({})),
        (
            "pull_request",
            "pull_request",
            "github_pr_changed",
            json!({}),
        ),
        ("release", "release", "github_release_published", json!({})),
        (
            "workflow_job",
            "workflow_job",
            "github_ci_job_failed",
            json!({"conclusion":"failure"}),
        ),
        (
            "workflow_job",
            "workflow_job",
            "github_ci_job_completed",
            json!({"conclusion":"success"}),
        ),
        (
            "workflow_run",
            "workflow_run",
            "github_ci_run_completed",
            json!({"conclusion":"success"}),
        ),
    ] {
        let (_scratch, store, _) = fixture("relay-kinds");
        match event_name {
            "workflow_job" | "workflow_run" => {
                kind_watch(&store, "list_workflow_runs");
            }
            "release" => {
                kind_watch(&store, "get_latest_release");
            }
            _ => {}
        }
        let mut payload = json!({"id":7,"number":3,"created_at":TIME,"updated_at":TIME,"published_at":TIME,"completed_at":TIME,"status":"completed","run_attempt":2,"head_branch":"main"});
        for (key, value) in extra.as_object().unwrap() {
            payload[key] = value.clone();
        }
        let expected = plexus_core::derive_event_key(kind,&json!({"repo_id":101,"number":3,"updated_at":TIME,"release_id":7,"job_id":7,"run_id":7,"run_attempt":2,"conclusion":payload.get("conclusion")})).unwrap();
        let frame = json!({"type":"event","seq":1,"delivery_id":"identity","event":event_name,"action":"published","installation_id":42,"received_at":TIME,"stub":null,
            "body":{"repository":{"id":101,"full_name":"ORG/Repo"},(item):payload}}).to_string();
        replay(store.clone(), vec![hello(), frame], true).await;
        let events = store.drain_event_outbox(64).unwrap();
        assert_eq!(events.len(), 1, "{kind}");
        assert_eq!(events[0].event_key, expected, "{kind}");
        assert_eq!(events[0].event_name, kind);
        assert_eq!(events[0].headers.project.as_deref(), Some("p1"));
    }
}

#[tokio::test]
async fn unwatched_and_identity_changed_repositories_are_dropped_and_acked() {
    for changed in [false, true] {
        let (scratch, store, _) = fixture("relay-closed-drop");
        if changed {
            sql(
                &scratch,
                "INSERT INTO github_repo_id_cache VALUES ('org/repo',999,1,1)",
            );
        } else {
            sql(
                &scratch,
                "DELETE FROM trigger_subscriptions WHERE action='list_pull_requests'",
            );
        }
        replay(store, vec![hello(), full_event()], true).await;
        assert_eq!(count(&scratch, "event_outbox"), 0);
        let reason = if changed {
            "relay_drop_repository_identity_changed"
        } else {
            "relay_drop_unwatched_repository"
        };
        let ledger: i64 = Connection::open(scratch.path())
            .unwrap()
            .query_row(
                "SELECT value FROM event_outbox_counters WHERE name=?1",
                [reason],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ledger, 1);
        if changed {
            let suspended: i64 = Connection::open(scratch.path()).unwrap().query_row("SELECT count(*) FROM trigger_subscriptions WHERE suspended_reason='repository_identity_changed'",[],|r|r.get(0)).unwrap();
            assert_eq!(suspended, 2);
        }
    }
}

struct ObservedCredentials {
    source: Arc<StubCredentialSource>,
    reads: tokio::sync::mpsc::UnboundedSender<()>,
}
impl CredentialSource for ObservedCredentials {
    fn get_by_id(
        &self,
        id: &str,
    ) -> Result<plexus_core::ResolvedCredential, plexus_core::CredentialError> {
        let result = self.source.get_by_id(id);
        let _ = self.reads.send(());
        result
    }
    fn report_id_auth_failure(&self, id: &str, status: u16) {
        self.source.report_id_auth_failure(id, status);
    }
}
#[tokio::test]
async fn rejected_credential_is_reread_with_backoff_and_only_new_bytes_reconnect() {
    let (_scratch, store, _) = fixture("relay-new-credential");
    let credentials = Arc::new(StubCredentialSource::with_default_success(
        b"rejected-bytes".to_vec(),
    ));
    let (reads, mut read) = mpsc::unbounded_channel();
    let provider = Arc::new(ObservedCredentials {
        source: credentials.clone(),
        reads,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let status = Arc::new(Status::default());
    let task_status = status.clone();
    let (stop, rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        run(
            &url,
            store,
            provider,
            Arc::new(ConnectorHome::test_admitted()),
            &task_status,
            rx,
        )
        .await;
    });
    bounded(read.recv()).await.unwrap();
    let (tcp, _) = bounded(listener.accept()).await.unwrap();
    let mut socket = accept_async(tcp).await.unwrap();
    socket
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Library(4001),
            reason: "revoked".into(),
        })))
        .await
        .unwrap();
    wait_state(&status, State::CredentialRejected).await;
    let rejected_at = tokio::time::Instant::now();

    tokio::time::pause();
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    tokio::time::timeout(Duration::from_secs(3), read.recv())
        .await
        .expect("credential must be reread after the initial five-second delay")
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err(),
        "unchanged rejected bytes must not connect"
    );

    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    credentials.set_success(
        CREDENTIAL.as_bytes(),
        b"replacement-bytes".to_vec(),
        None,
        1,
    );
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(3), read.recv())
        .await
        .expect("replacement credential must be picked up well before five minutes")
        .unwrap();
    let (tcp, _) = bounded(listener.accept()).await.unwrap();
    let mut socket = tokio_tungstenite::accept_hdr_async(
        tcp,
        ExpectedAuthorization(b"Bearer replacement-bytes"),
    )
    .await
    .unwrap();
    socket.send(Message::Text(hello().into())).await.unwrap();
    wait_state(&status, State::Connected).await;
    assert!(
        tokio::time::Instant::now() - rejected_at < Duration::from_secs(300),
        "replacement credential must be picked up well before five minutes"
    );
    drop(stop);
    bounded(task).await.unwrap();
}

#[tokio::test]
async fn protocol_ping_is_sent_every_thirty_seconds() {
    let (_scratch, store, _) = fixture("relay-ping");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let accept = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        accept_async(tcp).await.unwrap()
    });
    let home = Arc::new(ConnectorHome::test_admitted());
    let socket = bounded(dial(&url, b"secret", &home)).await.unwrap();
    let mut server = bounded(accept).await.unwrap();
    let status = Arc::new(Status::default());
    let task_status = status.clone();
    let task = tokio::spawn(async move { consume(socket, store, &task_status, &home).await });
    server.send(Message::Text(hello().into())).await.unwrap();
    wait_state(&status, State::Connected).await;
    for _ in 0..2 {
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::time::resume();
        assert!(
            matches!(bounded(server.next()).await,Some(Ok(Message::Ping(payload))) if payload.is_empty()),
            "relay liveness must use a WebSocket protocol ping"
        );
        server.flush().await.unwrap();
        // Complete a round trip before advancing time again, so the client has
        // observed this pong and reset its receive deadline.
        server
            .send(Message::Ping(b"barrier".to_vec().into()))
            .await
            .unwrap();
        assert!(
            matches!(bounded(server.next()).await, Some(Ok(Message::Pong(payload))) if payload.as_ref() == b"barrier")
        );
    }
    server.close(None).await.unwrap();
    bounded(task).await.unwrap();
}

#[tokio::test]
async fn webhook_seeds_null_repository_identity_for_the_polled_copy() {
    let (scratch, store, sub) = fixture("relay-null-repository-id");
    sql(
        &scratch,
        "INSERT INTO github_repo_id_cache VALUES ('org/repo',NULL,1,NULL)",
    );
    replay(store.clone(), vec![hello(), full_event()], true).await;
    let repo_id = store.repo_id_cache("org/repo").unwrap().unwrap().repo_id;
    assert_eq!(
        repo_id,
        Some(101),
        "webhook must fill a failed resolution's null repository id"
    );
    let payload = serde_json::from_str::<Value>(&full_event()).unwrap()["body"]["issue"].clone();
    let key = plexus_core::derive_event_key(
        "github_issue_changed",
        &json!({"repo_id":repo_id,"number":3,"updated_at":TIME}),
    )
    .unwrap();
    crate::bus::tests::insert_test_event(
        &store,
        &sub,
        &key,
        "github_issue_changed",
        "org/repo",
        &payload,
    );
    assert_eq!(count(&scratch, "event_outbox"), 1);
    assert_eq!(count(&scratch, "trigger_events"), 1);
}

/// A source the relay does not serve is asked about again later, not parked
/// until a restart: the account may enable it. Time is paused, so the retry
/// lands at the recheck interval without a real five-minute wait.
#[tokio::test]
async fn an_unserved_source_is_retried_after_the_recheck_interval() {
    let (_scratch, store, _) = fixture("relay-unserved-retry");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let status = Arc::new(Status::default());
    let task_status = status.clone();
    let (stop, rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        run(
            &url,
            store,
            Arc::new(StubCredentialSource::with_default_success(
                b"secret".to_vec(),
            )),
            Arc::new(ConnectorHome::test_admitted()),
            &task_status,
            rx,
        )
        .await;
    });
    let body = r#"{"error":"unknown_source"}"#;
    let (mut first, _) = bounded(listener.accept()).await.unwrap();
    let mut request = [0u8; 4096];
    let _ = first.read(&mut request).await;
    first
        .write_all(
            format!(
                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    drop(first);
    wait_state(&status, State::SourceNotServed).await;
    tokio::time::pause();
    let retried = tokio::time::timeout(CREDENTIAL_RECHECK * 2, listener.accept()).await;
    tokio::time::resume();
    assert!(
        retried.is_ok(),
        "an unserved source must be asked about again after the recheck interval"
    );
    drop(stop);
    bounded(task).await.unwrap();
}

/// After the connector home was not held, the relay tries again soon after
/// this machine regains it, not after a fixed five minutes.
#[tokio::test]
async fn a_regained_connector_home_redials_within_the_claim_refresh_interval() {
    use std::sync::atomic::Ordering::SeqCst;
    let (_scratch, store, _) = fixture("relay-home-regained");
    let claim = Arc::new(Claim {
        held: false.into(),
        reads: 0.into(),
    });
    let home = Arc::new(ConnectorHome::new(claim.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let status = Arc::new(Status::default());
    let task_status = status.clone();
    let (stop, rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        run(
            &url,
            store,
            Arc::new(StubCredentialSource::with_default_success(
                b"secret".to_vec(),
            )),
            home,
            &task_status,
            rx,
        )
        .await;
    });
    // The first dial reads the claim, finds it not held, and backs off.
    bounded(async {
        while claim.reads.load(SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while status.status()["sources"][0]["state"] != "not_home" {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("not-home relay must report a deliberate stop");
    claim.held.store(true, SeqCst);
    tokio::time::pause();
    // Advance only the retry timer. Credential lookup runs on a real blocking
    // worker and TCP uses real I/O; auto-advancing through those awaits can jump
    // the clock to the dial timeout even when the retry started on time.
    tokio::time::advance(NOT_HOME_RECHECK).await;
    tokio::time::resume();
    let redialed = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;
    drop(stop);
    bounded(task).await.unwrap();
    assert!(
        redialed.is_ok(),
        "the redial waited longer than the claim refresh interval"
    );
}

#[tokio::test]
async fn local_store_failures_log_the_underlying_cause() {
    const TEST: &str = "relay::tests::local_store_failures_log_the_underlying_cause";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_none() {
        let prepared = prepare_relay_log_fixture("relay-commit-log");
        let output = crate::bounded::child_output(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env("PLEXUS_LOG_STDERR_CHILD", "1")
                .env(PREPARED_RELAY_LOG_STORE, prepared.path()),
            Duration::from_secs(30),
            "local store diagnostic child",
        )
        .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(
            stderr.contains("event commit store failure") && stderr.contains("relay_cursor"),
            "local store errors must be logged with their cause: {stderr}"
        );
        return;
    }
    diagnostic_logging::init_child();
    let (_scratch, store, path) = relay_log_fixture("relay-commit-log");
    Connection::open(path)
        .unwrap()
        .execute("DROP TABLE relay_cursor", [])
        .unwrap();
    let result = tokio::task::spawn_blocking(move || store.relay_cursor("github")).await;
    assert!(local_store_failed("event commit", result));
}

fn age_relay(status: &Status, seconds: u64) {
    let since = Instant::now()
        .checked_sub(Duration::from_secs(seconds))
        .unwrap();
    let mut snapshot = status.0.lock().unwrap();
    snapshot.connected_since = Some(since);
    snapshot.healthy_since = Some(since);
}

fn relay_scheduler(
    store: &Arc<PlexusStore>,
    status: Arc<Status>,
) -> plexus_core::Scheduler<StubCredentialSource, plexus_core::transport::MockTransport> {
    let engine = plexus_core::GovernanceEngine::new(
        store.clone(),
        Arc::new(StubCredentialSource::default()),
        Arc::new(plexus_core::transport::MockTransport::default()),
    );
    plexus_core::Scheduler::new(engine, 86_400_000).with_relay_health(status)
}

#[test]
fn relay_polling_requires_one_unbroken_hour_and_reports_why() {
    let health = crate::health::HealthState::new();
    let status = &health.relay;
    assert_eq!(status.polling_status()["mode"], "normal");
    assert_eq!(
        status.polling_status()["last_clock_reset"],
        "process_started"
    );
    status.set(State::Connected);
    let snapshot = status.0.lock().unwrap();
    let start = snapshot.connected_since.unwrap();
    assert!(!Status::slow_at(
        &snapshot,
        start + Duration::from_secs(3599)
    ));
    assert!(Status::slow_at(
        &snapshot,
        start + Duration::from_secs(3600)
    ));
    drop(snapshot);
    age_relay(status, 3600);
    let subc_protocol::session::ModuleControlResponse::HealthCheck {
        metrics: Some(metrics),
        ..
    } = health.report()
    else {
        panic!("health metrics")
    };
    assert_eq!(metrics["githubPolling"]["mode"], "relay_slow");
    assert_eq!(metrics["githubPolling"]["relay_state"], "connected");
    assert!(
        metrics["githubPolling"]["connected_for_ms"]
            .as_u64()
            .unwrap()
            >= 3_600_000
    );
    status.reset_clock("overflow");
    let polling = status.polling_status();
    assert_eq!(polling["mode"], "normal");
    assert_eq!(polling["last_clock_reset"], "overflow");
    assert!(polling["healthy_for_ms"].as_u64().unwrap() < 1000);
    assert!(polling["connected_for_ms"].as_u64().unwrap() >= 3_600_000);
    status.set(State::Reconnecting);
    assert_eq!(status.polling_status()["connected_for_ms"], Value::Null);
    status.set(State::Connected);
    let snapshot = status.0.lock().unwrap();
    let reconnected = snapshot.connected_since.unwrap();
    assert!(!Status::slow_at(
        &snapshot,
        reconnected + Duration::from_secs(3599)
    ));
    assert!(Status::slow_at(
        &snapshot,
        reconnected + Duration::from_secs(3600)
    ));
    drop(snapshot);
    assert_eq!(status.polling_status()["last_clock_reset"], "reconnecting");
    assert_eq!(Status::default().polling_status()["mode"], "normal");
}

#[test]
fn relay_polling_scheduler_slows_issue_pr_ci_but_not_releases() {
    let (scratch, store, issue) = fixture("relay-slow-scheduler");
    let release = kind_watch(&store, "get_latest_release");
    let ci = kind_watch(&store, "list_workflow_runs");
    let now = now_ms();
    sql(
        &scratch,
        &format!(
            "UPDATE trigger_subscriptions SET last_polled_at_ms={};",
            now - 300_000
        ),
    );
    let status = Arc::new(Status::default());
    status.set(State::Connected);
    let scheduler = relay_scheduler(&store, status.clone());
    let principals = ["direct".into()];
    assert_eq!(scheduler.due_now(&principals, now).len(), 4);
    age_relay(&status, 3600);
    let due = scheduler.due_now(&principals, now);
    assert_eq!(
        due.iter().map(|s| &s.subscription_id).collect::<Vec<_>>(),
        [&release]
    );
    assert_eq!(scheduler.due_now(&principals, now + 1_499_999).len(), 1);
    assert_eq!(scheduler.due_now(&principals, now + 1_500_000).len(), 4);
    for id in [&issue, &ci, &release, &"pr-watch".to_owned()] {
        assert_eq!(
            store.subscription("direct", id).unwrap().unwrap().cadence_s,
            300
        );
    }
    sql(
        &scratch,
        "UPDATE trigger_subscriptions SET cadence_s=2400 WHERE action='list_workflow_runs'",
    );
    assert_eq!(scheduler.due_now(&principals, now + 1_500_000).len(), 3);
    sql(
        &scratch,
        "UPDATE connections SET app_key='another_provider' WHERE connection_id='conn-1'",
    );
    assert_eq!(
        scheduler.due_now(&principals, now).len(),
        3,
        "other providers must keep their cadence"
    );
}

#[test]
fn relay_polling_ci_spacing_keeps_the_shared_quota_floor() {
    let (scratch, store, _) = fixture("relay-ci-quota-floor");
    let ci = kind_watch(&store, "list_workflow_runs");
    sql(&scratch, "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<99)
        INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,schema_hash,status,created_at_ms,fixed_args)
        SELECT 'ci-' || i,principal,connection_id,action,300,cursor_kind,schema_hash,'active',0,json_object('owner','org','repo','repo-' || i)
        FROM trigger_subscriptions,n WHERE action='list_workflow_runs';");
    let sub = store.subscription("direct", &ci).unwrap().unwrap();
    assert_eq!(
        store.ci_quota_cadence_s().unwrap(),
        5807,
        "100 watches share 62 whole eight-request cycles after repository lookups"
    );
    for slow in [false, true] {
        let mut cadences = plexus_core::scheduler::PollingCadences::new(&store, slow);
        assert_eq!(cadences.effective_cadence_s(&sub), 5807);
        let mut longer = sub.clone();
        longer.cadence_s = 10_000;
        assert_eq!(cadences.effective_cadence_s(&longer), 10_000);
        sql(&scratch, &format!("UPDATE trigger_subscriptions SET status='retired' WHERE cursor_kind='ci_runs' AND subscription_id!='{ci}'"));
        assert_eq!(
            cadences.effective_cadence_s(&sub),
            5807,
            "quota inputs must be read once for the whole pass"
        );
        let mut next_pass = plexus_core::scheduler::PollingCadences::new(&store, slow);
        assert_eq!(
            next_pass.effective_cadence_s(&sub),
            if slow { 1800 } else { 300 }
        );
        sql(
            &scratch,
            "UPDATE trigger_subscriptions SET status='active' WHERE cursor_kind='ci_runs'",
        );
    }
}

#[test]
fn relay_polling_batches_connections_and_refreshes_them_next_pass() {
    let (scratch, store, issue) = fixture("relay-connection-snapshot");
    let issue = store.subscription("direct", &issue).unwrap().unwrap();
    let pr = store.subscription("direct", "pr-watch").unwrap().unwrap();
    let mut cadences = plexus_core::scheduler::PollingCadences::new(&store, true);
    assert_eq!(cadences.effective_cadence_s(&issue), 1800);
    sql(
        &scratch,
        "UPDATE connections SET app_key='another_provider' WHERE connection_id='conn-1'",
    );
    assert_eq!(
        cadences.effective_cadence_s(&pr),
        1800,
        "one connection snapshot must serve all watches in a pass"
    );
    let mut next_pass = plexus_core::scheduler::PollingCadences::new(&store, true);
    assert_eq!(
        next_pass.effective_cadence_s(&pr),
        300,
        "the next pass must observe connection changes"
    );
}

#[tokio::test]
async fn relay_polling_gap_reset_and_overflow_restart_the_clock_and_catch_up() {
    for reason in ["gap", "sequence_reset", "stream_changed", "overflow"] {
        let (scratch, store, _) = fixture(&format!("relay-clock-{reason}"));
        store
            .relay_hello(
                SOURCE,
                &serde_json::from_str::<Hello>(&vector(HELLOS, "empty")).unwrap(),
            )
            .unwrap();
        let status = Status::default();
        status.set(State::Connected);
        age_relay(&status, 3600);
        assert_eq!(status.polling_status()["mode"], "relay_slow");
        let mut greeting: Value = serde_json::from_str(&vector(HELLOS, "empty")).unwrap();
        match reason {
            "gap" => {
                greeting["next_seq"] = json!(10);
                greeting["oldest_seq"] = json!(3);
            }
            "sequence_reset" => sql(&scratch, "UPDATE relay_cursor SET committed_seq=8"),
            "stream_changed" => greeting["stream_id"] = json!(RECREATED_STREAM),
            _ => {}
        }
        let mut frames = vec![greeting.to_string()];
        if reason == "overflow" {
            let mut event: Value = serde_json::from_str(&full_event()).unwrap();
            event["stub"] = json!("overflow");
            frames.push(event.to_string());
        }
        replay_using_status(store.clone(), frames, reason == "overflow", None, &status).await;
        assert_eq!(status.polling_status()["mode"], "normal", "{reason}");
        assert_eq!(status.polling_status()["last_clock_reset"], reason);
        assert_eq!(due(&scratch), 2, "{reason} must reuse reconciliation");
        let scheduler = relay_scheduler(&store, Arc::new(status));
        assert_eq!(scheduler.due_now(&["direct".into()], now_ms()).len(), 2);
    }
}

#[tokio::test]
async fn relay_polling_normal_disconnect_catches_up_once_and_reconnects_fresh() {
    let (scratch, store, _) = fixture("relay-disconnect-catchup");
    let release = kind_watch(&store, "get_latest_release");
    kind_watch(&store, "list_workflow_runs");
    let now = now_ms();
    sql(
        &scratch,
        &format!("UPDATE trigger_subscriptions SET last_polled_at_ms={now}"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let status = Arc::new(Status::default());
    let scheduler = relay_scheduler(&store, status.clone());
    let task_status = status.clone();
    let task_store = store.clone();
    let (stop, rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        run(
            &url,
            task_store,
            Arc::new(StubCredentialSource::with_default_success(
                b"secret".to_vec(),
            )),
            Arc::new(ConnectorHome::test_admitted()),
            &task_status,
            rx,
        )
        .await;
    });
    let (tcp, _) = bounded(listener.accept()).await.unwrap();
    let mut socket = accept_async(tcp).await.unwrap();
    socket
        .send(Message::Text(vector(HELLOS, "empty").into()))
        .await
        .unwrap();
    wait_state(&status, State::Connected).await;
    assert_eq!(status.polling_status()["mode"], "normal");
    assert!(scheduler.due_now(&["direct".into()], now).is_empty());
    socket.close(None).await.unwrap();
    wait_state(&status, State::Reconnecting).await;
    bounded(async {
        while due(&scratch) != 3 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(status.polling_status()["mode"], "normal");
    assert_eq!(status.polling_status()["last_clock_reset"], "reconnecting");
    let catchup = scheduler.due_now(&["direct".into()], now);
    assert_eq!(
        catchup.len(),
        3,
        "disconnect must immediately schedule issue, PR and CI"
    );
    assert!(!catchup.iter().any(|s| s.subscription_id == release));
    for sub in catchup {
        store
            .record_poll_attempt("direct", &sub.subscription_id, now)
            .unwrap();
    }
    assert!(
        scheduler.due_now(&["direct".into()], now).is_empty(),
        "catch-up must not repeat every pass"
    );
    let (tcp, _) = bounded(listener.accept()).await.unwrap();
    let mut socket = accept_async(tcp).await.unwrap();
    socket
        .send(Message::Text(vector(HELLOS, "empty").into()))
        .await
        .unwrap();
    wait_state(&status, State::Connected).await;
    assert_eq!(status.polling_status()["mode"], "normal");
    assert!(status.polling_status()["healthy_for_ms"].as_u64().unwrap() < 1000);
    drop(stop);
    bounded(task).await.unwrap();
}

#[test]
fn relay_polling_clean_reconnect_grace_has_a_five_minute_limit() {
    for (elapsed, expected) in [
        (Duration::from_secs(300), "relay_slow"),
        (Duration::from_secs(300) + Duration::from_nanos(1), "normal"),
    ] {
        let status = Status::default();
        status.connected(ORIGINAL_STREAM.into(), None);
        age_relay(&status, 3600);
        status.set(State::Reconnecting);
        let disconnected = status.0.lock().unwrap().disconnected_at.unwrap();
        // The bound is inclusive; test it without sleeping or wall-clock jitter.
        status.connected_at(ORIGINAL_STREAM.into(), None, disconnected + elapsed);
        let snapshot = status.0.lock().unwrap();
        assert_eq!(
            if Status::slow_at(&snapshot, disconnected + elapsed) {
                "relay_slow"
            } else {
                "normal"
            },
            expected,
            "clean reconnect grace must end after five minutes"
        );
        assert_eq!(snapshot.reconcile_pending, expected == "normal");
        if expected == "normal" {
            assert_eq!(snapshot.last_clock_reset, "reconnect_timeout");
        }
    }
}

#[test]
fn relay_polling_disqualifiers_cancel_reconnect_grace_immediately() {
    for reason in [
        "credential_rejected",
        "not_home",
        "no_credential",
        "source_not_served",
        "superseded",
        "overflow",
    ] {
        let status = Status::default();
        status.connected(ORIGINAL_STREAM.into(), None);
        age_relay(&status, 3600);
        status.set(State::Reconnecting);
        assert_eq!(status.polling_status()["mode"], "relay_slow");
        match reason {
            "credential_rejected" => status.rejected(RejectionCause::Close4001),
            "not_home" => status.set(State::NotHome),
            "no_credential" => status.set(State::NoCredential),
            "source_not_served" => status.set(State::SourceNotServed),
            "superseded" => status.superseded(),
            "overflow" => status.reset_clock("overflow"),
            _ => unreachable!(),
        }
        assert_eq!(status.polling_status()["mode"], "normal", "{reason}");
        assert_eq!(status.polling_status()["last_clock_reset"], reason);
        assert!(status.0.lock().unwrap().disconnected_at.is_none());
        // Overflow reconciliation is already committed with the event.
        assert_eq!(status.take_reconcile(), reason != "overflow");
        status.connected(ORIGINAL_STREAM.into(), None);
        assert_eq!(status.polling_status()["mode"], "normal");
    }
}

async fn reconnect_scenario(reason: &str) {
    reconnect_scenario_with_preparation_delay(reason, Duration::ZERO).await;
}

async fn reconnect_scenario_with_preparation_delay(reason: &str, retry_delay: Duration) {
    struct DelayedCredentials {
        reads: std::sync::atomic::AtomicUsize,
        retry_delay: Duration,
    }
    impl CredentialSource for DelayedCredentials {
        fn get_by_id(
            &self,
            _: &str,
        ) -> Result<plexus_core::ResolvedCredential, plexus_core::CredentialError> {
            if self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                std::thread::sleep(self.retry_delay);
            }
            Ok(plexus_core::ResolvedCredential::new(
                b"secret".to_vec(),
                None,
                1,
            ))
        }
    }
    struct PreparedHome(tokio::sync::mpsc::UnboundedSender<()>);
    impl crate::connector_home::RolePeer for PreparedHome {
        fn call(&self, _: &str, _: Value) -> Result<Value, subc_protocol::ErrorBody> {
            let _ = self.0.send(());
            Ok(
                json!({"role":"connector_home","epoch":1,"known":true,"stale":false,
                "holder":null,"holder_name":null,"source":"cloud","held_here":true}),
            )
        }
    }
    async fn prepared(
        ready: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
        reason: &str,
        phase: &str,
    ) {
        crate::bounded::recv_within(
            ready.recv(),
            crate::bounded::STORE_WORK_WAIT,
            &format!("{reason}: {phase} must reach the pre-dial home check"),
        )
        .await;
    }
    let (scratch, store, _) = fixture(&format!("relay-reconnect-{reason}"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/relay/github/ws", listener.local_addr().unwrap());
    let status = Arc::new(Status::default());
    let task_status = status.clone();
    let task_store = store.clone();
    let (ready, mut preparation) = tokio::sync::mpsc::unbounded_channel();
    let home = Arc::new(ConnectorHome::new(Arc::new(PreparedHome(ready))));
    // Refresh ConnectorHome and drain its initial readiness signal before
    // starting run, so that signal cannot satisfy a later pre-dial wait.
    home.refresh().unwrap();
    preparation.try_recv().unwrap();
    let (stop, rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        run(
            &url,
            task_store,
            Arc::new(DelayedCredentials {
                reads: 0.into(),
                retry_delay,
            }),
            home,
            &task_status,
            rx,
        )
        .await;
    });
    prepared(&mut preparation, reason, "initial preparation").await;
    let (tcp, _) = bounded(listener.accept()).await.unwrap();
    let mut socket = bounded(accept_async(tcp)).await.unwrap();
    socket
        .send(Message::Text(vector(HELLOS, "empty").into()))
        .await
        .unwrap();
    wait_state(&status, State::Connected).await;
    // Commit seq 1 so a clean resume must actually continue the durable cursor.
    socket
        .send(Message::Text(full_event().into()))
        .await
        .unwrap();
    let ack = bounded(socket.next()).await.unwrap().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(ack.to_text().unwrap()).unwrap()["through_seq"],
        1
    );
    let now = now_ms();
    sql(
        &scratch,
        &format!("UPDATE trigger_subscriptions SET last_polled_at_ms={now}"),
    );
    age_relay(&status, 3600);
    status.1.notify_one();
    bounded(async {
        while !status.0.lock().unwrap().logged_slow {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(status.polling_status()["mode"], "relay_slow");
    socket.close(None).await.unwrap();
    wait_state(&status, State::Reconnecting).await;
    assert_eq!(status.polling_status()["mode"], "relay_slow");
    assert_eq!(due(&scratch), 0, "short disconnect must not queue catch-up");
    // A normal retry waits two seconds of backoff; the delayed-credential case
    // adds another two seconds. Wait for the home check so neither consumes the
    // unchanged three-second WebSocket observation deadline.
    prepared(&mut preparation, reason, "retry preparation").await;
    let (tcp, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
        .await
        .expect("reconnect socket observation deadline")
        .unwrap();
    let mut socket = bounded(accept_async(tcp)).await.unwrap();
    let mut greeting: Value = serde_json::from_str(&vector(HELLOS, "empty")).unwrap();
    greeting["next_seq"] = json!(2);
    greeting["oldest_seq"] = json!(2);
    greeting["last_acked_seq"] = json!(1);
    match reason {
        "clean" => {}
        "timeout" => {
            status.0.lock().unwrap().disconnected_at =
                Some(Instant::now() - Duration::from_secs(600));
            status.1.notify_one();
            // No hello or health read: the supervisor must time out a stalled handshake itself.
            let queued = tokio::time::timeout(Duration::from_secs(3), async {
                while due(&scratch) != 2 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;
            assert!(
                queued.is_ok(),
                "expired reconnect must queue catch-up without hello"
            );
            assert_eq!(
                status.polling_status()["last_clock_reset"],
                "reconnect_timeout"
            );
        }
        "gap" => {
            greeting["next_seq"] = json!(4);
            greeting["oldest_seq"] = json!(3);
        }
        "sequence_reset" => {
            greeting["next_seq"] = json!(1);
            greeting["oldest_seq"] = json!(1);
            greeting["last_acked_seq"] = json!(0);
        }
        "stream_changed" => greeting["stream_id"] = json!(RECREATED_STREAM),
        _ => unreachable!(),
    }
    socket
        .send(Message::Text(greeting.to_string().into()))
        .await
        .unwrap();
    wait_state(&status, State::Connected).await;
    if reason == "clean" {
        assert_eq!(
            status.polling_status()["mode"],
            "relay_slow",
            "clean resume must preserve slow polling"
        );
        assert_eq!(due(&scratch), 0, "clean resume must not queue catch-up");
        assert!(relay_scheduler(&store, status.clone())
            .due_now(&["direct".into()], now + 300_000)
            .is_empty());
        let mut event: Value = serde_json::from_str(&full_event()).unwrap();
        event["seq"] = json!(2);
        event["delivery_id"] = json!("resumed-event");
        socket
            .send(Message::Text(event.to_string().into()))
            .await
            .unwrap();
        let ack = bounded(socket.next()).await.unwrap().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(ack.to_text().unwrap()).unwrap()["through_seq"],
            2
        );
        assert_eq!(
            store.relay_cursor(SOURCE).unwrap().unwrap().committed_seq,
            2
        );
    } else {
        assert_eq!(
            status.polling_status()["mode"],
            "normal",
            "reset hello must cancel slow reconnect grace: {reason}"
        );
        assert_eq!(due(&scratch), 2);
        assert_eq!(
            status.polling_status()["last_clock_reset"],
            if reason == "timeout" {
                "reconnect_timeout"
            } else {
                reason
            }
        );
        assert!(status.polling_status()["healthy_for_ms"].as_u64().unwrap() < 1000);
    }
    drop(stop);
    bounded(task).await.unwrap();
}

#[tokio::test]
async fn relay_polling_short_clean_reconnect_preserves_slow_without_catchup() {
    reconnect_scenario("clean").await;
}

#[tokio::test]
async fn relay_polling_expired_reconnect_goes_normal_without_waiting_for_hello() {
    reconnect_scenario("timeout").await;
}

#[tokio::test]
async fn relay_polling_reset_hello_cancels_slow_reconnect_grace() {
    reconnect_scenario("gap").await;
    reconnect_scenario("sequence_reset").await;
}

#[tokio::test]
async fn relay_polling_changed_stream_cancels_slow_reconnect_grace() {
    reconnect_scenario("stream_changed").await;
}

#[tokio::test]
async fn reconnect_socket_deadline_starts_after_credential_and_home_preparation() {
    reconnect_scenario_with_preparation_delay("clean", Duration::from_secs(2)).await;
}

#[test]
fn relay_polling_mode_changes_log_once_with_reason() {
    const TEST: &str = "relay::tests::relay_polling_mode_changes_log_once_with_reason";
    let reasons = [
        "overflow",
        "gap",
        "stream_changed",
        "sequence_reset",
        "not_home",
        "credential_rejected",
        "superseded",
        "reconnect_timeout",
    ];
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_none() {
        let output = crate::bounded::child_output(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env("PLEXUS_LOG_STDERR_CHILD", "1"),
            Duration::from_secs(30),
            "polling mode log child",
        )
        .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        for reason in reasons {
            let message = format!("GitHub polling mode changed: mode=normal reason={reason}");
            assert_eq!(
                stderr.matches(&message).count(),
                1,
                "every fallback must log its reason exactly once: {stderr}"
            );
        }
        assert_eq!(stderr.matches("GitHub polling mode changed: mode=relay_slow reason=healthy_relay_window_elapsed").count(), reasons.len() + 1, "slow entry must log once: {stderr}");
        assert_eq!(
            stderr
                .matches("GitHub polling kept relay_slow: reason=clean_resume")
                .count(),
            1,
            "clean resume needs one explanation: {stderr}"
        );
        assert_eq!(
            stderr.matches("GitHub polling mode changed:").count(),
            reasons.len() * 2 + 1,
            "reads must not repeat transition logs: {stderr}"
        );
        return;
    }
    diagnostic_logging::init_child();
    for reason in reasons {
        let status = Status::default();
        status.connected(ORIGINAL_STREAM.into(), None);
        age_relay(&status, 3600);
        assert_eq!(status.polling_status()["mode"], "relay_slow");
        status.polling_status();
        match reason {
            "overflow" => status.reset_clock(reason),
            "gap" | "stream_changed" | "sequence_reset" => {
                use plexus_core::storage::relay::CoverageReset;
                status.set(State::Reconnecting);
                let reset = match reason {
                    "gap" => CoverageReset::Gap,
                    "stream_changed" => CoverageReset::StreamChanged,
                    _ => CoverageReset::SequenceReset,
                };
                status.connected(ORIGINAL_STREAM.into(), Some(reset));
            }
            "not_home" => status.set(State::NotHome),
            "credential_rejected" => status.rejected(RejectionCause::Close4001),
            "superseded" => status.superseded(),
            "reconnect_timeout" => {
                status.set(State::Reconnecting);
                status.0.lock().unwrap().disconnected_at =
                    Some(Instant::now() - Duration::from_secs(600));
            }
            _ => unreachable!(),
        }
        assert_eq!(status.polling_status()["mode"], "normal");
        status.polling_status();
    }
    let status = Status::default();
    status.connected(ORIGINAL_STREAM.into(), None);
    age_relay(&status, 3600);
    status.polling_status();
    status.set(State::Reconnecting);
    status.connected(ORIGINAL_STREAM.into(), None);
    assert_eq!(status.polling_status()["mode"], "relay_slow");
}

#[test]
fn relay_marker_logging_counts_committed_watches_and_suppresses_repeats() {
    const TEST: &str =
        "relay::tests::relay_marker_logging_counts_committed_watches_and_suppresses_repeats";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_none() {
        let output = crate::bounded::child_output(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env("PLEXUS_LOG_STDERR_CHILD", "1"),
            Duration::from_secs(30),
            "marker due log child",
        )
        .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert_eq!(
            stderr.matches("relay markers made watches due:").count(),
            1,
            "marker bursts need one rate-limited line: {stderr}"
        );
        assert!(
            stderr.contains("latest_reason=installation_bound markers=1 watch_marks=2"),
            "log must count the affected watches: {stderr}"
        );
        return;
    }
    diagnostic_logging::init_child();
    let (scratch, store, _) = fixture("relay-marker-log");
    store
        .relay_hello(
            SOURCE,
            &serde_json::from_str::<Hello>(&vector(HELLOS, "empty")).unwrap(),
        )
        .unwrap();
    for seq in 1..=2 {
        let event: Event = serde_json::from_value(json!({"seq":seq,"delivery_id":format!("marker-{seq}"),"event":"cortexkit_installation_bound","installation_id":42,"received_at":TIME,"stub":null,"body":{"repositories":null}})).unwrap();
        store
            .commit_relay_event(SOURCE, ORIGINAL_STREAM, &event)
            .unwrap();
    }
    assert_eq!(due(&scratch), 2);
}

#[test]
fn credential_id_is_the_public_field_only() {
    const ID: &str = "01HZX3K7Q9M2R8T4V6W0Y5Z1AB";
    let good = format!("ckwr_acct42.{ID}.key7.macPART.secretPART");
    assert_eq!(credential_id(good.as_bytes()), Some(ID));
    // Anything other than exactly five fields with a ULID id yields nothing,
    // so no part of an unexpected credential format is ever logged.
    for malformed in [
        format!("ckwr_acct42.{ID}.key7.macPART"),
        format!("ckwr_acct42.{ID}.key7.macPART.secretPART.extra"),
        format!("other_acct42.{ID}.key7.macPART.secretPART"),
        "ckwr_acct42.01HZX3K7Q9M2R8T4V6W0Y5Z1AI.key7.mac.secret".to_string(),
        "ckwr_acct42.01hzx3k7q9m2r8t4v6w0y5z1ab.key7.mac.secret".to_string(),
        "ckwr_acct42.01HZX3K7Q9M2R8T4V6W0Y5Z1A.key7.mac.secret".to_string(),
    ] {
        assert_eq!(credential_id(malformed.as_bytes()), None, "{malformed}");
    }
    assert_eq!(credential_id(b"\xff\xfe"), None);
}
