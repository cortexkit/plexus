use super::*;
use cortexkit_bus_trait::ContentDigest;
use cortexkit_store_types::StorageDescriptor;
use plexus_core::{
    storage::event_outbox::{EventHeaders, KeyedEventIdentity, KeyedPollEventInput},
    test_scratch::Scratch,
    ActorAttribution, GrantInput, PlexusStore, PollEventInput,
};

fn test_store(name: &str) -> (Scratch, Arc<PlexusStore>, PathBuf) {
    let scratch = Scratch::database(name);
    let path = scratch.path().to_path_buf();
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: "test".to_string(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: scratch.to_string_lossy().into_owned(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).expect("open test plexus store"));
    (scratch, store, path)
}

fn seed_agent_binding(path: &Path, agent_id: &str, repo: &str) {
    let conn = rusqlite::Connection::open(path).expect("open sqlite for seeding");
    let handle = format!("handle-{agent_id}");
    conn.execute("INSERT INTO github_app_handle(app_handle_id, agent_id, app_id, credential_reference, status, proven_at, connection_principal, connection_id)
            VALUES (?1, ?2, 1, ?3, 'enabled', 1, 'direct', 'conn-github')
            ON CONFLICT(app_handle_id) DO UPDATE SET status='enabled'", rusqlite::params![handle, agent_id, format!("github_app:{agent_id}")]).expect("seed handle");
    conn.execute(
        "INSERT INTO github_repo_binding(repository, app_handle_id) VALUES (?1, ?2)
            ON CONFLICT(repository) DO UPDATE SET app_handle_id=excluded.app_handle_id",
        rusqlite::params![repo, handle],
    )
    .expect("seed binding");
}

fn unbind_repo(path: &Path, repo: &str) {
    let conn = rusqlite::Connection::open(path).expect("open sqlite for unbind");
    conn.execute(
        "DELETE FROM github_repo_binding WHERE repository = ?1",
        [repo],
    )
    .expect("unbind repo");
}

pub(super) fn seed_test_events(path: &Path, store: &PlexusStore) -> (String, String) {
    let conn = rusqlite::Connection::open(path).expect("open test db");
    conn.execute_batch(
            "INSERT INTO connections (connection_id, principal, app_key, status, created_at_ms, updated_at_ms)
             VALUES ('conn-github', 'direct', 'github', 'active', 1, 1),
                    ('conn-github-actions', 'direct', 'github_actions', 'active', 1, 1);
             INSERT INTO trigger_subscriptions (subscription_id, principal, connection_id, action, cadence_s, cursor_kind, cursor_state, schema_hash, status, created_at_ms)
             VALUES ('issue-sub-1', 'direct', 'conn-github', 'list_issues', 300, 'ordered_timestamp', '{}', 'hash', 'active', 1),
                    ('ci-sub-1', 'direct', 'conn-github-actions', 'list_workflow_runs', 300, 'ci_runs', '{}', 'hash', 'active', 1);
            ",
        )
        .expect("seed connections and subscriptions");

    // Grant core consume authority on conn-github
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-core-consume".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-github".to_string(),
            grantee_principal: "reserved:prefrontal-core".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["list_issues".to_string()],
            authority_kind: "events_consume".to_string(),
            expires_at: Some(i64::MAX / 2),
        })
        .expect("seed core consume grant");

    let issue_sub_id = "issue-sub-1".to_string();
    let ci_sub_id = "ci-sub-1".to_string();

    // Insert issue event
    let issue_key = "0000000000000000000000000000000000000000000000000000000000000001".to_string();
    let issue_payload = json!({"id": 1, "title": "bug report"});
    let issue_headers = EventHeaders {
        repo: "owner/repo".to_string(),
        project: Some("project-1".to_string()),
        pr: None,
        branch: None,
        conclusion: None,
    };
    let actor = ActorAttribution::NotEnriched;
    let issue_input = KeyedPollEventInput {
        event: PollEventInput {
            vendor_event_id: "issue-1",
            payload: &issue_payload,
            observed_at_ms: plexus_core::now_ms(),
            item_kind: Some("issue"),
            activity_at_ms: Some(plexus_core::now_ms()),
            actor: &actor,
        },
        identity: Some(KeyedEventIdentity {
            event_key: &issue_key,
            event_name: "github_issue_changed",
            repo_id: 101,
            change: Some("opened"),
            headers: &issue_headers,
        }),
        delivery_id: None,
        envelope_context: Default::default(),
    };
    store
        .commit_keyed_poll_success(
            "direct",
            "conn-github",
            &issue_sub_id,
            &json!({}),
            &[issue_input],
            plexus_core::now_ms(),
            &[],
        )
        .expect("commit issue event");

    // Insert CI event
    let ci_key = "0000000000000000000000000000000000000000000000000000000000000002".to_string();
    let ci_payload = json!({"run_id": 99, "status": "completed"});
    let ci_headers = EventHeaders {
        repo: "owner/repo".to_string(),
        project: Some("project-1".to_string()),
        pr: None,
        branch: Some("main".to_string()),
        conclusion: Some("failure".to_string()),
    };
    let ci_input = KeyedPollEventInput {
        event: PollEventInput {
            vendor_event_id: "run-99",
            payload: &ci_payload,
            observed_at_ms: plexus_core::now_ms(),
            item_kind: Some("ci_run"),
            activity_at_ms: Some(plexus_core::now_ms()),
            actor: &actor,
        },
        identity: Some(KeyedEventIdentity {
            event_key: &ci_key,
            event_name: "github_ci_run_completed",
            repo_id: 101,
            change: None,
            headers: &ci_headers,
        }),
        delivery_id: None,
        envelope_context: Default::default(),
    };
    store
        .commit_keyed_poll_success(
            "direct",
            "conn-github-actions",
            &ci_sub_id,
            &json!({"pinned": {}, "open": {}}),
            &[ci_input],
            plexus_core::now_ms(),
            &[],
        )
        .expect("commit ci event");

    (issue_key, ci_key)
}

async fn execute_tool_call(
    store: Arc<PlexusStore>,
    principal: Principal,
    scope: Option<CallScope>,
    tool_name: &str,
    arguments: Value,
) -> Value {
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(store),
    });
    let bindings = Arc::new(RouteBindings::new());
    bindings
        .insert_scoped(10, 1, principal, scope)
        .expect("bind route");
    let (writer, mut responses) = mpsc::channel(1);
    handle_tool_request(
        Frame::build(
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
            10,
            1,
            1,
            serde_json::to_vec(&json!({
                "name": tool_name,
                "arguments": arguments,
            }))
            .unwrap(),
        )
        .unwrap(),
        &writer,
        &state,
        &bindings,
    )
    .await
    .unwrap();
    let frame = crate::bounded::recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "events tool response",
    )
    .await;
    serde_json::from_slice(&frame.body).unwrap()
}

#[tokio::test]
async fn event_pages_preserve_full_listing_and_stable_ties() {
    let (_scratch, store, path) = test_store("event_pages");
    seed_test_events(&path, &store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("UPDATE trigger_events SET created_at_ms=123", [])
        .unwrap();
    for principal in [
        Principal::Direct,
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
    ] {
        let full = execute_tool_call(
            store.clone(),
            principal.clone(),
            None,
            manifest::EVENTS_TOOL,
            json!({"op":"list"}),
        )
        .await;
        let mut expected = store.list_events("direct", None, None).unwrap();
        if !matches!(principal, Principal::Direct) {
            expected.retain(|event| event.connection_id == "conn-github");
        }
        assert_eq!(full["result"]["events"], json!(expected));
        let first = execute_tool_call(
            store.clone(),
            principal.clone(),
            None,
            manifest::EVENTS_TOOL,
            json!({"op":"list","limit":1}),
        )
        .await;
        assert_eq!(first["result"]["events"].as_array().unwrap().len(), 1);
        let mut collected = first["result"]["events"].as_array().unwrap().clone();
        if full["result"]["events"].as_array().unwrap().len() > 1 {
            assert!(first["result"]["next_after"].is_object());
            let second = execute_tool_call(
                store.clone(),
                principal.clone(),
                None,
                manifest::EVENTS_TOOL,
                json!({"op":"list","limit":1,"after":first["result"]["next_after"]}),
            )
            .await;
            collected.extend(second["result"]["events"].as_array().unwrap().clone());
            assert!(second["result"].get("next_after").is_none());
        } else {
            assert!(first["result"].get("next_after").is_none());
        }
        assert_eq!(json!(collected), full["result"]["events"]);
        assert_eq!(
            first["result"]["events_consume_authority"],
            full["result"]["events_consume_authority"]
        );
        assert!(full["result"].get("next_after").is_none());
    }
    let invalid = execute_tool_call(
        store,
        Principal::Direct,
        None,
        manifest::EVENTS_TOOL,
        json!({"op":"list","limit":1001}),
    )
    .await;
    assert_eq!(invalid["error"]["code"], "invalid_request");
}

fn basal_flow_scope(agent_id: Option<&str>) -> CallScope {
    CallScope {
        owner: "basal".to_string(),
        scope_ref: "scope-1".to_string(),
        scope_epoch: 1,
        kind: None,
        parent: None,
        parent_state: None,
        agent_id: agent_id.map(str::to_string),
        flow_id: Some("flow-100".to_string()),
        delegates: false,
        owner_authorized: true,
    }
}

#[tokio::test]
async fn events_get_carrier_and_flow_scope_checks() {
    let (_scratch, store, path) = test_store("events_get_carrier_checks");
    let (issue_key, _) = seed_test_events(&path, &store);

    // 1. reserved:basal without flow scope -> flow_scope_required
    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        None,
        manifest::EVENTS_TOOL,
        json!({"op": "get", "event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    assert_eq!(res["error"]["code"], "flow_scope_required");

    // 2. non-admitted carrier with flow scope -> flow_carrier_not_admitted
    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "aft".to_string(),
        },
        Some(basal_flow_scope(None)),
        manifest::EVENTS_GET_TOOL,
        json!({ "event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    assert_eq!(res["error"]["code"], "flow_carrier_not_admitted");

    // 3. direct caller without flow scope -> events_get_carrier_refused
    let res = execute_tool_call(
        store.clone(),
        Principal::Direct,
        None,
        manifest::EVENTS_TOOL,
        json!({"op": "get", "event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    assert_eq!(res["error"]["code"], "events_get_carrier_refused");

    // 4. The consumer events lane is classic-only, including list and ack.
    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        Some(basal_flow_scope(None)),
        manifest::EVENTS_TOOL,
        json!({"op": "list"}),
    )
    .await;
    assert_eq!(res["error"]["code"], "call_mode_unsupported");
    assert_eq!(
        res["error"]["detail"],
        json!({"tool":"events","mode":"flow"})
    );

    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        Some(basal_flow_scope(None)),
        manifest::EVENTS_TOOL,
        json!({"op": "ack", "event_ids": ["123"]}),
    )
    .await;
    assert_eq!(res["error"]["code"], "call_mode_unsupported");
    assert_eq!(
        res["error"]["detail"],
        json!({"tool":"events","mode":"flow"})
    );
}

async fn compare_get_replies(
    store: Arc<PlexusStore>,
    principal: Principal,
    scope: Option<CallScope>,
    arguments: Value,
) -> Value {
    let get = execute_tool_call(
        store.clone(),
        principal.clone(),
        scope.clone(),
        manifest::EVENTS_GET_TOOL,
        arguments.clone(),
    )
    .await;
    if scope.as_ref().is_some_and(|scope| scope.flow_id.is_some()) {
        return get;
    }
    let mut legacy_arguments = arguments;
    legacy_arguments["op"] = json!("get");
    let legacy = execute_tool_call(
        store,
        principal,
        scope,
        manifest::EVENTS_TOOL,
        legacy_arguments,
    )
    .await;
    assert_eq!(
        get, legacy,
        "both event fetch surfaces must reply identically"
    );
    get
}

fn assert_issue_reply(reply: &Value, issue_key: &str) {
    use sha2::Digest;
    let result = reply["result"].as_object().expect("event lookup succeeds");
    assert_eq!(result.len(), 6);
    assert_eq!(result["event_key"], issue_key);
    assert_eq!(result["event_name"], "github_issue_changed");
    assert_eq!(result["repo"], "owner/repo");
    let body = result["body"].as_str().expect("stored body string");
    assert_eq!(
        serde_json::from_str::<Value>(body).unwrap(),
        json!({"id": 1, "title": "bug report"})
    );
    assert_eq!(
        result["digest"],
        format!("{:x}", sha2::Sha256::digest(body.as_bytes()))
    );
    assert_eq!(result["published_at"], Value::Null);
    assert_eq!(reply["structuredContent"], reply["result"]);
    assert_eq!(reply["isError"], false);
    assert_eq!(reply["content"][0]["type"], "text");
    assert_eq!(
        serde_json::from_str::<Value>(reply["content"][0]["text"].as_str().unwrap()).unwrap(),
        json!({"result": reply["result"]})
    );
}

#[tokio::test]
async fn events_get_tool_matches_legacy_for_consumer() {
    let (_scratch, store, path) = test_store("get_tool_consumer");
    let (issue_key, _) = seed_test_events(&path, &store);
    let reply = compare_get_replies(
        store,
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        None,
        json!({"event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    assert_issue_reply(&reply, &issue_key);
}

#[tokio::test]
async fn events_get_tool_fetches_for_basal_agent_flow() {
    let (_scratch, store, path) = test_store("get_tool_agent");
    let (issue_key, _) = seed_test_events(&path, &store);
    seed_agent_binding(&path, "agent-a", "Owner/Repo");
    let reply = compare_get_replies(
        store,
        Principal::Reserved {
            module_id: "basal".into(),
        },
        Some(basal_flow_scope(Some("agent-a"))),
        json!({"event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    assert_issue_reply(&reply, &issue_key);
}

#[tokio::test]
async fn events_get_tool_matches_legacy_refusals() {
    let (_scratch, store, path) = test_store("get_tool_refusals");
    let (issue_key, ci_key) = seed_test_events(&path, &store);
    seed_agent_binding(&path, "agent-a", "owner/repo");
    for (principal, scope, invisible_key, invisible_name) in [
        (
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            None,
            ci_key,
            "github_ci_run_completed",
        ),
        (
            Principal::Reserved {
                module_id: "basal".into(),
            },
            Some(basal_flow_scope(Some("agent-a"))),
            issue_key.clone(),
            "github_issue_changed",
        ),
    ] {
        for (key, name, code) in [
            ("f".repeat(64), "github_issue_changed", "event_not_visible"),
            (
                issue_key.clone(),
                "github_pr_changed",
                "event_name_mismatch",
            ),
        ] {
            let reply = compare_get_replies(
                store.clone(),
                principal.clone(),
                scope.clone(),
                json!({"event_key": key, "event_name": name}),
            )
            .await;
            assert_eq!(reply["error"]["code"], code);
            assert_eq!(reply["isError"], true, "a refusal must set isError");
        }
        let invisible_scope = scope.map(|_| basal_flow_scope(Some("agent-b")));
        let reply = compare_get_replies(
            store.clone(),
            principal,
            invisible_scope,
            json!({"event_key": invisible_key, "event_name": invisible_name}),
        )
        .await;
        assert_eq!(reply["error"]["code"], "event_not_visible");
    }
}

#[tokio::test]
async fn events_get_tool_rejects_non_basal_flow_carrier() {
    let (_scratch, store, _) = test_store("get_tool_carrier");
    let reply = execute_tool_call(
        store,
        Principal::Reserved {
            module_id: "aft".into(),
        },
        Some(basal_flow_scope(Some("agent-a"))),
        manifest::EVENTS_GET_TOOL,
        json!({"event_key": "0".repeat(64), "event_name": "github_issue_changed"}),
    )
    .await;
    assert_eq!(reply["error"]["code"], "flow_carrier_not_admitted");
    assert_eq!(reply["error"]["transmission"], "not_sent");
}

#[tokio::test]
async fn events_get_tool_requires_basal_flow_scope() {
    let (_scratch, store, _) = test_store("get_tool_scope");
    let mut non_flow_scope = basal_flow_scope(Some("agent-a"));
    non_flow_scope.flow_id = None;
    for scope in [None, Some(non_flow_scope)] {
        let reply = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".into(),
            },
            scope,
            manifest::EVENTS_GET_TOOL,
            json!({"event_key": "0".repeat(64), "event_name": "github_issue_changed"}),
        )
        .await;
        assert_eq!(reply["error"]["code"], "flow_scope_required");
        assert_eq!(reply["error"]["transmission"], "not_sent");
    }
}

#[tokio::test]
async fn events_get_tool_rejects_extra_arguments() {
    let (_scratch, store, path) = test_store("get_tool_extra");
    let (issue_key, _) = seed_test_events(&path, &store);
    for (key, value) in [
        ("op", json!("get")),
        ("agent_id", json!("agent-a")),
        ("extra", json!(null)),
    ] {
        let mut arguments = json!({"event_key": issue_key, "event_name": "github_issue_changed"});
        arguments[key] = value;
        let reply = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            None,
            manifest::EVENTS_GET_TOOL,
            arguments,
        )
        .await;
        assert_eq!(reply["error"]["code"], "invalid_request");
    }
}

#[tokio::test]
async fn events_get_version_one_is_the_default_and_version_two_never_falls_back() {
    let (_scratch, store, path) = test_store("get_tool_version");
    let (issue_key, _) = seed_test_events(&path, &store);
    let core = || Principal::Reserved {
        module_id: "prefrontal-core".into(),
    };
    let call = |arguments: Value| {
        execute_tool_call(
            store.clone(),
            core(),
            None,
            manifest::EVENTS_GET_TOOL,
            arguments,
        )
    };
    let base = json!({"event_key": issue_key, "event_name": "github_issue_changed"});
    let default = call(base.clone()).await;
    let mut explicit = base.clone();
    explicit["version"] = json!(1);
    assert_eq!(call(explicit).await["result"], default["result"]);
    assert!(default["result"]["body"].is_string());

    // Model a pre-v2 row: migration never backfills old events. Version 2
    // must refuse exactly as an unknown key does, never return the v1 body.
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE event_outbox SET envelope_v2=NULL, digest_v2=NULL WHERE event_key=?1",
            [&issue_key],
        )
        .unwrap();
    let mut v2 = base.clone();
    v2["version"] = json!(2);
    let v2_reply = call(v2).await;
    let unknown =
        call(json!({"event_key": "0".repeat(64), "event_name": "github_issue_changed"})).await;
    assert_eq!(
        v2_reply["error"], unknown["error"],
        "version 2 must not fall back to version 1"
    );
    assert!(v2_reply.get("result").is_none());

    for bad in [json!(0), json!(3), json!("2"), json!(1.5), json!(null)] {
        let mut arguments = base.clone();
        arguments["version"] = bad;
        let reply = call(arguments).await;
        assert_eq!(reply["error"]["code"], "invalid_request");
        assert_eq!(reply["error"]["field"], "version");
    }
}

#[tokio::test]
async fn v2_fetch_preserves_pre_workflow_name_ci_job_envelope_and_digest() {
    use sha2::Digest;

    let (_scratch, store, path) = test_store("v2-old-ci-job-envelope");
    seed_test_events(&path, &store);
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-core-ci-consume".into(),
            principal: "direct".into(),
            connection_id: "conn-github-actions".into(),
            grantee_principal: "reserved:prefrontal-core".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["list_workflow_runs".into()],
            authority_kind: "events_consume".into(),
            expires_at: Some(i64::MAX / 2),
        })
        .unwrap();

    let key = "0000000000000000000000000000000000000000000000000000000000000003";
    let payload = json!({
        "id": 703,
        "name": "legacy CI job",
        "workflow_name": "workflow name from newer source",
        "conclusion": "failure",
        "status": "completed",
        "head_branch": "main",
        "head_sha": "0123456789abcdef",
        "html_url": "https://github.com/owner/repo/actions/runs/702/job/703",
        "run_id": 702,
        "run_attempt": 1,
        "completed_at": "2026-10-11T00:45:44Z",
        "created_at": "2026-10-11T00:30:12Z",
        "updated_at": "2026-10-11T00:45:44Z"
    });
    let event_headers = EventHeaders {
        repo: "owner/repo".into(),
        project: Some("project-1".into()),
        pr: None,
        branch: Some("main".into()),
        conclusion: Some("failure".into()),
    };
    let actor = ActorAttribution::NotEnriched;
    let job = KeyedPollEventInput {
        event: PollEventInput {
            vendor_event_id: "job-703",
            payload: &payload,
            observed_at_ms: plexus_core::now_ms(),
            item_kind: Some("ci_job"),
            activity_at_ms: Some(plexus_core::now_ms()),
            actor: &actor,
        },
        identity: Some(KeyedEventIdentity {
            event_key: key,
            event_name: "github_ci_job_failed",
            repo_id: 101,
            change: Some("completed"),
            headers: &event_headers,
        }),
        delivery_id: None,
        envelope_context: Default::default(),
    };
    store
        .commit_keyed_poll_success(
            "direct",
            "conn-github-actions",
            "ci-sub-1",
            &json!({"pinned": {}, "open": {}}),
            &[job],
            plexus_core::now_ms(),
            &[],
        )
        .unwrap();

    // A ci_job envelope exactly as plexus stored it before the envelope gained
    // workflow_name. Stored envelopes are never rewritten, so fetching this
    // event must return these bytes and their original digest unchanged.
    let historical = r#"{"action":"updated","actor_logins":null,"actor_unknown":null,"completed_at":"2026-10-11T00:45:44Z","conclusion":"failure","event_key":"0000000000000000000000000000000000000000000000000000000000000003","head_branch":"main","head_sha":"0123456789abcdef","id":703,"kind":"ci_job","name":"legacy CI job","repo":"owner/repo","run_attempt":1,"run_id":702,"status":"completed","url":"https://github.com/owner/repo/actions/runs/702/job/703"}"#;
    let digest = format!("{:x}", sha2::Sha256::digest(historical.as_bytes()));
    let db = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        db.execute(
            "UPDATE event_outbox SET envelope_v2=?1,digest_v2=?2 WHERE event_key=?3",
            rusqlite::params![historical, digest, key],
        )
        .unwrap(),
        1
    );

    let result = execute_tool_call(
        store,
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        None,
        manifest::EVENTS_GET_TOOL,
        json!({"event_key":key,"event_name":"github_ci_job_failed","version":2}),
    )
    .await;
    assert_eq!(result["result"]["body"], historical);
    assert_eq!(result["result"]["digest"], digest);
}

#[tokio::test]
async fn v2_fetch_returns_stored_bytes_and_digest_without_recomputation() {
    use sha2::Digest;
    let (_scratch, store, path) = test_store("v2-stored-fetch");
    let (key, _) = seed_test_events(&path, &store);
    let db = rusqlite::Connection::open(&path).unwrap();
    let (stored, digest, legacy): (String,String,String) = db.query_row(
            "SELECT o.envelope_v2,o.digest_v2,e.payload FROM event_outbox o JOIN trigger_events e USING(event_id) WHERE o.event_key=?1", [&key],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(
        digest,
        format!("{:x}", sha2::Sha256::digest(stored.as_bytes()))
    );
    let body: Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(body["event_key"], key);
    assert_eq!(body["kind"], "issue");
    assert_eq!(body["actor_unknown"]["reason"], "actor_source_unbound");
    assert!(body["actor_logins"].is_null());
    let core = || Principal::Reserved {
        module_id: "prefrontal-core".into(),
    };
    let default = execute_tool_call(
        store.clone(),
        core(),
        None,
        manifest::EVENTS_GET_TOOL,
        json!({"event_key":key,"event_name":"github_issue_changed"}),
    )
    .await;
    assert_eq!(
        default["result"]["body"], legacy,
        "v1 must retain original stored bytes"
    );
    // A changed source body must not reconstruct or overwrite the envelope.
    assert_eq!(db.execute("UPDATE trigger_events SET payload='{\"number\":999,\"title\":\"changed after insert\"}' WHERE event_key=?1", [&key]).unwrap(), 1, "source-body mutation must touch one row");
    assert_eq!(db.execute("UPDATE event_outbox SET body_v1='{\"number\":999,\"title\":\"changed after insert\"}' WHERE event_key=?1", [&key]).unwrap(), 1, "canonical-body mutation must touch one row");
    let v2 = execute_tool_call(
        store.clone(),
        core(),
        None,
        manifest::EVENTS_GET_TOOL,
        json!({"event_key":key,"event_name":"github_issue_changed","version":2}),
    )
    .await;
    assert_eq!(
        v2["result"]["body"], stored,
        "v2 fetch must return stored envelope bytes without recomputing"
    );
    assert_eq!(v2["result"]["digest"], digest);
    let legacy_get = execute_tool_call(
        store.clone(),
        core(),
        None,
        manifest::EVENTS_TOOL,
        json!({"op":"get","event_key":key,"event_name":"github_issue_changed","version":2}),
    )
    .await;
    assert_eq!(legacy_get, v2);
    assert_eq!(
        digest,
        format!(
            "{:x}",
            sha2::Sha256::digest(v2["result"]["body"].as_str().unwrap().as_bytes())
        )
    );
    db.execute(
        "DELETE FROM grants WHERE authority_kind='events_consume'",
        [],
    )
    .unwrap();
    let denied = execute_tool_call(
        store,
        core(),
        None,
        manifest::EVENTS_GET_TOOL,
        json!({"event_key":key,"event_name":"github_issue_changed","version":2}),
    )
    .await;
    assert_eq!(denied["error"]["code"], "event_not_visible");
}

#[tokio::test]
async fn events_get_tool_matches_legacy_argument_validation() {
    let (_scratch, store, _) = test_store("get_tool_validation");
    for (arguments, field) in [
        (json!({"event_name": "github_issue_changed"}), "event_key"),
        (
            json!({"event_key": 1, "event_name": "github_issue_changed"}),
            "event_key",
        ),
        (
            json!({"event_key": "A".repeat(64), "event_name": "github_issue_changed"}),
            "event_key",
        ),
        (
            json!({"event_key": "0".repeat(63), "event_name": "github_issue_changed"}),
            "event_key",
        ),
        (json!({"event_key": "0".repeat(64)}), "event_name"),
        (
            json!({"event_key": "0".repeat(64), "event_name": null}),
            "event_name",
        ),
    ] {
        let reply = compare_get_replies(
            store.clone(),
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            None,
            arguments,
        )
        .await;
        assert_eq!(reply["error"]["code"], "invalid_request");
        assert_eq!(reply["error"]["field"], field);
    }
}

#[tokio::test]
async fn events_get_validates_request_fields() {
    let (_scratch, store, path) = test_store("events_get_val");
    let (issue_key, _) = seed_test_events(&path, &store);

    // Missing event_key
    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        Some(basal_flow_scope(Some("agent-1"))),
        manifest::EVENTS_GET_TOOL,
        json!({ "event_name": "github_issue_changed"}),
    )
    .await;
    assert_eq!(res["error"]["code"], "invalid_request");
    assert_eq!(res["error"]["field"], "event_key");

    // Malformed event_key (not 64 lowercase hex)
    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        Some(basal_flow_scope(Some("agent-1"))),
        manifest::EVENTS_GET_TOOL,
        json!({ "event_key": "not-64-hex", "event_name": "github_issue_changed"}),
    )
    .await;
    assert_eq!(res["error"]["code"], "invalid_request");
    assert_eq!(res["error"]["field"], "event_key");

    // Missing event_name
    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        Some(basal_flow_scope(Some("agent-1"))),
        manifest::EVENTS_GET_TOOL,
        json!({ "event_key": issue_key}),
    )
    .await;
    assert_eq!(res["error"]["code"], "invalid_request");
    assert_eq!(res["error"]["field"], "event_name");
}

#[tokio::test]
async fn events_get_refusals_and_mismatches() {
    let (_scratch, store, path) = test_store("events_get_refusals");
    let (issue_key, _) = seed_test_events(&path, &store);

    seed_agent_binding(&path, "agent-a", "owner/repo");

    // 1. Unknown key gives event_not_visible (NOT event_not_found)
    let unknown_key = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        Some(basal_flow_scope(Some("agent-a"))),
        manifest::EVENTS_GET_TOOL,
        json!({ "event_key": unknown_key, "event_name": "github_issue_changed"}),
    )
    .await;
    assert_eq!(res["error"]["code"], "event_not_visible");

    // 2. Mismatched event_name gives event_name_mismatch
    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        Some(basal_flow_scope(Some("agent-a"))),
        manifest::EVENTS_GET_TOOL,
        json!({ "event_key": issue_key, "event_name": "github_pr_changed"}),
    )
    .await;
    assert_eq!(res["error"]["code"], "event_name_mismatch");
}

#[tokio::test]
async fn events_get_agent_owned_flow_and_unbind() {
    let (_scratch, store, path) = test_store("events_get_agent_flow");
    let (issue_key, _) = seed_test_events(&path, &store);

    seed_agent_binding(&path, "agent-a", "Owner/Repo");

    // Agent A can read (case-insensitive binding check works!)
    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        Some(basal_flow_scope(Some("agent-a"))),
        manifest::EVENTS_GET_TOOL,
        json!({ "event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    assert!(
        res.get("result").is_some(),
        "agent-a must read bound event: {res}"
    );
    let result = &res["result"];
    assert_eq!(result["event_key"], issue_key);
    assert_eq!(result["event_name"], "github_issue_changed");
    assert_eq!(result["repo"], "owner/repo");
    let body_str = result["body"].as_str().expect("body string");
    let digest_str = result["digest"].as_str().expect("digest string");
    let computed_digest = ContentDigest::of_bytes(body_str.as_bytes()).to_string();
    assert_eq!(digest_str, computed_digest);

    // Agent B cannot read -> event_not_visible
    let res_b = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        Some(basal_flow_scope(Some("agent-b"))),
        manifest::EVENTS_GET_TOOL,
        json!({ "event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    assert_eq!(res_b["error"]["code"], "event_not_visible");

    // Unbind repository -> Agent A immediately gets event_not_visible
    unbind_repo(&path, "Owner/Repo");
    let res_after_unbind = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        Some(basal_flow_scope(Some("agent-a"))),
        manifest::EVENTS_GET_TOOL,
        json!({ "event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    assert_eq!(res_after_unbind["error"]["code"], "event_not_visible");
}

#[tokio::test]
async fn review_events_get_enforces_live_agent_repository_binding() {
    use plexus_core::storage::relay::{Event, Hello};
    let (_scratch, store, path) = test_store("review-event-visibility");
    seed_test_events(&path, &store);
    rusqlite::Connection::open(&path).unwrap().execute_batch(
            "UPDATE trigger_subscriptions SET fixed_args='{\"owner\":\"org\",\"repo\":\"repo\"}' WHERE subscription_id='issue-sub-1';
             INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,schema_hash,status,created_at_ms,fixed_args)
             VALUES ('pr-review','direct','conn-github','list_pull_requests',300,'ordered_timestamp','hash','active',1,'{\"owner\":\"org\",\"repo\":\"repo\"}');"
        ).unwrap();
    let hello: Hello = serde_json::from_value(json!({"v":1,"source":"github","stream_id":"reviews","next_seq":1,"oldest_seq":1,"last_acked_seq":0})).unwrap();
    store.relay_hello("github", &hello).unwrap();
    seed_agent_binding(&path, "review-agent", "ORG/REPO");
    for (seq, event_type, source, kind) in [
        (
            1,
            "pull_request_review",
            include_str!("../tests/fixtures/webhook-relay/review-submitted.json"),
            "github_pr_review_submitted",
        ),
        (
            2,
            "pull_request_review_comment",
            include_str!("../tests/fixtures/webhook-relay/review-comment-created.json"),
            "github_pr_review_comment_created",
        ),
    ] {
        let body: Value = serde_json::from_str(source).unwrap();
        let event: Event = serde_json::from_value(json!({"seq":seq,"delivery_id":format!("visibility-{seq}"),"event":event_type,
                "action":body["action"],"installation_id":42,"received_at":"2030-10-08T09:00:00.000Z","stub":null,"body":body})).unwrap();
        store
            .commit_relay_event("github", "reviews", &event)
            .unwrap();
        let row = store
            .drain_event_outbox(10)
            .unwrap()
            .into_iter()
            .find(|row| row.event_name == kind)
            .unwrap();
        for (agent, visible) in [
            ("review-agent".to_owned(), true),
            ("unbound-agent".into(), false),
        ] {
            let reply = execute_tool_call(
                store.clone(),
                Principal::Reserved {
                    module_id: "basal".into(),
                },
                Some(basal_flow_scope(Some(&agent))),
                manifest::EVENTS_GET_TOOL,
                json!({"event_key":row.event_key,"event_name":kind}),
            )
            .await;
            if visible {
                assert_eq!(reply["result"]["body"], row.body);
            } else {
                assert_eq!(
                    reply["error"]["code"], "event_not_visible",
                    "review events must enforce the calling agent's repository binding"
                );
            }
        }
    }
    unbind_repo(&path, "ORG/REPO");
    for row in store
        .drain_event_outbox(10)
        .unwrap()
        .into_iter()
        .filter(|row| row.event_name.starts_with("github_pr_review"))
    {
        let reply = execute_tool_call(
            store.clone(),
            Principal::Reserved {
                module_id: "basal".into(),
            },
            Some(basal_flow_scope(Some("review-agent"))),
            manifest::EVENTS_GET_TOOL,
            json!({"event_key":row.event_key,"event_name":row.event_name}),
        )
        .await;
        assert_eq!(reply["error"]["code"], "event_not_visible");
    }
}

#[tokio::test]
async fn events_get_global_flow_and_core_grants() {
    let (_scratch, store, path) = test_store("events_get_global_core");
    let (issue_key, ci_key) = seed_test_events(&path, &store);

    // Global flow without grant -> event_not_visible
    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        Some(basal_flow_scope(None)),
        manifest::EVENTS_GET_TOOL,
        json!({ "event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    assert_eq!(res["error"]["code"], "event_not_visible");

    // Add events_consume grant for reserved:basal on conn-github
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-basal-consume".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-github".to_string(),
            grantee_principal: "reserved:basal".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["list_issues".to_string()],
            authority_kind: "events_consume".to_string(),
            expires_at: Some(i64::MAX / 2),
        })
        .expect("grant basal consume");

    // Global flow now sees issue event!
    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "basal".to_string(),
        },
        Some(basal_flow_scope(None)),
        manifest::EVENTS_GET_TOOL,
        json!({ "event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    assert!(res.get("result").is_some());

    // Prefrontal-core: sees issue event on conn-github
    let res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "prefrontal-core".to_string(),
        },
        None,
        manifest::EVENTS_TOOL,
        json!({"op": "get", "event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    assert!(res.get("result").is_some());

    // Prefrontal-core: cannot see CI event on conn-github-actions -> event_not_visible
    let res_ci = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "prefrontal-core".to_string(),
        },
        None,
        manifest::EVENTS_TOOL,
        json!({"op": "get", "event_key": ci_key, "event_name": "github_ci_run_completed"}),
    )
    .await;
    assert_eq!(res_ci["error"]["code"], "event_not_visible");
}

#[tokio::test]
async fn scoped_core_requires_own_consume_grant() {
    let (_scratch, store, path) = test_store("scoped_core_grant");
    let (_, ci_key) = seed_test_events(&path, &store);
    seed_agent_binding(&path, "agent-a", "owner/repo");
    let mut scope = basal_flow_scope(Some("agent-a"));
    scope.flow_id = None;
    let reply = execute_tool_call(
        store,
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        Some(scope),
        manifest::EVENTS_TOOL,
        json!({"op":"get", "event_key":ci_key, "event_name":"github_ci_run_completed"}),
    )
    .await;
    assert_eq!(reply["error"]["code"], "event_not_visible");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn codemode_events_get_keeps_module_visibility_despite_delegation() {
    let (_scratch, store, path) = test_store("run_events");
    let (issue_key, ci_key) = seed_test_events(&path, &store);
    seed_agent_binding(&path, "agent-a", "owner/repo");
    let principal = Principal::Reserved {
        module_id: "prefrontal-core".into(),
    };
    let stamp = subc_protocol::scope::ScopeStamp::new(
        principal.clone(),
        "run-events",
        1,
        subc_protocol::scope::ScopeKind::Worker,
    )
    .with_attributes(
        subc_protocol::scope::ScopeAttributes::new()
            .with_agent_id(Some("agent-a".into()))
            .with_run_id(Some("run-events".into()))
            .with_delegates(true),
    )
    .with_owner_authorized(true);
    for (key, name, visible) in [
        (issue_key, "github_issue_changed", true),
        (ci_key, "github_ci_run_completed", false),
    ] {
        let reply = crate::call_mode_tests::bound_call(
            runtime_for_test(store.clone()),
            principal.clone(),
            Some(stamp.clone()),
            Some(CallMode::Codemode),
            manifest::EVENTS_GET_TOOL,
            json!({"event_key":key,"event_name":name}),
        )
        .await;
        if visible {
            assert!(reply.get("result").is_some(), "{reply}");
        } else {
            assert_eq!(
                reply["error"]["code"], "event_not_visible",
                "a run cannot borrow its agent's event bindings: {reply}"
            );
        }
    }
}

#[test]
fn hostile_argument_agent_id_never_overrides_stamp() {
    let (_scratch, store, path) = test_store("hostile_event_identity");
    let (issue_key, _) = seed_test_events(&path, &store);
    seed_agent_binding(&path, "agent-a", "owner/repo");
    for (stamp, argument, visible) in [("agent-b", "agent-a", false), ("agent-a", "agent-b", true)]
    {
        // Exercise the reader itself with hostile input. The public
        // events_get schema rejects this field before reaching the reader.
        let reply = event_get_reply(&store,
                json!({"event_key":issue_key, "event_name":"github_issue_changed", "agent_id":argument}).as_object().unwrap(),
                "reserved:basal", Some(&basal_flow_scope(Some(stamp))), None);
        if visible {
            assert!(reply.get("result").is_some(), "{reply}");
        } else {
            assert_eq!(reply["error"]["code"], "event_not_visible");
        }
    }
}

#[tokio::test]
async fn events_get_body_matches_independent_sqlite_payload_bytes() {
    use sha2::Digest;
    let (_scratch, store, path) = test_store("verbatim_event_body");
    let (key, _) = seed_test_events(&path, &store);
    let db = rusqlite::Connection::open(&path).unwrap();
    // Overwrite the stored version-1 body with JSON spacing and a `\u00e9`
    // escape that a serializer would not produce, as a body written by an
    // older producer may look. Fetching the event must return these exact
    // bytes, not JSON rebuilt from the watch's linked `trigger_events` row.
    let raw = "{ \"z\": 1,\n  \"a\": \"\\u00e9\" }\n";
    let digest = format!("{:x}", sha2::Sha256::digest(raw.as_bytes()));
    assert_eq!(
        db.execute(
            "UPDATE event_outbox SET body_v1=?1,digest_v1=?2 WHERE event_key=?3",
            (raw, &digest, &key),
        )
        .unwrap(),
        1,
        "verbatim payload mutation must touch one seeded row"
    );
    let stored: String = db
        .query_row(
            "SELECT body_v1 FROM event_outbox WHERE event_key = ?1",
            [&key],
            |r| r.get(0),
        )
        .unwrap();
    let reply = execute_tool_call(
        store,
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        None,
        manifest::EVENTS_TOOL,
        json!({"op":"get", "event_key":key, "event_name":"github_issue_changed"}),
    )
    .await;
    assert_eq!(
        reply["result"]["body"].as_str().unwrap().as_bytes(),
        stored.as_bytes(),
        "reply must preserve stored bytes"
    );
    assert_eq!(
        reply["result"]["digest"],
        format!("{:x}", sha2::Sha256::digest(stored.as_bytes()))
    );
}

#[tokio::test]
async fn events_get_read_only_and_survives_ack() {
    let (_scratch, store, path) = test_store("events_get_ack");
    let (issue_key, _) = seed_test_events(&path, &store);

    // Core reads before ack
    let res_before = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "prefrontal-core".to_string(),
        },
        None,
        manifest::EVENTS_TOOL,
        json!({"op": "get", "event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    let body_before = res_before["result"]["body"].as_str().unwrap();
    let digest_before = res_before["result"]["digest"].as_str().unwrap();

    // Core lists events
    let list_res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "prefrontal-core".to_string(),
        },
        None,
        manifest::EVENTS_TOOL,
        json!({"op": "list"}),
    )
    .await;
    let event_id = list_res["result"]["events"][0]["event_id"]
        .as_str()
        .unwrap();

    // Core acks the event
    let ack_res = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "prefrontal-core".to_string(),
        },
        None,
        manifest::EVENTS_TOOL,
        json!({"op": "ack", "event_ids": [event_id]}),
    )
    .await;
    assert_eq!(ack_res["result"]["acked"], 1);

    // Core reads after ack: body is verbatim, sha256(body) == digest
    let res_after = execute_tool_call(
        store.clone(),
        Principal::Reserved {
            module_id: "prefrontal-core".to_string(),
        },
        None,
        manifest::EVENTS_TOOL,
        json!({"op": "get", "event_key": issue_key, "event_name": "github_issue_changed"}),
    )
    .await;
    let body_after = res_after["result"]["body"].as_str().unwrap();
    let digest_after = res_after["result"]["digest"].as_str().unwrap();

    assert_eq!(body_before, body_after);
    assert_eq!(digest_before, digest_after);
    assert_eq!(
        digest_after,
        ContentDigest::of_bytes(body_after.as_bytes()).to_string()
    );
}
