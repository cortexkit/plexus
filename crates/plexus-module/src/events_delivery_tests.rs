use super::*;
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{BindIdentity, RouteTarget};

fn consume_authority_store(test_name: &str) -> Arc<PlexusStore> {
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: format!(
            "events-consume-authority-{test_name}-{}",
            std::process::id()
        ),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).expect("test store"));
    let manifest_source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github.jsonc"),
    )
    .expect("read the shipped github manifest");
    let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize manifest");
    let ingested = plexus_core::ingest_value(
        serde_json::from_str::<Value>(&normalized).expect("parse manifest"),
    )
    .expect("ingest manifest");
    store
        .upsert_manifest("system", &ingested)
        .expect("seed manifest");
    store
        .insert_connection(
            "direct",
            "conn-consume-authority",
            &ingested.manifest.key,
            "active",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("seed connection");
    store
}

fn insert_consume_grant(store: &PlexusStore, grant_id: &str, expires_at: Option<i64>) {
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: grant_id.to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-consume-authority".to_string(),
            grantee_principal: "reserved:prefrontal-core".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["list_issues".to_string()],
            authority_kind: plexus_core::AUTHORITY_EVENTS_CONSUME.to_string(),
            expires_at,
        })
        .expect("seed consume grant");
}

async fn list_as_reserved_consumer(store: Arc<PlexusStore>) -> Value {
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(store),
    });
    crate::test_support::send_tool_call(
        &state,
        Principal::Reserved {
            module_id: "prefrontal-core".to_string(),
        },
        None,
        None,
        manifest::EVENTS_TOOL,
        json!({"op": "list"}),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_consume_authority_is_visible_on_an_empty_wire_list() {
    let store = consume_authority_store("expired");
    let deadline = plexus_core::now_ms() - 1;
    insert_consume_grant(&store, "grant-consume-expired", Some(deadline));

    let body = list_as_reserved_consumer(store).await;
    assert_eq!(body["result"]["events"], json!([]));
    let grants = body["result"]["events_consume_authority"]["grants"]
        .as_array()
        .unwrap_or_else(|| panic!("consume authority grants missing: {body}"));
    assert_eq!(grants.len(), 1, "expired grant missing: {body}");
    assert_eq!(grants[0]["authority_state"], "expired");
    assert_eq!(grants[0]["authority_expires_at_ms"], deadline);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_consume_authority_is_visible_on_an_empty_wire_list() {
    let body = list_as_reserved_consumer(consume_authority_store("absent")).await;

    assert_eq!(body["result"]["events"], json!([]));
    assert_eq!(
        body["result"]["events_consume_authority"]["grants"],
        json!([]),
        "the complete caller-authority list must be empty: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_consume_authority_is_visible_on_a_quiet_wire_list() {
    let store = consume_authority_store("live-empty");
    let deadline = i64::MAX / 2;
    insert_consume_grant(&store, "grant-consume-live-empty", Some(deadline));

    let body = list_as_reserved_consumer(store).await;
    assert_eq!(body["result"]["events"], json!([]));
    let grants = body["result"]["events_consume_authority"]["grants"]
        .as_array()
        .unwrap_or_else(|| panic!("consume authority grants missing: {body}"));
    assert_eq!(grants.len(), 1, "live grant missing: {body}");
    assert_eq!(grants[0]["authority_state"], "live");
    assert_eq!(grants[0]["authority_expires_at_ms"], deadline);
}

/// A reserved consumer sees another principal's stored events only through
/// live consume authority. Check both denied and granted reads on the wire
/// so neither an always-empty response nor an unscoped read can pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reserved_consumer_sees_granted_events_only_through_the_wire() {
    let (writer, mut responses) = mpsc::channel(8);
    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "events-consume-{}",
        std::process::id()
    )));

    let manifest_source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github.jsonc"),
    )
    .expect("read the shipped github manifest");
    let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize manifest");
    let ingested = plexus_core::ingest_value(
        serde_json::from_str::<Value>(&normalized).expect("parse manifest"),
    )
    .expect("ingest manifest");
    store
        .upsert_manifest("system", &ingested)
        .expect("seed manifest");
    store
        .insert_connection(
            "direct",
            "conn-consume",
            &ingested.manifest.key,
            "active",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("seed connection");
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: "conn-consume".to_string(),
            principal: "direct".to_string(),
            name: "list_issues".to_string(),
            title: None,
            schema: json!({
                "type": "object",
                "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}}
            }),
            schema_hash: "sha256:events-consume".to_string(),
            risk: "read".to_string(),
            severity: "S1".to_string(),
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
            ask_first: false,
        })
        .expect("seed catalog action");
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "grant-consume-poll".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-consume".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["list_issues".to_string()],
            authority_kind: "poll".to_string(),
            expires_at: Some(i64::MAX / 2),
        })
        .expect("seed poll grant");
    let subscription = store
        .subscribe_with_cursor_state(
            "direct",
            "conn-consume",
            "list_issues",
            30,
            &json!({}),
            &json!({"owner": "cortexkit", "repo": "plexus"}),
        )
        .expect("subscribe")
        .expect("subscribable");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    let outcome = store
        .insert_event(
            "direct",
            "conn-consume",
            &subscription.subscription_id,
            "vendor-consume-1",
            &json!({"title": "owned by direct"}),
            now,
        )
        .expect("seed event");
    assert!(
        matches!(
            outcome,
            plexus_core::TriggerEventInsertOutcome::Inserted { .. }
        ),
        "the seed stored no event: {outcome:?}"
    );
    assert!(store
        .set_subscription_deliver_to("direct", &subscription.subscription_id, Some("agent-route"))
        .expect("seed delivery target"));

    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    let bindings = Arc::new(RouteBindings::new());
    // Bound as RESERVED, not Direct. That is the whole point: this principal
    // owns nothing, so every row it sees must arrive by grant.
    handle_control_request(
        Frame::build(
            FrameType::Request,
            wire::control_flags(),
            0,
            0,
            7,
            serde_json::to_vec(&ModuleControlRequest::RouteBind {
                scope: None,
                call_mode: None,
                role_versions: None,
                route_channel: 4,
                epoch: 2,
                target: RouteTarget::ToolProvider {
                    module_id: DEFAULT_MODULE_ID.to_string(),
                },
                identity: BindIdentity::new(
                    "/tmp/project",
                    "test".to_string(),
                    "consumer".to_string(),
                ),
                // The REAL consumer identity rather than an invented one.
                // Reserved principals must be first-party to bind at all, so
                // an invented module id is refused at the bind and every
                // later assertion then fails for the wrong reason.
                principal: Some(Principal::Reserved {
                    module_id: "prefrontal-core".to_string(),
                }),
                consumer_capabilities: None,
                admission_facts: None,
            })
            .expect("serialize bind"),
        )
        .expect("build bind frame"),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("bind succeeds");
    // The bind ACK is asserted rather than discarded. A refused bind makes
    // every later tool call answer `route_not_bound`, and an unchecked ack
    // turns that into a confusing assertion failure about events instead of
    // naming the real cause.
    let bind_ack = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "bind response",
    )
    .await;
    assert_bind_ack(&bind_ack);

    let list = |writer: mpsc::Sender<Frame>,
                state: Arc<ModuleState>,
                bindings: Arc<RouteBindings>| async move {
        handle_tool_request(
            Frame::build(
                FrameType::Request,
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                4,
                2,
                9,
                serde_json::to_vec(&json!({
                    "name": manifest::EVENTS_TOOL,
                    "arguments": {"op": "list"}
                }))
                .expect("serialize tool request"),
            )
            .expect("build tool frame"),
            &writer,
            &state,
            &bindings,
        )
        .await
        .expect("tool request succeeds");
    };

    // ARM 1: no grant yet.
    list(writer.clone(), Arc::clone(&state), Arc::clone(&bindings)).await;
    let body: Value = serde_json::from_slice(
        &recv_within(responses.recv(), std::time::Duration::from_secs(5), "resp")
            .await
            .body,
    )
    .expect("body");
    assert_eq!(
        body["result"]["events"].as_array().map(Vec::len),
        Some(0),
        "an ungranted reserved consumer must see nothing: {body}"
    );

    // ARM 2: the operator names this consumer.
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "grant-consume-events".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-consume".to_string(),
            grantee_principal: "reserved:prefrontal-core".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["list_issues".to_string()],
            authority_kind: plexus_core::AUTHORITY_EVENTS_CONSUME.to_string(),
            expires_at: Some(i64::MAX / 2),
        })
        .expect("mint consume grant");

    list(writer.clone(), Arc::clone(&state), Arc::clone(&bindings)).await;
    let body: Value = serde_json::from_slice(
        &recv_within(responses.recv(), std::time::Duration::from_secs(5), "resp")
            .await
            .body,
    )
    .expect("body");
    let events = body["result"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("events array missing: {body}"));
    assert_eq!(
        events.len(),
        1,
        "the granted consumer saw no events through the wire: {body}"
    );
    // Asserted on identity and payload, not the count: a handler returning a
    // placeholder row would satisfy a length check.
    assert_eq!(events[0]["vendor_event_id"], "vendor-consume-1");
    assert_eq!(events[0]["payload"], json!({"title": "owned by direct"}));
    let consume_grants = body["result"]["events_consume_authority"]["grants"]
        .as_array()
        .unwrap_or_else(|| panic!("consume authority grants missing: {body}"));
    assert_eq!(consume_grants.len(), 1, "live grant missing: {body}");
    assert_eq!(consume_grants[0]["authority_state"], "live");
    assert_eq!(consume_grants[0]["authority_expires_at_ms"], i64::MAX / 2);

    // SUBSCRIPTIONS MUST BE WIDENED TOO, and this assertion exists because
    // without it a grantee can see every event and ZERO subscriptions. An
    // event names its subscription and nothing else -- which repository it
    // came from lives in the
    // subscription`s `fixed_args` -- so events without subscriptions are
    // payloads the consumer cannot attribute, and the failure looks like an
    // empty lane rather than a partial one.
    let subscriptions = body["result"]["subscriptions"]
        .as_array()
        .unwrap_or_else(|| panic!("subscriptions array missing: {body}"));
    assert_eq!(
        subscriptions.len(),
        1,
        "the granted consumer must receive the subscription behind its events: {body}"
    );
    // Mutation proved: removing `deliver_to` from the subscription projection
    // leaves events readable but makes the grantee unable to apply the first
    // delivery-routing rung.
    assert_eq!(
        subscriptions[0]["fixed_args"]["repo"], "plexus",
        "the subscription must carry the container it watches: {body}"
    );
    assert_eq!(
        subscriptions[0]["deliver_to"], "agent-route",
        "the grantee list must carry explicit delivery routing: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_consumer_ack_respects_the_same_action_selectors_as_its_read() {
    let (writer, mut responses) = mpsc::channel(2);
    let store = consume_authority_store("ack-action-selectors");
    for (action, hash) in [
        ("list_issues", "sha256:ack-list-issues"),
        ("get_latest_release", "sha256:ack-latest-release"),
    ] {
        store
            .upsert_catalog_action(&plexus_core::CatalogActionInput {
                connection_id: "conn-consume-authority".to_string(),
                principal: "direct".to_string(),
                name: action.to_string(),
                title: None,
                schema: json!({"type": "object", "properties": {}}),
                schema_hash: hash.to_string(),
                risk: "read".to_string(),
                severity: "S1".to_string(),
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
                ask_first: false,
            })
            .expect("seed catalog action");
    }
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "grant-ack-poll".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-consume-authority".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["list_issues".to_string(), "get_latest_release".to_string()],
            authority_kind: "poll".to_string(),
            expires_at: Some(i64::MAX / 2),
        })
        .expect("seed poll grant");
    let allowed_subscription = store
        .subscribe("direct", "conn-consume-authority", "list_issues", 30)
        .expect("subscribe to allowed action")
        .expect("allowed action is subscribable");
    let excluded_subscription = store
        .subscribe("direct", "conn-consume-authority", "get_latest_release", 30)
        .expect("subscribe to excluded action")
        .expect("excluded action is subscribable");
    let allowed_payload = json!({"title": "visible to consumer"});
    let excluded_payload = json!({"tag_name": "v2.0.0"});
    let allowed_event_id = match store
        .insert_event(
            "direct",
            "conn-consume-authority",
            &allowed_subscription.subscription_id,
            "vendor-allowed",
            &allowed_payload,
            100,
        )
        .expect("insert allowed event")
    {
        plexus_core::TriggerEventInsertOutcome::Inserted { event_id } => event_id,
        other => panic!("expected allowed insertion, got {other:?}"),
    };
    let excluded_event_id = match store
        .insert_event(
            "direct",
            "conn-consume-authority",
            &excluded_subscription.subscription_id,
            "vendor-excluded",
            &excluded_payload,
            101,
        )
        .expect("insert excluded event")
    {
        plexus_core::TriggerEventInsertOutcome::Inserted { event_id } => event_id,
        other => panic!("expected excluded insertion, got {other:?}"),
    };
    insert_consume_grant(&store, "grant-ack-consume", Some(i64::MAX / 2));

    let now = plexus_core::now_ms();
    let visible = store
        .list_events_including_granted(
            "reserved:prefrontal-core",
            Some("conn-consume-authority"),
            None,
            now,
        )
        .expect("list granted events");
    assert_eq!(
        visible
            .iter()
            .map(|event| event.event_id.as_str())
            .collect::<Vec<_>>(),
        vec![allowed_event_id.as_str()],
        "the consume grant must expose only its selected action"
    );

    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    let bindings = Arc::new(RouteBindings::new());
    bindings
        .insert(
            4,
            2,
            Principal::Reserved {
                module_id: "prefrontal-core".to_string(),
            },
        )
        .expect("bind reserved consumer");
    handle_tool_request(
        Frame::build(
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
            4,
            2,
            10,
            serde_json::to_vec(&json!({
                "name": manifest::EVENTS_TOOL,
                "arguments": {
                    "op": "ack",
                    "event_ids": [allowed_event_id, excluded_event_id]
                }
            }))
            .expect("serialize ack request"),
        )
        .expect("build ack frame"),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("ack request succeeds");

    let response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "ack response",
    )
    .await;
    let body: Value = serde_json::from_slice(&response.body).expect("ack response body");
    assert_eq!(
        body["result"]["acked"], 1,
        "only the event selected by the grant may be acknowledged: {body}"
    );
    assert_eq!(
        body["result"]["unacked"],
        json!([excluded_event_id]),
        "only the excluded event may remain unacked: {body}"
    );

    assert!(
        store
            .list_events(
                "direct",
                Some("conn-consume-authority"),
                Some(&allowed_subscription.subscription_id),
            )
            .expect("read allowed lane after ack")
            .is_empty(),
        "the selected event must be acknowledged"
    );
    let excluded_rows = store
        .list_events(
            "direct",
            Some("conn-consume-authority"),
            Some(&excluded_subscription.subscription_id),
        )
        .expect("read excluded lane after ack");
    assert_eq!(
        excluded_rows.len(),
        1,
        "the excluded event must remain unacked"
    );
    assert_eq!(excluded_rows[0].event_id, excluded_event_id);
    assert_eq!(
        excluded_rows[0].payload, excluded_payload,
        "a refused ack must leave the excluded event payload intact"
    );
    assert_eq!(
        excluded_rows[0].acked_at_ms, None,
        "the excluded event row must remain unacked"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
/// A stored event must survive the facade's list and ack delivery path.
async fn a_stored_event_is_delivered_through_the_tool_surface() {
    let (writer, mut responses) = mpsc::channel(8);
    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "events-delivery-{}",
        std::process::id()
    )));

    // Built through the store's ordinary API, because each row is a real
    // precondition of the next: `insert_event` refuses an orphan, and
    // `subscribe` refuses without a poll grant and a manifest-declared poll
    // shape. Assembling the chain proves those compose, and adds no
    // production surface that exists only for tests.
    let manifest_source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github.jsonc"),
    )
    .expect("read the shipped github manifest");
    let normalized = subc_jsonc::jsonc_to_json(&manifest_source).expect("normalize manifest");
    let ingested = plexus_core::ingest_value(
        serde_json::from_str::<Value>(&normalized).expect("parse manifest"),
    )
    .expect("ingest manifest");
    store
        .upsert_manifest("system", &ingested)
        .expect("seed manifest");
    store
        .insert_connection(
            "direct",
            "conn-events",
            &ingested.manifest.key,
            "active",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("seed connection");
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: "conn-events".to_string(),
            principal: "direct".to_string(),
            name: "list_issues".to_string(),
            title: None,
            schema: json!({
                "type": "object",
                "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}}
            }),
            schema_hash: "sha256:events-delivery".to_string(),
            risk: "read".to_string(),
            severity: "S1".to_string(),
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
            ask_first: false,
        })
        .expect("seed catalog action");
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "grant-events-delivery".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-events".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["list_issues".to_string()],
            authority_kind: "poll".to_string(),
            expires_at: Some(i64::MAX / 2),
        })
        .expect("seed poll grant");
    let subscription = store
        .subscribe_with_cursor_state(
            "direct",
            "conn-events",
            "list_issues",
            30,
            &json!({}),
            &json!({"owner": "rust-lang", "repo": "rust"}),
        )
        .expect("subscribe")
        .expect("the shipped manifest must be subscribable");

    // The OUTCOME is asserted, not just the Result: `insert_event` returns
    // Ok for a duplicate and for a payload conflict too, so a seed that
    // stored nothing would look successful and the test would then fail
    // with an empty list that reads as a broken delivery path.
    //
    // Observation time describes the source event. Retention uses its
    // insertion timestamp, and listing itself does not prune events.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    let outcome = store
        .insert_event(
            "direct",
            "conn-events",
            &subscription.subscription_id,
            "vendor-evt-1",
            &json!({"title": "a real payload"}),
            now,
        )
        .expect("seed event");
    assert!(
        matches!(
            outcome,
            plexus_core::TriggerEventInsertOutcome::Inserted { .. }
        ),
        "the seed stored no event: {outcome:?}"
    );

    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    let bindings = Arc::new(RouteBindings::new());
    // Bind the route first: the tool handler resolves its principal from
    // this table, and an unbound channel is refused before any store read.
    handle_control_request(
        Frame::build(
            FrameType::Request,
            wire::control_flags(),
            0,
            0,
            7,
            serde_json::to_vec(&ModuleControlRequest::RouteBind {
                scope: None,
                call_mode: None,
                role_versions: None,
                route_channel: 4,
                epoch: 2,
                target: RouteTarget::ToolProvider {
                    module_id: DEFAULT_MODULE_ID.to_string(),
                },
                identity: BindIdentity::new(
                    "/tmp/project",
                    "test".to_string(),
                    "session".to_string(),
                ),
                principal: Some(Principal::Direct),
                consumer_capabilities: None,
                admission_facts: None,
            })
            .expect("serialize bind"),
        )
        .expect("build bind frame"),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("bind succeeds");
    let _bind_ack = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "bind response",
    )
    .await;
    assert_bind_ack(&_bind_ack);

    handle_tool_request(
        Frame::build(
            FrameType::Request,
            // A tool frame carries ordinary interactive flags, unlike the
            // control frame above which sets the control bit.
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
            4,
            2,
            9,
            serde_json::to_vec(&json!({
                "name": manifest::EVENTS_TOOL,
                "arguments": {"op": "list"}
            }))
            .expect("serialize tool request"),
        )
        .expect("build tool frame"),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("tool request succeeds");

    let response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "events response",
    )
    .await;
    let body: Value = serde_json::from_slice(&response.body).expect("events response body");
    let events = body["result"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("events array missing from response: {body}"));

    assert_eq!(
        events.len(),
        1,
        "the stored event was not delivered to the caller: {body}"
    );
    // Asserted on the vendor id, not the count alone: a handler returning
    // some other row or a placeholder would satisfy a length check while
    // delivering the wrong thing.
    assert_eq!(
        events[0]["vendor_event_id"], "vendor-evt-1",
        "a different event was delivered: {body}"
    );
    assert_eq!(
        events[0]["payload"],
        json!({"title": "a real payload"}),
        "the payload did not survive delivery: {body}"
    );

    // ACK, and prove the event stops being delivered.
    //
    // Delivery and acknowledgement are one loop: a feed that delivers but
    // never forgets is as broken as one that never delivers, and it fails
    // in the noisier direction — the same event is returned on every poll
    // forever, so a caller processing its feed acts on it repeatedly.
    //
    // Measured before this existed: acking an EMPTY slice instead of the
    // requested ids (the store is never told anything) left the whole
    // module suite green.
    //
    // The count is asserted as well as the disappearance, because they
    // fail differently: a handler reporting 0 while acking correctly is a
    // caller-visible lie about what happened, and one reporting the
    // requested count while acking nothing is the silent redelivery loop.
    let event_id = events[0]["event_id"]
        .as_str()
        .expect("delivered event carries an id")
        .to_string();

    handle_tool_request(
        Frame::build(
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
            4,
            2,
            10,
            serde_json::to_vec(&json!({
                "name": manifest::EVENTS_TOOL,
                "arguments": {"op": "ack", "event_ids": [event_id]}
            }))
            .expect("serialize ack request"),
        )
        .expect("build ack frame"),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("ack request succeeds");

    let ack_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "ack response",
    )
    .await;
    let ack_body: Value = serde_json::from_slice(&ack_response.body).expect("ack response body");
    assert_eq!(
        ack_body["result"]["acked"], 1,
        "ack must report the event it acknowledged: {ack_body}"
    );
    assert_eq!(
        ack_body["result"]["unacked"],
        json!([]),
        "a fully successful ack must report nothing outstanding: {ack_body}"
    );

    // An id that acks nothing must be NAMED, not merely absent from a count.
    // A consumer acks what it has already delivered, so an id that lands on
    // no row means the two sides disagree about what exists -- and with only
    // a count, noticing requires the caller to compare against its own
    // request length. Missing it means the event redelivers forever while
    // both sides report healthy, which is why the ack path is the one where
    // a swallowed refusal costs the most.
    handle_tool_request(
        Frame::build(
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
            4,
            2,
            12,
            serde_json::to_vec(&json!({
                "name": manifest::EVENTS_TOOL,
                "arguments": {"op": "ack", "event_ids": ["event_does_not_exist"]}
            }))
            .expect("serialize unknown ack request"),
        )
        .expect("build unknown ack frame"),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("unknown ack request succeeds");
    let unknown_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "unknown ack response",
    )
    .await;
    let unknown_body: Value =
        serde_json::from_slice(&unknown_response.body).expect("unknown ack body");
    assert_eq!(
        unknown_body["result"]["acked"], 0,
        "an unknown id must ack nothing: {unknown_body}"
    );
    assert_eq!(
        unknown_body["result"]["unacked"],
        json!(["event_does_not_exist"]),
        "an id that acked nothing must be named so the caller can act on it: \
             {unknown_body}"
    );

    // Re-acking an ALREADY-acked id reports zero acked and nothing
    // outstanding: it landed on no row, but the caller's goal for it is
    // satisfied and it will not redeliver. Reporting it as outstanding would
    // name a problem with no remedy, and a consumer retrying after an
    // ambiguous reply does exactly this.
    handle_tool_request(
        Frame::build(
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
            4,
            2,
            13,
            serde_json::to_vec(&json!({
                "name": manifest::EVENTS_TOOL,
                "arguments": {"op": "ack", "event_ids": [event_id]}
            }))
            .expect("serialize repeat ack request"),
        )
        .expect("build repeat ack frame"),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("repeat ack request succeeds");
    let repeat_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "repeat ack response",
    )
    .await;
    let repeat_body: Value =
        serde_json::from_slice(&repeat_response.body).expect("repeat ack body");
    assert_eq!(repeat_body["result"]["acked"], 0, "re-ack must be a no-op");
    assert_eq!(
        repeat_body["result"]["unacked"],
        json!([]),
        "re-acking an already-acked event must not report it outstanding: \
             {repeat_body}"
    );

    handle_tool_request(
        Frame::build(
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
            4,
            2,
            11,
            serde_json::to_vec(&json!({
                "name": manifest::EVENTS_TOOL,
                "arguments": {"op": "list"}
            }))
            .expect("serialize second list"),
        )
        .expect("build second list frame"),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("second list succeeds");

    let after = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "second list response",
    )
    .await;
    let after_body: Value = serde_json::from_slice(&after.body).expect("second list body");
    assert_eq!(
        after_body["result"]["events"],
        json!([]),
        "an acked event must not be delivered again: {after_body}"
    );
}
