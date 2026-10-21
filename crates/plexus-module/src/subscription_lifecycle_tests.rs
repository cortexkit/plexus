use super::*;
use plexus_core::{AgentLookup, StubAgentRegistry};
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{BindIdentity, RouteTarget};

/// Subscribe, resume, and unsubscribe take effect THROUGH the tool surface.
///
/// A store call can be neutered at the handler and nothing notices when every
/// behaviour test calls the store directly. Measured before this existed — passing an empty
/// object where `fixed_args` belongs, and unsubscribing an id the caller
/// never named, both left the whole module suite green.
///
/// The subscribe half is the one that matters. `fixed_args` carries WHICH
/// container a subscription watches, and the poller builds its request from
/// the cursor strategy, the manifest's constants and that object alone. So
/// a handler that drops it creates a subscription the vendor rejects on
/// every poll — accepted at the surface, dead in operation, and reported as
/// a vendor failure rather than as the misconfiguration it is.
///
/// The unsubscribe half fails the other way: a subscription that survives
/// its own removal keeps polling a vendor the operator believes they
/// stopped watching, which is authority outliving the decision to withdraw
/// it.
///
/// Asserted on STORE STATE rather than on the response, in both halves. A
/// handler can report success while doing nothing, and that is exactly the
/// mutation this has to catch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_resume_and_unsubscribe_take_effect_through_the_tool_surface() {
    let (writer, mut responses) = mpsc::channel(8);
    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "sub-lifecycle-{}",
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
            "conn-lifecycle",
            &ingested.manifest.key,
            "active",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("seed connection");
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: "conn-lifecycle".to_string(),
            principal: "direct".to_string(),
            name: "list_issues".to_string(),
            title: None,
            schema: json!({
                "type": "object",
                "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}}
            }),
            schema_hash: "sha256:sub-lifecycle".to_string(),
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
            grant_id: "grant-sub-lifecycle".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-lifecycle".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["list_issues".to_string()],
            authority_kind: "poll".to_string(),
            expires_at: Some(i64::MAX / 2),
        })
        .expect("seed poll grant");

    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    let bindings = Arc::new(RouteBindings::new());
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

    let tool_frame = |correlation: u64, arguments: Value| {
        Frame::build(
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
            4,
            2,
            correlation,
            serde_json::to_vec(&json!({
                "name": manifest::EVENTS_TOOL,
                "arguments": arguments
            }))
            .expect("serialize tool request"),
        )
        .expect("build tool frame")
    };

    handle_tool_request(
        tool_frame(
            20,
            json!({
                "op": "subscribe",
                "connection": "conn-lifecycle",
                "action": "list_issues",
                "cadence_s": 30,
                "fixed_args": {"owner": "rust-lang", "repo": "rust"}
            }),
        ),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("subscribe request succeeds");
    let subscribe_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "subscribe response",
    )
    .await;
    let subscribe_body: Value =
        serde_json::from_slice(&subscribe_response.body).expect("subscribe body");
    assert!(
        subscribe_body["error"].is_null(),
        "subscribe failed: {subscribe_body}"
    );

    let stored = store
        .list_subscriptions("direct", None, None)
        .expect("read subscriptions");
    assert_eq!(stored.len(), 1, "subscribe stored no subscription");
    assert_eq!(
        stored[0].fixed_args,
        json!({"owner": "rust-lang", "repo": "rust"}),
        "the caller's container scope did not reach the store"
    );
    let subscription_id = stored[0].subscription_id.clone();

    // A handler that reports a successful resume without calling the store
    // leaves the subscription suspended. Assert the durable state and the
    // scheduler input after the tool call, not its self-authored reply.
    //
    // Mutation proved: replacing the handler's store call with a success
    // response leaves `status` suspended and fails the assertions below.
    let cursor_before_resume = json!({"watermark_ms": 1_700_000_000_000i64});
    assert!(store
        .record_poll_success("direct", &subscription_id, &cursor_before_resume, 1,)
        .expect("seed cursor"));
    assert!(store
        .record_vendor_failure("direct", &subscription_id)
        .expect("seed vendor failure"));
    assert!(store
        .suspend(
            "direct",
            &subscription_id,
            plexus_core::CIRCUIT_BREAKER_SUSPENSION_REASON,
        )
        .expect("trip circuit breaker"));
    assert!(
        !store
            .due_subscriptions("direct", plexus_core::now_ms())
            .expect("due subscriptions before resume")
            .iter()
            .any(|candidate| candidate.subscription_id == subscription_id),
        "suspension must keep the watch out of scheduling before resume"
    );

    handle_tool_request(
        tool_frame(
            21,
            json!({"op": "resume", "subscription_id": subscription_id}),
        ),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("resume request succeeds");
    let _resume_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "resume response",
    )
    .await;
    let resume_body: Value = serde_json::from_slice(&_resume_response.body).expect("resume body");
    assert!(
        resume_body["error"].is_null(),
        "resume must answer success: {resume_body}"
    );
    let resumed = store
        .subscription("direct", &subscription_id)
        .expect("read resumed subscription")
        .expect("subscription exists");
    assert_eq!(
        resumed.status, "active",
        "the handler did not resume the watch"
    );
    assert_eq!(resumed.suspended_reason, None);
    assert_eq!(resumed.consecutive_vendor_failures, 0);
    assert_eq!(
        resumed.cursor_state, cursor_before_resume,
        "resume through the facade must preserve the durable cursor"
    );
    assert!(
        store
            .due_subscriptions("direct", plexus_core::now_ms())
            .expect("due subscriptions after resume")
            .iter()
            .any(|candidate| candidate.subscription_id == subscription_id),
        "resume through the facade must return the watch to scheduling"
    );

    // The authority deadline must reach the WIRE, not merely the store. A
    // consumer warning that a watch is about to lapse reads this field off
    // the facade response, and the store method being correct says nothing
    // about whether the handler serializes it -- the whole point of a
    // subscription is that it dies silently when its poll grant expires, so
    // a field that stops at the store boundary leaves the consumer exactly
    // as blind as before.
    handle_tool_request(
        tool_frame(22, json!({"op": "list"})),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("list request succeeds");
    let list_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "list response",
    )
    .await;
    let list_body: Value = serde_json::from_slice(&list_response.body).expect("list body");
    let listed = &list_body["result"]["subscriptions"][0];
    assert_eq!(
        listed["authority_state"], "live",
        "the wire must report whether the authority behind a watch still holds: {list_body}"
    );
    assert!(
        listed["authority_expires_at_ms"]
            .as_i64()
            .is_some_and(|at| at > plexus_core::now_ms()),
        "the wire must carry the deadline itself, or a consumer cannot warn \
             before it passes: {list_body}"
    );

    // A SEEDED cursor state must reach the store, because seeding IS how a
    // threshold watch is expressed. A scalar-diff subscription that starts
    // empty baselines silently on its first poll; one seeded with a value
    // the subscriber has already seen reports immediately if the vendor has
    // moved past it. Those are the same mechanism with different starting
    // states, which is why no threshold field exists -- and it means a
    // handler that dropped the seed would silently convert every threshold
    // watch into a plain change watch, losing exactly one event: the one the
    // subscriber asked for.
    //
    // Asserted on the wire because the store honours the seed and the
    // strategy honours it, while nothing proved the handler PASSES it. The
    // whole workspace stayed green with the seed discarded.
    handle_tool_request(
        tool_frame(
            23,
            json!({
                "op": "subscribe",
                "connection": "conn-lifecycle",
                "action": "list_issues",
                "cadence_s": 30,
                "fixed_args": {"owner": "cortexkit", "repo": "plexus"},
                // The correct key for list_issues, whose cursor kind is
                // ordered-timestamp: its resume point is `watermark_ms`. A
                // scalar key is refused here because that strategy never
                // reads one, so seeding with it would leave the watch
                // behaving as though it had no starting state at all.
                "cursor_state": {"watermark_ms": 1_700_000_000_000i64}
            }),
        ),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("seeded subscribe request succeeds");
    let seeded_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "seeded subscribe response",
    )
    .await;
    let seeded_body: Value =
        serde_json::from_slice(&seeded_response.body).expect("seeded subscribe body");
    assert!(
        seeded_body["error"].is_null(),
        "seeded subscribe failed: {seeded_body}"
    );
    assert_eq!(
        seeded_body["result"]["subscription"]["cursor_state"],
        json!({"watermark_ms": 1_700_000_000_000i64}),
        "the caller's seed must survive the handler: dropping it turns every \
             threshold watch into a plain change watch"
    );
    let seeded_id = seeded_body["result"]["subscription"]["subscription_id"]
        .as_str()
        .expect("seeded subscription id")
        .to_string();
    let stored_seed = store
        .list_subscriptions("direct", None, Some(&seeded_id))
        .expect("read seeded subscription");
    assert_eq!(
        stored_seed[0].cursor_state,
        json!({"watermark_ms": 1_700_000_000_000i64}),
        "the seed must be durable, not merely echoed back in the response"
    );

    handle_tool_request(
        tool_frame(
            24,
            json!({"op": "unsubscribe", "subscription_id": subscription_id}),
        ),
        &writer,
        &state,
        &bindings,
    )
    .await
    .expect("unsubscribe request succeeds");
    let unsubscribe_response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "unsubscribe response",
    )
    .await;
    assert_eq!(
        unsubscribe_response.header.corr, 24,
        "unsubscribe must echo its unique correlation"
    );
    let unsubscribe_body: Value =
        serde_json::from_slice(&unsubscribe_response.body).expect("unsubscribe body");
    assert_eq!(
        unsubscribe_body["result"]["unsubscribed"],
        json!(true),
        "unsubscribe did not report success: {unsubscribe_body}"
    );

    assert!(
        store
            .list_subscriptions("direct", None, Some(&subscription_id))
            .expect("read subscriptions after unsubscribe")
            .is_empty(),
        "the subscription survived its own removal"
    );
    // Scoped to the removed id rather than asserting an empty store, because
    // the seeded subscription above is still live -- and an unsubscribe that
    // removed BYSTANDERS would pass an emptiness check while destroying
    // watches the caller never named.
    assert_eq!(
        store
            .list_subscriptions("direct", None, Some(&seeded_id))
            .expect("read the bystander subscription")
            .len(),
        1,
        "unsubscribing one watch must not remove another"
    );
}

/// Subscription project, delivery-target, and actor-source bindings persist
/// THROUGH the tool surface, and each clearing path works.
///
/// This call-site test verifies that the handler reaches the store methods
/// and that each binding and clearing path works through the tool surface.
/// Store-level tests cannot detect a handler that never invokes a correct
/// store method.
///
/// Asserted against the STORE after each call rather than against the
/// response body alone. A handler that echoed its own argument back would
/// satisfy a response check while writing nothing -- the echo is the caller's
/// input, not evidence about persistence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscription_bindings_persist_through_the_tool_surface() {
    let (writer, mut responses) = mpsc::channel(8);
    let store = Arc::new(crate::test_support::open_memory_store(format!(
        "set-project-{}",
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
            "conn-project",
            &ingested.manifest.key,
            "active",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("seed connection");
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: "conn-project".to_string(),
            principal: "direct".to_string(),
            name: "list_issues".to_string(),
            title: None,
            schema: json!({
                "type": "object",
                "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}}
            }),
            schema_hash: "sha256:set-project".to_string(),
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
            grant_id: "grant-set-project".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-project".to_string(),
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
            "conn-project",
            "list_issues",
            30,
            &json!({}),
            &json!({"owner": "cortexkit", "repo": "plexus"}),
        )
        .expect("subscribe")
        .expect("subscribable");

    let registry = Arc::new(StubAgentRegistry::with_default_response(AgentLookup::Known));
    let mut runtime = runtime_for_test(Arc::clone(&store));
    runtime.agent_registry = registry.clone();
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    });
    let bindings = Arc::new(RouteBindings::new());
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
    let bind_ack = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "bind response",
    )
    .await;
    assert_bind_ack(&bind_ack);

    let call = |args: Value,
                writer: mpsc::Sender<Frame>,
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
                    "arguments": args
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
    let stored = |store: &PlexusStore| {
        store
            .subscription("direct", &subscription.subscription_id)
            .expect("read subscription")
            .expect("row present")
            .project_id
    };
    let stored_delivery = |store: &PlexusStore| {
        store
            .subscription("direct", &subscription.subscription_id)
            .expect("read subscription")
            .expect("row present")
            .deliver_to
    };

    assert_eq!(stored(&store), None, "a fresh subscription has no project");
    assert_eq!(
        stored_delivery(&store),
        None,
        "a fresh subscription has no explicit delivery target"
    );

    call(
        json!({
            "op": "set_project",
            "subscription_id": subscription.subscription_id,
            "project_id": "proj_plexus"
        }),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(responses.recv(), std::time::Duration::from_secs(5), "resp")
            .await
            .body,
    )
    .expect("body");
    assert!(
        body.get("error").is_none(),
        "set_project was refused: {body}"
    );
    assert_eq!(
        stored(&store),
        Some("proj_plexus".to_string()),
        "the handler did not persist the project: {body}"
    );

    for project_id in ["a\nb", "a\rb", "a\tb", "a\0b", "a\u{85}b"] {
        call(
                json!({"op":"set_project", "subscription_id":subscription.subscription_id, "project_id":project_id}),
                writer.clone(), Arc::clone(&state), Arc::clone(&bindings),
            ).await;
        let body: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "invalid project response",
            )
            .await
            .body,
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "invalid_request", "{body}");
        assert_eq!(stored(&store).as_deref(), Some("proj_plexus"));
    }

    // Omitting the key is refused and leaves the binding alone: read as a
    // clear, a misspelled field name would wipe it.
    call(
        json!({
            "op": "set_project",
            "subscription_id": subscription.subscription_id
        }),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "omitted resp",
        )
        .await
        .body,
    )
    .expect("body");
    assert_eq!(
        body["error"]["missing"],
        json!(["project_id"]),
        "omitting project_id must be refused: {body}"
    );
    assert_eq!(
        stored(&store),
        Some("proj_plexus".to_string()),
        "omitting project_id must not clear the binding"
    );

    // An explicit null clears it.
    call(
        json!({
            "op": "set_project",
            "subscription_id": subscription.subscription_id,
            "project_id": null
        }),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let cleared: Value = serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "clear resp",
        )
        .await
        .body,
    )
    .expect("body");
    assert!(
        cleared["error"].is_null(),
        "an explicit null project_id must be accepted: {cleared}"
    );
    assert_eq!(
        stored(&store),
        None,
        "an explicit null project_id must clear the binding"
    );

    // A value that is not a string or null is refused, never read as a
    // clear: the binding set below must survive it.
    call(
        json!({
            "op": "set_project",
            "subscription_id": subscription.subscription_id,
            "project_id": "proj_plexus"
        }),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let set: Value = serde_json::from_slice(
        &recv_within(responses.recv(), std::time::Duration::from_secs(5), "set")
            .await
            .body,
    )
    .expect("body");
    assert!(
        set["error"].is_null(),
        "setting the project the next step must preserve: {set}"
    );
    call(
        json!({
            "op": "set_project",
            "subscription_id": subscription.subscription_id,
            "project_id": 42
        }),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(responses.recv(), std::time::Duration::from_secs(5), "resp")
            .await
            .body,
    )
    .expect("body");
    assert_eq!(body["error"]["code"], "invalid_request", "{body}");
    assert_eq!(
        stored(&store),
        Some("proj_plexus".to_string()),
        "a non-string project_id must not clear the binding"
    );

    // An unknown subscription is refused rather than silently accepted.
    call(
        json!({
            "op": "set_project",
            "subscription_id": "subscription_missing",
            "project_id": "proj_x"
        }),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(responses.recv(), std::time::Duration::from_secs(5), "resp")
            .await
            .body,
    )
    .expect("body");
    assert_eq!(
        body["error"]["code"], "subscription_not_found",
        "an unknown subscription must be refused: {body}"
    );

    // Mutation proved: replacing the set_deliver_to handler arm with a
    // success response that discards its value leaves this store assertion
    // and the owner-path list assertion below red.
    call(
        json!({"op": "set_deliver_to"}),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "missing response",
        )
        .await
        .body,
    )
    .expect("missing body");
    assert_eq!(
        body["error"]["missing"],
        json!(["subscription_id", "deliver_to"]),
        "set_deliver_to must report every missing field: {body}"
    );

    let generation_before_delivery_set = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read subscription")
        .expect("row present")
        .generation;
    call(
        json!({
            "op": "set_deliver_to",
            "subscription": subscription.subscription_id,
            "deliver_to": "agent-live"
        }),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "delivery response",
        )
        .await
        .body,
    )
    .expect("delivery body");
    assert!(
        body.get("error").is_none(),
        "set_deliver_to refused: {body}"
    );
    assert_eq!(
        stored_delivery(&store),
        Some("agent-live".to_string()),
        "the handler discarded the delivery target: {body}"
    );
    let stored_generation = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read subscription")
        .expect("row present")
        .generation;
    assert_eq!(
        stored_generation, generation_before_delivery_set,
        "a routing rebind must preserve an in-flight subscription generation"
    );

    call(
        json!({"op": "list", "subscription": subscription.subscription_id}),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "owner list response",
        )
        .await
        .body,
    )
    .expect("owner list body");
    assert_eq!(
        body["result"]["subscriptions"][0]["deliver_to"], "agent-live",
        "the owner list must surface delivery routing: {body}"
    );

    // With both spellings present, `subscription_id` wins, as it does for
    // every sibling op.
    call(
        json!({
            "op": "set_deliver_to",
            "subscription_id": subscription.subscription_id,
            "subscription": "subscription_missing",
            "deliver_to": "agent-live"
        }),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "both spellings response",
        )
        .await
        .body,
    )
    .expect("both spellings body");
    assert!(
        body.get("error").is_none(),
        "set_deliver_to must read subscription_id first: {body}"
    );

    // Principal scoping is proven through the handler and durable state. A
    // refusal body alone could hide a handler that wrote before refusing.
    bindings
        .insert(
            4,
            2,
            Principal::Reserved {
                module_id: "other".to_string(),
            },
        )
        .expect("bind foreign principal");
    call(
        json!({
            "op": "set_deliver_to",
            "subscription": subscription.subscription_id,
            "deliver_to": "agent-foreign"
        }),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "foreign response",
        )
        .await
        .body,
    )
    .expect("foreign body");
    assert_eq!(body["error"]["code"], "subscription_not_found");
    assert_eq!(
        stored_delivery(&store),
        Some("agent-live".to_string()),
        "a foreign set must leave the owner's row unchanged"
    );
    bindings
        .insert(4, 2, Principal::Direct)
        .expect("restore owner principal");

    registry.set_response("agent-unknown", AgentLookup::Unknown);
    registry.set_response("agent-retired", AgentLookup::Retired);
    registry.set_response("agent-unavailable", AgentLookup::Unavailable);
    let mut refusal_codes = Vec::new();
    for (agent_id, expected_code) in [
        ("agent-unknown", "deliver_to_unknown_agent"),
        ("agent-retired", "deliver_to_agent_retired"),
        ("agent-unavailable", "agent_registry_unavailable"),
    ] {
        call(
            json!({
                "op": "set_deliver_to",
                "subscription": subscription.subscription_id,
                "deliver_to": agent_id
            }),
            writer.clone(),
            Arc::clone(&state),
            Arc::clone(&bindings),
        )
        .await;
        let body: Value = serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "registry refusal response",
            )
            .await
            .body,
        )
        .expect("registry refusal body");
        assert_eq!(
            body["error"]["code"], expected_code,
            "the registry verdict needs its own operator remedy: {body}"
        );
        refusal_codes.push(body["error"]["code"].clone());
        assert_eq!(
            stored_delivery(&store),
            Some("agent-live".to_string()),
            "a refused registry verdict must not alter the stored target"
        );
    }
    assert_ne!(refusal_codes[0], refusal_codes[1]);
    assert_ne!(refusal_codes[0], refusal_codes[2]);
    assert_ne!(refusal_codes[1], refusal_codes[2]);

    registry.set_default_response(AgentLookup::Unavailable);
    let registry_requests_before_clear = registry.requests().len();
    call(
        json!({
            "op": "set_deliver_to",
            "subscription": subscription.subscription_id,
            "deliver_to": null
        }),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "delivery clear response",
        )
        .await
        .body,
    )
    .expect("delivery clear body");
    assert!(body.get("error").is_none(), "clear was refused: {body}");
    assert_eq!(stored_delivery(&store), None, "clear must restore absence");
    assert_eq!(
        registry.requests().len(),
        registry_requests_before_clear,
        "clearing must not consult an unavailable registry"
    );
    call(
        json!({"op": "list", "subscription": subscription.subscription_id}),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "cleared list response",
        )
        .await
        .body,
    )
    .expect("cleared list body");
    assert!(
        body["result"]["subscriptions"][0]["deliver_to"].is_null(),
        "the owner list must show that clearing removed delivery routing: {body}"
    );

    let source = ActorSource {
        connection_id: "conn-github-comments".to_string(),
        action: "issue_read".to_string(),
        methods: vec!["get_comments".to_string()],
    };
    call(
        json!({
            "op": "set_actor_source",
            "subscription_id": subscription.subscription_id,
            "actor_source": source
        }),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "actor resp",
        )
        .await
        .body,
    )
    .expect("actor body");
    assert!(
        body.get("error").is_none(),
        "set_actor_source was refused: {body}"
    );
    assert_eq!(
        store
            .subscription("direct", &subscription.subscription_id)
            .expect("read subscription")
            .expect("row present")
            .actor_source,
        Some(ActorSource {
            connection_id: "conn-github-comments".to_string(),
            action: "issue_read".to_string(),
            methods: vec!["get_comments".to_string()],
        }),
        "the handler must persist the actor source rather than echoing input"
    );

    call(
        json!({
            "op": "set_actor_source",
            "subscription_id": subscription.subscription_id
        }),
        writer.clone(),
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let body: Value = serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "actor omitted resp",
        )
        .await
        .body,
    )
    .expect("body");
    assert_eq!(body["error"]["missing"], json!(["actor_source"]), "{body}");
    assert!(
        store
            .subscription("direct", &subscription.subscription_id)
            .expect("read subscription")
            .expect("row present")
            .actor_source
            .is_some(),
        "omitting actor_source must not clear the persisted binding"
    );

    call(
        json!({
            "op": "set_actor_source",
            "subscription_id": subscription.subscription_id,
            "actor_source": null
        }),
        writer,
        Arc::clone(&state),
        Arc::clone(&bindings),
    )
    .await;
    let cleared: Value = serde_json::from_slice(
        &recv_within(
            responses.recv(),
            std::time::Duration::from_secs(5),
            "actor clear resp",
        )
        .await
        .body,
    )
    .expect("body");
    assert!(
        cleared["error"].is_null(),
        "an explicit null actor_source must be accepted: {cleared}"
    );
    assert_eq!(
        store
            .subscription("direct", &subscription.subscription_id)
            .expect("read subscription")
            .expect("row present")
            .actor_source,
        None,
        "an explicit null actor_source must clear the persisted binding"
    );
}
