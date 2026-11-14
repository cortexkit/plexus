use super::*;

fn invoke_body(connection: &str) -> Value {
    json!({"name":"invoke", "arguments":{"op":"call", "connection":connection, "action":"meta.read", "args":{}}})
}

#[test]
fn standing_liveness_refusals_are_not_sent_with_explicit_retryability() {
    for (denial, code, retryable) in [
        (
            plexus_core::Denial::FederatedPairingEnded,
            "federated_pairing_ended",
            false,
        ),
        (
            plexus_core::Denial::FederatedLivenessUnavailable,
            "federated_liveness_unavailable",
            true,
        ),
    ] {
        assert_eq!(
            denial_response(&denial),
            json!({"error": {"code":code, "message":code,
            "retryable":retryable, "transmission":"not_sent"}})
        );
    }
}

#[test]
fn federated_invoke_wrapper_preserves_an_existing_error_transmission() {
    for transmission in ["sent", "outcome_unknown", "not_sent"] {
        let local = json!({"error":{"code":"dispatch_failed", "message":"fake vendor failure", "transmission":transmission}});
        assert_eq!(federated_invoke_reply(local.clone()), local);
    }
    let denial = denial_response(&plexus_core::Denial::FederatedConsentDenied);
    let mut expected = denial.clone();
    expected["error"]["transmission"] = json!("not_sent");
    assert_eq!(federated_invoke_reply(denial), expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standing_federated_invoke_keeps_local_dispatch_failure_transmission() {
    for risk in ["read", "write"] {
        for (failure, expected) in [
            (plexus_core::MockResponse::OutcomeUnknown, "outcome_unknown"),
            (
                plexus_core::MockResponse::VendorError {
                    code: "fake_vendor_failure".into(),
                    message: String::new(),
                },
                "failed",
            ),
        ] {
            let (mut state, store, transport, scratch) =
                super::super::github_read_frame_tests::imported_runtime();
            let runtime = &mut Arc::get_mut(&mut state).unwrap().runtime;
            runtime.set_federated_callers_enabled_for_test(true);
            runtime.engine = runtime
                .engine
                .clone()
                .with_scope_reader(crate::consent_test_support::live_reader(
                    CallScope::from_stamp(&stamp()),
                ))
                .with_freshness_check(Arc::new(|_| Ok(())));
            let mut manifest: Value = serde_json::from_str(
                &subc_jsonc::jsonc_to_json(include_str!("../../../catalog/searxng_rest.jsonc"))
                    .unwrap(),
            )
            .unwrap();
            manifest["tier"] = json!("S1");
            manifest["actions_baseline"][0]["name"] = json!("meta.test");
            store
                .upsert_manifest(
                    plexus_core::storage::CATALOG_PRINCIPAL,
                    &plexus_core::ingest_value(manifest).unwrap(),
                )
                .unwrap();
            store
                .insert_connection(
                    "direct",
                    "plain",
                    "searxng_rest",
                    "active",
                    &json!({"write_enabling":["resource"]}),
                )
                .unwrap();
            store
                .upsert_catalog_action(&plexus_core::storage::CatalogActionInput {
                    principal: "direct".into(),
                    connection_id: "plain".into(),
                    name: "meta.test".into(),
                    title: None,
                    schema: json!({"type":"object","properties":{"resource":{"type":"string"}}}),
                    schema_hash: "schema".into(),
                    risk: risk.into(),
                    severity: "S1".into(),
                    ask_first: risk == "write",
                    status: "active".into(),
                    quarantine_reason: None,
                    reconciliation: None,
                })
                .unwrap();
            store
                .set_policy("direct", "plain", "*", "allow", None)
                .unwrap();
            let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
            db.execute_batch("UPDATE connections SET ceiling_risk='write',ceiling_selectors='[\"meta.test\"]' WHERE connection_id='plain'").unwrap();
            db.execute("INSERT INTO federated_rows (id,peer_fingerprint,pairing_id,peer_class,selector,claim_kind,canonical_claim_identity,owner_principal,subject,scope,peer_name,effect,granted_at_ms,card_ref,card_refs_json)
                VALUES ('plxf_dispatch',?1,'pairing','computer','claimless','','','direct','plain',?2,'Peer','allow',1,'el_seed','[\"el_seed\"]')", rusqlite::params!["a".repeat(32),risk]).unwrap();
            transport.set_response(failure);
            let body = json!({"name":"invoke","arguments":{"op":"call","connection":"plain","action":"meta.test","args":{"resource":"target"}}});
            let federated_routes = bind_accepted(&state, stamp(), CallMode::Classic).await;
            let federated = reply(call(&state, &federated_routes, body.clone()).await);
            assert_eq!(transport.requests().len(), 1, "{federated}");
            store
                .insert_grant(&plexus_core::storage::GrantInput {
                    grant_id: "local-dispatch".into(),
                    principal: "direct".into(),
                    connection_id: "plain".into(),
                    grantee_principal: "direct".into(),
                    risk_ceiling: "write".into(),
                    action_selectors: vec!["meta.test".into()],
                    authority_kind: "invoke".into(),
                    expires_at: None,
                })
                .unwrap();
            let local_routes = Arc::new(RouteBindings::new());
            local_routes
                .insert_mode(17, 3, Principal::Direct, None, CallMode::Classic)
                .unwrap();
            let local = reply(call(&state, &local_routes, body).await);
            assert_eq!(transport.requests().len(), 2, "{local}");
            assert!(federated.get("error").is_none(), "{federated}");
            assert!(local.get("error").is_none(), "{local}");
            assert_eq!(federated["result"]["transmission"], expected);
            assert_ne!(federated["result"]["transmission"], "not_sent");
            assert_eq!(
                serde_json::to_vec(&federated["result"]["transmission"]).unwrap(),
                serde_json::to_vec(&local["result"]["transmission"]).unwrap()
            );
            assert!(store.list_action_requests("direct").unwrap().is_empty());
            let cards: i64 = db
                .query_row("SELECT count(*) FROM federated_card_records", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(cards, 0);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn synthetic_bind_held_reply_declaration_controls_federated_card_filing() {
    for (declared, claim) in [
        (false, None),
        (true, None),
        (true, Some(json!({"kind":"run","agent_id":"r"}))),
        (
            true,
            Some(
                json!({"kind":"flow","flow_id":"f","flow_version":1,"flow_code_hash":"hash","flow_install_id":"i"}),
            ),
        ),
    ] {
        let (mut state, store, transport, scratch) =
            super::super::github_read_frame_tests::imported_runtime();
        let runtime = &mut Arc::get_mut(&mut state).unwrap().runtime;
        runtime.set_federated_callers_enabled_for_test(true);
        runtime.engine = runtime
            .engine
            .clone()
            .with_consent_cards(crate::consent_test_support::pending_cards());
        let mut manifest: Value = serde_json::from_str(
            &subc_jsonc::jsonc_to_json(include_str!("../../../catalog/searxng_rest.jsonc"))
                .unwrap(),
        )
        .unwrap();
        manifest["tier"] = json!("S1");
        manifest["actions_baseline"][0]["name"] = json!("meta.read");
        store
            .upsert_manifest(
                plexus_core::storage::CATALOG_PRINCIPAL,
                &plexus_core::ingest_value(manifest).unwrap(),
            )
            .unwrap();
        store
            .insert_connection("direct", "plain", "searxng_rest", "active", &json!({}))
            .unwrap();
        store
            .upsert_catalog_action(&plexus_core::storage::CatalogActionInput {
                principal: "direct".into(),
                connection_id: "plain".into(),
                name: "meta.read".into(),
                title: None,
                schema: json!({"type":"object","properties":{}}),
                schema_hash: "schema".into(),
                risk: "read".into(),
                severity: "S1".into(),
                ask_first: false,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
        let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
        db.execute_batch("UPDATE connections SET ceiling_risk='read',ceiling_selectors='[\"meta.read\"]' WHERE connection_id='plain'; DROP TABLE grants;").unwrap();
        let mut scope = stamp();
        scope.attributes.federated.as_mut().unwrap().remote_claim =
            claim.clone().map(|v| serde_json::from_value(v).unwrap());
        let mut body = bind_body(reserved("callosum"), Some(scope), CallMode::Classic);
        if declared {
            body["consumer_capabilities"] = json!(["held-reply/v1", "tool-result/v1"]);
        }
        let routes = Arc::new(RouteBindings::new());
        assert_eq!(
            bind(&state, &routes, body).await.header.ty,
            FrameType::Response
        );
        assert_eq!(
            routes.binding(17, 3).unwrap().unwrap().held_reply_v1,
            declared
        );
        let actual = reply(call(&state, &routes, invoke_body("plain")).await);
        let waits = declared && claim.is_none();
        let error = if waits {
            &actual["structuredContent"]
        } else {
            &actual["error"]
        };
        assert_eq!(
            error["code"],
            if waits {
                "access_pending"
            } else {
                "consent_unavailable"
            },
            "{actual}"
        );
        if !waits {
            assert_eq!(error["transmission"], "not_sent");
        }
        if waits {
            assert_eq!(error["message"], "Waiting for the user to answer this request. Send the same call again to collect the answer.");
            assert!(!error["message"].as_str().unwrap().contains("resum"));
        }
        let cards: i64 = db
            .query_row("SELECT count(*) FROM federated_card_records", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(cards, i64::from(waits));
        assert!(store.list_action_requests("direct").unwrap().is_empty());
        assert!(transport.requests().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_metadata_is_hidden_only_from_federated_callers() {
    let (mut state, store, transport, scratch) =
        super::super::github_read_frame_tests::imported_runtime();
    Arc::get_mut(&mut state)
        .unwrap()
        .runtime
        .set_federated_callers_enabled_for_test(true);
    for connection in ["ordinary-looking", "github-handle-not-a-bot"] {
        store
            .insert_connection("direct", connection, "github_rest", "active", &json!({}))
            .unwrap();
    }
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    db.execute_batch(
        "UPDATE github_app_handle SET connection_id='ordinary-looking' WHERE app_handle_id='app-x'",
    )
    .unwrap();
    store
        .upsert_catalog_action(&plexus_core::storage::CatalogActionInput {
            principal: "direct".into(),
            connection_id: "ordinary-looking".into(),
            name: "meta.read".into(),
            title: Some("Private bot action".into()),
            schema: json!({"type":"object","properties":{}}),
            schema_hash: "schema".into(),
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    let local = Arc::new(RouteBindings::new());
    local
        .insert_mode(17, 3, Principal::Direct, None, CallMode::Classic)
        .unwrap();
    for (name, arguments, result) in [
        (
            "connections",
            json!({"op":"list"}),
            json!({"connections":store.list_connections("direct").unwrap()}),
        ),
        (
            "catalog",
            json!({"op":"list","connection":"ordinary-looking"}),
            json!({"actions":store.list_catalog_actions("direct", "ordinary-looking").unwrap()}),
        ),
        (
            "catalog",
            json!({"op":"inspect","connection":"ordinary-looking","action":"meta.read"}),
            json!({"actions":store.list_catalog_actions("direct", "ordinary-looking").unwrap()}),
        ),
    ] {
        let actual = call(&state, &local, json!({"name":name,"arguments":arguments})).await;
        let expected = with_call_tool_result_for_route(
            Some(name),
            json!({"result":result}),
            None,
            false,
            false,
        );
        assert_eq!(actual.body, serde_json::to_vec(&expected).unwrap());
    }
    for negotiated in [false, true] {
        let routes = metadata_routes(&state, negotiated).await;
        let listed = reply(
            call(
                &state,
                &routes,
                json!({"name":"connections","arguments":{"op":"list"}}),
            )
            .await,
        );
        let ids: Vec<_> = listed["result"]["connections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["connection_id"].as_str().unwrap())
            .collect();
        let mut catalog_pairs = Vec::new();
        for arguments in [
            json!({"op":"list"}),
            json!({"op":"inspect","action":"meta.read"}),
            json!({"op":"inspect"}),
        ] {
            let mut hidden_args = arguments.clone();
            hidden_args["connection"] = json!("ordinary-looking");
            let mut unknown_args = arguments;
            unknown_args["connection"] = json!("never-existed");
            let hidden = call(
                &state,
                &routes,
                json!({"name":"catalog","arguments":hidden_args}),
            )
            .await;
            let unknown = call(
                &state,
                &routes,
                json!({"name":"catalog","arguments":unknown_args}),
            )
            .await;
            catalog_pairs.push((hidden.body, unknown.body));
        }
        assert!(!ids.contains(&"ordinary-looking"), "{listed}");
        assert!(ids.contains(&"github-handle-not-a-bot"), "{listed}");
        assert_item_keys(
            &listed,
            "connections",
            &["connection_id", "app_key", "status"],
            2,
        );
        for (hidden, unknown) in catalog_pairs {
            assert_eq!(
                hidden, unknown,
                "bot catalog metadata must match an unknown connection byte for byte"
            );
        }
    }
    assert!(transport.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_handle_connection_is_local_only_even_without_a_handle_name_prefix() {
    let (mut state, store, transport, scratch) =
        super::super::github_read_frame_tests::imported_runtime();
    Arc::get_mut(&mut state)
        .unwrap()
        .runtime
        .set_federated_callers_enabled_for_test(true);
    store
        .insert_connection(
            "direct",
            "ordinary-looking",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    db.execute_batch("UPDATE github_app_handle SET connection_id='ordinary-looking' WHERE app_handle_id='app-x'; DROP TABLE grants;").unwrap();
    let routes = bind_accepted(&state, stamp(), CallMode::Classic).await;
    let actual = reply(call(&state, &routes, invoke_body("ordinary-looking")).await);
    assert_eq!(
        actual["error"],
        json!({"code":"bot_action_requires_facade", "terminal":true, "message":"governance denied the connector operation", "transmission":"not_sent"})
    );
    assert!(transport.requests().is_empty());
    for table in [
        "action_requests",
        "reservations",
        "federated_rows",
        "federated_card_records",
    ] {
        let count: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
    let metadata = reply(
        call(
            &state,
            &routes,
            json!({"name":"connections", "arguments":{"op":"list"}}),
        )
        .await,
    );
    assert!(metadata["result"]["connections"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["connection_id"] != "ordinary-looking"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_kept_gates_pass_but_invoke_still_files_nothing() {
    let (mut state, store, transport, scratch) =
        super::super::github_read_frame_tests::imported_runtime();
    Arc::get_mut(&mut state)
        .unwrap()
        .runtime
        .set_federated_callers_enabled_for_test(true);
    let mut manifest: Value = serde_json::from_str(
        &subc_jsonc::jsonc_to_json(include_str!("../../../catalog/searxng_rest.jsonc")).unwrap(),
    )
    .unwrap();
    manifest["tier"] = json!("S1");
    manifest["actions_baseline"][0]["name"] = json!("meta.read");
    store
        .upsert_manifest(
            plexus_core::storage::CATALOG_PRINCIPAL,
            &plexus_core::ingest_value(manifest).unwrap(),
        )
        .unwrap();
    store
        .insert_connection("direct", "plain", "searxng_rest", "active", &json!({}))
        .unwrap();
    store
        .upsert_catalog_action(&plexus_core::storage::CatalogActionInput {
            principal: "direct".into(),
            connection_id: "plain".into(),
            name: "meta.read".into(),
            title: None,
            schema: json!({"type":"object","properties":{}}),
            schema_hash: "schema".into(),
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
    db.execute_batch("UPDATE connections SET ceiling_risk='read',ceiling_selectors='[\"meta.read\"]' WHERE connection_id='plain'; DROP TABLE grants;").unwrap();
    let routes = bind_accepted(&state, stamp(), CallMode::Classic).await;
    let actual = reply(call(&state, &routes, invoke_body("plain")).await);
    let mut expected = denial_response(&plexus_core::Denial::ConsentUnavailable {
        action: "meta.read".into(),
    });
    expected["error"]["transmission"] = json!("not_sent");
    assert_eq!(actual["error"], expected["error"]);
    assert!(transport.requests().is_empty());
    assert!(store.list_action_requests("direct").unwrap().is_empty());
    let row: (Option<String>, String, String) = db.query_row("SELECT agent_id,claim_kind,canonical_claim_identity FROM audit_journal WHERE action='meta.read'", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    assert_eq!(row, (None, "".into(), "".into()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invoke_reaches_direct_gates_with_no_grants_and_never_dispatches() {
    let state = metadata_state();
    let routes = bind_accepted(&state, stamp(), CallMode::Classic).await;
    let cases = [
        (invoke_body("callosum-only"), "connection_not_found"),
        (invoke_body("shared"), "grant_risk_ceiling"),
        (
            json!({"name":"invoke","arguments":{"op":"call","connection":"shared","action":"meta.destructive","args":{}}}),
            "needs_decision_plane",
        ),
        (
            json!({"name":"invoke","arguments":{"op":"call","connection":"shared","action":"meta.write","args":{}}}),
            "needs_decision_plane",
        ),
    ];
    for (body, code) in cases {
        let actual = reply(call(&state, &routes, body).await);
        assert_eq!(actual["error"]["code"], code, "{actual}");
        assert_eq!(actual["error"]["transmission"], "not_sent");
    }
    state
        .store()
        .set_policy("direct", "shared", "*", "block", None)
        .unwrap();
    let actual = reply(call(&state, &routes, invoke_body("shared")).await);
    let mut expected = denial_response(&plexus_core::Denial::Policy(
        plexus_core::governance::PolicyDenial::Blocked,
    ));
    expected["error"]["transmission"] = json!("not_sent");
    // The federated wrapper adds one member, not a new denial envelope.
    assert_eq!(actual["error"], expected["error"]);
    assert!(state
        .store()
        .list_action_requests("direct")
        .unwrap()
        .is_empty());
    assert!(state
        .store()
        .list_audit("reserved:callosum")
        .unwrap()
        .iter()
        .all(|row| row.reason_code == "connection_not_found"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_refusal_body_is_unchanged_for_local_invoke() {
    let state = state(true);
    let local = Arc::new(RouteBindings::new());
    local
        .insert_mode(17, 3, Principal::Direct, None, CallMode::Classic)
        .unwrap();
    let local_reply = reply(call(&state, &local, invoke_body("absent")).await);
    let remote = bind_accepted(&state, stamp(), CallMode::Classic).await;
    let remote_reply = reply(call(&state, &remote, invoke_body("absent")).await);
    assert_eq!(
        local_reply["error"],
        json!({"code":"connection_not_found", "terminal":true, "message":"governance denied the connector operation"})
    );
    let mut expected = local_reply["error"].clone();
    expected["transmission"] = json!("not_sent");
    assert_eq!(remote_reply["error"], expected);
}
