use super::*;

fn invoke_body(connection: &str) -> Value {
    json!({"name":"invoke", "arguments":{"op":"call", "connection":connection, "action":"meta.read", "args":{}}})
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
        .any(|item| item["connection_id"] == "ordinary-looking"));
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
