use super::*;
use plexus_core::storage::github_store::{GithubHandle, GithubImportRow};
use std::collections::BTreeSet;

fn call(state: &Arc<ModuleState>, caller: &str, arguments: &Value) -> Value {
    let object = json!({"name":"github","arguments":arguments});
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
    routes
        .insert(
            2,
            1,
            Principal::Reserved {
                module_id: caller.into(),
            },
        )
        .unwrap();
    facade_tool_reply(&frame, object.as_object().unwrap(), state, &routes).unwrap()
}

fn fixture() -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    let (state, store, transport, scratch) = crate::github_read_frame_tests::imported_runtime();
    store
        .import_github_handles(&[GithubImportRow {
            handle: GithubHandle {
                app_handle_id: "app-y".into(),
                agent_id: "agent-y".into(),
                app_id: 2,
                installation_id: None,
                credential_reference: "github_app:app-y".into(),
                credential_generation: 0,
                status: "enabled".into(),
                proven_at: None,
                connection_principal: "direct".into(),
                connection_id: "github-handle-app-y".into(),
            },
            repositories: vec!["o/z".into(), "o/a".into()],
            grants: vec![],
            module_actions: vec![],
            policies: vec![],
        }])
        .unwrap();
    for handle in ["x", "y"] {
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: format!("bindings-{handle}"),
                principal: "direct".into(),
                connection_id: format!("github-handle-app-{handle}"),
                grantee_principal: "reserved:prefrontal-core".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec![],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
    }
    assert_eq!(store.github_repo_binding_generation().unwrap(), 3);
    (state, store, transport, scratch)
}

#[test]
fn github_bindings_contract_files_match_handler() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../plexus-core/tests/fixtures/gh_shim_wire/bindings-contract");
    let x = json!({"repository":"o/x","app_handle_id":"app-x","agent_id":"agent-x"});
    let y = json!([
        {"repository":"o/a","app_handle_id":"app-y","agent_id":"agent-y"},
        {"repository":"o/z","app_handle_id":"app-y","agent_id":"agent-y"}
    ]);
    let cases = [
        ("connection", "prefrontal-core", json!([x.clone()]), None),
        ("agent", "prefrontal-core", json!([x]), None),
        ("other-agent", "prefrontal-core", y, None),
        ("none", "prefrontal-core", json!([]), None),
        ("no-grant", "without-grant", json!([]), None),
        (
            "missing-agent-id",
            "prefrontal-core",
            Value::Null,
            Some("agent_id"),
        ),
        (
            "non-string-agent-id",
            "prefrontal-core",
            Value::Null,
            Some("agent_id"),
        ),
        (
            "extra-field",
            "prefrontal-core",
            Value::Null,
            Some("connection_id"),
        ),
        (
            "secret-extra-field",
            "prefrontal-core",
            Value::Null,
            Some("token"),
        ),
    ];
    let regenerate = std::env::var_os("PLEXUS_REGENERATE_GITHUB_BINDINGS_CONTRACT").is_some();
    let mut expected_files = BTreeSet::new();
    for (name, caller, bindings, invalid_field) in cases {
        let (state, _store, transport, scratch) = fixture();
        let request_name = format!("{name}.request.json");
        let reply_name = format!("{name}.reply.json");
        let arguments: Value =
            serde_json::from_slice(&std::fs::read(root.join(&request_name)).unwrap()).unwrap();
        let reply = call(&state, caller, &arguments);
        let expected = if let Some(field) = invalid_field {
            json!({"error":{"code":"invalid_request","field":field}})
        } else {
            json!({"result":{"repo_binding_generation":3,"bindings":bindings}})
        };
        assert_eq!(reply, expected, "{name}");
        let rendered = format!("{}\n", serde_json::to_string_pretty(&reply).unwrap());
        if regenerate {
            std::fs::write(root.join(&reply_name), &rendered).unwrap();
        }
        assert_eq!(
            std::fs::read(root.join(&reply_name)).unwrap(),
            rendered.as_bytes(),
            "{name}"
        );
        expected_files.extend([request_name, reply_name]);
        assert!(transport.requests().is_empty(), "{name} contacted GitHub");
        let db = rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap();
        let (action, agent, decision, reason): (String, Option<String>, String, String) = db.query_row(
            "SELECT action,agent_id,decision,reason_code FROM audit_journal WHERE gate='github_control'",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        ).unwrap();
        assert_eq!(
            action,
            format!("github.{}", arguments["op"].as_str().unwrap())
        );
        assert_eq!(
            agent.as_deref(),
            arguments.get("agent_id").and_then(Value::as_str)
        );
        assert_eq!(
            decision,
            if invalid_field.is_some() {
                "deny"
            } else {
                "allow"
            }
        );
        assert_eq!(
            reason,
            if invalid_field.is_some() {
                "invalid_request"
            } else {
                "allowed"
            }
        );
    }
    let actual_files: BTreeSet<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        actual_files, expected_files,
        "every bindings contract file must be replayed"
    );
}
