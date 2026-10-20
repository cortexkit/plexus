use super::*;
use plexus_core::storage::github_store::GithubHandleReadGrant;

const ACTION: &str = "github.repo.get";

fn request(dry_run: bool) -> GithubHandleReadGrant {
    GithubHandleReadGrant {
        app_handle_id: Some("app-x".into()),
        all_handles: false,
        module: "reserved:aft".into(),
        actions: vec![ACTION.into()],
        dry_run,
    }
}

fn database(scratch: &Scratch) -> rusqlite::Connection {
    rusqlite::Connection::open(scratch.as_ref() as &Path).unwrap()
}

fn snapshot(db: &rusqlite::Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "connections",
        "grants",
        "catalog_actions",
        "audit_journal",
        "policies",
        "github_app_handle",
    ]
    .iter()
    .map(|table| {
        let mut stmt = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = stmt.column_count();
        stmt.query_map([], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    })
    .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_read_upgrade_seeds_and_serves_bot_read() {
    let (runtime, store, transport, scratch) = imported_runtime();
    let db = database(&scratch);
    db.execute("DELETE FROM catalog_actions WHERE name=?1", [ACTION])
        .unwrap();
    let before = snapshot(&db);
    let preview = store
        .grant_github_handle_read(&request(true))
        .unwrap()
        .unwrap();
    assert_eq!(preview["handles"][0]["catalog_additions"], json!([ACTION]));
    assert_eq!(preview["handles"][0]["ceiling_additions"], json!([ACTION]));
    assert_eq!(
        snapshot(&db),
        before,
        "preview must persist nothing, including catalog and audit"
    );
    let denied = read(
        &runtime,
        Some(head(Some("agent-x"))),
        ACTION,
        "o/x",
        json!({"path":""}),
    )
    .await;
    assert!(denied.get("error").is_some(), "{denied}");
    assert!(transport.requests().is_empty());
    let generation: i64 = db
        .query_row(
            "SELECT generation FROM connections WHERE connection_id='github-handle-app-x'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let grant_generation: i64 = db
        .query_row(
            "SELECT generation FROM grants WHERE grant_id='github-import:app-x:aft'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let applied = store
        .grant_github_handle_read(&request(false))
        .unwrap()
        .unwrap();
    assert_eq!(applied["handles"][0]["catalog_additions"], json!([ACTION]));
    let after_generation: i64 = db
        .query_row(
            "SELECT generation FROM connections WHERE connection_id='github-handle-app-x'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(after_generation, generation + 1);
    let after_grant_generation: i64 = db
        .query_row(
            "SELECT generation FROM grants WHERE grant_id='github-import:app-x:aft'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(after_grant_generation, grant_generation);
    let audits: i64 = db.query_row("SELECT count(*) FROM audit_journal WHERE action='github.handle.grant' AND outcome='applied'", [], |row| row.get(0)).unwrap();
    assert_eq!(audits, 1);
    transport.set_response(envelope(json!({"full_name":"o/x"})));
    let reply = read(
        &runtime,
        Some(head(Some("agent-x"))),
        ACTION,
        "o/x",
        json!({"path":""}),
    )
    .await;
    assert_eq!(reply["result"]["body"]["full_name"], "o/x", "{reply}");
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(transport.requests()[0].connection_id, "github-handle-app-x");
    let before = snapshot(&db);
    let no_op = store
        .grant_github_handle_read(&request(false))
        .unwrap()
        .unwrap();
    assert_eq!(no_op["handles"][0]["grants"][0]["op"], "unchanged");
    assert_eq!(
        snapshot(&db),
        before,
        "no-op must not bump any generation or append audit"
    );
}

#[test]
fn read_upgrade_refuses_writes_unknown_actions_and_nonoperator() {
    let (_, store, _, scratch) = imported_runtime();
    let db = database(&scratch);
    let before = snapshot(&db);
    for action in [
        "create_issue",
        "github.issue.create",
        "github.issue.get",
        "*",
    ] {
        let mut grant = request(false);
        grant.actions = vec![action.into()];
        let refusal = store.grant_github_handle_read(&grant).unwrap().unwrap_err();
        assert!(refusal.starts_with("action_not_grantable"), "{refusal}");
        assert!(refusal.contains(action), "{refusal}");
    }
    assert_eq!(
        plexus_core::github::control::grant_read(&store, "reserved:aft", &request(false))
            .unwrap_err(),
        "operator_authority_required"
    );
    assert_eq!(snapshot(&db), before);
}

#[test]
fn read_upgrade_requires_enabled_bot_connection() {
    let (_, store, _, scratch) = imported_runtime();
    let db = database(&scratch);
    // An ordinary connection ID cannot be used as an imported handle ID.
    let mut grant = request(false);
    grant.app_handle_id = Some("github-handle-app-x".into());
    assert_eq!(
        store.grant_github_handle_read(&grant).unwrap().unwrap_err(),
        "agent_handle_unknown"
    );
    db.execute(
        "UPDATE connections SET app_key='other' WHERE connection_id='github-handle-app-x'",
        [],
    )
    .unwrap();
    let before = snapshot(&db);
    assert!(store
        .grant_github_handle_read(&request(false))
        .unwrap()
        .unwrap_err()
        .starts_with("bot_connection_required"));
    assert_eq!(snapshot(&db), before);
    db.execute(
        "UPDATE connections SET app_key='github_rest',status='disabled'",
        [],
    )
    .unwrap();
    assert!(store
        .grant_github_handle_read(&request(false))
        .unwrap()
        .unwrap_err()
        .starts_with("bot_connection_required"));
    db.execute(
        "UPDATE connections SET status='active',ceiling_risk='unclassified'",
        [],
    )
    .unwrap();
    assert!(store
        .grant_github_handle_read(&request(false))
        .unwrap()
        .unwrap_err()
        .starts_with("risk_above_ceiling"));
    db.execute("UPDATE connections SET ceiling_risk='write'", [])
        .unwrap();
    db.execute("UPDATE github_app_handle SET status='disabled'", [])
        .unwrap();
    let before = snapshot(&db);
    assert!(store
        .grant_github_handle_read(&request(false))
        .unwrap()
        .unwrap_err()
        .starts_with("agent_handle_disabled"));
    assert_eq!(snapshot(&db), before);
}

#[test]
fn read_upgrade_preserves_inactive_catalog_and_refuses_risk_drift() {
    for (risk, status, expected) in [
        ("read", "quarantined", "catalog_action_inactive"),
        ("read", "disabled", "catalog_action_inactive"),
        ("write", "active", "action_not_read"),
    ] {
        let (_, store, _, scratch) = imported_runtime();
        let db = database(&scratch);
        db.execute(
            "UPDATE catalog_actions SET risk=?1,status=?2 WHERE name=?3",
            rusqlite::params![risk, status, ACTION],
        )
        .unwrap();
        let before = snapshot(&db);
        let refusal = store
            .grant_github_handle_read(&request(false))
            .unwrap()
            .unwrap_err();
        assert!(refusal.starts_with(expected), "{refusal}");
        assert_eq!(snapshot(&db), before);
    }
}

#[test]
fn read_upgrade_requires_reviewed_manifest_action() {
    let (_, store, _, scratch) = imported_runtime();
    let db = database(&scratch);
    db.execute(
        "UPDATE app_manifests SET status='disabled' WHERE key='github_rest'",
        [],
    )
    .unwrap();
    let before = snapshot(&db);
    assert!(store
        .grant_github_handle_read(&request(false))
        .unwrap()
        .unwrap_err()
        .starts_with("reviewed_read_required"));
    assert_eq!(snapshot(&db), before);
}

fn add_handle(store: &PlexusStore, id: &str, status: &str) {
    store
        .import_github_handles(&[GithubImportRow {
            handle: GithubHandle {
                app_handle_id: id.into(),
                agent_id: format!("agent-{id}"),
                app_id: 2,
                installation_id: None,
                credential_reference: format!("github_app:{id}"),
                credential_generation: 0,
                status: status.into(),
                proven_at: None,
                connection_principal: "direct".into(),
                connection_id: format!("github-handle-{id}"),
            },
            repositories: vec![format!("o/{id}")],
            grants: vec![],
            module_actions: vec!["github.issue.get".into()],
            policies: vec![],
        }])
        .unwrap();
}

#[test]
fn read_upgrade_bulk_is_atomic_skips_disabled_and_creates_missing_module_grant() {
    let (_, store, _, scratch) = imported_runtime();
    add_handle(&store, "app-y", "enabled");
    add_handle(&store, "app-z", "disabled");
    let db = database(&scratch);
    db.execute(
        "DELETE FROM grants WHERE grant_id='github-import:app-y:aft'",
        [],
    )
    .unwrap();
    let mut grant = request(true);
    grant.app_handle_id = None;
    grant.all_handles = true;
    let before = snapshot(&db);
    let preview = store.grant_github_handle_read(&grant).unwrap().unwrap();
    assert_eq!(preview["handles"].as_array().unwrap().len(), 2);
    assert_eq!(preview["handles"][1]["app_handle_id"], "app-y");
    assert_eq!(preview["handles"][1]["grants"][0]["op"], "insert");
    assert_eq!(snapshot(&db), before);
    grant.dry_run = false;
    // A refusal on the second handle must roll back changes to the first.
    db.execute("UPDATE catalog_actions SET status='disabled' WHERE connection_id='github-handle-app-y' AND name=?1", [ACTION]).unwrap();
    let before = snapshot(&db);
    assert!(store.grant_github_handle_read(&grant).unwrap().is_err());
    assert_eq!(snapshot(&db), before, "bulk refuses atomically");
    db.execute("UPDATE catalog_actions SET status='active' WHERE connection_id='github-handle-app-y' AND name=?1", [ACTION]).unwrap();
    let applied = store.grant_github_handle_read(&grant).unwrap().unwrap();
    assert_eq!(applied["handles"].as_array().unwrap().len(), 2);
    let mut stmt = db.prepare("SELECT connection_id,action_selectors FROM grants WHERE grantee_principal='reserved:aft' AND agent_id IS NULL ORDER BY connection_id").unwrap();
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(rows.len(), 3);
    for (connection, selectors) in rows {
        let selectors: Vec<String> = serde_json::from_str(&selectors).unwrap();
        assert_eq!(
            selectors.contains(&ACTION.to_owned()),
            connection != "github-handle-app-z"
        );
    }
    let before = snapshot(&db);
    store.grant_github_handle_read(&grant).unwrap().unwrap();
    assert_eq!(snapshot(&db), before);
}

#[test]
fn read_upgrade_audit_failure_rolls_back_authority() {
    let (_, store, _, scratch) = imported_runtime();
    let db = database(&scratch);
    db.execute_batch("CREATE TRIGGER fail_read_upgrade_audit BEFORE INSERT ON audit_journal BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;").unwrap();
    let before = snapshot(&db);
    assert!(store.grant_github_handle_read(&request(false)).is_err());
    assert_eq!(snapshot(&db), before);
}

#[test]
fn read_upgrade_requires_one_selector_and_nonempty_authority() {
    let (_, store, _, _) = imported_runtime();
    for (handle, all, module, actions) in [
        (None, false, "reserved:aft", vec![ACTION.into()]),
        (
            Some("app-x".into()),
            true,
            "reserved:aft",
            vec![ACTION.into()],
        ),
        (Some("app-x".into()), false, "", vec![ACTION.into()]),
        (Some("app-x".into()), false, "reserved:aft", vec![]),
    ] {
        let grant = GithubHandleReadGrant {
            app_handle_id: handle,
            all_handles: all,
            module: module.into(),
            actions,
            dry_run: false,
        };
        assert!(store.grant_github_handle_read(&grant).unwrap().is_err());
    }
}

#[test]
fn read_upgrade_seeds_only_requested_missing_rows() {
    let (_, store, _, scratch) = imported_runtime();
    let db = database(&scratch);
    db.execute(
        "DELETE FROM catalog_actions WHERE name IN ('github.repo.get','github.search.code')",
        [],
    )
    .unwrap();
    db.execute("UPDATE catalog_actions SET risk='destructive',status='quarantined' WHERE name='create_issue'", []).unwrap();
    let before: (String, String, i64) = db
        .query_row(
            "SELECT risk,status,generation FROM catalog_actions WHERE name='create_issue'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    store
        .grant_github_handle_read(&request(false))
        .unwrap()
        .unwrap();
    let after: (String, String, i64) = db
        .query_row(
            "SELECT risk,status,generation FROM catalog_actions WHERE name='create_issue'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        after, before,
        "upgrade must not reconcile unrelated catalog rows"
    );
    assert!(store
        .catalog_action("direct", "github-handle-app-x", "github.search.code")
        .unwrap()
        .is_none());
}
