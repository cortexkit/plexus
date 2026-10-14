use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::governance::{AuthorizationRequest, GovernanceSeams};
use plexus_core::storage::github_store::{GithubGovernanceSeams, GithubHandle};
use plexus_core::{PlexusStore, MIGRATIONS};
use rusqlite::{params, Connection};
use serde_json::json;

fn fixture() -> (plexus_core::test_scratch::Scratch, PlexusStore) {
    let path = plexus_core::test_scratch::Scratch::database("github-store");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "github-store".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.path().to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).unwrap();
    (path, store)
}

fn handle(id: &str, agent: &str) -> GithubHandle {
    GithubHandle {
        app_handle_id: id.into(),
        agent_id: agent.into(),
        app_id: 7,
        installation_id: None,
        credential_reference: format!("github_app:{id}"),
        credential_generation: 1,
        status: "enabled".into(),
        proven_at: None,
        connection_principal: "operator".into(),
        connection_id: format!("conn-{id}"),
    }
}

#[test]
fn versioned_schema_rehearses_existing_rows_and_rejects_duplicate_nonces() {
    let source = plexus_core::test_scratch::Scratch::database("github-migration-source");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "github-migration".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: source.path().to_string_lossy().into_owned(),
        },
    };
    let boundary = MIGRATIONS
        .iter()
        .position(|migration| migration.version == 30)
        .unwrap();
    let old_store = cortexkit_store::open_sqlite(&descriptor).unwrap();
    old_store
        .migrate("plexus", &MIGRATIONS[..boundary])
        .unwrap();
    drop(old_store);
    let conn = Connection::open(source.path()).unwrap();
    conn.execute(
        "INSERT INTO grants (grant_id, principal, connection_id, grantee_principal,
        risk_ceiling, authority_kind, created_at_ms) VALUES ('g','p','c','a','write','invoke',1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO action_requests (request_id, principal, connection_id, action,
        args_snapshot, schema_hash, requester, status, expires_at, created_at_ms)
        VALUES ('r','p','c','x','{}','h','a','pending',10,1)",
        [],
    )
    .unwrap();
    // SQLite creates a consistent on-disk backup rather than copying a live WAL file.
    let backup = plexus_core::test_scratch::Scratch::database("github-migration-backup");
    let backup_path = backup.path().with_extension("backup");
    conn.execute("VACUUM INTO ?1", [backup_path.to_string_lossy().as_ref()])
        .unwrap();
    drop(conn);
    let descriptor = StorageDescriptor {
        backend: StorageBackend::Sqlite {
            path: backup_path.to_string_lossy().into_owned(),
        },
        ..descriptor
    };
    drop(PlexusStore::open(&descriptor).unwrap());
    // Reopening must not replay version 30 over the already migrated copy.
    drop(PlexusStore::open(&descriptor).unwrap());
    let conn = Connection::open(&backup_path).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT MAX(version) FROM cortexkit_schema_version WHERE namespace='plexus'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        MIGRATIONS.last().unwrap().version as i64
    );
    assert_eq!(
        conn.query_row("SELECT agent_id FROM grants WHERE grant_id='g'", [], |r| {
            r.get::<_, Option<String>>(0)
        })
        .unwrap(),
        None
    );
    assert_eq!(
        conn.query_row(
            "SELECT agent_id FROM action_requests WHERE request_id='r'",
            [],
            |r| r.get::<_, Option<String>>(0)
        )
        .unwrap(),
        None
    );
    conn.execute(
        "INSERT INTO github_bot_receipt (agent_id, request_nonce, request_fingerprint, state, created_at, updated_at)
        VALUES ('a','nonce','fingerprint','pending',1,1)",
        [],
    )
    .unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT effects FROM github_bot_receipt WHERE agent_id='a'",
            [],
            |row| row.get::<_, String>(0)
        )
        .unwrap(),
        "[]"
    );
    assert_eq!(
        conn.query_row(
            "SELECT created_at, updated_at FROM github_bot_receipt WHERE agent_id='a'",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        )
        .unwrap(),
        (1, 1)
    );
    let effects: Vec<_> = (0..6)
        .map(|leg| {
            json!({
                "effect": format!("issue_edit_leg_{leg}"),
                "dispatch_attempted_at": if leg < 4 { Some(100 + leg) } else { None },
                "outcome": if leg < 3 { Some("completed") } else { None },
            })
        })
        .collect();
    conn.execute(
        "UPDATE github_bot_receipt SET effects=?1 WHERE agent_id='a' AND request_nonce='nonce'",
        [serde_json::to_string(&effects).unwrap()],
    )
    .unwrap();
    let saved: String = conn
        .query_row(
            "SELECT effects FROM github_bot_receipt WHERE agent_id='a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&saved).unwrap(),
        json!(effects)
    );
    assert!(conn
        .execute(
            "UPDATE github_bot_receipt SET effects='not-json' WHERE agent_id='a'",
            []
        )
        .is_err());
    assert!(conn
        .execute(
            "INSERT INTO github_bot_receipt (agent_id, request_nonce, request_fingerprint, state, created_at, updated_at)
        VALUES ('a','nonce','other','completed',1,1)",
            []
        )
        .is_err());
    assert!(conn
        .execute(
            "INSERT INTO github_bot_receipt (agent_id, request_nonce, request_fingerprint, state, created_at, updated_at)
        VALUES ('b','different','fingerprint','invalid',1,1)",
            []
        )
        .is_err());
}

#[test]
fn handle_generation_and_agent_uniqueness() {
    let (path, store) = fixture();
    let first = handle("one", "agent-a");
    store.put_github_handle(&first).unwrap();
    assert!(store.put_github_handle(&handle("two", "agent-a")).is_err());
    let conn = Connection::open(path.path()).unwrap();
    conn.execute(
        "UPDATE github_app_handle SET proven_at=10 WHERE app_handle_id='one'",
        [],
    )
    .unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT app_handle_generation FROM github_app_handle",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    store.put_github_handle(&first).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT app_handle_generation FROM github_app_handle",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        3
    );
}

#[test]
fn binding_write_bumps_global_generation_and_rewrites_both_connection_filters() {
    let (path, store) = fixture();
    for id in ["one", "two"] {
        store
            .insert_connection(
                "operator",
                &format!("conn-{id}"),
                "github_rest",
                "active",
                &json!({"values":{"other":["untouched"]}}),
            )
            .unwrap();
        store
            .put_github_handle(&handle(id, &format!("agent-{id}")))
            .unwrap();
    }
    assert_eq!(store.bind_github_repo("org/repo", "one").unwrap(), 1);
    assert_eq!(store.bind_github_repo("org/repo", "two").unwrap(), 2);
    let conn = Connection::open(path.path()).unwrap();
    for (id, expected_repo, expected_owner) in [
        ("one", json!([]), json!(null)),
        ("two", json!(["repo"]), json!("org")),
    ] {
        let filter: String = conn
            .query_row(
                "SELECT resource_filters FROM connections WHERE connection_id=?1",
                [format!("conn-{id}")],
                |r| r.get(0),
            )
            .unwrap();
        let filter: serde_json::Value = serde_json::from_str(&filter).unwrap();
        assert_eq!(filter["values"]["repo"], expected_repo);
        assert_eq!(filter["values"]["owner"], expected_owner);
        assert_eq!(filter["values"]["other"], json!(["untouched"]));
        assert_eq!(filter["write_enabling"], json!(["owner", "repo"]));
    }
    assert!(store.bind_github_repo("org/repo", "missing").is_err());
    assert_eq!(
        conn.query_row(
            "SELECT generation FROM github_repo_binding_generation",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(store.unbind_github_repo("org/repo").unwrap(), 3);
}

#[test]
fn governance_reads_handle_grants_policy_and_agent_bound_approval() {
    let (path, store) = fixture();
    store
        .insert_connection("operator", "conn-one", "github_rest", "active", &json!({}))
        .unwrap();
    store.put_github_handle(&handle("one", "agent-a")).unwrap();
    let conn = Connection::open(path.path()).unwrap();
    for (id, agent) in [("module", None), ("agent", Some("agent-a"))] {
        conn.execute(
            "INSERT INTO grants (grant_id, principal, connection_id, grantee_principal,
            risk_ceiling, authority_kind, created_at_ms, action_selectors, generation, agent_id)
            VALUES (?1,'operator','conn-one','reserved:aft','write','invoke',1,'[\"write\"]',4,?2)",
            params![id, agent],
        )
        .unwrap();
    }
    conn.execute("INSERT INTO policies (policy_id, principal, connection_id, action_selector, effect, updated_at_ms, generation)
        VALUES ('policy','operator','conn-one','write','ask_first',1,3)", []).unwrap();
    conn.execute("INSERT INTO policies (policy_id, principal, connection_id, action_selector, effect, updated_at_ms, generation)
        VALUES ('agent-policy','agent-a','conn-one','write','allow',1,1)", []).unwrap();
    conn.execute("INSERT INTO action_requests (request_id, principal, connection_id, action, args_snapshot,
        schema_hash, requester, status, expires_at, created_at_ms, agent_id)
        VALUES ('approval','operator','conn-one','write','{}','hash','reserved:aft','approved',10000000000000,1,'agent-a')", []).unwrap();
    let seams = GithubGovernanceSeams {
        store: &store,
        credential_provider: None,
    };
    let connection = store.connection("operator", "conn-one").unwrap().unwrap();
    let authority = seams.handle_row(&connection).unwrap().unwrap();
    assert_eq!(authority.credential_reference, b"github_app:one");
    assert!(authority.enabled);
    let request = AuthorizationRequest::new(
        plexus_core::github::AFT_PRINCIPAL,
        "conn-one",
        "write",
        json!({}),
    )
    .with_bound_agent("agent-a", "one");
    let rows = seams.grant_rows(&connection, &request).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter()
            .find(|row| row.grant.grant_id == "module")
            .unwrap()
            .agent_id,
        None
    );
    assert_eq!(
        rows.iter()
            .find(|row| row.grant.grant_id == "agent")
            .unwrap()
            .agent_id
            .as_deref(),
        Some("agent-a")
    );
    assert_eq!(
        seams
            .grant_generations(
                &connection,
                plexus_core::github::AFT_PRINCIPAL,
                "agent-a",
                "write"
            )
            .unwrap(),
        (4, 4)
    );
    assert_eq!(
        seams
            .grant_generations(
                &connection,
                plexus_core::github::AFT_PRINCIPAL,
                "other",
                "write"
            )
            .unwrap(),
        (-1, 4)
    );
    let action = plexus_core::storage::CatalogAction {
        connection_id: "conn-one".into(),
        principal: "operator".into(),
        name: "write".into(),
        title: None,
        schema: json!({}),
        schema_hash: "hash".into(),
        risk: "write".into(),
        severity: "S1".into(),
        status: "active".into(),
        quarantine_reason: None,
        reconciliation: None,
        generation: 0,
        ask_first: false,
    };
    let inputs = seams
        .policy_inputs(&connection, "agent-a", &action)
        .unwrap();
    assert_eq!(inputs.module_effect.as_deref(), Some("ask_first"));
    assert_eq!(inputs.agent_effect.as_deref(), Some("allow"));
    let policy_hash = |effect: Option<&str>| {
        plexus_core::jcs_sha256(&json!([inputs.module_effect, effect, action.ask_first])).unwrap()
    };
    let original_hash = policy_hash(inputs.agent_effect.as_deref());
    assert_eq!(original_hash, policy_hash(Some("allow")));
    conn.execute(
        "UPDATE policies SET effect='block' WHERE policy_id='agent-policy'",
        [],
    )
    .unwrap();
    let changed = seams
        .policy_inputs(&connection, "agent-a", &action)
        .unwrap();
    assert_eq!(changed.agent_effect.as_deref(), Some("block"));
    assert_ne!(original_hash, policy_hash(changed.agent_effect.as_deref()));
    assert_eq!(
        seams
            .receipt_approval(&connection, "approval")
            .unwrap()
            .unwrap()
            .agent_id,
        "agent-a"
    );
    assert!(seams
        .receipt_approval(&connection, "unknown")
        .unwrap()
        .is_none());
}

#[test]
fn migration_30_preserves_all_approval_columns_and_expands_terminal_status() {
    use rusqlite::types::Value as SqlValue;
    let scratch = plexus_core::test_scratch::Scratch::database("github-approval-migration");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "github-approval-migration".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.path().to_string_lossy().into_owned(),
        },
    };
    let boundary = MIGRATIONS
        .iter()
        .position(|migration| migration.version == 30)
        .unwrap();
    let old = cortexkit_store::open_sqlite(&descriptor).unwrap();
    old.migrate("plexus", &MIGRATIONS[..boundary]).unwrap();
    drop(old);
    let db = Connection::open(scratch.path()).unwrap();
    for (id, status) in ["pending", "approved", "denied", "expired"]
        .into_iter()
        .enumerate()
    {
        db.execute("INSERT INTO action_requests (request_id,principal,connection_id,action,args_snapshot,schema_hash,requester,
            status,decision,decider,expires_at,created_at_ms,args_hash,reconciliation_status,decision_id)
            VALUES (?1,'owner','connection','action','{\"body\":\"value\"}','schema','requester',?2,'decision','decider',100,50,'hash','pending','decision-id')",
            params![format!("r{id}"), status]).unwrap();
    }
    let rows = |db: &Connection| {
        let mut stmt = db
            .prepare("SELECT * FROM action_requests ORDER BY request_id")
            .unwrap();
        let count = stmt.column_count();
        stmt.query_map([], |row| {
            (0..count)
                .map(|column| row.get::<_, SqlValue>(column))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    };
    let before = rows(&db);
    let objects = |db: &Connection| {
        db.prepare("SELECT type,name FROM sqlite_master WHERE tbl_name='action_requests' AND type IN ('index','trigger') ORDER BY type,name").unwrap()
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).unwrap()
            .collect::<rusqlite::Result<Vec<_>>>().unwrap()
    };
    let before_objects = objects(&db);
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    for table in tables {
        let mut stmt = db
            .prepare(&format!("PRAGMA foreign_key_list(\"{table}\")"))
            .unwrap();
        let references: Vec<String> = stmt
            .query_map([], |row| row.get(2))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            !references.iter().any(|table| table == "action_requests"),
            "{table} references action_requests"
        );
    }
    drop(db);
    // Migration 30 rebuilds action_requests to add agent_id and consumed status.
    // A later migration must not move the boundary this rebuild test exercises.
    let upgraded = cortexkit_store::open_sqlite(&descriptor).unwrap();
    upgraded
        .migrate("plexus", &MIGRATIONS[..=boundary])
        .unwrap();
    drop(upgraded);
    let db = Connection::open(scratch.path()).unwrap();
    let after = rows(&db);
    assert_eq!(before.len(), after.len());
    for (old, new) in before.iter().zip(&after) {
        assert_eq!(old, &new[..old.len()]);
        assert_eq!(new.last(), Some(&SqlValue::Null));
    }
    // A rebuild must keep every index and trigger the table had, under the
    // same name. It may add new ones (generation 36 adds the per-carrier
    // call_key index), so this checks that nothing was lost rather than
    // that nothing changed.
    let after_objects = objects(&db);
    assert!(
        before_objects
            .iter()
            .all(|object| after_objects.contains(object)),
        "action request indexes/triggers must retain their names: {before_objects:?} -> {after_objects:?}"
    );
    db.execute(
        "UPDATE action_requests SET status='consumed' WHERE request_id='r1'",
        [],
    )
    .unwrap();
    assert!(db
        .execute(
            "UPDATE action_requests SET status='bogus' WHERE request_id='r2'",
            []
        )
        .is_err());
}

#[test]
fn latest_schema_preserves_the_consent_call_key_foreign_key() {
    let (path, _store) = fixture();
    let db = Connection::open(path.path()).unwrap();
    let references: Vec<(i64, String, String, String)> = db
        .prepare("PRAGMA foreign_key_list(consent_call_keys)")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    // Consent aliases reference an owner-scoped request id. The composite FK
    // must preserve both owner and id, not accidentally link another owner's row.
    assert_eq!(
        references,
        vec![
            (
                0,
                "action_requests".into(),
                "principal".into(),
                "principal".into()
            ),
            (
                0,
                "action_requests".into(),
                "request_id".into(),
                "request_id".into()
            )
        ],
        "consent aliases must retain their request FK"
    );
}
