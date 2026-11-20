//! Storage regression tests and their shared fixtures.

use super::*;
use crate::poller::CursorStrategy;
use crate::test_scratch::Scratch;
use cortexkit_store_types::Isolation;
use rusqlite::Connection;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

static TRIGGER_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

include!("../storage_api_tests.rs");

fn empty_schema() -> Connection {
    let connection = Connection::open_in_memory().expect("open sqlite memory");
    PlexusStore::apply_migrations(&connection).expect("apply schema");
    connection
}

fn audit_store() -> PlexusStore {
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!(
            "audit-retention-test-{}-{}",
            now_ms(),
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    PlexusStore::open(&descriptor).expect("open audit retention store")
}

fn instance_rule_manifest(store: &PlexusStore, key: &str, takes_instance_url: bool) {
    let mut manifest: Value = serde_json::from_str(
        &subc_jsonc::jsonc_to_json(include_str!("../../../../catalog/searxng_rest.jsonc")).unwrap(),
    )
    .unwrap();
    manifest["key"] = serde_json::json!(key);
    if !takes_instance_url {
        manifest["transport"] =
            serde_json::json!({"kind":"rest_api","url":"https://fixed.invalid"});
    }
    store
        .upsert_manifest(
            CATALOG_PRINCIPAL,
            &crate::manifest::ingest_value(manifest).unwrap(),
        )
        .unwrap();
}

#[test]
fn searxng_instance_ticket_requirements_come_from_the_reviewed_manifest() {
    let store = audit_store();
    // Give searxng_rest a fixed URL and private_rest a connection-supplied
    // URL to catch admission checks based on the app key.
    instance_rule_manifest(&store, "searxng_rest", false);
    instance_rule_manifest(&store, "private_rest", true);
    let instance =
        crate::instance_url::InstanceUrl::parse("https://private-ticket.invalid/base").unwrap();
    let ceiling = Ceiling {
        risk: Risk::Read,
        action_selectors: vec!["search".into()],
    };
    let issue = |app: &str, connection: &str, instance| {
        store.issue_binding_ticket_audited_at_instance(
            "direct",
            connection,
            app,
            NO_CREDENTIAL_REF_ROLE,
            &[],
            &ceiling,
            &|_| {
                AuditRecord::ceremony(
                    "direct",
                    Some(app),
                    Some(connection),
                    "issue_ticket",
                    "read",
                    None,
                )
            },
            instance,
        )
    };
    let error = issue("searxng_rest", "fixed", Some(&instance)).unwrap_err();
    assert!(error
        .to_string()
        .contains("this provider takes no instance_url"));
    assert!(
        store.connection("direct", "fixed").unwrap().is_none(),
        "rejected instance must write no connection"
    );
    assert!(
        store.list_audit("direct").unwrap().is_empty(),
        "rejected instance must write no audit"
    );
    let ticket = issue("private_rest", "private", Some(&instance))
        .expect("instance manifest must admit its approved destination")
        .unwrap();
    let summary = store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    assert_eq!(summary.app_key, "private_rest");
    assert_eq!(
        store
            .connection("direct", "private")
            .unwrap()
            .unwrap()
            .instance_url,
        Some(instance.clone())
    );
    let error = issue("private_rest", "missing", None).unwrap_err();
    assert!(error
        .to_string()
        .contains("this provider requires instance_url"));
    assert!(store.connection("direct", "missing").unwrap().is_none());
}

#[test]
fn searxng_instance_manifest_storage_errors_never_become_no_instance() {
    let store = audit_store();
    store
        .inner
        .with_conn_fenced(|conn| conn.execute_batch("DROP TABLE app_manifests"))
        .unwrap();
    assert!(store.manifest_takes_instance_url("private_rest").is_err());
    let ceiling = Ceiling {
        risk: Risk::Read,
        action_selectors: vec!["search".into()],
    };
    assert!(store
        .issue_binding_ticket_audited_at_instance(
            "direct",
            "unreadable",
            "private_rest",
            NO_CREDENTIAL_REF_ROLE,
            &[],
            &ceiling,
            &|_| AuditRecord::ceremony(
                "direct",
                Some("private_rest"),
                Some("unreadable"),
                "issue_ticket",
                "read",
                None
            ),
            None
        )
        .is_err());
    assert!(store.connection("direct", "unreadable").unwrap().is_none());
}

#[test]
fn searxng_migration_57_is_additive_across_forward_rollback_and_forward_again() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "searxng-migration".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let inner = open_sqlite(&descriptor).unwrap();
    let boundary = MIGRATIONS.iter().position(|m| m.version == 57).unwrap();
    inner.migrate("plexus", &MIGRATIONS[..boundary]).unwrap();
    let old_insert = |inner: &SqliteStore, id: &str| {
        inner.with_conn_fenced(|conn| {
            conn.execute("INSERT INTO connections (principal,connection_id,app_key,status,created_at_ms,updated_at_ms) VALUES ('direct',?1,'public','pending',1,1)",[id])?;
            conn.execute("INSERT INTO binding_tickets (ticket_id,principal,connection_id,ref_role,expires_at,status,created_at_ms,risk_ceiling,action_selectors) VALUES (?1,'direct',?1,'none',?2,'issued',1,'read','[]')",(id,now_ms()+600_000))?;
            Ok(())
        }).unwrap();
    };
    old_insert(&inner, "before");
    assert_eq!(
        inner.migrate("plexus", MIGRATIONS).unwrap().applied,
        u32::try_from(MIGRATIONS.len() - boundary).unwrap()
    );
    let store = PlexusStore {
        inner,
        grant_journal: None,
        outbox_ready: tokio::sync::Notify::new(),
        orphan_sweep_after: Default::default(),
        ci_runs: Default::default(),
        manifest_cache: Default::default(),
    };
    instance_rule_manifest(&store, "searxng_rest", true);
    assert!(store
        .connection("direct", "before")
        .unwrap()
        .unwrap()
        .instance_url
        .is_none());
    assert!(
        store
            .connect_with_ticket("direct", "before")
            .unwrap()
            .is_some(),
        "a pre-migration ticket still connects without an address"
    );
    store
        .insert_connection(
            "direct",
            "sx",
            "searxng_rest",
            "pending",
            &serde_json::json!({}),
        )
        .unwrap();
    let address =
        crate::instance_url::InstanceUrl::parse("https://private-migration.invalid/base").unwrap();
    let ticket = store
        .create_binding_ticket_with_instance(
            "direct",
            "sx",
            NO_CREDENTIAL_REF_ROLE,
            &[],
            Some(&address),
        )
        .unwrap();
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    let rollback = store
        .inner
        .migrate("plexus", &MIGRATIONS[..boundary])
        .unwrap();
    assert!(rollback.store_ahead());
    let older_rows: Vec<(String, String)> = store
        .inner
        .with_read(|conn| {
            conn.prepare("SELECT connection_id,status FROM connections ORDER BY connection_id")?
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect()
        })
        .unwrap();
    assert_eq!(
        older_rows,
        vec![
            ("before".into(), "active".into()),
            ("sx".into(), "active".into())
        ]
    );
    old_insert(&store.inner, "rollback");
    assert_eq!(
        store.inner.migrate("plexus", MIGRATIONS).unwrap().applied,
        0
    );
    assert!(store
        .connect_with_ticket("direct", "rollback")
        .unwrap()
        .is_some());
    assert!(store
        .connection("direct", "rollback")
        .unwrap()
        .unwrap()
        .instance_url
        .is_none());
    assert_eq!(
        store
            .connection("direct", "sx")
            .unwrap()
            .unwrap()
            .instance_url,
        Some(address)
    );
}

fn reservation_store() -> PlexusStore {
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!(
            "reservation-retention-test-{}-{}",
            now_ms(),
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    PlexusStore::open(&descriptor).expect("open reservation retention store")
}

fn schema_table_names(connection: &Connection) -> rusqlite::Result<BTreeSet<String>> {
    let mut statement =
        connection.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    Ok(names)
}

fn grant_record(selectors: &[&str], expires_at: Option<i64>) -> GrantRecord {
    GrantRecord {
        grant_id: "grant-1".to_string(),
        principal: "direct".to_string(),
        connection_id: "conn-1".to_string(),
        grantee_principal: "direct".to_string(),
        risk_ceiling: "read".to_string(),
        action_selectors: selectors.iter().map(|s| s.to_string()).collect(),
        authority_kind: "poll".to_string(),
        expires_at,
        generation: 0,
        revoked_at_ms: None,
        revoked_by: None,
        state: grant_state(expires_at, None, now_ms()).to_string(),
    }
}

/// `authorizes` requires two independent things -- a deadline that has not
/// passed, and a selector list covering the requested action -- and each is
/// tested here with the other satisfied.
///
/// The predicate exists because callers were re-deriving it, and a
/// re-derivation that drops one condition is indistinguishable from a
/// correct check at the call site. Testing them independently is what makes
/// dropping either one visible: a suite that only ever varies both at once
/// passes against a predicate that checks the wrong one.
#[test]
fn a_grant_authorizes_only_a_named_action_before_its_deadline() {
    let far_future = now_ms() + 3_600_000;

    // Live and naming the action, so the grant is genuinely usable. Without
    // this vector the rest are satisfied by a predicate returning false.
    assert!(grant_record(&["read_feed"], Some(far_future)).authorizes("read_feed", now_ms()));
    // Mint expands wildcards to pin authority to named actions. Empty must
    // mean no authority, or it would bypass that expansion invariant.
    assert!(!grant_record(&[], Some(far_future)).authorizes("read_feed", now_ms()));
    assert!(grant_record(&["*"], Some(far_future)).authorizes("read_feed", now_ms()));
    // No deadline at all: unrestricted in time rather than expired.
    assert!(grant_record(&["read_feed"], None).authorizes("read_feed", now_ms()));

    // Live, but scoped to a different action. This is the case that made
    // any poll grant on a connection authorize a subscription to any other
    // action.
    assert!(!grant_record(&["read_other"], Some(far_future)).authorizes("read_feed", now_ms()));
    // Names the action, but its deadline has passed.
    assert!(!grant_record(&["read_feed"], Some(1)).authorizes("read_feed", now_ms()));
    // A deadline exactly at the current instant is spent, not live: the
    // boundary belongs to the expired side so a grant cannot be used during
    // the millisecond it lapses.
    let now = now_ms();
    assert!(!grant_record(&["read_feed"], Some(now)).authorizes("read_feed", now));
}

#[test]
fn an_empty_selector_grant_authorizes_nothing() {
    let grant = grant_record(&[], None);
    for action in ["read_feed", "*", "read_*"] {
        assert!(
            !grant.authorizes(action, now_ms()),
            "empty grant authorized {action}"
        );
    }
}

#[test]
fn a_selector_grant_authorizes_exactly_its_named_actions() {
    let grant = grant_record(&["read_feed", "read_other"], None);
    assert!(grant.authorizes("read_feed", now_ms()));
    assert!(grant.authorizes("read_other", now_ms()));
    assert!(!grant.authorizes("write_feed", now_ms()));
    assert!(!grant.authorizes("*", now_ms()));
}

#[test]
fn migration_41_adds_nullable_flow_columns_without_changing_rows() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "migration41".into(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let inner = open_sqlite(&descriptor).unwrap();
    assert_eq!(
        inner.migrate("plexus", &MIGRATIONS[..18]).unwrap().recorded,
        40
    );
    inner
        .with_conn_fenced(|conn| {
            conn.execute_batch(
        "INSERT INTO audit_journal (ts,principal,actor,acting_principal,decision,reason_code)
         VALUES (1,'direct','direct','direct','allow','old');
         INSERT INTO action_requests (request_id,principal,connection_id,action,args_snapshot,
            args_hash,schema_hash,requester,status,expires_at,created_at_ms)
         VALUES ('old','direct','c','a','{}','h','s','direct','pending',2,1);"
    )
        })
        .unwrap();
    let result = inner.migrate("plexus", MIGRATIONS).unwrap();
    assert_eq!(
        (result.applied, result.recorded),
        (
            MIGRATIONS.len() as u32 - 18,
            MIGRATIONS.last().unwrap().version
        )
    );
    inner
        .with_conn(|conn| {
            for table in ["audit_journal", "action_requests"] {
                let (count, flows): (i64, i64) = conn.query_row(
                    &format!("SELECT COUNT(*), COUNT(scope_flow_id) FROM {table}"),
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                assert_eq!((count, flows), (1, 0), "{table}");
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn a_generation_23_store_migrates_to_24_without_losing_other_tables() {
    assert_eq!(
        MIGRATIONS.len(),
        (MIGRATIONS.last().unwrap().version - MIGRATIONS[0].version + 1) as usize,
        "migration generations must remain contiguous"
    );
    assert_eq!(
        MIGRATIONS[0].version, 23,
        "the fresh-store schema remains generation 23"
    );
    assert_eq!(
        MIGRATIONS[1].version, 24,
        "the table removal belongs to generation 24"
    );

    let serial = TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let directory = Scratch::directory("schema-generation");
    let path = directory.join("store.db");
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("schema-generation-{serial}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    let store = open_sqlite(&descriptor).expect("open schema test store");
    let initial = store
        .migrate("plexus", &MIGRATIONS[..1])
        .expect("build store with the shipped generation 23 schema");
    assert_eq!(
        initial.recorded, 23,
        "fixture store must stop at generation 23"
    );

    let tables_before = store
        .with_conn(schema_table_names)
        .expect("read generation 23 tables");
    assert!(
        tables_before.contains("oauth_flows"),
        "generation 23 must reproduce the production shape"
    );

    let outcome = store
        .migrate("plexus", &MIGRATIONS[..2])
        .expect("migrate generation 23 store to 24");
    let tables_after = store
        .with_conn(schema_table_names)
        .expect("read generation 24 tables");

    let mut expected_tables = tables_before;
    assert!(expected_tables.remove("oauth_flows"));
    assert_eq!(
        tables_after, expected_tables,
        "migration 24 must preserve every table except oauth_flows"
    );
    assert_eq!(outcome.applied, 1, "only migration 24 should run");
    assert_eq!(outcome.recorded, 24, "store must record generation 24");
    assert_eq!(
        outcome.chain_max, 24,
        "the shipped chain ends at generation 24"
    );
    assert!(!outcome.store_ahead(), "generation 24 must be current");

    drop(store);
}

#[test]
fn migration_25_preserves_live_grants_and_records_only_future_revocations() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "revocation-migration-{}",
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let inner = open_sqlite(&descriptor).unwrap();
    assert_eq!(
        inner.migrate("plexus", &MIGRATIONS[..2]).unwrap().recorded,
        24
    );
    inner.with_conn_fenced(|conn| {
        conn.execute("INSERT INTO grants (grant_id, principal, connection_id, grantee_principal,
            risk_ceiling, action_selectors, authority_kind, expires_at, generation, created_at_ms)
            VALUES ('legacy', 'direct', 'connection', 'direct', 'read', '[\"read_action\"]', 'invoke', NULL, 7, 123)", [])?;
        Ok(())
    }).unwrap();
    let outcome = inner.migrate("plexus", &MIGRATIONS[..3]).unwrap();
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.recorded, 25);
    assert_eq!(
        inner.migrate("plexus", &MIGRATIONS[..3]).unwrap().applied,
        0
    );
    // Current grant queries require columns added by later migrations.
    inner.migrate("plexus", MIGRATIONS).unwrap();
    let store = PlexusStore {
        inner,
        grant_journal: None,
        outbox_ready: tokio::sync::Notify::new(),
        orphan_sweep_after: Default::default(),
        ci_runs: Default::default(),
        manifest_cache: Default::default(),
    };
    let live = store
        .matching_grant(
            "direct",
            "connection",
            "direct",
            "read_action",
            "invoke",
            now_ms(),
            None,
        )
        .unwrap()
        .unwrap();
    assert!(live.authorizes("read_action", now_ms()));
    assert_eq!(live.generation, 7);
    assert!(live.revoked_at_ms.is_none());
    assert!(live.revoked_by.is_none());
    assert_eq!(revocation_count(&store), 0);
    assert!(store.revoke_grant("direct", "legacy").unwrap());
    let listed = store.list_grants("direct", "connection").unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].state, "revoked");
    assert_eq!(listed[0].generation, 7);
    assert_eq!(listed[0].action_selectors, ["read_action"]);
    assert!(store
        .matching_grant(
            "direct",
            "connection",
            "direct",
            "read_action",
            "invoke",
            now_ms(),
            None,
        )
        .unwrap()
        .is_none());
}

#[test]
fn migration_26_narrows_only_the_audit_delete_trigger_and_preserves_rows() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "audit-retention-migration-{}",
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let store = open_sqlite(&descriptor).expect("open migration store");
    assert_eq!(
        store
            .migrate("plexus", &MIGRATIONS[..3])
            .expect("migrate through generation 25")
            .recorded,
        25
    );
    store
        .with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO audit_journal
                    (ts, principal, actor, acting_principal, decision, reason_code)
                 VALUES (1, 'old', 'plexus', 'old', 'allow', 'old'),
                        (2, 'recent', 'plexus', 'recent', 'allow', 'recent')",
                [],
            )?;
            Ok(())
        })
        .expect("seed pre-migration audit rows");

    let outcome = store
        .migrate("plexus", &MIGRATIONS[..4])
        .expect("apply audit retention migration");
    assert_eq!(outcome.applied, 1, "only generation 26 should run");
    assert_eq!(outcome.recorded, 26);
    store
        .with_conn(|conn| {
            let rows: i64 =
                conn.query_row("SELECT COUNT(*) FROM audit_journal", [], |row| row.get(0))?;
            assert_eq!(rows, 2, "the trigger migration must not prune by itself");

            let delete_trigger: String = conn.query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = 'trigger' AND name = 'audit_journal_append_only_delete'",
                [],
                |row| row.get(0),
            )?;
            assert!(
                delete_trigger.contains("WHEN OLD.ts >"),
                "the delete trigger must retain an age floor: {delete_trigger}"
            );
            let update_trigger: String = conn.query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = 'trigger' AND name = 'audit_journal_append_only_update'",
                [],
                |row| row.get(0),
            )?;
            assert!(
                !update_trigger.contains("WHEN"),
                "the update refusal must remain unconditional: {update_trigger}"
            );
            let index_exists: bool = conn.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'index' AND name = 'idx_audit_ts'
                )",
                [],
                |row| row.get(0),
            )?;
            assert!(
                index_exists,
                "bounded age pruning needs the timestamp index"
            );
            Ok(())
        })
        .expect("inspect generation 26 schema");
}

#[test]
fn migration_27_adds_only_the_terminal_reservation_index_and_preserves_rows() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "reservation-retention-migration-{}",
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let store = open_sqlite(&descriptor).expect("open migration store");
    assert_eq!(
        store
            .migrate("plexus", &MIGRATIONS[..4])
            .expect("migrate through generation 26")
            .recorded,
        26
    );
    store
        .with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO reservations
                    (reservation_id, principal, connection_id, action,
                     snapshot_generations, approved_args_hash, schema_hash,
                     expires_at, status, created_at_ms)
                 VALUES ('terminal', 'p', 'c', 'a', '{}', 'args', 'schema', 2,
                         'dispatched', 1),
                        ('active', 'p', 'c', 'a', '{}', 'args', 'schema', 2,
                         'reserved', 1)",
                [],
            )?;
            Ok(())
        })
        .expect("seed pre-migration reservations");

    let outcome = store
        .migrate("plexus", &MIGRATIONS[..5])
        .expect("apply reservation retention migration");
    assert_eq!(outcome.applied, 1, "only generation 27 should run");
    assert_eq!(outcome.recorded, 27);
    store
        .with_conn(|conn| {
            let rows: i64 =
                conn.query_row("SELECT COUNT(*) FROM reservations", [], |row| row.get(0))?;
            assert_eq!(rows, 2, "adding the index must not prune by itself");

            let index_sql: String = conn.query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = 'index' AND name = 'idx_reservations_terminal_created_at'",
                [],
                |row| row.get(0),
            )?;
            assert!(
                index_sql.contains("created_at_ms, principal, reservation_id")
                    && index_sql.contains("'invalidated', 'dispatched', 'expired'"),
                "the index must serve only terminal age selection: {index_sql}"
            );
            let reservation_triggers: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'trigger' AND tbl_name = 'reservations'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(
                reservation_triggers, 0,
                "reservation retention neither needs nor adds a trigger"
            );
            Ok(())
        })
        .expect("inspect generation 27 schema");
}

#[test]
fn migration_28_adds_reserved_lookup_without_changing_reservations() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "reserved-lookup-migration-{}",
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let store = open_sqlite(&descriptor).expect("open migration store");
    assert_eq!(
        store.migrate("plexus", &MIGRATIONS[..5]).unwrap().recorded,
        27
    );
    store
        .with_conn(|conn| {
            seed_reserved_invalidation_rows(conn);
            Ok(())
        })
        .unwrap();
    let outcome = store.migrate("plexus", &MIGRATIONS[..6]).unwrap();
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.recorded, 28);
    store
        .with_conn(|conn| {
            let counts: (i64, i64) = conn.query_row(
                "SELECT COUNT(*), SUM(status = 'reserved') FROM reservations",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(
                counts,
                (1007, 4),
                "an index migration must not invalidate or prune"
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(
        store.migrate("plexus", &MIGRATIONS[..6]).unwrap().applied,
        0
    );
    let latest = store.migrate("plexus", MIGRATIONS).unwrap();
    assert_eq!(
        (latest.applied, latest.recorded),
        (
            MIGRATIONS.len() as u32 - 6,
            MIGRATIONS.last().unwrap().version
        )
    );
    assert_eq!(store.migrate("plexus", MIGRATIONS).unwrap().applied, 0);
}

#[test]
fn migration_31_adds_the_actor_reason_and_old_rows_stay_readable() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "actor-reason-migration-{}",
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let inner = open_sqlite(&descriptor).unwrap();
    assert_eq!(
        inner.migrate("plexus", &MIGRATIONS[..8]).unwrap().recorded,
        30
    );
    // One actor-sourced issue watch and one release watch without an actor
    // source, each with an event written before the reason column existed.
    inner
        .with_conn_fenced(|conn| {
            conn.execute_batch(
                r#"INSERT INTO trigger_subscriptions
                    (subscription_id, principal, connection_id, action, cadence_s,
                     cursor_kind, schema_hash, status, created_at_ms, actor_source_json)
                 VALUES
                    ('issues', 'direct', 'c', 'list_issues', 30, 'sync_token', 'h',
                     'active', 1,
                     '{"connection_id":"a","action":"issue_read","methods":["get_comments"]}'),
                    ('releases', 'direct', 'c', 'get_latest_release', 30, 'sync_token',
                     'h', 'active', 1, NULL);
                 INSERT INTO trigger_events
                    (event_id, principal, connection_id, subscription_id, vendor_event_id,
                     payload_hash, payload, kind, observed_at_ms, created_at_ms,
                     item_kind, actor_logins)
                 VALUES
                    ('e-known', 'direct', 'c', 'issues', 'issue-1', 'h1', '{}', 'event',
                     1, 1, 'issue', '["alice"]'),
                    ('e-unknown', 'direct', 'c', 'issues', 'issue-2', 'h2', '{}', 'event',
                     1, 2, 'issue', NULL),
                    ('e-release', 'direct', 'c', 'releases', 'rel-1', 'h3', '{}', 'event',
                     1, 3, 'release', NULL);"#,
            )?;
            Ok(())
        })
        .unwrap();

    let outcome = inner.migrate("plexus", MIGRATIONS).unwrap();
    assert_eq!(
        (outcome.applied, outcome.recorded),
        (
            MIGRATIONS.len() as u32 - 8,
            MIGRATIONS.last().unwrap().version
        )
    );
    assert_eq!(inner.migrate("plexus", MIGRATIONS).unwrap().applied, 0);
    let store = PlexusStore {
        inner,
        grant_journal: None,
        outbox_ready: tokio::sync::Notify::new(),
        orphan_sweep_after: Default::default(),
        ci_runs: Default::default(),
        manifest_cache: Default::default(),
    };
    let served = store
        .list_events("direct", None, None)
        .unwrap()
        .into_iter()
        .map(|event| {
            (
                event.event_id.clone(),
                serde_json::to_value(&event).unwrap(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(served.len(), 3, "every pre-migration row stays readable");
    assert_eq!(
        served["e-known"]["actor_logins"],
        serde_json::json!(["alice"])
    );
    assert!(served["e-known"].get("actor_unknown").is_none());
    assert_eq!(
        served["e-unknown"]["actor_unknown"],
        serde_json::json!({"reason": "unrecorded", "class": "unexpected"})
    );
    assert!(served["e-unknown"].get("actor_logins").is_none());
    assert!(served["e-release"].get("actor_logins").is_none());
    assert!(served["e-release"].get("actor_unknown").is_none());
}

/// Generation 32 is additive: rows written before it read back with NULL
/// query columns, only the web_search writer sets them, the prior binary's
/// explicit-column INSERT still works on the migrated store, and the prior
/// chain opens the migrated store as "ahead" rather than failing.
#[test]
fn migration_32_adds_web_search_columns_and_limits_additively() {
    use crate::storage::web_search_store::WebSearchLimits;
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "web-search-migration-{}",
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let inner = open_sqlite(&descriptor).unwrap();
    assert_eq!(
        inner.migrate("plexus", &MIGRATIONS[..9]).unwrap().recorded,
        31
    );
    // The insert a generation-31 binary issues: it names its own columns.
    let prior_binary_insert = "INSERT INTO audit_journal
            (ts, principal, actor, acting_principal, decision, reason_code)
         VALUES (1, 'direct', 'direct', 'direct', 'allow', 'prior_binary')";
    inner
        .with_conn_fenced(|conn| conn.execute_batch(prior_binary_insert))
        .unwrap();

    let outcome = inner.migrate("plexus", MIGRATIONS).unwrap();
    assert_eq!(
        (outcome.applied, outcome.recorded),
        (
            MIGRATIONS.len() as u32 - 9,
            MIGRATIONS.last().unwrap().version
        )
    );
    let rolled_back = inner.migrate("plexus", &MIGRATIONS[..9]).unwrap();
    assert!(
        rolled_back.store_ahead(),
        "the prior chain must open the store as ahead, not fail"
    );
    assert_eq!(rolled_back.applied, 0);
    inner
        .with_conn_fenced(|conn| conn.execute_batch(prior_binary_insert))
        .unwrap();

    let store = PlexusStore {
        inner,
        grant_journal: None,
        outbox_ready: tokio::sync::Notify::new(),
        orphan_sweep_after: Default::default(),
        ci_runs: Default::default(),
        manifest_cache: Default::default(),
    };
    let record = AuditRecord::ceremony("direct", None, None, "test", "read", None);
    store.append_audit(&record).unwrap();
    store
        .append_web_search_audit(&record, Some("rust async"), Some(3), None, None)
        .unwrap();
    let columns: Vec<(String, Option<String>, Option<i64>)> = store
        .inner
        .with_conn(|conn| {
            let mut statement = conn.prepare(
                "SELECT reason_code, query_text, result_count
                 FROM audit_journal ORDER BY journal_id",
            )?;
            let rows =
                statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
            rows.collect()
        })
        .unwrap();
    assert_eq!(
        columns,
        vec![
            ("prior_binary".to_string(), None, None),
            ("prior_binary".to_string(), None, None),
            ("ceremony_test".to_string(), None, None),
            (
                "ceremony_test".to_string(),
                Some("rust async".to_string()),
                Some(3)
            ),
        ]
    );
    assert_eq!(store.list_audit("direct").unwrap().len(), 4);

    assert_eq!(store.web_search_limits("exa").unwrap(), None);
    let first = WebSearchLimits {
        per_caller_per_minute: 5,
        per_backend_per_minute: 50,
    };
    assert_eq!(store.set_web_search_limits("exa", first).unwrap(), None);
    let second = WebSearchLimits {
        per_caller_per_minute: 6,
        per_backend_per_minute: 60,
    };
    assert_eq!(
        store.set_web_search_limits("exa", second).unwrap(),
        Some(first)
    );
    assert_eq!(store.web_search_limits("exa").unwrap(), Some(second));
}

/// Generation 35 is additive: rows a generation-34 binary writes (it names
/// its columns on INSERT) keep NULL scope columns before and after the
/// migration, the prior chain opens the migrated store as ahead, and a
/// scoped audit row and approval request read back with their scope.
#[test]
fn migration_35_adds_scope_columns_additively() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "scope-migration-{}",
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let inner = open_sqlite(&descriptor).unwrap();
    assert_eq!(
        inner.migrate("plexus", &MIGRATIONS[..12]).unwrap().recorded,
        34
    );
    // The inserts a generation-34 binary issues, naming their own columns.
    let prior_binary_inserts = "INSERT INTO audit_journal
            (ts, principal, actor, acting_principal, decision, reason_code)
         VALUES (1, 'direct', 'direct', 'direct', 'allow', 'prior_binary');
         INSERT INTO action_requests
            (request_id, principal, connection_id, action, args_snapshot, args_hash,
             schema_hash, requester, status, expires_at, created_at_ms)
         VALUES ('req-prior-' || (SELECT COUNT(*) FROM action_requests), 'direct', 'c',
                 'a', '{}', 'h', 's', 'direct', 'pending', 9999999999999, 1);
         INSERT INTO reservations
            (reservation_id, principal, connection_id, action, snapshot_generations,
             approved_args_hash, schema_hash, expires_at, status, created_at_ms, grant_id,
             approval_request_id)
         VALUES ('res-prior-' || (SELECT COUNT(*) FROM reservations), 'direct', 'c', 'a',
                 '{}', 'h', 's', 2, 'dispatched', 1, 'g', NULL);";
    inner
        .with_conn_fenced(|conn| conn.execute_batch(prior_binary_inserts))
        .unwrap();

    let outcome = inner.migrate("plexus", MIGRATIONS).unwrap();
    assert_eq!(
        (outcome.applied, outcome.recorded),
        (
            MIGRATIONS.len() as u32 - 12,
            MIGRATIONS.last().unwrap().version
        )
    );
    let rolled_back = inner.migrate("plexus", &MIGRATIONS[..12]).unwrap();
    assert!(
        rolled_back.store_ahead(),
        "the prior chain must open the store as ahead, not fail"
    );
    assert_eq!(rolled_back.applied, 0);
    inner
        .with_conn_fenced(|conn| conn.execute_batch(prior_binary_inserts))
        .unwrap();

    let store = PlexusStore {
        inner,
        grant_journal: None,
        outbox_ready: tokio::sync::Notify::new(),
        orphan_sweep_after: Default::default(),
        ci_runs: Default::default(),
        manifest_cache: Default::default(),
    };
    let scope = CallScope {
        owner: "reserved:prefrontal".into(),
        scope_ref: "head-1".into(),
        scope_epoch: u64::MAX,
        kind: Some("head".into()),
        parent: Some("reserved:prefrontal/root@1".into()),
        parent_state: Some("linked".into()),
        agent_id: Some("agent-a".into()),
        delegates: true,
        owner_authorized: true,
        flow_id: Some("flow-storage".into()),
    };
    let mut record = AuditRecord::ceremony("direct", None, None, "test", "read", None);
    record.agent_id = Some("agent-a".into());
    store.append_audit_scoped(&record, Some(&scope)).unwrap();
    let scopes: Vec<(String, Option<CallScope>)> = store
        .list_audit("direct")
        .unwrap()
        .into_iter()
        .map(|row| (row.reason_code, row.scope))
        .collect();
    assert_eq!(
        scopes,
        vec![
            ("prior_binary".to_string(), None),
            ("prior_binary".to_string(), None),
            ("ceremony_test".to_string(), Some(scope.clone())),
        ],
        "the largest epoch survives the round trip through a signed column"
    );

    let request_id = store
        .create_action_request(
            "direct",
            "c",
            "a",
            &serde_json::json!({}),
            "s",
            "reserved:aft",
            now_ms() + 60_000,
            Some(&scope),
            None,
        )
        .unwrap();
    let requests = store.list_action_requests("direct").unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[..2]
        .iter()
        .all(|request| request.scope.is_none() && request.scope_outcome.is_none()));
    let scoped = store
        .action_request("direct", &request_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        scoped.scope,
        Some(RequestScope::from_call_scope(&scope)),
        "the request keeps the scope it was raised under"
    );
}

/// Generation 36 rebuilds `action_requests` to accept `cancelled` and
/// adds `call_key` and `claimed_request_id`. Every row a generation-35
/// binary wrote survives unchanged with NULL in the new columns, the prior
/// chain opens the migrated store as ahead and keeps inserting, and a key
/// is unique per carrier (`requester`) only.
#[test]
fn migration_36_keeps_every_request_and_keys_calls_per_carrier() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "call-key-migration-{}",
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let inner = open_sqlite(&descriptor).unwrap();
    assert_eq!(
        inner.migrate("plexus", &MIGRATIONS[..13]).unwrap().recorded,
        35
    );
    // The insert a generation-35 binary issues, naming its own columns.
    let prior_binary_insert = "INSERT INTO action_requests
            (request_id, principal, connection_id, action, args_snapshot, args_hash,
             schema_hash, requester, status, expires_at, created_at_ms, agent_id,
             scope_owner, scope_ref, scope_epoch, scope_delegates,
             scope_owner_authorized, scope_outcome)
         VALUES ('req-prior-' || (SELECT COUNT(*) FROM action_requests), 'direct', 'c',
                 'a', '{}', 'h', 's', 'reserved:aft', 'consumed', 5, 1, 'agent-a',
                 'reserved:prefrontal-core', 'head-1', 3, 1, 1, 'not_run:scope_ended')";
    let columns = "SELECT request_id, principal, connection_id, action, args_snapshot,
            args_hash, schema_hash, requester, status, expires_at, created_at_ms, agent_id,
            scope_owner, scope_ref, scope_epoch, scope_delegates, scope_owner_authorized,
            scope_outcome, call_key, claimed_request_id
         FROM action_requests ORDER BY request_id";
    let read = |inner: &SqliteStore| -> Vec<Vec<rusqlite::types::Value>> {
        inner
            .with_conn(|conn| {
                let mut statement = conn.prepare(columns)?;
                let rows =
                    statement.query_map([], |row| (0..20).map(|index| row.get(index)).collect())?;
                rows.collect()
            })
            .unwrap()
    };
    inner
        .with_conn_fenced(|conn| conn.execute_batch(prior_binary_insert))
        .unwrap();
    let before = inner
        .with_conn(|conn| {
            let mut statement =
                conn.prepare(&columns.replace(", call_key, claimed_request_id", ""))?;
            let rows =
                statement.query_map([], |row| (0..18).map(|index| row.get(index)).collect())?;
            rows.collect::<Result<Vec<Vec<rusqlite::types::Value>>, _>>()
        })
        .unwrap();

    let outcome = inner.migrate("plexus", &MIGRATIONS[..14]).unwrap();
    assert_eq!((outcome.applied, outcome.recorded), (1, 36));
    let after = read(&inner);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0][..18], before[0][..], "the row is copied unchanged");
    assert_eq!(
        after[0][18..],
        [rusqlite::types::Value::Null, rusqlite::types::Value::Null],
        "a request raised before keys has none"
    );

    let rolled_back = inner.migrate("plexus", &MIGRATIONS[..13]).unwrap();
    assert!(
        rolled_back.store_ahead(),
        "the prior chain must open the store as ahead, not fail"
    );
    inner
        .with_conn_fenced(|conn| conn.execute_batch(prior_binary_insert))
        .unwrap();
    assert_eq!(read(&inner).len(), 2);

    let insert_keyed = |request_id: &str, requester: &str, call_key: Option<&str>| {
        inner.with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO action_requests
                    (request_id, principal, connection_id, action, args_snapshot,
                     schema_hash, requester, status, expires_at, created_at_ms, call_key)
                 VALUES (?1, 'direct', 'c', 'a', '{}', 's', ?2, 'cancelled', 5, 1, ?3)",
                rusqlite::params![request_id, requester, call_key],
            )
        })
    };
    insert_keyed("req-aft", "reserved:aft", Some("call-0"))
        .expect("cancelled is a valid status and a first key is accepted");
    insert_keyed("req-broca", "reserved:broca", Some("call-0"))
        .expect("another carrier may use the same key");
    insert_keyed("req-aft-again", "reserved:aft", Some("call-0"))
        .expect_err("one carrier cannot hold two requests under one key");
    insert_keyed("req-unkeyed-1", "reserved:aft", None).expect("unkeyed");
    insert_keyed("req-unkeyed-2", "reserved:aft", None)
        .expect("requests without a key are not constrained");
}

/// Generation 37 adds `settled_outcome` to `action_requests`. A row a
/// generation-36 binary wrote keeps every value with NULL in the new
/// column, and the prior chain opens the migrated store as ahead and keeps
/// inserting.
#[test]
fn migration_37_adds_a_settled_outcome_without_touching_existing_requests() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "settled-outcome-migration-{}",
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let inner = open_sqlite(&descriptor).unwrap();
    assert_eq!(
        inner.migrate("plexus", &MIGRATIONS[..14]).unwrap().recorded,
        36
    );
    // The insert a generation-36 binary issues, naming its own columns.
    let prior_binary_insert = "INSERT INTO action_requests
            (request_id, principal, connection_id, action, args_snapshot, args_hash,
             schema_hash, requester, status, expires_at, created_at_ms, agent_id,
             call_key, claimed_request_id)
         VALUES ('req-prior-' || (SELECT COUNT(*) FROM action_requests), 'direct', 'c',
                 'a', '{}', 'h', 's', 'reserved:aft', 'consumed', 5, 1, 'agent-a',
                 'key-' || (SELECT COUNT(*) FROM action_requests), 'attempt-1')";
    let columns = "SELECT request_id, principal, connection_id, action, args_snapshot,
            args_hash, schema_hash, requester, status, expires_at, created_at_ms, agent_id,
            call_key, claimed_request_id, settled_outcome
         FROM action_requests ORDER BY request_id";
    let read = |inner: &SqliteStore, width: usize| -> Vec<Vec<rusqlite::types::Value>> {
        inner
            .with_conn(|conn| {
                let sql = if width == 15 {
                    columns.to_string()
                } else {
                    columns.replace(", settled_outcome", "")
                };
                let mut statement = conn.prepare(&sql)?;
                let rows = statement
                    .query_map([], |row| (0..width).map(|index| row.get(index)).collect())?;
                rows.collect()
            })
            .unwrap()
    };
    inner
        .with_conn_fenced(|conn| conn.execute_batch(prior_binary_insert))
        .unwrap();
    let before = read(&inner, 14);

    let outcome = inner.migrate("plexus", &MIGRATIONS[..15]).unwrap();
    assert_eq!((outcome.applied, outcome.recorded), (1, 37));
    let after = read(&inner, 15);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0][..14], before[0][..], "the row is unchanged");
    assert_eq!(
        after[0][14],
        rusqlite::types::Value::Null,
        "a request settled before this generation has no settled outcome"
    );

    let rolled_back = inner.migrate("plexus", &MIGRATIONS[..14]).unwrap();
    assert!(
        rolled_back.store_ahead(),
        "the prior chain must open the store as ahead, not fail"
    );
    inner
        .with_conn_fenced(|conn| conn.execute_batch(prior_binary_insert))
        .unwrap();
    assert_eq!(read(&inner, 15).len(), 2);
}

/// Generation 38 adds the relayed-call origin columns to `audit_journal`
/// and `action_requests`. Rows a generation-37 binary wrote keep every
/// value with NULL origins, nothing about how a held request is keyed
/// changes, and the prior chain opens the migrated store as ahead and keeps
/// inserting.
#[test]
fn migration_38_adds_origin_columns_additively() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "relay-origin-migration-{}",
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let inner = open_sqlite(&descriptor).unwrap();
    assert_eq!(
        inner.migrate("plexus", &MIGRATIONS[..15]).unwrap().recorded,
        37
    );
    // The inserts a generation-37 binary issues, naming their own columns.
    let prior_binary_inserts = "INSERT INTO action_requests
            (request_id, principal, connection_id, action, args_snapshot, args_hash,
             schema_hash, requester, status, expires_at, created_at_ms, agent_id,
             call_key, settled_outcome)
         VALUES ('req-prior-' || (SELECT COUNT(*) FROM action_requests), 'direct', 'c',
                 'a', '{}', 'h', 's', 'reserved:aft', 'pending', 5, 1, 'agent-a',
                 'key-' || (SELECT COUNT(*) FROM action_requests), NULL);
         INSERT INTO audit_journal (ts, principal, actor, acting_principal, decision,
                 reason_code, scope_owner)
         VALUES (1, 'direct', 'reserved:aft', 'reserved:aft', 'allow', 'dispatched',
                 'reserved:prefrontal-core');";
    let read = |inner: &SqliteStore, with_origin: bool| -> Vec<Vec<rusqlite::types::Value>> {
        inner
            .with_conn(|conn| {
                let origin = if with_origin {
                    ", origin_carrier, origin_call_key"
                } else {
                    ""
                };
                let mut rows = Vec::new();
                for sql in [
                    format!(
                        "SELECT request_id, principal, requester, status, call_key,
                             settled_outcome{origin} FROM action_requests ORDER BY request_id"
                    ),
                    format!(
                        "SELECT journal_id, ts, principal, actor, decision, reason_code,
                             scope_owner{origin} FROM audit_journal ORDER BY journal_id"
                    ),
                ] {
                    let mut statement = conn.prepare(&sql)?;
                    let width = statement.column_count();
                    let read = statement
                        .query_map([], |row| (0..width).map(|index| row.get(index)).collect())?;
                    for row in read {
                        rows.push(row?);
                    }
                }
                Ok(rows)
            })
            .unwrap()
    };
    inner
        .with_conn_fenced(|conn| conn.execute_batch(prior_binary_inserts))
        .unwrap();
    let before = read(&inner, false);
    assert_eq!(before.len(), 2);

    // Migrate only through migration version 38: this test is about what
    // that one step does, and later versions are tested on their own.
    let outcome = inner.migrate("plexus", &MIGRATIONS[..16]).unwrap();
    assert_eq!((outcome.applied, outcome.recorded), (1, 38));
    let after = read(&inner, true);
    assert_eq!(after.len(), 2);
    for (after, before) in after.iter().zip(&before) {
        let width = before.len();
        assert_eq!(after[..width], before[..], "the row is unchanged");
        assert_eq!(
            after[width..],
            [rusqlite::types::Value::Null, rusqlite::types::Value::Null],
            "a row written before this generation states no origin"
        );
    }
    // The only call-key index is still the one on (requester, call_key):
    // nothing indexes, and so nothing can key on, an origin column.
    let indexed: Vec<String> = inner
        .with_conn(|conn| {
            let mut statement = conn.prepare(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL
                   AND tbl_name IN ('action_requests', 'audit_journal')",
            )?;
            let rows = statement.query_map([], |row| row.get(0))?;
            rows.collect()
        })
        .unwrap();
    assert!(
        indexed.iter().all(|sql| !sql.contains("origin_")),
        "{indexed:?}"
    );

    let rolled_back = inner.migrate("plexus", &MIGRATIONS[..15]).unwrap();
    assert!(
        rolled_back.store_ahead(),
        "the prior chain must open the store as ahead, not fail"
    );
    inner
        .with_conn_fenced(|conn| conn.execute_batch(prior_binary_inserts))
        .unwrap();
    assert_eq!(read(&inner, true).len(), 4);
}

/// Migration version 39 adds `action_requests.elicitation_id` and the
/// one-row `elicitation_answers_cursor` table. Requests written by a
/// binary whose migration chain ends at 38 keep every value and have no
/// `elicitation_id`, and the cursor table starts empty. Such a binary still opens
/// the migrated store (reporting the store as ahead of its own chain rather
/// than failing) and keeps inserting requests.
#[test]
fn migration_39_adds_the_consent_card_column_and_cursor_additively() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "consent-card-migration-{}",
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let inner = open_sqlite(&descriptor).unwrap();
    assert_eq!(
        inner.migrate("plexus", &MIGRATIONS[..16]).unwrap().recorded,
        38
    );
    // The insert a binary whose migration chain ends at 38 issues, naming
    // its own columns.
    let prior_binary_insert = "INSERT INTO action_requests
            (request_id, principal, connection_id, action, args_snapshot, args_hash,
             schema_hash, requester, status, expires_at, created_at_ms, agent_id,
              call_key, origin_carrier, origin_call_key)
          VALUES ('req-prior-' || (SELECT COUNT(*) FROM action_requests), 'direct', 'c',
                 'a', '{}', 'h', 's', 'reserved:aft', 'pending', 5, 1, 'agent-a',
                 'key-' || (SELECT COUNT(*) FROM action_requests), NULL, NULL);";
    let read = |inner: &SqliteStore, with_card: bool| -> Vec<Vec<rusqlite::types::Value>> {
        inner
            .with_conn(|conn| {
                let card = if with_card { ", elicitation_id" } else { "" };
                let mut statement = conn.prepare(&format!(
                    "SELECT request_id, principal, requester, status, call_key,
                         origin_carrier{card} FROM action_requests ORDER BY request_id"
                ))?;
                let width = statement.column_count();
                let rows = statement
                    .query_map([], |row| (0..width).map(|index| row.get(index)).collect())?;
                rows.collect()
            })
            .unwrap()
    };
    inner
        .with_conn_fenced(|conn| conn.execute_batch(prior_binary_insert))
        .unwrap();
    let before = read(&inner, false);
    assert_eq!(before.len(), 1);

    let outcome = inner.migrate("plexus", MIGRATIONS).unwrap();
    assert_eq!(
        (outcome.applied, outcome.recorded),
        (
            MIGRATIONS.len() as u32 - 16,
            MIGRATIONS.last().unwrap().version
        )
    );
    let after = read(&inner, true);
    assert_eq!(after.len(), 1);
    let width = before[0].len();
    assert_eq!(after[0][..width], before[0][..], "the row is unchanged");
    assert_eq!(
        after[0][width],
        rusqlite::types::Value::Null,
        "a request written before this generation has no card"
    );
    let cursor_rows: i64 = inner
        .with_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM elicitation_answers_cursor",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(cursor_rows, 0, "no answer has been read yet");
    // The table holds one row at most.
    let second_row = inner.with_conn_fenced(|conn| {
        conn.execute_batch(
            "INSERT INTO elicitation_answers_cursor VALUES (1, 0, 1);
             INSERT INTO elicitation_answers_cursor VALUES (2, 0, 1);",
        )
    });
    assert!(second_row.is_err(), "a second cursor row is refused");

    let rolled_back = inner.migrate("plexus", &MIGRATIONS[..16]).unwrap();
    assert!(
        rolled_back.store_ahead(),
        "the prior chain must open the store as ahead, not fail"
    );
    inner
        .with_conn_fenced(|conn| conn.execute_batch(prior_binary_insert))
        .unwrap();
    assert_eq!(read(&inner, true).len(), 2);
}

fn seed_reserved_invalidation_rows(conn: &Connection) {
    conn.execute_batch(
        "WITH RECURSIVE history(n) AS (
             SELECT 1 UNION ALL SELECT n + 1 FROM history WHERE n < 1000
         )
         INSERT INTO reservations
             (reservation_id, principal, connection_id, action, snapshot_generations,
              approved_args_hash, schema_hash, expires_at, status, created_at_ms)
         SELECT 'spent-' || n, 'direct', 'other-connection', 'other-action',
                '{}', 'args', 'schema', 2, 'dispatched', 1 FROM history;
         INSERT INTO reservations
             (reservation_id, principal, connection_id, action, snapshot_generations,
              approved_args_hash, schema_hash, expires_at, status, created_at_ms)
         VALUES ('matching', 'direct', 'c', 'a', '{}', 'args', 'schema', 2, 'reserved', 1),
                ('connection', 'direct', 'other', 'a', '{}', 'args', 'schema', 2, 'reserved', 1),
                ('action', 'direct', 'c', 'other', '{}', 'args', 'schema', 2, 'reserved', 1),
                ('principal', 'other', 'c', 'a', '{}', 'args', 'schema', 2, 'reserved', 1),
                ('dispatched', 'direct', 'c', 'a', '{}', 'args', 'schema', 2, 'dispatched', 1),
                ('expired', 'direct', 'c', 'a', '{}', 'args', 'schema', 2, 'expired', 1),
                ('invalidated', 'direct', 'c', 'a', '{}', 'args', 'schema', 2, 'invalidated', 1);",
    )
    .unwrap();
}

fn reservation_update_plan(conn: &Connection, predicate: &str) -> String {
    let mut statement = conn
        .prepare(&format!(
            "EXPLAIN QUERY PLAN UPDATE reservations SET status = 'invalidated' WHERE {predicate}"
        ))
        .unwrap();
    statement
        .query_map(["direct", "c", "a"], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .join("; ")
}

#[test]
fn reserved_invalidation_plan_uses_live_lookup_for_action_and_connection() {
    let conn = empty_schema();
    seed_reserved_invalidation_rows(&conn);
    let plan = reservation_update_plan(
        &conn,
        "principal = ?1 AND connection_id = ?2 AND action = ?3 AND status = 'reserved'",
    );
    assert!(plan.contains("USING INDEX idx_reservations_reserved_lookup (principal=? AND connection_id=? AND action=?)"), "action invalidation: {plan}");
    // Revocation omits the action filter; quarantine and repin use all three keys.
    let mut statement = conn
        .prepare(
            "EXPLAIN QUERY PLAN UPDATE reservations SET status = 'invalidated'
         WHERE principal = ?1 AND connection_id = ?2 AND status = 'reserved'",
        )
        .unwrap();
    let plan = statement
        .query_map(["direct", "c"], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .join("; ");
    assert!(
        plan.contains(
            "USING INDEX idx_reservations_reserved_lookup (principal=? AND connection_id=?)"
        ),
        "connection invalidation: {plan}"
    );
}

#[test]
fn reserved_invalidation_plan_excludes_terminal_history_from_lookup() {
    let conn = empty_schema();
    seed_reserved_invalidation_rows(&conn);
    // A full index can satisfy the live lookup too. This negative plan control
    // proves the lookup excludes spent rows rather than indexing all history.
    let plan = reservation_update_plan(
        &conn,
        "principal = ?1 AND connection_id = ?2 AND action = ?3 AND status = 'dispatched'",
    );
    assert!(
        !plan.contains("idx_reservations_reserved_lookup"),
        "terminal rows must not use the live-only lookup: {plan}"
    );
    assert!(
        plan.contains("sqlite_autoindex_reservations_1"),
        "terminal control: {plan}"
    );
}

#[test]
fn reserved_invalidation_refresh_preserves_nonmatching_and_terminal_rows() {
    let store = reservation_store();
    store
        .inner
        .with_conn(|conn| {
            seed_reserved_invalidation_rows(conn);
            Ok(())
        })
        .unwrap();
    let input = CatalogActionInput {
        principal: "direct".into(),
        connection_id: "c".into(),
        name: "a".into(),
        title: None,
        schema: serde_json::json!({"type": "object"}),
        schema_hash: "schema".into(),
        risk: "read".into(),
        severity: "S1".into(),
        ask_first: false,
        status: "quarantined".into(),
        quarantine_reason: Some("review".into()),
        reconciliation: None,
    };
    store.refresh_catalog_action(input.clone()).unwrap();
    store.refresh_catalog_action(input).unwrap();
    store
        .inner
        .with_conn(|conn| {
            let mut statement = conn.prepare(
                "SELECT reservation_id, status FROM reservations ORDER BY reservation_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
            assert_eq!(rows.len(), 1007);
            for (id, status) in rows {
                let expected = match id.as_str() {
                    "matching" | "invalidated" => "invalidated",
                    "connection" | "action" | "principal" => "reserved",
                    "expired" => "expired",
                    _ => "dispatched",
                };
                assert_eq!(status, expected, "reservation {id}");
            }
            Ok(())
        })
        .unwrap();
}

/// Both catalog read paths must project identically so every field added
/// later is covered without anyone remembering to extend this test.
#[test]
fn both_catalog_reads_project_a_row_identically() {
    let serial = TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("projection-parity-{serial}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let store = PlexusStore::open(&descriptor).expect("open store");
    store
        .insert_connection(
            "direct",
            "connection",
            "app",
            "active",
            &serde_json::json!({"required": [], "write_enabling": []}),
        )
        .expect("connection");

    // Every nullable field populated: a row with `title` and
    // `reconciliation` absent would compare equal under a mapper that
    // dropped them, which is the vacuity this test has to avoid.
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "connection".to_string(),
            principal: "direct".to_string(),
            name: "parity_action".to_string(),
            title: Some("Parity Action".to_string()),
            schema: serde_json::json!({"type": "object"}),
            schema_hash: "sha256:parity".to_string(),
            risk: "write".to_string(),
            severity: "S3".to_string(),
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: Some(serde_json::json!({"class": "reversible"})),
            ask_first: true,
        })
        .expect("seed action");

    let listed = store
        .list_catalog_actions("direct", "connection")
        .expect("list actions")
        .into_iter()
        .find(|action| action.name == "parity_action")
        .expect("action present in the list projection");
    let fetched = store
        .catalog_action("direct", "connection", "parity_action")
        .expect("read action")
        .expect("action present in the single-row projection");

    assert_eq!(
        listed, fetched,
        "the two catalog reads disagree about the same row"
    );

    // Parity alone is only half the property, and the weaker half: a SHARED
    // mapper cannot disagree with itself, so once the duplication is gone
    // the equality above passes even if the mapper drops a column entirely.
    // Measured — a mapper returning `title: None` unconditionally left the
    // whole core suite green, because nothing anywhere asserted that column
    // survives a round trip.
    //
    // So this half checks the values against what was SEEDED. Together they
    // say what the test claims: the two projections agree, and they agree on
    // the truth rather than on the same mistake.
    assert_eq!(fetched.title.as_deref(), Some("Parity Action"));
    assert_eq!(fetched.schema_hash, "sha256:parity");
    assert_eq!(fetched.risk, "write");
    assert_eq!(fetched.severity, "S3");
    assert_eq!(fetched.status, "active");
    assert!(fetched.ask_first);
    assert_eq!(
        fetched.reconciliation,
        Some(serde_json::json!({"class": "reversible"})),
        "the reconciliation column must survive the projection"
    );
    assert_eq!(fetched.schema, serde_json::json!({"type": "object"}));
}

#[test]
fn catalog_action_with_no_stored_ask_first_fails_closed() {
    // Mutation under test: change the migration default to 0. A row with no
    // recorded ask-first value — any action reconciled before the column
    // existed — would then read as non-ask-first and proceed silently. The
    // default must fail closed: an unknown ask-first status asks, never
    // proceeds.
    let serial = TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("ask-first-closed-{serial}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let store = PlexusStore::open(&descriptor).expect("open store");
    store
        .insert_connection(
            "direct",
            "connection",
            "ghost_app",
            "active",
            &serde_json::json!({"required": [], "write_enabling": []}),
        )
        .expect("connection");

    // Simulate a row reconciled before the ask_first column existed: insert
    // without naming the column so it takes the schema default.
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO catalog_actions
                    (connection_id, principal, name, title, schema_json, schema_hash,
                     risk, severity, status, quarantine_reason, reconciliation_json,
                     first_seen_at_ms, last_seen_at_ms, generation)
                 VALUES ('connection','direct','ghost_read','ghost','{\"type\":\"object\"}',
                     'sha256:ghost','read','S1','active', NULL, NULL, 0, 0, 1)",
                [],
            )
        })
        .expect("raw insert without ask_first");

    // STATE: the missing value reads back as ask-first (fail-closed default).
    let row = store
        .catalog_action("direct", "connection", "ghost_read")
        .expect("read ghost")
        .expect("ghost row");
    assert!(
        row.ask_first,
        "a row with no stored ask-first must fail closed"
    );

    // STATE + behaviour: with no policy the unknown-status read asks rather
    // than proceeds, and the request row actually exists.
    store
        .insert_grant(&crate::GrantInput {
            grant_id: "ghost-grant".to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["ghost_read".to_string()],
            authority_kind: "invoke".to_string(),
            expires_at: None,
        })
        .expect("grant");
    let engine = crate::GovernanceEngine::new(
        std::sync::Arc::new(store),
        std::sync::Arc::new(crate::StubCredentialSource::default()),
        std::sync::Arc::new(crate::MockTransport::default()),
    );
    let Err(crate::Denial::ActionRequestCreated { request_id }) =
        engine.authorize(crate::AuthorizationRequest::new(
            "direct",
            "connection",
            "ghost_read",
            serde_json::json!({}),
        ))
    else {
        panic!("a row with no stored ask-first must ask first, not proceed");
    };
    assert!(engine
        .store()
        .list_action_requests("direct")
        .expect("requests")
        .iter()
        .any(|item| item.request_id == request_id && item.status == "pending"));
}

fn trigger_manifest() -> Value {
    serde_json::json!({
        "schema_version": 1,
        "key": "trigger_fixture",
        "name": "Trigger fixture",
        "description": "manifest used by trigger storage tests",
        "reuse_path": "deep_wrapper",
        "reuse_rationale": "test",
        "tier": "S2",
        "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
        "auth": {"mode": "none"},
        "credential_bindings": [],
        "resource_filters": {"required": [], "optional": [], "write_enabling": []},
        "actions_baseline": [
            {
                "name": "read_action",
                "risk": "read",
                "poll": {
                    "item_kind": "issue",
                    "cursor_kind": "ordered_timestamp",
                    "item_kind": "issue",
                    "timestamp_field": "updated_at",
                    "tiebreaker_id_field": "id",
                    "request_constants": {"orderBy": "UPDATED_AT"}
                }
            },
            {
                "name": "write_action",
                "risk": "write"
            }
        ],
        "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 60}},
        "availability": "ga"
    })
}

/// The store file is owner-only on disk after open, including when it
/// already exists with a permissive mode.
///
/// The hardening itself lives in `cortexkit-store`, which owns the file's
/// lifecycle and applies the same rule for every module. This test stays
/// here deliberately rather than being deleted with the local
/// implementation it replaced: plexus is the module whose store retains
/// VENDOR RESPONSE BODIES in `trigger_events`, so the property is one we
/// depend on rather than merely benefit from, and a consumer-side
/// assertion is what notices if the shared crate ever stops providing it.
///
/// Asserts the MODE ON DISK rather than that `open` returned Ok: the
/// property is a filesystem fact, and a hardening step that silently did
/// nothing would still return Ok. The pre-existing-file half is the case
/// that actually bites — every already-deployed store was created at 0644
/// by the umask, so correcting only at creation time would leave every
/// existing installation permissive forever.
///
/// Mutation-proved against the shared crate: removing the `protect_file`
/// loop from `open_sqlite` fails this test.
#[cfg(unix)]
#[test]
fn the_store_file_and_its_wal_are_owner_only_on_disk() {
    use std::os::unix::fs::PermissionsExt;

    let serial = TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let directory = Scratch::directory("perm");
    let path = directory.join("store.db");

    // Pre-create the database file world-readable, reproducing what the
    // umask produced for every store deployed before this hardening.
    std::fs::write(&path, b"").expect("pre-create store file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("set permissive mode");

    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("perm-{serial}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).expect("open store");

    let mode = std::fs::metadata(&path)
        .expect("stat store file")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "the store file stayed group/world readable at {mode:o}"
    );

    // Write something so the WAL exists, then confirm it is protected too:
    // recently committed rows live there before checkpointing, so a
    // permissive WAL exposes the NEWEST events while store.db looks correct.
    store
        .insert_connection(
            "direct",
            "connection",
            "mock",
            "pending",
            &serde_json::json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("insert connection");
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    if wal.exists() {
        let wal_mode = std::fs::metadata(&wal)
            .expect("stat wal")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            wal_mode, 0o600,
            "the WAL stayed group/world readable at {wal_mode:o}"
        );
    }

    drop(store);
}

/// Scheduler principals come from the state they can act on, not historical
/// evidence that such a principal once existed.
///
/// The subscription-only row is intentionally valid without a matching
/// connection because this query answers ownership, while later poll
/// validation decides whether the subscription can run. The audit-only row
/// proves that durable history cannot enlarge the scheduler's work set.
///
/// Mutation-proved: selecting principals from `audit_journal` instead makes
/// the audit-only principal appear and both authoritative owners disappear.
#[test]
fn poll_and_probe_principals_unions_authoritative_owners_and_excludes_audit_only_history() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO trigger_subscriptions
                    (subscription_id, principal, connection_id, action, cadence_s,
                     cursor_kind, cursor_state, fixed_args, schema_hash, status,
                     generation, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, 60, 'sync_token', '{}', '{}', ?5,
                         'active', 0, ?6)",
                rusqlite::params![
                    "subscription-only-row",
                    "subscription-only",
                    "absent-connection",
                    "read_action",
                    "subscription-only-schema",
                    now_ms(),
                ],
            )?;
            Ok(())
        })
        .expect("insert subscription-only owner");
    store
        .insert_connection(
            "connection-only",
            "connection-only-row",
            "unused-app",
            "pending",
            &serde_json::json!({}),
        )
        .expect("insert connection-only owner");
    store
        .append_audit(&AuditRecord::ceremony(
            "audit-only",
            Some("historical-app"),
            Some("historical-connection"),
            "historical_action",
            "read",
            None,
        ))
        .expect("append audit-only history");

    let principals = store
        .poll_and_probe_principals()
        .expect("poll and probe principals");

    assert!(
        principals.iter().any(|value| value == "subscription-only"),
        "a principal owning only a subscription must be scheduled: {principals:?}"
    );
    assert!(
        principals.iter().any(|value| value == "connection-only"),
        "a principal owning only a connection must be probed: {principals:?}"
    );
    assert!(
        !principals.iter().any(|value| value == "audit-only"),
        "audit history with no subscription or connection is not scheduler work: {principals:?}"
    );
}

fn trigger_store(authority_kind: &str) -> PlexusStore {
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!(
            "trigger-test-{}-{}",
            now_ms(),
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let store = PlexusStore::open(&descriptor).expect("open trigger store");
    store
        .insert_connection(
            "direct",
            "connection",
            "trigger_fixture",
            "active",
            &serde_json::json!({}),
        )
        .expect("insert connection");
    let manifest = crate::manifest::ingest_value(trigger_manifest()).expect("manifest");
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest)
        .expect("store manifest");
    for (name, risk) in [("read_action", "read"), ("write_action", "write")] {
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "connection".to_string(),
                principal: "direct".to_string(),
                name: name.to_string(),
                title: Some(name.to_string()),
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {"orderBy": {"type": "string"}}
                }),
                schema_hash: format!("hash-{name}"),
                risk: risk.to_string(),
                severity: "S2".to_string(),
                ask_first: matches!(risk, "write" | "destructive"),
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("catalog action");
    }
    store
        .insert_grant(&GrantInput {
            grant_id: format!("grant-{authority_kind}"),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "write".to_string(),
            action_selectors: vec!["*".to_string()],
            authority_kind: authority_kind.to_string(),
            expires_at: Some(now_ms() + 60_000),
        })
        .expect("grant");
    store
}

fn insert_grant_with_selectors_for_test(
    store: &PlexusStore,
    grant_id: &str,
    grantee: &str,
    selectors: &[&str],
    authority_kind: &str,
) {
    store
        .insert_grant(&GrantInput {
            grant_id: grant_id.to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: grantee.to_string(),
            risk_ceiling: "write".to_string(),
            action_selectors: selectors
                .iter()
                .map(|selector| (*selector).to_string())
                .collect(),
            authority_kind: authority_kind.to_string(),
            expires_at: Some(now_ms() + 60_000),
        })
        .expect("insert grant directly");
}

#[test]
fn revocation_records_the_grant_snapshot() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let before = now_ms();
    assert!(store.revoke_grant("direct", "grant-poll").unwrap());
    let after = now_ms();
    store
        .inner
        .with_conn(|conn| {
            let snapshot = conn.query_row(
                "SELECT grant_id, principal, connection_id, grantee_principal,
                    authority_kind, risk_ceiling, action_selectors, revoked_at_ms, revoked_by
             FROM grant_revocations",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, String>(8)?,
                    ))
                },
            )?;
            assert_eq!(snapshot.0, "grant-poll");
            assert_eq!(snapshot.1, "direct");
            assert_eq!(snapshot.2, "connection");
            assert_eq!(snapshot.3, "direct");
            assert_eq!(snapshot.4, "poll");
            assert_eq!(snapshot.5, "write");
            assert_eq!(snapshot.6, r#"["*"]"#);
            assert!((before..=after).contains(&snapshot.7));
            assert_eq!(snapshot.8, "direct");
            Ok(())
        })
        .unwrap();
    assert_eq!(revocation_count(&store), 1);
}

#[test]
fn retrying_revocation_does_not_duplicate_the_snapshot() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    assert!(store.revoke_grant("direct", "grant-poll").unwrap());
    let first = store.list_grants("direct", "connection").unwrap();
    assert!(!store.revoke_grant("direct", "grant-poll").unwrap());
    assert_eq!(revocation_count(&store), 1);
    assert_eq!(store.list_grants("direct", "connection").unwrap(), first);
}

fn revocation_count(store: &PlexusStore) -> i64 {
    store
        .inner
        .with_conn(|conn| {
            conn.query_row("SELECT count(*) FROM grant_revocations", [], |row| {
                row.get(0)
            })
        })
        .unwrap()
}

#[test]
fn revocation_removes_the_authority_row_for_older_binaries() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    assert!(store.revoke_grant("direct", "grant-poll").unwrap());
    let remaining: i64 = store
        .inner
        .with_conn(|conn| {
            conn.query_row(
        "SELECT count(*) FROM grants WHERE principal = 'direct' AND grant_id = 'grant-poll'",
        [], |row| row.get(0),
    )
        })
        .unwrap();
    assert_eq!(remaining, 0, "older binaries must see no authority row");
}

#[test]
fn revocation_delete_failure_rolls_back_the_snapshot() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    store
        .inner
        .with_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER fail_grant_delete BEFORE DELETE ON grants
         BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END;",
            )
        })
        .unwrap();
    assert!(store.revoke_grant("direct", "grant-poll").is_err());
    assert_eq!(
        revocation_count(&store),
        0,
        "a failed delete must roll back the preceding insert"
    );
    assert!(store
        .matching_grant(
            "direct",
            "connection",
            "direct",
            "read_action",
            "poll",
            now_ms(),
            None,
        )
        .unwrap()
        .unwrap()
        .authorizes("read_action", now_ms()));
    store
        .inner
        .with_conn(|conn| conn.execute_batch("DROP TRIGGER fail_grant_delete;"))
        .unwrap();
    assert!(store.revoke_grant("direct", "grant-poll").unwrap());
    assert_eq!(revocation_count(&store), 1);
}

#[test]
fn revocation_insert_failure_keeps_the_grant_live() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    store
        .inner
        .with_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER fail_revocation_insert BEFORE INSERT ON grant_revocations
         BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END;",
            )
        })
        .unwrap();
    assert!(store.revoke_grant("direct", "grant-poll").is_err());
    assert_eq!(revocation_count(&store), 0);
    assert!(store
        .matching_grant(
            "direct",
            "connection",
            "direct",
            "read_action",
            "poll",
            now_ms(),
            None,
        )
        .unwrap()
        .unwrap()
        .authorizes("read_action", now_ms()));
}

#[test]
fn revocation_snapshots_are_immutable_and_principal_scoped() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    assert!(!store.revoke_grant("other", "grant-poll").unwrap());
    assert_eq!(revocation_count(&store), 0);
    assert!(store.revoke_grant("direct", "grant-poll").unwrap());
    store
        .inner
        .with_conn(|conn| {
            assert!(conn
                .execute("UPDATE grant_revocations SET risk_ceiling = 'read'", [])
                .is_err());
            assert!(conn.execute("DELETE FROM grant_revocations", []).is_err());
            Ok(())
        })
        .unwrap();
    assert_eq!(revocation_count(&store), 1);
    assert!(store.list_grants("other", "connection").unwrap().is_empty());
    assert!(store.list_all_grants("other").unwrap().is_empty());
}

#[test]
fn grant_listings_distinguish_live_and_revoked_grants() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    store
        .insert_grant(&GrantInput {
            grant_id: "live-grant".into(),
            principal: "direct".into(),
            connection_id: "connection".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["read_action".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    store.revoke_grant("direct", "grant-poll").unwrap();
    let listed = store.list_grants("direct", "connection").unwrap();
    assert_eq!(listed.len(), 2);
    let revoked = listed
        .iter()
        .find(|grant| grant.grant_id == "grant-poll")
        .unwrap();
    assert_eq!(revoked.state, "revoked");
    assert!(revoked.revoked_at_ms.is_some());
    assert_eq!(revoked.revoked_by.as_deref(), Some("direct"));
    assert!(!revoked.authorizes("read_action", now_ms()));
    let live = listed
        .iter()
        .find(|grant| grant.grant_id == "live-grant")
        .unwrap();
    assert_eq!(live.state, "until_revoked");
    assert!(live.revoked_at_ms.is_none());
    assert!(live.authorizes("read_action", now_ms()));
    let summaries = store.list_all_grants("direct").unwrap();
    assert_eq!(summaries.len(), 2);
    let summary = summaries
        .iter()
        .find(|grant| grant.grant_id == "grant-poll")
        .unwrap();
    assert_eq!(summary.state, "revoked");
    assert_eq!(summary.revoked_at_ms, revoked.revoked_at_ms);
    assert_eq!(summary.revoked_by, revoked.revoked_by);
    assert_eq!(
        summaries
            .iter()
            .find(|grant| grant.grant_id == "live-grant")
            .unwrap()
            .state,
        "until_revoked"
    );
}

#[test]
fn revoked_grant_is_not_a_matching_grant_diagnostic_candidate() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    store.revoke_grant("direct", "grant-poll").unwrap();
    for action in ["read_action", "unrelated_action"] {
        assert!(store
            .matching_grant(
                "direct",
                "connection",
                "direct",
                action,
                "poll",
                now_ms(),
                None,
            )
            .unwrap()
            .is_none());
    }
}

#[test]
fn revoked_grant_refuses_subscribe() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    assert!(store
        .subscribe("direct", "connection", "read_action", 30)
        .unwrap()
        .is_ok());
    store.revoke_grant("direct", "grant-poll").unwrap();
    assert_eq!(
        store
            .subscribe("direct", "connection", "read_action", 30)
            .unwrap(),
        Err(SubscriptionRefusal::PollGrantRequired)
    );
}

#[test]
fn revoked_grant_refuses_connection_admin() {
    let store = trigger_store("connection_admin");
    assert!(store
        .has_connection_admin_grant("direct", "connection", "direct")
        .unwrap());
    store
        .revoke_grant("direct", "grant-connection_admin")
        .unwrap();
    assert!(!store
        .has_connection_admin_grant("direct", "connection", "direct")
        .unwrap());
}

#[test]
fn revoked_grant_refuses_events_consume() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = read_subscription(&store);
    store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &serde_json::json!({"value": "private"}),
            now_ms(),
        )
        .unwrap();
    store
        .insert_grant(&GrantInput {
            grant_id: "consume".into(),
            principal: "direct".into(),
            connection_id: "connection".into(),
            grantee_principal: "reader".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["read_action".into()],
            authority_kind: "events_consume".into(),
            expires_at: None,
        })
        .unwrap();
    assert_eq!(
        store
            .list_events_including_granted("reader", None, None, now_ms())
            .unwrap()
            .len(),
        1
    );
    store.revoke_grant("direct", "consume").unwrap();
    assert!(store
        .list_events_including_granted("reader", None, None, now_ms())
        .unwrap()
        .is_empty());
}

#[test]
fn revoked_grant_refuses_poll_connection_discovery() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    assert_eq!(store.poll_connections("direct", now_ms()).unwrap().len(), 1);
    store.revoke_grant("direct", "grant-poll").unwrap();
    assert!(store
        .poll_connections("direct", now_ms())
        .unwrap()
        .is_empty());
}

fn read_subscription(store: &PlexusStore) -> TriggerSubscription {
    store
        .subscribe("direct", "connection", "read_action", 60)
        .expect("subscribe call")
        .expect("read action is subscribable")
}

#[test]
fn catalog_seed_skips_the_action_whose_schema_hash_fails() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    store
        .insert_connection(
            "direct",
            "seed-connection",
            "trigger_fixture",
            "active",
            &serde_json::json!({}),
        )
        .expect("insert seed connection");

    let inserted = crate::jcs::with_sha256_failure_on_call(0, || {
        store.seed_catalog_from_manifest("direct", "seed-connection", "trigger_fixture")
    })
    .expect("seed returns normally after refusing one action");

    assert_eq!(inserted, 1, "the second classifiable action still seeds");
    assert!(
        store
            .catalog_action("direct", "seed-connection", "read_action")
            .expect("query refused action")
            .is_none(),
        "the action whose schema cannot be pinned must not be seeded"
    );
}

#[test]
fn probe_registration_returns_a_store_error_when_its_schema_hash_fails() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let actions = vec!["read_action".to_string()];
    let fixed_args = serde_json::json!({});
    let cursor_state = serde_json::json!({});
    let return_schema = serde_json::json!({"kind": "bool"});

    let result = crate::jcs::with_sha256_failure_on_call(0, || {
        store.register_probe(
            "direct",
            "connection",
            ProbeRegistration {
                name: "watch",
                actions: &actions,
                script_source: "() => true",
                return_schema: &return_schema,
                rearm: "always",
                cadence_s: 30,
                fixed_args: &fixed_args,
                cursor_state: &cursor_state,
            },
        )
    });

    assert!(
        result.is_err(),
        "registration must return the store failure"
    );
    assert!(
        store
            .list_subscriptions("direct", Some("connection"), None)
            .expect("list subscriptions")
            .is_empty(),
        "a probe without a trustworthy return-schema pin must not be registered"
    );
}

#[test]
fn payload_hash_failures_abort_dedupe_and_poll_writes() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = read_subscription(&store);
    let payload = serde_json::json!({"id": 1});

    let unchanged = crate::jcs::with_sha256_failure_on_call(0, || {
        store.unchanged_event_payloads(
            "direct",
            &subscription.subscription_id,
            &[("vendor-1", &payload)],
        )
    });
    assert!(
        unchanged.is_err(),
        "dedupe lookup must return the hash failure"
    );

    let event = PollEventInput {
        vendor_event_id: "vendor-1",
        payload: &payload,
        observed_at_ms: 100,
        item_kind: Some("issue"),
        activity_at_ms: Some(100),
        actor: &ActorAttribution::NotEnriched,
    };
    let committed = crate::jcs::with_sha256_failure_on_call(0, || {
        store.commit_poll_success(
            "direct",
            "connection",
            &subscription.subscription_id,
            &serde_json::json!({"cursor": 1}),
            &[event],
            100,
            None,
        )
    });
    assert!(
        committed.is_err(),
        "poll write must return the hash failure"
    );
    assert!(
        store
            .list_events("direct", None, Some(&subscription.subscription_id))
            .expect("list events")
            .is_empty(),
        "a failed payload hash must roll back both event and cursor writes"
    );
}

#[test]
fn gap_hash_failures_abort_direct_and_transactional_gap_writes() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = read_subscription(&store);

    let direct = crate::jcs::with_sha256_failure_on_call(0, || {
        store.insert_gap_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            1,
            2,
            "test_gap",
            2,
        )
    });
    assert!(
        direct.is_err(),
        "direct gap write must return the hash failure"
    );

    let suspended = crate::jcs::with_sha256_failure_on_call(0, || {
        store.suspend("direct", &subscription.subscription_id, "test_suspend")
    });
    assert!(
        suspended.is_err(),
        "transactional gap write must return the hash failure"
    );
    assert_eq!(
        store
            .subscription("direct", &subscription.subscription_id)
            .expect("query subscription")
            .expect("subscription exists")
            .status,
        "active",
        "the suspension must roll back when its gap payload cannot be hashed"
    );
}

#[test]
fn action_request_hash_failures_abort_create_and_reuse_writes() {
    let store = trigger_store(crate::governance::AUTHORITY_INVOKE);
    let args = serde_json::json!({"team": "core"});

    let created = crate::jcs::with_sha256_failure_on_call(0, || {
        store.create_action_request(
            "direct",
            "connection",
            "write_action",
            &args,
            "sha256:schema",
            "direct",
            now_ms() + 60_000,
            None,
            None,
        )
    });
    assert!(created.is_err(), "create must return the hash failure");

    let reused = crate::jcs::with_sha256_failure_on_call(0, || {
        store.ensure_action_request(
            "direct",
            "connection",
            "write_action",
            &args,
            "sha256:schema",
            "direct",
            now_ms() + 60_000,
            None,
            None,
        )
    });
    assert!(reused.is_err(), "reuse lookup must return the hash failure");
    assert!(
        store
            .list_action_requests("direct")
            .expect("list action requests")
            .is_empty(),
        "no action request may be stored without its argument pin"
    );
}

/// A misspelled required key is reported as the undeclared key the caller
/// typed, not as the required key it left missing, and a whole number
/// written as `5.0` is an integer, as JSON Schema counts it.
#[test]
fn fixed_args_name_the_typo_and_accept_whole_number_floats_as_integers() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            "per_page": {"type": "integer"}
        },
        "required": ["owner", "repo"]
    });
    let none = BTreeSet::new();
    let check = |args: Value| validate_fixed_args(&args, &schema, &none);
    assert!(matches!(
        check(serde_json::json!({"owner": "o", "rpeo": "r"})),
        Err(SubscriptionRefusal::FixedArgNotDeclared(ref key)) if key == "rpeo"
    ));
    assert!(matches!(
        check(serde_json::json!({"owner": "o"})),
        Err(SubscriptionRefusal::FixedArgRequiredMissing(ref key)) if key == "repo"
    ));
    assert!(
        check(serde_json::json!({"owner": "o", "repo": "r", "per_page": 5.0})).is_ok(),
        "a whole-number float must count as an integer"
    );
    assert!(check(serde_json::json!({"owner": "o", "repo": "r", "per_page": 5})).is_ok());
    assert!(matches!(
        check(serde_json::json!({"owner": "o", "repo": "r", "per_page": 5.5})),
        Err(SubscriptionRefusal::FixedArgTypeMismatch { .. })
    ));
}

/// The retired-app predicate names the catalog principal by value, since it
/// is spliced into SQL text; it must stay the same value.
#[test]
fn the_retired_app_predicate_names_the_catalog_principal() {
    assert!(APP_RETIRED_PREDICATE.contains(&format!("principal = '{CATALOG_PRINCIPAL}'")));
}

fn set_race_hook(point: &'static str, hook: impl FnOnce() + 'static) {
    RACE_HOOK.with(|slot| *slot.borrow_mut() = Some((point, Box::new(hook))));
}

fn subscription_rows(store: &PlexusStore) -> i64 {
    store
        .inner
        .with_conn(|conn| {
            conn.query_row("SELECT COUNT(*) FROM trigger_subscriptions", [], |row| {
                row.get(0)
            })
        })
        .unwrap()
}

/// A quarantine, a revoked connection or a revoked grant that lands after
/// a subscription's checks but before its insert must still stop it: the
/// insert's own transaction checks those facts again.
#[test]
fn a_subscription_rechecks_its_authority_inside_the_insert_transaction() {
    type Change = fn(&PlexusStore);
    let cases: [(&str, Change); 3] = [
        ("connection revoked", |store| {
            store.revoke_connection("direct", "connection").unwrap();
        }),
        ("action quarantined", |store| {
            store
                .inner
                .with_conn_fenced(|conn| {
                    conn.execute(
                        "UPDATE catalog_actions SET status = 'quarantined',
                            quarantine_reason = 'risk_drift' WHERE name = 'read_action'",
                        [],
                    )
                })
                .unwrap();
        }),
        ("grant revoked", |store| {
            assert!(store.revoke_grant("direct", "grant-poll").unwrap());
        }),
    ];
    for (label, change) in cases {
        let store = std::sync::Arc::new(trigger_store(crate::governance::AUTHORITY_POLL));
        let racing = store.clone();
        set_race_hook("subscription_insert", move || change(&racing));
        let outcome = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("store call");
        assert!(outcome.is_err(), "{label}: subscribed anyway: {outcome:?}");
        assert_eq!(subscription_rows(&store), 0, "{label}");
    }
    // Positive control: with nothing racing, the same call subscribes.
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    assert!(store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("store call")
        .is_ok());
    assert_eq!(subscription_rows(&store), 1);
}

/// A blank delivery target clears the binding rather than storing "".
#[test]
fn a_blank_delivery_target_clears_the_binding() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .unwrap()
        .unwrap();
    let stored = |store: &PlexusStore| -> Option<String> {
        store
            .inner
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT deliver_to FROM trigger_subscriptions WHERE subscription_id = ?1",
                    [&subscription.subscription_id],
                    |row| row.get(0),
                )
            })
            .unwrap()
    };
    assert!(store
        .set_subscription_deliver_to("direct", &subscription.subscription_id, Some("agent-a"))
        .unwrap());
    assert_eq!(stored(&store).as_deref(), Some("agent-a"));
    for blank in ["", "   "] {
        assert!(store
            .set_subscription_deliver_to("direct", &subscription.subscription_id, Some(blank))
            .unwrap());
        assert_eq!(
            stored(&store),
            None,
            "a blank delivery target must clear the binding: {blank:?}"
        );
    }
}

/// A decline that arrives after the request's own deadline settles it as
/// expired; one that arrives in time settles it as denied.
#[test]
fn a_decline_after_the_deadline_settles_the_request_as_expired() {
    let store = trigger_store(crate::governance::AUTHORITY_INVOKE);
    let request = |args: Value, expires_at: i64| {
        store
            .create_action_request(
                "direct",
                "connection",
                "write_action",
                &args,
                "sha256:schema",
                "direct",
                expires_at,
                None,
                None,
            )
            .unwrap()
    };
    let lapsed = request(serde_json::json!({"n": 1}), now_ms() - 1);
    let live = request(serde_json::json!({"n": 2}), now_ms() + 60_000);
    let denied = |request_id: &str| ConsentSettlement::Denied {
        principal: "direct".into(),
        request_id: request_id.into(),
        decider: "operator".into(),
    };
    store
        .settle_consent_requests(&[denied(&lapsed), denied(&live)])
        .unwrap();
    let status = |request_id: &str| {
        store
            .list_action_requests("direct")
            .unwrap()
            .into_iter()
            .find(|row| row.request_id == request_id)
            .unwrap()
            .status
    };
    assert_eq!(
        status(&lapsed),
        "expired",
        "a decline after the deadline must settle as expired"
    );
    assert_eq!(status(&live), "denied");
}

/// An identical write that lands while another arrival of it is on its way
/// to the insert does not raise a second approval request: the lookup and
/// the insert share one transaction, so the later one finds the row.
#[test]
fn a_concurrent_identical_write_raises_one_action_request() {
    let store = std::sync::Arc::new(trigger_store(crate::governance::AUTHORITY_INVOKE));
    let ensure = |store: &PlexusStore| {
        store
            .ensure_action_request(
                "direct",
                "connection",
                "write_action",
                &serde_json::json!({"team": "core"}),
                "sha256:schema",
                "direct",
                now_ms() + 60_000,
                None,
                None,
            )
            .expect("ensure request")
    };
    let racing = store.clone();
    let raced = std::rc::Rc::new(std::cell::RefCell::new(None));
    let raced_slot = raced.clone();
    set_race_hook("action_request_insert", move || {
        *raced_slot.borrow_mut() = Some(ensure(&racing));
    });
    let id = ensure(&store);
    assert_eq!(
        raced.borrow().as_deref(),
        Some(id.as_str()),
        "both arrivals must share one request"
    );
    assert_eq!(
        store.list_action_requests("direct").expect("list").len(),
        1,
        "a concurrent identical write must not raise a second request"
    );
}

/// One policy per scope: a second row for the same scope is refused by the
/// schema, and `set_policy` updates the one row and reports the generation
/// it stored.
#[test]
fn one_policy_per_scope_and_set_policy_reports_the_stored_generation() {
    let store = trigger_store(crate::governance::AUTHORITY_INVOKE);
    let first = store
        .set_policy("direct", "connection", "write_action", "allow", None)
        .expect("create");
    let second = store
        .set_policy("direct", "connection", "write_action", "block", Some(42))
        .expect("update");
    assert_eq!(first.policy_id, second.policy_id);
    let stored = store
        .matching_policy("direct", "connection", "write_action", 0)
        .expect("read")
        .expect("policy");
    assert_eq!(stored, second);
    assert_eq!(
        (stored.effect.as_str(), stored.expires_at),
        ("block", Some(42))
    );
    assert!(
        store
            .insert_policy(&PolicyInput {
                policy_id: "duplicate".into(),
                principal: "direct".into(),
                connection_id: "connection".into(),
                action_selector: "write_action".into(),
                effect: "allow".into(),
                expires_at: None,
            })
            .is_err(),
        "a second policy for one scope must be refused"
    );
}

/// Migration 49 removes duplicate policies for the same principal,
/// connection, and action selector. Keep the row with the lowest policy ID
/// because existing writers and readers already selected that row.
#[test]
fn migration_49_resolves_duplicate_policies_to_the_governing_row() {
    let scratch = Scratch::database("policy-scope-migration");
    let inner = open_sqlite(&StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "policy-scope-migration".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.to_string_lossy().into_owned(),
        },
    })
    .expect("open");
    let boundary = MIGRATIONS.iter().position(|m| m.version == 49).unwrap();
    inner.migrate("plexus", &MIGRATIONS[..boundary]).unwrap();
    inner
        .with_conn_fenced(|conn| {
            conn.execute_batch(
                "INSERT INTO policies (policy_id, principal, connection_id, action_selector, effect, updated_at_ms)
                 VALUES ('policy_b', 'direct', 'c', 'send', 'block', 1),
                        ('policy_a', 'direct', 'c', 'send', 'allow', 1),
                        ('policy_c', 'direct', 'c', 'send', 'ask_first', 1),
                        ('policy_z', 'direct', 'c', 'read', 'allow', 1),
                        ('policy_y', 'other', 'c', 'send', 'block', 1);",
            )
        })
        .unwrap();
    let governing = |inner: &SqliteStore| {
        inner
            .with_conn(|conn| governing_policy(conn, "direct", "c", "send", 0))
            .unwrap()
            .unwrap()
            .policy_id
    };
    assert_eq!(governing(&inner), "policy_a");
    let outcome = inner.migrate("plexus", &MIGRATIONS[..=boundary]).unwrap();
    assert_eq!((outcome.applied, outcome.recorded), (1, 49));
    let ids: Vec<String> = inner
        .with_conn(|conn| {
            conn.prepare("SELECT policy_id FROM policies ORDER BY policy_id")?
                .query_map([], |row| row.get(0))?
                .collect()
        })
        .unwrap();
    assert_eq!(ids, vec!["policy_a", "policy_y", "policy_z"]);
    assert_eq!(governing(&inner), "policy_a", "the governing row survives");
    let again = inner.migrate("plexus", &MIGRATIONS[..=boundary]).unwrap();
    assert_eq!((again.applied, again.recorded), (0, 49));
}

/// The seed path is a backstop for stored manifest rows this binary's
/// typed ingestion never vouched for (written by an older or newer
/// schema generation). Its defensive arms must fail CLOSED: an action
/// whose risk is missing is not seeded at all (reconcile's quarantine is
/// the reviewed path for unclassified rows), and a manifest whose tier is
/// unreadable seeds its actions at S4 so execution requires an explicit
/// authorization verdict instead of bypassing that check at a lower tier.
/// MUTATIONS: restoring `unwrap_or("read")` on the risk arm reddens the
/// skip assertions; restoring `unwrap_or("S1")` on the tier arm reddens
/// the severity assertion.
#[test]
fn seeding_skips_unclassifiable_actions_and_gates_unknown_tiers() {
    let serial = TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("seed-backstop-{serial}"),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let store = PlexusStore::open(&descriptor).expect("open store");
    store
        .insert_connection(
            "direct",
            "connection",
            "trigger_fixture",
            "active",
            &serde_json::json!({}),
        )
        .expect("insert connection");

    // Ingest a fully valid manifest, then mutate the STORED JSON the way a
    // different binary generation would have written it: no tier, and one
    // action with no risk. The typed half stays valid, which is the point
    // - these arms are only reachable when stored JSON and this binary's
    // expectations have drifted apart.
    let mut ingested = crate::manifest::ingest_value(trigger_manifest()).expect("manifest");
    ingested
        .json
        .as_object_mut()
        .expect("manifest object")
        .remove("tier");
    ingested.json["actions_baseline"][0]
        .as_object_mut()
        .expect("action object")
        .remove("risk");
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &ingested)
        .expect("store manifest");

    let inserted = store
        .seed_catalog_from_manifest("direct", "connection", "trigger_fixture")
        .expect("seed");
    assert_eq!(inserted, 1, "only the classifiable action is seeded");
    assert!(
        store
            .catalog_action("direct", "connection", "read_action")
            .expect("query")
            .is_none(),
        "the riskless action must not be seeded at any risk class"
    );
    let seeded = store
        .catalog_action("direct", "connection", "write_action")
        .expect("query")
        .expect("write_action seeded");
    assert_eq!(
        seeded.severity, "S4",
        "an unreadable tier must gate at the strongest severity"
    );
}

/// Implemented cursor strategies must also be accepted by the SQL CHECK
/// constraint. The exhaustive shape helper forces a review when the enum
/// grows; the runtime list covers the strategies that ingest currently
/// admits. SnapshotDiff remains decodable for legacy rows, but new manifests
/// cannot declare it because no polling strategy implements it.
#[test]
fn every_implemented_cursor_kind_can_back_a_stored_subscription() {
    /// Keep this list aligned with the strategies accepted at ingest.
    const ALL: [CursorKind; 5] = [
        CursorKind::SyncToken,
        CursorKind::OrderedTimestamp,
        CursorKind::ScalarDiff,
        CursorKind::SortedHead,
        CursorKind::CiRuns,
    ];

    /// The minimum poll shape each kind's validation demands.
    ///
    /// EXHAUSTIVE ON PURPOSE, with no wildcard arm: a new variant must break
    /// this build. A `_ =>` here would restore the exact hole this test
    /// exists to close.
    fn poll_shape_for(kind: CursorKind) -> serde_json::Value {
        match kind {
            CursorKind::SyncToken => serde_json::json!({
                "cursor_kind": "sync_token",
                "item_kind": "issue",
                "token_field": "nextSyncToken",
                "request_token_field": "syncToken",
                "items_field": "items"
            }),
            CursorKind::OrderedTimestamp => serde_json::json!({
                "cursor_kind": "ordered_timestamp",
                "item_kind": "issue",
                "timestamp_field": "updated_at",
                "tiebreaker_id_field": "id",
                "items_field": "items",
                "request_since_field": "since",
                "request_constants": {}
            }),
            CursorKind::SnapshotDiff => serde_json::json!({
                "cursor_kind": "snapshot_diff",
                "item_kind": "issue",
                "items_field": "items",
                "item_count_ceiling": 100
            }),
            CursorKind::ScalarDiff => serde_json::json!({
                "cursor_kind": "scalar_diff",
                "item_kind": "issue",
                "scalar_field": "tag_name"
            }),
            CursorKind::SortedHead => serde_json::json!({
                "cursor_kind": "sorted_head",
                "item_kind": "pull_request",
                "timestamp_field": "updated_at",
                "tiebreaker_id_field": "number",
                "request_page_size_field": "perPage",
                "request_constants": {"sort": "updated", "direction": "desc", "perPage": 100}
            }),
            CursorKind::CiRuns => serde_json::json!({
                "cursor_kind": "ci_runs",
                "item_kind": "ci_run"
            }),
        }
    }

    let actions: Vec<serde_json::Value> = ALL
        .iter()
        .map(|kind| {
            serde_json::json!({
                "name": format!("read_{}", kind.as_str()),
                "risk": "read",
                "poll": poll_shape_for(*kind)
            })
        })
        .collect();

    let mut manifest_value = trigger_manifest();
    manifest_value["actions_baseline"] = serde_json::Value::Array(actions);
    let manifest = crate::manifest::ingest_value(manifest_value).expect("every shape must ingest");

    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest)
        .expect("store the manifest");

    for kind in ALL {
        let name = format!("read_{}", kind.as_str());
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "connection".to_string(),
                principal: "direct".to_string(),
                name: name.clone(),
                title: Some(name.clone()),
                schema: serde_json::json!({"type": "object", "properties": {}}),
                schema_hash: format!("hash-{name}"),
                risk: "read".to_string(),
                severity: "S2".to_string(),
                ask_first: false,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("catalog action");

        let outcome = store
            .subscribe("direct", "connection", &name, 300)
            .unwrap_or_else(|error| {
                panic!(
                    "cursor kind '{}' could not be stored -- the SQL constraint and the \
                     CursorKind enum have diverged: {error}",
                    kind.as_str()
                )
            });
        let subscription = outcome.unwrap_or_else(|refusal| {
            panic!(
                "cursor kind '{}' was refused by subscribe: {refusal:?}",
                kind.as_str()
            )
        });
        assert_eq!(
            subscription.cursor_kind,
            kind.as_str(),
            "the stored kind must be the declared one"
        );
    }
}

#[test]
fn invoke_grant_does_not_authorize_subscription_but_poll_grant_does() {
    let store = trigger_store(crate::governance::AUTHORITY_INVOKE);
    let refused = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe check");
    assert!(matches!(
        refused,
        Err(SubscriptionRefusal::PollGrantRequired)
    ));

    store
        .insert_grant(&GrantInput {
            grant_id: "grant-poll".to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["read_action".to_string()],
            authority_kind: crate::governance::AUTHORITY_POLL.to_string(),
            expires_at: Some(now_ms() + 60_000),
        })
        .expect("poll grant");
    assert!(store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .is_ok());
}

/// Direct insertion and imported legacy rows can still contain an empty
/// selector list. Such a row must not shadow a later grant that actually
/// names the action: wildcard expansion stores concrete actions precisely
/// so an implicit empty wildcard can never widen authority.
#[test]
fn an_empty_poll_grant_authorizes_no_subscription_and_cannot_shadow_a_matching_grant() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    assert!(store
        .revoke_grant("direct", "grant-poll")
        .expect("remove fixture grant"));
    insert_grant_with_selectors_for_test(
        &store,
        "grant-a-empty",
        "direct",
        &[],
        crate::governance::AUTHORITY_POLL,
    );

    assert!(matches!(
        store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("empty grant check"),
        Err(SubscriptionRefusal::PollGrantRequired)
    ));

    insert_grant_with_selectors_for_test(
        &store,
        "grant-z-matching",
        "direct",
        &["read_action"],
        crate::governance::AUTHORITY_POLL,
    );
    assert!(store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("matching grant check")
        .is_ok());
}

#[test]
fn an_empty_connection_admin_grant_authorizes_nothing_but_a_nonempty_grant_does() {
    let store = trigger_store("connection_admin");
    assert!(store
        .revoke_grant("direct", "grant-connection_admin")
        .expect("remove fixture grant"));
    insert_grant_with_selectors_for_test(
        &store,
        "grant-admin-empty",
        "direct",
        &[],
        "connection_admin",
    );
    assert!(!store
        .has_connection_admin_grant("direct", "connection", "direct")
        .expect("empty admin grant check"));

    insert_grant_with_selectors_for_test(
        &store,
        "grant-admin-matching",
        "direct",
        &["*"],
        "connection_admin",
    );
    assert!(store
        .has_connection_admin_grant("direct", "connection", "direct")
        .expect("nonempty admin grant check"));
}

#[test]
fn missing_cursor_shape_is_refused_at_subscribe() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let manifest = crate::manifest::ingest_value({
        let mut value = trigger_manifest();
        value["actions_baseline"][0]
            .as_object_mut()
            .expect("action object")
            .remove("poll");
        value
    })
    .expect("manifest without poll");
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest)
        .expect("update manifest");
    assert!(matches!(
        store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("cursor subscription check"),
        Err(SubscriptionRefusal::CursorShapeMissing)
    ));
}

/// Fixed arguments cannot reuse a manifest constant's name and override its
/// reviewed value. Refuse the collision before creating a subscription row.
#[test]
fn fixed_args_colliding_with_manifest_constants_are_refused_before_insert() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let before = store
        .list_subscriptions("direct", Some("connection"), None)
        .expect("list subscriptions before collision check");
    assert!(
        before.is_empty(),
        "collision fixture must start without a subscription row"
    );
    let refusal = store
        .subscribe_with_cursor_state(
            "direct",
            "connection",
            "read_action",
            30,
            &serde_json::json!({}),
            &serde_json::json!({"orderBy": "CREATED_AT"}),
        )
        .expect("collision subscription check")
        .expect_err("fixed_args must not override a manifest constant");
    assert_eq!(
        refusal,
        SubscriptionRefusal::FixedArgRequestConstant("orderBy".to_string())
    );
    let after = store
        .list_subscriptions("direct", Some("connection"), None)
        .expect("list subscriptions after collision check");
    assert!(
        after.is_empty(),
        "refused subscription must not create a row"
    );
}

#[test]
fn write_and_quarantined_actions_are_refused_at_subscribe() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    assert!(matches!(
        store
            .subscribe("direct", "connection", "write_action", 30)
            .expect("write subscription check"),
        Err(SubscriptionRefusal::ActionRiskNotRead)
    ));
    store
        .quarantine_action("direct", "connection", "read_action", "review_required")
        .expect("quarantine");
    assert!(matches!(
        store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("quarantined subscription check"),
        Err(SubscriptionRefusal::ActionUnavailable(_))
    ));
}

/// A vendor item edited under a stable id delivers each distinct payload once.
///
/// Mutation-proved: reverting the changed-payload path to write a gap leaves
/// only one event and fails the assertions for the edited payload below.
/// Re-pinning is intentionally more selective than `resume`: it clears only
/// the schema-drift suspension it reviewed and must never rewrite a poller's
/// cursor, which is the durable boundary between resuming coverage and
/// re-reading or skipping a vendor interval.
#[test]
fn repinning_a_reviewed_action_preserves_cursors_and_other_suspensions() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let cursor_state = serde_json::json!({"watermark_ms": 1_726_000_000_000_i64});
    let schema_changed = store
        .subscribe_with_cursor_state(
            "direct",
            "connection",
            "read_action",
            30,
            &cursor_state,
            &serde_json::json!({}),
        )
        .expect("subscribe")
        .expect("read action subscribes");
    let risk_drift = store
        .subscribe_with_cursor_state(
            "direct",
            "connection",
            "read_action",
            30,
            &cursor_state,
            &serde_json::json!({}),
        )
        .expect("subscribe")
        .expect("second read action subscribes");
    let cursor_before = |subscription_id: &str| {
        store
            .inner
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT cursor_state FROM trigger_subscriptions WHERE subscription_id = ?1",
                    [subscription_id],
                    |row| row.get::<_, String>(0),
                )
            })
            .expect("read raw cursor state")
    };
    let schema_cursor_before = cursor_before(&schema_changed.subscription_id);
    let risk_cursor_before = cursor_before(&risk_drift.subscription_id);

    let reviewed_schema = store
        .catalog_action("direct", "connection", "read_action")
        .expect("read action")
        .expect("action exists")
        .schema;
    store
        .refresh_catalog_action(CatalogActionInput {
            connection_id: "connection".to_string(),
            principal: "direct".to_string(),
            name: "read_action".to_string(),
            title: Some("read_action".to_string()),
            schema: serde_json::json!({
                "type": "object",
                "properties": {"orderBy": {"type": "string"}, "labels": {"type": "array"}}
            }),
            schema_hash: "hash-read-action-reviewed".to_string(),
            risk: "read".to_string(),
            severity: "S2".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("refresh changed schema");
    assert_eq!(
        store
            .subscription("direct", &schema_changed.subscription_id)
            .expect("read subscription")
            .expect("schema subscription exists")
            .suspended_reason
            .as_deref(),
        Some("schema_changed")
    );
    store
        .suspend("direct", &risk_drift.subscription_id, "risk_drift")
        .expect("suspend for risk drift");
    let generation_before = store
        .catalog_action("direct", "connection", "read_action")
        .expect("read quarantined action")
        .expect("action exists")
        .generation;

    let reactivated = store
        .repin_reviewed_action(
            "direct",
            "connection",
            "read_action",
            "hash-read-action-reviewed",
        )
        .expect("re-pin store operation")
        .expect("quarantined read action re-pins");
    assert_eq!(reactivated.status, "active");
    assert!(
        reactivated.generation > generation_before,
        "the re-pin must invalidate reservations from the quarantined generation"
    );
    let review = store
        .catalog_action_review("direct", "connection", "read_action")
        .expect("read action review")
        .expect("action review exists");
    assert_eq!(review.reviewed_schema, Some(reviewed_schema));

    let resumed = store
        .subscription("direct", &schema_changed.subscription_id)
        .expect("read resumed subscription")
        .expect("schema subscription exists");
    assert_eq!(resumed.status, "active");
    assert_eq!(resumed.suspended_reason, None);
    assert_eq!(resumed.schema_hash, "hash-read-action-reviewed");
    let still_suspended = store
        .subscription("direct", &risk_drift.subscription_id)
        .expect("read risk drift subscription")
        .expect("risk drift subscription exists");
    assert_eq!(still_suspended.status, "suspended");
    assert_eq!(
        still_suspended.suspended_reason.as_deref(),
        Some("risk_drift")
    );
    assert_eq!(still_suspended.schema_hash, "hash-read-action-reviewed");
    assert_eq!(
        cursor_before(&schema_changed.subscription_id),
        schema_cursor_before
    );
    assert_eq!(
        cursor_before(&risk_drift.subscription_id),
        risk_cursor_before
    );
}

#[test]
fn repin_refuses_disabled_actions_nonread_risk_and_stale_reviews() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    store
        .quarantine_action(
            "direct",
            "connection",
            "read_action",
            "schema_changed_requires_review",
        )
        .expect("quarantine read action");
    let stale = store
        .repin_reviewed_action("direct", "connection", "read_action", "stale-hash")
        .expect("stale review is a store result");
    assert!(matches!(
        stale,
        Err(RepinActionRefusal::ExpectedHashMismatch { .. })
    ));
    store
        .disable_catalog_action("direct", "connection", "read_action")
        .expect("disable action");
    let disabled = store
        .repin_reviewed_action("direct", "connection", "read_action", "hash-read_action")
        .expect("disabled re-pin is a store result");
    assert!(matches!(
        disabled,
        Err(RepinActionRefusal::ActionNotQuarantined(_))
    ));
    assert_eq!(
        store
            .catalog_action("direct", "connection", "read_action")
            .expect("read disabled action")
            .expect("action exists")
            .status,
        "disabled",
        "the SQL status guard must prevent a disabled action becoming active"
    );

    store
        .quarantine_action(
            "direct",
            "connection",
            "write_action",
            "schema_changed_requires_review",
        )
        .expect("quarantine write action");
    let changed_risk = store
        .repin_reviewed_action("direct", "connection", "write_action", "hash-write_action")
        .expect("write risk is a store result");
    assert!(matches!(changed_risk, Err(RepinActionRefusal::RiskNotRead(risk)) if risk == "write"));
}

#[test]
fn reviewed_schema_survives_refreshes_while_an_action_is_quarantined() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let initial_schema = store
        .catalog_action("direct", "connection", "read_action")
        .expect("read initial action")
        .expect("action exists")
        .schema;
    for (schema_hash, schema) in [
        (
            "hash-read-action-first-review",
            serde_json::json!({
                "type": "object",
                "properties": {"since": {"type": "string"}, "labels": {"type": "array"}}
            }),
        ),
        (
            "hash-read-action-second-review",
            serde_json::json!({
                "type": "object",
                "properties": {"since": {"type": "integer"}, "labels": {"type": "array"}, "after": {"type": "string"}}
            }),
        ),
    ] {
        store
            .refresh_catalog_action(CatalogActionInput {
                connection_id: "connection".to_string(),
                principal: "direct".to_string(),
                name: "read_action".to_string(),
                title: Some("read_action".to_string()),
                schema,
                schema_hash: schema_hash.to_string(),
                risk: "read".to_string(),
                severity: "S2".to_string(),
                ask_first: false,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("refresh action");
    }
    let review = store
        .catalog_action_review("direct", "connection", "read_action")
        .expect("read preserved review")
        .expect("action review exists");
    assert_eq!(review.action.status, "quarantined");
    assert_eq!(review.action.schema_hash, "hash-read-action-second-review");
    assert_eq!(review.reviewed_schema, Some(initial_schema));
}

#[test]
fn an_edited_vendor_item_delivers_each_distinct_payload_once() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");

    let original = serde_json::json!({"number": 3, "title": "before"});
    let edited = serde_json::json!({"number": 3, "title": "after"});
    let original_id = match store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-3",
            &original,
            1,
        )
        .expect("insert original")
    {
        TriggerEventInsertOutcome::Inserted { event_id } => event_id,
        outcome => panic!("expected original insertion, got {outcome:?}"),
    };
    let edited_id = match store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-3",
            &edited,
            2,
        )
        .expect("insert edit")
    {
        TriggerEventInsertOutcome::Inserted { event_id } => event_id,
        outcome => panic!("expected edited delivery, got {outcome:?}"),
    };
    assert_ne!(
        original_id, edited_id,
        "each version gets its own event row"
    );

    // Re-reading an unchanged edited version through an overlap window must
    // not redeliver it.
    for observed_at in 3..8 {
        assert!(
            matches!(
                store.insert_event(
                    "direct",
                    "connection",
                    &subscription.subscription_id,
                    "vendor-3",
                    &edited,
                    observed_at,
                ),
                Ok(TriggerEventInsertOutcome::Duplicate { .. })
            ),
            "re-observing identical content must be a duplicate"
        );
    }

    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("list events");
    assert_eq!(
        events.iter().filter(|event| event.kind == "event").count(),
        2,
        "the original and its edit are both delivered"
    );
    assert_eq!(
        events.iter().filter(|event| event.kind == "gap").count(),
        0,
        "an edit is not a coverage hole"
    );
    assert!(
        events.iter().any(|event| event.payload == edited),
        "the edited vendor payload is delivered rather than replaced by a warning"
    );

    let later_edit = serde_json::json!({"number": 3, "title": "after again"});
    assert!(matches!(
        store.insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-3",
            &later_edit,
            9,
        ),
        Ok(TriggerEventInsertOutcome::Inserted { .. })
    ));
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("list after later edit");
    assert_eq!(
        events.iter().filter(|event| event.kind == "event").count(),
        3,
        "every distinct version is delivered exactly once"
    );
    assert!(
        events.iter().all(|event| event.kind != "gap"),
        "edits must never create a dedupe coverage gap"
    );
}

/// The boundary lookup identifies only identical content in the named
/// subscription; changed payloads and unseen ids remain candidates.
///
/// Mutation-proved: omitting the payload hash marks the edited pair unchanged,
/// while omitting the candidate id marks the unseen pair unchanged.
#[test]
fn unchanged_event_payloads_are_scoped_by_id_content_and_subscription() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let first = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("first subscription");
    let second = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("second subscription");
    let original = serde_json::json!({"title": "before"});
    let edited = serde_json::json!({"title": "after"});
    let unseen = original.clone();
    store
        .insert_event(
            "direct",
            "connection",
            &first.subscription_id,
            "vendor-3",
            &original,
            1,
        )
        .expect("insert original");

    assert_eq!(
        store
            .unchanged_event_payloads(
                "direct",
                &first.subscription_id,
                &[
                    ("vendor-3", &original),
                    ("vendor-3", &edited),
                    ("vendor-4", &unseen),
                ],
            )
            .expect("compare candidate content"),
        vec![true, false, false]
    );
    assert_eq!(
        store
            .unchanged_event_payloads(
                "direct",
                &second.subscription_id,
                &[("vendor-3", &original)],
            )
            .expect("compare other subscription"),
        vec![false],
        "an identical row in another subscription must not suppress this one"
    );
}

#[test]
fn event_dedupe_is_scoped_and_versions_are_delivered() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let first = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let second = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let payload = serde_json::json!({"value": 1});
    assert!(matches!(
        store.insert_event(
            "direct",
            "connection",
            &first.subscription_id,
            "vendor-1",
            &payload,
            1,
        ),
        Ok(TriggerEventInsertOutcome::Inserted { .. })
    ));
    assert!(matches!(
        store.insert_event(
            "direct",
            "connection",
            &second.subscription_id,
            "vendor-1",
            &payload,
            2,
        ),
        Ok(TriggerEventInsertOutcome::Inserted { .. })
    ));
    assert!(matches!(
        store.insert_event(
            "direct",
            "connection",
            &first.subscription_id,
            "vendor-1",
            &payload,
            3,
        ),
        Ok(TriggerEventInsertOutcome::Duplicate { .. })
    ));
    assert!(matches!(
        store.insert_event(
            "direct",
            "connection",
            &first.subscription_id,
            "vendor-1",
            &serde_json::json!({"value": 2}),
            4,
        ),
        Ok(TriggerEventInsertOutcome::Inserted { .. })
    ));
    let events = store
        .list_events("direct", None, Some(&first.subscription_id))
        .expect("list events");
    assert_eq!(events.len(), 2, "both payload versions are delivered");
    assert!(events.iter().all(|event| event.kind == "event"));
}

#[test]
fn suspend_is_visible_and_writes_a_gap_marker() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let slow_subscription = store
        .subscribe("direct", "connection", "read_action", 1_800)
        .expect("subscribe slow watch")
        .expect("slow subscription");
    assert_eq!(
        store
            .active_subscription_schedule()
            .expect("read active subscription schedule"),
        Some((2, 1_800)),
        "the scheduler allowance must follow the longest active cadence"
    );
    assert!(store
        .suspend(
            "direct",
            &subscription.subscription_id,
            "authorization_revoked"
        )
        .expect("suspend"));
    let listed = store
        .subscription("direct", &subscription.subscription_id)
        .expect("subscription projection")
        .expect("subscription exists");
    assert_eq!(listed.status, "suspended");
    assert_eq!(
        store
            .active_subscription_schedule()
            .expect("read active subscription schedule"),
        Some((1, 1_800)),
        "suspending the faster watch leaves the slower active cadence"
    );
    assert!(store
        .suspend(
            "direct",
            &slow_subscription.subscription_id,
            "authorization_revoked"
        )
        .expect("suspend slow watch"));
    assert_eq!(
        store
            .active_subscription_schedule()
            .expect("read active subscription schedule"),
        None,
        "a fully suspended set has neither scheduler work nor a maximum cadence"
    );
    assert_eq!(
        listed.suspended_reason.as_deref(),
        Some("authorization_revoked")
    );
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("gap list");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "gap");
}

/// A circuit-breaker pause is recoverable without losing the cursor that
/// tells the next poll where vendor history begins.
#[test]
fn resume_reactivates_a_circuit_breaker_subscription_without_rewriting_its_cursor() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let cursor = serde_json::json!({"watermark_ms": 1_700_000_000_000i64});
    let subscription = store
        .subscribe_with_cursor_state(
            "direct",
            "connection",
            "read_action",
            30,
            &cursor,
            &serde_json::json!({}),
        )
        .expect("subscribe")
        .expect("subscription");
    assert!(store
        .record_vendor_failure("direct", &subscription.subscription_id)
        .expect("seed vendor failure"));
    assert!(store
        .suspend(
            "direct",
            &subscription.subscription_id,
            CIRCUIT_BREAKER_SUSPENSION_REASON,
        )
        .expect("trip circuit breaker"));
    let raw_cursor_before: String = store
        .inner
        .with_conn(|conn| {
            conn.query_row(
                "SELECT cursor_state FROM trigger_subscriptions WHERE subscription_id = ?1",
                [&subscription.subscription_id],
                |row| row.get(0),
            )
        })
        .expect("read stored cursor before resume");
    let suspended = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read suspended subscription")
        .expect("subscription exists");
    assert!(
        !store
            .due_subscriptions("direct", now_ms())
            .expect("due subscriptions before resume")
            .iter()
            .any(|candidate| candidate.subscription_id == subscription.subscription_id),
        "a suspended subscription must not be scheduled"
    );

    let resumed = store
        .resume("direct", &subscription.subscription_id)
        .expect("resume")
        .expect("circuit-breaker suspension is resumable");
    let raw_cursor_after: String = store
        .inner
        .with_conn(|conn| {
            conn.query_row(
                "SELECT cursor_state FROM trigger_subscriptions WHERE subscription_id = ?1",
                [&subscription.subscription_id],
                |row| row.get(0),
            )
        })
        .expect("read stored cursor after resume");
    assert_eq!(resumed.status, "active");
    assert_eq!(resumed.suspended_reason, None);
    assert_eq!(resumed.consecutive_vendor_failures, 0);
    assert_eq!(
        resumed.cursor_state, cursor,
        "resuming must keep the next vendor watermark"
    );
    assert_eq!(
        raw_cursor_after, raw_cursor_before,
        "resume must leave the durable cursor bytes untouched"
    );
    assert_eq!(resumed.generation, suspended.generation + 1);
    assert!(
        store
            .due_subscriptions("direct", now_ms())
            .expect("due subscriptions after resume")
            .iter()
            .any(|candidate| candidate.subscription_id == subscription.subscription_id),
        "an operator-resumed subscription must be scheduled again"
    );

    let retried = store
        .resume("direct", &subscription.subscription_id)
        .expect("idempotent resume")
        .expect("active subscription resumes successfully");
    assert_eq!(retried.generation, resumed.generation);
    assert_eq!(retried.consecutive_vendor_failures, 0);
    assert_eq!(
        raw_cursor_after,
        store
            .inner
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT cursor_state FROM trigger_subscriptions WHERE subscription_id = ?1",
                    [&subscription.subscription_id],
                    |row| row.get::<_, String>(0),
                )
            })
            .expect("read stored cursor after idempotent resume"),
        "repeating resume must not rewrite the cursor"
    );
}

/// Safety suspensions are not a substitute spelling for a circuit breaker.
///
/// Mutation proved: making `resume` reason-blind reactivates this row, so the
/// `SuspensionNotResumable` match below fails instead of permitting a
/// risk-drifted action to poll again.
#[test]
fn resume_refuses_a_risk_drift_suspension_by_name() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe_with_cursor_state(
            "direct",
            "connection",
            "read_action",
            30,
            &serde_json::json!({"watermark_ms": 42}),
            &serde_json::json!({}),
        )
        .expect("subscribe")
        .expect("subscription");
    assert!(store
        .suspend("direct", &subscription.subscription_id, "risk_drift")
        .expect("suspend for risk drift"));

    let refusal = store
        .resume("direct", &subscription.subscription_id)
        .expect("resume request")
        .expect_err("risk drift must not be resumable");
    assert_eq!(refusal.code(), "suspension_not_resumable");
    assert_eq!(
        refusal.to_string(),
        "subscription suspended for 'risk_drift' cannot be resumed"
    );
    assert_eq!(
        refusal,
        SubscriptionResumeRefusal::SuspensionNotResumable(Some("risk_drift".to_string()))
    );
    let stored = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read subscription")
        .expect("subscription exists");
    assert_eq!(stored.status, "suspended");
    assert_eq!(stored.suspended_reason.as_deref(), Some("risk_drift"));
    assert_eq!(stored.cursor_state, serde_json::json!({"watermark_ms": 42}));
    assert!(
        !store
            .due_subscriptions("direct", now_ms())
            .expect("due subscriptions")
            .iter()
            .any(|candidate| candidate.subscription_id == subscription.subscription_id),
        "risk drift must continue to keep the subscription out of the scheduler"
    );
}

#[test]
fn resume_distinguishes_an_unknown_subscription_from_an_unresumable_one() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    assert_eq!(
        store
            .resume("direct", "subscription_missing")
            .expect("resume request"),
        Err(SubscriptionResumeRefusal::SubscriptionNotFound)
    );
}

#[test]
fn resume_requires_the_same_live_poll_grant_as_subscribe() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    assert!(store
        .suspend(
            "direct",
            &subscription.subscription_id,
            CIRCUIT_BREAKER_SUSPENSION_REASON,
        )
        .expect("trip circuit breaker"));
    assert!(store
        .revoke_grant("direct", "grant-poll")
        .expect("revoke poll grant"));

    assert_eq!(
        store
            .resume("direct", &subscription.subscription_id)
            .expect("resume request"),
        Err(SubscriptionResumeRefusal::PollGrantRequired)
    );
    let stored = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read subscription")
        .expect("subscription exists");
    assert_eq!(stored.status, "suspended");
    assert_eq!(
        stored.suspended_reason.as_deref(),
        Some(CIRCUIT_BREAKER_SUSPENSION_REASON)
    );
}

/// A successful poll commits the cursor advance and its events together.
///
/// This is the happy path the atomicity guard below is meaningless without:
/// a suite that only ever refuses cannot tell a real implementation from one
/// that refuses everything. Asserts STATE — the stored cursor value moved
/// and the events are present — not merely that the call returned ok.
#[test]
fn commit_poll_success_advances_cursor_and_writes_events_together() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    // A prior vendor failure so the commit must also clear the streak.
    assert!(store
        .record_vendor_failure("direct", &subscription.subscription_id)
        .expect("seed vendor failure"));
    let first = serde_json::json!({"id": "e1", "value": 1});
    let second = serde_json::json!({"id": "e2", "value": 2});
    let new_cursor = serde_json::json!({"sync_token": "tok-1"});
    let outcomes = store
        .commit_poll_success(
            "direct",
            "connection",
            &subscription.subscription_id,
            &new_cursor,
            &[
                PollEventInput {
                    vendor_event_id: "e1",
                    payload: &first,
                    observed_at_ms: 100,
                    item_kind: None,
                    activity_at_ms: None,
                    actor: &ActorAttribution::NotEnriched,
                },
                PollEventInput {
                    vendor_event_id: "e2",
                    payload: &second,
                    observed_at_ms: 100,
                    item_kind: None,
                    activity_at_ms: None,
                    actor: &ActorAttribution::NotEnriched,
                },
            ],
            100,
            None,
        )
        .expect("commit succeeds");
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes
        .iter()
        .all(|outcome| matches!(outcome, TriggerEventInsertOutcome::Inserted { .. })));
    let stored = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read subscription")
        .expect("subscription exists");
    assert_eq!(stored.cursor_state, new_cursor, "cursor value must advance");
    assert_eq!(
        stored.consecutive_vendor_failures, 0,
        "success clears the streak"
    );
    assert_eq!(stored.last_success_at_ms, Some(100));
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("list events");
    assert_eq!(events.len(), 2, "both events are durable");
}

/// Atomicity, proved non-vacuously: when an event write fails, the cursor
/// must not move.
///
/// The first commit moves the cursor to `tok-1`. The second commit targets
/// `tok-2` but its batch carries an event with a blank vendor id, which the
/// commit refuses. Because the cursor advance and the event inserts share
/// ONE fenced transaction, the refusal rolls the cursor back to `tok-1`.
///
/// Mutation proved: split the method into a cursor transaction followed by
/// an event transaction and the cursor advance to `tok-2` commits on its
/// own; the event transaction then fails and rolls back only the events,
/// leaving the cursor at `tok-2`. The `cursor_state == tok-1` assertion is
/// the one that fails, which is exactly the ordering bug this guard exists
/// to make impossible — advancing past events that were never recorded.
#[test]
fn commit_poll_success_rolls_the_cursor_back_when_an_event_write_fails() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let first = serde_json::json!({"id": "e1"});
    store
        .commit_poll_success(
            "direct",
            "connection",
            &subscription.subscription_id,
            &serde_json::json!({"sync_token": "tok-1"}),
            &[PollEventInput {
                vendor_event_id: "e1",
                payload: &first,
                observed_at_ms: 100,
                item_kind: None,
                activity_at_ms: None,
                actor: &ActorAttribution::NotEnriched,
            }],
            100,
            None,
        )
        .expect("first commit succeeds");
    let valid = serde_json::json!({"id": "e2"});
    let blank = serde_json::json!({"id": "e3"});
    let result = store.commit_poll_success(
        "direct",
        "connection",
        &subscription.subscription_id,
        &serde_json::json!({"sync_token": "tok-2"}),
        &[
            PollEventInput {
                vendor_event_id: "e2",
                payload: &valid,
                observed_at_ms: 200,
                item_kind: None,
                activity_at_ms: None,
                actor: &ActorAttribution::NotEnriched,
            },
            // A blank vendor id cannot be deduped; it must abort the batch.
            PollEventInput {
                vendor_event_id: "   ",
                payload: &blank,
                observed_at_ms: 200,
                item_kind: None,
                activity_at_ms: None,
                actor: &ActorAttribution::NotEnriched,
            },
        ],
        200,
        None,
    );
    assert!(result.is_err(), "a blank vendor id must fail the commit");
    let stored = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read subscription")
        .expect("subscription exists");
    // The load-bearing assertion: the cursor is unmoved by the failed batch.
    assert_eq!(
        stored.cursor_state,
        serde_json::json!({"sync_token": "tok-1"}),
        "the failed commit must not advance the cursor"
    );
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("list events");
    assert_eq!(
        events.len(),
        1,
        "the valid event from the failed batch is rolled back too"
    );
    assert_eq!(events[0].vendor_event_id.as_deref(), Some("e1"));
}

/// Committing against a subscription that is no longer active writes nothing:
/// neither the cursor nor any event. The cursor update is gated on
/// `status = 'active'`, so a suspension that lands mid-cycle makes the whole
/// batch roll back rather than orphaning events under a dead subscription.
#[test]
fn commit_poll_success_writes_nothing_for_a_suspended_subscription() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    assert!(store
        .suspend(
            "direct",
            &subscription.subscription_id,
            "authorization_revoked"
        )
        .expect("suspend"));
    let payload = serde_json::json!({"id": "e1"});
    let result = store.commit_poll_success(
        "direct",
        "connection",
        &subscription.subscription_id,
        &serde_json::json!({"sync_token": "tok-1"}),
        &[PollEventInput {
            vendor_event_id: "e1",
            payload: &payload,
            observed_at_ms: 100,
            item_kind: None,
            activity_at_ms: None,
            actor: &ActorAttribution::NotEnriched,
        }],
        100,
        None,
    );
    assert!(result.is_err(), "a suspended subscription must not commit");
    let stored = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read subscription")
        .expect("subscription exists");
    assert_eq!(stored.cursor_state, serde_json::json!({}), "cursor unmoved");
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("list events");
    // Only the gap marker written by suspend; the commit added no event.
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "gap");
}

/// Poll bookkeeping is principal-scoped, and the cursor write is the one
/// that would hurt.
///
/// `record_poll_success` advances the cursor that decides which vendor
/// records the NEXT poll asks for. An unscoped write is therefore a silent
/// data-loss primitive rather than a bookkeeping slip: jumping another
/// principal's cursor forward makes their poller skip the window it passed
/// over, and their event log cannot distinguish "nothing happened" from
/// "we stopped looking". Asserts the cursor VALUE is unmoved rather than
/// only that the call reported no change.
#[test]
fn poll_bookkeeping_refuses_a_subscription_owned_by_another_principal() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    assert!(store
        .record_poll_success(
            "direct",
            &subscription.subscription_id,
            &serde_json::json!({"watermark": "owner"}),
            1_000,
        )
        .expect("owner advances its own cursor"));

    assert!(
        !store
            .record_poll_success(
                "intruder",
                &subscription.subscription_id,
                &serde_json::json!({"watermark": "stolen"}),
                2_000,
            )
            .expect("cross-principal cursor write"),
        "another principal advanced this subscription's cursor"
    );
    assert!(
        !store
            .record_poll_attempt("intruder", &subscription.subscription_id, 2_000)
            .expect("cross-principal attempt stamp"),
        "another principal stamped this subscription's poll attempt"
    );
    assert!(
        !store
            .record_vendor_failure("intruder", &subscription.subscription_id)
            .expect("cross-principal failure count"),
        "another principal incremented this subscription's failure streak"
    );

    let listed = store
        .subscription("direct", &subscription.subscription_id)
        .expect("subscription projection")
        .expect("subscription exists");
    assert_eq!(
        listed.cursor_state,
        serde_json::json!({"watermark": "owner"}),
        "the cursor moved under a principal that does not own it"
    );
    assert_eq!(
        listed.consecutive_vendor_failures, 0,
        "a cross-principal failure count reached the owner's backoff streak"
    );
}

/// Suspension is principal-scoped, so naming another principal's
/// subscription must change nothing.
///
/// A subscription id is an unguessable `subscription_<24 hex characters>`, which is why this
/// never showed up as a live hole — but unguessability is not an
/// authorization check, and an id that reaches a log line or an error
/// message would otherwise become authority over someone else's polling.
/// The assertion is that the subscription stays ACTIVE and no gap event is
/// written, not merely that the call returns false: a suspension that
/// happened while reporting failure is the worse outcome, and only the
/// state assertion distinguishes those.
#[test]
fn suspend_refuses_a_subscription_owned_by_another_principal() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");

    assert!(
        !store
            .suspend("intruder", &subscription.subscription_id, "revoked")
            .expect("suspend call"),
        "suspending another principal's subscription must report no change"
    );

    let listed = store
        .subscription("direct", &subscription.subscription_id)
        .expect("subscription projection")
        .expect("subscription exists");
    assert_eq!(
        listed.status, "active",
        "the subscription was suspended by a principal that does not own it"
    );
    assert!(
        store
            .list_events("direct", None, Some(&subscription.subscription_id))
            .expect("gap list")
            .is_empty(),
        "a cross-principal suspension wrote a gap marker into the owner's log"
    );
}

/// The retention gap marker must describe the rows that were actually
/// deleted.
///
/// A pruned unacked event is a coverage hole, and the gap kind exists so the
/// log cannot lie by omission. Before this, the interval was captured up
/// front with a `rn > max_rows` window while the count delete removed rows
/// with `ORDER BY created_at_ms LIMIT excess` -- the window numbers
/// oldest-first, so it named the NEWEST rows while the delete took the
/// OLDEST. The marker then reported a hole over rows still present and said
/// nothing about the rows dropped: lying by commission instead of omission.
///
/// Asserted by observed_at timestamps rather than row counts, because a
/// count-only assertion passes against an interval taken from the wrong end
/// of the log -- which is exactly how the defect survived the existing
/// prune test.
///
/// Mutation-proved: measuring the excess interval with the old `rn >
/// max_rows` window fails the upper-bound assertion by naming a surviving
/// row's timestamp.
#[test]
fn the_retention_gap_describes_the_rows_actually_pruned() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");

    // Five events with distinct, increasing observed_at values so the
    // interval can be read back unambiguously.
    for index in 1..=5i64 {
        store
            .insert_event(
                "direct",
                "connection",
                &subscription.subscription_id,
                &format!("vendor-{index}"),
                &serde_json::json!({"n": index}),
                index * 1000,
            )
            .expect("insert event");
    }

    // Age the bodies past the seven-day minimum retention so the row-count
    // limit can delete them even though no age cutoff is requested.
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE trigger_events SET created_at_ms = ?1 WHERE subscription_id = ?2",
                (
                    now_ms() - 8 * AUDIT_MILLIS_PER_DAY,
                    &subscription.subscription_id,
                ),
            )
            .map(|_| ())
        })
        .unwrap();
    // Count-only prune: no age cutoff, ceiling of 3, so the two OLDEST rows
    // go (observed_at 1000 and 2000).
    let removed = store
        .prune("direct", &subscription.subscription_id, i64::MAX, 3)
        .expect("prune");
    assert_eq!(removed, 2, "the ceiling must remove exactly the excess");

    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("list events");
    let gap = events
        .iter()
        .find(|event| event.gap_reason.as_deref() == Some("retention_pruned"))
        .expect("a pruned coverage hole must be recorded");

    // WHICH rows the ceiling drops is not fixed here, and asserting fixed
    // timestamps would be wrong rather than merely brittle: `prune` orders
    // by `created_at_ms`, which `insert_event` stamps from the wall clock,
    // so five rows inserted inside one millisecond tie and break on a random
    // `event_id`. An earlier version of this test asserted 1000 and 2000 and
    // passed by luck.
    //
    // So derive the deleted set from the survivors and assert the interval
    // against THAT. This is the property that matters and it holds however
    // the tie breaks: the marker must span exactly the rows that are gone.
    let survivors: Vec<i64> = events
        .iter()
        .filter(|event| event.kind == "event")
        .map(|event| event.observed_at_ms)
        .collect();
    let deleted: Vec<i64> = (1..=5i64)
        .map(|index| index * 1000)
        .filter(|observed| !survivors.contains(observed))
        .collect();
    assert_eq!(deleted.len(), 2, "exactly two rows must be gone");

    assert_eq!(
        gap.gap_from_ms,
        deleted.iter().min().copied(),
        "the gap must start at the oldest row actually pruned"
    );
    assert_eq!(
        gap.gap_to_ms,
        deleted.iter().max().copied(),
        "the gap must end at the newest row actually PRUNED, not at a surviving one"
    );
    assert!(
        !survivors
            .iter()
            .any(|observed| Some(*observed) == gap.gap_to_ms),
        "the interval must not name a row that is still present: \
         survivors={survivors:?} gap_to={:?}",
        gap.gap_to_ms
    );
}

#[test]
fn prune_enforces_age_and_count_per_subscription() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    for id in ["old", "keep-a", "keep-b", "new"] {
        store
            .insert_event(
                "direct",
                "connection",
                &subscription.subscription_id,
                id,
                &serde_json::json!({"id": id}),
                now_ms(),
            )
            .expect("event");
    }
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE trigger_events SET created_at_ms = ?1 WHERE subscription_id = ?2",
                (
                    now_ms() - 8 * AUDIT_MILLIS_PER_DAY,
                    &subscription.subscription_id,
                ),
            )?;
            conn.execute(
                "UPDATE trigger_events SET created_at_ms = ?1
                 WHERE subscription_id = ?2 AND vendor_event_id = 'old'",
                (
                    now_ms() - 10 * AUDIT_MILLIS_PER_DAY,
                    &subscription.subscription_id,
                ),
            )?;
            Ok(())
        })
        .expect("age old event");
    // Pruning is principal-scoped: another principal naming this
    // subscription must delete nothing. Asserted BEFORE the real prune so
    // the row count below is evidence the scoped call did the work, rather
    // than evidence that some call did.
    assert_eq!(
        store
            .prune("intruder", &subscription.subscription_id, 0, 0)
            .expect("cross-principal prune"),
        0,
        "another principal pruned this subscription's event history"
    );
    assert_eq!(
        store
            .list_events("direct", None, Some(&subscription.subscription_id))
            .expect("events after cross-principal prune")
            .len(),
        4,
        "a cross-principal prune deleted the owner's events"
    );

    let removed = store
        .prune(
            "direct",
            &subscription.subscription_id,
            9 * AUDIT_MILLIS_PER_DAY,
            2,
        )
        .expect("prune");
    assert_eq!(removed, 2);
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("remaining events");
    // Two ordinary events survive plus one gap marker recording the
    // interval of the pruned unacked event. The gap is the coverage hole
    // the pruning created, made visible rather than silent.
    assert_eq!(events.len(), 3);
    assert!(events
        .iter()
        .all(|event| event.vendor_event_id.as_deref() != Some("old")));
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == "gap"
                && event.gap_reason.as_deref() == Some("retention_pruned"))
            .count(),
        1,
        "pruning an unacked event records a retention_pruned gap marker"
    );
}

/// Count retention treats versions of one vendor item as separate delivered
/// rows and records the interval of the version it actually removes.
#[test]
fn count_pruning_accounts_for_distinct_content_versions() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let original_id = match store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &serde_json::json!({"version": 1}),
            100,
        )
        .expect("insert original")
    {
        TriggerEventInsertOutcome::Inserted { event_id } => event_id,
        outcome => panic!("expected original insertion, got {outcome:?}"),
    };
    let edited_id = match store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &serde_json::json!({"version": 2}),
            200,
        )
        .expect("insert edited version")
    {
        TriggerEventInsertOutcome::Inserted { event_id } => event_id,
        outcome => panic!("expected edited insertion, got {outcome:?}"),
    };
    let fresh_id = match store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-2",
            &serde_json::json!({"version": 1}),
            300,
        )
        .expect("insert fresh item")
    {
        TriggerEventInsertOutcome::Inserted { event_id } => event_id,
        outcome => panic!("expected fresh insertion, got {outcome:?}"),
    };
    store
        .inner
        .with_conn_fenced(|conn| {
            for (event_id, created_at_ms) in [
                (&original_id, 1_i64),
                (&edited_id, 2_i64),
                (&fresh_id, 3_i64),
            ] {
                conn.execute(
                    "UPDATE trigger_events SET created_at_ms = ?1 WHERE event_id = ?2",
                    rusqlite::params![created_at_ms, event_id],
                )?;
            }
            Ok(())
        })
        .expect("order versions for count pruning");

    assert_eq!(
        store
            .prune("direct", &subscription.subscription_id, i64::MAX, 2)
            .expect("count prune"),
        1,
        "the oldest delivered version is the one excess row"
    );
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("list after count prune");
    assert_eq!(
        events.iter().filter(|event| event.kind == "event").count(),
        2,
        "the newer version and the unrelated item survive"
    );
    assert!(
        events.iter().any(|event| event.event_id == edited_id)
            && events.iter().any(|event| event.event_id == fresh_id),
        "count pruning keeps the two newest rows even when two share a vendor id"
    );
    let gap = events
        .iter()
        .find(|event| event.gap_reason.as_deref() == Some("retention_pruned"))
        .expect("pruning the original version writes a coverage gap");
    assert_eq!(gap.gap_from_ms, Some(100));
    assert_eq!(gap.gap_to_ms, Some(100));
}

#[test]
fn gap_events_are_listed_alongside_ordinary_events() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &serde_json::json!({"value": 1}),
            10,
        )
        .expect("event");
    store
        .insert_gap_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            11,
            20,
            "cursor_reset",
            21,
        )
        .expect("gap");
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events.iter().filter(|event| event.kind == "gap").count(), 1);
    assert_eq!(
        events.iter().filter(|event| event.kind == "event").count(),
        1
    );
}

#[test]
fn oauth_flows_is_absent_after_migrations_run() {
    let connection = empty_schema();
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'oauth_flows'
            )",
            [],
            |row| row.get(0),
        )
        .expect("inspect migrated schema");

    assert!(!exists, "oauth_flows must not exist after migration 24");
}

#[test]
fn audit_update_trigger_rejects_both_old_and_recent_rows() {
    let connection = empty_schema();
    let now = now_ms();
    let old = now - (AUDIT_DELETE_FLOOR_DAYS + 1) * AUDIT_MILLIS_PER_DAY;
    connection
        .execute(
            "INSERT INTO audit_journal
                (ts, principal, actor, acting_principal, decision, reason_code)
             VALUES (?1, 'p', 'plexus', 'p', 'allow', 'old'),
                    (?2, 'p', 'plexus', 'p', 'allow', 'recent')",
            rusqlite::params![old, now],
        )
        .expect("insert old and recent audit rows");

    for reason_code in ["old", "recent"] {
        let update = connection.execute(
            "UPDATE audit_journal SET decision = 'deny' WHERE reason_code = ?1",
            [reason_code],
        );
        let error = update.expect_err("audit updates must always be rejected");
        assert!(
            error.to_string().contains("append-only"),
            "the update refusal must name the append-only contract: {error}"
        );
    }
}

#[test]
fn audit_delete_trigger_rejects_a_recent_row_and_permits_one_outside_the_floor() {
    let connection = empty_schema();
    let now = now_ms();
    let floor = AUDIT_DELETE_FLOOR_DAYS * AUDIT_MILLIS_PER_DAY;
    let boundary_margin = 60 * 60 * 1000;
    let outside_floor = now - floor - boundary_margin;
    let recent_inside_floor = now - floor + boundary_margin;
    connection
        .execute(
            "INSERT INTO audit_journal
                (ts, principal, actor, acting_principal, decision, reason_code)
             VALUES (?1, 'p', 'plexus', 'p', 'allow', 'outside-floor'),
                    (?2, 'p', 'plexus', 'p', 'allow', 'inside-floor')",
            rusqlite::params![outside_floor, recent_inside_floor],
        )
        .expect("insert audit rows around the delete floor");

    assert_eq!(
        connection
            .execute(
                "DELETE FROM audit_journal WHERE reason_code = 'outside-floor'",
                []
            )
            .expect("a row older than the floor may be deleted"),
        1
    );
    let error = connection
        .execute(
            "DELETE FROM audit_journal WHERE reason_code = 'inside-floor'",
            [],
        )
        .expect_err("a recent audit row must not be deleted");
    assert!(
        error.to_string().contains("7-day delete floor"),
        "the refusal must name the protected floor: {error}"
    );
}

#[test]
fn reservation_retention_deletes_old_terminal_and_keeps_recent_terminal() {
    let store = reservation_store();
    let now = now_ms();
    let cutoff = now - RESERVATION_RETENTION_MS;
    for status in ["invalidated", "dispatched", "expired"] {
        store
            .insert_reservation_at_for_test("p", &format!("old-{status}"), status, cutoff - 1)
            .expect("insert old terminal reservation");
        store
            .insert_reservation_at_for_test("p", &format!("recent-{status}"), status, cutoff + 1)
            .expect("insert recent terminal reservation");
    }

    assert_eq!(
        store.prune_reservations(now).expect("run retention"),
        3,
        "exactly the three terminal rows older than one day must be removed"
    );
    for status in ["invalidated", "dispatched", "expired"] {
        assert!(
            store
                .reservation("p", &format!("recent-{status}"))
                .unwrap()
                .is_some(),
            "recent {status} reservation was removed"
        );
        assert!(
            store
                .reservation("p", &format!("old-{status}"))
                .unwrap()
                .is_none(),
            "old {status} reservation survived retention"
        );
    }
}

#[test]
fn reservation_retention_never_deletes_non_terminal_reservations() {
    let store = reservation_store();
    let now = now_ms();
    store
        .insert_reservation_at_for_test(
            "p",
            "old-reserved",
            "reserved",
            now - RESERVATION_RETENTION_MS - 1,
        )
        .expect("insert old non-terminal reservation");
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE reservations SET expires_at=?1 WHERE reservation_id='old-reserved'",
                [now + 60_000],
            )
            .map(|_| ())
        })
        .unwrap();

    assert_eq!(
        store.prune_reservations(now).expect("run retention"),
        0,
        "an in-flight reservation must not be pruned regardless of age"
    );
    let survivor = store
        .reservation("p", "old-reserved")
        .unwrap()
        .expect("the in-flight fence must survive");
    assert_eq!(survivor.status, "reserved");
}

#[test]
fn reservation_retention_pass_is_bounded_to_one_batch() {
    let store = reservation_store();
    let now = now_ms();
    for index in 0..=RESERVATION_RETENTION_BATCH_ROWS {
        store
            .insert_reservation_at_for_test(
                "p",
                &format!("expired-{index}"),
                "expired",
                now - RESERVATION_RETENTION_MS - 1 - index as i64,
            )
            .expect("insert old terminal reservation");
    }

    assert_eq!(
        store
            .prune_reservations(now)
            .expect("run one bounded retention pass"),
        RESERVATION_RETENTION_BATCH_ROWS,
        "one scheduler tick must never delete an unbounded reservation backlog"
    );
    assert_eq!(
        store
            .prune_reservations(now)
            .expect("run the next retention pass"),
        1,
        "one row beyond the batch bound must remain for the next pass"
    );
}

#[test]
fn audit_retention_deletes_rows_older_than_the_window_and_keeps_rows_inside_it() {
    let store = audit_store();
    let now = now_ms();
    let retention_window_ms = DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY;
    store
        .append_audit_at_for_test("p", now - retention_window_ms - 1, "outside-window")
        .expect("insert expired audit row");
    store
        .append_audit_at_for_test("p", now - retention_window_ms + 1, "inside-window")
        .expect("insert retained audit row");

    assert_eq!(
        store
            .prune_audit(now, retention_window_ms)
            .expect("run retention"),
        1,
        "exactly the row older than the window must be removed"
    );
    let survivors = store.list_audit("p").expect("read retained audit rows");
    assert_eq!(survivors.len(), 1, "an over-broad delete removed both rows");
    assert_eq!(
        survivors[0].reason_code, "inside-window",
        "the row inside the retention window must survive"
    );
}

#[test]
fn audit_retention_pass_is_bounded_to_one_batch() {
    let store = audit_store();
    let now = now_ms();
    let retention_window_ms = DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY;
    for index in 0..=AUDIT_RETENTION_BATCH_ROWS {
        store
            .append_audit_at_for_test(
                "p",
                now - retention_window_ms - 1 - index as i64,
                &format!("expired-{index}"),
            )
            .expect("insert expired audit row");
    }

    let removed = store
        .prune_audit(now, retention_window_ms)
        .expect("run one bounded retention pass");
    assert_eq!(
        removed, AUDIT_RETENTION_BATCH_ROWS,
        "one scheduler tick must never delete an unbounded backlog"
    );
    assert_eq!(
        store.list_audit("p").expect("read remainder").len(),
        1,
        "one row beyond the batch bound must remain for the next pass"
    );
}

#[test]
fn audit_retention_never_prunes_grant_revocations() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    assert!(store.revoke_grant("direct", "grant-poll").unwrap());
    assert_eq!(revocation_count(&store), 1, "fixture needs one revocation");
    let now = now_ms();
    let retention_window_ms = DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY;
    store
        .append_audit_at_for_test("direct", now - retention_window_ms - 1, "expired-audit")
        .expect("insert expired audit row");

    assert_eq!(
        store.prune_audit(now, retention_window_ms).unwrap(),
        1,
        "the expired audit row should prove retention ran"
    );
    assert_eq!(
        revocation_count(&store),
        1,
        "grant revocations are a separate immutable record, not audit history"
    );
}

/// Acknowledgement leaves the stored payload bytes unchanged, so keyed
/// events remain readable by event key. Retention pruning can delete them
/// once the seven-day minimum has passed and timestamp-cursor watches can
/// no longer re-read them.
#[test]
fn ack_retains_the_event_payload() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let payload = serde_json::json!({"secret": "value", "id": "vendor-1"});
    let outcome = store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &payload,
            100,
        )
        .expect("insert event");
    let event_id = match outcome {
        TriggerEventInsertOutcome::Inserted { event_id } => event_id,
        _ => panic!("expected insertion, got {outcome:?}"),
    };
    // Before ack the payload is present and readable.
    let before = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("list before ack");
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].payload, payload, "payload is present before ack");

    let acked = store
        .ack_events("direct", std::slice::from_ref(&event_id))
        .expect("ack");
    assert_eq!(acked, 1);

    // Read the row back directly from the store. `list_events` only returns
    // unacked rows, so it cannot witness the post-ack state; the assertion
    // must inspect the stored row itself.
    let stored_payload: String = store
        .inner
        .with_conn(|conn| {
            conn.query_row(
                "SELECT payload FROM trigger_events WHERE event_id = ?1",
                (&event_id,),
                |row| row.get(0),
            )
        })
        .expect("read stored payload");
    assert_eq!(
        stored_payload,
        serde_json::to_string(&payload).unwrap(),
        "payload must remain byte-identical after ack"
    );
    // The row survives: its identity (vendor_event_id, payload_hash) is
    // what makes dedupe work, so the row must not be deleted.
    let row_count: i64 = store
        .inner
        .with_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM trigger_events WHERE event_id = ?1",
                (&event_id,),
                |row| row.get(0),
            )
        })
        .expect("count rows");
    assert_eq!(row_count, 1, "the row and payload survive ack");
}

/// A consumer with NO grant sees nothing, and one with a grant sees the
/// owner's events.
///
/// Both legs in one test because the pair is the whole property: the empty
/// answer must be the DEFAULT rather than an accident of an empty store, and
/// the granted answer must prove the empty one was really scoping. A test of
/// either half alone passes against an implementation that always returns
/// nothing, or against one that ignores grants entirely.
///
/// Mutation proved: dropping the expiry filter in
/// `events_consume_connections` fails the lapsed leg; ignoring
/// `action_selectors` fails the selector leg; returning owned rows only fails
/// the granted leg.
#[test]
fn events_are_visible_to_a_named_consumer_and_to_nobody_else() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &serde_json::json!({"id": "vendor-1"}),
            100,
        )
        .expect("insert event");

    let now = now_ms();
    // Before any grant: the consumer's lane is empty, and this is the
    // DEFAULT rather than a special case.
    assert!(
        store
            .list_events_including_granted("reserved:consumer", None, None, now)
            .expect("list")
            .is_empty(),
        "an ungranted consumer must see nothing"
    );
    // Control: the owner sees it, so the empty answer above is scoping rather
    // than an empty store.
    assert_eq!(
        store
            .list_events_including_granted("direct", None, None, now)
            .expect("list")
            .len(),
        1,
        "the owner must see its own event without any grant"
    );

    store
        .insert_grant(&GrantInput {
            grant_id: "grant-consume".to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: "reserved:consumer".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["read_action".to_string()],
            authority_kind: crate::governance::AUTHORITY_EVENTS_CONSUME.to_string(),
            expires_at: Some(now + 60_000),
        })
        .expect("mint consume grant");

    assert_eq!(
        store
            .list_events_including_granted("reserved:consumer", None, None, now)
            .expect("list")
            .len(),
        1,
        "a named consumer must see the owner's event"
    );
    // A DIFFERENT principal must still see nothing: the grant names one
    // grantee, and a test that only proved the granted case would pass
    // against an implementation that opened the lane to everyone.
    assert!(
        store
            .list_events_including_granted("reserved:other", None, None, now)
            .expect("list")
            .is_empty(),
        "the grant must admit only the principal it names"
    );
    // And an EXPIRED grant closes the lane again. Read one millisecond past
    // the deadline rather than far past it, so the boundary itself is the
    // thing under test.
    assert!(
        store
            .list_events_including_granted("reserved:consumer", None, None, now + 60_001)
            .expect("list")
            .is_empty(),
        "a lapsed consume grant must stop serving"
    );
}

fn consume_grant(store: &PlexusStore, grant_id: &str, selectors: &[&str]) {
    store
        .insert_grant(&GrantInput {
            grant_id: grant_id.to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: "reserved:consumer".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: selectors.iter().map(|s| s.to_string()).collect(),
            authority_kind: crate::governance::AUTHORITY_EVENTS_CONSUME.to_string(),
            expires_at: Some(now_ms() + 60_000),
        })
        .expect("mint consume grant");
}

/// Two overlapping consume grants from one owner deliver each event and
/// list each watch once, and an event the consumer acked through its grant
/// is not reported back to it as unacked.
#[test]
fn overlapping_consume_grants_deliver_once_and_granted_acks_count() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let TriggerEventInsertOutcome::Inserted { event_id } = store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &serde_json::json!({"id": "vendor-1"}),
            100,
        )
        .expect("insert event")
    else {
        panic!("expected insertion");
    };
    consume_grant(&store, "grant-consume-named", &["read_action"]);
    consume_grant(&store, "grant-consume-all", &["*"]);
    let now = now_ms();
    assert_eq!(
        store
            .list_events_including_granted("reserved:consumer", None, None, now)
            .expect("list")
            .len(),
        1,
        "one event, however many grants cover it"
    );
    assert_eq!(
        store
            .list_subscriptions_including_granted("reserved:consumer", None, None, now)
            .expect("list")
            .len(),
        1,
        "one watch, however many grants cover it"
    );
    let ids = vec![event_id.clone(), "event_unknown".to_string()];
    assert_eq!(
        store
            .ack_events_including_granted("reserved:consumer", &ids, now)
            .expect("ack"),
        1
    );
    assert_eq!(
        store
            .unacked_of("reserved:consumer", &ids)
            .expect("unacked"),
        vec!["event_unknown".to_string()],
        "the granted ack took effect; only the unknown id is pending"
    );
    assert_eq!(
        store.unacked_of("reserved:other", &ids).expect("unacked"),
        ids,
        "a principal without the grant learns nothing about the event"
    );
}

/// Grants are additive: a probe whose actions are covered by two poll
/// grants from one owner, one action each, registers.
#[test]
fn a_probe_may_rely_on_two_poll_grants_from_one_owner() {
    let store = trigger_store(crate::governance::AUTHORITY_INVOKE);
    let schema = serde_json::json!({"type": "object", "properties": {}});
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "connection".to_string(),
            principal: "direct".to_string(),
            name: "read_other".to_string(),
            title: None,
            schema: schema.clone(),
            schema_hash: "hash-read_other".to_string(),
            risk: "read".to_string(),
            severity: "S2".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("second read action");
    let poll = crate::governance::AUTHORITY_POLL;
    insert_grant_with_selectors_for_test(&store, "poll-one", "agent", &["read_action"], poll);
    insert_grant_with_selectors_for_test(&store, "poll-two", "agent", &["read_other"], poll);
    let registered = register_probe_on(
        &store,
        "agent",
        &["read_action", "read_other"],
        "always",
        &serde_json::json!({}),
    );
    assert!(registered.is_ok(), "{registered:?}");
    // Control: an action neither grant names is still refused.
    let refused = register_probe_on(
        &store,
        "agent",
        &["read_action", "write_action"],
        "always",
        &serde_json::json!({}),
    );
    assert!(
        matches!(refused, Err(SubscriptionRefusal::ActionNotCoveredByGrant { ref action }) if action == "write_action"),
        "{refused:?}"
    );
}

/// When two owners each share a connection id with the caller, the invoke
/// lookup names neither rather than whichever sorts first.
#[test]
fn an_invoke_lookup_shared_by_two_owners_is_ambiguous() {
    let store = trigger_store(crate::governance::AUTHORITY_INVOKE);
    let share = |owner: &str| {
        store
            .insert_grant(&GrantInput {
                grant_id: format!("share-{owner}"),
                principal: owner.to_string(),
                connection_id: "shared".to_string(),
                grantee_principal: "caller".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["read_action".to_string()],
                authority_kind: crate::governance::AUTHORITY_INVOKE.to_string(),
                expires_at: None,
            })
            .unwrap();
    };
    for owner in ["owner-a", "owner-b"] {
        store
            .insert_connection(
                owner,
                "shared",
                "trigger_fixture",
                "active",
                &serde_json::json!({}),
            )
            .unwrap();
    }
    share("owner-b");
    assert_eq!(
        store
            .connection_for_invoke("caller", "shared")
            .unwrap()
            .map(|connection| connection.principal)
            .as_deref(),
        Some("owner-b"),
        "control: one sharing owner is found"
    );
    share("owner-a");
    assert_eq!(
        store.connection_for_invoke("caller", "shared").unwrap(),
        None,
        "two sharing owners must not resolve to either"
    );
    assert_eq!(
        store
            .connection_for_invoke("owner-a", "shared")
            .unwrap()
            .map(|connection| connection.principal)
            .as_deref(),
        Some("owner-a"),
        "an owner still finds its own connection"
    );
}

/// A granted consumer can ACK what it can read, and acking is bounded by the
/// same grant.
///
/// Ack is part of the consume grant because `list_events` returns unacked
/// rows only: a consumer that could read but not acknowledge would receive
/// the same rows on every pass forever. That makes the ack surface a real
/// authority question rather than a convenience.
///
/// THE SHARED CONSEQUENCE IS ASSERTED, not just the success: acking clears
/// the payload, so a grantee draining a lane removes those rows from the
/// OWNER's view too. That is the designed reading -- minting the grant
/// designates who drains -- and it is surprising enough that a test should
/// state it rather than leave a future reader to discover it in production.
///
/// Mutation proved: acking under the grantee's own principal instead of the
/// owner's fails the drain leg (the row stays unacked); dropping the
/// visibility filter lets an ungranted principal ack a foreign row.
#[test]
fn a_granted_consumer_can_ack_and_the_owner_sees_the_drain() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let outcome = store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &serde_json::json!({"id": "vendor-1"}),
            100,
        )
        .expect("insert event");
    let event_id = match outcome {
        TriggerEventInsertOutcome::Inserted { event_id } => event_id,
        other => panic!("expected insertion, got {other:?}"),
    };

    let now = now_ms();
    // An UNGRANTED principal must not be able to ack a foreign row. Asserted
    // before the grant exists, so the refusal cannot be confused with a
    // grant that simply had not been minted yet.
    assert_eq!(
        store
            .ack_events_including_granted("reserved:consumer", std::slice::from_ref(&event_id), now)
            .expect("ack attempt"),
        0,
        "an ungranted principal must not ack another principal's event"
    );
    assert_eq!(
        store
            .list_events("direct", None, None)
            .expect("owner list")
            .len(),
        1,
        "the refused ack must leave the owner's row untouched"
    );

    store
        .insert_grant(&GrantInput {
            grant_id: "grant-consume-ack".to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: "reserved:consumer".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["read_action".to_string()],
            authority_kind: crate::governance::AUTHORITY_EVENTS_CONSUME.to_string(),
            expires_at: Some(now + 60_000),
        })
        .expect("mint consume grant");

    assert_eq!(
        store
            .ack_events_including_granted("reserved:consumer", std::slice::from_ref(&event_id), now)
            .expect("granted ack"),
        1,
        "a granted consumer must be able to ack what it can read"
    );
    // The drain is SHARED: the owner no longer sees the row either.
    assert!(
        store
            .list_events("direct", None, None)
            .expect("owner list")
            .is_empty(),
        "acking by the grantee must drain the owner's lane too"
    );
    // And the consumer does not receive it again.
    assert!(
        store
            .list_events_including_granted("reserved:consumer", None, None, now)
            .expect("consumer list")
            .is_empty(),
        "an acked row must not be redelivered to the consumer"
    );
}

/// THE ACK SURFACE IS NEVER WIDER THAN THE READ SURFACE: a grantee holding a
/// grant for a different action cannot ack what that grant does not let it
/// see.
///
/// Separated from the test above after a mutation SURVIVED it. Deleting the
/// visibility filter in `ack_events_including_granted` left that test green,
/// because its ungranted arm is refused earlier -- the grant lookup returns
/// nothing, so the loop body never runs and the filter is never reached. The
/// ungranted case therefore proves the grant gate and says nothing about the
/// filter beside it.
///
/// This is the case that reaches it: a REAL grant on the right connection,
/// whose selectors exclude the event being acked. Without the filter, the
/// grantee acks under the owner's principal and drains a lane it was never
/// permitted to read.
#[test]
fn a_consumer_cannot_ack_an_event_its_grant_excludes() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let outcome = store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &serde_json::json!({"id": "vendor-1"}),
            100,
        )
        .expect("insert event");
    let event_id = match outcome {
        TriggerEventInsertOutcome::Inserted { event_id } => event_id,
        other => panic!("expected insertion, got {other:?}"),
    };

    let now = now_ms();
    // A live consume grant on the RIGHT connection, naming a DIFFERENT
    // action. This is what makes the lookup succeed and the filter the only
    // thing standing between the grantee and the row.
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-consume-wrong-action".to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: "reserved:consumer".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["write_action".to_string()],
            authority_kind: crate::governance::AUTHORITY_EVENTS_CONSUME.to_string(),
            expires_at: Some(now + 60_000),
        })
        .expect("mint mismatched consume grant");

    // Precondition: the grantee cannot SEE the row. If this ever fails the
    // ack assertion below becomes vacuous, so it is asserted rather than
    // assumed.
    assert!(
        store
            .list_events_including_granted("reserved:consumer", None, None, now)
            .expect("consumer list")
            .is_empty(),
        "precondition: a mismatched grant must not expose the event"
    );
    assert_eq!(
        store
            .ack_events_including_granted("reserved:consumer", &[event_id], now)
            .expect("ack attempt"),
        0,
        "a grantee must not ack an event its selectors exclude"
    );
    assert_eq!(
        store
            .list_events("direct", None, None)
            .expect("owner list")
            .len(),
        1,
        "the owner's row must survive an unpermitted ack"
    );
}

/// A polled event carries the reviewed item kind and the parsed activity
/// time, so a consumer classifies without joining or re-parsing.
///
/// The point of the fields is that they arrive TYPED on the row. Before them,
/// telling an issue from a pull request meant joining the event to its
/// subscription and reading the action name -- information that existed but
/// only as homework, and homework a consumer gets wrong silently.
///
/// Mutation proved: dropping either column from the INSERT leaves it NULL and
/// fails here; passing the classification through without reading the
/// manifest's kind fails the kind assertion.
#[test]
fn a_polled_event_carries_its_reviewed_kind_and_activity_time() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let payload = serde_json::json!({"id": "vendor-1", "updated_at": "2026-08-15T00:00:00Z"});
    let outcomes = store
        .commit_poll_success(
            "direct",
            "connection",
            &subscription.subscription_id,
            &serde_json::json!({"watermark_ms": 1, "watermark_id": "vendor-1"}),
            &[PollEventInput {
                vendor_event_id: "vendor-1",
                payload: &payload,
                observed_at_ms: 100,
                item_kind: Some("pull_request"),
                activity_at_ms: Some(1_755_000_000_000),
                actor: &ActorAttribution::NotEnriched,
            }],
            100,
            None,
        )
        .expect("commit poll");
    assert_eq!(outcomes.len(), 1, "the event must have been stored");

    let events = store
        .list_events("direct", None, None)
        .expect("list events");
    let event = events
        .iter()
        .find(|event| event.vendor_event_id.as_deref() == Some("vendor-1"))
        .expect("the stored event");
    assert_eq!(
        event.item_kind.as_deref(),
        Some("pull_request"),
        "the reviewed item kind must reach the consumer on the row"
    );
    assert_eq!(
        event.activity_at_ms,
        Some(1_755_000_000_000),
        "the parsed activity time must reach the consumer on the row"
    );
    // `kind` and `item_kind` answer DIFFERENT questions and must not be
    // confused: one says delivery-or-gap, the other says what the thing is.
    assert_eq!(event.kind, "event");
}

/// A project binding round-trips, and every way of saying "no project"
/// reads back as absence rather than as a project.
///
/// The absence legs are the load-bearing ones. A consumer routes on this
/// field and must be able to tell "route here" from "nobody decided", so an
/// empty string stored as a project would satisfy a presence check while
/// carrying no routing information -- worse than absence, because it passes
/// the gate that exists to catch absence.
///
/// Mutation proved: storing the raw string instead of normalising fails the
/// empty and whitespace legs; dropping the principal predicate fails the
/// cross-principal leg; returning true unconditionally fails the unknown-id
/// leg.
#[test]
fn a_subscription_project_binding_round_trips_and_absence_stays_absent() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let id = subscription.subscription_id.clone();
    let read = |store: &PlexusStore| {
        store
            .subscription("direct", &id)
            .expect("read subscription")
            .expect("row present")
            .project_id
    };

    // A fresh subscription carries no project: binding is a separate
    // operator act, so mint must not invent one.
    assert_eq!(read(&store), None, "a new subscription has no project");

    assert!(
        store
            .set_subscription_project("direct", &id, Some("proj_alpha"))
            .expect("set project"),
        "setting a project on an existing row must report a change"
    );
    assert_eq!(read(&store), Some("proj_alpha".to_string()));

    // Explicit clearing must be expressible: an operator who bound the wrong
    // project needs a way back to "undecided".
    assert!(store
        .set_subscription_project("direct", &id, None)
        .expect("clear project"));
    assert_eq!(read(&store), None, "clearing must restore absence");

    // An empty and a whitespace-only value are CLEARING, not projects named
    // "" and " ".
    for blank in ["", "   "] {
        store
            .set_subscription_project("direct", &id, Some("proj_beta"))
            .expect("re-set project");
        store
            .set_subscription_project("direct", &id, Some(blank))
            .expect("blank set");
        assert_eq!(
            read(&store),
            None,
            "a blank project id must clear rather than store {blank:?}"
        );
    }

    // Surrounding whitespace is trimmed rather than stored, so two operators
    // typing the same id with different spacing do not produce two projects.
    store
        .set_subscription_project("direct", &id, Some("  proj_gamma  "))
        .expect("padded set");
    assert_eq!(read(&store), Some("proj_gamma".to_string()));

    // Another principal cannot re-route this watch, and learns it changed
    // nothing rather than assuming success.
    assert!(
        !store
            .set_subscription_project("reserved:other", &id, Some("proj_hostile"))
            .expect("foreign set"),
        "another principal must not bind this subscription's project"
    );
    assert_eq!(
        read(&store),
        Some("proj_gamma".to_string()),
        "the foreign write must have left the binding untouched"
    );

    // An unknown subscription reports no change.
    assert!(
        !store
            .set_subscription_project("direct", "subscription_missing", Some("proj_x"))
            .expect("unknown set"),
        "an unknown subscription must report that nothing changed"
    );
}

/// An explicit delivery target round-trips without changing poll state.
///
/// Mutation proved: replacing the write with a success response fails the
/// stored-target check; dropping the principal predicate fails the foreign
/// write check; incrementing generation fails the in-flight comparison.
#[test]
fn a_subscription_delivery_target_is_clearable_scoped_and_generation_neutral() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let id = subscription.subscription_id;
    let read = |store: &PlexusStore| {
        store
            .subscription("direct", &id)
            .expect("read subscription")
            .expect("row present")
    };
    let in_flight_generation = read(&store).generation;

    assert!(store
        .set_subscription_deliver_to("direct", &id, Some("agent-delivery"))
        .expect("set delivery target"));
    assert_eq!(
        read(&store).deliver_to,
        Some("agent-delivery".to_string()),
        "setting a target must persist it on the subscription"
    );
    assert_eq!(
        store
            .list_subscriptions("direct", None, Some(&id))
            .expect("list subscription")[0]
            .deliver_to,
        Some("agent-delivery".to_string()),
        "the owner list must surface the explicit target"
    );
    assert_eq!(
        read(&store).generation,
        in_flight_generation,
        "a routing rebind must not invalidate an in-flight poll snapshot"
    );

    assert!(!store
        .set_subscription_deliver_to("reserved:other", &id, Some("agent-hostile"))
        .expect("foreign set"));
    assert_eq!(
        read(&store).deliver_to,
        Some("agent-delivery".to_string()),
        "a foreign principal must not re-route the subscription"
    );

    assert!(store
        .set_subscription_deliver_to("direct", &id, None)
        .expect("clear delivery target"));
    let cleared = read(&store);
    assert_eq!(cleared.deliver_to, None, "clearing must restore absence");
    assert_eq!(
        cleared.generation, in_flight_generation,
        "clearing routing metadata must keep an in-flight poll valid"
    );
    assert!(!store
        .set_subscription_deliver_to("direct", "subscription_missing", Some("agent-x"))
        .expect("unknown subscription"));
}

/// An actor source round-trips independently of the watched connection, can
/// be cleared, and is scoped to the subscription owner.
///
/// The generation assertion fences the independent-authorization property:
/// removing it from the UPDATE is the mutation that must stay green, while
/// adding `generation = generation + 1` fails here. The principal and clear
/// arms fail if their predicates or NULL write are dropped.
#[test]
fn a_subscription_actor_source_is_clearable_scoped_and_generation_neutral() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let id = subscription.subscription_id;
    let source = ActorSource {
        connection_id: "conn-github-comments".to_string(),
        action: "issue_read".to_string(),
        methods: vec!["get_comments".to_string()],
    };
    let read = |store: &PlexusStore| {
        store
            .subscription("direct", &id)
            .expect("read subscription")
            .expect("row present")
    };
    let generation = read(&store).generation;

    assert!(store
        .set_subscription_actor_source("direct", &id, Some(&source))
        .expect("set actor source"));
    let stored = read(&store);
    assert_eq!(stored.actor_source, Some(source.clone()));
    assert_eq!(
        stored.generation, generation,
        "an independently authorized binding must not invalidate the watch"
    );

    assert!(!store
        .set_subscription_actor_source("reserved:other", &id, None)
        .expect("foreign clear"));
    assert_eq!(
        read(&store).actor_source,
        Some(source),
        "another principal must not clear the binding"
    );

    assert!(store
        .set_subscription_actor_source("direct", &id, None)
        .expect("clear actor source"));
    let cleared = read(&store);
    assert_eq!(cleared.actor_source, None);
    assert_eq!(cleared.generation, generation);
    assert!(!store
        .set_subscription_actor_source(
            "direct",
            "subscription_missing",
            Some(&ActorSource {
                connection_id: "conn-missing".to_string(),
                action: "issue_read".to_string(),
                methods: vec!["get_comments".to_string()],
            }),
        )
        .expect("unknown set"));
}

/// A consume grant's action selectors decide what crosses, so a grant naming
/// a DIFFERENT action exposes nothing.
///
/// Two arms over one subscription rather than two subscriptions with
/// different actions: the shared fixture declares one pollable read action,
/// and widening it to suit this test would change a fixture many other tests
/// depend on. The discriminating property is the same either way -- identical
/// setup, one selector changed, opposite outcome -- which is what a single
/// arm could never show, since seeing nothing is also what a broken
/// implementation returns.
#[test]
fn a_consume_grant_admits_only_the_actions_it_names() {
    let mint = |store: &PlexusStore, selector: &str, now: i64| {
        store
            .insert_grant(&GrantInput {
                grant_id: format!("grant-consume-{selector}"),
                principal: "direct".to_string(),
                connection_id: "connection".to_string(),
                grantee_principal: "reserved:consumer".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec![selector.to_string()],
                authority_kind: crate::governance::AUTHORITY_EVENTS_CONSUME.to_string(),
                expires_at: Some(now + 60_000),
            })
            .expect("mint consume grant");
    };
    let seed = |store: &PlexusStore| {
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription");
        store
            .insert_event(
                "direct",
                "connection",
                &subscription.subscription_id,
                "vendor-1",
                &serde_json::json!({"id": "vendor-1"}),
                100,
            )
            .expect("insert event");
    };

    // ARM A: the grant names the subscription's action.
    let matching = trigger_store(crate::governance::AUTHORITY_POLL);
    seed(&matching);
    let now = now_ms();
    mint(&matching, "read_action", now);
    assert_eq!(
        matching
            .list_events_including_granted("reserved:consumer", None, None, now)
            .expect("list")
            .len(),
        1,
        "a grant naming the action must admit its events"
    );

    // ARM B: identical in every respect except the selector.
    let mismatched = trigger_store(crate::governance::AUTHORITY_POLL);
    seed(&mismatched);
    mint(&mismatched, "write_action", now);
    assert!(
        mismatched
            .list_events_including_granted("reserved:consumer", None, None, now)
            .expect("list")
            .is_empty(),
        "a grant naming a different action must admit nothing"
    );
}

#[test]
fn an_empty_consume_grant_exposes_no_events_but_a_matching_grant_does() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = read_subscription(&store);
    store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-empty-selector",
            &serde_json::json!({"private": true}),
            now_ms(),
        )
        .expect("insert event");
    let now = now_ms();
    insert_grant_with_selectors_for_test(
        &store,
        "grant-consume-empty",
        "reserved:consumer",
        &[],
        crate::governance::AUTHORITY_EVENTS_CONSUME,
    );
    assert!(store
        .list_events_including_granted("reserved:consumer", None, None, now)
        .expect("empty-selector event list")
        .is_empty());

    insert_grant_with_selectors_for_test(
        &store,
        "grant-consume-matching",
        "reserved:consumer",
        &["read_action"],
        crate::governance::AUTHORITY_EVENTS_CONSUME,
    );
    assert_eq!(
        store
            .list_events_including_granted("reserved:consumer", None, None, now)
            .expect("matching-selector event list")
            .len(),
        1
    );
}

#[test]
fn an_empty_consume_grant_exposes_no_subscriptions_but_a_matching_grant_does() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = read_subscription(&store);
    let now = now_ms();
    insert_grant_with_selectors_for_test(
        &store,
        "grant-consume-empty",
        "reserved:consumer",
        &[],
        crate::governance::AUTHORITY_EVENTS_CONSUME,
    );
    assert!(store
        .list_subscriptions_including_granted("reserved:consumer", None, None, now)
        .expect("empty-selector subscription list")
        .is_empty());

    insert_grant_with_selectors_for_test(
        &store,
        "grant-consume-matching",
        "reserved:consumer",
        &["read_action"],
        crate::governance::AUTHORITY_EVENTS_CONSUME,
    );
    let listed = store
        .list_subscriptions_including_granted("reserved:consumer", None, None, now)
        .expect("matching-selector subscription list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].subscription_id, subscription.subscription_id);
}

/// Acknowledging an edited delivery retains its body and content hash, so
/// replaying that exact version remains a duplicate.
///
/// Clearing `payload_hash` on acknowledgement would let the same version
/// insert again. Writing a coverage gap instead of an edited event would
/// leave no edited delivery to acknowledge.
#[test]
fn acked_edited_delivery_retains_payload_and_preserves_version_dedupe() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let original = serde_json::json!({"value": 1, "id": "vendor-1"});
    let edited = serde_json::json!({"value": 2, "id": "vendor-1"});
    store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &original,
            100,
        )
        .expect("insert original");
    let edited_event_id = match store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &edited,
            200,
        )
        .expect("insert edited delivery")
    {
        TriggerEventInsertOutcome::Inserted { event_id } => event_id,
        outcome => panic!("expected edited insertion, got {outcome:?}"),
    };
    let edited_hash = crate::jcs::jcs_sha256(&edited).expect("test payload is JCS-compatible");

    assert_eq!(
        store
            .ack_events("direct", std::slice::from_ref(&edited_event_id))
            .expect("ack edit"),
        1
    );
    let stored: (String, String) = store
        .inner
        .with_conn(|conn| {
            conn.query_row(
                "SELECT payload, payload_hash FROM trigger_events WHERE event_id = ?1",
                [&edited_event_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .expect("read acked edited row");
    assert_eq!(
        stored.0,
        serde_json::to_string(&edited).unwrap(),
        "ack retains an edited event payload"
    );
    assert_eq!(
        stored.1, edited_hash,
        "ack retains the content hash used by versioned dedupe"
    );

    match store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &edited,
            300,
        )
        .expect("re-observe edited payload")
    {
        TriggerEventInsertOutcome::Duplicate {
            event_id,
            payload_hash,
        } => {
            assert_eq!(event_id, edited_event_id);
            assert_eq!(payload_hash, edited_hash);
        }
        outcome => panic!("acked identical edit must dedupe, got {outcome:?}"),
    }
}

/// A pruned unacked event leaves a gap marker naming the interval and a
/// machine-readable reason.
///
/// Mutation proved: removing the `insert_gap_row` call from `prune` would
/// drop uncollected events silently, making the log lie by omission. This
/// test fails the moment that gap recording is removed.
#[test]
fn pruned_unacked_event_leaves_a_gap_marker() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    // Insert an event with a known observed_at_ms so the gap interval is
    // deterministic.
    store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "vendor-1",
            &serde_json::json!({"id": "vendor-1"}),
            500,
        )
        .expect("event");
    // Age the event past the prune cutoff.
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE trigger_events SET created_at_ms = ?1
                 WHERE subscription_id = ?2 AND vendor_event_id = 'vendor-1'",
                (
                    now_ms() - 8 * AUDIT_MILLIS_PER_DAY,
                    &subscription.subscription_id,
                ),
            )?;
            Ok(())
        })
        .expect("age event");
    let _removed = store
        .prune("direct", &subscription.subscription_id, 1_000, 100)
        .expect("prune");
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("events after prune");
    let gap = events
        .iter()
        .find(|event| event.kind == "gap")
        .expect("a gap marker was recorded for the pruned event");
    assert_eq!(
        gap.gap_reason.as_deref(),
        Some("retention_pruned"),
        "the gap carries a machine-readable retention reason"
    );
    assert_eq!(
        gap.gap_from_ms,
        Some(500),
        "the gap interval starts at the pruned event's observed_at_ms"
    );
    assert_eq!(
        gap.gap_to_ms,
        Some(500),
        "the gap interval ends at the pruned event's observed_at_ms"
    );
}

/// A recent unacked event survives pruning and is still delivered by
/// `list`. This is the survival direction: a suite where every vector
/// expects removal cannot distinguish a real implementation from one that
/// deletes everything.
#[test]
fn recent_unacked_event_survives_prune_and_is_delivered() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let payload = serde_json::json!({"id": "fresh", "value": 42});
    store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "fresh",
            &payload,
            now_ms(),
        )
        .expect("fresh event");
    // Prune with a tight row ceiling (1) and an age bound tight relative to
    // production (30 days) but far larger than scheduling jitter.
    //
    // THE AGE BOUND WAS 1ms AND THAT MADE THIS TEST A COIN FLIP. The event is
    // stamped `now_ms()` and pruned a few statements later, so a 1ms bound
    // asserts that fewer than one millisecond of wall clock passes between an
    // insert and a prune on a machine running the rest of the suite in
    // parallel. It held when this test ran alone and failed in a full
    // test-suite run, which is the signature of a threshold below scheduling
    // granularity rather than of a real defect.
    //
    // Sixty seconds keeps the property under test intact -- an event far
    // newer than the cutoff must survive -- while putting the margin beyond
    // anything a loaded scheduler produces. The count leg is unchanged: one
    // row against a ceiling of one must also survive, which is what stops
    // this from passing merely because the age bound is now generous.
    const RECENT_ENOUGH_MS: i64 = 60_000;
    let removed = store
        .prune("direct", &subscription.subscription_id, RECENT_ENOUGH_MS, 1)
        .expect("prune");
    assert_eq!(removed, 0, "nothing was removed");
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("events");
    assert_eq!(events.len(), 1, "the fresh unacked event survives");
    assert_eq!(events[0].vendor_event_id.as_deref(), Some("fresh"));
    assert_eq!(
        events[0].payload, payload,
        "the payload is intact and delivered"
    );
}

/// A prune failure after a successful commit does not turn a successful
/// poll into a failed one. `commit_poll_success` has already made the
/// events and cursor durable, so `PollCycle::Completed` is the truthful
/// description of what happened — not `StoreFailed`.
///
/// Mutation proved: replacing the swallowed prune error with
/// `return PollCycle::StoreFailed { ... }` makes this test fail, because a
/// poll that genuinely completed would be reported as store-failing.
///
/// Vacuity guard proved: ageing the event to only 10 seconds (inside the
/// 30-day cutoff) makes the pre-check FAIL LOUDLY, because prune has
/// nothing to delete at the poll path's real parameters and returns Ok.
/// The pre-check uses the SAME parameters the poll path uses
/// (`UNACKED_MAX_AGE_MS`, `UNACKED_MAX_ROWS`), and the ageing is derived
/// from `UNACKED_MAX_AGE_MS + 1 day` so the two cannot drift apart.
///
/// The prune failure is induced by a SQLite trigger that raises an error
/// on DELETE from `trigger_events`, installed after the store is set up
/// but before the poll. `commit_poll_success` does only INSERTs and
/// UPDATEs, so it is unaffected; `prune` does DELETEs, so it fails. This
/// is a real database-level constraint, not a mock — the store genuinely
/// cannot trim rows, which is the condition under which the guard matters.
#[test]
fn prune_failure_after_commit_does_not_fail_the_poll_cycle() {
    // Build a sync_token store with a credentialed connection, mirroring
    // the poll_engine helper in poller.rs but from this module so the
    // test can access `store.inner` to install the trigger.
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!(
            "prune-fail-test-{}-{}",
            now_ms(),
            TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    };
    let store = PlexusStore::open(&descriptor).expect("open store");
    store
        .insert_connection(
            "direct",
            "connection",
            "poll_fixture",
            "pending",
            &serde_json::json!({}),
        )
        .expect("insert connection");
    let manifest = serde_json::json!({
        "schema_version": 1,
        "key": "poll_fixture",
        "name": "Poll fixture",
        "description": "manifest used by the prune-failure test",
        "reuse_path": "deep_wrapper",
        "reuse_rationale": "test",
        "tier": "S2",
        "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
        "auth": {"mode": "api_key"},
        "credential_bindings": [{
            "ref_role": "api_key",
            "placement": "header",
            "key": "Authorization",
            "prefix": "Bearer ",
            "required": true
        }],
        "resource_filters": {"required": [], "optional": [], "write_enabling": []},
        "actions_baseline": [{
            "name": "read_action",
            "risk": "read",
            "poll": {"item_kind": "issue", "cursor_kind": "sync_token"}
        }],
        "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 60}},
        "availability": "ga"
    });
    let manifest = crate::manifest::ingest_value(manifest).expect("manifest");
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest)
        .expect("store manifest");
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "connection".to_string(),
            principal: "direct".to_string(),
            name: "read_action".to_string(),
            title: Some("read_action".to_string()),
            schema: serde_json::json!({"type": "object"}),
            schema_hash: "hash-read".to_string(),
            risk: "read".to_string(),
            severity: "S2".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("catalog action");
    let handle = b"test:test-handle";
    let ticket = store
        .create_binding_ticket_bounded(
            "direct",
            "connection",
            "credential_reference",
            handle,
            &Ceiling::unrestricted_for_tests(),
        )
        .expect("binding ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("connect")
        .expect("connection activated");
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-poll".to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "write".to_string(),
            action_selectors: vec!["*".to_string()],
            authority_kind: crate::governance::AUTHORITY_POLL.to_string(),
            expires_at: Some(now_ms() + 60_000),
        })
        .expect("poll grant");
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    // Pre-load one event and age it past the prune cutoff the poll path
    // actually uses, so prune will try to delete it during the poll cycle
    // (otherwise prune succeeds trivially by deleting nothing and the test
    // proves nothing). The ageing is derived from the constant itself so
    // the two cannot drift apart.
    store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "old-event",
            &serde_json::json!({"id": "old-event"}),
            now_ms(),
        )
        .expect("pre-load event");
    let one_day_ms = 24 * 60 * 60 * 1000;
    let aged_ms = now_ms() - (crate::poller::UNACKED_MAX_AGE_MS + one_day_ms);
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE trigger_events SET created_at_ms = ?1
                 WHERE subscription_id = ?2 AND vendor_event_id = 'old-event'",
                (aged_ms, &subscription.subscription_id),
            )?;
            Ok(())
        })
        .expect("age event");
    // Install a trigger that makes DELETE from trigger_events fail. This
    // is the real, honest way to induce a prune-only failure: the trigger
    // is a database-level constraint, not a mock. `commit_poll_success`
    // does only INSERTs and UPDATEs, so it is unaffected; `prune` does
    // DELETEs, so it fails.
    store
        .inner
        .with_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER prevent_delete
                 BEFORE DELETE ON trigger_events
                 BEGIN
                     SELECT RAISE(ABORT, 'delete prevented');
                 END",
            )?;
            Ok(())
        })
        .expect("install trigger");
    // Verify the trigger actually makes prune fail AT THE SAME PARAMETERS
    // the poll path uses, so the test is not vacuously green — a prune that
    // succeeds would mean either the trigger does nothing or prune has
    // nothing to delete at these parameters, and in both cases the
    // assertion below proves nothing.
    assert!(
        store
            .prune(
                "direct",
                &subscription.subscription_id,
                crate::poller::UNACKED_MAX_AGE_MS,
                crate::poller::UNACKED_MAX_ROWS,
            )
            .is_err(),
        "the trigger must make prune fail at the poll path's real parameters; \
         otherwise this test proves nothing"
    );
    let store = std::sync::Arc::new(store);
    let credentials = crate::StubCredentialSource::default();
    credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
    let transport = crate::MockTransport::default();
    transport.set_response(crate::MockResponse::Success(serde_json::json!({
        "items": [{"id": "new-1", "title": "first"}],
        "next_cursor": "tok-1"
    })));
    let engine = crate::GovernanceEngine::new(
        store.clone(),
        std::sync::Arc::new(credentials),
        std::sync::Arc::new(transport),
    );
    let poller = crate::poller::Poller::new(engine);
    let cycle = poller.poll_once("direct", &subscription.subscription_id);
    // The poll completed: the vendor answered, the cursor advanced, the
    // event was committed. A prune failure must not change this outcome.
    // Mutation proved: returning StoreFailed on prune error makes this
    // assertion fail.
    match cycle {
        crate::poller::PollCycle::Completed {
            inserted,
            duplicates,
        } => {
            assert_eq!(inserted, 1, "one event was inserted");
            assert_eq!(duplicates, 0);
        }
        other => panic!("a prune failure must not turn a successful poll into {other:?}"),
    }
    // The event the poll committed is durable despite the prune failure.
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("list events");
    assert!(
        events
            .iter()
            .any(|event| event.vendor_event_id.as_deref() == Some("new-1")),
        "the committed event is present despite the prune failure"
    );
}

fn register_probe_on(
    store: &PlexusStore,
    registrant: &str,
    actions: &[&str],
    rearm: &str,
    cursor_state: &Value,
) -> Result<TriggerSubscription, SubscriptionRefusal> {
    store
        .register_probe(
            registrant,
            "connection",
            ProbeRegistration {
                name: "watch",
                actions: &actions
                    .iter()
                    .map(|action| action.to_string())
                    .collect::<Vec<_>>(),
                script_source: "() => true",
                return_schema: &serde_json::json!({"kind": "bool"}),
                rearm,
                cadence_s: 30,
                fixed_args: &serde_json::json!({}),
                cursor_state,
            },
        )
        .expect("register_probe store")
}

/// A return schema outside the closed grammar is refused AT REGISTRATION.
///
/// This fences the delegation to `plexus_probe`'s validator. Without it the
/// validator can be neutered with every other probe test still green — which
/// was true when this test was written, and is why it exists: an earlier
/// revision re-encoded the caps here instead of delegating, and nothing
/// asserted either copy actually refused anything.
///
/// The consequence of a missed refusal is worse than a late error. A schema
/// accepted here fails at POLL time as `probe_return_invalid`, which
/// deliberately does not retire the watch — so the subscription lives
/// forever, polls forever, and never delivers.
#[test]
fn probe_registration_refuses_a_return_schema_outside_the_grammar() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let over_cap = serde_json::json!({"kind": "string", "max_len": 4096});
    let refusal = store
        .register_probe(
            "direct",
            "connection",
            ProbeRegistration {
                name: "watch",
                actions: &["read_action".to_string()],
                script_source: "() => \"x\"",
                return_schema: &over_cap,
                rearm: "always",
                cadence_s: 30,
                fixed_args: &serde_json::json!({}),
                cursor_state: &serde_json::json!({}),
            },
        )
        .expect("register_probe store call succeeds with a typed refusal");
    assert!(
        refusal.is_err(),
        "a 4096-byte string cap is outside the grammar and must be refused: {refusal:?}"
    );

    // The positive arm, so this cannot pass by refusing everything.
    let within = serde_json::json!({"kind": "string", "max_len": 256});
    let accepted = store
        .register_probe(
            "direct",
            "connection",
            ProbeRegistration {
                name: "watch-ok",
                actions: &["read_action".to_string()],
                script_source: "() => \"x\"",
                return_schema: &within,
                rearm: "always",
                cadence_s: 30,
                fixed_args: &serde_json::json!({}),
                cursor_state: &serde_json::json!({}),
            },
        )
        .expect("register_probe store call");
    assert!(
        accepted.is_ok(),
        "a schema at the cap is inside the grammar and must be accepted: {accepted:?}"
    );
}

#[test]
fn probe_registration_rejects_an_empty_grant_but_accepts_a_matching_grant() {
    let empty = trigger_store(crate::governance::AUTHORITY_POLL);
    assert!(empty
        .revoke_grant("direct", "grant-poll")
        .expect("remove fixture grant"));
    insert_grant_with_selectors_for_test(
        &empty,
        "grant-poll-empty",
        "direct",
        &[],
        crate::governance::AUTHORITY_POLL,
    );
    assert_eq!(
        register_probe_on(
            &empty,
            "direct",
            &["read_action"],
            "always",
            &serde_json::json!({})
        )
        .expect_err("an empty grant must authorize no probe actions"),
        SubscriptionRefusal::ActionNotCoveredByGrant {
            action: "read_action".to_string(),
        }
    );

    let matching = trigger_store(crate::governance::AUTHORITY_POLL);
    assert!(register_probe_on(
        &matching,
        "direct",
        &["read_action"],
        "always",
        &serde_json::json!({}),
    )
    .is_ok());
}

/// Registration mints nothing: an action outside the grant is refused.
///
/// Mutation-proved: dropping the coverage check accepts this call, and the
/// assertion that it is refused fails.
#[test]
fn probe_registration_refuses_an_action_outside_the_grant() {
    // Narrow the grant to one action so the second is a real miss, not a
    // wildcard that would make this test pass for the wrong reason.
    let store = {
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!(
                "probe-grant-{}-{}",
                now_ms(),
                TRIGGER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
            ),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: crate::test_scratch::store_path(),
            },
        };
        let store = PlexusStore::open(&descriptor).expect("open");
        store
            .insert_connection(
                "direct",
                "connection",
                "trigger_fixture",
                "active",
                &serde_json::json!({}),
            )
            .expect("connection");
        let manifest = crate::manifest::ingest_value(trigger_manifest()).expect("manifest");
        store
            .upsert_manifest(CATALOG_PRINCIPAL, &manifest)
            .expect("manifest");
        for name in ["read_action", "other_read"] {
            store
                .upsert_catalog_action(&CatalogActionInput {
                    connection_id: "connection".to_string(),
                    principal: "direct".to_string(),
                    name: name.to_string(),
                    title: Some(name.to_string()),
                    schema: serde_json::json!({"type": "object", "properties": {}}),
                    schema_hash: format!("hash-{name}"),
                    risk: "read".to_string(),
                    severity: "S2".to_string(),
                    ask_first: false,
                    status: "active".to_string(),
                    quarantine_reason: None,
                    reconciliation: None,
                })
                .expect("catalog");
        }
        store
            .insert_grant(&GrantInput {
                grant_id: "grant-narrow".to_string(),
                principal: "direct".to_string(),
                connection_id: "connection".to_string(),
                grantee_principal: "module:prefrontal".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["read_action".to_string()],
                authority_kind: crate::governance::AUTHORITY_POLL.to_string(),
                expires_at: Some(now_ms() + 60_000),
            })
            .expect("narrow grant");
        store
    };
    let refusal = register_probe_on(
        &store,
        "module:prefrontal",
        &["read_action", "other_read"],
        "always",
        &serde_json::json!({}),
    )
    .expect_err("an action outside the grant must be refused");
    assert_eq!(
        refusal,
        SubscriptionRefusal::ActionNotCoveredByGrant {
            action: "other_read".to_string(),
        }
    );
    assert!(
        store
            .list_subscriptions("direct", None, None)
            .expect("list")
            .is_empty(),
        "a refused registration must not leave a row"
    );
}

/// A, B, A is three real transitions when the watch is seeded, and the
/// second A must deliver. Value-only identity is swallowed by the shipped
/// uniqueness constraint; the ordinal in the event id is what keeps the
/// third insert distinct.
///
/// Mutation-proved: removing the ordinal from event identity makes the
/// third commit a duplicate and this count fails.
#[test]
fn probe_a_b_a_delivers_three_times_when_seeded() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = register_probe_on(
        &store,
        "direct",
        &["read_action"],
        "always",
        &serde_json::json!({"baseline": "seed", "observation_ordinal": 0}),
    )
    .expect("register");
    let strategy = crate::poller::ProbeStrategy;
    let mut state = subscription.cursor_state.clone();
    let mut inserted = 0;
    for value in ["A", "B", "A"] {
        let advance = strategy
            .derive(&state, &serde_json::json!(value))
            .expect("derive");
        assert_eq!(
            advance.events.len(),
            1,
            "seeded A, B, A must each differ from the previous baseline"
        );
        let inputs: Vec<PollEventInput<'_>> = advance
            .events
            .iter()
            .map(|event| PollEventInput {
                vendor_event_id: event.vendor_event_id.as_str(),
                payload: &event.payload,
                observed_at_ms: now_ms(),
                item_kind: Some("probe"),
                activity_at_ms: None,
                actor: &ActorAttribution::NotEnriched,
            })
            .collect();
        let outcomes = store
            .commit_probe_success(
                "direct",
                "connection",
                &subscription.subscription_id,
                &advance.cursor_state,
                &inputs,
                now_ms(),
                false,
            )
            .expect("commit");
        inserted += outcomes
            .iter()
            .filter(|outcome| matches!(outcome, TriggerEventInsertOutcome::Inserted { .. }))
            .count();
        state = advance.cursor_state;
    }
    assert_eq!(
        inserted, 3,
        "A, B, A must deliver three times; if the ordinal is dropped from \
         event identity the second A is a duplicate"
    );
}

/// An unchanged value still does not deliver. Without this, dropping the
/// baseline comparison (always emit) would pass any test that only checks
/// that changes deliver.
#[test]
fn an_unchanged_probe_value_does_not_deliver() {
    let strategy = crate::poller::ProbeStrategy;
    let first = strategy
        .derive(&serde_json::json!({}), &serde_json::json!("A"))
        .expect("baseline");
    assert!(
        first.events.is_empty(),
        "the first unseeded observation is a baseline, not an event"
    );
    let again = strategy
        .derive(&first.cursor_state, &serde_json::json!("A"))
        .expect("unchanged");
    assert!(
        again.events.is_empty(),
        "re-observing the same value must not deliver"
    );
    let changed = strategy
        .derive(&again.cursor_state, &serde_json::json!("B"))
        .expect("changed");
    assert_eq!(changed.events.len(), 1, "a real change must still deliver");
}

/// Retirement is inside the fenced transaction with the insert. A failed
/// event write must roll the retirement back; otherwise a crash between
/// insert and retire is expressible as "retired with no event" or, if the
/// order flips, as a one-shot that can fire twice.
///
/// Mutation-proved: moving retire to a second transaction after a successful
/// cursor UPDATE (and before the insert) leaves the row retired when this
/// insert fails.
#[test]
fn once_retirement_rolls_back_when_the_event_write_fails() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let subscription = register_probe_on(
        &store,
        "direct",
        &["read_action"],
        "once",
        &serde_json::json!({"baseline": "seed"}),
    )
    .expect("register");
    let payload = serde_json::json!("A");
    let result = store.commit_probe_success(
        "direct",
        "connection",
        &subscription.subscription_id,
        &serde_json::json!({"baseline": "A", "observation_ordinal": 1}),
        &[PollEventInput {
            vendor_event_id: "",
            payload: &payload,
            observed_at_ms: now_ms(),
            item_kind: Some("probe"),
            activity_at_ms: None,
            actor: &ActorAttribution::NotEnriched,
        }],
        now_ms(),
        true,
    );
    assert!(result.is_err(), "a blank vendor id must abort the commit");
    let stored = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read")
        .expect("still present");
    assert_eq!(
        stored.status, "active",
        "retirement must roll back with the failed insert"
    );
    assert!(
        store
            .list_events("direct", None, Some(&subscription.subscription_id))
            .expect("events")
            .is_empty(),
        "no event may survive a rolled-back once fire"
    );
}

/// An unreadable random source must stop the mint rather than fall back to
/// an id built from guessable inputs such as the clock and the process id.
#[test]
fn new_id_refuses_to_mint_when_the_random_source_fails() {
    let outcome = std::panic::catch_unwind(|| {
        new_id_from("ticket", |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no random device",
            ))
        })
    });
    let panic = outcome.expect_err("an unreadable random source must stop the mint");
    let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        message.contains("refusing to mint a guessable ticket id"),
        "{message}"
    );
}

/// Random ids have no time component; consecutive calls must be distinct
/// without waiting for a pair to happen inside one clock tick.
#[test]
fn random_ids_from_consecutive_calls_are_distinct() {
    let first = new_id("event");
    let second = new_id("event");
    assert_ne!(first, second);
    assert!(first.starts_with("event_") && second.starts_with("event_"));
}
