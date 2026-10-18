//! Deleting connections: the one-time purge of revoked connections and
//! expired grants (migration version 40), and the operator's
//! `PlexusStore::delete_connection`.

use std::collections::BTreeMap;

use cortexkit_store_types::Isolation;
use rusqlite::{params, Connection};

use super::*;
use crate::test_scratch::Scratch;

/// Tables that hold a connection's rows but are not in
/// [`CONNECTION_KEYED_TABLES`]: the connection row itself, the audit trail and
/// historical allowance usage that `delete_connection` keeps, and the handle
/// table whose connections it refuses.
const KEPT_OR_REFUSED: [&str; 5] = [
    "connections",
    "audit_journal",
    "grant_revocations",
    "github_app_handle",
    "web_search_allowance_counts",
];

// Migration 40 deleted from the tables that existed at that schema version.
// Test it with this historical list, not today's connection-delete table list,
// which includes tables added by later migrations.
const MIGRATION_40_KEYED_TABLES: &[(&str, &str)] = &[
    ("probe_subscriptions", "subscription_id IN (SELECT subscription_id FROM trigger_subscriptions WHERE principal = ?1 AND connection_id = ?2)"),
    ("trigger_events", "principal = ?1 AND connection_id = ?2"),
    ("trigger_subscriptions", "principal = ?1 AND connection_id = ?2"),
    ("catalog_actions", "principal = ?1 AND connection_id = ?2"),
    ("grants", "principal = ?1 AND connection_id = ?2"),
    ("policies", "principal = ?1 AND connection_id = ?2"),
    ("action_requests", "principal = ?1 AND connection_id = ?2"),
    ("reservations", "principal = ?1 AND connection_id = ?2"),
    ("binding_tickets", "principal = ?1 AND connection_id = ?2"),
    ("write_reconciliation_results", "principal = ?1 AND connection_id = ?2"),
    ("pending_write_reconciliations", "principal = ?1 AND CASE WHEN json_valid(record_json) THEN json_extract(record_json, '$.connection_id') END = ?2"),
];

fn memory_descriptor(label: &str) -> StorageDescriptor {
    StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!("{label}-{}", new_id("ns")),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: ":memory:".into(),
        },
    }
}

fn file_descriptor(path: &std::path::Path) -> StorageDescriptor {
    StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!("connection-delete-{}", new_id("ns")),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    }
}

/// The chain up to and including version 39, the store shape before the purge.
fn before_purge() -> &'static [Migration] {
    &MIGRATIONS[..purge_position()]
}

/// The chain up to and including the purge itself, so the test applies exactly
/// migration 40 however many migrations are added after it.
fn through_purge() -> &'static [Migration] {
    &MIGRATIONS[..=purge_position()]
}

fn purge_position() -> usize {
    MIGRATIONS
        .iter()
        .position(|migration| migration.version == 40)
        .expect("the purge is migration version 40")
}

/// One connection with one row in every table that can hold a connection's
/// rows. Ids are derived from the connection id so several connections can
/// be seeded side by side. `grant_expires_at` is the seeded grant's deadline
/// and `audit_ts` the seeded audit row's timestamp.
fn seed_connection(
    conn: &Connection,
    principal: &str,
    connection_id: &str,
    status: &str,
    grant_expires_at: Option<i64>,
    audit_ts: i64,
) -> rusqlite::Result<()> {
    let c = connection_id;
    // Fixtures for migration 40 lack the recipient table, which was added in
    // migration 43. When the table exists, seed an entry so the connection
    // deletion test proves that deleting a connection also removes its
    // recipient authority rather than leaving permission for a reused id.
    if conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE name='recipient_allowlist'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .is_some()
    {
        // From migration 48 on, each list belongs to the connection's owner.
        let owned: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('recipient_allowlist') WHERE name='principal')",
            [],
            |r| r.get(0),
        )?;
        if owned {
            conn.execute(
                "INSERT INTO recipient_allowlist (principal, connection_id, agent_id, recipient)
                 VALUES (?1, ?2, NULL, 'alice@example.com')",
                params![principal, c],
            )?;
        } else {
            conn.execute(
                "INSERT INTO recipient_allowlist VALUES (?1,NULL,'alice@example.com')",
                [c],
            )?;
        }
    }
    conn.execute(
        "INSERT INTO connections (connection_id, principal, app_key, status, created_at_ms,
             updated_at_ms) VALUES (?1, ?2, 'mock', ?3, 1, 1)",
        params![c, principal, status],
    )?;
    conn.execute(
        "INSERT INTO catalog_actions (connection_id, principal, name, schema_json, schema_hash,
             risk, severity, status, first_seen_at_ms, last_seen_at_ms)
         VALUES (?1, ?2, 'mock.read', '{}', 'h', 'read', 'low', 'active', 1, 1)",
        params![c, principal],
    )?;
    conn.execute(
        "INSERT INTO grants (grant_id, principal, connection_id, grantee_principal, risk_ceiling,
             authority_kind, expires_at, created_at_ms)
         VALUES ('grant-' || ?1, ?2, ?1, 'reserved:aft', 'read', 'invoke', ?3, 1)",
        params![c, principal, grant_expires_at],
    )?;
    conn.execute(
        "INSERT INTO policies (policy_id, principal, connection_id, action_selector, effect,
             updated_at_ms) VALUES ('policy-' || ?1, ?2, ?1, '*', 'allow', 1)",
        params![c, principal],
    )?;
    conn.execute(
        "INSERT INTO action_requests (request_id, principal, connection_id, action,
             args_snapshot, schema_hash, requester, status, expires_at, created_at_ms)
         VALUES ('request-' || ?1, ?2, ?1, 'mock.read', '{}', 'h', 'reserved:aft', 'pending',
             10, 1)",
        params![c, principal],
    )?;
    conn.execute(
        "INSERT INTO reservations (reservation_id, principal, connection_id, action,
             snapshot_generations, approved_args_hash, schema_hash, expires_at, status,
             created_at_ms)
         VALUES ('reservation-' || ?1, ?2, ?1, 'mock.read', '{}', 'h', 'h', 10, 'reserved', 1)",
        params![c, principal],
    )?;
    conn.execute(
        "INSERT INTO binding_tickets (ticket_id, principal, connection_id, ref_role, expires_at,
             status, created_at_ms)
         VALUES ('ticket-' || ?1, ?2, ?1, 'credential', 10, 'issued', 1)",
        params![c, principal],
    )?;
    conn.execute(
        "INSERT INTO trigger_subscriptions (subscription_id, principal, connection_id, action,
             cadence_s, cursor_kind, schema_hash, status, created_at_ms)
         VALUES ('subscription-' || ?1, ?2, ?1, 'mock.read', 60, 'probe', 'h', 'active', 1)",
        params![c, principal],
    )?;
    conn.execute(
        "INSERT INTO probe_subscriptions (subscription_id, name, actions, script_source,
             return_schema, rearm, registered_by)
         VALUES ('subscription-' || ?1, 'probe', '[\"mock.read\"]', '', '{}', 'always', ?2)",
        params![c, principal],
    )?;
    conn.execute(
        "INSERT INTO trigger_events (event_id, principal, connection_id, subscription_id,
             vendor_event_id, payload_hash, payload, kind, observed_at_ms, created_at_ms)
         VALUES ('event-' || ?1, ?2, ?1, 'subscription-' || ?1, 'vendor-1', 'h', '{}', 'event',
             1, 1)",
        params![c, principal],
    )?;
    if conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE name='event_outbox'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .is_some()
    {
        // Insert an outbox row so the connection-delete test must remove one;
        // checking an empty table would pass even if deletion were omitted.
        conn.execute("INSERT INTO event_outbox(event_key, event_id, event_name, repo_id, repo, created_at_ms)
            VALUES ('key-' || ?1, 'event-' || ?1, 'github_issue_changed', 101, 'owner/repo', 1)", [c])?;
    }
    conn.execute(
        "INSERT INTO write_reconciliation_results (principal, request_id, acting_principal,
             connection_id, action, status, updated_at_ms)
         VALUES (?2, 'reconciled-' || ?1, ?2, ?1, 'mock.write', 'confirmed', 1)",
        params![c, principal],
    )?;
    conn.execute(
        "INSERT INTO pending_write_reconciliations (principal, request_id, record_json,
             expires_at_ms)
         VALUES (?2, 'unknown-' || ?1,
             json_object('request_id', 'unknown-' || ?1, 'principal', ?2,
                 'acting_principal', ?2, 'actor', 'agent', 'connection_id', ?1,
                 'action', 'mock.write', 'args', json('{}'), 'occurred_at_ms', 1),
             10)",
        params![c, principal],
    )?;
    conn.execute(
        "INSERT INTO audit_journal (ts, principal, actor, acting_principal, connection_id,
             decision, reason_code)
         VALUES (?3, ?2, 'agent', ?2, ?1, 'allow', 'invoke')",
        params![c, principal, audit_ts],
    )?;
    conn.execute(
        "INSERT INTO grant_revocations (revocation_id, grant_id, principal, connection_id,
             grantee_principal, authority_kind, risk_ceiling, action_selectors, expires_at,
             generation, created_at_ms, revoked_at_ms, revoked_by)
         VALUES ('revocation-' || ?1, 'revoked-grant-' || ?1, ?2, ?1, 'reserved:aft', 'invoke',
             'read', '[]', NULL, 0, 1, 2, ?2)",
        params![c, principal],
    )?;
    Ok(())
}

/// Rows a connection owns, per table, including the connection row and the
/// tables `delete_connection` keeps.
fn rows_for(
    conn: &Connection,
    principal: &str,
    connection_id: &str,
) -> rusqlite::Result<BTreeMap<String, i64>> {
    rows_for_tables(conn, principal, connection_id, CONNECTION_KEYED_TABLES)
}

fn rows_for_v40(
    conn: &Connection,
    principal: &str,
    connection_id: &str,
) -> rusqlite::Result<BTreeMap<String, i64>> {
    rows_for_tables(conn, principal, connection_id, MIGRATION_40_KEYED_TABLES)
}

fn rows_for_tables(
    conn: &Connection,
    principal: &str,
    connection_id: &str,
    tables: &[(&str, &str)],
) -> rusqlite::Result<BTreeMap<String, i64>> {
    let mut rows = BTreeMap::new();
    let keyed = tables.iter().copied().chain([
        ("connections", "principal = ?1 AND connection_id = ?2"),
        ("audit_journal", "principal = ?1 AND connection_id = ?2"),
        ("grant_revocations", "principal = ?1 AND connection_id = ?2"),
    ]);
    for (table, keyed_by) in keyed {
        let count: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE {keyed_by}"),
            (principal, connection_id),
            |row| row.get(0),
        )?;
        rows.insert(table.to_string(), count);
    }
    Ok(rows)
}

fn triggers(conn: &Connection) -> rusqlite::Result<BTreeMap<String, String>> {
    let mut statement =
        conn.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' ORDER BY name")?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    rows.collect()
}

fn insert_handle(conn: &Connection, principal: &str, connection_id: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO github_app_handle (app_handle_id, agent_id, app_id, credential_reference,
             status, connection_principal, connection_id)
         VALUES ('handle-' || ?2, 'agent-' || ?2, 1, 'github_app:handle-' || ?2, 'enabled',
             ?1, ?2)",
        (principal, connection_id),
    )?;
    Ok(())
}

/// Every table that names a connection is either deleted by
/// `delete_connection` or deliberately kept or refused. A new table with a
/// `connection_id` column fails here until someone decides which.
#[test]
fn every_connection_keyed_table_is_deleted_or_deliberately_kept() {
    let conn = Connection::open_in_memory().unwrap();
    PlexusStore::apply_migrations(&conn).unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let mut with_connection_column = BTreeSet::new();
    for table in &tables {
        let columns: Vec<String> = conn
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        if columns.iter().any(|column| column == "connection_id") {
            with_connection_column.insert(table.clone());
        }
    }
    // Keyed by a connection without a `connection_id` column: a probe through
    // its subscription, a pending reconciliation through its JSON record.
    with_connection_column.insert("probe_subscriptions".to_string());
    with_connection_column.insert("pending_write_reconciliations".to_string());
    with_connection_column.insert("event_outbox".to_string());
    let accounted: BTreeSet<String> = CONNECTION_KEYED_TABLES
        .iter()
        .map(|(table, _)| *table)
        .chain(KEPT_OR_REFUSED)
        .map(str::to_string)
        .collect();
    assert_eq!(with_connection_column, accounted);
}

/// Migration 40 deletes every revoked connection with all of its rows,
/// including its audit and revocation rows, and every expired grant. Other
/// connections keep every row, a revoked connection a GitHub App handle names
/// is kept, and the delete triggers come back byte for byte and still refuse.
#[test]
fn migration_40_purges_revoked_connections_and_expired_grants_and_restores_the_triggers() {
    let store = open_sqlite(&memory_descriptor("migration-40")).unwrap();
    assert_eq!(
        store.migrate("plexus", before_purge()).unwrap().recorded,
        39
    );
    let recent = now_ms();
    store
        .with_conn(|conn| {
            seed_connection(conn, "direct", "conn-old-rest", "revoked", None, recent)?;
            seed_connection(conn, "direct", "conn-live", "active", None, recent)?;
            seed_connection(conn, "direct", "github-handle-h1", "revoked", None, recent)?;
            insert_handle(conn, "direct", "github-handle-h1")?;
            // One lapsed and one future grant on the connection that stays.
            conn.execute_batch(
                "INSERT INTO grants (grant_id, principal, connection_id, grantee_principal,
                     risk_ceiling, authority_kind, expires_at, created_at_ms)
                 VALUES ('grant-lapsed', 'direct', 'conn-live', 'direct', 'read', 'poll', 1, 1),
                        ('grant-future', 'direct', 'conn-live', 'direct', 'read', 'poll',
                         99999999999999, 1);",
            )
        })
        .unwrap();
    let (before_triggers, old_before, live_before, handle_before) = store
        .with_conn(|conn| {
            Ok((
                triggers(conn)?,
                rows_for_v40(conn, "direct", "conn-old-rest")?,
                rows_for_v40(conn, "direct", "conn-live")?,
                rows_for_v40(conn, "direct", "github-handle-h1")?,
            ))
        })
        .unwrap();
    assert!(
        old_before.values().all(|count| *count == 1),
        "{old_before:?}"
    );

    let outcome = store.migrate("plexus", through_purge()).unwrap();
    assert_eq!((outcome.applied, outcome.recorded), (1, 40));

    store
        .with_conn(|conn| {
            assert_eq!(
                triggers(conn)?,
                before_triggers,
                "every trigger's SQL must be byte-identical after the purge"
            );
            let old_after = rows_for_v40(conn, "direct", "conn-old-rest")?;
            assert!(
                old_after.values().all(|count| *count == 0),
                "a revoked connection kept rows: {old_after:?}"
            );
            let mut live_expected = live_before.clone();
            *live_expected.get_mut("grants").unwrap() -= 1;
            assert_eq!(rows_for_v40(conn, "direct", "conn-live")?, live_expected);
            let lapsed: i64 = conn.query_row(
                "SELECT COUNT(*) FROM grants WHERE grant_id = 'grant-lapsed'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(lapsed, 0, "an expired grant survived the purge");
            assert_eq!(
                rows_for_v40(conn, "direct", "github-handle-h1")?,
                handle_before,
                "a connection a GitHub App handle names must be kept"
            );
            let scratch_table: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_temp_master
                 WHERE name = 'migration_40_purged_connections'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(scratch_table, 0, "the purge left its working table behind");
            let audit = conn
                .execute(
                    "DELETE FROM audit_journal WHERE connection_id = 'conn-live'",
                    [],
                )
                .unwrap_err()
                .to_string();
            assert!(audit.contains("append-only"), "{audit}");
            let revocations = conn
                .execute("DELETE FROM grant_revocations", [])
                .unwrap_err()
                .to_string();
            assert!(revocations.contains("immutable"), "{revocations}");
            Ok(())
        })
        .unwrap();
}

/// A store migrated by `PlexusStore::open` whose grant revocation journal
/// still names grants of a purged connection opens cleanly and recreates
/// nothing for them, because replay acts only on a grant still in `grants`.
/// The journal also names a live grant of a kept connection, which replay
/// does revoke: that proves replay ran in this test.
#[test]
fn a_purged_store_with_a_grant_journal_opens_cleanly_and_recreates_nothing() {
    let scratch = Scratch::database("migration-40-journal");
    let descriptor = file_descriptor(scratch.path());
    let raw = open_sqlite(&descriptor).unwrap();
    raw.migrate("plexus", before_purge()).unwrap();
    raw.with_conn(|conn| {
        seed_connection(conn, "direct", "conn-old-rest", "revoked", None, 1)?;
        seed_connection(conn, "direct", "conn-live", "active", None, 1)?;
        // Restored from a backup taken before this grant's revocation: the
        // grant is back in `grants`, and the journal names it.
        conn.execute_batch(
            "INSERT INTO grants (grant_id, principal, connection_id, grantee_principal,
                 risk_ceiling, authority_kind, expires_at, created_at_ms)
             VALUES ('grant-restored', 'direct', 'conn-old-rest', 'direct', 'read', 'invoke',
                 NULL, 1);",
        )
    })
    .unwrap();
    drop(raw);
    let journal = scratch
        .path()
        .parent()
        .unwrap()
        .join(crate::grant_journal::NAME);
    std::fs::write(
        &journal,
        concat!(
            r#"{"principal":"direct","grant_id":"revoked-grant-conn-old-rest","revoked_at_ms":2}"#,
            "\n",
            r#"{"principal":"direct","grant_id":"grant-restored","revoked_at_ms":3}"#,
            "\n",
            r#"{"principal":"direct","grant_id":"grant-conn-live","revoked_at_ms":4}"#,
            "\n",
        ),
    )
    .unwrap();

    for open in ["migrating open", "second open"] {
        let store =
            PlexusStore::open(&descriptor).unwrap_or_else(|error| panic!("{open}: {error}"));
        store
            .inner
            .with_conn(|conn| {
                // Replay writes only `grants` and `grant_revocations`; the
                // connection row shows nothing else brought it back.
                let old = rows_for(conn, "direct", "conn-old-rest")?;
                for table in ["grants", "grant_revocations", "connections"] {
                    assert_eq!(
                        old[table], 0,
                        "{open}: replay recreated {table} rows of a purged connection"
                    );
                }
                let restored: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM grant_revocations WHERE grant_id = 'grant-restored'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(restored, 0, "{open}: a purged grant got a snapshot");
                let live = rows_for(conn, "direct", "conn-live")?;
                assert_eq!(
                    live["grants"], 0,
                    "{open}: replay did not revoke the live grant"
                );
                assert_eq!(
                    live["grant_revocations"], 2,
                    "{open}: the replayed revocation is recorded once, beside the seeded one"
                );
                assert_eq!(live["connections"], 1);
                assert_eq!(live["catalog_actions"], 1);
                Ok(())
            })
            .unwrap();
    }
}

/// `delete_connection` refuses while a grant is live and for a GitHub App
/// handle's connection; a dry run counts and writes nothing; an apply deletes
/// the connection and every row keyed by it, keeps its audit and revocation
/// rows, writes one audit row naming it, and leaves the sibling untouched.
#[test]
fn delete_connection_deletes_every_keyed_row_and_keeps_the_audit_trail() {
    let store = PlexusStore::open(&memory_descriptor("delete-connection")).unwrap();
    store
        .inner
        .with_conn(|conn| {
            // The audit row is far older than the 7 days inside which the
            // audit delete trigger refuses a delete, so the trigger would
            // allow deleting it; only `audit_journal`'s absence from
            // `CONNECTION_KEYED_TABLES` keeps it.
            seed_connection(conn, "direct", "conn-target", "revoked", Some(1), 1)?;
            seed_connection(conn, "direct", "conn-sibling", "active", None, 1)?;
            seed_connection(conn, "direct", "github-handle-x", "active", Some(1), 1)?;
            seed_connection(conn, "direct", "conn-backing-handle", "active", Some(1), 1)?;
            insert_handle(conn, "direct", "conn-backing-handle")?;
            conn.execute_batch(
                "INSERT INTO grants (grant_id, principal, connection_id, grantee_principal,
                     risk_ceiling, authority_kind, expires_at, created_at_ms)
                 VALUES ('grant-live', 'direct', 'conn-target', 'direct', 'read', 'invoke',
                     NULL, 1);",
            )
        })
        .unwrap();
    let snapshot = |connection_id: &str| {
        store
            .inner
            .with_conn(|conn| rows_for(conn, "direct", connection_id))
            .unwrap()
    };
    let target_before = snapshot("conn-target");
    let sibling_before = snapshot("conn-sibling");

    assert_eq!(
        store
            .delete_connection("direct", "conn-target", true)
            .unwrap(),
        DeleteConnectionOutcome::HasLiveGrants { count: 1 }
    );
    assert_eq!(snapshot("conn-target"), target_before);
    for handle in ["github-handle-x", "conn-backing-handle"] {
        assert_eq!(
            store.delete_connection("direct", handle, true).unwrap(),
            DeleteConnectionOutcome::HandleConnection,
            "{handle}"
        );
        assert_eq!(snapshot(handle)["connections"], 1, "{handle}");
    }
    assert_eq!(
        store
            .delete_connection("direct", "conn-missing", true)
            .unwrap(),
        DeleteConnectionOutcome::NotFound
    );

    assert!(store.revoke_grant("direct", "grant-live").unwrap());
    let target_before = snapshot("conn-target");
    let expected_rows: Vec<(&str, i64)> = CONNECTION_KEYED_TABLES
        .iter()
        .map(|(table, _)| (*table, 1))
        .collect();
    assert_eq!(
        store
            .delete_connection("direct", "conn-target", false)
            .unwrap(),
        DeleteConnectionOutcome::WouldDelete {
            app_key: "mock".into(),
            status: "revoked".into(),
            rows: expected_rows.clone(),
        }
    );
    assert_eq!(snapshot("conn-target"), target_before, "a dry run wrote");

    assert_eq!(
        store
            .delete_connection("direct", "conn-target", true)
            .unwrap(),
        DeleteConnectionOutcome::Deleted {
            app_key: "mock".into(),
            status: "revoked".into(),
            rows: expected_rows,
        }
    );
    let target_after = snapshot("conn-target");
    for (table, count) in &target_after {
        let expected = match table.as_str() {
            // The seeded row and the row recording this delete.
            "audit_journal" => target_before["audit_journal"] + 1,
            "grant_revocations" => target_before["grant_revocations"],
            _ => 0,
        };
        assert_eq!(*count, expected, "{table}: {target_after:?}");
    }
    assert_eq!(target_before["grant_revocations"], 2, "seeded plus revoked");
    let (reason, summary): (String, String) = store
        .inner
        .with_conn(|conn| {
            conn.query_row(
                "SELECT reason_code, args_redaction_summary FROM audit_journal
                 WHERE connection_id = 'conn-target' AND action = 'delete_connection'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap();
    assert_eq!(reason, "ceremony_delete_connection");
    assert!(summary.contains("status revoked"), "{summary}");
    assert!(summary.contains("catalog_actions=1"), "{summary}");
    assert_eq!(snapshot("conn-sibling"), sibling_before);
    assert_eq!(
        store
            .delete_connection("direct", "conn-target", true)
            .unwrap(),
        DeleteConnectionOutcome::NotFound,
        "a repeated delete finds nothing"
    );
}
