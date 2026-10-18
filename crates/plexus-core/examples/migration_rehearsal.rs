//! Apply the shipped migrations to a COPY of a real store and report what moved.
//!
//! Exists because a migration that rebuilds a table cannot be judged from its SQL
//! alone. The question is not "is this SQL correct" but "do THIS store's rows
//! survive it", and the only honest answer comes from running it against those
//! rows. Row counts before and after are the check, because a rebuild that
//! silently drops or duplicates rows is exactly the failure a migration reporting
//! success would hide.
//!
//! TAKES A PATH, with no default, and always creates a private SQLite backup
//! before seeding or migrating anything. The source is opened read-only, so a
//! rehearsal cannot become a deployment by accidentally naming the live store.
//!
//! Row counts alone are not sufficient and are not trusted here. A migration that
//! never ran would also report every count unchanged, so newly required schema
//! properties are asserted directly.

use std::collections::BTreeMap;

const USAGE: &str = "usage: migration_rehearsal <store-copy.db> [--seed-declared-changes] | --backup-live <live-store.db>";

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect(USAGE);
    if path == "--backup-live" {
        let live = args.next().expect("--backup-live requires the source path");
        assert!(args.next().is_none(), "unexpected argument; {USAGE}");
        backup_live(&live);
        return;
    }
    match args.next().as_deref() {
        None => backup_live(&path),
        Some("--seed-declared-changes") => {
            assert!(args.next().is_none(), "unexpected argument; {USAGE}");
            backup_live_with_seed(&path, true);
        }
        Some(other) => panic!("unknown argument {other:?}; {USAGE}"),
    }
}

/// A migration that changes the row count of an existing table on purpose.
///
/// The rehearsal predicts that count by running `expected_after_sql` against
/// the copy BEFORE migrating, and a table that ends at exactly the predicted
/// count is reported as a declared change instead of drift. A declared table
/// that ends at any other count is drift, and so is any change to a table no
/// entry declares. A store already at or past `migration` declares nothing.
struct DeclaredChange {
    migration: i64,
    table: &'static str,
    expected_after_sql: &'static str,
    why: &'static str,
}

const DECLARED_CHANGES: &[DeclaredChange] = &[
    DeclaredChange {
        migration: 48,
        table: "recipient_allowlist",
        // Each owner-less row becomes one row per principal owning a connection
        // with its id; a row whose connection no longer exists is dropped.
        expected_after_sql: "SELECT COUNT(*) FROM (
            SELECT DISTINCT c.principal, r.connection_id, r.agent_id, r.recipient
            FROM recipient_allowlist r JOIN connections c ON c.connection_id = r.connection_id)",
        why: "each recipient list copied to every owner of its connection id",
    },
    DeclaredChange {
        migration: 49,
        table: "policies",
        expected_after_sql: "SELECT COUNT(*) FROM (
            SELECT DISTINCT principal, connection_id, action_selector FROM policies)",
        why: "duplicate policy scopes resolved to the lowest policy id",
    },
];

/// The declared after-count of each table this run's migrations change on
/// purpose, computed from the unmigrated copy.
fn declared_expectations(
    path: &str,
    version_before: i64,
    before: &BTreeMap<String, i64>,
) -> BTreeMap<&'static str, (i64, &'static DeclaredChange)> {
    let conn = open_existing(path).expect("open the copy for expectations");
    DECLARED_CHANGES
        .iter()
        .filter(|change| version_before < change.migration && before.contains_key(change.table))
        .map(|change| {
            let expected: i64 = conn
                .query_row(change.expected_after_sql, [], |row| row.get(0))
                .unwrap_or_else(|error| {
                    panic!("migration {} expectation: {error}", change.migration)
                });
            (change.table, (expected, change))
        })
        .collect()
}

/// How one table's row count moved, and whether that move is drift.
fn row_verdict(
    table: &str,
    before: Option<i64>,
    after: i64,
    declared: Option<&(i64, &DeclaredChange)>,
) -> (String, bool) {
    let Some(before) = before else {
        return ("created".to_string(), false);
    };
    match declared {
        Some((expected, change)) if after == *expected => (
            if before == after {
                format!("same (migration {} declares {expected})", change.migration)
            } else {
                format!(
                    "changed as declared by migration {}: {}",
                    change.migration, change.why
                )
            },
            false,
        ),
        Some((expected, change)) => (
            format!(
                "CHANGED: migration {} declares {expected}",
                change.migration
            ),
            true,
        ),
        None if before == after => ("same".to_string(), false),
        // The migration ledger grows with every migration applied.
        None if table == "cortexkit_schema_version" => ("CHANGED".to_string(), false),
        None => ("CHANGED".to_string(), true),
    }
}

/// Seed the copy with a row of every kind migrations 48 and 49 change, so the
/// rehearsal exercises them even when the store being copied has none: a
/// connection id shared by two owners with a module-only and an agent
/// recipient, a single-owner recipient, a recipient of a deleted connection,
/// and two duplicated policy scopes. Rows are added only to the copy.
fn seed_declared_variants(path: &str) {
    assert!(
        (43..48).contains(&version(path)),
        "seeding writes pre-48 recipient rows into the table migration 43 creates; this copy is at {}",
        version(path)
    );
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
            .expect("open existing private copy to seed");
    conn.execute_batch(
        r#"
INSERT OR IGNORE INTO connections (connection_id, principal, app_key, status, resource_filters, created_at_ms, updated_at_ms)
    VALUES ('rehearsal-shared', 'direct', 'rehearsal', 'active', '{}', 1, 1),
           ('rehearsal-shared', 'rehearsal-owner-b', 'rehearsal', 'active', '{}', 1, 1),
           ('rehearsal-solo', 'direct', 'rehearsal', 'active', '{}', 1, 1);
INSERT INTO recipient_allowlist (connection_id, agent_id, recipient)
    VALUES ('rehearsal-shared', NULL, 'alice@example.com'),
           ('rehearsal-shared', 'rehearsal-agent', 'bob@example.com'),
           ('rehearsal-solo', NULL, 'carol@example.com'),
           ('rehearsal-gone', NULL, 'dave@example.com');
INSERT INTO policies (policy_id, principal, connection_id, action_selector, effect, updated_at_ms)
    VALUES ('rehearsal-policy-a', 'direct', 'rehearsal-solo', 'send', 'allow', 1),
           ('rehearsal-policy-b', 'direct', 'rehearsal-solo', 'send', 'block', 1),
           ('rehearsal-policy-c', 'direct', 'rehearsal-solo', 'read', 'allow', 1),
           ('rehearsal-policy-d', 'direct', 'rehearsal-solo', 'read', 'ask_first', 1),
           ('rehearsal-policy-e', 'direct', 'rehearsal-solo', 'read', 'block', 1);
"#,
    )
    .expect("seed the declared variants");
    println!("  seeded: 2 owners of rehearsal-shared, 4 recipient rows, 5 policies in 2 scopes");
}

fn prepare_backup(copy: &plexus_core::test_scratch::Scratch) {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::set_permissions(
            copy.owned_directory(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("private backup directory");
        options.mode(0o600);
    }
    options
        .open(copy.path())
        .expect("create private backup output");
}

fn backup_live(live: &str) {
    backup_live_with_seed(live, false);
}

fn backup_live_with_seed(live: &str, seed: bool) {
    let copy = private_source_copy(live);
    println!(
        "  rehearsing sqlite3 .backup copy: {}",
        copy.path().display()
    );
    run_with(copy.path().to_str().expect("UTF-8 scratch copy"), seed);
}

fn private_source_copy(live: &str) -> plexus_core::test_scratch::Scratch {
    let source = open_existing(live).expect("source must be an existing readable SQLite store");
    drop(source);
    let copy = plexus_core::test_scratch::Scratch::database("migration45-live-backup");
    prepare_backup(&copy);
    let output = bounded_output(
        std::process::Command::new("sqlite3")
            .arg("-readonly")
            .arg(live)
            .arg(format!(".backup '{}'", copy.path().display())),
    );
    assert!(
        output.status.success(),
        "sqlite3 .backup: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    copy
}

#[cfg(test)]
fn run(path: &str) {
    run_with(path, false);
}

fn open_existing(path: &str) -> rusqlite::Result<rusqlite::Connection> {
    rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
}

fn run_with(path: &str, seed: bool) {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .try_init()
        .expect("install migration rehearsal stderr subscriber");

    if seed {
        seed_declared_variants(path);
    }
    let before = counts(path);
    let version_before = version(path);
    let declared = declared_expectations(path, version_before, &before);
    let preexisting_events: i64 = before.get("trigger_events").copied().unwrap_or(0);
    let snapshots: Vec<_> = ["trigger_subscriptions", "trigger_events"]
        .into_iter()
        .map(|table| (table, row_snapshot(path, table, None)))
        .collect();

    // Opened through PlexusStore rather than by replaying the SQL by hand, so the
    // rehearsal exercises the real migration path. A hand-replayed copy proves
    // the SQL works and says nothing about the code that chooses to run it.
    let descriptor = cortexkit_store_types::StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: "rehearsal".to_string(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: path.to_string(),
        },
    };
    let store = plexus_core::PlexusStore::open(&descriptor).expect("migrations must apply");
    drop(store);

    let after = counts(path);
    let version_after = version(path);
    for (table, (columns, rows)) in &snapshots {
        assert_eq!(
            row_snapshot(path, table, Some(columns)).1,
            *rows,
            "migration changed existing values in {table}"
        );
    }

    println!("  schema version: {version_before} -> {version_after}");
    let mut drift = 0;
    for (table, &a) in &after {
        let (verdict, drifted) = row_verdict(
            table,
            before.get(table).copied(),
            a,
            declared.get(table.as_str()),
        );
        drift += usize::from(drifted);
        let b = before.get(table).copied().unwrap_or(0);
        println!("  {table:<22} {b:>7} -> {a:<7} {verdict}");
    }

    let conn = open_existing(path).expect("reopen the copy");
    let null_keys: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM trigger_events WHERE event_key IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let outbox_depth: i64 = conn
        .query_row("SELECT COUNT(*) FROM event_outbox", [], |r| r.get(0))
        .unwrap();
    println!("  pre-existing event rows: {preexisting_events}; NULL event_key rows: {null_keys}");
    println!("  outbox depth: {outbox_depth}");
    if version_before < 44 {
        assert_eq!(
            null_keys, preexisting_events,
            "existing events must not be backfilled"
        );
        assert_eq!(outbox_depth, 0, "migration must not create notices");
    }
    assert!(
        conn.prepare("SELECT connection_id, agent_id, recipient FROM recipient_allowlist")
            .is_ok(),
        "migration 43 must create the recipient allowlist"
    );
    println!("  recipient_allowlist present: true");
    let grants_ddl: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='grants'",
            [],
            |row| row.get(0),
        )
        .expect("read the grants schema");
    println!(
        "  grants admits events_consume: {}",
        grants_ddl.contains("events_consume")
    );
    // Prepared rather than selected, so an empty table still answers the
    // question. A SELECT returning no rows cannot distinguish "column missing"
    // from "table empty".
    println!(
        "  trigger_subscriptions.project_id present: {}",
        conn.prepare("SELECT project_id FROM trigger_subscriptions LIMIT 1")
            .is_ok()
    );
    let project_source_present = conn
        .prepare("SELECT project_source FROM trigger_subscriptions LIMIT 1")
        .is_ok();
    let invalid_sources: i64 = conn.query_row(
        "SELECT COUNT(*) FROM trigger_subscriptions WHERE (project_id IS NULL) != (project_source IS NULL)
         OR (project_source IS NOT NULL AND project_source NOT IN ('hand','entorhinal'))", [], |row| row.get(0)).unwrap();
    assert!(
        project_source_present && invalid_sources == 0,
        "project provenance must be consistent"
    );
    let actor_source_present = conn
        .prepare("SELECT actor_source_json FROM trigger_subscriptions LIMIT 1")
        .is_ok();
    println!("  trigger_subscriptions.actor_source_json present: {actor_source_present}");
    let deliver_to_present = conn
        .prepare("SELECT deliver_to FROM trigger_subscriptions LIMIT 1")
        .is_ok();
    println!("  trigger_subscriptions.deliver_to present: {deliver_to_present}");
    let agent_attribution_columns_present = conn
        .prepare("SELECT agent_id, agent_handle FROM audit_journal LIMIT 1")
        .is_ok();
    println!(
        "  audit_journal agent attribution columns present: {agent_attribution_columns_present}"
    );
    let subscriptions_ddl: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='trigger_subscriptions'",
            [],
            |row| row.get(0),
        )
        .expect("read the subscriptions schema");
    println!(
        "  trigger_subscriptions admits probe: {}",
        subscriptions_ddl.contains("'probe'")
    );
    assert!(
        subscriptions_ddl.contains("'ci_runs'"),
        "cursor CHECK must admit ci_runs"
    );
    let stamped: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM trigger_subscriptions WHERE project_id IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    if stamped > 0 {
        assert!(
            conn.execute(
                "UPDATE trigger_subscriptions SET project_id=NULL WHERE project_id IS NOT NULL",
                []
            )
            .is_err(),
            "project provenance trigger must reject mismatched project/source pairs"
        );
    }
    println!("  trigger_subscriptions admits ci_runs: true");
    println!(
        "  trigger_subscriptions admits retired: {}",
        subscriptions_ddl.contains("'retired'")
    );
    println!(
        "  probe_subscriptions present: {}",
        conn.prepare("SELECT name FROM probe_subscriptions LIMIT 1")
            .is_ok()
    );
    // Prepared rather than selected so an empty catalog still proves the column
    // that preserves the schema before a quarantine exists after migration.
    println!(
        "  catalog_actions.reviewed_schema_json present: {}",
        conn.prepare("SELECT reviewed_schema_json FROM catalog_actions LIMIT 1")
            .is_ok()
    );
    let event_dedupe_sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'index'
             AND name = 'idx_trigger_events_dedupe'",
            [],
            |row| row.get(0),
        )
        .expect("read trigger-event dedupe index");
    println!(
        "  trigger-event dedupe includes payload_hash: {}",
        event_dedupe_sql
            .contains("(connection_id, subscription_id, vendor_event_id, payload_hash)")
    );
    let actor_logins_present = conn
        .prepare("SELECT actor_logins FROM trigger_events LIMIT 1")
        .is_ok();
    println!("  trigger_events.actor_logins present: {actor_logins_present}");
    let actor_unknown_reason_present = conn
        .prepare("SELECT actor_unknown_reason FROM trigger_events LIMIT 1")
        .is_ok();
    println!("  trigger_events.actor_unknown_reason present: {actor_unknown_reason_present}");
    let settled_outcome_present = conn
        .prepare("SELECT settled_outcome FROM action_requests LIMIT 1")
        .is_ok();
    println!("  action_requests.settled_outcome present: {settled_outcome_present}");
    for (index, predicate) in [
        (
            "idx_event_outbox_pending_v1",
            "WHERE published_at_ms IS NULL",
        ),
        (
            "idx_event_outbox_pending_v2",
            "WHERE envelope_v2 IS NOT NULL AND published_v2_at_ms IS NULL",
        ),
        (
            "idx_github_receipts_pending_lease",
            "WHERE state = 'pending'",
        ),
        (
            "idx_github_receipts_terminal_updated",
            "WHERE state IN ('completed','refused')",
        ),
        (
            "idx_trigger_subscriptions_active_due",
            "WHERE status = 'active'",
        ),
    ] {
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
                [index],
                |r| r.get(0),
            )
            .expect("migration 50 index must exist");
        assert!(sql.contains(predicate), "{index} must be partial: {sql}");
        println!("  migration 50 partial index: {index}");
    }
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("run the integrity check");
    println!("  integrity_check: {integrity}");
    assert!(
        settled_outcome_present && integrity == "ok",
        "the settled-outcome column must exist and the copy must pass its integrity check"
    );
    assert!(
        actor_source_present
            && actor_logins_present
            && actor_unknown_reason_present
            && deliver_to_present
            && agent_attribution_columns_present,
        "actor enrichment, delivery routing, and additive agent attribution columns must exist after rehearsal"
    );
    println!("  tables with row drift: {drift}");
    assert_eq!(drift, 0, "domain row counts must not drift");
    drop(conn);
    let store = plexus_core::PlexusStore::open(&descriptor).expect("second migration run");
    assert_eq!(
        counts(path),
        after,
        "second migration run must change no row count"
    );
    drop(store);
    // Count markers directly to check the upgrade without loading event bodies.
    if version_before < 44 {
        let conn = rusqlite::Connection::open(path).expect("reopen the copy");
        let pending: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM event_outbox WHERE published_at_ms IS NULL",
                [],
                |row| row.get(0),
            )
            .expect("count unpublished outbox markers");
        assert_eq!(
            pending, 0,
            "the first drain after the upgrade must publish nothing"
        );
        println!("  first drain notices: 0");
    }
    assert_eq!(version(path), version_after);
    println!("  second migration run: unchanged");
}

fn row_snapshot(
    path: &str,
    table: &str,
    columns: Option<&[String]>,
) -> (Vec<String>, Vec<Vec<rusqlite::types::Value>>) {
    let conn = open_existing(path).unwrap();
    let columns = columns.map(|columns| columns.to_vec()).unwrap_or_else(|| {
        conn.prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    });
    let select = columns
        .iter()
        .map(|name| format!("\"{}\"", name.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(",");
    let order = (1..=columns.len())
        .map(|column| column.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let rows = conn
        .prepare(&format!("SELECT {select} FROM {table} ORDER BY {order}"))
        .unwrap()
        .query_map([], |r| (0..columns.len()).map(|i| r.get(i)).collect())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    (columns, rows)
}

#[path = "../tests/support/bounded.rs"]
mod bounded_child;

/// A stuck backup or child test is a failed rehearsal, not an unbounded wait.
fn bounded_output(command: &mut std::process::Command) -> std::process::Output {
    bounded_child::child_output(
        command,
        std::time::Duration::from_secs(30),
        "migration rehearsal",
    )
    .expect("rehearsal child output")
}

fn version(path: &str) -> i64 {
    open_existing(path)
        .expect("open the copy")
        .query_row(
            "SELECT MAX(version) FROM cortexkit_schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0)
}

fn counts(path: &str) -> BTreeMap<String, i64> {
    let conn = open_existing(path).expect("open the copy for counts");
    // Enumerate every table, including SQLite and migration metadata: a new
    // table must appear in the report without anyone updating a manual list.
    let tables = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let escaped = table.replace('"', "\"\"");
            let count = conn
                .query_row(&format!("SELECT COUNT(*) FROM \"{escaped}\""), [], |row| {
                    row.get(0)
                })
                .unwrap();
            (table, count)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_mistyped_source_path_is_never_created() {
        let missing = Scratch::file("missing-rehearsal-source", "absent.db");
        assert!(open_existing(missing.path().to_str().unwrap()).is_err());
        assert!(!missing.path().exists());
    }

    #[test]
    fn rehearsal_mutations_cannot_modify_the_source() {
        let source = Scratch::database("rehearsal-source");
        let connection = rusqlite::Connection::open(source.path()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sentinel (value TEXT); INSERT INTO sentinel VALUES ('original');",
            )
            .unwrap();
        drop(connection);
        let copy = private_source_copy(source.path().to_str().unwrap());
        let writable = rusqlite::Connection::open(copy.path()).unwrap();
        writable
            .execute("UPDATE sentinel SET value='mutated'", [])
            .unwrap();
        drop(writable);
        let original: String = open_existing(source.path().to_str().unwrap())
            .unwrap()
            .query_row("SELECT value FROM sentinel", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            original, "original",
            "rehearsals must mutate only their private backup"
        );
    }
    #[cfg(unix)]
    #[test]
    fn backup_output_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let copy = Scratch::database("private-backup");
        prepare_backup(&copy);
        assert_eq!(
            std::fs::metadata(copy.path()).unwrap().permissions().mode() & 0o777,
            0o600,
            "a live backup file must be mode 0600"
        );
        assert_eq!(
            std::fs::metadata(copy.owned_directory())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "a live backup directory must be mode 0700"
        );
    }

    #[test]
    fn composite_snapshot_survives_reordered_insertion() {
        let scratch = Scratch::database("composite-snapshot");
        let db = rusqlite::Connection::open(scratch.path()).unwrap();
        db.execute_batch("CREATE TABLE rows (id TEXT, owner TEXT); INSERT INTO rows VALUES ('same','b'),('same','a');").unwrap();
        let before = row_snapshot(scratch.path().to_str().unwrap(), "rows", None);
        db.execute_batch("DELETE FROM rows; INSERT INTO rows VALUES ('same','a'),('same','b');")
            .unwrap();
        assert_eq!(
            row_snapshot(scratch.path().to_str().unwrap(), "rows", None),
            before,
            "snapshot ordering must use every selected column"
        );
    }

    #[test]
    fn chatty_child_drains_stdout_and_stderr() {
        let output = bounded_output(Command::new("python3").args(["-c", "import sys; sys.stdout.buffer.write(b'x'*262144); sys.stderr.buffer.write(b'y'*262144)"]));
        assert!(
            output.status.success(),
            "chatty child must finish without blocking on pipes"
        );
        assert_eq!(output.stdout.len(), 262144);
        assert_eq!(output.stderr.len(), 262144);
    }

    use super::*;
    use plexus_core::test_scratch::Scratch;
    use std::process::Command;

    #[test]
    fn migration_42_rehearses_existing_hand_stamps_and_is_version_guarded() {
        const NAME: &str =
            "tests::migration_42_rehearses_existing_hand_stamps_and_is_version_guarded";
        const ENV: &str = "PLEXUS_REHEARSE_42";
        if let Ok(path) = std::env::var(ENV) {
            run(&path);
            return;
        }
        let scratch = Scratch::database("migration42-rehearsal");
        let descriptor = cortexkit_store_types::StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "rehearsal42".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        };
        let inner = cortexkit_store::open_sqlite(&descriptor).unwrap();
        let migrations = plexus_core::storage::MIGRATIONS;
        let boundary = migrations.iter().position(|m| m.version == 42).unwrap();
        inner.migrate("plexus", &migrations[..boundary]).unwrap();
        inner.with_conn_fenced(|conn| conn.execute_batch(
            "INSERT INTO trigger_subscriptions (subscription_id,principal,connection_id,action,cadence_s,cursor_kind,cursor_state,schema_hash,status,generation,created_at_ms,project_id)
             VALUES ('hand','direct','c','list_issues',300,'ordered_timestamp','{}','hash','active',0,1,'project'),
                    ('none','direct','c','list_pull_requests',300,'sorted_head','{}','hash','active',0,1,NULL);"
        )).unwrap();
        drop(inner);
        // The chain's head moves with every migration; derive it so a new
        // migration doesn't break a rehearsal of an older one.
        let head = migrations.last().unwrap().version;
        for expected in [format!("41 -> {head}"), format!("{head} -> {head}")] {
            let output = bounded_output(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", NAME, "--nocapture"])
                    .env(ENV, scratch.path()),
            );
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(stdout.contains(&expected), "{stdout}");
            // The migration ledger grows; existing domain tables do not.
            assert!(stdout.contains("tables with row drift: 0"), "{stdout}");
        }
        let conn = rusqlite::Connection::open(scratch.path()).unwrap();
        let rows = conn.prepare("SELECT subscription_id, project_source FROM trigger_subscriptions ORDER BY subscription_id").unwrap()
            .query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?))).unwrap()
            .collect::<Result<Vec<_>,_>>().unwrap();
        assert_eq!(
            rows,
            vec![("hand".into(), Some("hand".into())), ("none".into(), None)]
        );
        assert!(conn.execute("UPDATE trigger_subscriptions SET project_source='unknown' WHERE subscription_id='hand'",[]).is_err());
        assert!(conn
            .execute(
                "UPDATE trigger_subscriptions SET project_id=NULL WHERE subscription_id='hand'",
                []
            )
            .is_err());
    }

    const TEST_NAME: &str = "tests::ahead_store_warning_reaches_stderr";
    const CHILD_STORE: &str = "PLEXUS_MIGRATION_REHEARSAL_CHILD_STORE";

    #[test]
    fn ahead_store_warning_reaches_stderr() {
        if let Some(path) = std::env::var_os(CHILD_STORE) {
            run(path.to_str().expect("UTF-8 scratch store path"));
            return;
        }

        let path = Scratch::database("migration-rehearsal-ahead");
        let descriptor = cortexkit_store_types::StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: "rehearsal".to_string(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        };
        drop(plexus_core::PlexusStore::open(&descriptor).expect("create current store"));
        {
            let connection = rusqlite::Connection::open(path.path()).expect("open current store");
            let updated = connection
                .execute(
                    "INSERT INTO cortexkit_schema_version \
                     (namespace, version, applied_at_unix) VALUES ('plexus', 99, 0)",
                    [],
                )
                .expect("plant ahead-of-chain schema version");
            assert!(updated > 0, "schema ledger must contain a version row");
        }

        let output = bounded_output(
            Command::new(std::env::current_exe().expect("example test executable"))
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(CHILD_STORE, path.path()),
        );
        assert!(
            output.status.success(),
            "rehearsal fixture exited with {}; stdout: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8(output.stdout).expect("UTF-8 fixture stdout");
        assert!(stdout.contains("schema version: 99 -> 99"), "{stdout}");
        assert!(stdout.contains("1 passed"), "fixture did not run: {stdout}");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 fixture stderr");
        assert!(
            stderr.contains("store schema is ahead of this binary"),
            "warning did not reach stderr: {stderr}"
        );
    }
}

#[cfg(test)]
mod declared_change_tests {
    use super::*;

    /// A change a migration declares passes only at the predicted count; any
    /// other change to an existing table is drift.
    #[test]
    fn only_a_declared_change_at_its_predicted_count_is_not_drift() {
        let change = &DECLARED_CHANGES[0];
        let declared = (5, change);
        assert!(!row_verdict("recipient_allowlist", Some(4), 5, Some(&declared)).1);
        assert!(!row_verdict("recipient_allowlist", Some(5), 5, Some(&declared)).1);
        assert!(
            row_verdict("recipient_allowlist", Some(4), 6, Some(&declared)).1,
            "a declared table ending at another count is drift"
        );
        assert!(
            row_verdict("recipient_allowlist", Some(4), 4, Some(&declared)).1,
            "a declared change that did not happen is drift"
        );
        assert!(
            row_verdict("grants", Some(4), 3, None).1,
            "an undeclared change is drift"
        );
        assert!(!row_verdict("grants", Some(4), 4, None).1);
        assert!(!row_verdict("cortexkit_schema_version", Some(25), 27, None).1);
        assert!(!row_verdict("new_table", None, 3, None).1);
        let mut tables: Vec<&str> = DECLARED_CHANGES.iter().map(|change| change.table).collect();
        tables.sort_unstable();
        tables.dedup();
        assert_eq!(
            tables.len(),
            DECLARED_CHANGES.len(),
            "one declaration per table, or their predictions would not compose"
        );
    }

    /// A copy at schema 47 seeded with every kind of row migrations 48 and 49
    /// change rehearses to the declared counts with no drift.
    #[test]
    fn seeded_changes_of_migrations_48_and_49_are_declared_not_drift() {
        const NAME: &str =
            "declared_change_tests::seeded_changes_of_migrations_48_and_49_are_declared_not_drift";
        const ENV: &str = "PLEXUS_REHEARSE_DECLARED_CHANGES";
        if let Ok(path) = std::env::var(ENV) {
            run_with(&path, true);
            return;
        }
        let scratch = plexus_core::test_scratch::Scratch::database("declared-changes");
        let inner = cortexkit_store::open_sqlite(&cortexkit_store_types::StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "declared-changes".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap();
        let migrations = plexus_core::MIGRATIONS;
        let boundary = migrations.iter().position(|m| m.version == 48).unwrap();
        inner.migrate("plexus", &migrations[..boundary]).unwrap();
        drop(inner);
        let output = bounded_output(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture"])
                .env(ENV, scratch.path()),
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for expected in [
            "changed as declared by migration 48",
            "changed as declared by migration 49",
            "tables with row drift: 0",
            "second migration run: unchanged",
        ] {
            assert!(stdout.contains(expected), "{expected}: {stdout}");
        }
        let conn = rusqlite::Connection::open(scratch.path()).unwrap();
        let count = |sql: &str| -> i64 { conn.query_row(sql, [], |row| row.get(0)).unwrap() };
        assert_eq!(count("SELECT COUNT(*) FROM recipient_allowlist"), 5);
        assert_eq!(count("SELECT COUNT(*) FROM policies"), 2);
    }
}

#[cfg(test)]
mod seeded_rehearsal_tests {
    use super::*;

    #[test]
    fn seeded_schema_49_backup_rehearses_migration_50_without_row_drift() {
        const NAME: &str = "seeded_rehearsal_tests::seeded_schema_49_backup_rehearses_migration_50_without_row_drift";
        const ENV: &str = "PLEXUS_SEEDED_49_BACKUP";
        if let Ok(path) = std::env::var(ENV) {
            backup_live(&path);
            return;
        }
        let scratch = plexus_core::test_scratch::Scratch::database("seeded-schema-49");
        let inner = cortexkit_store::open_sqlite(&cortexkit_store_types::StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "seeded-schema-49".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap();
        let migrations = plexus_core::MIGRATIONS;
        let boundary = migrations.iter().position(|m| m.version == 50).unwrap();
        inner.migrate("plexus", &migrations[..boundary]).unwrap();
        inner.with_conn_fenced(|conn| conn.execute_batch("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<25000)
            INSERT INTO trigger_events(event_id,principal,connection_id,subscription_id,vendor_event_id,payload_hash,payload,kind,observed_at_ms,created_at_ms)
            SELECT printf('%064x',i),'direct','a','a',CAST(i AS TEXT),'hash','{}','event',i,i FROM n;
            INSERT INTO event_outbox(event_key,event_id,event_name,repo_id,repo,created_at_ms,published_at_ms,envelope_v2,digest_v2,published_v2_at_ms)
            SELECT event_id,event_id,'github_issue_changed',101,'owner/repo',created_at_ms,1,'{}','digest',1 FROM trigger_events;")).unwrap();
        drop(inner);
        let before = counts(scratch.path().to_str().unwrap());
        let output = bounded_output(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture"])
                .env(ENV, scratch.path()),
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        // The chain runs to the newest migration, so the expected head comes
        // from the migration list; a later migration must not break this test.
        let head = format!(
            "schema version: 49 -> {}",
            plexus_core::MIGRATIONS.last().unwrap().version
        );
        for expected in [
            head.as_str(),
            "migration 50 partial index: idx_event_outbox_pending_v1",
            "migration 50 partial index: idx_event_outbox_pending_v2",
            "tables with row drift: 0",
            "second migration run: unchanged",
        ] {
            assert!(stdout.contains(expected), "{expected}: {stdout}");
        }
        println!("{stdout}");
        assert_eq!(
            version(scratch.path().to_str().unwrap()),
            49,
            "rehearsal must migrate only the backup copy"
        );
        assert_eq!(counts(scratch.path().to_str().unwrap()), before);
    }

    #[test]
    fn seeded_schema_43_backup_preserves_all_cursor_rows_and_project_triggers() {
        const NAME: &str = "seeded_rehearsal_tests::seeded_schema_43_backup_preserves_all_cursor_rows_and_project_triggers";
        const ENV: &str = "PLEXUS_SEEDED_43_BACKUP";
        if let Ok(path) = std::env::var(ENV) {
            backup_live(&path);
            return;
        }
        let scratch = plexus_core::test_scratch::Scratch::database("seeded-schema-43");
        let descriptor = cortexkit_store_types::StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "seeded-schema-43".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        };
        let inner = cortexkit_store::open_sqlite(&descriptor).unwrap();
        let migrations = plexus_core::MIGRATIONS;
        let boundary = migrations.iter().position(|m| m.version == 44).unwrap();
        inner.migrate("plexus", &migrations[..boundary]).unwrap();
        inner.with_conn_fenced(|conn| {
            for kind in ["sync_token", "ordered_timestamp", "snapshot_diff", "scalar_diff", "sorted_head", "probe"] {
                conn.execute("INSERT INTO trigger_subscriptions
                    (subscription_id, principal, connection_id, action, cadence_s, cursor_kind, cursor_state, schema_hash, status,
                     created_at_ms, project_id, project_source, actor_source_json, deliver_to, fixed_args)
                    VALUES (?1, 'direct', 'github', 'list_issues', 300, ?1, '{\"watermark_ms\":9}', 'hash', 'active',
                        1, 'project', 'hand', '{\"action\":\"comments\"}', 'agent', '{\"owner\":\"owner\",\"repo\":\"repo\"}')", [kind])?;
                conn.execute("INSERT INTO trigger_events
                    (event_id, principal, connection_id, subscription_id, vendor_event_id, payload_hash, payload, kind, observed_at_ms, created_at_ms)
                    VALUES (?1, 'direct', 'github', ?1, '7', 'hash', '{\"number\":7}', 'event', 2, 3)", [kind])?;
            }
            assert!(conn.execute("UPDATE trigger_subscriptions SET project_id=NULL WHERE subscription_id='probe'", []).is_err());
            Ok(())
        }).unwrap();
        drop(inner);
        let before = counts(scratch.path().to_str().unwrap());
        let output = bounded_output(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture"])
                .env(ENV, scratch.path()),
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let head = format!(
            "schema version: 43 -> {}",
            migrations.last().unwrap().version
        );
        for expected in [
            head.as_str(),
            "pre-existing event rows: 6; NULL event_key rows: 6",
            "outbox depth: 0",
            "first drain notices: 0",
            "tables with row drift: 0",
            "second migration run: unchanged",
        ] {
            assert!(stdout.contains(expected), "{stdout}");
        }
        println!("{stdout}");
        assert_eq!(
            version(scratch.path().to_str().unwrap()),
            43,
            "backup must not migrate source"
        );
        assert_eq!(counts(scratch.path().to_str().unwrap()), before);
    }
}
