use super::*;
use crate::storage::MIGRATIONS;
use cortexkit_store::{open_sqlite, StorageDescriptor};
use cortexkit_store_types::{Isolation, StorageBackend};
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

// These are exact UTC month boundaries, not durations approximating a month.
const FEBRUARY: i64 = 1_706_745_600_000; // 2024-02-01T00:00:00Z
const MARCH: i64 = 1_709_251_200_000; // 2024-03-01T00:00:00Z

fn descriptor() -> StorageDescriptor {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "web-search-store-tests-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: ":memory:".into(),
        },
    }
}

fn store() -> PlexusStore {
    PlexusStore::open(&descriptor()).unwrap()
}

fn names(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn reserve(
    store: &PlexusStore,
    provider: &str,
    owner_principal: &str,
    at_ms: i64,
) -> WebSearchAllowanceReservation {
    let WebSearchAllowanceAdmission::Reserved(receipt) = store
        .reserve_web_search_allowance(provider, owner_principal, at_ms)
        .unwrap()
    else {
        panic!("expected a counted reservation");
    };
    receipt
}

#[test]
fn order_round_trips_replaces_and_clears_to_none() {
    let store = store();
    let first = names(&["tavily", "exa", "brave"]);
    let second = names(&["exa"]);
    assert_eq!(store.web_search_order().unwrap(), None);
    assert_eq!(store.clear_web_search_order().unwrap(), None);
    assert_eq!(store.set_web_search_order(&first).unwrap(), None);
    assert_eq!(store.web_search_order().unwrap(), Some(first.clone()));
    assert_eq!(store.set_web_search_order(&second).unwrap(), Some(first));
    assert_eq!(store.clear_web_search_order().unwrap(), Some(second));
    assert_eq!(store.web_search_order().unwrap(), None);
}

#[test]
fn order_rejects_empty_unknown_and_duplicate_names_without_writing() {
    let store = store();
    let valid = names(&["exa", "tavily"]);
    store.set_web_search_order(&valid).unwrap();
    for invalid in [
        names(&[]),
        names(&["EXA"]),
        names(&["exa_rest"]),
        names(&["exa", "exa"]),
        names(&["exa", "unknown"]),
    ] {
        assert!(store.set_web_search_order(&invalid).is_err(), "{invalid:?}");
        assert_eq!(store.web_search_order().unwrap(), Some(valid.clone()));
    }
}

#[test]
fn allowances_and_limits_support_every_provider_name() {
    let store = store();
    for provider in crate::web_search::providers::PROVIDER_NAMES {
        let name = provider.name;
        assert_eq!(store.web_search_allowance(name).unwrap(), None);
        assert_eq!(store.clear_web_search_allowance(name).unwrap(), None);
        assert_eq!(store.set_web_search_allowance(name, 1).unwrap(), None);
        assert_eq!(
            store.set_web_search_allowance(name, 10_000_000).unwrap(),
            Some(1)
        );
        assert_eq!(store.web_search_allowance(name).unwrap(), Some(10_000_000));
        for invalid in [0, 10_000_001, u32::MAX] {
            assert!(store.set_web_search_allowance(name, invalid).is_err());
            assert_eq!(store.web_search_allowance(name).unwrap(), Some(10_000_000));
        }
        assert_eq!(
            store.clear_web_search_allowance(name).unwrap(),
            Some(10_000_000)
        );
        assert_eq!(store.web_search_allowance(name).unwrap(), None);
        let limits = WebSearchLimits {
            per_caller_per_minute: 2,
            per_backend_per_minute: 20,
        };
        assert_eq!(store.set_web_search_limits(name, limits).unwrap(), None);
        assert_eq!(store.web_search_limits(name).unwrap(), Some(limits));
    }
    let order = crate::web_search::providers::PROVIDER_NAMES
        .iter()
        .map(|provider| provider.name.to_owned())
        .collect::<Vec<_>>();
    store.set_web_search_order(&order).unwrap();
    assert_eq!(store.web_search_order().unwrap(), Some(order));
}

#[test]
fn allowance_access_rejects_unknown_provider_names() {
    let store = store();
    for unknown in ["", "EXA", "exa_rest", "google"] {
        assert!(store.web_search_allowance(unknown).is_err());
        assert!(store.set_web_search_allowance(unknown, 2).is_err());
        assert!(store.clear_web_search_allowance(unknown).is_err());
        assert!(store
            .web_search_allowance_used(unknown, "owner", FEBRUARY)
            .is_err());
        assert!(store
            .reserve_web_search_allowance(unknown, "owner", FEBRUARY)
            .is_err());
    }
}

#[test]
fn reservation_stops_at_allowance_and_does_not_increment_when_exhausted() {
    let store = store();
    store.set_web_search_allowance("exa", 2).unwrap();
    reserve(&store, "exa", "owner", FEBRUARY);
    assert_eq!(
        store
            .web_search_allowance_used("exa", "owner", FEBRUARY)
            .unwrap(),
        1
    );
    reserve(&store, "exa", "owner", FEBRUARY);
    for _ in 0..3 {
        assert_eq!(
            store
                .reserve_web_search_allowance("exa", "owner", FEBRUARY)
                .unwrap(),
            WebSearchAllowanceAdmission::Exhausted
        );
        assert_eq!(
            store
                .web_search_allowance_used("exa", "owner", FEBRUARY)
                .unwrap(),
            2
        );
    }
}

#[test]
fn counts_are_per_provider_principal_and_calendar_month_utc() {
    let store = store();
    for provider in ["exa", "tavily"] {
        store.set_web_search_allowance(provider, 1).unwrap();
    }
    let feb = reserve(&store, "exa", "owner", MARCH - 1);
    assert_eq!(feb.month_utc, "2024-02");
    assert_eq!(
        store
            .web_search_allowance_used("exa", "owner", FEBRUARY)
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .web_search_allowance_used("exa", "other", FEBRUARY)
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .web_search_allowance_used("tavily", "owner", FEBRUARY)
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .web_search_allowance_used("exa", "owner", MARCH)
            .unwrap(),
        0
    );
    let march = reserve(&store, "exa", "owner", MARCH);
    assert_eq!(march.month_utc, "2024-03");
    reserve(&store, "exa", "other", FEBRUARY);
    reserve(&store, "tavily", "owner", FEBRUARY);
    for (provider, owner_principal, month) in [
        ("exa", "owner", FEBRUARY),
        ("exa", "owner", MARCH),
        ("exa", "other", FEBRUARY),
        ("tavily", "owner", FEBRUARY),
    ] {
        assert_eq!(
            store
                .web_search_allowance_used(provider, owner_principal, month)
                .unwrap(),
            1
        );
    }
    let december = reserve(&store, "exa", "owner", 1_735_689_600_000 - 1);
    let january = reserve(&store, "exa", "owner", 1_735_689_600_000);
    assert_eq!(december.month_utc, "2024-12");
    assert_eq!(january.month_utc, "2025-01");
}

#[test]
fn clearing_and_resetting_allowance_keeps_usage_and_does_not_affect_other_providers() {
    let store = store();
    store.set_web_search_allowance("exa", 2).unwrap();
    store.set_web_search_allowance("tavily", 7).unwrap();
    reserve(&store, "exa", "owner", FEBRUARY);
    reserve(&store, "exa", "owner", FEBRUARY);
    assert_eq!(store.clear_web_search_allowance("exa").unwrap(), Some(2));
    assert_eq!(
        store
            .web_search_allowance_used("exa", "owner", FEBRUARY)
            .unwrap(),
        2
    );
    assert_eq!(
        store
            .reserve_web_search_allowance("exa", "owner", FEBRUARY)
            .unwrap(),
        WebSearchAllowanceAdmission::Unlimited
    );
    assert_eq!(store.set_web_search_allowance("exa", 1).unwrap(), None);
    assert_eq!(
        store
            .reserve_web_search_allowance("exa", "owner", FEBRUARY)
            .unwrap(),
        WebSearchAllowanceAdmission::Exhausted
    );
    assert_eq!(store.set_web_search_allowance("exa", 3).unwrap(), Some(1));
    reserve(&store, "exa", "owner", FEBRUARY);
    assert_eq!(
        store
            .web_search_allowance_used("exa", "owner", FEBRUARY)
            .unwrap(),
        3
    );
    assert_eq!(store.web_search_allowance("tavily").unwrap(), Some(7));
    assert_eq!(store.web_search_order().unwrap(), None);
}

#[test]
fn unlimited_admission_creates_no_count() {
    let store = store();
    for _ in 0..3 {
        assert_eq!(
            store
                .reserve_web_search_allowance("exa", "owner", FEBRUARY)
                .unwrap(),
            WebSearchAllowanceAdmission::Unlimited
        );
    }
    let rows: u32 = store
        .inner
        .with_read(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM web_search_allowance_counts",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn concurrent_reservations_cannot_overshoot_the_remaining_allowance() {
    let store = Arc::new(store());
    store.set_web_search_allowance("exa", 2).unwrap();
    reserve(&store, "exa", "owner", FEBRUARY);
    let barrier = Arc::new(Barrier::new(9));
    let (tx, rx) = mpsc::channel();
    let mut workers = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        let barrier = barrier.clone();
        let tx = tx.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            tx.send(store.reserve_web_search_allowance("exa", "owner", FEBRUARY))
                .unwrap();
        }));
    }
    barrier.wait();
    let mut reserved = 0;
    let mut exhausted = 0;
    for _ in 0..8 {
        match rx
            .recv_timeout(Duration::from_secs(10))
            .expect("reservation worker deadline")
            .unwrap()
        {
            WebSearchAllowanceAdmission::Reserved(_) => reserved += 1,
            WebSearchAllowanceAdmission::Exhausted => exhausted += 1,
            WebSearchAllowanceAdmission::Unlimited => panic!("allowance must remain configured"),
        }
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!((reserved, exhausted), (1, 7));
    assert_eq!(
        store
            .web_search_allowance_used("exa", "owner", FEBRUARY)
            .unwrap(),
        2
    );
}

#[test]
fn release_returns_capacity_only_to_the_reserved_provider_principal_and_month() {
    let store = store();
    store.set_web_search_allowance("exa", 1).unwrap();
    store.set_web_search_allowance("tavily", 1).unwrap();
    let receipt = reserve(&store, "exa", "owner", MARCH - 1);
    reserve(&store, "exa", "owner", MARCH);
    reserve(&store, "exa", "other", FEBRUARY);
    reserve(&store, "tavily", "owner", FEBRUARY);
    store.clear_web_search_allowance("exa").unwrap();
    assert!(store.release_web_search_allowance(receipt).unwrap());
    assert_eq!(
        store
            .web_search_allowance_used("exa", "owner", FEBRUARY)
            .unwrap(),
        0
    );
    for (provider, owner_principal, month) in [
        ("exa", "owner", MARCH),
        ("exa", "other", FEBRUARY),
        ("tavily", "owner", FEBRUARY),
    ] {
        assert_eq!(
            store
                .web_search_allowance_used(provider, owner_principal, month)
                .unwrap(),
            1
        );
    }
    store.set_web_search_allowance("exa", 1).unwrap();
    reserve(&store, "exa", "owner", FEBRUARY);
}

#[test]
fn release_never_underflows_or_inserts_a_missing_count() {
    let store = store();
    store.set_web_search_allowance("exa", 1).unwrap();
    let receipt = reserve(&store, "exa", "owner", FEBRUARY);
    // Only the store can construct receipts. Recreate one here to exercise the
    // zero guard independently of the ownership discipline used by callers.
    let stale = || WebSearchAllowanceReservation {
        provider: "exa".into(),
        owner_principal: "owner".into(),
        month_utc: "2024-02".into(),
    };
    assert!(store.release_web_search_allowance(receipt).unwrap());
    assert!(!store.release_web_search_allowance(stale()).unwrap());
    assert_eq!(
        store
            .web_search_allowance_used("exa", "owner", FEBRUARY)
            .unwrap(),
        0
    );
    assert!(!store
        .release_web_search_allowance(WebSearchAllowanceReservation {
            owner_principal: "missing".into(),
            ..stale()
        })
        .unwrap());
    let rows: u32 = store
        .inner
        .with_read(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM web_search_allowance_counts",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn failed_count_write_rolls_back_admission() {
    let store = store();
    store.set_web_search_allowance("exa", 2).unwrap();
    reserve(&store, "exa", "owner", FEBRUARY);
    store.inner.with_conn_fenced(|conn| conn.execute_batch("CREATE TRIGGER reject_count BEFORE UPDATE ON web_search_allowance_counts BEGIN SELECT RAISE(ABORT, 'count rejected'); END;")).unwrap();
    assert!(store
        .reserve_web_search_allowance("exa", "owner", FEBRUARY)
        .is_err());
    assert_eq!(
        store
            .web_search_allowance_used("exa", "owner", FEBRUARY)
            .unwrap(),
        1
    );
    store
        .inner
        .with_conn_fenced(|conn| conn.execute_batch("DROP TRIGGER reject_count"))
        .unwrap();
    reserve(&store, "exa", "owner", FEBRUARY);
}

#[test]
fn reconnecting_cannot_reset_the_owners_monthly_allowance() {
    let store = store();
    insert_search_connection(&store, "owner", "old");
    insert_search_connection(&store, "owner", "sibling");
    store.set_web_search_allowance("exa", 1).unwrap();
    let original = store.connection("owner", "old").unwrap().unwrap();
    let receipt = reserve(&store, "exa", &original.principal, FEBRUARY);
    let sibling = store.connection("owner", "sibling").unwrap().unwrap();
    assert_eq!(
        store
            .reserve_web_search_allowance("exa", &sibling.principal, FEBRUARY)
            .unwrap(),
        WebSearchAllowanceAdmission::Exhausted
    );
    store.delete_connection("owner", "old", true).unwrap();
    assert!(!store.connection_id_exists("old").unwrap());
    insert_search_connection(&store, "owner", "replacement");
    let replacement = store.connection("owner", "replacement").unwrap().unwrap();
    assert_ne!(original.connection_id, replacement.connection_id);
    assert_eq!(
        store
            .web_search_allowance_used("exa", &replacement.principal, FEBRUARY)
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .reserve_web_search_allowance("exa", &replacement.principal, FEBRUARY)
            .unwrap(),
        WebSearchAllowanceAdmission::Exhausted
    );
    assert!(store.release_web_search_allowance(receipt).unwrap());
    reserve(&store, "exa", &replacement.principal, FEBRUARY);
}

fn insert_search_connection(store: &PlexusStore, owner: &str, connection_id: &str) {
    store.inner.with_conn_fenced(|conn| {
        conn.execute("INSERT INTO connections (principal, connection_id, app_key, status, created_at_ms, updated_at_ms) VALUES (?1, ?2, 'exa_rest', 'active', 1, 2)", (owner, connection_id))?;
        Ok(())
    }).unwrap();
}

#[test]
fn two_principals_using_the_same_provider_are_counted_separately() {
    let store = store();
    insert_search_connection(&store, "alice", "alice-exa");
    insert_search_connection(&store, "bob", "bob-exa");
    let alice = store.connection("alice", "alice-exa").unwrap().unwrap();
    let bob = store.connection("bob", "bob-exa").unwrap().unwrap();
    store.set_web_search_allowance("exa", 1).unwrap();
    reserve(&store, "exa", &alice.principal, FEBRUARY);
    assert_eq!(
        store
            .web_search_allowance_used("exa", &bob.principal, FEBRUARY)
            .unwrap(),
        0
    );
    reserve(&store, "exa", &bob.principal, FEBRUARY);
    for owner in [&alice.principal, &bob.principal] {
        assert_eq!(
            store
                .web_search_allowance_used("exa", owner, FEBRUARY)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .reserve_web_search_allowance("exa", owner, FEBRUARY)
                .unwrap(),
            WebSearchAllowanceAdmission::Exhausted
        );
    }
}

type Schema = Vec<(String, String, String, Option<String>)>;

fn schema(conn: &rusqlite::Connection) -> rusqlite::Result<Schema> {
    let mut statement =
        conn.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    rows.collect()
}

type TableRows = std::collections::BTreeMap<String, Vec<Vec<rusqlite::types::Value>>>;

fn data(conn: &rusqlite::Connection, schema: &Schema) -> rusqlite::Result<TableRows> {
    let mut tables = TableRows::new();
    for (kind, name, _, _) in schema {
        if kind != "table" || name == "cortexkit_schema_version" {
            continue;
        }
        let mut statement = conn.prepare(&format!(
            "SELECT * FROM \"{}\" ORDER BY rowid",
            name.replace('"', "\"\"")
        ))?;
        let count = statement.column_count();
        let rows =
            statement.query_map([], |row| (0..count).map(|column| row.get(column)).collect())?;
        tables.insert(name.clone(), rows.collect::<rusqlite::Result<_>>()?);
    }
    Ok(tables)
}

#[test]
fn migration_53_is_additive_and_preserves_existing_limits_and_rows() {
    let inner = open_sqlite(&descriptor()).unwrap();
    let through_53 = &MIGRATIONS[..=MIGRATIONS
        .iter()
        .position(|migration| migration.version == 53)
        .unwrap()];
    let old = &through_53[..through_53.len() - 1];
    assert_eq!(old.last().unwrap().version, 52);
    inner.migrate("plexus", old).unwrap();
    inner.with_conn_fenced(|conn| conn.execute_batch("INSERT INTO web_search_limits (backend, per_caller_per_minute, per_backend_per_minute, updated_at_ms) VALUES ('exa', 7, 70, 123);
        INSERT INTO connections (principal, connection_id, app_key, status, created_at_ms, updated_at_ms) VALUES ('owner', 'c', 'exa_rest', 'active', 1, 2);
        INSERT INTO audit_journal (ts, principal, actor, acting_principal, decision, reason_code) VALUES (1, 'owner', 'operator', 'owner', 'allow', 'test');")).unwrap();
    let before = inner.with_read(schema).unwrap();
    let before_data = inner.with_read(|conn| data(conn, &before)).unwrap();
    let outcome = inner.migrate("plexus", through_53).unwrap();
    assert_eq!((outcome.applied, outcome.recorded), (1, 53));
    let after = inner.with_read(schema).unwrap();
    for object in &before {
        assert!(
            after.contains(object),
            "existing schema object changed: {object:?}"
        );
    }
    let added = after
        .iter()
        .filter(|entry| entry.0 == "table" && !before.contains(entry))
        .map(|entry| entry.1.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        added,
        [
            "web_search_allowance_counts",
            "web_search_allowances",
            "web_search_order"
        ]
    );
    assert_eq!(
        inner.with_read(|conn| data(conn, &before)).unwrap(),
        before_data
    );
    let key = inner.with_read(|conn| {
        let mut statement = conn.prepare("SELECT name FROM pragma_table_info('web_search_allowance_counts') WHERE pk > 0 ORDER BY pk")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    }).unwrap();
    assert_eq!(key, ["principal", "provider", "month_utc"]);
    let rollback = inner.migrate("plexus", old).unwrap();
    assert!(rollback.store_ahead());
    assert_eq!(rollback.applied, 0);
    let store = PlexusStore {
        inner,
        grant_journal: None,
        outbox_ready: tokio::sync::Notify::new(),
        ci_runs: Default::default(),
        manifest_cache: Default::default(),
    };
    assert_eq!(
        store.web_search_limits("exa").unwrap(),
        Some(WebSearchLimits {
            per_caller_per_minute: 7,
            per_backend_per_minute: 70
        })
    );
    assert_eq!(store.web_search_order().unwrap(), None);
    assert_eq!(store.web_search_allowance("exa").unwrap(), None);
    assert_eq!(
        store
            .web_search_allowance_used("exa", "owner", FEBRUARY)
            .unwrap(),
        0
    );
}

/// Grant expiry in the candidate query is judged at the caller's `now`, not
/// the store's own wall clock, so it agrees with the caller's grant check.
#[test]
fn candidate_grant_expiry_uses_the_callers_clock() {
    let store = store();
    store
        .insert_connection(
            "owner",
            "shared",
            "exa_rest",
            "active",
            &serde_json::json!({}),
        )
        .unwrap();
    store
        .insert_grant(&crate::storage::GrantInput {
            grant_id: "expiring".into(),
            principal: "owner".into(),
            connection_id: "shared".into(),
            grantee_principal: "caller".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["search".into()],
            authority_kind: "invoke".into(),
            expires_at: Some(FEBRUARY),
        })
        .unwrap();
    assert_eq!(
        store
            .web_search_candidate_connection_ids("caller", "exa_rest", FEBRUARY - 1)
            .unwrap(),
        vec!["shared"],
        "a grant still live at the caller's now must keep its connection a candidate"
    );
    assert!(
        store
            .web_search_candidate_connection_ids("caller", "exa_rest", FEBRUARY)
            .unwrap()
            .is_empty(),
        "a grant expired at the caller's now must not widen the candidates"
    );
}
