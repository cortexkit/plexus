//! Plexus storage schema and the transactional persistence boundary for governance.
//!
//! Connection credentials are non-secret vault references stored in
//! `connections.credential_binding`, or NULL for credential-free vendors.
//! No projection or audit API exposes that column. Authorization writers
//! update state and invalidate reservations
//! in one transaction, preventing revocation or quarantine from leaving an
//! active reservation behind.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(test))]
use cortexkit_store::{open_sqlite, SqliteStore};
use cortexkit_store::{Migration, StorageDescriptor, StoreError};
use cortexkit_store_types::StorageBackend;
#[cfg(test)]
use counted_store::{open_sqlite, SqliteStore};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;

use crate::actor_attribution::{served_actor_fields, ActorAttribution, ActorUnknown};
use crate::manifest::{AppManifest, CursorKind, PollShape, Risk};
use crate::scope::CallScope;
use crate::withdraw::{
    WithdrawAnswer, WITHDRAW_OUTCOME_UNKNOWN, WITHDRAW_REFUSED_DENIED, WITHDRAW_REFUSED_EXPIRED,
    WITHDRAW_REFUSED_SCOPE_ENDED,
};

/// A scope epoch is an unsigned 64-bit number and SQLite stores signed 64-bit
/// integers, so the bits are stored as they are. The round trip through
/// [`epoch_from_sql`] is exact for every value.
fn epoch_to_sql(epoch: u64) -> i64 {
    epoch as i64
}

fn epoch_from_sql(stored: i64) -> u64 {
    stored as u64
}

/// Milliseconds in one policy day.
pub const AUDIT_MILLIS_PER_DAY: i64 = 24 * 60 * 60 * 1000;
/// Recent audit evidence cannot be deleted inside this floor, even by retention.
/// The SQL floor in migrations 26 and 40 is frozen; changing it needs a new migration.
pub const AUDIT_DELETE_FLOOR_DAYS: i64 = 7;
/// Safe deployment-wide retention policy when no environment override is stated.
pub const DEFAULT_AUDIT_RETENTION_DAYS: i64 = 30;
/// Maximum audit rows removed by one scheduler pass.
const AUDIT_RETENTION_BATCH_ROWS: usize = 1_000;
/// Terminal reservations remain inspectable for one day after their short fence.
pub(crate) const RESERVATION_RETENTION_MS: i64 = AUDIT_MILLIS_PER_DAY;
/// Reservation pruning shares the audit pass's transaction-size bound.
const RESERVATION_RETENTION_BATCH_ROWS: usize = AUDIT_RETENTION_BATCH_ROWS;
const CEREMONY_RETENTION_BATCH_ROWS: i64 = AUDIT_RETENTION_BATCH_ROWS as i64;
const RECONCILIATION_BATCH_ROWS: i64 = 1_000;

/// How long a write reconciliation waits before its next retry after
/// `attempts` earlier retries: five seconds, doubling, at most one minute. The
/// stored count never exceeds four. A negative count, which only a hand-edited
/// row could hold, waits nothing, as the SQL formula this replaced did.
pub(crate) fn reconciliation_retry_delay_ms(attempts: i64) -> i64 {
    if attempts < 0 {
        return 0;
    }
    crate::backoff::doubling_ms(5_000, attempts.min(4) as u32, 4, 60_000) as i64
}
const SUBSCRIPTION_EVENTS_PREDICATE: &str = "principal = ?1 AND subscription_id = ?2";
const BINDING_TICKET_TTL_MS: i64 = 60_000;
const MAX_DIAGNOSTIC_ACTION_CHARS: usize = 80;
/// Maximum ids processed under one acknowledgement transaction, not a request cap.
pub const MAX_EVENT_ACK_IDS: usize = 500;
const EVENT_ACK_AUTHORITY: &str = "(principal=?1 OR EXISTS (
    SELECT 1 FROM grants g JOIN trigger_subscriptions s
    ON s.subscription_id=trigger_events.subscription_id
    AND s.principal=trigger_events.principal AND s.connection_id=trigger_events.connection_id
    JOIN json_each(g.action_selectors) selector
    WHERE g.principal=trigger_events.principal AND g.connection_id=trigger_events.connection_id
    AND g.grantee_principal=?1 AND g.grantee_principal<>'*' AND g.authority_kind='events_consume'
    AND (g.expires_at IS NULL OR g.expires_at>?3)
    AND (selector.value=s.action OR selector.value='*')))";

/// True for a `catalog_actions` row whose connection's app is retired from the
/// reviewed catalog. Written for a query that reads `catalog_actions` without
/// an alias. `'system'` is [`CATALOG_PRINCIPAL`]; a test pins the two together.
macro_rules! app_retired_predicate {
    () => {
        "EXISTS (SELECT 1 FROM connections AS retired_connection
            JOIN app_manifests AS retired_manifest
              ON retired_manifest.principal = 'system'
             AND retired_manifest.key = retired_connection.app_key
            WHERE retired_connection.principal = catalog_actions.principal
              AND retired_connection.connection_id = catalog_actions.connection_id
              AND retired_manifest.status = 'retired')"
    };
}

const APP_RETIRED_PREDICATE: &str = app_retired_predicate!();

#[path = "store/migrations.rs"]
mod migrations_store;
pub use migrations_store::MIGRATIONS;
pub(crate) use migrations_store::PREFRONTAL_GRANT_BACKFILL;
use migrations_store::PREFRONTAL_GRANT_COPY_ID;
pub(crate) use migrations_store::RECIPIENT_ALLOWLIST_PRINCIPAL_BACKFILL;

#[path = "store/types.rs"]
mod types_store;
pub use types_store::*;

#[path = "store/connections.rs"]
mod connections_store;
#[path = "store/connector_home_generation.rs"]
mod connector_home_generation;
use connections_store::{
    connection_admin_grant_on_conn, encode_reference_binding, revoke_connection_on_conn,
    GITHUB_HANDLE_CONNECTION_PREFIX,
};
#[cfg(test)]
use connections_store::{decode_connection_binding, CONNECTION_KEYED_TABLES};
pub(crate) use connections_store::{is_reference_binding, removed_binding_error};

#[path = "store/ceremony.rs"]
mod ceremony_store;

#[path = "store/catalog.rs"]
mod catalog_store;
use catalog_store::{map_catalog_action_row, wider_than_recorded, CATALOG_ACTION_COLUMNS};
pub(crate) use catalog_store::{
    seed_catalog_actions_from_manifest_on_conn, seed_catalog_from_manifest_on_conn, SeedMode,
};

#[path = "store/github_outside_watches.rs"]
mod github_outside_watches_store;
#[path = "store/subscriptions.rs"]
mod subscriptions_store;
use github_outside_watches_store::outside_watch_poll_on_conn;
#[cfg(test)]
use subscriptions_store::{validate_fixed_args, DUE_SUBSCRIPTIONS_SELECT};

#[path = "store/events.rs"]
mod events_store;
use events_store::{insert_gap_row, insert_keyed_event_row, merge_intervals};

#[path = "store/grants.rs"]
mod grants_store;
use grants_store::{governing_policy, grant_ceiling_on_conn, map_grant_row, PollGrants};
pub(crate) use grants_store::{insert_policy_on_conn, mint_grants_bounded_on_conn};

#[path = "store/requests.rs"]
mod requests_store;
pub(crate) use requests_store::EnsuredRequest;

#[path = "store/audit.rs"]
mod audit_store;
use audit_store::{append_audit_for, append_audit_on_conn, AuditFor};

#[path = "store/reconciliation.rs"]
mod reconciliation_store;

#[cfg(test)]
#[path = "store/reference_binding_tests.rs"]
mod reference_binding_tests;

#[cfg(test)]
#[path = "store/exact_argument_tests.rs"]
mod exact_argument_tests;

#[cfg(test)]
#[path = "store/counted_store_tests.rs"]
mod counted_store;

#[path = "store/relay.rs"]
pub mod relay;

#[path = "store/event_outbox.rs"]
pub mod event_outbox;
#[path = "store/route_fact_outbox.rs"]
pub mod route_fact_outbox;
pub use event_outbox::{
    EventHeaders, KeyedEventIdentity, KeyedPollEventInput, OutboxVersion, PollGapInput,
};

#[path = "store/repository_ownership.rs"]
mod repository_ownership_store;

#[path = "store/recipients.rs"]
mod recipients_store;

#[path = "store/sent_text.rs"]
pub mod sent_text_store;

#[path = "store/ceiling.rs"]
mod ceiling_store;
pub use recipients_store::RecipientChange;

#[path = "store/web_search.rs"]
pub mod web_search_store;

#[path = "store/web_search_auto.rs"]
pub mod web_search_auto;

#[path = "store/github/mod.rs"]
pub mod github_store;

#[path = "store/github_bot_reads.rs"]
pub mod github_bot_reads_store;

#[path = "store/github_manifest_binding.rs"]
pub mod github_manifest_binding;

#[path = "store/permissions.rs"]
pub mod permissions_store;

#[path = "store/federated.rs"]
pub(crate) mod federated_store;

#[cfg(test)]
#[path = "store/connection_delete_tests.rs"]
mod connection_delete_tests;

#[cfg(test)]
#[path = "store/federated_tests.rs"]
mod federated_tests;

/// A test's code to run at one named point, and the point's name.
#[cfg(test)]
type RaceHook = (&'static str, Box<dyn FnOnce()>);

#[cfg(test)]
thread_local! {
    /// A test's code to run at one named point between a write's checks and
    /// its transaction, to stand in for a concurrent writer landing there.
    static RACE_HOOK: std::cell::RefCell<Option<RaceHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Run the test hook registered for `point`, once. A write whose checks run
/// before its transaction calls this between the two, so a test can change
/// the state those checks read and prove the transaction checks again.
fn race_point(point: &'static str) {
    #[cfg(test)]
    {
        let hook = RACE_HOOK.with(|slot| {
            let mut slot = slot.borrow_mut();
            match slot.as_ref() {
                Some((name, _)) if *name == point => slot.take().map(|(_, hook)| hook),
                _ => None,
            }
        });
        if let Some(hook) = hook {
            hook();
        }
    }
    #[cfg(not(test))]
    let _ = point;
}

type ManifestCache =
    std::collections::BTreeMap<(String, String), (String, std::sync::Arc<AppManifest>)>;

/// Lease-guarded store for the plexus domain.
pub struct PlexusStore {
    inner: SqliteStore,
    manifest_cache: std::sync::Mutex<ManifestCache>,
    grant_journal: Option<PathBuf>,
    outbox_ready: tokio::sync::Notify,
    /// Resume removal of outbox markers whose trigger event is gone; restart on open.
    orphan_sweep_after: std::sync::Mutex<Option<String>>,
    /// Run values from recent `workflow_run` webhooks, for later job webhooks.
    /// In memory only; empty after a restart.
    ci_runs: relay::CiRunCache,
}

impl PlexusStore {
    #[cfg(test)]
    pub(crate) fn count_store_calls_for_test(&self, work: impl FnOnce()) -> usize {
        counted_store::count_calls(work)
    }

    /// Run SQL against the store's own connection, for tests outside the
    /// storage module that must set up or inspect rows no API exposes.
    #[cfg(test)]
    pub(crate) fn sql_for_test<T>(
        &self,
        work: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
    ) -> T {
        self.inner
            .with_conn_fenced(|conn| work(conn))
            .expect("test SQL")
    }

    pub fn open(descriptor: &StorageDescriptor) -> Result<Self, StoreError> {
        let grant_journal = grant_journal_path(descriptor);
        let federated_journal = grant_journal
            .as_ref()
            .map(|path| path.with_file_name(crate::federated_journal::NAME));
        // Parse before opening SQLite: malformed restore evidence must cause no writes.
        let revocations = grant_journal
            .as_deref()
            .map(|path| crate::grant_journal::scan(path, |_| Ok(())))
            .transpose()
            .map_err(StoreError::Backend)?
            .unwrap_or_default();
        let deletions = federated_journal
            .as_deref()
            .map(|path| crate::federated_journal::scan(path, |_| Ok(())))
            .transpose()
            .map_err(StoreError::Backend)?
            .unwrap_or_default();
        let store = open_sqlite(descriptor)?;
        if let Some(path) = &grant_journal {
            crate::grant_journal::ensure(path).map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        if let Some(path) = &federated_journal {
            crate::grant_journal::ensure(path).map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        // Migration 63 copies every legacy prefrontal grant to the renamed
        // identity. When this open applies it to a restored older database, a
        // grant the journal has since revoked is still present and gets copied,
        // and replay below removes only the exact revoked id. Before migration
        // 63 runs, find the copies it will make of journal-revoked grants, so
        // replay revokes them too. A store already past 63 is left alone: its
        // renamed grants stand on their own and are revoked by their own ids.
        let mut revoked_copies = Vec::new();
        if revocations != 0 {
            let rename = MIGRATIONS
                .iter()
                .position(|migration| migration.version == 63)
                .expect("the chain carries migration 63");
            if store.migrate("plexus", &MIGRATIONS[..rename])?.recorded < 63 {
                let path = grant_journal.as_deref().expect("journal was scanned");
                revoked_copies = store.with_read(|conn| {
                    let mut copy_id = conn.prepare(PREFRONTAL_GRANT_COPY_ID)?;
                    let mut copies = Vec::new();
                    crate::grant_journal::scan(path, |entry| {
                        let id: Option<String> = copy_id
                            .query_row((&entry.principal, &entry.grant_id), |row| row.get(0))
                            .optional()
                            .map_err(|e| e.to_string())?;
                        if let Some(grant_id) = id {
                            copies.push(crate::grant_journal::Revocation { grant_id, ..entry });
                        }
                        Ok(())
                    })
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                    Ok(copies)
                })?;
            }
        }
        let outcome = store.migrate("plexus", MIGRATIONS)?;
        if outcome.store_ahead() {
            // A store written by a longer migration chain than this binary
            // carries is the rollback shape, and rolling the binary back is a
            // supported deploy move here: every migration ships only after a
            // rehearsal proves rows written under the newer schema stay
            // readable by the prior binary (additive, defaulted columns; SQL
            // names its columns explicitly). Refusing startup would brick that
            // rollback path, so this serves — loudly, because an operator
            // reading the log during an incident needs to know the store is
            // from the future before trusting any other symptom.
            eprintln!(warn storage:
                "store schema is ahead of this binary (store v{}, binary chain v{}); \
                 serving under the rehearsed rollback posture",
                outcome.recorded, outcome.chain_max
            );
        }
        // A store restore replaces store.db but not the revocation journal beside
        // it, so a restored database can be missing revocations the journal still
        // holds. Replay them before returning any handle that grants authority,
        // under the same writer fence. An empty replay needs no fence: a copied
        // store can record a higher writer epoch than its new lease file, and
        // opening it must not take the writer role when there is nothing to apply.
        if revocations != 0 {
            store.with_conn_fenced(|conn| {
                crate::grant_journal::scan(
                    grant_journal.as_deref().expect("journal was scanned"),
                    |entry| {
                        crate::grant_journal::apply(conn, &entry)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    },
                )
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                // Revoke each copy as replay revokes any journal entry: the
                // deleted row is kept in grant_revocations, and no audit row
                // is written.
                for copy in &revoked_copies {
                    crate::grant_journal::apply(conn, copy)?;
                }
                Ok(())
            })?;
        }
        if deletions != 0 {
            store.with_conn_fenced(|conn| {
                crate::federated_journal::scan(
                    federated_journal.as_deref().expect("journal was scanned"),
                    |entry| {
                        crate::federated_journal::apply(conn, &entry)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    },
                )
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                Ok(())
            })?;
        }
        let invalid = store.with_read(|conn| {
            let mut query = conn.prepare("SELECT connection_id, credential_binding FROM connections WHERE status != 'revoked' AND credential_binding IS NOT NULL ORDER BY connection_id")?;
            let rows = query.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, rusqlite::types::Value>(1)?)))?;
            let mut invalid = Vec::new();
            for row in rows {
                let (id, binding) = row?;
                if !matches!(binding, rusqlite::types::Value::Blob(ref bytes) if is_reference_binding(bytes)) {
                    invalid.push(id);
                }
            }
            Ok(invalid)
        })?;
        if !invalid.is_empty() {
            return Err(StoreError::Backend(removed_binding_error(
                &invalid.join(", "),
            )));
        }
        Ok(Self {
            inner: store,
            grant_journal,
            outbox_ready: tokio::sync::Notify::new(),
            orphan_sweep_after: Default::default(),
            ci_runs: Default::default(),
            manifest_cache: Default::default(),
        })
    }

    /// Apply the schema to an already-open sqlite connection. This is useful for
    /// deterministic migration tests and keeps the migration list inspectable.
    #[cfg(any(test, feature = "test-support"))]
    pub fn apply_migrations(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
        for migration in MIGRATIONS {
            conn.execute_batch(migration.statements)?;
        }
        Ok(())
    }
}

fn jcs_store_hash(value: &Value) -> Result<String, StoreError> {
    crate::jcs::jcs_sha256(value).map_err(|error| StoreError::Backend(error.to_string()))
}

fn jcs_sqlite_hash(value: &Value) -> rusqlite::Result<String> {
    crate::jcs::jcs_sha256(value)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
}

fn parse_json_column<T: serde::de::DeserializeOwned>(value: &str) -> rusqlite::Result<T> {
    serde_json::from_str(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn parse_string_list(value: &str) -> rusqlite::Result<Vec<String>> {
    parse_json_column(value)
}

fn grant_journal_path(descriptor: &StorageDescriptor) -> Option<PathBuf> {
    match &descriptor.backend {
        StorageBackend::Sqlite { path } if path != ":memory:" => {
            let database = PathBuf::from(path);
            let parent = database
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            Some(parent.join(crate::grant_journal::NAME))
        }
        _ => None,
    }
}

/// Generate an unguessable ID for a ticket, grant, approval, reservation, or
/// other row whose ID can confer authority or must remain unpredictable.
///
/// Panic if the operating system cannot supply random bytes. Never substitute
/// the clock, process ID, or a counter: someone who knows roughly when creation
/// occurred could guess such an ID and gain the authority it represents.
pub(crate) fn new_id(prefix: &str) -> String {
    new_id_from(prefix, |bytes| {
        getrandom::fill(bytes).map_err(|error| std::io::Error::other(error.to_string()))
    })
}

/// Generate an ID like [`new_id`] using `fill` to supply all 12 random bytes.
/// Inject the filler so tests can simulate a random-source failure and check
/// that ID creation panics rather than substituting predictable bytes.
fn new_id_from(prefix: &str, fill: impl FnOnce(&mut [u8]) -> std::io::Result<()>) -> String {
    let mut bytes = [0_u8; 12];
    if let Err(error) = fill(&mut bytes) {
        panic!("the system random source could not be read ({error}); refusing to mint a guessable {prefix} id");
    }
    format!("{prefix}_{}", hex::encode(bytes))
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        // A clock before 1970 is hardware- or configuration-level failure.
        // The previous arm substituted epoch ZERO, which travels into every
        // authority comparison treating expired authority as live: with now = 0,
        // an expired grant reads live (0 < expires_at) and an approval window never lapses.
        // A module that cannot read its clock cannot enforce time-bounded
        // authority; refusing to run is the honest failure. The supervisor stops
        // restarting a module that keeps failing and reports it to the operator.
        .expect(
            "system clock reads before the Unix epoch; refusing to serve time-bounded authority",
        )
}

#[cfg(test)]
#[path = "store/store_contract_tests.rs"]
mod store_contract_tests;

#[cfg(test)]
#[path = "store/storage_tests.rs"]
mod tests;
