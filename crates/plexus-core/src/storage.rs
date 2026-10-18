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

use cortexkit_store::{open_sqlite, Migration, SqliteStore, StorageDescriptor, StoreError};
use cortexkit_store_types::StorageBackend;
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
pub const AUDIT_RETENTION_BATCH_ROWS: usize = 1_000;
/// Terminal reservations remain inspectable for one day after their short fence.
pub(crate) const RESERVATION_RETENTION_MS: i64 = AUDIT_MILLIS_PER_DAY;
/// Reservation pruning shares the audit pass's transaction-size bound.
const RESERVATION_RETENTION_BATCH_ROWS: usize = AUDIT_RETENTION_BATCH_ROWS;
const CEREMONY_RETENTION_BATCH_ROWS: i64 = AUDIT_RETENTION_BATCH_ROWS as i64;
const RECONCILIATION_BATCH_ROWS: i64 = 1_000;
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

/// The connector schema, beginning with the complete fresh-store schema.
///
/// The base schema is numbered 23 because migration versions are schema
/// generation markers, not a count of steps in the current binary. Stores that
/// completed the fresh-schema cutover already record generation 23.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 23,
        statements: r#"
CREATE TABLE app_manifests (
    principal        TEXT NOT NULL,
    key              TEXT NOT NULL,
    schema_version   INTEGER NOT NULL,
    content_hash     TEXT NOT NULL,
    manifest_json    TEXT NOT NULL,
    ingested_at_ms   INTEGER NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',
    PRIMARY KEY (principal, key)
);

CREATE TABLE connections (
    connection_id              TEXT NOT NULL,
    principal                  TEXT NOT NULL,
    app_key                    TEXT NOT NULL,
    status                     TEXT NOT NULL CHECK (status IN
        ('pending','active','degraded','auth_required','disabled','revoked')),
    transport_config           TEXT NOT NULL DEFAULT '{}',
    credential_binding         BLOB,
    resource_filters           TEXT NOT NULL DEFAULT '{}',
    health_state               TEXT NOT NULL DEFAULT '{}',
    pending_ttl_s              INTEGER,
    pending_expires_at         INTEGER,
    generation                 INTEGER NOT NULL DEFAULT 0,
    created_at_ms              INTEGER NOT NULL,
    updated_at_ms              INTEGER NOT NULL,
    ceiling_risk               TEXT,
    ceiling_selectors          TEXT,
    PRIMARY KEY (principal, connection_id)
);
CREATE INDEX idx_connections_principal ON connections (principal, updated_at_ms);

CREATE TABLE catalog_actions (
    connection_id       TEXT NOT NULL,
    principal           TEXT NOT NULL,
    name                TEXT NOT NULL,
    title               TEXT,
    schema_json         TEXT NOT NULL,
    schema_hash         TEXT NOT NULL,
    risk                TEXT NOT NULL CHECK (risk IN ('read','write','destructive')),
    severity            TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('active','quarantined','disabled')),
    quarantine_reason   TEXT,
    reconciliation_json TEXT,
    first_seen_at_ms    INTEGER NOT NULL,
    last_seen_at_ms     INTEGER NOT NULL,
    generation          INTEGER NOT NULL DEFAULT 0,
    ask_first           INTEGER NOT NULL DEFAULT 1,
    reviewed_schema_json TEXT,
    PRIMARY KEY (principal, connection_id, name)
);

CREATE TABLE "grants" (
    grant_id             TEXT NOT NULL,
    principal            TEXT NOT NULL,
    connection_id        TEXT NOT NULL,
    grantee_principal    TEXT NOT NULL,
    risk_ceiling         TEXT NOT NULL,
    action_selectors     TEXT NOT NULL DEFAULT '[]',
    authority_kind       TEXT NOT NULL CHECK (authority_kind IN
        ('invoke','connection_admin','poll','events_consume')),
    expires_at           INTEGER,
    generation           INTEGER NOT NULL DEFAULT 0,
    created_at_ms        INTEGER NOT NULL,
    PRIMARY KEY (principal, grant_id)
);

CREATE TABLE policies (
    policy_id            TEXT NOT NULL,
    principal            TEXT NOT NULL,
    connection_id        TEXT NOT NULL,
    action_selector      TEXT NOT NULL,
    effect               TEXT NOT NULL CHECK (effect IN ('allow','ask_first','block')),
    rate_limit_json      TEXT,
    trust_rule_json      TEXT,
    expires_at           INTEGER,
    generation           INTEGER NOT NULL DEFAULT 0,
    updated_at_ms        INTEGER NOT NULL,
    PRIMARY KEY (principal, policy_id)
);

CREATE TABLE action_requests (
    request_id            TEXT NOT NULL,
    principal             TEXT NOT NULL,
    connection_id         TEXT NOT NULL,
    action                TEXT NOT NULL,
    args_snapshot         TEXT NOT NULL,
    schema_hash           TEXT NOT NULL,
    requester             TEXT NOT NULL,
    status                TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired')),
    decision              TEXT,
    decider               TEXT,
    expires_at            INTEGER NOT NULL,
    created_at_ms         INTEGER NOT NULL,
    args_hash             TEXT NOT NULL DEFAULT '',
    reconciliation_status TEXT,
    decision_id           TEXT,
    PRIMARY KEY (principal, request_id)
);

CREATE TABLE reservations (
    reservation_id        TEXT NOT NULL,
    principal             TEXT NOT NULL,
    connection_id         TEXT NOT NULL,
    action                TEXT NOT NULL,
    snapshot_generations  TEXT NOT NULL,
    approved_args_hash    TEXT NOT NULL,
    schema_hash           TEXT NOT NULL,
    expires_at            INTEGER NOT NULL,
    status                TEXT NOT NULL CHECK (status IN ('reserved','invalidated','dispatched','expired')),
    created_at_ms         INTEGER NOT NULL,
    grant_id              TEXT,
    PRIMARY KEY (principal, reservation_id)
);

CREATE TABLE binding_tickets (
    ticket_id             TEXT NOT NULL,
    principal             TEXT NOT NULL,
    connection_id         TEXT NOT NULL,
    ref_role              TEXT NOT NULL,
    expires_at            INTEGER NOT NULL,
    status                TEXT NOT NULL CHECK (status IN ('issued','consumed','expired','revoked')),
    created_at_ms         INTEGER NOT NULL,
    risk_ceiling          TEXT NOT NULL DEFAULT 'read',
    action_selectors      TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (principal, ticket_id)
);

CREATE TABLE audit_journal (
    journal_id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                            INTEGER NOT NULL,
    principal                     TEXT NOT NULL,
    actor                         TEXT NOT NULL,
    acting_principal              TEXT NOT NULL,
    connection_id                 TEXT,
    app_key                       TEXT,
    action                        TEXT,
    risk                          TEXT,
    severity                      TEXT,
    decision                      TEXT NOT NULL,
    reason_code                   TEXT NOT NULL,
    gate                          TEXT,
    args_redaction_summary        TEXT,
    outcome                       TEXT,
    latency_ms                    INTEGER,
    request_id                    TEXT,
    credential_fingerprint        TEXT,
    provider_account_fingerprint  TEXT,
    attempt_no                    INTEGER,
    vendor_request_id             TEXT,
    idempotency_key_fingerprint   TEXT,
    response_class                TEXT,
    reconciliation_of             TEXT,
    agent_id                      TEXT,
    agent_handle                  TEXT
);
CREATE INDEX idx_audit_principal_ts ON audit_journal (principal, ts);
CREATE TRIGGER audit_journal_append_only_update
BEFORE UPDATE ON audit_journal
BEGIN
    SELECT RAISE(ABORT, 'audit_journal is append-only');
END;
CREATE TRIGGER audit_journal_append_only_delete
BEFORE DELETE ON audit_journal
BEGIN
    SELECT RAISE(ABORT, 'audit_journal is append-only');
END;

CREATE TABLE oauth_flows (
    flow_handle    TEXT NOT NULL,
    connection_id  TEXT NOT NULL,
    principal      TEXT NOT NULL,
    expires_at     INTEGER NOT NULL,
    ux_status      TEXT NOT NULL,
    PRIMARY KEY (principal, flow_handle)
);

CREATE TABLE "trigger_subscriptions" (
    subscription_id             TEXT PRIMARY KEY,
    principal                   TEXT NOT NULL,
    connection_id               TEXT NOT NULL,
    action                      TEXT NOT NULL,
    cadence_s                   INTEGER NOT NULL CHECK (cadence_s > 0),
    cursor_kind                 TEXT NOT NULL CHECK (cursor_kind IN
        ('sync_token','ordered_timestamp','snapshot_diff','scalar_diff','sorted_head','probe')),
    cursor_state                TEXT NOT NULL DEFAULT '{}',
    schema_hash                 TEXT NOT NULL,
    status                      TEXT NOT NULL CHECK (status IN ('active','suspended','retired')),
    suspended_reason            TEXT,
    last_polled_at_ms           INTEGER,
    last_success_at_ms          INTEGER,
    consecutive_vendor_failures INTEGER NOT NULL DEFAULT 0
                                CHECK (consecutive_vendor_failures >= 0),
    generation                  INTEGER NOT NULL DEFAULT 0,
    created_at_ms               INTEGER NOT NULL,
    fixed_args                  TEXT NOT NULL DEFAULT '{}',
    project_id                  TEXT,
    actor_source_json           TEXT,
    deliver_to                  TEXT
);
CREATE INDEX idx_trigger_subscriptions_principal
    ON trigger_subscriptions (principal, created_at_ms);
CREATE INDEX idx_trigger_subscriptions_connection
    ON trigger_subscriptions (principal, connection_id, status);

CREATE TABLE trigger_events (
    event_id                    TEXT PRIMARY KEY,
    principal                   TEXT NOT NULL,
    connection_id               TEXT NOT NULL,
    subscription_id             TEXT NOT NULL,
    vendor_event_id             TEXT,
    payload_hash                TEXT NOT NULL,
    payload                     TEXT NOT NULL,
    kind                        TEXT NOT NULL CHECK (kind IN ('event','gap')),
    gap_from_ms                 INTEGER,
    gap_to_ms                   INTEGER,
    gap_reason                  TEXT,
    observed_at_ms              INTEGER NOT NULL,
    acked_at_ms                 INTEGER,
    created_at_ms               INTEGER NOT NULL,
    item_kind                   TEXT,
    activity_at_ms              INTEGER,
    actor_logins                TEXT,
    CHECK (
        (kind = 'event' AND vendor_event_id IS NOT NULL
            AND gap_from_ms IS NULL AND gap_to_ms IS NULL AND gap_reason IS NULL)
        OR
        (kind = 'gap' AND vendor_event_id IS NULL
            AND gap_from_ms IS NOT NULL AND gap_to_ms IS NOT NULL
            AND gap_reason IS NOT NULL)
    )
);
CREATE UNIQUE INDEX idx_trigger_events_dedupe
    ON trigger_events (connection_id, subscription_id, vendor_event_id, payload_hash)
    WHERE kind = 'event' AND vendor_event_id IS NOT NULL;
CREATE INDEX idx_trigger_events_delivery
    ON trigger_events (principal, acked_at_ms, created_at_ms);
CREATE INDEX idx_trigger_events_subscription
    ON trigger_events (principal, subscription_id, created_at_ms);

CREATE TABLE probe_subscriptions (
    subscription_id  TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    actions          TEXT NOT NULL,
    script_source    TEXT NOT NULL,
    return_schema    TEXT NOT NULL,
    rearm            TEXT NOT NULL CHECK (rearm IN ('once','always')),
    registered_by    TEXT NOT NULL
);
"#,
    },
    // Generation 23 has already run on existing stores, so removing this unused table
    // requires a later migration rather than an edit to the fresh-store schema.
    Migration {
        version: 24,
        statements: "DROP TABLE IF EXISTS oauth_flows;",
    },
    Migration {
        version: 25,
        statements: r#"
CREATE TABLE grant_revocations (
    revocation_id     TEXT PRIMARY KEY,
    grant_id          TEXT NOT NULL,
    principal         TEXT NOT NULL,
    connection_id     TEXT NOT NULL,
    grantee_principal TEXT NOT NULL,
    authority_kind    TEXT NOT NULL,
    risk_ceiling      TEXT NOT NULL,
    action_selectors  TEXT NOT NULL,
    expires_at        INTEGER NULL,
    generation        INTEGER NOT NULL,
    created_at_ms     INTEGER NOT NULL,
    revoked_at_ms     INTEGER NOT NULL,
    revoked_by        TEXT NOT NULL
);
CREATE INDEX idx_grant_revocations_principal_connection
    ON grant_revocations (principal, connection_id);
CREATE TRIGGER grant_revocations_no_update BEFORE UPDATE ON grant_revocations
BEGIN
    SELECT RAISE(ABORT, 'grant revocations are immutable');
END;
CREATE TRIGGER grant_revocations_no_delete BEFORE DELETE ON grant_revocations
BEGIN
    SELECT RAISE(ABORT, 'grant revocations are immutable');
END;
"#,
    },
    // Generations through 25 are already recorded in existing stores. Narrow the
    // delete trigger in a new migration so existing stores actually receive the
    // retention policy; the unconditional update trigger remains untouched.
    Migration {
        version: 26,
        statements: r#"
CREATE INDEX idx_audit_ts ON audit_journal (ts, journal_id);
DROP TRIGGER audit_journal_append_only_delete;
CREATE TRIGGER audit_journal_append_only_delete
BEFORE DELETE ON audit_journal
WHEN OLD.ts > (CAST(strftime('%s', 'now') AS INTEGER) * 1000 - 604800000)
BEGIN
    SELECT RAISE(ABORT, 'audit_journal is append-only inside the 7-day delete floor');
END;
"#,
    },
    // Generation 26 is recorded in existing stores. The scheduler visits retention
    // every second, so terminal-age selection must not scan the growing table.
    Migration {
        version: 27,
        statements: r#"
CREATE INDEX idx_reservations_terminal_created_at
    ON reservations (created_at_ms, principal, reservation_id)
    WHERE status IN ('invalidated', 'dispatched', 'expired');
"#,
    },
    // Catalog health refreshes reapply invalidation even for unchanged quarantine.
    // Index only live reservations so these safety checks never walk spent history.
    Migration {
        version: 28,
        statements: r#"
CREATE INDEX idx_reservations_reserved_lookup
    ON reservations (principal, connection_id, action)
    WHERE status = 'reserved';
"#,
    },
    Migration {
        version: 29,
        statements: r#"
CREATE TABLE pending_write_reconciliations (
    principal TEXT NOT NULL,
    request_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    intent_id TEXT,
    expires_at_ms INTEGER NOT NULL,
    PRIMARY KEY (principal, request_id)
);
CREATE INDEX idx_pending_write_reconciliations_expiry
    ON pending_write_reconciliations (expires_at_ms);
CREATE TABLE write_reconciliation_results (
    principal TEXT NOT NULL,
    request_id TEXT NOT NULL,
    acting_principal TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (principal, request_id)
);
CREATE INDEX idx_write_reconciliation_results_age ON write_reconciliation_results (updated_at_ms);
"#,
    },
    Migration {
        version: 30,
        statements: r#"
ALTER TABLE grants ADD COLUMN agent_id TEXT;
CREATE TABLE action_requests_v30 (
    request_id TEXT NOT NULL,
    principal TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    action TEXT NOT NULL,
    args_snapshot TEXT NOT NULL,
    schema_hash TEXT NOT NULL,
    requester TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired','consumed')),
    decision TEXT,
    decider TEXT,
    expires_at INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    args_hash TEXT NOT NULL DEFAULT '',
    reconciliation_status TEXT,
    decision_id TEXT,
    agent_id TEXT,
    PRIMARY KEY (principal, request_id)
);
INSERT INTO action_requests_v30 (
    request_id, principal, connection_id, action, args_snapshot, schema_hash,
    requester, status, decision, decider, expires_at, created_at_ms,
    args_hash, reconciliation_status, decision_id
) SELECT request_id, principal, connection_id, action, args_snapshot, schema_hash,
    requester, status, decision, decider, expires_at, created_at_ms,
    args_hash, reconciliation_status, decision_id FROM action_requests;
DROP TABLE action_requests;
ALTER TABLE action_requests_v30 RENAME TO action_requests;
ALTER TABLE audit_journal ADD COLUMN app_handle_id TEXT;
CREATE INDEX idx_grants_agent ON grants (principal, connection_id, agent_id);
CREATE TABLE github_app_handle (
    app_handle_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL UNIQUE,
    app_id INTEGER NOT NULL,
    installation_id INTEGER,
    credential_reference TEXT NOT NULL UNIQUE
        CHECK (credential_reference LIKE 'github_app:%' AND length(credential_reference) > 11),
    credential_generation INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('enabled','disabled')),
    proven_at INTEGER,
    app_handle_generation INTEGER NOT NULL DEFAULT 1,
    connection_principal TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    UNIQUE (connection_principal, connection_id)
);
CREATE TRIGGER github_app_handle_generation AFTER UPDATE ON github_app_handle
WHEN NEW.app_handle_generation = OLD.app_handle_generation
BEGIN
    UPDATE github_app_handle SET app_handle_generation = OLD.app_handle_generation + 1
    WHERE app_handle_id = NEW.app_handle_id;
END;
CREATE TABLE github_repo_binding_generation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL DEFAULT 0
);
INSERT INTO github_repo_binding_generation (singleton, generation) VALUES (1, 0);
CREATE TABLE github_repo_binding (
    repository TEXT PRIMARY KEY,
    app_handle_id TEXT NOT NULL REFERENCES github_app_handle(app_handle_id)
);
CREATE TRIGGER github_repo_binding_insert AFTER INSERT ON github_repo_binding BEGIN
    UPDATE github_repo_binding_generation SET generation = generation + 1 WHERE singleton = 1;
END;
CREATE TRIGGER github_repo_binding_update AFTER UPDATE ON github_repo_binding BEGIN
    UPDATE github_repo_binding_generation SET generation = generation + 1 WHERE singleton = 1;
END;
CREATE TRIGGER github_repo_binding_delete AFTER DELETE ON github_repo_binding BEGIN
    UPDATE github_repo_binding_generation SET generation = generation + 1 WHERE singleton = 1;
END;
CREATE TABLE github_bot_receipt (
    agent_id TEXT NOT NULL,
    request_nonce TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','pending_approval','completed','refused','outcome_unknown')),
    claim_owner TEXT,
    claim_lease_expires_at INTEGER,
    authority_baseline TEXT,
    effects TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(effects) AND json_type(effects) = 'array'),
    action_request_id TEXT,
    outcome TEXT,
    refusal_code TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, request_nonce)
);
"#,
    },
    // Why actor enrichment left an event's actors unknown, as a bare reason
    // code. Additive: rows written earlier keep NULL here and are served as
    // `unrecorded` when their subscription has an actor source.
    Migration {
        version: 31,
        statements: "ALTER TABLE trigger_events ADD COLUMN actor_unknown_reason TEXT;",
    },
    // The `web_search` tool. Additive only, so a binary built before this
    // generation keeps reading and writing the store after a rollback: it never
    // names the new audit columns (its INSERT lists its columns explicitly, so
    // they stay NULL) and never reads the new table.
    //
    // `query_text` and `result_count` are written only by `web_search` rows. The
    // query is stored as text, an exception to the hash-only argument policy,
    // because a search cannot be reviewed without the words searched for and
    // search terms are not credentials. It ages out with the rest of the
    // journal under the normal audit retention window.
    //
    // `web_search_limits` holds one operator-set row per backend. A backend with
    // no row uses the defaults compiled into the web_search module.
    Migration {
        version: 32,
        statements: r#"
ALTER TABLE audit_journal ADD COLUMN query_text TEXT;
ALTER TABLE audit_journal ADD COLUMN result_count INTEGER;
CREATE TABLE web_search_limits (
    backend                 TEXT PRIMARY KEY,
    per_caller_per_minute   INTEGER NOT NULL CHECK (per_caller_per_minute > 0),
    per_backend_per_minute  INTEGER NOT NULL CHECK (per_backend_per_minute > 0),
    updated_at_ms           INTEGER NOT NULL
);
"#,
    },
    // Revoked bearer bindings no longer confer authority. Keep reference bytes
    // intact so the preceding reference-aware binary can still serve a rollback.
    Migration {
        version: 33,
        statements: "UPDATE connections SET credential_binding = NULL WHERE status = 'revoked' AND credential_binding IS NOT NULL AND substr(credential_binding, 1, 26) != X'706c657875733a7661756c742d7265666572656e63653a763100';",
    },
    // The ordinary approval a reservation was authorized under, so claiming the
    // reservation for dispatch can consume that approval in the same
    // transaction. Additive: rows written earlier, and rows a prior binary
    // writes after a rollback (its INSERT names its columns), keep NULL, which
    // means "no approval to consume".
    Migration {
        version: 34,
        statements: "ALTER TABLE reservations ADD COLUMN approval_request_id TEXT;",
    },
    // The daemon scope a governed call's route was bound under, copied from the
    // bind stamp (docs/designs/daemon-scopes.md in the subconscious repository). The columns are
    // named after the stamp's own fields. There is deliberately no relay or
    // carrier column: the scopes design has no relay class, and the module that
    // carried the call is already `acting_principal`.
    //
    // - audit_journal: written on both rows of a governed call made under a
    //   scope, NULL otherwise. `scope_parent` is `owner/ref@epoch`.
    // - action_requests: the scope an approval request was raised under, so the
    //   approval can be re-checked against the daemon when it executes, and
    //   `scope_outcome`, what that re-check decided (`approved_waiting` while
    //   held, `not_run:<reason>` when refused).
    // - reservations: the agent grant a call made as an agent was authorized
    //   under, pinned at claim like the module grant.
    //
    // Additive only: every column is nullable, and a binary from before this
    // generation names its columns on INSERT, so after a rollback it keeps
    // writing NULL here and never reads these columns.
    Migration {
        version: 35,
        statements: r#"
ALTER TABLE audit_journal ADD COLUMN scope_owner TEXT;
ALTER TABLE audit_journal ADD COLUMN scope_ref TEXT;
ALTER TABLE audit_journal ADD COLUMN scope_epoch INTEGER;
ALTER TABLE audit_journal ADD COLUMN scope_kind TEXT;
ALTER TABLE audit_journal ADD COLUMN scope_parent TEXT;
ALTER TABLE audit_journal ADD COLUMN scope_parent_state TEXT;
ALTER TABLE audit_journal ADD COLUMN scope_delegates INTEGER;
ALTER TABLE audit_journal ADD COLUMN scope_owner_authorized INTEGER;
ALTER TABLE action_requests ADD COLUMN scope_owner TEXT;
ALTER TABLE action_requests ADD COLUMN scope_ref TEXT;
ALTER TABLE action_requests ADD COLUMN scope_epoch INTEGER;
ALTER TABLE action_requests ADD COLUMN scope_delegates INTEGER;
ALTER TABLE action_requests ADD COLUMN scope_owner_authorized INTEGER;
ALTER TABLE action_requests ADD COLUMN scope_outcome TEXT;
ALTER TABLE reservations ADD COLUMN agent_grant_id TEXT;
"#,
    },
    // Withdrawing a held call by its key (`tool.withdraw`).
    //
    // - `call_key`: the key the carrier gave the call that raised the request,
    //   NULL for a call sent without one. It is unique per carrier: the carrier
    //   is the module that carried the call, already stored as `requester`, so
    //   the unique index is on `(requester, call_key)` and needs no new carrier
    //   column. Two carriers may use the same key for different calls.
    // - `claimed_request_id`: the request id of the dispatch attempt whose claim
    //   consumed the approval. That attempt's `dispatch` audit row holds how the
    //   call settled, which is what a withdrawal arriving after the claim reports.
    // - status `cancelled`: a withdrawn request. Nothing claims, decides or
    //   retries a row in this status, so a withdrawn call can never be sent.
    //
    // SQLite cannot widen a CHECK constraint in place, so the table is rebuilt
    // the way generation 30 rebuilt it, copying every row and column unchanged.
    // Nothing is removed or rewritten, and the new columns are nullable. A binary
    // from before this generation names its columns on INSERT and never matches
    // `cancelled` in any status test, so after a rollback it treats a withdrawn
    // request as spent.
    Migration {
        version: 36,
        statements: r#"
CREATE TABLE action_requests_v36 (
    request_id TEXT NOT NULL,
    principal TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    action TEXT NOT NULL,
    args_snapshot TEXT NOT NULL,
    schema_hash TEXT NOT NULL,
    requester TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN
        ('pending','approved','denied','expired','consumed','cancelled')),
    decision TEXT,
    decider TEXT,
    expires_at INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    args_hash TEXT NOT NULL DEFAULT '',
    reconciliation_status TEXT,
    decision_id TEXT,
    agent_id TEXT,
    scope_owner TEXT,
    scope_ref TEXT,
    scope_epoch INTEGER,
    scope_delegates INTEGER,
    scope_owner_authorized INTEGER,
    scope_outcome TEXT,
    call_key TEXT,
    claimed_request_id TEXT,
    PRIMARY KEY (principal, request_id)
);
INSERT INTO action_requests_v36 (
    request_id, principal, connection_id, action, args_snapshot, schema_hash,
    requester, status, decision, decider, expires_at, created_at_ms,
    args_hash, reconciliation_status, decision_id, agent_id,
    scope_owner, scope_ref, scope_epoch, scope_delegates, scope_owner_authorized,
    scope_outcome
) SELECT request_id, principal, connection_id, action, args_snapshot, schema_hash,
    requester, status, decision, decider, expires_at, created_at_ms,
    args_hash, reconciliation_status, decision_id, agent_id,
    scope_owner, scope_ref, scope_epoch, scope_delegates, scope_owner_authorized,
    scope_outcome FROM action_requests;
DROP TABLE action_requests;
ALTER TABLE action_requests_v36 RENAME TO action_requests;
CREATE UNIQUE INDEX idx_action_requests_call_key
    ON action_requests (requester, call_key) WHERE call_key IS NOT NULL;
"#,
    },
    // The settled outcome of a claimed approval's send, kept on the request.
    //
    // - `settled_outcome`: the outcome of the first `dispatch` audit row the
    //   claiming attempt (`claimed_request_id`) wrote, copied in the same
    //   transaction as that row. A withdrawal arriving after the claim answers
    //   from here, so its answer no longer depends on the audit row, which
    //   audit retention deletes. NULL until the send settles, and for every
    //   request that settled before this generation (those still answer from
    //   their audit row while it exists).
    // - The partial index finds the request a dispatch row belongs to.
    //
    // Additive only: a binary from before this generation names its columns on
    // INSERT and never reads the new one.
    Migration {
        version: 37,
        statements: r#"
ALTER TABLE action_requests ADD COLUMN settled_outcome TEXT;
CREATE INDEX idx_action_requests_claimed_request
    ON action_requests (principal, claimed_request_id) WHERE claimed_request_id IS NOT NULL;
"#,
    },
    // The call a relayed call came from, as its relay stated it (the tool
    // call's top-level `origin`; see [`RelayOrigin`]).
    //
    // - `origin_carrier`: the principal that carried the original call, in
    //   its stored form (`reserved:broca`).
    // - `origin_call_key`: that carrier's key for the original call.
    //
    // Written on both audit rows of a relayed call and on the approval request
    // it raises. Attribution only: no index, uniqueness rule or lookup reads
    // them. A held request stays keyed on `(requester, call_key)`.
    //
    // Additive only: both pairs are nullable, NULL for every call that stated
    // no origin. A binary from before this generation names its columns on
    // INSERT and never reads these.
    Migration {
        version: 38,
        statements: r#"
ALTER TABLE audit_journal ADD COLUMN origin_carrier TEXT;
ALTER TABLE audit_journal ADD COLUMN origin_call_key TEXT;
ALTER TABLE action_requests ADD COLUMN origin_carrier TEXT;
ALTER TABLE action_requests ADD COLUMN origin_call_key TEXT;
"#,
    },
    // Consent cards: a call held for approval (a pending action request) is
    // also filed with Prefrontal core as a card the user can answer from
    // their phone.
    //
    // - `action_requests.elicitation_id`: the id Prefrontal core returned when
    //   the request's card was filed. NULL for a request with no card (stored
    //   before migration version 39, or its filing failed). The partial index
    //   finds the request an answered card belongs to.
    // - `elicitation_answers_cursor`: one row, the position in Prefrontal
    //   core's answer feed up to which every answer has been acted on. It is
    //   written in the same transaction as those answers' outcomes, so a
    //   restart neither acts on an answer twice nor skips one.
    //
    // Additive only: the column is nullable and the table is new. A binary
    // whose migration chain ends at 38 names its columns on INSERT and never
    // reads either.
    Migration {
        version: 39,
        statements: r#"
ALTER TABLE action_requests ADD COLUMN elicitation_id TEXT;
CREATE INDEX idx_action_requests_elicitation
    ON action_requests (elicitation_id) WHERE elicitation_id IS NOT NULL;
CREATE TABLE elicitation_answers_cursor (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    answers_cursor INTEGER NOT NULL CHECK (answers_cursor >= 0),
    updated_at_ms INTEGER NOT NULL
);
"#,
    },
    // A one-time purge of ended connections and lapsed authority. Revoked
    // connections used to be kept forever with everything keyed by them;
    // nothing reads that data, so it is deleted here, and from now on an
    // operator ends a connection for good with `delete_connection`.
    //
    // - Delete revoked connections and their rows from `probe_subscriptions`,
    //   `trigger_events`, `trigger_subscriptions`, `catalog_actions`, `grants`,
    //   `policies`, `action_requests`, `reservations`, `binding_tickets`,
    //   `write_reconciliation_results`, `pending_write_reconciliations`,
    //   `audit_journal`, and `grant_revocations`, then from `connections` itself.
    //   Revoked connections named by a `github_app_handle` row are excluded:
    //   the handle owns the connection, and `github_repo_binding` holds a
    //   foreign key to the handle.
    // - Every grant whose `expires_at` has passed, on any connection. An
    //   expired grant authorizes nothing.
    //
    // The audit and revocation delete triggers refuse these deletes, so they
    // are dropped and then recreated with SQL copied byte for byte from the
    // migrations that last defined them (`audit_journal_append_only_delete`
    // from migration version 26, `grant_revocations_no_delete` from 25); a
    // schema test compares `sqlite_master` before and after. The runner wraps the whole batch in one transaction.
    //
    // The grant revocation journal (`grant-revocations.jsonl`) is left alone:
    // replaying an entry only acts on a row still in `grants`, and this purge
    // removes every grant of a purged connection, so replay recreates
    // nothing (see `grant_journal::apply`).
    //
    // On a fresh store every statement matches no row.
    Migration {
        version: 40,
        statements: r#"
CREATE TEMP TABLE migration_40_purged_connections AS
    SELECT principal, connection_id FROM connections AS c
    WHERE c.status = 'revoked'
      AND NOT EXISTS (SELECT 1 FROM github_app_handle AS h
                      WHERE h.connection_principal = c.principal
                        AND h.connection_id = c.connection_id);
DELETE FROM probe_subscriptions WHERE subscription_id IN (
    SELECT subscription_id FROM trigger_subscriptions
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections));
DELETE FROM trigger_events
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections);
DELETE FROM trigger_subscriptions
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections);
DELETE FROM catalog_actions
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections);
DELETE FROM grants
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections);
DELETE FROM policies
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections);
DELETE FROM action_requests
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections);
DELETE FROM reservations
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections);
DELETE FROM binding_tickets
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections);
DELETE FROM write_reconciliation_results
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections);
DELETE FROM pending_write_reconciliations
    WHERE (principal, CASE WHEN json_valid(record_json)
                           THEN json_extract(record_json, '$.connection_id') END)
          IN (SELECT principal, connection_id FROM migration_40_purged_connections);
DROP TRIGGER audit_journal_append_only_delete;
DROP TRIGGER grant_revocations_no_delete;
DELETE FROM audit_journal
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections);
DELETE FROM grant_revocations
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections);
CREATE TRIGGER audit_journal_append_only_delete
BEFORE DELETE ON audit_journal
WHEN OLD.ts > (CAST(strftime('%s', 'now') AS INTEGER) * 1000 - 604800000)
BEGIN
    SELECT RAISE(ABORT, 'audit_journal is append-only inside the 7-day delete floor');
END;
CREATE TRIGGER grant_revocations_no_delete BEFORE DELETE ON grant_revocations
BEGIN
    SELECT RAISE(ABORT, 'grant revocations are immutable');
END;
DELETE FROM connections
    WHERE (principal, connection_id) IN (SELECT principal, connection_id FROM migration_40_purged_connections);
DROP TABLE migration_40_purged_connections;
DELETE FROM grants
    WHERE expires_at IS NOT NULL
      AND expires_at <= CAST(strftime('%s', 'now') AS INTEGER) * 1000;
"#,
    },
    Migration {
        version: 41,
        statements: "ALTER TABLE audit_journal ADD COLUMN scope_flow_id TEXT;
              ALTER TABLE action_requests ADD COLUMN scope_flow_id TEXT;",
    },
    Migration {
        version: 42,
        statements: r#"
ALTER TABLE trigger_subscriptions ADD COLUMN project_source TEXT
    CHECK (project_source IN ('hand', 'entorhinal') OR project_source IS NULL);
UPDATE trigger_subscriptions SET project_source = 'hand' WHERE project_id IS NOT NULL;
CREATE TRIGGER subscription_project_source_insert BEFORE INSERT ON trigger_subscriptions
WHEN (NEW.project_id IS NULL) != (NEW.project_source IS NULL)
BEGIN SELECT RAISE(ABORT, 'project and source must be set together'); END;
CREATE TRIGGER subscription_project_source_update BEFORE UPDATE OF project_id, project_source ON trigger_subscriptions
WHEN (NEW.project_id IS NULL) != (NEW.project_source IS NULL)
BEGIN SELECT RAISE(ABORT, 'project and source must be set together'); END;
"#,
    },
    Migration {
        version: 43,
        statements: r#"
CREATE TABLE recipient_allowlist (
    connection_id TEXT NOT NULL,
    agent_id TEXT,
    recipient TEXT NOT NULL CHECK (length(recipient) > 0)
);
CREATE UNIQUE INDEX recipient_allowlist_agent ON recipient_allowlist(connection_id, agent_id, recipient) WHERE agent_id IS NOT NULL;
CREATE UNIQUE INDEX recipient_allowlist_module ON recipient_allowlist(connection_id, recipient) WHERE agent_id IS NULL;
"#,
    },
    Migration {
        version: 44,
        statements: r#"
ALTER TABLE trigger_events ADD COLUMN event_key TEXT;
ALTER TABLE trigger_events ADD COLUMN delivery_id TEXT;
CREATE UNIQUE INDEX idx_trigger_events_key ON trigger_events(subscription_id, event_key)
    WHERE event_key IS NOT NULL;
CREATE UNIQUE INDEX idx_trigger_events_delivery_id ON trigger_events(delivery_id)
    WHERE delivery_id IS NOT NULL;
CREATE TABLE event_outbox (
    event_key TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    event_name TEXT NOT NULL,
    repo_id INTEGER NOT NULL,
    change TEXT,
    repo TEXT NOT NULL,
    project TEXT,
    pr TEXT,
    branch TEXT,
    conclusion TEXT,
    created_at_ms INTEGER NOT NULL,
    published_at_ms INTEGER
);
CREATE INDEX idx_event_outbox_pending ON event_outbox(published_at_ms, created_at_ms);
CREATE TABLE github_repo_id_cache (
    repo TEXT PRIMARY KEY CHECK (repo = lower(repo)),
    repo_id INTEGER,
    last_attempt_at_ms INTEGER NOT NULL,
    resolved_at_ms INTEGER
);
CREATE TABLE github_actions_quota (
    reservation_id TEXT PRIMARY KEY,
    reserved_at_ms INTEGER NOT NULL,
    requests INTEGER NOT NULL CHECK (requests IN (1, 8))
);
CREATE INDEX idx_github_actions_quota_time ON github_actions_quota(reserved_at_ms);
CREATE TABLE event_outbox_counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);
"#,
    },
    Migration {
        version: 45,
        statements: r#"
DROP TRIGGER subscription_project_source_insert;
DROP TRIGGER subscription_project_source_update;
CREATE TABLE trigger_subscriptions_widened (
    subscription_id TEXT PRIMARY KEY,
    principal TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    action TEXT NOT NULL,
    cadence_s INTEGER NOT NULL CHECK (cadence_s > 0),
    cursor_kind TEXT NOT NULL CHECK (cursor_kind IN
        ('sync_token','ordered_timestamp','snapshot_diff','scalar_diff','sorted_head','probe','ci_runs')),
    cursor_state TEXT NOT NULL DEFAULT '{}',
    schema_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active','suspended','retired')),
    suspended_reason TEXT,
    last_polled_at_ms INTEGER,
    last_success_at_ms INTEGER,
    consecutive_vendor_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_vendor_failures >= 0),
    generation INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL,
    fixed_args TEXT NOT NULL DEFAULT '{}',
    project_id TEXT,
    actor_source_json TEXT,
    deliver_to TEXT,
    project_source TEXT CHECK (project_source IN ('hand','entorhinal') OR project_source IS NULL)
);
INSERT INTO trigger_subscriptions_widened SELECT * FROM trigger_subscriptions;
DROP TABLE trigger_subscriptions;
ALTER TABLE trigger_subscriptions_widened RENAME TO trigger_subscriptions;
CREATE INDEX idx_trigger_subscriptions_principal ON trigger_subscriptions(principal, created_at_ms);
CREATE INDEX idx_trigger_subscriptions_connection ON trigger_subscriptions(principal, connection_id, status);
CREATE TRIGGER subscription_project_source_insert BEFORE INSERT ON trigger_subscriptions
WHEN (NEW.project_id IS NULL) != (NEW.project_source IS NULL)
BEGIN SELECT RAISE(ABORT, 'project and source must be set together'); END;
CREATE TRIGGER subscription_project_source_update BEFORE UPDATE OF project_id, project_source ON trigger_subscriptions
WHEN (NEW.project_id IS NULL) != (NEW.project_source IS NULL)
BEGIN SELECT RAISE(ABORT, 'project and source must be set together'); END;
"#,
    },
    Migration {
        version: 46,
        statements: r#"
CREATE TABLE relay_cursor (
    source TEXT PRIMARY KEY,
    stream_id TEXT NOT NULL,
    committed_seq INTEGER NOT NULL CHECK (committed_seq BETWEEN 0 AND 9007199254740991)
);
"#,
    },
    Migration {
        version: 47,
        statements: r#"
ALTER TABLE event_outbox ADD COLUMN envelope_v2 TEXT;
ALTER TABLE event_outbox ADD COLUMN digest_v2 TEXT;
ALTER TABLE event_outbox ADD COLUMN published_v2_at_ms INTEGER;
"#,
    },
    // Connection ids are unique only per owning principal, so a recipient
    // allowlist keyed by the id alone was shared by every owner of that id.
    // Each existing row is copied once for every principal that owns a
    // connection with its id, which keeps what each owner could send to
    // before; rows for an id no connection has any more are inert and dropped.
    // The column is nullable so an older binary can still insert its rows;
    // this binary never reads a row without a principal.
    Migration {
        version: 48,
        statements: RECIPIENT_ALLOWLIST_PRINCIPAL_MIGRATION,
    },
    // One policy per (owner, connection, selector). Without the index two
    // concurrent set_policy calls could each find no row and both insert, and
    // the duplicate's effect and expiry would then depend on which row a
    // reader happened to pick. Existing duplicates are resolved first by
    // keeping the row with the lowest policy id, which is the row both
    // set_policy and the governing-policy query already chose. An older binary
    // keeps working: the index only refuses a second row for a scope.
    Migration {
        version: 49,
        statements: r#"
DELETE FROM policies WHERE EXISTS (
    SELECT 1 FROM policies AS kept
    WHERE kept.principal = policies.principal
      AND kept.connection_id = policies.connection_id
      AND kept.action_selector = policies.action_selector
      AND kept.policy_id < policies.policy_id
);
CREATE UNIQUE INDEX policies_scope ON policies(principal, connection_id, action_selector);
"#,
    },
    Migration {
        version: 50,
        statements: r#"
CREATE INDEX idx_event_outbox_pending_v1 ON event_outbox(created_at_ms, event_key)
    WHERE published_at_ms IS NULL;
CREATE INDEX idx_event_outbox_pending_v2 ON event_outbox(created_at_ms, event_key)
    WHERE envelope_v2 IS NOT NULL AND published_v2_at_ms IS NULL;
DROP INDEX idx_event_outbox_pending;
CREATE INDEX idx_github_receipts_pending_lease ON github_bot_receipt(claim_lease_expires_at)
    WHERE state = 'pending';
CREATE INDEX idx_github_receipts_terminal_updated ON github_bot_receipt(updated_at, claim_lease_expires_at)
    WHERE state IN ('completed','refused');
CREATE INDEX idx_trigger_subscriptions_active_due ON trigger_subscriptions(principal, created_at_ms, subscription_id)
    WHERE status = 'active';
"#,
    },
    Migration {
        version: 51,
        statements: r#"
CREATE TABLE consent_call_keys (
    requester TEXT NOT NULL,
    call_key TEXT NOT NULL,
    principal TEXT NOT NULL,
    request_id TEXT NOT NULL,
    PRIMARY KEY (requester, call_key),
    FOREIGN KEY (principal, request_id) REFERENCES action_requests (principal, request_id)
);
"#,
    },
    Migration {
        version: 52,
        statements: r#"
ALTER TABLE event_outbox ADD COLUMN body_v1 TEXT;
ALTER TABLE event_outbox ADD COLUMN digest_v1 TEXT;
CREATE INDEX idx_grants_grantee_kind ON grants(grantee_principal, authority_kind);
CREATE INDEX idx_grants_agent_global ON grants(agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX idx_connections_app ON connections(app_key, principal, connection_id);
CREATE INDEX idx_connections_id ON connections(connection_id);
CREATE INDEX idx_action_requests_id ON action_requests(request_id);
CREATE INDEX idx_action_requests_call_scope ON action_requests(call_key,scope_owner,scope_ref,scope_epoch) WHERE call_key IS NOT NULL;
CREATE INDEX idx_action_requests_shape ON action_requests(principal,connection_id,action,args_hash);
ALTER TABLE action_requests ADD COLUMN scope_checked_at_ms INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_action_requests_waiting ON action_requests(scope_checked_at_ms,created_at_ms,principal,request_id) WHERE status='approved' AND scope_outcome='approved_waiting';
CREATE INDEX idx_trigger_events_global_key ON trigger_events(event_key) WHERE event_key IS NOT NULL;
CREATE INDEX idx_write_results_actor ON write_reconciliation_results(acting_principal,updated_at_ms);
CREATE INDEX idx_github_binding_handle ON github_repo_binding(app_handle_id);
CREATE INDEX idx_subscription_repo ON trigger_subscriptions(lower(json_extract(fixed_args,'$.owner') || '/' || json_extract(fixed_args,'$.repo')));
ALTER TABLE pending_write_reconciliations ADD COLUMN next_attempt_at_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE pending_write_reconciliations ADD COLUMN retry_attempts INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_reconciliation_next_attempt ON pending_write_reconciliations(next_attempt_at_ms);
ALTER TABLE action_requests ADD COLUMN settled_at_ms INTEGER;
UPDATE action_requests SET settled_at_ms=CAST(round(unixepoch('subsec')*1000) AS INTEGER) WHERE status IN ('consumed','denied','expired','cancelled');
CREATE TRIGGER action_request_settlement_clock AFTER UPDATE OF status ON action_requests
WHEN NEW.status IN ('consumed','denied','expired','cancelled') AND NEW.status <> OLD.status
BEGIN UPDATE action_requests SET settled_at_ms=CAST(round(unixepoch('subsec')*1000) AS INTEGER) WHERE principal=NEW.principal AND request_id=NEW.request_id; END;
CREATE INDEX idx_action_request_live_expiry ON action_requests(expires_at) WHERE status IN ('pending','approved');
CREATE INDEX idx_action_request_retention ON action_requests(settled_at_ms) WHERE status IN ('consumed','denied','expired','cancelled');
ALTER TABLE binding_tickets ADD COLUMN settled_at_ms INTEGER;
UPDATE binding_tickets SET settled_at_ms=CAST(round(unixepoch('subsec')*1000) AS INTEGER) WHERE status IN ('consumed','expired','revoked');
CREATE TRIGGER binding_ticket_settlement_clock AFTER UPDATE OF status ON binding_tickets
WHEN NEW.status IN ('consumed','expired','revoked') AND NEW.status <> OLD.status
BEGIN UPDATE binding_tickets SET settled_at_ms=CAST(round(unixepoch('subsec')*1000) AS INTEGER) WHERE principal=NEW.principal AND ticket_id=NEW.ticket_id; END;
CREATE INDEX idx_binding_ticket_live_expiry ON binding_tickets(expires_at) WHERE status='issued';
CREATE INDEX idx_binding_ticket_retention ON binding_tickets(settled_at_ms) WHERE status IN ('consumed','expired','revoked');
CREATE INDEX idx_github_receipt_unsettled_retention ON github_bot_receipt(updated_at) WHERE state IN ('outcome_unknown','pending','pending_approval');
"#,
    },
    Migration {
        version: 53,
        statements: r#"
CREATE TABLE web_search_order (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    providers TEXT NOT NULL CHECK (json_valid(providers) AND json_type(providers) = 'array' AND json_array_length(providers) > 0)
);
CREATE TABLE web_search_allowances (
    provider TEXT PRIMARY KEY NOT NULL,
    allowance INTEGER NOT NULL CHECK (allowance BETWEEN 1 AND 10000000)
);
CREATE TABLE web_search_allowance_counts (
    principal TEXT NOT NULL,
    provider TEXT NOT NULL,
    month_utc TEXT NOT NULL CHECK (month_utc GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]' AND substr(month_utc, 6, 2) BETWEEN '01' AND '12'),
    used INTEGER NOT NULL CHECK (used >= 0),
    PRIMARY KEY (principal, provider, month_utc)
);
"#,
    },
    Migration {
        version: 54,
        statements: r#"
ALTER TABLE action_requests ADD COLUMN routing_context TEXT;
ALTER TABLE grant_revocations ADD COLUMN agent_id TEXT;
"#,
    },
    Migration {
        version: 55,
        statements: r#"
CREATE TABLE event_outbox_failures (
    event_key TEXT NOT NULL REFERENCES event_outbox(event_key) ON DELETE CASCADE,
    version INTEGER NOT NULL CHECK(version IN (1,2)),
    failed_at_ms INTEGER NOT NULL,
    failure_reason TEXT NOT NULL,
    PRIMARY KEY(event_key,version)
);
CREATE INDEX idx_github_binding_lower_repo ON github_repo_binding(lower(repository));
"#,
    },
];

/// The backfill half of migration 48, shared with the store import so a store
/// copied from before the migration gets the same per-owner rows.
macro_rules! recipient_allowlist_principal_backfill {
    () => {
        r#"
INSERT INTO recipient_allowlist (principal, connection_id, agent_id, recipient)
    SELECT DISTINCT c.principal, r.connection_id, r.agent_id, r.recipient
    FROM recipient_allowlist r JOIN connections c ON c.connection_id = r.connection_id
    WHERE r.principal IS NULL;
DELETE FROM recipient_allowlist WHERE principal IS NULL;
"#
    };
}

pub(crate) const RECIPIENT_ALLOWLIST_PRINCIPAL_BACKFILL: &str =
    recipient_allowlist_principal_backfill!();

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

const RECIPIENT_ALLOWLIST_PRINCIPAL_MIGRATION: &str = concat!(
    r#"
ALTER TABLE recipient_allowlist ADD COLUMN principal TEXT;
DROP INDEX recipient_allowlist_agent;
DROP INDEX recipient_allowlist_module;
CREATE UNIQUE INDEX recipient_allowlist_owner_agent
    ON recipient_allowlist(principal, connection_id, agent_id, recipient) WHERE agent_id IS NOT NULL;
CREATE UNIQUE INDEX recipient_allowlist_owner_module
    ON recipient_allowlist(principal, connection_id, recipient) WHERE agent_id IS NULL;
"#,
    recipient_allowlist_principal_backfill!()
);

#[path = "store/relay.rs"]
pub mod relay;

#[path = "store/event_outbox.rs"]
pub mod event_outbox;
pub use event_outbox::{
    EventHeaders, KeyedEventIdentity, KeyedPollEventInput, OutboxVersion, PollGapInput,
};

#[path = "store/repository_ownership.rs"]
mod repository_ownership_store;

#[path = "store/recipients.rs"]
mod recipients_store;

#[path = "store/ceiling.rs"]
mod ceiling_store;
pub use recipients_store::RecipientChange;

#[path = "store/web_search.rs"]
pub mod web_search_store;

#[path = "store/github/mod.rs"]
pub mod github_store;

#[path = "store/permissions.rs"]
pub mod permissions_store;

#[cfg(test)]
#[path = "store/connection_delete_tests.rs"]
mod connection_delete_tests;

/// A principal-scoped connection projection. Credential bindings are deliberately
/// absent from this projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionSummary {
    pub connection_id: String,
    pub app_key: String,
    pub status: String,
    pub generation: i64,
}

/// Full non-secret connection state used by the governance engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRecord {
    pub connection_id: String,
    pub principal: String,
    pub app_key: String,
    pub status: String,
    pub resource_filters: Value,
    pub health_state: Value,
    pub generation: i64,
    pub has_credential_binding: bool,
}

/// What `PlexusStore::delete_connection` found, and did when applied.
///
/// `rows` lists, per table, how many rows keyed by the connection the delete
/// removes (dry run) or removed (applied), in deletion order, every table
/// listed even at zero. The connection row itself is not counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteConnectionOutcome {
    /// The principal owns no connection with that id.
    NotFound,
    /// The connection backs a GitHub App handle, whose connection is created
    /// and ended with the handle itself; nothing was written.
    HandleConnection,
    /// This many unexpired grants still reference the connection; nothing
    /// was written.
    HasLiveGrants { count: i64 },
    /// Dry run: what an apply would delete.
    WouldDelete {
        app_key: String,
        status: String,
        rows: Vec<(&'static str, i64)>,
    },
    /// Applied: the connection and these rows are gone.
    Deleted {
        app_key: String,
        status: String,
        rows: Vec<(&'static str, i64)>,
    },
}

/// The id prefix of a connection created for a GitHub App handle
/// (`github-handle-<app_handle_id>`).
const GITHUB_HANDLE_CONNECTION_PREFIX: &str = "github-handle-";

/// Every table whose rows belong to one connection, with the `WHERE` clause
/// that selects that connection's rows given `?1` = principal and
/// `?2` = connection id. `PlexusStore::delete_connection` deletes in this
/// order, so a row that finds its connection through another table
/// (`probe_subscriptions` through `trigger_subscriptions`) goes before that
/// table's row.
///
/// Deliberately absent:
/// - `audit_journal`: append-only at runtime, with bounded age-based retention.
/// - `grant_revocations`: immutable evidence kept indefinitely at runtime;
///   migration 40 was a one-time exception for eligible revoked connections.
/// - `github_app_handle`: a connection it references is refused instead.
///
/// The schema test `every_connection_keyed_table_is_deleted_or_deliberately_kept`
/// fails when a table gains a `connection_id` column without being listed
/// here or among those exceptions.
pub(crate) const CONNECTION_KEYED_TABLES: &[(&str, &str)] = &[
    (
        "probe_subscriptions",
        "subscription_id IN (SELECT subscription_id FROM trigger_subscriptions
                             WHERE principal = ?1 AND connection_id = ?2)",
    ),
    (
        "event_outbox_failures",
        "event_key IN (SELECT event_key FROM event_outbox WHERE event_id IN
            (SELECT event_id FROM trigger_events WHERE principal = ?1 AND connection_id = ?2))",
    ),
    (
        "event_outbox",
        "event_id IN (SELECT event_id FROM trigger_events WHERE principal = ?1 AND connection_id = ?2)",
    ),
    ("trigger_events", "principal = ?1 AND connection_id = ?2"),
    (
        "trigger_subscriptions",
        "principal = ?1 AND connection_id = ?2",
    ),
    ("catalog_actions", "principal = ?1 AND connection_id = ?2"),
    ("grants", "principal = ?1 AND connection_id = ?2"),
    ("policies", "principal = ?1 AND connection_id = ?2"),
    (
        "consent_call_keys",
        "(principal, request_id) IN (SELECT principal, request_id FROM action_requests
                                    WHERE principal = ?1 AND connection_id = ?2)",
    ),
    ("action_requests", "principal = ?1 AND connection_id = ?2"),
    ("reservations", "principal = ?1 AND connection_id = ?2"),
    ("binding_tickets", "principal = ?1 AND connection_id = ?2"),
    (
        "recipient_allowlist",
        "principal = ?1 AND connection_id = ?2",
    ),
    (
        "write_reconciliation_results",
        "principal = ?1 AND connection_id = ?2",
    ),
    // The connection id is inside the serialized `OutcomeUnknownRecord`, not
    // in a column. `json_valid` guards `json_extract`, which raises an error
    // on malformed text and would abort the whole delete.
    (
        "pending_write_reconciliations",
        "principal = ?1 AND CASE WHEN json_valid(record_json)
             THEN json_extract(record_json, '$.connection_id') END = ?2",
    ),
];

/// Result of inserting or replacing a reviewed manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestWriteOutcome {
    pub changed: bool,
}

/// The open-object schema a catalog row holds before anything has pinned a
/// reviewed argument schema on it. Governance's undeclared-argument check
/// treats a schema without `properties` as open, so a row holding this refuses
/// no argument at all.
pub(crate) fn placeholder_catalog_schema() -> Value {
    serde_json::json!({"type": "object", "additionalProperties": true})
}

/// The refusal for a ticket whose ceiling reaches beyond the ceiling a
/// connection already records, or `None` when it fits inside. A connection's
/// ceiling is permanent once set, so a later ticket may only restate it or ask
/// for less.
fn wider_than_recorded(
    requested: &Ceiling,
    recorded_risk: &str,
    recorded_selectors: &str,
) -> rusqlite::Result<Option<CeremonyRefusal>> {
    let Some(risk) = Risk::parse(recorded_risk) else {
        return Ok(Some(CeremonyRefusal::InvalidRisk(
            recorded_risk.to_string(),
        )));
    };
    let selectors = parse_string_list(recorded_selectors)?;
    if !requested.risk.within(risk) {
        return Ok(Some(CeremonyRefusal::RiskAboveCeiling {
            requested: requested.risk.to_string(),
            ceiling: risk.to_string(),
        }));
    }
    // A stored wildcard admits everything, as it does when a grant is minted.
    if selectors.iter().any(|selector| selector == "*") {
        return Ok(None);
    }
    Ok(requested
        .action_selectors
        .iter()
        .find(|selector| !selectors.contains(selector))
        .map(|outside| CeremonyRefusal::OutsideConnectionCeiling {
            action: outside.clone(),
            ceiling: selectors.clone(),
        }))
}

/// One GitHub handle catalog row moved from the open placeholder to its
/// reviewed argument schema by [`PlexusStore::pin_handle_placeholder_schemas`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedHandleSchema {
    pub principal: String,
    pub connection_id: String,
    pub action: String,
    pub schema_hash: String,
}

/// A GitHub handle catalog row left on the open placeholder because the
/// reviewed manifest offers no argument schema to pin for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleSchemaGap {
    pub principal: String,
    pub connection_id: String,
    pub action: String,
    /// Why nothing could be pinned, e.g. the action has no `http.args_schema`.
    pub reason: &'static str,
}

/// What one [`PlexusStore::pin_handle_placeholder_schemas`] pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandleSchemaPinReport {
    pub pinned: Vec<PinnedHandleSchema>,
    pub gaps: Vec<HandleSchemaGap>,
}

/// The maximum authority a connection may ever delegate: which actions, and up
/// to what risk. Established at ticket issuance (the one step that proves
/// credential possession) and copied onto the connection when the ticket is
/// consumed. `action_selectors` is always a concrete expanded list — never a
/// stored wildcard — so authority is pinned at mint time and a vendor that
/// later gains actions cannot retroactively widen an existing ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ceiling {
    pub risk: Risk,
    pub action_selectors: Vec<String>,
}

impl Ceiling {
    /// Test-only escape hatch preserving the pre-ceiling behaviour of the
    /// legacy ticket helpers: full write authority over every action. Not
    /// reachable from the operator surface, which always supplies an explicit
    /// manifest-bounded ceiling.
    #[cfg(any(test, feature = "test-support"))]
    pub fn unrestricted_for_tests() -> Self {
        Self {
            risk: Risk::Destructive,
            action_selectors: vec!["*".to_string()],
        }
    }

    /// True when `self` authorizes nothing beyond `other`.
    pub fn within(&self, other: &Ceiling) -> bool {
        if !self.risk.within(other.risk) {
            return false;
        }
        // A wildcard in the bounding ceiling is only produced by the test helper
        // above; stored ceilings are always expanded.
        if other.action_selectors.iter().any(|value| value == "*") {
            return true;
        }
        self.action_selectors
            .iter()
            .all(|selector| other.action_selectors.contains(selector))
    }
}

/// One grant-mint request. Bundled rather than passed positionally so a call
/// site cannot silently transpose the principal, the grantee, and the risk.
#[derive(Debug, Clone)]
pub struct GrantMintRequest<'a> {
    /// The connection owner whose authority is being delegated.
    pub principal: &'a str,
    pub connection_id: &'a str,
    /// Who may exercise the grant.
    pub grantee_principal: &'a str,
    /// The grant's authority kind: `invoke`, `connection_admin`, `poll` or `events_consume`.
    pub authority_kind: &'a str,
    pub requested_risk: &'a str,
    pub requested_selectors: &'a [String],
    pub expires_at: Option<i64>,
}

/// Why a privileged ceremony operation was refused. Overreach is always
/// refused rather than clamped: a silent clamp would leave the operator
/// believing they authorized something they did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyRefusal {
    UnknownApp(String),
    /// The vendor is stored but withdrawn from the reviewed catalog.
    ///
    /// Distinct from `UnknownApp` because the two call for different operator
    /// actions: an unknown key is a typo or a vendor never reviewed, while a
    /// retired one was deliberately withdrawn and the operator needs to know a
    /// decision was made rather than hunt for a spelling mistake.
    RetiredApp(String),
    ConnectionNotFound,
    /// The connection predates authority ceilings, so no intent was ever
    /// recorded to bound a grant against.
    CeilingAbsent,
    /// An action the vendor's reviewed manifest never declares.
    UndeclaredAction(String),
    UnreviewedAction(String),
    ExplicitActionsRequired,
    HandleCeilingRequiresHandleGrant,
    /// The action is declared by the vendor, but sits outside the ceiling this
    /// CONNECTION was created with.
    ///
    /// Separate from `UndeclaredAction` because the operator's next step differs
    /// entirely: that one is a manifest problem, this one needs an explicit
    /// operator ceiling widening, not another ticket. Naming the ceiling saves
    /// the operator from querying the store to learn what they are bounded by.
    OutsideConnectionCeiling {
        action: String,
        ceiling: Vec<String>,
    },
    /// A risk above what the bounding ceiling permits.
    RiskAboveCeiling {
        requested: String,
        ceiling: String,
    },
    InvalidRisk(String),
    /// No actions remain after expanding the requested selectors.
    EmptyActionSelectors,
    /// A ticket named an existing connection of a different app. Its ceiling
    /// was resolved against the requested app's manifest, so attaching it to
    /// this connection would bound one vendor by another vendor's actions.
    ConnectionAppMismatch {
        connection_app: String,
        requested_app: String,
    },
    /// A ticket named a revoked connection. Revocation is final; recovery is a
    /// new connection under a new id.
    ConnectionRevoked,
    ConnectionExists,
    WildcardGrantee,
}

impl std::fmt::Display for CeremonyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownApp(key) => write!(f, "app '{key}' is not in the catalog"),
            Self::RetiredApp(key) => write!(
                f,
                "app '{key}' was withdrawn from the reviewed catalog and cannot be connected"
            ),
            Self::ConnectionNotFound => f.write_str("connection was not found"),
            Self::CeilingAbsent => {
                f.write_str("connection has no recorded authority ceiling; re-enroll it")
            }
            Self::UndeclaredAction(action) => {
                write!(
                    f,
                    "action '{action}' is not declared by the vendor manifest"
                )
            }
            Self::UnreviewedAction(action) => write!(f, "action '{action}' has no active reviewed catalog row on this connection"),
            Self::ExplicitActionsRequired => f.write_str("name each action explicitly; wildcard selectors are refused"),
            Self::HandleCeilingRequiresHandleGrant => f.write_str("GitHub bot handle connections must use handle-grant to widen their ceiling"),
            Self::OutsideConnectionCeiling { action, ceiling } => write!(
                f,
                "action '{action}' is outside this connection's ceiling [{}]",
                ceiling.join(", ")
            ),
            Self::RiskAboveCeiling { requested, ceiling } => {
                write!(f, "risk '{requested}' exceeds the ceiling '{ceiling}'")
            }
            Self::InvalidRisk(value) => write!(f, "'{value}' is not a valid risk"),
            Self::EmptyActionSelectors => {
                f.write_str("at least one action is required")
            }
            Self::ConnectionAppMismatch {
                connection_app,
                requested_app,
            } => write!(
                f,
                "this connection id belongs to app '{connection_app}', not '{requested_app}'; choose another connection id"
            ),
            Self::ConnectionExists => f.write_str("connection already exists; use rebind-credential to rotate its credential"),
            Self::WildcardGrantee => f.write_str("a grant must name an exact grantee, not '*'") ,
            Self::ConnectionRevoked => f.write_str(
                "this connection was revoked and cannot be re-enrolled; issue a ticket for a new connection id",
            ),
        }
    }
}

/// Ticket `ref_role` marking an enrollment for a vendor that needs no
/// credential at all. Distinct from any real credential role so a
/// credential-free connection can never be confused with one whose binding
/// simply failed to be written.
pub const NO_CREDENTIAL_REF_ROLE: &str = "none";

/// Outcome of configuring a connection's resource filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigureOutcome {
    /// Filters were replaced; carries the stored document.
    Configured(Value),
    /// The request carried a top-level key this operation does not read.
    ///
    /// Refused rather than ignored: an ignored key produces a success response
    /// beside filters that do not reflect what the caller asked for, and the
    /// operator's next move is to debug the vendor rather than their spelling.
    UnreadFilterKey {
        key: String,
        accepted: Vec<String>,
    },
    ConnectionNotFound,
    /// The connection's vendor manifest is no longer in the catalog, so there
    /// is nothing to bound the request against — refuse rather than trust it.
    ManifestMissing,
    /// A requested key is not declared by the vendor's manifest.
    UndeclaredFilter(String),
    /// A part of the request has the wrong JSON shape (`field` names it,
    /// `expected` says what it must be). Refused rather than dropped: a
    /// dropped part would report success beside filters the caller did not
    /// ask for.
    MalformedFilters {
        field: String,
        expected: String,
    },
}

/// App manifests are module-wide catalog DATA, not per-caller state: they are
/// ingested once at boot from the catalog directory and shared by every
/// principal. They are stored under this reserved principal so that
/// connection- and grant-scoped rows (which are genuinely per-caller) never
/// collide with them.
pub const CATALOG_PRINCIPAL: &str = "system";

#[derive(Clone, Copy)]
pub(crate) enum PlaneVerdict {
    Approved,
    Denied,
    Pending,
}

/// Pre-connection discovery view of an ingested app manifest: what an
/// operator needs to choose a vendor to connect, with no transport or
/// credential detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestSummary {
    pub key: String,
    pub name: String,
    pub description: String,
    pub tier: String,
    pub reuse_path: String,
    pub auth_mode: String,
    pub availability: String,
    pub action_count: usize,
    pub required_filters: Vec<String>,
    pub schema_version: u32,
    pub ingested_at_ms: i64,
    /// How many connections this principal already has for the vendor that
    /// can still serve. A revoked connection never becomes active again, so it
    /// is not counted.
    pub connection_count: i64,
}

/// A catalog action projection with no vendor credential state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogAction {
    pub connection_id: String,
    pub principal: String,
    pub name: String,
    pub title: Option<String>,
    pub schema: Value,
    pub schema_hash: String,
    pub risk: String,
    pub severity: String,
    /// Whether this action asks first on the default (no-policy) branch.
    /// Derived at reconcile time as the union of the hardcoded write/destructive
    /// floor and the manifest's declared `ask_first_risk`, so a manifest can
    /// widen but never narrow the floor. Fail-closed: a row with no recorded
    /// value reads as `true`.
    pub ask_first: bool,
    pub status: String,
    pub quarantine_reason: Option<String>,
    /// Declared write reconciliation class from the manifest/catalog, when present.
    pub reconciliation: Option<Value>,
    pub generation: i64,
}

/// The current catalog action together with the schema preserved for its review.
/// This projection is deliberately separate from [`CatalogAction`], which the
/// agent-facing catalog facade serializes and must not turn into a review surface.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CatalogActionReview {
    pub action: CatalogAction,
    pub reviewed_schema: Option<Value>,
}

/// Input for inserting or refreshing an observed catalog action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogActionInput {
    pub connection_id: String,
    pub principal: String,
    pub name: String,
    pub title: Option<String>,
    pub schema: Value,
    pub schema_hash: String,
    pub risk: String,
    pub severity: String,
    /// Whether this action asks first on the default (no-policy) branch. The
    /// reconciler computes this from the manifest; see [`CatalogAction::ask_first`].
    pub ask_first: bool,
    pub status: String,
    pub quarantine_reason: Option<String>,
    pub reconciliation: Option<Value>,
}

/// Operator-selected authority used only to enrich a subscription's derived events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorSource {
    pub connection_id: String,
    pub action: String,
    pub methods: Vec<String>,
}

/// Durable state for one agent-configured polling lease.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TriggerSubscription {
    pub subscription_id: String,
    pub principal: String,
    pub connection_id: String,
    pub action: String,
    pub cadence_s: i64,
    pub cursor_kind: String,
    pub cursor_state: Value,
    pub fixed_args: Value,
    pub schema_hash: String,
    pub status: String,
    pub suspended_reason: Option<String>,
    pub last_polled_at_ms: Option<i64>,
    pub last_success_at_ms: Option<i64>,
    pub cursor_age_ms: Option<i64>,
    pub consecutive_vendor_failures: i64,
    pub generation: i64,
    pub created_at_ms: i64,
    /// When the authority behind this watch lapses.
    ///
    /// A watch's poll grant may expire or remain live until revoked. Report a
    /// configured deadline even after it lapses so consumers can explain a feed
    /// that stopped. `None` means either no matching grant or an unexpiring grant;
    /// inspect `authority_state` to distinguish those cases.
    pub authority_expires_at_ms: Option<i64>,
    /// Whether that authority currently authorizes this subscription's action:
    /// `live`, `expired`, or `absent`.
    ///
    /// NOT SUFFICIENT ALONE to decide whether a watch is healthy. Revoking a
    /// connection deliberately leaves its grants intact -- authority and health
    /// are separate questions, and revocation answers the second -- so a watch
    /// on a revoked connection reports `live` here while never polling again.
    /// A reader must consult `status` and `suspended_reason` too; the pair is
    /// pinned by a test, because a consumer rendering health from authority
    /// alone would show a healthy watch on a dead connection.
    ///
    /// Derived from `GrantRecord::authorizes` rather than by comparing the
    /// timestamp above against a clock, because that comparison is only half the
    /// predicate -- a grant can be unexpired and still not name this action. A
    /// consumer deriving liveness from the timestamp alone would report a watch
    /// as healthy when its grant covers something else, which is the exact
    /// misreading that made any poll grant authorize any subscription before
    /// `authorizes` existed.
    pub authority_state: String,
    /// The project this watch's events belong to, set by the operator.
    ///
    /// A subscription names a CONNECTION and an ACTION; for a per-repo watch the
    /// repository lives in `fixed_args`, which is vendor request parameters and
    /// nothing more. Neither says which project the work belongs to, so a
    /// consumer routing events to a project's agent has nothing to route ON.
    ///
    /// `None` means the operator named no project, and a consumer must treat
    /// that as LOUDLY UNROUTABLE rather than falling back to a guess. A repo
    /// slug and a checkout path are not project identity -- one project can span
    /// several repositories, and one repository can be checked out at many paths
    /// -- so a derived value routes confidently to the WRONG place, which is
    /// worse than refusing to route at all.
    pub project_id: Option<String>,
    /// The registry agent selected to receive this watch's events.
    ///
    /// `deliver_to` is delivery metadata rather than authority. A consumer reads
    /// it before project-derived routing, while `project_id` remains attribution
    /// and the fallback when no explicit delivery target is stored.
    pub deliver_to: Option<String>,
    /// The separately governed read action used to identify actors on derived
    /// events. `None` means no operator has bound an enrichment source; it never
    /// falls back to the watched connection because that connection may have a
    /// permanently narrower ceiling.
    pub actor_source: Option<ActorSource>,
    /// Probe display name. Vendor watches have none: they are identified by
    /// action. A listing that omitted this would force every consumer to join
    /// the companion table to answer "which probe fired".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Who registered a probe. Provenance, never ownership -- the subscription
    /// row belongs to the connection owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered_by: Option<String>,
    /// `once` or `always` for a probe. Absent on vendor watches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rearm: Option<String>,
    /// The granted actions a probe may invoke. Absent on vendor watches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
}

/// Sentinel stored in `trigger_subscriptions.action` for a probe.
///
/// A probe watches a SET of actions, not one vendor endpoint, so the shared
/// column cannot name the thing being polled. The real set lives on the
/// companion row. This value keeps the NOT NULL column honest and lets the
/// poller branch on `cursor_kind` rather than on an action name that could
/// collide with a real vendor action.
pub const PROBE_SUBSCRIPTION_ACTION: &str = "probe";

/// The sole suspension reason an operator may resume.
///
/// A circuit breaker stops repeated vendor calls without changing the watch's
/// authority or reviewed safety. Every other suspension reason records a safety
/// decision and must remain stopped until a separate review resolves it.
pub const CIRCUIT_BREAKER_SUSPENSION_REASON: &str = "circuit_breaker_vendor_failures";

/// Durable probe-only fields, keyed on the subscription they belong to.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProbeSubscription {
    pub subscription_id: String,
    pub name: String,
    pub actions: Vec<String>,
    pub script_source: String,
    pub return_schema: Value,
    pub rearm: String,
    pub registered_by: String,
}

/// Inputs for registering a probe against a connection the caller may poll.
pub struct ProbeRegistration<'a> {
    pub name: &'a str,
    pub actions: &'a [String],
    pub script_source: &'a str,
    pub return_schema: &'a Value,
    pub rearm: &'a str,
    pub cadence_s: i64,
    pub fixed_args: &'a Value,
    pub cursor_state: &'a Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionRefusal {
    InvalidCadence,
    ConnectionNotFound,
    ConnectionInactive(String),
    ActionNotFound,
    ActionRiskNotRead,
    /// A seeded cursor state carries a key the cursor kind does not read.
    ///
    /// Refused rather than ignored because ignoring it produces a working-looking
    /// watch that behaves as though it were never seeded, and the difference is
    /// exactly the first event.
    CursorStateKeyUnknown {
        key: String,
        accepted: Vec<String>,
    },
    ActionUnavailable(String),
    ManifestMissing,
    ManifestInvalid(String),
    CursorShapeMissing,
    SnapshotItemCountCeilingRequired,
    PollGrantRequired,
    FixedArgsMustBeObject,
    FixedArgCursorOwned(String),
    FixedArgRequestConstant(String),
    FixedArgNotDeclared(String),
    /// The action's schema requires an argument the subscription does not supply
    /// and the poller cannot produce.
    FixedArgRequiredMissing(String),
    FixedArgTypeMismatch {
        key: String,
        expected: String,
        actual: String,
    },
    /// A probe named an action the authorizing poll grant does not cover.
    ///
    /// Registration mints nothing: every declared action must already be on
    /// that grant. Refusing here is what keeps a plan that needs new authority
    /// parked as an operator ask rather than silently widening the grant.
    ActionNotCoveredByGrant {
        action: String,
    },
    ProbeNameRequired,
    ProbeScriptRequired,
    ProbeSourceTooLarge,
    ProbeActionsRequired,
    ProbeReturnSchemaInvalid(String),
    ProbeRearmInvalid,
    /// `fixed_args` for a probe is a map of action name to that action's args,
    /// not a single flat object. A flat object would be validated against one
    /// schema and then applied to every action, which is the wrong check.
    FixedArgsMustBePerActionMap,
    /// Two connection owners granted this caller the same connection id.
    AmbiguousConnectionOwner,
}

/// Why a stored subscription cannot be resumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionResumeRefusal {
    SubscriptionNotFound,
    SubscriptionRetired,
    PollGrantRequired,
    /// Only a circuit-breaker suspension is operational. The optional value is
    /// retained so the caller can see the exact safety decision that blocked
    /// resumption; a missing stored reason is itself not safe to override.
    SuspensionNotResumable(Option<String>),
}

/// Why an operator-reviewed action could not be re-pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepinActionRefusal {
    ActionNotFound,
    ActionNotQuarantined(String),
    RiskNotRead(String),
    ExpectedHashMismatch { expected: String, current: String },
}

impl RepinActionRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ActionNotFound => "action_not_found",
            Self::ActionNotQuarantined(_) => "action_not_quarantined",
            Self::RiskNotRead(_) => "action_risk_not_read",
            Self::ExpectedHashMismatch { .. } => "expected_schema_hash_mismatch",
        }
    }
}

impl std::fmt::Display for RepinActionRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActionNotFound => formatter.write_str("action was not found in the catalog"),
            Self::ActionNotQuarantined(status) => {
                write!(formatter, "action is not quarantined (status: {status})")
            }
            Self::RiskNotRead(risk) => {
                write!(
                    formatter,
                    "action risk is '{risk}', but re-pinning requires read risk"
                )
            }
            Self::ExpectedHashMismatch { expected, current } => write!(
                formatter,
                "reviewed schema hash '{expected}' no longer matches current hash '{current}'"
            ),
        }
    }
}

impl SubscriptionResumeRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SubscriptionNotFound => "subscription_not_found",
            Self::PollGrantRequired => "poll_grant_required",
            Self::SuspensionNotResumable(_) => "suspension_not_resumable",
            Self::SubscriptionRetired => "subscription_retired",
        }
    }
}

impl std::fmt::Display for SubscriptionResumeRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SubscriptionRetired => {
                formatter.write_str("one-shot probe has finished and cannot be resumed")
            }
            Self::SubscriptionNotFound => formatter.write_str("subscription was not found"),
            Self::PollGrantRequired => {
                formatter.write_str("a poll grant permitting this action is required")
            }
            Self::SuspensionNotResumable(Some(reason)) => write!(
                formatter,
                "subscription suspended for '{reason}' cannot be resumed"
            ),
            Self::SuspensionNotResumable(None) => formatter
                .write_str("subscription has no recorded suspension reason and cannot be resumed"),
        }
    }
}

impl SubscriptionRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidCadence => "invalid_cadence",
            Self::ConnectionNotFound => "connection_not_found",
            Self::ConnectionInactive(_) => "connection_inactive",
            Self::ActionNotFound => "action_not_found",
            Self::ActionRiskNotRead => "trigger_requires_read_action",
            Self::ActionUnavailable(_) => "action_unavailable",
            Self::ManifestMissing => "manifest_missing",
            Self::ManifestInvalid(_) => "manifest_invalid",
            Self::CursorShapeMissing => "cursor_shape_missing",
            Self::SnapshotItemCountCeilingRequired => "snapshot_item_count_ceiling_required",
            Self::PollGrantRequired => "poll_grant_required",
            Self::FixedArgsMustBeObject => "fixed_args_must_be_object",
            Self::FixedArgCursorOwned(_) => "fixed_arg_cursor_owned",
            Self::FixedArgRequestConstant(_) => "fixed_arg_request_constant",
            Self::FixedArgNotDeclared(_) => "fixed_arg_not_declared",
            Self::FixedArgRequiredMissing(_) => "fixed_arg_required_missing",
            Self::FixedArgTypeMismatch { .. } => "fixed_arg_type_mismatch",
            Self::CursorStateKeyUnknown { .. } => "cursor_state_key_unknown",
            Self::ActionNotCoveredByGrant { .. } => "action_not_covered_by_grant",
            Self::ProbeNameRequired => "probe_name_required",
            Self::ProbeScriptRequired => "probe_script_required",
            Self::ProbeSourceTooLarge => "probe_source_too_large",
            Self::ProbeActionsRequired => "probe_actions_required",
            Self::ProbeReturnSchemaInvalid(_) => "probe_return_schema_invalid",
            Self::ProbeRearmInvalid => "probe_rearm_invalid",
            Self::FixedArgsMustBePerActionMap => "fixed_args_must_be_per_action_map",
            Self::AmbiguousConnectionOwner => "ambiguous_connection_owner",
        }
    }
}

impl std::fmt::Display for SubscriptionRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCadence => formatter.write_str("cadence_s must be positive"),
            Self::ConnectionNotFound => formatter.write_str("connection was not found"),
            Self::ConnectionInactive(status) => {
                write!(formatter, "connection is not active (status: {status})")
            }
            Self::ActionNotFound => formatter.write_str("action was not found in the catalog"),
            Self::ActionRiskNotRead => {
                formatter.write_str("triggers require an action with read risk")
            }
            // Names the accepted keys, because the caller supplied a starting
            // state on purpose and the useful reply is which spelling this
            // cursor kind reads -- not merely that theirs was wrong.
            Self::CursorStateKeyUnknown { key, accepted } => write!(
                formatter,
                "cursor_state key '{key}' is not read by this cursor kind (accepted: {})",
                accepted.join(", ")
            ),
            Self::ActionUnavailable(reason) => write!(formatter, "action is unavailable: {reason}"),
            Self::ManifestMissing => formatter.write_str("vendor manifest is not in the catalog"),
            Self::ManifestInvalid(reason) => {
                write!(formatter, "vendor manifest is invalid: {reason}")
            }
            Self::CursorShapeMissing => {
                formatter.write_str("action has no usable polling cursor shape")
            }
            Self::SnapshotItemCountCeilingRequired => {
                formatter.write_str("snapshot diff requires a positive item-count ceiling")
            }
            Self::PollGrantRequired => {
                formatter.write_str("a poll grant permitting this action is required")
            }
            Self::FixedArgsMustBeObject => formatter.write_str("fixed_args must be an object"),
            Self::FixedArgCursorOwned(key) => write!(
                formatter,
                "fixed_args key '{key}' is owned by the cursor strategy"
            ),
            Self::FixedArgRequestConstant(key) => write!(
                formatter,
                "fixed_args key '{key}' collides with a manifest request constant"
            ),
            Self::FixedArgNotDeclared(key) => write!(
                formatter,
                "fixed_args key '{key}' is not declared by the action schema"
            ),
            Self::FixedArgRequiredMissing(key) => write!(
                formatter,
                "the action requires '{key}', which fixed_args must supply"
            ),
            Self::FixedArgTypeMismatch {
                key,
                expected,
                actual,
            } => write!(
                formatter,
                "fixed_args key '{key}' has type {actual}, expected {expected}"
            ),
            Self::ActionNotCoveredByGrant { action } => {
                write!(formatter, "poll grant does not cover action '{action}'")
            }
            Self::ProbeNameRequired => formatter.write_str("probe name must be non-empty"),
            Self::ProbeScriptRequired => {
                formatter.write_str("probe script_source must be non-empty")
            }
            Self::ProbeSourceTooLarge => write!(
                formatter,
                "probe script_source exceeds {} bytes",
                plexus_probe::MAX_SOURCE_BYTES
            ),
            Self::ProbeActionsRequired => {
                formatter.write_str("probe must declare at least one action")
            }
            Self::ProbeReturnSchemaInvalid(reason) => {
                write!(formatter, "probe return_schema is invalid: {reason}")
            }
            Self::ProbeRearmInvalid => {
                formatter.write_str("probe rearm must be 'once' or 'always'")
            }
            Self::FixedArgsMustBePerActionMap => {
                formatter.write_str("probe fixed_args must be an object keyed by action name")
            }
            Self::AmbiguousConnectionOwner => formatter.write_str(
                "more than one connection owner granted this caller the named connection",
            ),
        }
    }
}

/// One stored `events_consume` grant the caller may exercise.
///
/// This is deliberately grant-scoped rather than collapsed to one caller-wide
/// state. A consumer can be live on one connection while expired on another,
/// and reducing those facts to one scalar would recreate the ambiguity this
/// projection exists to remove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventsConsumeAuthority {
    pub principal: String,
    pub connection_id: String,
    /// The grant deadline, retained after lapse so `expired` is actionable.
    pub authority_expires_at_ms: Option<i64>,
    /// Uses the subscription authority vocabulary: `live` or `expired` here.
    /// `absent` is represented by no record in the complete authority list.
    pub authority_state: String,
}

struct EventsConsumeGrant {
    owner: String,
    connection_id: String,
    selectors: Vec<String>,
    expires_at: Option<i64>,
    authority_state: &'static str,
}

/// Events visible to a caller together with the grants that made widening
/// possible. Keeping both in one result ensures the authority projection comes
/// from the same grant rows used to select events.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventsIncludingGranted {
    pub events: Vec<TriggerEvent>,
    /// Every `events_consume` grant this caller can exercise. A principal and
    /// connection absent from this complete list has no such grant.
    pub consume_authority: Vec<EventsConsumeAuthority>,
}

/// An event, or a marker recording that polling was suspended or otherwise
/// missed part of the vendor history, in the durable log.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TriggerEvent {
    pub event_id: String,
    pub principal: String,
    pub connection_id: String,
    pub subscription_id: String,
    pub vendor_event_id: Option<String>,
    pub payload_hash: String,
    pub payload: Value,
    pub kind: String,
    pub gap_from_ms: Option<i64>,
    pub gap_to_ms: Option<i64>,
    pub gap_reason: Option<String>,
    pub observed_at_ms: i64,
    pub acked_at_ms: Option<i64>,
    pub created_at_ms: i64,
    /// What the vendor's reviewed manifest says this action yields: `issue`,
    /// `pull_request`, `release`.
    ///
    /// DISTINCT FROM `kind` ABOVE, which is `event` or `gap` -- the two answer
    /// different questions and sharing a name would make a misread silent. This
    /// one says what the thing IS; `kind` says whether the row delivers content
    /// or records a hole in coverage.
    ///
    /// `None` on rows written before the manifest carried it, and on the direct
    /// insert path which has no manifest context to classify from.
    pub item_kind: Option<String>,
    /// When the vendor last touched this item, as the cursor strategy parsed it.
    ///
    /// Lets a consumer ask "has anything happened since I saw this?" without
    /// re-parsing a vendor-specific date field out of the payload. `None` for
    /// strategies with no per-item time: sync-token ordering is opaque and a
    /// scalar watch observes a value rather than a dated item.
    pub activity_at_ms: Option<i64>,
    /// GitHub logins that authored comments in this event's observation window.
    ///
    /// Absent means actor identity is unknown. A present empty array is narrower:
    /// the governed read succeeded and the first-observation window contained no
    /// comments. Unknown must stay absent on the wire so a consumer cannot mistake
    /// a failed enrichment for a known empty actor set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_logins: Option<Vec<String>>,
    /// Why the actors are unknown, as `{"reason": "<code>", "class": "<class>"}`.
    ///
    /// For an event whose subscription has an actor source, exactly one of
    /// this and `actor_logins` is present. Events with no actor source (release
    /// watches) and coverage gaps carry neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_unknown: Option<ActorUnknown>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerEventInsertOutcome {
    Inserted {
        event_id: String,
    },
    Duplicate {
        event_id: String,
        payload_hash: String,
    },
}

/// A selected watch may become inactive, or receive invalid poll input,
/// without the database failing.
#[derive(Debug)]
pub enum PollCommitError {
    Inactive,
    InvalidInput(&'static str),
    Store(StoreError),
}
impl From<StoreError> for PollCommitError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}
impl std::fmt::Display for PollCommitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inactive => formatter.write_str("subscription is no longer active"),
            Self::InvalidInput(reason) => formatter.write_str(reason),
            Self::Store(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for PollCommitError {}

/// One event extracted from a vendor response, borrowed for an atomic poll commit.
#[derive(Clone, Copy)]
pub struct PollEventInput<'a> {
    pub vendor_event_id: &'a str,
    pub payload: &'a Value,
    pub observed_at_ms: i64,
    /// What the reviewed manifest says this action yields. Constant for every
    /// event in one poll, carried per event so the row is self-describing.
    pub item_kind: Option<&'a str>,
    /// When the vendor last touched this item, as the strategy parsed it.
    pub activity_at_ms: Option<i64>,
    /// What the subscription's independent enrichment read learned about this
    /// event's actors: a login list (possibly a known-empty one), the reason
    /// they are unknown, or nothing because no enrichment applies.
    pub actor: &'a ActorAttribution,
}

/// One grant as an operator reads it: what it authorizes, on which vendor, who
/// holds it, and whether it is still in force.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GrantSummary {
    pub grant_id: String,
    pub connection_id: String,
    /// The vendor this connection speaks to. `None` only if the connection row is
    /// gone, which is itself worth showing rather than hiding.
    pub app_key: Option<String>,
    pub grantee_principal: String,
    pub risk_ceiling: String,
    pub action_selectors: Vec<String>,
    pub authority_kind: String,
    pub expires_at: Option<i64>,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub revoked_by: Option<String>,
    /// `revoked` | `until_revoked` | `live` | `expired`, derived here so no two readers can
    /// disagree about it.
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    pub grant_id: String,
    pub principal: String,
    pub connection_id: String,
    pub grantee_principal: String,
    pub risk_ceiling: String,
    pub action_selectors: Vec<String>,
    pub authority_kind: String,
    pub expires_at: Option<i64>,
    pub generation: i64,
    pub revoked_at_ms: Option<i64>,
    pub revoked_by: Option<String>,
    pub state: String,
}

fn grant_state(expires_at: Option<i64>, revoked_at_ms: Option<i64>, now: i64) -> &'static str {
    if revoked_at_ms.is_some() {
        "revoked"
    } else {
        match expires_at {
            Some(deadline) if deadline <= now => "expired",
            Some(_) => "live",
            None => "until_revoked",
        }
    }
}

impl GrantRecord {
    /// Whether this grant actually authorizes `action` at time `now`.
    ///
    /// Exists because `matching_grant` returns the NEAREST grant rather than an
    /// authorizing one -- it deliberately falls back to a grant that names the
    /// action but has expired, and then to one that is live but covers
    /// something else, so a caller can report a specific reason for the
    /// refusal. Its `Some` therefore means "here is the most relevant grant",
    /// never "this is allowed".
    ///
    /// A caller reading that `Some` as permission grants everything the
    /// fallbacks were meant to explain. That is not hypothetical: subscription
    /// creation did exactly this, so any poll grant on a connection authorized
    /// a subscription to any other action, and an expired grant authorized one
    /// too. Callers that need a verdict rather than an explanation should ask
    /// here rather than re-deriving the two conditions, since a re-derivation
    /// that omits one looks identical to a correct check at the call site.
    pub fn authorizes(&self, action: &str, now: i64) -> bool {
        let live = !self.expires_at.is_some_and(|expires_at| expires_at <= now);
        let names_action = self
            .action_selectors
            .iter()
            .any(|selector| selector == action || selector == "*");
        self.revoked_at_ms.is_none() && live && names_action
    }
}

/// Pick the one grant that answers "may this action run?" from every grant
/// row that could apply to a request. Grants are additive, so a live grant
/// that names the action wins wherever it sits in the list; the first row in
/// storage order must never decide on its own.
///
/// When no live grant names the action, the remaining fallbacks are ordered
/// by how specifically they answer the operator's question -- "why can this
/// action not run?".
///
/// A grant that NAMES the action and has expired is the most specific answer
/// available, so it outranks a live grant that simply covers something else.
/// The reverse order produces a genuinely misleading denial: a connection
/// watching two actions, where one poll grant lapses, would report the
/// surviving grant's selector mismatch and send an operator hunting a scope
/// problem when the fix is to renew. Poll grants may have a deadline or remain
/// live until revoked; this fallback explains the ones that do expire.
///
/// None of this changes WHETHER the request is refused. All three fallbacks
/// are refusals; the ordering only decides which reason the caller reports.
pub(crate) fn grant_candidate<'a>(
    rows: impl IntoIterator<Item = &'a GrantRecord>,
    action: &str,
    now: i64,
    requested_risk: Option<&str>,
) -> Option<&'a GrantRecord> {
    let mut live_matching = None;
    let mut candidate = None;
    let mut expired_matching = None;
    let mut expired_other = None;
    for grant in rows {
        let names_action = grant
            .action_selectors
            .iter()
            .any(|selector| selector == action || selector == "*");
        if grant.expires_at.is_some_and(|expires_at| expires_at <= now) {
            if names_action {
                expired_matching = Some(grant);
            } else {
                expired_other = Some(grant);
            }
            continue;
        }
        if names_action {
            if live_matching.is_none() {
                live_matching = Some(grant);
            }
            let covers_risk = requested_risk.is_none_or(|risk| {
                Risk::parse(risk)
                    .zip(Risk::parse(&grant.risk_ceiling))
                    .is_some_and(|(requested, ceiling)| requested.within(ceiling))
            });
            if covers_risk {
                return Some(grant);
            }
            continue;
        }
        if candidate.is_none() {
            candidate = Some(grant);
        }
    }
    live_matching
        .or(expired_matching)
        .or(candidate)
        .or(expired_other)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantInput {
    pub grant_id: String,
    pub principal: String,
    pub connection_id: String,
    pub grantee_principal: String,
    pub risk_ceiling: String,
    pub action_selectors: Vec<String>,
    pub authority_kind: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRecord {
    pub policy_id: String,
    pub principal: String,
    pub connection_id: String,
    pub action_selector: String,
    pub effect: String,
    pub expires_at: Option<i64>,
    pub generation: i64,
}

/// One policy as an operator reads it, with the connection's vendor and its
/// current liveness derived by the store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PolicySummary {
    pub policy_id: String,
    pub connection_id: String,
    /// The vendor this connection speaks to. `None` means the connection was
    /// removed but the policy remains visible so an operator can remove it.
    pub app_key: Option<String>,
    pub action_selector: String,
    pub effect: String,
    pub expires_at: Option<i64>,
    /// `until_revoked` | `live` | `expired`, derived once by the store.
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyInput {
    pub policy_id: String,
    pub principal: String,
    pub connection_id: String,
    pub action_selector: String,
    pub effect: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotGenerations {
    pub connection: i64,
    pub catalog_action: i64,
    pub grant: i64,
    pub policy: i64,
    #[serde(default)]
    pub policy_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationRecord {
    pub reservation_id: String,
    pub principal: String,
    pub connection_id: String,
    pub action: String,
    /// The grant that authorized this reservation. Revalidation pins THIS row
    /// rather than comparing a maximum across matching grants, so revoking the
    /// authorizing grant invalidates the reservation even when other grants on
    /// the same action survive.
    pub grant_id: String,
    pub snapshot: SnapshotGenerations,
    pub approved_args_hash: String,
    pub schema_hash: String,
    pub expires_at: i64,
    pub status: String,
    /// For a call made as an agent, the agent grant that authorized it and
    /// that grant's generation then. The claim pins it like the module grant,
    /// so revoking the agent grant before the send aborts the call.
    pub agent_grant: Option<PinnedGrant>,
}

/// A grant row and the generation it had when a reservation was authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedGrant {
    pub grant_id: String,
    pub generation: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingTicket {
    pub ticket_id: String,
    pub principal: String,
    pub connection_id: String,
    pub ref_role: String,
    pub expires_at: i64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionRequestRecord {
    pub request_id: String,
    pub principal: String,
    pub connection_id: String,
    pub action: String,
    pub args_snapshot: Value,
    pub args_hash: String,
    pub schema_hash: String,
    pub requester: String,
    pub status: String,
    pub decision: Option<String>,
    pub decider: Option<String>,
    pub expires_at: i64,
    /// Decision-plane decision id when the request was decision-authorized, if any.
    pub decision_id: Option<String>,
    /// `pending` | `confirmed` | `not_found` | `ambiguous` for outcome_unknown writes.
    pub reconciliation_status: Option<String>,
    /// The daemon scope the request was raised under; absent for a request
    /// raised on a route bound without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<RequestScope>,
    /// What re-checking that scope at execution decided: `approved_waiting`
    /// while the approval is held unsent, `not_run:<reason>` when refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_outcome: Option<String>,
    /// The key the carrier (`requester`) gave the call that raised this
    /// request, by which it can withdraw the call. Absent for a call sent
    /// without a key, which cannot be withdrawn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_key: Option<String>,
    /// True when the request was withdrawn by its carrier or its scope's
    /// owner (status `cancelled`), so whoever reviews the request list sees
    /// that it was withdrawn and will never run, not merely that it is closed.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub withdrawn: bool,
    /// The call from which the requesting call was relayed, when the relay
    /// stated one. Kept for attribution and deliberately not serialized: these
    /// are caller-stated identifiers, never shown in a reply to the caller.
    #[serde(skip)]
    pub relay_origin: Option<RelayOrigin>,
    /// The consent card filed with Cingulate for this request, when
    /// filing succeeded. The user can answer the request from that card.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elicitation_id: Option<String>,
}

/// How one consent answer settles a still-pending approval request, stored by
/// [`PlexusStore::settle_consent_requests`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentSettlement {
    /// The user declined the request on its card.
    Denied {
        principal: String,
        request_id: String,
        /// Who decided, as written in the request's `decider` column.
        decider: String,
    },
    /// The consent card expired without granting approval.
    Expired {
        principal: String,
        request_id: String,
    },
}

/// The call a relayed tool call came from, as the relay stated it in the
/// call's top-level `origin` member: the principal that carried the original
/// call and that carrier's key for it.
///
/// Caller-stated and recorded for attribution only. Nothing keys, dedupes,
/// authorizes or withdraws on it: every record of the relayed call stays
/// keyed on the principal that carried it here and that call's own
/// `call_key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayOrigin {
    /// The original carrier as a principal key, the form every principal
    /// column in this store uses, e.g. `reserved:broca`.
    pub carrier: String,
    /// The original carrier's key for the original call.
    pub call_key: String,
}

/// The status of an approval request that was withdrawn with `tool.withdraw`.
/// Terminal: nothing decides, claims or retries a request in this status.
pub const REQUEST_CANCELLED: &str = "cancelled";

/// The scope an approval request was raised under, as stored with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestScope {
    pub owner: String,
    #[serde(rename = "ref")]
    pub scope_ref: String,
    pub scope_epoch: u64,
    /// The scope's agent when the request was raised.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    pub delegates: bool,
    pub owner_authorized: bool,
}

impl RequestScope {
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_call_scope(scope: &CallScope) -> Self {
        Self {
            owner: scope.owner.clone(),
            scope_ref: scope.scope_ref.clone(),
            scope_epoch: scope.scope_epoch,
            agent_id: scope.agent_id.clone(),
            flow_id: scope.flow_id.clone(),
            delegates: scope.delegates,
            owner_authorized: scope.owner_authorized,
        }
    }

    /// The scope as a call carries it, for re-authorizing the request. The
    /// stamp fields an approval does not keep (`kind`, `parent`,
    /// `parent_state`) are absent.
    pub fn to_call_scope(&self) -> CallScope {
        CallScope {
            owner: self.owner.clone(),
            scope_ref: self.scope_ref.clone(),
            scope_epoch: self.scope_epoch,
            kind: None,
            parent: None,
            parent_state: None,
            agent_id: self.agent_id.clone(),
            delegates: self.delegates,
            owner_authorized: self.owner_authorized,
            flow_id: self.flow_id.clone(),
        }
    }
}

/// A fully read-back audit row. It intentionally mirrors only redacted columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRow {
    pub journal_id: i64,
    pub app_handle_id: Option<String>,
    pub ts: i64,
    pub principal: String,
    pub actor: String,
    pub acting_principal: String,
    pub agent_id: Option<String>,
    pub agent_handle: Option<String>,
    pub connection_id: Option<String>,
    pub app_key: Option<String>,
    pub action: Option<String>,
    pub risk: Option<String>,
    pub severity: Option<String>,
    pub decision: String,
    pub reason_code: String,
    pub gate: Option<String>,
    pub args_redaction_summary: Option<String>,
    pub outcome: Option<String>,
    pub latency_ms: Option<i64>,
    pub request_id: Option<String>,
    pub credential_fingerprint: Option<String>,
    pub provider_account_fingerprint: Option<String>,
    pub attempt_no: Option<i64>,
    pub vendor_request_id: Option<String>,
    pub idempotency_key_fingerprint: Option<String>,
    pub response_class: Option<String>,
    pub reconciliation_of: Option<String>,
    /// The daemon scope the call's route was bound under, when there was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<CallScope>,
}

/// One grant row attributed to an agent: what revoking it needs, plus the
/// connection for the audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentHeldGrant {
    pub principal: String,
    pub grant_id: String,
    pub connection_id: String,
}

/// The append-only audit input. Optional fields are nullable because startup
/// manifest events do not have a connection, request, or vendor response yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub principal: String,
    pub actor: String,
    pub acting_principal: String,
    pub agent_id: Option<String>,
    pub app_handle_id: Option<String>,
    pub agent_handle: Option<String>,
    pub connection_id: Option<String>,
    pub app_key: Option<String>,
    pub action: Option<String>,
    pub risk: Option<String>,
    pub severity: Option<String>,
    pub decision: String,
    pub reason_code: String,
    pub gate: Option<String>,
    pub args_redaction_summary: Option<String>,
    pub outcome: Option<String>,
    pub latency_ms: Option<i64>,
    pub request_id: Option<String>,
    pub credential_fingerprint: Option<String>,
    pub provider_account_fingerprint: Option<String>,
    pub attempt_no: Option<i64>,
    pub vendor_request_id: Option<String>,
    pub idempotency_key_fingerprint: Option<String>,
    pub response_class: Option<String>,
    pub reconciliation_of: Option<String>,
}

impl AuditRecord {
    /// Record a privileged ceremony operation. The credential handle is recorded
    /// as a fingerprint only, per the secret-dataflow model: the audit journal is
    /// an enumerated prohibited sink for raw handles.
    pub fn ceremony(
        principal: &str,
        app_key: Option<&str>,
        connection_id: Option<&str>,
        operation: &str,
        granted_risk: &str,
        handle_fingerprint: Option<&str>,
    ) -> Self {
        Self {
            principal: principal.to_string(),
            actor: "operator".to_string(),
            acting_principal: principal.to_string(),
            agent_id: None,
            agent_handle: None,
            app_handle_id: None,
            connection_id: connection_id.map(str::to_owned),
            app_key: app_key.map(str::to_owned),
            action: Some(operation.to_string()),
            risk: Some(granted_risk.to_string()),
            severity: None,
            decision: "allow".to_string(),
            reason_code: format!("ceremony_{operation}"),
            gate: Some("operator_ceremony".to_string()),
            args_redaction_summary: Some("privileged ceremony arguments withheld".to_string()),
            outcome: Some("recorded".to_string()),
            latency_ms: None,
            request_id: None,
            credential_fingerprint: handle_fingerprint.map(str::to_owned),
            provider_account_fingerprint: None,
            attempt_no: None,
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class: None,
            reconciliation_of: None,
        }
    }

    /// Record one grant removed because prefrontal reports its agent retired.
    ///
    /// The actor is plexus itself: no operator asked for this, the scheduled
    /// retirement sweep did. The grant id goes in the summary because the audit
    /// row has no grant column, and an operator reconciling a revocation needs
    /// to know which row went.
    pub fn agent_retired_revocation(
        principal: &str,
        agent_id: &str,
        connection_id: &str,
        grant_id: &str,
    ) -> Self {
        Self {
            principal: principal.to_string(),
            actor: "plexus".to_string(),
            acting_principal: principal.to_string(),
            agent_id: Some(agent_id.to_string()),
            agent_handle: None,
            app_handle_id: None,
            connection_id: Some(connection_id.to_string()),
            app_key: None,
            action: Some("revoke_grant".to_string()),
            risk: None,
            severity: None,
            decision: "allow".to_string(),
            reason_code: crate::agent_retirement::AGENT_RETIRED_REASON.to_string(),
            gate: Some("agent_retirement_sweep".to_string()),
            args_redaction_summary: Some(format!("grant {grant_id} revoked")),
            outcome: Some("recorded".to_string()),
            latency_ms: None,
            request_id: None,
            credential_fingerprint: None,
            provider_account_fingerprint: None,
            attempt_no: None,
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class: None,
            reconciliation_of: None,
        }
    }

    pub fn manifest_changed(principal: &str, app_key: &str) -> Self {
        Self {
            principal: principal.to_string(),
            actor: "plexus".to_string(),
            acting_principal: principal.to_string(),
            agent_id: None,
            agent_handle: None,
            app_handle_id: None,
            connection_id: None,
            app_key: Some(app_key.to_string()),
            action: Some("manifest_changed".to_string()),
            risk: None,
            severity: None,
            decision: "allow".to_string(),
            reason_code: "manifest_changed".to_string(),
            gate: Some("manifest_ingest".to_string()),
            args_redaction_summary: Some("manifest content hash changed".to_string()),
            outcome: Some("recorded".to_string()),
            latency_ms: None,
            request_id: None,
            credential_fingerprint: None,
            provider_account_fingerprint: None,
            attempt_no: None,
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class: None,
            reconciliation_of: None,
        }
    }
}

/// Select the single policy governing an action at `now`.
///
/// Authorization and reservation claiming must use this same query so expiry
/// and selector priority cannot drift between the snapshot's writer and reader.
fn governing_policy(
    conn: &Connection,
    principal: &str,
    connection_id: &str,
    action: &str,
    now: i64,
) -> rusqlite::Result<Option<PolicyRecord>> {
    conn.query_row(
        "SELECT policy_id, principal, connection_id, action_selector, effect,
                expires_at, generation
         FROM policies
         WHERE principal = ?1 AND connection_id = ?2
           AND (action_selector = ?3 OR action_selector = '*')
           AND (expires_at IS NULL OR expires_at > ?4)
         ORDER BY action_selector = '*' ASC, policy_id LIMIT 1",
        (principal, connection_id, action, now),
        |row| {
            Ok(PolicyRecord {
                policy_id: row.get(0)?,
                principal: row.get(1)?,
                connection_id: row.get(2)?,
                action_selector: row.get(3)?,
                effect: row.get(4)?,
                expires_at: row.get(5)?,
                generation: row.get(6)?,
            })
        },
    )
    .optional()
}

/// Find a reusable logical-write row for the same principal/connection/action/args/schema.
/// Pending rows are preferred; approved rows are accepted for re-attempts after a transient
/// failure, so a write retried after a transient failure keeps one `intent_id`.
///
/// Only a row raised under the same daemon scope (owner, ref and epoch, or
/// no scope at all) is reused: an approval is bound to the session it was
/// asked in, so one session's pending request must never collect another
/// session's call.
///
/// Only a row raised by a call without a `call_key` is reused. A keyed row
/// belongs to the one call that carried the key, and its carrier or scope
/// owner may withdraw it; an unkeyed call joining it would be withdrawn
/// along with it without having asked to be.
#[allow(clippy::too_many_arguments)]
fn find_action_request_by_shape_on_conn(
    conn: &Connection,
    principal: &str,
    connection_id: &str,
    action: &str,
    args: &Value,
    schema_hash: &str,
    now: i64,
    scope: Option<&CallScope>,
    requester: &str,
) -> rusqlite::Result<Option<ActionRequestRecord>> {
    let mut statement = conn.prepare(&format!(
        "SELECT {ACTION_REQUEST_COLUMNS}
             FROM action_requests
             WHERE principal = ?1 AND connection_id = ?2 AND action = ?3
               AND args_hash = ?4 AND schema_hash = ?5
               AND status IN ('pending', 'approved')
               AND expires_at > ?6
               AND scope_owner IS ?7 AND scope_ref IS ?8 AND scope_epoch IS ?9
                AND call_key IS NULL
                AND requester = ?10
              ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, created_at_ms"
    ))?;
    let rows = statement.query_map(
        rusqlite::params![
            principal,
            connection_id,
            action,
            jcs_sqlite_hash(args)?,
            schema_hash,
            now,
            scope.map(|scope| scope.owner.as_str()),
            scope.map(|scope| scope.scope_ref.as_str()),
            scope.map(|scope| epoch_to_sql(scope.scope_epoch)),
            requester,
        ],
        map_action_request_row,
    )?;
    for row in rows {
        let row = row?;
        if row.args_snapshot == *args {
            return Ok(Some(row));
        }
    }
    Ok(None)
}

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

macro_rules! trigger_subscription_columns {
    () => {
        "subscription_id, principal, connection_id, action, cadence_s,
         cursor_kind, cursor_state, fixed_args, schema_hash, status, suspended_reason,
         last_polled_at_ms, last_success_at_ms, consecutive_vendor_failures, generation,
         created_at_ms, project_id, deliver_to, actor_source_json"
    };
}
const TRIGGER_SUBSCRIPTION_COLUMNS: &str = trigger_subscription_columns!();
const DUE_SUBSCRIPTIONS_SELECT: &str = concat!(
    "SELECT ", trigger_subscription_columns!(), " FROM trigger_subscriptions
    WHERE principal = ?1 AND status = 'active'
    AND (last_polled_at_ms IS NULL OR last_polled_at_ms > ?2 OR (?2 - last_polled_at_ms) >= cadence_s * 1000)
    ORDER BY created_at_ms, subscription_id");

type ManifestCache =
    std::collections::BTreeMap<(String, String), (String, std::sync::Arc<AppManifest>)>;

/// Lease-guarded store for the plexus domain.
pub struct PlexusStore {
    inner: SqliteStore,
    manifest_cache: std::sync::Mutex<ManifestCache>,
    grant_journal: Option<PathBuf>,
    outbox_ready: tokio::sync::Notify,
    /// Run values from recent `workflow_run` webhooks, for later job webhooks.
    /// In memory only; empty after a restart.
    ci_runs: relay::CiRunCache,
}

impl PlexusStore {
    pub fn open(descriptor: &StorageDescriptor) -> Result<Self, StoreError> {
        let grant_journal = grant_journal_path(descriptor);
        // Parse before opening SQLite: malformed restore evidence must cause no writes.
        let revocations = grant_journal
            .as_deref()
            .map(|path| crate::grant_journal::scan(path, |_| Ok(())))
            .transpose()
            .map_err(StoreError::Backend)?
            .unwrap_or_default();
        let store = open_sqlite(descriptor)?;
        if let Some(path) = &grant_journal {
            crate::grant_journal::ensure(path).map_err(|e| StoreError::Backend(e.to_string()))?;
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
        // Canonical restores replace the database, not its siblings. Replay before
        // returning any authority-bearing handle, under the same writer fence.
        // An empty replay needs no write fence. Store copies can retain a database
        // epoch ahead of their fresh lease; opening them must not claim authority
        // when there are no revocations to apply.
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

    pub fn list_connections(&self, principal: &str) -> Result<Vec<ConnectionSummary>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT connection_id, app_key, status, generation
                 FROM connections WHERE principal = ?1 ORDER BY connection_id",
            )?;
            let rows = statement.query_map([principal], |row| {
                Ok(ConnectionSummary {
                    connection_id: row.get(0)?,
                    app_key: row.get(1)?,
                    status: row.get(2)?,
                    generation: row.get(3)?,
                })
            })?;
            rows.collect()
        })
    }

    /// Existence only: flow diagnostics may name an invisible requested connection,
    /// but must not load its configuration or grant dispatch authority.
    pub fn connection_id_exists(&self, connection_id: &str) -> Result<bool, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM connections WHERE connection_id=?1)",
                [connection_id],
                |row| row.get(0),
            )
        })
    }

    pub fn connection(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Option<ConnectionRecord>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT connection_id, principal, app_key, status, resource_filters,
                        health_state, generation, credential_binding IS NOT NULL
                 FROM connections WHERE principal = ?1 AND connection_id = ?2",
                (principal, connection_id),
                map_connection_row,
            )
            .optional()
        })
    }

    /// Resolve an invoke-visible connection without conferring invoke authority.
    ///
    /// Owned rows remain the fast path. A caller that owns no such row may see an
    /// owner's row only when that owner has named the caller in an invoke grant;
    /// expiry and action scope are deliberately left to the grant gate so it can
    /// return the precise refusal.
    ///
    /// When more than one owner shares the id with the caller, nothing says
    /// which owner's connection the caller meant, so none is returned (as probe
    /// registration refuses the same case as ambiguous) rather than whichever
    /// owner sorts first.
    pub fn connection_for_invoke(
        &self,
        caller: &str,
        connection_id: &str,
    ) -> Result<Option<ConnectionRecord>, StoreError> {
        if let Some(connection) = self.connection(caller, connection_id)? {
            return Ok(Some(connection));
        }
        let candidates: Vec<ConnectionRecord> = self.inner.with_read(|conn| {
            conn.prepare(
                "SELECT connection.connection_id, connection.principal, connection.app_key,
                        connection.status, connection.resource_filters, connection.health_state,
                        connection.generation, connection.credential_binding IS NOT NULL
                 FROM connections AS connection
                 WHERE connection.connection_id = ?2
                   AND EXISTS (
                       SELECT 1 FROM grants AS grant
                       WHERE grant.principal = connection.principal
                         AND grant.connection_id = connection.connection_id
                         AND grant.authority_kind = 'invoke'
                         AND grant.grantee_principal = ?1 AND grant.grantee_principal <> '*'
                   )
                 ORDER BY connection.principal
                 LIMIT 2",
            )?
            .query_map((caller, connection_id), map_connection_row)?
            .collect()
        })?;
        match <[ConnectionRecord; 1]>::try_from(candidates) {
            Ok([connection]) => Ok(Some(connection)),
            Err(candidates) => {
                if !candidates.is_empty() {
                    crate::diag!(warn storage: "connection {connection_id:?} is shared with {caller:?} by more than one owner; refusing to pick one");
                }
                Ok(None)
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn create_connection(
        &self,
        principal: &str,
        connection_id: &str,
        app_key: &str,
    ) -> Result<(), StoreError> {
        self.insert_connection(
            principal,
            connection_id,
            app_key,
            "pending",
            &Value::Object(Default::default()),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_connection(
        &self,
        principal: &str,
        connection_id: &str,
        app_key: &str,
        status: &str,
        resource_filters: &Value,
    ) -> Result<(), StoreError> {
        let filters = serde_json::to_string(resource_filters)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO connections
                    (connection_id, principal, app_key, status, resource_filters,
                     created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                rusqlite::params![connection_id, principal, app_key, status, filters, now],
            )?;
            Ok(())
        })
    }

    /// Replace a connection's resource filters, bounded by the vendor's
    /// reviewed manifest.
    ///
    /// The manifest declares WHICH filter keys exist and which of them enable
    /// writes; an operator may only choose the allowed VALUES for those keys.
    /// Accepting arbitrary keys here would let a caller invent a
    /// `write_enabling` key the vendor never declared and so satisfy the write
    /// gate without narrowing anything, which is the whole point of the gate.
    /// `write_enabling` is therefore intersected with the manifest's list, and
    /// `values` keys must be declared filter keys.
    pub fn configure_connection_filters(
        &self,
        principal: &str,
        connection_id: &str,
        requested: &Value,
    ) -> Result<ConfigureOutcome, StoreError> {
        let Some(connection) = self.connection(principal, connection_id)? else {
            return Ok(ConfigureOutcome::ConnectionNotFound);
        };
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, &connection.app_key)? else {
            return Ok(ConfigureOutcome::ManifestMissing);
        };
        let manifest = match document {
            Ok(manifest) => manifest,
            Err(error) => return Err(StoreError::Backend(error.to_string())),
        };
        let declared: std::collections::BTreeSet<&str> = manifest
            .resource_filters
            .required
            .iter()
            .chain(manifest.resource_filters.optional.iter())
            .chain(manifest.resource_filters.write_enabling.iter())
            .map(String::as_str)
            .collect();
        let manifest_write_enabling: std::collections::BTreeSet<&str> = manifest
            .resource_filters
            .write_enabling
            .iter()
            .map(String::as_str)
            .collect();

        // Only two keys are read here. A third -- most likely a near-miss of
        // one of them, `write_enabled` for `write_enabling` -- is not a
        // security hole, because an unrecognised key leaves `write_enabling`
        // EMPTY and writes stay blocked: the failure is fail-closed, and the
        // stored document is echoed back so the emptiness is visible.
        //
        // It is refused anyway because "configured successfully" plus
        // "nothing you asked for took effect" is a debugging session an
        // operator should never have to run. The caller named the key
        // deliberately, so the useful reply is which keys exist.
        let malformed = |field: &str, expected: &str| {
            Ok(ConfigureOutcome::MalformedFilters {
                field: field.to_string(),
                expected: expected.to_string(),
            })
        };
        let Some(requested) = requested.as_object() else {
            return malformed("resource_filters", "an object");
        };
        {
            const READ_KEYS: [&str; 2] = ["write_enabling", "values"];
            if let Some(unread) = requested
                .keys()
                .find(|key| !READ_KEYS.contains(&key.as_str()))
            {
                return Ok(ConfigureOutcome::UnreadFilterKey {
                    key: unread.clone(),
                    accepted: READ_KEYS.map(String::from).to_vec(),
                });
            }
        }

        let requested_write_enabling: Vec<&str> = match requested.get("write_enabling") {
            None => Vec::new(),
            Some(Value::Array(values)) => {
                let mut keys = Vec::with_capacity(values.len());
                for value in values {
                    let Some(key) = value.as_str() else {
                        return malformed("write_enabling", "an array of strings");
                    };
                    keys.push(key);
                }
                keys
            }
            Some(_) => return malformed("write_enabling", "an array of strings"),
        };
        if let Some(undeclared) = requested_write_enabling
            .iter()
            .find(|key| !manifest_write_enabling.contains(**key))
        {
            return Ok(ConfigureOutcome::UndeclaredFilter(
                (*undeclared).to_string(),
            ));
        }
        let requested_values = match requested.get("values") {
            None => None,
            Some(Value::Object(values)) => Some(values),
            Some(_) => return malformed("values", "an object"),
        };
        if let Some(values) = requested_values {
            if let Some(undeclared) = values.keys().find(|key| !declared.contains(key.as_str())) {
                return Ok(ConfigureOutcome::UndeclaredFilter(undeclared.clone()));
            }
        }

        let mut filters = serde_json::Map::new();
        filters.insert(
            "required".to_string(),
            Value::from(manifest.resource_filters.required.clone()),
        );
        filters.insert(
            "write_enabling".to_string(),
            Value::from(requested_write_enabling.clone()),
        );
        if let Some(values) = requested_values {
            filters.insert("values".to_string(), Value::Object(values.clone()));
        }
        let filters = Value::Object(filters);
        if self.set_connection_filters(principal, connection_id, &filters)? {
            Ok(ConfigureOutcome::Configured(filters))
        } else {
            Ok(ConfigureOutcome::ConnectionNotFound)
        }
    }

    pub fn set_connection_filters(
        &self,
        principal: &str,
        connection_id: &str,
        resource_filters: &Value,
    ) -> Result<bool, StoreError> {
        let filters = serde_json::to_string(resource_filters)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE connections SET resource_filters = ?1,
                        generation = generation + 1, updated_at_ms = ?2
                 WHERE principal = ?3 AND connection_id = ?4",
                rusqlite::params![filters, now, principal, connection_id],
            )?;
            Ok(changed != 0)
        })
    }

    /// Restore a connection that had been marked `degraded` after a refresh
    /// failure, once a refresh has succeeded again.
    ///
    /// Deliberately narrow: the UPDATE is guarded on `status = 'degraded'`, so
    /// it can only ever undo the transition `mark_degraded` makes. The other
    /// non-active statuses describe AUTHORITY rather than health — `revoked`,
    /// `disabled` and `pending` are states an operator or a credential failure
    /// put the connection into — and a successful vendor call is not grounds
    /// to clear any of them. Doing this in SQL rather than by reading the
    /// status and writing back keeps the guard inside the same statement, so a
    /// concurrent revoke cannot land between the read and the write.
    pub fn clear_connection_degraded(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<bool, StoreError> {
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE connections SET status = 'active', health_state = ?1,
                        generation = generation + 1, updated_at_ms = ?2
                 WHERE principal = ?3 AND connection_id = ?4 AND status = 'degraded'",
                rusqlite::params![
                    "{\"reason\":\"catalog_refresh_recovered\"}",
                    now,
                    principal,
                    connection_id
                ],
            )?;
            Ok(changed != 0)
        })
    }

    /// Restore a connection that was marked `auth_required` once its credential
    /// resolves successfully again.
    ///
    /// Deliberately narrow: the UPDATE is guarded on `status = 'auth_required'`,
    /// so it can only ever undo the transition credential resolution makes after
    /// an authentication-required failure. The other non-active statuses describe
    /// AUTHORITY rather than credential health — `revoked`, `disabled` and
    /// `pending` must not be cleared merely because a credential now resolves.
    /// Keeping the guard in SQL rather than reading the status first prevents a
    /// concurrent authority change from landing between the check and this write.
    ///
    /// THE REMAINING ABSENCES ARE DECLINED, NOT FORCED, and this note exists
    /// because two inverses now sit side by side. With `clear_connection_degraded`
    /// and this function adjacent, the next reader reaches for
    /// `clear_connection_revoked` by analogy, and nothing would tell them the gap
    /// was chosen: an absence leaves no symbol to read and no test to fail.
    ///
    /// `revoked` and `disabled` have no inverse because recovery must be a NEW
    /// CEREMONY: a fresh binding ticket and a fresh connection, which is how a
    /// permanent authority ceiling is supposed to arrive. Both are perfectly
    /// implementable and refused on purpose, so the decision is arguable — argue
    /// with it rather than assuming it is impossible. That is the distinction
    /// worth preserving: a DECLINED absence can be contested, an IMPOSSIBLE one
    /// cannot, and collapsing them either invites someone to build the
    /// impossible or stops them questioning a decision that deserves it.
    ///
    /// `pending` is neither: `connect` completes it, so its inverse exists under
    /// a different name.
    pub fn clear_connection_auth_required(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<bool, StoreError> {
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE connections SET status = 'active', health_state = ?1,
                        generation = generation + 1, updated_at_ms = ?2
                 WHERE principal = ?3 AND connection_id = ?4 AND status = 'auth_required'",
                rusqlite::params![
                    "{\"reason\":\"credential_auth_recovered\"}",
                    now,
                    principal,
                    connection_id
                ],
            )?;
            Ok(changed != 0)
        })
    }

    /// Update recoverable health state without granting revocation authority.
    /// A late probe cannot change any field of a permanently revoked row.
    pub fn set_connection_health(
        &self,
        principal: &str,
        connection_id: &str,
        status: &str,
        health_state: &Value,
    ) -> Result<bool, StoreError> {
        if status == "revoked" {
            return Err(StoreError::Backend(
                "health updates cannot revoke a connection; use revoke_connection".into(),
            ));
        }
        let health = serde_json::to_string(health_state)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE connections SET status = ?1, health_state = ?2,
                        generation = generation + 1, updated_at_ms = ?3
                 WHERE principal = ?4 AND connection_id = ?5 AND status <> 'revoked'",
                rusqlite::params![status, health, now, principal, connection_id],
            )?;
            Ok(changed != 0)
        })
    }

    /// Revoke a connection and invalidate every undispatched reservation in the
    /// same fenced transaction. This is deliberately not a best-effort cleanup.
    /// Its unconsumed binding tickets expire with it, so none can be presented
    /// afterwards.
    pub fn revoke_connection(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<bool, StoreError> {
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE connections SET status = 'revoked', generation = generation + 1,
                        updated_at_ms = ?1
                 WHERE principal = ?2 AND connection_id = ?3 AND status <> 'revoked'",
                rusqlite::params![now, principal, connection_id],
            )?;
            if changed != 0 {
                conn.execute(
                    "UPDATE reservations SET status = 'invalidated'
                     WHERE principal = ?1 AND connection_id = ?2 AND status = 'reserved'",
                    (principal, connection_id),
                )?;
                conn.execute(
                    "UPDATE binding_tickets SET status = 'expired'
                     WHERE principal = ?1 AND connection_id = ?2 AND status = 'issued'",
                    (principal, connection_id),
                )?;
            }
            Ok(changed != 0)
        })
    }

    /// Delete a connection on an operator's instruction, with every row keyed
    /// by it ([`CONNECTION_KEYED_TABLES`]) except its audit rows and grant
    /// revocation snapshots. This runtime operator delete leaves both in place;
    /// audit retention ages out audit rows, not revocation snapshots. Migration 40
    /// was a historical exception that purged both for eligible revoked connections.
    /// An audit row naming the deleted connection is written in the
    /// same transaction, so the delete and its record commit or roll back
    /// together.
    ///
    /// Refuses while any grant on the connection still authorizes someone (not
    /// expired; revoked grants have already left the `grants` table), so a
    /// delete can never silently cut off a consumer: revoking those grants is
    /// the explicit act. Expired grants are deleted with the connection.
    /// Refuses a connection that backs a GitHub App handle (`github-handle-*`,
    /// or any connection a `github_app_handle` row names), because the handle
    /// owns that connection's lifecycle. Any status may be deleted; the usual
    /// path is revoke the connection, revoke its grants, then delete it.
    ///
    /// The checks and the deletes share one fenced transaction, so a grant
    /// minted between the check and the delete cannot slip through. With
    /// `apply` false this is a dry run: the same checks and row counts, and
    /// nothing written.
    pub fn delete_connection(
        &self,
        principal: &str,
        connection_id: &str,
        apply: bool,
    ) -> Result<DeleteConnectionOutcome, StoreError> {
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let row: Option<(String, String)> = conn
                .query_row(
                    "SELECT app_key, status FROM connections
                     WHERE principal = ?1 AND connection_id = ?2",
                    (principal, connection_id),
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((app_key, status)) = row else {
                return Ok(DeleteConnectionOutcome::NotFound);
            };
            let backs_handle: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM github_app_handle
                     WHERE connection_principal = ?1 AND connection_id = ?2)",
                (principal, connection_id),
                |row| row.get(0),
            )?;
            if backs_handle || connection_id.starts_with(GITHUB_HANDLE_CONNECTION_PREFIX) {
                return Ok(DeleteConnectionOutcome::HandleConnection);
            }
            let live_grants: i64 = conn.query_row(
                "SELECT COUNT(*) FROM grants
                 WHERE principal = ?1 AND connection_id = ?2
                   AND (expires_at IS NULL OR expires_at > ?3)",
                (principal, connection_id, now),
                |row| row.get(0),
            )?;
            if live_grants > 0 {
                return Ok(DeleteConnectionOutcome::HasLiveGrants { count: live_grants });
            }
            if apply {
                event_outbox::count_dropped(
                    conn,
                    "principal = ?1 AND connection_id = ?2",
                    (principal, connection_id),
                    "dropped_on_delete",
                )?;
            }
            let mut rows = Vec::with_capacity(CONNECTION_KEYED_TABLES.len());
            for (table, keyed_by) in CONNECTION_KEYED_TABLES {
                let count: i64 = if apply {
                    conn.execute(
                        &format!("DELETE FROM {table} WHERE {keyed_by}"),
                        (principal, connection_id),
                    )? as i64
                } else {
                    conn.query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE {keyed_by}"),
                        (principal, connection_id),
                        |row| row.get(0),
                    )?
                };
                rows.push((*table, count));
            }
            if !apply {
                return Ok(DeleteConnectionOutcome::WouldDelete {
                    app_key,
                    status,
                    rows,
                });
            }
            conn.execute(
                "DELETE FROM connections WHERE principal = ?1 AND connection_id = ?2",
                (principal, connection_id),
            )?;
            // Row counts and the prior status are not secrets, and they are
            // what a later reader of the trail needs to know what went.
            let summary = format!(
                "deleted connection (status {status}); rows: {}",
                rows.iter()
                    .map(|(table, count)| format!("{table}={count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            conn.execute(
                "INSERT INTO audit_journal (ts, principal, actor, acting_principal, connection_id,
                     app_key, action, risk, decision, reason_code, gate, args_redaction_summary,
                     outcome)
                 VALUES (?1, ?2, 'operator', ?2, ?3, ?4, 'delete_connection', 'read', 'allow',
                     'ceremony_delete_connection', 'operator_ceremony', ?5, 'applied')",
                rusqlite::params![now, principal, connection_id, app_key, summary],
            )?;
            Ok(DeleteConnectionOutcome::Deleted {
                app_key,
                status,
                rows,
            })
        })
    }

    /// Mark an observed action quarantined and invalidate outstanding invokes
    /// that were authorized against the previous catalog generation. A trigger
    /// on the action is suspended in this same fenced transaction, so the
    /// catalog cannot expose a quarantined action while its subscription remains
    /// active.
    #[cfg(any(test, feature = "test-support"))]
    pub fn quarantine_action(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let observed_at_ms = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE catalog_actions SET status = 'quarantined',
                        quarantine_reason = ?1,
                        reviewed_schema_json = CASE
                            WHEN status <> 'quarantined' THEN schema_json
                            ELSE reviewed_schema_json
                        END,
                        generation = generation + 1, last_seen_at_ms = ?2
                 WHERE principal = ?3 AND connection_id = ?4 AND name = ?5",
                rusqlite::params![reason, observed_at_ms, principal, connection_id, action],
            )?;
            if changed != 0 {
                conn.execute(
                    "UPDATE reservations SET status = 'invalidated'
                     WHERE principal = ?1 AND connection_id = ?2 AND action = ?3
                       AND status = 'reserved'",
                    (principal, connection_id, action),
                )?;
            }
            suspend_subscriptions_for_action(
                conn,
                principal,
                connection_id,
                action,
                Some("quarantined"),
                observed_at_ms,
            )?;
            Ok(changed != 0)
        })
    }

    /// Re-activate one quarantined read action after a human has reviewed the
    /// current schema. The action transition, subscription re-pins, and
    /// generation invalidation share one fence so an in-flight poll or reservation
    /// cannot survive a review against the prior catalog generation.
    pub fn repin_reviewed_action(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        expected_schema_hash: &str,
    ) -> Result<Result<CatalogAction, RepinActionRefusal>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let current: Option<(String, String, String)> = conn
                .query_row(
                    "SELECT schema_hash, risk, status FROM catalog_actions
                     WHERE principal = ?1 AND connection_id = ?2 AND name = ?3",
                    (principal, connection_id, action),
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((current_schema_hash, risk, status)) = current else {
                return Ok(Err(RepinActionRefusal::ActionNotFound));
            };
            if risk != "read" {
                return Ok(Err(RepinActionRefusal::RiskNotRead(risk)));
            }
            if current_schema_hash != expected_schema_hash {
                return Ok(Err(RepinActionRefusal::ExpectedHashMismatch {
                    expected: expected_schema_hash.to_string(),
                    current: current_schema_hash,
                }));
            }

            // The status predicate belongs in this statement rather than only in
            // the read above: a disable that lands between the read and write must
            // remain disabled, not be laundered into active by this review path.
            let activated = conn.execute(
                "UPDATE catalog_actions
                 SET status = 'active', quarantine_reason = NULL, generation = generation + 1
                 WHERE principal = ?1 AND connection_id = ?2 AND name = ?3
                   AND status = 'quarantined'",
                (principal, connection_id, action),
            )?;
            if activated == 0 {
                return Ok(Err(RepinActionRefusal::ActionNotQuarantined(status)));
            }
            conn.execute(
                "UPDATE reservations SET status = 'invalidated'
                 WHERE principal = ?1 AND connection_id = ?2 AND action = ?3
                   AND status = 'reserved'",
                (principal, connection_id, action),
            )?;

            // Every subscription now pins the reviewed current shape. Only schema
            // drift is resolved by this ceremony; another suspension reason is a
            // separate safety decision and remains suspended with its cursor intact.
            conn.execute(
                "UPDATE trigger_subscriptions
                 SET schema_hash = ?1,
                     status = CASE
                         WHEN status = 'suspended' AND suspended_reason = 'schema_changed'
                             THEN 'active'
                         ELSE status
                     END,
                     suspended_reason = CASE
                         WHEN status = 'suspended' AND suspended_reason = 'schema_changed'
                             THEN NULL
                         ELSE suspended_reason
                     END,
                     generation = generation + 1
                 WHERE principal = ?2 AND connection_id = ?3 AND action = ?4
                   AND (schema_hash IS NOT ?1
                        OR (status = 'suspended' AND suspended_reason = 'schema_changed'))",
                (expected_schema_hash, principal, connection_id, action),
            )?;

            let reactivated = conn.query_row(
                &format!(
                    "SELECT {CATALOG_ACTION_COLUMNS}
                     FROM catalog_actions
                     WHERE principal = ?1 AND connection_id = ?2 AND name = ?3"
                ),
                (principal, connection_id, action),
                map_catalog_action_row,
            )?;
            Ok(Ok(reactivated))
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn upsert_catalog_action(&self, input: &CatalogActionInput) -> Result<(), StoreError> {
        let schema = serde_json::to_string(&input.schema)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let reconciliation = input
            .reconciliation
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let observed_at_ms = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let reviewed_schema: Option<String> = if input.status == "quarantined" {
                conn.query_row(
                    "SELECT schema_json, status FROM catalog_actions
                     WHERE principal = ?1 AND connection_id = ?2 AND name = ?3",
                    (&input.principal, &input.connection_id, &input.name),
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
                .and_then(|(schema, status)| (status != "quarantined").then_some(schema))
            } else {
                None
            };
            upsert_catalog_action_row(
                conn,
                input,
                &schema,
                reconciliation.as_deref(),
                reviewed_schema.as_deref(),
                observed_at_ms,
            )?;
            if input.status == "quarantined" {
                conn.execute(
                    "UPDATE reservations SET status = 'invalidated'
                     WHERE principal = ?1 AND connection_id = ?2 AND action = ?3
                       AND status = 'reserved'",
                    (&input.principal, &input.connection_id, &input.name),
                )?;
            }
            suspend_subscriptions_for_action(
                conn,
                &input.principal,
                &input.connection_id,
                &input.name,
                catalog_suspension_reason(input),
                observed_at_ms,
            )?;
            Ok(())
        })
    }

    /// Seed the observed catalog from the reviewed manifest for a new connection.
    /// Keeping the seeder connection-scoped lets handle import use the same
    /// catalog logic within its transaction, without publishing partial handles.
    pub fn seed_catalog_from_manifest(
        &self,
        principal: &str,
        connection_id: &str,
        app_key: &str,
    ) -> Result<usize, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            seed_catalog_from_manifest_on_conn(
                conn,
                principal,
                connection_id,
                app_key,
                SeedMode::AddMissing,
            )
        })
    }

    /// Apply a transport catalog refresh. New or schema-changed write actions
    /// are quarantined until a reviewer explicitly reactivates them. The
    /// catalog write and any trigger suspension happen in one fenced
    /// transaction, so a refresh cannot leave a risky action pollable.
    #[cfg(any(test, feature = "test-support"))]
    pub fn refresh_catalog_action(&self, input: CatalogActionInput) -> Result<(), StoreError> {
        self.inner
            .with_conn_fenced(|conn| refresh_catalog_action_on_conn(conn, input, now_ms()))
    }

    /// Commit a complete catalog observation, including missing-action cascades,
    /// atomically. An empty observation cannot erase a live catalog.
    pub fn reconcile_catalog_actions(
        &self,
        principal: &str,
        connection_id: &str,
        actions: &[CatalogActionInput],
    ) -> Result<(), StoreError> {
        if actions
            .iter()
            .any(|input| input.principal != principal || input.connection_id != connection_id)
        {
            return Err(StoreError::Backend(
                "catalog observation refused: scope mismatch".into(),
            ));
        }
        let accepted = self.inner.with_conn_fenced(|conn| {
            let mut statement = conn.prepare("SELECT name FROM catalog_actions WHERE principal=?1 AND connection_id=?2 AND status <> 'disabled'")?;
            let existing: Vec<String> = statement.query_map((principal, connection_id), |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
            if actions.is_empty() && !existing.is_empty() {
                return Ok(false);
            }
            let now = now_ms();
            for input in actions {
                refresh_catalog_action_on_conn(conn, input.clone(), now)?;
            }
            for name in existing {
                if !actions.iter().any(|input| input.name == name) {
                    disable_catalog_action_on_conn(conn, principal, connection_id, &name, now)?;
                }
            }
            Ok(true)
        })?;
        if !accepted {
            return Err(StoreError::Backend(
                "catalog observation refused: empty observation".into(),
            ));
        }
        Ok(())
    }

    pub fn list_catalog_actions(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Vec<CatalogAction>, StoreError> {
        self.list_catalog_actions_with_status(principal, connection_id, true)
    }

    /// Return every observed action, including quarantined and disabled rows.
    /// The public catalog projection above remains active-only for callers that
    /// are selecting actions to invoke.
    pub fn list_catalog_actions_all(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Vec<CatalogAction>, StoreError> {
        self.list_catalog_actions_with_status(principal, connection_id, false)
    }

    fn list_catalog_actions_with_status(
        &self,
        principal: &str,
        connection_id: &str,
        active_only: bool,
    ) -> Result<Vec<CatalogAction>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(&format!(
                "SELECT {CATALOG_ACTION_COLUMNS}
                  FROM catalog_actions
                  WHERE principal = ?1 AND connection_id = ?2
                    AND (?3 = 0 OR (status = 'active' AND NOT {APP_RETIRED_PREDICATE}))
                  ORDER BY name"
            ))?;
            let rows = statement.query_map(
                (principal, connection_id, if active_only { 1 } else { 0 }),
                map_catalog_action_row,
            )?;
            rows.collect()
        })
    }

    /// Disable an action missing from a successful catalog refresh and consume
    /// any reservation that was approved against it. Any trigger on the action
    /// is suspended in this same fenced transaction.
    #[cfg(any(test, feature = "test-support"))]
    pub fn disable_catalog_action(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            disable_catalog_action_on_conn(conn, principal, connection_id, action, now_ms())
        })
    }

    pub fn catalog_last_seen_at(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Option<i64>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT MAX(last_seen_at_ms) FROM catalog_actions
                 WHERE principal = ?1 AND connection_id = ?2",
                (principal, connection_id),
                |row| row.get(0),
            )
        })
    }

    /// Read one catalog action INCLUDING quarantined and disabled rows. The
    /// public `list_catalog_actions` projection is active-only because callers
    /// use it to choose an action to invoke; this accessor exists for operators
    /// and tests that need to see why an action is not available.
    pub fn catalog_action(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
    ) -> Result<Option<CatalogAction>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                &format!(
                    "SELECT {CATALOG_ACTION_COLUMNS}
                 FROM catalog_actions
                 WHERE principal = ?1 AND connection_id = ?2 AND name = ?3"
                ),
                (principal, connection_id, action),
                map_catalog_action_row,
            )
            .optional()
        })
    }

    /// Read the current and last approved schemas for an operator reviewing a
    /// quarantined action. Ordinary catalog listings omit the approval snapshot.
    pub fn catalog_action_review(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
    ) -> Result<Option<CatalogActionReview>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                &format!(
                    "SELECT {CATALOG_ACTION_COLUMNS}, reviewed_schema_json
                     FROM catalog_actions
                     WHERE principal = ?1 AND connection_id = ?2 AND name = ?3"
                ),
                (principal, connection_id, action),
                |row| {
                    let reviewed_schema: Option<String> = row.get(14)?;
                    Ok(CatalogActionReview {
                        action: map_catalog_action_row(row)?,
                        reviewed_schema: reviewed_schema
                            .as_deref()
                            .map(parse_json_column)
                            .transpose()?,
                    })
                },
            )
            .optional()
        })
    }

    /// Read the reviewed manifest's declared poll shape. Missing manifests,
    /// actions and poll declarations return None.
    pub fn poll_shape(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
    ) -> Result<Option<PollShape>, StoreError> {
        let Some(connection) = self.connection(principal, connection_id)? else {
            return Ok(None);
        };
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, &connection.app_key)? else {
            return Ok(None);
        };
        let manifest = document.map_err(StoreError::Backend)?;
        Ok(manifest
            .actions_baseline
            .iter()
            .find(|candidate| candidate.name == action)
            .and_then(|baseline| baseline.poll.clone()))
    }

    /// The top-level argument names an action's reviewed manifest declares in
    /// `http.args_schema.properties`, read from the manifest rather than the
    /// pinned catalog row because a row seeded before the manifest's schema was
    /// pinned may still hold the open placeholder schema. `None` when the
    /// connection, its manifest, the action or its REST schema is missing.
    ///
    /// Plexus code that builds vendor arguments for a REST action uses this to
    /// send each call only the arguments that action declares: the REST
    /// transport sends every non-path argument to the vendor.
    pub fn reviewed_arg_names(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
    ) -> Result<Option<std::collections::BTreeSet<String>>, StoreError> {
        let Some(connection) = self.connection(principal, connection_id)? else {
            return Ok(None);
        };
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, &connection.app_key)? else {
            return Ok(None);
        };
        let manifest = document.map_err(StoreError::Backend)?;
        Ok(manifest
            .actions_baseline
            .iter()
            .find(|candidate| candidate.name == action)
            .and_then(|baseline| baseline.http.as_ref())
            .and_then(|http| http.args_schema.get("properties"))
            .and_then(Value::as_object)
            .map(|properties| properties.keys().cloned().collect()))
    }

    pub fn subscribe(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        cadence_s: i64,
    ) -> Result<Result<TriggerSubscription, SubscriptionRefusal>, StoreError> {
        self.subscribe_with_cursor_state(
            principal,
            connection_id,
            action,
            cadence_s,
            &Value::Object(Default::default()),
            &Value::Object(Default::default()),
        )
    }

    pub fn subscribe_with_cursor_state(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        cadence_s: i64,
        cursor_state: &Value,
        fixed_args: &Value,
    ) -> Result<Result<TriggerSubscription, SubscriptionRefusal>, StoreError> {
        self.prepare_subscription(
            principal,
            connection_id,
            action,
            cadence_s,
            cursor_state,
            fixed_args,
            false,
        )
    }

    // Automatic watches validate the entire pair before inserting either row.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_subscription(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        cadence_s: i64,
        cursor_state: &Value,
        fixed_args: &Value,
        prepare_only: bool,
    ) -> Result<Result<TriggerSubscription, SubscriptionRefusal>, StoreError> {
        if cadence_s <= 0 {
            return Ok(Err(SubscriptionRefusal::InvalidCadence));
        }
        if !fixed_args.is_object() {
            return Ok(Err(SubscriptionRefusal::FixedArgsMustBeObject));
        }
        let Some(connection) = self.connection(principal, connection_id)? else {
            return Ok(Err(SubscriptionRefusal::ConnectionNotFound));
        };
        if connection.status != "active" {
            return Ok(Err(SubscriptionRefusal::ConnectionInactive(
                connection.status,
            )));
        }
        let Some(catalog_action) = self.catalog_action(principal, connection_id, action)? else {
            return Ok(Err(SubscriptionRefusal::ActionNotFound));
        };
        if catalog_action.risk != "read" {
            return Ok(Err(SubscriptionRefusal::ActionRiskNotRead));
        }
        if catalog_action.status != "active" {
            let reason = catalog_action
                .quarantine_reason
                .unwrap_or_else(|| catalog_action.status.clone());
            return Ok(Err(SubscriptionRefusal::ActionUnavailable(reason)));
        }
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, &connection.app_key)? else {
            return Ok(Err(SubscriptionRefusal::ManifestMissing));
        };
        let manifest = match document {
            Ok(manifest) => manifest,
            Err(error) => return Ok(Err(SubscriptionRefusal::ManifestInvalid(error))),
        };
        let Some(baseline) = manifest
            .actions_baseline
            .iter()
            .find(|candidate| candidate.name == action)
        else {
            return Ok(Err(SubscriptionRefusal::CursorShapeMissing));
        };
        let Some(poll) = baseline.poll.as_ref() else {
            return Ok(Err(SubscriptionRefusal::CursorShapeMissing));
        };
        if matches!(poll.cursor_kind, CursorKind::SnapshotDiff)
            && poll.item_count_ceiling.unwrap_or(0) == 0
        {
            return Ok(Err(SubscriptionRefusal::SnapshotItemCountCeilingRequired));
        }
        // Collected while refusing collisions, so the two uses cannot disagree
        // about which keys the poller supplies: the same set that a
        // subscription may not set is the set it need not set.
        let mut supplied_elsewhere: BTreeSet<String> = BTreeSet::new();
        if let Some(strategy) = crate::poller::strategy_for(poll.cursor_kind.as_str(), Some(poll)) {
            // A seeded starting state must be one this strategy will actually
            // READ. Seeding is how a threshold watch is expressed -- a scalar
            // seeded with a value the subscriber has already seen reports on its
            // first poll rather than baselining -- and every strategy resolves
            // its state by key, so a seed under the wrong key silently resolves
            // to "no previous value".
            //
            // That failure is invisible in the worst way: the subscription is
            // accepted, polls happily, and behaves exactly like an UNSEEDED
            // watch, so the one event the subscriber asked for is the one that
            // never arrives. Refusing at subscribe time turns a typo at a console
            // into an immediate error naming the accepted keys.
            if let Some(seeded) = cursor_state.as_object() {
                let readable = strategy.state_keys();
                for key in seeded.keys() {
                    if !readable.contains(key) {
                        return Ok(Err(SubscriptionRefusal::CursorStateKeyUnknown {
                            key: key.clone(),
                            accepted: readable,
                        }));
                    }
                }
            }
            for key in strategy.owned_keys() {
                supplied_elsewhere.insert(key.clone());
                if fixed_args.get(&key).is_some() {
                    // A fixed value here pins the watermark forever: the poller
                    // keeps re-reading one window, dedupe hides the repeats, and
                    // the subscription looks healthy while delivering nothing.
                    return Ok(Err(SubscriptionRefusal::FixedArgCursorOwned(key)));
                }
            }
        }
        if let Some(request_constants) = poll.request_constants.as_ref() {
            for key in request_constants.keys() {
                supplied_elsewhere.insert(key.clone());
                if fixed_args.get(key).is_some() {
                    // A subscription silently losing to a manifest constant is
                    // indistinguishable from its value being honoured, so refuse
                    // it here rather than letting precedence decide quietly.
                    return Ok(Err(SubscriptionRefusal::FixedArgRequestConstant(
                        key.clone(),
                    )));
                }
            }
        }
        if let Err(refusal) =
            validate_fixed_args(fixed_args, &catalog_action.schema, &supplied_elsewhere)
        {
            return Ok(Err(refusal));
        }
        // `matching_grant` is a DIAGNOSTIC resolver, not an authorization check.
        // When nothing authorizes the action it still returns the nearest grant
        // on the connection so a caller can report a specific reason, so a
        // `Some` means "a poll grant exists here", never "this action is
        // authorized". The returned grant must therefore be checked before it
        // is trusted -- governance's `authorize` does exactly that, and rejects
        // with a selector or expiry denial.
        //
        // Reading it as a boolean let ANY poll grant on the connection
        // authorize a subscription to ANY other action with a declared poll
        // shape: a grant scoped to one read action would raise a standing
        // background poll of a different one, which is precisely the narrowing
        // the per-action selector exists to enforce.
        let now = now_ms();
        let authorizing = self
            .matching_grant(
                principal,
                connection_id,
                principal,
                action,
                crate::governance::AUTHORITY_POLL,
                now,
                None,
            )?
            .filter(|grant| grant.authorizes(action, now));
        let Some(authorizing) = authorizing else {
            return Ok(Err(SubscriptionRefusal::PollGrantRequired));
        };
        let authorizing_expiry = authorizing.expires_at;
        let cursor_value = cursor_state.clone();
        let fixed_value = fixed_args.clone();
        let cursor_state = serde_json::to_string(cursor_state)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let fixed_args = serde_json::to_string(fixed_args)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let subscription_id = new_id("subscription");
        let created_at_ms = now_ms();
        let cursor_kind = poll.cursor_kind.as_str().to_string();
        if !prepare_only {
            race_point("subscription_insert");
            // The checks above ran outside this transaction, so a quarantine,
            // a revoked connection or a revoked grant may have landed since.
            // Check the facts they established again here, where nothing can
            // change before the insert commits.
            let refusal = self.inner.with_conn_fenced(|conn| {
                if let Some(refusal) = recheck_watch_preconditions(
                    conn,
                    principal,
                    connection_id,
                    &[(action, Some(catalog_action.schema_hash.as_str()))],
                )? {
                    return Ok(Some(refusal));
                }
                let grant_live: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM grants
                        WHERE principal = ?1 AND grant_id = ?2
                          AND (expires_at IS NULL OR expires_at > ?3))",
                    rusqlite::params![principal, authorizing.grant_id, now_ms()],
                    |row| row.get(0),
                )?;
                if !grant_live {
                    return Ok(Some(SubscriptionRefusal::PollGrantRequired));
                }
                conn.execute(
                    "INSERT INTO trigger_subscriptions
                    (subscription_id, principal, connection_id, action, cadence_s,
                     cursor_kind, cursor_state, fixed_args, schema_hash, status,
                     generation, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'active', 0, ?10)",
                    rusqlite::params![
                        subscription_id,
                        principal,
                        connection_id,
                        action,
                        cadence_s,
                        cursor_kind,
                        cursor_state,
                        fixed_args,
                        catalog_action.schema_hash,
                        created_at_ms,
                    ],
                )?;
                Ok(None)
            })?;
            if let Some(refusal) = refusal {
                return Ok(Err(refusal));
            }
        }
        Ok(Ok(TriggerSubscription {
            subscription_id,
            principal: principal.to_string(),
            connection_id: connection_id.to_string(),
            action: action.to_string(),
            cadence_s,
            cursor_kind,
            cursor_state: cursor_value,
            fixed_args: fixed_value,
            schema_hash: catalog_action.schema_hash,
            status: "active".to_string(),
            suspended_reason: None,
            last_polled_at_ms: None,
            last_success_at_ms: None,
            cursor_age_ms: None,
            consecutive_vendor_failures: 0,
            generation: 0,
            created_at_ms,
            // The grant that just authorized this subscription is live by
            // construction -- `authorizes` returned true two statements ago, so
            // re-resolving it here would only introduce a way for the two to
            // disagree.
            authority_expires_at_ms: authorizing_expiry,
            authority_state: "live".to_string(),
            // Never set at subscribe. Binding a project is a SEPARATE operator
            // act via `set_subscription_project`, because the 59 watches already
            // running were minted before this field existed and a mint-only path
            // would force unsubscribe-and-resubscribe to bind them -- discarding
            // every cursor and re-backfilling each repo against the vendor.
            project_id: None,
            deliver_to: None,
            actor_source: None,
            name: None,
            registered_by: None,
            rearm: None,
            actions: None,
        }))
    }

    /// Register a probe against a connection the caller is already allowed to poll.
    ///
    /// THE SUBSCRIPTION ROW BELONGS TO THE CONNECTION OWNER. The caller is
    /// recorded as `registered_by` provenance and is not the owner. This is
    /// forced: every poll-time lookup (connection, catalog action, credential)
    /// is owner-scoped, so a row owned by the registrant would fail at the
    /// first lookup because the registrant owns no connection.
    ///
    /// Authority is the existing `poll` grant naming the caller as grantee.
    /// Registration mints nothing -- every declared action must already be
    /// covered by that grant.
    pub fn register_probe(
        &self,
        registrant: &str,
        connection_id: &str,
        request: ProbeRegistration<'_>,
    ) -> Result<Result<TriggerSubscription, SubscriptionRefusal>, StoreError> {
        let name = request.name.trim();
        if name.is_empty() {
            return Ok(Err(SubscriptionRefusal::ProbeNameRequired));
        }
        if request.script_source.len() > plexus_probe::MAX_SOURCE_BYTES {
            return Ok(Err(SubscriptionRefusal::ProbeSourceTooLarge));
        }
        if request.script_source.trim().is_empty() {
            return Ok(Err(SubscriptionRefusal::ProbeScriptRequired));
        }
        if request.cadence_s <= 0 {
            return Ok(Err(SubscriptionRefusal::InvalidCadence));
        }
        let rearm = request.rearm.trim();
        if rearm != "once" && rearm != "always" {
            return Ok(Err(SubscriptionRefusal::ProbeRearmInvalid));
        }
        let mut actions: BTreeSet<String> = BTreeSet::new();
        for action in request.actions {
            let action = action.trim();
            if action.is_empty() {
                continue;
            }
            actions.insert(action.to_string());
        }
        if actions.is_empty() {
            return Ok(Err(SubscriptionRefusal::ProbeActionsRequired));
        }
        if let Err(reason) = validate_probe_return_schema(request.return_schema) {
            return Ok(Err(SubscriptionRefusal::ProbeReturnSchemaInvalid(reason)));
        }
        let Some(fixed_args) = request.fixed_args.as_object() else {
            return Ok(Err(SubscriptionRefusal::FixedArgsMustBePerActionMap));
        };
        for key in fixed_args.keys() {
            if !actions.contains(key) {
                return Ok(Err(SubscriptionRefusal::FixedArgNotDeclared(key.clone())));
            }
            if !fixed_args[key].is_object() {
                return Ok(Err(SubscriptionRefusal::FixedArgsMustBePerActionMap));
            }
        }
        if !request.cursor_state.is_object() {
            return Ok(Err(SubscriptionRefusal::FixedArgsMustBeObject));
        }

        let now = now_ms();
        let granted = self.poll_connections(registrant, now)?;
        let matching: Vec<&(String, String, Vec<String>)> = granted
            .iter()
            .filter(|(_, granted_connection, _)| granted_connection == connection_id)
            .collect();
        // Grants are additive: two poll grants from one owner together cover
        // the union of their selectors. Each poll of each action is authorized
        // separately and any one live grant naming it suffices, so the probe
        // may rely on the union too.
        let (owner, selectors): (&str, Vec<String>) = match matching.as_slice() {
            [] => return Ok(Err(SubscriptionRefusal::PollGrantRequired)),
            [first, rest @ ..] => {
                if rest.iter().any(|(owner, _, _)| owner != &first.0) {
                    return Ok(Err(SubscriptionRefusal::AmbiguousConnectionOwner));
                }
                (
                    first.0.as_str(),
                    matching
                        .iter()
                        .flat_map(|(_, _, selectors)| selectors.iter().cloned())
                        .collect(),
                )
            }
        };

        let Some(connection) = self.connection(owner, connection_id)? else {
            return Ok(Err(SubscriptionRefusal::ConnectionNotFound));
        };
        if connection.status != "active" {
            return Ok(Err(SubscriptionRefusal::ConnectionInactive(
                connection.status,
            )));
        }

        let empty_elsewhere = BTreeSet::new();
        let mut pinned_actions = std::collections::BTreeMap::new();
        for action in &actions {
            let covered = selectors
                .iter()
                .any(|selector| selector == action || selector == "*");
            if !covered {
                return Ok(Err(SubscriptionRefusal::ActionNotCoveredByGrant {
                    action: action.clone(),
                }));
            }
            let Some(catalog_action) = self.catalog_action(owner, connection_id, action)? else {
                return Ok(Err(SubscriptionRefusal::ActionNotFound));
            };
            if catalog_action.risk != "read" {
                return Ok(Err(SubscriptionRefusal::ActionRiskNotRead));
            }
            if catalog_action.status != "active" {
                let reason = catalog_action
                    .quarantine_reason
                    .unwrap_or_else(|| catalog_action.status.clone());
                return Ok(Err(SubscriptionRefusal::ActionUnavailable(reason)));
            }
            pinned_actions.insert(action.clone(), catalog_action.schema_hash.clone());
            let action_args = fixed_args
                .get(action)
                .cloned()
                .unwrap_or_else(|| Value::Object(Default::default()));
            if let Err(refusal) =
                validate_fixed_args(&action_args, &catalog_action.schema, &empty_elsewhere)
            {
                return Ok(Err(refusal));
            }
        }

        // Pin the return schema, not a vendor action schema: a probe has no
        // single action whose hash would describe the watch.
        let action_list: Vec<String> = actions.into_iter().collect();
        let schema_hash = jcs_store_hash(request.return_schema)?;
        let cursor_state = serde_json::to_string(request.cursor_state)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let fixed_args_json = serde_json::to_string(request.fixed_args)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let actions_json = serde_json::to_string(&action_list)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let return_schema_json = serde_json::to_string(request.return_schema)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let subscription_id = new_id("subscription");
        let created_at_ms = now_ms();
        race_point("probe_insert");
        let refusal = self.inner.with_conn_fenced(|conn| {
            let pins: Vec<_> = pinned_actions.iter().map(|(action, hash)| (action.as_str(), Some(hash.as_str()))).collect();
            if let Some(refusal) = recheck_watch_preconditions(conn, owner, connection_id, &pins)? {
                return Ok(Some(refusal));
            }
            let mut grants = conn.prepare("SELECT action_selectors FROM grants WHERE principal=?1 AND connection_id=?2 AND grantee_principal=?3 AND authority_kind='poll' AND (expires_at IS NULL OR expires_at>?4)")?;
            let selectors: Vec<Vec<String>> = grants.query_map(rusqlite::params![owner,connection_id,registrant,now_ms()], |row| parse_string_list(&row.get::<_, String>(0)?))?.collect::<rusqlite::Result<_>>()?;
            for action in pinned_actions.keys() {
                if !selectors.iter().flatten().any(|selector| selector == action || selector == "*") {
                    return Ok(Some(SubscriptionRefusal::PollGrantRequired));
                }

            }
            conn.execute(
                "INSERT INTO trigger_subscriptions
                    (subscription_id, principal, connection_id, action, cadence_s,
                     cursor_kind, cursor_state, fixed_args, schema_hash, status,
                     generation, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'probe', ?6, ?7, ?8, 'active', 0, ?9)",
                rusqlite::params![
                    subscription_id,
                    owner,
                    connection_id,
                    PROBE_SUBSCRIPTION_ACTION,
                    request.cadence_s,
                    cursor_state,
                    fixed_args_json,
                    schema_hash,
                    created_at_ms,
                ],
            )?;
            conn.execute(
                "INSERT INTO probe_subscriptions
                    (subscription_id, name, actions, script_source, return_schema,
                     rearm, registered_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    subscription_id,
                    name,
                    actions_json,
                    request.script_source,
                    return_schema_json,
                    rearm,
                    registrant,
                ],
            )?;
            Ok(None)
        })?;
        if let Some(refusal) = refusal {
            return Ok(Err(refusal));
        }
        let mut subscription = TriggerSubscription {
            subscription_id,
            principal: owner.to_string(),
            connection_id: connection_id.to_string(),
            action: PROBE_SUBSCRIPTION_ACTION.to_string(),
            cadence_s: request.cadence_s,
            cursor_kind: "probe".to_string(),
            cursor_state: request.cursor_state.clone(),
            fixed_args: request.fixed_args.clone(),
            schema_hash,
            status: "active".to_string(),
            suspended_reason: None,
            last_polled_at_ms: None,
            last_success_at_ms: None,
            cursor_age_ms: None,
            consecutive_vendor_failures: 0,
            generation: 0,
            created_at_ms,
            authority_expires_at_ms: None,
            authority_state: "live".to_string(),
            project_id: None,
            deliver_to: None,
            actor_source: None,
            name: Some(name.to_string()),
            registered_by: Some(registrant.to_string()),
            rearm: Some(rearm.to_string()),
            actions: Some(action_list),
        };
        let (expiry, state) = self.subscription_authority(&subscription, now_ms())?;
        subscription.authority_expires_at_ms = expiry;
        subscription.authority_state = state.to_string();
        Ok(Ok(subscription))
    }

    /// Connections whose actions `grantee` may poll, by explicit grant.
    ///
    /// Same shape as [`Self::events_consume_connections`]: owner, connection,
    /// and the grant's action selectors, with expiry enforced here so a lapsed
    /// grant cannot authorize a registration through a path that forgot to
    /// check it.
    pub(crate) fn poll_connections(
        &self,
        grantee: &str,
        now_ms: i64,
    ) -> Result<Vec<(String, String, Vec<String>)>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT principal, connection_id, action_selectors, expires_at
                 FROM grants
                 WHERE authority_kind = ?1
                   AND grantee_principal = ?2 AND grantee_principal <> '*'
                 ORDER BY grant_id",
            )?;
            let rows =
                statement.query_map((crate::governance::AUTHORITY_POLL, grantee), |row| {
                    let selectors: String = row.get(2)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        parse_string_list(&selectors)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                })?;
            let mut granted = Vec::new();
            for row in rows {
                let (owner, connection_id, selectors, expires_at) = row?;
                if expires_at.is_some_and(|deadline| deadline <= now_ms) {
                    continue;
                }
                granted.push((owner, connection_id, selectors));
            }
            Ok(granted)
        })
    }

    /// Probe-only fields for one subscription, if it is a probe.
    pub fn probe_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<Option<ProbeSubscription>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT subscription_id, name, actions, script_source, return_schema,
                        rearm, registered_by
                 FROM probe_subscriptions
                 WHERE subscription_id = ?1",
                [subscription_id],
                map_probe_subscription_row,
            )
            .optional()
        })
    }

    fn attach_probe_fields(
        &self,
        subscriptions: &mut [TriggerSubscription],
    ) -> Result<(), StoreError> {
        let ids: Vec<_> = subscriptions
            .iter()
            .filter(|subscription| subscription.cursor_kind == "probe")
            .map(|subscription| subscription.subscription_id.clone())
            .collect();
        if ids.is_empty() {
            return Ok(());
        }
        let probes=self.inner.with_read(|conn| {
            let mut probes=std::collections::BTreeMap::new();
            for chunk in ids.chunks(900) {
                let placeholders=vec!["?";chunk.len()].join(",");
                let mut query=conn.prepare(&format!("SELECT subscription_id,name,registered_by,rearm,actions FROM probe_subscriptions WHERE subscription_id IN ({placeholders})"))?;
                let rows=query.query_map(rusqlite::params_from_iter(chunk),|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,parse_string_list(&row.get::<_,String>(4)?)?)))?;
                for row in rows { let (id,name,registrant,rearm,actions)=row?; probes.insert(id,(name,registrant,rearm,actions)); }
            }
            Ok(probes)
        })?;
        for subscription in subscriptions {
            if let Some((name, registrant, rearm, actions)) =
                probes.get(&subscription.subscription_id)
            {
                subscription.name = Some(name.clone());
                subscription.registered_by = Some(registrant.clone());
                subscription.rearm = Some(rearm.clone());
                subscription.actions = Some(actions.clone());
            }
        }
        Ok(())
    }

    fn subscription_authority(
        &self,
        subscription: &TriggerSubscription,
        now: i64,
    ) -> Result<(Option<i64>, &'static str), StoreError> {
        self.inner.with_read(|conn| {
            let grants = poll_grants_on_conn(
                conn,
                &subscription.principal,
                Some(&subscription.connection_id),
                now,
            )?;
            Ok(subscription_authority_from_grants(
                subscription,
                &grants,
                now,
            ))
        })
    }

    /// Bind (or clear) the project a subscription's events belong to.
    ///
    /// A SEPARATE operator act rather than a mint parameter, because the watches
    /// that need it most already exist: binding a project at mint only would mean
    /// unsubscribe-and-resubscribe for every running watch, which discards each
    /// cursor and re-backfills its repository against the vendor. One
    /// pull-request backfill on a busy repository can take tens of seconds of
    /// sequential polling and hundreds of events, so that cost is real rather
    /// than theoretical.
    ///
    /// `None` CLEARS the binding, and clearing is deliberately expressible: an
    /// operator who bound the wrong project must be able to say "no project"
    /// again rather than being stuck choosing between two wrong answers. A
    /// consumer reads the cleared state as loudly unroutable, which is the
    /// correct reading of "nobody has decided".
    ///
    /// Scoped to the caller's principal like every other write here, so one
    /// principal cannot re-route another's watch. Returns whether a row changed,
    /// so a caller naming an unknown subscription learns it did nothing instead
    /// of assuming success.
    ///
    /// Routing metadata leaves the subscription change counter unchanged.
    /// This counter is not part of governance's reservation snapshot.
    pub fn set_subscription_project(
        &self,
        principal: &str,
        subscription_id: &str,
        project_id: Option<&str>,
    ) -> Result<bool, StoreError> {
        // An empty or whitespace-only string is treated as CLEARING rather than
        // stored as a project named "". A stored empty string would satisfy a
        // consumer's "is it present" check while carrying no routing
        // information, which is worse than absence because it silently passes
        // the gate that exists to catch absence.
        let normalized = project_id.map(str::trim).filter(|value| !value.is_empty());
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE trigger_subscriptions SET project_id = ?1,
                     project_source = CASE WHEN ?1 IS NULL THEN NULL ELSE 'hand' END
                 WHERE principal = ?2 AND subscription_id = ?3",
                rusqlite::params![normalized, principal, subscription_id],
            )?;
            Ok(changed > 0)
        })
    }

    /// Bind (or clear) the registry agent that should receive a subscription's events.
    ///
    /// Delivery routing gives `deliver_to` precedence over project-derived routing;
    /// `project_id` remains attribution and the consumer's fallback. This stores
    /// routing metadata only: a consumer handles an agent that retires later.
    ///
    /// Scoped to the caller's principal like every other write here, so one
    /// principal cannot re-route another's watch. Returns whether a row changed.
    ///
    /// Delivery metadata leaves the subscription change counter unchanged.
    /// This counter is not a reservation fence.
    pub fn set_subscription_deliver_to(
        &self,
        principal: &str,
        subscription_id: &str,
        deliver_to: Option<&str>,
    ) -> Result<bool, StoreError> {
        // An empty or blank target clears the binding, as it does for a
        // project label: a stored "" would read as "routed somewhere" while
        // naming no agent.
        let deliver_to = deliver_to.map(str::trim).filter(|value| !value.is_empty());
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE trigger_subscriptions SET deliver_to = ?1
                 WHERE principal = ?2 AND subscription_id = ?3",
                rusqlite::params![deliver_to, principal, subscription_id],
            )?;
            Ok(changed > 0)
        })
    }

    /// Bind (or clear) the separately governed source used for actor enrichment.
    ///
    /// This is a separate operator act so an existing watch keeps its cursor and
    /// vendor history. Replacing the watch's connection would unsubscribe and
    /// re-subscribe under a different dedupe identity, re-backfilling every item;
    /// the actor read instead needs only its own permanently narrowed connection.
    ///
    /// `None` clears the binding. The write is principal-scoped and reports
    /// whether the named subscription row exists, matching
    /// [`Self::set_subscription_project`].
    ///
    /// The subscription change counter is not advanced for enrichment metadata.
    /// Actor reads are authorized independently against the source connection;
    /// this counter is not used to fence governance reservations.
    pub fn set_subscription_actor_source(
        &self,
        principal: &str,
        subscription_id: &str,
        actor_source: Option<&ActorSource>,
    ) -> Result<bool, StoreError> {
        let actor_source_json = actor_source
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE trigger_subscriptions SET actor_source_json = ?1
                 WHERE principal = ?2 AND subscription_id = ?3",
                rusqlite::params![actor_source_json, principal, subscription_id],
            )?;
            Ok(changed > 0)
        })
    }

    /// Corrupt a stored subscription only in unit tests, so poll-path tests can
    /// prove the runtime precedence guard against legacy rows that predate it.
    #[cfg(test)]
    pub(crate) fn replace_fixed_args_for_test(
        &self,
        principal: &str,
        subscription_id: &str,
        fixed_args: &Value,
    ) -> Result<(), StoreError> {
        let fixed_args = serde_json::to_string(fixed_args)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE trigger_subscriptions SET fixed_args = ?1
                 WHERE principal = ?2 AND subscription_id = ?3",
                rusqlite::params![fixed_args, principal, subscription_id],
            )?;
            Ok(())
        })
    }

    pub fn subscription(
        &self,
        principal: &str,
        subscription_id: &str,
    ) -> Result<Option<TriggerSubscription>, StoreError> {
        let mut found = self.inner.with_read(|conn| {
            conn.query_row(
                &format!(
                    "SELECT {TRIGGER_SUBSCRIPTION_COLUMNS} FROM trigger_subscriptions
                  WHERE principal = ?1 AND subscription_id = ?2"
                ),
                (principal, subscription_id),
                |row| map_trigger_subscription_row(row, now_ms()),
            )
            .optional()
        })?;
        if let Some(subscription) = found.as_mut() {
            self.attach_probe_fields(std::slice::from_mut(subscription))?;
        }
        Ok(found)
    }

    /// Count and longest cadence of subscriptions the scheduler can still act on.
    ///
    /// Suspended subscriptions remain stored so their reason and cursor can be
    /// inspected or resumed, but they are not work waiting for the scheduler.
    /// The optional result makes an empty active set explicit: there is no maximum
    /// cadence to invent when there is no work.
    pub fn active_subscription_schedule(&self) -> Result<Option<(u64, u64)>, StoreError> {
        let (count, max_cadence_s): (i64, Option<i64>) = self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT COUNT(*), MAX(cadence_s)
                   FROM trigger_subscriptions
                  WHERE status = 'active'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })?;

        match (count, max_cadence_s) {
            (0, None) => Ok(None),
            (count, Some(max_cadence_s)) if count > 0 && max_cadence_s > 0 => {
                Ok(Some((count as u64, max_cadence_s as u64)))
            }
            unexpected => Err(StoreError::Backend(format!(
                "active subscription schedule is inconsistent: {unexpected:?}"
            ))),
        }
    }

    pub fn list_subscriptions(
        &self,
        principal: &str,
        connection_id: Option<&str>,
        subscription_id: Option<&str>,
    ) -> Result<Vec<TriggerSubscription>, StoreError> {
        let now = now_ms();
        let mut subscriptions = self.inner.with_read(|conn| {
            let mut sql = format!("SELECT {TRIGGER_SUBSCRIPTION_COLUMNS} FROM trigger_subscriptions WHERE principal=?1");
            if connection_id.is_some() { sql.push_str(" AND connection_id=?2"); }
            if subscription_id.is_some() { sql.push_str(" AND subscription_id=?3"); }
            sql.push_str(" ORDER BY created_at_ms,subscription_id");
            let mut statement = conn.prepare(&sql)?;
            statement.raw_bind_parameter(1, principal)?;
            if let Some(connection) = connection_id { statement.raw_bind_parameter(2, connection)?; }
            if let Some(subscription) = subscription_id { statement.raw_bind_parameter(3, subscription)?; }
            let rows = statement.raw_query().mapped(|row| map_trigger_subscription_row(row, now));
            let subscriptions: Vec<TriggerSubscription> = rows.collect::<rusqlite::Result<_>>()?;
            Ok(subscriptions)
        })?;
        self.attach_probe_fields(&mut subscriptions)?;

        let grants = self
            .inner
            .with_read(|conn| poll_grants_on_conn(conn, principal, connection_id, now))?;
        for subscription in &mut subscriptions {
            let (expires_at, state) =
                subscription_authority_from_grants(subscription, &grants, now);
            subscription.authority_expires_at_ms = expires_at;
            subscription.authority_state = state.to_string();
        }
        Ok(subscriptions)
    }

    /// List owned and granted watches, filtering selectors before decoding rows.
    /// Probe metadata and poll authority are loaded once for the selected lanes,
    /// rather than once per overlapping consume grant.
    pub fn list_subscriptions_including_granted(
        &self,
        principal: &str,
        connection_id: Option<&str>,
        subscription_id: Option<&str>,
        now_ms_value: i64,
    ) -> Result<Vec<TriggerSubscription>, StoreError> {
        let mut subscriptions = self.inner.with_read(|conn| {
            let mut statement = conn.prepare(&format!(
                "SELECT {TRIGGER_SUBSCRIPTION_COLUMNS} FROM trigger_subscriptions
                 WHERE (?2 IS NULL OR connection_id=?2) AND (?3 IS NULL OR subscription_id=?3)
                 AND (principal=?1 OR EXISTS (
                    SELECT 1 FROM grants g, json_each(g.action_selectors) selector
                    WHERE g.principal=trigger_subscriptions.principal
                    AND g.connection_id=trigger_subscriptions.connection_id
                    AND g.grantee_principal=?1 AND g.grantee_principal<>'*'
                    AND g.authority_kind='events_consume' AND (g.expires_at IS NULL OR g.expires_at>?4)
                    AND (selector.value=trigger_subscriptions.action OR selector.value='*')))
                 ORDER BY created_at_ms,subscription_id"
            ))?;
            let rows = statement.query_map(rusqlite::params![principal, connection_id, subscription_id, now_ms_value],
                |row| map_trigger_subscription_row(row, now_ms_value))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })?;
        self.attach_probe_fields(&mut subscriptions)?;
        let lanes: BTreeSet<_> = subscriptions
            .iter()
            .map(|sub| (&sub.principal, &sub.connection_id))
            .collect();
        let lanes = serde_json::to_string(&lanes)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let grants = self.inner.with_read(|conn| {
            let mut query = conn.prepare(
                "SELECT grant_id,principal,connection_id,grantee_principal,risk_ceiling,
                 action_selectors,authority_kind,expires_at,generation FROM grants
                 WHERE authority_kind='poll' AND grantee_principal<>'*'
                 AND (principal,connection_id) IN (SELECT json_extract(value,'$[0]'),json_extract(value,'$[1]') FROM json_each(?1))
                 ORDER BY grant_id"
            )?;
            let rows = query.query_map([lanes], |row| map_grant_row(row, now_ms_value))?;
            let mut owners: std::collections::BTreeMap<String, PollGrants> = Default::default();
            for row in rows {
                let row = row?;
                owners.entry(row.principal.clone()).or_default()
                    .entry((row.connection_id.clone(), row.grantee_principal.clone())).or_default().push(row);
            }
            Ok(owners)
        })?;
        let empty = PollGrants::new();
        for sub in &mut subscriptions {
            let (expiry, state) = subscription_authority_from_grants(
                sub,
                grants.get(&sub.principal).unwrap_or(&empty),
                now_ms_value,
            );
            sub.authority_expires_at_ms = expiry;
            sub.authority_state = state.into();
        }
        Ok(subscriptions)
    }

    /// Subscriptions eligible to poll at `now_ms`: `active`, and either never
    /// polled (`last_polled_at_ms IS NULL`) or last polled at least `cadence_s`
    /// ago.
    ///
    /// This is the BASE cadence bound only. It deliberately knows nothing about
    /// failure backoff or the circuit breaker: those are scheduler-layer
    /// decisions that read `consecutive_vendor_failures` off the returned rows.
    /// Keeping the SQL to the cadence rule means a healthy subscription is
    /// selected at exactly its declared cadence and nothing else, while a
    /// failing one is still returned here and then held back (or suspended) by
    /// the scheduler rather than by a second, divergent notion of "due" baked
    /// into the query.
    ///
    /// Principal-scoped like every other query in this table. The scheduler
    /// calls this once per principal it acts for; it never reaches across
    /// principals in a single query.
    pub fn due_subscriptions(
        &self,
        principal: &str,
        now_ms: i64,
    ) -> Result<Vec<TriggerSubscription>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(DUE_SUBSCRIPTIONS_SELECT)?;
            let rows = statement.query_map((principal, now_ms), |row| {
                map_trigger_subscription_row(row, now_ms)
            })?;
            rows.collect()
        })
    }

    /// Suspend one subscription and record the coverage gap the suspension
    /// creates.
    ///
    /// Limited to the given principal's subscriptions, like every other query
    /// in this store. A subscription id is an unguessable
    /// `subscription_<24 hex characters>`, but ids do reach log lines and
    /// error messages, and being hard to guess is not an authorization check:
    /// without the principal condition, anyone who saw an id could suspend
    /// another principal's subscription. The condition is in this method
    /// itself rather than in a separate checked wrapper, because a safe wrapper
    /// beside an unchecked method stays safe only while every future caller
    /// picks the wrapper.
    pub fn suspend(
        &self,
        principal: &str,
        subscription_id: &str,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Ok(false);
        }
        self.inner.with_conn_fenced(|conn| {
            let row: Option<(String, Option<i64>, i64)> = conn
                .query_row(
                    "SELECT connection_id, last_success_at_ms, created_at_ms
                     FROM trigger_subscriptions
                     WHERE subscription_id = ?1 AND principal = ?2",
                    (subscription_id, principal),
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((connection_id, last_success_at_ms, created_at_ms)) = row else {
                return Ok(false);
            };
            let changed = conn.execute(
                "UPDATE trigger_subscriptions
                 SET status = 'suspended', suspended_reason = ?1, generation = generation + 1
                 WHERE subscription_id = ?2 AND principal = ?3
                   AND status <> 'retired' AND (status <> 'suspended' OR suspended_reason IS NOT ?1)",
                (reason, subscription_id, principal),
            )?;
            if changed != 0 {
                let observed_at_ms = now_ms();
                insert_gap_row(
                    conn,
                    principal,
                    &connection_id,
                    subscription_id,
                    last_success_at_ms.unwrap_or(created_at_ms),
                    observed_at_ms,
                    reason,
                    observed_at_ms,
                )?;
            }
            Ok(changed != 0)
        })
    }

    /// Resume an operational pause without replacing the vendor cursor.
    /// Catalog, schema, connection and grant checks share the write snapshot;
    /// reconciliation and authorization suspensions still require review.
    pub fn resume(
        &self,
        principal: &str,
        subscription_id: &str,
    ) -> Result<Result<TriggerSubscription, SubscriptionResumeRefusal>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let now = now_ms();
            let Some(mut subscription) = conn.query_row(
                &format!("SELECT {TRIGGER_SUBSCRIPTION_COLUMNS} FROM trigger_subscriptions
                          WHERE principal=?1 AND subscription_id=?2"),
                (principal, subscription_id), |row| map_trigger_subscription_row(row, now),
            ).optional()? else {
                return Ok(Err(SubscriptionResumeRefusal::SubscriptionNotFound));
            };
            if subscription.status == "retired" {
                return Ok(Err(SubscriptionResumeRefusal::SubscriptionRetired));
            }
            let resumable = subscription.suspended_reason.as_deref().is_some_and(|reason| {
                reason == CIRCUIT_BREAKER_SUSPENSION_REASON
                    || reason == "response_shape_invalid"
                    || reason.starts_with("response_shape_invalid:")
            });
            if subscription.status != "active" && !resumable {
                return Ok(Err(SubscriptionResumeRefusal::SuspensionNotResumable(subscription.suspended_reason)));
            }
            if subscription.cursor_kind == "probe" {
                let probe = conn.query_row(
                    "SELECT subscription_id,name,actions,script_source,return_schema,rearm,registered_by
                     FROM probe_subscriptions WHERE subscription_id=?1",
                    [subscription_id], map_probe_subscription_row,
                )?;
                subscription.name = Some(probe.name);
                subscription.registered_by = Some(probe.registered_by);
                subscription.rearm = Some(probe.rearm);
                subscription.actions = Some(probe.actions);
            }
            let actions = if let Some(actions) = &subscription.actions {
                actions.iter().map(|action| (action.as_str(), None)).collect::<Vec<_>>()
            } else {
                vec![(subscription.action.as_str(), Some(subscription.schema_hash.as_str()))]
            };
            if let Some(refusal) = recheck_watch_preconditions(conn, principal, &subscription.connection_id, &actions)? {
                return Ok(Err(SubscriptionResumeRefusal::SuspensionNotResumable(Some(refusal.to_string()))));
            }
            let grants = poll_grants_on_conn(conn, principal, Some(&subscription.connection_id), now)?;
            let (expiry, state) = subscription_authority_from_grants(&subscription, &grants, now);
            if state != "live" {
                return Ok(Err(SubscriptionResumeRefusal::PollGrantRequired));
            }
            subscription.authority_expires_at_ms = expiry;
            subscription.authority_state = state.to_string();
            if subscription.status == "suspended" {
                conn.execute(
                    "UPDATE trigger_subscriptions SET status='active', consecutive_vendor_failures=0,
                         suspended_reason=NULL, generation=generation+1
                     WHERE principal=?1 AND subscription_id=?2",
                    (principal, subscription_id),
                )?;
                subscription.status = "active".into();
                subscription.suspended_reason = None;
                subscription.consecutive_vendor_failures = 0;
                subscription.generation += 1;
            }
            Ok(Ok(subscription))
        })
    }

    pub fn unsubscribe(&self, principal: &str, subscription_id: &str) -> Result<bool, StoreError> {
        // The owner may always withdraw a watch on their connection. A probe's
        // registrant may also withdraw it, INCLUDING AFTER ITS GRANT IS REVOKED:
        // narrowing must stay frictionless, and a registrant that cannot clean
        // up its own probe after losing authority leaves rows only an operator
        // ceremony can remove.
        let probe = self.probe_subscription(subscription_id)?;
        let owner = self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT principal FROM trigger_subscriptions WHERE subscription_id = ?1",
                [subscription_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
        })?;
        let Some(owner) = owner else {
            return Ok(false);
        };
        let registrant = probe.as_ref().map(|probe| probe.registered_by.as_str());
        if principal != owner && registrant != Some(principal) {
            return Ok(false);
        }
        self.inner.with_conn_fenced(|conn| {
            event_outbox::count_dropped(
                conn,
                SUBSCRIPTION_EVENTS_PREDICATE,
                (owner.as_str(), subscription_id),
                "dropped_on_unsubscribe",
            )?;
            conn.execute(
                &format!(
                    "DELETE FROM event_outbox WHERE event_id IN
                (SELECT event_id FROM trigger_events WHERE {SUBSCRIPTION_EVENTS_PREDICATE})"
                ),
                (owner.as_str(), subscription_id),
            )?;
            conn.execute(
                &format!("DELETE FROM trigger_events WHERE {SUBSCRIPTION_EVENTS_PREDICATE}"),
                (owner.as_str(), subscription_id),
            )?;
            conn.execute(
                "DELETE FROM probe_subscriptions WHERE subscription_id = ?1",
                [subscription_id],
            )?;
            let changed = conn.execute(
                "DELETE FROM trigger_subscriptions WHERE subscription_id = ?1",
                [subscription_id],
            )?;
            Ok(changed != 0)
        })
    }

    /// Stamp a poll attempt. Principal-scoped like every other write in this
    /// table, so the poller's bookkeeping cannot reach across principals.
    pub fn record_poll_attempt(
        &self,
        principal: &str,
        subscription_id: &str,
        at_ms: i64,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            Ok(conn.execute(
                "UPDATE trigger_subscriptions
                 SET last_polled_at_ms = ?1, generation = generation + 1
                 WHERE subscription_id = ?2 AND principal = ?3 AND status = 'active'",
                (at_ms, subscription_id, principal),
            )? != 0)
        })
    }

    /// Commit a successful poll: advance the cursor, clear the vendor-failure
    /// streak, and stamp the success time.
    ///
    /// The principal scope matters most HERE. Cursor state decides which vendor
    /// records the next poll asks for, so an unscoped write is a silent
    /// data-loss primitive rather than a bookkeeping error: advancing another
    /// principal's cursor makes their poller skip the window it jumped over,
    /// and nothing downstream can tell the difference between "no events" and
    /// "we stopped looking".
    #[cfg(any(test, feature = "test-support"))]
    pub fn record_poll_success(
        &self,
        principal: &str,
        subscription_id: &str,
        cursor_state: &Value,
        at_ms: i64,
    ) -> Result<bool, StoreError> {
        let cursor_state = serde_json::to_string(cursor_state)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        self.inner.with_conn_fenced(|conn| {
            Ok(conn.execute(
                "UPDATE trigger_subscriptions
                 SET cursor_state = ?1, last_success_at_ms = ?2,
                     consecutive_vendor_failures = 0, generation = generation + 1
                 WHERE subscription_id = ?3 AND principal = ?4 AND status = 'active'",
                (cursor_state, at_ms, subscription_id, principal),
            )? != 0)
        })
    }

    /// Count one vendor-side failure toward the backoff streak. Vendor failure
    /// only — an authorization denial must suspend instead, since backing off
    /// a revoked subscription leaves it claiming coverage it no longer has.
    pub fn record_vendor_failure(
        &self,
        principal: &str,
        subscription_id: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            Ok(conn.execute(
                "UPDATE trigger_subscriptions
                 SET consecutive_vendor_failures = consecutive_vendor_failures + 1,
                     generation = generation + 1
                 WHERE subscription_id = ?1 AND principal = ?2 AND status = 'active'",
                (subscription_id, principal),
            )? != 0)
        })
    }

    /// Read the latest prior vendor activity time across an item's content versions.
    /// Host observation times cannot bound a vendor timeline when clocks differ.
    /// If any prior version lacks vendor time, fail instead of treating the item
    /// as unseen: an unbounded actor window could misattribute historical actions.
    pub(crate) fn previous_event_observed_at(
        &self,
        principal: &str,
        connection_id: &str,
        subscription_id: &str,
        vendor_event_id: &str,
    ) -> Result<Option<i64>, StoreError> {
        let (activity, missing): (Option<i64>, bool) = self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT MAX(activity_at_ms), COUNT(*) > COUNT(activity_at_ms) FROM trigger_events
                 WHERE principal = ?1 AND connection_id = ?2
                   AND subscription_id = ?3 AND vendor_event_id = ?4
                   AND kind = 'event'",
                (principal, connection_id, subscription_id, vendor_event_id),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })?;
        if missing {
            return Err(StoreError::Backend(
                "prior event vendor activity time unavailable".into(),
            ));
        }
        Ok(activity)
    }

    /// Identify candidate payloads already stored in this subscription's event lane.
    ///
    /// Payload hashing stays behind the storage boundary so this comparison and
    /// insert-time deduplication cannot drift when the canonical hash changes.
    /// Each query is constrained by the supplied vendor id; this never loads or
    /// hashes the subscription's existing event table. The returned flags align
    /// positionally with `candidates`.
    pub(crate) fn unchanged_event_payloads(
        &self,
        principal: &str,
        subscription_id: &str,
        candidates: &[(&str, &Value)],
    ) -> Result<Vec<bool>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT EXISTS(
                     SELECT 1 FROM trigger_events
                     WHERE principal = ?1 AND subscription_id = ?2
                       AND connection_id = (
                           SELECT connection_id FROM trigger_subscriptions
                           WHERE principal = ?1 AND subscription_id = ?2
                       )
                       AND vendor_event_id = ?3 AND payload_hash = ?4
                       AND kind = 'event'
                 )",
            )?;
            candidates
                .iter()
                .map(|(vendor_event_id, payload)| {
                    let payload_hash = jcs_sqlite_hash(payload)?;
                    statement.query_row(
                        (principal, subscription_id, vendor_event_id, payload_hash),
                        |row| row.get(0),
                    )
                })
                .collect()
        })
    }

    /// Report which (vendor id, activity time) pairs this subscription has
    /// already stored as events. The returned flags align positionally with
    /// `candidates`.
    ///
    /// The ordered-timestamp poller asks this about rows timestamped well below
    /// its previous watermark: a row never stored at its own timestamp was not
    /// visible when the previous poll read that span, which is the only
    /// evidence of late visibility a vendor that filters on the server gives.
    /// Matching the activity time rather than the payload keeps a change that
    /// leaves the timestamp alone (a reaction count, for instance) from reading
    /// as a late row.
    pub(crate) fn stored_event_activities(
        &self,
        principal: &str,
        subscription_id: &str,
        candidates: &[(&str, i64)],
    ) -> Result<Vec<bool>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT EXISTS(
                     SELECT 1 FROM trigger_events
                     WHERE principal = ?1 AND subscription_id = ?2
                       AND connection_id = (
                           SELECT connection_id FROM trigger_subscriptions
                           WHERE principal = ?1 AND subscription_id = ?2
                       )
                       AND vendor_event_id = ?3 AND activity_at_ms = ?4
                       AND kind = 'event'
                 )",
            )?;
            candidates
                .iter()
                .map(|(vendor_event_id, activity_at_ms)| {
                    statement.query_row(
                        (principal, subscription_id, vendor_event_id, activity_at_ms),
                        |row| row.get(0),
                    )
                })
                .collect()
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_event(
        &self,
        principal: &str,
        connection_id: &str,
        subscription_id: &str,
        vendor_event_id: &str,
        payload: &Value,
        observed_at_ms: i64,
    ) -> Result<TriggerEventInsertOutcome, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let subscription_exists: Option<String> = conn
                .query_row(
                    "SELECT principal FROM trigger_subscriptions
                     WHERE subscription_id = ?1 AND principal = ?2
                       AND connection_id = ?3",
                    (subscription_id, principal, connection_id),
                    |row| row.get(0),
                )
                .optional()?;
            if subscription_exists.is_none() {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            // No classification: this entry point takes a raw payload with no
            // manifest context, so there is nothing to classify FROM. The poll
            // path is where the reviewed kind is known.
            insert_event_row(
                conn,
                principal,
                connection_id,
                subscription_id,
                &PollEventInput {
                    vendor_event_id,
                    payload,
                    observed_at_ms,
                    // No manifest context on this entry point, so there is
                    // nothing to classify FROM. The poll path is where the
                    // reviewed kind is known.
                    item_kind: None,
                    activity_at_ms: None,
                    actor: &ActorAttribution::NotEnriched,
                },
            )
        })
    }

    /// Commit a successful poll: advance the cursor AND write every extracted
    /// event inside ONE fenced transaction.
    ///
    /// These two writes must be atomic. Advancing the cursor and then failing to
    /// write the events loses them permanently, because the next poll resumes
    /// from the advanced watermark and never asks for that window again. Doing
    /// them as two separate transactions would make that loss a matter of call
    /// ordering rather than a structural impossibility, so both happen here
    /// under a single `with_conn_fenced` and any error rolls the whole batch
    /// back.
    ///
    /// The cursor update runs first and is gated on the subscription still being
    /// `active` for this principal and connection. If it moves no row the
    /// subscription was suspended or deleted mid-cycle; returning an error then
    /// rolls the transaction back so no events are orphaned under a cursor that
    /// did not move.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_poll_success(
        &self,
        principal: &str,
        connection_id: &str,
        subscription_id: &str,
        cursor_state: &Value,
        events: &[PollEventInput<'_>],
        at_ms: i64,
        coverage_gap: Option<(i64, i64, &str)>,
    ) -> Result<Vec<TriggerEventInsertOutcome>, PollCommitError> {
        let keyed: Vec<_> = events
            .iter()
            .map(|event| KeyedPollEventInput {
                event: *event,
                identity: None,
                delivery_id: None,
                envelope_context: Default::default(),
            })
            .collect();
        let gaps: Vec<_> = coverage_gap
            .into_iter()
            .map(|(from_ms, to_ms, reason)| PollGapInput {
                from_ms,
                to_ms,
                reason,
            })
            .collect();
        self.commit_keyed_poll_success(
            principal,
            connection_id,
            subscription_id,
            cursor_state,
            &keyed,
            at_ms,
            &gaps,
        )
    }

    /// Commit event rows with supplied event keys, outbox markers for keyed
    /// events, any number of coverage gap rows, and the cursor in one transaction.
    /// Unlike `commit_poll_success`, which accepts unkeyed events and at most
    /// one gap, this accepts keyed events and multiple gaps.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_keyed_poll_success(
        &self,
        principal: &str,
        connection_id: &str,
        subscription_id: &str,
        cursor_state: &Value,
        events: &[KeyedPollEventInput<'_>],
        at_ms: i64,
        coverage_gaps: &[PollGapInput<'_>],
    ) -> Result<Vec<TriggerEventInsertOutcome>, PollCommitError> {
        if events
            .iter()
            .any(|event| event.event.vendor_event_id.trim().is_empty())
        {
            return Err(PollCommitError::InvalidInput(
                "poll event has a blank vendor_event_id",
            ));
        }
        let cursor_json = serde_json::to_string(cursor_state)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let outcomes = self
            .inner
            .with_conn_fenced(|conn| {
                let advanced = conn.execute(
                    "UPDATE trigger_subscriptions
                 SET cursor_state = ?1, last_success_at_ms = ?2,
                     consecutive_vendor_failures = 0, generation = generation + 1
                 WHERE subscription_id = ?3 AND principal = ?4
                   AND connection_id = ?5 AND status = 'active'",
                    rusqlite::params![
                        cursor_json,
                        at_ms,
                        subscription_id,
                        principal,
                        connection_id
                    ],
                )?;
                if advanced == 0 {
                    return Ok(None);
                }
                let mut outcomes = Vec::with_capacity(events.len());
                for event in events {
                    outcomes.push(insert_keyed_event_row(
                        conn,
                        principal,
                        connection_id,
                        subscription_id,
                        event,
                    )?);
                }
                // Written inside the SAME transaction as the cursor advance, which
                // is the only ordering that cannot lie. A gap recorded afterwards
                // could be lost to a crash while the advance survived, leaving a
                // cursor that had skipped an interval with nothing saying so -- and
                // an unrecorded coverage hole is indistinguishable from complete
                // coverage, which is the failure the gap kind exists to prevent.
                for gap in coverage_gaps {
                    insert_gap_row(
                        conn,
                        principal,
                        connection_id,
                        subscription_id,
                        gap.from_ms,
                        gap.to_ms,
                        gap.reason,
                        at_ms,
                    )?;
                }
                Ok(Some(outcomes))
            })?
            .ok_or(PollCommitError::Inactive)?;
        if events.iter().zip(&outcomes).any(|(event, outcome)| {
            event.identity.is_some()
                && matches!(outcome, TriggerEventInsertOutcome::Inserted { .. })
        }) {
            self.outbox_ready.notify_one();
        }
        Ok(outcomes)
    }

    /// Commit a probe observation: advance the baseline and ordinal, write any
    /// events, and -- for a successful `once` fire -- retire the subscription,
    /// all in one fenced transaction.
    ///
    /// Retirement belongs inside this transaction because a crash between
    /// insert and retire would re-fire a one-shot on the next pass, which is
    /// the failure a one-shot exists to prevent. The status change is the same
    /// UPDATE as the cursor advance so it cannot be reordered past the event
    /// insert without still sharing the transaction: a failed insert rolls the
    /// retirement back with the cursor.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_probe_success(
        &self,
        principal: &str,
        connection_id: &str,
        subscription_id: &str,
        cursor_state: &Value,
        events: &[PollEventInput<'_>],
        at_ms: i64,
        retire: bool,
    ) -> Result<Vec<TriggerEventInsertOutcome>, PollCommitError> {
        if events
            .iter()
            .any(|event| event.vendor_event_id.trim().is_empty())
        {
            return Err(PollCommitError::InvalidInput(
                "poll event has a blank vendor_event_id",
            ));
        }
        let cursor_json = serde_json::to_string(cursor_state)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let next_status = if retire { "retired" } else { "active" };
        self.inner
            .with_conn_fenced(|conn| {
                let advanced = conn.execute(
                    "UPDATE trigger_subscriptions
                 SET cursor_state = ?1, last_success_at_ms = ?2,
                     consecutive_vendor_failures = 0, generation = generation + 1,
                      status = ?3
                  WHERE subscription_id = ?4 AND principal = ?5
                    AND connection_id = ?6 AND status = 'active'",
                    rusqlite::params![
                        cursor_json,
                        at_ms,
                        next_status,
                        subscription_id,
                        principal,
                        connection_id
                    ],
                )?;
                if advanced == 0 {
                    return Ok(None);
                }
                let mut outcomes = Vec::with_capacity(events.len());
                for event in events {
                    outcomes.push(insert_event_row(
                        conn,
                        principal,
                        connection_id,
                        subscription_id,
                        event,
                    )?);
                }
                Ok(Some(outcomes))
            })?
            .ok_or(PollCommitError::Inactive)
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_gap_event(
        &self,
        principal: &str,
        connection_id: &str,
        subscription_id: &str,
        gap_from_ms: i64,
        gap_to_ms: i64,
        reason: &str,
        observed_at_ms: i64,
    ) -> Result<String, StoreError> {
        let event_id = new_id("event");
        let payload = serde_json::json!({});
        let payload_json = serde_json::to_string(&payload)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let payload_hash = jcs_store_hash(&payload)?;
        self.inner.with_conn_fenced(|conn| {
            let subscription_exists: Option<String> = conn
                .query_row(
                    "SELECT principal FROM trigger_subscriptions
                     WHERE subscription_id = ?1 AND principal = ?2
                       AND connection_id = ?3",
                    (subscription_id, principal, connection_id),
                    |row| row.get(0),
                )
                .optional()?;
            if subscription_exists.is_none() {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            insert_gap_row_with_payload(
                conn,
                principal,
                connection_id,
                subscription_id,
                gap_from_ms,
                gap_to_ms,
                reason,
                observed_at_ms,
                &event_id,
                &payload_json,
                &payload_hash,
            )?;
            Ok(event_id)
        })
    }

    /// Stored connections whose events `grantee` may consume, by explicit grant.
    ///
    /// Live and expired rows are both returned. Callers that widen data must
    /// admit only `live`; the wire listing also retains `expired` so a lapsed
    /// grant cannot look identical to a quiet feed. Keeping that state on this
    /// query means the response reports the same rows used for event selection.
    ///
    /// A grantee with no such grant gets an empty list, which is what keeps the
    /// default answer "you see only your own rows".
    fn events_consume_connections(
        &self,
        grantee: &str,
        now_ms: i64,
    ) -> Result<Vec<EventsConsumeGrant>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT principal, connection_id, action_selectors, expires_at
                 FROM grants
                 WHERE authority_kind = ?1
                   AND grantee_principal = ?2 AND grantee_principal <> '*'
                 ORDER BY grant_id",
            )?;
            let rows = statement.query_map(
                (crate::governance::AUTHORITY_EVENTS_CONSUME, grantee),
                |row| {
                    let selectors: String = row.get(2)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        parse_string_list(&selectors)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )?;
            let mut granted = Vec::new();
            for row in rows {
                let (owner, connection_id, selectors, expires_at) = row?;
                let state = if expires_at.is_some_and(|deadline| deadline <= now_ms) {
                    "expired"
                } else {
                    "live"
                };
                granted.push(EventsConsumeGrant {
                    owner,
                    connection_id,
                    selectors,
                    expires_at,
                    authority_state: state,
                });
            }
            Ok(granted)
        })
    }

    /// Events this principal owns, plus events on connections it holds a live
    /// `events_consume` grant for.
    ///
    /// The owned rows come first and unconditionally: a principal reading its own
    /// lane needs no grant, and adding one would break every existing caller.
    /// Granted rows are additive, scoped per connection, and further filtered by
    /// the grant's action selectors -- a consumer named for one action must not
    /// receive another action's vendor payloads from the same connection.
    pub fn list_events(
        &self,
        principal: &str,
        connection_id: Option<&str>,
        subscription_id: Option<&str>,
    ) -> Result<Vec<TriggerEvent>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                // The subscription's CURRENT actor source decides whether a row
                // with neither actor field predates the stored reason (and is
                // served as `unrecorded`) or simply has no actor enrichment.
                "SELECT e.event_id, e.principal, e.connection_id, e.subscription_id,
                        e.vendor_event_id, e.payload_hash, e.payload, e.kind,
                        e.gap_from_ms, e.gap_to_ms, e.gap_reason, e.observed_at_ms,
                        e.acked_at_ms, e.created_at_ms, e.item_kind, e.activity_at_ms,
                        e.actor_logins, e.actor_unknown_reason,
                        EXISTS(SELECT 1 FROM trigger_subscriptions s
                               WHERE s.subscription_id = e.subscription_id
                                 AND s.principal = e.principal
                                 AND s.actor_source_json IS NOT NULL)
                 FROM trigger_events e
                 WHERE e.principal = ?1 AND e.acked_at_ms IS NULL
                   AND (?2 IS NULL OR e.connection_id = ?2)
                   AND (?3 IS NULL OR e.subscription_id = ?3)
                 ORDER BY e.created_at_ms, e.event_id",
            )?;
            let rows = statement.query_map(
                (principal, connection_id, subscription_id),
                map_trigger_event_row,
            )?;
            rows.collect()
        })
    }

    /// [`Self::list_events`] widened by any `events_consume` grants this caller
    /// holds.
    ///
    /// Separate from `list_events` rather than folded into it, deliberately. The
    /// owner path is the hot one -- every poll and every operator read goes
    /// through it -- and it must keep costing exactly one scoped query with no
    /// grant lookup at all. Folding the grant check in would put a second query
    /// on a path that never needs it, and would make the plain owner read depend
    /// on the grants table being readable.
    #[cfg(any(test, feature = "test-support"))]
    pub fn list_events_including_granted(
        &self,
        principal: &str,
        connection_id: Option<&str>,
        subscription_id: Option<&str>,
        now_ms: i64,
    ) -> Result<Vec<TriggerEvent>, StoreError> {
        self.list_events_with_consume_authority(principal, connection_id, subscription_id, now_ms)
            .map(|listing| listing.events)
    }

    /// Return visible unacked events and the caller's consume-authority projection.
    /// Without a page size the historical full listing is preserved.
    pub fn list_events_with_consume_authority(
        &self,
        principal: &str,
        connection_id: Option<&str>,
        subscription_id: Option<&str>,
        now_ms: i64,
    ) -> Result<EventsIncludingGranted, StoreError> {
        self.list_events_page_with_consume_authority(
            principal,
            connection_id,
            subscription_id,
            now_ms,
            None,
            None,
        )
        .map(|(listing, _)| listing)
    }

    /// Page after the exclusive `(created_at_ms, event_id)` boundary. The extra
    /// row detects continuation without loading the rest of the payloads.
    pub fn list_events_page_with_consume_authority(
        &self,
        principal: &str,
        connection_id: Option<&str>,
        subscription_id: Option<&str>,
        now_ms: i64,
        limit: Option<usize>,
        after: Option<(i64, &str)>,
    ) -> Result<(EventsIncludingGranted, bool), StoreError> {
        let grants = self.events_consume_connections(principal, now_ms)?;
        let mut consume_authority = Vec::new();
        let mut live = Vec::new();
        for grant in grants {
            if connection_id.is_some_and(|requested| requested != grant.connection_id) {
                continue;
            }
            consume_authority.push(EventsConsumeAuthority {
                principal: grant.owner.clone(),
                connection_id: grant.connection_id.clone(),
                authority_expires_at_ms: grant.expires_at,
                authority_state: grant.authority_state.to_string(),
            });
            if grant.authority_state == "live" && grant.owner != principal {
                live.push(serde_json::json!({"owner":grant.owner, "connection":grant.connection_id, "selectors":grant.selectors}));
            }
        }
        // SQL receives the same grant snapshot used by the authority projection.
        // Filter by subscription action before SQLite reads or parses payloads;
        // EXISTS also makes overlapping grants deliver each event only once.
        let live_json = serde_json::Value::Array(live).to_string();
        let sql_limit = limit.map(|size| size.min(1000) as i64 + 1).unwrap_or(-1);
        let mut events = self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT e.event_id, e.principal, e.connection_id, e.subscription_id,
                        e.vendor_event_id, e.payload_hash, e.payload, e.kind,
                        e.gap_from_ms, e.gap_to_ms, e.gap_reason, e.observed_at_ms,
                        e.acked_at_ms, e.created_at_ms, e.item_kind, e.activity_at_ms,
                        e.actor_logins, e.actor_unknown_reason,
                        EXISTS(SELECT 1 FROM trigger_subscriptions s
                               WHERE s.subscription_id=e.subscription_id AND s.principal=e.principal
                                 AND s.actor_source_json IS NOT NULL)
                 FROM trigger_events e
                 WHERE e.acked_at_ms IS NULL
                   AND (?2 IS NULL OR e.connection_id=?2)
                   AND (?3 IS NULL OR e.subscription_id=?3)
                   AND (?5 IS NULL OR (e.created_at_ms,e.event_id) > (?5,?6))
                   AND (e.principal=?1 OR EXISTS (
                       SELECT 1 FROM json_each(?4) g
                       JOIN trigger_subscriptions s ON s.subscription_id=e.subscription_id
                            AND s.principal=e.principal AND s.connection_id=e.connection_id
                       JOIN json_each(g.value, '$.selectors') selector
                       WHERE json_extract(g.value,'$.owner')=e.principal
                         AND json_extract(g.value,'$.connection')=e.connection_id
                         AND (selector.value='*' OR selector.value=s.action)))
                 ORDER BY e.created_at_ms,e.event_id LIMIT ?7",
            )?;
            let rows = statement.query_map(
                rusqlite::params![
                    principal,
                    connection_id,
                    subscription_id,
                    live_json,
                    after.map(|cursor| cursor.0),
                    after.map(|cursor| cursor.1),
                    sql_limit
                ],
                map_trigger_event_row,
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })?;
        let has_more = limit.is_some_and(|size| events.len() > size.min(1000));
        if let Some(size) = limit {
            events.truncate(size.min(1000));
        }
        Ok((
            EventsIncludingGranted {
                events,
                consume_authority,
            },
            has_more,
        ))
    }

    /// Resolve acknowledgement results at the same authority timestamp as the ack.
    /// Unknown and foreign ids are deliberately indistinguishable.
    pub fn unacked_of_at(
        &self,
        principal: &str,
        event_ids: &[String],
        now: i64,
    ) -> Result<Vec<String>, StoreError> {
        let mut pending = Vec::new();
        for chunk in event_ids.chunks(MAX_EVENT_ACK_IDS) {
            let ids = serde_json::to_string(chunk)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            let mut rows = self.inner.with_read(|conn| {
                let mut query = conn.prepare(&format!(
                    "SELECT wanted.value FROM json_each(?2) wanted WHERE NOT EXISTS (
                        SELECT 1 FROM trigger_events WHERE event_id=wanted.value
                        AND acked_at_ms IS NOT NULL AND {EVENT_ACK_AUTHORITY}) ORDER BY wanted.key"
                ))?;
                let rows =
                    query.query_map(rusqlite::params![principal, ids, now], |row| row.get(0))?;
                rows.collect::<rusqlite::Result<Vec<String>>>()
            })?;
            pending.append(&mut rows);
        }
        Ok(pending)
    }

    pub fn unacked_of(
        &self,
        principal: &str,
        event_ids: &[String],
    ) -> Result<Vec<String>, StoreError> {
        self.unacked_of_at(principal, event_ids, now_ms())
    }

    /// Acknowledge events this principal owns.
    ///
    /// Strictly owner-scoped. A grantee acknowledging events it was granted goes
    /// through [`Self::ack_events_including_granted`], which resolves the owner
    /// first -- keeping the owner path free of any grant lookup, the same split
    /// as `list_events`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn ack_events(&self, principal: &str, event_ids: &[String]) -> Result<usize, StoreError> {
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let mut acked = 0;
            for event_id in event_ids {
                // Mark the event acknowledged for `events` tool consumers, but
                // keep its body for later reads by event key. Retention pruning
                // decides when the body can be deleted.
                acked += conn.execute(
                    "UPDATE trigger_events
                     SET acked_at_ms = ?1
                     WHERE principal = ?2 AND event_id = ?3 AND acked_at_ms IS NULL",
                    (now, principal, event_id),
                )?;
            }
            Ok(acked)
        })
    }

    /// Acknowledge owned events or events admitted by a current consume grant.
    /// Pull events are a shared work queue, not a per-consumer broadcast: an ack
    /// drains the owner and every overlapping grantee's unacked view. Payloads
    /// remain available to retention and outbox delivery, which ignore pull acks.
    /// Chunks commit independently so a large backlog cannot monopolize the writer;
    /// partial failure is safe to retry because acknowledgement is idempotent.
    pub fn ack_events_including_granted(
        &self,
        principal: &str,
        event_ids: &[String],
        now_ms_value: i64,
    ) -> Result<usize, StoreError> {
        let mut acked = 0;
        for chunk in event_ids.chunks(MAX_EVENT_ACK_IDS) {
            let ids = serde_json::to_string(chunk)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            acked += self.inner.with_conn_fenced(|conn| {
                conn.execute(
                    &format!(
                        "UPDATE trigger_events SET acked_at_ms=?3
                     WHERE event_id IN (SELECT value FROM json_each(?2))
                     AND acked_at_ms IS NULL AND {EVENT_ACK_AUTHORITY}"
                    ),
                    rusqlite::params![principal, ids, now_ms_value],
                )
            })?;
        }
        Ok(acked)
    }

    /// Prune by age and count, but keep rows with unpublished outbox markers,
    /// bodies within seven days of insertion or later publication, and rows a
    /// timestamp-cursor watch could re-read on resume (including its maximum
    /// lookback window). For an existing subscription, deleting rows that are
    /// neither acknowledged nor published records a coverage gap spanning their
    /// observation times.
    pub fn prune(
        &self,
        principal: &str,
        subscription_id: &str,
        max_age_ms: i64,
        max_rows: usize,
    ) -> Result<usize, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            event_outbox::prune_events(
                conn,
                principal,
                subscription_id,
                max_age_ms,
                max_rows,
                now_ms(),
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn age_subscription_events_for_test(
        &self,
        subscription_id: &str,
        at_ms: i64,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE trigger_events SET created_at_ms = ?1 WHERE subscription_id = ?2",
                (at_ms, subscription_id),
            )
            .map(|_| ())
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_grant(&self, input: &GrantInput) -> Result<(), StoreError> {
        self.inner
            .with_conn_fenced(|conn| insert_grant_on_conn(conn, input))
    }

    /// Find a grant authorizing this call. `authority_kind` is the kind the
    /// CALLER claims, so an interactive request can never be satisfied by a
    /// poll grant nor a poll by an interactive one.
    // Separate arguments rather than a struct, so every authorization call
    // site spells out the grant lookup key (owner, connection, grantee, action
    // and authority kind) and whether a risk ceiling is checked
    // (`requested_risk`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn matching_grant(
        &self,
        owner: &str,
        connection_id: &str,
        grantee: &str,
        action: &str,
        authority_kind: &str,
        now: i64,
        requested_risk: Option<&str>,
    ) -> Result<Option<GrantRecord>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT grant_id, principal, connection_id, grantee_principal, risk_ceiling,
                        action_selectors, authority_kind, expires_at, generation
                 FROM grants
                 WHERE principal = ?1 AND connection_id = ?2
                   AND authority_kind = ?4
                   AND grantee_principal = ?3 AND grantee_principal <> '*'
                   AND agent_id IS NULL
                 ORDER BY grant_id",
            )?;
            let rows = statement
                .query_map((owner, connection_id, grantee, authority_kind), |row| {
                    map_grant_row(row, now)
                })?;
            let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(grant_candidate(&rows, action, now, requested_risk).cloned())
        })
    }

    pub fn has_connection_admin_grant(
        &self,
        owner: &str,
        connection_id: &str,
        grantee: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT action_selectors FROM grants
                 WHERE principal = ?1 AND connection_id = ?2
                   AND authority_kind = 'connection_admin'
                   AND grantee_principal = ?3 AND grantee_principal <> '*'
                   AND (expires_at IS NULL OR expires_at > ?4)",
            )?;
            let rows = statement.query_map((owner, connection_id, grantee, now_ms()), |row| {
                let selectors: String = row.get(0)?;
                parse_string_list(&selectors)
            })?;
            for selectors in rows {
                if !selectors?.is_empty() {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn update_policy_effect(
        &self,
        principal: &str,
        policy_id: &str,
        effect: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE policies SET effect = ?1, generation = generation + 1,
                        updated_at_ms = ?2
                 WHERE principal = ?3 AND policy_id = ?4",
                (effect, now_ms(), principal, policy_id),
            )?;
            Ok(changed != 0)
        })
    }

    /// Create a policy, or update the policy scope an operator named.
    ///
    /// The lookup and the write share one transaction, and the effect and
    /// expiry change in one statement, so a reader never sees the new effect
    /// with the old expiry and two concurrent calls cannot both insert. The
    /// returned generation is the one stored.
    pub fn set_policy(
        &self,
        principal: &str,
        connection_id: &str,
        action_selector: &str,
        effect: &str,
        expires_at: Option<i64>,
    ) -> Result<PolicyRecord, StoreError> {
        let candidate_id = new_id("policy");
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let existing: Option<String> = conn
                .query_row(
                    "SELECT policy_id FROM policies
                     WHERE principal = ?1 AND connection_id = ?2 AND action_selector = ?3
                     ORDER BY policy_id LIMIT 1",
                    (principal, connection_id, action_selector),
                    |row| row.get(0),
                )
                .optional()?;
            let policy_id = match existing {
                Some(policy_id) => {
                    conn.execute(
                        "UPDATE policies SET effect = ?1, expires_at = ?2,
                                generation = generation + 1, updated_at_ms = ?3
                         WHERE principal = ?4 AND policy_id = ?5",
                        rusqlite::params![effect, expires_at, now, principal, policy_id],
                    )?;
                    policy_id
                }
                None => {
                    insert_policy_on_conn(
                        conn,
                        &PolicyInput {
                            policy_id: candidate_id.clone(),
                            principal: principal.to_string(),
                            connection_id: connection_id.to_string(),
                            action_selector: action_selector.to_string(),
                            effect: effect.to_string(),
                            expires_at,
                        },
                    )?;
                    candidate_id.clone()
                }
            };
            conn.query_row(
                "SELECT policy_id, principal, connection_id, action_selector, effect,
                        expires_at, generation
                 FROM policies WHERE principal = ?1 AND policy_id = ?2",
                (principal, &policy_id),
                |row| {
                    Ok(PolicyRecord {
                        policy_id: row.get(0)?,
                        principal: row.get(1)?,
                        connection_id: row.get(2)?,
                        action_selector: row.get(3)?,
                        effect: row.get(4)?,
                        expires_at: row.get(5)?,
                        generation: row.get(6)?,
                    })
                },
            )
        })
    }

    /// Remove a policy. Returning false for an absent id makes retried operator
    /// removals safe.
    pub fn remove_policy(&self, principal: &str, policy_id: &str) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "DELETE FROM policies WHERE principal = ?1 AND policy_id = ?2",
                (principal, policy_id),
            )?;
            Ok(changed != 0)
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_policy(&self, input: &PolicyInput) -> Result<(), StoreError> {
        self.inner
            .with_conn_fenced(|conn| insert_policy_on_conn(conn, input))
    }

    pub(crate) fn matching_policy(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        now: i64,
    ) -> Result<Option<PolicyRecord>, StoreError> {
        self.inner
            .with_read(|conn| governing_policy(conn, principal, connection_id, action, now))
    }

    /// `scope` is the daemon scope the raising call's route was bound under.
    /// It is stored with the request, with the scope's agent in `agent_id`, so
    /// the approval can be re-checked against that scope when it executes.
    /// `relay_origin`, the call from which the raising call was relayed, is
    /// stored for attribution only. Tests use it to plant a request directly;
    /// the serving path goes through [`Self::ensure_action_request`].
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_action_request(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        args: &Value,
        schema_hash: &str,
        requester: &str,
        expires_at: i64,
        scope: Option<&CallScope>,
        relay_origin: Option<&RelayOrigin>,
    ) -> Result<String, StoreError> {
        let row = NewActionRequest::new(
            principal,
            connection_id,
            action,
            args,
            schema_hash,
            requester,
            None,
            expires_at,
            scope,
            relay_origin,
        )?;
        self.inner
            .with_conn_fenced(|conn| insert_action_request_on_conn(conn, &row))?;
        Ok(row.request_id)
    }

    /// Preserve crate-internal routing without forwarding it as vendor arguments.
    /// A reused request may not change the routing shown when consent was filed.
    pub(crate) fn bind_action_request_routing(
        &self,
        principal: &str,
        id: &str,
        routing: &Value,
    ) -> Result<bool, StoreError> {
        let routing =
            serde_json::to_string(routing).map_err(|e| StoreError::Backend(e.to_string()))?;
        self.inner.with_conn_fenced(|conn| {
            Ok(conn.execute("UPDATE action_requests SET routing_context=?3 WHERE principal=?1 AND request_id=?2 AND (routing_context IS NULL OR routing_context=?3)", (principal, id, &routing))? == 1)
        })
    }

    pub(crate) fn action_request_routing(
        &self,
        principal: &str,
        id: &str,
    ) -> Result<Option<Value>, StoreError> {
        self.inner.with_read(|conn| {
            let routing: Option<String> = conn.query_row("SELECT routing_context FROM action_requests WHERE principal=?1 AND request_id=?2", (principal, id), |row| row.get(0)).optional()?.flatten();
            routing.as_deref().map(parse_json_column).transpose()
        })
    }

    /// Create-or-reuse the stable intent row for a logical write. A reused row
    /// keeps the `relay_origin` it was created with: the origin is attribution
    /// and never part of the shape the row is matched on.
    ///
    /// The lookup and the insert share one transaction, as in
    /// [`Self::ensure_keyed_action_request`], so two concurrent arrivals of the
    /// same write make one request rather than two approval prompts.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn ensure_action_request(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        args: &Value,
        schema_hash: &str,
        requester: &str,
        expires_at: i64,
        scope: Option<&CallScope>,
        relay_origin: Option<&RelayOrigin>,
    ) -> Result<String, StoreError> {
        let row = NewActionRequest::new(
            principal,
            connection_id,
            action,
            args,
            schema_hash,
            requester,
            None,
            expires_at,
            scope,
            relay_origin,
        )?;
        race_point("action_request_insert");
        self.inner.with_conn_fenced(|conn| {
            if let Some(existing) = find_action_request_by_shape_on_conn(
                conn,
                principal,
                connection_id,
                action,
                args,
                schema_hash,
                now_ms(),
                scope,
                requester,
            )? {
                return Ok(existing.request_id);
            }
            insert_action_request_on_conn(conn, &row)?;
            Ok(row.request_id.clone())
        })
    }

    /// Create-or-reuse the request for a call its carrier (`requester`) gave
    /// `call_key`. The key names one call, so the request is looked up by
    /// `(requester, call_key)` rather than by shape, and the lookup and insert
    /// share one transaction so two arrivals of the same call make one row.
    ///
    /// The call arriving again (same connection, action, arguments, schema and
    /// scope) while its request is still open reuses that request. Anything
    /// else already held under the key is returned as `KeyTaken`: the key
    /// belongs to another call, or to this call's request after it was
    /// decided, withdrawn, sent or expired, and a new request under the same
    /// key would let a withdrawn call run after all.
    ///
    /// `relay_origin` is written on a new row for attribution and plays no part
    /// in the lookup or the reuse test.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn ensure_keyed_action_request(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        args: &Value,
        schema_hash: &str,
        requester: &str,
        call_key: &str,
        expires_at: i64,
        scope: Option<&CallScope>,
        relay_origin: Option<&RelayOrigin>,
    ) -> Result<EnsuredRequest, StoreError> {
        let row = NewActionRequest::new(
            principal,
            connection_id,
            action,
            args,
            schema_hash,
            requester,
            Some(call_key),
            expires_at,
            scope,
            relay_origin,
        )?;
        self.inner.with_conn_fenced(|conn| {
            let existing = conn
                .query_row(
                    &format!(
                        "SELECT {ACTION_REQUEST_COLUMNS}
                         FROM action_requests WHERE requester = ?1 AND (call_key = ?2 OR
                                 request_id IN (SELECT request_id FROM consent_call_keys WHERE requester = ?1 AND call_key = ?2))"
                    ),
                    (requester, call_key),
                    map_action_request_row,
                )
                .optional()?;
            let Some(existing) = existing else {
                insert_action_request_on_conn(conn, &row)?;
                return Ok(EnsuredRequest::Held(row.request_id.clone()));
            };
            let same_scope = match (existing.scope.as_ref(), scope) {
                (None, None) => true,
                (Some(held), Some(call)) => {
                    held.owner == call.owner
                        && held.scope_ref == call.scope_ref
                        && held.scope_epoch == call.scope_epoch
                }
                _ => false,
            };
            let reusable = matches!(existing.status.as_str(), "pending" | "approved")
                && existing.expires_at > now_ms()
                && existing.principal == principal
                && existing.connection_id == connection_id
                && existing.action == action
                && existing.args_snapshot == *args
                && existing.schema_hash == schema_hash
                && same_scope;
            Ok(if reusable {
                EnsuredRequest::Held(existing.request_id)
            } else {
                EnsuredRequest::KeyTaken(Box::new(existing))
            })
        })
    }

    /// The request the carrier `requester` raised for the call it keyed
    /// `call_key`, whatever its status.
    pub(crate) fn keyed_action_request(
        &self,
        requester: &str,
        call_key: &str,
    ) -> Result<Option<ActionRequestRecord>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                &format!(
                    "SELECT {ACTION_REQUEST_COLUMNS}
                     FROM action_requests WHERE requester = ?1 AND (call_key = ?2 OR
                                 request_id IN (SELECT request_id FROM consent_call_keys WHERE requester = ?1 AND call_key = ?2))"
                ),
                (requester, call_key),
                map_action_request_row,
            )
            .optional()
        })
    }

    /// Whether any carrier holds a request keyed `call_key` raised under the
    /// scope `(owner, scope_ref, scope_epoch)`.
    pub(crate) fn call_key_held_in_scope(
        &self,
        call_key: &str,
        owner: &str,
        scope_ref: &str,
        scope_epoch: u64,
    ) -> Result<bool, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM action_requests
                 WHERE (call_key = ?1 OR request_id IN (SELECT request_id FROM consent_call_keys WHERE call_key = ?1)) AND scope_owner = ?2 AND scope_ref = ?3
                   AND scope_epoch = ?4)",
                rusqlite::params![call_key, owner, scope_ref, epoch_to_sql(scope_epoch)],
                |row| row.get(0),
            )
        })
    }

    /// Withdraw the call the carrier `requester` keyed `call_key`, and say
    /// where it stands. The caller has already been checked as allowed to
    /// withdraw it.
    ///
    /// The answer is read from the request row in the same fenced transaction
    /// that cancels it, so it is the same for every caller and every repeat,
    /// and survives a restart:
    ///
    /// - An open request (pending, or approved and not yet claimed) moves to
    ///   `cancelled`: `withdrawn`. The update is conditional on the status the
    ///   claim also requires, so a withdrawal and the claim that consumes the
    ///   approval cannot both succeed: whichever commits first wins, and the
    ///   other finds nothing to act on.
    /// - A request already `cancelled`: `withdrawn` again.
    /// - A request consumed by a claim: `already_started`, with the outcome its
    ///   send settled with (`settled_outcome`). A request that settled before
    ///   that column existed answers from its attempt's `dispatch` audit row
    ///   instead. `unknown` while neither is recorded (still in flight, or the
    ///   process stopped before recording it). Never a guessed success.
    /// - Denied, past its expiry, or retired by the scope re-check: `refused`.
    /// - No row under the key: `unknown_call`.
    pub(crate) fn withdraw_keyed_request(
        &self,
        requester: &str,
        call_key: &str,
    ) -> Result<WithdrawAnswer, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let now = now_ms();
            let cancelled = conn.execute(
                "UPDATE action_requests SET status = 'cancelled', scope_outcome = NULL
                 WHERE requester = ?1 AND (call_key = ?2 OR request_id IN (SELECT request_id FROM consent_call_keys WHERE requester = ?1 AND call_key = ?2))
                    AND status IN ('pending', 'approved') AND expires_at > ?3",
                rusqlite::params![requester, call_key, now],
            )?;
            if cancelled == 1 {
                return Ok(WithdrawAnswer::Withdrawn);
            }
            #[allow(clippy::type_complexity)]
            let current: Option<(
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
            )> = conn
                .query_row(
                    "SELECT principal, status, scope_outcome, claimed_request_id, settled_outcome
                     FROM action_requests WHERE requester = ?1 AND (call_key = ?2 OR
                                 request_id IN (SELECT request_id FROM consent_call_keys WHERE requester = ?1 AND call_key = ?2))",
                    (requester, call_key),
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()?;
            let Some((principal, status, scope_outcome, claimed_request_id, settled_outcome)) =
                current
            else {
                return Ok(WithdrawAnswer::UnknownCall);
            };
            Ok(match status.as_str() {
                REQUEST_CANCELLED => WithdrawAnswer::Withdrawn,
                "denied" => WithdrawAnswer::Refused {
                    reason: WITHDRAW_REFUSED_DENIED,
                },
                "consumed" => match scope_outcome.as_deref() {
                    Some(outcome) => WithdrawAnswer::Refused {
                        reason: scope_refusal_reason(outcome),
                    },
                    None => WithdrawAnswer::AlreadyStarted {
                        outcome: match (settled_outcome, claimed_request_id) {
                            (Some(settled), _) => settled,
                            (None, Some(attempt)) => conn
                                .query_row(
                                    "SELECT outcome FROM audit_journal
                                     WHERE principal = ?1 AND request_id = ?2
                                       AND gate = 'dispatch' AND outcome IS NOT NULL
                                     ORDER BY journal_id LIMIT 1",
                                    (principal.as_str(), attempt.as_str()),
                                    |row| row.get::<_, String>(0),
                                )
                                .optional()?
                                .unwrap_or_else(|| WITHDRAW_OUTCOME_UNKNOWN.to_string()),
                            (None, None) => WITHDRAW_OUTCOME_UNKNOWN.to_string(),
                        },
                    },
                },
                // `expired`, or `pending`/`approved` past the expiry the
                // update above tested.
                _ => WithdrawAnswer::Refused {
                    reason: WITHDRAW_REFUSED_EXPIRED,
                },
            })
        })
    }

    pub fn list_action_requests(
        &self,
        principal: &str,
    ) -> Result<Vec<ActionRequestRecord>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(&format!(
                "SELECT {ACTION_REQUEST_COLUMNS}
                 FROM action_requests WHERE principal = ?1 ORDER BY created_at_ms"
            ))?;
            let rows = statement.query_map([principal], map_action_request_row)?;
            rows.collect()
        })
    }

    pub(crate) fn action_request(
        &self,
        principal: &str,
        request_id: &str,
    ) -> Result<Option<ActionRequestRecord>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                &format!(
                    "SELECT {ACTION_REQUEST_COLUMNS}
                     FROM action_requests WHERE principal = ?1 AND request_id = ?2"
                ),
                (principal, request_id),
                map_action_request_row,
            )
            .optional()
        })
    }

    /// Approved requests held unsent because their scope could not yet be
    /// confirmed live. Checked rows rotate behind unchecked rows, so an unreachable
    /// scope cannot monopolize the bounded scheduler batch.
    pub(crate) fn waiting_scoped_approvals(
        &self,
        limit: usize,
    ) -> Result<Vec<ActionRequestRecord>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let mut statement = conn.prepare(&format!(
                "SELECT {ACTION_REQUEST_COLUMNS}
                 FROM action_requests
                  WHERE status = 'approved' AND scope_outcome = ?1
                    AND (expires_at <= ?3 OR scope_checked_at_ms <= ?4)
                 ORDER BY scope_checked_at_ms,created_at_ms,principal,request_id LIMIT ?2"
            ))?;
            let rows = statement.query_map(
                rusqlite::params![crate::scope::APPROVED_WAITING, limit as i64, now_ms(), now_ms().saturating_sub(5_000)],
                map_action_request_row,
            )?;
            let rows=rows.collect::<rusqlite::Result<Vec<_>>>()?;
                let updated_at = now_ms().max(1);
                let mut update = conn.prepare_cached("UPDATE action_requests SET scope_checked_at_ms=?3 WHERE principal=?1 AND request_id=?2")?;
                for row in &rows {
                    update.execute(rusqlite::params![row.principal,row.request_id,updated_at])?;
                }
            Ok(rows)
        })
    }

    /// Record that a scoped approval is held unsent, waiting for its scope to
    /// be confirmed. Only an approval still `approved` is marked.
    pub(crate) fn hold_scoped_approval(
        &self,
        principal: &str,
        request_id: &str,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE action_requests SET scope_outcome = ?1
                 WHERE principal = ?2 AND request_id = ?3 AND status = 'approved'",
                rusqlite::params![crate::scope::APPROVED_WAITING, principal, request_id],
            )?;
            Ok(())
        })
    }

    /// Retire a scoped approval whose scope re-check refused it, so it can
    /// never be sent: the status moves to `consumed` and `scope_outcome` says
    /// it was not run and why. `consumed` rather than a new status keeps the
    /// table's status check intact, and a binary from before scopes, which
    /// does not know this column, still reads the row as spent after a
    /// rollback.
    pub(crate) fn refuse_scoped_approval(
        &self,
        principal: &str,
        request_id: &str,
        reason: &str,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE action_requests SET status = 'consumed', scope_outcome = ?1
                 WHERE principal = ?2 AND request_id = ?3 AND status = 'approved'",
                rusqlite::params![format!("not_run:{reason}"), principal, request_id],
            )?;
            Ok(())
        })
    }

    pub fn decide_action_request(
        &self,
        principal: &str,
        request_id: &str,
        approved: bool,
        decider: &str,
    ) -> Result<bool, StoreError> {
        let status = if approved { "approved" } else { "denied" };
        let decision = if approved { "allow" } else { "block" };
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE action_requests SET status = ?1, decision = ?2, decider = ?3
                 WHERE principal = ?4 AND request_id = ?5 AND status = 'pending'
                   AND expires_at > ?6",
                rusqlite::params![status, decision, decider, principal, request_id, now_ms()],
            )?;
            Ok(changed != 0)
        })
    }

    /// Persist the decision plane's verdict without reviving a completed intent.
    /// A retry may replace an open approved verdict, but a consumed or withdrawn
    /// request must never become another dispatchable approval.
    pub(crate) fn record_decision_plane_verdict(
        &self,
        principal: &str,
        request_id: &str,
        verdict: PlaneVerdict,
        decider: &str,
        decision_id: Option<&str>,
    ) -> Result<bool, StoreError> {
        let (status, decision) = match verdict {
            PlaneVerdict::Approved => ("approved", Some("allow")),
            PlaneVerdict::Denied => ("denied", Some("block")),
            PlaneVerdict::Pending => ("pending", None),
        };
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE action_requests SET status = ?1, decision = ?2, decider = ?3,
                    decision_id = ?4
                 WHERE principal = ?5 AND request_id = ?6
                    AND status IN ('pending', 'approved') AND expires_at > ?7",
                rusqlite::params![
                    status,
                    decision,
                    decider,
                    decision_id,
                    principal,
                    request_id,
                    now_ms()
                ],
            )?;
            Ok(changed != 0)
        })
    }

    /// A new tool call can resume an existing approval request. Keep its call
    /// key as an alias so withdrawal using either key targets the same request.
    /// Aliases create no additional approval: the request is still claimed once.
    pub(crate) fn remember_consent_call_key(
        &self,
        request: &ActionRequestRecord,
        call_key: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let existing: Option<String> = conn.query_row(
                "SELECT request_id FROM action_requests WHERE requester = ?1 AND call_key = ?2
                 UNION SELECT request_id FROM consent_call_keys WHERE requester = ?1 AND call_key = ?2",
                (&request.requester, call_key), |row| row.get(0)).optional()?;
            if let Some(existing) = existing { return Ok(existing == request.request_id); }
            conn.execute("INSERT INTO consent_call_keys (requester, call_key, principal, request_id) VALUES (?1, ?2, ?3, ?4)",
                (&request.requester, call_key, &request.principal, &request.request_id))?;
            Ok(true)
        })
    }

    pub(crate) fn matching_consent_request(
        &self,
        call: &crate::governance::AuthorizationRequest,
    ) -> Result<Option<ActionRequestRecord>, StoreError> {
        self.inner.with_read(|conn| {
            let mut query = conn.prepare(&format!("SELECT {ACTION_REQUEST_COLUMNS} FROM action_requests
                WHERE requester = ?1 AND connection_id = ?2 AND action = ?3 AND elicitation_id IS NOT NULL ORDER BY created_at_ms DESC, rowid DESC"))?;
            let rows = query.query_map((&call.principal, &call.connection_id, &call.action), map_action_request_row)?;
            for row in rows {
                let row = row?;
                let same_scope = match (row.scope.as_ref(), call.scope()) {
                    (Some(held), Some(scope)) => held.owner == scope.owner && held.scope_ref == scope.scope_ref && held.scope_epoch == scope.scope_epoch,
                    _ => false,
                };
                if same_scope && row.args_snapshot == call.args { return Ok(Some(row)); }
            }
            Ok(None)
        })
    }

    /// Record the current card id, including a fresh card replacing one that
    /// Cingulate no longer retains.
    pub fn set_action_request_elicitation_id(
        &self,
        principal: &str,
        request_id: &str,
        elicitation_id: &str,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE action_requests SET elicitation_id = ?1
                 WHERE principal = ?2 AND request_id = ?3",
                rusqlite::params![elicitation_id, principal, request_id],
            )?;
            Ok(())
        })
    }

    /// The request with id `request_id`, whichever principal it belongs to.
    /// A consent card echoes this id as its opaque `requester_ref`.
    pub fn action_request_by_id(
        &self,
        request_id: &str,
    ) -> Result<Option<ActionRequestRecord>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                &format!(
                    "SELECT {ACTION_REQUEST_COLUMNS}
                     FROM action_requests WHERE request_id = ?1
                     ORDER BY created_at_ms LIMIT 1"
                ),
                [request_id],
                map_action_request_row,
            )
            .optional()
        })
    }

    pub(crate) fn settle_consent_request(
        &self,
        principal: &str,
        request_id: &str,
        state: &str,
        decider: &str,
    ) -> Result<(), StoreError> {
        if state == "withdrawn" {
            return self.inner.with_conn_fenced(|conn| {
                conn.execute("UPDATE action_requests SET status = 'cancelled' WHERE principal = ?1 AND request_id = ?2 AND status = 'pending'", (principal, request_id))?;
                Ok(())
            });
        }
        let settlement = if state == "expired" {
            ConsentSettlement::Expired {
                principal: principal.into(),
                request_id: request_id.into(),
            }
        } else {
            ConsentSettlement::Denied {
                principal: principal.into(),
                request_id: request_id.into(),
                decider: decider.into(),
            }
        };
        self.settle_consent_requests(&[settlement])
    }

    /// Settle only still-pending requests. A decline after the approval's own
    /// deadline records expiry, never a usable decision.
    pub fn settle_consent_requests(
        &self,
        settlements: &[ConsentSettlement],
    ) -> Result<(), StoreError> {
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            for settlement in settlements {
                match settlement {
                    ConsentSettlement::Denied {
                        principal,
                        request_id,
                        decider,
                    } => {
                        conn.execute(
                            "UPDATE action_requests
                             SET status = CASE WHEN expires_at <= ?4 THEN 'expired' ELSE 'denied' END,
                                 decision = CASE WHEN expires_at <= ?4 THEN decision ELSE 'block' END,
                                 decider = CASE WHEN expires_at <= ?4 THEN decider ELSE ?1 END
                             WHERE principal = ?2 AND request_id = ?3 AND status = 'pending'",
                            rusqlite::params![decider, principal, request_id, now],
                        )?;
                    }
                    ConsentSettlement::Expired {
                        principal,
                        request_id,
                    } => {
                        conn.execute(
                            "UPDATE action_requests SET status = 'expired'
                             WHERE principal = ?1 AND request_id = ?2 AND status = 'pending'",
                            rusqlite::params![principal, request_id],
                        )?;
                    }
                }
            }
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_reservation(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        grant_id: &str,
        snapshot: &SnapshotGenerations,
        approved_args_hash: &str,
        schema_hash: &str,
        expires_at: i64,
        approval_request_id: Option<&str>,
        agent_grant: Option<&PinnedGrant>,
    ) -> Result<ReservationRecord, StoreError> {
        let reservation_id = new_id("res");
        let generations = serde_json::to_string(snapshot)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO reservations
                    (reservation_id, principal, connection_id, action, snapshot_generations,
                     approved_args_hash, schema_hash, expires_at, status, created_at_ms, grant_id,
                     approval_request_id, agent_grant_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'reserved', ?9, ?10, ?11, ?12)",
                rusqlite::params![
                    reservation_id,
                    principal,
                    connection_id,
                    action,
                    generations,
                    approved_args_hash,
                    schema_hash,
                    expires_at,
                    now_ms(),
                    grant_id,
                    approval_request_id,
                    agent_grant.map(|grant| grant.grant_id.as_str()),
                ],
            )?;
            Ok(())
        })?;
        Ok(ReservationRecord {
            reservation_id,
            principal: principal.to_string(),
            connection_id: connection_id.to_string(),
            action: action.to_string(),
            grant_id: grant_id.to_string(),
            snapshot: snapshot.clone(),
            approved_args_hash: approved_args_hash.to_string(),
            schema_hash: schema_hash.to_string(),
            expires_at,
            status: "reserved".to_string(),
            agent_grant: agent_grant.cloned(),
        })
    }

    /// Atomically verifies a reservation's snapshot and claims it for dispatch.
    /// A false result means the reservation was expired, invalidated, or stale;
    /// stale/expired reserved rows are consumed so they cannot be replayed.
    ///
    /// A reservation authorized under an ordinary approval also consumes that
    /// approval here, in the same transaction: the approval must still be
    /// `approved` and unexpired, and moves to `consumed`. If another claim
    /// consumed it first, this claim fails and nothing is sent. Consuming at the
    /// claim rather than after the vendor answers means a crash, a lost reply or
    /// an unknown outcome can never leave the approval usable for a second send,
    /// while a reservation that expires or is abandoned before its claim leaves
    /// the approval untouched for a genuine retry.
    ///
    /// `attempt_request_id` is the request id of the dispatch attempt making
    /// this claim. It is recorded on the approval it consumes, because that
    /// attempt's `dispatch` audit row is where a later `tool.withdraw` reads
    /// how the call settled.
    ///
    /// A withdrawn approval is `cancelled`, not `approved`, so the approval
    /// update below matches nothing and the claim fails: the withdrawal and
    /// the claim race on the same row, and only one of them can win.
    pub(crate) fn claim_reservation(
        &self,
        reservation: &ReservationRecord,
        attempt_request_id: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let claim_now = now_ms();
            #[allow(clippy::type_complexity)]
            let current: Option<(
                String,
                i64,
                i64,
                i64,
                i64,
                Option<String>,
                Option<i64>,
            )> = conn
                .query_row(
                    "SELECT status, expires_at,
                            COALESCE((SELECT generation FROM connections
                             WHERE principal = ?1 AND connection_id = ?2), -1),
                            COALESCE((SELECT generation FROM catalog_actions
                             WHERE principal = ?1 AND connection_id = ?2 AND name = ?3), -1),
                            -- Pin the grant that authorized this reservation.
                            -- A maximum across matching grants cannot detect
                            -- the revocation of the authorizing grant whenever
                            -- another grant holds the maximum, and conversely
                            -- lets an unrelated grant invalidate work it never
                            -- authorized. A revoked grant yields NULL, which
                            -- coalesces to -1 and can never equal a stored
                            -- generation, so revocation always aborts.
                            COALESCE((SELECT generation FROM grants
                             WHERE principal = ?1 AND (expires_at IS NULL OR expires_at > ?5) AND grant_id = (
                                 SELECT grant_id FROM reservations
                                 WHERE principal = ?1 AND reservation_id = ?4
                         )), -1),
                            approval_request_id,
                            -- The agent grant of a call made as an agent, pinned
                            -- the same way. NULL when the call named no agent
                            -- grant or the grant is gone.
                            (SELECT generation FROM grants
                             WHERE principal = ?1 AND (expires_at IS NULL OR expires_at > ?5) AND grant_id = reservations.agent_grant_id)
                     FROM reservations
                     WHERE principal = ?1 AND reservation_id = ?4",
                    (
                        reservation.principal.as_str(),
                        reservation.connection_id.as_str(),
                        reservation.action.as_str(),
                        reservation.reservation_id.as_str(),
                        claim_now,
                    ),
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                status,
                expires_at,
                connection,
                catalog,
                grant,
                approval_request_id,
                agent_grant,
            )) = current
            else {
                return Ok(false);
            };
            let policy = governing_policy(
                conn,
                &reservation.principal,
                &reservation.connection_id,
                &reservation.action,
                claim_now,
            )?;
            let agent_grant_unchanged = match reservation.agent_grant.as_ref() {
                Some(pinned) => agent_grant == Some(pinned.generation),
                None => true,
            };
            let mut valid = status == "reserved"
                && expires_at > claim_now
                && connection == reservation.snapshot.connection
                && catalog == reservation.snapshot.catalog_action
                && grant == reservation.snapshot.grant
                && policy.as_ref().map_or(0, |value| value.generation) == reservation.snapshot.policy
                && policy.as_ref().map(|value| &value.policy_id) == reservation.snapshot.policy_id.as_ref()
                && agent_grant_unchanged;
            if valid {
                if let Some(approval_request_id) = approval_request_id.as_deref() {
                    // Zero rows means the approval was already consumed by
                    // another claim, lapsed, or was never approved: this
                    // reservation no longer has the consent it was issued
                    // under. A scope hold recorded on the approval is cleared,
                    // since the approval is now being sent.
                    let consumed = conn.execute(
                        "UPDATE action_requests SET status = 'consumed', scope_outcome = NULL,
                                claimed_request_id = ?4
                         WHERE principal = ?1 AND request_id = ?2
                           AND status = 'approved' AND expires_at > ?3",
                        (
                            reservation.principal.as_str(),
                            approval_request_id,
                            claim_now,
                            attempt_request_id,
                        ),
                    )?;
                    valid = consumed == 1;
                }
            }
            let next_status = if valid {
                "dispatched"
            } else if expires_at <= claim_now {
                "expired"
            } else {
                "invalidated"
            };
            conn.execute(
                "UPDATE reservations SET status = ?1
                 WHERE principal = ?2 AND reservation_id = ?3 AND status = 'reserved'",
                (
                    next_status,
                    reservation.principal.as_str(),
                    reservation.reservation_id.as_str(),
                ),
            )?;
            Ok(valid)
        })
    }

    pub fn reservation(
        &self,
        principal: &str,
        reservation_id: &str,
    ) -> Result<Option<ReservationRecord>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT reservation_id, principal, connection_id, action,
                        snapshot_generations, approved_args_hash, schema_hash, expires_at, status,
                        grant_id
                 FROM reservations WHERE principal = ?1 AND reservation_id = ?2",
                (principal, reservation_id),
                |row| {
                    let generations: String = row.get(4)?;
                    Ok(ReservationRecord {
                        reservation_id: row.get(0)?,
                        principal: row.get(1)?,
                        connection_id: row.get(2)?,
                        action: row.get(3)?,
                        grant_id: row.get::<_, Option<String>>(9)?.unwrap_or_default(),
                        snapshot: parse_json_column(&generations)?,
                        approved_args_hash: row.get(5)?,
                        schema_hash: row.get(6)?,
                        expires_at: row.get(7)?,
                        status: row.get(8)?,
                        // The reservation read-back serves inspection, not the
                        // claim, which always uses the in-memory pin.
                        agent_grant: None,
                    })
                },
            )
            .optional()
        })
    }

    /// Mark a reservation that will not be claimed as invalidated, so it can
    /// never be claimed later. Used when a stored approval's scope re-check
    /// stops a send before the claim.
    pub(crate) fn abandon_reservation(
        &self,
        principal: &str,
        reservation_id: &str,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE reservations SET status = 'invalidated'
                 WHERE principal = ?1 AND reservation_id = ?2 AND status = 'reserved'",
                (principal, reservation_id),
            )?;
            Ok(())
        })
    }

    /// Enroll a vault credential reference and return a single-use ticket.
    /// Public connect consumes the ticket, never credential material.
    #[cfg(any(test, feature = "test-support"))]
    pub fn create_binding_ticket(
        &self,
        principal: &str,
        connection_id: &str,
        credential_id_bytes: &[u8],
    ) -> Result<BindingTicket, StoreError> {
        self.create_binding_ticket_with_role(
            principal,
            connection_id,
            "credential_reference",
            credential_id_bytes,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn create_binding_ticket_with_role(
        &self,
        principal: &str,
        connection_id: &str,
        ref_role: &str,
        credential_id_bytes: &[u8],
    ) -> Result<BindingTicket, StoreError> {
        self.create_binding_ticket_bounded(
            principal,
            connection_id,
            ref_role,
            credential_id_bytes,
            &Ceiling::unrestricted_for_tests(),
        )
    }

    /// Store a validated vault id under `credential_reference`, or NULL under
    /// `none` for a manifest-reviewed credential-free vendor. The ticket carries
    /// the permanent authority ceiling; no resolved secret enters SQLite.
    ///
    /// The connection must already exist. Its refusals (revoked, or a ceiling
    /// wider than the one already recorded) surface as a store error; the
    /// operator ceremony uses [`Self::issue_binding_ticket`], which reports
    /// them by name.
    #[cfg(any(test, feature = "test-support"))]
    pub fn create_binding_ticket_bounded(
        &self,
        principal: &str,
        connection_id: &str,
        ref_role: &str,
        credential_id_bytes: &[u8],
        ceiling: &Ceiling,
    ) -> Result<BindingTicket, StoreError> {
        self.write_binding_ticket(
            principal,
            connection_id,
            None,
            ref_role,
            credential_id_bytes,
            ceiling,
        )?
        .map_err(|refusal| StoreError::Backend(format!("binding ticket refused: {refusal}")))
    }

    /// Issue the ticket that enrolls `connection_id` for `app_key`, creating the
    /// connection as `pending` when the principal has none with that id.
    ///
    /// A ticket may re-enroll an existing connection of the same app that is
    /// not revoked, but it never changes that connection's ceiling, which is
    /// permanent once set: a wider request is refused by name, and an equal or
    /// narrower one is accepted and the recorded ceiling stays as it was. It is
    /// refused for a connection of a different app, whose ceiling would
    /// otherwise be judged against the wrong vendor, and for a revoked
    /// connection, which never becomes active again. The checks and the writes
    /// share one transaction, and a refusal writes nothing.
    pub fn issue_binding_ticket(
        &self,
        principal: &str,
        connection_id: &str,
        app_key: &str,
        ref_role: &str,
        credential_id_bytes: &[u8],
        ceiling: &Ceiling,
    ) -> Result<Result<BindingTicket, CeremonyRefusal>, StoreError> {
        self.write_binding_ticket(
            principal,
            connection_id,
            Some(app_key),
            ref_role,
            credential_id_bytes,
            ceiling,
        )
    }

    fn write_binding_ticket(
        &self,
        principal: &str,
        connection_id: &str,
        create_for_app: Option<&str>,
        ref_role: &str,
        credential_id_bytes: &[u8],
        ceiling: &Ceiling,
    ) -> Result<Result<BindingTicket, CeremonyRefusal>, StoreError> {
        let credential_free = ref_role == NO_CREDENTIAL_REF_ROLE;
        if credential_free != credential_id_bytes.is_empty() {
            return Err(StoreError::Backend(
                "binding ticket: a credential-free enrollment must supply no credential id, and a \
                 credentialed one must supply a credential id"
                    .to_string(),
            ));
        }
        let binding = if credential_free {
            None
        } else if ref_role == "credential_reference" {
            let id = std::str::from_utf8(credential_id_bytes)
                .map_err(|_| StoreError::Backend("invalid credential id".into()))?;
            Some(encode_reference_binding(id).map_err(StoreError::Backend)?)
        } else {
            return Err(StoreError::Backend(
                "handle_bindings_removed: use credential_id with credential_reference".into(),
            ));
        };
        let ticket_id = new_id("ticket");
        let expires_at = now_ms().saturating_add(BINDING_TICKET_TTL_MS);
        let selectors = serde_json::to_string(&ceiling.action_selectors)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let risk = ceiling.risk.to_string();
        let now = now_ms();
        let refusal = self.inner.with_conn_fenced(|conn| {
            let existing: Option<(String, String, Option<String>, Option<String>)> = conn
                .query_row(
                    "SELECT app_key, status, ceiling_risk, ceiling_selectors FROM connections
                     WHERE principal = ?1 AND connection_id = ?2",
                    (principal, connection_id),
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            match (existing, create_for_app) {
                (None, None) => return Ok(Some(CeremonyRefusal::ConnectionNotFound)),
                (None, Some(app_key)) => {
                    conn.execute(
                        "INSERT INTO connections
                            (connection_id, principal, app_key, status, resource_filters,
                             created_at_ms, updated_at_ms)
                         VALUES (?1, ?2, ?3, 'pending', '{}', ?4, ?4)",
                        rusqlite::params![connection_id, principal, app_key, now],
                    )?;
                }
                (Some((app_key, status, ceiling_risk, ceiling_selectors)), requested_app) => {
                    if let Some(requested_app) = requested_app.filter(|app| *app != app_key) {
                        return Ok(Some(CeremonyRefusal::ConnectionAppMismatch {
                            connection_app: app_key,
                            requested_app: requested_app.to_string(),
                        }));
                    }
                    if status == "revoked" {
                        return Ok(Some(CeremonyRefusal::ConnectionRevoked));
                    }
                    if status != "pending" {
                        return Ok(Some(CeremonyRefusal::ConnectionExists));
                    }
                    if let (Some(recorded_risk), Some(recorded_selectors)) =
                        (ceiling_risk, ceiling_selectors)
                    {
                        if let Some(refusal) =
                            wider_than_recorded(ceiling, &recorded_risk, &recorded_selectors)?
                        {
                            return Ok(Some(refusal));
                        }
                    }
                }
            }
            // The pending binding belongs only to the newest ticket. Superseded
            // tickets must not pair their ceiling with that newer credential.
            conn.execute(
                "UPDATE binding_tickets SET status='expired', settled_at_ms=?3
                 WHERE principal=?1 AND connection_id=?2 AND status='issued'",
                (principal, connection_id, now),
            )?;
            conn.execute(
                "UPDATE connections SET credential_binding = ?1, updated_at_ms = ?2,
                        generation = generation + 1
                 WHERE principal = ?3 AND connection_id = ?4 AND status <> 'revoked'",
                rusqlite::params![binding, now, principal, connection_id],
            )?;
            conn.execute(
                "INSERT INTO binding_tickets
                    (ticket_id, principal, connection_id, ref_role, expires_at, status,
                     created_at_ms, risk_ceiling, action_selectors)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'issued', ?6, ?7, ?8)",
                rusqlite::params![
                    ticket_id,
                    principal,
                    connection_id,
                    ref_role,
                    expires_at,
                    now,
                    risk,
                    selectors
                ],
            )?;
            Ok(None)
        })?;
        if let Some(refusal) = refusal {
            return Ok(Err(refusal));
        }
        Ok(Ok(BindingTicket {
            ticket_id,
            principal: principal.to_string(),
            connection_id: connection_id.to_string(),
            ref_role: ref_role.to_string(),
            expires_at,
            status: "issued".to_string(),
        }))
    }

    /// Resolve a requested ceiling against the vendor's reviewed manifest.
    ///
    /// This is the first link of the authority chain: no ticket may authorize an
    /// action the vendor never declared, nor a risk above the highest risk the
    /// vendor's own action set contains. A `"*"` selector expands here to the
    /// manifest's declared action names, so the stored ceiling is concrete.
    pub fn ceiling_within_manifest(
        &self,
        app_key: &str,
        requested_risk: &str,
        requested_selectors: &[String],
    ) -> Result<Result<Ceiling, CeremonyRefusal>, StoreError> {
        let Some(risk) = Risk::parse(requested_risk) else {
            return Ok(Err(CeremonyRefusal::InvalidRisk(
                requested_risk.to_string(),
            )));
        };
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, app_key)? else {
            return Ok(Err(CeremonyRefusal::UnknownApp(app_key.to_string())));
        };
        // A retired manifest is refused here, at the FIRST link of the authority
        // chain, so no ticket can be minted against a vendor withdrawn from the
        // reviewed catalog. Hiding it from the connectable list is not enough on
        // its own: an operator working from a remembered app key, a script, or a
        // scrollback would otherwise still reach it, and the retirement exists
        // precisely because someone decided the vendor must not be used.
        if self.manifest_is_retired(app_key)? {
            return Ok(Err(CeremonyRefusal::RetiredApp(app_key.to_string())));
        }
        let manifest = document.map_err(StoreError::Backend)?;
        let declared: Vec<String> = manifest
            .actions_baseline
            .iter()
            .map(|action| action.name.clone())
            .collect();
        let manifest_max = manifest
            .actions_baseline
            .iter()
            .map(|action| action.risk)
            .max()
            .unwrap_or(Risk::Read);
        if !risk.within(manifest_max) {
            return Ok(Err(CeremonyRefusal::RiskAboveCeiling {
                requested: risk.to_string(),
                ceiling: manifest_max.to_string(),
            }));
        }
        let selectors = if requested_selectors.iter().any(|value| value == "*") {
            declared
        } else {
            for selector in requested_selectors {
                if !declared.contains(selector) {
                    return Ok(Err(CeremonyRefusal::UndeclaredAction(selector.clone())));
                }
            }
            requested_selectors.to_vec()
        };
        Ok(Ok(Ceiling {
            risk,
            action_selectors: selectors,
        }))
    }

    /// True when the vendor's reviewed manifest declares `auth.mode = none`.
    /// An unknown or unparseable manifest reports `false`, so a catalog problem
    /// makes a vendor look credentialed rather than credential-free — the
    /// direction that fails closed.
    pub fn manifest_requires_no_credential(&self, app_key: &str) -> Result<bool, StoreError> {
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, app_key)? else {
            return Ok(false);
        };
        let manifest = match document {
            Ok(manifest) => manifest,
            Err(_) => return Ok(false),
        };
        Ok(matches!(
            manifest.auth.mode,
            crate::manifest::AuthMode::None
        ))
    }

    /// The ceiling recorded on a connection, or `CeilingAbsent` when the
    /// connection predates ceilings (fail closed: nothing may be minted).
    #[cfg(any(test, feature = "test-support"))]
    pub fn connection_ceiling(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Result<Ceiling, CeremonyRefusal>, StoreError> {
        let row: Option<(Option<String>, Option<String>)> = self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT ceiling_risk, ceiling_selectors FROM connections
                 WHERE principal = ?1 AND connection_id = ?2",
                (principal, connection_id),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
        })?;
        let Some((risk, selectors)) = row else {
            return Ok(Err(CeremonyRefusal::ConnectionNotFound));
        };
        let (Some(risk), Some(selectors)) = (risk, selectors) else {
            return Ok(Err(CeremonyRefusal::CeilingAbsent));
        };
        let Some(risk) = Risk::parse(&risk) else {
            return Ok(Err(CeremonyRefusal::InvalidRisk(risk)));
        };
        let action_selectors = parse_string_list(&selectors)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(Ok(Ceiling {
            risk,
            action_selectors,
        }))
    }

    /// Mint a grant, refused unless it is a subset of the connection's ceiling.
    /// The refusal path writes nothing.
    pub fn mint_grant_bounded(
        &self,
        request: &GrantMintRequest,
    ) -> Result<Result<GrantRecord, CeremonyRefusal>, StoreError> {
        let GrantMintRequest {
            principal,
            connection_id,
            grantee_principal,
            authority_kind,
            requested_risk,
            requested_selectors,
            expires_at,
        } = request;
        // Expiry is OPTIONAL for every authority kind, poll included.
        //
        // This deliberately reverses a rule that made poll expiry mandatory. The
        // old comment here claimed expiry was "the only mechanism that makes
        // inattention STOP polling rather than continue it", and that was untrue:
        // VISIBILITY PLUS EASY REVOCATION is another mechanism, and a better one.
        // Mandatory expiry puts the cost on the common case -- the operator still
        // wants the watch -- to defend against the rare one, and collects it
        // forever, on a schedule, from someone who already consented.
        //
        // The hidden assumption was that inattention should default to REVOKING.
        // For a personal fleet, where the grant was given deliberately, it should
        // default to CONTINUING; the remedy for "I forgot this existed" is a
        // surface listing every live grant with one-click revoke, not a deadline.
        //
        // SILENTLY is why the old rule was harmful rather than merely annoying:
        // when a poll grant lapsed the watches just stopped collecting. No error,
        // no alarm -- the feed went quiet and looked like a quiet week.
        //
        // An operator who WANTS a bounded grant still passes an expiry and it is
        // still enforced on every poll. What is gone is the refusal to mint
        // without one.
        let expires_at = *expires_at;
        if *grantee_principal == "*" {
            return Ok(Err(CeremonyRefusal::WildcardGrantee));
        }
        race_point("grant_insert");
        self.inner.with_conn_fenced(|conn| {
            let ceiling = match grant_ceiling_on_conn(conn, principal, connection_id)? {
                Ok(ceiling) => ceiling,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let Some(risk) = Risk::parse(requested_risk) else {
                return Ok(Err(CeremonyRefusal::InvalidRisk(
                    requested_risk.to_string(),
                )));
            };
            // Expand a requested wildcard against the connection's ceiling,
            // which may name fewer actions than the app manifest.
            let selectors = if requested_selectors.iter().any(|value| value == "*") {
                ceiling.action_selectors.clone()
            } else {
                requested_selectors.to_vec()
            };
            // Wildcards expand to the connection's actions; an empty expansion is
            // just as unusable as an explicitly empty request, not unrestricted.
            if selectors.is_empty() {
                return Ok(Err(CeremonyRefusal::EmptyActionSelectors));
            }
            let requested = Ceiling {
                risk,
                action_selectors: selectors.clone(),
            };
            if !requested.risk.within(ceiling.risk) {
                return Ok(Err(CeremonyRefusal::RiskAboveCeiling {
                    requested: requested.risk.to_string(),
                    ceiling: ceiling.risk.to_string(),
                }));
            }
            // A stored '*' selector admits any action. Match Ceiling::within's
            // subset rule so minting and later grant checks interpret it identically.
            let ceiling_is_open = ceiling.action_selectors.iter().any(|value| value == "*");
            if !ceiling_is_open {
                if let Some(outside) = selectors
                    .iter()
                    .find(|selector| !ceiling.action_selectors.contains(selector))
                {
                    // Distinct from `UndeclaredAction`, which belongs to the
                    // manifest link of the chain. Reusing it here sends an operator
                    // to the manifest to look for an action that is sitting in the
                    // manifest, fully declared -- so the message denies something
                    // they can see is true, and the natural conclusion is that the
                    // module is broken.
                    //
                    // The two also have completely different remedies. An undeclared
                    // action is fixed by editing a manifest; a ceiling breach cannot
                    // be fixed by minting a grant or issuing another ticket. It
                    // requires an explicit operator ceiling-widening ceremony.
                    return Ok(Err(CeremonyRefusal::OutsideConnectionCeiling {
                        action: outside.clone(),
                        ceiling: ceiling.action_selectors.clone(),
                    }));
                }
            }
            let grant_id = new_id("grant");
            let input = GrantInput {
                grant_id: grant_id.clone(),
                principal: principal.to_string(),
                connection_id: connection_id.to_string(),
                grantee_principal: grantee_principal.to_string(),
                risk_ceiling: requested.risk.to_string(),
                action_selectors: selectors.clone(),
                authority_kind: authority_kind.to_string(),
                expires_at,
            };
            insert_grant_on_conn(conn, &input)?;
            Ok(Ok(GrantRecord {
                grant_id,
                principal: principal.to_string(),
                connection_id: connection_id.to_string(),
                grantee_principal: grantee_principal.to_string(),
                risk_ceiling: requested.risk.to_string(),
                action_selectors: selectors,
                authority_kind: authority_kind.to_string(),
                expires_at,
                // `insert_grant` stores a new grant at generation 1.
                generation: 1,
                revoked_at_ms: None,
                revoked_by: None,
                state: grant_state(expires_at, None, now_ms()).to_string(),
            }))
        })
    }

    /// Read one live grant by its owner-scoped id for revocation audit attribution.
    pub fn grant_by_id(
        &self,
        principal: &str,
        grant_id: &str,
    ) -> Result<Option<GrantSummary>, StoreError> {
        self.inner.with_read(|conn|conn.query_row(
            "SELECT g.grant_id,g.connection_id,c.app_key,g.grantee_principal,g.risk_ceiling,g.action_selectors,g.authority_kind,g.expires_at,g.created_at_ms,NULL,NULL FROM grants g LEFT JOIN connections c ON c.principal=g.principal AND c.connection_id=g.connection_id WHERE g.principal=?1 AND g.grant_id=?2",
            (principal,grant_id),|row|map_grant_summary_row(row,now_ms()),
        ).optional())
    }

    /// Read one policy without loading the owner's unrelated policy history.
    pub fn policy_by_id(
        &self,
        principal: &str,
        policy_id: &str,
    ) -> Result<Option<PolicySummary>, StoreError> {
        self.inner.with_read(|conn|conn.query_row(
            "SELECT p.policy_id,p.connection_id,c.app_key,p.action_selector,p.effect,p.expires_at FROM policies p LEFT JOIN connections c ON c.principal=p.principal AND c.connection_id=p.connection_id WHERE p.principal=?1 AND p.policy_id=?2",
            (principal,policy_id),|row|map_policy_summary_row(row,now_ms()),
        ).optional())
    }

    /// Every grant this principal holds, across all connections, shaped for an
    /// operator deciding what to revoke.
    ///
    /// WHY THIS EXISTS SEPARATELY from `list_grants`: that one answers "what is
    /// granted on THIS connection", which requires already knowing the connection
    /// id. An operator asking "what have I granted?" has no such starting point —
    /// and that is the question that matters, because the grant you need to
    /// revoke is by definition the one you forgot about.
    ///
    /// It carries `app_key` rather than only the connection id, because a
    /// connection id identifies a row and a vendor name identifies a decision.
    ///
    /// STATE IS DERIVED HERE, not left to the caller. A client recomputing
    /// liveness from a deadline and its own clock will eventually disagree with
    /// this module, silently and in the direction that shows a dead grant as
    /// live. One emitter, one answer.
    pub fn list_all_grants(&self, principal: &str) -> Result<Vec<GrantSummary>, StoreError> {
        let now = now_ms();
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT g.grant_id, g.connection_id, c.app_key, g.grantee_principal,
                        g.risk_ceiling, g.action_selectors, g.authority_kind,
                         g.expires_at, g.created_at_ms, g.revoked_at_ms, g.revoked_by
                 FROM (
                     SELECT grant_id, principal, connection_id, grantee_principal,
                            risk_ceiling, action_selectors, authority_kind, expires_at,
                            created_at_ms, NULL AS revoked_at_ms, NULL AS revoked_by FROM grants
                     UNION ALL
                     SELECT grant_id, principal, connection_id, grantee_principal,
                            risk_ceiling, action_selectors, authority_kind, expires_at,
                            created_at_ms, revoked_at_ms, revoked_by FROM grant_revocations
                 ) g
                 LEFT JOIN connections c
                   ON c.connection_id = g.connection_id AND c.principal = g.principal
                 WHERE g.principal = ?1
                 ORDER BY g.created_at_ms DESC",
            )?;
            let rows = statement.query_map((principal,), |row| map_grant_summary_row(row, now))?;
            rows.collect()
        })
    }

    /// List policies for a principal, optionally narrowed to one connection.
    ///
    /// Policies outlive a removed connection until an operator removes them, so
    /// this is deliberately a left join: hiding an orphaned policy would hide the
    /// row most likely to need cleanup.
    pub fn list_policies(
        &self,
        principal: &str,
        connection_id: Option<&str>,
    ) -> Result<Vec<PolicySummary>, StoreError> {
        let now = now_ms();
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT p.policy_id, p.connection_id, c.app_key, p.action_selector,
                        p.effect, p.expires_at
                 FROM policies p
                 LEFT JOIN connections c
                   ON c.connection_id = p.connection_id AND c.principal = p.principal
                 WHERE p.principal = ?1 AND (?2 IS NULL OR p.connection_id = ?2)
                 ORDER BY p.updated_at_ms DESC, p.policy_id",
            )?;
            let rows = statement.query_map((principal, connection_id), |row| {
                map_policy_summary_row(row, now)
            })?;
            rows.collect()
        })
    }

    /// List the grants recorded against a connection. An operator cannot decide
    /// what to revoke without seeing what exists, so this is part of the
    /// ceremony surface rather than an internal query.
    pub fn list_grants(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Vec<GrantRecord>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT grant_id, principal, connection_id, grantee_principal, risk_ceiling,
                        action_selectors, authority_kind, expires_at, generation,
                        revoked_at_ms, revoked_by
                 FROM (
                     SELECT grant_id, principal, connection_id, grantee_principal, risk_ceiling,
                            action_selectors, authority_kind, expires_at, generation, created_at_ms,
                            NULL AS revoked_at_ms, NULL AS revoked_by FROM grants
                     UNION ALL
                     SELECT grant_id, principal, connection_id, grantee_principal, risk_ceiling,
                            action_selectors, authority_kind, expires_at, generation, created_at_ms,
                            revoked_at_ms, revoked_by FROM grant_revocations
                 ) WHERE principal = ?1 AND connection_id = ?2 ORDER BY created_at_ms",
            )?;
            let rows = statement.query_map((principal, connection_id), |row| {
                let selectors: String = row.get(5)?;
                Ok(GrantRecord {
                    grant_id: row.get(0)?,
                    principal: row.get(1)?,
                    connection_id: row.get(2)?,
                    grantee_principal: row.get(3)?,
                    risk_ceiling: row.get(4)?,
                    action_selectors: parse_string_list(&selectors)?,
                    authority_kind: row.get(6)?,
                    expires_at: row.get(7)?,
                    generation: row.get(8)?,
                    revoked_at_ms: row.get(9)?,
                    revoked_by: row.get(10)?,
                    state: grant_state(row.get(7)?, row.get(9)?, now_ms()).to_string(),
                })
            })?;
            rows.collect()
        })
    }

    /// Durably journal before deleting authority in the fenced transaction.
    /// A failed transaction may leave an extra revocation, never an unjournalled
    /// deletion. The immutable SQL snapshot separately survives audit retention.
    /// Retries return false without creating another snapshot.
    pub fn revoke_grant(&self, principal: &str, grant_id: &str) -> Result<bool, StoreError> {
        self.revoke_grant_as(principal, grant_id, principal)
    }

    /// Revoke on the owner's authority while recording the actual revoking actor.
    pub fn revoke_grant_as(
        &self,
        principal: &str,
        grant_id: &str,
        actor: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM grants WHERE principal=?1 AND grant_id=?2)",
                (principal, grant_id),
                |row| row.get(0),
            )?;
            if !exists {
                return Ok(false);
            }
            let entry = crate::grant_journal::Revocation {
                principal: principal.into(),
                grant_id: grant_id.into(),
                revoked_at_ms: now_ms(),
            };
            if let Some(path) = &self.grant_journal {
                crate::grant_journal::append(path, &entry)?;
            }
            Ok(crate::grant_journal::apply_as(conn, &entry, actor)? != 0)
        })
    }

    /// Every distinct agent id that holds at least one grant row, across all
    /// principals. A revoked grant has already left `grants`, so an agent whose
    /// grants were all revoked is not listed again.
    pub fn agents_holding_grants(&self) -> Result<Vec<String>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT DISTINCT agent_id FROM grants
                 WHERE agent_id IS NOT NULL ORDER BY agent_id",
            )?;
            let rows = statement.query_map([], |row| row.get(0))?;
            rows.collect()
        })
    }

    /// The grant rows held by one agent, whichever principal owns them.
    pub fn grants_held_by_agent(&self, agent_id: &str) -> Result<Vec<AgentHeldGrant>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT principal, grant_id, connection_id FROM grants
                 WHERE agent_id = ?1 ORDER BY principal, grant_id",
            )?;
            let rows = statement.query_map([agent_id], |row| {
                Ok(AgentHeldGrant {
                    principal: row.get(0)?,
                    grant_id: row.get(1)?,
                    connection_id: row.get(2)?,
                })
            })?;
            rows.collect()
        })
    }

    /// Test-only: insert a grant and attribute it to an agent, the shape a
    /// GitHub handle import or handle grant writes.
    #[cfg(test)]
    pub(crate) fn insert_agent_grant_for_test(
        &self,
        input: &GrantInput,
        agent_id: &str,
    ) -> Result<(), StoreError> {
        self.insert_grant(input)?;
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE grants SET agent_id = ?3 WHERE principal = ?1 AND grant_id = ?2",
                rusqlite::params![input.principal, input.grant_id, agent_id],
            )?;
            Ok(())
        })
    }

    /// Consume a short-lived binding ticket without returning the credential
    /// handle. The connection becomes active only after this operation.
    /// The ticket's ceiling is copied onto the connection in the same
    /// transaction, so an active connection always carries its authority bound.
    pub fn connect_with_ticket(
        &self,
        principal: &str,
        ticket_id: &str,
    ) -> Result<Option<ConnectionSummary>, StoreError> {
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let ticket: Option<(String, i64, String, String, String, String)> = conn
                .query_row(
                    "SELECT connection_id, expires_at, status, risk_ceiling, action_selectors,
                            ref_role
                     FROM binding_tickets
                     WHERE principal = ?1 AND ticket_id = ?2",
                    (principal, ticket_id),
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                connection_id,
                expires_at,
                status,
                ceiling_risk,
                ceiling_selectors,
                ref_role,
            )) = ticket
            else {
                return Ok(None);
            };
            if status != "issued" || expires_at <= now {
                conn.execute(
                    "UPDATE binding_tickets SET status = 'expired'
                     WHERE principal = ?1 AND ticket_id = ?2 AND status = 'issued'",
                    (principal, ticket_id),
                )?;
                return Ok(None);
            }
            // A credentialed enrollment must have written its binding before it
            // can activate; the NULL check is what makes a half-finished
            // ceremony fail closed. A credential-free enrollment has no binding
            // to check by construction, so requiring one would make no-auth
            // vendors permanently unconnectable.
            //
            // A revoked connection never becomes active again. A connection
            // that already records a ceiling keeps it: the ticket's ceiling is
            // copied only onto a connection that has none yet, so a later
            // ticket can re-enroll a connection but never widen what it allows.
            let binding_check = if ref_role == NO_CREDENTIAL_REF_ROLE {
                "credential_binding IS NULL"
            } else {
                "credential_binding IS NOT NULL"
            };
            let changed = conn.execute(
                &format!(
                    "UPDATE connections SET status = 'active', generation = generation + 1,
                            updated_at_ms = ?1,
                            ceiling_selectors = CASE WHEN ceiling_risk IS NULL
                                THEN ?5 ELSE ceiling_selectors END,
                            ceiling_risk = COALESCE(ceiling_risk, ?4)
                     WHERE principal = ?2 AND connection_id = ?3 AND status = 'pending'
                       AND {binding_check}"
                ),
                rusqlite::params![
                    now,
                    principal,
                    connection_id.as_str(),
                    ceiling_risk,
                    ceiling_selectors
                ],
            )?;
            if changed == 0 {
                conn.execute("UPDATE binding_tickets SET status='expired' WHERE principal=?1 AND ticket_id=?2 AND status='issued'", (principal, ticket_id))?;
                return Ok(None);
            }
            conn.execute(
                "UPDATE binding_tickets SET status = 'consumed'
                 WHERE principal = ?1 AND ticket_id = ?2 AND status = 'issued'",
                (principal, ticket_id),
            )?;
            conn.query_row(
                "SELECT connection_id, app_key, status, generation FROM connections
                 WHERE principal = ?1 AND connection_id = ?2",
                (principal, connection_id),
                |row| {
                    Ok(ConnectionSummary {
                        connection_id: row.get(0)?,
                        app_key: row.get(1)?,
                        status: row.get(2)?,
                        generation: row.get(3)?,
                    })
                },
            )
            .optional()
        })
    }

    pub fn connection_has_app_handle(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM github_app_handle
                 WHERE connection_principal = ?1 AND connection_id = ?2)",
                (principal, connection_id),
                |row| row.get(0),
            )
        })
    }

    pub fn connection_credential_binding_kind(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Option<&'static str>, StoreError> {
        self.connection_credential_binding(principal, connection_id)
            .map(|binding| binding.map(|binding| binding.kind()))
    }

    pub(crate) fn connection_credential_binding(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Option<crate::credentials::ConnectionCredentialBinding>, StoreError> {
        self.inner.with_read(|conn| {
            // The column is nullable: a connection created without a binding
            // (an imported GitHub handle connection, whose token comes from the
            // App vault) stores NULL. Read it as `Option` so NULL means "no
            // binding" instead of failing as a column type error, which
            // callers could only report as an unexplained store failure.
            let binding: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT credential_binding FROM connections
                     WHERE principal = ?1 AND connection_id = ?2",
                    (principal, connection_id),
                    |row| row.get::<_, Option<Vec<u8>>>(0),
                )
                .optional()?
                .flatten();
            binding
                .map(|value| {
                    decode_connection_binding(&value).map_err(|error| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            error,
                        )))
                    })
                })
                .transpose()
        })
    }

    /// Replace only the active generation that was inspected before the proving
    /// vault read. The binding, generation and audit commit or roll back together.
    pub fn rebind_credential_reference(
        &self,
        principal: &str,
        connection_id: &str,
        expected_generation: i64,
        credential_id: &str,
    ) -> Result<bool, StoreError> {
        let binding = encode_reference_binding(credential_id).map_err(StoreError::Backend)?;
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE connections SET credential_binding = ?1, generation = generation + 1,
                     updated_at_ms = ?2
                 WHERE principal = ?3 AND connection_id = ?4 AND status = 'active'
                     AND generation = ?5
                     AND NOT EXISTS (SELECT 1 FROM github_app_handle
                         WHERE connection_principal = ?3 AND connection_id = ?4)",
                rusqlite::params![
                    binding,
                    now_ms(),
                    principal,
                    connection_id,
                    expected_generation
                ],
            )?;
            if changed == 0 {
                return Ok(false);
            }
            let fingerprint = crate::fingerprint::fingerprint(credential_id.as_bytes());
            let mut record = AuditRecord::ceremony(
                principal,
                None,
                Some(connection_id),
                "rebind_credential",
                "read",
                Some(&fingerprint),
            );
            record.outcome = Some("applied".into());
            append_audit_on_conn(conn, &record, None, None, None, None)?;
            Ok(true)
        })
    }

    /// Append one audit row. There is intentionally no arbitrary update or
    /// delete API; the only removal path is bounded age-based retention.
    pub fn append_audit(&self, record: &AuditRecord) -> Result<(), StoreError> {
        self.append_audit_row(record, None, None, None, None)
    }

    /// Append one audit row for a call made on a route bound under a daemon
    /// scope. `None` writes the same row as [`Self::append_audit`].
    pub fn append_audit_scoped(
        &self,
        record: &AuditRecord,
        scope: Option<&CallScope>,
    ) -> Result<(), StoreError> {
        self.append_audit_row(record, None, None, scope, None)
    }

    /// [`Self::append_audit_scoped`] for a governed call that may have been
    /// relayed: `relay_origin` is the call from which the audited call was
    /// relayed, recorded for attribution, and `None` leaves the origin columns
    /// NULL.
    pub(crate) fn append_audit_relayed(
        &self,
        record: &AuditRecord,
        scope: Option<&CallScope>,
        relay_origin: Option<&RelayOrigin>,
    ) -> Result<(), StoreError> {
        self.append_audit_row(record, None, None, scope, relay_origin)
    }

    /// The one audit INSERT. `query_text` and `result_count` are `Some` only for
    /// rows the `web_search` tool writes; every other writer goes through
    /// [`Self::append_audit`], which leaves both NULL. `scope` is the daemon
    /// scope the call's route was bound under, and leaves the scope columns
    /// NULL when absent. `relay_origin` is the call from which the audited call
    /// was relayed, and leaves the origin columns NULL when absent.
    pub(crate) fn append_audit_row(
        &self,
        record: &AuditRecord,
        query_text: Option<&str>,
        result_count: Option<i64>,
        scope: Option<&CallScope>,
        relay_origin: Option<&RelayOrigin>,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            append_audit_on_conn(conn, record, query_text, result_count, scope, relay_origin)
        })
    }

    /// Remove one bounded batch of old reservations and expire abandoned fences.
    /// A reservation past its TTL can never dispatch; classifying it as expired
    /// lets normal retention reclaim it without touching any live fence.
    pub fn prune_reservations(&self, now_ms: i64) -> Result<usize, StoreError> {
        let cutoff = now_ms.saturating_sub(RESERVATION_RETENTION_MS);
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE reservations SET status='expired' WHERE (principal,reservation_id) IN (
                    SELECT principal,reservation_id FROM reservations
                    WHERE status='reserved' AND expires_at<=?1
                    ORDER BY created_at_ms,principal,reservation_id LIMIT ?2)",
                rusqlite::params![now_ms, RESERVATION_RETENTION_BATCH_ROWS as i64],
            )?;
            conn.execute(
                "DELETE FROM reservations
                 WHERE (principal, reservation_id) IN (
                     SELECT principal, reservation_id FROM reservations
                     WHERE status IN ('invalidated', 'dispatched', 'expired')
                       AND created_at_ms < ?1
                     ORDER BY created_at_ms, principal, reservation_id
                     LIMIT ?2
                 )",
                rusqlite::params![cutoff, RESERVATION_RETENTION_BATCH_ROWS as i64],
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn insert_reservation_at_for_test(
        &self,
        principal: &str,
        reservation_id: &str,
        status: &str,
        created_at_ms: i64,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO reservations
                    (reservation_id, principal, connection_id, action, snapshot_generations,
                     approved_args_hash, schema_hash, expires_at, status, created_at_ms, grant_id)
                 VALUES (?1, ?2, 'connection', 'action',
                         '{\"connection\":0,\"catalog_action\":0,\"grant\":0,\"policy\":0}',
                         'args', 'schema', ?3, ?4, ?5, 'grant')",
                rusqlite::params![
                    reservation_id,
                    principal,
                    created_at_ms.saturating_add(60_000),
                    status,
                    created_at_ms,
                ],
            )?;
            Ok(())
        })
    }

    /// Expire and prune ceremony history independently of audit deletion.
    /// The scheduler can report this pass separately when audit retention fails.
    pub fn prune_ceremony_history(
        &self,
        now: i64,
        retention_window_ms: i64,
    ) -> Result<(), StoreError> {
        self.inner
            .with_conn_fenced(|conn| prune_ceremony_history_on_conn(conn, now, retention_window_ms))
    }

    /// Remove one bounded batch of audit rows older than the configured window.
    ///
    /// The generation-26 delete trigger independently protects rows inside the
    /// seven-day floor. Startup requires the configured window to be wider than
    /// that floor, so a valid pass reaches only rows the trigger permits deleting.
    /// A batch bound keeps the scheduler's one-second tick from turning a large
    /// backlog into one long write transaction.
    pub fn prune_audit(&self, now_ms: i64, retention_window_ms: i64) -> Result<usize, StoreError> {
        let cutoff = now_ms.saturating_sub(retention_window_ms);
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "DELETE FROM audit_journal
                 WHERE journal_id IN (
                     SELECT journal_id FROM audit_journal
                     WHERE ts < ?1
                     ORDER BY ts, journal_id
                     LIMIT ?2
                 )",
                rusqlite::params![cutoff, AUDIT_RETENTION_BATCH_ROWS as i64],
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn append_audit_at_for_test(
        &self,
        principal: &str,
        ts: i64,
        reason_code: &str,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO audit_journal
                    (ts, principal, actor, acting_principal, decision, reason_code)
                 VALUES (?1, ?2, 'plexus-test', ?2, 'allow', ?3)",
                rusqlite::params![ts, principal, reason_code],
            )?;
            Ok(())
        })
    }

    /// The principals that own state the scheduler can poll or health-probe.
    ///
    /// Subscriptions and connections are the authoritative ownership records.
    /// Audit history can outlive both until its retention window lapses, so
    /// consulting it would retain principals for which the scheduler has no work
    /// while making every one-second pass scan unrelated journal history.
    pub fn poll_and_probe_principals(&self) -> Result<Vec<String>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT principal FROM trigger_subscriptions
                 UNION
                 SELECT principal FROM connections
                 ORDER BY principal",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect()
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn list_audit(&self, principal: &str) -> Result<Vec<AuditRow>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT journal_id, ts, principal, actor, acting_principal, agent_id,
                        agent_handle, connection_id, app_key, action, risk, severity, decision,
                        reason_code, gate, args_redaction_summary, outcome, latency_ms, request_id,
                        credential_fingerprint, provider_account_fingerprint, attempt_no,
                        vendor_request_id, idempotency_key_fingerprint, response_class,
                        reconciliation_of, app_handle_id, scope_owner, scope_ref, scope_epoch,
                        scope_kind, scope_parent, scope_parent_state, scope_delegates,
                         scope_owner_authorized, scope_flow_id
                 FROM audit_journal WHERE principal = ?1 ORDER BY journal_id",
            )?;
            let rows = statement.query_map([principal], |row| {
                let scope_owner: Option<String> = row.get(27)?;
                let scope_ref: Option<String> = row.get(28)?;
                let scope_epoch: Option<i64> = row.get(29)?;
                let scope = match (scope_owner, scope_ref, scope_epoch) {
                    (Some(owner), Some(scope_ref), Some(epoch)) => Some(CallScope {
                        owner,
                        scope_ref,
                        scope_epoch: epoch_from_sql(epoch),
                        kind: row.get(30)?,
                        parent: row.get(31)?,
                        parent_state: row.get(32)?,
                        agent_id: row.get(5)?,
                        delegates: row.get::<_, Option<bool>>(33)?.unwrap_or(false),
                        owner_authorized: row.get::<_, Option<bool>>(34)?.unwrap_or(false),
                        flow_id: row.get(35)?,
                    }),
                    _ => None,
                };
                Ok(AuditRow {
                    journal_id: row.get(0)?,
                    app_handle_id: row.get(26)?,
                    ts: row.get(1)?,
                    principal: row.get(2)?,
                    actor: row.get(3)?,
                    acting_principal: row.get(4)?,
                    agent_id: row.get(5)?,
                    agent_handle: row.get(6)?,
                    connection_id: row.get(7)?,
                    app_key: row.get(8)?,
                    action: row.get(9)?,
                    risk: row.get(10)?,
                    severity: row.get(11)?,
                    decision: row.get(12)?,
                    reason_code: row.get(13)?,
                    gate: row.get(14)?,
                    args_redaction_summary: row.get(15)?,
                    outcome: row.get(16)?,
                    latency_ms: row.get(17)?,
                    request_id: row.get(18)?,
                    credential_fingerprint: row.get(19)?,
                    provider_account_fingerprint: row.get(20)?,
                    attempt_no: row.get(21)?,
                    vendor_request_id: row.get(22)?,
                    idempotency_key_fingerprint: row.get(23)?,
                    response_class: row.get(24)?,
                    reconciliation_of: row.get(25)?,
                    scope,
                })
            })?;
            rows.collect()
        })
    }

    /// List the app manifests available to connect. This is the only
    /// pre-connection discovery surface: every other catalog projection is
    /// scoped to an existing connection, so without this an operator on a
    /// fresh install cannot see which vendors the module even carries.
    /// Returns catalog metadata only — no transport URLs, credential
    /// bindings, or connection state.
    ///
    /// Manifests are ingested module-wide under [`CATALOG_PRINCIPAL`], not per
    /// caller, so the listing is shared; `principal` scopes only the
    /// per-vendor connection count, which is caller-private.
    pub fn list_manifest_summaries(
        &self,
        principal: &str,
    ) -> Result<Vec<ManifestSummary>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT m.key, m.schema_version, m.manifest_json, m.ingested_at_ms,
                        (SELECT COUNT(*) FROM connections c
                          WHERE c.principal = ?2 AND c.app_key = m.key
                            AND c.status <> 'revoked')
                 FROM app_manifests m
                 WHERE m.principal = ?1 AND m.status = 'active' ORDER BY m.key",
            )?;
            let rows = statement.query_map([CATALOG_PRINCIPAL, principal], |row| {
                let key: String = row.get(0)?;
                let schema_version: u32 = row.get(1)?;
                let document: String = row.get(2)?;
                let ingested_at_ms: i64 = row.get(3)?;
                let connection_count: i64 = row.get(4)?;
                let manifest: crate::manifest::AppManifest = parse_json_column(&document)?;
                Ok(ManifestSummary {
                    key,
                    name: manifest.name,
                    description: manifest.description,
                    tier: format!("{:?}", manifest.tier),
                    reuse_path: format!("{:?}", manifest.reuse_path),
                    auth_mode: format!("{:?}", manifest.auth.mode),
                    availability: format!("{:?}", manifest.availability),
                    action_count: manifest.actions_baseline.len(),
                    required_filters: manifest.resource_filters.required.clone(),
                    schema_version,
                    ingested_at_ms,
                    connection_count,
                })
            })?;
            rows.collect()
        })
    }

    /// Return the reviewed catalog manifest, checking its stored content hash even
    /// on a cache hit. The hash, rather than a per-action generation, also detects
    /// manifest replacement by another writer or by a rollback.
    pub fn cached_manifest(
        &self,
        app_key: &str,
    ) -> Result<std::sync::Arc<AppManifest>, StoreError> {
        self.parsed_manifest(CATALOG_PRINCIPAL, app_key)?
            .ok_or_else(|| StoreError::Backend(format!("manifest missing: {app_key}")))?
            .map_err(StoreError::Backend)
    }

    /// Preserve missing documents and parse errors separately from storage
    /// failures so tolerant projections can fail closed without hiding I/O errors.
    pub(crate) fn parsed_manifest(
        &self,
        principal: &str,
        key: &str,
    ) -> Result<Option<Result<std::sync::Arc<AppManifest>, String>>, StoreError> {
        let hash: Option<String> = self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT content_hash FROM app_manifests WHERE principal=?1 AND key=?2",
                (principal, key),
                |row| row.get(0),
            )
            .optional()
        })?;
        let Some(hash) = hash else {
            return Ok(None);
        };
        let mut cache = self
            .manifest_cache
            .lock()
            .map_err(|_| StoreError::Backend("manifest cache poisoned".into()))?;
        let cache_key = (principal.to_owned(), key.to_owned());
        if let Some((cached_hash, manifest)) = cache.get(&cache_key) {
            if cached_hash == &hash {
                return Ok(Some(Ok(manifest.clone())));
            }
        }
        // Re-read hash and document together on a miss; the row may have changed
        // since the cheap hash lookup, and that newer document needs its own key.
        let row: Option<(String, String)> = self.inner.with_read(|conn| {
            conn.query_row("SELECT content_hash,manifest_json FROM app_manifests WHERE principal=?1 AND key=?2",
                (principal, key), |row| Ok((row.get(0)?,row.get(1)?))).optional()
        })?;
        let Some((hash, json)) = row else {
            return Ok(None);
        };
        let manifest = match serde_json::from_str::<AppManifest>(&json) {
            Ok(manifest) => std::sync::Arc::new(manifest),
            Err(error) => return Ok(Some(Err(error.to_string()))),
        };
        cache.insert(cache_key, (hash, manifest.clone()));
        Ok(Some(Ok(manifest)))
    }

    pub fn manifest_json(&self, principal: &str, key: &str) -> Result<Option<Value>, StoreError> {
        self.inner.with_read(|conn| {
            let json: Option<String> = conn
                .query_row(
                    "SELECT manifest_json FROM app_manifests WHERE principal = ?1 AND key = ?2",
                    (principal, key),
                    |row| row.get(0),
                )
                .optional()?;
            json.map(|value| parse_json_column(&value)).transpose()
        })
    }

    pub fn upsert_manifest(
        &self,
        principal: &str,
        ingested: &crate::manifest::IngestedManifest,
    ) -> Result<ManifestWriteOutcome, StoreError> {
        let json = serde_json::to_string(&ingested.json)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let key = &ingested.manifest.key;
        let schema_version = ingested.manifest.schema_version;
        let hash = &ingested.content_hash;
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let previous_row: Option<(String,String)> = conn.query_row(
                "SELECT content_hash,manifest_json FROM app_manifests WHERE principal=?1 AND key=?2",
                (principal,key), |row| Ok((row.get(0)?,row.get(1)?)),
            ).optional()?;
            let previous = previous_row.as_ref().map(|row| row.0.clone());
            let recipient_declarations = |value: &Value| -> Value {
                serde_json::json!(value["actions_baseline"].as_array().into_iter().flatten()
                    .filter(|action| action.get("recipients").is_some())
                    .map(|action| serde_json::json!([action["name"],action["recipients"],action["input_schema"],action.pointer("/http/args_schema")]))
                    .collect::<Vec<_>>())
            };
            let old = if principal == CATALOG_PRINCIPAL {
                previous_row.as_ref().map(|row| serde_json::from_str::<Value>(&row.1)).transpose()
            } else { Ok(None) };
            let corrupt_old = old.is_err();
            let old = old.ok().flatten().unwrap_or(Value::Null);
            if principal == CATALOG_PRINCIPAL
                && (corrupt_old || recipient_declarations(&old) != recipient_declarations(&ingested.json))
            {
                // If the reviewed manifest changes an action's recipient
                // declaration, invalidate outstanding reservations so they
                // cannot send under the old declaration. The catalog manifest
                // is shared by every owner's connections to the app, so every
                // such connection is affected; a reservation is matched by its
                // owner as well as its connection id, so another app's
                // connection that shares an id is not.
                conn.execute("UPDATE connections SET generation=generation+1 WHERE app_key=?1", [key])?;
                conn.execute("UPDATE reservations SET status='invalidated' WHERE status='reserved' AND (principal, connection_id) IN (SELECT principal, connection_id FROM connections WHERE app_key=?1)", [key])?;
            }
            if principal == CATALOG_PRINCIPAL {
                // An action that declares recipients always asks first (the
                // seed sets it), and that must hold for connections that
                // existed before the declaration too, or old and new
                // connections to one app would disagree.
                let recipient_actions: Vec<String> = ingested
                    .json["actions_baseline"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|action| action.get("recipients").is_some())
                    .filter_map(|action| action["name"].as_str().map(str::to_string))
                    .collect();
                for action in &recipient_actions {
                    conn.execute(
                        "UPDATE catalog_actions SET ask_first = 1, generation = generation + 1
                         WHERE name = ?2 AND ask_first = 0 AND (principal, connection_id) IN
                            (SELECT principal, connection_id FROM connections WHERE app_key = ?1)",
                        (key, action),
                    )?;
                }
                // A manifest coming back un-retires its app (below), so the
                // watches its retirement suspended resume with their cursors.
                // Only that reason: a watch suspended for anything else stays
                // suspended for its own review.
                conn.execute(
                    "UPDATE trigger_subscriptions
                     SET status = 'active', suspended_reason = NULL, generation = generation + 1
                     WHERE status = 'suspended' AND suspended_reason = 'app_retired'
                        AND ((cursor_kind <> 'probe'
                        AND EXISTS (
                            SELECT 1 FROM catalog_actions ca
                            WHERE ca.principal=trigger_subscriptions.principal AND ca.connection_id=trigger_subscriptions.connection_id
                            AND ca.name=trigger_subscriptions.action AND ca.status='active' AND ca.risk='read'
                            AND ca.schema_hash=trigger_subscriptions.schema_hash)
                        AND EXISTS (SELECT 1 FROM grants g JOIN json_each(g.action_selectors) selector
                            WHERE g.principal=trigger_subscriptions.principal AND g.connection_id=trigger_subscriptions.connection_id
                            AND g.grantee_principal=trigger_subscriptions.principal AND g.authority_kind='poll'
                            AND (g.expires_at IS NULL OR g.expires_at>?2)
                            AND (selector.value=trigger_subscriptions.action OR selector.value='*')))
                        OR (cursor_kind='probe' AND EXISTS (
                            SELECT 1 FROM probe_subscriptions p WHERE p.subscription_id=trigger_subscriptions.subscription_id
                            AND NOT EXISTS (SELECT 1 FROM json_each(p.actions) a
                                WHERE NOT EXISTS (SELECT 1 FROM catalog_actions ca WHERE ca.principal=trigger_subscriptions.principal
                                    AND ca.connection_id=trigger_subscriptions.connection_id AND ca.name=a.value
                                    AND ca.status='active' AND ca.risk='read')
                                OR NOT EXISTS (SELECT 1 FROM grants g JOIN json_each(g.action_selectors) selector
                                    WHERE g.principal=trigger_subscriptions.principal AND g.connection_id=trigger_subscriptions.connection_id
                                    AND g.grantee_principal=p.registered_by AND g.authority_kind='poll'
                                    AND (g.expires_at IS NULL OR g.expires_at>?2) AND (selector.value=a.value OR selector.value='*'))))))
                        AND (principal, connection_id) IN
                         (SELECT principal, connection_id FROM connections
                           WHERE app_key = ?1 AND status <> 'revoked')",
                    rusqlite::params![key,now],
                )?;
            }
            conn.execute(
                "INSERT INTO app_manifests
                    (principal, key, schema_version, content_hash, manifest_json, ingested_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(principal, key) DO UPDATE SET
                    schema_version = excluded.schema_version,
                    content_hash = excluded.content_hash,
                    manifest_json = excluded.manifest_json,
                    ingested_at_ms = excluded.ingested_at_ms,
                    -- Re-ingesting a manifest un-retires it. A file returning to
                    -- the catalog directory is a reviewer's decision to offer it
                    -- again, and without this a vendor could never come back.
                    status = 'active'",
                rusqlite::params![principal, key, schema_version, hash, json, now],
            )?;
            // A REST connection's catalog IS its reviewed manifest, but nothing
            // else re-reads the manifest for a connection that already exists:
            // catalog refresh needs a stored credential binding, which GitHub
            // handle connections do not have (their token comes from the App
            // vault). So an action added to the manifest after a connection was
            // created would never reach that connection's catalog. Add the
            // missing rows here, in the same transaction as the manifest write.
            // Existing rows are left exactly as they are: their status
            // (quarantine, disablement) and schema pins are review decisions.
            if principal == CATALOG_PRINCIPAL
                && ingested.manifest.transport.kind == crate::manifest::TransportKind::RestApi
            {
                let mut statement = conn.prepare(
                    "SELECT principal, connection_id FROM connections
                     WHERE app_key = ?1 AND status != 'revoked'
                     ORDER BY principal, connection_id",
                )?;
                let connections: Vec<(String, String)> = statement
                    .query_map([key], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?;
                drop(statement);
                for (owner, connection_id) in connections {
                    seed_catalog_from_manifest_on_conn(
                        conn,
                        &owner,
                        &connection_id,
                        key,
                        SeedMode::AddMissing,
                    )?;
                }
            }
            Ok(ManifestWriteOutcome {
                changed: previous.is_some_and(|old_hash| old_hash != *hash),
            })
        })
    }

    /// Whether a stored manifest has been withdrawn from the reviewed catalog.
    ///
    /// A missing row reports `false` rather than an error: absence is
    /// `UnknownApp`'s business, and callers check that first.
    pub fn manifest_is_retired(&self, app_key: &str) -> Result<bool, StoreError> {
        self.inner.with_read(|conn| {
            let status: Option<String> = conn
                .query_row(
                    "SELECT status FROM app_manifests WHERE principal = ?1 AND key = ?2",
                    (CATALOG_PRINCIPAL, app_key),
                    |row| row.get(0),
                )
                .optional()?;
            Ok(status.is_some_and(|value| value == "retired"))
        })
    }

    /// Retire every stored manifest whose key is absent from the reviewed set,
    /// and return the keys retired.
    ///
    /// Called once per boot with the keys the catalog directory yielded, because
    /// ingestion alone cannot express a withdrawal: it upserts the files it
    /// finds and never consults the store, so a deleted manifest would otherwise
    /// remain connectable forever. Retiring for safety is the response to
    /// discovering a vendor surface cannot be governed, so a retirement that
    /// does not take effect defeats the remedy rather than merely leaving a
    /// stale row.
    ///
    /// REFUSES TO ACT ON AN EMPTY SET, and this is the load-bearing part. An
    /// empty `reviewed` means the catalog directory yielded nothing, which is a
    /// mis-set `PLEXUS_CATALOG_DIR` or a half-finished sync far more often than
    /// a deliberate withdrawal of every vendor. Since this runs at boot, before
    /// anything is served, acting on it would retire the entire catalog from one
    /// bad path. Same reasoning as the empty-discovery guard in
    /// `reconcile_actions`: refusing to destroy known state on an unbelievable
    /// observation.
    ///
    /// Marks rather than deletes: the row is the only record of what an existing
    /// connection was minted against, so removing it would orphan live
    /// connections and their audit history.
    pub fn retire_absent_manifests(
        &self,
        principal: &str,
        reviewed: &[String],
    ) -> Result<Vec<String>, StoreError> {
        if reviewed.is_empty() {
            return Ok(Vec::new());
        }
        self.inner.with_conn_fenced(|conn| {
            let mut statement = conn.prepare(
                "SELECT key FROM app_manifests
                 WHERE principal = ?1 AND status = 'active' ORDER BY key",
            )?;
            let stored: Vec<String> = statement
                .query_map([principal], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            drop(statement);

            let mut retired = Vec::new();
            for key in stored {
                if reviewed.iter().any(|name| name == &key) {
                    continue;
                }
                conn.execute(
                    "UPDATE app_manifests SET status = 'retired'
                     WHERE principal = ?1 AND key = ?2",
                    (principal, &key),
                )?;
                if principal == CATALOG_PRINCIPAL {
                    // Retirement must stop live traffic, not only new tickets:
                    // in-flight reservations are invalidated, every connection
                    // of the app moves to a new generation, and active watches
                    // are suspended as `app_retired` (catalog reads already
                    // report the actions disabled). A returning manifest
                    // resumes exactly those watches; see `upsert_manifest`.
                    conn.execute(
                        "UPDATE reservations SET status = 'invalidated'
                         WHERE status = 'reserved' AND (principal, connection_id) IN
                            (SELECT principal, connection_id FROM connections WHERE app_key = ?1)",
                        [&key],
                    )?;
                    conn.execute(
                        "UPDATE connections SET generation = generation + 1 WHERE app_key = ?1",
                        [&key],
                    )?;
                    let mut gap_query=conn.prepare("SELECT s.principal,s.connection_id,s.subscription_id,COALESCE(s.last_success_at_ms,s.created_at_ms) FROM trigger_subscriptions s JOIN connections c ON c.principal=s.principal AND c.connection_id=s.connection_id WHERE c.app_key=?1 AND s.status='active'")?;
                    let gaps:Vec<(String,String,String,i64)>=gap_query.query_map([&key],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?.collect::<rusqlite::Result<_>>()?;
                    let retired_at=now_ms();
                    for (owner,connection,subscription,from) in gaps {
                        insert_gap_row(conn,&owner,&connection,&subscription,from,retired_at,"app_retired",retired_at)?;
                    }
                    conn.execute(
                        "UPDATE trigger_subscriptions
                         SET status = 'suspended', suspended_reason = 'app_retired',
                             generation = generation + 1
                         WHERE status = 'active' AND (principal, connection_id) IN
                            (SELECT principal, connection_id FROM connections WHERE app_key = ?1)",
                        [&key],
                    )?;
                }
                retired.push(key);
            }
            Ok(retired)
        })
    }

    /// Replace the open placeholder schema on GitHub handle catalog rows with
    /// the reviewed `http.args_schema` from the stored manifest, and report
    /// what moved and what could not.
    ///
    /// Handle rows seeded before the seeder read `http.args_schema` still hold
    /// the placeholder, and nothing else ever rewrites them: the startup seed
    /// in `upsert_manifest` only adds missing rows, the handle health probe
    /// skips discovery, and catalog refresh needs a stored credential binding
    /// that handle connections do not have. Governance treats a schema without
    /// `properties` as open, so until a row moves, the undeclared-argument
    /// check refuses nothing on that bot action. Run at every boot, after the
    /// catalog ingest.
    ///
    /// Only a row whose stored schema is EXACTLY the placeholder moves, and
    /// only while it is active. Any other schema is a pin a reviewer made (or
    /// a changed schema awaiting review), and quarantined or disabled rows carry
    /// a review decision, so those are never touched. Once a row moves it no
    /// longer matches, so a second pass changes nothing.
    ///
    /// The move does not quarantine, for the same reason catalog refresh
    /// exempts the placeholder from its schema-change quarantine: the
    /// placeholder was never a reviewed schema, so replacing it discards no
    /// review. The replacement is also not a vendor observation but Plexus's
    /// own reviewed manifest, which is the reviewed source a schema is judged
    /// against in the first place.
    ///
    /// Revoked connections are skipped, as in the startup seed. A revoked
    /// connection refuses every call before its catalog is consulted, and it
    /// never becomes active again: recovery is a fresh connection, whose first
    /// seed pins the reviewed schemas anyway.
    ///
    /// Records what catalog refresh records for a schema change on an active
    /// row: the schema, its hash, the observation time, and a generation bump.
    pub fn pin_handle_placeholder_schemas(&self) -> Result<HandleSchemaPinReport, StoreError> {
        let placeholder = placeholder_catalog_schema();
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let mut statement = conn.prepare(
                "SELECT ca.principal, ca.connection_id, ca.name, ca.schema_json, c.app_key
                 FROM catalog_actions ca
                 JOIN connections c
                   ON c.principal = ca.principal AND c.connection_id = ca.connection_id
                 JOIN github_app_handle h
                   ON h.connection_principal = c.principal AND h.connection_id = c.connection_id
                 WHERE c.status != 'revoked' AND ca.status = 'active'
                 ORDER BY ca.principal, ca.connection_id, ca.name",
            )?;
            type Row = (String, String, String, String, String);
            let rows: Vec<Row> = statement
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<_>>()?;
            drop(statement);

            // One manifest read per app key, not per row.
            let mut manifests: std::collections::HashMap<String, Option<Value>> =
                std::collections::HashMap::new();
            let mut report = HandleSchemaPinReport::default();
            let mut corrupt_logged=BTreeSet::new();
            for (principal, connection_id, action, stored, app_key) in rows {
                let schema=match serde_json::from_str::<Value>(&stored) {
                    Ok(schema)=>schema,
                    Err(error)=> {
                        report.gaps.push(HandleSchemaGap{principal:principal.clone(),connection_id:connection_id.clone(),action:action.clone(),reason:"stored schema does not parse"});
                        if corrupt_logged.insert((app_key.clone(),action.clone())) {
                            crate::diag!(warn storage: "catalog schema does not parse: app={app_key:?} action={action:?}: class={:?} line={} column={}",error.classify(),error.line(),error.column());
                        }
                        continue;
                    }
                };
                // Parse JSON because stored object key order is not significant.
                if schema != placeholder {
                    continue;
                }
                if !manifests.contains_key(&app_key) {
                    let source: Option<String> = conn
                        .query_row(
                            "SELECT manifest_json FROM app_manifests
                             WHERE principal = ?1 AND key = ?2 AND status = 'active'",
                            (CATALOG_PRINCIPAL, &app_key),
                            |row| row.get(0),
                        )
                        .optional()?;
                    let manifest = source
                        .map(|source| parse_json_column::<Value>(&source))
                        .transpose()?;
                    manifests.insert(app_key.clone(), manifest);
                }
                let gap = |reason| HandleSchemaGap {
                    principal: principal.clone(),
                    connection_id: connection_id.clone(),
                    action: action.clone(),
                    reason,
                };
                let Some(manifest) = manifests.get(&app_key).and_then(Option::as_ref) else {
                    report.gaps.push(gap("no active reviewed manifest"));
                    continue;
                };
                let declared = manifest
                    .get("actions_baseline")
                    .and_then(Value::as_array)
                    .and_then(|actions| {
                        actions.iter().find(|declared| {
                            declared.get("name").and_then(Value::as_str) == Some(action.as_str())
                        })
                    });
                let Some(declared) = declared else {
                    report.gaps.push(gap("action not in the reviewed manifest"));
                    continue;
                };
                let Some(schema) = declared.pointer("/http/args_schema") else {
                    report
                        .gaps
                        .push(gap("reviewed manifest declares no http.args_schema"));
                    continue;
                };
                // A manifest whose reviewed schema is itself the placeholder
                // has nothing to pin, and writing it would bump the generation
                // on every boot.
                if *schema == placeholder {
                    report
                        .gaps
                        .push(gap("reviewed http.args_schema is the open placeholder"));
                    continue;
                }
                let Ok(schema_hash) = crate::jcs::jcs_sha256(schema) else {
                    report
                        .gaps
                        .push(gap("reviewed http.args_schema cannot be hashed"));
                    continue;
                };
                let schema_json = serde_json::to_string(schema)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
                // The row's current text and status are repeated in the
                // WHERE clause so the write cannot land on anything other
                // than the placeholder row just read.
                let changed = conn.execute(
                    "UPDATE catalog_actions
                     SET schema_json = ?1, schema_hash = ?2, last_seen_at_ms = ?3,
                         generation = generation + 1
                     WHERE principal = ?4 AND connection_id = ?5 AND name = ?6
                       AND status = 'active' AND schema_json = ?7",
                    rusqlite::params![
                        schema_json,
                        schema_hash,
                        now,
                        principal,
                        connection_id,
                        action,
                        stored
                    ],
                )?;
                if changed != 0 {
                    // A subscription stores the schema hash of the action it
                    // polls. Before review, the action can have a placeholder
                    // schema that imposes no argument constraints. Replacing it
                    // changes the hash. Suspend affected subscriptions so they
                    // require review against the actual schema before polling
                    // again, just as any catalog schema change requires.
                    suspend_subscriptions_for_action(
                        conn,
                        &principal,
                        &connection_id,
                        &action,
                        None,
                        now,
                    )?;
                    report.pinned.push(PinnedHandleSchema {
                        principal,
                        connection_id,
                        action,
                        schema_hash,
                    });
                }
            }
            Ok(report)
        })
    }
}

/// Apply one catalog observation inside the caller's transaction, preserving
/// review decisions and cascading reservation and subscription invalidation.
fn refresh_catalog_action_on_conn(
    conn: &rusqlite::Connection,
    mut input: CatalogActionInput,
    observed_at_ms: i64,
) -> rusqlite::Result<()> {
    let schema = serde_json::to_string(&input.schema)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
    let reconciliation = input
        .reconciliation
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
    type PreviousCatalogObservation = (String, String, String, Option<String>, Option<String>);
    let previous: Option<PreviousCatalogObservation> = conn
        .query_row(
            "SELECT schema_hash, schema_json, status, quarantine_reason, reviewed_schema_json
                     FROM catalog_actions
                     WHERE principal = ?1 AND connection_id = ?2 AND name = ?3",
            (&input.principal, &input.connection_id, &input.name),
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let mut reviewed_schema = None;
    if let Some((
        previous_schema_hash,
        previous_schema,
        previous_status,
        previous_reason,
        previous_reviewed_schema,
    )) = previous
    {
        // Active rows carry the approved schema, including immediately after
        // repin. Disabled rows retain that authority in their snapshot instead:
        // the last observed schema may still be awaiting review.
        let approved_schema = if previous_status == "disabled" {
            previous_reviewed_schema
                .as_deref()
                .unwrap_or(&previous_schema)
        } else {
            &previous_schema
        };
        let approved_hash = if previous_status == "disabled" && previous_reviewed_schema.is_some() {
            jcs_sqlite_hash(&parse_json_column::<Value>(approved_schema)?)?
        } else {
            previous_schema_hash.clone()
        };
        let is_placeholder =
            parse_json_column(approved_schema).ok() == Some(placeholder_catalog_schema());
        if previous_status == "quarantined" {
            input.status = "quarantined".to_string();
            input.quarantine_reason = previous_reason;
        } else if approved_hash != input.schema_hash && !is_placeholder && input.status == "active"
        {
            input.status = "quarantined".to_string();
            input.quarantine_reason = Some("schema_changed_requires_review".to_string());
        }
        if previous_status != "quarantined" && input.status == "quarantined" {
            reviewed_schema = Some(approved_schema.to_string());
        }
    } else if matches!(input.risk.as_str(), "write" | "destructive") && input.status == "active" {
        input.status = "quarantined".to_string();
        input.quarantine_reason = Some("new_write_requires_review".to_string());
    }
    upsert_catalog_action_row(
        conn,
        &input,
        &schema,
        reconciliation.as_deref(),
        reviewed_schema.as_deref(),
        observed_at_ms,
    )?;
    if input.status == "quarantined" {
        conn.execute(
            "UPDATE reservations SET status = 'invalidated'
                     WHERE principal = ?1 AND connection_id = ?2 AND action = ?3
                       AND status = 'reserved'",
            (&input.principal, &input.connection_id, &input.name),
        )?;
    }
    suspend_subscriptions_for_action(
        conn,
        &input.principal,
        &input.connection_id,
        &input.name,
        catalog_suspension_reason(&input),
        observed_at_ms,
    )?;
    Ok(())
}

fn disable_catalog_action_on_conn(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    action: &str,
    observed_at_ms: i64,
) -> rusqlite::Result<bool> {
    // A disabled row's snapshot must identify the approved schema. For an
    // active row that is the current schema (repin need not clear an older
    // snapshot); for a quarantined row the current schema is not approved.
    let changed = conn.execute(
        "UPDATE catalog_actions SET status = 'disabled',
                        reviewed_schema_json = CASE WHEN status = 'active' THEN schema_json
                            ELSE reviewed_schema_json END,
                        quarantine_reason = NULL, generation = generation + 1,
                        last_seen_at_ms = ?1
                 WHERE principal = ?2 AND connection_id = ?3 AND name = ?4
                   AND status != 'disabled'",
        rusqlite::params![observed_at_ms, principal, connection_id, action],
    )?;
    if changed != 0 {
        conn.execute(
            "UPDATE reservations SET status = 'invalidated'
                     WHERE principal = ?1 AND connection_id = ?2 AND action = ?3
                       AND status = 'reserved'",
            (principal, connection_id, action),
        )?;
    }
    suspend_subscriptions_for_action(
        conn,
        principal,
        connection_id,
        action,
        Some("disabled"),
        observed_at_ms,
    )?;
    Ok(changed != 0)
}

fn append_audit_on_conn(
    conn: &Connection,
    record: &AuditRecord,
    query_text: Option<&str>,
    result_count: Option<i64>,
    scope: Option<&CallScope>,
    relay_origin: Option<&RelayOrigin>,
) -> rusqlite::Result<()> {
    let now = now_ms();
    let scope_epoch = scope.map(|scope| epoch_to_sql(scope.scope_epoch));
    conn.execute(
        "INSERT INTO audit_journal (
            ts, principal, actor, acting_principal, agent_id, agent_handle,
            connection_id, app_key, action, risk, severity, decision, reason_code, gate,
            args_redaction_summary, outcome, latency_ms, request_id,
            credential_fingerprint, provider_account_fingerprint, attempt_no,
            vendor_request_id, idempotency_key_fingerprint, response_class,
            reconciliation_of, app_handle_id, query_text, result_count,
            scope_owner, scope_ref, scope_epoch, scope_kind, scope_parent,
            scope_parent_state, scope_delegates, scope_owner_authorized,
            origin_carrier, origin_call_key, scope_flow_id
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
            ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
            ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34,
            ?35, ?36, ?37, ?38, ?39
        )",
        rusqlite::params![
            now,
            record.principal,
            record.actor,
            record.acting_principal,
            record.agent_id,
            record.agent_handle,
            record.connection_id,
            record.app_key,
            record.action,
            record.risk,
            record.severity,
            record.decision,
            record.reason_code,
            record.gate,
            record.args_redaction_summary,
            record.outcome,
            record.latency_ms,
            record.request_id,
            record.credential_fingerprint,
            record.provider_account_fingerprint,
            record.attempt_no,
            record.vendor_request_id,
            record.idempotency_key_fingerprint,
            record.response_class,
            record.reconciliation_of,
            record.app_handle_id,
            query_text,
            result_count,
            scope.map(|scope| scope.owner.as_str()),
            scope.map(|scope| scope.scope_ref.as_str()),
            scope_epoch,
            scope.and_then(|scope| scope.kind.as_deref()),
            scope.and_then(|scope| scope.parent.as_deref()),
            scope.and_then(|scope| scope.parent_state.as_deref()),
            scope.map(|scope| scope.delegates),
            scope.map(|scope| scope.owner_authorized),
            relay_origin.map(|origin| origin.carrier.as_str()),
            relay_origin.map(|origin| origin.call_key.as_str()),
            scope.and_then(|scope| scope.flow_id.as_deref()),
        ],
    )?;
    // A settled send of a claimed approval also settles the approval
    // request: its outcome is copied there, in this transaction, so a
    // later withdrawal reads it even after retention deletes this row.
    // Only the first settled row counts, as the withdrawal fallback
    // (the earliest dispatch row with an outcome) also reads it.
    if let (Some("dispatch"), Some(outcome), Some(request_id)) = (
        record.gate.as_deref(),
        record.outcome.as_deref(),
        record.request_id.as_deref(),
    ) {
        conn.execute(
            "UPDATE action_requests SET settled_outcome = ?3
             WHERE principal = ?1 AND claimed_request_id = ?2
               AND status = 'consumed' AND settled_outcome IS NULL",
            rusqlite::params![record.principal, request_id, outcome],
        )?;
    }
    Ok(())
}

fn prune_ceremony_history_on_conn(
    conn: &rusqlite::Connection,
    now: i64,
    retention: i64,
) -> rusqlite::Result<()> {
    let cutoff = now.saturating_sub(retention);
    conn.execute("UPDATE action_requests SET status='expired' WHERE (principal,request_id) IN (SELECT principal,request_id FROM action_requests WHERE status IN ('pending','approved') AND expires_at<=?1 ORDER BY expires_at LIMIT ?2)",(now, CEREMONY_RETENTION_BATCH_ROWS))?;
    conn.execute("UPDATE binding_tickets SET status='expired' WHERE (principal,ticket_id) IN (SELECT principal,ticket_id FROM binding_tickets WHERE status='issued' AND expires_at<=?1 ORDER BY expires_at LIMIT ?2)",(now, CEREMONY_RETENTION_BATCH_ROWS))?;
    conn.execute("DELETE FROM consent_call_keys WHERE (principal,request_id) IN (SELECT principal,request_id FROM action_requests WHERE status IN ('consumed','denied','expired','cancelled') AND settled_at_ms<?1 ORDER BY settled_at_ms LIMIT ?2)",(cutoff, CEREMONY_RETENTION_BATCH_ROWS))?;
    conn.execute("DELETE FROM action_requests WHERE (principal,request_id) IN (SELECT principal,request_id FROM action_requests WHERE status IN ('consumed','denied','expired','cancelled') AND settled_at_ms<?1 ORDER BY settled_at_ms LIMIT ?2)",(cutoff, CEREMONY_RETENTION_BATCH_ROWS))?;
    conn.execute("DELETE FROM binding_tickets WHERE (principal,ticket_id) IN (SELECT principal,ticket_id FROM binding_tickets WHERE status IN ('consumed','expired','revoked') AND settled_at_ms<?1 ORDER BY settled_at_ms LIMIT ?2)",(now.saturating_sub(AUDIT_MILLIS_PER_DAY), CEREMONY_RETENTION_BATCH_ROWS))?;
    Ok(())
}

fn map_grant_summary_row(row: &rusqlite::Row<'_>, now: i64) -> rusqlite::Result<GrantSummary> {
    let expires_at = row.get(7)?;
    Ok(GrantSummary {
        grant_id: row.get(0)?,
        connection_id: row.get(1)?,
        app_key: row.get(2)?,
        grantee_principal: row.get(3)?,
        risk_ceiling: row.get(4)?,
        action_selectors: parse_string_list(&row.get::<_, String>(5)?)?,
        authority_kind: row.get(6)?,
        expires_at,
        created_at_ms: row.get(8)?,
        revoked_at_ms: row.get(9)?,
        revoked_by: row.get(10)?,
        state: grant_state(expires_at, row.get(9)?, now).into(),
    })
}
fn map_policy_summary_row(row: &rusqlite::Row<'_>, now: i64) -> rusqlite::Result<PolicySummary> {
    let expires_at = row.get(5)?;
    Ok(PolicySummary {
        policy_id: row.get(0)?,
        connection_id: row.get(1)?,
        app_key: row.get(2)?,
        action_selector: row.get(3)?,
        effect: row.get(4)?,
        expires_at,
        state: grant_state(expires_at, None, now).into(),
    })
}

fn map_grant_row(row: &rusqlite::Row<'_>, now: i64) -> rusqlite::Result<GrantRecord> {
    Ok(GrantRecord {
        grant_id: row.get(0)?,
        principal: row.get(1)?,
        connection_id: row.get(2)?,
        grantee_principal: row.get(3)?,
        risk_ceiling: row.get(4)?,
        action_selectors: parse_string_list(&row.get::<_, String>(5)?)?,
        authority_kind: row.get(6)?,
        expires_at: row.get(7)?,
        generation: row.get(8)?,
        revoked_at_ms: None,
        revoked_by: None,
        state: grant_state(row.get(7)?, None, now).into(),
    })
}

type PollGrants = std::collections::BTreeMap<(String, String), Vec<GrantRecord>>;
fn poll_grants_on_conn(
    conn: &rusqlite::Connection,
    principal: &str,
    connection: Option<&str>,
    now: i64,
) -> rusqlite::Result<PollGrants> {
    let mut statement=conn.prepare("SELECT grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,expires_at,generation FROM grants WHERE principal=?1 AND (?2 IS NULL OR connection_id=?2) AND authority_kind='poll' AND grantee_principal<>'*' ORDER BY grant_id")?;
    let rows = statement.query_map(rusqlite::params![principal, connection], |row| {
        map_grant_row(row, now)
    })?;
    let mut grouped = PollGrants::new();
    for row in rows {
        let row = row?;
        grouped
            .entry((row.connection_id.clone(), row.grantee_principal.clone()))
            .or_default()
            .push(row);
    }
    Ok(grouped)
}
fn subscription_authority_from_grants(
    subscription: &TriggerSubscription,
    grants: &PollGrants,
    now: i64,
) -> (Option<i64>, &'static str) {
    let (grantee, actions) = if subscription.cursor_kind == "probe" {
        (
            subscription
                .registered_by
                .as_deref()
                .unwrap_or(&subscription.principal),
            subscription.actions.clone().unwrap_or_default(),
        )
    } else {
        (
            subscription.principal.as_str(),
            vec![subscription.action.clone()],
        )
    };
    if actions.is_empty() {
        return (None, "absent");
    }
    let rows = grants
        .get(&(subscription.connection_id.clone(), grantee.to_string()))
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut expires_at: Option<i64> = None;
    let mut saw_expired = false;
    let mut saw_other = false;
    for action in actions {
        match grant_candidate(rows, &action, now, None) {
            Some(grant) if grant.authorizes(&action, now) => {
                expires_at = match (expires_at, grant.expires_at) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (None, b) => b,
                    (a, None) => a,
                };
            }
            Some(grant) if grant.expires_at.is_some_and(|at| at <= now) => {
                saw_expired = true;
                expires_at = grant.expires_at;
            }
            Some(_) => saw_other = true,
            None => return (None, "absent"),
        }
    }
    if saw_expired {
        (expires_at, "expired")
    } else if saw_other {
        (None, "absent")
    } else {
        (expires_at, "live")
    }
}

fn grant_ceiling_on_conn(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
) -> rusqlite::Result<Result<Ceiling, CeremonyRefusal>> {
    let row: Option<(String, Option<String>, Option<String>)> = conn.query_row(
        "SELECT status, ceiling_risk, ceiling_selectors FROM connections WHERE principal=?1 AND connection_id=?2",
        (principal, connection_id),
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional()?;
    let Some((status, risk, selectors)) = row else {
        return Ok(Err(CeremonyRefusal::ConnectionNotFound));
    };
    if status == "revoked" {
        return Ok(Err(CeremonyRefusal::ConnectionRevoked));
    }
    let (Some(risk), Some(selectors)) = (risk, selectors) else {
        return Ok(Err(CeremonyRefusal::CeilingAbsent));
    };
    let Some(risk) = Risk::parse(&risk) else {
        return Ok(Err(CeremonyRefusal::InvalidRisk(risk)));
    };
    Ok(Ok(Ceiling {
        risk,
        action_selectors: parse_string_list(&selectors)?,
    }))
}

fn insert_grant_on_conn(conn: &rusqlite::Connection, input: &GrantInput) -> rusqlite::Result<()> {
    let selectors = serde_json::to_string(&input.action_selectors)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
    conn.execute(
        "INSERT INTO grants
        (grant_id, principal, connection_id, grantee_principal, risk_ceiling,
        action_selectors, authority_kind, expires_at, generation, created_at_ms)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1,?9)",
        rusqlite::params![
            input.grant_id,
            input.principal,
            input.connection_id,
            input.grantee_principal,
            input.risk_ceiling,
            selectors,
            input.authority_kind,
            input.expires_at,
            now_ms()
        ],
    )?;
    Ok(())
}

/// Insert a policy in the caller's transaction alongside related grant writes.
pub(crate) fn insert_policy_on_conn(
    conn: &rusqlite::Connection,
    input: &PolicyInput,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO policies
            (policy_id, principal, connection_id, action_selector, effect,
             expires_at, generation, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
        rusqlite::params![
            input.policy_id,
            input.principal,
            input.connection_id,
            input.action_selector,
            input.effect,
            input.expires_at,
            now_ms(),
        ],
    )?;
    Ok(())
}

/// Whether a manifest seed may overwrite catalog rows that already exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeedMode {
    /// Write every declared action, replacing an existing row (a new
    /// connection's first seed).
    UpsertAll,
    /// Insert missing actions and refresh reviewed policy metadata, preserving
    /// existing operator status and schema-pin decisions.
    AddMissing,
}

/// Seed reviewed manifest declarations in the caller's transaction. UpsertAll
/// is reserved for new connections; repeat seeds preserve pins and operator state
/// while updating the reviewed policy metadata of existing rows.
pub(crate) fn seed_catalog_from_manifest_on_conn(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    app_key: &str,
    mode: SeedMode,
) -> rusqlite::Result<usize> {
    let source: Option<String> = conn.query_row(
        "SELECT manifest_json FROM app_manifests WHERE principal=?1 AND key=?2 AND status='active'",
        (CATALOG_PRINCIPAL, app_key), |row| row.get(0),
    ).optional()?;
    let Some(source) = source else { return Ok(0) };
    let manifest: Value = parse_json_column(&source)?;
    let tier = manifest.get("tier").and_then(Value::as_str).unwrap_or("S4");
    let declared_ask_first: Vec<Risk> = manifest
        .get("defaults")
        .and_then(|defaults| defaults.get("ask_first_risk"))
        .and_then(Value::as_array)
        .map(|risks| {
            risks
                .iter()
                .filter_map(|risk| risk.as_str().and_then(Risk::parse))
                .collect()
        })
        .unwrap_or_default();
    let actions = manifest.get("actions_baseline").and_then(Value::as_array);
    let mut inserted = 0;
    let mut skipped = std::collections::BTreeMap::new();
    for action in actions.into_iter().flatten() {
        let Some(name) = action.get("name").and_then(Value::as_str) else {
            skipped.insert("<unnamed>".to_string(), "action_name_missing");
            continue;
        };
        // An unclassified risk must not be seeded as a permissive read.
        let Some(parsed_risk) = action
            .get("risk")
            .and_then(Value::as_str)
            .and_then(Risk::parse)
        else {
            skipped.insert(
                name.chars()
                    .take(MAX_DIAGNOSTIC_ACTION_CHARS)
                    .filter(|ch| !ch.is_control())
                    .collect::<String>(),
                "risk_unclassified",
            );
            continue;
        };
        let risk = parsed_risk.to_string();
        let ask_first = crate::manifest::action_asks_first(
            parsed_risk,
            &declared_ask_first,
            action
                .get("ask_first")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            action.get("recipients").is_some(),
        );
        if mode == SeedMode::AddMissing {
            let reconciliation = action
                .get("reconciliation")
                .filter(|value| !value.is_null())
                .map(serde_json::to_string)
                .transpose()
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
            // A reviewed policy change must reach handle connections even when
            // they never perform discovery. Do not repin or reactivate a row:
            // those are separate operator decisions, not catalog policy.
            let updated = conn.execute(
                "UPDATE catalog_actions SET risk=?4, severity=?5, ask_first=?6,
                 reconciliation_json=?7, generation=generation + CASE
                   WHEN risk IS NOT ?4 OR severity IS NOT ?5 OR ask_first IS NOT ?6
                     OR reconciliation_json IS NOT ?7 THEN 1 ELSE 0 END
                 WHERE principal=?1 AND connection_id=?2 AND name=?3",
                rusqlite::params![
                    principal,
                    connection_id,
                    name,
                    risk,
                    tier,
                    ask_first,
                    reconciliation
                ],
            )?;
            if updated != 0 {
                suspend_subscriptions_for_action(
                    conn,
                    principal,
                    connection_id,
                    name,
                    (parsed_risk != Risk::Read).then_some("risk_drift"),
                    now_ms(),
                )?;
                continue;
            }
        }
        // Pin a reviewed http.args_schema or input_schema when declared. An
        // action with neither starts open until discovery supplies its schema.
        let schema = action
            .pointer("/http/args_schema")
            .or_else(|| action.get("input_schema"))
            .cloned()
            .unwrap_or_else(placeholder_catalog_schema);
        // A malformed schema hash cannot become a usable catalog action.
        let Ok(schema_hash) = crate::jcs::jcs_sha256(&schema) else {
            skipped.insert(
                name.chars()
                    .take(MAX_DIAGNOSTIC_ACTION_CHARS)
                    .filter(|ch| !ch.is_control())
                    .collect::<String>(),
                "schema_unhashable",
            );
            continue;
        };
        let input = CatalogActionInput {
            connection_id: connection_id.to_string(),
            principal: principal.to_string(),
            name: name.to_string(),
            title: Some(name.to_string()),
            schema,
            schema_hash,
            risk: risk.to_string(),
            severity: tier.to_string(),
            ask_first,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: action.get("reconciliation").cloned(),
        };
        let schema = serde_json::to_string(&input.schema)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
        let reconciliation = input
            .reconciliation
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
        upsert_catalog_action_row(
            conn,
            &input,
            &schema,
            reconciliation.as_deref(),
            None,
            now_ms(),
        )?;
        inserted += 1;
    }
    for (action, reason) in skipped {
        crate::diag!(warn storage: "catalog action skipped: app={app_key:?} action={action:?} reason={reason}");
    }
    Ok(inserted)
}

fn upsert_catalog_action_row(
    conn: &rusqlite::Connection,
    input: &CatalogActionInput,
    schema: &str,
    reconciliation: Option<&str>,
    reviewed_schema: Option<&str>,
    observed_at_ms: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO catalog_actions
            (connection_id, principal, name, title, schema_json, schema_hash,
             risk, severity, status, quarantine_reason, reconciliation_json,
             ask_first, first_seen_at_ms, last_seen_at_ms, generation,
             reviewed_schema_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13, 1, ?14)
         ON CONFLICT(principal, connection_id, name) DO UPDATE SET
            title = excluded.title, schema_json = excluded.schema_json,
            schema_hash = excluded.schema_hash, risk = excluded.risk,
            severity = excluded.severity, status = excluded.status,
            quarantine_reason = excluded.quarantine_reason,
            reconciliation_json = excluded.reconciliation_json,
            ask_first = excluded.ask_first,
            reviewed_schema_json = COALESCE(
                excluded.reviewed_schema_json, catalog_actions.reviewed_schema_json
            ),
            last_seen_at_ms = excluded.last_seen_at_ms,
            generation = CASE
                WHEN catalog_actions.schema_hash IS NOT excluded.schema_hash
                  OR catalog_actions.risk IS NOT excluded.risk
                  OR catalog_actions.severity IS NOT excluded.severity
                  OR catalog_actions.status IS NOT excluded.status
                  OR catalog_actions.quarantine_reason IS NOT excluded.quarantine_reason
                  OR catalog_actions.reconciliation_json IS NOT excluded.reconciliation_json
                  OR catalog_actions.ask_first IS NOT excluded.ask_first
                THEN catalog_actions.generation + 1
                ELSE catalog_actions.generation
            END",
        rusqlite::params![
            input.connection_id,
            input.principal,
            input.name,
            input.title,
            schema,
            input.schema_hash,
            input.risk,
            input.severity,
            input.status,
            input.quarantine_reason,
            reconciliation,
            input.ask_first,
            observed_at_ms,
            reviewed_schema,
        ],
    )?;
    Ok(())
}

fn catalog_suspension_reason(input: &CatalogActionInput) -> Option<&'static str> {
    match input.status.as_str() {
        "quarantined" => Some("quarantined"),
        "disabled" => Some("disabled"),
        _ if input.risk != "read" => Some("risk_drift"),
        _ => None,
    }
}

/// Suspend active subscriptions when the refreshed catalog no longer confirms
/// that their action is read-only. The catalog caller invokes this helper inside
/// its write transaction, and this helper records the suspension reason before
/// that transaction commits.
fn suspend_subscriptions_for_action(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    action: &str,
    base_reason: Option<&str>,
    observed_at_ms: i64,
) -> rusqlite::Result<()> {
    let subscriptions = {
        let mut statement = conn.prepare(
            "SELECT subscription_id, CASE WHEN cursor_kind='probe' THEN ?4 ELSE schema_hash END,
                    last_success_at_ms, created_at_ms
             FROM trigger_subscriptions
              WHERE principal = ?1 AND connection_id = ?2
                AND status = 'active'
                AND (action = ?3 OR (cursor_kind = 'probe' AND EXISTS (
                    SELECT 1 FROM probe_subscriptions p, json_each(p.actions) a
                    WHERE p.subscription_id = trigger_subscriptions.subscription_id AND a.value = ?3)))",
        )?;
        let current_hash = action_schema_hash(conn, principal, connection_id, action)?;
        let rows =
            statement.query_map((principal, connection_id, action, current_hash), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };

    let current_hash = if subscriptions.is_empty() {
        None
    } else {
        Some(action_schema_hash(conn, principal, connection_id, action)?)
    };
    for (subscription_id, pinned_schema_hash, last_success_at_ms, created_at_ms) in subscriptions {
        let reason = if Some(&pinned_schema_hash) != current_hash.as_ref() {
            Some("schema_changed")
        } else {
            base_reason
        };
        let Some(reason) = reason else {
            continue;
        };
        let changed = conn.execute(
            "UPDATE trigger_subscriptions
             SET status = 'suspended', suspended_reason = ?1,
                 generation = generation + 1
             WHERE subscription_id = ?2 AND status = 'active'",
            (reason, &subscription_id),
        )?;
        if changed != 0 {
            insert_gap_row(
                conn,
                principal,
                connection_id,
                &subscription_id,
                last_success_at_ms.unwrap_or(created_at_ms),
                observed_at_ms,
                reason,
                observed_at_ms,
            )?;
        }
    }
    Ok(())
}

fn action_schema_hash(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    action: &str,
) -> rusqlite::Result<String> {
    conn.query_row(
        "SELECT schema_hash FROM catalog_actions
         WHERE principal = ?1 AND connection_id = ?2 AND name = ?3",
        (principal, connection_id, action),
        |row| row.get(0),
    )
}

/// Validate connection status and read-only action availability in the writer
/// snapshot, treating a retired app as disabled without rewriting its actions.
/// A scripted probe may call several vendor actions and pins its own return
/// schema, so only an ordinary single-action watch has a vendor-schema pin.
fn recheck_watch_preconditions(
    conn: &Connection,
    principal: &str,
    connection_id: &str,
    actions: &[(&str, Option<&str>)],
) -> rusqlite::Result<Option<SubscriptionRefusal>> {
    let status: Option<String> = conn
        .query_row(
            "SELECT status FROM connections WHERE principal=?1 AND connection_id=?2",
            (principal, connection_id),
            |row| row.get(0),
        )
        .optional()?;
    match status {
        None => return Ok(Some(SubscriptionRefusal::ConnectionNotFound)),
        Some(status) if status != "active" => {
            return Ok(Some(SubscriptionRefusal::ConnectionInactive(status)))
        }
        _ => {}
    }
    for (action, pin) in actions {
        let row = conn.query_row(
            &format!("SELECT {CATALOG_ACTION_COLUMNS} FROM catalog_actions WHERE principal=?1 AND connection_id=?2 AND name=?3"),
            (principal, connection_id, action), map_catalog_action_row,
        ).optional()?;
        let Some(row) = row else {
            return Ok(Some(SubscriptionRefusal::ActionNotFound));
        };
        if row.risk != "read" {
            return Ok(Some(SubscriptionRefusal::ActionRiskNotRead));
        }
        if row.status != "active" {
            return Ok(Some(SubscriptionRefusal::ActionUnavailable(
                row.quarantine_reason.unwrap_or(row.status),
            )));
        }
        if pin.is_some_and(|pin| pin != row.schema_hash) {
            return Ok(Some(SubscriptionRefusal::ActionUnavailable(
                "schema_changed".into(),
            )));
        }
    }
    Ok(None)
}

fn map_probe_subscription_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProbeSubscription> {
    let actions: String = row.get(2)?;
    let return_schema: String = row.get(4)?;
    Ok(ProbeSubscription {
        subscription_id: row.get(0)?,
        name: row.get(1)?,
        actions: parse_string_list(&actions)?,
        script_source: row.get(3)?,
        return_schema: parse_json_column(&return_schema)?,
        rearm: row.get(5)?,
        registered_by: row.get(6)?,
    })
}

/// The sandbox's closed grammar, checked at registration so a bad schema is a
/// refused watch rather than a poll that never completes.
///
/// Delegates to the probe crate's own validator rather than re-encoding its
/// limits. An earlier revision duplicated the 256-byte and 16-field caps here,
/// which is two sources of truth for one grammar: they drift silently, and the
/// symptom is a registration this store accepted producing a poll-time
/// `probe_return_invalid` forever, on a watch that never retires.
fn validate_probe_return_schema(schema: &Value) -> Result<(), String> {
    let parsed: plexus_probe::ReturnSchema =
        serde_json::from_value(schema.clone()).map_err(|error| error.to_string())?;
    parsed
        .validate_declaration()
        .map_err(|error| error.to_string())
}

fn map_trigger_subscription_row(
    row: &rusqlite::Row<'_>,
    now: i64,
) -> rusqlite::Result<TriggerSubscription> {
    let cursor_state: String = row.get(6)?;
    let fixed_args: String = row.get(7)?;
    let last_success_at_ms: Option<i64> = row.get(12)?;
    let actor_source_json: Option<String> = row.get(18)?;
    Ok(TriggerSubscription {
        subscription_id: row.get(0)?,
        principal: row.get(1)?,
        connection_id: row.get(2)?,
        action: row.get(3)?,
        cadence_s: row.get(4)?,
        cursor_kind: row.get(5)?,
        cursor_state: parse_json_column(&cursor_state)?,
        fixed_args: parse_json_column(&fixed_args)?,
        schema_hash: row.get(8)?,
        status: row.get(9)?,
        suspended_reason: row.get(10)?,
        last_polled_at_ms: row.get(11)?,
        last_success_at_ms,
        cursor_age_ms: last_success_at_ms.map(|value| now.saturating_sub(value)),
        consecutive_vendor_failures: row.get(13)?,
        generation: row.get(14)?,
        created_at_ms: row.get(15)?,
        project_id: row.get(16)?,
        deliver_to: row.get(17)?,
        actor_source: actor_source_json
            .as_deref()
            .map(parse_json_column)
            .transpose()?,
        // Authority lives in the grants table, not this row. `list_subscriptions`
        // resolves it per subscription after mapping; every other reader gets
        // `absent` rather than a guess, because a row mapper that invented a
        // liveness value would be asserting something it cannot see.
        authority_expires_at_ms: None,
        authority_state: "absent".to_string(),
        name: None,
        registered_by: None,
        rearm: None,
        actions: None,
    })
}

fn map_trigger_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TriggerEvent> {
    let payload: String = row.get(6)?;
    let actor_logins_json: Option<String> = row.get(16)?;
    let actor_unknown_reason: Option<String> = row.get(17)?;
    let subscription_has_actor_source: bool = row.get(18)?;
    let kind: String = row.get(7)?;
    let actor_logins = actor_logins_json
        .as_deref()
        .map(parse_json_column)
        .transpose()?;
    let (actor_logins, actor_unknown) = served_actor_fields(
        actor_logins,
        actor_unknown_reason.as_deref(),
        kind == "event",
        subscription_has_actor_source,
    );
    Ok(TriggerEvent {
        event_id: row.get(0)?,
        principal: row.get(1)?,
        connection_id: row.get(2)?,
        subscription_id: row.get(3)?,
        vendor_event_id: row.get(4)?,
        payload_hash: row.get(5)?,
        payload: parse_json_column(&payload)?,
        kind,
        gap_from_ms: row.get(8)?,
        gap_to_ms: row.get(9)?,
        gap_reason: row.get(10)?,
        observed_at_ms: row.get(11)?,
        acked_at_ms: row.get(12)?,
        created_at_ms: row.get(13)?,
        item_kind: row.get(14)?,
        activity_at_ms: row.get(15)?,
        actor_logins,
        actor_unknown,
    })
}

fn jcs_store_hash(value: &Value) -> Result<String, StoreError> {
    crate::jcs::jcs_sha256(value).map_err(|error| StoreError::Backend(error.to_string()))
}

fn jcs_sqlite_hash(value: &Value) -> rusqlite::Result<String> {
    crate::jcs::jcs_sha256(value)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
}

/// Insert one event row under an open transaction, deduping only an identical
/// `(connection_id, subscription_id, vendor_event_id, payload_hash)` version.
///
/// A changed payload is new content to deliver, not a coverage gap. Shared by
/// [`PlexusStore::insert_event`] (which wraps it in its own transaction) and
/// [`PlexusStore::commit_poll_success`] (which must commit the events and cursor
/// advance atomically, so it cannot reuse the self-transactional `insert_event`).
///
/// Takes the event as ONE bundle rather than six positional arguments. Four of
/// them were adjacent `&str`s and the typed fields added three more; at that width
/// nothing but argument order distinguishes a kind from a principal, and a
/// swapped pair compiles and writes the wrong column. Same reasoning as the
/// bundled grant-mint request.
fn insert_event_row(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    subscription_id: &str,
    event: &PollEventInput<'_>,
) -> rusqlite::Result<TriggerEventInsertOutcome> {
    insert_keyed_event_row(
        conn,
        principal,
        connection_id,
        subscription_id,
        &KeyedPollEventInput {
            event: *event,
            identity: None,
            delivery_id: None,
            envelope_context: Default::default(),
        },
    )
}

fn insert_keyed_event_row(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    subscription_id: &str,
    keyed: &KeyedPollEventInput<'_>,
) -> rusqlite::Result<TriggerEventInsertOutcome> {
    let PollEventInput {
        vendor_event_id,
        payload,
        observed_at_ms,
        item_kind,
        activity_at_ms,
        actor,
    } = keyed.event;
    // Only the bare reason code is stored, never enrichment's diagnostic
    // detail, which can carry vendor error text.
    let (actor_logins, actor_unknown_reason) = match actor {
        ActorAttribution::NotEnriched => (None, None),
        ActorAttribution::Known(logins) => (Some(logins), None),
        ActorAttribution::Unknown { code } => (None, Some(code.as_str())),
    };
    let actor_logins_json = actor_logins
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    let payload_json = serde_json::to_string(payload)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    let payload_hash = jcs_sqlite_hash(payload)?;
    let created_at_ms = now_ms();
    let existing_event_id: Option<String> = conn
        .query_row(
            "SELECT event_id FROM trigger_events
             WHERE connection_id = ?1 AND subscription_id = ?2
               AND vendor_event_id = ?3 AND payload_hash = ?4 AND kind = 'event'",
            (
                connection_id,
                subscription_id,
                vendor_event_id,
                &payload_hash,
            ),
            |row| row.get(0),
        )
        .optional()?;
    if let Some(event_id) = existing_event_id {
        return Ok(TriggerEventInsertOutcome::Duplicate {
            event_id,
            payload_hash,
        });
    }
    if let Some(identity) = &keyed.identity {
        event_outbox::validate_identity(identity)?;
        let existing: Option<(String, String)> = conn.query_row(
            "SELECT event_id, payload_hash FROM trigger_events WHERE subscription_id = ?1 AND event_key = ?2",
            (subscription_id, identity.event_key), |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
        if let Some((event_id, payload_hash)) = existing {
            return Ok(TriggerEventInsertOutcome::Duplicate {
                event_id,
                payload_hash,
            });
        }
    }
    if let Some(delivery_id) = keyed.delivery_id {
        let existing: Option<(String, String)> = conn
            .query_row(
                "SELECT event_id, payload_hash FROM trigger_events WHERE delivery_id = ?1",
                [delivery_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((event_id, payload_hash)) = existing {
            return Ok(TriggerEventInsertOutcome::Duplicate {
                event_id,
                payload_hash,
            });
        }
    }
    let incoming_event_id = new_id("event");
    conn.execute(
        "INSERT INTO trigger_events
            (event_id, principal, connection_id, subscription_id,
             vendor_event_id, payload_hash, payload, kind, observed_at_ms, created_at_ms,
             item_kind, activity_at_ms, actor_logins, actor_unknown_reason, event_key, delivery_id)
          VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'event', ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        rusqlite::params![
            incoming_event_id,
            principal,
            connection_id,
            subscription_id,
            vendor_event_id,
            payload_hash,
            payload_json,
            observed_at_ms,
            created_at_ms,
            item_kind,
            activity_at_ms,
            actor_logins_json,
            actor_unknown_reason,
            keyed.identity.as_ref().map(|identity| identity.event_key),
            keyed.delivery_id,
        ],
    )?;
    if let Some(identity) = &keyed.identity {
        let envelope = crate::event_envelope::envelope(
            identity.event_key,
            identity.event_name,
            &identity.headers.repo,
            payload,
            actor,
            &keyed.envelope_context,
        )
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        event_outbox::insert_marker(
            conn,
            &incoming_event_id,
            identity,
            created_at_ms,
            &envelope,
            &payload_json,
        )?;
    }
    Ok(TriggerEventInsertOutcome::Inserted {
        event_id: incoming_event_id,
    })
}

/// Fold selected unacknowledged observation intervals into one coverage span.
/// An absent bound contributes nothing; treating None as zero would invent a
/// coverage gap reaching back to the epoch.
fn merge_intervals(
    left: (Option<i64>, Option<i64>),
    right: (Option<i64>, Option<i64>),
) -> (Option<i64>, Option<i64>) {
    let from = match (left.0, right.0) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (value, None) | (None, value) => value,
    };
    let to = match (left.1, right.1) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (value, None) | (None, value) => value,
    };
    (from, to)
}

#[allow(clippy::too_many_arguments)]
fn insert_gap_row(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    subscription_id: &str,
    gap_from_ms: i64,
    gap_to_ms: i64,
    reason: &str,
    observed_at_ms: i64,
) -> rusqlite::Result<()> {
    let event_id = new_id("event");
    let payload = serde_json::json!({});
    let payload_json = serde_json::to_string(&payload)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    let payload_hash = jcs_sqlite_hash(&payload)?;
    insert_gap_row_with_payload(
        conn,
        principal,
        connection_id,
        subscription_id,
        gap_from_ms,
        gap_to_ms,
        reason,
        observed_at_ms,
        &event_id,
        &payload_json,
        &payload_hash,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_gap_row_with_payload(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    subscription_id: &str,
    gap_from_ms: i64,
    gap_to_ms: i64,
    reason: &str,
    observed_at_ms: i64,
    event_id: &str,
    payload: &str,
    payload_hash: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO trigger_events
            (event_id, principal, connection_id, subscription_id,
             payload_hash, payload, kind, gap_from_ms, gap_to_ms, gap_reason,
             observed_at_ms, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'gap', ?7, ?8, ?9, ?10, ?10)",
        rusqlite::params![
            event_id,
            principal,
            connection_id,
            subscription_id,
            payload_hash,
            payload,
            gap_from_ms.min(gap_to_ms),
            gap_to_ms,
            reason,
            observed_at_ms,
        ],
    )?;
    Ok(())
}

/// The column list every `catalog_actions` read selects, in the order
/// [`map_catalog_action_row`] expects.
///
/// Kept beside the mapper because the two are one unit: the mapper reads by
/// POSITIONAL index, so a query that selects the same columns in a different
/// order silently mis-assigns fields of the same type rather than failing.
const CATALOG_ACTION_COLUMNS: &str = concat!(
    "connection_id, principal, name, title, schema_json, schema_hash,
     risk, severity, status, quarantine_reason, reconciliation_json, ask_first, generation, ",
    app_retired_predicate!()
);

fn map_connection_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConnectionRecord> {
    let filters: String = row.get(4)?;
    let health: String = row.get(5)?;
    Ok(ConnectionRecord {
        connection_id: row.get(0)?,
        principal: row.get(1)?,
        app_key: row.get(2)?,
        status: row.get(3)?,
        resource_filters: parse_json_column(&filters)?,
        health_state: parse_json_column(&health)?,
        generation: row.get(6)?,
        has_credential_binding: row.get(7)?,
    })
}

/// Build a [`CatalogAction`] from a row selecting [`CATALOG_ACTION_COLUMNS`].
///
/// Shared by the active-only list projection and the single-action accessor,
/// which had identical twenty-line bodies. The duplication was a live hazard
/// rather than an aesthetic one: adding a column means updating both, and the
/// one that is missed keeps returning a stale default for that field while
/// every test of the other path passes. Migration 8 added `ask_first` with a
/// fail-closed default of true, so exactly that miss would have made an action
/// ask for approval through one read and not the other.
fn map_catalog_action_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CatalogAction> {
    let schema: String = row.get(4)?;
    let reconciliation: Option<String> = row.get(10)?;
    // Retirement is projected once without rewriting the reviewed action row.
    let retired: bool = row.get(13)?;
    Ok(CatalogAction {
        connection_id: row.get(0)?,
        principal: row.get(1)?,
        name: row.get(2)?,
        title: row.get(3)?,
        schema: parse_json_column(&schema)?,
        schema_hash: row.get(5)?,
        risk: row.get(6)?,
        severity: row.get(7)?,
        status: if retired {
            "disabled".into()
        } else {
            row.get(8)?
        },
        quarantine_reason: if retired {
            Some("app_retired".into())
        } else {
            row.get(9)?
        },
        reconciliation: reconciliation
            .as_deref()
            .map(parse_json_column)
            .transpose()?,
        ask_first: row.get(11)?,
        generation: row.get(12)?,
    })
}

fn map_action_request_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ActionRequestRecord> {
    let args: String = row.get(4)?;
    Ok(ActionRequestRecord {
        request_id: row.get(0)?,
        principal: row.get(1)?,
        connection_id: row.get(2)?,
        action: row.get(3)?,
        args_snapshot: parse_json_column(&args)?,
        args_hash: row.get(5)?,
        schema_hash: row.get(6)?,
        requester: row.get(7)?,
        status: row.get(8)?,
        decision: row.get(9)?,
        decider: row.get(10)?,
        expires_at: row.get(11)?,
        decision_id: row.get(12)?,
        reconciliation_status: row.get(13)?,
        scope: match (
            row.get::<_, Option<String>>(15)?,
            row.get::<_, Option<String>>(16)?,
            row.get::<_, Option<i64>>(17)?,
        ) {
            (Some(owner), Some(scope_ref), Some(epoch)) => Some(RequestScope {
                owner,
                scope_ref,
                scope_epoch: epoch_from_sql(epoch),
                agent_id: row.get(14)?,
                flow_id: row.get(25)?,
                delegates: row.get::<_, Option<bool>>(18)?.unwrap_or(false),
                owner_authorized: row.get::<_, Option<bool>>(19)?.unwrap_or(false),
            }),
            _ => None,
        },
        scope_outcome: row.get(20)?,
        call_key: row.get(21)?,
        withdrawn: row.get::<_, String>(8)? == REQUEST_CANCELLED,
        relay_origin: match (
            row.get::<_, Option<String>>(22)?,
            row.get::<_, Option<String>>(23)?,
        ) {
            (Some(carrier), Some(call_key)) => Some(RelayOrigin { carrier, call_key }),
            _ => None,
        },
        elicitation_id: row.get(24)?,
    })
}

/// What [`PlexusStore::ensure_keyed_action_request`] found or made.
#[derive(Debug)]
pub(crate) enum EnsuredRequest {
    /// The open request that holds the call, new or reused.
    Held(String),
    /// The carrier already holds a request under this key that cannot take
    /// this call.
    KeyTaken(Box<ActionRequestRecord>),
}

/// A new approval request row, with its id minted and its arguments hashed.
struct NewActionRequest<'a> {
    request_id: String,
    principal: &'a str,
    connection_id: &'a str,
    action: &'a str,
    snapshot: String,
    args_hash: String,
    schema_hash: &'a str,
    requester: &'a str,
    call_key: Option<&'a str>,
    expires_at: i64,
    scope: Option<&'a CallScope>,
    relay_origin: Option<&'a RelayOrigin>,
}

impl<'a> NewActionRequest<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        principal: &'a str,
        connection_id: &'a str,
        action: &'a str,
        args: &Value,
        schema_hash: &'a str,
        requester: &'a str,
        call_key: Option<&'a str>,
        expires_at: i64,
        scope: Option<&'a CallScope>,
        relay_origin: Option<&'a RelayOrigin>,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            request_id: new_id("req"),
            principal,
            connection_id,
            action,
            snapshot: serde_json::to_string(args)
                .map_err(|error| StoreError::Backend(error.to_string()))?,
            args_hash: jcs_store_hash(args)?,
            schema_hash,
            requester,
            call_key,
            expires_at,
            scope,
            relay_origin,
        })
    }
}

fn insert_action_request_on_conn(
    conn: &rusqlite::Connection,
    row: &NewActionRequest<'_>,
) -> rusqlite::Result<()> {
    let scope = row.scope;
    conn.execute(
        "INSERT INTO action_requests
            (request_id, principal, connection_id, action, args_snapshot, args_hash,
             schema_hash, requester, status, expires_at, created_at_ms, agent_id,
              scope_owner, scope_ref, scope_epoch, scope_delegates, scope_owner_authorized,
              call_key, origin_carrier, origin_call_key, scope_flow_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20)",
        rusqlite::params![
            row.request_id,
            row.principal,
            row.connection_id,
            row.action,
            row.snapshot,
            row.args_hash,
            row.schema_hash,
            row.requester,
            row.expires_at,
            now_ms(),
            scope.and_then(|scope| scope.agent_id.as_deref()),
            scope.map(|scope| scope.owner.as_str()),
            scope.map(|scope| scope.scope_ref.as_str()),
            scope.map(|scope| epoch_to_sql(scope.scope_epoch)),
            scope.map(|scope| scope.delegates),
            scope.map(|scope| scope.owner_authorized),
            row.call_key,
            row.relay_origin.map(|origin| origin.carrier.as_str()),
            row.relay_origin.map(|origin| origin.call_key.as_str()),
            scope.and_then(|scope| scope.flow_id.as_deref()),
        ],
    )?;
    Ok(())
}

/// The `refused` reason a withdrawal reports for a request the scope
/// re-check retired, from its `scope_outcome` (`not_run:<code>`).
///
/// - `scope_ended` and `delegation_withdrawn`: the session, or the authority
///   the call was raised under, is gone: `scope_ended`.
/// - `scope_unverifiable`: almost always an approval whose own expiry passed
///   while it waited for its scope to be confirmed: `expired`. (The same code
///   also covers a scope owner the daemon never runs, which is not a case a
///   real carrier's scope can be in.)
/// - Anything else is a held approval that full re-authorization refused
///   later, a grant revoked for example. Plexus's own authority refused it:
///   `denied`.
fn scope_refusal_reason(scope_outcome: &str) -> &'static str {
    match scope_outcome.strip_prefix("not_run:") {
        Some(crate::scope::SCOPE_ENDED | crate::scope::DELEGATION_WITHDRAWN) => {
            WITHDRAW_REFUSED_SCOPE_ENDED
        }
        Some(crate::scope::SCOPE_UNVERIFIABLE) => WITHDRAW_REFUSED_EXPIRED,
        _ => WITHDRAW_REFUSED_DENIED,
    }
}

/// The columns [`map_action_request_row`] reads, in its order. Every query that
/// maps through it selects exactly this list, so a new column is added once.
const ACTION_REQUEST_COLUMNS: &str = "request_id, principal, connection_id, action, args_snapshot,
    args_hash, schema_hash, requester, status, decision, decider, expires_at, decision_id,
    reconciliation_status, agent_id, scope_owner, scope_ref, scope_epoch, scope_delegates,
    scope_owner_authorized, scope_outcome, call_key, origin_carrier, origin_call_key,
    elicitation_id, scope_flow_id";

fn parse_json_column<T: serde::de::DeserializeOwned>(value: &str) -> rusqlite::Result<T> {
    serde_json::from_str(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

/// Validate fixed arguments against the schema snapshot pinned to a subscription.
/// This is intentionally shallow: presence and JSON type are enough to reject a
/// misspelled container argument without pretending to implement JSON Schema.
///
/// Checks both directions, because they catch opposite mistakes. Every supplied
/// key must be DECLARED, which rejects a typo. Every REQUIRED key must be
/// supplied, which rejects a subscription the vendor will refuse on every
/// poll -- the poller builds its request from the cursor strategy and
/// `fixed_args` alone, so an argument absent here can never appear later.
///
/// Without the required check the failure is deferred rather than prevented,
/// and deferral is expensive here: the subscription is accepted, polls on its
/// cadence, and fails at the vendor every time. That reads as a flaky
/// integration rather than a subscription that was never viable, and the
/// backoff makes it quieter the longer it runs.
fn validate_fixed_args(
    fixed_args: &Value,
    schema: &Value,
    supplied_elsewhere: &BTreeSet<String>,
) -> Result<(), SubscriptionRefusal> {
    let Some(fixed_args) = fixed_args.as_object() else {
        return Err(SubscriptionRefusal::FixedArgsMustBeObject);
    };
    let properties = schema.get("properties").and_then(Value::as_object);

    // Supplied keys are checked before required ones: a misspelled required
    // key is both "not declared" and leaves the real one "missing", and only
    // the first names the typo the caller has to fix.
    for (key, value) in fixed_args {
        let Some(property) = properties.and_then(|properties| properties.get(key)) else {
            return Err(SubscriptionRefusal::FixedArgNotDeclared(key.clone()));
        };
        let Some(declared_type) = property.get("type") else {
            return Err(SubscriptionRefusal::FixedArgTypeMismatch {
                key: key.clone(),
                expected: "a declared JSON type".to_string(),
                actual: json_type_name(value).to_string(),
            });
        };
        if !json_type_matches(value, declared_type) {
            return Err(SubscriptionRefusal::FixedArgTypeMismatch {
                key: key.clone(),
                expected: schema_type_name(declared_type),
                actual: json_type_name(value).to_string(),
            });
        }
    }
    // Accept required keys that the poller supplies outside `fixed_args`.
    // Cursor-based pagination adds request arguments, and the manifest supplies
    // constant arguments on every poll. The checks above reject both kinds in
    // `fixed_args`, so requiring them there would prevent subscribing to an
    // action even though each poll supplies them.
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for entry in required {
            let Some(key) = entry.as_str() else { continue };
            if fixed_args.contains_key(key) || supplied_elsewhere.contains(key) {
                continue;
            }
            return Err(SubscriptionRefusal::FixedArgRequiredMissing(
                key.to_string(),
            ));
        }
    }
    Ok(())
}

fn json_type_matches(value: &Value, declared_type: &Value) -> bool {
    let actual_type = json_type_name(value);
    // JSON Schema counts any number with a zero fractional part, such as
    // `5.0`, as an integer; serde reads it as a float.
    let whole_number = value
        .as_f64()
        .is_some_and(|number| number.is_finite() && number.fract() == 0.0);
    let matches = |declared_type: &str| {
        type_names_match(declared_type, actual_type) || (declared_type == "integer" && whole_number)
    };
    match declared_type {
        Value::String(declared_type) => matches(declared_type.as_str()),
        Value::Array(types) => types
            .iter()
            .any(|declared_type| declared_type.as_str().is_some_and(matches)),
        _ => false,
    }
}

fn type_names_match(declared_type: &str, actual_type: &str) -> bool {
    declared_type == actual_type || (declared_type == "number" && actual_type == "integer")
}

fn schema_type_name(declared_type: &Value) -> String {
    match declared_type {
        Value::String(value) => value.clone(),
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" or "),
        _ => declared_type.to_string(),
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
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

// Versioned non-secret vault references are the only stored credential binding.
const REFERENCE_BINDING_PREFIX: &[u8] = b"plexus:vault-reference:v1\0";

fn encode_reference_binding(id: &str) -> Result<Vec<u8>, String> {
    if !crate::credentials::valid_credential_id(id) {
        return Err("invalid credential id".into());
    }
    let mut encoded = REFERENCE_BINDING_PREFIX.to_vec();
    encoded.extend_from_slice(id.as_bytes());
    Ok(encoded)
}

fn decode_connection_binding(
    value: &[u8],
) -> Result<crate::credentials::ConnectionCredentialBinding, String> {
    use crate::credentials::ConnectionCredentialBinding;
    if let Some(id) = value.strip_prefix(REFERENCE_BINDING_PREFIX) {
        let id = std::str::from_utf8(id).map_err(|_| "invalid credential id")?;
        if !crate::credentials::valid_credential_id(id) {
            return Err("invalid credential id".into());
        }
        Ok(ConnectionCredentialBinding::Reference(id.to_owned()))
    } else {
        Err("handle_bindings_removed: use credential_id".into())
    }
}

pub(crate) fn removed_binding_error(connection_id: &str) -> String {
    format!("handle_bindings_removed: non-revoked connection(s) {connection_id}; use ck-plexus-admin rebind-credential with credential_id on the previous build before opening this store")
}

pub(crate) fn is_reference_binding(value: &[u8]) -> bool {
    decode_connection_binding(value).is_ok()
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
        // authority comparison pointing OPEN: with now = 0, an expired grant
        // reads live (0 < expires_at) and an approval window never lapses.
        // A module that cannot read its clock cannot enforce time-bounded
        // authority; refusing to run is the honest failure, and the
        // supervisor's restart budget parks it in front of an operator.
        .expect(
            "system clock reads before the Unix epoch; refusing to serve time-bounded authority",
        )
}

impl PlexusStore {
    /// Persist screened arguments only until the next terminal read-back. One day
    /// is a hard retention ceiling independent of mutable manifest timeouts.
    pub fn enqueue_write_reconciliation(
        &self,
        record: &crate::reconciliation::OutcomeUnknownRecord,
        intent_id: Option<&str>,
    ) -> Result<(), StoreError> {
        if crate::secret_input::contains_secret_input(&record.args) {
            return Err(StoreError::Backend("secret_input_rejected".to_string()));
        }
        let encoded =
            serde_json::to_string(record).map_err(|e| StoreError::Backend(e.to_string()))?;
        self.inner.with_conn_fenced(|conn| {
            let tx = conn;
            tx.execute(
                "INSERT INTO pending_write_reconciliations
                (principal,request_id,record_json,intent_id,expires_at_ms) VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![
                    record.principal,
                    record.request_id,
                    encoded,
                    intent_id,
                    record.occurred_at_ms.saturating_add(AUDIT_MILLIS_PER_DAY)
                ],
            )?;
            tx.execute(
                "INSERT INTO write_reconciliation_results
                (principal,request_id,acting_principal,connection_id,action,status,updated_at_ms)
                 VALUES (?1,?2,?3,?4,?5,'pending',?6)
                 ON CONFLICT(principal,request_id) DO UPDATE SET status='pending',reason=NULL,updated_at_ms=excluded.updated_at_ms",
                rusqlite::params![
                    record.principal,
                    record.request_id,
                    record.acting_principal,
                    record.connection_id,
                    record.action,
                    now_ms()
                ],
            )?;
            tx.execute("UPDATE action_requests SET reconciliation_status='pending' WHERE principal=?1 AND request_id=?2",rusqlite::params![record.principal,intent_id])?;
            Ok(())
        })
    }

    pub(crate) fn pending_write_reconciliations_at(
        &self,
        now: i64,
    ) -> Result<Vec<crate::reconciliation::PendingWriteReconciliation>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let mut stmt = conn.prepare("SELECT principal,request_id,record_json,expires_at_ms FROM pending_write_reconciliations WHERE next_attempt_at_ms<=?1 ORDER BY expires_at_ms,principal,request_id LIMIT ?2")?;
            let rows = stmt
                .query_map((now, RECONCILIATION_BATCH_ROWS), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(stmt);
            let mut pending = Vec::with_capacity(rows.len());
            for (principal, request_id, encoded, expires_at_ms) in rows {
                match serde_json::from_str(&encoded) {
                    Ok(record) => pending.push(crate::reconciliation::PendingWriteReconciliation {
                        record,
                        expires_at_ms,
                    }),
                    Err(error) => {
                        crate::diag!(warn storage: "write reconciliation record does not decode; settling it as ambiguous: principal={principal:?} request_id={request_id:?}: class={:?} line={} column={}",error.classify(),error.line(),error.column());
                        conn.execute("UPDATE write_reconciliation_results SET status='ambiguous', reason='record_undecodable', updated_at_ms=?3
                            WHERE principal=?1 AND request_id=?2", rusqlite::params![principal, request_id, now_ms()])?;
                        conn.execute("UPDATE action_requests SET reconciliation_status='ambiguous' WHERE principal=?1 AND request_id IN
                            (SELECT intent_id FROM pending_write_reconciliations WHERE principal=?1 AND request_id=?2)",
                            rusqlite::params![principal, request_id])?;
                        conn.execute("DELETE FROM pending_write_reconciliations WHERE principal=?1 AND request_id=?2",
                            rusqlite::params![principal, request_id])?;
                    }
                }
            }
            Ok(pending)
        })
    }

    /// Delete the argument-bearing record in the same transaction that records
    /// the terminal status. Results deliberately retain neither args nor evidence.
    pub(crate) fn finish_write_reconciliation(
        &self,
        record: &crate::reconciliation::OutcomeUnknownRecord,
        status: &str,
        reason: Option<&str>,
    ) -> Result<(), StoreError> {
        self.finish_write_reconciliation_with_intent(record, None, status, reason)
    }

    pub(crate) fn finish_write_reconciliation_with_intent(
        &self,
        record: &crate::reconciliation::OutcomeUnknownRecord,
        intent_id: Option<&str>,
        status: &str,
        reason: Option<&str>,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let tx = conn;
            tx.execute("INSERT INTO write_reconciliation_results
                (principal,request_id,acting_principal,connection_id,action,status,reason,updated_at_ms)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                ON CONFLICT(principal,request_id) DO UPDATE SET status=excluded.status,reason=excluded.reason,updated_at_ms=excluded.updated_at_ms",
                rusqlite::params![record.principal, record.request_id, record.acting_principal,record.connection_id,record.action,status,reason,now_ms()])?;
            tx.execute("UPDATE action_requests SET reconciliation_status=?3 WHERE principal=?1 AND request_id=COALESCE(?4,
                (SELECT intent_id FROM pending_write_reconciliations WHERE principal=?1 AND request_id=?2))",
                rusqlite::params![record.principal,record.request_id,status,intent_id])?;
            tx.execute("DELETE FROM pending_write_reconciliations WHERE principal=?1 AND request_id=?2", rusqlite::params![record.principal, record.request_id])?;
            Ok(())
        })
    }

    /// Owners see their connections' results; callers see only their own results.
    /// The flag reports additional rows beyond this bounded diagnostic snapshot.
    pub fn list_write_reconciliations(
        &self,
        principal: &str,
    ) -> Result<(Vec<crate::reconciliation::WriteReconciliationStatus>, bool), StoreError> {
        self.inner.with_read(|conn| {
            let mut stmt = conn.prepare("SELECT request_id,connection_id,action,status,reason FROM write_reconciliation_results WHERE principal=?1 OR acting_principal=?1 ORDER BY updated_at_ms DESC,request_id LIMIT ?2")?;
            let mut rows: Vec<_> = stmt.query_map((principal, RECONCILIATION_BATCH_ROWS + 1), |row| Ok(crate::reconciliation::WriteReconciliationStatus {
                request_id: row.get(0)?, connection_id: row.get(1)?, action: row.get(2)?, status: row.get(3)?, reason: row.get(4)?,
            }))?.collect::<rusqlite::Result<_>>()?;
            let truncated = rows.len() > RECONCILIATION_BATCH_ROWS as usize;
            rows.truncate(RECONCILIATION_BATCH_ROWS as usize);
            Ok((rows, truncated))
        })
    }

    pub(crate) fn backoff_write_reconciliation(
        &self,
        record: &crate::reconciliation::OutcomeUnknownRecord,
        now: i64,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute("UPDATE pending_write_reconciliations SET next_attempt_at_ms=?3 + MIN(60000,5000 * (1 << MIN(retry_attempts,4))), retry_attempts=MIN(retry_attempts+1,4) WHERE principal=?1 AND request_id=?2",rusqlite::params![record.principal,record.request_id,now])?;
            Ok(())
        })
    }

    pub(crate) fn prune_write_reconciliation_results(
        &self,
        now: i64,
        retention_window_ms: i64,
    ) -> Result<usize, StoreError> {
        self.inner.with_conn_fenced(|conn| conn.execute("DELETE FROM write_reconciliation_results WHERE (principal,request_id) IN
            (SELECT principal,request_id FROM write_reconciliation_results WHERE status!='pending' AND updated_at_ms < ?1 ORDER BY updated_at_ms LIMIT ?2)",
            (now.saturating_sub(retention_window_ms), RECONCILIATION_BATCH_ROWS)))
    }
}

#[cfg(test)]
#[path = "store/store_contract_tests.rs"]
mod store_contract_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poller::CursorStrategy;
    use crate::test_scratch::Scratch;
    use cortexkit_store_types::Isolation;
    use rusqlite::Connection;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TRIGGER_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    include!("storage_api_tests.rs");

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
                path: ":memory:".to_string(),
            },
        };
        PlexusStore::open(&descriptor).expect("open audit retention store")
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
                path: ":memory:".to_string(),
            },
        };
        PlexusStore::open(&descriptor).expect("open reservation retention store")
    }

    fn schema_table_names(connection: &Connection) -> rusqlite::Result<BTreeSet<String>> {
        let mut statement = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
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
                path: ":memory:".into(),
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
                path: ":memory:".into(),
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
        // Current authority queries require the later agent-layer columns.
        inner.migrate("plexus", MIGRATIONS).unwrap();
        let store = PlexusStore {
            inner,
            grant_journal: None,
            outbox_ready: tokio::sync::Notify::new(),
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
                path: ":memory:".into(),
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
                path: ":memory:".into(),
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
                path: ":memory:".into(),
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
                path: ":memory:".into(),
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
                path: ":memory:".into(),
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
                path: ":memory:".into(),
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
            ci_runs: Default::default(),
            manifest_cache: Default::default(),
        };
        let scope = CallScope {
            owner: "reserved:prefrontal-core".into(),
            scope_ref: "head-1".into(),
            scope_epoch: u64::MAX,
            kind: Some("head".into()),
            parent: Some("reserved:prefrontal-core/root@1".into()),
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
                path: ":memory:".into(),
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
                    let rows = statement
                        .query_map([], |row| (0..20).map(|index| row.get(index)).collect())?;
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
                path: ":memory:".into(),
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
                path: ":memory:".into(),
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
                        let read = statement.query_map([], |row| {
                            (0..width).map(|index| row.get(index)).collect()
                        })?;
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
    /// card, and the cursor table starts empty. Such a binary still opens the
    /// migrated store (reporting the store as ahead of its own chain rather
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
                path: ":memory:".into(),
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
                    ('invalidated', 'direct', 'c', 'a', '{}', 'args', 'schema', 2, 'invalidated', 1);"
        ).unwrap();
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
                path: ":memory:".to_string(),
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
                path: ":memory:".to_string(),
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
                path: ":memory:".to_string(),
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
    /// unreadable seeds its actions at S4 so they route through the decision
    /// plane rather than past it.
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
                path: ":memory:".to_string(),
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
        let manifest =
            crate::manifest::ingest_value(manifest_value).expect("every shape must ingest");

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

    /// Mutation proved: removing the manifest-constant collision branch creates
    /// a subscription row and fails the refusal and empty-after assertions.
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
        assert!(
            matches!(changed_risk, Err(RepinActionRefusal::RiskNotRead(risk)) if risk == "write")
        );
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
                .insert_reservation_at_for_test(
                    "p",
                    &format!("recent-{status}"),
                    status,
                    cutoff + 1,
                )
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
                .ack_events_including_granted(
                    "reserved:consumer",
                    std::slice::from_ref(&event_id),
                    now
                )
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
                .ack_events_including_granted(
                    "reserved:consumer",
                    std::slice::from_ref(&event_id),
                    now
                )
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
        // parallel. It held when this test ran alone and failed in a full gate
        // run, which is the signature of a threshold below scheduling
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
                path: ":memory:".to_string(),
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
                    path: ":memory:".to_string(),
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
}

#[cfg(test)]
mod reference_binding_tests {
    use super::*;

    #[test]
    fn reference_binding_decoder_refuses_legacy_blobs() {
        let reference = encode_reference_binding("apikey:github").unwrap();
        assert_eq!(
            decode_connection_binding(&reference).unwrap().kind(),
            "reference"
        );
        assert_eq!(
            format!("{:?}", decode_connection_binding(&reference).unwrap()),
            "reference"
        );
        assert!(decode_connection_binding(&[42; 64]).is_err());
    }
}

#[cfg(test)]
mod exact_argument_tests {
    use super::*;
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    use serde_json::json;

    #[test]
    fn action_request_reuse_distinguishes_large_integers() {
        let store = PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "exact-arguments".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap();
        let a = json!({"n": 9007199254740992_u64});
        let b = json!({"n": 9007199254740993_u64});
        let expires = now_ms() + 60_000;
        let first = store
            .ensure_action_request(
                "direct", "conn", "write", &a, "schema", "actor", expires, None, None,
            )
            .unwrap();
        let second = store
            .ensure_action_request(
                "direct", "conn", "write", &b, "schema", "actor", expires, None, None,
            )
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            second,
            store
                .ensure_action_request(
                    "direct", "conn", "write", &b, "schema", "actor", expires, None, None
                )
                .unwrap()
        );
        assert!(matches!(
            store
                .ensure_keyed_action_request(
                    "direct", "conn", "write", &a, "schema", "actor", "key", expires, None, None
                )
                .unwrap(),
            EnsuredRequest::Held(_)
        ));
        assert!(matches!(
            store
                .ensure_keyed_action_request(
                    "direct", "conn", "write", &b, "schema", "actor", "key", expires, None, None
                )
                .unwrap(),
            EnsuredRequest::KeyTaken(_)
        ));
    }
}
