//! Schema generations and the frozen migration backfills.

use super::*;

/// The connector schema, beginning with the complete fresh-store schema.
///
/// The base schema is numbered 23 because migration versions are schema
/// generation markers, not a count of steps in the current binary. Stores that
/// completed the fresh-schema cutover already record generation 23.
pub const MIGRATIONS: &[Migration] = &[
    // `policies.rate_limit_json` and `policies.trust_rule_json` below are
    // reserved columns: no policy write sets them, policy evaluation never
    // reads them, and plexus enforces no per-policy rate limit or trust rule.
    // The store importer still copies them so an older store's values survive
    // an import unchanged.
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
    // Each catalog refresh invalidates the live reservations of a quarantined
    // action again, even when the action was already quarantined. Index only
    // live reservations so these repeated checks never walk spent history.
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
    // The daemon scope a governed call's route was bound under: the binding's
    // scope owner, scope reference, and epoch. There is deliberately no relay or
    // carrier column: a scope identifies the session, while the module that
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
    //   before migration version 39, or its filing failed). The card's answer
    //   is awaited with the id read from the request row. No query looks a
    //   request up by a particular id (one only checks that the column is not
    //   NULL), so the partial index below speeds up nothing. It stays because
    //   migrations are append-only; a later migration may drop it.
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
    // GitHub bot reads share each App installation's 5,000-request hourly
    // quota with that bot's writes. The ledger counts the read requests each
    // installation's handle sent in the trailing hour, so reads can be capped
    // below the quota and writes always keep headroom. The rate-limit row
    // keeps the last `x-ratelimit-remaining` and reset GitHub reported for
    // the handle. The audit column records the agent a worker scope works
    // for, kept apart from `agent_id`, which only ever names the acting or
    // attributed agent.
    Migration {
        version: 56,
        statements: r#"
CREATE TABLE github_bot_read_ledger (
    app_handle_id TEXT NOT NULL,
    reserved_at_ms INTEGER NOT NULL,
    units INTEGER NOT NULL CHECK (units BETWEEN 1 AND 16)
);
CREATE INDEX idx_github_bot_read_ledger_handle_time ON github_bot_read_ledger(app_handle_id, reserved_at_ms);
CREATE TABLE github_bot_rate_limit (
    app_handle_id TEXT PRIMARY KEY NOT NULL,
    remaining INTEGER NOT NULL CHECK (remaining >= 0),
    reset_at_ms INTEGER NOT NULL,
    observed_at_ms INTEGER NOT NULL
);
ALTER TABLE audit_journal ADD COLUMN scope_on_behalf_of_agent TEXT;
"#,
    },
    Migration {
        version: 57,
        statements: "ALTER TABLE connections ADD COLUMN instance_url TEXT;
                     ALTER TABLE binding_tickets ADD COLUMN instance_url TEXT;",
    },
    Migration {
        version: 58,
        statements: r#"
CREATE TABLE gmail_accounts (
    principal TEXT NOT NULL, connection_id TEXT NOT NULL, mailbox TEXT NOT NULL,
    next_send_ms INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (principal, connection_id)
);
CREATE TABLE sent_text (
    row_id TEXT PRIMARY KEY, principal TEXT NOT NULL, connection_id TEXT NOT NULL,
    recipient_hash TEXT NOT NULL, key_id TEXT NOT NULL, enc BLOB NOT NULL,
    ciphertext BLOB NOT NULL, expires_at_ms INTEGER NOT NULL, created_at_ms INTEGER NOT NULL
);
CREATE INDEX sent_text_expiry ON sent_text(expires_at_ms);
CREATE TABLE sent_text_settings (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 1 AND 3650)
);
INSERT INTO sent_text_settings VALUES (1,30);
ALTER TABLE action_requests ADD COLUMN terminal_args_snapshot TEXT;
CREATE TRIGGER scrub_gmail_terminal_text AFTER UPDATE OF status ON action_requests
WHEN NEW.action='gmail.send' AND NEW.status IN ('consumed','denied','expired','cancelled')
     AND NEW.terminal_args_snapshot IS NOT NULL
BEGIN
    UPDATE action_requests SET args_snapshot=NEW.terminal_args_snapshot,
        terminal_args_snapshot=NULL
    WHERE principal=NEW.principal AND request_id=NEW.request_id;
END;
"#,
    },
    Migration {
        version: 59,
        statements: r#"
CREATE TABLE web_search_auto_connections (
    principal TEXT NOT NULL,
    provider TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    incarnation TEXT NOT NULL,
    record_version INTEGER NOT NULL CHECK(record_version > 0),
    connection_id TEXT NOT NULL,
    appended_at_ms INTEGER,
    revoked_at_ms INTEGER,
    PRIMARY KEY (principal, provider, credential_id, incarnation, record_version)
);
"#,
    },
    Migration {
        version: 60,
        statements: r#"
CREATE TABLE github_manifest_binding (
    app_handle_id TEXT NOT NULL REFERENCES github_app_handle(app_handle_id) ON DELETE CASCADE,
    repository TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    proposal_id TEXT,
    manifest_version INTEGER,
    manifest_sha256 TEXT,
    statement_b64url TEXT,
    expires_at_ms INTEGER,
    state TEXT NOT NULL CHECK(state IN ('observed','pending','card_conflict','awaiting_active','declined','expired','terminal','bound')),
    card_id TEXT,
    present INTEGER NOT NULL CHECK(present IN (0,1)),
    revision INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(app_handle_id, repository)
);
CREATE UNIQUE INDEX github_manifest_proposal_id ON github_manifest_binding(proposal_id)
    WHERE proposal_id IS NOT NULL;
"#,
    },
    // Federated authority is separate from local grants. Existing writers name
    // their columns, leaving the new audit and reservation fields NULL.
    Migration {
        version: 61,
        statements: include_str!("../federated_schema.sql"),
    },
    Migration {
        version: 62,
        statements: r#"
CREATE TABLE route_fact_outbox (
    msg_id TEXT PRIMARY KEY NOT NULL,
    body TEXT NOT NULL CHECK(length(CAST(body AS BLOB)) <= 4096),
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX route_fact_outbox_age ON route_fact_outbox(created_at_ms, msg_id);
"#,
    },
    // Keep the old identity's grants for rollback binaries without bumping
    // grant or connection generations or writing audit/revocation records.
    // Opening a restored older database runs this before journal replay, so
    // `PlexusStore::open` revokes the copies of grants the journal had already
    // revoked.
    // Deterministic copy ids let later journal entries remove those same
    // copies after a backup restore.
    Migration {
        version: 63,
        statements: PREFRONTAL_GRANT_BACKFILL,
    },
    Migration {
        version: 64,
        statements: r#"
CREATE TABLE policy_apply_switch (
    service TEXT PRIMARY KEY NOT NULL,
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1))
);
CREATE TABLE policy_applied (
    service TEXT NOT NULL,
    agent TEXT NOT NULL,
    policy_version INTEGER NOT NULL CHECK(policy_version > 0),
    policy_sha256 TEXT NOT NULL,
    manifest_version INTEGER NOT NULL CHECK(manifest_version > 0),
    grant_ids TEXT NOT NULL,
    applied_at_ms INTEGER NOT NULL,
    PRIMARY KEY (service, agent)
);
"#,
    },
];

/// Shared with offline store import, whose destination is migrated before
/// source rows are copied. Existing aliases and their metadata stay untouched.
pub(crate) const PREFRONTAL_GRANT_BACKFILL: &str = r#"
INSERT OR IGNORE INTO grants (grant_id, principal, connection_id, grantee_principal,
                    risk_ceiling, action_selectors, authority_kind, expires_at,
                    generation, created_at_ms, agent_id)
SELECT CASE WHEN old.grant_id GLOB 'github-import:*:prefrontal'
            THEN substr(old.grant_id, 1, length(old.grant_id) - length('prefrontal')) || 'reserved-prefrontal'
            ELSE old.grant_id || '-reserved-prefrontal' END,
       old.principal, old.connection_id, 'reserved:prefrontal', old.risk_ceiling,
       old.action_selectors, old.authority_kind, old.expires_at, old.generation,
       old.created_at_ms, old.agent_id
FROM grants old
WHERE old.grantee_principal = 'reserved:prefrontal-core'
  AND NOT EXISTS (
      SELECT 1 FROM grants new
      WHERE new.principal = old.principal
        AND new.connection_id = old.connection_id
        AND new.grantee_principal = 'reserved:prefrontal'
        AND new.authority_kind = old.authority_kind
        AND new.action_selectors = old.action_selectors
  );
"#;

/// The id `PREFRONTAL_GRANT_BACKFILL` would give its copy of one grant, named
/// by owner (?1) and grant id (?2). No row means the backfill would copy
/// nothing for that grant: it is absent or not held by the legacy identity, a
/// matching renamed grant already exists, or another row already holds the
/// copy's id. These conditions repeat the backfill's own, so this answer is
/// exact only when read before the backfill runs.
pub(crate) const PREFRONTAL_GRANT_COPY_ID: &str = r#"
SELECT candidate.copy_id FROM (
    SELECT old.principal AS principal,
           CASE WHEN old.grant_id GLOB 'github-import:*:prefrontal'
                THEN substr(old.grant_id, 1, length(old.grant_id) - length('prefrontal')) || 'reserved-prefrontal'
                ELSE old.grant_id || '-reserved-prefrontal' END AS copy_id
    FROM grants old
    WHERE old.principal = ?1
      AND old.grant_id = ?2
      AND old.grantee_principal = 'reserved:prefrontal-core'
      AND NOT EXISTS (
          SELECT 1 FROM grants new
          WHERE new.principal = old.principal
            AND new.connection_id = old.connection_id
            AND new.grantee_principal = 'reserved:prefrontal'
            AND new.authority_kind = old.authority_kind
            AND new.action_selectors = old.action_selectors
      )
) candidate
WHERE NOT EXISTS (
    SELECT 1 FROM grants taken
    WHERE taken.principal = candidate.principal AND taken.grant_id = candidate.copy_id
);
"#;

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

#[cfg(test)]
#[path = "prefrontal_rename_tests.rs"]
mod tests;
