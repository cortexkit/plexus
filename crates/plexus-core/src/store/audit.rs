//! Transactional audit evidence and bounded history retention.

use super::*;

/// The audit row an operator write appends inside its own transaction, built
/// from what the write produced. `None` writes no row: the unaudited forms of
/// those writes are kept for internal callers and tests.
pub(super) type AuditFor<'a, T> = Option<&'a dyn Fn(&T) -> AuditRecord>;

pub(super) fn append_audit_for<T>(
    conn: &Connection,
    audit: AuditFor<'_, T>,
    value: &T,
) -> rusqlite::Result<()> {
    match audit {
        Some(build) => append_audit_on_conn(conn, &build(value), None, None, None, None),
        None => Ok(()),
    }
}

/// What an audit row records beside its [`AuditRecord`]: the web search
/// query columns, the daemon scope the call's route was bound under, the
/// call it was relayed from, and the agent a worker scope works for. Each
/// absent part leaves its columns NULL.
#[derive(Default)]
struct AuditContext<'a> {
    query_text: Option<&'a str>,
    result_count: Option<i64>,
    scope: Option<&'a CallScope>,
    relay_origin: Option<&'a RelayOrigin>,
    on_behalf_of_agent: Option<&'a str>,
    federated_caller: Option<&'a crate::federated::FederatedCaller>,
    federated_row_id: Option<&'a str>,
    card_ref: Option<&'a str>,
}

pub(super) fn append_audit_on_conn(
    conn: &Connection,
    record: &AuditRecord,
    query_text: Option<&str>,
    result_count: Option<i64>,
    scope: Option<&CallScope>,
    relay_origin: Option<&RelayOrigin>,
) -> rusqlite::Result<()> {
    append_audit_on_conn_with(
        conn,
        record,
        &AuditContext {
            query_text,
            result_count,
            scope,
            relay_origin,
            ..AuditContext::default()
        },
    )
}

fn append_audit_on_conn_with(
    conn: &Connection,
    record: &AuditRecord,
    context: &AuditContext<'_>,
) -> rusqlite::Result<()> {
    let AuditContext {
        query_text,
        result_count,
        scope,
        relay_origin,
        on_behalf_of_agent,
        federated_caller,
        federated_row_id,
        card_ref,
    } = *context;
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
            origin_carrier, origin_call_key, scope_flow_id, scope_on_behalf_of_agent,
            peer_fingerprint, pairing_id, peer_class, claim_kind, canonical_claim_identity,
            federated_row_id, card_ref
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
            ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
            ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34,
            ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46, ?47
        )",
        rusqlite::params![
            now,
            record.principal,
            record.actor,
            record.acting_principal,
            record
                .agent_id
                .as_ref()
                .filter(|_| federated_caller.is_none()),
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
            on_behalf_of_agent,
            federated_caller.map(|caller| caller.attributes.peer_fingerprint.as_str()),
            federated_caller.map(|caller| caller.attributes.pairing_id.as_str()),
            federated_caller.map(|caller| match caller.attributes.peer_class {
                subc_protocol::scope::FederatedPeerClass::Computer => "computer",
                subc_protocol::scope::FederatedPeerClass::Phone => "phone",
                subc_protocol::scope::FederatedPeerClass::Sim => "sim",
                _ => "unknown",
            }),
            federated_caller.map(|caller| caller.claim.claim_kind),
            federated_caller.map(|caller| caller.claim.canonical_claim_identity.as_str()),
            federated_row_id,
            card_ref,
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

impl PlexusStore {
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
    /// `on_behalf_of_agent` is the agent a worker scope works for, written to
    /// its own column for attribution; it never fills `agent_id`.
    pub(crate) fn append_audit_relayed(
        &self,
        record: &AuditRecord,
        scope: Option<&CallScope>,
        relay_origin: Option<&RelayOrigin>,
        on_behalf_of_agent: Option<&str>,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            append_audit_on_conn_with(
                conn,
                record,
                &AuditContext {
                    scope,
                    relay_origin,
                    on_behalf_of_agent,
                    ..AuditContext::default()
                },
            )
        })
    }

    pub(crate) fn append_audit_federated(
        &self,
        record: &AuditRecord,
        scope: Option<&CallScope>,
        relay_origin: Option<&RelayOrigin>,
        caller: &crate::federated::FederatedCaller,
        row_id: Option<&str>,
        card_ref: Option<&str>,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            append_audit_on_conn_with(
                conn,
                record,
                &AuditContext {
                    scope,
                    relay_origin,
                    federated_caller: Some(caller),
                    federated_row_id: row_id,
                    card_ref,
                    ..AuditContext::default()
                },
            )
        })
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
                         scope_owner_authorized, scope_flow_id, scope_on_behalf_of_agent
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
                    scope_on_behalf_of_agent: row.get(36)?,
                })
            })?;
            rows.collect()
        })
    }
}
