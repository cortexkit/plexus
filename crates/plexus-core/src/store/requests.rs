//! Action-request consent settlement and reservation fencing.

use super::*;

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
    // Approval dispatch and exact-argument re-calls need plaintext while the
    // request is pending. Precompute only the terminal copy; the status trigger
    // swaps it in atomically for every terminal path, including withdrawal and
    // expiry. Gmail is the only archived-text action; other actions keep their
    // existing snapshot contract.
    if row.action == "gmail.send" {
        let mut terminal: Value =
            serde_json::from_str(&row.snapshot).expect("serialized arguments");
        for field in ["subject", "body"] {
            if let Some(text) = terminal.get(field).and_then(Value::as_str) {
                terminal[field] = Value::String(format!(
                    "sha256:{}",
                    hex::encode(sha2::Sha256::digest(text.as_bytes()))
                ));
            }
        }
        conn.execute("UPDATE action_requests SET terminal_args_snapshot=?1 WHERE principal=?2 AND request_id=?3", rusqlite::params![terminal.to_string(),row.principal,row.request_id])?;
    }
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

impl PlexusStore {
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

    /// Put approvals that a retry batch selected but did not reach back at the
    /// front of the rotation. Selection stamps every row it returns as checked;
    /// a row the pass ran out of time for was not checked, and keeping its
    /// stamp would let the rows tried first be chosen ahead of it again.
    pub(crate) fn release_untried_scoped_approvals(
        &self,
        rows: &[(String, String)],
    ) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        self.inner.with_conn_fenced(|conn| {
            let mut update = conn.prepare_cached(
                "UPDATE action_requests SET scope_checked_at_ms=0
                 WHERE principal=?1 AND request_id=?2 AND status='approved' AND scope_outcome=?3",
            )?;
            for (principal, request_id) in rows {
                update.execute(rusqlite::params![
                    principal,
                    request_id,
                    crate::scope::APPROVED_WAITING
                ])?;
            }
            Ok(())
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
    pub(super) fn settle_consent_requests(
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
    ///
    /// `now_ms` is the governance engine's clock. It is read inside the
    /// transaction, the moment the claim is judged, so the claim and the
    /// engine's own expiry checks use one clock.
    ///
    /// `consumed_search_use` is carried only from a search whose answer was
    /// consumed before its cache lookup. Such a dispatch pins the reservation,
    /// not the now-terminal card; fallback attempts share that call's use.
    pub(crate) fn claim_reservation(
        &self,
        reservation: &ReservationRecord,
        attempt_request_id: &str,
        now_ms: &dyn Fn() -> i64,
        consumed_search_use: bool,
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
                            CASE WHEN federated_row_id IS NOT NULL THEN
                                CASE WHEN EXISTS (SELECT 1 FROM federated_rows
                                    WHERE id = reservations.federated_row_id AND effect = 'allow')
                                    AND grant_id IS NULL AND agent_grant_id IS NULL
                                    THEN 0 ELSE -1 END
                            WHEN card_ref IS NOT NULL THEN
                                CASE WHEN grant_id IS NULL AND agent_grant_id IS NULL
                                  THEN CASE WHEN ?6 THEN 0
                                  WHEN EXISTS (SELECT 1 FROM federated_card_records c
                                    WHERE c.card_ref=reservations.card_ref AND c.state='consumed'
                                      AND c.owner_principal=?1 AND c.subject=?2 AND c.action=?3
                                      AND c.args_digest=reservations.approved_args_hash
                                      AND c.schema_hash=reservations.schema_hash)
                                  THEN 0 ELSE -1 END ELSE -1 END
                            ELSE COALESCE((SELECT generation FROM grants
                             WHERE principal = ?1 AND (expires_at IS NULL OR expires_at > ?5) AND grant_id = (
                                 SELECT grant_id FROM reservations
                                 WHERE principal = ?1 AND reservation_id = ?4
                         )), -1) END,
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
                        consumed_search_use,
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
}
