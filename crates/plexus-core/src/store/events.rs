//! Trigger event commits, delivery visibility, acknowledgements, and pruning.

use super::*;

struct EventsConsumeGrant {
    owner: String,
    connection_id: String,
    selectors: Vec<String>,
    expires_at: Option<i64>,
    authority_state: &'static str,
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

pub(super) fn insert_keyed_event_row(
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
    // Only normalized notices get a stamped v1 body. Legacy v1 vendor objects
    // stay untouched; the first committed outbox snapshot owns the timestamp.
    let notice;
    let payload = if keyed
        .identity
        .as_ref()
        .is_some_and(|identity| crate::event_key::is_normalized_notice(identity.event_name))
    {
        notice = crate::event_envelope::observed_notice(payload, observed_at_ms);
        &notice
    } else {
        payload
    };
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
            observed_at_ms,
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
pub(super) fn merge_intervals(
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
pub(super) fn insert_gap_row(
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

impl PlexusStore {
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

    /// Identify keys already stored in this subscription, including webhook
    /// deliveries whose vendor id differs from polling's item number. This is
    /// the same subscription/key check used by insert-time deduplication.
    pub(crate) fn stored_event_keys(
        &self,
        subscription_id: &str,
        keys: &[Option<&str>],
    ) -> Result<Vec<bool>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT EXISTS(SELECT 1 FROM trigger_events
                 WHERE subscription_id = ?1 AND event_key = ?2)",
            )?;
            keys.iter()
                .map(|key| match key {
                    Some(key) => statement.query_row((subscription_id, key), |row| row.get(0)),
                    None => Ok(false),
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
            // No classification: this entry point takes a raw payload without
            // the watch's manifest, so there is nothing to classify from. The
            // poll path classifies, because it knows the kind the manifest declares.
            insert_event_row(
                conn,
                principal,
                connection_id,
                subscription_id,
                &PollEventInput {
                    vendor_event_id,
                    payload,
                    observed_at_ms,
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
    #[cfg(any(test, feature = "test-support"))]
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
        self.commit_keyed_poll_success_observing_relay(
            principal,
            connection_id,
            subscription_id,
            cursor_state,
            events,
            at_ms,
            coverage_gaps,
            None,
        )
    }

    /// Collect relay-coverable activity only from new inserts, in the same
    /// transaction that checks watch eligibility and wins the deduplication race.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_keyed_poll_success_observing_relay(
        &self,
        principal: &str,
        connection_id: &str,
        subscription_id: &str,
        cursor_state: &Value,
        events: &[KeyedPollEventInput<'_>],
        at_ms: i64,
        coverage_gaps: &[PollGapInput<'_>],
        relay_activity: Option<&mut Vec<i64>>,
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
        let (outcomes, activity) = self
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
                let mut activity = Vec::new();
                let mut coverage = std::collections::HashMap::new();
                for event in events {
                    let outcome = insert_keyed_event_row(
                        conn,
                        principal,
                        connection_id,
                        subscription_id,
                        event,
                    )?;
                    if relay_activity.is_some()
                        && matches!(outcome, TriggerEventInsertOutcome::Inserted { .. })
                        && !relay::github_sends_no_webhook(event)
                    {
                        if let Some((identity, time, action)) =
                            event.identity.as_ref().and_then(|identity| {
                                Some((
                                    identity,
                                    event.event.activity_at_ms?,
                                    relay::poll_coverage_action(identity.event_name)?,
                                ))
                            })
                        {
                            // Read coverage once per repository/action in an
                            // actual inserting poll, never on an idle scheduler pass.
                            let key = (&identity.headers.repo, action);
                            let covered = match coverage.get(&key) {
                                Some(&covered) => covered,
                                None => {
                                    let covered = relay::covers_poll_watch(
                                        conn,
                                        principal,
                                        subscription_id,
                                        &identity.headers.repo,
                                        action,
                                    )?;
                                    coverage.insert(key, covered);
                                    covered
                                }
                            };
                            if covered {
                                activity.push(time);
                            }
                        }
                    }
                    outcomes.push(outcome);
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
                Ok(Some((outcomes, activity)))
            })?
            .ok_or(PollCommitError::Inactive)?;
        if events.iter().zip(&outcomes).any(|(event, outcome)| {
            event.identity.is_some()
                && matches!(outcome, TriggerEventInsertOutcome::Inserted { .. })
        }) {
            self.outbox_ready.notify_one();
        }
        if let Some(relay_activity) = relay_activity {
            relay_activity.extend(activity);
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
}
