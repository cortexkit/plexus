//! Stores keyed event publication markers, repository ids and GitHub request
//! reservations; decides event visibility, retention and request quota admission.
//! Every write checks the single-writer lease epoch in a fenced transaction and
//! is refused if another process holds a newer lease. Send a GitHub request only
//! after its quota reservation commits, so a failed or competing reservation
//! cannot leave a sent request uncounted against the shared quota.

use super::*;

pub const EVENT_BODY_FLOOR_MS: i64 = 7 * AUDIT_MILLIS_PER_DAY;
pub const QUOTA_WINDOW_MS: i64 = 3_600_000;
// Ordered timestamp polling can widen its lookback to one hour. Retention
// must preserve the full ceiling, not only the currently selected window.
pub const RETENTION_MAX_WINDOW_MS: i64 = 3_600_000;
pub const REPO_RETRY_MS: i64 = 3_600_000;
pub const REPO_REFRESH_MS: i64 = 24 * REPO_RETRY_MS;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHeaders {
    pub repo: String,
    pub project: Option<String>,
    pub pr: Option<String>,
    pub branch: Option<String>,
    pub conclusion: Option<String>,
}

#[derive(Clone, Copy)]
pub struct KeyedEventIdentity<'a> {
    pub event_key: &'a str,
    pub event_name: &'a str,
    pub repo_id: i64,
    pub change: Option<&'a str>,
    pub headers: &'a EventHeaders,
}

pub struct KeyedPollEventInput<'a> {
    pub event: PollEventInput<'a>,
    pub identity: Option<KeyedEventIdentity<'a>>,
    pub delivery_id: Option<&'a str>,
    pub envelope_context: crate::event_envelope::EnvelopeContext,
}

pub struct PollGapInput<'a> {
    pub from_ms: i64,
    pub to_ms: i64,
    pub reason: &'a str,
}

/// A stable keyset position in the ordered pending outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxCursor {
    pub created_at_ms: i64,
    pub event_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalEvent {
    pub event_key: String,
    pub event_id: String,
    pub event_name: String,
    pub repo_id: i64,
    pub change: Option<String>,
    pub headers: EventHeaders,
    pub published_at_ms: Option<i64>,
    pub body: String,
    pub digest: String,
    pub principal: String,
    pub connection_id: String,
    pub subscription_id: String,
    #[serde(skip)]
    pub envelope_v2: Option<String>,
    #[serde(skip)]
    pub digest_v2: Option<String>,
    #[serde(skip)]
    pub published_v2_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventLookupOutcome {
    Found(Box<CanonicalEvent>),
    NotFound,
    NotVisible,
}

/// Module callers must first check an accepted route binding for the call's
/// channel and epoch: only `reserved:basal` may relay flow calls, and its route
/// must carry a flow scope. For an agent-owned flow, this store checks the
/// event's repository name against the agent's live, enabled bot repository
/// binding, not the event's stored project or the repository-id cache.
pub enum EventReader<'a> {
    Agent { agent_id: &'a str },
    Consumer { principal: &'a str },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OutboxHealth {
    pub depth: i64,
    pub overlapping_key_rows: i64,
    pub dropped_on_unsubscribe: i64,
    pub dropped_on_delete: i64,
    pub orphaned_markers: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoIdCacheEntry {
    pub repo: String,
    pub repo_id: Option<i64>,
    pub last_attempt_at_ms: i64,
    pub resolved_at_ms: Option<i64>,
}

impl RepoIdCacheEntry {
    pub fn resolution_due(&self, now: i64) -> bool {
        self.resolved_at_ms
            .is_none_or(|at| now.saturating_sub(at) >= REPO_REFRESH_MS)
            && now.saturating_sub(self.last_attempt_at_ms) >= REPO_RETRY_MS
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaRequest {
    CiCycle,
    GetRepository,
    FlowRead,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaAdmission {
    Inactive,
    Reserved {
        reservation_id: String,
        requests: i64,
    },
    Deferred {
        retry_at_ms: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoResolutionAdmission {
    Reserved {
        reservation_id: String,
        cached_repo_id: Option<i64>,
    },
    NotDue,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoIdUpdate {
    Resolved,
    Failed,
    IdentityChanged {
        old_repo_id: i64,
        new_repo_id: i64,
        suspended: usize,
    },
}

pub(super) fn validate_identity(identity: &KeyedEventIdentity<'_>) -> rusqlite::Result<()> {
    let key = identity.event_key;
    if key.len() != 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !crate::event_key::PUBLISHED_EVENTS
            .iter()
            .any(|event| event.name == identity.event_name)
        || identity.headers.repo.is_empty()
    {
        return Err(rusqlite::Error::InvalidParameterName(
            "invalid event identity".into(),
        ));
    }
    Ok(())
}

pub(super) fn insert_marker(
    conn: &Connection,
    event_id: &str,
    identity: &KeyedEventIdentity<'_>,
    now: i64,
    envelope: &str,
    body_v1: &str,
) -> rusqlite::Result<()> {
    let h = identity.headers;
    conn.execute("INSERT INTO event_outbox
        (event_key, event_id, event_name, repo_id, change, repo, project, pr, branch, conclusion, created_at_ms, envelope_v2, digest_v2, body_v1, digest_v1)
         VALUES (?1, ?2, ?3, ?4, ?5, lower(?6), ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        ON CONFLICT(event_key) DO NOTHING", rusqlite::params![identity.event_key, event_id,
        identity.event_name, identity.repo_id, identity.change, h.repo, h.project, h.pr, h.branch, h.conclusion, now,
        envelope, hex::encode(sha2::Sha256::digest(envelope.as_bytes())),body_v1,hex::encode(sha2::Sha256::digest(body_v1.as_bytes()))])?;
    if identity.event_name.starts_with("github_ci_") {
        conn.execute(
            "INSERT INTO github_repo_id_cache (repo, repo_id, last_attempt_at_ms, resolved_at_ms)
            VALUES (lower(?1), ?2, ?3, ?3) ON CONFLICT(repo) DO NOTHING",
            (&h.repo, identity.repo_id, now),
        )?;
    }
    Ok(())
}

fn increment(conn: &Connection, name: &str, count: i64) -> rusqlite::Result<()> {
    if count > 0 {
        conn.execute(
            "INSERT INTO event_outbox_counters(name, value) VALUES (?1, ?2)
            ON CONFLICT(name) DO UPDATE SET value = value + excluded.value",
            (name, count),
        )?;
    }
    Ok(())
}

// Normal deletes remove their markers in the same transaction. Retention also
// repairs orphaned markers left by older binaries or imported stores, not on
// every publisher pass through the seven-day event history.
pub(super) fn cleanup_orphans(conn: &Connection) -> rusqlite::Result<()> {
    let deleted = conn.execute(
        "DELETE FROM event_outbox WHERE NOT EXISTS
        (SELECT 1 FROM trigger_events e WHERE e.event_id = event_outbox.event_id)",
        [],
    )?;
    increment(conn, "orphaned_markers", deleted as i64)
}

/// Repoint visibility before deleting a canonical watch, without changing the
/// notice's stored bytes or routing hints. Legacy v1 bodies are captured from
/// the original row before it disappears; an unavailable body gets an empty
/// digest marker, so a later fetch cannot substitute the surviving row's body.
pub(super) fn preserve_overlapping_markers(
    conn: &Connection,
    predicate: &str,
    params: impl rusqlite::Params,
) -> rusqlite::Result<()> {
    let mut statement=conn.prepare(&format!(
        "SELECT o.event_key,survivor.event_id,o.body_v1,o.digest_v1,
        CASE WHEN typeof(original.payload)='text' THEN original.payload ELSE NULL END
        FROM event_outbox o LEFT JOIN trigger_events original ON original.event_id=o.event_id
        JOIN trigger_events survivor ON survivor.event_id=(
            SELECT e.event_id FROM trigger_events e JOIN trigger_subscriptions s ON s.subscription_id=e.subscription_id
            WHERE e.event_key=o.event_key AND s.status='active'
              AND e.event_id NOT IN (SELECT event_id FROM trigger_events WHERE {predicate})
            ORDER BY e.created_at_ms,e.event_id LIMIT 1)
        WHERE o.event_id IN (SELECT event_id FROM trigger_events WHERE {predicate})"
    ))?;
    type TransferRow = (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<TransferRow> = statement
        .query_map(params, |row| {
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
    for (key, event_id, body, digest, original) in rows {
        let (body, digest) = if body.is_none() && digest.is_none() {
            match original.filter(|body| !body.is_empty()) {
                Some(body) => {
                    let digest = hex::encode(sha2::Sha256::digest(body.as_bytes()));
                    (Some(body), Some(digest))
                }
                None => (None, Some(String::new())),
            }
        } else {
            (body, digest)
        };
        conn.execute(
            "UPDATE event_outbox SET event_id=?2,body_v1=?3,digest_v1=?4 WHERE event_key=?1",
            rusqlite::params![key, event_id, body, digest],
        )?;
    }
    Ok(())
}

pub(super) fn count_dropped(
    conn: &Connection,
    predicate: &str,
    params: (&str, &str),
    counter: &str,
) -> rusqlite::Result<()> {
    preserve_overlapping_markers(conn, predicate, params)?;
    let count: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM event_outbox WHERE (published_at_ms IS NULL OR (envelope_v2 IS NOT NULL AND published_v2_at_ms IS NULL))
        AND event_id IN (SELECT event_id FROM trigger_events WHERE {predicate})"
        ),
        params,
        |r| r.get(0),
    )?;
    increment(conn, counter, count)
}

const CANONICAL_SELECT: &str = "SELECT o.event_key, o.event_id, o.event_name, o.repo_id, o.change,
    o.repo, o.project, o.pr, o.branch, o.conclusion, o.published_at_ms,
    CASE WHEN o.digest_v1='' THEN NULL WHEN typeof(COALESCE(o.body_v1,e.payload))='text' THEN COALESCE(o.body_v1,e.payload) ELSE NULL END,
    e.principal, e.connection_id, e.subscription_id, o.envelope_v2, o.digest_v2, o.published_v2_at_ms,o.digest_v1
    FROM event_outbox o JOIN trigger_events e ON e.event_id = o.event_id";

// Select only metadata so denied lookups never read the stored body. Unknown
// and invisible keys should do the same lookup work; otherwise response time
// can reveal that an event exists.
const LOOKUP_METADATA: &str = "SELECT o.repo, e.principal, e.connection_id, e.subscription_id
    FROM event_outbox o JOIN trigger_events e ON e.event_id = o.event_id
    WHERE o.event_key = ?1";

fn canonical_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CanonicalEvent> {
    let body: String = row.get::<_, Option<String>>(11)?.unwrap_or_default();
    let digest = if body.is_empty() {
        String::new()
    } else {
        row.get::<_, Option<String>>(18)?
            .unwrap_or_else(|| hex::encode(sha2::Sha256::digest(body.as_bytes())))
    };
    Ok(CanonicalEvent {
        event_key: row.get(0)?,
        event_id: row.get(1)?,
        event_name: row.get(2)?,
        repo_id: row.get(3)?,
        change: row.get(4)?,
        headers: EventHeaders {
            repo: row.get(5)?,
            project: row.get(6)?,
            pr: row.get(7)?,
            branch: row.get(8)?,
            conclusion: row.get(9)?,
        },
        published_at_ms: row.get(10)?,
        body,
        digest,
        principal: row.get(12)?,
        connection_id: row.get(13)?,
        subscription_id: row.get(14)?,
        envelope_v2: row.get(15)?,
        digest_v2: row.get(16)?,
        published_v2_at_ms: row.get(17)?,
    })
}

impl PlexusStore {
    /// Wait for a committed outbox insert. A stored permit covers an insert
    /// between the drain's last read and its next wait; wakes may coalesce.
    pub async fn outbox_committed(&self) {
        self.outbox_ready.notified().await;
    }

    /// Lookup without a visibility check, for the outbox publisher only.
    /// User-facing reads must use `event_by_key` to enforce access permissions.
    pub fn canonical_event_by_key(&self, key: &str) -> Result<Option<CanonicalEvent>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                &format!("{CANONICAL_SELECT} WHERE o.event_key = ?1"),
                [key],
                canonical_row,
            )
            .optional()
        })
    }

    pub fn event_by_key(
        &self,
        key: &str,
        reader: EventReader<'_>,
        now: i64,
    ) -> Result<EventLookupOutcome, StoreError> {
        self.event_by_key_version(key, reader, now, 1)
    }

    /// Fetch the requested immutable wire version. An unavailable legacy v1 body
    /// cannot fall back to another watch's body; a stored v2 remains readable.
    pub fn event_by_key_version(
        &self,
        key: &str,
        reader: EventReader<'_>,
        now: i64,
        version: u8,
    ) -> Result<EventLookupOutcome, StoreError> {
        self.inner.with_read(|conn| {
            let metadata = conn.query_row(LOOKUP_METADATA, [key], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?, r.get::<_, String>(3)?))
            }).optional()?;
            // Run the visibility query even for a missing key, using empty metadata.
            // Returning early would make missing keys faster than invisible ones,
            // revealing which events exist through response time.
            let (repo, owner, connection, subscription) = metadata.clone().unwrap_or_default();
            let visible = match reader {
                EventReader::Agent { agent_id } => conn.query_row("SELECT EXISTS(
                    SELECT 1 FROM github_repo_binding b JOIN github_app_handle h ON h.app_handle_id = b.app_handle_id
                    WHERE lower(b.repository) = lower(?1) AND h.agent_id = ?2 AND h.status = 'enabled')",
                    (&repo, agent_id), |r| r.get::<_, bool>(0))?,
                EventReader::Consumer { principal } => {
                    let mut query = conn.prepare("SELECT g.action_selectors, s.action FROM grants g
                        JOIN trigger_subscriptions s ON s.subscription_id = ?1
                            AND s.principal = g.principal AND s.connection_id = g.connection_id
                        WHERE g.principal = ?2 AND g.connection_id = ?3 AND g.authority_kind = 'events_consume'
                            AND g.grantee_principal = ?4 AND g.grantee_principal <> '*'
                            AND (g.expires_at IS NULL OR g.expires_at > ?5)")?;
                    let grants = query.query_map(rusqlite::params![subscription, owner,
                        connection, principal, now], |r| Ok((parse_string_list(&r.get::<_, String>(0)?)?, r.get::<_, String>(1)?)))?;
                    let mut admitted = false;
                    for grant in grants {
                        let (selectors, action) = grant?;
                        admitted |= selectors.iter().any(|selector| selector == "*" || selector == &action);
                    }
                    admitted
                }
            };
            if metadata.is_none() {
                return Ok(EventLookupOutcome::NotFound);
            }
            if !visible {
                return Ok(EventLookupOutcome::NotVisible);
            }
            let event = conn.query_row(&format!("{CANONICAL_SELECT} WHERE o.event_key = ?1"), [key], canonical_row)?;
            if (version!=2 && event.digest.is_empty()) || (version==2 && (event.envelope_v2.is_none() || event.digest_v2.is_none())) {
                return Ok(EventLookupOutcome::NotVisible);
            }
            Ok(EventLookupOutcome::Found(Box::new(event)))
        })
    }

    /// Read pending markers without a write transaction or writer fence. Orphan
    /// repair belongs to retention; the join never publishes a missing body.
    #[cfg(any(test, feature = "test-support"))]
    pub fn drain_event_outbox(&self, limit: usize) -> Result<Vec<CanonicalEvent>, StoreError> {
        self.drain_event_outbox_version(limit, 1)
    }

    pub fn drain_event_outbox_version(
        &self,
        limit: usize,
        version: u8,
    ) -> Result<Vec<CanonicalEvent>, StoreError> {
        self.inner.with_read(|conn| {
            let mut query = conn.prepare(&pending_query(version))?;
            let rows = query
                .query_map(rusqlite::params![limit as i64, i64::MIN], canonical_row)?
                .collect();
            rows
        })
    }

    /// Read only rows beyond the last attempted publication, including ties in
    /// creation time. A failing row cannot force later pages to rescan a prefix.
    pub fn drain_event_outbox_version_after(
        &self,
        limit: usize,
        version: u8,
        after: Option<&OutboxCursor>,
    ) -> Result<Vec<(CanonicalEvent, OutboxCursor)>, StoreError> {
        let (created, key) = after.map_or((i64::MIN, ""), |cursor| {
            (cursor.created_at_ms, cursor.event_key.as_str())
        });
        self.inner.with_read(|conn| {
            let mut query = conn.prepare(&pending_after_query(version))?;
            let rows = query
                .query_map(rusqlite::params![limit as i64, created, key], |row| {
                    let event = canonical_row(row)?;
                    let cursor = OutboxCursor {
                        created_at_ms: row.get(19)?,
                        event_key: event.event_key.clone(),
                    };
                    Ok((event, cursor))
                })?
                .collect();
            rows
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn mark_event_published(&self, key: &str, at_ms: i64) -> Result<bool, StoreError> {
        self.mark_event_version_published(key, 1, at_ms)
    }

    pub fn mark_event_version_published(
        &self,
        key: &str,
        version: u8,
        at_ms: i64,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let column = if version == 2 {
                "published_v2_at_ms"
            } else {
                "published_at_ms"
            };
            Ok(conn.execute(
                &format!(
                    "UPDATE event_outbox SET {column} = ?2
            WHERE event_key = ?1 AND {column} IS NULL"
                ),
                (key, at_ms),
            )? != 0)
        })
    }

    pub fn event_outbox_health(&self) -> Result<OutboxHealth, StoreError> {
        self.inner.with_read(|conn| {
            let count = |name: &str| -> rusqlite::Result<i64> {
                Ok(conn
                    .query_row(
                        "SELECT value FROM event_outbox_counters WHERE name = ?1",
                        [name],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or(0))
            };
            Ok(OutboxHealth {
                depth: conn.query_row(
                    "SELECT COUNT(*) FROM event_outbox WHERE published_at_ms IS NULL OR (envelope_v2 IS NOT NULL AND published_v2_at_ms IS NULL)",
                    [],
                    |r| r.get(0),
                )?,
                overlapping_key_rows: conn.query_row(
                    "SELECT COUNT(*) FROM trigger_events e
                    JOIN event_outbox o ON o.event_key = e.event_key AND o.event_id != e.event_id
                    JOIN trigger_events canonical ON canonical.event_id = o.event_id
                    JOIN trigger_subscriptions s ON s.subscription_id = canonical.subscription_id
                    WHERE s.status = 'active'",
                    [],
                    |r| r.get(0),
                )?,
                dropped_on_unsubscribe: count("dropped_on_unsubscribe")?,
                dropped_on_delete: count("dropped_on_delete")?,
                orphaned_markers: count("orphaned_markers")?,
            })
        })
    }

    /// Reserve the whole maximum cycle before dispatch. Unspent capacity is not
    /// refunded: conservative reservations keep the trailing-hour bound simple.
    pub fn reserve_github_actions_quota(
        &self,
        principal: &str,
        subscription_id: &str,
        request: QuotaRequest,
        now: i64,
    ) -> Result<QuotaAdmission, StoreError> {
        self.inner.with_conn_fenced(
            |conn| match require_active(conn, principal, subscription_id) {
                Ok(()) => quota_admit(conn, request, now),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(QuotaAdmission::Inactive),
                Err(error) => Err(error),
            },
        )
    }

    /// Reserves one GitHub Actions request for a flow read. Flow reads belong to no
    /// watch, but they spend the same operator token as CI polling, so they draw on
    /// the same rolling one-hour request ledger and use the same admission and
    /// retry-time calculation as `reserve_github_actions_quota`.
    pub fn reserve_github_actions_flow_read_quota(
        &self,
        now: i64,
    ) -> Result<QuotaAdmission, StoreError> {
        self.inner
            .with_conn_fenced(|conn| quota_admit(conn, QuotaRequest::FlowRead, now))
    }

    /// Commit the last-attempt time for this case-insensitive owner/name and
    /// its GitHub request quota reservation together. Watches sharing the name
    /// cannot both resolve it within an hour; successful resolutions are refreshed
    /// after a day. Quota deferral leaves the attempt time unchanged for retry.
    pub fn reserve_repo_id_resolution(
        &self,
        principal: &str,
        subscription_id: &str,
        repo: &str,
        now: i64,
    ) -> Result<RepoResolutionAdmission, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            require_active(conn, principal, subscription_id)?;
            let entry = cache_entry(conn, repo)?;
            if entry
                .as_ref()
                .is_some_and(|entry| !entry.resolution_due(now))
            {
                return Ok(RepoResolutionAdmission::NotDue);
            }
            let cached_repo_id = entry.and_then(|entry| entry.repo_id);
            let QuotaAdmission::Reserved { reservation_id, .. } =
                quota_admit(conn, QuotaRequest::GetRepository, now)?
            else {
                return Ok(RepoResolutionAdmission::Deferred);
            };
            conn.execute(
                "INSERT INTO github_repo_id_cache(repo, last_attempt_at_ms) VALUES (lower(?1), ?2)
                ON CONFLICT(repo) DO UPDATE SET last_attempt_at_ms = excluded.last_attempt_at_ms",
                (repo, now),
            )?;
            Ok(RepoResolutionAdmission::Reserved {
                reservation_id,
                cached_repo_id,
            })
        })
    }

    pub fn repo_id_cache(&self, repo: &str) -> Result<Option<RepoIdCacheEntry>, StoreError> {
        self.inner.with_read(|conn| cache_entry(conn, repo))
    }

    /// Record a resolution or failed refresh. If the id changes, update the cache
    /// and suspend active watches for that owner/name in the same transaction.
    /// Retained events keep the id of the repository they were stored for;
    /// visibility uses their stored repository name and a live binding or consume
    /// grant, not the cache's replacement id.
    pub fn record_repo_id_resolution(
        &self,
        repo: &str,
        repo_id: Option<i64>,
        at_ms: i64,
    ) -> Result<RepoIdUpdate, StoreError> {
        self.inner
            .with_conn_fenced(|conn| record_repo_id_resolution_on_conn(conn, repo, repo_id, at_ms))
    }
}

pub(super) fn record_repo_id_resolution_on_conn(
    conn: &Connection,
    repo: &str,
    repo_id: Option<i64>,
    at_ms: i64,
) -> rusqlite::Result<RepoIdUpdate> {
    let old: Option<i64> = conn
        .query_row(
            "SELECT repo_id FROM github_repo_id_cache WHERE repo = lower(?1)",
            [repo],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    conn.execute("INSERT INTO github_repo_id_cache(repo, repo_id, last_attempt_at_ms, resolved_at_ms)
                VALUES (lower(?1), ?2, ?3, CASE WHEN ?2 IS NULL THEN NULL ELSE ?3 END)
                ON CONFLICT(repo) DO UPDATE SET repo_id = COALESCE(excluded.repo_id, repo_id),
                    last_attempt_at_ms = excluded.last_attempt_at_ms,
                    resolved_at_ms = CASE WHEN excluded.repo_id IS NULL THEN resolved_at_ms ELSE excluded.resolved_at_ms END",
                (repo, repo_id, at_ms))?;
    if let (Some(old_repo_id), Some(new_repo_id)) = (old, repo_id) {
        if old_repo_id != new_repo_id {
            let suspended = conn.execute("UPDATE trigger_subscriptions SET status = 'suspended',
                        suspended_reason = 'repository_identity_changed', generation = generation + 1
                        WHERE lower(json_extract(fixed_args, '$.owner') || '/' || json_extract(fixed_args, '$.repo')) = lower(?1)
                            AND status = 'active'", [repo])?;
            increment(conn, "repository_identity_changed", 1)?;
            crate::diag!(warn storage: "repository {repo} identity changed from {old_repo_id} to {new_repo_id}; suspended {suspended} watches");
            return Ok(RepoIdUpdate::IdentityChanged {
                old_repo_id,
                new_repo_id,
                suspended,
            });
        }
    }
    Ok(if repo_id.is_some() {
        RepoIdUpdate::Resolved
    } else {
        RepoIdUpdate::Failed
    })
}

fn pending_after_query(version: u8) -> String {
    let predicate = if version == 2 {
        "o.envelope_v2 IS NOT NULL AND o.published_v2_at_ms IS NULL"
    } else {
        "o.published_at_ms IS NULL"
    };
    let select = CANONICAL_SELECT.replace(
        "FROM event_outbox o",
        ", o.created_at_ms FROM event_outbox o",
    );
    format!("{select} WHERE {predicate} AND (o.created_at_ms,o.event_key)>(?2,?3) ORDER BY o.created_at_ms,o.event_key LIMIT ?1")
}

fn pending_query(version: u8) -> String {
    let pending = if version == 2 {
        "o.envelope_v2 IS NOT NULL AND o.published_v2_at_ms IS NULL"
    } else {
        "o.published_at_ms IS NULL"
    };
    // Seek from the smallest SQLite integer, including negative timestamps.
    // This gives both partial indexes a range search and preserves batch order.
    format!(
        "{CANONICAL_SELECT} WHERE {pending} AND o.created_at_ms >= ?2
        ORDER BY o.created_at_ms, o.event_key LIMIT ?1"
    )
}

/// Select at most one retention batch in SQLite, then delete that id set.
/// Publication, body-floor and cursor protections still contribute to the row
/// cap, but are never removed just to meet it. The caller owns the transaction.
pub(super) fn prune_events(
    conn: &Connection,
    principal: &str,
    subscription_id: &str,
    max_age_ms: i64,
    max_rows: usize,
    now: i64,
) -> rusqlite::Result<usize> {
    let mut query=conn.prepare(
        "WITH candidates AS (
            SELECT e.event_id,e.created_at_ms,e.observed_at_ms,
            e.acked_at_ms IS NULL AND (o.published_at_ms IS NULL OR (o.envelope_v2 IS NOT NULL AND o.published_v2_at_ms IS NULL)) AS undelivered,
            COALESCE((o.event_id IS NOT NULL AND (o.published_at_ms IS NULL OR (o.envelope_v2 IS NOT NULL AND o.published_v2_at_ms IS NULL)))
            OR max(e.created_at_ms,COALESCE(o.published_at_ms,e.created_at_ms),COALESCE(o.published_v2_at_ms,e.created_at_ms))>?3
            OR (e.activity_at_ms IS NOT NULL AND ((s.cursor_kind='ordered_timestamp' AND e.activity_at_ms>=json_extract(s.cursor_state,'$.watermark_ms')-?4)
                OR (s.cursor_kind='sorted_head' AND e.activity_at_ms>=json_extract(s.cursor_state,'$.watermark_ms')))),0) AS protected
            FROM trigger_events e LEFT JOIN event_outbox o ON o.event_id=e.event_id
            LEFT JOIN trigger_subscriptions s ON s.subscription_id=e.subscription_id
            WHERE e.principal=?1 AND e.subscription_id=?2
        ), stats AS (
            SELECT count(*) AS total,COALESCE(sum(NOT protected AND created_at_ms<?5),0) AS aged FROM candidates
        ), ranked AS (
            SELECT *,sum(created_at_ms>=?5) OVER (ORDER BY created_at_ms,event_id) AS recent_ordinal
            FROM candidates WHERE NOT protected
        )
        SELECT event_id,observed_at_ms,undelivered FROM ranked,stats
        WHERE created_at_ms<?5 OR recent_ordinal<=max(0,total-aged-?6)
        ORDER BY created_at_ms,event_id LIMIT 1000"
    )?;
    let rows = query
        .query_map(
            rusqlite::params![
                principal,
                subscription_id,
                now.saturating_sub(EVENT_BODY_FLOOR_MS),
                RETENTION_MAX_WINDOW_MS,
                now.saturating_sub(max_age_ms.max(0)),
                i64::try_from(max_rows).unwrap_or(i64::MAX)
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(query);
    let interval = rows
        .iter()
        .filter(|row| row.2)
        .fold((None, None), |interval, row| {
            merge_intervals(interval, (Some(row.1), Some(row.1)))
        });
    let ids: Vec<_> = rows.iter().map(|row| &row.0).collect();
    let mut removed = 0;
    for chunk in ids.chunks(900) {
        let keys = (1..=chunk.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(",");
        preserve_overlapping_markers(
            conn,
            &format!("event_id IN ({keys})"),
            rusqlite::params_from_iter(chunk.iter()),
        )?;
        conn.execute(
            &format!("DELETE FROM event_outbox WHERE event_id IN ({keys})"),
            rusqlite::params_from_iter(chunk.iter()),
        )?;
        removed += conn.execute(
            &format!("DELETE FROM trigger_events WHERE event_id IN ({keys})"),
            rusqlite::params_from_iter(chunk.iter()),
        )?;
    }
    if let (Some(from), Some(to)) = interval {
        let connection:Option<String>=conn.query_row("SELECT connection_id FROM trigger_subscriptions WHERE principal=?1 AND subscription_id=?2",(principal,subscription_id),|row|row.get(0)).optional()?;
        if let Some(connection) = connection {
            insert_gap_row(
                conn,
                principal,
                &connection,
                subscription_id,
                from,
                to,
                "retention_pruned",
                now,
            )?;
        }
    }
    Ok(removed)
}

fn require_active(
    conn: &Connection,
    principal: &str,
    subscription_id: &str,
) -> rusqlite::Result<()> {
    let active: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM trigger_subscriptions
        WHERE principal = ?1 AND subscription_id = ?2 AND status = 'active')",
        (principal, subscription_id),
        |r| r.get(0),
    )?;
    if active {
        Ok(())
    } else {
        Err(rusqlite::Error::QueryReturnedNoRows)
    }
}

/// Most GitHub Actions requests plexus sends in any trailing hour, including
/// repository id lookups. Every GitHub read plexus makes, and every agent's
/// `gh` read, share one personal token whose REST quota is 5,000 an hour, so
/// CI polling is held to a small share of it. A cycle that would go over is
/// deferred, which delays CI failure reports rather than losing them. Webhooks
/// will replace most of this polling.
pub(crate) const GITHUB_ACTIONS_HOURLY_REQUESTS: i64 = 600;

/// Requests one CI polling cycle reserves against that hourly limit.
pub(crate) const CI_CYCLE_REQUESTS: i64 = 8;

pub(super) fn effective_ci_ceiling(conn: &Connection) -> rusqlite::Result<i64> {
    let names: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT
        lower(json_extract(fixed_args, '$.owner') || '/' || json_extract(fixed_args, '$.repo')))
        FROM trigger_subscriptions WHERE status = 'active' AND json_valid(fixed_args)
        AND json_extract(fixed_args, '$.owner') IS NOT NULL
        AND json_extract(fixed_args, '$.repo') IS NOT NULL",
        [],
        |row| row.get(0),
    )?;
    Ok(GITHUB_ACTIONS_HOURLY_REQUESTS.saturating_sub(names).max(0))
}

fn quota_admit(
    conn: &Connection,
    request: QuotaRequest,
    now: i64,
) -> rusqlite::Result<QuotaAdmission> {
    conn.execute(
        "DELETE FROM github_actions_quota WHERE reserved_at_ms < ?1",
        [now.saturating_sub(QUOTA_WINDOW_MS)],
    )?;
    let used: i64 = conn.query_row(
        "SELECT COALESCE(SUM(requests), 0) FROM github_actions_quota",
        [],
        |r| r.get(0),
    )?;
    let (requests, ceiling) = match request {
        QuotaRequest::CiCycle => {
            // A cached id outlives the watches that resolved it. Only a repository
            // that something still watches will ever be re-resolved, so only
            // those may hold back hourly requests from CI polling; counting every
            // repository ever cached would shrink the CI share for good. The
            // stale rows are deleted here as well, keeping a suspended watch's
            // row so its recorded identity can still be compared.
            conn.execute(
                "DELETE FROM github_repo_id_cache WHERE repo NOT IN (
                    SELECT lower(json_extract(fixed_args, '$.owner') || '/' || json_extract(fixed_args, '$.repo'))
                    FROM trigger_subscriptions WHERE status <> 'retired' AND json_valid(fixed_args)
                        AND json_extract(fixed_args, '$.owner') IS NOT NULL
                        AND json_extract(fixed_args, '$.repo') IS NOT NULL)",
                [],
            )?;
            (CI_CYCLE_REQUESTS, effective_ci_ceiling(conn)?)
        }
        QuotaRequest::GetRepository => (1, GITHUB_ACTIONS_HOURLY_REQUESTS),
        QuotaRequest::FlowRead => (1, GITHUB_ACTIONS_HOURLY_REQUESTS),
    };
    if used + requests > ceiling {
        let mut remaining = used;
        let mut statement = conn.prepare("SELECT reserved_at_ms, SUM(requests) FROM github_actions_quota GROUP BY reserved_at_ms ORDER BY reserved_at_ms")?;
        let expirations =
            statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        for expiration in expirations {
            let (reserved_at_ms, units) = expiration?;
            remaining -= units;
            if remaining + requests <= ceiling {
                // Admission removes rows strictly older than the hour, so the
                // first admissible millisecond is one past their expiry.
                return Ok(QuotaAdmission::Deferred {
                    retry_at_ms: reserved_at_ms
                        .saturating_add(QUOTA_WINDOW_MS)
                        .saturating_add(1),
                });
            }
        }
        // More watched repositories than the CI allowance can support means
        // expiration alone cannot admit a cycle. Re-evaluate that topology on
        // the next quota window rather than retrying every scheduler tick.
        return Ok(QuotaAdmission::Deferred {
            retry_at_ms: now.saturating_add(QUOTA_WINDOW_MS).saturating_add(1),
        });
    }
    let reservation_id = new_id("actions-quota");
    conn.execute(
        "INSERT INTO github_actions_quota VALUES (?1, ?2, ?3)",
        (&reservation_id, now, requests),
    )?;
    Ok(QuotaAdmission::Reserved {
        reservation_id,
        requests,
    })
}

fn cache_entry(conn: &Connection, repo: &str) -> rusqlite::Result<Option<RepoIdCacheEntry>> {
    conn.query_row(
        "SELECT repo, repo_id, last_attempt_at_ms, resolved_at_ms
        FROM github_repo_id_cache WHERE repo = lower(?1)",
        [repo],
        |r| {
            Ok(RepoIdCacheEntry {
                repo: r.get(0)?,
                repo_id: r.get(1)?,
                last_attempt_at_ms: r.get(2)?,
                resolved_at_ms: r.get(3)?,
            })
        },
    )
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "90408920809451f415f29865340b3b6d57d032c1d13f5a8d2062742300645740";

    #[test]
    fn overlapping_watch_keeps_pending_publication_after_canonical_withdrawal() {
        for delete_connection in [false, true] {
            for published in [false, true] {
                let store = store();
                for id in ["a", "b"] {
                    store
                        .insert_connection("direct", id, "fixture", "active", &json!({}))
                        .unwrap();
                    subscription(&store, id, "ordered_timestamp");
                    store
                        .set_subscription_project("direct", id, Some(id))
                        .unwrap();
                    commit(
                        &store,
                        id,
                        &[input(&json!({"number":7,"title":id}), KEY, &headers(id))],
                    );
                }
                grant(
                    &store,
                    "consume-b",
                    "consumer",
                    "b",
                    "direct",
                    "[\"list_issues\"]",
                    None,
                );
                let original = store.canonical_event_by_key(KEY).unwrap().unwrap();
                if published {
                    for version in [1, 2] {
                        store
                            .mark_event_version_published(KEY, version, 1234)
                            .unwrap();
                    }
                }
                if delete_connection {
                    store.revoke_connection("direct", "a").unwrap();
                    assert!(matches!(
                        store.delete_connection("direct", "a", true).unwrap(),
                        DeleteConnectionOutcome::Deleted { .. }
                    ));
                } else {
                    assert!(store.unsubscribe("direct", "a").unwrap());
                }
                for version in [1, 2] {
                    let EventLookupOutcome::Found(event) = store
                        .event_by_key_version(
                            KEY,
                            EventReader::Consumer {
                                principal: "consumer",
                            },
                            now_ms(),
                            version,
                        )
                        .unwrap()
                    else {
                        panic!("surviving watch must retain canonical visibility");
                    };
                    assert_eq!(event.subscription_id, "b");
                    assert_eq!(
                        event.body, original.body,
                        "transfer must not rebuild canonical v1 bytes"
                    );
                    assert_eq!(event.digest, original.digest);
                    assert_eq!(
                        event.envelope_v2, original.envelope_v2,
                        "transfer must not rebuild canonical v2 bytes"
                    );
                    assert_eq!(event.digest_v2, original.digest_v2);
                    assert_eq!(event.headers, original.headers);
                    assert_eq!(
                        store.drain_event_outbox_version(10, version).unwrap().len(),
                        usize::from(!published),
                        "surviving overlapping watch must keep its pending publication"
                    );
                }
                let health = store.event_outbox_health().unwrap();
                assert_eq!(health.dropped_on_unsubscribe + health.dropped_on_delete, 0);
            }
        }
    }

    #[test]
    fn legacy_v1_lookup_keeps_original_bytes_and_refuses_unrecoverable_transfer() {
        let store = store();
        for id in ["a", "b"] {
            subscription(&store, id, "ordered_timestamp");
            commit(
                &store,
                id,
                &[input(&json!({"number":7,"title":id}), KEY, &headers("p"))],
            );
            grant(
                &store,
                &format!("consume-{id}"),
                "consumer",
                id,
                "direct",
                "[\"list_issues\"]",
                None,
            );
        }
        let original = store.canonical_event_by_key(KEY).unwrap().unwrap();
        for version in [1, 2] {
            store
                .mark_event_version_published(KEY, version, 1234)
                .unwrap();
        }
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute("UPDATE event_outbox SET body_v1=NULL,digest_v1=NULL", [])
            })
            .unwrap();
        let EventLookupOutcome::Found(before) = store
            .event_by_key(
                KEY,
                EventReader::Consumer {
                    principal: "consumer",
                },
                now_ms(),
            )
            .unwrap()
        else {
            panic!("ordinary legacy v1 must work without backfill");
        };
        assert_eq!(before.body, original.body);
        // Some legacy stores have already lost the original source body. The
        // surviving watch's different copy cannot satisfy a published digest.
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "UPDATE trigger_events SET payload='' WHERE subscription_id='a'",
                    [],
                )
            })
            .unwrap();
        store.unsubscribe("direct", "a").unwrap();
        assert!(
            matches!(
                store
                    .event_by_key(
                        KEY,
                        EventReader::Consumer {
                            principal: "consumer"
                        },
                        now_ms()
                    )
                    .unwrap(),
                EventLookupOutcome::NotVisible
            ),
            "unrecoverable legacy v1 must never substitute the surviving body"
        );
        let EventLookupOutcome::Found(v2) = store
            .event_by_key_version(
                KEY,
                EventReader::Consumer {
                    principal: "consumer",
                },
                now_ms(),
                2,
            )
            .unwrap()
        else {
            panic!("legacy v2 bytes remain available");
        };
        assert_eq!(v2.envelope_v2, original.envelope_v2);
        assert_eq!(v2.digest_v2, original.digest_v2);
    }

    #[test]
    fn keyset_drain_pages_ties_strictly_and_uses_partial_searches() {
        let store = store();
        subscription(&store, "a", "ordered_timestamp");
        for n in 1..=5 {
            commit(
                &store,
                "a",
                &[input(
                    &json!({"number":n}),
                    &format!("{n:064x}"),
                    &headers("p"),
                )],
            );
        }
        store
            .inner
            .with_conn_fenced(|conn| conn.execute("UPDATE event_outbox SET created_at_ms=7", []))
            .unwrap();
        for version in [1, 2] {
            let first = store
                .drain_event_outbox_version_after(2, version, None)
                .unwrap();
            let second = store
                .drain_event_outbox_version_after(2, version, Some(&first[1].1))
                .unwrap();
            let third = store
                .drain_event_outbox_version_after(2, version, Some(&second[1].1))
                .unwrap();
            assert_eq!(
                third.len(),
                1,
                "keyset pages must neither skip nor repeat tied timestamps"
            );
            let keys: Vec<_> = first
                .iter()
                .chain(&second)
                .chain(&third)
                .map(|(_, cursor)| cursor.event_key.clone())
                .collect();
            assert_eq!(
                keys,
                (1..=5).map(|n| format!("{n:064x}")).collect::<Vec<_>>()
            );
            assert!(store
                .drain_event_outbox_version_after(2, version, Some(&third[0].1))
                .unwrap()
                .is_empty());
            let plan = store
                .inner
                .with_read(|conn| {
                    let mut query = conn.prepare(&format!(
                        "EXPLAIN QUERY PLAN {}",
                        pending_after_query(version)
                    ))?;
                    let rows = query
                        .query_map(rusqlite::params![2, 7, first[1].1.event_key], |row| {
                            row.get::<_, String>(3)
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(rows.join("; "))
                })
                .unwrap();
            println!("keyset v{version}: {plan}");
            assert!(
                plan.contains(&format!(
                    "SEARCH o USING INDEX idx_event_outbox_pending_v{version}"
                )),
                "keyset drain must SEARCH the ordered partial index: {plan}"
            );
            assert!(!plan.contains("TEMP B-TREE"));
        }
    }

    fn store() -> PlexusStore {
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: new_id("outbox-test"),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap()
    }

    fn subscription(store: &PlexusStore, id: &str, kind: &str) {
        store.inner.with_conn_fenced(|conn| {
            conn.execute("INSERT INTO trigger_subscriptions
                (subscription_id, principal, connection_id, action, cadence_s, cursor_kind, cursor_state, schema_hash, status, created_at_ms, fixed_args)
                VALUES (?1, 'direct', ?1, 'list_issues', 300, ?2, '{\"watermark_ms\":10000000}', 'hash', 'active', 1, '{\"owner\":\"OWNER\",\"repo\":\"Repo\"}')", (id, kind))?;
            Ok(())
        }).unwrap();
    }

    fn headers(project: &str) -> EventHeaders {
        EventHeaders {
            repo: "OWNER/Repo".into(),
            project: Some(project.into()),
            pr: Some("7".into()),
            branch: None,
            conclusion: None,
        }
    }

    fn input<'a>(
        payload: &'a Value,
        key: &'a str,
        headers: &'a EventHeaders,
    ) -> KeyedPollEventInput<'a> {
        KeyedPollEventInput {
            event: PollEventInput {
                vendor_event_id: "7",
                payload,
                observed_at_ms: 100,
                item_kind: Some("issue"),
                activity_at_ms: Some(100),
                actor: &ActorAttribution::NotEnriched,
            },
            identity: Some(KeyedEventIdentity {
                event_key: key,
                event_name: "github_issue_changed",
                repo_id: 101,
                change: Some("updated"),
                headers,
            }),
            delivery_id: None,
            envelope_context: Default::default(),
        }
    }

    fn commit(
        store: &PlexusStore,
        sub: &str,
        inputs: &[KeyedPollEventInput<'_>],
    ) -> Vec<TriggerEventInsertOutcome> {
        store
            .commit_keyed_poll_success(
                "direct",
                sub,
                sub,
                &json!({"watermark_ms": 10000000}),
                inputs,
                1234,
                &[],
            )
            .unwrap()
    }

    fn count(store: &PlexusStore, table: &str) -> i64 {
        store
            .inner
            .with_conn(|conn| {
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            })
            .unwrap()
    }

    #[test]
    fn denied_lookup_never_selects_payload() {
        let store = store();
        subscription(&store, "a", "ordered_timestamp");
        commit(
            &store,
            "a",
            &[input(&json!({"large": "body"}), KEY, &headers("p"))],
        );
        store
            .inner
            .with_conn(|conn| {
                let query = conn.prepare(LOOKUP_METADATA)?;
                assert_eq!(
                    query.column_names(),
                    ["repo", "principal", "connection_id", "subscription_id"],
                    "access metadata must never select payload"
                );
                // A blob cannot be decoded as a String by canonical_row. Denial
                // must still succeed without attempting to decode or hash it.
                conn.execute("UPDATE trigger_events SET payload = X'ff'", [])?;
                Ok(())
            })
            .unwrap();
        for reader in [
            EventReader::Agent { agent_id: "absent" },
            EventReader::Consumer {
                principal: "reserved:prefrontal-core",
            },
        ] {
            assert!(matches!(
                store.event_by_key(KEY, reader, 1234).unwrap(),
                EventLookupOutcome::NotVisible
            ));
        }
    }

    #[test]
    fn colliding_batch_keeps_one_marker_and_advances_with_multiple_gaps() {
        let store = store();
        subscription(&store, "a", "ordered_timestamp");
        let h = headers("first");
        let one = json!({"number": 7, "value": 1});
        let two = json!({"number": 7, "value": 2});
        let inputs = [input(&one, KEY, &h), input(&two, KEY, &h)];
        let gaps = [
            PollGapInput {
                from_ms: 1,
                to_ms: 2,
                reason: "ci_runs_outage",
            },
            PollGapInput {
                from_ms: 3,
                to_ms: 4,
                reason: "ci_runs_page_cap",
            },
        ];
        let outcomes = store
            .commit_keyed_poll_success(
                "direct",
                "a",
                "a",
                &json!({"advanced": true}),
                &inputs,
                1234,
                &gaps,
            )
            .unwrap();
        assert!(matches!(
            outcomes[0],
            TriggerEventInsertOutcome::Inserted { .. }
        ));
        assert!(matches!(
            outcomes[1],
            TriggerEventInsertOutcome::Duplicate { .. }
        ));
        assert_eq!(count(&store, "trigger_events"), 3);
        assert_eq!(count(&store, "event_outbox"), 1);
        let cursor: String = store
            .inner
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT cursor_state FROM trigger_subscriptions WHERE subscription_id='a'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(cursor, "{\"advanced\":true}");
        let row = store.canonical_event_by_key(KEY).unwrap().unwrap();
        assert_eq!(row.body, "{\"number\":7,\"value\":1}");
        assert_eq!(
            row.digest,
            "997710638e7fd5695aa94a6168bd83b787166d80b7e0ce29635d6e1002d35f16"
        );
        assert_eq!(row.change.as_deref(), Some("updated"));
        assert!(!row.body.contains("change"));
        let duplicate = commit(&store, "a", &[input(&two, KEY, &h)]);
        assert!(matches!(
            duplicate[0],
            TriggerEventInsertOutcome::Duplicate { .. }
        ));
        assert_eq!(count(&store, "event_outbox"), 1);
    }

    #[test]
    fn failed_keyed_commit_rolls_back_events_markers_gaps_and_cursor() {
        let store = store();
        subscription(&store, "a", "probe");
        let h = headers("p");
        let body = json!({"number": 7});
        let mut bad = input(&body, KEY, &h);
        bad.event.vendor_event_id = " ";
        assert!(store
            .commit_keyed_poll_success(
                "direct",
                "a",
                "a",
                &json!({"changed": true}),
                &[input(&body, KEY, &h), bad],
                1,
                &[PollGapInput {
                    from_ms: 0,
                    to_ms: 1,
                    reason: "gap"
                }]
            )
            .is_err());
        assert_eq!(count(&store, "event_outbox"), 0);
        assert_eq!(count(&store, "trigger_events"), 0);
        let cursor: String = store
            .inner
            .with_conn(|conn| {
                conn.query_row("SELECT cursor_state FROM trigger_subscriptions", [], |r| {
                    r.get(0)
                })
            })
            .unwrap();
        assert_eq!(cursor, "{\"watermark_ms\":10000000}");
    }

    #[test]
    fn first_inserter_owns_headers_body_and_visibility_in_either_order() {
        for (first, second) in [("a", "b"), ("b", "a")] {
            let store = store();
            subscription(&store, "a", "sorted_head");
            subscription(&store, "b", "sorted_head");
            let h1 = headers(first);
            let h2 = headers(second);
            let body1 = json!({"first": first});
            let body2 = json!({"second": second});
            commit(&store, first, &[input(&body1, KEY, &h1)]);
            commit(&store, second, &[input(&body2, KEY, &h2)]);
            assert_eq!(count(&store, "trigger_events"), 2);
            assert_eq!(count(&store, "event_outbox"), 1);
            let row = store.canonical_event_by_key(KEY).unwrap().unwrap();
            assert_eq!(row.subscription_id, first);
            assert_eq!(row.headers.project.as_deref(), Some(first));
            assert_eq!(row.body, serde_json::to_string(&body1).unwrap());
            assert_eq!(store.event_outbox_health().unwrap().overlapping_key_rows, 1);
            grant(
                &store,
                "grant",
                "consumer",
                second,
                "direct",
                "[\"list_issues\"]",
                None,
            );
            assert_eq!(
                store
                    .event_by_key(
                        KEY,
                        EventReader::Consumer {
                            principal: "consumer"
                        },
                        1
                    )
                    .unwrap(),
                EventLookupOutcome::NotVisible
            );
            grant(
                &store,
                "grant-first",
                "consumer",
                first,
                "direct",
                "[\"list_issues\"]",
                None,
            );
            assert!(matches!(
                store
                    .event_by_key(
                        KEY,
                        EventReader::Consumer {
                            principal: "consumer"
                        },
                        1
                    )
                    .unwrap(),
                EventLookupOutcome::Found(_)
            ));
            store.inner.with_conn_fenced(|conn| conn.execute("UPDATE trigger_subscriptions SET status='suspended' WHERE subscription_id=?1", [first]).map(|_| ())).unwrap();
            assert_eq!(store.event_outbox_health().unwrap().overlapping_key_rows, 0);
        }
    }

    #[test]
    fn legacy_dedup_runs_before_keys_and_change_never_enters_body() {
        let store = store();
        subscription(&store, "a", "ordered_timestamp");
        let body = json!({"number": 7, "updated_at": "2026-10-07T00:00:00Z"});
        let h = headers("p");
        store
            .insert_event("direct", "a", "a", "7", &body, 100)
            .unwrap();
        assert!(matches!(
            commit(&store, "a", &[input(&body, KEY, &h)])[0],
            TriggerEventInsertOutcome::Duplicate { .. }
        ));
        assert_eq!(count(&store, "trigger_events"), 1);
        assert_eq!(count(&store, "event_outbox"), 0);
        let changed = json!({"number": 7, "updated_at": "2026-10-07T00:00:01Z"});
        commit(&store, "a", &[input(&changed, KEY, &h)]);
        assert_eq!(
            store.canonical_event_by_key(KEY).unwrap().unwrap().body,
            serde_json::to_string(&changed).unwrap()
        );
    }

    #[test]
    fn delivery_id_is_unique_when_present() {
        let store = store();
        subscription(&store, "a", "probe");
        subscription(&store, "b", "probe");
        let h = headers("p");
        let body = json!({"x": 1});
        let body2 = json!({"x": 2});
        let mut one = input(&body, KEY, &h);
        one.delivery_id = Some("delivery");
        commit(&store, "a", &[one]);
        let mut two = input(&body2, KEY, &h);
        two.delivery_id = Some("delivery");
        assert!(matches!(
            commit(&store, "b", &[two])[0],
            TriggerEventInsertOutcome::Duplicate { .. }
        ));
        assert_eq!(count(&store, "trigger_events"), 1);
    }

    #[test]
    fn schema_indices_enforce_nullable_key_and_delivery_uniqueness() {
        let store = store();
        subscription(&store, "a", "probe");
        for id in ["one", "two", "three"] {
            store
                .insert_event("direct", "a", "a", id, &json!({"id": id}), 1)
                .unwrap();
        }
        store.inner.with_conn_fenced(|conn| {
            conn.execute("UPDATE trigger_events SET event_key=?1, delivery_id='delivery' WHERE vendor_event_id='one'", [KEY])?;
            assert!(conn.execute("UPDATE trigger_events SET event_key=?1 WHERE vendor_event_id='two'", [KEY]).is_err(), "partial key index must reject a same-subscription collision");
            assert!(conn.execute("UPDATE trigger_events SET delivery_id='delivery' WHERE vendor_event_id='two'", []).is_err(), "delivery index must reject a duplicate delivery id");
            assert_eq!(conn.query_row("SELECT COUNT(*) FROM trigger_events WHERE event_key IS NULL AND delivery_id IS NULL", [], |r| r.get::<_, i64>(0))?, 2);
            Ok(())
        }).unwrap();
    }

    fn grant(
        store: &PlexusStore,
        id: &str,
        grantee: &str,
        connection: &str,
        owner: &str,
        selectors: &str,
        expires: Option<i64>,
    ) {
        store.inner.with_conn_fenced(|conn| conn.execute("INSERT INTO grants
            (grant_id, principal, connection_id, grantee_principal, risk_ceiling, action_selectors, authority_kind, expires_at, created_at_ms)
            VALUES (?1, ?2, ?3, ?4, 'read', ?5, 'events_consume', ?6, 0)",
            rusqlite::params![id, owner, connection, grantee, selectors, expires]).map(|_| ())).unwrap();
    }

    #[test]
    fn consumer_lookup_requires_owner_connection_selector_and_live_grant() {
        let store = store();
        subscription(&store, "a", "probe");
        let h = headers("p");
        let body = json!({"number": 7});
        commit(&store, "a", &[input(&body, KEY, &h)]);
        for (id, connection, owner, selectors, expires) in [
            ("owner", "a", "other", "[\"list_issues\"]", None),
            ("connection", "other", "direct", "[\"list_issues\"]", None),
            ("selector", "a", "direct", "[\"other\"]", None),
            ("expired", "a", "direct", "[\"list_issues\"]", Some(1)),
            ("empty", "a", "direct", "[]", None),
        ] {
            grant(
                &store, id, "consumer", connection, owner, selectors, expires,
            );
        }
        assert_eq!(
            store
                .event_by_key(
                    KEY,
                    EventReader::Consumer {
                        principal: "consumer"
                    },
                    2
                )
                .unwrap(),
            EventLookupOutcome::NotVisible
        );
        grant(
            &store,
            "yes",
            "consumer",
            "a",
            "direct",
            "[\"list_issues\"]",
            None,
        );
        let EventLookupOutcome::Found(row) = store
            .event_by_key(
                KEY,
                EventReader::Consumer {
                    principal: "consumer",
                },
                2,
            )
            .unwrap()
        else {
            panic!("grant must serve canonical body");
        };
        assert_eq!(row.headers.repo, "owner/repo");
        store
            .ack_events("direct", std::slice::from_ref(&row.event_id))
            .unwrap();
        let EventLookupOutcome::Found(acked) = store
            .event_by_key(
                KEY,
                EventReader::Consumer {
                    principal: "consumer",
                },
                2,
            )
            .unwrap()
        else {
            panic!("ack must retain body");
        };
        assert_eq!(acked.body, row.body);
        assert_eq!(acked.digest, row.digest);
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "DELETE FROM trigger_subscriptions WHERE subscription_id='a'",
                    [],
                )
                .map(|_| ())
            })
            .unwrap();
        assert_eq!(
            store
                .event_by_key(
                    KEY,
                    EventReader::Consumer {
                        principal: "consumer"
                    },
                    2
                )
                .unwrap(),
            EventLookupOutcome::NotVisible
        );
    }

    #[test]
    fn agent_lookup_uses_case_insensitive_live_binding_not_repo_id_cache() {
        let store = store();
        subscription(&store, "a", "probe");
        let h = headers("p");
        let body = json!({"number": 7});
        commit(&store, "a", &[input(&body, KEY, &h)]);
        store.inner.with_conn_fenced(|conn| conn.execute_batch("INSERT INTO github_app_handle
            (app_handle_id, agent_id, app_id, credential_reference, status, connection_principal, connection_id)
            VALUES ('handle','agent-a',1,'github_app:reference','enabled','direct','handle-connection');
            INSERT INTO github_repo_binding VALUES ('OwNeR/RePo','handle');")).unwrap();
        assert!(matches!(
            store
                .event_by_key(
                    KEY,
                    EventReader::Agent {
                        agent_id: "agent-a"
                    },
                    1
                )
                .unwrap(),
            EventLookupOutcome::Found(_)
        ));
        assert_eq!(
            store
                .event_by_key(
                    KEY,
                    EventReader::Agent {
                        agent_id: "agent-b"
                    },
                    1
                )
                .unwrap(),
            EventLookupOutcome::NotVisible
        );
        store
            .record_repo_id_resolution("OWNER/REPO", Some(101), 1)
            .unwrap();
        assert_eq!(
            store
                .record_repo_id_resolution("owner/repo", Some(202), 2)
                .unwrap(),
            RepoIdUpdate::IdentityChanged {
                old_repo_id: 101,
                new_repo_id: 202,
                suspended: 1
            }
        );
        assert!(matches!(
            store
                .event_by_key(
                    KEY,
                    EventReader::Agent {
                        agent_id: "agent-a"
                    },
                    1
                )
                .unwrap(),
            EventLookupOutcome::Found(event) if event.repo_id == 101
        ));
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute("UPDATE github_app_handle SET status='disabled'", [])
                    .map(|_| ())
            })
            .unwrap();
        assert_eq!(
            store
                .event_by_key(
                    KEY,
                    EventReader::Agent {
                        agent_id: "agent-a"
                    },
                    1
                )
                .unwrap(),
            EventLookupOutcome::NotVisible
        );
        store.inner.with_conn_fenced(|conn| conn.execute_batch("UPDATE github_app_handle SET status='enabled'; DELETE FROM github_repo_binding;")).unwrap();
        assert_eq!(
            store
                .event_by_key(
                    KEY,
                    EventReader::Agent {
                        agent_id: "agent-a"
                    },
                    1
                )
                .unwrap(),
            EventLookupOutcome::NotVisible
        );
    }

    #[test]
    fn identity_change_suspends_active_repo_watches_and_preserves_other_states() {
        let store = store();
        let active = [
            ("issues", "ordered_timestamp", "list_issues", 10),
            ("prs", "sorted_head", "list_pull_requests", 20),
            ("releases", "scalar_diff", "get_latest_release", 30),
            ("ci", "ci_runs", "list_workflow_runs", 40),
        ];
        for (id, kind, action, generation) in active {
            subscription(&store, id, kind);
            store
                .inner
                .with_conn_fenced(|conn| {
                    conn.execute(
                        "UPDATE trigger_subscriptions SET action = ?2, generation = ?3
                    WHERE subscription_id = ?1",
                        (id, action, generation),
                    )
                    .map(|_| ())
                })
                .unwrap();
        }
        subscription(&store, "other-repo", "ordered_timestamp");
        subscription(&store, "already-suspended", "sorted_head");
        store.inner.with_conn_fenced(|conn| conn.execute_batch(
            "UPDATE trigger_subscriptions SET fixed_args = '{\"owner\":\"Owner\",\"repo\":\"Else\"}',
                generation = 50 WHERE subscription_id = 'other-repo';
             UPDATE trigger_subscriptions SET status = 'suspended', suspended_reason = 'schema_hash_changed',
                generation = 60 WHERE subscription_id = 'already-suspended';"
        )).unwrap();

        let read_states = |repo: &str| {
            store.inner.with_conn(|conn| {
                let mut query = conn.prepare("SELECT subscription_id, status, suspended_reason, generation
                    FROM trigger_subscriptions
                    WHERE lower(json_extract(fixed_args, '$.owner') || '/' || json_extract(fixed_args, '$.repo')) = lower(?1)")?;
                let states = query.query_map([repo], |row| Ok((row.get(0)?, (row.get(1)?, row.get(2)?, row.get(3)?))))?
                    .collect::<rusqlite::Result<std::collections::BTreeMap<String, (String, Option<String>, i64)>>>() ;
                states
            }).unwrap()
        };
        assert_eq!(
            store
                .record_repo_id_resolution("owner/repo", Some(101), 1)
                .unwrap(),
            RepoIdUpdate::Resolved
        );
        let before = read_states("OWNER/Repo");
        assert_eq!(before.len(), 5);
        for (id, _, _, generation) in active {
            assert_eq!(
                before.get(id).unwrap(),
                &("active".into(), None, generation)
            );
        }
        let other_before = read_states("owner/else");
        assert_eq!(
            other_before.get("other-repo").unwrap(),
            &("active".into(), None, 50)
        );

        assert_eq!(
            store
                .record_repo_id_resolution("OwNeR/rEpO", Some(202), 2)
                .unwrap(),
            RepoIdUpdate::IdentityChanged {
                old_repo_id: 101,
                new_repo_id: 202,
                suspended: 4
            }
        );
        // SQLite's UPDATE count proves only that rows matched. Read the persisted
        // effects so an assignment that keeps the old status cannot pass.
        let after = read_states("owner/repo");
        assert_eq!(after.len(), 5);
        for (id, _, _, _) in active {
            let (status, reason, generation) = after.get(id).unwrap();
            assert_eq!(
                status, "suspended",
                "identity change must suspend every active watch for the repository: {id}"
            );
            assert_eq!(
                reason.as_deref(),
                Some("repository_identity_changed"),
                "identity change must record its suspension reason: {id}"
            );
            assert_eq!(
                *generation,
                before.get(id).unwrap().2 + 1,
                "identity change must advance each affected generation exactly once: {id}"
            );
        }
        assert_eq!(
            after.get("already-suspended").unwrap(),
            &("suspended".into(), Some("schema_hash_changed".into()), 60),
            "already-suspended watches must keep their original reason and generation"
        );
        assert_eq!(
            read_states("OWNER/Else"),
            other_before,
            "identity change must not alter a different repository's active watch"
        );
    }

    #[test]
    fn drain_restarts_with_same_key_and_retention_deletes_orphans_once() {
        let store = store();
        subscription(&store, "a", "probe");
        let h = headers("p");
        let body = json!({"number": 7});
        commit(&store, "a", &[input(&body, KEY, &h)]);
        let first = store.drain_event_outbox(10).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(store.drain_event_outbox(10).unwrap(), first);
        assert!(store.mark_event_published(KEY, 100).unwrap());
        assert!(!store.mark_event_published(KEY, 101).unwrap());
        assert!(store.drain_event_outbox(10).unwrap().is_empty());
        store
            .inner
            .with_conn_fenced(|conn| conn.execute("DELETE FROM trigger_events", []).map(|_| ()))
            .unwrap();
        assert_eq!(
            store
                .event_by_key(KEY, EventReader::Agent { agent_id: "a" }, 1)
                .unwrap(),
            EventLookupOutcome::NotFound
        );
        assert!(store.drain_event_outbox(10).unwrap().is_empty());
        assert_eq!(
            count(&store, "event_outbox"),
            1,
            "drain must not delete orphaned markers"
        );
        store
            .prune("direct", "a", EVENT_BODY_FLOOR_MS, 100)
            .unwrap();
        assert_eq!(count(&store, "event_outbox"), 0);
        assert_eq!(store.event_outbox_health().unwrap().orphaned_markers, 1);
        store
            .prune("direct", "a", EVENT_BODY_FLOOR_MS, 100)
            .unwrap();
        assert_eq!(store.event_outbox_health().unwrap().orphaned_markers, 1);
    }

    #[test]
    fn idle_and_pending_drains_are_read_only() {
        let store = store();
        subscription(&store, "a", "probe");
        commit(
            &store,
            "a",
            &[input(&json!({"number": 7}), KEY, &headers("p"))],
        );
        store
            .inner
            .with_conn(|conn| conn.execute_batch("PRAGMA query_only=ON"))
            .unwrap();
        for version in [1, 2] {
            assert_eq!(
                store
                    .drain_event_outbox_version(50, version)
                    .expect("pending drain must be read-only")
                    .len(),
                1
            );
        }
        assert!(
            store.mark_event_published(KEY, 1).is_err(),
            "positive control: query_only must refuse the fenced writer"
        );
        store
            .inner
            .with_conn(|conn| conn.execute_batch("PRAGMA query_only=OFF"))
            .unwrap();
        store.mark_event_version_published(KEY, 1, 1).unwrap();
        store.mark_event_version_published(KEY, 2, 1).unwrap();
        store
            .inner
            .with_conn(|conn| conn.execute_batch("PRAGMA query_only=ON"))
            .unwrap();
        for version in [1, 2] {
            assert!(store
                .drain_event_outbox_version(50, version)
                .expect("idle drain must be read-only")
                .is_empty());
        }
    }

    #[test]
    fn pending_queries_search_partial_indexes_without_sorting() {
        let store = store();
        subscription(&store, "a", "probe");
        commit(
            &store,
            "a",
            &[input(&json!({"number": 7}), KEY, &headers("p"))],
        );
        store
            .inner
            .with_conn(|conn| {
                for version in [1, 2] {
                    let plan = conn
                        .prepare(&format!("EXPLAIN QUERY PLAN {}", pending_query(version)))?
                        .query_map(rusqlite::params![50, i64::MIN], |r| r.get::<_, String>(3))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    assert!(
                        plan.iter().any(|s| s.contains(&format!(
                            "SEARCH o USING INDEX idx_event_outbox_pending_v{version}"
                        ))),
                        "pending v{version} must search its partial index: {plan:?}"
                    );
                    assert!(
                        !plan
                            .iter()
                            .any(|s| s.contains("TEMP B-TREE") || s.starts_with("SCAN")),
                        "pending v{version} must not scan or sort: {plan:?}"
                    );
                }
                Ok(())
            })
            .unwrap();
        // The range seek must include the entire integer timestamp domain.
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute("UPDATE event_outbox SET created_at_ms=?1", [i64::MIN])
                    .map(|_| ())
            })
            .unwrap();
        assert_eq!(store.drain_event_outbox(50).unwrap().len(), 1);
    }

    #[test]
    fn scheduler_queries_use_indexes_instead_of_historical_table_scans() {
        let store = store();
        store
            .inner
            .with_conn(|conn| {
                let queries = [
                    (
                        github_store::pending_receipts_query(),
                        vec![1, 50],
                        "idx_github_receipts_pending_lease",
                        "github_bot_receipt",
                    ),
                    (
                        github_store::RECEIPT_RETENTION_DELETE.to_string(),
                        vec![1, 2, 50],
                        "idx_github_receipts_terminal_updated",
                        "github_bot_receipt",
                    ),
                    (
                        DUE_SUBSCRIPTIONS_SELECT.to_string(),
                        vec![1, 2],
                        "idx_trigger_subscriptions_active_due",
                        "trigger_subscriptions",
                    ),
                ];
                for (sql, params, index, table) in queries {
                    let plan = conn
                        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?
                        .query_map(rusqlite::params_from_iter(params), |r| {
                            r.get::<_, String>(3)
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    assert!(
                        plan.iter()
                            .any(|s| s.contains(&format!("SEARCH {table} USING"))
                                && s.contains(index)),
                        "scheduler query must search {index}: {plan:?}"
                    );
                    assert!(
                        !plan
                            .iter()
                            .any(|s| s.contains(&format!("SCAN {table}"))
                                || s.contains("TEMP B-TREE")),
                        "scheduler query must not scan historical rows or sort: {plan:?}"
                    );
                }
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test]
    async fn poll_commit_wakes_only_after_success_and_keeps_a_permit() {
        // Run SQLite on a blocking thread and check the saved wake only after
        // commit completes. File-backed commits have taken about three seconds
        // in parallel suites; ten seconds allows several store operations even
        // at that latency, without charging their time to notification delivery.
        let commit_wait = std::time::Duration::from_secs(10);
        let wake_wait = std::time::Duration::from_secs(3);
        let store = tokio::time::timeout(
            commit_wait,
            tokio::task::spawn_blocking(|| {
                let store = store();
                subscription(&store, "a", "probe");
                let body = json!({"number": 7});
                let h = headers("p");
                let bad = KeyedPollEventInput {
                    event: PollEventInput {
                        vendor_event_id: "",
                        ..input(&body, KEY, &h).event
                    },
                    ..input(&body, KEY, &h)
                };
                assert!(store
                    .commit_keyed_poll_success(
                        "direct",
                        "a",
                        "a",
                        &json!({}),
                        &[input(&body, KEY, &h), bad],
                        1,
                        &[]
                    )
                    .is_err());
                store
            }),
        )
        .await
        .expect("poll rollback must finish within the durable-work budget")
        .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                store.outbox_committed()
            )
            .await
            .is_err(),
            "rolled-back inserts must not wake the publisher"
        );
        let store = tokio::time::timeout(
            commit_wait,
            tokio::task::spawn_blocking(move || {
                commit(
                    &store,
                    "a",
                    &[input(&json!({"number": 7}), KEY, &headers("p"))],
                );
                store
            }),
        )
        .await
        .expect("poll insert must finish within the durable-work budget")
        .unwrap();
        tokio::time::timeout(wake_wait, store.outbox_committed())
            .await
            .expect("committed poll outbox row must store a wake permit");
        let store = tokio::time::timeout(
            commit_wait,
            tokio::task::spawn_blocking(move || {
                commit(
                    &store,
                    "a",
                    &[input(&json!({"number": 7}), KEY, &headers("p"))],
                );
                store
            }),
        )
        .await
        .expect("duplicate poll commit must finish within the durable-work budget")
        .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                store.outbox_committed()
            )
            .await
            .is_err(),
            "duplicate events must not keep waking an idle drain"
        );
    }

    #[test]
    #[ignore = "measurement: 25,000 published rows, 100 idle passes before/after migration 50"]
    fn idle_outbox_25000_rows_before_and_after() {
        let scratch = crate::test_scratch::Scratch::database("idle-outbox-bench");
        let descriptor = StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: new_id("idle-bench"),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        };
        let inner = open_sqlite(&descriptor).unwrap();
        let boundary = MIGRATIONS.iter().position(|m| m.version == 50).unwrap();
        inner.migrate("plexus", &MIGRATIONS[..boundary]).unwrap();
        inner.with_conn_fenced(|conn| conn.execute_batch("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<25000)
            INSERT INTO trigger_events(event_id,principal,connection_id,subscription_id,vendor_event_id,payload_hash,payload,kind,observed_at_ms,created_at_ms)
            SELECT printf('%064x',i),'direct','a','a',CAST(i AS TEXT),'hash','{}','event',i,i FROM n;
            INSERT INTO event_outbox(event_key,event_id,event_name,repo_id,repo,created_at_ms,published_at_ms,envelope_v2,digest_v2,published_v2_at_ms)
            SELECT event_id,event_id,'github_issue_changed',101,'owner/repo',created_at_ms,1,'{}','digest',1 FROM trigger_events;")).unwrap();
        let start = std::time::Instant::now();
        for _ in 0..100 {
            for version in [1, 2] {
                inner.with_conn_fenced(|conn| {
                    cleanup_orphans(conn)?;
                    let predicate = if version == 2 { "o.envelope_v2 IS NOT NULL AND o.published_v2_at_ms IS NULL" } else { "o.published_at_ms IS NULL" };
                    // Every marker here is published, so the query returns no
                    // rows. Selecting event_key avoids later additive body columns.
                    let rows = conn.prepare(&format!("SELECT o.event_key FROM event_outbox o JOIN trigger_events e ON e.event_id=o.event_id WHERE {predicate} ORDER BY o.created_at_ms, o.event_key LIMIT ?1"))?
                        .query_map([50], |row|row.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                    assert!(rows.is_empty());
                    Ok(())
                }).unwrap();
            }
        }
        let before = start.elapsed();
        inner.migrate("plexus", MIGRATIONS).unwrap();
        let store = PlexusStore {
            inner,
            grant_journal: None,
            outbox_ready: tokio::sync::Notify::new(),
            ci_runs: Default::default(),
        };
        let start = std::time::Instant::now();
        for _ in 0..100 {
            for version in [1, 2] {
                assert!(store
                    .drain_event_outbox_version(50, version)
                    .unwrap()
                    .is_empty());
            }
        }
        println!(
            "25,000 published rows; 100 idle passes (both versions): before={before:?}, after={:?}",
            start.elapsed()
        );
        assert_eq!(count(&store, "event_outbox"), 25000);
    }

    #[test]
    #[ignore = "event-retention scaling measurement"]
    fn measure_large_event_retention_batch() {
        let store = store();
        subscription(&store, "a", "ci_runs");
        bulk_ci(&store, 10000, 8 * AUDIT_MILLIS_PER_DAY, 0);
        let started = std::time::Instant::now();
        let removed = store
            .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 1000)
            .unwrap();
        println!(
            "event retention: rows=10000 removed={removed} elapsed={}us",
            started.elapsed().as_micros()
        );
    }

    fn bulk_ci(store: &PlexusStore, n: usize, age: i64, unkeyed: usize) {
        let now = now_ms();
        store.inner.with_conn_fenced(|conn| {
            for i in 0..n {
                let id = format!("row-{i:04}");
                let key = format!("{i:064x}");
                conn.execute("INSERT INTO trigger_events
                    (event_id, principal, connection_id, subscription_id, vendor_event_id, payload_hash, payload, kind, observed_at_ms, created_at_ms, activity_at_ms, event_key)
                    VALUES (?1, 'direct', 'a', 'a', ?1, ?1, '{}', 'event', ?2, ?3, ?2, ?4)",
                    rusqlite::params![id, i as i64, now - age + i as i64, if i < unkeyed { None } else { Some(&key) }])?;
                if i >= unkeyed {
                    conn.execute("INSERT INTO event_outbox(event_key, event_id, event_name, repo_id, repo, created_at_ms, published_at_ms)
                        VALUES (?1, ?2, 'github_ci_run_completed', 101, 'owner/repo', ?3, ?3)", (&key, &id, now - age))?;
                }
            }
            Ok(())
        }).unwrap();
    }

    #[test]
    fn young_ci_body_floor_overrides_count_cap() {
        let store = store();
        subscription(&store, "a", "ci_runs");
        bulk_ci(&store, 1100, AUDIT_MILLIS_PER_DAY, 0);
        assert_eq!(
            store
                .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 1000)
                .unwrap(),
            0
        );
        assert_eq!(count(&store, "trigger_events"), 1100);
    }

    #[test]
    fn published_ci_prunes_to_cap_without_gap() {
        let store = store();
        subscription(&store, "a", "ci_runs");
        bulk_ci(&store, 1100, 8 * AUDIT_MILLIS_PER_DAY, 0);
        assert_eq!(
            store
                .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 1000)
                .unwrap(),
            100
        );
        assert_eq!(count(&store, "trigger_events"), 1000);
        assert_eq!(count(&store, "event_outbox"), 1000);
        assert_eq!(count(&store, "trigger_events WHERE kind = 'gap'"), 0);
    }

    #[test]
    fn retention_gap_covers_only_fifty_undelivered_rows() {
        let store = store();
        subscription(&store, "a", "ci_runs");
        bulk_ci(&store, 1100, 8 * AUDIT_MILLIS_PER_DAY, 50);
        assert_eq!(
            store
                .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 1000)
                .unwrap(),
            100
        );
        let gap: (i64, i64) = store
            .inner
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT gap_from_ms, gap_to_ms FROM trigger_events WHERE kind='gap'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .unwrap();
        assert_eq!(gap, (0, 49));
        assert_eq!(count(&store, "trigger_events WHERE kind='event'"), 1000);
    }

    fn old_row(store: &PlexusStore, kind: &str, activity: i64, published_age: Option<i64>) {
        subscription(store, "a", kind);
        let h = headers("p");
        let body = json!({"number": 7});
        let mut event = input(&body, KEY, &h);
        event.event.activity_at_ms = Some(activity);
        commit(store, "a", &[event]);
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "UPDATE trigger_events SET created_at_ms=?1",
                    [now_ms() - 40 * AUDIT_MILLIS_PER_DAY],
                )?;
                conn.execute(
                    "UPDATE event_outbox SET published_at_ms=?1, published_v2_at_ms=?1",
                    [published_age.map(|age| now_ms() - age)],
                )?;
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn v2_pending_marker_and_later_ack_protect_retention() {
        let store = store();
        old_row(&store, "ci_runs", 1, Some(8 * AUDIT_MILLIS_PER_DAY));
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute_batch("UPDATE event_outbox SET published_v2_at_ms=NULL")
            })
            .unwrap();
        assert_eq!(store.event_outbox_health().unwrap().depth, 1);
        assert_eq!(
            store
                .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 0)
                .unwrap(),
            0
        );
        store
            .mark_event_version_published(KEY, 2, now_ms())
            .unwrap();
        assert_eq!(store.event_outbox_health().unwrap().depth, 0);
        assert_eq!(
            store
                .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 0)
                .unwrap(),
            0
        );
        assert_eq!(count(&store, "trigger_events"), 1);
    }

    #[test]
    fn webhook_first_and_poll_first_envelopes_differ_only_in_action_and_comment_fields() {
        let webhook: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/event-envelope-v2/webhook_pull_request.json"
        ))
        .unwrap();
        let mut poll: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/event-envelope-v2/poll_pull_request.json"
        ))
        .unwrap();
        // These captures are eight seconds apart. Align the update identity to
        // model both transports observing the same change, retaining each shape.
        poll["updated_at"] = webhook["updated_at"].clone();
        let actors = ActorAttribution::Known(vec!["basal-alfonso[bot]".into()]);
        let mut winners = Vec::new();
        for webhook_first in [true, false] {
            let store = store();
            subscription(&store, "a", "sorted_head");
            let h = EventHeaders {
                repo: "CortexKit/Basal".into(),
                ..Default::default()
            };
            let make = |webhook_source: bool| {
                let mut keyed = input(if webhook_source { &webhook } else { &poll }, KEY, &h);
                keyed.identity.as_mut().unwrap().event_name = "github_pr_changed";
                keyed.event.item_kind = Some("pull_request");
                keyed.event.actor = &actors;
                if webhook_source {
                    keyed.envelope_context = crate::event_envelope::EnvelopeContext {
                        source: crate::event_envelope::EnvelopeSource::Webhook(Some(
                            "created".into(),
                        )),
                        comment: Some(
                            json!({"html_url":"https://github.com/cortexkit/basal/pull/13#issuecomment-1","user":{"login":"basal-alfonso[bot]"}}),
                        ),
                        ci_run: None,
                    };
                }
                keyed
            };
            commit(&store, "a", &[make(webhook_first)]);
            let first = store.canonical_event_by_key(KEY).unwrap().unwrap();
            commit(&store, "a", &[make(!webhook_first)]);
            let after = store.canonical_event_by_key(KEY).unwrap().unwrap();
            assert_eq!(
                first.envelope_v2, after.envelope_v2,
                "losing insert cannot recompute envelope"
            );
            assert_eq!(first.digest_v2, after.digest_v2);
            assert_eq!(first.body, after.body);
            winners
                .push(serde_json::from_str::<Value>(after.envelope_v2.as_ref().unwrap()).unwrap());
        }
        let one = winners[0].as_object().unwrap();
        let two = winners[1].as_object().unwrap();
        assert_eq!(
            one.keys().collect::<Vec<_>>(),
            two.keys().collect::<Vec<_>>()
        );
        let differences = one
            .keys()
            .filter(|key| one[*key] != two[*key])
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(differences, vec!["action", "comment_author", "comment_url"]);
    }

    #[test]
    fn stored_ci_job_envelopes_include_workflow_name_from_webhooks_and_polls() {
        let webhook: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/event-envelope-v2/webhook_ci_job.json"
        ))
        .unwrap();
        let poll: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/event-envelope-v2/poll_ci_job.json"
        ))
        .unwrap();
        let cases = [
            (
                "webhook",
                &webhook,
                crate::event_envelope::EnvelopeSource::Webhook(Some("completed".into())),
                "Tests",
            ),
            (
                "poll",
                &poll,
                crate::event_envelope::EnvelopeSource::Poll,
                "Design gate",
            ),
        ];
        for (subscription_id, item, source, expected_workflow_name) in cases {
            let store = store();
            subscription(&store, subscription_id, "sorted_head");
            let event_headers = headers("owner/repo");
            let actor = ActorAttribution::NotEnriched;
            let mut keyed = input(item, KEY, &event_headers);
            keyed.event.item_kind = Some("ci_job");
            keyed.event.actor = &actor;
            let identity = keyed.identity.as_mut().unwrap();
            identity.event_name = "github_ci_job_completed";
            identity.change = Some("completed");
            keyed.envelope_context = crate::event_envelope::EnvelopeContext {
                source,
                comment: None,
                ci_run: None,
            };
            commit(&store, subscription_id, &[keyed]);

            let stored = store
                .canonical_event_by_key(KEY)
                .unwrap()
                .unwrap()
                .envelope_v2
                .unwrap();
            let envelope: Value = serde_json::from_str(&stored).unwrap();
            assert_eq!(envelope["workflow_name"], expected_workflow_name);
            assert!(stored.contains(&format!(r#""workflow_name":"{expected_workflow_name}""#)));
        }
    }

    #[test]
    fn older_stored_ci_run_envelope_is_served_byte_identical() {
        let store = store();
        subscription(&store, "a", "ci_runs");
        let item = json!({"id":7,"run_attempt":1,"status":"completed","conclusion":"success",
            "updated_at":"2026-10-15T23:52:00Z"});
        let event_headers = headers("owner/repo");
        let make = || {
            let mut keyed = input(&item, KEY, &event_headers);
            keyed.event.item_kind = Some("ci_run");
            keyed.identity.as_mut().unwrap().event_name = "github_ci_run_completed";
            keyed
        };
        commit(&store, "a", &[make()]);
        let inserted = store.canonical_event_by_key(KEY).unwrap().unwrap();
        let new_envelope: Value =
            serde_json::from_str(inserted.envelope_v2.as_ref().unwrap()).unwrap();
        assert_eq!(new_envelope["completed_at"], "2026-10-15T23:52:00Z");
        assert_eq!(inserted.body, serde_json::to_string(&item).unwrap());

        // A ci_run envelope stored before plexus filled `completed_at` from a
        // finished run's `updated_at`. Its v1 body carries `updated_at`, so
        // rebuilding the envelope on read would now fill the field and change
        // the bytes; fetching must return the stored bytes instead.
        let old_envelope = String::from_utf8(
            crate::jcs::canonicalize_exact_integers(&json!({
                "event_key":KEY,"kind":"ci_run","repo":"owner/repo","action":"updated",
                "actor_logins":null,"actor_unknown":null,"id":7,"name":null,
                "conclusion":"success","status":"completed","head_branch":null,"head_sha":null,
                "url":null,"run_id":7,"run_attempt":1,"completed_at":null
            }))
            .unwrap(),
        )
        .unwrap();
        let old_digest = hex::encode(sha2::Sha256::digest(old_envelope.as_bytes()));
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "UPDATE event_outbox SET envelope_v2=?1,digest_v2=?2 WHERE event_key=?3",
                    (&old_envelope, &old_digest, KEY),
                )
            })
            .unwrap();
        commit(&store, "a", &[make()]);
        grant(
            &store,
            "consume-a",
            "consumer",
            "a",
            "direct",
            "[\"list_issues\"]",
            None,
        );
        let EventLookupOutcome::Found(served) = store
            .event_by_key_version(
                KEY,
                EventReader::Consumer {
                    principal: "consumer",
                },
                now_ms(),
                2,
            )
            .unwrap()
        else {
            panic!("stored CI run must remain visible");
        };
        assert_eq!(served.envelope_v2.as_deref(), Some(old_envelope.as_str()));
        assert_eq!(served.digest_v2.as_deref(), Some(old_digest.as_str()));
        assert_eq!(served.body, inserted.body);
        assert_eq!(served.digest, inserted.digest);
        assert_eq!(served.event_key, inserted.event_key);
    }

    #[test]
    fn ci_envelopes_stored_before_run_attribution_are_served_byte_identical() {
        let cases = [
            (
                "webhook_run",
                "ci_runs",
                "ci_run",
                "github_ci_run_completed",
                serde_json::from_str::<Value>(include_str!(
                    "../../tests/fixtures/event-envelope-v2/webhook_ci_run.json"
                ))
                .unwrap(),
            ),
            (
                "webhook_job",
                "ci_runs",
                "ci_job",
                "github_ci_job_completed",
                serde_json::from_str::<Value>(include_str!(
                    "../../tests/fixtures/event-envelope-v2/webhook_ci_job.json"
                ))
                .unwrap(),
            ),
        ];
        for (subscription_id, cursor_kind, item_kind, event_name, item) in cases {
            let store = store();
            subscription(&store, subscription_id, cursor_kind);
            let event_headers = headers("project-ci");
            let make = || {
                let mut keyed = input(&item, KEY, &event_headers);
                keyed.event.item_kind = Some(item_kind);
                let identity = keyed.identity.as_mut().unwrap();
                identity.event_name = event_name;
                keyed.envelope_context = crate::event_envelope::EnvelopeContext {
                    source: crate::event_envelope::EnvelopeSource::Webhook(Some(
                        "completed".into(),
                    )),
                    comment: None,
                    ci_run: Some(crate::event_envelope::CiRunAttribution {
                        actor: Some("octo-lantern".into()),
                        triggering_actor: Some("ualtinok".into()),
                        event: Some("push".into()),
                        head_repo_is_fork: Some(false),
                    }),
                };
                keyed
            };
            commit(&store, subscription_id, &[make()]);
            let inserted = store.canonical_event_by_key(KEY).unwrap().unwrap();
            let mut older: Value =
                serde_json::from_str(inserted.envelope_v2.as_ref().unwrap()).unwrap();
            assert_eq!(
                older["actor"], "octo-lantern",
                "a new {item_kind} envelope carries the run values"
            );
            // Rebuild the envelope an older binary, before run attribution and
            // job execution fields were added, would have stored for this change.
            for field in [
                "actor",
                "triggering_actor",
                "event",
                "head_repo_is_fork",
                "runner_name",
                "steps_run",
            ] {
                older.as_object_mut().unwrap().remove(field);
            }
            let older = String::from_utf8(crate::jcs::canonicalize_exact_integers(&older).unwrap())
                .unwrap();
            let older_digest = hex::encode(sha2::Sha256::digest(older.as_bytes()));
            store
                .inner
                .with_conn_fenced(|conn| {
                    conn.execute(
                        "UPDATE event_outbox SET envelope_v2=?1,digest_v2=?2 WHERE event_key=?3",
                        (&older, &older_digest, KEY),
                    )
                })
                .unwrap();
            // A second copy arrives with run values and job execution fields;
            // the stored envelope is not rewritten.
            commit(&store, subscription_id, &[make()]);
            grant(
                &store,
                &format!("consume-{subscription_id}"),
                "consumer",
                subscription_id,
                "direct",
                "[\"list_issues\"]",
                None,
            );
            let EventLookupOutcome::Found(served) = store
                .event_by_key_version(
                    KEY,
                    EventReader::Consumer {
                        principal: "consumer",
                    },
                    now_ms(),
                    2,
                )
                .unwrap()
            else {
                panic!("stored {item_kind} must remain visible");
            };
            assert_eq!(
                served.envelope_v2.as_deref(),
                Some(older.as_str()),
                "an older {item_kind} envelope must be served byte-identical"
            );
            assert_eq!(served.digest_v2.as_deref(), Some(older_digest.as_str()));
            assert_eq!(served.body, inserted.body);
            assert_eq!(served.digest, inserted.digest);
        }
    }

    #[test]
    fn migration_47_forward_rollback_and_reforward_without_backfill() {
        let scratch = crate::test_scratch::Scratch::database("envelope-migration");
        let descriptor = StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "envelope-migration".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        };
        let inner = open_sqlite(&descriptor).unwrap();
        let prior = &MIGRATIONS[..24];
        // Stop at migration 47, the version this test exercises.
        let through_47 = &MIGRATIONS[..=MIGRATIONS.iter().position(|m| m.version == 47).unwrap()];
        assert_eq!(inner.migrate("plexus", prior).unwrap().recorded, 46);
        const LEGACY_INSERT: &str =
            "INSERT INTO event_outbox(event_key,event_id,event_name,repo_id,repo,created_at_ms)
            VALUES ('legacy','legacy','github_issue_changed',101,'owner/repo',1)";
        inner
            .with_conn_fenced(|conn| conn.execute_batch(LEGACY_INSERT))
            .unwrap();
        let forward = inner.migrate("plexus", through_47).unwrap();
        assert_eq!((forward.applied, forward.recorded), (1, 47));
        inner.with_conn_fenced(|conn| {
            let row: (Option<String>, Option<String>, Option<i64>) = conn.query_row(
                "SELECT envelope_v2,digest_v2,published_v2_at_ms FROM event_outbox WHERE event_key='legacy'", [],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            assert_eq!(row, (None,None,None), "migration must not backfill v2");
            conn.execute_batch("INSERT INTO event_outbox(event_key,event_id,event_name,repo_id,repo,created_at_ms,envelope_v2,digest_v2,published_v2_at_ms)
                VALUES ('new','new','github_issue_changed',101,'owner/repo',1,'{}','digest',7)")
        }).unwrap();
        drop(inner);
        let older = open_sqlite(&descriptor).unwrap();
        let rollback = older.migrate("plexus", prior).unwrap();
        assert!(rollback.store_ahead());
        assert_eq!(rollback.applied, 0);
        older.with_conn_fenced(|conn| {
            conn.execute("UPDATE event_outbox SET published_at_ms=5 WHERE event_key='new'", [])?;
            conn.execute_batch("INSERT INTO event_outbox(event_key,event_id,event_name,repo_id,repo,created_at_ms)
                VALUES ('rollback','rollback','github_issue_changed',101,'owner/repo',1)")
        }).unwrap();
        drop(older);
        let newer = open_sqlite(&descriptor).unwrap();
        assert_eq!(newer.migrate("plexus", through_47).unwrap().applied, 0);
        newer.with_conn(|conn| {
            let row: (String, String, i64, i64) = conn.query_row(
                "SELECT envelope_v2,digest_v2,published_v2_at_ms,published_at_ms FROM event_outbox WHERE event_key='new'", [],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
            assert_eq!(row, ("{}".into(),"digest".into(),7,5));
            assert_eq!(conn.query_row("SELECT count(*) FROM event_outbox WHERE envelope_v2 IS NULL", [], |r| r.get::<_,i64>(0))?, 2);
            Ok(())
        }).unwrap();
    }

    #[test]
    fn unpublished_marker_protects_forty_day_row_and_writes_no_gap() {
        let store = store();
        old_row(&store, "ci_runs", 10000000, None);
        assert_eq!(
            store
                .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 0)
                .unwrap(),
            0
        );
        assert_eq!(count(&store, "trigger_events"), 1);
    }

    #[test]
    fn body_floor_starts_at_later_publication_not_insert() {
        let store = store();
        old_row(&store, "ci_runs", 10000000, Some(6 * AUDIT_MILLIS_PER_DAY));
        assert_eq!(
            store
                .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 0)
                .unwrap(),
            0
        );
        assert!(store.canonical_event_by_key(KEY).unwrap().is_some());
    }

    #[test]
    fn ordered_timestamp_retains_full_window_and_boundary() {
        // Fixed vendor timestamps witness the full one-hour lookback. Deriving
        // these from the retention constant would let a shortened window pass.
        for activity in [10_000_000, 6_400_000] {
            let store = store();
            old_row(
                &store,
                "ordered_timestamp",
                activity,
                Some(8 * AUDIT_MILLIS_PER_DAY),
            );
            assert_eq!(
                store
                    .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 0)
                    .unwrap(),
                0
            );
        }
        let store = store();
        old_row(
            &store,
            "ordered_timestamp",
            6_399_999,
            Some(8 * AUDIT_MILLIS_PER_DAY),
        );
        assert_eq!(
            store
                .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 0)
                .unwrap(),
            1
        );
    }

    #[test]
    fn sorted_head_retains_exact_watermark_only() {
        let store = store();
        old_row(
            &store,
            "sorted_head",
            10000000,
            Some(8 * AUDIT_MILLIS_PER_DAY),
        );
        assert_eq!(
            store
                .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 0)
                .unwrap(),
            0
        );
        let store2 = self::store();
        old_row(
            &store2,
            "sorted_head",
            9999999,
            Some(8 * AUDIT_MILLIS_PER_DAY),
        );
        assert_eq!(
            store2
                .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 0)
                .unwrap(),
            1
        );
    }

    macro_rules! non_watermark_test {
        ($name:ident, $kind:literal) => {
            #[test]
            fn $name() {
                let store = store();
                old_row(&store, $kind, 10000001, Some(8 * AUDIT_MILLIS_PER_DAY));
                assert_eq!(
                    store
                        .prune("direct", "a", 30 * AUDIT_MILLIS_PER_DAY, 0)
                        .unwrap(),
                    1
                );
                assert_eq!(count(&store, "trigger_events"), 0);
            }
        };
    }
    non_watermark_test!(sync_token_has_no_watermark_protection, "sync_token");
    non_watermark_test!(snapshot_diff_has_no_watermark_protection, "snapshot_diff");
    non_watermark_test!(scalar_diff_has_no_watermark_protection, "scalar_diff");
    non_watermark_test!(probe_has_no_watermark_protection, "probe");
    non_watermark_test!(ci_runs_has_no_watermark_protection, "ci_runs");

    #[test]
    fn unsubscribe_and_delete_connection_remove_and_count_pending_markers() {
        let store = store();
        subscription(&store, "a", "probe");
        let h = headers("p");
        let body = json!({"number": 7});
        commit(&store, "a", &[input(&body, KEY, &h)]);
        assert!(!store.unsubscribe("intruder", "a").unwrap());
        assert_eq!(count(&store, "event_outbox"), 1);
        assert!(store.unsubscribe("direct", "a").unwrap());
        assert_eq!(count(&store, "event_outbox"), 0);
        assert_eq!(
            store.event_outbox_health().unwrap().dropped_on_unsubscribe,
            1
        );
        subscription(&store, "a", "ci_runs");
        bulk_ci(&store, 4, AUDIT_MILLIS_PER_DAY, 0);
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "UPDATE event_outbox SET published_at_ms=NULL WHERE event_id != 'row-0000'",
                    [],
                )
                .map(|_| ())
            })
            .unwrap();
        store
            .insert_connection("direct", "a", "github_actions", "active", &json!({}))
            .unwrap();
        let DeleteConnectionOutcome::WouldDelete { rows, .. } =
            store.delete_connection("direct", "a", false).unwrap()
        else {
            panic!("dry run");
        };
        assert_eq!(
            rows.iter()
                .find(|(name, _)| *name == "event_outbox")
                .unwrap()
                .1,
            4
        );
        assert_eq!(store.event_outbox_health().unwrap().dropped_on_delete, 0);
        assert!(matches!(
            store.delete_connection("direct", "a", true).unwrap(),
            DeleteConnectionOutcome::Deleted { .. }
        ));
        assert_eq!(count(&store, "event_outbox"), 0);
        assert_eq!(store.event_outbox_health().unwrap().dropped_on_delete, 3);
        assert!(store.drain_event_outbox(10).unwrap().is_empty());
    }

    #[test]
    fn quota_admission_fences_reservations_and_trailing_hour_limit() {
        let store = store();
        subscription(&store, "a", "ci_runs");
        // The active watch's uncached owner/repo leaves one of the 600 hourly
        // requests available for resolving its id, rather than for CI polling.
        for _ in 0..74 {
            assert!(matches!(
                store
                    .reserve_github_actions_quota("direct", "a", QuotaRequest::CiCycle, 10000000)
                    .unwrap(),
                QuotaAdmission::Reserved { requests: 8, .. }
            ));
        }
        assert_eq!(
            store
                .reserve_github_actions_quota("direct", "a", QuotaRequest::CiCycle, 10000000)
                .unwrap(),
            QuotaAdmission::Deferred {
                retry_at_ms: 13_600_001
            }
        );
        for _ in 0..8 {
            assert!(matches!(
                store
                    .reserve_github_actions_quota(
                        "direct",
                        "a",
                        QuotaRequest::GetRepository,
                        10000000
                    )
                    .unwrap(),
                QuotaAdmission::Reserved { requests: 1, .. }
            ));
        }
        assert_eq!(
            store
                .reserve_github_actions_quota("direct", "a", QuotaRequest::GetRepository, 10000000)
                .unwrap(),
            QuotaAdmission::Deferred {
                retry_at_ms: 13_600_001
            }
        );
        assert_eq!(count(&store, "github_actions_quota"), 82);
        assert_eq!(
            store
                .reserve_github_actions_quota(
                    "intruder",
                    "a",
                    QuotaRequest::GetRepository,
                    10000001
                )
                .unwrap(),
            QuotaAdmission::Inactive
        );
        assert!(matches!(
            store
                .reserve_github_actions_quota("direct", "a", QuotaRequest::CiCycle, 13_600_001)
                .unwrap(),
            QuotaAdmission::Reserved { .. }
        ));
        assert_eq!(count(&store, "github_actions_quota"), 1);
    }

    #[test]
    fn quota_deferral_waits_until_enough_mixed_reservations_expire() {
        let store = store();
        subscription(&store, "a", "ci_runs");
        let now = 10_000_000;
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "INSERT INTO github_actions_quota VALUES ('first-eight', ?1, 8)",
                    [now - 500],
                )?;
                for id in 0..8 {
                    conn.execute(
                        "INSERT INTO github_actions_quota VALUES (?1, ?2, 1)",
                        (format!("single-{id}"), now - 400 + id),
                    )?;
                }
                for id in 0..73 {
                    conn.execute(
                        "INSERT INTO github_actions_quota VALUES (?1, ?2, 8)",
                        (format!("cycle-{id}"), now),
                    )?;
                }
                Ok(())
            })
            .unwrap();
        let retry_at = now - 400 + QUOTA_WINDOW_MS + 1;
        assert_eq!(
            store
                .reserve_github_actions_quota("direct", "a", QuotaRequest::CiCycle, now)
                .unwrap(),
            QuotaAdmission::Deferred {
                retry_at_ms: retry_at
            },
            "one eight-unit expiry is not enough under the repository allowance"
        );
        assert!(matches!(
            store
                .reserve_github_actions_quota("direct", "a", QuotaRequest::CiCycle, retry_at - 1)
                .unwrap(),
            QuotaAdmission::Deferred { .. }
        ));
        assert!(matches!(
            store
                .reserve_github_actions_quota("direct", "a", QuotaRequest::CiCycle, retry_at)
                .unwrap(),
            QuotaAdmission::Reserved { requests: 8, .. }
        ));
    }

    #[test]
    fn quota_counts_each_watched_repository_once_and_prunes_unwatched_cache_rows() {
        let store = store();
        subscription(&store, "a", "ci_runs");
        subscription(&store, "b", "ci_runs");
        // Both active watches and the cache name the same owner/repo, counted
        // once, leaving 599 of the 600 hourly requests to CI polling. Seven
        // more cached names belong to repositories nothing watches any more;
        // they must neither shrink that share nor stay cached.
        store
            .record_repo_id_resolution("owner/repo", Some(101), 1)
            .unwrap();
        for i in 0..7 {
            store
                .record_repo_id_resolution(&format!("owner/new{i}"), None, 1)
                .unwrap();
        }
        // 590 requests used: one more cycle fits under 599, but would not fit
        // under the 592 left if the seven stale names were still counted.
        store
            .inner
            .with_conn_fenced(|conn| {
                for i in 0..73 {
                    conn.execute(
                        "INSERT INTO github_actions_quota VALUES (?1, 10000000, 8)",
                        [format!("seed{i}")],
                    )?;
                }
                for i in 0..6 {
                    conn.execute(
                        "INSERT INTO github_actions_quota VALUES (?1, 10000000, 1)",
                        [format!("lookup{i}")],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        assert!(
            matches!(
                store
                    .reserve_github_actions_quota("direct", "a", QuotaRequest::CiCycle, 10000000)
                    .unwrap(),
                QuotaAdmission::Reserved { requests: 8, .. }
            ),
            "590 used must leave room for one more cycle under 599"
        );
        assert_eq!(
            count(&store, "github_repo_id_cache"),
            1,
            "unwatched cache rows must be pruned"
        );
        assert_eq!(
            store
                .repo_id_cache("owner/repo")
                .unwrap()
                .and_then(|entry| entry.repo_id),
            Some(101),
            "the watched repository keeps its recorded identity"
        );
        assert_eq!(
            store
                .reserve_github_actions_quota("direct", "a", QuotaRequest::CiCycle, 10000000)
                .unwrap(),
            QuotaAdmission::Deferred {
                retry_at_ms: 13_600_001
            },
            "598 used: another cycle would pass the 599 left to CI polling"
        );
        assert!(matches!(
            store
                .reserve_github_actions_quota("direct", "a", QuotaRequest::GetRepository, 10000000)
                .unwrap(),
            QuotaAdmission::Reserved { .. }
        ));
    }

    #[test]
    fn repo_resolution_claims_are_shared_hourly_and_refresh_daily() {
        // Use literal clock advances, not the implementation's constants, to
        // detect changes to the one-hour retry and one-day successful-refresh
        // intervals, shared by all watches for the same repository name.
        let store = store();
        for id in ["a", "b", "c"] {
            subscription(&store, id, "probe");
        }
        let now = 10000000;
        assert!(matches!(
            store
                .reserve_repo_id_resolution("direct", "a", "OWNER/Repo", now)
                .unwrap(),
            RepoResolutionAdmission::Reserved {
                cached_repo_id: None,
                ..
            }
        ));
        for id in ["b", "c"] {
            assert_eq!(
                store
                    .reserve_repo_id_resolution("direct", id, "owner/repo", now)
                    .unwrap(),
                RepoResolutionAdmission::NotDue
            );
        }
        store
            .record_repo_id_resolution("owner/repo", None, now)
            .unwrap();
        assert_eq!(
            store
                .reserve_repo_id_resolution("direct", "a", "owner/repo", now + 3_600_000 - 1)
                .unwrap(),
            RepoResolutionAdmission::NotDue
        );
        assert!(matches!(
            store
                .reserve_repo_id_resolution("direct", "a", "owner/repo", now + 3_600_000)
                .unwrap(),
            RepoResolutionAdmission::Reserved { .. }
        ));
        store
            .record_repo_id_resolution("owner/repo", Some(101), now + 3_600_000)
            .unwrap();
        assert_eq!(
            store
                .reserve_repo_id_resolution("direct", "b", "Owner/Repo", now + 86_400_000)
                .unwrap(),
            RepoResolutionAdmission::NotDue
        );
        assert!(matches!(
            store
                .reserve_repo_id_resolution("direct", "b", "Owner/Repo", now + 90_000_000)
                .unwrap(),
            RepoResolutionAdmission::Reserved {
                cached_repo_id: Some(101),
                ..
            }
        ));
        let cache = store.repo_id_cache("OWNER/REPO").unwrap().unwrap();
        assert_eq!(cache.repo, "owner/repo");
        assert_eq!(cache.repo_id, Some(101));
        store
            .record_repo_id_resolution("owner/repo", None, now + 90_000_000)
            .unwrap();
        assert_eq!(
            store.repo_id_cache("owner/repo").unwrap().unwrap().repo_id,
            Some(101)
        );
    }

    #[test]
    fn deferred_identity_read_does_not_claim_an_hour_or_change_cache() {
        let store = store();
        subscription(&store, "a", "probe");
        store
            .inner
            .with_conn_fenced(|conn| {
                for i in 0..300 {
                    conn.execute(
                        "INSERT INTO github_actions_quota VALUES (?1, 10000000, 8)",
                        [format!("seed{i}")],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store
                .reserve_repo_id_resolution("direct", "a", "owner/repo", 10000000)
                .unwrap(),
            RepoResolutionAdmission::Deferred
        );
        assert!(store.repo_id_cache("owner/repo").unwrap().is_none());
        assert!(matches!(
            store
                .reserve_repo_id_resolution("direct", "a", "owner/repo", 13_600_001)
                .unwrap(),
            RepoResolutionAdmission::Reserved { .. }
        ));
    }

    #[test]
    fn migrations_preserve_rows_admit_ci_runs_and_are_idempotent() {
        let scratch = crate::test_scratch::Scratch::database("event-migrations");
        let descriptor = StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "migration-test".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        };
        let inner = open_sqlite(&descriptor).unwrap();
        let boundary = MIGRATIONS.iter().position(|m| m.version == 44).unwrap();
        inner.migrate("plexus", &MIGRATIONS[..boundary]).unwrap();
        const CI_INSERT: &str = "INSERT INTO trigger_subscriptions
            (subscription_id, principal, connection_id, action, cadence_s, cursor_kind, schema_hash, status, created_at_ms)
            VALUES ('ci', 'direct', 'a', 'list_workflow_runs', 300, 'ci_runs', 'hash', 'active', 1)";
        inner.with_conn_fenced(|conn| {
            assert!(conn.execute(CI_INSERT, []).is_err(), "old CHECK must refuse ci_runs");
            conn.execute_batch("INSERT INTO trigger_subscriptions
                (subscription_id, principal, connection_id, action, cadence_s, cursor_kind, cursor_state, schema_hash, status, created_at_ms, project_id, project_source, deliver_to, actor_source_json)
                VALUES ('old','direct','a','list_issues',300,'ordered_timestamp','{\"watermark_ms\":9}','hash','suspended',1,'project','entorhinal','agent','{\"action\":\"comments\"}');
                INSERT INTO trigger_events(event_id, principal, connection_id, subscription_id, vendor_event_id, payload_hash, payload, kind, observed_at_ms, created_at_ms)
                VALUES ('old-event','direct','a','old','7','hash','{\"number\":7}','event',2,3);")
        }).unwrap();
        let old: Vec<rusqlite::types::Value> = inner
            .with_conn(|conn| {
                conn.query_row("SELECT * FROM trigger_subscriptions", [], |r| {
                    (0..r.as_ref().column_count()).map(|i| r.get(i)).collect()
                })
            })
            .unwrap();
        drop(inner);
        let store = PlexusStore::open(&descriptor).unwrap();
        store.inner.with_conn_fenced(|conn| {
            let after: Vec<rusqlite::types::Value> = conn.query_row("SELECT * FROM trigger_subscriptions", [], |r| (0..r.as_ref().column_count()).map(|i| r.get(i)).collect())?;
            assert_eq!(old, after, "CHECK rebuild must preserve every column");
            assert_eq!(conn.query_row("SELECT COUNT(*) FROM trigger_events WHERE event_key IS NULL AND delivery_id IS NULL AND payload='{\"number\":7}'", [], |r| r.get::<_, i64>(0))?, 1);
            assert_eq!(conn.execute(CI_INSERT, [])?, 1, "new CHECK must admit ci_runs");
            assert!(conn.execute("UPDATE trigger_subscriptions SET project_id=NULL WHERE subscription_id='old'", []).is_err(), "project provenance trigger must survive rebuild");
            Ok(())
        }).unwrap();
        assert_eq!(count(&store, "event_outbox"), 0);
        assert!(store.drain_event_outbox(10).unwrap().is_empty());
        let versions = count(&store, "cortexkit_schema_version");
        drop(store);
        let store = PlexusStore::open(&descriptor).unwrap();
        assert_eq!(count(&store, "trigger_subscriptions"), 2);
        assert_eq!(count(&store, "trigger_events"), 1);
        assert_eq!(count(&store, "cortexkit_schema_version"), versions);
    }
}
