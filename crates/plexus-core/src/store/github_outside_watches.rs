//! Storage for watches created by agent-stamped Basal flows.

use super::*;
use crate::github_watch::{
    audit_record, WatchError, WatchKey, BASAL, CADENCE_S, HOUR_MS, OWNER, PUBLIC_CHECK,
    PUBLIC_CONNECTION,
};
use rusqlite::params;

pub(crate) struct OutsidePoll {
    pub(crate) repo_id: Option<i64>,
    numbers: BTreeSet<i64>,
}

impl OutsidePoll {
    pub(crate) fn admits(&self, item_kind: Option<&str>, payload: &Value) -> bool {
        self.repo_id.is_some()
            && if item_kind == Some("release") {
                self.numbers.contains(&0)
            } else {
                payload["number"]
                    .as_i64()
                    .is_some_and(|number| self.numbers.contains(&number))
            }
    }
}

// Any row identifies an outside subscription, even when every watch is expired
// or its proof is stale. Neither case may fall through to ordinary fleet polling.
pub(super) fn outside_watch_poll_on_conn(
    conn: &Connection,
    subscription: &str,
    now: i64,
) -> rusqlite::Result<Option<OutsidePoll>> {
    let mut query = conn.prepare(
        "SELECT number, expires_at_ms, last_public_check_at_ms, repo_id
        FROM github_outside_watches WHERE subscription_id=?1",
    )?;
    let mut rows = query.query([subscription])?;
    let mut data = None;
    while let Some(row) = rows.next()? {
        let poll = data.get_or_insert_with(|| OutsidePoll {
            repo_id: None,
            numbers: BTreeSet::new(),
        });
        let expiry: i64 = row.get(1)?;
        let checked: i64 = row.get(2)?;
        if expiry > now && checked > now.saturating_sub(HOUR_MS) {
            poll.repo_id = Some(row.get(3)?);
            poll.numbers.insert(row.get(0)?);
        }
    }
    Ok(data)
}

// Positive matches must name the Basal module, never a wildcard grantee or an
// agent grant. The operator may grant several selectors on the one connection.
fn poll_grant(
    conn: &Connection,
    grantee: &str,
    connection: &str,
    action: &str,
    now: i64,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM grants g, json_each(g.action_selectors) a
         WHERE g.principal=?1 AND g.connection_id=?2 AND g.grantee_principal=?3
           AND g.authority_kind='poll' AND g.agent_id IS NULL
           AND (g.expires_at IS NULL OR g.expires_at>?4) AND a.value=?5)",
        params![OWNER, connection, grantee, now, action],
        |r| r.get(0),
    )
}

fn retire_after_removing(
    conn: &Connection,
    predicate: &str,
    args: impl rusqlite::Params + Clone,
) -> rusqlite::Result<usize> {
    let mut lookup = conn.prepare(&format!(
        "SELECT DISTINCT subscription_id FROM github_outside_watches WHERE {predicate}"
    ))?;
    let ids = lookup
        .query_map(args.clone(), |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let removed = conn.execute(
        &format!("DELETE FROM github_outside_watches WHERE {predicate}"),
        args,
    )?;
    for id in ids {
        conn.execute(
            "UPDATE trigger_subscriptions SET status='retired',generation=generation+1
            WHERE subscription_id=?1 AND status<>'retired'
              AND NOT EXISTS (SELECT 1 FROM github_outside_watches WHERE subscription_id=?1)",
            [&id],
        )?;
    }
    Ok(removed)
}

impl PlexusStore {
    pub(crate) fn outside_watch_poll(
        &self,
        subscription: &str,
        now: i64,
    ) -> Result<Option<OutsidePoll>, StoreError> {
        self.inner
            .with_read(|conn| outside_watch_poll_on_conn(conn, subscription, now))
    }

    pub(crate) fn fleet_has_github_watch(&self, key: &WatchKey) -> Result<bool, StoreError> {
        let (connection, action) = key.kind.poll();
        self.inner.with_read(|conn| conn.query_row("SELECT EXISTS (SELECT 1 FROM trigger_subscriptions s
            JOIN connections c ON c.principal=s.principal AND c.connection_id=s.connection_id
            WHERE s.principal=?1 AND s.connection_id=?2 AND s.action=?3 AND s.status='active'
              AND c.status='active' AND c.app_key='github'
              AND lower(json_extract(s.fixed_args,'$.owner') || '/' || json_extract(s.fixed_args,'$.repo'))=?4
              AND NOT EXISTS (SELECT 1 FROM github_outside_watches w WHERE w.subscription_id=s.subscription_id))",
            params![OWNER, connection, action, key.repository], |r| r.get(0)))
    }

    pub(crate) fn outside_watch_check_grants(
        &self,
        key: &WatchKey,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.inner.with_read(|conn| check_grants(conn, key, now))
    }

    pub(crate) fn outside_watch_existing(
        &self,
        scope: &CallScope,
        key: &WatchKey,
        now: i64,
    ) -> Result<Option<i64>, StoreError> {
        self.inner.with_read(|conn| existing(conn, scope, key, now))
    }

    pub(crate) fn outside_watch_insert(
        &self,
        scope: &CallScope,
        key: &WatchKey,
        expiry: i64,
        repo_id: i64,
        checked_at: i64,
        prepared: &TriggerSubscription,
    ) -> Result<Result<i64, WatchError>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let now = now_ms();
            let (connection, action) = key.kind.poll();
            if !check_grants(conn, key, now)? {
                return Ok(Err(WatchError::GrantMissing));
            }
            if let Some(expiry) = existing(conn, scope, key, now)? {
                audit_ensure(conn, scope, "outside")?;
                return Ok(Ok(expiry));
            }
            if expiry <= now {
                return Ok(Err(WatchError::InvalidRequest));
            }
            let (total, for_agent): (i64, i64) = conn.query_row(
                "SELECT count(*), count(CASE WHEN agent_id=?1 THEN 1 END)
                 FROM github_outside_watches WHERE expires_at_ms>?2", params![scope.agent_id, now],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if total >= 25 || for_agent >= 5 {
                return Ok(Err(WatchError::Limit));
            }
            if super::subscriptions_store::recheck_watch_preconditions(conn, OWNER, connection, &[(action, Some(&prepared.schema_hash))])?.is_some() {
                return Ok(Err(WatchError::ReadUnavailable));
            }
            // A vendor name may have been reassigned. A fresh proof must not
            // turn an older watch into consent for a different repository.
            if !poll_grant(conn, OWNER, connection, action, now)? {
                return Ok(Err(WatchError::GrantMissing));
            }
            retire_after_removing(conn, "repository=?1 AND repo_id<>?2", params![key.repository, repo_id])?;
            let shared = conn.query_row("SELECT w.subscription_id FROM github_outside_watches w
                JOIN trigger_subscriptions s ON s.subscription_id=w.subscription_id
                WHERE w.repository=?1 AND w.kind=?2 AND s.status<>'retired' LIMIT 1",
                params![key.repository, key.kind.as_str()], |r| r.get::<_, String>(0)).optional()?;
            let subscription = if let Some(shared) = shared {
                shared
            } else {
                conn.execute("INSERT INTO trigger_subscriptions
                    (subscription_id,principal,connection_id,action,cadence_s,cursor_kind,cursor_state,fixed_args,schema_hash,status,generation,created_at_ms)
                    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'active',0,?10)",
                    params![prepared.subscription_id, OWNER, connection, action, CADENCE_S, prepared.cursor_kind,
                        prepared.cursor_state.to_string(), prepared.fixed_args.to_string(), prepared.schema_hash, now])?;
                prepared.subscription_id.clone()
            };
            conn.execute("UPDATE github_outside_watches SET last_public_check_at_ms=?2,
                last_public_attempt_at_ms=MAX(last_public_attempt_at_ms,?2) WHERE repository=?1 AND last_public_check_at_ms<?2",
                params![key.repository, checked_at])?;
            conn.execute("INSERT INTO github_outside_watches
                (flow_id,agent_id,repository,kind,number,expires_at_ms,subscription_id,created_at_ms,last_public_check_at_ms,last_public_attempt_at_ms,repo_id)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9,?10)
                ON CONFLICT(flow_id,repository,kind,number) DO UPDATE SET agent_id=excluded.agent_id,
                expires_at_ms=excluded.expires_at_ms,subscription_id=excluded.subscription_id,created_at_ms=excluded.created_at_ms,
                last_public_check_at_ms=excluded.last_public_check_at_ms,last_public_attempt_at_ms=excluded.last_public_attempt_at_ms,repo_id=excluded.repo_id
                WHERE github_outside_watches.expires_at_ms<=?8",
                params![scope.flow_id, scope.agent_id, key.repository, key.kind.as_str(), key.number_key(), expiry, subscription, now, checked_at, repo_id])?;
            audit_ensure(conn, scope, "outside")?;
            Ok(Ok(expiry))
        })
    }

    pub(crate) fn outside_watch_end(
        &self,
        scope: &CallScope,
        key: &WatchKey,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let removed = retire_after_removing(conn, "flow_id=?1 AND agent_id=?2 AND repository=?3 AND kind=?4 AND number=?5 AND expires_at_ms>?6",
                params![scope.flow_id, scope.agent_id, key.repository, key.kind.as_str(), key.number_key(), now])? > 0;
            let audit = audit_record("end", BASAL, Some(scope), if removed { "ended" } else { "not_found" }, true);
            append_audit_on_conn(conn, &audit, None, None, Some(scope), None)?;
            Ok(removed)
        })
    }

    pub(crate) fn outside_watch_end_repository(&self, repository: &str) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            retire_after_removing(conn, "repository=?1", [repository])?;
            Ok(())
        })
    }

    pub(crate) fn expire_outside_watches(&self, now: i64) -> Result<Vec<String>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            retire_after_removing(conn, "expires_at_ms<=?1", [now])?;
            let mut query = conn.prepare("SELECT DISTINCT repository FROM github_outside_watches WHERE last_public_check_at_ms<=?1")?;
            let stale = now.saturating_sub(24 * HOUR_MS);
            let stale_repos = query.query_map([stale], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for repository in &stale_repos {
                retire_after_removing(conn, "repository=?1", [repository])?;
            }
            for kind in crate::github_watch::WatchKind::ALL {
                let (connection, action) = kind.poll();
                if !poll_grant(conn, BASAL, connection, action, now)? {
                    retire_after_removing(conn, "kind=?1", [kind.as_str()])?;
                }
            }
            Ok(stale_repos)
        })
    }

    pub(crate) fn outside_watch_rechecks_due(&self, now: i64) -> Result<Vec<String>, StoreError> {
        self.inner.with_read(|conn| {
            let mut query = conn.prepare(
                "SELECT repository FROM github_outside_watches
                WHERE expires_at_ms>?1 GROUP BY repository HAVING MAX(last_public_attempt_at_ms)<=?2
                ORDER BY MAX(last_public_attempt_at_ms), repository",
            )?;
            let rows = query.query_map((now, now.saturating_sub(HOUR_MS)), |r| r.get(0))?;
            rows.collect()
        })
    }

    pub(crate) fn reserve_outside_watch_recheck(
        &self,
        repository: &str,
        now: i64,
    ) -> Result<Option<bool>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let (attempt, check): (Option<i64>, Option<i64>) = conn.query_row(
                "SELECT MAX(last_public_attempt_at_ms),MAX(last_public_check_at_ms) FROM github_outside_watches WHERE repository=?1 AND expires_at_ms>?2",
                (repository, now), |r| Ok((r.get(0)?, r.get(1)?)))?;
            let Some(attempt) = attempt.filter(|at| *at <= now.saturating_sub(HOUR_MS)) else {
                return Ok(None);
            };
            conn.execute("UPDATE github_outside_watches SET last_public_attempt_at_ms=?2 WHERE repository=?1", (repository, now))?;
            Ok(Some(check == Some(attempt)))
        })
    }

    pub(crate) fn confirm_outside_watch_recheck(
        &self,
        repository: &str,
        repo_id: i64,
        now: i64,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            retire_after_removing(conn, "repository=?1 AND repo_id<>?2", (repository, repo_id))?;
            conn.execute(
                "UPDATE github_outside_watches SET last_public_check_at_ms=?2
                WHERE repository=?1 AND last_public_attempt_at_ms=?2",
                (repository, now),
            )?;
            Ok(())
        })
    }
}

fn existing(
    conn: &Connection,
    scope: &CallScope,
    key: &WatchKey,
    now: i64,
) -> rusqlite::Result<Option<i64>> {
    conn.query_row("SELECT expires_at_ms FROM github_outside_watches
        WHERE flow_id=?1 AND agent_id=?2 AND repository=?3 AND kind=?4 AND number=?5 AND expires_at_ms>?6",
        params![scope.flow_id, scope.agent_id, key.repository, key.kind.as_str(), key.number_key(), now], |r| r.get(0)).optional()
}

fn audit_ensure(conn: &Connection, scope: &CallScope, outcome: &str) -> rusqlite::Result<()> {
    let audit = audit_record("ensure", BASAL, Some(scope), outcome, true);
    append_audit_on_conn(conn, &audit, None, None, Some(scope), None)
}

fn check_grants(conn: &Connection, key: &WatchKey, now: i64) -> rusqlite::Result<bool> {
    let (connection, poll) = key.kind.poll();
    Ok(poll_grant(conn, BASAL, connection, poll, now)?
        && poll_grant(conn, BASAL, connection, key.kind.item_read(), now)?
        && poll_grant(conn, BASAL, PUBLIC_CONNECTION, PUBLIC_CHECK, now)?)
}
