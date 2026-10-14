//! Store access shared by search facades: per-backend rate limits, the audit
//! row that carries the query, and the connections that could back a search.

use cortexkit_store::StoreError;
use rusqlite::OptionalExtension;

use super::{now_ms, AuditRecord, PlexusStore};

/// Operator-set per-minute limits for one web search backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSearchLimits {
    /// Calls one caller (a principal, plus its verified agent when present)
    /// may make per minute.
    pub per_caller_per_minute: u32,
    /// Calls every caller together may make per minute.
    pub per_backend_per_minute: u32,
}

impl PlexusStore {
    /// The stored limits for `backend`, or `None` when the operator never set
    /// any and the compiled defaults apply.
    pub fn web_search_limits(&self, backend: &str) -> Result<Option<WebSearchLimits>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT per_caller_per_minute, per_backend_per_minute
                 FROM web_search_limits WHERE backend = ?1",
                [backend],
                |row| {
                    Ok(WebSearchLimits {
                        per_caller_per_minute: row.get(0)?,
                        per_backend_per_minute: row.get(1)?,
                    })
                },
            )
            .optional()
        })
    }

    /// Replace the limits for `backend` and return the row it replaced. The
    /// read of the old row and the write share one transaction, so the row
    /// returned is the one this write replaced even when another write lands
    /// at the same moment.
    pub fn set_web_search_limits(
        &self,
        backend: &str,
        limits: WebSearchLimits,
    ) -> Result<Option<WebSearchLimits>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let previous = conn
                .query_row(
                    "SELECT per_caller_per_minute, per_backend_per_minute
                     FROM web_search_limits WHERE backend = ?1",
                    [backend],
                    |row| {
                        Ok(WebSearchLimits {
                            per_caller_per_minute: row.get(0)?,
                            per_backend_per_minute: row.get(1)?,
                        })
                    },
                )
                .optional()?;
            conn.execute(
                "INSERT INTO web_search_limits
                    (backend, per_caller_per_minute, per_backend_per_minute, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (backend) DO UPDATE SET
                    per_caller_per_minute = excluded.per_caller_per_minute,
                    per_backend_per_minute = excluded.per_backend_per_minute,
                    updated_at_ms = excluded.updated_at_ms",
                rusqlite::params![
                    backend,
                    limits.per_caller_per_minute,
                    limits.per_backend_per_minute,
                    now_ms()
                ],
            )?;
            Ok(previous)
        })
    }

    /// Append the audit row for one search call (web_search or code_search):
    /// its query text, the number of results returned, the daemon scope bound
    /// to the caller's route when there is one, and the originating call a
    /// relay reported when it reported one.
    pub fn append_web_search_audit(
        &self,
        record: &AuditRecord,
        query_text: Option<&str>,
        result_count: Option<i64>,
        scope: Option<&crate::scope::CallScope>,
        relay_origin: Option<&super::RelayOrigin>,
    ) -> Result<(), StoreError> {
        self.append_audit_row(record, query_text, result_count, scope, relay_origin)
    }

    /// Ids of the connections to `app_key` that `caller` could invoke: the ones
    /// it owns, and the ones another principal shares with it through an invoke
    /// grant. This only narrows the search. Each id is then resolved with
    /// [`PlexusStore::connection_for_invoke`], the resolution the governance
    /// engine itself uses, and checked for a grant that actually admits the
    /// action.
    ///
    /// Revoked, disabled and never-activated connections are left out. Degraded
    /// and auth-required rows remain candidates so governance can name their
    /// recoverable health condition. Expired grants do not widen the candidate set.
    pub fn web_search_candidate_connection_ids(
        &self,
        caller: &str,
        app_key: &str,
    ) -> Result<Vec<String>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT DISTINCT connection.connection_id
                 FROM connections AS connection
                 WHERE connection.app_key = ?2
                   AND connection.status NOT IN ('pending', 'disabled', 'revoked')
                   AND (connection.principal = ?1 OR EXISTS (
                       SELECT 1 FROM grants AS grant
                       WHERE grant.principal = connection.principal
                         AND grant.connection_id = connection.connection_id
                         AND grant.authority_kind = 'invoke'
                          AND grant.grantee_principal = ?1 AND grant.grantee_principal <> '*'
                          AND (grant.expires_at IS NULL OR grant.expires_at > ?3)
                   ))
                 ORDER BY connection.connection_id",
            )?;
            let rows =
                statement.query_map((caller, app_key, now_ms()), |row| row.get::<_, String>(0))?;
            rows.collect()
        })
    }
}
