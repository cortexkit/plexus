//! Store access shared by search facades: chain order, monthly allowances,
//! per-backend rate limits, query audit rows and candidate connections.

use cortexkit_store::StoreError;
use rusqlite::OptionalExtension;

use super::{now_ms, AuditRecord, PlexusStore};
use crate::web_search::providers::provider_named;

pub const MAX_WEB_SEARCH_ALLOWANCE: u32 = 10_000_000;

/// Admission with no configured allowance does not create a count or a receipt.
#[derive(Debug, PartialEq, Eq)]
pub enum WebSearchAllowanceAdmission {
    Unlimited,
    Reserved(WebSearchAllowanceReservation),
    Exhausted,
}

/// A counted attempt, bound to the UTC month in which it was admitted. Keep it
/// for Sent/OutcomeUnknown; consume it with `release_web_search_allowance` when
/// nothing was sent. It is deliberately not Clone, so settlement owns the receipt.
#[derive(Debug, PartialEq, Eq)]
pub struct WebSearchAllowanceReservation {
    owner_principal: String,
    provider: String,
    month_utc: String,
}

fn validate_provider(provider: &str) -> Result<(), StoreError> {
    if provider_named(provider).is_none() {
        return Err(StoreError::Backend("unknown web search provider".into()));
    }
    Ok(())
}

fn order_on_conn(conn: &rusqlite::Connection) -> rusqlite::Result<Option<Vec<String>>> {
    conn.query_row(
        "SELECT providers FROM web_search_order WHERE singleton = 1",
        [],
        |row| super::parse_json_column(&row.get::<_, String>(0)?),
    )
    .optional()
}

fn allowance_on_conn(conn: &rusqlite::Connection, provider: &str) -> rusqlite::Result<Option<u32>> {
    conn.query_row(
        "SELECT allowance FROM web_search_allowances WHERE provider = ?1",
        [provider],
        |row| row.get(0),
    )
    .optional()
}

fn month_on_conn(conn: &rusqlite::Connection, at_ms: i64) -> rusqlite::Result<String> {
    conn.query_row(
        "SELECT strftime('%Y-%m', ?1 / 1000.0, 'unixepoch')",
        [at_ms],
        |row| row.get(0),
    )
}

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
    /// The operator's ordered names, or None for the Exa compatibility path.
    pub fn web_search_order(&self) -> Result<Option<Vec<String>>, StoreError> {
        self.inner.with_read(order_on_conn)
    }

    /// Replace a nonempty, duplicate-free order and return the replaced order.
    pub fn set_web_search_order(
        &self,
        providers: &[String],
    ) -> Result<Option<Vec<String>>, StoreError> {
        if providers.is_empty() {
            return Err(StoreError::Backend(
                "web search order must not be empty".into(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for provider in providers {
            validate_provider(provider)?;
            if !seen.insert(provider) {
                return Err(StoreError::Backend("duplicate web search provider".into()));
            }
        }
        let json = serde_json::to_string(providers)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        self.inner.with_conn_fenced(|conn| {
            let previous = order_on_conn(conn)?;
            conn.execute(
                "INSERT INTO web_search_order (singleton, providers) VALUES (1, ?1)
                ON CONFLICT (singleton) DO UPDATE SET providers = excluded.providers",
                [json],
            )?;
            Ok(previous)
        })
    }

    /// Return to compatibility mode, returning the order removed by this write.
    pub fn clear_web_search_order(&self) -> Result<Option<Vec<String>>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let previous = order_on_conn(conn)?;
            conn.execute("DELETE FROM web_search_order WHERE singleton = 1", [])?;
            Ok(previous)
        })
    }

    pub fn web_search_allowance(&self, provider: &str) -> Result<Option<u32>, StoreError> {
        validate_provider(provider)?;
        self.inner
            .with_read(|conn| allowance_on_conn(conn, provider))
    }

    /// Set a monthly limit applied separately to each connection owner's usage,
    /// without resetting any usage when that owner reconnects.
    pub fn set_web_search_allowance(
        &self,
        provider: &str,
        allowance: u32,
    ) -> Result<Option<u32>, StoreError> {
        validate_provider(provider)?;
        if !(1..=MAX_WEB_SEARCH_ALLOWANCE).contains(&allowance) {
            return Err(StoreError::Backend(
                "web search allowance must be between 1 and 10000000".into(),
            ));
        }
        self.inner.with_conn_fenced(|conn| {
            let previous = allowance_on_conn(conn, provider)?;
            conn.execute(
                "INSERT INTO web_search_allowances (provider, allowance) VALUES (?1, ?2)
                ON CONFLICT (provider) DO UPDATE SET allowance = excluded.allowance",
                (provider, allowance),
            )?;
            Ok(previous)
        })
    }

    /// Remove only the limit. Retained usage applies if the limit is set again.
    pub fn clear_web_search_allowance(&self, provider: &str) -> Result<Option<u32>, StoreError> {
        validate_provider(provider)?;
        self.inner.with_conn_fenced(|conn| {
            let previous = allowance_on_conn(conn, provider)?;
            conn.execute(
                "DELETE FROM web_search_allowances WHERE provider = ?1",
                [provider],
            )?;
            Ok(previous)
        })
    }

    /// Count for the calendar month UTC containing `at_ms` (Unix milliseconds).
    /// `owner_principal` is the resolved connection's owner, not a caller that
    /// invokes it through a grant. All of that owner's connections share usage.
    pub fn web_search_allowance_used(
        &self,
        provider: &str,
        owner_principal: &str,
        at_ms: i64,
    ) -> Result<u32, StoreError> {
        validate_provider(provider)?;
        self.inner.with_read(|conn| {
            let month = month_on_conn(conn, at_ms)?;
            Ok(conn
                .query_row(
                    "SELECT used FROM web_search_allowance_counts
                WHERE principal = ?1 AND provider = ?2 AND month_utc = ?3",
                    (owner_principal, provider, month),
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0))
        })
    }

    /// Check the live allowance and reserve one attempt in the same fenced
    /// transaction. The caller supplies its admission clock in Unix milliseconds.
    /// Pass the resolved connection's owner as `owner_principal`, never the
    /// grantee making the call; reconnecting must not create a fresh allowance.
    pub fn reserve_web_search_allowance(
        &self,
        provider: &str,
        owner_principal: &str,
        at_ms: i64,
    ) -> Result<WebSearchAllowanceAdmission, StoreError> {
        validate_provider(provider)?;
        self.inner.with_conn_fenced(|conn| {
            let Some(allowance) = allowance_on_conn(conn, provider)? else {
                return Ok(WebSearchAllowanceAdmission::Unlimited);
            };
            let month = month_on_conn(conn, at_ms)?;
            let changed = conn.execute(
                "INSERT INTO web_search_allowance_counts (principal, provider, month_utc, used)
                VALUES (?1, ?2, ?3, 1)
                ON CONFLICT (principal, provider, month_utc) DO UPDATE SET used = used + 1
                WHERE used < ?4",
                rusqlite::params![owner_principal, provider, month, allowance],
            )?;
            if changed == 0 {
                return Ok(WebSearchAllowanceAdmission::Exhausted);
            }
            Ok(WebSearchAllowanceAdmission::Reserved(
                WebSearchAllowanceReservation {
                    owner_principal: owner_principal.to_owned(),
                    provider: provider.to_owned(),
                    month_utc: month,
                },
            ))
        })
    }

    /// Release a NotSent attempt against its original month, even if the month
    /// rolled over or the allowance was cleared while dispatch was in flight.
    /// Returns false if the count is already zero or absent; never underflows.
    pub fn release_web_search_allowance(
        &self,
        reservation: WebSearchAllowanceReservation,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            Ok(conn.execute(
                "UPDATE web_search_allowance_counts SET used = used - 1
                WHERE principal = ?1 AND provider = ?2 AND month_utc = ?3 AND used > 0",
                (
                    reservation.owner_principal,
                    reservation.provider,
                    reservation.month_utc,
                ),
            )? == 1)
        })
    }

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
    ///
    /// Expiry is judged at `now_ms`, the caller's clock, so the candidate set
    /// agrees with the grant check the caller then applies at the same instant.
    pub fn web_search_candidate_connection_ids(
        &self,
        caller: &str,
        app_key: &str,
        now_ms: i64,
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
                statement.query_map((caller, app_key, now_ms), |row| row.get::<_, String>(0))?;
            rows.collect()
        })
    }
}

#[cfg(test)]
#[path = "web_search_tests.rs"]
mod tests;
