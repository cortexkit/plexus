//! The read budget for GitHub bot reads.
//!
//! A bot's reads and writes spend the same GitHub App installation quota
//! (5,000 requests an hour). Heavy reading must never leave a bot unable to
//! post, so reads are budgeted per installation's handle and writes are not:
//!
//! - a ledger counts every read request sent in the trailing hour, and a read
//!   that would take the hour past [`BOT_READ_HOURLY_CAP`] is refused;
//! - the `x-ratelimit-remaining` GitHub last reported for the handle is kept,
//!   and while it is under [`BOT_READ_REMAINING_FLOOR`] reads are refused until
//!   GitHub's reported reset time.
//!
//! Each GitHub request is reserved before it is sent and is never refunded,
//! because a request that was sent spent quota whatever its outcome. Ledger
//! entries older than an hour no longer count and are deleted as reads arrive.

use cortexkit_store::StoreError;
use rusqlite::OptionalExtension;

use super::PlexusStore;

/// Read requests one installation's handle may send in any trailing hour. It
/// leaves 1,500 of GitHub's 5,000 for the bot's writes.
pub const BOT_READ_HOURLY_CAP: i64 = 3_500;
/// Below this many requests remaining in GitHub's own window, reads stop until
/// GitHub's reset, so the bot keeps quota for writes even when something
/// outside plexus spent the installation's quota.
pub const BOT_READ_REMAINING_FLOOR: i64 = 1_000;
/// The window the ledger counts over.
pub const BOT_READ_WINDOW_MS: i64 = 60 * 60 * 1_000;

/// Whether a read may be sent now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotReadAdmission {
    /// The units were recorded in the ledger; send the requests.
    Reserved,
    /// Nothing was recorded; retry no sooner than this many milliseconds.
    Exhausted { retry_after_ms: i64 },
}

/// The rate-limit state GitHub reported on its last reply to a handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BotRateLimit {
    pub remaining: i64,
    pub reset_at_ms: i64,
}

impl PlexusStore {
    /// Reserve `units` read requests for `app_handle_id` at `now`, or say how
    /// long to wait. One unit is one HTTP request: each page, and the storage
    /// download a log read is redirected to, is a unit of its own.
    pub fn reserve_github_bot_read(
        &self,
        app_handle_id: &str,
        units: i64,
        now: i64,
    ) -> Result<BotReadAdmission, StoreError> {
        if !(1..=16).contains(&units) {
            return Err(StoreError::Backend(
                "a bot read reserves between 1 and 16 requests".into(),
            ));
        }
        self.inner.with_conn_fenced(|conn| {
            let window_start = now.saturating_sub(BOT_READ_WINDOW_MS);
            conn.execute(
                "DELETE FROM github_bot_read_ledger WHERE reserved_at_ms <= ?1",
                [window_start],
            )?;
            let limit: Option<(i64, i64)> = conn
                .query_row(
                    "SELECT remaining, reset_at_ms FROM github_bot_rate_limit WHERE app_handle_id = ?1",
                    [app_handle_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((remaining, reset_at_ms)) = limit {
                if remaining < BOT_READ_REMAINING_FLOOR && now < reset_at_ms {
                    return Ok(BotReadAdmission::Exhausted {
                        retry_after_ms: reset_at_ms - now,
                    });
                }
            }
            let mut statement = conn.prepare(
                "SELECT reserved_at_ms, units FROM github_bot_read_ledger
                 WHERE app_handle_id = ?1 AND reserved_at_ms > ?2
                 ORDER BY reserved_at_ms",
            )?;
            let entries: Vec<(i64, i64)> = statement
                .query_map((app_handle_id, window_start), |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
            let used: i64 = entries.iter().map(|(_, units)| units).sum();
            if used + units > BOT_READ_HOURLY_CAP {
                // The earliest moment enough old entries leave the window for
                // this reservation to fit.
                let mut freed = 0;
                let mut retry_at = now + BOT_READ_WINDOW_MS;
                for (reserved_at, entry_units) in &entries {
                    freed += entry_units;
                    if used - freed + units <= BOT_READ_HOURLY_CAP {
                        retry_at = reserved_at + BOT_READ_WINDOW_MS;
                        break;
                    }
                }
                return Ok(BotReadAdmission::Exhausted {
                    retry_after_ms: (retry_at - now).max(1),
                });
            }
            conn.execute(
                "INSERT INTO github_bot_read_ledger (app_handle_id, reserved_at_ms, units)
                 VALUES (?1, ?2, ?3)",
                (app_handle_id, now, units),
            )?;
            Ok(BotReadAdmission::Reserved)
        })
    }

    /// Record the `x-ratelimit-remaining` and reset GitHub reported on a reply
    /// to `app_handle_id`. Called for every bot read reply that carried them.
    pub fn record_github_bot_rate_limit(
        &self,
        app_handle_id: &str,
        limit: BotRateLimit,
        now: i64,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO github_bot_rate_limit (app_handle_id, remaining, reset_at_ms, observed_at_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(app_handle_id) DO UPDATE SET
                     remaining = excluded.remaining,
                     reset_at_ms = excluded.reset_at_ms,
                     observed_at_ms = excluded.observed_at_ms",
                (app_handle_id, limit.remaining.max(0), limit.reset_at_ms, now),
            )?;
            Ok(())
        })
    }

    /// The read requests `app_handle_id` has reserved in the hour before `now`.
    pub fn github_bot_reads_in_window(
        &self,
        app_handle_id: &str,
        now: i64,
    ) -> Result<i64, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT COALESCE(SUM(units), 0) FROM github_bot_read_ledger
                 WHERE app_handle_id = ?1 AND reserved_at_ms > ?2",
                (app_handle_id, now.saturating_sub(BOT_READ_WINDOW_MS)),
                |row| row.get(0),
            )
        })
    }

    /// The ledger rows stored for every handle, aged-out ones included until a
    /// later reservation deletes them.
    #[cfg(test)]
    pub(crate) fn github_bot_read_ledger_rows(&self) -> Result<i64, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row("SELECT COUNT(*) FROM github_bot_read_ledger", [], |row| {
                row.get(0)
            })
        })
    }
}

#[cfg(test)]
#[path = "github_bot_reads_tests.rs"]
mod tests;
