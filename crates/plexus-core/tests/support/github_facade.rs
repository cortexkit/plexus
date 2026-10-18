//! Shared deterministic fixtures for the GitHub facade integration tests.
//! Include this module from each test binary rather than copying its assertions.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

/// One clock for receipt leases, approval deadlines and credential expiry.
#[derive(Clone)]
pub struct FixedClock(Arc<AtomicI64>);

impl FixedClock {
    pub fn new(now_ms: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now_ms)))
    }

    pub fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    pub fn advance_ms(&self, delta_ms: i64) {
        assert!(delta_ms >= 0, "clock cannot move backwards");
        self.0.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

/// Exact five-column assertion on one facade audit row, including SQL NULLs.
/// Querying the columns by name prevents an old agent_id/agent_handle column
/// from accidentally satisfying the new facade attribution contract.
pub fn assert_facade_audit_row(
    row: &rusqlite::Row<'_>,
    claimed_agent_id: Option<&str>,
    app_handle_id: Option<&str>,
    action: Option<&str>,
    request_id: Option<&str>,
    refusal_code: Option<&str>,
) {
    for (column, expected) in [
        ("claimed_agent_id", claimed_agent_id),
        ("app_handle_id", app_handle_id),
        ("action", action),
        ("request_id", request_id),
        ("refusal_code", refusal_code),
    ] {
        let actual: Option<String> = row
            .get(column)
            .unwrap_or_else(|error| panic!("{column}: {error}"));
        assert_eq!(actual.as_deref(), expected, "audit column {column}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_advances_lease_time() {
        let clock = FixedClock::new(1_700_000_000_999);
        clock.advance_ms(60_001);
        assert_eq!(clock.now_ms(), 1_700_000_061_000);
    }

    #[test]
    fn audit_helper_checks_all_five_columns_including_null() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE facade_audit (claimed_agent_id TEXT, app_handle_id TEXT, action TEXT, request_id TEXT, refusal_code TEXT); INSERT INTO facade_audit VALUES ('agent-1', 'app-1', 'github.bot_request', 'req-1', NULL);").unwrap();
        db.query_row("SELECT * FROM facade_audit", [], |row| {
            assert_facade_audit_row(
                row,
                Some("agent-1"),
                Some("app-1"),
                Some("github.bot_request"),
                Some("req-1"),
                None,
            );
            Ok(())
        })
        .unwrap();
    }
}
