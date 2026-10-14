//! Startup and periodic receipt maintenance use the same bounded store pass.
use crate::github::receipt::Receipt;
use crate::storage::PlexusStore;
use cortexkit_store::StoreError;

/// Run once at startup and again on each scheduler tick. Returned rows belong
/// in the uncertain-write reconciliation queue; approvals are never consumed.
pub fn sweep_receipts(store: &PlexusStore, now_ms: i64) -> Result<Vec<Receipt>, StoreError> {
    store.sweep_github_receipts(now_ms, 100)
}
