//! Test-only instrumentation for store boundary calls.

use super::{Connection, StorageDescriptor, StoreError};
use std::cell::Cell;

thread_local! {
    static CALLS: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
}

// Count all store-boundary reads and transactions, not just selected
// scheduler methods. A new per-watch lookup must spend this budget too.
pub(super) struct SqliteStore(cortexkit_store::SqliteStore);

impl std::ops::Deref for SqliteStore {
    type Target = cortexkit_store::SqliteStore;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn record(fenced: bool) {
    CALLS.with(|calls| {
        if let Some((total, fenced_total)) = calls.get() {
            calls.set(Some((total + 1, fenced_total + usize::from(fenced))));
        }
    });
}

impl SqliteStore {
    pub(super) fn with_read<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, StoreError> {
        record(false);
        self.0.with_read(f)
    }

    pub(super) fn with_conn_fenced<T>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> rusqlite::Result<T>,
    ) -> Result<T, StoreError> {
        record(true);
        self.0.with_conn_fenced(f)
    }

    #[allow(deprecated)]
    pub(super) fn with_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, StoreError> {
        record(false);
        self.0.with_conn(f)
    }
}

pub(super) fn open_sqlite(descriptor: &StorageDescriptor) -> Result<SqliteStore, StoreError> {
    cortexkit_store::open_sqlite(descriptor).map(SqliteStore)
}

pub(super) fn count_calls(work: impl FnOnce()) -> usize {
    count_calls_by_kind(work).0
}

pub(super) fn count_calls_by_kind(work: impl FnOnce()) -> (usize, usize) {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            CALLS.with(|calls| calls.set(None));
        }
    }
    let _guard = Guard;
    CALLS.with(|calls| calls.set(Some((0, 0))));
    work();
    CALLS.with(|calls| calls.get().unwrap())
}
