//! Durable router reports, independent of the connection-keyed GitHub outbox.

use super::{PlexusStore, StoreError};

pub const ROUTE_FACT_MAX_BYTES: usize = 4096;
const MAX_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const MAX_ROWS: i64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteFact {
    pub msg_id: String,
    pub body: String,
}

impl PlexusStore {
    #[cfg(test)]
    pub(crate) fn fail_route_fact_insert_for_test(&self) {
        self.inner.with_conn_fenced(|conn| conn.execute_batch(
            "CREATE TRIGGER fail_route_fact BEFORE INSERT ON route_fact_outbox BEGIN SELECT RAISE(ABORT, 'route fact test failure'); END;"
        )).unwrap();
    }
    /// Store exactly the params used by the call. Oversized reports stay call-only.
    pub fn enqueue_route_fact(
        &self,
        msg_id: &str,
        params: &serde_json::Value,
        at_ms: i64,
    ) -> Result<bool, StoreError> {
        let body = serde_json::json!({"op": "route.report", "params": params}).to_string();
        if body.len() > ROUTE_FACT_MAX_BYTES {
            return Ok(false);
        }
        let queued = self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO route_fact_outbox(msg_id, body, created_at_ms)
                 VALUES (?1, ?2, ?3) ON CONFLICT(msg_id) DO NOTHING",
                (msg_id, body, at_ms),
            )?;
            Ok(true)
        })?;
        self.outbox_ready.notify_one();
        Ok(queued)
    }

    pub fn pending_route_facts(&self, limit: usize) -> Result<Vec<RouteFact>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT msg_id, body FROM route_fact_outbox
                 ORDER BY created_at_ms, msg_id LIMIT ?1",
            )?;
            let rows = statement.query_map([limit as i64], |row| {
                Ok(RouteFact {
                    msg_id: row.get(0)?,
                    body: row.get(1)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    /// Delete only after the body publisher confirms durable acceptance.
    pub fn delete_published_route_fact(&self, msg_id: &str) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute("DELETE FROM route_fact_outbox WHERE msg_id=?1", [msg_id])?;
            Ok(())
        })
    }

    /// Hourly housekeeping uses the age index for both the range and row-cap scans.
    pub fn prune_route_facts(&self, now_ms: i64) -> Result<usize, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let aged = conn.execute(
                "DELETE FROM route_fact_outbox WHERE created_at_ms < ?1",
                [now_ms.saturating_sub(MAX_AGE_MS)],
            )?;
            let excess = conn.execute(
                "DELETE FROM route_fact_outbox WHERE msg_id IN (
                    SELECT msg_id FROM route_fact_outbox
                    ORDER BY created_at_ms DESC, msg_id DESC LIMIT -1 OFFSET ?1)",
                [MAX_ROWS],
            )?;
            Ok(aged + excess)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn descriptor() -> cortexkit_store::StorageDescriptor {
        let path = crate::test_scratch::store_path();
        cortexkit_store::StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "route-fact-tests".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite { path },
        }
    }

    fn store() -> PlexusStore {
        PlexusStore::open(&descriptor()).unwrap()
    }

    #[test]
    fn migration_62_adds_reports_without_changing_existing_data() {
        let inner = cortexkit_store::open_sqlite(&descriptor()).unwrap();
        // Pinned to migration 62 by version, not by position: later migrations
        // append after it and must not move what this test applies.
        let all = super::super::MIGRATIONS;
        let at = all
            .iter()
            .position(|migration| migration.version == 62)
            .expect("migration 62 exists");
        let migrations = &all[..=at];
        inner.migrate("plexus", &migrations[..at]).unwrap();
        inner.with_conn_fenced(|conn| conn.execute_batch("INSERT INTO connections(principal,connection_id,app_key,status,created_at_ms,updated_at_ms) VALUES('owner','c','exa_rest','active',1,2)")).unwrap();
        let outcome = inner.migrate("plexus", migrations).unwrap();
        assert_eq!((outcome.applied, outcome.recorded), (1, 62));
        assert_eq!(inner.migrate("plexus", migrations).unwrap().applied, 0);
        inner.with_read(|conn| {
            assert_eq!(conn.query_row("SELECT connection_id FROM connections", [], |row| row.get::<_,String>(0))?, "c");
            assert_eq!(conn.query_row("SELECT count(*) FROM route_fact_outbox", [], |row| row.get::<_,i64>(0))?, 0);
            let mut statement = conn.prepare("EXPLAIN QUERY PLAN SELECT msg_id FROM route_fact_outbox WHERE created_at_ms < 100 ORDER BY created_at_ms, msg_id")?;
            let plan = statement.query_map([], |row| row.get::<_,String>(3))?.collect::<rusqlite::Result<Vec<_>>>()?;
            assert!(plan.iter().any(|line| line.contains("route_fact_outbox_age")), "{plan:?}");
            Ok(())
        }).unwrap();
    }

    #[test]
    fn report_row_preserves_call_params_and_size_limit() {
        let store = store();
        let params = json!({"decision_id":"d", "outcome":"completed"});
        assert!(store.enqueue_route_fact("d", &params, 1).unwrap());
        let rows = store.pending_route_facts(10).unwrap();
        assert_eq!(rows[0].msg_id, "d");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&rows[0].body).unwrap(),
            json!({"op":"route.report", "params":params})
        );
        assert!(!store
            .enqueue_route_fact("large", &json!({"text":"x".repeat(4096)}), 1)
            .unwrap());
        assert_eq!(store.pending_route_facts(10).unwrap().len(), 1);
        store.delete_published_route_fact("d").unwrap();
        assert!(store.pending_route_facts(10).unwrap().is_empty());
    }

    #[test]
    fn hourly_retention_removes_expired_and_oldest_excess_reports() {
        let store = store();
        store.inner.with_conn_fenced(|conn| {
            conn.execute_batch("WITH RECURSIVE seq(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM seq WHERE n<10000)
                INSERT INTO route_fact_outbox SELECT printf('d%05d',n), '{}', n FROM seq;")?;
            Ok(())
        }).unwrap();
        assert_eq!(store.prune_route_facts(MAX_AGE_MS).unwrap(), 1);
        assert_eq!(store.pending_route_facts(1).unwrap()[0].msg_id, "d00001");
        assert_eq!(
            store.prune_route_facts(MAX_AGE_MS + 10_001).unwrap(),
            10_000
        );
    }

    #[test]
    fn scheduler_prunes_route_facts_only_at_the_hourly_event_gate() {
        let store = std::sync::Arc::new(store());
        let engine = crate::governance::GovernanceEngine::new(
            store.clone(),
            std::sync::Arc::new(crate::credentials::StubCredentialSource::default()),
            std::sync::Arc::new(crate::transport::MockTransport::default()),
        );
        let scheduler = crate::scheduler::Scheduler::new(engine, 30 * 24 * 60 * 60 * 1000);
        let now = crate::storage::now_ms();
        let params = json!({"decision_id":"d", "outcome":"completed"});
        store
            .enqueue_route_fact("first:outcome", &params, 0)
            .unwrap();
        scheduler.run_pass(&[], now);
        assert!(store.pending_route_facts(1).unwrap().is_empty());
        store
            .enqueue_route_fact("second:outcome", &params, 0)
            .unwrap();
        scheduler.run_pass(&[], now + 60_000);
        assert_eq!(store.pending_route_facts(1).unwrap().len(), 1);
        scheduler.reset_event_retention_for_test();
        scheduler.run_pass(&[], now + 61_000);
        assert!(store.pending_route_facts(1).unwrap().is_empty());
    }
}
