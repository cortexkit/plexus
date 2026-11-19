//! Persisted write reconciliation retries and terminal results.

use super::*;

const DUE_PENDING: &str = "next_attempt_at_ms<=:now";
const EXPIRED_RESULTS: &str = "status!='pending' AND updated_at_ms < :cutoff";

impl PlexusStore {
    /// Persist screened arguments only until the next terminal read-back. One day
    /// is a hard retention ceiling independent of mutable manifest timeouts.
    pub fn enqueue_write_reconciliation(
        &self,
        record: &crate::reconciliation::OutcomeUnknownRecord,
        intent_id: Option<&str>,
    ) -> Result<(), StoreError> {
        if crate::secret_input::contains_secret_input(&record.args) {
            return Err(StoreError::Backend("secret_input_rejected".to_string()));
        }
        let encoded =
            serde_json::to_string(record).map_err(|e| StoreError::Backend(e.to_string()))?;
        self.inner.with_conn_fenced(|conn| {
            let tx = conn;
            tx.execute(
                "INSERT INTO pending_write_reconciliations
                (principal,request_id,record_json,intent_id,expires_at_ms) VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![
                    record.principal,
                    record.request_id,
                    encoded,
                    intent_id,
                    record.occurred_at_ms.saturating_add(AUDIT_MILLIS_PER_DAY)
                ],
            )?;
            tx.execute(
                "INSERT INTO write_reconciliation_results
                (principal,request_id,acting_principal,connection_id,action,status,updated_at_ms)
                 VALUES (?1,?2,?3,?4,?5,'pending',?6)
                 ON CONFLICT(principal,request_id) DO UPDATE SET status='pending',reason=NULL,updated_at_ms=excluded.updated_at_ms",
                rusqlite::params![
                    record.principal,
                    record.request_id,
                    record.acting_principal,
                    record.connection_id,
                    record.action,
                    now_ms()
                ],
            )?;
            tx.execute("UPDATE action_requests SET reconciliation_status='pending' WHERE principal=?1 AND request_id=?2",rusqlite::params![record.principal,intent_id])?;
            Ok(())
        })
    }

    pub(crate) fn write_reconciliation_work(
        &self,
        now: i64,
        retention_window_ms: i64,
    ) -> Result<(bool, bool), StoreError> {
        self.inner.with_read(|conn| {
            conn.prepare_cached(&format!("SELECT
                EXISTS(SELECT 1 FROM pending_write_reconciliations WHERE {DUE_PENDING}),
                EXISTS(SELECT 1 FROM write_reconciliation_results WHERE {EXPIRED_RESULTS})"))?
                .query_row(rusqlite::named_params!{":now":now, ":cutoff":now.saturating_sub(retention_window_ms)}, |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
        })
    }

    /// Due records in expiry order, decoded only until `limit` valid ones are
    /// found, so a backlog does not decode payloads the caller will not reach
    /// this tick. A record that does not decode is settled ambiguous and
    /// removed as it is passed; those removals are bounded by the row limit
    /// of the scan, not by `limit`.
    pub(crate) fn pending_write_reconciliations_at(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<crate::reconciliation::PendingWriteReconciliation>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let mut stmt = conn.prepare(&format!("SELECT principal,request_id,record_json,expires_at_ms FROM pending_write_reconciliations WHERE {DUE_PENDING} ORDER BY expires_at_ms,principal,request_id LIMIT :limit"))?;
            let mut rows = stmt.query(rusqlite::named_params!{":now":now, ":limit":RECONCILIATION_BATCH_ROWS})?;
            let mut pending = Vec::with_capacity(limit.min(RECONCILIATION_BATCH_ROWS as usize));
            let mut undecodable = Vec::new();
            while pending.len() < limit {
                let Some(row) = rows.next()? else {
                    break;
                };
                let (principal, request_id, encoded, expires_at_ms): (String, String, String, i64) =
                    (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?);
                match serde_json::from_str(&encoded) {
                    Ok(record) => pending.push(crate::reconciliation::PendingWriteReconciliation {
                        record,
                        expires_at_ms,
                    }),
                    Err(error) => {
                        crate::diag!(warn storage: "write reconciliation record does not decode; settling it as ambiguous: principal={principal:?} request_id={request_id:?}: class={:?} line={} column={}",error.classify(),error.line(),error.column());
                        undecodable.push((principal, request_id));
                    }
                }
            }
            drop(rows);
            drop(stmt);
            for (principal, request_id) in undecodable {
                conn.execute("UPDATE write_reconciliation_results SET status='ambiguous', reason='record_undecodable', updated_at_ms=?3
                    WHERE principal=?1 AND request_id=?2", rusqlite::params![principal, request_id, now_ms()])?;
                conn.execute("UPDATE action_requests SET reconciliation_status='ambiguous' WHERE principal=?1 AND request_id IN
                    (SELECT intent_id FROM pending_write_reconciliations WHERE principal=?1 AND request_id=?2)",
                    rusqlite::params![principal, request_id])?;
                conn.execute("DELETE FROM pending_write_reconciliations WHERE principal=?1 AND request_id=?2",
                    rusqlite::params![principal, request_id])?;
            }
            Ok(pending)
        })
    }

    /// Delete the argument-bearing record in the same transaction that records
    /// the terminal status. Results deliberately retain neither args nor evidence.
    pub(crate) fn finish_write_reconciliation(
        &self,
        record: &crate::reconciliation::OutcomeUnknownRecord,
        status: &str,
        reason: Option<&str>,
    ) -> Result<(), StoreError> {
        self.finish_write_reconciliation_with_intent(record, None, status, reason)
    }

    pub(crate) fn finish_write_reconciliation_with_intent(
        &self,
        record: &crate::reconciliation::OutcomeUnknownRecord,
        intent_id: Option<&str>,
        status: &str,
        reason: Option<&str>,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let tx = conn;
            tx.execute("INSERT INTO write_reconciliation_results
                (principal,request_id,acting_principal,connection_id,action,status,reason,updated_at_ms)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                ON CONFLICT(principal,request_id) DO UPDATE SET status=excluded.status,reason=excluded.reason,updated_at_ms=excluded.updated_at_ms",
                rusqlite::params![record.principal, record.request_id, record.acting_principal,record.connection_id,record.action,status,reason,now_ms()])?;
            tx.execute("UPDATE action_requests SET reconciliation_status=?3 WHERE principal=?1 AND request_id=COALESCE(?4,
                (SELECT intent_id FROM pending_write_reconciliations WHERE principal=?1 AND request_id=?2))",
                rusqlite::params![record.principal,record.request_id,status,intent_id])?;
            tx.execute("DELETE FROM pending_write_reconciliations WHERE principal=?1 AND request_id=?2", rusqlite::params![record.principal, record.request_id])?;
            Ok(())
        })
    }

    /// Owners see their connections' results; callers see only their own results.
    /// The flag reports additional rows beyond this bounded diagnostic snapshot.
    pub fn list_write_reconciliations(
        &self,
        principal: &str,
    ) -> Result<(Vec<crate::reconciliation::WriteReconciliationStatus>, bool), StoreError> {
        self.inner.with_read(|conn| {
            let mut stmt = conn.prepare("SELECT request_id,connection_id,action,status,reason FROM write_reconciliation_results WHERE principal=?1 OR acting_principal=?1 ORDER BY updated_at_ms DESC,request_id LIMIT ?2")?;
            let mut rows: Vec<_> = stmt.query_map((principal, RECONCILIATION_BATCH_ROWS + 1), |row| Ok(crate::reconciliation::WriteReconciliationStatus {
                request_id: row.get(0)?, connection_id: row.get(1)?, action: row.get(2)?, status: row.get(3)?, reason: row.get(4)?,
            }))?.collect::<rusqlite::Result<_>>()?;
            let truncated = rows.len() > RECONCILIATION_BATCH_ROWS as usize;
            rows.truncate(RECONCILIATION_BATCH_ROWS as usize);
            Ok((rows, truncated))
        })
    }

    pub(crate) fn backoff_write_reconciliation(
        &self,
        record: &crate::reconciliation::OutcomeUnknownRecord,
        now: i64,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            // Read the attempt count and write the next attempt under the same
            // writer, so the delay is computed in Rust by the shared backoff.
            let attempts: Option<i64> = conn
                .query_row(
                    "SELECT retry_attempts FROM pending_write_reconciliations WHERE principal=?1 AND request_id=?2",
                    rusqlite::params![record.principal, record.request_id],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(attempts) = attempts else {
                return Ok(());
            };
            let delay_ms = reconciliation_retry_delay_ms(attempts);
            conn.execute("UPDATE pending_write_reconciliations SET next_attempt_at_ms=?3 + ?4, retry_attempts=MIN(retry_attempts+1,4) WHERE principal=?1 AND request_id=?2",rusqlite::params![record.principal,record.request_id,now,delay_ms])?;
            Ok(())
        })
    }

    pub(crate) fn prune_write_reconciliation_results(
        &self,
        now: i64,
        retention_window_ms: i64,
    ) -> Result<usize, StoreError> {
        self.inner.with_conn_fenced(|conn| conn.execute(&format!("DELETE FROM write_reconciliation_results WHERE (principal,request_id) IN
            (SELECT principal,request_id FROM write_reconciliation_results WHERE {EXPIRED_RESULTS} ORDER BY updated_at_ms LIMIT :limit)"),
            rusqlite::named_params!{":cutoff":now.saturating_sub(retention_window_ms), ":limit":RECONCILIATION_BATCH_ROWS}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn quiet_reconciliation_tick_takes_one_read_and_no_fenced_calls() {
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "quiet-reconciliation-tick".into(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: StorageBackend::Sqlite {
                    path: crate::test_scratch::store_path(),
                },
            })
            .unwrap(),
        );
        let engine = crate::GovernanceEngine::new(
            store.clone(),
            Arc::new(crate::StubCredentialSource::default()),
            Arc::new(crate::MockTransport::default()),
        );
        let now = now_ms();

        let (total, fenced) = counted_store::count_calls_by_kind(|| {
            assert_eq!(
                engine
                    .sweep_write_reconciliations(now, AUDIT_MILLIS_PER_DAY)
                    .unwrap(),
                0
            );
        });

        assert_eq!((total, fenced), (1, 0), "store calls (total, fenced)");

        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "INSERT INTO write_reconciliation_results
                (principal,request_id,acting_principal,connection_id,action,status,updated_at_ms)
                VALUES ('direct','fresh','direct','connection','write','confirmed',?1),
                       ('direct','old','direct','connection','write','confirmed',?2)",
                    (now, now - AUDIT_MILLIS_PER_DAY - 1),
                )
            })
            .unwrap();
        let (total, fenced) = counted_store::count_calls_by_kind(|| {
            assert_eq!(
                engine
                    .sweep_write_reconciliations(now, AUDIT_MILLIS_PER_DAY)
                    .unwrap(),
                0
            );
        });
        assert_eq!(
            (total, fenced),
            (2, 1),
            "only result pruning needs the writer"
        );
        let (remaining, _) = store.list_write_reconciliations("direct").unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].request_id, "fresh");
    }
}
