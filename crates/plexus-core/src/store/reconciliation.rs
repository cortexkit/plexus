//! Persisted write reconciliation retries and terminal results.

use super::*;

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

    pub(crate) fn pending_write_reconciliations_at(
        &self,
        now: i64,
    ) -> Result<Vec<crate::reconciliation::PendingWriteReconciliation>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let mut stmt = conn.prepare("SELECT principal,request_id,record_json,expires_at_ms FROM pending_write_reconciliations WHERE next_attempt_at_ms<=?1 ORDER BY expires_at_ms,principal,request_id LIMIT ?2")?;
            let rows = stmt
                .query_map((now, RECONCILIATION_BATCH_ROWS), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(stmt);
            let mut pending = Vec::with_capacity(rows.len());
            for (principal, request_id, encoded, expires_at_ms) in rows {
                match serde_json::from_str(&encoded) {
                    Ok(record) => pending.push(crate::reconciliation::PendingWriteReconciliation {
                        record,
                        expires_at_ms,
                    }),
                    Err(error) => {
                        crate::diag!(warn storage: "write reconciliation record does not decode; settling it as ambiguous: principal={principal:?} request_id={request_id:?}: class={:?} line={} column={}",error.classify(),error.line(),error.column());
                        conn.execute("UPDATE write_reconciliation_results SET status='ambiguous', reason='record_undecodable', updated_at_ms=?3
                            WHERE principal=?1 AND request_id=?2", rusqlite::params![principal, request_id, now_ms()])?;
                        conn.execute("UPDATE action_requests SET reconciliation_status='ambiguous' WHERE principal=?1 AND request_id IN
                            (SELECT intent_id FROM pending_write_reconciliations WHERE principal=?1 AND request_id=?2)",
                            rusqlite::params![principal, request_id])?;
                        conn.execute("DELETE FROM pending_write_reconciliations WHERE principal=?1 AND request_id=?2",
                            rusqlite::params![principal, request_id])?;
                    }
                }
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
        self.inner.with_conn_fenced(|conn| conn.execute("DELETE FROM write_reconciliation_results WHERE (principal,request_id) IN
            (SELECT principal,request_id FROM write_reconciliation_results WHERE status!='pending' AND updated_at_ms < ?1 ORDER BY updated_at_ms LIMIT ?2)",
            (now.saturating_sub(retention_window_ms), RECONCILIATION_BATCH_ROWS)))
    }
}
