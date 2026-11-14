use crate::federated::card::{CallBinding, CallerIdentity, Record, Scope, State};
use rusqlite::{params, OptionalExtension, Transaction};

/// Insert one unfiled pending record in the caller's `with_conn_fenced`
/// transaction. Allows only absent -> pending with no card ref; never replaces
/// an existing record, changes a terminal state or writes a local request.
pub(crate) fn insert_on_conn(tx: &Transaction<'_>, record: &Record) -> rusqlite::Result<()> {
    if record.state != State::Pending || record.card_ref.is_some() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let filed_scope = serde_json::to_string(&record.filed_scope)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    let binding = &record.binding;
    let caller = &binding.caller;
    tx.execute(
        "INSERT INTO federated_card_records
         (id,peer_fingerprint,pairing_id,peer_class,claim_kind,canonical_claim_identity,
          owner_principal,subject,action,args_digest,selector,scope,filed_scope_json,
           schema_hash,state,card_ref,standing_choices_offered)
          VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,'pending',NULL,?15)",
        params![
            record.id,
            caller.peer_fingerprint,
            caller.pairing_id,
            caller.peer_class,
            caller.claim_kind,
            caller.canonical_claim_identity,
            binding.owner_principal,
            binding.subject,
            binding.action,
            binding.args_digest,
            record.selector,
            record.scope.as_str(),
            filed_scope,
            record.schema_hash,
            record.standing_choices_offered
        ],
    )?;
    Ok(())
}

/// Attach the returned Cingulate ref in the caller's fenced transaction.
/// Allows only pending/unfiled -> pending/filed. A missing or terminal record,
/// an empty ref, or any second attachment (even the same ref) is refused.
pub(crate) fn attach_card_ref_on_conn(
    tx: &Transaction<'_>,
    id: &str,
    card_ref: &str,
) -> rusqlite::Result<()> {
    if card_ref.is_empty()
        || tx.execute(
            "UPDATE federated_card_records SET card_ref=?2
             WHERE id=?1 AND state='pending' AND card_ref IS NULL",
            (id, card_ref),
        )? != 1
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

const COLUMNS: &str = "id,peer_fingerprint,pairing_id,peer_class,claim_kind,
    canonical_claim_identity,owner_principal,subject,action,args_digest,selector,
    scope,filed_scope_json,schema_hash,state,card_ref,standing_choices_offered";

/// Read by correlation id within the caller's fenced transaction, including
/// terminal records. Read-only: allows no state or card-ref transitions.
pub(crate) fn read_on_conn(tx: &Transaction<'_>, id: &str) -> rusqlite::Result<Option<Record>> {
    tx.query_row(
        &format!("SELECT {COLUMNS} FROM federated_card_records WHERE id=?1"),
        [id],
        from_row,
    )
    .optional()
}

/// Find a pending record for this entire call binding, scope and invoke schema
/// in the caller's fenced transaction. Route/epoch and display names do not
/// select a record. Read-only: terminal records never match; no state changes.
pub(crate) fn pending_on_conn(
    tx: &Transaction<'_>,
    binding: &CallBinding,
    scope: Scope,
    schema_hash: Option<&str>,
) -> rusqlite::Result<Option<Record>> {
    let caller = &binding.caller;
    tx.query_row(
        &format!(
            "SELECT {COLUMNS} FROM federated_card_records
             WHERE peer_fingerprint=?1 AND pairing_id=?2 AND peer_class=?3
               AND claim_kind=?4 AND canonical_claim_identity=?5 AND owner_principal=?6
               AND subject=?7 AND action=?8 AND args_digest=?9 AND scope=?10
               AND schema_hash IS ?11 AND state='pending' ORDER BY id LIMIT 1"
        ),
        params![
            caller.peer_fingerprint,
            caller.pairing_id,
            caller.peer_class,
            caller.claim_kind,
            caller.canonical_claim_identity,
            binding.owner_principal,
            binding.subject,
            binding.action,
            binding.args_digest,
            scope.as_str(),
            schema_hash
        ],
        from_row,
    )
    .optional()
}

fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Record> {
    Ok(Record {
        id: row.get(0)?,
        binding: CallBinding {
            caller: CallerIdentity {
                peer_fingerprint: row.get(1)?,
                pairing_id: row.get(2)?,
                peer_class: row.get(3)?,
                claim_kind: row.get(4)?,
                canonical_claim_identity: row.get(5)?,
            },
            owner_principal: row.get(6)?,
            subject: row.get(7)?,
            action: row.get(8)?,
            args_digest: row.get(9)?,
        },
        selector: row.get(10)?,
        scope: enum_column(row, 11)?,
        filed_scope: super::super::parse_json_column(&row.get::<_, String>(12)?)?,
        schema_hash: row.get(13)?,
        state: enum_column(row, 14)?,
        card_ref: row.get(15)?,
        standing_choices_offered: row.get(16)?,
    })
}

fn enum_column<T: serde::de::DeserializeOwned>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<T> {
    serde_json::from_value(serde_json::Value::String(row.get(index)?)).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

impl crate::storage::PlexusStore {
    pub(crate) fn ensure_federated_card(
        &self,
        record: &Record,
    ) -> Result<Record, cortexkit_store::StoreError> {
        self.inner.with_conn_fenced(|tx| {
            if let Some(pending) = pending_on_conn(
                tx,
                &record.binding,
                record.scope,
                record.schema_hash.as_deref(),
            )? {
                return Ok(pending);
            }
            insert_on_conn(tx, record)?;
            Ok(record.clone())
        })
    }

    pub(crate) fn attach_federated_card(
        &self,
        id: &str,
        card_ref: &str,
    ) -> Result<(), cortexkit_store::StoreError> {
        self.inner
            .with_conn_fenced(|tx| attach_card_ref_on_conn(tx, id, card_ref))
    }

    /// Settle the answer and reserve its one call under the same writer fence.
    /// Liveness is checked by the collector before this transaction. Re-read
    /// rows, the record and `federated_processed_cards` here so a revoke or
    /// answer commit performed during describe cannot authorize reuse.
    pub(crate) fn reserve_federated_card(
        &self,
        call: &crate::federated::matcher::Call<'_>,
        input: &super::FederatedReservationInput<'_>,
        expected: &Record,
        answer: super::commit::Answer,
    ) -> Result<
        Result<(Option<super::FederatedStandingRow>, String), crate::governance::Denial>,
        cortexkit_store::StoreError,
    > {
        use super::commit::Answer;
        use crate::governance::Denial;
        self.inner.with_conn_fenced(|tx| {
            let unavailable = || Denial::ConsentUnavailable { action: input.action.into() };
            let row = super::matching_row_on_conn(tx, call, input.now)?;
            if row.as_ref().is_some_and(|row| row.effect == crate::federated::matcher::Effect::Deny) {
                return Ok(Err(Denial::FederatedConsentDenied));
            }
            let Some(record) = read_on_conn(tx, &expected.id)? else { return Ok(Err(unavailable())) };
            if record != *expected || record.card_ref.is_none() {
                return Ok(Err(unavailable()));
            }
            let claim = crate::federated::canonicalize_claim(call.claim)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let identity = &record.binding.caller;
            if identity.peer_fingerprint != call.peer_fingerprint
                || identity.pairing_id != call.pairing_id
                || identity.peer_class != call.peer_class
                || identity.claim_kind != claim.claim_kind
                || identity.canonical_claim_identity != claim.canonical_claim_identity
                || record.binding.owner_principal != call.owner_principal
                || record.binding.subject != call.subject
                || record.binding.action != input.action
                || record.binding.args_digest != input.args_hash
                || record.schema_hash.as_deref() != Some(input.schema_hash)
                || record.scope.as_str() != call.scope
            {
                return Ok(Err(unavailable()));
            }
            let card_ref = record.card_ref.as_deref().expect("checked above");
            let processed: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM federated_processed_cards WHERE card_ref=?1)", [card_ref], |row| row.get(0))?;
            if answer == Answer::AllowAlways {
                let reserved: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM reservations WHERE card_ref=?1)", [card_ref], |row| row.get(0))?;
                if record.state != State::Committed || !processed || row.is_none() || reserved {
                    return Ok(Err(unavailable()));
                }
            } else if record.state != State::Pending || processed {
                if processed {
                    tx.execute("UPDATE federated_card_records SET state='retired' WHERE id=?1", [&record.id])?;
                }
                return Ok(Err(unavailable()));
            }
            let (state, refusal) = match answer {
                Answer::AllowOnce => (State::Consumed, None),
                Answer::AllowAlways => (State::Committed, None),
                Answer::Expired => (State::Expired, Some("consent_expired")),
                Answer::Withdrawn => (State::Withdrawn, Some("consent_withdrawn")),
                _ => (State::Declined, Some("consent_denied")),
            };
            tx.execute("UPDATE federated_card_records SET state=?2 WHERE id=?1", (&record.id, state.as_str()))?;
            if let Some(code) = refusal {
                return Ok(Err(Denial::ConsentRefused { code, elicitation_id: card_ref.into() }));
            }
            let id = crate::storage::new_id("res");
            let snapshot = serde_json::to_string(input.snapshot).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            tx.execute("INSERT INTO reservations (reservation_id,principal,connection_id,action,snapshot_generations,approved_args_hash,schema_hash,expires_at,status,created_at_ms,federated_row_id,card_ref)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'reserved',?9,?10,?11)", params![id,call.owner_principal,call.subject,input.action,snapshot,input.args_hash,input.schema_hash,input.expires_at,input.now,row.as_ref().map(|r| &r.id),card_ref])?;
            Ok(Ok((row, id)))
        })
    }
}

#[cfg(test)]
#[path = "federated_cards/tests.rs"]
mod tests;
