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
          schema_hash,state,card_ref)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,'pending',NULL)",
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
            record.schema_hash
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
    scope,filed_scope_json,schema_hash,state,card_ref";

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

#[cfg(test)]
#[path = "federated_cards/tests.rs"]
mod tests;
