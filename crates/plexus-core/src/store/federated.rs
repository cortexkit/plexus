use super::*;
use crate::federated_journal::{self, Deletion};

#[path = "federated_cards.rs"]
pub(crate) mod cards;

#[path = "federated_commit.rs"]
pub(crate) mod commit;

/// The exact unique key shared by a standing row and its pending card records.
#[derive(Debug, Clone)]
pub(crate) struct FederatedRowKey {
    pub peer_fingerprint: String,
    pub pairing_id: String,
    pub peer_class: String,
    pub selector: String,
    pub claim_kind: String,
    pub canonical_claim_identity: String,
    pub owner_principal: String,
    pub subject: String,
    pub scope: String,
}

impl FederatedRowKey {
    /// Read the nine key columns in their schema order, starting at column zero.
    pub(crate) fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            peer_fingerprint: row.get(0)?,
            pairing_id: row.get(1)?,
            peer_class: row.get(2)?,
            selector: row.get(3)?,
            claim_kind: row.get(4)?,
            canonical_claim_identity: row.get(5)?,
            owner_principal: row.get(6)?,
            subject: row.get(7)?,
            scope: row.get(8)?,
        })
    }

    fn params(&self) -> [&str; 9] {
        [
            &self.peer_fingerprint,
            &self.pairing_id,
            &self.peer_class,
            &self.selector,
            &self.claim_kind,
            &self.canonical_claim_identity,
            &self.owner_principal,
            &self.subject,
            &self.scope,
        ]
    }
}

impl PlexusStore {
    pub(crate) fn matching_federated_row(
        &self,
        call: &crate::federated::matcher::Call<'_>,
        now: i64,
    ) -> Result<Option<FederatedStandingRow>, StoreError> {
        self.inner
            .with_conn_fenced(|conn| matching_row_on_conn(conn, call, now))
    }

    /// Re-read standing authority under the writer fence after the caller's
    /// liveness check. A revoke that committed during describe must win.
    pub(crate) fn reserve_federated_invoke(
        &self,
        call: &crate::federated::matcher::Call<'_>,
        input: &FederatedReservationInput<'_>,
    ) -> Result<(Option<FederatedStandingRow>, Option<String>), StoreError> {
        let snapshot = serde_json::to_string(input.snapshot)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        self.inner.with_conn_fenced(|conn| {
            let row = matching_row_on_conn(conn, call, input.now)?;
            let Some(standing) = row.as_ref().filter(|row| {
                row.effect == crate::federated::matcher::Effect::Allow && !input.ask_first
            }) else {
                return Ok((row, None));
            };
            let id = super::new_id("res");
            conn.execute(
                "INSERT INTO reservations
                 (reservation_id, principal, connection_id, action, snapshot_generations,
                  approved_args_hash, schema_hash, expires_at, status, created_at_ms,
                  federated_row_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'reserved', ?9, ?10)",
                rusqlite::params![
                    id,
                    call.owner_principal,
                    call.subject,
                    input.action,
                    snapshot,
                    input.args_hash,
                    input.schema_hash,
                    input.expires_at,
                    input.now,
                    standing.id
                ],
            )?;
            Ok((row, Some(id)))
        })
    }

    /// The caller holds `with_conn_fenced` for the entire connection deletion.
    /// Include pending-card keys without a standing row so an answer restored
    /// from an older database cannot recreate authority for a deleted connection.
    /// Terminal records are removed too, but only pending records add their
    /// Cingulate card refs to the federated deletion journal and the insert-only
    /// `federated_processed_cards` table, preventing reuse of their answers.
    pub(super) fn delete_federated_connection_on_conn(
        &self,
        conn: &Connection,
        principal: &str,
        connection_id: &str,
        deleted_at_ms: i64,
    ) -> rusqlite::Result<()> {
        let keys: Vec<FederatedRowKey> = conn
            .prepare(
                "SELECT peer_fingerprint,pairing_id,peer_class,selector,claim_kind,
                    canonical_claim_identity,owner_principal,subject,scope
                 FROM federated_rows WHERE owner_principal=?1 AND subject=?2
                 UNION
                 SELECT peer_fingerprint,pairing_id,peer_class,selector,claim_kind,
                    canonical_claim_identity,owner_principal,subject,scope
                 FROM federated_card_records
                 WHERE owner_principal=?1 AND subject=?2 AND state='pending'",
            )?
            .query_map((principal, connection_id), FederatedRowKey::from_row)?
            .collect::<rusqlite::Result<_>>()?;
        for key in keys {
            self.delete_federated_key_on_conn(conn, &key, None, deleted_at_ms)?;
        }
        conn.execute(
            "DELETE FROM federated_card_records WHERE owner_principal=?1 AND subject=?2",
            (principal, connection_id),
        )?;
        Ok(())
    }

    /// Durably delete only this stored row without describing its pairing's
    /// base scope. Revocation must work even when that scope cannot be read.
    /// A missing id is a no-op; ids are never resolved through local grants.
    pub fn delete_federated_row(&self, row_id: &str) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            self.delete_federated_row_on_conn(conn, row_id, None, now_ms())
        })
    }

    /// The caller must hold `with_conn_fenced` for the entire transaction. Append
    /// and fsync precede every SQL delete; rollback may leave a conservative
    /// journal entry that boot replay applies. `except_card_id` is the tracking
    /// record id of the card changing an allow to a deny or vice versa, not its
    /// `card_ref` assigned by Cingulate. That answer must remain usable if a
    /// crash leaves only the old row's deletion journaled. All other
    /// pending records under the exact key are retired. Processed refs are only
    /// inserted, never deleted, including on retries and replay.
    pub(crate) fn delete_federated_row_on_conn(
        &self,
        conn: &Connection,
        row_id: &str,
        except_card_id: Option<&str>,
        deleted_at_ms: i64,
    ) -> rusqlite::Result<bool> {
        let key = conn
            .query_row(
                "SELECT peer_fingerprint,pairing_id,peer_class,selector,claim_kind,
                    canonical_claim_identity,owner_principal,subject,scope
             FROM federated_rows WHERE id=?1",
                [row_id],
                FederatedRowKey::from_row,
            )
            .optional()?;
        let Some(key) = key else { return Ok(false) };
        self.delete_federated_key_on_conn(conn, &key, except_card_id, deleted_at_ms)
    }

    /// Journal-first cleanup for one exact key, including a key with no row.
    /// The caller holds `with_conn_fenced`; a connection cleanup can call this
    /// for each row key and each remaining pending-card key before deleting its
    /// records. Only pending records are retired, and the optional tracking id
    /// is left untouched when changing an allow to a deny or vice versa. A
    /// rowless key journals its retired refs with `row_id: null`; a record with
    /// no `card_ref` contributes none.
    /// Processed refs outlive every cleanup and must never be deleted. Returns
    /// whether a standing row was removed, not whether cards were retired.
    pub(crate) fn delete_federated_key_on_conn(
        &self,
        conn: &Connection,
        key: &FederatedRowKey,
        except_card_id: Option<&str>,
        deleted_at_ms: i64,
    ) -> rusqlite::Result<bool> {
        let row: Option<(String, String, String)> = conn
            .query_row(
                "SELECT id,card_ref,card_refs_json FROM federated_rows
             WHERE peer_fingerprint=?1 AND pairing_id=?2 AND peer_class=?3 AND selector=?4
               AND claim_kind=?5 AND canonical_claim_identity=?6 AND owner_principal=?7
               AND subject=?8 AND scope=?9",
                key.params(),
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let mut refs = BTreeSet::new();
        if let Some((_, mint_ref, all_refs)) = &row {
            refs.extend(parse_json_column::<Vec<String>>(all_refs)?);
            refs.insert(mint_ref.clone());
        }
        let cards: Vec<(String, Option<String>)> = conn
            .prepare(
                "SELECT id,card_ref FROM federated_card_records
             WHERE peer_fingerprint=?1 AND pairing_id=?2 AND peer_class=?3 AND selector=?4
               AND claim_kind=?5 AND canonical_claim_identity=?6 AND owner_principal=?7
               AND subject=?8 AND scope=?9 AND state='pending'",
            )?
            .query_map(key.params(), |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let cards: Vec<_> = cards
            .into_iter()
            .filter(|(id, _)| Some(id.as_str()) != except_card_id)
            .collect();
        refs.extend(cards.iter().filter_map(|(_, card_ref)| card_ref.clone()));
        let entry = Deletion {
            row_id: row.map(|(id, _, _)| id),
            card_refs: refs.into_iter().collect(),
            deleted_at_ms,
        };
        if entry.row_id.is_some() || !entry.card_refs.is_empty() {
            if let Some(path) = &self.grant_journal {
                federated_journal::append(&path.with_file_name(federated_journal::NAME), &entry)?;
            }
        }
        for (id, _) in cards {
            conn.execute(
                "UPDATE federated_card_records SET state='retired' WHERE id=?1",
                [id],
            )?;
        }
        federated_journal::apply(conn, &entry).map(|removed| removed != 0)
    }
}

pub(crate) struct FederatedReservationInput<'a> {
    pub action: &'a str,
    pub snapshot: &'a super::SnapshotGenerations,
    pub args_hash: &'a str,
    pub schema_hash: &'a str,
    pub expires_at: i64,
    pub now: i64,
    pub ask_first: bool,
}

pub(crate) struct FederatedStandingRow {
    pub id: String,
    pub effect: crate::federated::matcher::Effect,
}

pub(crate) fn matching_row_on_conn(
    conn: &rusqlite::Connection,
    call: &crate::federated::matcher::Call<'_>,
    now: i64,
) -> rusqlite::Result<Option<FederatedStandingRow>> {
    use crate::federated::matcher::{match_rows, Effect, Row};
    let mut query = conn.prepare(
        "SELECT id, selector, claim_json, effect FROM federated_rows
         WHERE peer_fingerprint=?1 AND pairing_id=?2 AND peer_class=?3
           AND owner_principal=?4 AND subject=?5 AND scope=?6 ORDER BY id",
    )?;
    let stored = query
        .query_map(
            (
                call.peer_fingerprint,
                call.pairing_id,
                call.peer_class,
                call.owner_principal,
                call.subject,
                call.scope,
            ),
            |row| {
                let claim: Option<String> = row.get(2)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    claim
                        .map(|json| {
                            super::parse_json_column::<subc_protocol::scope::RemoteClaim>(&json)
                        })
                        .transpose()?,
                    row.get::<_, String>(3)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let rows: Vec<_> = stored
        .iter()
        .map(|(_, selector, claim, effect)| Row {
            peer_fingerprint: call.peer_fingerprint,
            pairing_id: call.pairing_id,
            peer_class: call.peer_class,
            selector: Some(selector),
            claim: claim.as_ref(),
            owner_principal: call.owner_principal,
            subject: call.subject,
            scope: call.scope,
            effect: if effect == "deny" {
                Effect::Deny
            } else {
                Effect::Allow
            },
            expires_at_ms: None,
        })
        .collect();
    Ok(
        match_rows(&rows, call, now).map(|index| FederatedStandingRow {
            id: stored[index].0.clone(),
            effect: rows[index].effect,
        }),
    )
}

#[cfg(test)]
#[path = "federated_deletion_tests.rs"]
mod tests;
