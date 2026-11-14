use crate::federated::canonicalize_claim;
use crate::permissions::ListError;
use crate::scope::{ScopeReader, ScopeStatus};
use crate::storage::{parse_json_column, PlexusStore};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use subc_protocol::scope::RemoteClaim;

struct Row {
    id: String,
    fingerprint: String,
    pairing: String,
    peer_class: String,
    selector: String,
    claim: Option<RemoteClaim>,
    peer_name: String,
    owner: String,
    subject: String,
    scope: String,
    effect: String,
    granted_at_ms: i64,
    card_ref: String,
}

impl PlexusStore {
    pub(crate) fn list_federated_permissions(
        &self,
        reader: Option<&dyn ScopeReader>,
        now: i64,
    ) -> Result<Vec<Value>, ListError> {
        // Release the connection before describing: a revoke must never wait
        // for the daemon while holding the store's writer fence.
        let rows: Vec<Row> = self.inner.with_read(|conn| {
            conn.prepare(
                "SELECT id,peer_fingerprint,pairing_id,peer_class,selector,claim_json,
                    peer_name,owner_principal,subject,scope,effect,granted_at_ms,card_ref
                 FROM federated_rows ORDER BY id",
            )?
            .query_map([], |row| {
                let claim: Option<String> = row.get(5)?;
                Ok(Row {
                    id: row.get(0)?,
                    fingerprint: row.get(1)?,
                    pairing: row.get(2)?,
                    peer_class: row.get(3)?,
                    selector: row.get(4)?,
                    claim: claim.as_deref().map(parse_json_column).transpose()?,
                    peer_name: row.get(6)?,
                    owner: row.get(7)?,
                    subject: row.get(8)?,
                    scope: row.get(9)?,
                    effect: row.get(10)?,
                    granted_at_ms: row.get(11)?,
                    card_ref: row.get(12)?,
                })
            })?
            .collect()
        })?;
        let pairs: BTreeSet<_> = rows
            .iter()
            .map(|row| (&row.fingerprint, &row.pairing))
            .collect();
        let mut ended = BTreeSet::new();
        let mut unavailable = false;
        for (fingerprint, pairing) in pairs {
            let description = reader.map(|reader| {
                reader.describe(
                    "reserved:callosum",
                    &format!("fed-base:{fingerprint}:{pairing}"),
                )
            });
            match description {
                Some(Ok(description)) if description.status == ScopeStatus::Live => {}
                Some(Ok(description))
                    if description.status == ScopeStatus::Ended
                        || (description.status == ScopeStatus::NotLive
                            && description.owner_synced
                            && description.owner_configured) =>
                {
                    ended.insert((fingerprint.clone(), pairing.clone()));
                }
                _ => unavailable = true,
            }
        }
        // Check every pairing before deciding the result. Confirmed-ended
        // rows must be journaled even if a different pairing is indeterminate.
        for row in &rows {
            if ended.contains(&(row.fingerprint.clone(), row.pairing.clone())) {
                self.inner.with_conn_fenced(|conn| {
                    self.delete_federated_row_on_conn(conn, &row.id, None, now)
                })?;
            }
        }
        if unavailable {
            return Err(ListError::LivenessUnavailable);
        }
        rows.into_iter()
            .filter(|row| !ended.contains(&(row.fingerprint.clone(), row.pairing.clone())))
            .map(|row| row.to_wire(self))
            .collect()
    }
}

impl Row {
    fn to_wire(&self, store: &PlexusStore) -> Result<Value, ListError> {
        let claim = canonicalize_claim(self.claim.as_ref()).map_err(|_| {
            crate::storage::StoreError::Backend("unsupported stored federated claim".into())
        })?;
        let mut holder = json!({
            "kind": "federated", "peer_fingerprint": self.fingerprint,
            "pairing_id": self.pairing, "peer_class": self.peer_class,
            "selector": self.selector,
        });
        if let Some(label) = claim.holder_label(&self.peer_name, &self.selector) {
            holder["label"] = json!(label);
        }
        if let Some(claim) = claim.claim {
            holder["claim"] = json!(claim);
        }
        let (subject, scope): (String, String) = match (self.owner.as_str(), self.subject.as_str())
        {
            ("", "web_search") => ("Web search".into(), "search the web".into()),
            ("", "code_search") => ("Code search".into(), "search public code".into()),
            _ => {
                let connection =
                    store
                        .connection(&self.owner, &self.subject)?
                        .ok_or_else(|| {
                            crate::storage::StoreError::Backend(
                                "federated subject connection missing".into(),
                            )
                        })?;
                let subject = crate::consent_card::service_label(store, &connection.app_key);
                let verb = if self.scope == "read" {
                    "read from"
                } else {
                    "make changes in"
                };
                let scope = format!("{verb} {subject}");
                (subject, scope)
            }
        };
        let mut wire = json!({
            "id": self.id, "holder": holder, "module": "plexus",
            "subject_label": subject, "scope": self.scope,
            "scope_label": if self.effect == "deny" { format!("never {scope}") } else { scope },
            "granted_at_ms": self.granted_at_ms, "card_ref": self.card_ref,
        });
        if self.effect == "deny" {
            wire["effect"] = json!("deny");
        }
        Ok(wire)
    }
}

#[cfg(test)]
#[path = "federated_list_tests.rs"]
mod tests;
