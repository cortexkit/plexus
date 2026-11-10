//! Durable vault-key consent and its connection/order association.

use super::{append_audit_on_conn, now_ms, revoke_connection_on_conn, AuditRecord, PlexusStore};
use cortexkit_store::StoreError;
use rusqlite::{params, OptionalExtension};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SearchKey {
    pub provider: String,
    pub credential_id: String,
    pub incarnation: String,
    pub record_version: u64,
}

#[derive(Debug, Clone)]
pub struct AutoSearchConnection {
    pub key: SearchKey,
    pub connection_id: String,
    pub appended_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
}

impl PlexusStore {
    pub fn auto_search_connections(
        &self,
        principal: &str,
    ) -> Result<Vec<AutoSearchConnection>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT provider, credential_id, incarnation, record_version, connection_id,
                        appended_at_ms, revoked_at_ms
                 FROM web_search_auto_connections WHERE principal = ?1 ORDER BY provider, credential_id, incarnation, record_version",
            )?;
            let rows = statement.query_map([principal], |row| Ok(AutoSearchConnection {
                key: SearchKey {
                    provider: row.get(0)?, credential_id: row.get(1)?,
                    incarnation: row.get(2)?, record_version: row.get(3)?,
                },
                connection_id: row.get(4)?, appended_at_ms: row.get(5)?, revoked_at_ms: row.get(6)?,
            }))?.collect();
            rows
        })
    }

    /// Save the association before issuing the credential-binding ticket so a
    /// restart can resume incomplete discovery or remove the inert connection
    /// if the key vanishes.
    pub fn remember_auto_search_connection(
        &self,
        principal: &str,
        key: &SearchKey,
        connection_id: &str,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO web_search_auto_connections
                    (principal, provider, credential_id, incarnation, record_version, connection_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING",
                params![
                    principal,
                    key.provider,
                    key.credential_id,
                    key.incarnation,
                    key.record_version,
                    connection_id
                ],
            )?;
            Ok(())
        })
    }

    /// Append once per key, atomically with its receipt and source audit row.
    /// The receipt is kept even when the person later drops the order entry.
    pub fn complete_auto_search_connection(
        &self,
        principal: &str,
        key: &SearchKey,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let id: Option<String> = conn.query_row(
                "SELECT a.connection_id FROM web_search_auto_connections a
                 JOIN connections c ON c.principal=a.principal AND c.connection_id=a.connection_id
                 WHERE a.principal=?1 AND a.provider=?2 AND a.credential_id=?3
                   AND a.incarnation=?4 AND a.record_version=?5
                   AND a.appended_at_ms IS NULL AND a.revoked_at_ms IS NULL
                   AND c.status NOT IN ('revoked','pending','disabled')",
                params![principal, key.provider, key.credential_id, key.incarnation, key.record_version],
                |row| row.get(0),
            ).optional()?;
            let Some(id) = id else { return Ok(false) };
            let mut order = super::web_search_store::order_on_conn(conn)?.unwrap_or_default();
            if !order.contains(&key.provider) {
                order.push(key.provider.clone());
                conn.execute(
                    "INSERT INTO web_search_order(singleton, providers) VALUES (1, ?1)
                     ON CONFLICT(singleton) DO UPDATE SET providers=excluded.providers",
                    [serde_json::to_string(&order).expect("provider names serialize")],
                )?;
            }
            conn.execute(
                "UPDATE web_search_auto_connections SET appended_at_ms=?6
                 WHERE principal=?1 AND provider=?2 AND credential_id=?3 AND incarnation=?4 AND record_version=?5",
                params![principal, key.provider, key.credential_id, key.incarnation, key.record_version, now_ms()],
            )?;
            let mut audit = AuditRecord::ceremony(principal, None, Some(&id), "auto_connected", "read", None);
            audit.actor = "plexus".into();
            audit.gate = Some("stored_search_key_consent".into());
            audit.args_redaction_summary = Some(serde_json::json!({
                "source":"auto_connected", "provider":key.provider, "credential_id":key.credential_id,
                "incarnation":key.incarnation, "record_version":key.record_version,
            }).to_string());
            append_audit_on_conn(conn, &audit, None, None, None, None)?;
            Ok(true)
        })
    }

    /// Use the normal connection-revoke transaction. A person's already
    /// committed revoke is recorded separately from Plexus removing a key.
    pub fn revoke_auto_search_connection(
        &self,
        principal: &str,
        key: &SearchKey,
        key_removed: bool,
    ) -> Result<Option<String>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let id: Option<String> = conn.query_row(
                "SELECT connection_id FROM web_search_auto_connections
                 WHERE principal=?1 AND provider=?2 AND credential_id=?3 AND incarnation=?4
                   AND record_version=?5 AND revoked_at_ms IS NULL",
                params![principal, key.provider, key.credential_id, key.incarnation, key.record_version],
                |row| row.get(0),
            ).optional()?;
            let Some(id) = id else { return Ok(None) };
            let now = now_ms();
            let already_revoked = conn.query_row(
                "SELECT status='revoked' FROM connections WHERE principal=?1 AND connection_id=?2",
                params![principal, id], |row| row.get::<_, bool>(0),
            ).optional()?.unwrap_or(true);
            if key_removed { revoke_connection_on_conn(conn, principal, &id, now)?; }
            conn.execute(
                "UPDATE web_search_auto_connections SET revoked_at_ms=?6
                 WHERE principal=?1 AND provider=?2 AND credential_id=?3 AND incarnation=?4 AND record_version=?5",
                params![principal, key.provider, key.credential_id, key.incarnation, key.record_version, now],
            )?;
            let operation = if key_removed && !already_revoked { "auto_key_removed" } else { "auto_person_revoked" };
            let mut audit = AuditRecord::ceremony(principal, None, Some(&id), operation, "read", None);
            audit.actor = "plexus".into();
            append_audit_on_conn(conn, &audit, None, None, None, None)?;
            Ok(Some(id))
        })
    }
}

#[cfg(test)]
#[path = "web_search_auto_tests.rs"]
mod tests;
