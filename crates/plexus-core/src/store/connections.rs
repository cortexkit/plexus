//! Connection lifecycle, filters, and non-secret credential references.

use super::*;

/// The id prefix of a connection created for a GitHub App handle
/// (`github-handle-<app_handle_id>`).
pub(super) const GITHUB_HANDLE_CONNECTION_PREFIX: &str = "github-handle-";

/// Every table whose rows belong to one connection, with the `WHERE` clause
/// that selects that connection's rows given `?1` = principal and
/// `?2` = connection id. `PlexusStore::delete_connection` deletes in this
/// order, so a row that finds its connection through another table
/// (`probe_subscriptions` through `trigger_subscriptions`) goes before that
/// table's row.
///
/// Deliberately absent:
/// - `audit_journal`: append-only at runtime, with bounded age-based retention.
/// - `grant_revocations`: immutable evidence kept indefinitely at runtime;
///   migration 40 was a one-time exception for eligible revoked connections.
/// - `github_app_handle`: a connection it references is refused instead.
/// - `web_search_auto_connections`: the record that a stored vault key
///   created this connection. It must outlive the connection: once the key's
///   connection has completed, the next vault notice treats a missing
///   connection as the person's revoke, so the same key never reconnects.
///
/// The schema test `every_connection_keyed_table_is_deleted_or_deliberately_kept`
/// fails when a table gains a `connection_id` column without being listed
/// here or among those exceptions.
pub(crate) const CONNECTION_KEYED_TABLES: &[(&str, &str)] = &[
    ("gmail_accounts", "principal=?1 AND connection_id=?2"),
    ("sent_text", "principal=?1 AND connection_id=?2"),
    (
        "probe_subscriptions",
        "subscription_id IN (SELECT subscription_id FROM trigger_subscriptions
                             WHERE principal = ?1 AND connection_id = ?2)",
    ),
    (
        "event_outbox_failures",
        "event_key IN (SELECT event_key FROM event_outbox WHERE event_id IN
            (SELECT event_id FROM trigger_events WHERE principal = ?1 AND connection_id = ?2))",
    ),
    (
        "event_outbox",
        "event_id IN (SELECT event_id FROM trigger_events WHERE principal = ?1 AND connection_id = ?2)",
    ),
    ("trigger_events", "principal = ?1 AND connection_id = ?2"),
    (
        "trigger_subscriptions",
        "principal = ?1 AND connection_id = ?2",
    ),
    ("catalog_actions", "principal = ?1 AND connection_id = ?2"),
    ("grants", "principal = ?1 AND connection_id = ?2"),
    ("policies", "principal = ?1 AND connection_id = ?2"),
    (
        "consent_call_keys",
        "(principal, request_id) IN (SELECT principal, request_id FROM action_requests
                                    WHERE principal = ?1 AND connection_id = ?2)",
    ),
    ("action_requests", "principal = ?1 AND connection_id = ?2"),
    ("reservations", "principal = ?1 AND connection_id = ?2"),
    ("binding_tickets", "principal = ?1 AND connection_id = ?2"),
    (
        "recipient_allowlist",
        "principal = ?1 AND connection_id = ?2",
    ),
    (
        "write_reconciliation_results",
        "principal = ?1 AND connection_id = ?2",
    ),
    // The connection id is inside the serialized `OutcomeUnknownRecord`, not
    // in a column. `json_valid` guards `json_extract`, which raises an error
    // on malformed text and would abort the whole delete.
    (
        "pending_write_reconciliations",
        "principal = ?1 AND CASE WHEN json_valid(record_json)
             THEN json_extract(record_json, '$.connection_id') END = ?2",
    ),
];

/// Whether `grantee` holds a live connection-admin grant on the connection:
/// an unexpired `connection_admin` grant naming them, with at least one
/// action selector. Shared by the read-only check and by the writes that
/// must repeat that check inside their own transaction.
pub(super) fn connection_admin_grant_on_conn(
    conn: &Connection,
    owner: &str,
    connection_id: &str,
    grantee: &str,
    now: i64,
) -> rusqlite::Result<bool> {
    let mut statement = conn.prepare(
        "SELECT action_selectors FROM grants
         WHERE principal = ?1 AND connection_id = ?2
           AND authority_kind = 'connection_admin'
           AND grantee_principal = ?3 AND grantee_principal <> '*'
           AND (expires_at IS NULL OR expires_at > ?4)",
    )?;
    let rows = statement.query_map((owner, connection_id, grantee, now), |row| {
        let selectors: String = row.get(0)?;
        parse_string_list(&selectors)
    })?;
    for selectors in rows {
        if !selectors?.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn set_connection_filters_on_conn(
    conn: &Connection,
    principal: &str,
    connection_id: &str,
    filters: &str,
    now: i64,
) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE connections SET resource_filters = ?1,
                generation = generation + 1, updated_at_ms = ?2
         WHERE principal = ?3 AND connection_id = ?4",
        rusqlite::params![filters, now, principal, connection_id],
    )?;
    Ok(changed != 0)
}

/// Revoke a connection, invalidating its undispatched reservations and
/// expiring its unconsumed binding tickets, inside the caller's transaction.
/// `false` when there is no such connection or it was already revoked.
pub(super) fn revoke_connection_on_conn(
    conn: &Connection,
    principal: &str,
    connection_id: &str,
    now: i64,
) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE connections SET status = 'revoked', generation = generation + 1,
                updated_at_ms = ?1
         WHERE principal = ?2 AND connection_id = ?3 AND status <> 'revoked'",
        rusqlite::params![now, principal, connection_id],
    )?;
    if changed != 0 {
        conn.execute(
            "UPDATE reservations SET status = 'invalidated'
             WHERE principal = ?1 AND connection_id = ?2 AND status = 'reserved'",
            (principal, connection_id),
        )?;
        conn.execute(
            "UPDATE binding_tickets SET status = 'expired'
             WHERE principal = ?1 AND connection_id = ?2 AND status = 'issued'",
            (principal, connection_id),
        )?;
    }
    Ok(changed != 0)
}

fn map_connection_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConnectionRecord> {
    let filters: String = row.get(4)?;
    let health: String = row.get(5)?;
    Ok(ConnectionRecord {
        connection_id: row.get(0)?,
        principal: row.get(1)?,
        app_key: row.get(2)?,
        status: row.get(3)?,
        resource_filters: parse_json_column(&filters)?,
        health_state: parse_json_column(&health)?,
        generation: row.get(6)?,
        has_credential_binding: row.get(7)?,
        instance_url: row
            .get::<_, Option<String>>(8)?
            .and_then(|url| crate::instance_url::InstanceUrl::parse(&url).ok()),
    })
}

// Versioned non-secret vault references are the only stored credential binding.
const REFERENCE_BINDING_PREFIX: &[u8] = b"plexus:vault-reference:v1\0";

pub(super) fn encode_reference_binding(id: &str) -> Result<Vec<u8>, String> {
    if !crate::credentials::valid_credential_id(id) {
        return Err("invalid credential id".into());
    }
    let mut encoded = REFERENCE_BINDING_PREFIX.to_vec();
    encoded.extend_from_slice(id.as_bytes());
    Ok(encoded)
}

pub(super) fn decode_connection_binding(
    value: &[u8],
) -> Result<crate::credentials::ConnectionCredentialBinding, String> {
    use crate::credentials::ConnectionCredentialBinding;
    if let Some(id) = value.strip_prefix(REFERENCE_BINDING_PREFIX) {
        let id = std::str::from_utf8(id).map_err(|_| "invalid credential id")?;
        if !crate::credentials::valid_credential_id(id) {
            return Err("invalid credential id".into());
        }
        Ok(ConnectionCredentialBinding::Reference(id.to_owned()))
    } else {
        Err("handle_bindings_removed: use credential_id".into())
    }
}

pub(crate) fn removed_binding_error(connection_id: &str) -> String {
    format!("handle_bindings_removed: non-revoked connection(s) {connection_id}; use ck-plexus-admin rebind-credential with credential_id on the previous build before opening this store")
}

pub(crate) fn is_reference_binding(value: &[u8]) -> bool {
    decode_connection_binding(value).is_ok()
}

impl PlexusStore {
    pub fn list_connections(&self, principal: &str) -> Result<Vec<ConnectionSummary>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT connection_id, app_key, status, generation
                 FROM connections WHERE principal = ?1 ORDER BY connection_id",
            )?;
            let rows = statement.query_map([principal], |row| {
                Ok(ConnectionSummary {
                    connection_id: row.get(0)?,
                    app_key: row.get(1)?,
                    status: row.get(2)?,
                    generation: row.get(3)?,
                })
            })?;
            rows.collect()
        })
    }

    /// Existence only: flow diagnostics may name an invisible requested connection,
    /// but must not load its configuration or grant dispatch authority.
    pub fn connection_id_exists(&self, connection_id: &str) -> Result<bool, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM connections WHERE connection_id=?1)",
                [connection_id],
                |row| row.get(0),
            )
        })
    }

    pub fn connection(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Option<ConnectionRecord>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT connection_id, principal, app_key, status, resource_filters,
                        health_state, generation, credential_binding IS NOT NULL, instance_url
                 FROM connections WHERE principal = ?1 AND connection_id = ?2",
                (principal, connection_id),
                map_connection_row,
            )
            .optional()
        })
    }

    /// Registration is keyed by bare id. Pending connections count because
    /// connect-time discovery registers a transport before activation.
    pub(crate) fn other_transport_owner(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Option<String>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT principal FROM connections
                 WHERE connection_id = ?2 AND principal <> ?1
                   AND status IN ('pending', 'active', 'degraded') LIMIT 1",
                (principal, connection_id),
                |row| row.get(0),
            )
            .optional()
        })
    }

    pub(crate) fn connection_for_dispatch(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Option<(ConnectionRecord, bool)>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT connection_id, principal, app_key, status, resource_filters,
                        health_state, generation, credential_binding IS NOT NULL, instance_url,
                        EXISTS(SELECT 1 FROM connections
                               WHERE connection_id = ?2 AND principal <> ?1
                                 AND status IN ('pending', 'active', 'degraded'))
                 FROM connections WHERE principal = ?1 AND connection_id = ?2",
                (principal, connection_id),
                |row| Ok((map_connection_row(row)?, row.get(9)?)),
            )
            .optional()
        })
    }

    /// Resolve an invoke-visible connection without conferring invoke authority.
    ///
    /// Owned rows remain the fast path. A caller that owns no such row may see an
    /// owner's row only when that owner has named the caller in an invoke grant;
    /// expiry and action scope are deliberately left to the grant gate so it can
    /// return the precise refusal.
    ///
    /// When more than one owner shares the id with the caller, nothing says
    /// which owner's connection the caller meant, so none is returned (as probe
    /// registration refuses the same case as ambiguous) rather than whichever
    /// owner sorts first.
    pub fn connection_for_invoke(
        &self,
        caller: &str,
        connection_id: &str,
    ) -> Result<Option<ConnectionRecord>, StoreError> {
        if let Some(connection) = self.connection(caller, connection_id)? {
            return Ok(Some(connection));
        }
        let candidates: Vec<ConnectionRecord> = self.inner.with_read(|conn| {
            conn.prepare(
                "SELECT connection.connection_id, connection.principal, connection.app_key,
                        connection.status, connection.resource_filters, connection.health_state,
                        connection.generation, connection.credential_binding IS NOT NULL, connection.instance_url
                 FROM connections AS connection
                 WHERE connection.connection_id = ?2
                   AND EXISTS (
                       SELECT 1 FROM grants AS grant
                       WHERE grant.principal = connection.principal
                         AND grant.connection_id = connection.connection_id
                         AND grant.authority_kind = 'invoke'
                         AND grant.grantee_principal = ?1 AND grant.grantee_principal <> '*'
                   )
                 ORDER BY connection.principal
                 LIMIT 2",
            )?
            .query_map((caller, connection_id), map_connection_row)?
            .collect()
        })?;
        match <[ConnectionRecord; 1]>::try_from(candidates) {
            Ok([connection]) => Ok(Some(connection)),
            Err(candidates) => {
                if !candidates.is_empty() {
                    crate::diag!(warn storage: "connection {connection_id:?} is shared with {caller:?} by more than one owner; refusing to pick one");
                }
                Ok(None)
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn create_connection(
        &self,
        principal: &str,
        connection_id: &str,
        app_key: &str,
    ) -> Result<(), StoreError> {
        self.insert_connection(
            principal,
            connection_id,
            app_key,
            "pending",
            &Value::Object(Default::default()),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_connection(
        &self,
        principal: &str,
        connection_id: &str,
        app_key: &str,
        status: &str,
        resource_filters: &Value,
    ) -> Result<(), StoreError> {
        let filters = serde_json::to_string(resource_filters)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO connections
                    (connection_id, principal, app_key, status, resource_filters,
                     created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                rusqlite::params![connection_id, principal, app_key, status, filters, now],
            )?;
            Ok(())
        })
    }

    /// Replace a connection's resource filters, bounded by the vendor's
    /// reviewed manifest.
    ///
    /// The manifest declares WHICH filter keys exist and which of them enable
    /// writes; an operator may only choose the allowed VALUES for those keys.
    /// Accepting arbitrary keys here would let a caller invent a
    /// `write_enabling` key the vendor never declared and so satisfy the write
    /// gate without narrowing anything, which is the whole point of the gate.
    /// `write_enabling` is therefore intersected with the manifest's list, and
    /// `values` keys must be declared filter keys.
    pub fn configure_connection_filters(
        &self,
        principal: &str,
        connection_id: &str,
        requested: &Value,
    ) -> Result<ConfigureOutcome, StoreError> {
        let filters = match self.checked_connection_filters(principal, connection_id, requested)? {
            Ok(filters) => filters,
            Err(refusal) => return Ok(refusal),
        };
        if self.set_connection_filters(principal, connection_id, &filters)? {
            Ok(ConfigureOutcome::Configured(filters))
        } else {
            Ok(ConfigureOutcome::ConnectionNotFound)
        }
    }

    /// [`Self::configure_connection_filters`] on behalf of `caller`, who must
    /// hold a live connection-admin grant on the connection.
    ///
    /// The grant is checked first, so a caller without authority learns
    /// nothing about the connection or its manifest. It is checked AGAIN inside
    /// the fenced transaction that writes the filters: a grant revoked after
    /// the first check, while the request was being validated, must stop the
    /// write rather than be outrun by it.
    pub fn configure_connection_filters_if_admin(
        &self,
        owner: &str,
        connection_id: &str,
        caller: &str,
        requested: &Value,
    ) -> Result<ConfigureOutcome, StoreError> {
        if !self.has_connection_admin_grant(owner, connection_id, caller)? {
            return Ok(ConfigureOutcome::AdminRequired);
        }
        let filters = match self.checked_connection_filters(owner, connection_id, requested)? {
            Ok(filters) => filters,
            Err(refusal) => return Ok(refusal),
        };
        let stored = serde_json::to_string(&filters)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        race_point("connection_admin_configure");
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            if !connection_admin_grant_on_conn(conn, owner, connection_id, caller, now)? {
                return Ok(ConfigureOutcome::AdminRequired);
            }
            if set_connection_filters_on_conn(conn, owner, connection_id, &stored, now)? {
                Ok(ConfigureOutcome::Configured(filters))
            } else {
                Ok(ConfigureOutcome::ConnectionNotFound)
            }
        })
    }

    /// The filter document a configure request would store, or the outcome
    /// that refuses it. Reads only; the caller writes.
    fn checked_connection_filters(
        &self,
        principal: &str,
        connection_id: &str,
        requested: &Value,
    ) -> Result<Result<Value, ConfigureOutcome>, StoreError> {
        let Some(connection) = self.connection(principal, connection_id)? else {
            return Ok(Err(ConfigureOutcome::ConnectionNotFound));
        };
        self.resource_filters_for_app(&connection.app_key, requested)
    }

    /// The filter document a configure request would store on a connection of
    /// `app_key`, or the outcome that refuses it, checked against the app's
    /// reviewed manifest. Reads only; lets an operator ceremony refuse bad
    /// filters before the connection they belong to exists.
    pub fn resource_filters_for_app(
        &self,
        app_key: &str,
        requested: &Value,
    ) -> Result<Result<Value, ConfigureOutcome>, StoreError> {
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, app_key)? else {
            return Ok(Err(ConfigureOutcome::ManifestMissing));
        };
        let manifest = match document {
            Ok(manifest) => manifest,
            Err(error) => return Err(StoreError::Backend(error.to_string())),
        };
        let declared: std::collections::BTreeSet<&str> = manifest
            .resource_filters
            .required
            .iter()
            .chain(manifest.resource_filters.optional.iter())
            .chain(manifest.resource_filters.write_enabling.iter())
            .map(String::as_str)
            .collect();
        let manifest_write_enabling: std::collections::BTreeSet<&str> = manifest
            .resource_filters
            .write_enabling
            .iter()
            .map(String::as_str)
            .collect();

        // Only two keys are read here. A third -- most likely a near-miss of
        // one of them, `write_enabled` for `write_enabling` -- is not a
        // security hole, because an unrecognised key leaves `write_enabling`
        // EMPTY and writes stay blocked: the failure is fail-closed, and the
        // stored document is echoed back so the emptiness is visible.
        //
        // It is refused anyway because "configured successfully" plus
        // "nothing you asked for took effect" is a debugging session an
        // operator should never have to run. The caller named the key
        // deliberately, so the useful reply is which keys exist.
        let malformed = |field: &str, expected: &str| {
            Ok(Err(ConfigureOutcome::MalformedFilters {
                field: field.to_string(),
                expected: expected.to_string(),
            }))
        };
        let Some(requested) = requested.as_object() else {
            return malformed("resource_filters", "an object");
        };
        {
            const READ_KEYS: [&str; 2] = ["write_enabling", "values"];
            if let Some(unread) = requested
                .keys()
                .find(|key| !READ_KEYS.contains(&key.as_str()))
            {
                return Ok(Err(ConfigureOutcome::UnreadFilterKey {
                    key: unread.clone(),
                    accepted: READ_KEYS.map(String::from).to_vec(),
                }));
            }
        }

        let requested_write_enabling: Vec<&str> = match requested.get("write_enabling") {
            None => Vec::new(),
            Some(Value::Array(values)) => {
                let mut keys = Vec::with_capacity(values.len());
                for value in values {
                    let Some(key) = value.as_str() else {
                        return malformed("write_enabling", "an array of strings");
                    };
                    keys.push(key);
                }
                keys
            }
            Some(_) => return malformed("write_enabling", "an array of strings"),
        };
        if let Some(undeclared) = requested_write_enabling
            .iter()
            .find(|key| !manifest_write_enabling.contains(**key))
        {
            return Ok(Err(ConfigureOutcome::UndeclaredFilter(
                (*undeclared).to_string(),
            )));
        }
        let requested_values = match requested.get("values") {
            None => None,
            Some(Value::Object(values)) => Some(values),
            Some(_) => return malformed("values", "an object"),
        };
        if let Some(values) = requested_values {
            if let Some(undeclared) = values.keys().find(|key| !declared.contains(key.as_str())) {
                return Ok(Err(ConfigureOutcome::UndeclaredFilter(undeclared.clone())));
            }
        }

        let mut filters = serde_json::Map::new();
        filters.insert(
            "required".to_string(),
            Value::from(manifest.resource_filters.required.clone()),
        );
        filters.insert(
            "write_enabling".to_string(),
            Value::from(requested_write_enabling.clone()),
        );
        if let Some(values) = requested_values {
            filters.insert("values".to_string(), Value::Object(values.clone()));
        }
        Ok(Ok(Value::Object(filters)))
    }

    pub fn set_connection_filters(
        &self,
        principal: &str,
        connection_id: &str,
        resource_filters: &Value,
    ) -> Result<bool, StoreError> {
        let filters = serde_json::to_string(resource_filters)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            set_connection_filters_on_conn(conn, principal, connection_id, &filters, now)
        })
    }

    /// Restore a connection that had been marked `degraded` after a refresh
    /// failure, once a refresh has succeeded again.
    ///
    /// Deliberately narrow: the UPDATE is guarded on `status = 'degraded'`, so
    /// it can only ever undo the transition `mark_degraded` makes. `revoked`
    /// and `pending` describe AUTHORITY rather than health, and a successful
    /// vendor call is not grounds to clear either. Doing this in SQL rather
    /// than by reading the status and writing back keeps the guard inside the
    /// same statement, so a concurrent revoke cannot land between the read and
    /// the write.
    ///
    /// This is the only status inverse, and the absence of the others is a
    /// decision. `revoked` has no inverse because recovery must be a NEW
    /// CEREMONY: a fresh binding ticket and a fresh connection, which is how a
    /// permanent authority ceiling is supposed to arrive. That is perfectly
    /// implementable and refused on purpose, so argue with it rather than
    /// assuming it is impossible. `pending` is completed by `connect`, so its
    /// inverse exists under a different name.
    ///
    /// The schema's status CHECK also admits `auth_required` and `disabled`,
    /// but no production path writes either and neither has a recovery: they
    /// are retired states. They stay in the constraint because narrowing it
    /// would need a table-rebuilding migration, and leaving the schema as it
    /// is keeps a rollback to an older binary safe. Readers treat them as not
    /// routable.
    pub fn clear_connection_degraded(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<bool, StoreError> {
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE connections SET status = 'active', health_state = ?1,
                        generation = generation + 1, updated_at_ms = ?2
                 WHERE principal = ?3 AND connection_id = ?4 AND status = 'degraded'",
                rusqlite::params![
                    "{\"reason\":\"catalog_refresh_recovered\"}",
                    now,
                    principal,
                    connection_id
                ],
            )?;
            Ok(changed != 0)
        })
    }

    /// Update recoverable health state without granting revocation authority.
    /// A late probe cannot change any field of a permanently revoked row.
    pub fn set_connection_health(
        &self,
        principal: &str,
        connection_id: &str,
        status: &str,
        health_state: &Value,
    ) -> Result<bool, StoreError> {
        if status == "revoked" {
            return Err(StoreError::Backend(
                "health updates cannot revoke a connection; use revoke_connection".into(),
            ));
        }
        let health = serde_json::to_string(health_state)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE connections SET status = ?1, health_state = ?2,
                        generation = generation + 1, updated_at_ms = ?3
                 WHERE principal = ?4 AND connection_id = ?5 AND status <> 'revoked'",
                rusqlite::params![status, health, now, principal, connection_id],
            )?;
            Ok(changed != 0)
        })
    }

    /// Revoke a connection and invalidate every undispatched reservation in the
    /// same fenced transaction. This is deliberately not a best-effort cleanup.
    /// Its unconsumed binding tickets expire with it, so none can be presented
    /// afterwards.
    pub fn revoke_connection(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<bool, StoreError> {
        let now = now_ms();
        self.inner
            .with_conn_fenced(|conn| revoke_connection_on_conn(conn, principal, connection_id, now))
    }

    /// [`Self::revoke_connection`] on behalf of `caller`, who must hold a live
    /// connection-admin grant on the connection.
    ///
    /// The grant is checked again inside the fenced transaction that revokes,
    /// so a grant revoked after the first check cannot be outrun by the
    /// revocation it no longer authorizes. The caller unregisters the
    /// connection's transports only after `Revoked` comes back, which is after
    /// the transaction committed.
    pub fn revoke_connection_if_admin(
        &self,
        owner: &str,
        connection_id: &str,
        caller: &str,
    ) -> Result<ConnectionAdminRevokeOutcome, StoreError> {
        if !self.has_connection_admin_grant(owner, connection_id, caller)? {
            return Ok(ConnectionAdminRevokeOutcome::AdminRequired);
        }
        race_point("connection_admin_revoke");
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            if !connection_admin_grant_on_conn(conn, owner, connection_id, caller, now)? {
                return Ok(ConnectionAdminRevokeOutcome::AdminRequired);
            }
            Ok(
                if revoke_connection_on_conn(conn, owner, connection_id, now)? {
                    ConnectionAdminRevokeOutcome::Revoked
                } else {
                    ConnectionAdminRevokeOutcome::ConnectionNotFound
                },
            )
        })
    }

    /// Delete a connection on an operator's instruction, with every row keyed
    /// by it ([`CONNECTION_KEYED_TABLES`]) except its audit rows and grant
    /// revocation snapshots. This runtime operator delete leaves both in place;
    /// audit retention ages out audit rows, not revocation snapshots. Migration 40
    /// was a historical exception that purged both for eligible revoked connections.
    /// An audit row naming the deleted connection is written in the
    /// same transaction, so the delete and its record commit or roll back
    /// together.
    ///
    /// Refuses while any grant on the connection still authorizes someone (not
    /// expired; revoked grants have already left the `grants` table), so a
    /// delete can never silently cut off a consumer: revoking those grants is
    /// the explicit act. Expired grants are deleted with the connection.
    /// Refuses a connection that backs a GitHub App handle (`github-handle-*`,
    /// or any connection a `github_app_handle` row names), because the handle
    /// owns that connection's lifecycle. Any status may be deleted; the usual
    /// path is revoke the connection, revoke its grants, then delete it.
    ///
    /// The checks and the deletes share one fenced transaction, so a grant
    /// minted between the check and the delete cannot slip through. With
    /// `apply` false this is a dry run: the same checks and row counts, and
    /// nothing written.
    pub fn delete_connection(
        &self,
        principal: &str,
        connection_id: &str,
        apply: bool,
    ) -> Result<DeleteConnectionOutcome, StoreError> {
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let row: Option<(String, String)> = conn
                .query_row(
                    "SELECT app_key, status FROM connections
                     WHERE principal = ?1 AND connection_id = ?2",
                    (principal, connection_id),
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((app_key, status)) = row else {
                return Ok(DeleteConnectionOutcome::NotFound);
            };
            let backs_handle: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM github_app_handle
                     WHERE connection_principal = ?1 AND connection_id = ?2)",
                (principal, connection_id),
                |row| row.get(0),
            )?;
            if backs_handle || connection_id.starts_with(GITHUB_HANDLE_CONNECTION_PREFIX) {
                return Ok(DeleteConnectionOutcome::HandleConnection);
            }
            let live_grants: i64 = conn.query_row(
                "SELECT COUNT(*) FROM grants
                 WHERE principal = ?1 AND connection_id = ?2
                   AND (expires_at IS NULL OR expires_at > ?3)",
                (principal, connection_id, now),
                |row| row.get(0),
            )?;
            if live_grants > 0 {
                return Ok(DeleteConnectionOutcome::HasLiveGrants { count: live_grants });
            }
            if apply {
                self.delete_federated_connection_on_conn(conn, principal, connection_id, now)?;
                event_outbox::count_dropped(
                    conn,
                    "principal = ?1 AND connection_id = ?2",
                    (principal, connection_id),
                    "dropped_on_delete",
                )?;
            }
            let mut rows = Vec::with_capacity(CONNECTION_KEYED_TABLES.len());
            for (table, keyed_by) in CONNECTION_KEYED_TABLES {
                let count: i64 = if apply {
                    conn.execute(
                        &format!("DELETE FROM {table} WHERE {keyed_by}"),
                        (principal, connection_id),
                    )? as i64
                } else {
                    conn.query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE {keyed_by}"),
                        (principal, connection_id),
                        |row| row.get(0),
                    )?
                };
                rows.push((*table, count));
            }
            if !apply {
                return Ok(DeleteConnectionOutcome::WouldDelete {
                    app_key,
                    status,
                    rows,
                });
            }
            conn.execute(
                "DELETE FROM connections WHERE principal = ?1 AND connection_id = ?2",
                (principal, connection_id),
            )?;
            // Row counts and the prior status are not secrets, and they are
            // what a later reader of the trail needs to know what went.
            let summary = format!(
                "deleted connection (status {status}); rows: {}",
                rows.iter()
                    .map(|(table, count)| format!("{table}={count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            conn.execute(
                "INSERT INTO audit_journal (ts, principal, actor, acting_principal, connection_id,
                     app_key, action, risk, decision, reason_code, gate, args_redaction_summary,
                     outcome)
                 VALUES (?1, ?2, 'operator', ?2, ?3, ?4, 'delete_connection', 'read', 'allow',
                     'ceremony_delete_connection', 'operator_ceremony', ?5, 'applied')",
                rusqlite::params![now, principal, connection_id, app_key, summary],
            )?;
            Ok(DeleteConnectionOutcome::Deleted {
                app_key,
                status,
                rows,
            })
        })
    }

    /// Consume a short-lived binding ticket without returning the credential
    /// handle. The connection becomes active only after this operation.
    /// The ticket's ceiling is copied onto the connection in the same
    /// transaction, so an active connection always carries its authority bound.
    pub fn connect_with_ticket(
        &self,
        principal: &str,
        ticket_id: &str,
    ) -> Result<Option<ConnectionSummary>, StoreError> {
        type TicketRow = (String, i64, String, String, String, String, Option<String>);
        let app_key: Option<String> = self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT c.app_key FROM binding_tickets t JOIN connections c
                   ON c.principal=t.principal AND c.connection_id=t.connection_id
                 WHERE t.principal=?1 AND t.ticket_id=?2",
                (principal, ticket_id),
                |row| row.get(0),
            )
            .optional()
        })?;
        let Some(app_key) = app_key else {
            return Ok(None);
        };
        let takes_instance_url = self.manifest_takes_instance_url(&app_key)?;
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let ticket: Option<TicketRow> = conn
                .query_row(
                    "SELECT connection_id, expires_at, status, risk_ceiling, action_selectors,
                            ref_role, instance_url
                     FROM binding_tickets
                     WHERE principal = ?1 AND ticket_id = ?2",
                    (principal, ticket_id),
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                connection_id,
                expires_at,
                status,
                ceiling_risk,
                ceiling_selectors,
                ref_role,
                instance_address,
            )) = ticket
            else {
                return Ok(None);
            };
            if status != "issued" || expires_at <= now {
                conn.execute(
                    "UPDATE binding_tickets SET status = 'expired'
                     WHERE principal = ?1 AND ticket_id = ?2 AND status = 'issued'",
                    (principal, ticket_id),
                )?;
                return Ok(None);
            }
            let instance = match instance_address.as_deref().map(crate::instance_url::InstanceUrl::parse).transpose() {
                Ok(instance) => instance,
                Err(_) => return Ok(None),
            };
            if takes_instance_url != instance.is_some() {
                return Ok(None);
            }
            // A credentialed enrollment must have written its binding before it
            // can activate; the NULL check is what makes a half-finished
            // ceremony fail closed. A credential-free enrollment has no binding
            // to check by construction, so requiring one would make no-auth
            // vendors permanently unconnectable.
            //
            // A revoked connection never becomes active again. A connection
            // that already records a ceiling keeps it: the ticket's ceiling is
            // copied only onto a connection that has none yet, so a later
            // ticket can re-enroll a connection but never widen what it allows.
            let binding_check = if ref_role == NO_CREDENTIAL_REF_ROLE {
                "credential_binding IS NULL"
            } else {
                "credential_binding IS NOT NULL"
            };
            let changed = conn.execute(
                &format!(
                    "UPDATE connections SET status = 'active', generation = generation + 1,
                            updated_at_ms = ?1,
                            ceiling_selectors = CASE WHEN ceiling_risk IS NULL
                                THEN ?5 ELSE ceiling_selectors END,
                            ceiling_risk = COALESCE(ceiling_risk, ?4), instance_url = ?6
                     WHERE principal = ?2 AND connection_id = ?3 AND status = 'pending'
                       AND {binding_check}"
                ),
                rusqlite::params![
                    now,
                    principal,
                    connection_id.as_str(),
                    ceiling_risk,
                    ceiling_selectors,
                    instance.as_ref().map(|url| url.as_str())
                ],
            )?;
            if changed == 0 {
                conn.execute("UPDATE binding_tickets SET status='expired' WHERE principal=?1 AND ticket_id=?2 AND status='issued'", (principal, ticket_id))?;
                return Ok(None);
            }
            conn.execute(
                "UPDATE binding_tickets SET status = 'consumed'
                 WHERE principal = ?1 AND ticket_id = ?2 AND status = 'issued'",
                (principal, ticket_id),
            )?;
            conn.query_row(
                "SELECT connection_id, app_key, status, generation FROM connections
                 WHERE principal = ?1 AND connection_id = ?2",
                (principal, connection_id),
                |row| {
                    Ok(ConnectionSummary {
                        connection_id: row.get(0)?,
                        app_key: row.get(1)?,
                        status: row.get(2)?,
                        generation: row.get(3)?,
                    })
                },
            )
            .optional()
        })
    }

    pub fn connection_has_app_handle(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM github_app_handle
                 WHERE connection_principal = ?1 AND connection_id = ?2)",
                (principal, connection_id),
                |row| row.get(0),
            )
        })
    }

    pub fn connection_credential_binding_kind(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Option<&'static str>, StoreError> {
        self.connection_credential_binding(principal, connection_id)
            .map(|binding| binding.map(|binding| binding.kind()))
    }

    /// The vault reference name a connection is bound to, or `None` when it
    /// has no credential binding. The name is not a secret; the bytes behind
    /// it are only ever read from the vault.
    pub fn connection_credential_reference(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Option<String>, StoreError> {
        self.connection_credential_binding(principal, connection_id)
            .map(|binding| {
                binding.map(|binding| match binding {
                    crate::credentials::ConnectionCredentialBinding::Reference(id) => id,
                })
            })
    }

    pub(crate) fn connection_credential_binding(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Option<crate::credentials::ConnectionCredentialBinding>, StoreError> {
        self.inner.with_read(|conn| {
            // The column is nullable: a connection created without a binding
            // (an imported GitHub handle connection, whose token comes from the
            // App vault) stores NULL. Read it as `Option` so NULL means "no
            // binding" instead of failing as a column type error, which
            // callers could only report as an unexplained store failure.
            let binding: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT credential_binding FROM connections
                     WHERE principal = ?1 AND connection_id = ?2",
                    (principal, connection_id),
                    |row| row.get::<_, Option<Vec<u8>>>(0),
                )
                .optional()?
                .flatten();
            binding
                .map(|value| {
                    decode_connection_binding(&value).map_err(|error| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            error,
                        )))
                    })
                })
                .transpose()
        })
    }

    /// Replace only the active generation that was inspected before the vault
    /// read. The binding, generation and audit commit or roll back together.
    pub fn rebind_credential_reference(
        &self,
        principal: &str,
        connection_id: &str,
        expected_generation: i64,
        credential_id: &str,
    ) -> Result<bool, StoreError> {
        let binding = encode_reference_binding(credential_id).map_err(StoreError::Backend)?;
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE connections SET credential_binding = ?1, generation = generation + 1,
                     updated_at_ms = ?2
                 WHERE principal = ?3 AND connection_id = ?4 AND status = 'active'
                     AND generation = ?5
                     AND NOT EXISTS (SELECT 1 FROM github_app_handle
                         WHERE connection_principal = ?3 AND connection_id = ?4)",
                rusqlite::params![
                    binding,
                    now_ms(),
                    principal,
                    connection_id,
                    expected_generation
                ],
            )?;
            if changed == 0 {
                return Ok(false);
            }
            let fingerprint = crate::fingerprint::fingerprint(credential_id.as_bytes());
            let mut record = AuditRecord::ceremony(
                principal,
                None,
                Some(connection_id),
                "rebind_credential",
                "read",
                Some(&fingerprint),
            );
            record.outcome = Some("applied".into());
            append_audit_on_conn(conn, &record, None, None, None, None)?;
            Ok(true)
        })
    }
}
