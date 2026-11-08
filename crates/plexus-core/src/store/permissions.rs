//! Store reads behind `permissions/v1`: live agent GitHub bot grants and
//! module invoke grants whose connections can be classified by the provider.

use cortexkit_store::StoreError;
use rusqlite::params;

use super::{parse_string_list, AuditRecord, PlexusStore};

/// One live agent-layer grant (a `grants` row with an `agent_id`), with the
/// GitHub bot identity of the connection it is on, when there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveAgentGrant {
    pub principal: String,
    pub grant_id: String,
    pub agent_id: String,
    pub connection_id: String,
    pub action_selectors: Vec<String>,
    pub expires_at: Option<i64>,
    pub created_at_ms: i64,
    /// The bot's GitHub login (`<app slug>[bot]`), or `None` when no GitHub
    /// App handle names this connection.
    pub bot_login: Option<String>,
    /// The repositories bound to that handle, sorted. Empty without a handle.
    pub repositories: Vec<String>,
}

/// A live module invoke grant with the connection facts used to identify
/// search capabilities. Other module capabilities are not listed by the provider.
pub struct LiveModuleGrant {
    pub principal: String,
    pub grant_id: String,
    pub module_id: String,
    pub connection_id: String,
    pub app_key: String,
    pub status: String,
    pub expires_at: Option<i64>,
    pub created_at_ms: i64,
}

impl PlexusStore {
    /// Every live agent-layer grant, optionally for one agent only.
    ///
    /// Module-layer grants (`agent_id IS NULL`) and policies are not returned
    /// by this agent-only query. A grant is live while `now < expires_at`; a revoked
    /// grant has already left `grants`. One read transaction answers the whole
    /// list, so the bot identities match the grants they label.
    pub fn live_agent_grants(
        &self,
        agent_id: Option<&str>,
        now: i64,
    ) -> Result<Vec<LiveAgentGrant>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT g.principal, g.grant_id, g.agent_id, g.connection_id,
                        g.action_selectors, g.expires_at, g.created_at_ms,
                        h.app_handle_id, h.credential_reference
                 FROM grants g
                 LEFT JOIN github_app_handle h
                   ON h.connection_principal = g.principal AND h.connection_id = g.connection_id
                 WHERE g.agent_id IS NOT NULL
                   AND (?1 IS NULL OR g.agent_id = ?1)
                   AND (g.expires_at IS NULL OR g.expires_at > ?2)
                 ORDER BY g.agent_id, g.connection_id, g.principal, g.grant_id",
            )?;
            let rows = statement
                .query_map(params![agent_id, now], |row| {
                    let selectors: String = row.get(4)?;
                    let handle: Option<String> = row.get(7)?;
                    let credential: Option<String> = row.get(8)?;
                    Ok((
                        LiveAgentGrant {
                            principal: row.get(0)?,
                            grant_id: row.get(1)?,
                            agent_id: row.get(2)?,
                            connection_id: row.get(3)?,
                            action_selectors: parse_string_list(&selectors)?,
                            expires_at: row.get(5)?,
                            created_at_ms: row.get(6)?,
                            // Display the same bot login used for ownership checks.
                            bot_login: credential
                                .as_deref()
                                .and_then(crate::github::credential::bot_login),
                            repositories: Vec::new(),
                        },
                        handle,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut bound = conn.prepare(
                "SELECT repository FROM github_repo_binding
                 WHERE app_handle_id = ?1 ORDER BY repository",
            )?;
            let mut bindings = std::collections::HashMap::<String, Vec<String>>::new();
            rows.into_iter()
                .map(|(mut grant, handle)| {
                    if let Some(handle) = handle {
                        if let Some(repositories) = bindings.get(&handle) {
                            grant.repositories = repositories.clone();
                        } else {
                            grant.repositories = bound
                                .query_map([&handle], |row| row.get(0))?
                                .collect::<rusqlite::Result<Vec<String>>>()?;
                            bindings.insert(handle, grant.repositories.clone());
                        }
                    }
                    Ok(grant)
                })
                .collect()
        })
    }

    /// Live module-layer invoke grants to principals in the `reserved:`
    /// namespace. Revoked grants have already left `grants`.
    pub fn live_module_grants(&self, now: i64) -> Result<Vec<LiveModuleGrant>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT g.principal, g.grant_id, substr(g.grantee_principal, 10),
                        g.connection_id, c.app_key, c.status, g.expires_at, g.created_at_ms
                 FROM grants g
                 JOIN connections c ON c.principal = g.principal AND c.connection_id = g.connection_id
                 WHERE g.agent_id IS NULL AND g.authority_kind = 'invoke'
                   AND substr(g.grantee_principal, 1, 9) = 'reserved:'
                   AND length(g.grantee_principal) > 9
                   AND (g.expires_at IS NULL OR g.expires_at > ?1)
                 ORDER BY g.grantee_principal, g.principal, g.connection_id, g.grant_id",
            )?;
            let rows = statement
                .query_map([now], |row| {
                    Ok(LiveModuleGrant {
                        principal: row.get(0)?,
                        grant_id: row.get(1)?,
                        module_id: row.get(2)?,
                        connection_id: row.get(3)?,
                        app_key: row.get(4)?,
                        status: row.get(5)?,
                        expires_at: row.get(6)?,
                        created_at_ms: row.get(7)?,
                    })
                })?;
            rows.collect()
        })
    }
}

impl AuditRecord {
    /// Record one grant removed by an operator's `permissions.revoke`.
    ///
    /// The row is owned by the grant's principal, as the row written by
    /// `ceremony::revoke_grant` in plexus-module (the operation behind
    /// `ck-plexus-admin revoke-grant`) is. So it shows beside that principal's
    /// other ceremony rows: the audit rows `AuditRecord::ceremony` writes for
    /// the operator's privileged operations (tickets, grants, revokes,
    /// policies). The caller is the acting principal: `reserved:cingulate`,
    /// the module that serves the operator's permissions page, or `direct`,
    /// the local operator's own route. The grant id and the page row go in
    /// the summary because the audit row has no grant column.
    pub fn permissions_revocation(
        caller: &str,
        principal: &str,
        agent_id: Option<&str>,
        connection_id: &str,
        grant_id: &str,
        row_id: &str,
    ) -> Self {
        let mut record = Self::ceremony(
            principal,
            None,
            Some(connection_id),
            "revoke_grant",
            "read",
            None,
        );
        record.acting_principal = caller.to_string();
        record.agent_id = agent_id.map(str::to_string);
        record.reason_code = "permissions_revoke".to_string();
        record.gate = Some("permissions_v1".to_string());
        record.args_redaction_summary = Some(format!(
            "grant {grant_id} revoked with permissions row {row_id}"
        ));
        record
    }
}
