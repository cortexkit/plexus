//! Transactional GitHub handle and binding writes, plus governance projections.

use super::PlexusStore;
use crate::credentials::ResolvedCredential;
use crate::github::credential::HandleCredentialProvider;
use crate::github::receipt::{
    has_uncertain_effect, lease_expires_at, Claim, Effect, Receipt, RETENTION_MS,
};
use crate::governance::{
    AuthorizationRequest, Denial, GovernanceSeams, HandleAuthority, PolicyInputs,
    ReceiptApprovalRow, ResolverDenial, ScopedGrantRow,
};
use crate::storage::{
    insert_policy_on_conn, map_grant_row, now_ms, CatalogAction, ConnectionRecord,
};
use cortexkit_store::StoreError;
use rusqlite::{params, OptionalExtension};
use serde_json::Value;
use std::sync::Arc;

mod invoke_grant;
mod read_grant;
pub use read_grant::GithubHandleReadGrant;

enum GithubBindingSelector<'a> {
    Connection(&'a str),
    Agent(&'a str),
}

/// The credential reference identifies one App; an installation id is optional
/// because the vault delivers a ready installation token by credential id.
#[derive(Debug, Clone)]
pub struct GithubHandle {
    pub app_handle_id: String,
    pub agent_id: String,
    pub app_id: i64,
    pub installation_id: Option<i64>,
    pub credential_reference: String,
    pub credential_generation: i64,
    pub status: String,
    pub proven_at: Option<i64>,
    pub connection_principal: String,
    pub connection_id: String,
}

/// A handle owned by one agent, with the repositories currently bound to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGithubHandle {
    pub app_handle_id: String,
    pub status: String,
    pub repositories: Vec<String>,
}

impl PlexusStore {
    pub(crate) fn github_handle_agents(&self) -> Result<Vec<String>, StoreError> {
        self.inner.with_read(|conn| {
            let mut query =
                conn.prepare("SELECT agent_id FROM github_app_handle ORDER BY agent_id")?;
            let rows = query
                .query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
    }

    pub(crate) fn retire_github_agent(&self, agent: &str) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute("UPDATE github_app_handle SET status='disabled',proven_at=NULL WHERE agent_id=?1 AND status<>'disabled'", [agent])?;
            conn.execute("UPDATE action_requests SET status='denied' WHERE agent_id=?1 AND status IN ('pending','approved')", [agent])?;
            Ok(())
        })
    }

    /// Resolve one canonical repository binding without enumerating unrelated handles.
    pub fn github_handle_for_repo(
        &self,
        repository: &str,
    ) -> Result<Option<GithubHandle>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT h.app_handle_id,h.agent_id,h.app_id,h.installation_id,h.credential_reference,
                h.credential_generation,h.status,h.proven_at,h.connection_principal,h.connection_id
                FROM github_repo_binding b JOIN github_app_handle h ON h.app_handle_id=b.app_handle_id
                WHERE b.repository=?1",
                [repository.to_lowercase()],
                |row| Ok(GithubHandle { app_handle_id:row.get(0)?,agent_id:row.get(1)?,app_id:row.get(2)?,installation_id:row.get(3)?,credential_reference:row.get(4)?,credential_generation:row.get(5)?,status:row.get(6)?,proven_at:row.get(7)?,connection_principal:row.get(8)?,connection_id:row.get(9)? }),
            ).optional()
        })
    }

    /// Insert or update the handle in a fenced transaction. SQL uniqueness
    /// rejects an agent or credential assigned to two different handles.
    #[cfg(any(test, feature = "test-support"))]
    pub fn put_github_handle(&self, handle: &GithubHandle) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO github_app_handle
                 (app_handle_id, agent_id, app_id, installation_id, credential_reference,
                  credential_generation, status, proven_at, connection_principal, connection_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
                 ON CONFLICT(app_handle_id) DO UPDATE SET
                  agent_id=excluded.agent_id, app_id=excluded.app_id,
                  installation_id=excluded.installation_id,
                  credential_reference=excluded.credential_reference,
                  credential_generation=excluded.credential_generation,
                  status=excluded.status, proven_at=excluded.proven_at,
                  connection_principal=excluded.connection_principal,
                  connection_id=excluded.connection_id",
                params![
                    handle.app_handle_id,
                    handle.agent_id,
                    handle.app_id,
                    handle.installation_id,
                    handle.credential_reference,
                    handle.credential_generation,
                    handle.status,
                    handle.proven_at,
                    handle.connection_principal,
                    handle.connection_id
                ],
            )?;
            Ok(())
        })
    }

    /// Replace one repository binding and rewrite both affected connections'
    /// allowlists in the same transaction. A failed rewrite rolls back the
    /// binding and its global generation increment as well.
    #[cfg(any(test, feature = "test-support"))]
    pub fn bind_github_repo(
        &self,
        repository: &str,
        app_handle_id: &str,
    ) -> Result<i64, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            bind_repo_on_conn(conn, repository, app_handle_id)?;
            conn.query_row(
                "SELECT generation FROM github_repo_binding_generation WHERE singleton=1",
                [],
                |row| row.get(0),
            )
        })
    }

    /// The handles an agent owns, each with the repositories bound to it. Read
    /// only, so the retirement sweep can name what an operator must rebind
    /// without touching the handle itself.
    pub fn github_handles_for_agent(
        &self,
        agent_id: &str,
    ) -> Result<Vec<AgentGithubHandle>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT app_handle_id, status FROM github_app_handle
                 WHERE agent_id=?1 ORDER BY app_handle_id",
            )?;
            let handles = statement
                .query_map([agent_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get(1)?))
                })?
                .collect::<rusqlite::Result<Vec<(String, String)>>>()?;
            let mut repositories = conn.prepare(
                "SELECT repository FROM github_repo_binding
                 WHERE app_handle_id=?1 ORDER BY repository",
            )?;
            handles
                .into_iter()
                .map(|(app_handle_id, status)| {
                    let bound = repositories
                        .query_map([&app_handle_id], |row| row.get(0))?
                        .collect::<rusqlite::Result<Vec<String>>>()?;
                    Ok(AgentGithubHandle {
                        app_handle_id,
                        status,
                        repositories: bound,
                    })
                })
                .collect()
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn unbind_github_repo(&self, repository: &str) -> Result<i64, StoreError> {
        let repository = &crate::github::canonical_repository(repository);
        self.inner.with_conn_fenced(|conn| {
            let tx = conn;
            let previous: Option<String> = tx
                .query_row(
                    "SELECT app_handle_id FROM github_repo_binding WHERE repository=?1",
                    [repository],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(previous) = previous {
                tx.execute(
                    "DELETE FROM github_repo_binding WHERE repository=?1",
                    [repository],
                )?;
                rewrite_filters(tx, &previous)?;
            }
            let generation = tx.query_row(
                "SELECT generation FROM github_repo_binding_generation WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            Ok(generation)
        })
    }
}

/// Bind (or move) one repository to a handle on an already open, fenced
/// connection, so several bindings can share one transaction. Enforces one
/// owner per handle and rewrites the write filters of the handle and of any
/// handle the repository moved away from; the binding-table triggers advance
/// the global binding generation. The repository is stored in its canonical
/// (lowercase) form.
fn bind_repo_on_conn(
    tx: &rusqlite::Connection,
    repository: &str,
    app_handle_id: &str,
) -> rusqlite::Result<()> {
    let repository = &crate::github::canonical_repository(repository);
    let owner = repository
        .split_once('/')
        .map(|(owner, _)| owner)
        .filter(|owner| !owner.is_empty())
        .ok_or_else(|| rusqlite::Error::InvalidParameterName("binding_owner_mismatch".into()))?;
    let existing_owner: Option<String> = tx
        .query_row(
            "SELECT repository FROM github_repo_binding WHERE app_handle_id=?1 LIMIT 1",
            [app_handle_id],
            |row| row.get(0),
        )
        .optional()?;
    if existing_owner
        .as_deref()
        .is_some_and(|existing| existing.split_once('/').map(|(value, _)| value) != Some(owner))
    {
        return Err(rusqlite::Error::InvalidParameterName(
            "binding_owner_mismatch".into(),
        ));
    }
    let previous: Option<String> = tx
        .query_row(
            "SELECT app_handle_id FROM github_repo_binding WHERE repository=?1",
            [repository],
            |row| row.get(0),
        )
        .optional()?;
    if previous.as_deref() == Some(app_handle_id) {
        // Explicit writes advance the counter even when the binding is unchanged.
        tx.execute(
            "UPDATE github_repo_binding SET app_handle_id=?2 WHERE repository=?1",
            params![repository, app_handle_id],
        )?;
    } else {
        tx.execute(
            "INSERT INTO github_repo_binding (repository, app_handle_id) VALUES (?1,?2)
            ON CONFLICT(repository) DO UPDATE SET app_handle_id=excluded.app_handle_id",
            params![repository, app_handle_id],
        )?;
    }
    rewrite_filters(tx, app_handle_id)?;
    if let Some(previous) = previous.filter(|id| id != app_handle_id) {
        rewrite_filters(tx, &previous)?;
    }
    Ok(())
}

fn rewrite_filters(conn: &rusqlite::Connection, handle: &str) -> rusqlite::Result<()> {
    let (principal, connection_id): (String, String) = conn.query_row(
        "SELECT connection_principal, connection_id FROM github_app_handle WHERE app_handle_id=?1",
        [handle],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let repositories: Vec<String> = conn
        .prepare(
            "SELECT repository FROM github_repo_binding WHERE app_handle_id=?1 ORDER BY repository",
        )?
        .query_map([handle], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let owner = repositories
        .first()
        .and_then(|name| name.split_once('/').map(|(owner, _)| owner));
    if repositories
        .iter()
        .any(|name| name.split_once('/').map(|(value, _)| value) != owner)
    {
        return Err(rusqlite::Error::InvalidParameterName(
            "binding_owner_mismatch".into(),
        ));
    }
    let names: Vec<_> = repositories
        .iter()
        .map(|name| name.split_once('/').map(|(_, repo)| repo).unwrap_or(""))
        .collect();
    let json = serde_json::to_string(&names)
        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(err.into()))?;
    let updated = conn.execute(
        "UPDATE connections SET resource_filters=json_set(
            json_set(json_set(resource_filters, '$.values.repo', json(?3)),
                '$.values.owner', ?4),
            '$.write_enabling', json('[\"owner\",\"repo\"]')),
            generation=generation+1, updated_at_ms=?5
         WHERE principal=?1 AND connection_id=?2",
        params![principal, connection_id, json, owner, now_ms()],
    )?;
    if updated != 1 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    Ok(())
}

impl PlexusStore {
    /// The invoke grant rows on one connection that can speak for a call from
    /// `grantee`, optionally carrying a verified `agent_id`: module rows (no
    /// agent) naming the exact grantee, plus every row keyed to the agent.
    ///
    /// Module rows belong to the calling module. Agent rows state what the agent
    /// may do, so they apply whichever module carries a call for that agent (as
    /// named by the route's scope stamp) and are not filtered by grantee. Callers pick the module and agent layers
    /// out of the result with `governance::scoped_grant`.
    pub(crate) fn scoped_invoke_grant_rows(
        &self,
        connection: &ConnectionRecord,
        grantee: &str,
        agent_id: Option<&str>,
    ) -> Result<Vec<ScopedGrantRow>, StoreError> {
        let now = now_ms();
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT grant_id, principal, connection_id, grantee_principal, risk_ceiling,
                        action_selectors, authority_kind, expires_at, generation, agent_id
                 FROM grants WHERE principal=?1 AND connection_id=?2 AND authority_kind='invoke'
                   AND ((agent_id IS NULL AND grantee_principal=?3 AND grantee_principal<>'*')
                        OR agent_id=?4) ORDER BY grant_id",
            )?;
            let rows = statement
                .query_map(
                    params![
                        connection.principal,
                        connection.connection_id,
                        grantee,
                        agent_id
                    ],
                    |row| {
                        let grant = map_grant_row(row, now)?;
                        Ok(ScopedGrantRow {
                            grant,
                            agent_id: row.get(9)?,
                        })
                    },
                )?
                .collect();
            rows
        })
    }
}

/// Store-backed governance projections and repository-bound invoke resolution.
/// Ordinary invokes cannot use GitHub write actions; those require an internal
/// facade-origin request, which still undergoes grant matching.
pub struct GithubGovernanceSeams<S: std::ops::Deref<Target = PlexusStore>> {
    pub store: S,
    /// Without an installed scoped vault reader, handle dispatch fails closed.
    pub credential_provider: Option<Arc<dyn HandleCredentialProvider>>,
}

impl<S: std::ops::Deref<Target = PlexusStore> + Send + Sync> GovernanceSeams
    for GithubGovernanceSeams<S>
{
    fn prepare_invoke(&self, request: &mut AuthorizationRequest) -> Result<(), ResolverDenial> {
        if request.action != "github.issue.search" || request.resolved_github_search() {
            return Ok(());
        }
        let Some(connection) = self
            .store
            .connection_for_invoke(&request.principal, &request.connection_id)
            .map_err(|_| ResolverDenial::StoreFailure)?
        else {
            return Ok(());
        };
        if !self
            .store
            .is_github_handle_connection(&connection.principal, &connection.connection_id)
            .map_err(|_| ResolverDenial::StoreFailure)?
        {
            return Ok(());
        }
        self.resolve_invoke(request)?;
        let repositories = request.args["repositories"]
            .as_array()
            .ok_or(ResolverDenial::RepositoryUnbound)?;
        let resolved = crate::github::resolver::ResolvedRepositories {
            repositories: repositories
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or(ResolverDenial::RepositoryUnbound)
                })
                .collect::<Result<_, _>>()?,
            binding: crate::github::resolver::Binding {
                app_handle_id: String::new(),
                connection_id: request.connection_id.clone(),
            },
        };
        *request = crate::github::reads::prepare_search_request(request.clone(), &resolved)?;
        Ok(())
    }

    fn resolve_invoke(&self, request: &AuthorizationRequest) -> Result<(), ResolverDenial> {
        use crate::github::resolver::{self, Binding};
        // A handle is identified by its full connection key, which is unique
        // only per principal. Check the connection this invoke will actually
        // run on, found the same way authorization finds it, so another
        // principal's ordinary connection that happens to share a handle
        // connection's id is not routed through the repository resolver.
        let is_handle = match self
            .store
            .connection_for_invoke(&request.principal, &request.connection_id)
            .map_err(|_| ResolverDenial::StoreFailure)?
        {
            Some(connection) => self
                .store
                .is_github_handle_connection(&connection.principal, &connection.connection_id)
                .map_err(|_| ResolverDenial::StoreFailure)?,
            None => false,
        };
        if !is_handle {
            return Ok(());
        }
        let mut routed = request.clone();
        if request.resolved_github_search() {
            // Plexus built q from the binding-checked selection. Omit it only
            // from this validation copy, where caller-built queries are forbidden;
            // the governed request still sends Plexus's constructed query.
            routed
                .args
                .as_object_mut()
                .ok_or(ResolverDenial::RepositoryUnbound)?
                .remove("q");
        }
        if request.origin() == crate::governance::RequestOrigin::Facade {
            let owner = request
                .args
                .get("owner")
                .and_then(Value::as_str)
                .ok_or(ResolverDenial::RepositoryUnbound)?;
            let repo = request
                .args
                .get("repo")
                .and_then(Value::as_str)
                .ok_or(ResolverDenial::RepositoryUnbound)?;
            routed.args["repository"] = Value::String(format!("{owner}/{repo}"));
        } else if let Some(repository) = request.resolved_repository() {
            // Plexus's own read path resolved the binding already and keeps
            // the routing field out of the vendor arguments. The resolver
            // still checks it against the owner and repo actually sent.
            if request.args.get("repository").is_some() {
                return Err(ResolverDenial::RequestFieldForbidden {
                    field: "repository".into(),
                });
            }
            routed.args["repository"] = Value::String(repository.to_string());
        }
        resolver::resolve_invoke(&routed, |repository| {
            let repository = crate::github::canonical_repository(repository);
            self.store
                .inner
                .with_read(|conn| {
                    conn.query_row(
                        "SELECT h.app_handle_id, h.connection_id FROM github_repo_binding b
                     JOIN github_app_handle h ON h.app_handle_id=b.app_handle_id
                     WHERE b.repository=?1",
                        [&repository],
                        |row| {
                            Ok(Binding {
                                app_handle_id: row.get(0)?,
                                connection_id: row.get(1)?,
                            })
                        },
                    )
                    .optional()
                })
                .map_err(|_| ResolverDenial::StoreFailure)
        })
    }

    fn facade_only(&self, action: &CatalogAction) -> bool {
        crate::catalog::facade_only_from_stored_manifest(&self.store, action)
    }

    fn handle_row(&self, connection: &ConnectionRecord) -> Result<Option<HandleAuthority>, Denial> {
        self.store
            .inner
            .with_read(|conn| {
                conn.query_row(
                "SELECT app_handle_generation, credential_generation, status, credential_reference,
                    (SELECT generation FROM github_repo_binding_generation WHERE singleton=1)
                 FROM github_app_handle WHERE connection_principal=?1 AND connection_id=?2",
                params![connection.principal, connection.connection_id], |row| {
                    let status: String = row.get(2)?;
                    let reference: String = row.get(3)?;
                    Ok(HandleAuthority {
                        app_handle_generation: row.get(0)?,
                        credential_generation: row.get(1)?,
                        enabled: status == "enabled",
                        credential_reference: reference.into_bytes(),
                        repo_binding_generation: row.get(4)?,
                    })
                },
            ).optional()
            })
            .map_err(|_| Denial::StoreFailure)
    }

    fn prepare_handle_credential(
        &self,
        connection: &ConnectionRecord,
        handle: &HandleAuthority,
    ) -> Result<ResolvedCredential, &'static str> {
        use crate::github::credential::{UNRESOLVABLE_PERMANENT, UNRESOLVABLE_TRANSIENT};
        // No provider wired in is a plexus setup fault; a failed store read may
        // clear on retry; a non-UTF-8 reference is malformed. The provider's
        // own refusal already names its class and passes through unchanged.
        let provider = self
            .credential_provider
            .as_ref()
            .ok_or(UNRESOLVABLE_PERMANENT)?;
        let app_handle_id: String = self.store.inner.with_read(|conn| {
            conn.query_row(
                "SELECT app_handle_id FROM github_app_handle WHERE connection_principal=?1 AND connection_id=?2",
                params![connection.principal, connection.connection_id],
                |row| row.get(0),
            )
        }).map_err(|_| UNRESOLVABLE_TRANSIENT)?;
        let reference = std::str::from_utf8(&handle.credential_reference)
            .map_err(|_| UNRESOLVABLE_PERMANENT)?;
        provider.prepare(&app_handle_id, handle.credential_generation, reference)
    }

    fn handle_auth_failure(&self, connection: &ConnectionRecord, handle: &HandleAuthority) {
        let Some(provider) = self.credential_provider.as_ref() else {
            return;
        };
        let app_handle_id = self.store.inner.with_read(|conn| {
            conn.query_row::<String, _, _>(
                "SELECT app_handle_id FROM github_app_handle WHERE connection_principal=?1 AND connection_id=?2",
                params![connection.principal, connection.connection_id],
                |row| row.get(0),
            )
        });
        if let (Ok(id), Ok(reference)) = (
            app_handle_id,
            std::str::from_utf8(&handle.credential_reference),
        ) {
            provider.vendor_status(&id, handle.credential_generation, reference, 401);
        }
    }

    fn grant_rows(
        &self,
        connection: &ConnectionRecord,
        request: &AuthorizationRequest,
    ) -> Result<Vec<ScopedGrantRow>, Denial> {
        self.store
            .scoped_invoke_grant_rows(
                connection,
                &request.principal,
                request.attributed_agent_id.as_deref(),
            )
            .map_err(|_| Denial::StoreFailure)
    }

    fn grant_generations(
        &self,
        connection: &ConnectionRecord,
        principal: &str,
        agent_id: &str,
        action: &str,
    ) -> Result<(i64, i64), Denial> {
        let request = AuthorizationRequest::new(
            principal,
            &connection.connection_id,
            action,
            serde_json::json!({}),
        )
        .with_bound_agent(agent_id, "");
        let rows = self.grant_rows(connection, &request)?;
        let generation = |agent: Option<&str>| {
            rows.iter()
                .filter(|row| {
                    row.agent_id.as_deref() == agent && row.grant.authorizes(action, now_ms())
                })
                .map(|row| row.grant.generation)
                .max()
        };
        // Missing grants must differ from a claimed baseline after revocation;
        // grant presence is checked before a new receipt can be claimed.
        Ok((
            generation(Some(agent_id)).unwrap_or(-1),
            generation(None).unwrap_or(-1),
        ))
    }

    fn policy_inputs(
        &self,
        connection: &ConnectionRecord,
        agent_id: &str,
        action: &CatalogAction,
    ) -> Result<PolicyInputs, Denial> {
        self.store
            .inner
            .with_read(|conn| {
                let mut statement = conn.prepare(
                    "SELECT principal, action_selector, effect, generation FROM policies
                 WHERE connection_id=?1 AND principal IN (?2, ?3)
                    AND action_selector IN (?4, '*')
                    AND (expires_at IS NULL OR expires_at > ?5)
                 ORDER BY (action_selector = ?4) DESC, generation DESC",
                )?;
                let mut module_effect = None;
                let mut agent_effect = None;
                let mut module_generation = 0;
                let rows = statement.query_map(
                    params![
                        connection.connection_id,
                        connection.principal,
                        agent_id,
                        action.name,
                        now_ms()
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )?;
                for row in rows {
                    let (owner, effect, generation) = row?;
                    if owner == connection.principal && module_effect.is_none() {
                        module_effect = Some(effect);
                        module_generation = generation;
                    } else if owner == agent_id && agent_effect.is_none() {
                        agent_effect = Some(effect);
                    }
                }
                Ok(PolicyInputs {
                    module_effect,
                    agent_effect,
                    module_generation,
                })
            })
            .map_err(|_| Denial::StoreFailure)
    }

    fn ownership_reads_complete(&self, request: &AuthorizationRequest) -> bool {
        request
            .ownership_proof()
            .is_some_and(|proof| proof.satisfies(&request.action))
    }

    fn pre_transmit(&self, reservation: &crate::governance::Reservation) -> bool {
        let Some(claim) = reservation.receipt.as_ref() else {
            return reservation.origin == crate::governance::RequestOrigin::Facade
                && reservation.risk == crate::manifest::Risk::Read;
        };
        if reservation.attributed_agent_id.as_deref() != Some(claim.agent_id.as_str()) {
            return false;
        }
        match self.store.mark_github_dispatch(
            &claim.agent_id,
            &claim.request_nonce,
            &claim.claim_owner,
            claim.effect_index,
            now_ms(),
            &reservation.request_id,
        ) {
            Ok(marked) => marked,
            Err(_) => {
                crate::diag!(warn governance: "dispatch marker mark failed: request_id={:?}; contact refused",reservation.request_id);
                false
            }
        }
    }

    fn abandon_transmit(&self, reservation: &crate::governance::Reservation) {
        if let Some(claim) = reservation.receipt.as_ref() {
            if self
                .store
                .clear_github_dispatch(
                    &claim.agent_id,
                    &claim.request_nonce,
                    &claim.claim_owner,
                    claim.effect_index,
                    &reservation.request_id,
                    now_ms(),
                )
                .is_err()
            {
                crate::diag!(warn governance: "dispatch marker clear failed: request_id={:?}; marker stays set and retries may remain in flight until expiry",reservation.request_id);
            }
        }
    }

    fn receipt_approval(
        &self,
        connection: &ConnectionRecord,
        id: &str,
    ) -> Result<Option<ReceiptApprovalRow>, Denial> {
        self.store
            .inner
            .with_read(|conn| {
                conn.query_row(
                    "SELECT request_id, agent_id, status, expires_at FROM action_requests
                 WHERE principal=?1 AND connection_id=?2 AND request_id=?3",
                    params![connection.principal, connection.connection_id, id],
                    |row| {
                        let agent_id: Option<String> = row.get(1)?;
                        let action_request_id = row.get(0)?;
                        let status = row.get(2)?;
                        let expires_at_ms = row.get(3)?;
                        Ok(agent_id.map(|agent_id| ReceiptApprovalRow {
                            action_request_id,
                            agent_id,
                            status,
                            expires_at_ms,
                        }))
                    },
                )
                .optional()
                .map(|row| row.flatten())
            })
            .map_err(|_| Denial::StoreFailure)
    }
}

fn receipt_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Receipt> {
    fn json<T: serde::de::DeserializeOwned>(text: String) -> rusqlite::Result<T> {
        serde_json::from_str(&text).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, error.into())
        })
    }
    let baseline: Option<String> = row.get(6)?;
    let outcome: Option<String> = row.get(9)?;
    Ok(Receipt {
        agent_id: row.get(0)?,
        request_nonce: row.get(1)?,
        request_fingerprint: row.get(2)?,
        state: row.get(3)?,
        claim_owner: row.get(4)?,
        claim_lease_expires_at: row.get(5)?,
        authority_baseline: baseline.map(json).transpose()?.unwrap_or(Value::Null),
        effects: json(row.get(7)?)?,
        action_request_id: row.get(8)?,
        outcome: outcome.map(json).transpose()?,
        refusal_code: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

// A receipt transition and every uncertainty disposition share one transaction.
// A failed disposition therefore leaves the pending receipt available to retry.
fn expire_attempted_receipt(
    conn: &rusqlite::Connection,
    row: &Receipt,
    now: i64,
) -> rusqlite::Result<Option<Receipt>> {
    if row.state != "pending"
        || !row
            .claim_lease_expires_at
            .is_some_and(|expiry| expiry <= now)
        || !has_uncertain_effect(row)
    {
        return Ok(None);
    }
    conn.execute_batch("SAVEPOINT github_unknown")?;
    let tx = conn;
    let changed = tx.execute(
        "UPDATE github_bot_receipt SET state='outcome_unknown', outcome=?4,
         claim_owner=NULL, claim_lease_expires_at=?3, updated_at=?3
         WHERE agent_id=?1 AND request_nonce=?2 AND state='pending'
         AND claim_lease_expires_at<=?3
         AND EXISTS (SELECT 1 FROM json_each(effects)
           WHERE json_type(value,'$.dispatch_attempted_at')='integer'
           AND json_type(value,'$.outcome')='null')",
        params![
            row.agent_id,
            row.request_nonce,
            now,
            serde_json::json!({"status":"outcome_unknown"}).to_string()
        ],
    )?;
    if changed == 0 {
        tx.execute_batch("RELEASE github_unknown")?;
        return Ok(None);
    }
    let handle = row.authority_baseline["app_handle_id"]
        .as_str()
        .unwrap_or("");
    // Receipts claimed before the baseline recorded its caller were all AFT's.
    let acting = row.authority_baseline["caller_principal"]
        .as_str()
        .unwrap_or(crate::github::AFT_PRINCIPAL);
    let (principal, connection_id): (String, String) = tx.query_row(
        "SELECT connection_principal,connection_id FROM github_app_handle WHERE app_handle_id=?1",
        [handle], |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional()?.unwrap_or_else(|| {
        eprintln!(error governance: "attempted GitHub effect has no surviving handle row");
        (crate::github::AFT_PRINCIPAL.into(), String::new())
    });
    for (index, effect) in
        row.effects.iter().enumerate().filter(|(_, effect)| {
            effect.dispatch_attempted_at.is_some() && effect.outcome.is_none()
        })
    {
        let fallback = format!(
            "missing-github-effect-{}-{}-{index}",
            row.agent_id, row.request_nonce
        );
        let request_id = effect.request_id.as_deref().unwrap_or_else(|| {
            eprintln!(error governance: "attempted GitHub effect has no request_id");
            &fallback
        });
        let has_class: Option<Option<String>> = tx.query_row(
            "SELECT reconciliation_json FROM catalog_actions WHERE principal=?1 AND connection_id=?2 AND name=?3",
            params![principal, connection_id, effect.effect], |r| r.get(0),
        ).optional()?;
        tx.execute(
            "INSERT INTO write_reconciliation_results
            (principal,request_id,acting_principal,connection_id,action,status,reason,updated_at_ms)
            VALUES (?1,?2,?7,?3,?4,'unreconcilable',?5,?6)
            ON CONFLICT(principal,request_id) DO NOTHING",
            params![
                principal,
                request_id,
                connection_id,
                effect.effect,
                if has_class.flatten().is_some() {
                    "reconciliation_args_unavailable"
                } else {
                    "reconciliation_class_missing"
                },
                now,
                acting
            ],
        )?;
    }
    tx.execute_batch("RELEASE github_unknown")?;
    let mut unknown = row.clone();
    unknown.state = "outcome_unknown".into();
    unknown.outcome = Some(serde_json::json!({"status":"outcome_unknown"}));
    unknown.claim_owner = None;
    unknown.claim_lease_expires_at = Some(now);
    unknown.updated_at = now;
    Ok(Some(unknown))
}

const RECEIPT_COLUMNS: &str = "agent_id, request_nonce, request_fingerprint, state, claim_owner,
    claim_lease_expires_at, authority_baseline, effects, action_request_id, outcome,
    refusal_code, created_at, updated_at";

impl PlexusStore {
    pub fn github_receipt(&self, agent: &str, nonce: &str) -> Result<Option<Receipt>, StoreError> {
        self.inner.with_read(|conn| conn.query_row(
            &format!("SELECT {RECEIPT_COLUMNS} FROM github_bot_receipt WHERE agent_id=?1 AND request_nonce=?2"),
            params![agent, nonce], receipt_row,
        ).optional())
    }

    /// Atomic insert-or-return. Only an expired, unattempted claim may rotate.
    #[allow(clippy::too_many_arguments)] // Claim identity, lease and baseline must share one transaction.
    #[cfg(any(test, feature = "test-support"))]
    pub fn claim_github_receipt(
        &self,
        agent: &str,
        nonce: &str,
        fingerprint: &str,
        owner: &str,
        baseline: &Value,
        effects: &[Effect],
        approval_id: Option<&str>,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Claim, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let existing = conn.query_row(
                &format!("SELECT {RECEIPT_COLUMNS} FROM github_bot_receipt WHERE agent_id=?1 AND request_nonce=?2"),
                params![agent, nonce], receipt_row,
            ).optional()?;
            if let Some(row) = existing {
                if row.request_fingerprint != fingerprint { return Ok(Claim::PayloadMismatch); }
                if row.state == "completed" || row.state == "refused" { return Ok(Claim::Replay(row)); }
                if row.state == "outcome_unknown" { return Ok(Claim::Unknown(row)); }
                if row.state == "pending_approval" { return Ok(Claim::PendingApproval(row)); }
                if row.claim_lease_expires_at.is_some_and(|expiry| expiry > now) { return Ok(Claim::InFlight); }
                if let Some(unknown) = expire_attempted_receipt(conn, &row, now)? {
                    return Ok(Claim::Unknown(unknown));
                }
                let expiry = lease_expires_at(row.created_at, now, lease_seconds);
                conn.execute("UPDATE github_bot_receipt SET claim_owner=?3, claim_lease_expires_at=?4,
                    authority_baseline=?5, updated_at=?6 WHERE agent_id=?1 AND request_nonce=?2
                    AND state='pending' AND (claim_lease_expires_at IS NULL OR claim_lease_expires_at<=?6)",
                    params![agent, nonce, owner, expiry, baseline.to_string(), now])?;
                return Ok(Claim::Owned(Receipt { claim_owner: Some(owner.into()),
                    claim_lease_expires_at: Some(expiry), authority_baseline: baseline.clone(), updated_at: now, ..row }));
            }
            let expiry = lease_expires_at(now, now, lease_seconds);
            let state = if approval_id.is_some() { "pending_approval" } else { "pending" };
            let effects_json = serde_json::to_string(effects).map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
            conn.execute("INSERT INTO github_bot_receipt (agent_id,request_nonce,request_fingerprint,state,
                claim_owner,claim_lease_expires_at,authority_baseline,effects,action_request_id,created_at,updated_at)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",
                params![agent, nonce, fingerprint, state, owner, expiry, baseline.to_string(), effects_json, approval_id, now])?;
            let row = conn.query_row(&format!("SELECT {RECEIPT_COLUMNS} FROM github_bot_receipt WHERE agent_id=?1 AND request_nonce=?2"),
                params![agent, nonce], receipt_row)?;
            Ok(if approval_id.is_some() { Claim::PendingApproval(row) } else { Claim::Owned(row) })
        })
    }

    /// The committed marker is the last operation before transport dispatch.
    /// A resumed worker with an obsolete owner cannot mark or transmit.
    pub fn mark_github_dispatch(
        &self,
        agent: &str,
        nonce: &str,
        owner: &str,
        index: usize,
        now: i64,
        request_id: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute("UPDATE github_bot_receipt SET
                effects=json_set(effects, '$[' || ?4 || '].dispatch_attempted_at', ?5,
                    '$[' || ?4 || '].request_id', ?6), updated_at=?5
                WHERE agent_id=?1 AND request_nonce=?2 AND claim_owner=?3 AND state='pending'
                AND claim_lease_expires_at>?5 AND json_type(effects, '$[' || ?4 || '].effect')='text'
                AND json_type(effects, '$[' || ?4 || '].dispatch_attempted_at')='null'",
                params![agent, nonce, owner, index as i64, now, request_id])?;
            Ok(changed == 1)
        })
    }

    /// Undo `mark_github_dispatch` when the marked send never happened: the
    /// handle credential could not be prepared after the marker was written.
    /// Left in place, the marker would claim a GitHub write may have occurred,
    /// which blocks `release_github_claim` and makes a lease takeover record
    /// `outcome_unknown` for a request that never left plexus. Only the
    /// current owner can clear it, and only for the request that set it.
    pub(crate) fn clear_github_dispatch(
        &self,
        agent: &str,
        nonce: &str,
        owner: &str,
        index: usize,
        request_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            Ok(conn.execute(
                "UPDATE github_bot_receipt SET
            effects=json_set(effects, '$[' || ?4 || '].dispatch_attempted_at', json('null'),
                '$[' || ?4 || '].request_id', json('null')), updated_at=?6
            WHERE agent_id=?1 AND request_nonce=?2 AND claim_owner=?3 AND state='pending'
            AND json_extract(effects, '$[' || ?4 || '].request_id')=?5
            AND json_type(effects, '$[' || ?4 || '].outcome')='null'",
                params![agent, nonce, owner, index as i64, request_id, now],
            )? == 1)
        })
    }

    /// Record one write's GitHub response on its effect. A JSON `null` in an
    /// effect's `outcome` means "no outcome recorded", which every reader
    /// treats as a write in doubt. A success with no body (such as a 204) is
    /// therefore recorded as an empty object, so it reads back as settled.
    pub fn finish_github_effect(
        &self,
        agent: &str,
        nonce: &str,
        owner: &str,
        index: usize,
        outcome: &Value,
        now: i64,
    ) -> Result<bool, StoreError> {
        let recorded = if outcome.is_null() {
            Value::Object(serde_json::Map::new())
        } else {
            outcome.clone()
        };
        self.inner.with_conn_fenced(|conn| {
            Ok(conn.execute(
                "UPDATE github_bot_receipt SET
            effects=json_set(effects, '$[' || ?4 || '].outcome', json(?5)), updated_at=?6
            WHERE agent_id=?1 AND request_nonce=?2 AND claim_owner=?3 AND state='pending'
            AND json_type(effects, '$[' || ?4 || '].dispatch_attempted_at')='integer'
            AND json_type(effects, '$[' || ?4 || '].outcome')='null'",
                params![agent, nonce, owner, index as i64, recorded.to_string(), now],
            )? == 1)
        })
    }

    /// Authorization refusals and store failures before dispatch do not permanently
    /// record an outcome; releasing the claim lets a fresh retry re-evaluate.
    #[cfg(any(test, feature = "test-support"))]
    pub fn release_github_claim(
        &self,
        agent: &str,
        nonce: &str,
        owner: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| Ok(conn.execute("UPDATE github_bot_receipt SET
            claim_owner=NULL, claim_lease_expires_at=?4, updated_at=?4
            WHERE agent_id=?1 AND request_nonce=?2 AND claim_owner=?3 AND state='pending'
            AND NOT EXISTS (SELECT 1 FROM json_each(effects) WHERE json_type(value,'$.dispatch_attempted_at')='integer')",
            params![agent, nonce, owner, now])? == 1))
    }

    /// Release the claim of a receipt some of whose writes may already have
    /// been sent, so a retry can resume from the first unsent one. Allowed only
    /// while every write that was attempted has a recorded outcome: a write in
    /// doubt must never be sent again, so such a receipt keeps its claim.
    pub fn release_github_claim_between_legs(
        &self,
        agent: &str,
        nonce: &str,
        owner: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| Ok(conn.execute("UPDATE github_bot_receipt SET
            claim_owner=NULL, claim_lease_expires_at=NULL, updated_at=?4
            WHERE agent_id=?1 AND request_nonce=?2 AND claim_owner=?3 AND state='pending'
            AND NOT EXISTS (SELECT 1 FROM json_each(effects) WHERE json_type(value,'$.dispatch_attempted_at')='integer'
                AND json_type(value,'$.outcome')='null')",
            params![agent, nonce, owner, now])? == 1))
    }

    /// Commit the refusal and approval consumption in the same transaction. An
    /// uncertain write never comes here: its approval stays approved.
    #[allow(clippy::too_many_arguments)]
    pub fn finish_github_facade(
        &self,
        agent: &str,
        nonce: &str,
        owner: &str,
        state: &str,
        outcome: &Value,
        refusal_code: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        if !matches!(state, "completed" | "refused") {
            return Ok(false);
        }
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE github_bot_receipt SET state=?4,outcome=?5,
                refusal_code=?6,updated_at=?7,claim_owner=NULL,claim_lease_expires_at=?7
                WHERE agent_id=?1 AND request_nonce=?2 AND claim_owner=?3 AND state='pending'",
                params![
                    agent,
                    nonce,
                    owner,
                    state,
                    outcome.to_string(),
                    refusal_code,
                    now
                ],
            )?;
            if changed == 1 {
                conn.execute(
                    "UPDATE action_requests SET status='consumed'
                    WHERE request_id=(SELECT action_request_id FROM github_bot_receipt
                        WHERE agent_id=?1 AND request_nonce=?2)
                    AND agent_id=?1 AND status='approved'",
                    params![agent, nonce],
                )?;
            }
            Ok(changed == 1)
        })
    }

    /// Once a transport may have sent a write, retries must never re-transmit it.
    pub fn mark_github_outcome_unknown(
        &self,
        agent: &str,
        nonce: &str,
        owner: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            Ok(conn.execute(
                "UPDATE github_bot_receipt SET state='outcome_unknown',outcome=?4,
                claim_owner=NULL,claim_lease_expires_at=?5,updated_at=?5
             WHERE agent_id=?1 AND request_nonce=?2 AND claim_owner=?3 AND state='pending'",
                params![
                    agent,
                    nonce,
                    owner,
                    serde_json::json!({"status":"outcome_unknown"}).to_string(),
                    now
                ],
            )? == 1)
        })
    }

    /// Retry and sweep use the same durable transition for an expired attempted
    /// receipt. If another update changes it first, do not record a second disposition.
    fn expire_github_attempted_receipt(
        &self,
        agent: &str,
        nonce: &str,
        now: i64,
    ) -> Result<Option<Receipt>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let row: Option<Receipt> = conn.query_row(
                &format!("SELECT {RECEIPT_COLUMNS} FROM github_bot_receipt WHERE agent_id=?1 AND request_nonce=?2"),
                params![agent, nonce], receipt_row,
            ).optional()?;
            let Some(row) = row else { return Ok(None); };
            Ok(expire_attempted_receipt(conn, &row, now)?.or(Some(row)))
        })
    }

    /// One bounded tick handles uncertainty before applying receipt retention.
    /// Unsettled rows retain their retry evidence for thirty days after the
    /// later of their last update and claim lease; approvals are not consumed.
    pub fn sweep_github_receipts(&self, now: i64, batch: i64) -> Result<Vec<Receipt>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let mut statement = conn.prepare(&pending_receipts_query())?;
            let candidates: Vec<Receipt> = statement
                .query_map(params![now, batch], receipt_row)?
                .collect::<rusqlite::Result<_>>()?;
            drop(statement);
            let mut changed = Vec::new();
            for row in candidates {
                if let Some(unknown) = expire_attempted_receipt(conn, &row, now)? {
                    changed.push(unknown);
                }
            }
            conn.execute(
                RECEIPT_RETENTION_DELETE,
                params![now.saturating_sub(RETENTION_MS), now, batch],
            )?;
            conn.execute(
                UNSETTLED_RECEIPT_RETENTION_DELETE,
                params![now.saturating_sub(RETENTION_MS), batch],
            )?;
            Ok(changed)
        })
    }
}

pub(super) fn pending_receipts_query() -> String {
    format!("SELECT {RECEIPT_COLUMNS} FROM github_bot_receipt
        WHERE state='pending' AND claim_lease_expires_at<=?1
        AND EXISTS (SELECT 1 FROM json_each(effects) WHERE json_type(value,'$.dispatch_attempted_at')='integer'
            AND json_type(value,'$.outcome')='null') LIMIT ?2")
}

pub(super) const RECEIPT_RETENTION_DELETE: &str = "DELETE FROM github_bot_receipt WHERE rowid IN
    (SELECT rowid FROM github_bot_receipt WHERE state IN ('completed','refused')
     AND updated_at<=?1 AND (claim_lease_expires_at IS NULL OR claim_lease_expires_at<=?2)
     LIMIT ?3)";

const UNSETTLED_RECEIPT_RETENTION_DELETE: &str = "DELETE FROM github_bot_receipt WHERE rowid IN
    (SELECT rowid FROM github_bot_receipt WHERE state IN ('outcome_unknown','pending','pending_approval')
     AND updated_at<=?1 AND COALESCE(claim_lease_expires_at,updated_at)<=?1 LIMIT ?2)";

#[cfg(test)]
impl PlexusStore {
    pub fn drop_github_receipts_for_test(&self) {
        self.inner
            .with_conn(|conn| conn.execute_batch("DROP TABLE github_bot_receipt"))
            .unwrap();
    }
}

impl PlexusStore {
    pub fn github_repo_binding_generation(&self) -> Result<i64, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT generation FROM github_repo_binding_generation WHERE singleton=1",
                [],
                |row| row.get(0),
            )
        })
    }

    /// Facade refusals are recorded separately from inner catalog reservations.
    pub fn audit_github_facade(
        &self,
        reply: &crate::github::facade::gates::GateReply,
    ) -> Result<(), StoreError> {
        let scope = reply.scope.as_ref();
        self.inner.with_conn_fenced(|conn| {
            // The stamp names an agent, not a claimed bot login. Keep the
            // additive agent_handle column NULL on facade ingress audit rows.
            conn.execute("INSERT INTO audit_journal (ts,principal,actor,acting_principal,agent_id,app_handle_id,
                action,request_id,decision,reason_code,gate,idempotency_key_fingerprint,agent_handle,
                scope_owner,scope_ref,scope_epoch,scope_kind,scope_parent,scope_parent_state,
                scope_delegates,scope_owner_authorized,scope_flow_id)
                VALUES (?1,?10,?10,?10,?2,?3,?4,?5,?6,?7,?8,?9,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
                params![now_ms(), reply.claimed_agent_id, reply.app_handle_id, reply.action,
                    reply.request_id, if reply.refusal_code.is_some() {"deny"} else {"allow"},
                    reply.refusal_code.as_deref().unwrap_or("allowed"), reply.gate,
                    reply.mapped.as_ref().map(|mapped| mapped.fingerprint.as_str()),
                    reply.caller_principal, Option::<String>::None,
                    scope.map(|scope| scope.owner.as_str()),
                    scope.map(|scope| scope.scope_ref.as_str()),
                    scope.map(|scope| scope.scope_epoch as i64),
                    scope.and_then(|scope| scope.kind.as_deref()),
                    scope.and_then(|scope| scope.parent.as_deref()),
                    scope.and_then(|scope| scope.parent_state.as_deref()),
                    scope.map(|scope| scope.delegates),
                    scope.map(|scope| scope.owner_authorized),
                    scope.and_then(|scope| scope.flow_id.as_deref())])?;
            Ok(())
        })
    }
}

impl crate::github::facade::gates::GateStore for PlexusStore {
    fn handle(&self, id: &str) -> Result<Option<crate::github::facade::gates::Handle>, String> {
        self.inner
            .with_read(|conn| {
                conn.query_row(
            "SELECT app_handle_id,agent_id,connection_id,connection_principal,status,proven_at,credential_reference
             FROM github_app_handle WHERE app_handle_id=?1", [id], |row| {
                Ok(crate::github::facade::gates::Handle {
                    app_handle_id: row.get(0)?, agent_id: row.get(1)?, connection_id: row.get(2)?,
                    connection_principal: row.get(3)?, status: row.get(4)?,
                    proven: row.get::<_, Option<i64>>(5)?.is_some(),
                    credential_reference: row.get(6)?,
                })
            }).optional()
            })
            .map_err(|_| "store_failure".into())
    }

    fn handle_for_agent(
        &self,
        agent: &str,
    ) -> Result<Option<crate::github::facade::gates::Handle>, String> {
        // `agent_id` is unique on github_app_handle, so this is the one bot
        // bound to the agent, if it has one.
        let id: Option<String> = self
            .inner
            .with_read(|conn| {
                conn.query_row(
                    "SELECT app_handle_id FROM github_app_handle WHERE agent_id=?1",
                    [agent],
                    |row| row.get(0),
                )
                .optional()
            })
            .map_err(|_| String::from("store_failure"))?;
        match id {
            Some(id) => crate::github::facade::gates::GateStore::handle(self, &id),
            None => Ok(None),
        }
    }

    fn binding(
        &self,
        repository: &str,
    ) -> Result<Option<(crate::github::resolver::Binding, String)>, String> {
        let repository = crate::github::canonical_repository(repository);
        self.inner
            .with_read(|conn| {
                conn.query_row(
                    "SELECT h.app_handle_id,h.connection_id,h.agent_id FROM github_repo_binding b
             JOIN github_app_handle h ON h.app_handle_id=b.app_handle_id WHERE b.repository=?1",
                    [&repository],
                    |row| {
                        Ok((
                            crate::github::resolver::Binding {
                                app_handle_id: row.get(0)?,
                                connection_id: row.get(1)?,
                            },
                            row.get(2)?,
                        ))
                    },
                )
                .optional()
            })
            .map_err(|_| "store_failure".into())
    }

    fn grant_cause(
        &self,
        handle: &crate::github::facade::gates::Handle,
        caller: &str,
        agent: &str,
        mapped: &crate::github::facade::request_map::MappedRequest,
        layer: crate::grant_refusal::Layer,
    ) -> crate::grant_refusal::Cause {
        use crate::governance::{scoped_grant, scoped_grant_refusal, GrantDenial};
        use crate::grant_refusal::{Cause, Layer};
        let Ok(Some(connection)) =
            self.connection(&handle.connection_principal, &handle.connection_id)
        else {
            return Cause::Missing;
        };
        let Ok(rows) = self.scoped_invoke_grant_rows(&connection, caller, Some(agent)) else {
            return Cause::Missing;
        };
        let grant = scoped_grant(
            &rows,
            &connection,
            caller,
            if layer == Layer::Agent {
                Some(agent)
            } else {
                None
            },
            "invoke",
            mapped.action,
            now_ms(),
            None,
        );
        let risk = self
            .catalog_action(
                &connection.principal,
                &connection.connection_id,
                mapped.action,
            )
            .ok()
            .flatten()
            .map(|action| action.risk)
            .unwrap_or_else(|| "read".into());
        match scoped_grant_refusal(grant.as_ref(), mapped.action, &risk, now_ms()) {
            Some(GrantDenial::Expired) => Cause::Expired,
            Some(GrantDenial::ActionSelector) => Cause::ActionSelector,
            Some(GrantDenial::RiskCeiling) => Cause::RiskCeiling,
            _ => Cause::Missing,
        }
    }

    fn authority(
        &self,
        handle: &crate::github::facade::gates::Handle,
        caller: &str,
        agent: &str,
        mapped: &crate::github::facade::request_map::MappedRequest,
        repository: &str,
    ) -> Result<crate::github::facade::gates::Authority, String> {
        use crate::governance::{compose_policy_effect, GovernanceSeams};
        let connection = self
            .connection(&handle.connection_principal, &handle.connection_id)
            .map_err(|_| "store_failure")?
            .ok_or("module_grant_absent")?;
        let request = AuthorizationRequest::new(
            caller,
            &handle.connection_id,
            mapped.action,
            mapped.args.clone(),
        )
        .with_bound_agent(agent, &handle.app_handle_id);
        let seams = GithubGovernanceSeams {
            store: self,
            credential_provider: None,
        };
        let rows = seams
            .grant_rows(&connection, &request)
            .map_err(|_| "store_failure")?;
        use crate::governance::{grant_key_matches, AgentGrantKey};
        let selector = |row: &ScopedGrantRow, sought_agent: Option<&str>| {
            grant_key_matches(
                &AgentGrantKey {
                    connection_id: &row.grant.connection_id,
                    principal: &row.grant.grantee_principal,
                    agent_id: row.agent_id.as_deref(),
                },
                &AgentGrantKey {
                    connection_id: &handle.connection_id,
                    principal: caller,
                    agent_id: sought_agent,
                },
            )
        };
        let module_grant = rows
            .iter()
            .any(|row| selector(row, None) && row.grant.authorizes(mapped.action, now_ms()));
        let agent_grant = rows.iter().any(|row| selector(row, Some(agent)));
        // The 1:1 agent-to-handle row and repository binding carry repository scope.
        // The agent grant's selectors narrow the request-kind dimension on that handle.
        let pair_allowed = rows
            .iter()
            .any(|row| selector(row, Some(agent)) && row.grant.authorizes(mapped.action, now_ms()));
        let action = self
            .catalog_action(
                &handle.connection_principal,
                &handle.connection_id,
                mapped.action,
            )
            .map_err(|_| "store_failure")?
            .ok_or("request_kind_unmapped")?;
        let policies = seams
            .policy_inputs(&connection, agent, &action)
            .map_err(|_| "store_failure")?;
        let module_policy = policies.module_effect.clone();
        let module_effect = policies.module_effect.unwrap_or_else(|| {
            if action.ask_first {
                "ask_first"
            } else {
                "allow"
            }
            .into()
        });
        let row = seams
            .handle_row(&connection)
            .map_err(|_| "store_failure")?
            .ok_or("store_failure")?;
        let (agent_grant_generation, module_grant_generation) = seams
            .grant_generations(&connection, caller, agent, mapped.action)
            .map_err(|_| "store_failure")?;
        let policy_effect_hash = crate::governance::policy_effect_hash(
            module_policy.as_deref(),
            policies.agent_effect.as_deref(),
            action.ask_first,
        )
        .map_err(|_| "store_failure")?;
        let baseline = serde_json::json!({
            "app_handle_id": handle.app_handle_id, "repository": repository,
            // Recorded so an uncertain write's reconciliation row names the
            // module that claimed the receipt. Not an authority dimension.
            "caller_principal": caller,
            "app_handle_generation": row.app_handle_generation,
            "repo_binding_generation": row.repo_binding_generation,
            "credential_generation": row.credential_generation,
            "handle_enabled": row.enabled,
            "agent_grant_generation": agent_grant_generation,
            "module_grant_generation": module_grant_generation,
            "policy_effect_hash": policy_effect_hash,
            "module_effect": module_effect, "agent_effect": policies.agent_effect,
            "composed_effect": compose_policy_effect(&module_effect, policies.agent_effect.as_deref()),
        });
        Ok(crate::github::facade::gates::Authority {
            module_grant,
            agent_grant,
            pair_allowed,
            module_effect,
            agent_effect: policies.agent_effect,
            baseline,
        })
    }

    fn receipt(&self, agent: &str, nonce: &str) -> Result<Option<Receipt>, String> {
        self.expire_github_attempted_receipt(agent, nonce, now_ms())
            .map_err(|_| "store_failure".into())
    }

    fn claim(
        &self,
        agent: &str,
        nonce: &str,
        mapped: &crate::github::facade::request_map::MappedRequest,
        handle: &crate::github::facade::gates::Handle,
        owner: &str,
        baseline: &Value,
        effects: &[Effect],
        ask_first: bool,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Claim, String> {
        self.claim_github_facade(
            agent,
            nonce,
            mapped,
            handle,
            owner,
            baseline,
            effects,
            ask_first,
            now,
            lease_seconds,
        )
        .map_err(|error| {
            eprintln!(warn storage: "GitHub receipt claim failed: {error}");
            "store_failure".to_string()
        })
    }
}

impl PlexusStore {
    /// Claim and approval adoption share one SQLite write fence. A competing
    /// first caller observes the receipt, never creates a second approval.
    #[allow(clippy::too_many_arguments)]
    pub fn claim_github_facade(
        &self,
        agent: &str,
        nonce: &str,
        mapped: &crate::github::facade::request_map::MappedRequest,
        handle: &crate::github::facade::gates::Handle,
        owner: &str,
        baseline: &Value,
        effects: &[Effect],
        ask_first: bool,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Claim, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let load = |conn: &rusqlite::Connection| conn.query_row(
                &format!("SELECT {RECEIPT_COLUMNS} FROM github_bot_receipt WHERE agent_id=?1 AND request_nonce=?2"),
                params![agent, nonce], receipt_row).optional();
            let existing = load(conn)?;
            if let Some(row) = &existing {
                if row.request_fingerprint != mapped.fingerprint { return Ok(Claim::PayloadMismatch); }
                if let Some(outcome) = crate::github::facade::vendor_band::recover_completed(row, &mapped.request_kind) {
                    conn.execute("UPDATE github_bot_receipt SET state='completed',outcome=?3,claim_owner=NULL,claim_lease_expires_at=NULL,updated_at=?4 WHERE agent_id=?1 AND request_nonce=?2",
                        params![agent, nonce, outcome.to_string(), now])?;
                    return Ok(Claim::Replay(load(conn)?.expect("completed receipt")));
                }
                if ["completed", "refused"].contains(&row.state.as_str()) { return Ok(Claim::Replay(row.clone())); }
                if row.state == "outcome_unknown" || has_uncertain_effect(row) {
                    return Ok(Claim::Unknown(row.clone()));
                }
                if row.state == "pending" && row.claim_lease_expires_at.is_some_and(|expiry| expiry > now) {
                    return Ok(Claim::InFlight);
                }
                if row.state == "pending_approval" {
                    let (status, expires_at): (String, i64) = conn.query_row(
                        "SELECT status,expires_at FROM action_requests WHERE principal=?1 AND request_id=?2",
                        params![handle.connection_principal, row.action_request_id],
                        |row| Ok((row.get(0)?, row.get(1)?)))?;
                    let refusal = if expires_at <= now || status == "expired" { Some("approval_expired") }
                        else if status == "denied" { Some("approval_denied") } else { None };
                    if let Some(code) = refusal {
                        conn.execute("UPDATE github_bot_receipt SET state='refused',refusal_code=?3,
                            outcome=?4,updated_at=?5 WHERE agent_id=?1 AND request_nonce=?2",
                            params![agent, nonce, code, serde_json::json!({"status":"refused","refusal_code":code, "retry_same_nonce":false}).to_string(), now])?;
                        return Ok(Claim::Replay(load(conn)?.expect("updated receipt")));
                    }
                    if status != "approved" { return Ok(Claim::PendingApproval(row.clone())); }
                    let expiry = lease_expires_at(row.created_at, now, lease_seconds);
                    conn.execute("UPDATE github_bot_receipt SET state='pending', claim_owner=?3,
                        claim_lease_expires_at=?4, authority_baseline=?5, updated_at=?6
                        WHERE agent_id=?1 AND request_nonce=?2 AND state='pending_approval'",
                        params![agent, nonce, owner, expiry, baseline.to_string(), now])?;
                    return Ok(Claim::Owned(load(conn)?.expect("claimed receipt")));
                }
                let expiry = lease_expires_at(row.created_at, now, lease_seconds);
                conn.execute("UPDATE github_bot_receipt SET claim_owner=?3,claim_lease_expires_at=?4,
                    authority_baseline=?5,updated_at=?6 WHERE agent_id=?1 AND request_nonce=?2
                    AND state='pending' AND (claim_lease_expires_at IS NULL OR claim_lease_expires_at<=?6)",
                    params![agent, nonce, owner, expiry, baseline.to_string(), now])?;
                return Ok(Claim::Owned(load(conn)?.expect("reclaimed receipt")));
            }
            let approval = if ask_first {
                let schema_hash: String = conn.query_row(
                    "SELECT schema_hash FROM catalog_actions WHERE principal=?1 AND connection_id=?2 AND name=?3",
                    params![handle.connection_principal, handle.connection_id, mapped.action], |row| row.get(0))?;
                let mut candidates = Vec::new();
                if let Some(id) = mapped.approval_id.as_deref() {
                    let row = conn.query_row("SELECT request_id,agent_id,status,args_snapshot FROM action_requests
                        WHERE principal=?1 AND connection_id=?2 AND request_id=?3 AND action=?4
                        AND args_hash=?5 AND schema_hash=?6",
                        params![handle.connection_principal, handle.connection_id, id, mapped.action, mapped.fingerprint, schema_hash],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?))).optional()?;
                    candidates.extend(row);
                } else {
                    let mut statement = conn.prepare("SELECT request_id,agent_id,status,args_snapshot FROM action_requests WHERE principal=?1 AND connection_id=?2
                        AND action=?3 AND args_hash=?4 AND schema_hash=?5 AND status IN ('pending','approved')
                        AND expires_at>?6 AND (agent_id IS NULL OR agent_id<>?7 OR NOT EXISTS (
                            SELECT 1 FROM github_bot_receipt WHERE action_request_id=action_requests.request_id))
                        ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END,created_at_ms")?;
                    let rows = statement.query_map(params![handle.connection_principal, handle.connection_id, mapped.action, mapped.fingerprint, schema_hash, now, agent],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)))?;
                    for row in rows { candidates.push(row?); }
                }
                let mut matched = None;
                for (id, holder, status, snapshot) in candidates {
                    let args: Value = serde_json::from_str(&snapshot).map_err(|err| rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, err.into()))?;
                    if args == mapped.canonical {
                        matched = Some((id, holder, status));
                        break;
                    }
                }
                if let Some((id, holder, status)) = matched {
                    let associated: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM github_bot_receipt
                        WHERE action_request_id=?1 AND (agent_id<>?2 OR request_nonce<>?3))",
                        params![id, agent, nonce], |row| row.get(0))?;
                    let refusal = if holder.as_deref() != Some(agent) { Some("approval_agent_mismatch") }
                        else if associated || !matches!(status.as_str(), "pending" | "approved") { Some("approval_denied") }
                        else { None };
                    if let Some(code) = refusal {
                        conn.execute("INSERT INTO github_bot_receipt (agent_id,request_nonce,request_fingerprint,state,
                            claim_owner,claim_lease_expires_at,authority_baseline,effects,refusal_code,outcome,created_at,updated_at)
                            VALUES (?1,?2,?3,'refused',NULL,?4,?5,?6,?7,?8,?9,?9)",
                            params![agent, nonce, mapped.fingerprint, now, baseline.to_string(),
                                serde_json::to_string(effects).map_err(|err| rusqlite::Error::ToSqlConversionFailure(err.into()))?,
                                code, serde_json::json!({"status":"refused","refusal_code":code, "retry_same_nonce":false}).to_string(), now])?;
                        return Ok(Claim::Replay(load(conn)?.expect("refused receipt")));
                    }
                    id
                } else if mapped.approval_id.is_some() {
                    conn.execute("INSERT INTO github_bot_receipt (agent_id,request_nonce,request_fingerprint,state,
                        claim_owner,claim_lease_expires_at,authority_baseline,effects,refusal_code,outcome,created_at,updated_at)
                        VALUES (?1,?2,?3,'refused',NULL,?4,?5,?6,'approval_denied',?7,?8,?8)",
                        params![agent, nonce, mapped.fingerprint, now, baseline.to_string(),
                            serde_json::to_string(effects).map_err(|err| rusqlite::Error::ToSqlConversionFailure(err.into()))?,
                            serde_json::json!({"status":"refused","refusal_code":"approval_denied", "retry_same_nonce":false}).to_string(), now])?;
                    return Ok(Claim::Replay(load(conn)?.expect("refused receipt")));
                } else {
                    // A fresh id per approval: a nonce can be reused once its
                    // receipt has aged out, and the approval rows outlive
                    // receipts, so an id derived from the agent and nonce
                    // alone would collide with the earlier approval.
                    let id = format!("gh-{}", crate::jcs::jcs_sha256(&serde_json::json!([agent, nonce, crate::storage::new_id("approval")]))
                        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(err.into()))?);
                    // The requester is the module that carried the request,
                    // which the authority baseline records.
                    let requester = baseline["caller_principal"]
                        .as_str()
                        .unwrap_or(crate::github::AFT_PRINCIPAL);
                    conn.execute("INSERT INTO action_requests (request_id,principal,connection_id,action,args_snapshot,
                        args_hash,schema_hash,requester,status,expires_at,created_at_ms,agent_id)
                        VALUES (?1,?2,?3,?4,?5,?6,?7,?11,'pending',?8,?9,?10)",
                        params![id, handle.connection_principal, handle.connection_id, mapped.action,
                            mapped.canonical.to_string(), mapped.fingerprint, schema_hash, now.saturating_add(300_000), now, agent,
                            requester])?;
                    id
                }
            } else { String::new() };
            let expiry = lease_expires_at(now, now, lease_seconds);
            conn.execute("INSERT INTO github_bot_receipt (agent_id,request_nonce,request_fingerprint,state,
                claim_owner,claim_lease_expires_at,authority_baseline,effects,action_request_id,created_at,updated_at)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",
                params![agent, nonce, mapped.fingerprint, if ask_first {"pending_approval"} else {"pending"},
                    owner, expiry, baseline.to_string(),
                    serde_json::to_string(effects).map_err(|err| rusqlite::Error::ToSqlConversionFailure(err.into()))?,
                    if ask_first {Some(approval.as_str())} else {None}, now])?;
            let row = load(conn)?.expect("inserted receipt");
            Ok(if ask_first {Claim::PendingApproval(row)} else {Claim::Owned(row)})
        })
    }
}

/// An import row carries only repositories reachable with its installation
/// token and agent actions in the operator's imported permissions inventory.
#[derive(Debug, Clone)]
pub struct GithubImportedGrant {
    pub action: String,
    pub repository: String,
    pub provenance: String,
}

#[derive(Debug, Clone)]
pub struct GithubImportRow {
    pub handle: GithubHandle,
    pub repositories: Vec<String>,
    pub grants: Vec<GithubImportedGrant>,
    pub module_actions: Vec<String>,
    pub policies: Vec<GithubImportedPolicy>,
}

/// One imported policy row on the handle connection: module-level (owned by
/// the connection principal) or agent-level (owned by the handle's agent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubImportedPolicy {
    pub agent: bool,
    pub action: String,
    pub effect: String,
}

/// One operator grant of scheduled-poll read authority on an existing handle.
/// The grantee is always the handle connection's own principal: a poll's
/// request names the subscription owner as both the connection owner and the
/// grantee, and enrichment reads only connections that principal owns.
#[derive(Debug, Clone)]
pub struct GithubHandlePollGrant {
    pub app_handle_id: String,
    pub actions: Vec<String>,
    pub dry_run: bool,
}

/// One operator grant of write abilities on an existing handle. `expanded` is
/// `actions` plus every read and leg they imply, and `policy_actions` is the
/// writes among `expanded`; both are computed by the control surface.
#[derive(Debug, Clone)]
pub struct GithubHandleGrant {
    pub app_handle_id: String,
    pub module: String,
    pub actions: Vec<String>,
    pub expanded: Vec<String>,
    pub policy_actions: Vec<String>,
    pub effect: String,
    pub dry_run: bool,
}

/// One operator request to bind more repositories to an existing handle.
/// `installation` is every repository the handle's own installation token can
/// read, listed by the control surface before the transaction opens.
#[derive(Debug, Clone)]
pub struct GithubHandleBind {
    pub app_handle_id: String,
    pub repositories: Vec<String>,
    pub installation: Vec<String>,
    pub dry_run: bool,
}

impl PlexusStore {
    /// Whether this connection was created by a GitHub handle import, so its
    /// credential comes from the handle credential provider rather than a
    /// stored credential binding.
    pub(crate) fn is_github_handle_connection(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT 1 FROM github_app_handle
                     WHERE connection_principal=?1 AND connection_id=?2",
                    params![principal, connection_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .is_some())
        })
    }

    /// An import is all-or-nothing, including connection filters and grants.
    /// Existing handles must be explicitly retired rather than silently replaced.
    #[cfg(any(test, feature = "test-support"))]
    pub fn import_github_handles(&self, rows: &[GithubImportRow]) -> Result<(), StoreError> {
        self.import_github_handles_checked(rows, false)?
            .map_err(StoreError::Backend)
    }

    /// Check repository ownership before any writes in the import transaction,
    /// including previews, so another handle's binding cannot be taken over.
    pub fn import_github_handles_checked(
        &self,
        rows: &[GithubImportRow],
        dry_run: bool,
    ) -> Result<Result<(), String>, StoreError> {
        let refusal = std::sync::Mutex::new(None::<String>);
        let result = self.inner.with_conn_fenced(|conn| {
            let tx = conn;
            let mut planned = std::collections::BTreeMap::new();
            for row in rows {
                let conflict: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM github_app_handle WHERE app_handle_id=?1 OR agent_id=?2 OR credential_reference=?3)
                    OR EXISTS(SELECT 1 FROM connections WHERE principal=?4 AND connection_id=?5)
                    OR EXISTS(SELECT 1 FROM grants WHERE principal=?4 AND grant_id LIKE ?6)",
                    params![row.handle.app_handle_id,row.handle.agent_id,row.handle.credential_reference,row.handle.connection_principal,row.handle.connection_id,
                        format!("github-import:{}:%",row.handle.app_handle_id)], |row| row.get(0))?;
                if conflict {
                    eprintln!(warn storage: "GitHub import conflicts with an existing handle, agent, credential, connection or grant: handle {}, agent {}, connection {}/{}; inspect the existing rows and rerun the preview", row.handle.app_handle_id, row.handle.agent_id, row.handle.connection_principal, row.handle.connection_id);
                    *refusal.lock().unwrap_or_else(|poison| poison.into_inner()) = Some("inventory_handle_invalid".into());
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
                for repository in &row.repositories {
                    let repository = &crate::github::canonical_repository(repository);
                    let current: Option<String> = tx.query_row("SELECT app_handle_id FROM github_repo_binding WHERE repository=?1", [repository], |row| row.get(0)).optional()?;
                    let holder = current.or_else(|| planned.get(repository).cloned());
                    if let Some(other) = holder.filter(|id| *id != row.handle.app_handle_id) {
                        *refusal.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(format!("repository_bound_elsewhere{{repository: {repository}, app_handle_id: {other}}}"));
                        return Err(rusqlite::Error::QueryReturnedNoRows);
                    }
                    planned.insert(repository.clone(), row.handle.app_handle_id.clone());
                }
            }
            if dry_run { return Ok(()); }
            for row in rows {
                let handle = &row.handle;
                // Filled in by rewrite_filters once the bindings exist, so an
                // imported handle gets the same owner-plus-names allowlist and
                // single-owner check as one bound by bind_github_repo.
                let filter = serde_json::json!({"values":{},"write_enabling":[]}).to_string();
                let now = now_ms();
                tx.execute("INSERT INTO connections (principal,connection_id,app_key,status,resource_filters,created_at_ms,updated_at_ms,ceiling_risk,ceiling_selectors)
                    VALUES (?1,?2,'github_rest','active',?3,?4,?4,'write',?5)",
                    params![handle.connection_principal,handle.connection_id,filter,now,
                        serde_json::to_string(&row.module_actions).map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?])?;
                // The ticket-connection seeder reads the reviewed manifest and
                // writes catalog rows on this same fenced connection.
                if super::seed_catalog_from_manifest_on_conn(tx, &handle.connection_principal,
                    &handle.connection_id, "github_rest", super::SeedMode::UpsertAll)? == 0 {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
                tx.execute("INSERT INTO github_app_handle (app_handle_id,agent_id,app_id,installation_id,credential_reference,
                    credential_generation,status,proven_at,connection_principal,connection_id)
                    VALUES (?1,?2,?3,?4,?5,?6,?7,NULL,?8,?9)",
                    params![handle.app_handle_id,handle.agent_id,handle.app_id,handle.installation_id,
                        handle.credential_reference,handle.credential_generation,handle.status,
                        handle.connection_principal,handle.connection_id])?;
                for repository in &row.repositories {
                    tx.execute("INSERT INTO github_repo_binding(repository,app_handle_id) VALUES (?1,?2)",
                        params![crate::github::canonical_repository(repository),handle.app_handle_id])?;
                }
                rewrite_filters(tx, &handle.app_handle_id)?;
                for (suffix, principal, selectors) in [
                    ("aft", crate::github::AFT_PRINCIPAL, row.module_actions.clone()),
                    ("prefrontal", crate::github::PREFRONTAL_PRINCIPAL, crate::github::control::prefrontal_selectors()),
                ] {
                    // Both module grants carry a write: AFT's writes and
                    // prefrontal-core's seen-marker reaction. Each row admits
                    // only the actions its selectors name.
                    tx.execute("INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,expires_at,generation,created_at_ms)
                        VALUES (?1,?2,?3,?4,?5,?6,'invoke',NULL,1,?7)",
                        params![format!("github-import:{}:{suffix}",handle.app_handle_id),handle.connection_principal,
                            handle.connection_id,principal,"write",
                            serde_json::to_string(&selectors).map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?,now])?;
                }
                for (index, grant) in row.grants.iter().enumerate() {
                    tx.execute("INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,expires_at,generation,created_at_ms,agent_id)
                        VALUES (?1,?2,?3,?8,?4,?5,'invoke',NULL,1,?6,?7)",
                        params![format!("github-import:{}:agent:{index}:{}",handle.app_handle_id,grant.provenance),
                            handle.connection_principal,handle.connection_id,
                            if grant.action.starts_with("github.") {"read"} else {"write"},
                            serde_json::json!([grant.action]).to_string(),now,handle.agent_id,
                            crate::github::AFT_PRINCIPAL])?;
                }
                // Module policies are owned by the connection's principal and
                // agent policies by the agent, which is how policy_inputs tells
                // the two apart when it composes them.
                for policy in &row.policies {
                    let (scope, owner) = if policy.agent {
                        ("agent", handle.agent_id.as_str())
                    } else {
                        ("module", handle.connection_principal.as_str())
                    };
                    insert_policy_on_conn(tx, &crate::storage::PolicyInput {
                        policy_id: format!("github-import:{}:{scope}-policy:{}", handle.app_handle_id, policy.action),
                        principal: owner.to_owned(),
                        connection_id: handle.connection_id.clone(),
                        action_selector: policy.action.clone(),
                        effect: policy.effect.clone(),
                        expires_at: None,
                    })?;
                }
            }
            Ok(())
        });
        match result {
            Ok(()) => Ok(Ok(())),
            Err(error) => match refusal
                .into_inner()
                .unwrap_or_else(|poison| poison.into_inner())
            {
                Some(code) => Ok(Err(code)),
                None => Err(error),
            },
        }
    }

    /// Add abilities to one imported handle in a single transaction: widen the
    /// handle connection's ceiling by exactly `grant.expanded`, give the handle's
    /// agent a grant row per missing action, extend (or add) the carrying
    /// module's grant, and write `grant.effect` policies for
    /// `grant.policy_actions` at the module and agent levels.
    ///
    /// The returned plan is computed from the same reads whether or not it is
    /// applied, so a dry run shows exactly what the apply would write. The inner
    /// `Err` is a named refusal; nothing is written when one is returned.
    ///
    /// Rows are written the way [`Self::import_github_handles`] writes them: new
    /// grant rows start at generation 1, module policies are owned by the
    /// connection principal and agent policies by the agent. An extended module
    /// grant keeps its generation, because the facade reads a changed grant
    /// generation on an in-flight receipt as a revocation, and adding actions
    /// revokes nothing.
    pub fn grant_github_handle(
        &self,
        grant: &GithubHandleGrant,
    ) -> Result<Result<Value, String>, StoreError> {
        let refusal = std::sync::Mutex::new(None::<String>);
        let result = self
            .inner
            .with_conn_fenced(|tx| Self::grant_github_handle_on_conn(tx, grant, &refusal));
        match result {
            Ok(plan) => Ok(Ok(plan)),
            Err(error) => match refusal
                .into_inner()
                .unwrap_or_else(|poison| poison.into_inner())
            {
                Some(code) => Ok(Err(code)),
                None => Err(error),
            },
        }
    }

    fn grant_github_handle_on_conn(
        tx: &rusqlite::Connection,
        grant: &GithubHandleGrant,
        refusal: &std::sync::Mutex<Option<String>>,
    ) -> rusqlite::Result<Value> {
        use serde_json::json;
        let to_json = |value: &Vec<String>| {
            serde_json::to_string(value)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))
        };
        // A refusal rolls the transaction back through an error and leaves
        // its code here for the caller.
        let refuse = |code: String| -> rusqlite::Result<Value> {
            *refusal.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(code);
            Err(rusqlite::Error::QueryReturnedNoRows)
        };
        let handle: Option<(String, String, String, String)> = tx
            .query_row(
                "SELECT agent_id,status,connection_principal,connection_id
                     FROM github_app_handle WHERE app_handle_id=?1",
                [&grant.app_handle_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((agent, status, principal, connection_id)) = handle else {
            return refuse("agent_handle_unknown".into());
        };
        if status != "enabled" {
            return refuse(format!(
                "agent_handle_disabled{{app_handle_id: {}}}",
                grant.app_handle_id
            ));
        }
        let read_ceiling =
            |tx: &rusqlite::Connection| -> rusqlite::Result<Option<(String, Vec<String>)>> {
                let row: Option<(Option<String>, Option<String>)> = tx
                    .query_row(
                        "SELECT ceiling_risk,ceiling_selectors FROM connections
                         WHERE principal=?1 AND connection_id=?2",
                        params![principal, connection_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let Some((Some(risk), Some(selectors))) = row else {
                    return Ok(None);
                };
                let selectors: Vec<String> = serde_json::from_str(&selectors).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        error.into(),
                    )
                })?;
                Ok(Some((risk, selectors)))
            };
        let Some((_, ceiling)) = read_ceiling(tx)? else {
            return refuse(format!(
                "connection_ceiling_absent{{connection_id: {connection_id}}}"
            ));
        };
        let ceiling_is_open = ceiling.iter().any(|selector| selector == "*");
        let ceiling_additions: Vec<String> = if ceiling_is_open {
            Vec::new()
        } else {
            grant
                .expanded
                .iter()
                .filter(|action| !ceiling.contains(action))
                .cloned()
                .collect()
        };
        let now = now_ms();
        // Live invoke grants on the handle connection: (id, grantee, agent, selectors).
        let mut statement = tx.prepare(
            "SELECT grant_id,grantee_principal,agent_id,action_selectors FROM grants
                 WHERE principal=?1 AND connection_id=?2 AND authority_kind='invoke'
                   AND (expires_at IS NULL OR expires_at>?3) ORDER BY grant_id",
        )?;
        let rows = statement
            .query_map(params![principal, connection_id, now], |row| {
                let selectors: String = row.get(3)?;
                let selectors: Vec<String> = serde_json::from_str(&selectors).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        error.into(),
                    )
                })?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    selectors,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let names = |selectors: &[String], action: &str| {
            selectors
                .iter()
                .any(|selector| selector == action || selector == "*")
        };
        let agent_missing: Vec<String> = grant
            .expanded
            .iter()
            .filter(|action| {
                !rows.iter().any(|(_, _, row_agent, selectors)| {
                    row_agent.as_deref() == Some(agent.as_str()) && names(selectors, action)
                })
            })
            .cloned()
            .collect();
        let module_row = rows
            .iter()
            .find(|(_, grantee, row_agent, _)| row_agent.is_none() && grantee == &grant.module);
        let module_added: Vec<String> = grant
            .expanded
            .iter()
            .filter(|action| {
                module_row.is_none_or(|(_, _, _, selectors)| !names(selectors, action))
            })
            .cloned()
            .collect();
        let agent_grant_id =
            |action: &str| format!("github-grant:{}:agent:{action}:{now}", grant.app_handle_id);
        let module_grant_id = module_row.map(|(id, ..)| id.clone()).unwrap_or_else(|| {
            format!(
                "github-grant:{}:module:{}:{now}",
                grant.app_handle_id, grant.module
            )
        });
        let mut grant_plan: Vec<Value> = agent_missing
            .iter()
            .map(|action| {
                json!({"level":"agent","op":"insert","grant_id":agent_grant_id(action),
                    "agent_id":agent,"action":action})
            })
            .collect();
        if !module_added.is_empty() {
            grant_plan.push(json!({"level":"module",
                    "op": if module_row.is_some() {"extend"} else {"insert"},
                    "grant_id":module_grant_id,"grantee_principal":grant.module,"actions":module_added}));
        }
        // (owner, level, action, existing policy id when there is one).
        let mut policy_rows = Vec::new();
        for (level, owner) in [("module", principal.as_str()), ("agent", agent.as_str())] {
            for action in &grant.policy_actions {
                let existing: Option<(String, String, Option<i64>)> = tx
                    .query_row(
                        "SELECT policy_id,effect,expires_at FROM policies
                             WHERE principal=?1 AND connection_id=?2 AND action_selector=?3
                             ORDER BY policy_id LIMIT 1",
                        params![owner, connection_id, action],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                let op = match &existing {
                    None => "insert",
                    Some((_, effect, None)) if effect == &grant.effect => "unchanged",
                    Some(_) => "update",
                };
                policy_rows.push((
                    owner.to_owned(),
                    level,
                    action.clone(),
                    op,
                    existing.map(|row| row.0),
                ));
            }
        }
        let plan = json!({
            "app_handle_id": grant.app_handle_id,
            "connection_id": connection_id,
            "agent_id": agent,
            "module": grant.module,
            "actions": grant.actions,
            "expanded": grant.expanded,
            "dry_run": grant.dry_run,
            "ceiling_additions": ceiling_additions,
            "grants": grant_plan,
            "policies": policy_rows.iter().map(|(_, level, action, op, _)| json!({
                "level":level,"action":action,"effect":grant.effect,"op":op})).collect::<Vec<_>>(),
        });
        if grant.dry_run {
            return Ok(plan);
        }
        if !ceiling_additions.is_empty() {
            super::ceiling_store::extend_connection_ceiling_on_conn(
                tx,
                &principal,
                &connection_id,
                &ceiling,
                &ceiling_additions,
                now,
            )?;
        }
        // Mint-time bound, as for every other grant: each action a row is
        // about to carry must sit inside the connection ceiling as stored.
        let Some((risk, stored)) = read_ceiling(tx)? else {
            return refuse(format!(
                "connection_ceiling_absent{{connection_id: {connection_id}}}"
            ));
        };
        if !crate::manifest::Risk::parse(&risk)
            .is_some_and(|risk| crate::manifest::Risk::Write.within(risk))
        {
            return refuse(format!(
                "risk_above_ceiling{{requested: write, ceiling: {risk}}}"
            ));
        }
        if !stored.iter().any(|selector| selector == "*") {
            if let Some(outside) = agent_missing
                .iter()
                .chain(&module_added)
                .find(|action| !stored.contains(action))
            {
                return refuse(format!("outside_connection_ceiling{{action: {outside}}}"));
            }
        }
        for action in &agent_missing {
            tx.execute("INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,expires_at,generation,created_at_ms,agent_id)
                    VALUES (?1,?2,?3,?4,?5,?6,'invoke',NULL,1,?7,?8)",
                    params![agent_grant_id(action), principal, connection_id, grant.module,
                        if action.starts_with("github.") {"read"} else {"write"},
                        json!([action]).to_string(), now, agent])?;
        }
        if !module_added.is_empty() {
            match module_row {
                Some((id, _, _, selectors)) => {
                    let mut extended = selectors.clone();
                    extended.extend(module_added.iter().cloned());
                    tx.execute(
                        "UPDATE grants SET action_selectors=?3 WHERE principal=?1 AND grant_id=?2",
                        params![principal, id, to_json(&extended)?],
                    )?;
                }
                None => {
                    tx.execute("INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,expires_at,generation,created_at_ms)
                            VALUES (?1,?2,?3,?4,'write',?5,'invoke',NULL,1,?6)",
                            params![module_grant_id, principal, connection_id, grant.module,
                                to_json(&module_added)?, now])?;
                }
            }
        }
        for (owner, level, action, op, existing) in &policy_rows {
            match (*op, existing) {
                ("update", Some(id)) => {
                    // A changed effect bumps the generation, as set_policy
                    // does, so reservations pinned to the old effect lapse.
                    tx.execute("UPDATE policies SET effect=?3, expires_at=NULL, generation=generation+1, updated_at_ms=?4
                            WHERE principal=?1 AND policy_id=?2", params![owner, id, grant.effect, now])?;
                }
                ("insert", _) => insert_policy_on_conn(
                    tx,
                    &crate::storage::PolicyInput {
                        policy_id: format!(
                            "github-grant:{}:{level}-policy:{action}",
                            grant.app_handle_id
                        ),
                        principal: owner.clone(),
                        connection_id: connection_id.clone(),
                        action_selector: action.clone(),
                        effect: grant.effect.clone(),
                        expires_at: None,
                    },
                )?,
                _ => {}
            }
        }
        Ok(plan)
    }

    /// Grant scheduled-poll authority for reviewed reads on one imported
    /// handle's connection, in one fenced transaction.
    ///
    /// A handle connection's ceiling was fixed at import to the actions the
    /// import granted, so a read added to the manifest later (such as the
    /// issue timeline) sits outside it and an ordinary `grant` refuses it. This
    /// widens the ceiling by exactly the requested reads and mints (or extends)
    /// one `poll` grant whose grantee is the connection's own principal, which
    /// is the principal that owns the subscriptions a poll runs for.
    ///
    /// Each action must already be an active `read` row in the connection's
    /// catalog: a missing row means the manifest carrying it has not been
    /// ingested yet, and granting a timer authority over a write is refused by
    /// name. The inner `Err` is that named refusal; a refusal writes nothing.
    /// A dry run runs the same checks and returns the plan without writing.
    pub fn grant_github_handle_poll(
        &self,
        grant: &GithubHandlePollGrant,
    ) -> Result<Result<Value, String>, StoreError> {
        use serde_json::json;
        let refusal = std::sync::Mutex::new(None::<String>);
        let to_json = |value: &Vec<String>| {
            serde_json::to_string(value)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))
        };
        let result = self.inner.with_conn_fenced(|tx| {
            let refuse = |code: String| -> rusqlite::Result<Value> {
                *refusal.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(code);
                Err(rusqlite::Error::QueryReturnedNoRows)
            };
            let handle: Option<(String, String, String)> = tx
                .query_row(
                    "SELECT status,connection_principal,connection_id
                     FROM github_app_handle WHERE app_handle_id=?1",
                    [&grant.app_handle_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((status, principal, connection_id)) = handle else {
                return refuse("agent_handle_unknown".into());
            };
            if status != "enabled" {
                return refuse(format!(
                    "agent_handle_disabled{{app_handle_id: {}}}",
                    grant.app_handle_id
                ));
            }
            for action in &grant.actions {
                let row: Option<(String, String)> = tx
                    .query_row(
                        "SELECT risk,status FROM catalog_actions
                         WHERE principal=?1 AND connection_id=?2 AND name=?3",
                        params![principal, connection_id, action],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                match row {
                    None => {
                        return refuse(format!(
                            "catalog_action_missing{{connection_id: {connection_id}, action: {action}}}"
                        ))
                    }
                    Some((risk, _)) if risk != "read" => {
                        return refuse(format!("action_not_read{{action: {action}, risk: {risk}}}"))
                    }
                    Some((_, status)) if status != "active" => {
                        return refuse(format!(
                            "catalog_action_inactive{{action: {action}, status: {status}}}"
                        ))
                    }
                    Some(_) => {}
                }
            }
            let read_ceiling = |tx: &rusqlite::Connection| -> rusqlite::Result<Option<(String, Vec<String>)>> {
                let row: Option<(Option<String>, Option<String>)> = tx
                    .query_row(
                        "SELECT ceiling_risk,ceiling_selectors FROM connections
                         WHERE principal=?1 AND connection_id=?2",
                        params![principal, connection_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let Some((Some(risk), Some(selectors))) = row else {
                    return Ok(None);
                };
                let selectors: Vec<String> = serde_json::from_str(&selectors).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, error.into())
                })?;
                Ok(Some((risk, selectors)))
            };
            let Some((_, ceiling)) = read_ceiling(tx)? else {
                return refuse(format!("connection_ceiling_absent{{connection_id: {connection_id}}}"));
            };
            let ceiling_additions: Vec<String> = if ceiling.iter().any(|selector| selector == "*") {
                Vec::new()
            } else {
                grant
                    .actions
                    .iter()
                    .filter(|action| !ceiling.contains(action))
                    .cloned()
                    .collect()
            };
            let now = now_ms();
            // Live module-level poll grants to the connection's own principal.
            let mut statement = tx.prepare(
                "SELECT grant_id,action_selectors FROM grants
                 WHERE principal=?1 AND connection_id=?2 AND authority_kind='poll'
                   AND grantee_principal=?1 AND agent_id IS NULL
                   AND (expires_at IS NULL OR expires_at>?3) ORDER BY grant_id",
            )?;
            let rows = statement
                .query_map(params![principal, connection_id, now], |row| {
                    let selectors: String = row.get(1)?;
                    let selectors: Vec<String> = serde_json::from_str(&selectors).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, error.into())
                    })?;
                    Ok((row.get::<_, String>(0)?, selectors))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(statement);
            let added: Vec<String> = grant
                .actions
                .iter()
                .filter(|action| {
                    !rows.iter().any(|(_, selectors)| {
                        selectors.iter().any(|selector| selector == *action || selector == "*")
                    })
                })
                .cloned()
                .collect();
            let existing = rows.first();
            // Reuse live authority by its key, never by a deterministic mint id.
            // A revoked issuance remains journaled across database restores.
            let poll_grant_id = existing.map(|(id, _)| id.clone())
                .unwrap_or_else(|| crate::storage::new_id(&format!("github-grant:{}:poll", grant.app_handle_id)));
            let op = match (added.is_empty(), existing.is_some()) {
                (true, _) => "unchanged",
                (false, true) => "extend",
                (false, false) => "insert",
            };
            let plan = json!({
                "app_handle_id": grant.app_handle_id,
                "connection_id": connection_id,
                "authority_kind": crate::governance::AUTHORITY_POLL,
                "grantee_principal": principal,
                "actions": grant.actions,
                "expanded": grant.actions,
                "dry_run": grant.dry_run,
                "ceiling_additions": ceiling_additions,
                "grants": [{"level": "module", "op": op, "grant_id": poll_grant_id,
                    "grantee_principal": principal, "actions": added}],
                "policies": [],
            });
            if grant.dry_run {
                return Ok(plan);
            }
            if !ceiling_additions.is_empty() {
                super::ceiling_store::extend_connection_ceiling_on_conn(
                    tx, &principal, &connection_id, &ceiling, &ceiling_additions, now,
                )?;
            }
            // Mint-time bound, as for every other grant: each action the grant
            // is about to carry must sit inside the connection ceiling as stored.
            let Some((risk, stored)) = read_ceiling(tx)? else {
                return refuse(format!("connection_ceiling_absent{{connection_id: {connection_id}}}"));
            };
            if !crate::manifest::Risk::parse(&risk)
                .is_some_and(|risk| crate::manifest::Risk::Read.within(risk))
            {
                return refuse(format!("risk_above_ceiling{{requested: read, ceiling: {risk}}}"));
            }
            if !stored.iter().any(|selector| selector == "*") {
                if let Some(outside) = added.iter().find(|action| !stored.contains(action)) {
                    return refuse(format!("outside_connection_ceiling{{action: {outside}}}"));
                }
            }
            match (op, existing) {
                ("extend", Some((id, selectors))) => {
                    let mut extended = selectors.clone();
                    extended.extend(added.iter().cloned());
                    tx.execute(
                        "UPDATE grants SET action_selectors=?3 WHERE principal=?1 AND grant_id=?2",
                        params![principal, id, to_json(&extended)?],
                    )?;
                }
                ("insert", _) => {
                    tx.execute(
                        "INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,expires_at,generation,created_at_ms)
                         VALUES (?1,?2,?3,?2,'read',?4,'poll',NULL,1,?5)",
                        params![poll_grant_id, principal, connection_id, to_json(&added)?, now],
                    )?;
                }
                _ => {}
            }
            Ok(plan)
        });
        match result {
            Ok(plan) => Ok(Ok(plan)),
            Err(error) => match refusal
                .into_inner()
                .unwrap_or_else(|poison| poison.into_inner())
            {
                Some(code) => Ok(Err(code)),
                None => Err(error),
            },
        }
    }

    /// Bind every listed repository to one imported handle in a single fenced
    /// transaction, or none of them.
    ///
    /// Each repository is checked and then written in turn: it must share the
    /// handle's owner, must not be bound to a different handle (a binding is
    /// never moved here, although [`bind_repo_on_conn`] would move it), and
    /// must be in `bind.installation`. A repository already bound to this
    /// handle is reported and left untouched. A refusal on any repository
    /// rolls back the ones written before it. The inner `Err` is that named
    /// refusal. A dry run runs the same checks and writes nothing.
    pub fn bind_github_handle_repos(
        &self,
        bind: &GithubHandleBind,
    ) -> Result<Result<Value, String>, StoreError> {
        use serde_json::json;
        let refusal = std::sync::Mutex::new(None::<String>);
        // Compared and stored in canonical form; a name listed twice in
        // different case is one repository.
        let mut repositories: Vec<String> = Vec::new();
        for repository in &bind.repositories {
            let repository = crate::github::canonical_repository(repository);
            if !repositories.contains(&repository) {
                repositories.push(repository);
            }
        }
        let installation: std::collections::BTreeSet<String> = bind
            .installation
            .iter()
            .map(|name| crate::github::canonical_repository(name))
            .collect();
        let result = self.inner.with_conn_fenced(|tx| {
            // A refusal rolls the transaction back through an error and leaves
            // its code here for the caller.
            let refuse = |code: String| -> rusqlite::Result<Value> {
                *refusal.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(code);
                Err(rusqlite::Error::QueryReturnedNoRows)
            };
            let handle: Option<(String, String)> = tx
                .query_row(
                    "SELECT status,connection_id FROM github_app_handle WHERE app_handle_id=?1",
                    [&bind.app_handle_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((status, connection_id)) = handle else {
                return refuse("agent_handle_unknown".into());
            };
            if status != "enabled" {
                return refuse(format!(
                    "agent_handle_disabled{{app_handle_id: {}}}",
                    bind.app_handle_id
                ));
            }
            let owner_of = |name: &str| name.split_once('/').map(|(owner, _)| owner.to_owned());
            let bound_owner: Option<String> = tx
                .query_row(
                    "SELECT repository FROM github_repo_binding WHERE app_handle_id=?1
                     ORDER BY repository LIMIT 1",
                    [&bind.app_handle_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .and_then(|name| owner_of(&name));
            // A handle with no binding yet takes the owner of the first listed
            // repository, so the listed ones must still agree with each other.
            let owner = bound_owner.or_else(|| repositories.first().and_then(|name| owner_of(name)));
            let before: i64 = tx.query_row(
                "SELECT generation FROM github_repo_binding_generation WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            let mut added = Vec::new();
            let mut already_bound = Vec::new();
            for repository in &repositories {
                if owner_of(repository) != owner {
                    return refuse(format!(
                        "binding_owner_mismatch{{repository: {repository}, owner: {}}}",
                        owner.as_deref().unwrap_or("")
                    ));
                }
                let current: Option<String> = tx
                    .query_row(
                        "SELECT app_handle_id FROM github_repo_binding WHERE repository=?1",
                        [repository],
                        |row| row.get(0),
                    )
                    .optional()?;
                if let Some(other) = current.as_deref().filter(|id| *id != bind.app_handle_id) {
                    return refuse(format!(
                        "repository_bound_elsewhere{{repository: {repository}, app_handle_id: {other}}}"
                    ));
                }
                if !installation.contains(repository) {
                    return refuse(format!(
                        "repository_not_in_installation{{repository: {repository}}}"
                    ));
                }
                if current.is_some() {
                    already_bound.push(repository.clone());
                    continue;
                }
                if !bind.dry_run {
                    bind_repo_on_conn(tx, repository, &bind.app_handle_id)?;
                }
                added.push(repository.clone());
            }
            let after: i64 = if bind.dry_run {
                before + added.len() as i64
            } else {
                tx.query_row(
                    "SELECT generation FROM github_repo_binding_generation WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )?
            };
            Ok(json!({
                "app_handle_id": bind.app_handle_id,
                "connection_id": connection_id,
                "dry_run": bind.dry_run,
                "add": added,
                "already_bound": already_bound,
                "repo_binding_generation": {"before": before, "after": after, "delta": after - before},
            }))
        });
        match result {
            Ok(plan) => Ok(Ok(plan)),
            Err(error) => match refusal
                .into_inner()
                .unwrap_or_else(|poison| poison.into_inner())
            {
                Some(code) => Ok(Err(code)),
                None => Err(error),
            },
        }
    }

    /// Remove a binding and record the operator's change in one transaction.
    /// The DELETE trigger advances the binding generation so dispatch refuses
    /// writes authorized before the binding was removed, and the handle
    /// connection's write filter is rewritten from the bindings that remain,
    /// so the connection's own owner/repo allowlist stops naming the
    /// repository too.
    pub fn unbind_github_handle_repo(
        &self,
        principal: &str,
        app_handle_id: &str,
        repository: &str,
        request_id: &str,
        dry_run: bool,
    ) -> Result<Result<Value, String>, StoreError> {
        let repository = &crate::github::canonical_repository(repository);
        let refusal = std::sync::Mutex::new(None::<String>);
        let result = self.inner.with_conn_fenced(|tx| {
            let refuse = |code: String| -> rusqlite::Result<Value> {
                *refusal.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(code);
                Err(rusqlite::Error::QueryReturnedNoRows)
            };
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM github_app_handle WHERE app_handle_id=?1)",
                [app_handle_id], |row| row.get(0),
            )?;
            if !exists {
                return refuse("agent_handle_unknown".into());
            }
            let current: Option<String> = tx.query_row(
                "SELECT app_handle_id FROM github_repo_binding WHERE repository=?1",
                [repository], |row| row.get(0),
            ).optional()?;
            if current.as_deref() != Some(app_handle_id) {
                return refuse(format!("repo_not_bound_to_handle{{repository: {repository}, app_handle_id: {app_handle_id}, held_by: {}}}", current.as_deref().unwrap_or("none")));
            }
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM github_repo_binding WHERE app_handle_id=?1",
                [app_handle_id], |row| row.get(0),
            )?;
            let before: i64 = tx.query_row(
                "SELECT generation FROM github_repo_binding_generation WHERE singleton=1",
                [], |row| row.get(0),
            )?;
            if !dry_run {
                tx.execute("DELETE FROM github_repo_binding WHERE repository=?1 AND app_handle_id=?2", params![repository, app_handle_id])?;
                rewrite_filters(tx, app_handle_id)?;
                tx.execute("INSERT INTO audit_journal (ts,principal,actor,acting_principal,app_handle_id,action,request_id,decision,reason_code,gate,args_redaction_summary) VALUES (?1,?2,?2,?2,?3,'github.handle.unbind',?4,'allow','allowed','github_control',?5)", params![now_ms(), principal, app_handle_id, request_id, serde_json::json!({"repository": repository}).to_string()])?;
            }
            let after: i64 = if dry_run { before + 1 } else {
                tx.query_row("SELECT generation FROM github_repo_binding_generation WHERE singleton=1", [], |row| row.get(0))?
            };
            Ok(serde_json::json!({
                "app_handle_id": app_handle_id, "repository": repository,
                "dry_run": dry_run, "remove": [repository],
                "remaining_repositories": count - 1, "last_repository": count == 1,
                "repo_binding_generation": {"before": before, "after": after, "delta": after - before}
            }))
        });
        match result {
            Ok(plan) => Ok(Ok(plan)),
            Err(error) => match refusal
                .into_inner()
                .unwrap_or_else(|poison| poison.into_inner())
            {
                Some(code) => Ok(Err(code)),
                None => Err(error),
            },
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn github_module_grant(
        &self,
        connection_id: &str,
        principal: &str,
    ) -> Result<bool, StoreError> {
        self.github_module_grant_refusal(connection_id, principal)
            .map(|cause| cause.is_none())
    }

    pub fn github_module_grant_refusal(
        &self,
        connection_id: &str,
        principal: &str,
    ) -> Result<Option<crate::grant_refusal::Cause>, StoreError> {
        self.inner.with_read(|conn| {
            let (total, live): (i64, i64) = conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(g.expires_at IS NULL OR g.expires_at>?3),0) FROM github_app_handle h JOIN grants g
                 ON g.principal=h.connection_principal AND g.connection_id=h.connection_id
                 WHERE h.connection_id=?1 AND g.grantee_principal=?2 AND g.agent_id IS NULL AND g.authority_kind='invoke'",
                params![connection_id, principal, now_ms()], |row| Ok((row.get(0)?, row.get(1)?)))?;
            Ok(if live > 0 { None } else if total > 0 { Some(crate::grant_refusal::Cause::Expired) } else { Some(crate::grant_refusal::Cause::Missing) })
        })
    }

    pub fn read_github_bindings(&self) -> Result<Value, StoreError> {
        self.inner.with_read(|conn| {
            let generation: i64 = conn.query_row("SELECT generation FROM github_repo_binding_generation WHERE singleton=1",[],|row| row.get(0))?;
            let mut query = conn.prepare("SELECT b.repository,h.app_handle_id,h.agent_id FROM github_repo_binding b
                JOIN github_app_handle h ON h.app_handle_id=b.app_handle_id
                ORDER BY b.repository")?;
            let bindings = query.query_map([], |row| Ok(serde_json::json!({
                "repository":row.get::<_,String>(0)?,"app_handle_id":row.get::<_,String>(1)?,"agent_id":row.get::<_,String>(2)?
            })))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(serde_json::json!({"repo_binding_generation":generation,"bindings":bindings}))
        })
    }

    pub fn read_github_bindings_for_connection(
        &self,
        connection_id: &str,
        caller: &str,
    ) -> Result<Value, StoreError> {
        self.read_github_bindings_permitted(
            GithubBindingSelector::Connection(connection_id),
            caller,
        )
    }

    pub fn read_github_bindings_for_agent(
        &self,
        agent_id: &str,
        caller: &str,
    ) -> Result<Value, StoreError> {
        self.read_github_bindings_permitted(GithubBindingSelector::Agent(agent_id), caller)
    }

    fn read_github_bindings_permitted(
        &self,
        selector: GithubBindingSelector<'_>,
        caller: &str,
    ) -> Result<Value, StoreError> {
        let (column, value) = match selector {
            GithubBindingSelector::Connection(id) => ("h.connection_id", id),
            GithubBindingSelector::Agent(id) => ("h.agent_id", id),
        };
        self.inner.with_read(|conn| {
            let generation: i64 = conn.query_row("SELECT generation FROM github_repo_binding_generation WHERE singleton=1",[],|row| row.get(0))?;
            let mut query = conn.prepare(&format!("SELECT b.repository,h.app_handle_id,h.agent_id FROM github_repo_binding b
                JOIN github_app_handle h ON h.app_handle_id=b.app_handle_id
                WHERE {column}=?1 AND EXISTS(SELECT 1 FROM grants g WHERE g.principal=h.connection_principal
                    AND g.connection_id=h.connection_id AND g.grantee_principal=?2 AND g.agent_id IS NULL
                    AND g.authority_kind='invoke' AND (g.expires_at IS NULL OR g.expires_at>?3)) ORDER BY b.repository"))?;
            let bindings = query.query_map(params![value,caller,now_ms()], |row| Ok(serde_json::json!({
                "repository":row.get::<_,String>(0)?,"app_handle_id":row.get::<_,String>(1)?,"agent_id":row.get::<_,String>(2)?
            })))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(serde_json::json!({"repo_binding_generation":generation,"bindings":bindings}))
        })
    }

    pub fn github_handle_and_bindings(
        &self,
        id: &str,
    ) -> Result<Option<(GithubHandle, Vec<String>)>, StoreError> {
        self.inner.with_read(|conn| {
            let handle = conn.query_row("SELECT app_handle_id,agent_id,app_id,installation_id,credential_reference,
                credential_generation,status,proven_at,connection_principal,connection_id FROM github_app_handle WHERE app_handle_id=?1",[id],|row| Ok(GithubHandle {
                app_handle_id:row.get(0)?,agent_id:row.get(1)?,app_id:row.get(2)?,installation_id:row.get(3)?,
                credential_reference:row.get(4)?,credential_generation:row.get(5)?,status:row.get(6)?,proven_at:row.get(7)?,
                connection_principal:row.get(8)?,connection_id:row.get(9)?
            })).optional()?;
            handle.map(|handle| {
                let mut statement = conn.prepare("SELECT repository FROM github_repo_binding WHERE app_handle_id=?1 ORDER BY repository")?;
                let repositories = statement.query_map([id],|row| row.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                Ok((handle,repositories))
            }).transpose()
        })
    }

    /// The handle connection bound to one `owner/repo`, as
    /// `(connection_principal, connection_id)`. The binding table is the only
    /// authority on which App identity reads a repository, so callers that need
    /// a REST read for a repository resolve the connection here instead of
    /// carrying their own per-caller setting.
    pub fn github_handle_connection_for_repo(
        &self,
        repository: &str,
    ) -> Result<Option<(String, String)>, StoreError> {
        let repository = crate::github::canonical_repository(repository);
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT h.connection_principal, h.connection_id FROM github_repo_binding b
                 JOIN github_app_handle h ON h.app_handle_id=b.app_handle_id
                 WHERE b.repository=?1",
                [&repository],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
        })
    }

    pub fn prove_github_handle(
        &self,
        id: &str,
        credential_generation: i64,
        binding_generation: i64,
        proven_at: Option<i64>,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            Ok(conn.execute(
                "UPDATE github_app_handle SET proven_at=?2 WHERE app_handle_id=?1 AND credential_generation=?3
                    AND (SELECT generation FROM github_repo_binding_generation WHERE singleton=1)=?4",
                params![id, proven_at, credential_generation, binding_generation],
            )? == 1)
        })
    }
}

impl PlexusStore {
    /// Record claimed agent ID, app handle ID, action, request ID, and refusal
    /// code explicitly, including NULLs for facts not established by a gate.
    pub fn audit_github_control(
        &self,
        principal: &str,
        claimed_agent_id: Option<&str>,
        app_handle_id: Option<&str>,
        action: &str,
        request_id: &str,
        refusal_code: Option<&str>,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute("INSERT INTO audit_journal (ts,principal,actor,acting_principal,agent_id,app_handle_id,
                action,request_id,decision,reason_code,gate) VALUES (?1,?2,?2,?2,?3,?4,?5,?6,?7,?8,'github_control')",
                params![now_ms(), principal, claimed_agent_id, app_handle_id, action, request_id,
                    if refusal_code.is_some() {"deny"} else {"allow"}, refusal_code.unwrap_or("allowed")])?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod facade_seam_tests {
    use super::*;
    use crate::governance::{facade_origin, RequestOrigin, Reservation, Severity};
    use crate::manifest::Risk;
    use crate::storage::SnapshotGenerations;
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

    fn store() -> (crate::test_scratch::Scratch, PlexusStore) {
        let scratch = crate::test_scratch::Scratch::database("facade-default-deny-seams");
        let descriptor = StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "facade-default-deny-seams".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: scratch.path().to_string_lossy().into_owned(),
            },
        };
        (scratch, PlexusStore::open(&descriptor).unwrap())
    }

    #[test]
    fn unproved_facade_write_cannot_pass_ownership_barrier() {
        let (_scratch, store) = store();
        let seams = GithubGovernanceSeams {
            store: &store,
            credential_provider: None,
        };
        let request = facade_origin::request(
            AuthorizationRequest::new(
                crate::github::AFT_PRINCIPAL,
                "conn",
                "close_issue",
                Value::Null,
            ),
            None,
        );
        assert!(request.ownership_proof().is_none());
        assert!(!seams.ownership_reads_complete(&request));
    }

    #[test]
    fn unclaimed_facade_write_never_pretransmits() {
        let (_scratch, store) = store();
        let seams = GithubGovernanceSeams {
            store: &store,
            credential_provider: None,
        };
        let mut reservation = Reservation {
            reservation_id: String::new(),
            principal: String::new(),
            acting_principal: String::new(),
            actor: String::new(),
            attributed_agent_id: None,
            bound_agent_handle: None,
            connection_id: String::new(),
            app_key: String::new(),
            action: "close_issue".into(),
            args: Value::Null,
            approved_args: Value::Null,
            grant_id: String::new(),
            approved_args_hash: String::new(),
            args_snapshot_hash: String::new(),
            schema_hash: String::new(),
            risk: Risk::Write,
            severity: Severity::S1,
            snapshot: SnapshotGenerations {
                policy_id: None,
                connection: 0,
                catalog_action: 0,
                grant: 0,
                policy: 0,
            },
            expires_at_ms: 0,
            request_id: String::new(),
            credential_fingerprint: String::new(),
            decision_id: None,
            grant_hash: None,
            intent_id: None,
            authority_baseline: None,
            receipt: None,
            origin: RequestOrigin::Facade,
            scope: None,
            relay_origin: None,
            on_behalf_of_agent: None,
            agent_grant: None,
            approval_scope: None,
        };
        assert!(!seams.pre_transmit(&reservation));
        reservation.risk = Risk::Read;
        assert!(seams.pre_transmit(&reservation));
        reservation.origin = RequestOrigin::Ordinary;
        assert!(!seams.pre_transmit(&reservation));
    }

    /// Connection ids are unique only per principal. Another principal's
    /// ordinary connection that shares a handle connection's id is not
    /// routed through the repository resolver; an invoke that runs on the
    /// handle connection still is.
    #[test]
    fn only_the_invoked_handle_connection_is_resolved_by_repository() {
        let (_scratch, store) = store();
        for principal in ["operator", "reserved:other"] {
            store
                .insert_connection(
                    principal,
                    "shared-id",
                    "github_rest",
                    "active",
                    &serde_json::json!({}),
                )
                .unwrap();
        }
        store
            .put_github_handle(&GithubHandle {
                app_handle_id: "app".into(),
                agent_id: "agent".into(),
                app_id: 1,
                installation_id: None,
                credential_reference: "github_app:app".into(),
                credential_generation: 0,
                status: "enabled".into(),
                proven_at: Some(1),
                connection_principal: "operator".into(),
                connection_id: "shared-id".into(),
            })
            .unwrap();
        let seams = GithubGovernanceSeams {
            store: &store,
            credential_provider: None,
        };
        let invoke = |principal: &str| {
            seams.resolve_invoke(&AuthorizationRequest::new(
                principal,
                "shared-id",
                "add_issue_comment",
                serde_json::json!({}),
            ))
        };
        assert_eq!(invoke("reserved:other"), Ok(()));
        assert_eq!(invoke("operator"), Err(ResolverDenial::RepositoryUnbound));
    }
}
