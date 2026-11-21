use super::{rewrite_filters_with_generation, GithubHandle, PlexusStore};
use crate::github::agent_policy::{
    plan::{self, Applied, StoreView, StoredGrant, StoredPolicy},
    ActivePolicy, AgentChange, ApplyPlan, CheckedGitHub, PolicyConflict,
};
use crate::grant_journal::{self, Revocation};
use crate::storage::{ceiling_store, now_ms, parse_json_column, PolicyInput};
use cortexkit_store::StoreError;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeSet;

type Checked<'a> = (&'a ActivePolicy, &'a CheckedGitHub);

impl PlexusStore {
    pub fn github_policy_preview(
        &self,
        checked: Option<Checked<'_>>,
    ) -> Result<ApplyPlan, StoreError> {
        self.inner.with_read(|conn| {
            let mut plan = plan::derive(checked, &read_view(conn)?, now_ms());
            self.refuse_revoked_ids(conn, &mut plan)?;
            Ok(plan)
        })
    }

    pub fn set_github_policy_apply(&self, enabled: bool) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO policy_apply_switch(service,enabled) VALUES ('github',?1)
                 ON CONFLICT(service) DO UPDATE SET enabled=excluded.enabled
                 WHERE enabled<>excluded.enabled",
                [enabled],
            )?;
            Ok(())
        })
    }

    pub(crate) fn github_policy_apply_enabled(&self) -> Result<bool, StoreError> {
        self.inner.with_read(enabled_on_conn)
    }

    /// Replan in the write transaction so no concurrent bind or grant change can invalidate it.
    pub fn apply_github_policy(
        &self,
        checked: Checked<'_>,
        connector_home: impl Fn() -> bool,
    ) -> Result<ApplyPlan, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let now = now_ms();
            let before = read_view(conn)?;
            let mut plan = plan::derive(Some(checked), &before, now);
            if !plan.enabled || !connector_home() || !plan.has_eligible_agents() {
                return Ok(plan);
            }
            self.refuse_revoked_ids(conn, &mut plan)?;
            let entries: BTreeSet<_> = plan
                .agents
                .iter()
                .filter_map(|row| row.target.as_ref())
                .flat_map(|target| target.revoke.iter())
                .collect();
            let revocations: Vec<_> = entries
                .into_iter()
                .map(|(principal, grant_id)| Revocation {
                    principal: principal.clone(),
                    grant_id: grant_id.clone(),
                    revoked_at_ms: now,
                })
                .collect();
            // Persist revocations before changing SQLite. Restoring an older
            // backup must not revive either an operator-set or a derived grant.
            if let Some(path) = &self.grant_journal {
                grant_journal::append_all(path, &revocations)?;
            }
            for entry in &revocations {
                grant_journal::apply_as(conn, entry, "direct")?;
            }
            for row in plan.agents.iter().filter(|row| row.target.is_some()) {
                apply_agent(conn, row, checked.0, &before, now)?;
            }
            if !connector_home() {
                return Err(refusal("connector home lost during policy apply"));
            }
            let mut remaining = plan::derive(Some(checked), &read_view(conn)?, now);
            self.refuse_revoked_ids(conn, &mut remaining)?;
            Ok(remaining)
        })
    }

    fn refuse_revoked_ids(&self, conn: &Connection, plan: &mut ApplyPlan) -> rusqlite::Result<()> {
        let candidates: BTreeSet<_> = plan
            .agents
            .iter()
            .filter_map(|row| {
                let grant = row.derived_grant.as_ref().filter(|grant| grant.insert)?;
                let target = row.target.as_ref()?;
                Some((target.principal.as_str(), grant.id.as_str()))
            })
            .collect();
        if candidates.is_empty() {
            return Ok(());
        }
        let mut revoked = BTreeSet::new();
        if let Some(path) = &self.grant_journal {
            grant_journal::scan(path, |entry| {
                if candidates.contains(&(entry.principal.as_str(), entry.grant_id.as_str())) {
                    revoked.insert((entry.principal, entry.grant_id));
                }
                Ok(())
            })
            .map_err(refusal)?;
        }
        for row in &mut plan.agents {
            let Some(grant) = row.derived_grant.as_ref().filter(|grant| grant.insert) else {
                continue;
            };
            let Some(target) = &row.target else { continue };
            if revoked.contains(&(target.principal.clone(), grant.id.clone()))
                || conn.query_row("SELECT EXISTS(SELECT 1 FROM grant_revocations WHERE principal=?1 AND grant_id=?2)",
                    params![target.principal, grant.id], |row| row.get::<_, bool>(0))?
            {
                row.target = None;
                row.conflicts.push(PolicyConflict {
                    reason: "derived_grant_id_revoked", resource: None, handle: row.handle.clone(),
                });
            }
        }
        Ok(())
    }
}

fn refusal(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(message.into())
}

pub(super) fn enabled_on_conn(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(conn
        .query_row(
            "SELECT enabled FROM policy_apply_switch WHERE service='github'",
            [],
            |row| row.get::<_, bool>(0),
        )
        .optional()?
        .unwrap_or_default())
}

fn read_view(conn: &Connection) -> rusqlite::Result<StoreView> {
    let enabled = enabled_on_conn(conn)?;
    let applied = conn.prepare("SELECT agent,policy_version,policy_sha256,manifest_version,grant_ids FROM policy_applied WHERE service='github'")?
        .query_map([], |row| Ok((row.get(0)?, Applied {
            version: row.get(1)?, sha256: row.get(2)?, manifest_version: row.get(3)?,
            grant_ids: parse_json_column(&row.get::<_, String>(4)?)?,
        })))?.collect::<rusqlite::Result<_>>()?;
    let handles = conn.prepare("SELECT app_handle_id,agent_id,app_id,installation_id,credential_reference,
        credential_generation,status,proven_at,connection_principal,connection_id FROM github_app_handle ORDER BY app_handle_id")?
        .query_map([], |row| Ok(GithubHandle {
            app_handle_id: row.get(0)?, agent_id: row.get(1)?, app_id: row.get(2)?, installation_id: row.get(3)?,
            credential_reference: row.get(4)?, credential_generation: row.get(5)?, status: row.get(6)?,
            proven_at: row.get(7)?, connection_principal: row.get(8)?, connection_id: row.get(9)?,
        }))?.collect::<rusqlite::Result<_>>()?;
    let bindings = conn
        .prepare("SELECT repository,app_handle_id FROM github_repo_binding")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let grants = conn.prepare("SELECT g.principal,g.connection_id,g.grant_id,g.agent_id,g.action_selectors,g.expires_at,g.generation
        FROM grants g WHERE g.agent_id IS NOT NULL AND g.authority_kind='invoke'
        AND (g.grant_id GLOB 'policy:github:*' OR EXISTS (SELECT 1 FROM github_app_handle h
            WHERE h.connection_principal=g.principal AND h.connection_id=g.connection_id AND h.agent_id=g.agent_id))
        ORDER BY g.principal,g.grant_id")?
        .query_map([], |row| Ok(StoredGrant {
            principal: row.get(0)?, connection: row.get(1)?, id: row.get(2)?, agent: row.get(3)?,
            selectors: parse_json_column(&row.get::<_, String>(4)?)?, expires_at: row.get(5)?, generation: row.get(6)?,
        }))?.collect::<rusqlite::Result<_>>()?;
    let mut policies = std::collections::BTreeMap::new();
    let mut query = conn.prepare("SELECT p.principal,p.connection_id,p.action_selector,p.policy_id,p.effect,p.expires_at
        FROM policies p JOIN github_app_handle h ON h.connection_id=p.connection_id AND h.agent_id=p.principal
        ORDER BY p.generation DESC,p.policy_id")?;
    let rows = query.query_map([], |row| {
        Ok((
            (row.get(0)?, row.get(1)?, row.get(2)?),
            StoredPolicy {
                id: row.get(3)?,
                effect: row.get(4)?,
                expires_at: row.get(5)?,
            },
        ))
    })?;
    for row in rows {
        let (key, policy) = row?;
        policies.entry(key).or_insert(policy);
    }
    Ok(StoreView {
        enabled,
        applied,
        handles,
        bindings,
        grants,
        policies,
    })
}

fn apply_agent(
    conn: &Connection,
    row: &AgentChange,
    active: &ActivePolicy,
    before: &StoreView,
    now: i64,
) -> rusqlite::Result<()> {
    let target = row.target.as_ref().expect("only apply eligible agents");
    let handle = row.handle.as_ref().expect("eligible agent has a handle");
    let mut ceiling_changed = false;
    if let Some(grant) = &row.derived_grant {
        let ceiling = match crate::storage::grant_ceiling_on_conn(
            conn,
            &target.principal,
            &target.connection,
        )? {
            Ok(ceiling) => ceiling,
            Err(error) => return Err(refusal(format!("policy grant ceiling: {error:?}"))),
        };
        if !crate::manifest::Risk::Write.within(ceiling.risk) {
            return Err(refusal("policy grant requires a write connection ceiling"));
        }
        let additions: Vec<_> = grant
            .selectors
            .iter()
            .filter(|action| {
                !ceiling
                    .action_selectors
                    .iter()
                    .any(|selector| selector == "*" || selector == *action)
            })
            .cloned()
            .collect();
        ceiling_changed = !additions.is_empty();
        ceiling_store::extend_connection_ceiling_on_conn(
            conn,
            &target.principal,
            &target.connection,
            &ceiling.action_selectors,
            &additions,
            now,
        )?;
        if grant.insert {
            let json = encode(&grant.selectors)?;
            let generation = target
                .next_grant_generation
                .ok_or_else(|| refusal("agent grant generation overflow"))?;
            conn.execute(
                "INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,
                    action_selectors,authority_kind,expires_at,generation,created_at_ms,agent_id)
                 VALUES (?1,?2,?3,?4,'write',?5,'invoke',NULL,?6,?7,?8)",
                params![grant.id, target.principal, target.connection, crate::github::AFT_PRINCIPAL, json, generation, now, row.agent],
            )?;
        }
    }
    for repo in &row.remove_repos {
        conn.execute(
            "DELETE FROM github_repo_binding WHERE repository=?1 AND app_handle_id=?2",
            params![repo, handle],
        )?;
    }
    for repo in &row.add_repos {
        conn.execute(
            "INSERT INTO github_repo_binding(repository,app_handle_id) VALUES (?1,?2)",
            params![repo, handle],
        )?;
    }
    if !row.add_repos.is_empty() || !row.remove_repos.is_empty() {
        // Both changed filters and a widened ceiling invalidate old authority.
        // Doing both together is still only one new connection generation.
        rewrite_filters_with_generation(conn, handle, !ceiling_changed)?;
    }
    for action in &row.allow_policies {
        if let Some(policy) =
            before
                .policies
                .get(&(row.agent.clone(), target.connection.clone(), action.clone()))
        {
            conn.execute("UPDATE policies SET effect='allow',expires_at=NULL,generation=generation+1,updated_at_ms=?3
                         WHERE principal=?1 AND policy_id=?2", params![row.agent, policy.id, now])?;
        } else {
            crate::storage::insert_policy_on_conn(
                conn,
                &PolicyInput {
                    policy_id: format!(
                        "policy:github:{}:{}:{action}",
                        row.agent, target.connection
                    ),
                    principal: row.agent.clone(),
                    connection_id: target.connection.clone(),
                    action_selector: action.clone(),
                    effect: "allow".into(),
                    expires_at: None,
                },
            )?;
        }
    }
    let grant_ids: Vec<_> = row.derived_grant.iter().map(|grant| &grant.id).collect();
    conn.execute(
        "INSERT INTO policy_applied (service,agent,policy_version,policy_sha256,manifest_version,grant_ids,applied_at_ms)
         VALUES ('github',?1,?2,?3,?4,?5,?6)
         ON CONFLICT(service,agent) DO UPDATE SET policy_version=excluded.policy_version,
           policy_sha256=excluded.policy_sha256,manifest_version=excluded.manifest_version,
           grant_ids=excluded.grant_ids,applied_at_ms=excluded.applied_at_ms",
        params![row.agent, active.policy.version, active.policy_sha256, active.manifest_version, encode(&grant_ids)?, now],
    )?;
    Ok(())
}

fn encode(value: &impl serde::Serialize) -> rusqlite::Result<String> {
    serde_json::to_string(value).map_err(|err| rusqlite::Error::ToSqlConversionFailure(err.into()))
}

#[cfg(test)]
mod tests;
