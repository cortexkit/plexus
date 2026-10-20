use super::*;

/// A read upgrade targets one imported handle, or every enabled handle.
/// It seeds missing reviewed catalog rows and adds reads to the connection's
/// ceiling and module invoke grant; agent write grants and policies stay intact.
pub struct GithubHandleReadGrant {
    pub app_handle_id: Option<String>,
    pub all_handles: bool,
    pub module: String,
    pub actions: Vec<String>,
    pub dry_run: bool,
}

impl PlexusStore {
    /// Plan and apply a bounded bot-read upgrade in one fenced transaction.
    /// Preview uses a savepoint to exercise the real reviewed catalog seeder,
    /// then rolls it back, including any catalog generations it would create.
    pub fn grant_github_handle_read(
        &self,
        grant: &GithubHandleReadGrant,
    ) -> Result<Result<Value, String>, StoreError> {
        let refusal = std::sync::Mutex::new(None::<String>);
        let result = self.inner.with_conn_fenced(|tx| {
            let refuse = |code: String| -> rusqlite::Result<Value> {
                *refusal.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(code);
                Err(rusqlite::Error::QueryReturnedNoRows)
            };
            if grant.all_handles == grant.app_handle_id.is_some() {
                return refuse("exactly_one_handle_selector_required".into());
            }
            if grant.module.is_empty() || grant.actions.is_empty() {
                return refuse("module_and_actions_required".into());
            }
            let actions: Vec<String> = grant.actions.iter().cloned()
                .collect::<std::collections::BTreeSet<_>>().into_iter().collect();
            for action in &actions {
                if !crate::github::reads::bot::GRANT_ACTIONS.contains(&action.as_str()) {
                    return refuse(format!("action_not_grantable{{action: {action}}}"));
                }
            }
            let source: Option<String> = tx.query_row(
                "SELECT manifest_json FROM app_manifests WHERE principal=?1 AND key='github_rest' AND status='active'",
                [super::super::CATALOG_PRINCIPAL], |row| row.get(0),
            ).optional()?;
            let manifest: Value = serde_json::from_str(source.as_deref().unwrap_or("null"))
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
            for action in &actions {
                let reviewed = manifest["actions_baseline"].as_array().and_then(|rows|
                    rows.iter().find(|row| row["name"].as_str() == Some(action.as_str())));
                if reviewed.is_none_or(|row| row["risk"] != "read") {
                    return refuse(format!("reviewed_read_required{{action: {action}}}"));
                }
            }
            let mut stmt = tx.prepare(
                "SELECT app_handle_id,status,connection_principal,connection_id FROM github_app_handle
                 WHERE (?1 AND status='enabled') OR app_handle_id=?2 ORDER BY app_handle_id")?;
            let handles = stmt.query_map(params![grant.all_handles, grant.app_handle_id], |row|
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(stmt);
            if !grant.all_handles && handles.is_empty() {
                return refuse("agent_handle_unknown".into());
            }
            tx.execute_batch("SAVEPOINT bot_read_upgrade")?;
            let now = now_ms();
            let mut plans = Vec::new();
            for (handle, status, principal, connection) in handles {
                if status != "enabled" {
                    return refuse(format!("agent_handle_disabled{{app_handle_id: {handle}}}"));
                }
                let row: Option<(String, String, Option<String>, Option<String>)> = tx.query_row(
                    "SELECT app_key,status,ceiling_risk,ceiling_selectors FROM connections WHERE principal=?1 AND connection_id=?2",
                    params![principal, connection], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
                ).optional()?;
                let Some((app, connection_status, Some(risk), Some(selectors))) = row else {
                    return refuse(format!("connection_ceiling_absent{{connection_id: {connection}}}"));
                };
                if principal != "direct" || app != "github_rest" || connection_status != "active" {
                    return refuse(format!("bot_connection_required{{connection_id: {connection}}}"));
                }
                if !crate::manifest::Risk::parse(&risk).is_some_and(|risk| crate::manifest::Risk::Read.within(risk)) {
                    return refuse(format!("risk_above_ceiling{{requested: read, ceiling: {risk}}}"));
                }
                let ceiling: Vec<String> = super::super::parse_json_column(&selectors)?;
                let mut seeded = Vec::new();
                for action in &actions {
                    let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM catalog_actions WHERE principal=?1 AND connection_id=?2 AND name=?3)",
                        params![principal, connection, action], |row| row.get(0))?;
                    if !exists { seeded.push(action.clone()); }
                }
                if !seeded.is_empty() {
                    super::super::seed_catalog_actions_from_manifest_on_conn(tx, &principal, &connection,
                        "github_rest", super::super::SeedMode::AddMissing, Some(&seeded))?;
                }
                for action in &actions {
                    let row: Option<(String, String)> = tx.query_row(
                        "SELECT risk,status FROM catalog_actions WHERE principal=?1 AND connection_id=?2 AND name=?3",
                        params![principal,connection,action], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
                    match row {
                        None => return refuse(format!("catalog_action_missing{{action: {action}}}")),
                        Some((risk, _)) if risk != "read" => return refuse(format!("action_not_read{{action: {action}, risk: {risk}}}")),
                        Some((_, status)) if status != "active" => return refuse(format!("catalog_action_inactive{{action: {action}, status: {status}}}")),
                        _ => {}
                    }
                }
                let additions: Vec<String> = actions.iter().filter(|action|
                    !ceiling.iter().any(|s| s == "*" || s == *action)).cloned().collect();
                let existing: Option<(String, String)> = tx.query_row(
                    "SELECT grant_id,action_selectors FROM grants WHERE principal=?1 AND connection_id=?2
                     AND grantee_principal=?3 AND authority_kind='invoke' AND agent_id IS NULL
                     AND (expires_at IS NULL OR expires_at>?4) ORDER BY grant_id LIMIT 1",
                    params![principal,connection,grant.module,now], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
                let mut selectors: Vec<String> = existing.as_ref().map(|(_, json)| super::super::parse_json_column(json)).transpose()?.unwrap_or_default();
                let added: Vec<String> = actions.iter().filter(|action|
                    !selectors.iter().any(|s| s == "*" || s == *action)).cloned().collect();
                let id = existing.as_ref().map(|(id, _)| id.clone()).unwrap_or_else(||
                    crate::storage::new_id(&format!("github-grant:{handle}:read")));
                let op = if added.is_empty() { "unchanged" } else if existing.is_some() { "extend" } else { "insert" };
                let plan = serde_json::json!({"app_handle_id":handle,"connection_id":connection,
                    "module":grant.module,"actions":actions,"dry_run":grant.dry_run,
                    "catalog_additions":seeded,"ceiling_additions":additions,
                    "grants":[{"level":"module","op":op,"grant_id":id,"actions":added}],"policies":[]});
                if !grant.dry_run {
                    super::super::ceiling_store::extend_connection_ceiling_on_conn(tx, &principal, &connection, &ceiling, &additions, now)?;
                    selectors.extend(added.iter().cloned());
                    let json = serde_json::to_string(&selectors).map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
                    if op == "extend" {
                        // Adding reads must not revoke write receipts pinned to this grant.
                        tx.execute("UPDATE grants SET action_selectors=?3 WHERE principal=?1 AND grant_id=?2", params![principal,id,json])?;
                    } else if op == "insert" {
                        tx.execute("INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,expires_at,generation,created_at_ms)
                            VALUES (?1,?2,?3,?4,'read',?5,'invoke',NULL,1,?6)", params![id,principal,connection,grant.module,json,now])?;
                    }
                    if !seeded.is_empty() || !additions.is_empty() || !added.is_empty() {
                        let mut audit = crate::storage::AuditRecord::ceremony(&principal, Some("github_rest"), Some(&connection),
                            "github.handle.grant", "read", None);
                        audit.app_handle_id = Some(handle);
                        audit.outcome = Some("applied".into());
                        audit.args_redaction_summary = Some(plan.to_string());
                        super::super::append_audit_on_conn(tx, &audit, None, None, None, None)?;
                    }
                }
                plans.push(plan);
            }
            if grant.dry_run { tx.execute_batch("ROLLBACK TO bot_read_upgrade")?; }
            tx.execute_batch("RELEASE bot_read_upgrade")?;
            Ok(serde_json::json!({"kind":"read","all_handles":grant.all_handles,"dry_run":grant.dry_run,"handles":plans}))
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
}
