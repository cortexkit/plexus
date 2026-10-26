use super::*;

impl PlexusStore {
    /// Apply one reviewed write intent to every enabled handle atomically.
    /// The per-handle writer is shared with single-handle grants, so ceilings,
    /// agent/module grants and policies have exactly the same authority shape.
    pub fn grant_all_github_handles(
        &self,
        grant: &GithubHandleGrant,
    ) -> Result<Result<Value, String>, StoreError> {
        let refusal = std::sync::Mutex::new(None::<String>);
        let result = self.inner.with_conn_fenced(|tx| {
            let refuse = |code: String| -> rusqlite::Result<Value> {
                *refusal.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(code);
                Err(rusqlite::Error::QueryReturnedNoRows)
            };
            let source: Option<String> = tx.query_row(
                "SELECT manifest_json FROM app_manifests WHERE principal=?1 AND key='github_rest' AND status='active'",
                [super::super::CATALOG_PRINCIPAL], |row| row.get(0),
            ).optional()?;
            let manifest: Value = serde_json::from_str(source.as_deref().unwrap_or("null"))
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
            if grant.actions.is_empty() {
                return refuse("actions_required".into());
            }
            for action in &grant.actions {
                let reviewed = manifest["actions_baseline"].as_array().and_then(|rows|
                    rows.iter().find(|row| row["name"].as_str() == Some(action.as_str())));
                if reviewed.is_none_or(|row| row["risk"] != "write" || row["facade_only"] != true) {
                    return refuse(format!("reviewed_facade_write_required{{action: {action}}}"));
                }
            }
            for action in &grant.expanded {
                let reviewed = manifest["actions_baseline"].as_array().and_then(|rows|
                    rows.iter().find(|row| row["name"].as_str() == Some(action.as_str())));
                let write = grant.policy_actions.contains(action);
                if reviewed.is_none_or(|row| row["risk"] != if write {"write"} else {"read"}
                    || (write && row["facade_only"] != true)) {
                    return refuse(format!("reviewed_facade_write_required{{action: {action}}}"));
                }
            }
            let mut statement = tx.prepare("SELECT app_handle_id FROM github_app_handle WHERE status='enabled' ORDER BY app_handle_id")?;
            let handles = statement.query_map([], |row| row.get::<_,String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(statement);
            // Like read upgrades, preview exercises catalog seeding but rolls
            // it back, including catalog generation changes.
            tx.execute_batch("SAVEPOINT bot_invoke_upgrade")?;
            let mut plans = Vec::new();
            for handle in handles {
                let (principal,connection,app,status,risk): (String,String,String,String,Option<String>) = tx.query_row(
                    "SELECT h.connection_principal,h.connection_id,c.app_key,c.status,c.ceiling_risk
                     FROM github_app_handle h JOIN connections c ON c.principal=h.connection_principal AND c.connection_id=h.connection_id
                     WHERE h.app_handle_id=?1", [&handle], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?;
                if principal != "direct" || app != "github_rest" || status != "active" {
                    return refuse(format!("bot_connection_required{{connection_id: {connection}}}"));
                }
                if !risk.as_deref().and_then(crate::manifest::Risk::parse).is_some_and(|risk| crate::manifest::Risk::Write.within(risk)) {
                    return refuse(format!("risk_above_ceiling{{requested: write, ceiling: {}}}",risk.unwrap_or_default()));
                }
                let mut seeded = Vec::new();
                for action in &grant.expanded {
                    let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM catalog_actions WHERE principal=?1 AND connection_id=?2 AND name=?3)",
                        params![principal,connection,action], |row| row.get(0))?;
                    if !exists { seeded.push(action.clone()); }
                }
                if !seeded.is_empty() {
                    super::super::seed_catalog_actions_from_manifest_on_conn(tx,&principal,&connection,"github_rest",
                        super::super::SeedMode::AddMissing,Some(&seeded))?;
                }
                for action in &grant.expanded {
                    let row: Option<(String,String)> = tx.query_row("SELECT risk,status FROM catalog_actions WHERE principal=?1 AND connection_id=?2 AND name=?3",
                        params![principal,connection,action], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
                    let expected = if grant.policy_actions.contains(action) {"write"} else {"read"};
                    match row {
                        None => return refuse(format!("catalog_action_missing{{action: {action}}}")),
                        Some((risk,_)) if risk != expected => return refuse(format!("catalog_action_risk_mismatch{{action: {action}}}")),
                        Some((_,status)) if status != "active" => return refuse(format!("catalog_action_inactive{{action: {action}, status: {status}}}")),
                        _ => {}
                    }
                }
                let mut request = grant.clone();
                request.app_handle_id = handle.clone();
                let mut plan = Self::grant_github_handle_on_conn(tx,&request,&refusal)?;
                plan["catalog_additions"] = serde_json::json!(seeded);
                if !grant.dry_run {
                    let changed = !seeded.is_empty() || plan["ceiling_additions"].as_array().is_some_and(|rows| !rows.is_empty())
                        || plan["grants"].as_array().is_some_and(|rows| !rows.is_empty())
                        || plan["policies"].as_array().is_some_and(|rows| rows.iter().any(|row| row["op"] != "unchanged"));
                    if changed {
                        let mut audit = crate::storage::AuditRecord::ceremony(&principal,Some("github_rest"),Some(&connection),"github.handle.grant","invoke",None);
                        audit.app_handle_id = Some(handle);
                        audit.outcome = Some("applied".into());
                        audit.args_redaction_summary = Some(plan.to_string());
                        super::super::append_audit_on_conn(tx,&audit,None,None,None,None)?;
                    }
                }
                plans.push(plan);
            }
            if grant.dry_run { tx.execute_batch("ROLLBACK TO bot_invoke_upgrade")?; }
            tx.execute_batch("RELEASE bot_invoke_upgrade")?;
            Ok(serde_json::json!({"kind":"invoke","all_handles":true,"dry_run":grant.dry_run,
                "actions":grant.actions,"expanded":grant.expanded,"handles":plans}))
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
