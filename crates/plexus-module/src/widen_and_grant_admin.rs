//! Widen a connection's ceiling and grant the added actions under a single
//! operator confirmation: `plexus.admin.widen_and_grant`.
//!
//! By hand this is `widen-ceiling --apply` followed by one `grant` per
//! grantee, and each asks the operator for presence. Neither step contacts a
//! vendor, so here the widening and every grant commit in one store
//! transaction, or nothing does. A preview runs the same transaction and
//! rolls it back, so it checks each grant against the widened ceiling exactly
//! as an apply would.
//!
//! A rerun is safe: actions already in the ceiling are left as they are, and
//! a grantee already holding a live grant of the same kind and risk that
//! covers the actions is not granted again.

use std::sync::Arc;

use plexus_core::{AuditRecord, GrantMintRequest};
use serde_json::{json, Value};
use subc_protocol::Frame;
use tokio::sync::mpsc;

use crate::composite_admin::{
    self, named_actions, named_principals, prompt_label, prompt_list, refusal, Caller, Composite,
    ConnectorHome,
};
use crate::{ceremony, manifest, ModuleError, ModuleState, RouteBindings, RouteFrameContext};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    connection_id: String,
    actions: Vec<String>,
    grantees: Vec<String>,
    #[serde(default = "invoke_kind")]
    authority_kind: String,
    #[serde(default = "read_risk")]
    risk_ceiling: String,
    #[serde(default = "preview_by_default")]
    dry_run: bool,
}

fn invoke_kind() -> String {
    "invoke".to_string()
}

fn read_risk() -> String {
    "read".to_string()
}

fn preview_by_default() -> bool {
    true
}

struct Plan {
    connection_id: String,
    actions: Vec<String>,
    kind: String,
    risk: String,
    grantees: Vec<String>,
    /// Grantees whose existing grant already covers the actions.
    present: Vec<String>,
    /// The widening as the store reported it in the rolled-back preview.
    widening: Value,
    dry_run: bool,
}

/// Serve `plexus.admin.widen_and_grant`.
pub(crate) async fn widen_and_grant(
    route: RouteFrameContext,
    params: &Value,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    principal: &str,
) -> Result<Value, ModuleError> {
    // Neither widen-ceiling nor grant needs the connector-home role, since
    // both only change the store; so neither does their combination.
    composite_admin::run(
        Caller {
            route,
            writer,
            state,
            route_bindings,
            method: manifest::ADMIN_WIDEN_AND_GRANT_OP,
        },
        ConnectorHome::NotNeeded,
        || plan(state, principal, params),
        |plan| apply(state, principal, plan),
    )
    .await
}

fn plan(state: &Arc<ModuleState>, principal: &str, params: &Value) -> Result<Plan, Value> {
    let request = serde_json::from_value::<Request>(params.clone()).map_err(|_| {
        refusal(
            "invalid_request",
            "widen_and_grant takes connection_id, actions, grantees and optional \
             authority_kind, risk_ceiling and dry_run",
        )
    })?;
    if request.connection_id.trim().is_empty() {
        return Err(refusal("invalid_request", "connection_id is required"));
    }
    if !matches!(
        request.authority_kind.as_str(),
        "invoke" | plexus_core::AUTHORITY_POLL | plexus_core::AUTHORITY_EVENTS_CONSUME
    ) {
        return Err(refusal(
            "invalid_request",
            "authority_kind must be invoke, poll or events_consume",
        ));
    }
    let actions = named_actions("actions", request.actions)?;
    let grantees = named_principals(request.grantees)?;
    if grantees.is_empty() {
        return Err(refusal(
            "grantees_required",
            "name each principal that may use the added actions with --grantee",
        ));
    }
    let mut plan = Plan {
        connection_id: request.connection_id,
        actions,
        kind: request.authority_kind,
        risk: request.risk_ceiling,
        grantees,
        present: Vec::new(),
        widening: Value::Null,
        dry_run: request.dry_run,
    };
    plan.present = present(state, principal, &plan)?;
    // The whole change, run and rolled back: every refusal the apply could
    // meet is met here, before anyone is asked.
    let (widening, _) = commit(state, principal, &plan, true)?;
    plan.widening = widening;
    Ok(plan)
}

/// The grantees that already hold a live grant covering the actions.
fn present(state: &Arc<ModuleState>, principal: &str, plan: &Plan) -> Result<Vec<String>, Value> {
    let grants = state.store().list_all_grants(principal).map_err(|error| {
        crate::wire::store_failure(
            "connection grant read",
            "the connection's grants could not be read",
            &error,
        )
    })?;
    Ok(plan
        .grantees
        .iter()
        .filter(|grantee| {
            grants.iter().any(|grant| {
                composite_admin::grant_covers(
                    grant,
                    &plan.connection_id,
                    grantee,
                    &plan.kind,
                    &plan.risk,
                    &plan.actions,
                )
            })
        })
        .cloned()
        .collect())
}

/// Widen and mint the missing grants in one transaction; with `dry_run`
/// the transaction is rolled back after every write ran.
fn commit(
    state: &Arc<ModuleState>,
    principal: &str,
    plan: &Plan,
    dry_run: bool,
) -> Result<(Value, Vec<plexus_core::storage::GrantRecord>), Value> {
    let requests = plan
        .grantees
        .iter()
        .filter(|grantee| !plan.present.contains(grantee))
        .map(|grantee| GrantMintRequest {
            principal,
            connection_id: &plan.connection_id,
            grantee_principal: grantee,
            authority_kind: &plan.kind,
            requested_risk: &plan.risk,
            requested_selectors: &plan.actions,
            expires_at: None,
        })
        .collect::<Vec<_>>();
    // The audit row is the one `grant` writes for each grant it mints.
    match state.store().widen_ceiling_and_mint_grants(
        principal,
        &plan.connection_id,
        &plan.actions,
        &requests,
        &|minted| {
            AuditRecord::ceremony(
                principal,
                None,
                Some(&plan.connection_id),
                "grant",
                &minted.risk_ceiling,
                None,
            )
        },
        dry_run,
    ) {
        Ok(Ok(committed)) => Ok(committed),
        Ok(Err(refused)) => Err(ceremony::refusal_response(&refused)),
        Err(error) => Err(crate::wire::store_failure(
            "ceiling widened and grants minted",
            "the ceiling could not be widened or the grants could not be minted",
            &error,
        )),
    }
}

impl Plan {
    fn json(&self, widening: &Value, minted: &[plexus_core::storage::GrantRecord]) -> Value {
        let grants = self
            .grantees
            .iter()
            .map(|grantee| {
                let mut grant = json!({
                    "step": "grant",
                    "grantee": grantee,
                    "authority_kind": self.kind,
                    "risk_ceiling": self.risk,
                    "action_selectors": self.actions,
                    "status": if self.present.contains(grantee) { "already_present" } else { "to_mint" },
                });
                if let Some(record) = minted
                    .iter()
                    .find(|record| &record.grantee_principal == grantee)
                {
                    grant["status"] = json!("minted");
                    grant["grant_id"] = json!(record.grant_id);
                }
                grant
            })
            .collect::<Vec<_>>();
        let mut steps = vec![json!({
            "step": "widen_ceiling",
            "added_actions": widening["added_actions"],
            "unchanged_actions": widening["unchanged_actions"],
            "resulting_ceiling": widening["resulting_ceiling"],
            "ceiling_risk": widening["ceiling_risk"],
            "status": if widening["added_actions"].as_array().is_some_and(|added| !added.is_empty()) {
                if self.dry_run { "to_widen" } else { "widened" }
            } else {
                "unchanged"
            },
        })];
        steps.extend(grants);
        json!({
            "operation": "widen_and_grant",
            "connection_id": self.connection_id,
            "steps": steps,
            "summary": self.summary(),
            "dry_run": self.dry_run,
            "applied": false,
        })
    }
}

impl Composite for Plan {
    fn dry_run(&self) -> bool {
        self.dry_run
    }

    fn preview(&self) -> Value {
        self.json(&self.widening, &[])
    }

    /// One line naming the actions added to the ceiling and every grantee.
    fn summary(&self) -> String {
        let added = self.widening["added_actions"]
            .as_array()
            .map(|added| added.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let widen = if added.is_empty() {
            "the ceiling already holds every action".to_string()
        } else {
            format!(
                "widen the ceiling by {} at its {} risk",
                prompt_list(&added),
                prompt_label(self.widening["ceiling_risk"].as_str().unwrap_or("recorded"))
            )
        };
        let grantees = self
            .grantees
            .iter()
            .map(|grantee| {
                let label = prompt_label(grantee);
                if self.present.contains(grantee) {
                    format!("{label} (already granted)")
                } else {
                    label
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "widen and grant on {}: {widen}; grant {} {} on {} to {grantees}",
            prompt_label(&self.connection_id),
            prompt_label(&self.kind),
            prompt_label(&self.risk),
            prompt_list(&self.actions),
        )
    }
}

fn apply(state: &Arc<ModuleState>, principal: &str, plan: &Plan) -> Value {
    // The plan's grant statuses were read before the confirmation; read them
    // again so a grant minted while the operator decided is not minted twice.
    let mut fresh = Plan {
        connection_id: plan.connection_id.clone(),
        actions: plan.actions.clone(),
        kind: plan.kind.clone(),
        risk: plan.risk.clone(),
        grantees: plan.grantees.clone(),
        present: Vec::new(),
        widening: Value::Null,
        dry_run: false,
    };
    fresh.present = match present(state, principal, &fresh) {
        Ok(present) => present,
        Err(response) => return response,
    };
    let (widening, minted) = match commit(state, principal, &fresh, false) {
        Ok(committed) => committed,
        Err(response) => return response,
    };
    fresh.widening = widening.clone();
    let mut result = fresh.json(&widening, &minted);
    result["applied"] = json!(true);
    json!({ "result": result })
}
