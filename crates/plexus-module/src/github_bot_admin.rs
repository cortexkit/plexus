//! Onboard one GitHub bot (an App handle) for an agent under a single
//! operator confirmation: `plexus.admin.onboard_github_bot`.
//!
//! By hand, a bot takes `github.handle.import`, `github.handle.probe`,
//! `handle-bind` for the repositories beyond its inventory, and `handle-grant`
//! for its writes, optionally followed by `handle-grant --kind read` and
//! `--kind poll`. The import, the bind and each grant ask the operator for
//! presence. This ceremony plans all of it, asks once, and then runs the same
//! control operations, writing the same rows and the same control audit rows.
//!
//! The import, the probe and the bind each list the handle's installation on
//! GitHub with the handle's own token, even on a dry run. Here that listing
//! is read once, while planning and before anyone is asked, so the preview
//! shows what GitHub reports, and the import, probe and bind reuse it: an
//! applied run sends nothing to GitHub after the confirmation.
//!
//! Binding a repository changes what AFT's `gh` shim must agree with. The
//! shim compares plexus's repository bindings with its own signed manifest on
//! every bot write and refuses every governed bot write, fleet-wide, while
//! they disagree. So an applied run that binds any repository requires the
//! operator to state, with `shim_manifest_maps_repo`, that the active shim
//! manifest already maps those repositories to the same agent, and the
//! confirmation prompt repeats that statement.
//!
//! A rerun is safe: an imported handle whose agent, app, installation,
//! credential and status match the inventory is reused (its grants are not
//! compared), repositories already bound are left alone and grants that exist
//! are not written again; a handle that differs in any of those fields is
//! refused by name.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use plexus_core::github::control::{self, Inventory, InventoryHandle};
use serde_json::{json, Value};
use subc_protocol::Frame;
use tokio::sync::mpsc;

use crate::composite_admin::{
    self, diagnostic, named_actions, prompt_label, prompt_list, refusal, Caller, Composite,
    ConnectorHome,
};
use crate::{manifest, ModuleError, ModuleState, RouteBindings, RouteFrameContext};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    inventory: Inventory,
    #[serde(default)]
    repositories: Vec<String>,
    actions: Vec<String>,
    carrier: String,
    effect: String,
    #[serde(default)]
    read_actions: Option<Vec<String>>,
    #[serde(default)]
    poll_actions: Option<Vec<String>>,
    #[serde(default)]
    shim_manifest_maps_repo: bool,
    #[serde(default = "preview_by_default")]
    dry_run: bool,
}

fn preview_by_default() -> bool {
    true
}

const COMMAND: &str = "onboard-github-bot";

/// One `github.handle.grant` the onboarding runs, with the parameters the
/// admin client's `handle-grant` sends for it.
struct GrantStep {
    /// `invoke`, `read` or `poll`.
    kind: &'static str,
    params: Value,
    /// The grant's dry-run plan, or `None` while the handle is not imported
    /// yet, when only its argument checks can run.
    preview: Option<Value>,
}

struct Plan {
    handle: InventoryHandle,
    inventory: Inventory,
    /// The stored handle's agent, app, installation, credential and status
    /// match the inventory, so it is not imported again.
    reuse: bool,
    /// The installation's repositories, read once while planning.
    installation: Vec<String>,
    import_preview: Option<Value>,
    /// Repositories the import binds: those its inventory grants name.
    imported_repositories: Vec<String>,
    repositories: Vec<String>,
    bind_preview: Option<Value>,
    grants: Vec<GrantStep>,
    /// Repositories this run binds that were not bound before it.
    newly_bound: Vec<String>,
    shim_manifest_maps_repo: bool,
    dry_run: bool,
}

/// Serve `plexus.admin.onboard_github_bot`.
pub(crate) async fn onboard(
    route: RouteFrameContext,
    params: &Value,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    principal: &str,
) -> Result<Value, ModuleError> {
    // Planning lists the installation with the handle's stored credential, as
    // the manual import, probe and bind do, so even a preview needs the
    // connector-home role.
    composite_admin::run(
        Caller {
            route,
            writer,
            state,
            route_bindings,
            method: manifest::ADMIN_ONBOARD_GITHUB_BOT_OP,
        },
        ConnectorHome::BeforePlanning,
        || crate::blocking_section(|| plan(state, principal, params)),
        |plan| apply(state, principal, plan),
    )
    .await
}

/// A control operation's refusal code, as its management operation returns
/// it.
fn control_refusal(code: &str, app_handle_id: &str) -> Value {
    crate::github_handle_refusal(code, app_handle_id)
}

fn plan(state: &Arc<ModuleState>, principal: &str, params: &Value) -> Result<Plan, Value> {
    let request = serde_json::from_value::<Request>(params.clone()).map_err(|_| {
        refusal(
            "invalid_request",
            "onboard_github_bot takes inventory, actions, carrier, effect and optional \
             repositories, read_actions, poll_actions, shim_manifest_maps_repo and dry_run",
        )
    })?;
    let [handle] = request.inventory.handles.as_slice() else {
        return Err(refusal(
            "inventory_single_handle_required",
            "the inventory must hold exactly the one handle being onboarded",
        ));
    };
    let handle = handle.clone();
    let id = handle.app_handle_id.clone();
    let actions = named_actions("actions", request.actions)?;
    let repositories = request
        .repositories
        .iter()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    let store = state.store();
    let stored = store.github_handle_and_bindings(&id).map_err(|error| {
        crate::wire::store_failure(
            "github handle read",
            "the GitHub handle could not be read",
            &error,
        )
    })?;
    let mut bound_before = BTreeSet::new();
    let reuse = match &stored {
        None => false,
        Some((existing, bindings)) => {
            let matches = existing.agent_id == handle.agent_id
                && existing.app_id == handle.app_id
                && existing.installation_id == handle.installation_id
                && existing.credential_reference == handle.credential_id
                && existing.status == handle.status;
            if !matches {
                return Err(refusal(
                    "github_handle_mismatch",
                    format!(
                        "handle {} is already imported with a different agent, app, installation, credential or status; nothing was changed",
                        diagnostic(&id)
                    ),
                ));
            }
            bound_before.extend(bindings.iter().cloned());
            true
        }
    };
    let Some(provider) = state.runtime.github_handle_credentials.as_ref() else {
        return Err(json!({"error":{"code":"handle_credential_unresolvable"}}));
    };
    // The one GitHub read: the import, the probe and the bind all reuse it.
    let reader = crate::github_control_reader(state);
    let installation = control::installation_repositories(
        store,
        &handle,
        provider.as_ref(),
        reader.as_ref(),
        plexus_core::storage::now_ms(),
    )
    .map_err(|code| control_refusal(&code, &id))?;
    let imported_repositories = handle
        .grants
        .iter()
        .map(|grant| plexus_core::github::canonical_repository(&grant.repository))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let import_preview = if reuse {
        None
    } else {
        let listings = BTreeMap::from([(id.clone(), installation.clone())]);
        Some(
            control::import_listed(store, principal, &request.inventory, &listings, true)
                .map_err(|code| control_refusal(&code, &id))?,
        )
    };
    let bind_preview = if repositories.is_empty() {
        None
    } else if reuse {
        Some(
            control::bind_listed(store, principal, &id, &repositories, &installation, true)
                .map_err(|code| control_refusal(&code, &id))?,
        )
    } else {
        Some(
            control::bind_after_import_preview(
                store,
                &handle,
                &imported_repositories,
                &repositories,
                &installation,
            )
            .map_err(|code| control_refusal(&code, &id))?,
        )
    };
    let mut grants = vec![GrantStep {
        kind: "invoke",
        params: json!({"app_handle_id": id, "actions": actions, "module": request.carrier,
            "effect": request.effect}),
        preview: None,
    }];
    if let Some(named) = request.read_actions {
        let actions = named_actions("read_actions", named)?;
        grants.push(GrantStep {
            kind: "read",
            params: json!({"kind": "read", "app_handle_id": id, "module": request.carrier,
                "actions": actions, "all_handles": false}),
            preview: None,
        });
    }
    if let Some(named) = request.poll_actions {
        let actions = named_actions("poll_actions", named)?;
        grants.push(GrantStep {
            kind: "poll",
            params: json!({"kind": "poll", "app_handle_id": id, "actions": actions}),
            preview: None,
        });
    }
    for grant in &mut grants {
        let mut params = grant.params.clone();
        params["dry_run"] = json!(true);
        let previewed = crate::github_handle_grant(state, principal, &params);
        match previewed.pointer("/error/code").and_then(Value::as_str) {
            None => grant.preview = previewed.get("result").cloned(),
            // Before the import the grant can check only its arguments; it
            // reports the missing handle once they pass.
            Some("agent_handle_unknown") if !reuse => {}
            Some(_) => return Err(previewed),
        }
    }
    let mut newly_bound = BTreeSet::new();
    if !reuse {
        newly_bound.extend(imported_repositories.iter().cloned());
    }
    if let Some(added) = bind_preview
        .as_ref()
        .and_then(|preview| preview["add"].as_array())
    {
        newly_bound.extend(added.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    newly_bound.retain(|repository| !bound_before.contains(repository));
    let newly_bound = newly_bound.into_iter().collect::<Vec<_>>();
    if !request.dry_run && !newly_bound.is_empty() && !request.shim_manifest_maps_repo {
        return Err(refusal(
            "shim_manifest_unconfirmed",
            format!(
                "binding {} changes what AFT's gh shim checks; confirm the active shim manifest maps them to agent {} with --shim-manifest-maps-repo; nothing was changed",
                prompt_list(&newly_bound),
                prompt_label(&handle.agent_id)
            ),
        ));
    }
    Ok(Plan {
        handle,
        inventory: request.inventory,
        reuse,
        installation,
        import_preview,
        imported_repositories,
        repositories,
        bind_preview,
        grants,
        newly_bound,
        shim_manifest_maps_repo: request.shim_manifest_maps_repo,
        dry_run: request.dry_run,
    })
}

fn grant_label(kind: &str) -> &'static str {
    match kind {
        "read" => "grant_reads",
        "poll" => "grant_poll",
        _ => "grant_writes",
    }
}

impl Plan {
    fn json(&self, steps: Vec<Value>) -> Value {
        json!({
            "operation": "onboard_github_bot",
            "app_handle_id": self.handle.app_handle_id,
            "agent_id": self.handle.agent_id,
            "connection_id": control::handle_connection_id(&self.handle.app_handle_id),
            "handle": if self.reuse { "reuse" } else { "import" },
            "installation_repositories": self.installation,
            "newly_bound": self.newly_bound,
            "shim_manifest_maps_repo": self.shim_manifest_maps_repo,
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
        let mut steps = vec![json!({
            "step": "import",
            "status": if self.reuse { "reuse" } else { "to_import" },
            "repositories": self.imported_repositories,
            "plan": self.import_preview,
        })];
        steps.push(json!({"step": "probe", "status": "to_probe"}));
        if let Some(bind) = &self.bind_preview {
            steps.push(json!({"step": "bind", "status": "to_bind", "plan": bind}));
        }
        for grant in &self.grants {
            steps.push(json!({
                "step": grant_label(grant.kind),
                "status": if grant.preview.is_some() { "planned" } else { "after_import" },
                "params": grant.params,
                "plan": grant.preview,
            }));
        }
        self.json(steps)
    }

    /// Keep the handle, agent and shim-manifest statement in the prompt;
    /// action lists remain in the preview and repositories are counted if needed.
    fn summary(&self) -> String {
        let handle = prompt_label(&self.handle.app_handle_id);
        let agent = prompt_label(&self.handle.agent_id);
        let mut parts = vec![if self.reuse {
            "reuse app".to_string()
        } else {
            format!("import app {}", self.handle.app_id)
        }];
        let repositories = self
            .imported_repositories
            .iter()
            .chain(&self.repositories)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut grants = Vec::new();
        for grant in &self.grants {
            let count = grant.params["actions"].as_array().map_or(0, Vec::len);
            grants.push(match grant.kind {
                "read" => format!("{count} reads"),
                "poll" => format!("{count} poll read"),
                _ => format!(
                    "{count} writes via {} ({})",
                    prompt_label(grant.params["module"].as_str().unwrap_or_default()),
                    prompt_label(grant.params["effect"].as_str().unwrap_or_default())
                ),
            });
        }
        let repo_index = parts.len();
        if !repositories.is_empty() {
            parts.push(format!("bind {}", prompt_list(&repositories)));
        }
        parts.push(format!("grant {}", grants.join(", ")));
        if !self.newly_bound.is_empty() {
            parts.push("you state AFT's manifest maps it".to_string());
        }
        let render = |parts: &[String]| {
            format!(
                "onboard bot {handle} for agent {agent}: {}",
                parts.join("; ")
            )
        };
        let named = render(&parts);
        if named.chars().count() <= 200 || repositories.is_empty() {
            return named;
        }
        parts[repo_index] = format!("bind {} repositories", repositories.len());
        render(&parts)
    }
}

/// Record a control step's audit row the way its management operation does.
/// A failed row is reported in the reply rather than undoing the step.
fn audit(
    state: &Arc<ModuleState>,
    principal: &str,
    app_handle_id: Option<&str>,
    method: &str,
    response: &Value,
    warnings: &mut Vec<Value>,
) {
    if let Err(error) = state.store().audit_github_control(
        principal,
        None,
        app_handle_id,
        method,
        &crate::fresh_request_id(),
        response.pointer("/error/code").and_then(Value::as_str),
    ) {
        let mut warned = json!({});
        crate::warn_audit_failed(&mut warned, method, &error);
        if let Some(warning) = warned.get("warning") {
            warnings.push(warning.clone());
        }
    }
}

fn failure(stage: &str, response: &Value, completed: &[Value], warnings: &[Value]) -> Value {
    let code = response
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("unknown_error");
    let mut failure = json!({"error": {
        "code": code,
        "stage": stage,
        "completed": completed,
        "message": format!(
            "{stage} failed ({code}); the steps listed as completed stay and the steps after it did not run. Rerun {COMMAND} to finish"
        ),
    }});
    if let Some(detail) = response.pointer("/error/detail") {
        failure["error"]["detail"] = detail.clone();
    }
    if !warnings.is_empty() {
        failure["warnings"] = json!(warnings);
    }
    failure
}

/// Run the confirmed plan through the control operations the manual commands
/// use, in their order: import, probe, bind, then each grant. The import,
/// probe and bind use the listing read while planning.
fn apply(state: &Arc<ModuleState>, principal: &str, plan: &Plan) -> Value {
    crate::blocking_section(|| apply_steps(state, principal, plan))
}

fn apply_steps(state: &Arc<ModuleState>, principal: &str, plan: &Plan) -> Value {
    let store = state.store();
    let id = plan.handle.app_handle_id.as_str();
    let wrap = |outcome: Result<Value, String>| match outcome {
        Ok(result) => json!({ "result": result }),
        Err(code) => control_refusal(&code, id),
    };
    let mut completed = Vec::new();
    let mut warnings = Vec::new();
    if plan.reuse {
        completed.push(json!({"step": "import", "status": "reused"}));
    } else {
        let listings = BTreeMap::from([(id.to_string(), plan.installation.clone())]);
        let imported = wrap(control::import_listed(
            store,
            principal,
            &plan.inventory,
            &listings,
            false,
        ));
        // The import request names no handle id, so its management
        // operation's audit row has none either.
        audit(
            state,
            principal,
            None,
            manifest::GITHUB_IMPORT_OP,
            &imported,
            &mut warnings,
        );
        if imported.get("error").is_some() {
            return failure("import", &imported, &completed, &warnings);
        }
        // The new connection row commits without running discovery, so its
        // REST transport has no config until this runs. A failure is logged
        // with the connection id and the import is kept.
        crate::register_handle_connection_transports(
            state,
            principal,
            &[control::handle_connection_id(id)],
        );
        completed.push(json!({"step": "import", "status": "imported", "plan": imported["result"]}));
    }
    let probed = wrap(control::probe_listed(
        store,
        principal,
        id,
        &plan.installation,
        plexus_core::storage::now_ms(),
    ));
    audit(
        state,
        principal,
        Some(id),
        manifest::GITHUB_PROBE_OP,
        &probed,
        &mut warnings,
    );
    if probed.get("error").is_some() {
        return failure("probe", &probed, &completed, &warnings);
    }
    completed.push(json!({"step": "probe", "status": "proven", "proof": probed["result"]}));
    if !plan.repositories.is_empty() {
        let bound = wrap(control::bind_listed(
            store,
            principal,
            id,
            &plan.repositories,
            &plan.installation,
            false,
        ));
        audit(
            state,
            principal,
            Some(id),
            manifest::GITHUB_BIND_OP,
            &bound,
            &mut warnings,
        );
        if bound.get("error").is_some() {
            return failure("bind", &bound, &completed, &warnings);
        }
        completed.push(json!({"step": "bind", "status": "bound", "plan": bound["result"]}));
    }
    for grant in &plan.grants {
        let mut params = grant.params.clone();
        params["dry_run"] = json!(false);
        let granted = crate::github_handle_grant(state, principal, &params);
        // A read upgrade audits inside its own transaction, so its management
        // operation appends no control row; the other grants do.
        if grant.kind != "read" {
            audit(
                state,
                principal,
                Some(id),
                manifest::GITHUB_GRANT_OP,
                &granted,
                &mut warnings,
            );
        }
        if granted.get("error").is_some() {
            return failure(grant_label(grant.kind), &granted, &completed, &warnings);
        }
        completed.push(json!({"step": grant_label(grant.kind), "status": "granted",
            "plan": granted["result"]}));
    }
    let mut result = plan.json(completed);
    result["dry_run"] = json!(false);
    result["applied"] = json!(true);
    let mut response = json!({ "result": result });
    if let Some(warning) = warnings.into_iter().next() {
        response["warning"] = warning;
    }
    response
}
