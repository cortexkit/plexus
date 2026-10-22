//! Enroll one connection and the authority that uses it under a single
//! operator confirmation: `plexus.admin.add_write_connection` and
//! `plexus.admin.add_poll_connection`.
//!
//! By hand, a write-capable connection takes a binding ticket, its
//! redemption with `connections op=connect`, a `connection_admin` grant to
//! `direct`, `connections op=configure` with the resource filters, one invoke
//! grant per agent and optionally an allow policy; a polled connection takes
//! the ticket, the connect, a poll grant and one `events_consume` grant per
//! consumer. Each ticket, grant and allow policy asks the operator for
//! presence. These ceremonies plan all of it, ask once, and then run the same
//! code paths the manual commands use, so they write the same rows.
//!
//! Connecting runs discovery, which can contact the vendor, so it cannot share
//! a transaction with the steps after it. Those run only after the connection
//! is active and discovery completed, and a rerun is safe: an existing
//! connection with the same app, credential and a ceiling covering the
//! request is reused, and grants, filters and policies that already exist are
//! not written again. Anything that does not match is refused by name before
//! anyone is asked.

use std::sync::Arc;

use plexus_core::Risk;
use serde_json::{json, Value};
use subc_protocol::Frame;
use tokio::sync::mpsc;

use crate::composite_admin::{
    self, diagnostic, named_actions, named_principals, prompt_label, prompt_list, refusal, Caller,
    Composite, ConnectorHome,
};
use crate::{
    ceremony, manifest, FacadeArguments, ModuleError, ModuleState, RouteBindings, RouteFrameContext,
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteRequest {
    app_key: String,
    #[serde(default)]
    connection_id: Option<String>,
    #[serde(default)]
    credential_id: Option<String>,
    #[serde(default = "write_risk")]
    risk: String,
    actions: Vec<String>,
    grantees: Vec<String>,
    #[serde(default)]
    invoke_actions: Option<Vec<String>>,
    #[serde(default)]
    resource_filters: Option<Value>,
    #[serde(default)]
    allow_actions: Option<Vec<String>>,
    #[serde(default = "preview_by_default")]
    dry_run: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PollRequest {
    app_key: String,
    #[serde(default)]
    connection_id: Option<String>,
    #[serde(default)]
    credential_id: Option<String>,
    actions: Vec<String>,
    #[serde(default)]
    consumers: Vec<String>,
    #[serde(default)]
    consume_actions: Option<Vec<String>>,
    #[serde(default = "preview_by_default")]
    dry_run: bool,
}

fn write_risk() -> String {
    "write".to_string()
}

fn preview_by_default() -> bool {
    true
}

/// Which of the two ceremonies a plan belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Write,
    Poll,
}

impl Purpose {
    fn command(self) -> &'static str {
        match self {
            Self::Write => "add-write-connection",
            Self::Poll => "add-poll-connection",
        }
    }

    fn operation(self) -> &'static str {
        match self {
            Self::Write => "add_write_connection",
            Self::Poll => "add_poll_connection",
        }
    }

    fn method(self) -> &'static str {
        match self {
            Self::Write => manifest::ADMIN_ADD_WRITE_CONNECTION_OP,
            Self::Poll => manifest::ADMIN_ADD_POLL_CONNECTION_OP,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionStep {
    /// No connection with this id exists yet.
    Create,
    /// A pending connection exists (a ticket was issued but not redeemed); a
    /// new ticket replaces the old one and is redeemed.
    Reenroll,
    /// An active connection with the same app and credential, whose ceiling
    /// covers the request, exists; it is kept and only discovery and the
    /// missing steps run.
    Reuse,
}

impl ConnectionStep {
    fn label(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Reenroll => "reenroll",
            Self::Reuse => "reuse",
        }
    }
}

/// One write after the connection is active, in the order it runs.
#[derive(Debug, Clone)]
enum Step {
    Grant {
        grantee: String,
        kind: &'static str,
        risk: String,
        actions: Vec<String>,
    },
    /// The requested filters, as `configure` takes them, and the document
    /// `configure` would store for them.
    Filters {
        requested: Value,
        stored: Value,
    },
    AllowPolicy {
        action: String,
    },
}

/// Whether a step still has to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    ToDo,
    AlreadyDone,
}

struct Plan {
    purpose: Purpose,
    app_key: String,
    connection_id: String,
    credential: Option<String>,
    /// The ceiling the ticket requests, or for a reused connection the one it
    /// already records.
    ceiling_risk: String,
    ceiling_actions: Vec<String>,
    step: ConnectionStep,
    steps: Vec<Step>,
    statuses: Vec<Status>,
    dry_run: bool,
}

/// Serve `plexus.admin.add_write_connection`.
pub(crate) async fn add_write(
    route: RouteFrameContext,
    params: &Value,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    principal: &str,
) -> Result<Value, ModuleError> {
    serve(
        Purpose::Write,
        route,
        writer,
        state,
        route_bindings,
        principal,
        || plan_write(state, principal, params),
    )
    .await
}

/// Serve `plexus.admin.add_poll_connection`.
pub(crate) async fn add_poll(
    route: RouteFrameContext,
    params: &Value,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    principal: &str,
) -> Result<Value, ModuleError> {
    serve(
        Purpose::Poll,
        route,
        writer,
        state,
        route_bindings,
        principal,
        || plan_poll(state, principal, params),
    )
    .await
}

async fn serve(
    purpose: Purpose,
    route: RouteFrameContext,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    principal: &str,
    plan: impl FnOnce() -> Result<Plan, Value>,
) -> Result<Value, ModuleError> {
    // Planning reads the store only: no vault read, no ticket, no vendor
    // request. Redeeming the ticket enrolls a stored credential and contacts
    // the vendor, so an applied run needs the connector-home role.
    composite_admin::run(
        Caller {
            route,
            writer,
            state,
            route_bindings,
            method: purpose.method(),
        },
        ConnectorHome::BeforeApplying,
        plan,
        |plan| apply(state, principal, plan),
    )
    .await
}

fn plan_write(state: &Arc<ModuleState>, principal: &str, params: &Value) -> Result<Plan, Value> {
    let request = serde_json::from_value::<WriteRequest>(params.clone()).map_err(|_| {
        refusal(
            "invalid_request",
            "add_write_connection takes app_key, actions, grantees and optional \
             connection_id, credential_id, risk, invoke_actions, resource_filters, \
             allow_actions and dry_run",
        )
    })?;
    if !matches!(request.risk.as_str(), "write" | "destructive") {
        return Err(refusal(
            "invalid_request",
            "risk must be write or destructive; enroll a read-only connection with issue-ticket",
        ));
    }
    let actions = named_actions("actions", request.actions)?;
    let grantees = named_principals(request.grantees)?;
    if grantees.is_empty() {
        return Err(refusal(
            "grantees_required",
            "name each agent that may use the connection with --grantee",
        ));
    }
    let invoke_actions = match request.invoke_actions {
        Some(named) => named_actions("invoke_actions", named)?,
        None => actions.clone(),
    };
    let allow_actions = match request.allow_actions {
        Some(named) => named_actions("allow_actions", named)?,
        None => Vec::new(),
    };
    let mut plan = plan_enrollment(
        state,
        principal,
        Purpose::Write,
        &request.app_key,
        request.connection_id,
        request.credential_id,
        &request.risk,
        actions,
        request.dry_run,
    )?;
    let risk = plan.ceiling_risk.clone();
    plan.steps.push(Step::Grant {
        grantee: principal.to_string(),
        kind: "connection_admin",
        risk: risk.clone(),
        actions: plan.ceiling_actions.clone(),
    });
    if let Some(requested) = request.resource_filters {
        let stored = match state
            .store()
            .resource_filters_for_app(&plan.app_key, &requested)
        {
            Ok(Ok(stored)) => stored,
            Ok(Err(outcome)) => return Err(crate::configure_outcome_response(Ok(outcome))),
            Err(error) => return Err(crate::configure_outcome_response(Err(error))),
        };
        plan.steps.push(Step::Filters { requested, stored });
    }
    for grantee in grantees {
        plan.steps.push(Step::Grant {
            grantee,
            kind: "invoke",
            risk: risk.clone(),
            actions: invoke_actions.clone(),
        });
    }
    for action in allow_actions {
        if !plan.ceiling_actions.contains(&action) {
            return Err(refusal(
                "action_outside_ceiling",
                format!(
                    "allow policy action {} is not in the connection ceiling; nothing was changed",
                    diagnostic(&action)
                ),
            ));
        }
        plan.steps.push(Step::AllowPolicy { action });
    }
    finish(state, principal, plan)
}

fn plan_poll(state: &Arc<ModuleState>, principal: &str, params: &Value) -> Result<Plan, Value> {
    let request = serde_json::from_value::<PollRequest>(params.clone()).map_err(|_| {
        refusal(
            "invalid_request",
            "add_poll_connection takes app_key, actions and optional connection_id, \
             credential_id, consumers, consume_actions and dry_run",
        )
    })?;
    let actions = named_actions("actions", request.actions)?;
    let consumers = named_principals(request.consumers)?;
    let consume_actions = match (request.consume_actions, consumers.is_empty()) {
        (Some(named), false) => named_actions("consume_actions", named)?,
        (None, false) => {
            return Err(refusal(
                "invalid_request",
                "consume_actions names the actions whose events each consumer may read",
            ))
        }
        (Some(_), true) => {
            return Err(refusal(
                "invalid_request",
                "consume_actions applies only with at least one consumer",
            ))
        }
        (None, true) => Vec::new(),
    };
    let mut plan = plan_enrollment(
        state,
        principal,
        Purpose::Poll,
        &request.app_key,
        request.connection_id,
        request.credential_id,
        "read",
        actions.clone(),
        request.dry_run,
    )?;
    // The subscriptions a poll runs for belong to the connection's owner, so
    // the poll grant goes to the operator principal itself.
    plan.steps.push(Step::Grant {
        grantee: principal.to_string(),
        kind: plexus_core::AUTHORITY_POLL,
        risk: "read".to_string(),
        actions,
    });
    for consumer in consumers {
        plan.steps.push(Step::Grant {
            grantee: consumer,
            kind: plexus_core::AUTHORITY_EVENTS_CONSUME,
            risk: "read".to_string(),
            actions: consume_actions.clone(),
        });
    }
    finish(state, principal, plan)
}

/// Check every grant against the ceiling it will be minted under, then read
/// which steps an earlier run already did.
fn finish(state: &Arc<ModuleState>, principal: &str, mut plan: Plan) -> Result<Plan, Value> {
    let ceiling_risk = Risk::parse(&plan.ceiling_risk);
    for step in &plan.steps {
        let Step::Grant { risk, actions, .. } = step else {
            continue;
        };
        if let Some(outside) = actions
            .iter()
            .find(|action| !plan.ceiling_actions.contains(action))
        {
            return Err(refusal(
                "action_outside_ceiling",
                format!(
                    "{} is not in the connection ceiling; nothing was changed",
                    diagnostic(outside)
                ),
            ));
        }
        let within = match (Risk::parse(risk), ceiling_risk) {
            (Some(requested), Some(ceiling)) => requested.within(ceiling),
            _ => false,
        };
        if !within {
            return Err(refusal(
                "risk_above_ceiling",
                format!(
                    "a {risk} grant does not fit the connection's {} ceiling; nothing was changed",
                    plan.ceiling_risk
                ),
            ));
        }
    }
    plan.statuses = match plan.step {
        ConnectionStep::Create => vec![Status::ToDo; plan.steps.len()],
        ConnectionStep::Reenroll | ConnectionStep::Reuse => {
            statuses(state, principal, &plan.connection_id, &plan.steps)?
        }
    };
    Ok(plan)
}

/// Validate the connection half of a request and decide whether to create,
/// re-enroll or reuse the connection. Refuses, writing nothing, when an
/// existing connection belongs to another app, is revoked, is bound to a
/// different credential, or records a ceiling that does not cover the
/// request.
#[allow(clippy::too_many_arguments)]
fn plan_enrollment(
    state: &Arc<ModuleState>,
    principal: &str,
    purpose: Purpose,
    app_key: &str,
    connection_id: Option<String>,
    credential_id: Option<String>,
    risk: &str,
    actions: Vec<String>,
    dry_run: bool,
) -> Result<Plan, Value> {
    let store = state.store();
    let read_failure = |error: &dyn std::fmt::Display| {
        crate::wire::store_failure(
            "connection plan read",
            "the app's manifest or the connection could not be read",
            &error.to_string(),
        )
    };
    // The reviewed manifest bounds the ticket; this is the check the ticket
    // itself makes first.
    match store.ceiling_within_manifest(app_key, risk, &actions) {
        Ok(Ok(_)) => {}
        Ok(Err(refused)) => return Err(ceremony::refusal_response(&refused)),
        Err(error) => return Err(read_failure(&error)),
    }
    if store
        .manifest_takes_instance_url(app_key)
        .map_err(|error| read_failure(&error))?
    {
        return Err(refusal(
            "instance_url_unsupported",
            "this app needs an instance address; enroll it with issue-ticket",
        ));
    }
    let credential_free = store
        .manifest_requires_no_credential(app_key)
        .map_err(|error| read_failure(&error))?;
    let optional_credential = store
        .manifest_has_optional_credential(app_key)
        .map_err(|error| read_failure(&error))?;
    match (&credential_id, credential_free, optional_credential) {
        (Some(_), true, _) => {
            return Err(refusal(
                "invalid_request",
                "this app requires no credential; do not supply credential_id",
            ))
        }
        (Some(id), false, _) if !plexus_core::credentials::valid_credential_id(id) => {
            return Err(refusal(
                "invalid_request",
                "credential_id is not a well-formed vault reference",
            ))
        }
        (None, false, false) => {
            return Err(refusal(
                "credential_required",
                "this app needs a vault credential; supply credential_id",
            ))
        }
        _ => {}
    }
    let connection_id = connection_id.unwrap_or_else(|| format!("conn-{app_key}"));
    if connection_id.trim().is_empty() || connection_id.chars().any(char::is_whitespace) {
        return Err(refusal(
            "invalid_request",
            "connection_id must be an identifier without spaces",
        ));
    }
    let mut plan = Plan {
        purpose,
        app_key: app_key.to_string(),
        connection_id: connection_id.clone(),
        credential: credential_id.clone(),
        ceiling_risk: risk.to_string(),
        ceiling_actions: actions,
        step: ConnectionStep::Create,
        steps: Vec::new(),
        statuses: Vec::new(),
        dry_run,
    };
    let Some(existing) = store
        .connection(principal, &connection_id)
        .map_err(|error| read_failure(&error))?
    else {
        return Ok(plan);
    };
    let id = diagnostic(&connection_id);
    if existing.app_key != app_key {
        return Err(refusal(
            "connection_app_mismatch",
            format!(
                "connection {id} exists for app {}, not {}; nothing was changed",
                diagnostic(&existing.app_key),
                diagnostic(app_key)
            ),
        ));
    }
    if existing.status == "revoked" {
        return Err(refusal(
            "connection_revoked",
            format!("connection {id} is revoked and cannot be enrolled again; nothing was changed"),
        ));
    }
    let bound = store
        .connection_credential_reference(principal, &connection_id)
        .map_err(|error| read_failure(&error))?;
    // A pending connection may not have a binding yet; any binding it has
    // must be the one this run asks for.
    if (existing.status != "pending" || bound.is_some()) && bound != credential_id {
        return Err(refusal(
            "connection_credential_mismatch",
            format!(
                "connection {id} is bound to a different credential than the one supplied; nothing was changed"
            ),
        ));
    }
    let recorded = store
        .connection_ceiling(principal, &connection_id)
        .map_err(|error| read_failure(&error))?;
    let requested = plan.ceiling_actions.clone();
    let covers = |ceiling: &plexus_core::Ceiling| {
        Risk::parse(risk).is_some_and(|wanted| wanted.within(ceiling.risk))
            && requested.iter().all(|action| {
                ceiling
                    .action_selectors
                    .iter()
                    .any(|selector| selector == action)
            })
    };
    let mismatch = || {
        refusal(
            "connection_ceiling_mismatch",
            format!(
                "connection {id} records a ceiling that does not cover {risk} on {}; widen it with widen-and-grant first; nothing was changed",
                prompt_list(&requested)
            ),
        )
    };
    match (existing.status.as_str(), recorded) {
        // A pending connection with no recorded ceiling takes the new one.
        ("pending", Ok(ceiling)) if !covers(&ceiling) => Err(mismatch()),
        ("pending", _) => {
            plan.step = ConnectionStep::Reenroll;
            Ok(plan)
        }
        (_, Ok(ceiling)) if covers(&ceiling) => {
            plan.step = ConnectionStep::Reuse;
            plan.ceiling_risk = ceiling.risk.to_string();
            plan.ceiling_actions = ceiling.action_selectors;
            Ok(plan)
        }
        _ => Err(mismatch()),
    }
}

/// Which steps an earlier run (or the operator by hand) already did on the
/// connection. A filter document or a policy that differs from the request
/// is refused rather than overwritten.
fn statuses(
    state: &Arc<ModuleState>,
    principal: &str,
    connection_id: &str,
    steps: &[Step],
) -> Result<Vec<Status>, Value> {
    let store = state.store();
    let read_failure = |error: &dyn std::fmt::Display| {
        crate::wire::store_failure(
            "connection authority read",
            "the connection's grants, filters or policies could not be read",
            &error.to_string(),
        )
    };
    let grants = store
        .list_all_grants(principal)
        .map_err(|error| read_failure(&error))?;
    let policies = store
        .list_policies(principal, Some(connection_id))
        .map_err(|error| read_failure(&error))?;
    let filters = store
        .connection(principal, connection_id)
        .map_err(|error| read_failure(&error))?
        .map(|connection| connection.resource_filters);
    let id = diagnostic(connection_id);
    steps
        .iter()
        .map(|step| match step {
            Step::Grant {
                grantee,
                kind,
                risk,
                actions,
            } => Ok(
                if grants.iter().any(|grant| {
                    composite_admin::grant_covers(grant, connection_id, grantee, kind, risk, actions)
                }) {
                    Status::AlreadyDone
                } else {
                    Status::ToDo
                },
            ),
            Step::Filters { stored, .. } => match &filters {
                Some(current) if current == stored => Ok(Status::AlreadyDone),
                // A connection starts with an empty filter document.
                Some(current) if current == &json!({}) => Ok(Status::ToDo),
                None => Ok(Status::ToDo),
                Some(_) => Err(refusal(
                    "resource_filters_mismatch",
                    format!(
                        "connection {id} already has different resource filters; nothing was changed"
                    ),
                )),
            },
            Step::AllowPolicy { action } => {
                match policies
                    .iter()
                    .find(|policy| &policy.action_selector == action)
                {
                    None => Ok(Status::ToDo),
                    Some(policy) if policy.effect == "allow" && policy.expires_at.is_none() => {
                        Ok(Status::AlreadyDone)
                    }
                    Some(policy) => Err(refusal(
                        "policy_mismatch",
                        format!(
                            "connection {id} already has a {} policy on {}; nothing was changed",
                            diagnostic(&policy.effect),
                            diagnostic(action)
                        ),
                    )),
                }
            }
        })
        .collect()
}

impl Step {
    /// The step's preview or result row.
    fn json(&self, status: &str) -> Value {
        match self {
            Self::Grant {
                grantee,
                kind,
                risk,
                actions,
            } => json!({
                "step": "grant",
                "grantee": grantee,
                "authority_kind": kind,
                "risk_ceiling": risk,
                "action_selectors": actions,
                "status": status,
            }),
            Self::Filters { stored, .. } => json!({
                "step": "resource_filters",
                "resource_filters": stored,
                "status": status,
            }),
            Self::AllowPolicy { action } => json!({
                "step": "policy",
                "action_selector": action,
                "effect": "allow",
                "status": status,
            }),
        }
    }

    /// The step's part of the confirmation prompt.
    fn summary(&self) -> String {
        match self {
            Self::Grant {
                grantee,
                kind,
                risk,
                actions,
            } => format!(
                "grant {kind} {risk} on {} to {}",
                prompt_list(actions),
                prompt_label(grantee)
            ),
            Self::Filters { stored, .. } => {
                let mut parts = Vec::new();
                if let Some(keys) = stored["write_enabling"].as_array() {
                    let keys = keys
                        .iter()
                        .map(|key| key.as_str().unwrap_or_default())
                        .collect::<Vec<_>>();
                    parts.push(format!("write_enabling {}", prompt_list(&keys)));
                }
                if let Some(values) = stored["values"].as_object() {
                    for (key, value) in values {
                        let value = match value {
                            Value::String(text) => text.clone(),
                            other => other.to_string(),
                        };
                        parts.push(format!("{}={}", prompt_label(key), prompt_label(&value)));
                    }
                }
                format!("set resource filters {}", parts.join(" "))
            }
            Self::AllowPolicy { action } => {
                format!("allow {} without asking", prompt_label(action))
            }
        }
    }
}

fn pending_label(step: &Step) -> &'static str {
    match step {
        Step::Grant { .. } => "to_mint",
        Step::Filters { .. } | Step::AllowPolicy { .. } => "to_set",
    }
}

fn done_label(step: &Step) -> &'static str {
    match step {
        Step::Grant { .. } => "already_present",
        Step::Filters { .. } | Step::AllowPolicy { .. } => "unchanged",
    }
}

impl Plan {
    fn json(&self, rows: Vec<Value>) -> Value {
        let mut plan = json!({
            "operation": self.purpose.operation(),
            "app_key": self.app_key,
            "connection_id": self.connection_id,
            "connection": self.step.label(),
            "credential": self.credential,
            "ceiling": {"risk": self.ceiling_risk, "action_selectors": self.ceiling_actions},
            "steps": rows,
            "summary": self.summary(),
            "dry_run": self.dry_run,
            "applied": false,
        });
        if self.step == ConnectionStep::Reuse {
            plan["ceiling_note"] = json!("the existing connection keeps its recorded ceiling");
        }
        plan
    }
}

impl Composite for Plan {
    fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// Everything an apply would do, with the credential named but never
    /// resolved.
    fn preview(&self) -> Value {
        let rows = self
            .steps
            .iter()
            .zip(&self.statuses)
            .map(|(step, status)| {
                step.json(match status {
                    Status::ToDo => pending_label(step),
                    Status::AlreadyDone => done_label(step),
                })
            })
            .collect();
        self.json(rows)
    }

    /// One line naming every change: the connection, how it authenticates,
    /// its ceiling and every later step. It never names the vault reference.
    fn summary(&self) -> String {
        let connect = match self.step {
            ConnectionStep::Create => "connect",
            ConnectionStep::Reenroll => "re-enroll and connect",
            ConnectionStep::Reuse => "reuse",
        };
        let auth = match self.credential {
            Some(_) => "using your stored credential",
            None => "anonymous",
        };
        let ceiling = if self.step == ConnectionStep::Reuse {
            "keeping its ceiling".to_string()
        } else {
            format!(
                "ceiling {} on {}",
                self.ceiling_risk,
                prompt_list(&self.ceiling_actions)
            )
        };
        let steps = self
            .steps
            .iter()
            .zip(&self.statuses)
            .map(|(step, status)| match status {
                Status::ToDo => step.summary(),
                Status::AlreadyDone => format!("{} (already done)", step.summary()),
            })
            .collect::<Vec<_>>()
            .join("; ");
        format!(
            "{} {}: {connect} for {}, {auth}, {ceiling}; {steps}",
            self.purpose.operation().replace('_', " "),
            prompt_label(&self.connection_id),
            prompt_label(&self.app_key),
        )
    }
}

/// Run the confirmed plan through the paths the manual commands use: the
/// ticket ceremony, the facade connect (with its discovery), then the grants,
/// `configure` and policies in plan order.
fn apply(state: &Arc<ModuleState>, principal: &str, plan: &Plan) -> Value {
    let connection_id = plan.connection_id.as_str();
    let command = plan.purpose.command();
    let discovery = match plan.step {
        ConnectionStep::Create | ConnectionStep::Reenroll => {
            let mut ticket = json!({
                "app_key": plan.app_key,
                "connection_id": connection_id,
                "risk_ceiling": plan.ceiling_risk,
                "action_selectors": plan.ceiling_actions,
            });
            if let Some(credential) = &plan.credential {
                ticket["credential_id"] = json!(credential);
            }
            match composite_admin::issue_and_connect(state, principal, &ticket) {
                Ok(discovery) => discovery,
                Err((stage, response)) => {
                    return composite_admin::step_failure(
                        state,
                        principal,
                        connection_id,
                        stage,
                        "no later step ran",
                        command,
                        &response,
                    )
                }
            }
        }
        ConnectionStep::Reuse => {
            composite_admin::rediscover(state, principal, connection_id, &plan.app_key)
        }
    };
    if discovery.outcome != "complete" {
        return composite_admin::discovery_incomplete(
            state,
            principal,
            connection_id,
            &discovery,
            "no later step ran",
            command,
        );
    }
    // Read again after connecting: a step done since the plan was made must
    // not be done a second time.
    let statuses = match statuses(state, principal, connection_id, &plan.steps) {
        Ok(statuses) => statuses,
        Err(response) => return response,
    };
    let mut rows = Vec::with_capacity(plan.steps.len());
    for (step, status) in plan.steps.iter().zip(statuses) {
        if status == Status::AlreadyDone {
            rows.push(step.json(done_label(step)));
            continue;
        }
        let (stage, response) = match step {
            Step::Grant {
                grantee,
                kind,
                risk,
                actions,
            } => (
                "grant",
                ceremony::grant(
                    state,
                    principal,
                    &json!({
                        "connection_id": connection_id,
                        "grantee_principal": grantee,
                        "authority_kind": kind,
                        "risk_ceiling": risk,
                        "action_selectors": actions,
                    }),
                ),
            ),
            Step::Filters { requested, .. } => {
                let arguments = json!({
                    "op": "configure",
                    "connection": connection_id,
                    "resource_filters": requested,
                });
                (
                    "configure",
                    crate::facade_connections_configure(&FacadeArguments {
                        state,
                        arguments: arguments
                            .as_object()
                            .expect("configure arguments are an object"),
                        principal_key: principal,
                        op: Some("configure"),
                    })
                    .unwrap_or_else(|error| refusal("configure_failed", error.to_string())),
                )
            }
            Step::AllowPolicy { action } => (
                "policy",
                ceremony::set_policy(
                    state,
                    principal,
                    &json!({
                        "connection_id": connection_id,
                        "action_selector": action,
                        "effect": "allow",
                    }),
                ),
            ),
        };
        if response.get("error").is_some() {
            let mut failure = composite_admin::step_failure(
                state,
                principal,
                connection_id,
                stage,
                "the steps after it did not run",
                command,
                &response,
            );
            failure["error"]["completed"] = json!(rows);
            return failure;
        }
        let mut row = step.json(match step {
            Step::Grant { .. } => "minted",
            Step::Filters { .. } | Step::AllowPolicy { .. } => "set",
        });
        if let Some(id) = response.pointer("/result/grant/grant_id") {
            row["grant_id"] = id.clone();
        }
        rows.push(row);
    }
    let mut result = plan.json(rows);
    result["dry_run"] = json!(false);
    result["applied"] = json!(true);
    result["discovery"] = json!(discovery.outcome);
    json!({ "result": result })
}
