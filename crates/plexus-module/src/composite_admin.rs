//! The shared shape of an admin command that bundles several authority
//! changes under one operator confirmation.
//!
//! Done by hand, enrolling a connection or onboarding a bot takes several
//! management operations, and each one that widens authority asks the
//! operator for presence. A composite command instead plans every step,
//! refuses before asking when anything in the plan is wrong, asks exactly
//! once with a compact summary of the change, and then runs the same code paths
//! the manual commands use, so it writes the same rows. Without `dry_run:
//! false` it only previews: nothing is written and no vendor is contacted
//! beyond what planning itself must read.
//!
//! Each command supplies its plan and its apply step; [`run`] supplies the
//! order and the checks between them, so no command can ask twice or write
//! before asking.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{json, Value};
use subc_protocol::Frame;
use tokio::sync::mpsc;

use crate::{
    ceremony, operator_confirmation, FacadeArguments, ModuleError, ModuleState, RouteBindings,
    RouteFrameContext,
};

/// What a planned composite command offers [`run`].
pub(crate) trait Composite {
    /// Whether the caller asked only for a preview.
    fn dry_run(&self) -> bool;
    /// Everything an apply would do, for the preview reply.
    fn preview(&self) -> Value;
    /// The compact confirmation prompt names the change; the preview lists
    /// every item. The prompt never names a vault credential, instance address
    /// or secret.
    fn summary(&self) -> String;
}

/// Where the connector-home role is checked. The role fences every effect
/// that reaches a vendor with a stored credential, so the check runs before
/// the first such effect, and always before the operator is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectorHome {
    /// Planning itself reads a vendor with a stored credential (a GitHub
    /// installation listing), so even a preview needs the role, as the manual
    /// import, probe and bind do.
    BeforePlanning,
    /// Only an applied run contacts a vendor or enrolls a credential.
    BeforeApplying,
    /// None of the manual steps needs the role, so the composite does not.
    NotNeeded,
}

/// The management route a composite command was called on.
pub(crate) struct Caller<'a> {
    pub route: RouteFrameContext,
    pub writer: &'a mpsc::Sender<Frame>,
    pub state: &'a Arc<ModuleState>,
    pub route_bindings: &'a Arc<RouteBindings>,
    /// The management operation, named in a refusal's audit row.
    pub method: &'static str,
}

/// Plan, then preview or (with `dry_run: false`) ask once and apply.
///
/// A refusal from planning is returned before anyone is asked. A declined or
/// unavailable confirmation, or a route that closed while waiting, records
/// its audit row and applies nothing.
pub(crate) async fn run<P: Composite>(
    caller: Caller<'_>,
    home: ConnectorHome,
    plan: impl FnOnce() -> Result<P, Value>,
    apply: impl FnOnce(&P) -> Value,
) -> Result<Value, ModuleError> {
    let state = caller.state;
    if home == ConnectorHome::BeforePlanning {
        if let Some(refusal) = state.runtime.connector_home.refusal() {
            return Ok(refusal);
        }
    }
    let plan = match plan() {
        Ok(plan) => plan,
        Err(response) => return Ok(response),
    };
    if plan.dry_run() {
        return Ok(json!({ "result": plan.preview() }));
    }
    if home == ConnectorHome::BeforeApplying {
        if let Some(refusal) = state.runtime.connector_home.refusal() {
            return Ok(refusal);
        }
    }
    if let Err(refusal) = operator_confirmation::confirm(
        &plan.summary(),
        caller.route,
        caller.writer,
        &caller.route_bindings.control_replies,
    )
    .await
    {
        return Ok(operator_confirmation::audit_refusal(
            state,
            caller.method,
            &refusal,
        ));
    }
    if caller
        .route_bindings
        .binding(caller.route.channel, caller.route.epoch)?
        .is_none()
    {
        return Ok(operator_confirmation::audit_refusal(
            state,
            caller.method,
            &operator_confirmation::Refusal {
                code: "operator_confirmation_unavailable",
                reason: "the caller route closed while awaiting confirmation".to_string(),
            },
        ));
    }
    Ok(apply(&plan))
}

pub(crate) fn refusal(code: &str, message: impl Into<String>) -> Value {
    json!({"error": {"code": code, "message": message.into()}})
}

/// Bound caller-supplied text before it is echoed in a refusal.
pub(crate) fn diagnostic(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .take(60)
        .collect()
}

/// Restrict a caller-supplied label to identifier characters, so it cannot
/// add sentences or formatting to the confirmation prompt.
pub(crate) fn prompt_label(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_:./".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// A list of labels for a prompt or a preview line.
pub(crate) fn prompt_list<S: AsRef<str>>(values: &[S]) -> String {
    values
        .iter()
        .map(|value| prompt_label(value.as_ref()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Caller-named principals, in the order given and without repeats. A
/// wildcard would hand the authority to every principal, so it is refused.
pub(crate) fn named_principals(named: Vec<String>) -> Result<Vec<String>, Value> {
    let mut seen = BTreeSet::new();
    let mut principals = Vec::new();
    for principal in named {
        if principal.trim().is_empty() || principal.chars().any(char::is_whitespace) {
            return Err(refusal(
                "invalid_request",
                "each grantee must be a principal name without spaces",
            ));
        }
        if principal.contains('*') {
            return Err(refusal(
                "wildcard_grantee",
                "a wildcard grantee is never granted; name each caller",
            ));
        }
        if seen.insert(principal.clone()) {
            principals.push(principal);
        }
    }
    Ok(principals)
}

/// Explicit action names, in the order given and without repeats. A
/// composite names exactly what it grants, so a wildcard is refused.
pub(crate) fn named_actions(field: &str, named: Vec<String>) -> Result<Vec<String>, Value> {
    let mut seen = BTreeSet::new();
    let mut actions = Vec::new();
    for action in named {
        if action.trim().is_empty() || action.chars().any(char::is_whitespace) {
            return Err(refusal(
                "invalid_request",
                format!("each entry of {field} must be an action name without spaces"),
            ));
        }
        if action.contains('*') {
            return Err(refusal(
                "explicit_actions_required",
                format!("{field} must name each action; a wildcard is not accepted"),
            ));
        }
        if seen.insert(action.clone()) {
            actions.push(action);
        }
    }
    if actions.is_empty() {
        return Err(refusal(
            "invalid_request",
            format!("{field} must name at least one action"),
        ));
    }
    Ok(actions)
}

/// Whether a stored grant is in force and gives `grantee` `kind` authority at
/// `risk` over every one of `actions` on `connection_id`, so a rerun can
/// reuse it instead of minting a second one.
pub(crate) fn grant_covers(
    grant: &plexus_core::storage::GrantSummary,
    connection_id: &str,
    grantee: &str,
    kind: &str,
    risk: &str,
    actions: &[String],
) -> bool {
    grant.connection_id == connection_id
        && grant.grantee_principal == grantee
        && grant.authority_kind == kind
        && grant.risk_ceiling == risk
        && matches!(grant.state.as_str(), "live" | "until_revoked")
        && actions.iter().all(|action| {
            grant
                .action_selectors
                .iter()
                .any(|selector| selector == action || selector == "*")
        })
}

/// What exists after a failed step, for the operator deciding what to do next.
pub(crate) fn existing_connection(
    state: &Arc<ModuleState>,
    principal: &str,
    connection_id: &str,
) -> String {
    match state.store().connection(principal, connection_id) {
        Ok(Some(connection)) => format!("connection {connection_id} is {}", connection.status),
        Ok(None) => format!("no connection {connection_id} exists"),
        Err(_) => format!("the state of connection {connection_id} could not be read"),
    }
}

/// A step of an applied composite failed. The reply keeps the step's own
/// code, says where the connection stands and what was not done, and names
/// the command whose rerun finishes the job.
pub(crate) fn step_failure(
    state: &Arc<ModuleState>,
    principal: &str,
    connection_id: &str,
    stage: &str,
    not_done: &str,
    command: &str,
    response: &Value,
) -> Value {
    let code = response
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("unknown_error");
    let message = response
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("no message");
    json!({"error": {
        "code": code,
        "stage": stage,
        "connection_id": connection_id,
        "message": format!(
            "{stage} failed ({message}); {}; {not_done}. Rerun {command} to finish",
            existing_connection(state, principal, connection_id)
        ),
    }})
}

/// How far a connection's discovery got: `complete`, or another outcome
/// with an optional reason.
pub(crate) struct Discovery {
    pub outcome: String,
    pub reason: Option<Value>,
}

/// Activate a connection the way the manual commands do: issue the binding
/// ticket `ticket` describes, then redeem it with `connections op=connect`,
/// which runs discovery and so may contact the vendor. The error reply names
/// the failed stage.
pub(crate) fn issue_and_connect(
    state: &Arc<ModuleState>,
    principal: &str,
    ticket: &Value,
) -> Result<Discovery, (&'static str, Value)> {
    let issued = ceremony::issue_ticket(state, principal, ticket);
    let Some(ticket_id) = issued.pointer("/result/ticket_id").and_then(Value::as_str) else {
        return Err(("ticket", issued));
    };
    let arguments = json!({"op": "connect", "ticket_id": ticket_id});
    let connected = crate::facade_connections_connect(&FacadeArguments {
        state,
        arguments: arguments
            .as_object()
            .expect("connect arguments are an object"),
        principal_key: principal,
        op: Some("connect"),
    })
    .unwrap_or_else(|error| refusal("connect_failed", error.to_string()));
    let Some(result) = connected.get("result") else {
        return Err(("connect", connected));
    };
    Ok(Discovery {
        outcome: result["discovery"]
            .as_str()
            .unwrap_or("degraded")
            .to_string(),
        reason: result.get("reason").cloned(),
    })
}

/// Discovery again for a connection that is already active, as connect runs
/// it, so a rerun after a failed discovery can finish.
pub(crate) fn rediscover(
    state: &Arc<ModuleState>,
    principal: &str,
    connection_id: &str,
    app_key: &str,
) -> Discovery {
    let (outcome, reason) = crate::connect_time_catalog(state, principal, connection_id, app_key);
    Discovery {
        outcome: outcome.to_string(),
        reason: reason.map(Value::String),
    }
}

/// The reply when discovery did not complete: the connection stays, and no
/// later step ran.
pub(crate) fn discovery_incomplete(
    state: &Arc<ModuleState>,
    principal: &str,
    connection_id: &str,
    discovery: &Discovery,
    not_done: &str,
    command: &str,
) -> Value {
    json!({"error": {
        "code": "discovery_incomplete",
        "stage": "discovery",
        "connection_id": connection_id,
        "discovery": discovery.outcome,
        "reason": discovery.reason,
        "message": format!(
            "{}, but discovery is {}; {not_done}. Fix the cause, then rerun {command} to finish",
            existing_connection(state, principal, connection_id),
            discovery.outcome,
        ),
    }})
}
