//! `permissions.list` and `permissions.revoke`, the `permissions/v1` provider
//! operations cingulate calls to show and end an agent's GitHub bot grants.
//!
//! They arrive as `{method, params}` route requests, like `grants.would_ask`,
//! and are never facade tools. The rows and the revoke are in
//! `plexus_core::permissions`; this file admits the caller and checks the
//! request.
use super::*;
use plexus_core::permissions::{self as core_permissions, RevokeOutcome};

pub(super) const OPERATOR_REQUIRED: &str = "permissions_operator_required";
/// The message of the refusal in the permissions/v1 contract's test vector
/// `provider-revoke-refused-agent.json`, so a caller logging it sees the same
/// sentence from every provider.
const OPERATOR_REQUIRED_MESSAGE: &str =
    "permissions operations need reserved:cingulate or the local operator's direct route";

pub(super) fn is_method(method: &str) -> bool {
    matches!(
        method,
        core_permissions::LIST_METHOD | core_permissions::REVOKE_METHOD
    )
}

/// Listing and revoking grants is operator authority. Only cingulate, which
/// serves the operator's permissions page, and the local operator's `direct`
/// route are admitted. A flow or a codemode run carries an agent's work, not
/// the operator's, so a route bound for either is refused even when its
/// principal would otherwise be admitted.
fn admitted(caller: &str, mode: Option<&CallMode>, scope: Option<&CallScope>) -> bool {
    matches!(caller, "direct" | "reserved:cingulate")
        && mode == Some(&CallMode::Classic)
        && !scope.is_some_and(|scope| scope.flow_id.is_some())
}

fn invalid(field: &str, reason: &str) -> Value {
    json!({"error":{"code":"invalid_request", "field":field, "reason":reason, "message":format!("{reason}: {field}")}})
}

/// The one string field `name` of `params`: `Ok(None)` when absent, a refusal
/// when present but not a non-empty string.
fn string_param<'a>(
    params: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<&'a str>, Value> {
    match params.get(name) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value)),
        Some(_) => Err(invalid(name, "string_required")),
    }
}

pub(super) fn run(
    state: &ModuleState,
    caller: &str,
    mode: Option<&CallMode>,
    scope: Option<&CallScope>,
    method: &str,
    request: &serde_json::Map<String, Value>,
) -> Value {
    if !admitted(caller, mode, scope) {
        eprintln!(info wire: "{method} refused: caller {caller} is not the operator (mode {mode:?}, flow {})",
            scope.and_then(|scope| scope.flow_id.as_deref()).unwrap_or("none"));
        return tool_error(OPERATOR_REQUIRED, OPERATOR_REQUIRED_MESSAGE);
    }
    if let Some(field) = request
        .keys()
        .find(|field| !matches!(field.as_str(), "method" | "params"))
    {
        return invalid(field, "unknown_field");
    }
    let empty = serde_json::Map::new();
    let params = match request.get("params") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(params)) => params,
        Some(_) => return invalid("params", "object_required"),
    };
    let known: &[&str] = if method == core_permissions::LIST_METHOD {
        &["agent_id"]
    } else {
        &["id"]
    };
    if let Some(field) = params.keys().find(|field| !known.contains(&field.as_str())) {
        return invalid(field, "unknown_field");
    }
    let now = plexus_core::storage::now_ms();
    if method == core_permissions::LIST_METHOD {
        let agent_id = match string_param(params, "agent_id") {
            Ok(agent_id) => agent_id,
            Err(refusal) => return refusal,
        };
        return match core_permissions::list(state.store(), agent_id, now) {
            Ok(rows) => {
                let grants: Vec<Value> = rows.iter().map(|row| row.to_wire()).collect();
                json!({"result": {"grants": grants}})
            }
            Err(error) => {
                crate::wire::store_failure("permissions listed", "grants could not be read", &error)
            }
        };
    }
    let id = match string_param(params, "id") {
        Ok(Some(id)) => id,
        Ok(None) => return invalid("id", "string_required"),
        Err(refusal) => return refusal,
    };
    match core_permissions::revoke(state.store(), caller, id, now) {
        Ok(RevokeOutcome::Revoked(grants)) => {
            eprintln!(info governance: "permissions.revoke by {caller}: row {id} revoked {} grant(s)", grants.len());
            json!({"result": {"outcome": "revoked"}})
        }
        Ok(RevokeOutcome::NotFound) => json!({"result": {"outcome": "not_found"}}),
        Err(error) => crate::wire::store_failure(
            "permissions revoked",
            "the grants could not be revoked; already revoked grants stay revoked, and a retry revokes the rest",
            &error,
        ),
    }
}
