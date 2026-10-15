//! Read-only flow grant and policy inspection on the management route.
use super::*;
use plexus_core::grant_refusal::{GrantTarget, Layer};

pub const METHOD: &str = "grants.would_ask";

fn invalid(field: &str, reason: &str) -> Value {
    json!({"error":{"code":"invalid_request", "field":field, "reason":reason, "message":format!("{reason}: {field}")}})
}

pub(super) fn run(
    state: &ModuleState,
    caller: &str,
    scope: Option<&plexus_core::scope::CallScope>,
    request: &serde_json::Map<String, Value>,
) -> Value {
    let reply = evaluate(state, caller, scope, request);
    let params = request.get("params").unwrap_or(&Value::Null);
    let items = reply.pointer("/result/items").and_then(Value::as_array);
    let count = |verdict: &str| {
        items.map_or(0, |items| {
            items
                .iter()
                .filter(|item| item["verdict"] == verdict)
                .count()
        })
    };
    let counts = json!({"item_count":items.map_or(0, Vec::len), "yes":count("yes"), "no":count("no"), "would_ask":count("would_ask")});
    let mut audit = AuditRecord::ceremony(caller, None, None, METHOD, "read", None);
    audit.actor = if caller == "direct" {
        "operator"
    } else {
        "module"
    }
    .into();
    audit.gate = Some(METHOD.into());
    audit.decision = if reply.get("error").is_some() {
        "deny"
    } else {
        "allow"
    }
    .into();
    audit.agent_id = params["agent_id"].as_str().map(str::to_owned);
    audit.reason_code = reply
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or(METHOD)
        .into();
    audit.args_redaction_summary = Some(json!({"event":METHOD,"caller":{"agent_id":params["agent_id"],"flow_id":params["flow_id"]},"counts":counts}).to_string());
    if state.store().append_audit_scoped(&audit, scope).is_err() {
        return tool_error("store_failure", "could not audit grants.would_ask");
    }
    reply
}

fn evaluate(
    state: &ModuleState,
    caller: &str,
    scope: Option<&plexus_core::scope::CallScope>,
    request: &serde_json::Map<String, Value>,
) -> Value {
    if !matches!(caller, "reserved:basal" | "reserved:prefrontal-core") {
        return tool_error("principal_denied", "grants.would_ask is reserved to reserved:prefrontal-core and flow-scoped reserved:basal");
    }
    if caller == "reserved:basal" && !scope.is_some_and(|scope| scope.flow_id.is_some()) {
        return tool_error(
            "flow_scope_required",
            "reserved:basal requires a flow scope for grants.would_ask",
        );
    }
    for field in request.keys() {
        if !matches!(field.as_str(), "method" | "params") {
            return invalid(field, "unknown_field");
        }
    }
    let Some(params) = request.get("params").and_then(Value::as_object) else {
        return invalid("params", "object_required");
    };
    for field in params.keys() {
        if !matches!(field.as_str(), "agent_id" | "flow_id" | "items") {
            return invalid(field, "unknown_field");
        }
    }
    let agent = params
        .get("agent_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    if params.contains_key("agent_id") && agent.is_none() {
        return invalid("agent_id", "string_required");
    }
    let Some(flow) = params
        .get("flow_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return invalid("flow_id", "string_required");
    };
    if caller == "reserved:basal" {
        let scope = scope.expect("checked scope");
        if scope.agent_id.as_deref() != agent {
            return tool_error(
                "agent_identity_conflict",
                "agent_id differs from the route stamp",
            );
        }
        if scope.flow_id.as_deref() != Some(flow) {
            return tool_error(
                "flow_identity_conflict",
                "flow_id differs from the route stamp",
            );
        }
    }
    let Some(items) = params.get("items").and_then(Value::as_array) else {
        return invalid("items", "array_required");
    };
    // Unknown fields refuse the whole request before any item's evaluation.
    for item in items {
        let Some(fields) = item.as_object() else {
            return invalid("items", "object_required");
        };
        let grant_form = fields.contains_key("grant");
        for field in fields.keys() {
            if (grant_form && field != "grant")
                || (!grant_form && !matches!(field.as_str(), "tool" | "connection" | "action"))
            {
                return invalid(field, "unknown_field");
            }
        }
    }
    // grants.would_ask predicts grants and policy without a repository argument.
    // Like agent-owned flows, workspace flows check repository access on each
    // real call rather than treating a grant prediction as repository authority.
    let audience_refusal = if agent.is_none() {
        state.runtime.flow_audiences.for_agentless_flow(flow).err()
    } else {
        None
    };
    let results: Vec<Value> = items
        .iter()
        .map(|item| {
            if let Some(refusal) = &audience_refusal {
                let code = refusal["error"]["code"]
                    .as_str()
                    .expect("audience refusal code");
                let mut result = verdict(item.clone(), "no", code);
                result["code"] = json!(code);
                result["detail"] = refusal["error"].clone();
                return result;
            }
            evaluate_item(
                state,
                agent,
                flow,
                if caller == "reserved:basal" {
                    scope
                } else {
                    None
                },
                item,
            )
        })
        .collect();
    json!({"result":{"items":results}})
}

/// Prefrontal, which installs flows, registers an agent-owned flow with an
/// `agent_id` and `delegates: true`, and a global (operator-installed) flow
/// with neither (`flow_scope_record` in prefrontal-core). At run time Basal
/// calls on its flow's route, and the daemon attaches that scope to the route,
/// so the check reads `agent_id` and `delegates` from there. At install time
/// there is no route scope yet, so the same rule is derived from whether the
/// request names an `agent_id`.
fn evaluate_item(
    state: &ModuleState,
    agent: Option<&str>,
    flow: &str,
    scope: Option<&plexus_core::scope::CallScope>,
    item: &Value,
) -> Value {
    let mut result = item.clone();
    let target = if let Some(reference) = item.get("grant") {
        reference.as_str().and_then(GrantTarget::decode)
    } else {
        let tool = item["tool"].as_str();
        let action = item["action"].as_str();
        match (tool, action) {
            (Some("web_search"), Some("search" | "web_search"))
                if item.get("connection").is_none_or(Value::is_null) =>
            {
                Some(plexus_core::web_search::WebSearchService::grant_target(
                    "reserved:basal",
                ))
            }
            (Some(tool @ ("invoke" | "github")), Some(action)) if !action.is_empty() => item
                ["connection"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(|connection| {
                    GrantTarget::new(
                        Layer::Module,
                        "reserved:basal",
                        tool,
                        Some(connection),
                        action,
                    )
                }),
            _ => None,
        }
    };
    let Some(target) = target.filter(|target| match target.layer {
        Layer::Module => target.grantee == "reserved:basal",
        Layer::Agent => Some(target.grantee.as_str()) == agent,
    }) else {
        return verdict(result, "no", "invalid_target");
    };
    if !matches!(target.tool.as_str(), "invoke" | "github" | "web_search")
        || target.action.is_empty()
    {
        return verdict(result, "no", "invalid_target");
    }
    let decision = if target.tool == "web_search" {
        if target != plexus_core::web_search::WebSearchService::grant_target("reserved:basal") {
            return verdict(result, "no", "invalid_target");
        }
        match state
            .runtime
            .web_search
            .would_ask(state.store(), "reserved:basal")
        {
            Ok(effect) => Ok(effect),
            Err(plexus_core::web_search::WebSearchRefusal::Grant(refusal)) => {
                Err(plexus_core::Denial::GrantRefusal(refusal))
            }
            Err(_) => return verdict(result, "no", "invalid_target"),
        }
    } else if let Some(connection) = target.connection.as_deref().filter(|s| !s.is_empty()) {
        if target.tool == "github" && target.action == "bindings.read" {
            plexus_core::github::control::bindings_read(state.store(), "reserved:basal", connection)
                .map(|_| "allow")
        } else {
            state.runtime.engine.would_ask(
                agent,
                flow,
                scope,
                &target.tool,
                connection,
                &target.action,
            )
        }
    } else {
        return verdict(result, "no", "invalid_target");
    };
    match decision {
        Ok("allow") => verdict(result, "yes", "allowed"),
        Ok("ask_first") => verdict(result, "would_ask", "consent_unavailable"),
        Ok(_) => verdict(result, "no", "policy_blocked"),
        Err(plexus_core::Denial::GrantRefusal(refusal)) => {
            result["code"] = json!(refusal.code());
            result["detail"] = json!(refusal.detail());
            verdict(result, "no", refusal.code())
        }
        // A store error says nothing about the target, so it is not reported
        // as an invalid one: the verdict stays a fail-closed "no", with the
        // reason naming the failure so a caller can retry.
        Err(plexus_core::Denial::StoreFailure) => {
            eprintln!(warn governance: "grants.would_ask could not read the store for {}/{}", target.tool, target.action);
            verdict(result, "no", "store_failure")
        }
        Err(denial) => verdict(result, "no", denial.reason_code()),
    }
}

fn verdict(mut item: Value, verdict: &str, reason: &str) -> Value {
    item["verdict"] = json!(verdict);
    item["reason"] = json!(reason);
    item
}
