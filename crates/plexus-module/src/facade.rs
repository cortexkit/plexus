//! Facade tool admission, invoke dispatch and shared facade call context.

use super::*;

// Only Basal may carry flows so relaying cannot replace its module grants with
// a broader module's grants and widen the flow's authority.
// Basal must also be on the first-party list that route.bind admits
// (principal.rs) to reach Plexus at all.
//
// The rule also runs the other way: a flow carrier's call must carry a flow
// stamp. Basal holds broad module grants on behalf of flows. A call without the
// stamp would use them with no flow attached, outside the flow rules
// (`consent_unavailable` would not apply, so an ask_first action could file a
// consent card), and with no owning flow on the audit row.
pub(super) const ADMITTED_FLOW_CARRIERS: &[&str] = &[principal::BASAL_PRINCIPAL];

/// Serve one facade tool call (a `{name, arguments}` request naming one of
/// the tools in `manifest`, as opposed to a `{method, params}` management
/// request) and return its reply body,
/// `{"result": ...}` or `{"error": ...}`. The caller sends it, adding the MCP
/// `CallToolResult` fields in one place, so every early refusal below returns
/// its body rather than sending a frame of its own.
pub(super) fn facade_tool_reply_with_budget(
    frame: &Frame,
    object: &serde_json::Map<String, Value>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    budget: Arc<request_execution::RequestBudget>,
) -> Result<Value, ModuleError> {
    let reply = facade_tool_reply_inner(frame, object, state, route_bindings, budget)?;
    let reply = if is_event_get_call(object) {
        with_event_get_retryable(reply)
    } else {
        reply
    };
    // Every module-level `bot_request` refusal runs before the facade claims a
    // receipt, so the same nonce stays safe to retry. The flag lives beside
    // the code, in the top-level `error` object.
    let reply = if is_bot_request_call(object) && reply.get("error").is_some() {
        with_bot_retry_flag(reply)
    } else {
        reply
    };
    let name = object.get("name").and_then(Value::as_str).unwrap_or("");
    let mut reply = reply;
    if name == manifest::INVOKE_TOOL
        && route_bindings
            .binding(frame.header.channel, frame.header.epoch)?
            .is_some_and(|binding| binding.federated_caller.is_some())
    {
        reply = federated_invoke_reply(reply);
    }
    if let Some(error) = reply.get("error") {
        if tool_provider::is_metadata_op(name)
            || (object.contains_key("preset") && error["field"] == "preset")
        {
            log_tool_provider_refusal(frame, object, route_bindings, name, error)?;
        }
    }
    Ok(reply)
}

pub(super) fn federated_invoke_reply(mut reply: Value) -> Value {
    if let Some(error) = reply.get_mut("error").and_then(Value::as_object_mut) {
        // Invoke's top-level errors refuse the call before contacting the vendor;
        // dispatched outcomes use result.transmission. Preserve any transmission
        // an error producer already supplied rather than asserting a safe retry.
        error
            .entry("transmission")
            .or_insert_with(|| json!("not_sent"));
        if error.get("code").and_then(Value::as_str) == Some("access_pending") {
            error.insert("message".into(), json!("Waiting for the user to answer this request. Send the same call again to collect the answer."));
        }
    }
    reply
}

fn log_tool_provider_refusal(
    frame: &Frame,
    object: &serde_json::Map<String, Value>,
    route_bindings: &Arc<RouteBindings>,
    name: &str,
    error: &Value,
) -> Result<(), ModuleError> {
    fn keys(value: Option<&Value>) -> Vec<String> {
        value
            .and_then(Value::as_object)
            .map(|object| object.keys().map(|key| diagnostic_label(key)).collect())
            .unwrap_or_default()
    }
    let caller = route_bindings
        .binding(frame.header.channel, frame.header.epoch)?
        .map(|binding| principal::principal_key(&binding.principal))
        .unwrap_or_else(|| "unbound".to_owned());
    let arguments = object.get("arguments");
    let argument_keys = keys(arguments);
    let params_keys = keys(arguments.and_then(|arguments| arguments.get("params")));
    let preset = object
        .get("preset")
        .and_then(Value::as_str)
        .filter(|preset| subc_protocol::tool_call::validate_preset(preset).is_ok())
        .map(|preset| format!(" preset={preset}"))
        .unwrap_or_default();
    // Catalog errors may echo a capability or a malformed JSON value to the
    // caller. Logs retain the reason but must not copy those request values.
    let message = if error["detail"].get("capability").is_some() {
        "plexus serves no requested capability (value redacted)"
    } else if error["detail"]["field"] == "arguments" {
        "malformed catalog arguments (values redacted)"
    } else {
        error["message"].as_str().unwrap_or("request refused")
    };
    let op = diagnostic_label(name);
    let caller = diagnostic_label(&caller);
    let code = error["code"].as_str().unwrap_or("unknown");
    let message = diagnostic_label(message);
    eprintln!(warn wire: "tool call refused: op={op} caller={caller} code={code} message={message} argument_keys={argument_keys:?} params_keys={params_keys:?}{preset}");
    Ok(())
}

fn facade_tool_reply_inner(
    frame: &Frame,
    object: &serde_json::Map<String, Value>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    budget: Arc<request_execution::RequestBudget>,
) -> Result<Value, ModuleError> {
    let held_deadline = budget.deadline;
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    let federated_held_reply = route_bindings
        .binding(channel, epoch)?
        .is_some_and(|binding| binding.held_reply_v1);
    let bulk_read = object.get("method").and_then(Value::as_str)
        == Some(plexus_core::github::reads::bot::BULK_METHOD);
    if bulk_read {
        if let Some(field) = object
            .keys()
            .find(|key| !matches!(key.as_str(), "method" | "params"))
        {
            return Ok(json!({"error": {
                "code": "invalid_request",
                "field": plexus_core::text::refusal_echo(field),
                "message": "github.read.bulk requires only method and params",
            }}));
        }
    }
    let name = match object.get("name").and_then(Value::as_str) {
        _ if bulk_read => manifest::GITHUB_READ_TOOL,
        Some(name) => name,
        None => {
            return Ok(tool_error(
                "invalid_request",
                "tool request requires a string name",
            ));
        }
    };
    let log_name = diagnostic_label(name);
    let arguments = match object
        .get(if bulk_read { "params" } else { "arguments" })
        .and_then(Value::as_object)
    {
        Some(arguments) => arguments,
        None => {
            return Ok(tool_error(
                "invalid_request",
                "tool request requires an arguments object",
            ));
        }
    };
    // Retired identity tokens are undeclared on every tool, even if their
    // value is null or contains secrets. Refuse the field before any handler
    // can read credentials, send a request or silently discard it.
    if let Some(field) = retired_identity_field(arguments) {
        return Ok(retired_identity_refusal(field));
    }
    // Broca, the model runner, copies the preset name from the session's plan
    // ("worker", "reader" or "head") onto every request it sends a provider, the
    // catalog fetch and each later tool call alike. Accept the presets plexus's
    // tool catalog serves and refuse any other. Which plexus tools a session gets
    // is decided by capability tags when the plan is built, and every call is
    // still authorized on its own, so the preset grants nothing.
    if let Some(preset) = object.get("preset") {
        if !preset.as_str().is_some_and(tool_provider::serves_preset) {
            return Ok(json!({"error":{"code":"invalid_request", "field":"preset",
                "preset":preset, "message":"unknown or malformed plexus preset"}}));
        }
        if name == cortexkit_role_tool_provider::ops::TOOL_CATALOG
            && arguments
                .get("preset")
                .is_some_and(|argument| argument != preset)
        {
            return Ok(json!({"error":{"code":"invalid_request", "field":"preset",
                "message":"top-level preset must equal arguments.preset"}}));
        }
    }
    // `call_key` is the consumer's name for this call, a sibling of `name` and
    // `arguments`. Its shape is checked here, before any handler runs, so a
    // malformed key is refused rather than silently dropped the way unknown
    // top-level members are. Absent and `null` both mean no key, as they do
    // when the protocol's `ToolCallRequest` decodes the same body.
    //
    // A valid key is stored on the approval request if the call is held for
    // approval, so its carrier or its scope's owner can withdraw it with
    // `tool.withdraw`. A call that runs in its own request keeps nothing.
    if let Some(refusal) = call_key_refusal(object.get(CALL_KEY_FIELD)) {
        eprintln!(info wire: "tool call refused: malformed {CALL_KEY_FIELD} on channel {channel} (tool '{log_name}'): {refusal}");
        return Ok(json!({"error": {
            "code": "invalid_request",
            "message": refusal,
            "field": CALL_KEY_FIELD,
        }}));
    }
    // `origin` names the call from which a relayed call came. It is checked
    // here, beside `call_key`, so a malformed one is refused before any
    // handler runs. A valid one is recorded for attribution on the call's
    // audit rows and on any approval request it raises; nothing keys,
    // authorizes or withdraws on it. Its value is never logged or echoed: the
    // log line and the refusal name only the faulty field.
    let relay_origin = match relay_origin_of(object) {
        Ok(relay_origin) => relay_origin,
        Err(refusal) => {
            eprintln!(info wire: "tool call refused: malformed {} on channel {channel} (tool '{log_name}')", refusal.field);
            return Ok(json!({"error": {
                "code": "invalid_request",
                "message": refusal.message,
                "field": refusal.field,
            }}));
        }
    };
    if !matches!(
        name,
        manifest::CONNECTIONS_TOOL
            | manifest::CATALOG_TOOL
            | manifest::INVOKE_TOOL
            | manifest::GITHUB_TOOL
            | manifest::GITHUB_READ_TOOL
            | manifest::GITHUB_REACT_TOOL
            | manifest::EVENTS_GET_TOOL
            | manifest::REQUESTS_TOOL
            | manifest::EVENTS_TOOL
            | manifest::WEB_SEARCH_TOOL
            | manifest::CODE_SEARCH_TOOL
            | manifest::WITHDRAW_TOOL
            | cortexkit_role_tool_provider::ops::TOOL_CATALOG
            | cortexkit_role_tool_provider::ops::ROLE_DESCRIBE
    ) {
        // Logged for the same reason as the bind gates: a tool call refused
        // before any handler runs leaves no trace otherwise, so an operator
        // cannot tell a REFUSED call from one that never arrived -- and those
        // have different owners.
        eprintln!(info wire: "tool call refused: unknown facade tool '{log_name}' on channel {channel}");
        return Ok(tool_error("unknown_method", "unknown plexus facade tool"));
    }

    let Some(RouteBinding {
        principal,
        scope: route_scope,
        mode,
        on_behalf_of_agent,
        federated_caller,
        ..
    }) = route_bindings.binding(channel, epoch)?
    else {
        // THE CHANNEL AND EPOCH ARE PRINTED because this refusal can follow a
        // SUCCESSFUL bind: the binding is keyed on (channel, epoch), so a tool
        // frame carrying a different pair finds nothing even though the consumer
        // bound correctly moments earlier. Without both numbers the log cannot
        // distinguish that from a client that never bound at all, and the two
        // have different fixes.
        eprintln!(info wire:
            "tool call refused: no binding for channel {channel} epoch {epoch} (tool '{log_name}') -- a bind on a DIFFERENT channel/epoch does not cover this call"
        );
        return Ok(tool_error(
            "route_not_bound",
            "plexus tools require an accepted route.bind",
        ));
    };
    let principal_key = principal::principal_key(&principal);
    if bulk_read && principal_key != plexus_core::github::AFT_PRINCIPAL {
        return Ok(json!({"error": {
            "code": "caller_not_allowed",
            "message": "github.read.bulk is reserved for AFT",
            "transmission": "not_sent",
        }}));
    }
    if let Some(refusal) = tool_provider::mode_refusal(name, &mode) {
        return Ok(json!({"error": refusal}));
    }
    let federated_route = federated::is_callosum(Some(&principal));
    if name == manifest::GITHUB_TOOL {
        let operation = arguments.get("op").and_then(Value::as_str);
        if !matches!(
            operation,
            Some("bot_request" | "bindings.read" | "bindings.read_for_agent")
        ) {
            return Ok(json!({"error": {
                "code": "invalid_operation",
                "op": operation,
                "message": "unsupported github operation"
            }}));
        }
    }
    if !federated_route
        && (mode == CallMode::Flow
            || route_scope
                .as_ref()
                .is_some_and(|scope| scope.flow_id.is_some()))
        && !ADMITTED_FLOW_CARRIERS.contains(&principal_key.as_str())
    {
        eprintln!(info wire: "tool call refused: flow carrier {principal_key} is not admitted (tool '{log_name}')");
        return Ok(json!({"error": {
            "code": "flow_carrier_not_admitted",
            "message": format!("flow carrier {principal_key} is not admitted"),
            "carrier": principal_key,
            "transmission": "not_sent",
        }}));
    }
    // role.describe and tool.catalog only describe plexus's tools and carry no
    // authority. Basal reads them on an unscoped route when it installs a flow,
    // before any flow scope exists, so they are exempt from the flow-scope
    // requirement; every real tool still needs a flow scope from Basal.
    if !federated_route
        && !tool_provider::is_metadata_op(name)
        && (mode == CallMode::Flow || ADMITTED_FLOW_CARRIERS.contains(&principal_key.as_str()))
        && !route_scope
            .as_ref()
            .is_some_and(|scope| scope.flow_id.is_some())
    {
        eprintln!(info wire: "tool call refused: flow carrier {principal_key} sent no flow scope (tool '{log_name}')");
        return Ok(json!({"error": {
            "code": "flow_scope_required",
            "message": format!("{principal_key} carries only flow calls; this route carries no flow scope"),
            "carrier": principal_key,
            "transmission": "not_sent",
        }}));
    }
    if tool_provider::is_metadata_op(name) {
        // Metadata needs only the existing route admission, not connector
        // authority. Composition is opaque, so secret-shaped keys inside it
        // must not pass through the connector-argument filter.
        return Ok(match tool_provider::reply(name, arguments) {
            Ok(answer) => answer,
            Err(error) => json!({"error": error}),
        });
    }
    let audience = if federated_route {
        None
    } else {
        match state
            .runtime
            .flow_audiences
            .for_route(&principal_key, route_scope.as_ref())
        {
            Ok(audience) => audience,
            Err(refusal) => return Ok(refusal),
        }
    };
    if let Some(audience) = &audience {
        if let Err(refusal) = flow_audience::check_call(state, audience, name, arguments) {
            return Ok(refusal);
        }
    }
    if name == manifest::GITHUB_READ_TOOL {
        let action = arguments
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !bulk_read && action == "github.bindings.list" {
            return Ok(github_bindings_list::reply(
                state,
                &principal_key,
                arguments,
                route_scope.as_ref(),
                audience.as_ref(),
            ));
        }
        // Refuse by action name before inspecting repository/args, secrets, or
        // connection authority. The read-only surface cannot carry a bot write.
        let actions = if bulk_read {
            plexus_core::github::reads::bot::BULK_ACTIONS
        } else {
            plexus_core::github::reads::ACTIONS
        };
        if !actions.contains(&action) {
            return Ok(json!({"error": {
                "code": "read_action_unsupported",
                "action": plexus_core::text::refusal_echo(action),
                "message": format!("GitHub read action {:?} is not supported", plexus_core::text::refusal_echo(action)),
            }}));
        }
        if arguments
            .keys()
            .any(|key| !matches!(key.as_str(), "action" | "repository" | "args"))
            || !arguments.get("args").is_some_and(Value::is_object)
            || !arguments.get("repository").is_some_and(|repository| {
                repository.is_string()
                    || repository
                        .as_array()
                        .is_some_and(|items| items.iter().all(Value::is_string))
            })
        {
            if action == "github.actions.run.superseded" {
                return Ok(tool_error(
                    "run_arguments_invalid",
                    "run.superseded requires repository and args containing only a positive run_id",
                ));
            }
            return Ok(tool_error("invalid_request", "github_read requires only action, repository (string or string array), and args (object)"));
        }
    }
    // github_react's arguments are checked here, after the same mode, flow
    // and audience checks as every tool. They are turned into the same
    // `request` object a `github` tool `bot_request` reaction would carry
    // (action, repository, target number and reaction), and dispatch below
    // sends it through the bot_request path, so both tools share one
    // implementation.
    let reaction_request = if name == manifest::GITHUB_REACT_TOOL {
        match github_react::reaction_request(arguments) {
            Ok(built) => Some(built),
            Err(refusal) => return Ok(refusal),
        }
    } else {
        None
    };
    if name == manifest::EVENTS_GET_TOOL
        || (name == manifest::EVENTS_TOOL
            && arguments.get("op").and_then(Value::as_str) == Some("get"))
    {
        let invalid_key = arguments.keys().any(|key| {
            !matches!(key.as_str(), "event_key" | "event_name" | "version")
                && !(name == manifest::EVENTS_TOOL && key == "op")
        });
        if invalid_key {
            return Ok(tool_error(
                "invalid_request",
                "event reads accept only event_key, event_name and version",
            ));
        }
    }
    let op = arguments.get("op").and_then(Value::as_str);
    if name == manifest::EVENTS_TOOL
        && route_scope
            .as_ref()
            .is_some_and(|scope| scope.flow_id.is_some())
        && op != Some("get")
    {
        return Ok(tool_error(
            "events_op_not_for_flows",
            "events operations other than get are not admitted on flow routes",
        ));
    }
    if name == manifest::REQUESTS_TOOL
        && matches!(
            arguments.get("op").and_then(Value::as_str),
            Some("approve" | "deny")
        )
        && route_scope
            .as_ref()
            .is_some_and(|scope| scope.flow_id.is_some())
    {
        return Ok(tool_error(
            "flow_cannot_decide_approvals",
            "flows cannot approve or deny held calls",
        ));
    }
    if name == manifest::CONNECTIONS_TOOL
        && arguments.get("op").and_then(Value::as_str) == Some("connect")
        && arguments.contains_key("handle")
    {
        return Ok(tool_error(
            "handle_bindings_removed",
            "use credential_id during issue_ticket enrollment, then connect with ticket_id",
        ));
    }
    // The agent binding read has a closed field list checked below. Name any
    // unexpected field as invalid_request before screening its value for secrets.
    if !(name == manifest::GITHUB_TOOL && op == Some("bindings.read_for_agent"))
        && map_contains_secret_input(arguments)
    {
        return Ok(tool_error(
            "secret_input_rejected",
            "credential material may only enter through the binding-ticket ceremony",
        ));
    }
    let effect_op = if name == manifest::GITHUB_READ_TOOL {
        arguments.get("action").and_then(Value::as_str)
    } else {
        op
    };
    if connector_home::tool_effect(name, effect_op) {
        if let Some(refusal) = state.runtime.connector_home.refusal() {
            return Ok(refusal);
        }
    }
    let call = FacadeArguments {
        state,
        arguments,
        principal_key: &principal_key,
        op,
    };
    let response = match (name, op) {
        (manifest::GITHUB_TOOL, Some("bindings.read_for_agent")) => {
            let agent_id = arguments.get("agent_id").and_then(Value::as_str);
            let invalid_field = arguments
                .keys()
                .find(|key| !matches!(key.as_str(), "op" | "agent_id"))
                .map(String::as_str)
                .or_else(|| agent_id.is_none().then_some("agent_id"));
            let mut response = if let Some(field) = invalid_field {
                json!({"error":{"code":"invalid_request","field":plexus_core::text::refusal_echo(field)}})
            } else {
                match plexus_core::github::control::bindings_read_for_agent(
                    state.store(),
                    &principal_key,
                    agent_id.expect("agent_id validated"),
                ) {
                    Ok(result) => json!({"result":result}),
                    Err(denial) => denial_response(&denial),
                }
            };
            if let Err(error) = state.store().audit_github_control(
                &principal_key,
                agent_id,
                None,
                "github.bindings.read_for_agent",
                &fresh_request_id(),
                response.pointer("/error/code").and_then(Value::as_str),
            ) {
                warn_audit_failed(&mut response, "github.bindings.read_for_agent", &error);
            }
            response
        }
        (manifest::GITHUB_TOOL, Some("bindings.read")) => {
            let mut response = match arguments.get("connection_id").and_then(Value::as_str) {
                Some(id) => match plexus_core::github::control::bindings_read(
                    state.store(),
                    &principal_key,
                    id,
                ) {
                    Ok(result) => json!({"result":result}),
                    Err(denial) => denial_response(&denial),
                },
                None => json!({"error":{"code":"invalid_request"}}),
            };
            if let Err(error) = state.store().audit_github_control(
                &principal_key,
                None,
                None,
                "github.bindings.read",
                &fresh_request_id(),
                response.pointer("/error/code").and_then(Value::as_str),
            ) {
                warn_audit_failed(&mut response, "github.bindings.read", &error);
            }
            response
        }
        (manifest::GITHUB_READ_TOOL, _) => {
            let action = arguments
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("");
            let repository = arguments.get("repository").cloned().unwrap_or(Value::Null);
            let args = arguments.get("args").cloned().unwrap_or_else(|| json!({}));
            if bulk_read {
                return Ok(bot_read_reply(plexus_core::github::reads::bot::read_bulk(
                    &state.runtime.engine,
                    &principal_key,
                    action,
                    &repository,
                    &args,
                    route_scope.as_ref(),
                    on_behalf_of_agent.as_deref(),
                )));
            }
            let bot_read = BotReadForm::of(action, &principal_key, &args);
            let (args, applied_max_bytes) = github_read_tool::bounded_args(
                action,
                args,
                bot_read == Some(BotReadForm::JobLogRange),
            );
            if let Some(bot_read) = bot_read {
                return Ok(blocking_section(|| {
                    let engine = &state.runtime.engine;
                    let scope = route_scope.as_ref();
                    let on_behalf_of = on_behalf_of_agent.as_deref();
                    bot_read_reply(match bot_read {
                        BotReadForm::Repository => plexus_core::github::reads::bot::read(
                            engine,
                            &principal_key,
                            action,
                            &repository,
                            &args,
                            scope,
                            on_behalf_of,
                        ),
                        BotReadForm::JobLogRange => plexus_core::github::reads::bot::job_log(
                            engine,
                            &principal_key,
                            &repository,
                            &args,
                            scope,
                            on_behalf_of,
                        ),
                    })
                }));
            }
            blocking_section(|| {
                let read = if mode == CallMode::Codemode {
                    plexus_core::github::reads::read_codemode
                } else {
                    plexus_core::github::reads::read_scoped
                };
                match read(
                    &state.runtime.engine,
                    &principal_key,
                    action,
                    &repository,
                    &args,
                    route_scope.as_ref(),
                ) {
                    Ok(mut result) => {
                        if let Some(max_bytes) = applied_max_bytes {
                            result["max_bytes"] = json!(max_bytes);
                        }
                        json!({"result": result})
                    }
                    Err(plexus_core::github::reads::ReadError::UnsupportedAction) => {
                        json!({"error":{"code":"read_action_unsupported"}})
                    }
                    Err(plexus_core::github::reads::ReadError::Denied(denial)) => {
                        denial_response(&denial)
                    }
                    Err(plexus_core::github::reads::ReadError::Dispatch(outcome)) => {
                        github_read_failure(outcome)
                    }
                    Err(plexus_core::github::reads::ReadError::InvalidResponse) => {
                        json!({"error":{"code":"read_response_invalid"}})
                    }
                    Err(plexus_core::github::reads::ReadError::PageBound) => {
                        json!({"error":{"code":"pre_dispatch_read_incomplete","reason":"page_bound"}})
                    }
                    Err(plexus_core::github::reads::ReadError::LeaseExpired) => {
                        json!({"error":{"code":"pre_dispatch_read_incomplete","reason":"lease_expired"}})
                    }
                    Err(plexus_core::github::reads::ReadError::Refused(
                        "repository_not_visible",
                    )) => {
                        json!({"error":{"code":"repository_not_visible","message":"repository_not_visible","transmission":"not_sent"}})
                    }
                    Err(plexus_core::github::reads::ReadError::Refused(code)) => {
                        tool_error(code, code)
                    }
                    Err(plexus_core::github::reads::ReadError::QuotaExhausted {
                        retry_after_ms,
                    }) => {
                        json!({"error":{"code":"github_actions_quota_exhausted","message":"CI read interrupted before the next GitHub request; earlier requests may already have been sent","transmission":"not_sent","detail":{"retry_after_ms":retry_after_ms}}})
                    }
                }
            })
        }
        (manifest::GITHUB_TOOL, Some("bot_request")) | (manifest::GITHUB_REACT_TOOL, _) => {
            let (request, nonce) = match &reaction_request {
                Some(built) => (built.request.clone(), built.request_nonce.as_str()),
                None => (
                    arguments.get("request").cloned().unwrap_or(Value::Null),
                    arguments
                        .get("request_nonce")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                ),
            };
            let request_id = fresh_request_id();
            let owner = request_id.clone();
            let now = plexus_core::now_ms();
            blocking_section(|| {
                plexus_core::github::facade::bot_request_scoped_with_preconditions(
                    state.store(),
                    &state.runtime.engine,
                    &principal_key,
                    route_scope.as_ref(),
                    &request,
                    nonce,
                    arguments
                        .get("expect")
                        .filter(|_| reaction_request.is_none()),
                    arguments
                        .get("run_scope")
                        .filter(|_| reaction_request.is_none()),
                    &request_id,
                    &owner,
                    now,
                )
            })
        }
        (manifest::CONNECTIONS_TOOL, Some("list")) => return facade_connections_list(&call),
        (manifest::CONNECTIONS_TOOL, Some("connect")) => return facade_connections_connect(&call),
        // Without configure, a connection's filters stay at their empty
        // default and every write action is denied as write_filters_absent
        // with no way to narrow scope through the tool surface. The store
        // bounds the request against the vendor's reviewed manifest.
        (manifest::CONNECTIONS_TOOL, Some("configure")) => {
            return facade_connections_configure(&call)
        }
        (manifest::CONNECTIONS_TOOL, Some("revoke")) => return facade_connections_revoke(&call),
        (manifest::CONNECTIONS_TOOL, Some("check" | "inspect")) => {
            return facade_connections_check(&call)
        }
        (manifest::CONNECTIONS_TOOL, _) => {
            json!({"error": {"code": "invalid_operation", "message": "unsupported connection operation"}})
        }
        // Pre-connection discovery: which vendors can be connected at all.
        // Every other catalog projection is connection-scoped, so on a fresh
        // install this is the only way to see what the module carries.
        (manifest::CATALOG_TOOL, Some("apps")) => return facade_catalog_apps(&call),
        (manifest::CATALOG_TOOL, Some("list" | "inspect")) => return facade_catalog_list(&call),
        (manifest::CATALOG_TOOL, _) => {
            json!({"error": {"code": "invalid_operation", "message": "catalog requires apps, list, or inspect"}})
        }
        (manifest::INVOKE_TOOL, Some("call")) => {
            if let Some(missing) = missing_string_fields(arguments, &["connection", "action"]) {
                return Ok(json!({"error": {
                    "code": "invalid_request",
                    "message": format!("invoke requires {}", missing.join(" and ")),
                    "missing": missing,
                    "example": {"op": "call", "connection": "conn-exa", "action": "web_search_exa", "args": {}}
                }}));
            }
            let connection_id = arguments
                .get("connection")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let action = arguments
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let call_agent = resolve_call_agent(route_scope.as_ref());
            // This read must select the stamped agent's bot and reserve its read
            // budget; raw invoke cannot supply those guarantees.
            if action == "github.pulls.open" {
                return Ok(json!({"error":{"code":"github_read_required",
                    "message":"use github_read for github.pulls.open","transmission":"not_sent"}}));
            }
            let args = arguments.get("args").cloned().unwrap_or_else(|| json!({}));
            let mut request =
                AuthorizationRequest::new(&principal_key, connection_id, action, args);
            if let Some(agent_id) = call_agent.attributed {
                request = request.with_attributed_agent(agent_id);
            }
            // Under a delegating scope whose owner is authorized, the engine
            // judges this call as the scope's agent: the agent's own grant is
            // required on top of this module's grant.
            if let Some(scope) = route_scope.clone() {
                request = request.with_scope(scope);
            }
            if let Some(caller) = federated_caller.clone() {
                request = request
                    .with_federated_caller(caller)
                    .with_federated_held_reply(
                        route_bindings
                            .binding(channel, epoch)?
                            .is_some_and(|binding| binding.held_reply_v1),
                    );
            }
            if let Some(schema_hash) = arguments.get("schema_hash").and_then(Value::as_str) {
                request = request.with_schema_hash(schema_hash);
            }
            if let Some(call_key) = object.get(CALL_KEY_FIELD).and_then(Value::as_str) {
                request = request.with_call_key(call_key);
            }
            if let Some(relay_origin) = relay_origin.clone() {
                request = request.with_relay_origin(relay_origin);
            }
            // Authorization first: the freshness check `dispatch_checked`
            // runs before sending may contact the vendor, so it never runs for
            // a caller the engine refused.
            let home = state.runtime.connector_home.clone();
            let guard_budget = budget.clone();
            let engine = state
                .runtime
                .engine
                .clone()
                .with_connector_home_guard(Arc::new(move || {
                    home.refusal()
                        .or_else(|| guard_budget.expired().then(request_expired_reply))
                }));
            blocking_section(|| match engine.invoke_held(request, held_deadline) {
                Ok(outcome) => dispatch_response(outcome),
                Err(denial) => denial_response(&denial),
            })
        }
        (manifest::INVOKE_TOOL, _) => {
            // Name the whole shape rather than only the missing op. A caller who
            // reaches here guessed the envelope, and telling them "requires
            // call" sends them round again to guess the parameter names — which
            // are `connection` and `args`, not the `connection_id`/`arguments`
            // an operator naturally reaches for.
            json!({"error": {
                "code": "invalid_operation",
                "message": "invoke requires op=call with connection, action, and optional args",
                "example": {"op": "call", "connection": "conn-exa", "action": "web_search_exa", "args": {}}
            }})
        }
        (manifest::WEB_SEARCH_TOOL, _) => {
            // Pass every web-search argument to core's closed-schema validator;
            // undeclared identity-token fields were already refused at ingress.
            blocking_section(|| {
                let outcome = if let Some(caller) = &federated_caller {
                    state.runtime.web_search.search_federated_held(
                        &state.runtime.engine,
                        caller,
                        arguments,
                        route_scope.as_ref(),
                        relay_origin.as_ref(),
                        Some((federated_held_reply, held_deadline)),
                    )
                } else {
                    state.runtime.web_search.search_scoped(
                        &state.runtime.engine,
                        &principal_key,
                        arguments,
                        route_scope.as_ref(),
                        relay_origin.as_ref(),
                    )
                };
                match outcome {
                    Ok(response) => json!({"result": response}),
                    Err(refusal) => refusal.to_wire(),
                }
            })
        }
        (manifest::CODE_SEARCH_TOOL, _) => blocking_section(|| {
            let outcome = if let Some(caller) = &federated_caller {
                state.runtime.code_search.search_federated_held(
                    &state.runtime.engine,
                    caller,
                    arguments,
                    route_scope.as_ref(),
                    relay_origin.as_ref(),
                    Some((federated_held_reply, held_deadline)),
                )
            } else {
                state.runtime.code_search.search_scoped(
                    &state.runtime.engine,
                    &principal_key,
                    arguments,
                    route_scope.as_ref(),
                    relay_origin.as_ref(),
                )
            };
            match outcome {
                Ok(response) => json!({"result": response}),
                Err(refusal) => refusal.to_wire(),
            }
        }),
        (manifest::WITHDRAW_TOOL, _) => blocking_section(|| {
            withdraw_response(
                &state.runtime.engine,
                &principal_key,
                route_scope.as_ref(),
                object.get(CALL_KEY_FIELD),
                arguments,
            )
        }),
        (manifest::REQUESTS_TOOL, Some("inspect")) => return facade_requests_inspect(&call),
        (manifest::REQUESTS_TOOL, Some("list")) => return facade_requests_list(&call),
        (manifest::REQUESTS_TOOL, Some("approve")) => return facade_requests_approve(&call),
        (manifest::REQUESTS_TOOL, Some("deny")) => return facade_requests_deny(&call),
        (manifest::REQUESTS_TOOL, _) => {
            json!({"error": {"code": "invalid_operation", "message": "unsupported request operation"}})
        }
        (manifest::EVENTS_TOOL, Some("register_probe")) => {
            return facade_events_register_probe(&call)
        }
        (manifest::EVENTS_TOOL, Some("subscribe")) => return facade_events_subscribe(&call),
        (manifest::EVENTS_TOOL, Some("get")) | (manifest::EVENTS_GET_TOOL, _) => event_get_reply(
            state.store(),
            arguments,
            &principal_key,
            route_scope.as_ref(),
            audience.as_ref(),
        ),
        (manifest::EVENTS_TOOL, Some("resume")) => return facade_events_resume(&call),
        (manifest::EVENTS_TOOL, Some("list")) => return facade_events_list(&call),
        (manifest::EVENTS_TOOL, Some("ack")) => return facade_events_ack(&call),
        (manifest::EVENTS_TOOL, Some("unsubscribe")) => return facade_events_unsubscribe(&call),
        (manifest::EVENTS_TOOL, Some("set_project")) => return facade_events_set_project(&call),
        (manifest::EVENTS_TOOL, Some("set_deliver_to")) => {
            return facade_events_set_deliver_to(&call)
        }
        (manifest::EVENTS_TOOL, Some("set_actor_source")) => {
            return facade_events_set_actor_source(&call)
        }
        (manifest::EVENTS_TOOL, _) => {
            json!({"error": {"code": "invalid_operation", "message": "unsupported events operation"}})
        }
        _ => json!({"error": {"code": "unknown_method", "message": "unknown plexus facade tool"}}),
    };
    Ok(response)
}

pub(super) struct FacadeArguments<'a> {
    pub(super) state: &'a Arc<ModuleState>,
    pub(super) arguments: &'a serde_json::Map<String, Value>,
    pub(super) principal_key: &'a str,
    pub(super) op: Option<&'a str>,
}

impl FacadeArguments<'_> {
    pub(super) fn federated_metadata(&self) -> bool {
        // route.bind rejects this principal unless the daemon stamp identifies
        // a paired computer. Request arguments cannot select this namespace.
        self.principal_key == "reserved:callosum"
    }

    pub(super) fn metadata_owner(&self) -> &str {
        if self.federated_metadata() {
            "direct"
        } else {
            self.principal_key
        }
    }
}

pub(super) fn fresh_request_id() -> String {
    static NONCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = NONCE.get_or_init(|| {
        use std::io::Read;
        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .expect("request identity requires operating-system randomness");
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    });
    format!(
        "gh-{nonce}-{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

pub(super) fn request_expired_reply() -> Value {
    json!({"error":{"code":"request_deadline_exceeded", "transmission":"not_sent", "message":"request deadline passed; recall the approved call to retry"}})
}

/// Which `github_read` calls are agent bot reads, served with the stamped
/// agent's own bot rather than the calling module's connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BotReadForm {
    /// `github.repo.get`, `github.search.code` and `github.search.issues`,
    /// whichever module carries the call.
    Repository,
    /// `github.actions.job_log` carried by AFT (principal `reserved:aft`, the
    /// module whose `gh` shim routes agents' GitHub reads) without `max_bytes`:
    /// a byte range of the log, read with the agent's bot. All other
    /// `github.actions.job_log` calls, from AFT with `max_bytes` or from any
    /// other module, are not bot reads: they keep the older bounded tail read
    /// through the operator's Actions connection.
    JobLogRange,
}

impl BotReadForm {
    fn of(action: &str, principal_key: &str, args: &Value) -> Option<Self> {
        if plexus_core::github::reads::bot::ACTIONS.contains(&action) {
            return Some(Self::Repository);
        }
        (action == "github.actions.job_log"
            && principal_key == plexus_core::github::AFT_PRINCIPAL
            && args.get("max_bytes").is_none())
        .then_some(Self::JobLogRange)
    }
}

/// The reply body for a bot read: `{"result": ...}`, or an error whose
/// `transmission` says whether GitHub was asked. These codes and fields are a
/// contract AFT's `gh` shim reads (see tests/fixtures/github-read-bot).
fn bot_read_reply(result: Result<Value, plexus_core::github::reads::bot::BotReadError>) -> Value {
    use plexus_core::github::reads::bot::BotReadError;
    let refusal = |code: &str, message: &str, transmission: &str| json!({"error": {"code": code, "message": message, "transmission": transmission}});
    match result {
        Ok(result) => json!({"result": result}),
        Err(BotReadError::AgentIdentityRequired) => refusal(
            "agent_identity_required",
            "GitHub bot reads need a head scope's agent or a worker scope working on behalf of one",
            "not_sent",
        ),
        Err(BotReadError::RepositoryNotVisible) => refusal(
            "repository_not_visible",
            "repository_not_visible",
            "not_sent",
        ),
        Err(BotReadError::EndpointNotAllowed { field }) => {
            let mut reply = refusal(
                "endpoint_not_allowed",
                "this argument is not one GitHub bot reads serve",
                "not_sent",
            );
            reply["error"]["field"] = json!(field);
            reply
        }
        Err(BotReadError::BudgetExhausted { retry_after_ms }) => {
            let mut reply = refusal(
                "read_budget_exhausted",
                "this bot's GitHub read budget is spent; retry later",
                "not_sent",
            );
            reply["error"]["retry_after_ms"] = json!(retry_after_ms);
            reply
        }
        Err(BotReadError::ResponseTooLarge) => refusal(
            "response_too_large",
            "GitHub's reply is larger than 1 MiB and was not returned",
            "sent",
        ),
        Err(BotReadError::Vendor { status }) => {
            let mut reply = refusal("vendor_error", "GitHub refused the read", "sent");
            reply["error"]["status"] = json!(status);
            reply
        }
        Err(BotReadError::JobNotFinished) => {
            refusal("job_not_finished", "the job has not completed", "sent")
        }
        Err(BotReadError::JobLog(code)) => refusal(code, code, "sent"),
        Err(BotReadError::Denied(denial)) => denial_response(&denial),
        Err(BotReadError::Dispatch(outcome)) => github_read_failure(outcome),
        Err(BotReadError::InvalidResponse) => json!({"error":{"code":"read_response_invalid"}}),
    }
}

pub(super) fn github_read_failure(outcome: TransportOutcome) -> Value {
    let (transmission, code) = match outcome {
        TransportOutcome::Completed { .. } => ("completed", None),
        TransportOutcome::VendorFailed { code, .. } => ("failed", Some(code)),
        TransportOutcome::OutcomeUnknown => ("unknown", None),
        TransportOutcome::NotSent { code, .. } => ("not_sent", Some(code)),
    };
    json!({"error":{"code":"read_dispatch_failed", "outcome":{"transmission":transmission,"code":code,
        "message":"GitHub read dispatch did not complete"}}})
}

/// Serve a `tool.withdraw` request: withdraw the held call named by
/// `arguments.call_key`, on behalf of `caller`, the principal of the route the
/// request arrived on.
///
/// The reply is `{"result": {"answer": ...}}` with the answer read from the
/// stored request, or the route error `withdraw_not_permitted` when the caller
/// may not withdraw that call. A malformed request is `invalid_request`
/// naming the field. When the call is withdrawn, its consent card, if it has
/// one, is withdrawn from Prefrontal core too.
fn withdraw_response(
    engine: &crate::composition::FacadeEngine,
    caller: &str,
    route_scope: Option<&CallScope>,
    own_call_key: Option<&Value>,
    arguments: &serde_json::Map<String, Value>,
) -> Value {
    let invalid = |field: &str, message: String| json!({"error": {"code": "invalid_request", "field": field, "message": message}});
    let not_permitted = |why: &str| {
        eprintln!(info wire: "tool.withdraw refused for {caller}: {why}");
        json!({"error": {"code": WITHDRAW_NOT_PERMITTED, "message": why}})
    };
    // The call being withdrawn is named inside `arguments`. A top-level key
    // would give the withdrawal a key of its own, as though it were a call
    // that could itself be held and withdrawn, which it is not.
    if !matches!(own_call_key, None | Some(Value::Null)) {
        return invalid(
            CALL_KEY_FIELD,
            format!(
                "{} names the call in arguments.{CALL_KEY_FIELD}; \
                 its own {CALL_KEY_FIELD} must be absent",
                manifest::WITHDRAW_TOOL
            ),
        );
    }
    let call_key = match arguments.get(CALL_KEY_FIELD) {
        Some(Value::String(key)) => match validate_call_key(key) {
            Ok(()) => key.as_str(),
            Err(error) => return invalid("arguments.call_key", error.to_string()),
        },
        Some(_) => {
            return invalid(
                "arguments.call_key",
                "arguments.call_key must be a string".to_string(),
            )
        }
        None => {
            return invalid(
                "arguments.call_key",
                format!("{} requires arguments.call_key", manifest::WITHDRAW_TOOL),
            )
        }
    };
    let carrier = match arguments.get("carrier") {
        None | Some(Value::Null) => None,
        Some(Value::String(carrier)) => Some(carrier.as_str()),
        Some(_) => {
            return invalid(
                "arguments.carrier",
                "arguments.carrier must be a principal string".to_string(),
            )
        }
    };
    // The scope always comes from the route's stamp. A caller that also
    // states one is only accepted when it states that same scope: a
    // different one is refused, never used in place of the stamp's.
    match arguments.get("scope") {
        None | Some(Value::Null) => {}
        Some(claimed) => {
            let matches_stamp = route_scope.is_some_and(|scope| {
                claimed.get("owner").and_then(Value::as_str) == Some(scope.owner.as_str())
                    && claimed.get("ref").and_then(Value::as_str) == Some(scope.scope_ref.as_str())
                    && claimed.get("scope_epoch").and_then(Value::as_u64) == Some(scope.scope_epoch)
            });
            if !matches_stamp {
                return not_permitted("arguments.scope is not the scope stamped on this route");
            }
        }
    }
    match engine.withdraw_call(&WithdrawCall {
        caller,
        call_key,
        carrier,
        scope: route_scope,
    }) {
        Ok(answer) => json!({"result": answer.to_wire()}),
        Err(WithdrawRefusal::NotPermitted(why)) => not_permitted(why),
        Err(WithdrawRefusal::Store(error)) => crate::wire::store_failure(
            "withdrawal completed",
            "the withdrawal could not be completed",
            &error,
        ),
    }
}
