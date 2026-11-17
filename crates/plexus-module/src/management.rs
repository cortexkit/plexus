//! Management-surface dispatch and GitHub handle administration.

use super::*;

/// Serve the privileged ceremony. Direct admission excludes supervised modules,
/// not other code running as this user. Minting or widening authority therefore
/// also requires operation-bound confirmation from the daemon's operator UI;
/// narrowing authority and read-only previews require no step-up.
pub(super) async fn handle_management_request(
    route: RouteFrameContext,
    method: &str,
    params: &Value,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    let RouteFrameContext {
        version,
        channel,
        epoch,
        correlation,
    } = route;
    if !matches!(
        method,
        manifest::ADMIN_ISSUE_TICKET_OP
            | manifest::ADMIN_GRANT_OP
            | manifest::ADMIN_WIDEN_CEILING_OP
            | manifest::ADMIN_REVOKE_GRANT_OP
            | manifest::ADMIN_LIST_GRANTS_OP
            | manifest::ADMIN_SET_POLICY_OP
            | manifest::ADMIN_LIST_POLICIES_OP
            | manifest::ADMIN_REMOVE_POLICY_OP
            | manifest::ADMIN_REVIEW_ACTION_OP
            | manifest::ADMIN_REPIN_ACTION_OP
            | manifest::ADMIN_DELETE_CONNECTION_OP
            | manifest::ADMIN_REBIND_CREDENTIAL_OP
            | manifest::ADMIN_SET_WEB_SEARCH_LIMIT_OP
            | manifest::ADMIN_SET_WEB_SEARCH_ORDER_OP
            | manifest::ADMIN_SET_WEB_SEARCH_ALLOWANCE_OP
            | manifest::ADMIN_ADD_WEB_SEARCH_PROVIDER_OP
            | manifest::ADMIN_ADD_WRITE_CONNECTION_OP
            | manifest::ADMIN_ADD_POLL_CONNECTION_OP
            | manifest::ADMIN_WIDEN_AND_GRANT_OP
            | manifest::ADMIN_ONBOARD_GITHUB_BOT_OP
            | manifest::ADMIN_RECIPIENTS_ADD_OP
            | manifest::ADMIN_RECIPIENTS_REMOVE_OP
            | manifest::ADMIN_RECIPIENTS_LIST_OP
            | manifest::ADMIN_SENT_TEXT_READ_OP
            | manifest::ADMIN_SENT_TEXT_RETENTION_OP
            | manifest::GITHUB_IMPORT_OP
            | manifest::GITHUB_PROBE_OP
            | manifest::GITHUB_GRANT_OP
            | manifest::GITHUB_BIND_OP
            | manifest::GITHUB_UNBIND_OP
            | connector_home::STATUS_OP
            | relay::STATUS_OP
    ) {
        // THE LAST SILENT GATE, and the one that actually bit: a consumer sent
        // {"method":"events","params":{"op":"list"}}, which lands here rather
        // than on the tool surface, because a `method` key routes to management
        // BEFORE any tool name is read. It was refused correctly and invisibly.
        //
        // The two shapes are easy to confuse and the failure is quiet: the
        // facade ops (connections, catalog, invoke, requests, events) live on
        // the TOOL surface and take {"name","arguments"}; this surface serves
        // administrative and status operations.
        // A consumer using the management shape for a facade op gets unknown_method, and a client
        // that renders an error frame as an empty result then shows a working
        // lane that is permanently empty.
        //
        // The message names both the surface and the correct shape, because
        // "unknown plexus management operation" is true and useless to someone
        // who does not yet know they are on the wrong surface.
        let method = diagnostic_label(method);
        eprintln!(info wire:
            "management call refused: '{method}' is not a management operation on channel {channel}; facade tools take {{name, arguments}}"
        );
        return send_tool_error(
            writer,
            version,
            channel,
            epoch,
            correlation,
            "unknown_method",
            &format!(
                "'{method}' is not a plexus management operation. The management surface serves administration and status operations; facade tools (connections, catalog, invoke, requests, events) take {{\"name\": \"events\", \"arguments\": {{...}}}}"
            ),
        )
        .await;
    }
    let Some(binding) = route_bindings.binding(channel, epoch)? else {
        return send_tool_error(
            writer,
            version,
            channel,
            epoch,
            correlation,
            "route_not_bound",
            "plexus management operations require an accepted route.bind",
        )
        .await;
    };
    let principal = binding.principal;
    if !matches!(principal, Principal::Direct)
        || binding.mode != CallMode::Classic
        || binding.scope.is_some()
    {
        let mut response = tool_error(
            "operator_authority_required",
            "plexus management operations require an unscoped Classic direct principal",
        );
        if matches!(
            method,
            manifest::GITHUB_IMPORT_OP
                | manifest::GITHUB_PROBE_OP
                | manifest::GITHUB_GRANT_OP
                | manifest::GITHUB_BIND_OP
                | manifest::GITHUB_UNBIND_OP
        ) {
            if let Err(error) = state.store().audit_github_control(
                &principal::principal_key(&principal),
                None,
                params.get("app_handle_id").and_then(Value::as_str),
                method,
                &fresh_request_id(),
                Some("operator_authority_required"),
            ) {
                warn_audit_failed(&mut response, "github control refusal", &error);
            }
        }
        return send_tool_response(writer, version, channel, epoch, correlation, response).await;
    }
    let principal_key = principal::principal_key(&principal);
    if matches!(
        method,
        manifest::GITHUB_IMPORT_OP
            | manifest::GITHUB_PROBE_OP
            | manifest::GITHUB_BIND_OP
            | manifest::ADMIN_ISSUE_TICKET_OP
            | manifest::ADMIN_REBIND_CREDENTIAL_OP
    ) {
        if let Some(refusal) = state.runtime.connector_home.refusal() {
            return send_tool_response(writer, version, channel, epoch, correlation, refusal).await;
        }
    }
    let bulk_invoke_grant = method == manifest::GITHUB_GRANT_OP
        && params["all_handles"] == true
        && params["kind"] != "read";
    let summary = if bulk_invoke_grant {
        let mut preview = params.clone();
        preview["dry_run"] = json!(true);
        let plan = github_handle_grant(state, &principal_key, &preview);
        if plan.get("error").is_some() {
            return send_tool_response(writer, version, channel, epoch, correlation, plan).await;
        }
        if params["dry_run"] != false {
            return send_tool_response(writer, version, channel, epoch, correlation, plan).await;
        }
        let module: String = params["module"]
            .as_str()
            .unwrap_or("")
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "-_:./".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .take(60)
            .collect();
        Some(format!(
            "grant {} writes ({} expanded) to {} ({}) on all enabled GitHub handles ({} planned)",
            plan["result"]["actions"].as_array().map_or(0, Vec::len),
            plan["result"]["expanded"].as_array().map_or(0, Vec::len),
            module,
            params["effect"].as_str().unwrap_or(""),
            plan["result"]["handles"].as_array().map_or(0, Vec::len)
        ))
    } else {
        operator_confirmation::summary(method, params)
    };
    if let Some(summary) = summary {
        if let Err(refusal) = operator_confirmation::confirm(
            method,
            &summary,
            route,
            writer,
            &route_bindings.control_replies,
        )
        .await
        {
            let response = operator_confirmation::audit_refusal(state, method, &refusal);
            return send_tool_response(writer, version, channel, epoch, correlation, response)
                .await;
        }
        if route_bindings.binding(channel, epoch)?.is_none() {
            let response = operator_confirmation::audit_refusal(
                state,
                method,
                &operator_confirmation::Refusal {
                    code: "operator_confirmation_unavailable",
                    reason: "the caller route closed while awaiting confirmation".to_string(),
                },
            );
            return send_tool_response(writer, version, channel, epoch, correlation, response)
                .await;
        }
    }
    let mut response = match method {
        manifest::ADMIN_SENT_TEXT_READ_OP => blocking_section(|| {
            let Some(row_id) = params.get("row_id").and_then(Value::as_str) else {
                return json!({"error":{"code":"invalid_request","message":"row_id is required"}});
            };
            match state.runtime.engine.read_sent_text("direct", row_id) {
                Ok(bytes) => match std::str::from_utf8(&bytes) {
                    Ok(text) => json!({"result":{"row_id":row_id,"text":text}}),
                    Err(_) => json!({"error":{"code":"sent_text_invalid_utf8"}}),
                },
                Err(code) => json!({"error":{"code":code}}),
            }
        }),
        manifest::ADMIN_SENT_TEXT_RETENTION_OP => {
            match params
                .get("days")
                .and_then(Value::as_i64)
                .filter(|days| (1..=3650).contains(days))
            {
                Some(days) => match state.store().set_sent_text_retention(days) {
                    Ok(()) => json!({"result":{"retention_days":days}}),
                    Err(_) => json!({"error":{"code":"store_failure"}}),
                },
                None => {
                    json!({"error":{"code":"invalid_request","message":"days must be 1..3650"}})
                }
            }
        }
        relay::STATUS_OP => json!({"result": state.health.relay.status()}),
        manifest::ADMIN_RECIPIENTS_ADD_OP
        | manifest::ADMIN_RECIPIENTS_REMOVE_OP
        | manifest::ADMIN_RECIPIENTS_LIST_OP => ceremony::recipients(state, params, method),
        connector_home::STATUS_OP => {
            blocking_section(|| state.runtime.connector_home.live_status())
        }
        manifest::GITHUB_IMPORT_OP => {
            let inventory = serde_json::from_value::<plexus_core::github::control::Inventory>(
                params.get("inventory").cloned().unwrap_or(Value::Null),
            );
            match (inventory, state.runtime.github_handle_credentials.as_ref()) {
                (Ok(inventory), Some(provider)) => {
                    // The reader owns a blocking HTTP client whose runtime may
                    // only be built and dropped off the async worker, so it
                    // lives inside the section.
                    let dry_run = params
                        .get("dry_run")
                        .and_then(Value::as_bool)
                        .unwrap_or(true);
                    match blocking_section(|| {
                        let reader = github_control_reader(state);
                        plexus_core::github::control::import(
                            state.store(),
                            &principal_key,
                            &inventory,
                            provider.as_ref(),
                            reader.as_ref(),
                            plexus_core::storage::now_ms(),
                            dry_run,
                        )
                    }) {
                        Ok(plan) => {
                            if !dry_run {
                                let connection_ids = inventory
                                    .handles
                                    .iter()
                                    .map(|handle| {
                                        plexus_core::github::control::handle_connection_id(
                                            &handle.app_handle_id,
                                        )
                                    })
                                    .collect::<Vec<_>>();
                                register_handle_connection_transports(
                                    state,
                                    &principal_key,
                                    &connection_ids,
                                );
                            }
                            json!({"result":plan})
                        }
                        Err(code) => json!({"error":{"code":code}}),
                    }
                }
                (Err(error), _) => {
                    eprintln!(warn wire: "GitHub inventory could not be decoded: {error}");
                    json!({"error":{"code":"inventory_invalid"}})
                }
                (_, None) => json!({"error":{"code":"handle_credential_unresolvable"}}),
            }
        }
        manifest::GITHUB_PROBE_OP => {
            match (
                params.get("app_handle_id").and_then(Value::as_str),
                state.runtime.github_handle_credentials.as_ref(),
            ) {
                (Some(id), Some(provider)) => {
                    // The reader must be built and dropped inside
                    // `blocking_section`, as in the import arm above.
                    match blocking_section(|| {
                        let reader = github_control_reader(state);
                        plexus_core::github::control::probe(
                            state.store(),
                            &principal_key,
                            id,
                            provider.as_ref(),
                            reader.as_ref(),
                            plexus_core::storage::now_ms(),
                        )
                    }) {
                        Ok(proof) => json!({"result":proof}),
                        Err(code) => json!({"error":{"code":code}}),
                    }
                }
                _ => json!({"error":{"code":"invalid_request"}}),
            }
        }
        manifest::GITHUB_GRANT_OP => github_handle_grant(state, &principal_key, params),
        manifest::GITHUB_BIND_OP => github_handle_bind(state, &principal_key, params),
        manifest::GITHUB_UNBIND_OP => {
            github_handle_unbind(state, &principal_key, params, &fresh_request_id())
        }
        manifest::ADMIN_ISSUE_TICKET_OP => ceremony::issue_ticket(state, &principal_key, params),
        manifest::ADMIN_REBIND_CREDENTIAL_OP => {
            ceremony::rebind_credential(state, &principal_key, params)
        }
        manifest::ADMIN_GRANT_OP => ceremony::grant(state, &principal_key, params),
        manifest::ADMIN_WIDEN_CEILING_OP => ceremony::widen_ceiling(state, &principal_key, params),
        manifest::ADMIN_LIST_GRANTS_OP => ceremony::list_grants(state, &principal_key, params),
        manifest::ADMIN_SET_POLICY_OP => ceremony::set_policy(state, &principal_key, params),
        manifest::ADMIN_LIST_POLICIES_OP => ceremony::list_policies(state, &principal_key, params),
        manifest::ADMIN_REMOVE_POLICY_OP => ceremony::remove_policy(state, &principal_key, params),
        manifest::ADMIN_REVIEW_ACTION_OP => ceremony::review_action(state, &principal_key, params),
        manifest::ADMIN_REPIN_ACTION_OP => ceremony::repin_action(state, &principal_key, params),
        manifest::ADMIN_REVOKE_GRANT_OP => ceremony::revoke_grant(state, &principal_key, params),
        manifest::ADMIN_DELETE_CONNECTION_OP => {
            ceremony::delete_connection(state, &principal_key, params)
        }
        manifest::ADMIN_SET_WEB_SEARCH_LIMIT_OP => {
            ceremony::set_web_search_limit(state, &principal_key, params)
        }
        manifest::ADMIN_SET_WEB_SEARCH_ORDER_OP => {
            ceremony::set_web_search_order(state, &principal_key, params)
        }
        manifest::ADMIN_SET_WEB_SEARCH_ALLOWANCE_OP => {
            ceremony::set_web_search_allowance(state, &principal_key, params)
        }
        // The composite operations confirm for themselves, once, with a
        // summary built from their own plan.
        manifest::ADMIN_ADD_WEB_SEARCH_PROVIDER_OP => {
            web_search_provider_admin::add(
                route,
                params,
                writer,
                state,
                route_bindings,
                &principal_key,
            )
            .await?
        }
        manifest::ADMIN_ADD_WRITE_CONNECTION_OP => {
            connection_enrollment_admin::add_write(
                route,
                params,
                writer,
                state,
                route_bindings,
                &principal_key,
            )
            .await?
        }
        manifest::ADMIN_ADD_POLL_CONNECTION_OP => {
            connection_enrollment_admin::add_poll(
                route,
                params,
                writer,
                state,
                route_bindings,
                &principal_key,
            )
            .await?
        }
        manifest::ADMIN_WIDEN_AND_GRANT_OP => {
            widen_and_grant_admin::widen_and_grant(
                route,
                params,
                writer,
                state,
                route_bindings,
                &principal_key,
            )
            .await?
        }
        manifest::ADMIN_ONBOARD_GITHUB_BOT_OP => {
            github_bot_admin::onboard(route, params, writer, state, route_bindings, &principal_key)
                .await?
        }
        _ => unreachable!("management operation was checked above"),
    };
    if matches!(
        method,
        manifest::GITHUB_IMPORT_OP
            | manifest::GITHUB_PROBE_OP
            | manifest::GITHUB_GRANT_OP
            | manifest::GITHUB_BIND_OP
    ) && !(method == manifest::GITHUB_GRANT_OP
        && (params["kind"] == "read" || bulk_invoke_grant))
    {
        // Bulk and read upgrades audit changes inside their transaction and leave previews
        // and no-ops untouched, rather than appending a second control audit here.
        // The op has run (an applied bind or grant has changed the store), so
        // a failed audit row is reported alongside its reply, not in place of it.
        if let Err(error) = state.store().audit_github_control(
            &principal_key,
            None,
            params.get("app_handle_id").and_then(Value::as_str),
            method,
            &fresh_request_id(),
            response.pointer("/error/code").and_then(Value::as_str),
        ) {
            warn_audit_failed(&mut response, method, &error);
        }
    }
    send_tool_response(writer, version, channel, epoch, correlation, response).await
}

fn github_handle_unbind(
    state: &ModuleState,
    principal_key: &str,
    params: &Value,
    request_id: &str,
) -> Value {
    let (Some(handle), Some(repository)) = (
        params.get("app_handle_id").and_then(Value::as_str),
        params.get("repository").and_then(Value::as_str),
    ) else {
        return json!({"error":{"code":"invalid_request"}});
    };
    let dry_run = params
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    // Applied unbinds record their audit in the deletion transaction so an
    // audit failure cannot leave an unaudited removal behind.
    match blocking_section(|| {
        plexus_core::github::control::unbind(
            state.store(),
            principal_key,
            handle,
            repository,
            request_id,
            dry_run,
        )
    }) {
        Ok(plan) => json!({"result":plan}),
        Err(code) => github_handle_refusal(&code, handle),
    }
}

pub(super) fn github_control_reader(
    state: &ModuleState,
) -> Arc<dyn plexus_core::github::control::InstallationReader + Send + Sync> {
    state
        .runtime
        .github_control_reader
        .clone()
        .unwrap_or_else(|| Arc::new(plexus_core::github::control::GithubApiReader::default()))
}

/// Register each newly imported handle connection's REST transport from its
/// reviewed manifest, through the same connection-loading path boot uses to
/// re-register every stored connection. A handle import commits its
/// connection row without running discovery, so the in-memory transport map
/// has no config for it until this runs: without it the dispatch router falls
/// through to MCP and the first write reports `mcp_transport_error`.
/// A registration failure is logged at error level with the connection id
/// and the import is kept; a restart still recovers it.
pub(crate) fn register_handle_connection_transports(
    state: &ModuleState,
    principal_key: &str,
    connection_ids: &[String],
) {
    for connection_id in connection_ids {
        if let Err(error) = state.runtime.reconciler.register_connection_transport(
            principal_key,
            connection_id,
            state.runtime.endpoint_override.as_deref(),
        ) {
            eprintln!(error catalog: "handle transport registration failed for connection {principal_key}/{connection_id}: {error}");
        }
    }
}

/// Decode `github.handle.bind` parameters and run the bind against the
/// handle's installation, read with its vault token as the probe reads it.
/// `dry_run` defaults to true, as for the import and the grant.
fn github_handle_bind(state: &ModuleState, principal_key: &str, params: &Value) -> Value {
    let Some(app_handle_id) = params.get("app_handle_id").and_then(Value::as_str) else {
        return json!({"error":{"code":"invalid_request",
            "message":"app_handle_id and repositories are required"}});
    };
    let repositories: Option<Vec<String>> = params
        .get("repositories")
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .map(|value| value.as_str().map(str::to_owned))
                .collect()
        });
    let Some(repositories) = repositories else {
        return json!({"error":{"code":"invalid_request",
            "message":"repositories must be an array of owner/name strings"}});
    };
    let Some(provider) = state.runtime.github_handle_credentials.as_ref() else {
        return json!({"error":{"code":"handle_credential_unresolvable"}});
    };
    let dry_run = params
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    // The reader owns a blocking HTTP client whose runtime may only be built
    // and dropped off the async worker, so it lives inside the section.
    match blocking_section(|| {
        let reader = github_control_reader(state);
        plexus_core::github::control::bind(
            state.store(),
            principal_key,
            app_handle_id,
            &repositories,
            provider.as_ref(),
            reader.as_ref(),
            plexus_core::storage::now_ms(),
            dry_run,
        )
    }) {
        Ok(plan) => json!({"result":plan}),
        Err(code) => github_handle_refusal(&code, app_handle_id),
    }
}

/// Decode `github.handle.grant` parameters and run the grant. `module` and
/// `effect` have no default because each changes what the grant authorizes;
/// `dry_run` defaults to true, as for the import.
///
/// `kind: "poll"` selects the poll form: scheduled-poll read authority for the
/// handle connection's own principal. It takes no `module` or `effect`, since
/// its grantee is fixed and it mints no policy; either is refused rather than
/// silently ignored.
pub(super) fn github_handle_grant(
    state: &ModuleState,
    principal_key: &str,
    params: &Value,
) -> Value {
    let text = |name: &str| params.get(name).and_then(Value::as_str);
    match params.get("kind").map(|kind| kind.as_str()) {
        None | Some(Some("invoke")) => {}
        Some(Some("poll")) => return github_handle_poll_grant(state, principal_key, params),
        Some(Some("read")) => return github_handle_read_grant(state, principal_key, params),
        Some(_) => {
            return json!({"error":{"code":"invalid_request",
                "message":"kind must be \"invoke\", \"poll\" or \"read\""}})
        }
    }
    let all_handles = params
        .get("all_handles")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if params
        .get("all_handles")
        .is_some_and(|value| !value.is_boolean())
        || all_handles == params.get("app_handle_id").is_some()
    {
        return json!({"error":{"code":"invalid_request","message":"invoke requires exactly one of app_handle_id or all_handles: true"}});
    }
    let (Some(module), Some(effect)) = (text("module"), text("effect")) else {
        return json!({"error":{"code":"invalid_request",
            "message":"app_handle_id, actions, module and effect are required"}});
    };
    let app_handle_id = if all_handles {
        "all enabled handles"
    } else {
        let Some(handle) = text("app_handle_id") else {
            return json!({"error":{"code":"invalid_request"}});
        };
        handle
    };
    let actions: Option<Vec<String>> =
        params
            .get("actions")
            .and_then(Value::as_array)
            .and_then(|values| {
                values
                    .iter()
                    .map(|value| value.as_str().map(str::to_owned))
                    .collect()
            });
    let Some(actions) = actions else {
        return json!({"error":{"code":"invalid_request",
            "message":"actions must be an array of action names"}});
    };
    let dry_run = params
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let result = if all_handles {
        plexus_core::github::control::grant_all(
            state.store(),
            principal_key,
            &actions,
            module,
            effect,
            dry_run,
        )
    } else {
        plexus_core::github::control::grant(
            state.store(),
            principal_key,
            app_handle_id,
            &actions,
            module,
            effect,
            dry_run,
        )
    };
    match result {
        Ok(plan) => json!({"result":plan}),
        Err(code) => github_handle_refusal(&code, app_handle_id),
    }
}

/// The poll form of `github.handle.grant`: `app_handle_id`, `actions`, and
/// `dry_run` (default true).
fn github_handle_poll_grant(state: &ModuleState, principal_key: &str, params: &Value) -> Value {
    if params.get("module").is_some() || params.get("effect").is_some() {
        return json!({"error":{"code":"invalid_request",
            "message":"the poll form takes no module or effect: its grantee is the connection's own principal"}});
    }
    let Some(app_handle_id) = params.get("app_handle_id").and_then(Value::as_str) else {
        return json!({"error":{"code":"invalid_request",
            "message":"app_handle_id and actions are required"}});
    };
    let actions: Option<Vec<String>> =
        params
            .get("actions")
            .and_then(Value::as_array)
            .and_then(|values| {
                values
                    .iter()
                    .map(|value| value.as_str().map(str::to_owned))
                    .collect()
            });
    let Some(actions) = actions else {
        return json!({"error":{"code":"invalid_request",
            "message":"actions must be an array of action names"}});
    };
    let dry_run = params
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    match plexus_core::github::control::grant_poll(
        state.store(),
        principal_key,
        app_handle_id,
        &actions,
        dry_run,
    ) {
        Ok(plan) => json!({"result":plan}),
        Err(code) => github_handle_refusal(&code, app_handle_id),
    }
}

fn github_handle_read_grant(state: &ModuleState, principal_key: &str, params: &Value) -> Value {
    let actions: Option<Vec<String>> =
        params
            .get("actions")
            .and_then(Value::as_array)
            .and_then(|values| {
                values
                    .iter()
                    .map(|value| value.as_str().map(str::to_owned))
                    .collect()
            });
    let module = params.get("module").and_then(Value::as_str);
    let handle = params.get("app_handle_id").and_then(Value::as_str);
    let all_handles = params
        .get("all_handles")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (Some(actions), Some(module)) = (actions, module) else {
        return json!({"error":{"code":"invalid_request","message":"module and an array of actions are required"}});
    };
    if params.get("effect").is_some() || all_handles == handle.is_some() || handle == Some("") {
        return json!({"error":{"code":"invalid_request","message":"read takes no effect and requires exactly one of app_handle_id or all_handles: true"}});
    }
    let request = plexus_core::storage::github_store::GithubHandleReadGrant {
        app_handle_id: handle.map(str::to_owned),
        all_handles,
        module: module.to_owned(),
        actions,
        dry_run: params
            .get("dry_run")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    };
    match plexus_core::github::control::grant_read(state.store(), principal_key, &request) {
        Ok(plan) => json!({"result":plan}),
        Err(code) => github_handle_refusal(&code, handle.unwrap_or("all enabled handles")),
    }
}

pub(super) fn github_handle_refusal(code: &str, app_handle_id: &str) -> Value {
    if code == "agent_handle_unknown" {
        json!({"error":{"code":code,"detail":{"app_handle_id":app_handle_id}}})
    } else {
        json!({"error":{"code":code}})
    }
}
