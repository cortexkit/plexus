//! Facade catalog application and action discovery.

use super::*;

pub(super) fn facade_catalog_apps(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let principal_key = call.metadata_owner();
    Ok({
        match state.store().list_manifest_summaries(principal_key) {
            Ok(apps) => {
                let mut values = Vec::with_capacity(apps.len());
                for app in apps {
                    if call.federated_metadata() {
                        values.push(json!({"key": app.key, "name": app.name, "tier": app.tier}));
                        continue;
                    }
                    let takes_instance_url =
                        match state.store().manifest_takes_instance_url(&app.key) {
                            Ok(value) => value,
                            Err(error) => {
                                return Ok(crate::wire::store_failure(
                                    "app catalog read",
                                    "app catalog could not be read",
                                    &error,
                                ))
                            }
                        };
                    let mut value = json!(app);
                    value["takes_instance_url"] = json!(takes_instance_url);
                    values.push(value);
                }
                json!({"result": {"apps": values}})
            }
            Err(error) => crate::wire::store_failure(
                "app catalog read",
                "app catalog could not be read",
                &error,
            ),
        }
    })
}

pub(super) fn facade_catalog_list(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let op = call.op;
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.metadata_owner();
    Ok({
        let Some(connection_id) = arguments.get("connection").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "catalog list/inspect requires connection; use op=apps to discover connectable vendors"}}),
            );
        };
        let hidden = if call.federated_metadata() {
            match state
                .store()
                .is_github_handle_connection(principal_key, connection_id)
            {
                Ok(hidden) => hidden,
                Err(error) => {
                    return Ok(crate::wire::store_failure(
                        "catalog read",
                        "catalog could not be read",
                        &error,
                    ))
                }
            }
        } else {
            false
        };
        // A bot connection is undiscoverable to remote callers, including by
        // direct catalog queries. Keep the unknown-id response and validation.
        let actions = if hidden {
            Ok(Vec::new())
        } else {
            state
                .store()
                .list_catalog_actions(principal_key, connection_id)
        };
        match actions {
            Ok(actions) => {
                let actions = if op == Some("inspect") {
                    let Some(action) = arguments
                        .get("action")
                        .and_then(Value::as_str)
                        .filter(|action| !action.is_empty())
                    else {
                        return Ok(tool_error(
                            "invalid_request",
                            "catalog inspect requires action",
                        ));
                    };
                    actions
                        .into_iter()
                        .filter(|row| row.name == action)
                        .collect::<Vec<_>>()
                } else {
                    actions
                };
                if call.federated_metadata() {
                    if hidden {
                        return Ok(json!({"result": {"actions": []}}));
                    }
                    return Ok(
                        match federated::project_actions(state.store(), connection_id, actions) {
                            Ok(actions) => json!({"result": {"actions": actions}}),
                            Err(error) => crate::wire::store_failure(
                                "catalog read",
                                "catalog could not be read",
                                &error,
                            ),
                        },
                    );
                }
                json!({"result": {"actions": actions}})
            }
            Err(error) => {
                crate::wire::store_failure("catalog read", "catalog could not be read", &error)
            }
        }
    })
}
