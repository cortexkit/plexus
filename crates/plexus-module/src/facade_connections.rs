//! Facade connection listing, enrollment, configuration, revocation and checks.

use super::*;

pub(super) fn facade_connections_list(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let principal_key = call.metadata_owner();
    Ok({
        match state.store().list_connections(principal_key) {
            Ok(connections) if call.federated_metadata() => {
                let mut visible = Vec::with_capacity(connections.len());
                for connection in connections {
                    match state
                        .store()
                        .is_github_handle_connection(principal_key, &connection.connection_id)
                    {
                        Ok(true) => continue,
                        Ok(false) => visible.push(json!({
                            "connection_id": connection.connection_id,
                            "app_key": connection.app_key,
                            "status": connection.status,
                        })),
                        Err(error) => {
                            return Ok(crate::wire::store_failure(
                                "connections listed",
                                "connections could not be listed",
                                &error,
                            ))
                        }
                    }
                }
                json!({"result": {"connections": visible}})
            }
            Ok(connections) => json!({"result": {"connections": connections}}),
            Err(error) => crate::wire::store_failure(
                "connections listed",
                "connections could not be listed",
                &error,
            ),
        }
    })
}

pub(super) fn facade_connections_connect(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        // The destination is approved on the operator's ticket. Accepting it
        // here would let a ticket holder redirect the bound bearer key.
        if arguments.contains_key("instance_url") {
            return Ok(
                json!({"error":{"code":"argument_undeclared", "field":"instance_url",
                "message":"argument_undeclared{field: instance_url}", "transmission":"not_sent"}}),
            );
        }
        let Some(ticket_id) = arguments.get("ticket_id").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "connect requires ticket_id"}}),
            );
        };
        match state.store().connect_with_ticket(principal_key, ticket_id) {
            Ok(Some(connection)) => {
                // Consuming the ticket has already committed the binding and
                // activated the connection, and the ticket is now spent. So a
                // discovery failure here is NOT a failed connect: reporting
                // one would tell the operator to retry a ticket that no longer
                // exists, while an active connection they cannot see sits in
                // the store. Every outcome therefore returns the connection,
                // with discovery reported separately and honestly — the
                // catalog is refreshed again at invoke time.
                let (discovery, reason) = connect_time_catalog(
                    state,
                    principal_key,
                    &connection.connection_id,
                    &connection.app_key,
                );
                let mut result = json!({"connection": connection, "discovery": discovery});
                if let Some(reason) = reason {
                    result["reason"] = json!(reason);
                }
                json!({ "result": result })
            }
            Ok(None) => {
                json!({"error": {"code": "binding_ticket_invalid", "message": "binding ticket is expired, consumed, or unknown"}})
            }
            Err(error) => crate::wire::store_failure(
                "connection completed",
                "connection could not be completed",
                &error,
            ),
        }
    })
}

/// Seed a connection's catalog from its reviewed manifest, then run
/// discovery, and say how far it got: `complete`, or `degraded`,
/// `unavailable` or `credential_unresolved` with an optional reason. Shared by
/// `connections op=connect` and the admin ceremony that adds a web search
/// provider, so both report the same outcome for the same failure.
pub(super) fn connect_time_catalog(
    state: &Arc<ModuleState>,
    principal_key: &str,
    connection_id: &str,
    app_key: &str,
) -> (&'static str, Option<String>) {
    // The connection's catalog is first seeded from the reviewed manifest, and
    // discovery then reconciles it with the vendor. A failed seed leaves the
    // connection active (the ticket is spent) but its catalog incomplete, so it
    // is reported as degraded discovery, never as complete.
    if let Err(error) =
        state
            .store()
            .seed_catalog_from_manifest(principal_key, connection_id, app_key)
    {
        eprintln!(warn catalog:
            "catalog seed failed during connect of {connection_id}: {error}"
        );
        return (
            "degraded",
            Some("the reviewed manifest's actions could not be seeded; the module log names the cause".to_string()),
        );
    }
    match blocking_section(|| {
        state.runtime.reconciler.discover_for_connection(
            principal_key,
            connection_id,
            state.runtime.credential_source().as_ref(),
            state.runtime.endpoint_override.as_deref(),
        )
    }) {
        Ok(_) => ("complete", None),
        Err(CatalogError::TransportUnavailable { kind }) => (
            "unavailable",
            Some(format!("transport kind '{kind}' is not available")),
        ),
        Err(CatalogError::Credential) => (
            "credential_unresolved",
            Some("credential could not be resolved during connect discovery".to_string()),
        ),
        // Not a store failure and deliberately not an error: connect SUCCEEDS
        // while reporting that discovery did not complete, because refusing
        // here would consume the single-use ticket and leave the operator with
        // neither a connection nor a ticket. The cause is still logged, so an
        // operator can diagnose a degraded discovery whose reply gives no
        // reason.
        Err(error) => {
            eprintln!(warn catalog: "discovery degraded during connect: {error}");
            ("degraded", None)
        }
    }
}

pub(super) fn facade_connections_configure(
    call: &FacadeArguments<'_>,
) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(connection_id) = arguments.get("connection").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "configure requires connection"}}),
            );
        };
        let Some(filters) = arguments.get("resource_filters") else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "configure requires resource_filters"}}),
            );
        };
        // The store checks the admin grant and writes the filters in one
        // fenced transaction, so a grant revoked mid-request cannot be outrun.
        configure_outcome_response(state.store().configure_connection_filters_if_admin(
            principal_key,
            connection_id,
            principal_key,
            filters,
        ))
    })
}

/// The reply for a configure outcome, whether the filters were written or
/// only checked.
pub(super) fn configure_outcome_response(
    outcome: Result<ConfigureOutcome, cortexkit_store::StoreError>,
) -> Value {
    match outcome {
        Ok(ConfigureOutcome::AdminRequired) => {
            json!({"error": {"code": "connection_admin_required", "message": "connection administration grant required"}})
        }
        Ok(ConfigureOutcome::Configured(stored)) => {
            json!({"result": {"resource_filters": stored}})
        }
        Ok(ConfigureOutcome::ConnectionNotFound) => {
            json!({"error": {"code": "connection_not_found", "message": "connection was not found"}})
        }
        Ok(ConfigureOutcome::ManifestMissing) => {
            json!({"error": {"code": "manifest_missing", "message": "vendor manifest is not in the catalog"}})
        }
        Ok(ConfigureOutcome::UndeclaredFilter(key)) => {
            let key = plexus_core::text::refusal_echo(&key);
            json!({"error": {"code": "undeclared_filter", "message": format!("filter key '{key}' is not declared by the vendor manifest"), "key": key}})
        }
        // Distinct from undeclared_filter because the fixes differ:
        // an undeclared filter names a key the VENDOR does not have,
        // while this names one this OPERATION does not read. Telling
        // an operator their key is not in the manifest when they
        // actually mistyped `write_enabling` sends them to read
        // vendor documentation for a spelling mistake.
        Ok(ConfigureOutcome::UnreadFilterKey { key, accepted }) => {
            let key = plexus_core::text::refusal_echo(&key);
            json!({"error": {
                "code": "unread_filter_key",
                "message": format!(
                    "resource_filters key '{key}' is not read by configure (accepted: {})",
                    accepted.join(", ")
                ),
                "key": key,
                "accepted": accepted
            }})
        }
        Ok(ConfigureOutcome::MalformedFilters { field, expected }) => {
            let field = plexus_core::text::refusal_echo(&field);
            json!({"error": {
                "code": "malformed_filters",
                "message": format!("resource_filters {field} must be {expected}"),
                "field": field,
                "expected": expected
            }})
        }
        Err(error) => crate::wire::store_failure(
            "filters configured",
            "filters could not be configured",
            &error,
        ),
    }
}

pub(super) fn facade_connections_revoke(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(connection_id) = arguments.get("connection").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "revoke requires connection"}}),
            );
        };
        // The admin check and the revocation share one fenced transaction.
        // Transports are unregistered only once `Revoked` reports the commit.
        match state
            .store()
            .revoke_connection_if_admin(principal_key, connection_id, principal_key)
        {
            Ok(ConnectionAdminRevokeOutcome::AdminRequired) => {
                json!({"error": {"code": "connection_admin_required", "message": "connection administration grant required"}})
            }
            Ok(ConnectionAdminRevokeOutcome::Revoked) => {
                state
                    .runtime
                    .mcp_transport
                    .unregister_connection(connection_id);
                state
                    .runtime
                    .rest_transport
                    .unregister_connection(connection_id);
                json!({"result": {"revoked": true}})
            }
            Ok(ConnectionAdminRevokeOutcome::ConnectionNotFound) => {
                json!({"error": {"code": "connection_not_found", "message": "connection was not found"}})
            }
            Err(error) => crate::wire::store_failure(
                "connection revoked",
                "connection could not be revoked",
                &error,
            ),
        }
    })
}

pub(super) fn facade_connections_check(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(connection_id) = arguments.get("connection").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "check requires connection"}}),
            );
        };
        match state.store().connection(principal_key, connection_id) {
            Ok(Some(connection)) => json!({"result": {"connection": {
                "connection_id": connection.connection_id,
                "app_key": connection.app_key,
                "status": connection.status,
                "generation": connection.generation,
                "credential_bound": connection.has_credential_binding
            }}}),
            Ok(None) => {
                json!({"error": {"code": "connection_not_found", "message": "connection was not found"}})
            }
            Err(error) => crate::wire::store_failure(
                "connection read",
                "connection could not be read",
                &error,
            ),
        }
    })
}
