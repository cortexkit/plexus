//! The privileged operator ceremony: the only path that can create authority.
//!
//! Everything an agent can do with a connection through the module's tools
//! needs authority that has to come from somewhere: `connections op=connect`
//! redeems a binding ticket (a one-time token that attaches a credential to a
//! connection), `configure`/`revoke` need a connection-admin grant, and every
//! `invoke` needs a grant covering that action. None of these can be created
//! through the tools, by design: the enrollment secret must never be a tool
//! argument. So the operations that create and manage authority are served
//! only on the module's management interface (its `ManagementSurface` role),
//! which the operator's admin CLI uses and the agent-facing MCP gateway
//! cannot reach.
//!
//! Authority passes through four links, and each can only narrow what the
//! next one may do, so a reviewer can check the model by reading it rather
//! than by simulating it:
//!
//! 1. the vendor's reviewed manifest limits the maximum risk and the actions
//!    a ticket may authorize;
//! 2. the ticket carries a credential reference, whose vault read is proven
//!    before the ticket is issued, and the limits it was issued with;
//!    redeeming it makes those limits the connection's permanent ceiling;
//! 3. the connection's ceiling limits every grant minted against it;
//! 4. the grant limits every invoke, which the governance engine's grant
//!    check enforces.

use std::sync::Arc;

use plexus_core::storage::web_search_store::WebSearchLimits;
use plexus_core::{
    AuditRecord, Ceiling, CeremonyRefusal, DeleteConnectionOutcome, GrantMintRequest, PolicyRecord,
    RepinActionRefusal,
};
use serde_json::{json, Value};

fn invalid_optional_strings(params: &Value, fields: &[&str]) -> Option<Value> {
    fields
        .iter()
        .find(|field| params.get(**field).is_some_and(|v| !v.is_string()))
        .map(|field| {
            json!({"error":{"code":"invalid_request", "field":field,
            "message":format!("{field} must be a string")}})
        })
}

use crate::ModuleState;

fn prove_credential_read(state: &Arc<ModuleState>, credential_id: &str) -> Result<(), Value> {
    state.runtime.credential_source().get_by_id(credential_id).map(|_| ()).map_err(|error| {
        json!({"error": {
            "code": "credential_read_refused",
            "class": error.class(),
            "message": format!("vault read refused for {credential_id}; verify the exact {credential_id} read grant to reserved:plexus")
        }})
    })
}

pub(crate) fn rebind_credential(
    state: &Arc<ModuleState>,
    principal: &str,
    params: &Value,
) -> Value {
    let Some(connection_id) = params.get("connection_id").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "connection_id is required"}});
    };
    let Some(id) = params
        .get("credential_id")
        .and_then(Value::as_str)
        .filter(|id| plexus_core::credentials::valid_credential_id(id))
    else {
        return json!({"error": {"code": "invalid_request", "message": "a well-formed credential_id is required"}});
    };
    let apply = match params.get("apply") {
        None => false,
        Some(Value::Bool(value)) => *value,
        _ => {
            return json!({"error": {"code": "invalid_request", "message": "apply must be a boolean"}})
        }
    };
    let connection = match state.store().connection(principal, connection_id) {
        Ok(Some(connection)) if connection.status == "active" => connection,
        Ok(_) => {
            return json!({"error": {"code": "connection_not_active", "message": "rebind requires an active connection"}})
        }
        Err(error) => {
            return crate::wire::store_failure(
                "rebind read",
                "connection could not be read",
                &error,
            )
        }
    };
    // App handles have their own reference and generation. Changing the ordinary
    // binding would have no effect on their dispatch authority, so refuse it.
    match state
        .store()
        .connection_has_app_handle(principal, connection_id)
    {
        Ok(true) => {
            return json!({"error": {"code": "invalid_request", "message": "GitHub App handles use the handle management ceremony"}})
        }
        Ok(false) => {}
        Err(error) => {
            return crate::wire::store_failure(
                "handle read",
                "connection authority could not be read",
                &error,
            )
        }
    }
    match state
        .store()
        .manifest_requires_no_credential(&connection.app_key)
    {
        Ok(true) => {
            return json!({"error": {"code": "invalid_request", "message": "this vendor requires no credential"}})
        }
        Ok(false) => {}
        Err(error) => {
            return crate::wire::store_failure(
                "manifest read",
                "manifest could not be read",
                &error,
            )
        }
    }
    let kind = match state
        .store()
        .connection_credential_binding_kind(principal, connection_id)
    {
        Ok(Some(kind)) => kind,
        Ok(None) => "none",
        Err(error) => {
            return crate::wire::store_failure(
                "binding read",
                "binding could not be decoded",
                &error,
            )
        }
    };
    if apply {
        if let Err(error) = prove_credential_read(state, id) {
            return error;
        }
        match state.store().rebind_credential_reference(
            principal,
            connection_id,
            connection.generation,
            id,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return json!({"error": {"code": "connection_changed", "message": "connection changed during the vault read; retry"}})
            }
            Err(error) => {
                return crate::wire::store_failure(
                    "rebind",
                    "credential binding could not be replaced",
                    &error,
                )
            }
        }
    }
    json!({"result": {"connection_id": connection_id, "current_binding_kind": kind,
        "credential_id": id, "applied": apply}})
}

/// Map a refusal onto a typed error body.
///
/// Overreach is always refused, never clamped down to the ceiling: a silent
/// narrowing would leave the operator believing they authorized something they
/// did not, which is worse than a visible failure.
pub(crate) fn refusal_response(refusal: &CeremonyRefusal) -> Value {
    let code = match refusal {
        CeremonyRefusal::UnknownApp(_) => "unknown_app",
        // Distinct from unknown_app on purpose: the operator needs to learn that
        // a decision was taken to withdraw this vendor, not go looking for a
        // spelling mistake.
        CeremonyRefusal::RetiredApp(_) => "app_retired",
        CeremonyRefusal::ConnectionNotFound => "connection_not_found",
        CeremonyRefusal::CeilingAbsent => "ceiling_absent",
        CeremonyRefusal::UndeclaredAction(_) => "action_outside_ceiling",
        // Its own code, because the remedies differ: an undeclared action means
        // editing a manifest, while a connection-ceiling breach cannot be
        // repaired on that connection at all -- the ceiling is permanent from
        // ticket issuance, so the only route is a new ticket. A shared code
        // would send an operator to fix the wrong thing.
        CeremonyRefusal::OutsideConnectionCeiling { .. } => "outside_connection_ceiling",
        CeremonyRefusal::RiskAboveCeiling { .. } => "risk_above_ceiling",
        CeremonyRefusal::InvalidRisk(_) => "invalid_risk",
        CeremonyRefusal::EmptyActionSelectors => "empty_action_selectors",
        CeremonyRefusal::ConnectionAppMismatch { .. } => "connection_app_mismatch",
        CeremonyRefusal::ConnectionRevoked => "connection_revoked",
        CeremonyRefusal::ConnectionExists => "connection_exists",
        CeremonyRefusal::WildcardGrantee => "wildcard_grantee",
    };
    json!({"error": {"code": code, "message": refusal.to_string()}})
}

/// Absent selectors mean "everything this bound allows", which the store expands
/// to a concrete list before storing. A wildcard is never persisted.
fn requested_selectors(params: &Value) -> Result<Vec<String>, Value> {
    let Some(value) = params.get("action_selectors") else {
        return Ok(vec!["*".to_string()]);
    };
    let values = value.as_array().ok_or_else(|| {
        json!({"error": {"code": "invalid_request", "message": "action_selectors must be an array of strings"}})
    })?;
    values.iter().enumerate().map(|(index, value)| {
        value.as_str().map(str::to_owned).ok_or_else(|| {
            json!({"error": {"code": "invalid_request", "message": format!("action_selectors[{index}] must be a string")}})
        })
    }).collect()
}

fn parse_optional_expiry(params: &Value) -> Result<Option<i64>, Value> {
    match params.get("expires_at") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or_else(|| {
            json!({"error": {
                "code": "invalid_request",
                "message": "expires_at must be an epoch milliseconds integer"
            }})
        }),
    }
}

/// Prove a vault reference, store it, and issue the ticket that activates it.
/// Credential-free vendors require no vault read and persist no binding.
pub(crate) fn issue_ticket(state: &Arc<ModuleState>, principal_key: &str, params: &Value) -> Value {
    if let Some(error) = invalid_optional_strings(params, &["risk_ceiling", "connection_id"]) {
        return error;
    }
    if params.get("handle").is_some() {
        return json!({"error": {"code": "handle_bindings_removed", "message": "use credential_id instead of handle"}});
    }
    let Some(app_key) = params.get("app_key").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "issue_ticket requires app_key"}});
    };
    // Only the reviewed manifest may waive a credential, never operator input.
    // Direct-principal admission is the enrollment authority for anonymous vendors.
    let credential_free = match state.store().manifest_requires_no_credential(app_key) {
        Ok(value) => value,
        Err(error) => {
            return crate::wire::store_failure(
                "manifest read",
                "manifest could not be read",
                &error,
            );
        }
    };
    let credential_id = params.get("credential_id").and_then(Value::as_str);
    if params.get("credential_id").is_some() && credential_id.is_none() {
        return json!({"error": {"code": "invalid_request", "message": "credential_id must be a string"}});
    }
    if let Some(id) = credential_id {
        if credential_free || !plexus_core::credentials::valid_credential_id(id) {
            return json!({"error": {"code": "invalid_request", "message": "supply a well-formed credential_id only for a credentialed vendor"}});
        }
        if let Err(error) = prove_credential_read(state, id) {
            return error;
        }
    }
    let reference_bytes = match credential_id {
        Some(id) => id.as_bytes().to_vec(),
        None if credential_free => Vec::new(),
        None => {
            return json!({"error": {"code": "invalid_request", "message": "issue_ticket requires credential_id"}});
        }
    };
    let risk = params
        .get("risk_ceiling")
        .and_then(Value::as_str)
        .unwrap_or("read");
    let selectors = match requested_selectors(params) {
        Ok(selectors) => selectors,
        Err(response) => return response,
    };

    // Link 1: the vendor's reviewed manifest bounds the ticket.
    let ceiling: Ceiling = match state
        .store()
        .ceiling_within_manifest(app_key, risk, &selectors)
    {
        Ok(Ok(ceiling)) => ceiling,
        Ok(Err(refusal)) => return refusal_response(&refusal),
        Err(error) => {
            return crate::wire::store_failure(
                "ceiling resolution",
                "ceiling could not be resolved",
                &error,
            );
        }
    };

    let connection_id = params
        .get("connection_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("conn-{app_key}"));
    // The store creates the connection when the principal has none with this
    // id, and refuses one that is revoked or belongs to a different app.
    // Re-enrolling an existing connection of the same app keeps its ceiling:
    // a wider request is refused by name.

    // The ticket carries the maximum risk and allowed actions. Redeeming it
    // copies those limits to a connection that has none yet. Preserve an
    // existing connection's limits permanently.
    let ref_role = if credential_free {
        plexus_core::NO_CREDENTIAL_REF_ROLE
    } else {
        "credential_reference"
    };
    match state.store().issue_binding_ticket(
        principal_key,
        &connection_id,
        app_key,
        ref_role,
        &reference_bytes,
        &ceiling,
    ) {
        Ok(Err(refusal)) => refusal_response(&refusal),
        Ok(Ok(ticket)) => {
            let fingerprint = if credential_free {
                None
            } else {
                Some(plexus_core::fingerprint(&reference_bytes))
            };
            if let Err(error) = state.store().append_audit(&AuditRecord::ceremony(
                principal_key,
                Some(app_key),
                Some(&connection_id),
                "issue_ticket",
                &ceiling.risk.to_string(),
                fingerprint.as_deref(),
            )) {
                eprintln!(error governance: "audit append failed: ceremony issue_ticket principal={principal_key:?} connection_id={connection_id:?}: {error}");
            }
            json!({"result": {
                "ticket_id": ticket.ticket_id,
                "connection_id": connection_id,
                "expires_at": ticket.expires_at,
                "ceiling": {
                    "risk": ceiling.risk.to_string(),
                    "action_selectors": ceiling.action_selectors
                }
            }})
        }
        Err(error) => crate::wire::store_failure(
            "binding ticket issued",
            "binding ticket could not be issued",
            &error,
        ),
    }
}

/// Mint a grant, bounded by the connection's ceiling (link 3).
pub(crate) fn grant(state: &Arc<ModuleState>, principal_key: &str, params: &Value) -> Value {
    if let Some(error) = invalid_optional_strings(
        params,
        &["grantee_principal", "authority_kind", "risk_ceiling"],
    ) {
        return error;
    }
    let Some(connection_id) = params.get("connection_id").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "grant requires connection_id"}});
    };
    let grantee = params
        .get("grantee_principal")
        .and_then(Value::as_str)
        .unwrap_or(principal_key);
    let authority_kind = params
        .get("authority_kind")
        .and_then(Value::as_str)
        .unwrap_or("invoke");
    // `poll` belongs here even though no agent may ask for it: a subscription
    // cannot be authorized without a poll grant, and minting one is an operator
    // act by construction because this surface is unreachable from the MCP
    // gateway. Omitting it made the entire trigger plane unreachable in
    // production -- the store accepts poll grants and the poller claims poll
    // authority, so every layer worked except the one an operator has to type
    // through.
    //
    // Expiry is optional for every authority kind, including poll. An operator
    // who wants a bounded grant passes an expiry; omitted or null means the
    // grant lasts until revoked. Forgotten grants remain recoverable through
    // the listing surface plus explicit revocation.
    if !matches!(
        authority_kind,
        "invoke"
            | "connection_admin"
            | plexus_core::AUTHORITY_POLL
            | plexus_core::AUTHORITY_EVENTS_CONSUME
    ) {
        return json!({"error": {"code": "invalid_request", "message": "authority_kind must be invoke, connection_admin, poll, or events_consume"}});
    }
    let risk = params
        .get("risk_ceiling")
        .and_then(Value::as_str)
        .unwrap_or("read");
    let selectors = match requested_selectors(params) {
        Ok(selectors) => selectors,
        Err(response) => return response,
    };
    let expires_at = match parse_optional_expiry(params) {
        Ok(expires_at) => expires_at,
        Err(response) => return response,
    };
    match state.store().mint_grant_bounded(&GrantMintRequest {
        principal: principal_key,
        connection_id,
        grantee_principal: grantee,
        authority_kind,
        requested_risk: risk,
        requested_selectors: &selectors,
        expires_at,
    }) {
        Ok(Ok(minted)) => {
            if let Err(error) = state.store().append_audit(&AuditRecord::ceremony(
                principal_key,
                None,
                Some(connection_id),
                "grant",
                &minted.risk_ceiling,
                None,
            )) {
                eprintln!(error governance: "audit append failed: ceremony grant principal={principal_key:?} connection_id={connection_id:?}: {error}");
            }
            json!({"result": {"grant": {
                "grant_id": minted.grant_id,
                "connection_id": minted.connection_id,
                "grantee_principal": minted.grantee_principal,
                "authority_kind": minted.authority_kind,
                "risk_ceiling": minted.risk_ceiling,
                "action_selectors": minted.action_selectors,
                "expires_at": minted.expires_at
            }}})
        }
        Ok(Err(refusal)) => refusal_response(&refusal),
        Err(error) => {
            crate::wire::store_failure("grant minted", "grant could not be minted", &error)
        }
    }
}

/// Every grant this operator holds, across all connections, or on the one
/// connection named by `connection_id`.
///
/// The counterpart to revocation: an operator cannot revoke what they cannot
/// see, and the grant most needing revocation is by definition the one they
/// forgot. This is the surface an app renders that list from.
///
/// Read-only. It reports the caller's own grants, so there is no way to ask
/// about someone else's. A `connection_id` that is present but not a string is
/// refused rather than ignored: ignoring it would answer with every grant.
pub(crate) fn list_grants(state: &Arc<ModuleState>, principal_key: &str, params: &Value) -> Value {
    let connection_id = match params.get("connection_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(connection_id)) => Some(connection_id.as_str()),
        Some(_) => {
            return json!({"error": {"code": "invalid_request", "message": "connection_id must be a string"}})
        }
    };
    match state.store().list_all_grants(principal_key) {
        Ok(mut grants) => {
            if let Some(connection_id) = connection_id {
                grants.retain(|grant| grant.connection_id == connection_id);
            }
            json!({"result": {"grants": grants}})
        }
        Err(error) => {
            crate::wire::store_failure("grants listed", "grants could not be read", &error)
        }
    }
}

pub(crate) fn revoke_grant(state: &Arc<ModuleState>, principal_key: &str, params: &Value) -> Value {
    let Some(grant_id) = params.get("grant_id").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "revoke_grant requires grant_id"}});
    };
    // Read before the revoke so the audit row can name the grant's
    // connection and ceiling; after it the row is gone. A failed read only
    // thins the audit row, it never blocks the revoke.
    let revoked = match state.store().grant_by_id(principal_key, grant_id) {
        Ok(grant) => grant,
        Err(error) => {
            eprintln!(warn governance: "revoke_grant could not read grant {grant_id:?} for its audit row: {error}");
            None
        }
    };
    match state
        .store()
        .revoke_grant_as(principal_key, grant_id, principal_key)
    {
        Ok(removed) => {
            if removed {
                let mut audit = AuditRecord::ceremony(
                    principal_key,
                    revoked.as_ref().and_then(|grant| grant.app_key.as_deref()),
                    revoked.as_ref().map(|grant| grant.connection_id.as_str()),
                    "revoke_grant",
                    revoked
                        .as_ref()
                        .map_or("unknown", |grant| grant.risk_ceiling.as_str()),
                    None,
                );
                // The audit row has no grant column, so the grant id goes in
                // the summary, the same way `AuditRecord::agent_retired_revocation`
                // records it.
                audit.args_redaction_summary = Some(format!("grant {grant_id} revoked"));
                if let Err(error) = state.store().append_audit(&audit) {
                    eprintln!(error governance: "audit append failed: ceremony revoke_grant principal={principal_key:?} grant_id={grant_id:?}: {error}");
                }
            }
            json!({"result": {"revoked": removed}})
        }
        Err(error) => {
            crate::wire::store_failure("grant revoked", "grant could not be revoked", &error)
        }
    }
}

/// Return the preserved and observed schemas for an operator's explicit review.
pub(crate) fn review_action(
    state: &Arc<ModuleState>,
    principal_key: &str,
    params: &Value,
) -> Value {
    let Some(connection_id) = params.get("connection_id").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "review_action requires connection_id"}});
    };
    let Some(action) = params.get("action").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "review_action requires action"}});
    };
    match state
        .store()
        .catalog_action_review(principal_key, connection_id, action)
    {
        Ok(Some(review)) => action_review_response(connection_id, review, plexus_core::jcs_sha256),
        Ok(None) => {
            json!({"error": {"code": "action_not_found", "message": "action was not found in the catalog"}})
        }
        Err(error) => crate::wire::store_failure(
            "action review read",
            "action review could not be read",
            &error,
        ),
    }
}

fn action_review_response(
    connection_id: &str,
    review: plexus_core::CatalogActionReview,
    hash: impl FnOnce(&Value) -> Result<String, plexus_core::JcsError>,
) -> Value {
    let pinned_schema_hash = match review.reviewed_schema.as_ref().map(hash).transpose() {
        Ok(hash) => hash,
        Err(error) => {
            return crate::wire::store_failure(
                "action review schema hash",
                "action review could not be read",
                &error,
            )
        }
    };
    json!({"result": {
        "connection_id": connection_id,
        "action": review.action.name,
        "status": review.action.status,
        "pinned_schema_hash": pinned_schema_hash,
        "current_schema_hash": review.action.schema_hash,
        "reviewed_schema_json": review.reviewed_schema,
        "current_schema_json": review.action.schema,
    }})
}

/// Activate exactly the current read schema after the operator has reviewed it.
pub(crate) fn repin_action(state: &Arc<ModuleState>, principal_key: &str, params: &Value) -> Value {
    let Some(connection_id) = params.get("connection_id").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "repin_action requires connection_id"}});
    };
    let Some(action) = params.get("action").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "repin_action requires action"}});
    };
    let Some(expected_schema_hash) = params.get("expected_schema_hash").and_then(Value::as_str)
    else {
        return json!({"error": {"code": "invalid_request", "message": "repin_action requires expected_schema_hash"}});
    };
    match state.store().repin_reviewed_action(
        principal_key,
        connection_id,
        action,
        expected_schema_hash,
    ) {
        Ok(Ok(reactivated)) => {
            if let Err(error) = state.store().append_audit(&AuditRecord::ceremony(
                principal_key,
                None,
                Some(connection_id),
                "repin_action",
                "read",
                None,
            )) {
                eprintln!(error governance: "audit append failed: ceremony repin_action principal={principal_key:?} connection_id={connection_id:?}: {error}");
            }
            json!({"result": {
                "action": reactivated.name,
                "status": reactivated.status,
                "schema_hash": reactivated.schema_hash,
            }})
        }
        Ok(Err(refusal)) => repin_refusal_response(&refusal),
        Err(error) => {
            crate::wire::store_failure("action re-pinned", "action could not be re-pinned", &error)
        }
    }
}

fn repin_refusal_response(refusal: &RepinActionRefusal) -> Value {
    json!({"error": {"code": refusal.code(), "message": refusal.to_string()}})
}

/// Create or update the policy scope an operator names.
pub(crate) fn set_policy(state: &Arc<ModuleState>, principal_key: &str, params: &Value) -> Value {
    let Some(connection_id) = params.get("connection_id").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "set_policy requires connection_id"}});
    };
    let Some(action_selector) = params.get("action_selector").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "set_policy requires action_selector"}});
    };
    if action_selector.is_empty() {
        return json!({"error": {"code": "invalid_request", "message": "action_selector must not be empty"}});
    }
    let Some(effect) = params.get("effect").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "set_policy requires effect"}});
    };
    if !matches!(effect, "allow" | "ask_first" | "block") {
        return json!({"error": {"code": "invalid_request", "message": "effect must be allow, ask_first, or block"}});
    }
    let expires_at = match parse_optional_expiry(params) {
        Ok(expires_at) => expires_at,
        Err(response) => return response,
    };
    match state.store().set_policy(
        principal_key,
        connection_id,
        action_selector,
        effect,
        expires_at,
    ) {
        Ok(policy) => {
            let mut audit = AuditRecord::ceremony(
                principal_key,
                None,
                Some(connection_id),
                "set_policy",
                "write",
                None,
            );
            audit.risk = None;
            audit.args_redaction_summary = Some(format!("policy effect={effect}"));
            if let Err(error) = state.store().append_audit(&audit) {
                eprintln!(error governance: "audit append failed: ceremony set_policy principal={principal_key:?} connection_id={connection_id:?}: {error}");
            }
            json!({"result": {"policy": policy_json(&policy)}})
        }
        Err(error) => crate::wire::store_failure("policy set", "policy could not be set", &error),
    }
}

/// List policy rows an operator owns, optionally narrowed to one connection.
pub(crate) fn list_policies(
    state: &Arc<ModuleState>,
    principal_key: &str,
    params: &Value,
) -> Value {
    let connection_id = match params.get("connection_id") {
        None => None,
        Some(Value::String(id)) => Some(id.as_str()),
        Some(_) => {
            return json!({"error":{"code":"invalid_request","field":"connection_id", "message":"connection_id must be a string"}})
        }
    };
    match state.store().list_policies(principal_key, connection_id) {
        Ok(policies) => json!({"result": {"policies": policies}}),
        Err(error) => {
            crate::wire::store_failure("policies listed", "policies could not be read", &error)
        }
    }
}

/// Remove a policy. Retrying an already-completed removal is safe.
pub(crate) fn remove_policy(
    state: &Arc<ModuleState>,
    principal_key: &str,
    params: &Value,
) -> Value {
    let Some(policy_id) = params.get("policy_id").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "remove_policy requires policy_id"}});
    };
    // Read before the delete so the audit row can name the policy's
    // connection and effect, as set_policy's row does. A failed read only
    // thins the audit row, it never blocks the removal.
    let removed_policy = match state.store().policy_by_id(principal_key, policy_id) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!(warn governance: "remove_policy could not read policy {policy_id:?} for its audit row: {error}");
            None
        }
    };
    match state.store().remove_policy(principal_key, policy_id) {
        Ok(removed) => {
            if removed {
                let mut audit = AuditRecord::ceremony(
                    principal_key,
                    removed_policy
                        .as_ref()
                        .and_then(|policy| policy.app_key.as_deref()),
                    removed_policy
                        .as_ref()
                        .map(|policy| policy.connection_id.as_str()),
                    "remove_policy",
                    "write",
                    None,
                );
                audit.risk = None;
                audit.args_redaction_summary = Some(format!(
                    "policy {policy_id} removed; effect={}",
                    removed_policy
                        .as_ref()
                        .map_or("unknown", |p| p.effect.as_str())
                ));
                if let Err(error) = state.store().append_audit(&audit) {
                    eprintln!(error governance: "audit append failed: ceremony remove_policy principal={principal_key:?} policy_id={policy_id:?}: {error}");
                }
            }
            json!({"result": {"removed": removed}})
        }
        Err(error) => {
            crate::wire::store_failure("policy removed", "policy could not be removed", &error)
        }
    }
}

/// Delete a connection, with every row keyed by it except its audit rows and
/// grant revocation snapshots, which age out through audit retention.
///
/// It removes no authority anyone still holds, so it needs no step-up: it
/// refuses while a grant on the connection is live (revoking those grants is
/// the explicit act that cuts a consumer off, and this op must never do it as
/// a side effect), and it refuses a connection that backs a GitHub App
/// handle, whose lifecycle belongs to the handle. Dry run unless `dry_run` is
/// exactly `false`, matching the handle ops. The store writes the audit row
/// in the delete's own transaction. Deleting a connection that is already
/// gone reports `connection_not_found` and writes nothing, so a retry is safe.
pub(crate) fn delete_connection(
    state: &Arc<ModuleState>,
    principal_key: &str,
    params: &Value,
) -> Value {
    let Some(connection_id) = params.get("connection_id").and_then(Value::as_str) else {
        return json!({"error": {"code": "invalid_request", "message": "delete_connection requires connection_id"}});
    };
    let dry_run = params
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let outcome = match state
        .store()
        .delete_connection(principal_key, connection_id, !dry_run)
    {
        Ok(outcome) => outcome,
        Err(error) => {
            return crate::wire::store_failure(
                "connection deleted",
                "connection could not be deleted",
                &error,
            )
        }
    };
    let rows_json = |rows: &[(&str, i64)]| -> Value {
        rows.iter()
            .map(|(table, count)| ((*table).to_string(), Value::from(*count)))
            .collect::<serde_json::Map<_, _>>()
            .into()
    };
    match outcome {
        DeleteConnectionOutcome::NotFound => json!({"error": {
            "code": "connection_not_found",
            "message": format!("no connection {connection_id} is owned by this principal"),
        }}),
        DeleteConnectionOutcome::HandleConnection => json!({"error": {
            "code": "connection_is_github_handle",
            "message": format!(
                "{connection_id} backs a GitHub App handle; it is created and ended with the handle"
            ),
        }}),
        // A fixed code with the count beside it, so a script can match the
        // code exactly however many grants remain.
        DeleteConnectionOutcome::HasLiveGrants { count } => json!({"error": {
            "code": "connection_has_live_grants",
            "count": count,
            "message": format!(
                "{connection_id} still has {count} live grant(s); list them with list-grants \
                 --connection {connection_id} and revoke them first"
            ),
        }}),
        DeleteConnectionOutcome::WouldDelete {
            app_key,
            status,
            rows,
        } => json!({"result": {
            "connection_id": connection_id,
            "app_key": app_key,
            "outcome": "would_delete",
            "status": status,
            "rows": rows_json(&rows),
            "dry_run": true,
        }}),
        DeleteConnectionOutcome::Deleted {
            app_key,
            status,
            rows,
        } => {
            state
                .runtime
                .mcp_transport
                .unregister_connection(connection_id);
            state
                .runtime
                .rest_transport
                .unregister_connection(connection_id);
            json!({"result": {
            "connection_id": connection_id,
            "app_key": app_key,
            "outcome": "deleted",
            "status": status,
            "rows": rows_json(&rows),
                "dry_run": false,
            }})
        }
    }
}

/// Largest per-minute limit the operator may set. Far above any real search
/// budget; it exists so a typo cannot store a number that disables limiting.
const MAX_WEB_SEARCH_LIMIT: u64 = 100_000;

/// Set one web search backend's per-caller and per-backend calls per minute.
///
/// Dry run unless `dry_run` is exactly `false`, matching the other operator
/// ops: the dry run reports the current and proposed limits and writes
/// nothing. An applied change writes the limits row and one audit row, and
/// takes effect on the next search without a restart.
pub(crate) fn set_web_search_limit(
    state: &Arc<ModuleState>,
    principal_key: &str,
    params: &Value,
) -> Value {
    let backend = state.runtime.web_search.backend_name();
    match params.get("backend").and_then(Value::as_str) {
        Some(named) if named == backend => {}
        Some(named) => {
            return json!({"error": {
                "code": "unknown_backend",
                "message": format!("'{named}' is not a web search backend; known: {backend}"),
            }})
        }
        None => {
            return json!({"error": {"code": "invalid_request", "message": "set_web_search_limit requires backend"}})
        }
    }
    let limit = |field: &str| {
        params
            .get(field)
            .and_then(Value::as_u64)
            .filter(|value| (1..=MAX_WEB_SEARCH_LIMIT).contains(value))
            .map(|value| value as u32)
    };
    let (Some(per_caller), Some(per_backend)) = (
        limit("per_caller_per_minute"),
        limit("per_backend_per_minute"),
    ) else {
        return json!({"error": {
            "code": "invalid_request",
            "message": format!(
                "set_web_search_limit requires per_caller_per_minute and per_backend_per_minute, each 1..={MAX_WEB_SEARCH_LIMIT}"
            ),
        }});
    };
    let proposed = WebSearchLimits {
        per_caller_per_minute: per_caller,
        per_backend_per_minute: per_backend,
    };
    let dry_run = params
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let limits_json = |limits: WebSearchLimits| {
        json!({
            "per_caller_per_minute": limits.per_caller_per_minute,
            "per_backend_per_minute": limits.per_backend_per_minute,
        })
    };
    let current = match state.store().web_search_limits(backend) {
        Ok(current) => current,
        Err(error) => {
            return crate::wire::store_failure(
                "web search limits read",
                "web search limits could not be read",
                &error,
            )
        }
    };
    let (current, current_source) = match current {
        Some(current) => (current, "set"),
        None => (plexus_core::web_search::default_limits(), "default"),
    };
    if dry_run {
        return json!({"result": {
            "backend": backend,
            "outcome": "would_set",
            "current": limits_json(current),
            "current_source": current_source,
            "proposed": limits_json(proposed),
            "dry_run": true,
        }});
    }
    if let Err(error) = state.store().set_web_search_limits(backend, proposed) {
        return crate::wire::store_failure(
            "web search limits set",
            "web search limits could not be set",
            &error,
        );
    }
    let mut record = AuditRecord::ceremony(
        principal_key,
        None,
        None,
        "set_web_search_limit",
        "write",
        None,
    );
    record.args_redaction_summary = Some(format!(
        "backend={backend} per_caller_per_minute {} -> {per_caller}, per_backend_per_minute {} -> {per_backend} (previous values were {current_source})",
        current.per_caller_per_minute, current.per_backend_per_minute
    ));
    if let Err(error) = state.store().append_audit(&record) {
        eprintln!(error governance: "audit append failed: ceremony set_web_search_limit principal={principal_key:?} backend={backend:?}: {error}");
    }
    json!({"result": {
        "backend": backend,
        "outcome": "set",
        "previous": limits_json(current),
        "previous_source": current_source,
        "current": limits_json(proposed),
        "dry_run": false,
    }})
}

/// Only the operator's direct connection may manage recipient lists. Omitting
/// the agent or passing null selects the module-only list, never every agent's
/// list, so a module-only entry cannot widen an agent's own authority.
///
/// Management calls come only from the direct principal, so the list edited is
/// the one on that principal's own connection. Connection ids are unique only
/// per owner; another owner's connection with the same id is not found here.
pub(crate) fn recipients(state: &Arc<ModuleState>, params: &Value, method: &str) -> Value {
    let owner = crate::principal::principal_key(&subc_protocol::Principal::Direct);
    let Some(connection) = params
        .get("connection")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
    else {
        return json!({"error":{"code":"invalid_request","message":"connection is required"}});
    };
    let agent = match params.get("agent") {
        None | Some(Value::Null) => None,
        Some(Value::String(agent)) if !agent.trim().is_empty() => Some(agent.as_str()),
        _ => {
            return json!({"error":{"code":"invalid_request","message":"agent must be a nonempty string or null"}})
        }
    };
    match state.store().connection(&owner, connection) {
        Ok(Some(_)) => {}
        Ok(None) => return json!({"error":{"code":"connection_not_found"}}),
        Err(error) => {
            return crate::wire::store_failure(
                "recipients connection",
                "connection could not be read",
                &error,
            )
        }
    }
    if method == crate::manifest::ADMIN_RECIPIENTS_LIST_OP {
        return match state.store().list_recipients(&owner, connection, agent) {
            Ok(recipients) => {
                json!({"result":{"connection":connection,"agent":agent,"recipients":recipients}})
            }
            Err(error) => crate::wire::store_failure(
                "recipients list",
                "recipient allowlist could not be read",
                &error,
            ),
        };
    }
    let Some(recipient) = params
        .get("recipient")
        .and_then(Value::as_str)
        .map(plexus_core::recipients::normalize_recipient)
        .filter(|s| !s.is_empty())
    else {
        return json!({"error":{"code":"invalid_request","message":"recipient is required"}});
    };
    let add = method == crate::manifest::ADMIN_RECIPIENTS_ADD_OP;
    let apply = params.get("dry_run") == Some(&Value::Bool(false));
    match state
        .store()
        .change_recipient(&owner, connection, agent, &recipient, add, apply)
    {
        Ok(plexus_core::storage::RecipientChange::ConnectionNotFound) => {
            json!({"error":{"code":"connection_not_found"}})
        }
        Ok(change) => {
            let outcome = if !apply {
                if add {
                    "would_add"
                } else {
                    "would_remove"
                }
            } else if change == plexus_core::storage::RecipientChange::Unchanged {
                if add {
                    "already_present"
                } else {
                    "not_present"
                }
            } else if add {
                "added"
            } else {
                "removed"
            };
            json!({"result":{"connection":connection,"agent":agent,"recipient":recipient,"dry_run":!apply,"widening":add,"outcome":outcome}})
        }
        Err(error) => crate::wire::store_failure(
            "recipients change",
            "recipient allowlist could not be changed",
            &error,
        ),
    }
}

fn policy_json(policy: &PolicyRecord) -> Value {
    json!({
        "policy_id": policy.policy_id,
        "connection_id": policy.connection_id,
        "action_selector": policy.action_selector,
        "effect": policy.effect,
        "expires_at": policy.expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    use plexus_core::test_scratch::Scratch;
    use plexus_core::{ingest_value, PlexusStore};

    const TEST_CONNECTION: &str = "conn-grant-expiry";

    #[test]
    fn deleting_connection_unregisters_transports_only_after_commit() {
        let (state, _store) = grant_test_state("delete-unregister");
        state
            .runtime
            .mcp_transport
            .register_connection(plexus_core::McpConnection::new(
                TEST_CONNECTION,
                "http://127.0.0.1:1",
            ));
        state
            .runtime
            .rest_transport
            .register_connection(plexus_core::RestConnection::new(
                TEST_CONNECTION,
                "http://127.0.0.1:1",
            ));
        let preview =
            delete_connection(&state, "direct", &json!({"connection_id":TEST_CONNECTION}));
        assert_eq!(preview["result"]["outcome"], "would_delete");
        assert!(state.runtime.mcp_transport.has_connection(TEST_CONNECTION));
        assert!(state.runtime.rest_transport.has_connection(TEST_CONNECTION));
        let deleted = delete_connection(
            &state,
            "direct",
            &json!({"connection_id":TEST_CONNECTION, "dry_run":false}),
        );
        assert_eq!(deleted["result"]["outcome"], "deleted");
        assert!(!state.runtime.mcp_transport.has_connection(TEST_CONNECTION));
        assert!(!state.runtime.rest_transport.has_connection(TEST_CONNECTION));
    }

    fn grant_test_state(label: &str) -> (Arc<ModuleState>, Arc<PlexusStore>) {
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: label.to_string(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        grant_test_state_with_descriptor(&descriptor)
    }

    fn grant_test_state_with_descriptor(
        descriptor: &StorageDescriptor,
    ) -> (Arc<ModuleState>, Arc<PlexusStore>) {
        let store = Arc::new(PlexusStore::open(descriptor).expect("open grant test store"));
        let manifest = ingest_value(json!({
            "schema_version": 1,
            "key": "grant_expiry_test",
            "name": "Grant expiry test",
            "description": "Exercises management grant expiry parsing",
            "reuse_path": "mcp_direct",
            "reuse_rationale": "tests",
            "tier": "S1",
            "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
            "auth": {"mode": "api_key"},
            "credential_bindings": [{
                "ref_role": "api_key",
                "placement": "header",
                "key": "Authorization",
                "prefix": "Bearer ",
                "required": true
            }],
            "resource_filters": {"required": [], "optional": [], "write_enabling": []},
            "actions_baseline": [
                {"name": "read_item", "risk": "read"},
                {"name": "read_other", "risk": "read"}
            ],
            "defaults": {
                "ask_first_risk": ["write"],
                "rate_limit": {"calls_per_min": 30}
            },
            "availability": "ga"
        }))
        .expect("test manifest ingests");
        store
            .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &manifest)
            .expect("store test manifest");
        let ceiling = store
            .ceiling_within_manifest("grant_expiry_test", "read", &["*".to_string()])
            .expect("resolve test ceiling")
            .expect("test ceiling is within manifest");
        store
            .create_connection("direct", TEST_CONNECTION, "grant_expiry_test")
            .expect("create grant test connection");
        let ticket = store
            .create_binding_ticket_bounded(
                "direct",
                TEST_CONNECTION,
                "credential_reference",
                b"test:grant_expiry",
                &ceiling,
            )
            .expect("create bounded test ticket");
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("consume test ticket")
            .expect("activate test connection");
        let state = Arc::new(ModuleState {
            health: Arc::new(crate::health::HealthState::new()),
            runtime: crate::runtime_for_test(Arc::clone(&store)),
        });
        (state, store)
    }

    fn grant_params() -> Value {
        json!({
            "connection_id": TEST_CONNECTION,
            "risk_ceiling": "read",
            "action_selectors": ["read_item"]
        })
    }

    struct SelectorFixture {
        state: Arc<ModuleState>,
        store: Arc<PlexusStore>,
        // Removing this directory is the guard's own job, which is why this
        // fixture no longer has a `Drop` of its own.
        directory: Scratch,
    }

    impl SelectorFixture {
        fn new() -> Self {
            let directory = Scratch::directory("selectors");
            let descriptor = StorageDescriptor {
                module_id: "plexus".to_string(),
                storage_namespace: "selector-shape".to_string(),
                isolation: Isolation::Module,
                backend: StorageBackend::Sqlite {
                    path: directory.join("store.db").to_string_lossy().into_owned(),
                },
            };
            let (state, store) = grant_test_state_with_descriptor(&descriptor);
            Self {
                state,
                store,
                directory,
            }
        }

        fn ticket_count(&self) -> i64 {
            // Count the actual rows, including consumed tickets, so a refusal
            // cannot hide a ticket minted before the error response.
            rusqlite::Connection::open_with_flags(
                self.directory.join("store.db"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap()
            .query_row("SELECT COUNT(*) FROM binding_tickets", [], |row| row.get(0))
            .unwrap()
        }
    }

    fn audit_failure_scenario(operation: &str) {
        for fail in [false, true] {
            let fixture = SelectorFixture::new();
            let path = fixture.directory.join("store.db");
            let mut params = match operation {
                "issue_ticket" => ticket_params(),
                "grant" => grant_params(),
                "revoke_grant" => {
                    let response = grant(&fixture.state, "direct", &grant_params());
                    json!({"grant_id": response["result"]["grant"]["grant_id"]})
                }
                "set_policy" => {
                    json!({"connection_id": TEST_CONNECTION, "action_selector": "read_item", "effect": "block"})
                }
                "remove_policy" => {
                    let policy = fixture
                        .store
                        .set_policy("direct", TEST_CONNECTION, "read_item", "block", None)
                        .unwrap();
                    json!({"policy_id": policy.policy_id})
                }
                "repin_action" => {
                    fixture
                        .store
                        .upsert_catalog_action(&plexus_core::CatalogActionInput {
                            principal: "direct".into(),
                            connection_id: TEST_CONNECTION.into(),
                            name: "read_item".into(),
                            title: None,
                            schema: json!({"type":"object"}),
                            schema_hash: "reviewed-hash".into(),
                            risk: "read".into(),
                            severity: "S1".into(),
                            ask_first: false,
                            status: "quarantined".into(),
                            quarantine_reason: Some("schema_changed".into()),
                            reconciliation: None,
                        })
                        .unwrap();
                    json!({"connection_id": TEST_CONNECTION, "action": "read_item", "expected_schema_hash": "reviewed-hash"})
                }
                _ => panic!("unknown ceremony"),
            };
            // Install the audit-insert fault after fixture setup so only the
            // operation under test loses its audit record.
            let before = fixture.store.list_audit("direct").unwrap().len();
            if fail {
                crate::audit_test::reject_inserts(&path);
            }
            let response = match operation {
                "issue_ticket" => issue_ticket(&fixture.state, "direct", &params),
                "grant" => grant(&fixture.state, "direct", &params),
                "revoke_grant" => revoke_grant(&fixture.state, "direct", &params),
                "set_policy" => set_policy(&fixture.state, "direct", &params),
                "remove_policy" => remove_policy(&fixture.state, "direct", &params),
                "repin_action" => repin_action(&fixture.state, "direct", &params),
                _ => unreachable!(),
            };
            assert!(response.get("error").is_none(), "{response}");
            match operation {
                "issue_ticket" => {
                    assert!(response["result"]["ticket_id"].is_string());
                    assert_eq!(fixture.ticket_count(), 2);
                }
                "grant" => {
                    assert!(response["result"]["grant"]["grant_id"].is_string());
                    assert_eq!(
                        fixture
                            .store
                            .list_grants("direct", TEST_CONNECTION)
                            .unwrap()
                            .len(),
                        1
                    );
                }
                "revoke_grant" => {
                    assert_eq!(response["result"]["revoked"], true);
                    assert_eq!(
                        revoke_grant(&fixture.state, "direct", &params)["result"]["revoked"],
                        false
                    );
                }
                "remove_policy" => {
                    assert_eq!(response["result"]["removed"], true);
                    assert_eq!(
                        remove_policy(&fixture.state, "direct", &params)["result"]["removed"],
                        false
                    );
                }
                "repin_action" => {
                    assert_eq!(response["result"]["status"], "active");
                    assert_eq!(
                        fixture
                            .store
                            .catalog_action("direct", TEST_CONNECTION, "read_item")
                            .unwrap()
                            .unwrap()
                            .status,
                        "active"
                    );
                }
                "set_policy" => {
                    assert_eq!(response["result"]["policy"]["effect"], "block");
                    params["policy_id"] = response["result"]["policy"]["policy_id"].clone();
                    assert!(fixture
                        .store
                        .remove_policy("direct", params["policy_id"].as_str().unwrap())
                        .unwrap());
                }
                _ => unreachable!(),
            }
            assert_eq!(
                fixture.store.list_audit("direct").unwrap().len(),
                before + usize::from(!fail)
            );
        }
    }

    #[test]
    fn issue_ticket_audit_failure_is_loud_and_preserves_success() {
        if !crate::audit_test::captured_by_parent(
            "ceremony::tests::issue_ticket_audit_failure_is_loud_and_preserves_success",
            "ceremony issue_ticket",
        ) {
            audit_failure_scenario("issue_ticket");
        }
    }
    #[test]
    fn grant_audit_failure_is_loud_and_preserves_success() {
        if !crate::audit_test::captured_by_parent(
            "ceremony::tests::grant_audit_failure_is_loud_and_preserves_success",
            "ceremony grant",
        ) {
            audit_failure_scenario("grant");
        }
    }
    #[test]
    fn revoke_grant_audit_failure_is_loud_and_preserves_success() {
        if !crate::audit_test::captured_by_parent(
            "ceremony::tests::revoke_grant_audit_failure_is_loud_and_preserves_success",
            "ceremony revoke_grant",
        ) {
            audit_failure_scenario("revoke_grant");
        }
    }
    #[test]
    fn repin_action_audit_failure_is_loud_and_preserves_success() {
        if !crate::audit_test::captured_by_parent(
            "ceremony::tests::repin_action_audit_failure_is_loud_and_preserves_success",
            "ceremony repin_action",
        ) {
            audit_failure_scenario("repin_action");
        }
    }
    #[test]
    fn set_policy_audit_failure_is_loud_and_preserves_success() {
        if !crate::audit_test::captured_by_parent(
            "ceremony::tests::set_policy_audit_failure_is_loud_and_preserves_success",
            "ceremony set_policy",
        ) {
            audit_failure_scenario("set_policy");
        }
    }
    #[test]
    fn remove_policy_audit_failure_is_loud_and_preserves_success() {
        if !crate::audit_test::captured_by_parent(
            "ceremony::tests::remove_policy_audit_failure_is_loud_and_preserves_success",
            "ceremony remove_policy",
        ) {
            audit_failure_scenario("remove_policy");
        }
    }

    /// The connection id the ticket tests issue tickets for. It does not
    /// exist in the fixture, so issuing a ticket creates it as a pending
    /// connection, and redeeming the ticket copies the ticket's limits (its
    /// maximum risk and allowed actions) onto it for the tests to read back.
    /// An active connection would refuse a new ticket; its credential is
    /// replaced with the admin CLI's `rebind-credential` command instead.
    const TICKET_TEST_CONNECTION: &str = "conn-selector-ticket";

    fn ticket_params() -> Value {
        json!({
            "app_key": "grant_expiry_test",
            "connection_id": TICKET_TEST_CONNECTION,
            "credential_id": "test:selector",
            "action_selectors": ["read_item"]
        })
    }

    #[test]
    fn issue_ticket_existing_connection_has_named_admin_refusal_without_mutation() {
        let fixture = SelectorFixture::new();
        let conn = rusqlite::Connection::open(fixture.directory.join("store.db")).unwrap();
        let snapshot = || {
            conn.query_row("SELECT credential_binding,generation FROM connections WHERE principal='direct' AND connection_id=?1",[TEST_CONNECTION],|row|Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,i64>(1)?))).unwrap()
        };
        let before = snapshot();
        let mut params = ticket_params();
        params["connection_id"] = json!(TEST_CONNECTION);
        let reply = issue_ticket(&fixture.state, "direct", &params);
        assert_eq!(
            reply["error"]["code"], "connection_exists",
            "admin issue-ticket --connection must refuse an existing live connection"
        );
        assert!(reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("rebind-credential"));
        assert_eq!(
            snapshot(),
            before,
            "refusal must leave credential bytes and generation unchanged"
        );
    }

    fn assert_selector_refusal(value: Value, message: &str, ticket: bool) {
        let fixture = SelectorFixture::new();
        let before = fixture.ticket_count();
        let mut params = if ticket {
            ticket_params()
        } else {
            grant_params()
        };
        params["action_selectors"] = value;
        let response = if ticket {
            issue_ticket(&fixture.state, "direct", &params)
        } else {
            grant(&fixture.state, "direct", &params)
        };
        assert_eq!(
            fixture.ticket_count(),
            before,
            "refusal must not write a ticket"
        );
        assert!(
            fixture
                .store
                .list_grants("direct", TEST_CONNECTION)
                .unwrap()
                .is_empty(),
            "refusal must not write a grant"
        );
        assert_eq!(response["error"]["code"], "invalid_request");
        assert_eq!(response["error"]["message"], message);
    }

    #[test]
    fn grant_refuses_string_selectors_without_minting_authority() {
        assert_selector_refusal(
            json!("read_item"),
            "action_selectors must be an array of strings",
            false,
        );
    }

    #[test]
    fn issue_ticket_refuses_string_selectors_without_issuing_ticket() {
        assert_selector_refusal(
            json!("read_item"),
            "action_selectors must be an array of strings",
            true,
        );
    }

    #[test]
    fn both_callers_refuse_mixed_selector_arrays_without_authority() {
        for ticket in [false, true] {
            assert_selector_refusal(
                json!(["read_item", 7]),
                "action_selectors[1] must be a string",
                ticket,
            );
        }
    }

    #[test]
    fn both_callers_refuse_other_non_array_selectors() {
        for ticket in [false, true] {
            for value in [Value::Null, json!(7), json!({}), json!(true)] {
                assert_selector_refusal(
                    value,
                    "action_selectors must be an array of strings",
                    ticket,
                );
            }
        }
    }

    fn assert_selector_success(absent: bool) {
        for ticket in [false, true] {
            let fixture = SelectorFixture::new();
            let before = fixture.ticket_count();
            let mut params = if ticket {
                ticket_params()
            } else {
                grant_params()
            };
            if absent {
                params.as_object_mut().unwrap().remove("action_selectors");
            }
            let expected = if absent {
                vec!["read_item", "read_other"]
            } else {
                vec!["read_item"]
            };
            if ticket {
                let response = issue_ticket(&fixture.state, "direct", &params);
                assert_eq!(
                    response["result"]["ceiling"]["action_selectors"],
                    json!(expected)
                );
                assert_eq!(fixture.ticket_count(), before + 1);
                fixture
                    .store
                    .connect_with_ticket(
                        "direct",
                        response["result"]["ticket_id"].as_str().unwrap(),
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    fixture
                        .store
                        .connection_ceiling("direct", TICKET_TEST_CONNECTION)
                        .unwrap()
                        .unwrap()
                        .action_selectors,
                    expected
                );
            } else {
                let response = grant(&fixture.state, "direct", &params);
                assert_eq!(
                    response["result"]["grant"]["action_selectors"],
                    json!(expected)
                );
                let grants = fixture
                    .store
                    .list_grants("direct", TEST_CONNECTION)
                    .unwrap();
                assert_eq!(grants.len(), 1);
                assert_eq!(grants[0].action_selectors, expected);
            }
        }
    }

    #[test]
    fn both_callers_absent_selectors_still_authorize_full_bound() {
        assert_selector_success(true);
    }

    #[test]
    fn both_callers_string_arrays_preserve_explicit_selection() {
        assert_selector_success(false);
    }

    #[test]
    fn grant_refuses_a_string_expiry_without_minting_authority() {
        let (state, store) = grant_test_state("grant-string-expiry");
        let mut params = grant_params();
        params["expires_at"] = json!("1800000000000");

        let response = grant(&state, "direct", &params);

        assert_eq!(response["error"]["code"], "invalid_request");
        assert_eq!(
            response["error"]["message"],
            "expires_at must be an epoch milliseconds integer"
        );
        assert!(store
            .list_grants("direct", TEST_CONNECTION)
            .expect("list grants after refusal")
            .is_empty());
    }

    #[test]
    fn grant_with_integer_expiry_mints_with_that_expiry() {
        let (state, store) = grant_test_state("grant-integer-expiry");
        let expiry = 1_900_000_000_000_i64;
        let mut params = grant_params();
        params["expires_at"] = json!(expiry);

        let response = grant(&state, "direct", &params);

        assert_eq!(response["result"]["grant"]["expires_at"], expiry);
        let grants = store
            .list_grants("direct", TEST_CONNECTION)
            .expect("list bounded grant");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].expires_at, Some(expiry));
    }

    #[test]
    fn grant_without_expiry_mints_until_revoked_authority() {
        let (state, store) = grant_test_state("grant-absent-expiry");

        let response = grant(&state, "direct", &grant_params());

        assert!(response["result"]["grant"]["expires_at"].is_null());
        let grants = store
            .list_grants("direct", TEST_CONNECTION)
            .expect("list until-revoked grant");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].expires_at, None);
        assert_eq!(grants[0].state, "until_revoked");
    }

    #[test]
    fn null_grant_expiry_behaves_as_absent() {
        let (state, store) = grant_test_state("grant-null-expiry");
        let mut params = grant_params();
        params["expires_at"] = Value::Null;

        let response = grant(&state, "direct", &params);

        assert!(response["result"]["grant"]["expires_at"].is_null());
        let grants = store
            .list_grants("direct", TEST_CONNECTION)
            .expect("list null-expiry grant");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].expires_at, None);
        assert_eq!(grants[0].state, "until_revoked");
    }

    #[test]
    fn policy_expiry_keeps_its_integer_and_wrong_type_behavior() {
        let (state, store) = grant_test_state("policy-expiry");
        let policy_params = |expires_at: Value| {
            json!({
                "connection_id": TEST_CONNECTION,
                "action_selector": "read_item",
                "effect": "allow",
                "expires_at": expires_at
            })
        };

        let refused = set_policy(&state, "direct", &policy_params(json!("1800000000000")));
        assert_eq!(refused["error"]["code"], "invalid_request");
        assert_eq!(
            refused["error"]["message"],
            "expires_at must be an epoch milliseconds integer"
        );
        assert!(store
            .list_policies("direct", Some(TEST_CONNECTION))
            .expect("list policies after refusal")
            .is_empty());

        let expiry = 1_900_000_000_000_i64;
        let accepted = set_policy(&state, "direct", &policy_params(json!(expiry)));
        assert_eq!(accepted["result"]["policy"]["expires_at"], expiry);
        let policies = store
            .list_policies("direct", Some(TEST_CONNECTION))
            .expect("list bounded policy");
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].expires_at, Some(expiry));
    }

    #[test]
    fn empty_action_selectors_have_a_named_wire_refusal() {
        let response = refusal_response(&CeremonyRefusal::EmptyActionSelectors);
        assert_eq!(response["error"]["code"], "empty_action_selectors");
        assert!(response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("at least one action"));
        assert!(requested_selectors(&json!({"action_selectors": []}))
            .unwrap()
            .is_empty());
        assert_eq!(
            requested_selectors(&json!({})).unwrap(),
            vec!["*".to_string()]
        );
    }

    #[test]
    fn review_action_returns_store_failure_when_the_pinned_schema_hash_fails() {
        let review = plexus_core::CatalogActionReview {
            action: plexus_core::CatalogAction {
                connection_id: "connection".to_string(),
                principal: "direct".to_string(),
                name: "read_item".to_string(),
                title: None,
                schema: json!({"type": "object"}),
                schema_hash: "sha256:current".to_string(),
                risk: "read".to_string(),
                severity: "S1".to_string(),
                ask_first: false,
                status: "quarantined".to_string(),
                quarantine_reason: Some("schema_changed_requires_review".to_string()),
                reconciliation: None,
                generation: 2,
            },
            reviewed_schema: Some(json!({"type": "object"})),
        };

        let response = action_review_response("connection", review, |_| {
            Err(plexus_core::JcsError::NonFiniteNumber)
        });

        assert_eq!(response["error"]["code"], "store_failure");
        assert!(response.get("result").is_none());
    }
}
