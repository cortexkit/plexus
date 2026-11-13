//! Federated admission is separate from first-party module authority.

use plexus_core::storage::{CatalogAction, PlexusStore};
use serde_json::{json, Map, Value};
use subc_protocol::{
    scope::{FederatedPeerClass, ParentState, RemoteClaim, ScopeKind, ScopeStamp},
    Principal,
};

/// Admission stays dormant until federated consent checks and the restricted
/// connection/catalog metadata replies are implemented.
pub const FEDERATED_CALLERS_ENABLED: bool = false;

/// The module runtime owns one switch; only Rust test code may override it.
pub(crate) struct Admission {
    enabled: bool,
}

impl Default for Admission {
    fn default() -> Self {
        Self {
            enabled: FEDERATED_CALLERS_ENABLED,
        }
    }
}

impl Admission {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn set_for_test(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub(crate) fn admits_scope(
        &self,
        principal: &Option<Principal>,
        stamp: Option<&ScopeStamp>,
    ) -> bool {
        // Callosum never inherits first-party authority, even with a local stamp.
        if is_callosum(principal.as_ref())
            || stamp.is_some_and(|stamp| stamp.kind == ScopeKind::Federated)
        {
            return self.enabled
                && is_callosum(principal.as_ref())
                && stamp.is_some_and(|stamp| {
                    stamp.kind == ScopeKind::Federated
                        && is_callosum(Some(&stamp.owner))
                        && matches!(stamp.parent_state, None | Some(ParentState::Linked))
                        && stamp
                            .attributes
                            .federated
                            .as_ref()
                            .is_some_and(|attributes| {
                                attributes.peer_class == FederatedPeerClass::Computer
                                    && attributes.remote_claim.as_ref().is_none_or(|claim| {
                                        matches!(
                                            claim,
                                            RemoteClaim::Agent { .. }
                                                | RemoteClaim::Worker { .. }
                                                | RemoteClaim::Flow { .. }
                                                | RemoteClaim::Run { .. }
                                        )
                                    })
                            })
                });
        }
        stamp.is_none_or(|stamp| {
            matches!(
                stamp.kind,
                ScopeKind::Head | ScopeKind::Worker | ScopeKind::Ephemeral
            )
        })
    }
}

pub(crate) fn is_callosum(principal: Option<&Principal>) -> bool {
    matches!(principal, Some(Principal::Reserved { module_id }) if module_id == "callosum")
}

/// The protocol decoder rejects future claim variants. Keep that rejection a
/// bind admission denial rather than discarding the claim or calling it absent.
pub(crate) fn unknown_claim_bind(body: &[u8]) -> Option<Option<Principal>> {
    let body: Value = serde_json::from_slice(body).ok()?;
    if body.get("op")?.as_str()? != "route.bind" {
        return None;
    }
    let scope = body.get("scope")?;
    if scope.get("kind")?.as_str()? != "federated" {
        return None;
    }
    let claim = scope
        .get("attributes")?
        .get("federated")?
        .get("remote_claim")?;
    if claim.is_null()
        || matches!(
            claim.get("kind").and_then(Value::as_str),
            Some("agent" | "worker" | "flow" | "run")
        )
    {
        return None;
    }
    Some(
        body.get("principal")
            .and_then(|value| serde_json::from_value(value.clone()).ok()),
    )
}

/// Match dispatch's discriminator, including malformed and mixed method frames.
/// No method is served; a newly added tool or sub-operation starts out denied.
pub(crate) fn serves(object: &Map<String, Value>) -> bool {
    if object.contains_key("method") {
        return false;
    }
    match object.get("name").and_then(Value::as_str) {
        Some("invoke" | "web_search" | "code_search" | "tool.catalog" | "role.describe") => true,
        Some("connections") => op(object) == Some("list"),
        Some("catalog") => matches!(op(object), Some("apps" | "list" | "inspect")),
        _ => false,
    }
}

fn op(object: &Map<String, Value>) -> Option<&str> {
    object.get("arguments")?.get("op")?.as_str()
}

pub(crate) fn caller_not_allowed() -> Value {
    json!({"error": {
        "code": "caller_not_allowed",
        "message": "this frame is not served to federated callers",
        "transmission": "not_sent",
    }})
}

/// Build only public discovery fields, using the same severity rule as invoke.
pub(crate) fn project_actions(
    store: &PlexusStore,
    connection_id: &str,
    actions: Vec<CatalogAction>,
) -> Result<Vec<Value>, cortexkit_store::StoreError> {
    let connection = store.connection("direct", connection_id)?;
    let app_key = connection
        .as_ref()
        .map_or("", |connection| connection.app_key.as_str());
    actions
        .into_iter()
        .map(|action| {
            let severity = plexus_core::governance::effective_severity(&action, app_key, store)?;
            Ok(json!({
                "name": action.name,
                "title": action.title,
                "risk": action.risk,
                "severity": severity,
                "schema": action.schema,
                "status": action.status,
            }))
        })
        .collect()
}

/// Fail closed before any local namespace or grant lookup until the dedicated
/// federated handlers are available. Role metadata carries no authority.
pub(crate) fn pending_handler() -> Value {
    json!({"error": {
        "code": "consent_unavailable",
        "message": "federated handling is not available for this tool",
        "transmission": "not_sent",
    }})
}
