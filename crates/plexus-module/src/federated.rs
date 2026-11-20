//! Federated admission is separate from first-party module authority.

use plexus_core::storage::{CatalogAction, PlexusStore};
use serde_json::{json, Map, Value};
use subc_protocol::{
    scope::{FederatedPeerClass, ParentState, RemoteClaim, ScopeKind, ScopeStamp},
    Principal,
};

/// Federated admission ships together with the scope-federated/v1 declaration.
pub const FEDERATED_CALLERS_ENABLED: bool = true;

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
/// New tools and sub-operations start out denied.
pub(crate) fn serves(
    object: &Map<String, Value>,
    caller: Option<&plexus_core::federated::FederatedCaller>,
) -> bool {
    if is_github_frame(object) {
        return github_claim(object, caller).is_some();
    }
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

pub(super) fn is_github_frame(object: &Map<String, Value>) -> bool {
    object.get("method").and_then(Value::as_str)
        == Some(plexus_core::github::reads::bot::BULK_METHOD)
        || matches!(
            object.get("name").and_then(Value::as_str),
            Some("github" | "github_react" | "github_read")
        )
}

/// Only bot forms can get past this gate. In particular no remote call may
/// fall through to the operator's GitHub connections or management handler.
pub(super) fn github_claim<'a>(
    object: &Map<String, Value>,
    caller: Option<&'a plexus_core::federated::FederatedCaller>,
) -> Option<plexus_core::github::moved_bot::Claim<'a>> {
    use plexus_core::github::{moved_bot::Claim, reads::bot, AFT_PRINCIPAL};

    let claim = Claim::from_caller(caller?)?;
    let principal = format!("reserved:{}", claim.module_id());
    let allowed = if let Some(method) = object.get("method") {
        method.as_str() == Some(bot::BULK_METHOD)
            && object
                .keys()
                .all(|key| matches!(key.as_str(), "method" | "params"))
            && principal == AFT_PRINCIPAL
            && !claim.is_flow()
            && object
                .get("params")
                .and_then(|args| args.get("action"))
                .and_then(Value::as_str)
                .is_some_and(|action| bot::BULK_ACTIONS.contains(&action))
    } else {
        let arguments = object.get("arguments")?.as_object()?;
        match object.get("name").and_then(Value::as_str) {
            Some("github") => !claim.is_flow() && op(object) == Some("bot_request"),
            Some("github_react") => true,
            Some("github_read") => {
                arguments
                    .get("action")
                    .and_then(Value::as_str)
                    .is_some_and(|action| {
                        action == "github.bindings.list"
                            || crate::facade::BotReadForm::of(
                                action,
                                &principal,
                                arguments.get("args").unwrap_or(&Value::Null),
                            )
                            .is_some()
                    })
            }
            _ => false,
        }
    };
    allowed.then_some(claim)
}

fn op(object: &Map<String, Value>) -> Option<&str> {
    object.get("arguments")?.get("op")?.as_str()
}

const NOT_SERVED: &str = "this frame is not served to federated callers";

pub(crate) fn caller_not_allowed() -> Value {
    json!({"error": {
        "code": "caller_not_allowed",
        "message": NOT_SERVED,
        "transmission": "not_sent",
    }})
}

pub(super) fn is_admission_refusal(reply: &Value) -> bool {
    reply["error"]["code"] == "caller_not_allowed" && reply["error"]["message"] == NOT_SERVED
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
