//! Provider choice through the routing role (`routing/v1`, search selection).
//!
//! Plexus keeps dispatch, credentials, audit, capability checks and allowance
//! metering. Before contacting a vendor it works out which providers could
//! serve this search right now (the eligible routes) and asks the one routing
//! provider in the daemon catalog to choose among them with `route.select`
//! (`kind: "search"`). It dispatches the provider the answer names and reports
//! the attempt's outcome on that decision with `route.report`. A failed attempt
//! is followed by a new select with the failed route removed.
//!
//! Every wire body this module builds or reads is defined by the routing role
//! contract (`cortexkit-role-routing` 0.7.32, CONTRACT.md §16.4, §16.4.2 and
//! §16.6); the request builder is checked byte for byte against reply pairs
//! recorded from the routing provider's real handler.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::scope::CallScope;

/// The capability a routing provider lists in its catalog entry.
pub const ROUTING_CAPABILITY: &str = "routing/v1";
/// The role-declaration slot that tells routing which search routes plexus serves.
pub const SEARCH_PROVIDER_SLOT: &str = "search-provider/v1";
/// The consumer name plexus selects web searches under. Routing admits it
/// because plexus declares it in its own `routing/v1` slot.
pub const CONSUMER: &str = "plexus.web_search";
/// The module allowed to select for [`CONSUMER`]: plexus itself.
pub const SELECTOR: &str = "plexus";
/// The demand level sent as `requirements.iq` on every search select. Routing
/// maps it onto the search rows' catalog quality grades, and only routes at or
/// above it are adequate (CONTRACT.md §16.4.1 `select_media.demand`). The
/// contract defines no default level for a search consumer, so plexus states
/// one: 75, the level routing's recorded search pairs use.
pub const SEARCH_DEMAND_IQ: u8 = 75;
/// The longest plexus waits for one catalog read, `role.describe` or
/// `route.select`. Every call is also cut to what is left of the search's
/// overall admission deadline, so a slow router never holds a search past it.
pub const ROUTING_CALL_TIMEOUT: Duration = Duration::from_secs(3);
/// The longest plexus waits for routing to accept one attempt report.
pub const ROUTING_REPORT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a `role.describe` answer that serves search is trusted before it
/// is read again.
pub const DESCRIBE_TTL_MS: i64 = 60_000;
/// How long after plexus adds a route to its declaration a `no_route` answer
/// is read as "routing has not seen the new declaration yet" rather than "no
/// provider can serve". Routing rereads the daemon catalog about every 30
/// seconds; the extra 5 seconds cover one reread taking a while.
pub const DECLARATION_GRACE_MS: i64 = 35_000;

/// The optional routing groups a search select needs (§16.4.2: `select_search`
/// requires `select_kind` and `select_media`; `eligible_routes` is its own group).
const REQUIRED_GROUPS: [&str; 4] = [
    "select_kind",
    "select_media",
    "select_search",
    "select_eligible_routes",
];
const ATTEMPT_OUTCOMES_GROUP: &str = "report_attempt_outcomes";

/// One routing route: a Fusiform search row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteRef {
    pub provider: String,
    pub model: String,
}

impl RouteRef {
    pub fn new(provider: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
        }
    }

    fn to_json(&self) -> Value {
        json!({"model": self.model, "provider": self.provider})
    }
}

/// How one call to routing failed.
#[derive(Debug, Clone, PartialEq)]
pub enum RoutingCallError {
    /// Nothing usable came back: no routing provider in the catalog, more
    /// than one, a route that would not open, a timeout or an unreadable
    /// reply. The text is for the operator log only.
    Unreachable(String),
    /// Routing answered with a refusal (an `ERROR` frame body, §2).
    Refused {
        code: String,
        message: String,
        detail: Value,
    },
}

/// The route plexus sends routing ops over. A call sends the op `method` with
/// `params` in the `{method, params}` envelope and returns the whole reply
/// body, `{"result": answer}` (§2).
///
/// `scope` is the scope stamp of the search the call is for: routing applies
/// the stamp of the route a select arrives on (§3), so a search made inside an
/// agent's session is selected, and its cost attributed, inside that session.
pub trait RoutingPeer: Send + Sync {
    fn call(
        &self,
        method: &str,
        params: Value,
        scope: Option<&CallScope>,
        timeout: Duration,
    ) -> Result<Value, RoutingCallError>;
}

/// The `route.select` body plexus sends for one search, envelope included.
/// Routes are sent sorted, so equal inputs always give the same bytes.
pub fn select_request(eligible: &[RouteRef], allowance_left: &[RouteRef]) -> Value {
    json!({"method": "route.select", "params": select_params(eligible, allowance_left)})
}

/// The `params` of [`select_request`]. `allowance_left` lists the eligible
/// routes whose operator-set monthly allowance still has searches left, which
/// routing prices at zero; it is always sent, empty when there are none.
pub fn select_params(eligible: &[RouteRef], allowance_left: &[RouteRef]) -> Value {
    let sorted = |routes: &[RouteRef]| {
        let mut routes = routes.to_vec();
        routes.sort();
        routes.dedup();
        routes.iter().map(RouteRef::to_json).collect::<Vec<_>>()
    };
    json!({
        "allowance_left": sorted(allowance_left),
        "consumer": CONSUMER,
        "eligible_routes": sorted(eligible),
        "kind": "search",
        "privacy": "remote_allowed",
        "requirements": {"iq": SEARCH_DEMAND_IQ},
    })
}

/// What routing chose for one select.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub decision_id: String,
    pub route: RouteRef,
}

/// How one select ended.
#[derive(Debug, Clone, PartialEq)]
pub enum SelectOutcome {
    Selected(Selection),
    /// Routing found no adequate route among the eligible ones (`no_route`).
    NoRoute {
        reason: Option<String>,
    },
    /// Routing could not be reached or refused for another reason. The text
    /// is for the operator log only.
    Unavailable(String),
}

/// Read a `route.select` reply for a search (§16.4.2 `select_search.answer`).
pub fn read_select_reply(reply: Result<Value, RoutingCallError>) -> SelectOutcome {
    let body = match reply {
        Ok(body) => body,
        Err(RoutingCallError::Refused { code, detail, .. }) if code == "no_route" => {
            return SelectOutcome::NoRoute {
                reason: detail
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            }
        }
        Err(RoutingCallError::Refused { code, .. }) => {
            return SelectOutcome::Unavailable(format!("route.select refused: {code}"))
        }
        Err(RoutingCallError::Unreachable(why)) => return SelectOutcome::Unavailable(why),
    };
    let Some(answer) = result_of(&body) else {
        return SelectOutcome::Unavailable("route.select reply has no result".into());
    };
    let text = |value: Option<&Value>| value.and_then(Value::as_str).map(str::to_owned);
    let engine = answer.get("engine");
    match (
        text(answer.get("decision_id")),
        text(engine.and_then(|engine| engine.get("provider"))),
        text(engine.and_then(|engine| engine.get("model"))),
    ) {
        (Some(decision_id), Some(provider), Some(model)) if !decision_id.is_empty() => {
            SelectOutcome::Selected(Selection {
                decision_id,
                route: RouteRef { provider, model },
            })
        }
        _ => SelectOutcome::Unavailable("route.select answer is malformed".into()),
    }
}

/// A routing reply's answer: the reply body must be exactly `{"result": ...}`.
fn result_of(body: &Value) -> Option<&Value> {
    let object = body.as_object()?;
    (object.len() == 1).then(|| object.get("result"))?
}

/// What plexus learned from `role.describe` about a router that serves search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescribeFacts {
    /// The router reads `attempt_outcome` on reports (§16.6).
    pub attempt_outcomes: bool,
}

/// Check a `role.describe` reply: the router must be a version 1 routing
/// provider that serves search selection over an eligible route subset.
pub fn read_describe_reply(
    reply: Result<Value, RoutingCallError>,
) -> Result<DescribeFacts, String> {
    let body = match reply {
        Ok(body) => body,
        Err(RoutingCallError::Refused { code, .. }) => {
            return Err(format!("role.describe refused: {code}"))
        }
        Err(RoutingCallError::Unreachable(why)) => return Err(why),
    };
    let answer = result_of(&body).ok_or("role.describe reply has no result")?;
    if answer.get("role").and_then(Value::as_str) != Some("routing")
        || answer.get("version").and_then(Value::as_u64) != Some(1)
    {
        return Err("role.describe does not describe routing version 1".into());
    }
    let listed = |member: &str, name: &str| {
        answer
            .get(member)
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(name)))
    };
    if !listed("kinds", "search") {
        return Err("routing does not list search in its kinds".into());
    }
    if let Some(missing) = REQUIRED_GROUPS
        .iter()
        .find(|group| !listed("capabilities", group))
    {
        return Err(format!("routing does not serve {missing}"));
    }
    Ok(DescribeFacts {
        attempt_outcomes: listed("capabilities", ATTEMPT_OUTCOMES_GROUP),
    })
}

/// One attempt's outcome as reported to routing (§16.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptStatus {
    Served,
    /// The provider answered with no results. It still served the search.
    ServedEmpty,
    Quota,
    /// `retry_after_ms` is set only when the provider itself named the wait.
    Throttled {
        retry_after_ms: Option<u64>,
    },
    Credential,
    Unavailable,
    /// The provider refused the request itself (400 or 422); never counted
    /// against the route.
    Rejected,
}

impl AttemptStatus {
    pub fn status(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::ServedEmpty => "served_empty",
            Self::Quota => "quota",
            Self::Throttled { .. } => "throttled",
            Self::Credential => "credential",
            Self::Unavailable => "unavailable",
            Self::Rejected => "rejected",
        }
    }

    /// The legacy `outcome` the contract pairs with each status.
    fn companion(self) -> &'static str {
        match self {
            Self::Served | Self::ServedEmpty => "completed",
            Self::Rejected => "cancelled",
            _ => "failed",
        }
    }
}

/// The `route.report` params for one attempt. A router that does not read
/// `attempt_outcome` is sent only the legacy `outcome`, since it would refuse
/// a member it does not read (§2).
pub fn report_params(decision_id: &str, status: AttemptStatus, attempt_outcomes: bool) -> Value {
    let mut params = json!({"decision_id": decision_id, "outcome": status.companion()});
    if attempt_outcomes {
        let mut outcome = json!({"status": status.status()});
        if let AttemptStatus::Throttled {
            retry_after_ms: Some(wait),
        } = status
        {
            outcome["retry_after_ms"] = json!(wait);
        }
        params["attempt_outcome"] = outcome;
    }
    params
}

/// Why the catalog named no single routing provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryFailure {
    None,
    Ambiguous,
}

/// The one routing provider in a daemon `catalog.list` module array: a
/// nonce-verified entry whose capabilities provide `routing/v1` (§1). None or
/// several is a failure; plexus never picks one of several.
pub fn routing_provider(modules: &Value) -> Result<String, DiscoveryFailure> {
    let mut found = modules
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| entry.get("nonce_verified").and_then(Value::as_bool) == Some(true))
        .filter(|entry| {
            entry
                .pointer("/capabilities/provides")
                .and_then(Value::as_array)
                .is_some_and(|provides| {
                    provides
                        .iter()
                        .any(|value| value.as_str() == Some(ROUTING_CAPABILITY))
                })
        })
        .filter_map(|entry| entry.get("module_id").and_then(Value::as_str))
        .filter(|module| !module.is_empty());
    match (found.next(), found.next()) {
        (Some(module), None) => Ok(module.to_owned()),
        (None, _) => Err(DiscoveryFailure::None),
        (Some(_), Some(_)) => Err(DiscoveryFailure::Ambiguous),
    }
}

/// Plexus's complete role-declaration map: its search consumer in the
/// `routing/v1` slot and the search routes it serves in the
/// `search-provider/v1` slot. Both the HELLO manifest and every later
/// redeclaration are built here, so the two can never disagree in shape.
pub fn role_declarations(routes: &[RouteRef]) -> BTreeMap<String, Map<String, Value>> {
    let mut routes = routes.to_vec();
    routes.sort();
    routes.dedup();
    let object = |value: Value| match value {
        Value::Object(map) => map,
        _ => unreachable!("built from an object literal"),
    };
    BTreeMap::from([
        (
            ROUTING_CAPABILITY.to_owned(),
            object(json!({"consumers": [
                {"name": CONSUMER, "kind": "search", "selectors": [SELECTOR]}
            ]})),
        ),
        (
            SEARCH_PROVIDER_SLOT.to_owned(),
            object(json!({"routes": routes.iter().map(RouteRef::to_json).collect::<Vec<_>>()})),
        ),
    ])
}

/// Every route in the provider table, in table order.
pub fn table_routes() -> Vec<RouteRef> {
    super::providers::SEARCH_ROUTES
        .iter()
        .map(|(_, provider, model)| RouteRef::new(*provider, *model))
        .collect()
}

/// The routes plexus can serve now: one per provider that has a routing
/// catalog row and a connection, owned by one of `principals`, whose status
/// can serve a search. Also returns, by name, the connected providers that
/// have no catalog row and so are not declared.
pub fn live_routes(
    store: &crate::storage::PlexusStore,
    principals: &[String],
) -> Result<(Vec<RouteRef>, Vec<&'static str>), cortexkit_store::StoreError> {
    let mut routes = std::collections::BTreeSet::new();
    let mut unrouted = std::collections::BTreeSet::new();
    for principal in principals {
        for summary in store.list_connections(principal)? {
            if !super::connection_status_can_search(&summary.status) {
                continue;
            }
            let Some(provider) = super::providers::PROVIDER_NAMES
                .iter()
                .find(|provider| provider.app_key == summary.app_key)
            else {
                continue;
            };
            match super::providers::search_route(provider.name) {
                Some((route_provider, model)) => {
                    routes.insert(RouteRef::new(route_provider, model));
                }
                None => {
                    unrouted.insert(provider.name);
                }
            }
        }
    }
    Ok((routes.into_iter().collect(), unrouted.into_iter().collect()))
}

/// The routing provider found in the daemon catalog, reached over this
/// module's own subc connection. The provider's module id is found once and
/// kept; a route that no longer opens (the module went away or was replaced)
/// forgets it, so the next call looks again.
pub struct CatalogRoutingPeer {
    route: crate::github_identity::SubcPrefrontalRoutePeer,
    provider: std::sync::Mutex<Option<String>>,
}

impl CatalogRoutingPeer {
    pub fn new(route: crate::github_identity::SubcPrefrontalRoutePeer) -> Self {
        Self {
            route,
            provider: std::sync::Mutex::new(None),
        }
    }

    fn provider(&self, timeout: Duration) -> Result<String, RoutingCallError> {
        let mut cached = self
            .provider
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(module) = cached.as_ref() {
            return Ok(module.clone());
        }
        let modules = self.route.catalog_modules(timeout).map_err(|_| {
            RoutingCallError::Unreachable("the daemon catalog could not be read".into())
        })?;
        let module = routing_provider(&modules).map_err(|failure| {
            RoutingCallError::Unreachable(match failure {
                DiscoveryFailure::None => "the daemon catalog lists no routing provider".into(),
                DiscoveryFailure::Ambiguous => {
                    "the daemon catalog lists more than one routing provider".into()
                }
            })
        })?;
        *cached = Some(module.clone());
        Ok(module)
    }
}

impl RoutingPeer for CatalogRoutingPeer {
    fn call(
        &self,
        method: &str,
        params: Value,
        scope: Option<&CallScope>,
        timeout: Duration,
    ) -> Result<Value, RoutingCallError> {
        let started = std::time::Instant::now();
        let module = self.provider(timeout)?;
        let remaining = timeout.saturating_sub(started.elapsed());
        match self
            .route
            .call_module(&module, method, params, scope, remaining)
        {
            Ok(reply) => Ok(reply),
            Err(crate::github_identity::ModuleCallError::Refused { code, .. })
                if matches!(code.as_str(), "unknown_module" | "target_unavailable") =>
            {
                *self
                    .provider
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
                Err(RoutingCallError::Unreachable(format!(
                    "the route to routing provider {module} did not open ({code})"
                )))
            }
            Err(crate::github_identity::ModuleCallError::Refused {
                code,
                message,
                detail,
            }) => Err(RoutingCallError::Refused {
                code,
                message,
                detail: detail.unwrap_or_else(|| json!({})),
            }),
            Err(crate::github_identity::ModuleCallError::NoAnswer) => {
                Err(RoutingCallError::Unreachable(format!(
                    "routing provider {module} did not answer {method}"
                )))
            }
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod fake;

#[cfg(test)]
mod tests;
