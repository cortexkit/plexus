//! The `webSearch` section of the health report: whether plexus found its
//! routing provider, the search routes it has declared to routing, and one row
//! per search provider (one per connection when a provider has more than one,
//! across every owning principal).
//!
//! Routing chooses each search's provider, so the stored provider order is
//! not reported: nothing reads it any more.
//!
//! The store facts (which connections exist, allowance limits and this
//! month's counts) are read on the scheduler task with the rest of the store
//! snapshot, because the control-lane health answer does no store IO.
//! Cooldowns, the declaration and the routing look live in the running
//! module's memory, so the report reads them when it is built and a restarted
//! module starts them afresh.
//!
//! A row names the provider, the connection id and its owner and nothing
//! else: connection configuration, such as a SearXNG instance address, and
//! vendor replies are never read here.

use cortexkit_store::StoreError;
use plexus_core::storage::PlexusStore;
use plexus_core::web_search::{connection_status_can_search, providers, WebSearchService};
use serde_json::{json, Value};

use crate::search_declarations::DeclarationStatus;

/// What the scheduler last read from the store for the `webSearch` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Snapshot {
    rows: Vec<Row>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    provider: &'static str,
    /// The routing catalog row the provider is declared as, or `None` for a
    /// connected provider that has no row and so is never searched.
    route: Option<(&'static str, &'static str)>,
    connection: Option<Connection>,
    /// The provider's monthly allowance, if one is set.
    allowance_limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Connection {
    connection_id: String,
    principal: String,
    /// The owner's count for the current UTC month. Allowances are counted
    /// per owner, so connections of one owner report the same number.
    allowance_used: u32,
}

/// Read the store facts behind the `webSearch` section. `principals` are the
/// connection owners to list, as the health probe enumerates them. `now_ms`
/// picks the UTC month whose allowance counts are reported; pass the search
/// service's clock, the one its reservations are counted against.
///
/// Rows cover every provider with a routing catalog row, in that table's
/// order, then any other provider that has a live connection.
pub(crate) fn snapshot(
    store: &PlexusStore,
    principals: &[String],
    now_ms: i64,
) -> Result<Snapshot, StoreError> {
    let mut connections = Vec::new();
    for principal in principals {
        for summary in store.list_connections(principal)? {
            // Search resolution's own status rule: a connection that cannot
            // serve a search is not reported as present.
            if connection_status_can_search(&summary.status) {
                connections.push((principal.clone(), summary));
            }
        }
    }
    let routed = providers::SEARCH_ROUTES
        .iter()
        .filter_map(|(name, _, _)| providers::provider_named(name));
    let unrouted = providers::PROVIDER_NAMES.iter().filter(|provider| {
        providers::search_route(provider.name).is_none()
            && connections
                .iter()
                .any(|(_, summary)| summary.app_key == provider.app_key)
    });
    let mut rows = Vec::new();
    for provider in routed.chain(unrouted) {
        let route = providers::search_route(provider.name);
        let allowance_limit = store.web_search_allowance(provider.name)?;
        let mut present = false;
        for (principal, summary) in &connections {
            if summary.app_key != provider.app_key {
                continue;
            }
            present = true;
            rows.push(Row {
                provider: provider.name,
                route,
                connection: Some(Connection {
                    connection_id: summary.connection_id.clone(),
                    principal: principal.clone(),
                    allowance_used: store.web_search_allowance_used(
                        provider.name,
                        principal,
                        now_ms,
                    )?,
                }),
                allowance_limit,
            });
        }
        if !present {
            rows.push(Row {
                provider: provider.name,
                route,
                connection: None,
                allowance_limit,
            });
        }
    }
    Ok(Snapshot { rows })
}

/// The `webSearch` health value: `null` until the scheduler has read the
/// store once, or when that read failed.
///
/// `routing` is the search service's last look for a routing provider:
/// `discovery` is `found`, `none`, `several` or `unreachable` (the catalog
/// could not be read, or the module has no daemon route to look over), or
/// `null` before the first search that needed one; `at_ms` is when it looked.
/// `routes` is what plexus last declared to routing; `updated_at_ms` is when
/// that declaration was last replaced, `null` while HELLO's (every catalog
/// row) stands. Pass `declarations` as `None` when the module cannot replace
/// its declaration.
pub(crate) fn render(
    snapshot: Option<&Snapshot>,
    service: &WebSearchService,
    declarations: Option<&DeclarationStatus>,
) -> Value {
    let Some(snapshot) = snapshot else {
        return Value::Null;
    };
    let providers = snapshot
        .rows
        .iter()
        .map(|row| {
            let connection = row.connection.as_ref();
            json!({
                "provider": row.provider,
                "route": row.route.map(|(provider, model)| json!({"provider": provider, "model": model})),
                "connection_id": connection.map(|connection| &connection.connection_id),
                "principal": connection.map(|connection| &connection.principal),
                "connection_present": connection.is_some(),
                "cooldown_remaining_ms": connection.map_or(0, |connection| {
                    service.cooldown_remaining_ms(&connection.connection_id)
                }),
                "allowance_used": connection.map(|connection| connection.allowance_used),
                "allowance_limit": row.allowance_limit,
            })
        })
        .collect::<Vec<_>>();
    let routing = match (service.has_router(), service.routing_discovery()) {
        (false, _) => json!({"discovery": "unreachable", "provider": null, "at_ms": null}),
        (true, None) => json!({"discovery": null, "provider": null, "at_ms": null}),
        (true, Some(discovery)) => json!({
            "discovery": discovery.outcome.name(),
            "provider": discovery.provider,
            "at_ms": discovery.at_ms,
        }),
    };
    let declared = declarations
        .cloned()
        .unwrap_or_else(DeclarationStatus::at_hello);
    json!({
        "routing": routing,
        "routes": {
            "declared": declared
                .routes
                .iter()
                .map(|route| json!({"provider": route.provider, "model": route.model}))
                .collect::<Vec<_>>(),
            "updated_at_ms": declared.updated_at_ms,
        },
        "providers": providers,
    })
}
