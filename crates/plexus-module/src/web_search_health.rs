//! The `webSearch` section of the health report: one row per provider in the
//! stored web search order, and one per connection when a provider has more
//! than one, across every owning principal.
//!
//! The store facts (the order, which connections exist, allowance limits and
//! this month's counts) are read on the scheduler task with the rest of the
//! store snapshot, because the control-lane health answer does no store IO.
//! Cooldowns live in the running search service's memory, so the report reads
//! them when it is built and a restarted module reports 0.
//!
//! A row names the provider, the connection id and its owner and nothing
//! else: connection configuration, such as a SearXNG instance address, and
//! vendor replies are never read here.

use cortexkit_store::StoreError;
use plexus_core::storage::PlexusStore;
use plexus_core::web_search::{providers, WebSearchService};
use serde_json::{json, Value};

/// What the scheduler last read from the store for the `webSearch` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Snapshot {
    /// The stored order, or `None` for the Exa compatibility path.
    order: Option<Vec<String>>,
    rows: Vec<Row>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    provider: String,
    /// The provider's place in the order, counting from 1.
    order_position: usize,
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
pub(crate) fn snapshot(
    store: &PlexusStore,
    principals: &[String],
    now_ms: i64,
) -> Result<Snapshot, StoreError> {
    let Some(order) = store.web_search_order()? else {
        return Ok(Snapshot {
            order: None,
            rows: Vec::new(),
        });
    };
    let mut connections = Vec::new();
    for principal in principals {
        for summary in store.list_connections(principal)? {
            // The same statuses search resolution leaves out: these
            // connections cannot serve a search.
            if !matches!(summary.status.as_str(), "pending" | "disabled" | "revoked") {
                connections.push((principal.clone(), summary));
            }
        }
    }
    let mut rows = Vec::new();
    for (index, name) in order.iter().enumerate() {
        let order_position = index + 1;
        let Some(provider) = providers::provider_named(name) else {
            // Orders are validated on write. A damaged or imported store row
            // is still reported, with nothing behind it.
            rows.push(Row {
                provider: name.clone(),
                order_position,
                connection: None,
                allowance_limit: None,
            });
            continue;
        };
        let allowance_limit = store.web_search_allowance(provider.name)?;
        let mut present = false;
        for (principal, summary) in &connections {
            if summary.app_key != provider.app_key {
                continue;
            }
            present = true;
            rows.push(Row {
                provider: name.clone(),
                order_position,
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
                provider: name.clone(),
                order_position,
                connection: None,
                allowance_limit,
            });
        }
    }
    Ok(Snapshot {
        order: Some(order),
        rows,
    })
}

/// The `webSearch` health value: `null` until the scheduler has read the
/// store once, or when that read failed.
pub(crate) fn render(snapshot: Option<&Snapshot>, service: &WebSearchService) -> Value {
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
                "order_position": row.order_position,
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
    json!({"order": snapshot.order, "providers": providers})
}
