# Web search: provider choice through routing

Status: implemented. Routing (the one `routing/v1` provider in the daemon
catalog, today STRIATUM) chooses which provider serves each web search.
Plexus keeps dispatch, credentials, audit, capability checks, rate limits and
allowance metering. `code_search` is unchanged and is not routed.

The wire is `cortexkit-role-routing` 0.7.32's CONTRACT.md: §16.4 and §16.4.2
(`select_search`), §16.6 (`report_attempt_outcomes`) and the
`search-provider/v1` declaration slot.

## Declaration

Plexus's manifest carries two role declarations, built in one place
(`web_search::routing::role_declarations`):

- `routing/v1`: consumer `plexus.web_search`, `kind: "search"`, selectors
  `["plexus"]`.
- `search-provider/v1`: `{routes: [{provider, model}]}`, one Fusiform search
  row per provider. The provider-to-row table is `SEARCH_ROUTES` in
  `web_search/providers.rs` (exa `exa/search`, tavily `tavily/search`, brave
  `brave/web-search`, deepseek `deepseek/search`, kimi
  `kimi-for-coding/search`, ollama `ollama-cloud/web-search`). A provider
  without a row is never declared or offered; a connected one is named once in
  the log at INFO.

HELLO declares every row, because the store (and so which providers are
connected) cannot be read before HELLO_ACK. After readiness, and on every
scheduler pass, plexus narrows the declaration to providers with a live
connection and sends `catalog.update_role_declarations` whenever that set
changes. Routing rereads the catalog about every 30 seconds, so for
`DECLARATION_GRACE_MS` (35 s) after a route is added, a `no_route` answer is
treated as "not seen yet" (retryable `backend_unavailable` with backend
`routing`). Narrowing only removes routes and opens no such window.

## A search

1. The cache is tried first. A hit needs no routing: it sends no select and no
   report, and answers while routing is unreachable.
2. Every provider with a row and a backend is checked without contacting
   anyone: capability, the caller's grant and connection, connection and
   action status, policy, this process's cooldowns, and any operator-set
   monthly allowance. A provider whose allowance is spent is left out; one
   with searches left is also listed in `allowance_left`, which routing prices
   at zero. Federated searches defer policy, status and cooldown to their
   dispatch gates, as before.
3. `route.select` is sent with `consumer`, `kind: "search"`,
   `privacy: "remote_allowed"`, `requirements: {iq: 75}` (the constant
   `SEARCH_DEMAND_IQ`; the contract defines no default level for a search
   consumer, and 75 is the level used by the `route.select` request/reply
   pairs recorded from routing's own handler, vendored in the directory
   named below),
   `eligible_routes` and `allowance_left`. The request bytes are checked
   against routing's recorded pairs in
   `crates/plexus-module/tests/fixtures/route-select-search-v1/`.
4. Plexus dispatches the provider named by `engine`, with every gate it ran
   before (deadline, allowance reservation, rate limits, authorization).
5. An attempt that reached, or may have reached, the vendor is reported with
   `route.report` and `attempt_outcome`: `served`, `served_empty` (zero
   results, which ends the search), `quota`, `throttled` (with
   `retry_after_ms` only when the vendor named the wait), `credential` (HTTP
   401 only; a 403 is never a credential failure), `unavailable`, or
   `rejected` (400/422, which also ends the search).
6. A failed attempt is followed by a new select with the failed route removed,
   at most once per route first offered.

Selects and reports are sent on a route bound to the search's own scope (the
daemon's stamp naming the session or run the search was made in), so routing
attributes the decision and its cost to that work rather than to plexus
(CONTRACT.md §3); a search made on an unscoped route selects unscoped. Each routing
call waits at most `ROUTING_CALL_TIMEOUT` (3 s; reports 2 s), cut to what is
left of the search's existing 120-second admission deadline.

## Refusals

- Routing unreachable, ambiguous in the catalog, not advertising search, or
  refusing a select for any reason but `no_route`: `backend_unavailable` with
  `backend: "routing"` (retryable), with no vendor contact.
- `no_route`, or nothing eligible: `web_search_unavailable` with the
  per-provider skip list, as before.
- A caller granted no provider: `web_search_not_granted`, or a module grant
  refusal naming the module-wide web search target (connection null).

## Health

The health report's `webSearch` section shows:

- `routing`: the last look for a routing provider in the daemon catalog,
  `{discovery, provider, at_ms}`, with `discovery` one of `found`, `none`,
  `several` or `unreachable` (the catalog could not be read, or the module has
  no daemon route to look over), or `null` before any search needed routing.
- `routes`: `{declared, updated_at_ms}`, the routes plexus last declared to
  routing and when it last replaced the declaration (`null` while HELLO's,
  which lists every catalog row, stands).
- `providers`: one row per routed provider in table order, one per connection
  when it has several, then any connected provider without a catalog row.
  Each row carries `route` (`null` without a row), `connection_id`,
  `principal`, `connection_present`, `cooldown_remaining_ms`, `allowance_used`
  and `allowance_limit`. The stored order and `order_position` are no longer
  reported.

## Order and compatibility mode

The stored `web_search_order` is no longer read and the no-order Exa
compatibility path is gone: every search takes the routed walk above. The
table is kept so an older plexus can still read it after a rollback.
`set_web_search_order` is refused by name as `web_search_order_retired`;
allowance and limit commands work as before.
