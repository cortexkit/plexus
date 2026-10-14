# Agent grants on the ordinary invoke path

Status: implemented with daemon session stamps. The earlier signed-agent-token proposal is retired; no minting, verification, signing-key lookup or compatibility mode remains in Plexus.

## Identity and authority

The daemon stamps a route bind with its session scope. Plexus reads `agent_id`, `delegates` and `owner_authorized` from that stamp, never from caller arguments. The module principal remains the carrier identity.

1. **No scope, or no delegation.** Only module grants authorize ordinary invoke. A non-delegating scope's agent is audit attribution, not authority.
2. **Authorized delegation.** A scope naming an agent with both `delegates` and `owner_authorized` needs BOTH the carrier's module grant (`agent_id IS NULL`) and the agent's own grant. Neither substitutes for the other. Refusals name the failed layer: `module_grant_absent` or `agent_grant_absent`.
3. **Retired arguments.** `assertion` and `agent_assertion` are undeclared on all tools. Plexus refuses the field by name before secret screening or tool dispatch, including null, malformed and secret-bearing values. A token never supplies attribution or authority.
4. **Policies.** Agent policy combines with module policy; the stricter effect wins.
5. **Audit.** Rows retain the carrier, stamped agent and daemon scope. Token-only claim columns remain in the additive store but are left NULL.
6. **Reservation fences.** Revalidation pins both grant generations, so revoking agent authority between authorization and dispatch aborts the call.

## Search exception

`web_search` and `code_search` are not actions taken as an agent outside Plexus. The carrier's module grant authorizes them; a stamped agent is attribution only, even under a delegating scope. Web search uses the carrier plus optional stamped agent as its per-caller rate key. An agent grant cannot substitute for the carrier's module grant.

## GitHub bot writes and flows

`github.bot_request` requires an authorized delegating stamp. Without it, G1 refuses `delegating_scope_required`; there is no default identity. G2 resolves only the stamped agent's bound bot and checks its App credential and repository binding. Both grant layers remain required, and each write rechecks its scope with the daemon.

Flow calls are carried only by Basal (the flow-execution module) under a scope naming the flow in `flow_id`. Flows cannot request consent: an ask-first policy refuses `consent_unavailable` without parking an approval or claiming a bot receipt.

## Grant management and deployment

Operators mint agent grants with `grant --agent <agent_id>`, bounded by the connection ceiling. `github.handle.grant` does the same for bot handles. Event-consumption grants remain module-scoped.

Deploy the retirement of identity-token tool arguments in a restart window so routes and fetched definitions refresh together. All callers must already be stamp-only; old token-bearing calls fail closed rather than being silently upgraded.
