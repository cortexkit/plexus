# Flow grant diagnostics and restoration reads

A flow is an automation Basal runs for an agent (or, for a global flow, for the operator). The daemon attaches a scope to every route a flow's call travels on: its `agent_id`, whether it `delegates` that agent's authority, and its `flow_id`. That attached scope is the "stamp" below.

`grants.would_ask` is a management-route read, sent as `{method, params}`. Only the installing agent module (`reserved:prefrontal-core`) and the automation module on a daemon-stamped flow route (`reserved:basal`) may call this read; the exception admits no other management method. Connector-home ownership is not required because this operation reads only Plexus's store.

## Request and reply

Params contain `flow_id`, optional `agent_id`, and `items`. Unknown fields at the request, params or item level refuse the call with `invalid_request`, `reason: unknown_field`, and the field's name. For Basal, params.agent_id (including absence) and params.flow_id must equal the agent and flow attributes in the daemon's route scope stamp. A missing flow stamp returns `flow_scope_required`; mismatches return `agent_identity_conflict` or `flow_identity_conflict`.

Items are either `{grant}` or `{tool, connection?, action}`. Tools are `invoke`, `github`, and `web_search`. Invoke and GitHub items require a connection; web search is a capability without a connection and accepts action `search` or `web_search`. Each reply item echoes the input and adds `verdict` and `reason`. The closed reason set is:

- `allowed` (`yes`): grants present and policy allow.
- `module_grant_absent` or `agent_grant_absent` (`no`): includes `code` and mandatory `detail`.
- `policy_blocked` (`no`).
- `consent_unavailable` (`would_ask`): the policy requires operator consent before dispatch. Flows run unattended, and the operator ruled that they never raise approval cards, so a flow's call with this policy is refused rather than held.
- `invalid_target` (`no`): malformed capability reference, unsupported/invalid item, foreign grantee, absent connection/action, unavailable or ambiguous search backend.

No item reserves, prompts, resolves credentials or contacts a vendor. Each call on an accepted route binding writes one audit row. Its `args_redaction_summary` column stores the agent/flow attribution and item/verdict counts as JSON.

## Authority and capability references

Dispatch and restoration checks share `GovernanceEngine::evaluate_authority`; web search shares its candidate/grant selection and catalog-policy evaluation, including cache-hit policy. Agent-owned invokes evaluate both layers when the daemon stamp delegates under an authorized owner. Global and non-delegating invokes evaluate the module layer only. Install-time checks project agent-owned versus global authority from presence versus absence of `agent_id`, matching Prefrontal's `flow_scope_record`, which registers a delegating scope only when a flow names an owning agent. Web search and GitHub repository reads use agent identity for attribution only; GitHub bot writes always evaluate both layers.

A reference is `g1.` followed by unpadded base64url of the JSON Canonicalization Scheme (RFC 8785) object `{layer, grantee, tool, connection, action}`. This non-secret tuple identifies what a missing grant would cover, not a deleted row. Plexus decodes it without a lookup table or additional writes. It is stable across calls and restarts, and rejects noncanonical encodings. The reference is opaque as an API contract, not confidential or an authorization credential. A decoded module grantee must be `reserved:basal`; an agent grantee must match the request's owning agent.

Web search names the module capability, with `connection: null`, because backend selection is grant-dependent and the caller names no connection. Invoke names the requested connection and action even when the connection is invisible. A flow-only existence query distinguishes an existing but invisible connection (`module_grant_absent`) from a nonexistent one (`connection_not_found`); it returns no connection metadata and grants no dispatch authority.

Grant detail contains `grant`, `grant_label`, `layer`, `connection`, `action`, and `cause` (`missing`, `expired`, `action_selector`, or `risk_ceiling`). Typed `GrantRefusal` construction binds the layer code to that mandatory detail. Non-flow `grant_missing`, `grant_expired`, `grant_action_selector`, and `grant_risk_ceiling` codes remain unchanged; existing module/agent-absent codes also receive detail.

## Refusal census and wire placement

The following code paths can be reached by a flow-stamped tool call and can refuse invoke authority because a grant is absent or insufficient:

1. Governance module-layer selection and expiry/selector/risk checks, including its flow-only invisible-connection fallback.
2. Governance agent-layer checks, for delegating ordinary invoke and for facade legs.
3. GitHub bot module-authority gate, which checks the calling module's grant before any GitHub call (gate G6 in `github/facade/gates.rs`), including a handle connection missing from the store.
4. GitHub bot G6 agent presence and request-selector exclusion; the latter is unified only for flow calls, preserving non-flow `agent_grant_excludes_request`.
5. GitHub bot G8 ownership/pre-dispatch reads and G10 writes: both propagate typed governance refusals, retaining their action-specific detail in durable receipt outcomes.
6. `github.bindings.read`: module grant existence/expiry on the handle connection (selectors intentionally do not govern binding-table visibility).
7. `github.read`: each page's ordinary governance call, with flow scope attached for diagnostics only, preserving module-only authority.
8. Web-search candidate selection: no eligible module grant, including expiry, selector or risk-ceiling failure.
9. Web-search cache-miss governance recheck, when authority changes after candidate selection. Cache-hit policy refusal is a policy refusal, not a grant absence.

Flow-reachable exclusions retain their existing codes: `connections.configure`/`revoke` and non-flow `requests.approve`/`deny` require `connection_admin`; `events.subscribe`/`register_probe`/`resume` require poll grants. Basal's flow invocation grants authorize neither connection administration nor poll subscription changes. Flows cannot approve or deny held calls at all: `flow_cannot_decide_approvals` precedes any grant check, even if an admin grant is later minted. Event reads/acks filter rows by consume grants rather than returning grant-refusal errors. Catalog/connection/request listing and withdrawal enforce ownership or scope visibility, not additional grant refusals. Scheduled polling and reconciliation are separate background authorization paths, not daemon flow-stamped tool calls.

Wire placement preserves both contracts: invoke, web search, bindings and repository-read errors carry `error.detail`; GitHub bot refusal outcomes carry `result.detail` beside `refusal_code`/`code` and retain the top-level `repo_binding_generation`, a counter that moves whenever a repository is bound to or unbound from a bot, which clients such as AFT's `gh` shim compare to detect a routing change. MCP error results with detail serialize the complete original envelope into `content[0].text` and set `isError: true`. GitHub facade outcomes continue to use the existing result envelope and complete JSON text block. Management reads retain the ordinary `{result: {items}}` route response, without MCP adaptation.
