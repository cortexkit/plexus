# Flow repository visibility

## Agent-owned flows

For `reserved:basal` routes with both `flow_id` and `agent_id`, `github_read`
issue reads (`github.issue.get`, `github.issue_comments.list`, and
`github.issue.search`) use the same enabled-bot repository visibility rule as CI
reads. `scope::basal_flow_read_agent` selects these routes, as it does for
`events_get`. Every named repository must currently belong to that agent's bot;
search cannot combine an owned repository with another bot's repository.
The shared read check runs before connection resolution, grants or reservations
and rechecks each page before authorization and dispatch. A repository outside
those bindings refuses `repository_not_visible` with `transmission: not_sent`.
Visibility does not confer authority: allowed repositories still pass every
existing grant and policy check, with scope used for attribution only.

This fence does not apply to non-flow callers or routes carried by other
modules, even when they have an agent stamp. Agentless global flows continue to
use Basal's grants on any bound repository. Agentless workspace flows retain
the audience rules below, including the free-text search refusal.

## Agentless flow audience

Only `reserved:basal` routes stamped with `flow_id` and no `agent_id` consult
`prefrontal-core`'s `flow.audience`. The lookup uses Plexus's own unscoped
management route, like `agent.resolve`: it authenticates as Plexus without
borrowing any authority from the flow's scope. Successes are
cached in memory by flow ID for less than 30 seconds measured from lookup start;
refusals are never cached. Core's opaque revision travels with the cached answer.
Unconfigured routes, timeouts, unknown reply shapes and core failures refuse
before connector authorization or dispatch. An agent audience requires an agent
stamp and refuses an agentless call.

Workspace reach is an additional pre-dispatch fence, never a substitute for
Basal's existing grants. Excluded repositories refuse before the grant checks;
allowed repositories still pass every existing grant and policy check.
A repository must have exactly one distinct project across GitHub watch rows
with `project_source='entorhinal'` and `status <> 'retired'`. Suspended watches
are paused but still own their repository watch, so they participate. Retired
watches retain historical projects and are ignored.
Operator-set project labels (`project_source='hand'`) are annotations, not registry ownership evidence;
missing, conflicting or unreadable stamps deny reach. Owner and name compare
case-insensitively. Refusals disclose the repository, not workspace project IDs.

## Operation inventory

`tool_provider::modes_for` determines which tools `ops.call` may reach in each
call mode. In Flow mode:

| Operation | Repository source and audience decision |
| --- | --- |
| `github_read` | Check every string in `repository` (scalar or array). This includes issue reads, comments and repository-only issue search. On `github.issue.search`, caller-supplied `terms`, `q` or `query` refuse as an unresolved repository. |
| CI `github.actions.job_log` | Same outer `repository`; the reader derives both `get_job` and job-log request targets from it. |
| CI `github.actions.artifact_file` | Same outer `repository`; artifact listing, selection and file download use that repository. |
| CI `github.actions.run.superseded` | Same outer `repository`; run metadata and newest workflow run use that repository. |
| `invoke` / `call` | Resolve the invoke-visible connection, including owner-shared grants. For `github`, `github_rest` (imported bot handles), and `github_actions`, check all `args.repository`, `args.repositories`, and `args.owner`/`args.repo` selectors. Missing, malformed or empty selectors refuse. Any `terms`, `q` or `query` field within `args` refuses as an unresolved repository, regardless of the action or value. Non-GitHub connections retain their existing grant path. |
| `github` / `bot_request` | Check `request.repository` before receipts or preflight. Existing bot identity and grant rules still apply. |
| `github` / `bindings.read`, `bindings.read_for_agent` | Refuse workspace calls: these project stored repository bindings without a resolvable single repository selector. |
| `events_get` | Use the stored event's `headers.repo`, not caller arguments or the event's old project label. Apply the filter before name/version disclosure. Excluded and unknown events have the identical `event_not_visible` reply. |
| `catalog` (`apps`, `list`, `inspect`) | Describes vendor/action schemas, not repository data; unchanged. |
| `web_search`, `code_search` | Public search, no watched repository target; unchanged under the existing grants. |
| `tool.catalog`, `role.describe` | Metadata, no reach-dependent check; unchanged. |
| `tool.withdraw` | Existing call-key ownership checks; cancels a call, cannot dispatch a repository operation. |

The shipped REST catalog declares `terms` and `q` on `github.issue.search`.
The GitHub Model Context Protocol (MCP) catalog lists search actions without argument schemas, which are
discovered at runtime, so the fence also rejects the `query` alias. No nested
query aliases are declared by the shipped catalogs; the check nevertheless
finds these three field names in nested objects and arrays too.

`github_read` rebuilds `q` rather than forwarding a caller's `q`, but it appends
caller-controlled `terms` to the checked repositories. Workspace calls therefore
refuse those free-text fields rather than relying on the existing qualifier
prefix checks and post-search result filter to prove query confinement. With
no free-text fields, search builds its query from the checked repositories alone.

`connections`, `requests`, and `events` are Classic-only in the admission table,
not Flow-mode tools. A Classic route with a flow stamp retains the existing
flow restrictions (`events` permits only `get`; approval decisions refuse).
The shared audience gate also covers legacy `events` / `get` and `github_read`
on these stamped routes. Workspace calls to Classic-only `connections`
and `requests` refuse because they can expose stored repository selectors
without a resolvable target. Other management operations keep their existing
principal/direct-only checks.

`grants.would_ask` accepts a flow ID but no repository. It checks the agentless
flow's audience once per request (using the same bounded cache), returning each
item as `no` on audience refusal or agent-audience mismatch. Otherwise it predicts
only grants and policy, as for agent-stamped flows. Repository reach is checked
on the real call; an allowed workspace repository agrees with this prediction.

Prefrontal's published v1 conformance vectors are vendored byte-for-byte in
`crates/plexus-module/tests/fixtures/flow-audience-v1/`, with source provenance
in `PLEXUS-README.md`. The decoder harness exercises every recorded case through
Plexus's real subc lookup and parser and checks its outgoing request parameters.
Project IDs are opaque nonempty strings, sorted and unique; repository access
still requires an exact match with an entorhinal-set watch stamp.
