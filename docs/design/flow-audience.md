# Agentless flow audience

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
A repository must have exactly one distinct project on GitHub
watch rows with `project_source='entorhinal'`. Operator-set project labels
(`project_source='hand'`) are annotations, not registry ownership evidence;
missing, conflicting or unreadable stamps deny reach. Owner and name compare
case-insensitively. Refusals disclose the repository, not workspace project IDs.

## Operation inventory

`tool_provider::modes_for` determines which tools `ops.call` may reach in each
call mode. In Flow mode:

| Operation | Repository source and audience decision |
| --- | --- |
| `github_read` and legacy `github` / `read` | Check every string in `repository` (scalar or array). This includes issue reads, comments and issue search. |
| CI `github.actions.job_log` | Same outer `repository`; the reader derives both `get_job` and job-log request targets from it. |
| CI `github.actions.artifact_file` | Same outer `repository`; artifact listing, selection and file download use that repository. |
| `invoke` / `call` | Resolve the invoke-visible connection, including owner-shared grants. For `github`, `github_rest` (imported bot handles), and `github_actions`, check all `args.repository`, `args.repositories`, and `args.owner`/`args.repo` selectors. Missing, malformed or empty selectors refuse. Non-GitHub connections retain their existing grant path. |
| `github` / `bot_request` | Check `request.repository` before receipts or preflight. Existing bot identity and grant rules still apply. |
| `github` / `bindings.read` | Refuse workspace calls: this projects stored repository bindings without a resolvable single repository selector. |
| `events_get` | Use the stored event's `headers.repo`, not caller arguments or the event's old project label. Apply the filter before name/version disclosure. Excluded and unknown events have the identical `event_not_visible` reply. |
| `catalog` (`apps`, `list`, `inspect`) | Describes vendor/action schemas, not repository data; unchanged. |
| `web_search`, `code_search` | Public search, no watched repository target; unchanged under the existing grants. |
| `tool.catalog`, `role.describe` | Metadata, no reach-dependent check; unchanged. |
| `tool.withdraw` | Existing call-key ownership checks; cancels a call, cannot dispatch a repository operation. |

`connections`, `requests`, and `events` are Classic-only in the admission table,
not Flow-mode tools. A Classic route with a flow stamp retains the existing
flow restrictions (`events` permits only `get`; approval decisions refuse).
The shared audience gate also covers legacy `events` / `get` and legacy GitHub
reads on these stamped routes. Workspace calls to Classic-only `connections`
and `requests` refuse because they can expose stored repository selectors
without a resolvable target. Other management operations keep their existing
principal/direct-only checks.

`grants.would_ask` accepts a flow ID but no repository. It checks the agentless
flow's audience once per request (using the same bounded cache), returning each
item as `no` on audience refusal or agent-audience mismatch. Otherwise it predicts
only grants and policy, as for agent-stamped flows. Repository reach is checked
on the real call; an allowed workspace repository agrees with this prediction.

Prefrontal-core's conformance vectors belong in `test-vectors/flow-audience-v1/`. Until they are
published, the non-vacuous decoder harness is explicitly ignored; no upstream
compatibility is claimed.
