# Architecture

Plexus is the CortexKit module that lets agents act on external services (GitHub, Linear, Notion, Exa and others) without ever holding a credential. It runs as a subc-supervised daemon (`ck-plexus`). Every vendor call goes through one mediation pipeline that checks authority, records an audit row and only then dispatches. Credentials stay in the claustrum vault and are resolved per call.

## The pieces

**Catalog.** Each vendor is a reviewed static manifest in `catalog/*.jsonc`: transport, auth mode, actions with risk and severity, poll shapes and optional reconciliation read-backs. Manifests are parsed with `deny_unknown_fields`, so a field an older binary does not know refuses boot. At startup the catalog reconciler ingests them into the store, and live vendor discovery pins each action's input schema by hash. A changed schema (including a reworded description) quarantines that action until an operator reviews and re-pins it.

**Authority.** Authority narrows at every step: manifest → binding ticket ceiling → connection → grant → invoke. Operators mint it out of band with `ck-plexus-admin` over the privileged ManagementSurface (`Principal::Direct` only). Grant kinds: `invoke`, `connection_admin`, `poll`, `events_consume`. An empty selector list authorizes nothing, and `*` must be explicit. Grants are until-revoked unless given an expiry. A revocation deletes the grant, snapshots it in `grant_revocations`, and first appends it to a journal file beside the database, so restoring an older store cannot resurrect it.

**Governance pipeline** (`GovernanceEngine`). A tool call goes RESERVE → REVALIDATE → DISPATCH:
1. Refuse undeclared identity-token fields (`assertion`, `agent_assertion`) and credential material in arguments. Agent identity comes only from the daemon's route scope stamp; `agent_id` attributes the call, while `delegates: true` requests agent authority and `owner_authorized: true` confirms that the daemon allows the scope owner to delegate it.
2. Authorize: connection health, catalog status, a matching grant, policy (`allow` / `ask_first` / `block`), severity and the decision plane for S3/S4, and resource filters. Write a 60-second reservation that pins the generations of every row it read.
3. Revalidate at claim time. Any generation that moved aborts the call.
4. Resolve the credential from the vault (credential-free manifests dispatch anonymously), dispatch, report the outcome, and write the audit row.

A write whose outcome is unknown and whose action declares a read-back class is queued for reconciliation. It is resolved by a governed read under the acting caller's current grants and never re-sent.

**Facade tools.** `web_search` searches public web pages. `code_search` searches public GitHub code through grep.app. Both are Pure reads governed by module grants, connector home, rate limits and query audits. Code search caps replies at 20 file matches, 100 lines per file and 32 KiB of rendered text; private code and pinned versions must be read from disk.
Both record the stamp's agent on audit rows but authorize only the carrying module's grant, not an agent grant. Web search also uses it in its per-caller rate key. Flow calls are carried only by Basal with a `flow_id` scope and cannot request consent (`consent_unavailable`).
Plexus serves tool-provider/v1's `tool.catalog` with per-tool capability tags from the advertised facade definitions.

**Connector home.** Outside effects (polls, bot writes, invoke dispatch and approved-request execution) require Entorhinal's `role.read {role: "connector_home"}` to confirm `known: true`, `held_here: true`, `stale: false`. The exact peer id is `entorhinal`; reads run at boot and every 30 seconds. Transport errors, malformed replies and any stale answer retain the last confirmed decision; before one arrives, effects are refused. `claim_integrity_failed` revokes admission immediately. Health's `connectorHome` reports state, epoch, source, holder name and integrity code. `connector-home status` reads the role; taking it belongs to `ck roles take connector_home`, never Plexus. [Rollout: pending, run at deploy](docs/design/connector-home.md#rollout--pending-run-at-deploy): deploy, then Ufuk takes the role within the minute; effects remain refused until the confirmed read lands.

**Transports.** `VendorTransportRouter` picks `RestTransport`, `McpRemoteTransport` or `McpRouteTransport` (a local MCP server run by a subc adapter). Agents see only sanitized error text. Full vendor diagnostics go to the operator log.

**Triggers.** A scheduler task ticks every second and polls due subscriptions sequentially with one of five cursor strategies (`sync_token`, `ordered_timestamp`, `scalar_diff`, `sorted_head`, `probe`). Failures back off exponentially, and five in a row trip a resumable circuit breaker. Events are deduplicated on (connection, subscription, vendor id, payload hash), so an edited item arrives as a new event, and coverage holes are recorded as `gap` rows. A per-poll ledger enforces `examined == inserted + dropped` with a closed set of drop reasons. Consumers read and ack events through `events_consume` grants. Subscriptions can be tagged with a project and a delivery agent.

**Probes.** `plexus-probe` runs author-supplied JavaScript in a QuickJS/WASI guest on Wasmtime (32 MiB, 5 s epoch deadline), and it can call only the read actions it declared.

**Health.** `health.check` answers from cached state. It reports degraded when active subscriptions exist but nothing has completed within three times the longest cadence, measured on the awake clock so host sleep does not count.

## Code map

| Area | Location |
| --- | --- |
| Manifest model and validation | `crates/plexus-core/src/manifest.rs` |
| Store, migrations, retention | `crates/plexus-core/src/storage.rs` |
| Governance pipeline | `crates/plexus-core/src/governance.rs` |
| Catalog ingest and discovery | `crates/plexus-core/src/catalog.rs` |
| Daemon scope identity and rechecks | `crates/plexus-core/src/scope.rs` |
| Poller and scheduler | `crates/plexus-core/src/poller.rs`, `scheduler.rs` |
| Uncertain-write reconciliation | `crates/plexus-core/src/reconciliation.rs` |
| GitHub bot facade, import, reads | `crates/plexus-core/src/github/` |
| GitHub handle store | `crates/plexus-core/src/store/github/` |
| Transports | `crates/plexus-core/src/{rest_api,mcp_remote,mcp_route}.rs` |
| Wire daemon, ceremony, health | `crates/plexus-module/src/` |
| Operator CLI | `crates/plexus-module/src/bin/ck-plexus-admin.rs` |
| Probe sandbox | `crates/plexus-probe/` |
| Conformance and drift harness | `crates/plexus-conformance/` |

## Rules that bite

- **Fail closed.** A missing ceiling, grant, principal or decision plane, or a hash mismatch, is a denial, never a default. Unknown severity is S4. An action plexus cannot classify is refused.
- **Complete mediation.** Nothing reaches a vendor except through `GovernanceEngine`, including poller reads, enrichment calls and reconciliation read-backs.
- **Audit is append-only.** Update is refused by trigger, and delete only past a 7-day floor. Retention defaults to 30 days (`PLEXUS_AUDIT_RETENTION_DAYS`). Each governed call writes two rows, the decision and the dispatch, correlated by `request_id`.
- **Migrations are additive and version-guarded.** An older binary serves a newer store with a warning. Deploy binary before catalog, and roll back in reverse. Rehearse every migration on a `.backup` copy of the live store (`examples/migration_rehearsal.rs`).
- **Credentials are opaque.** Connection bindings contain only non-secret vault credential references, or NULL for credential-free vendors. Plexus never persists bearer handles or a binding encryption key; vendor secrets are resolved by id at dispatch, discovery and health probing. Secret bytes never appear in `Debug` output, logs or agent-visible errors. A 403 is a permission refusal and never invalidates a credential; only a 401 is reported to the vault.
- **Diagnostics** go through `diag!(<level> <component>: ...)`, and a bare `eprintln!` does not compile in the daemon crates. Logs land in `~/.local/share/cortexkit/plexus/logs/`.

## GitHub bot writes

GitHub App bot requests go through plexus. The `github` tool has two operations: `bot_request` (governed writes with ownership pre-reads, or recording an issue an agent has seen) and `bindings.read`. Repository-bound issue and CI reads use the separate `github_read` tool; the former `github`/`read` operation is no longer accepted.

On a `reserved:basal` flow route stamped with `agent_id`, `github_read` issue, comment, search and CI reads see only repositories currently bound to that agent's enabled GitHub bot. Every repository in an issue search must pass this check before grant checks or reservations; excluded repositories refuse `repository_not_visible` with `transmission: not_sent`. Allowed repositories still require all existing module grants and policies. Agentless global flows retain Basal's grant-based reach, workspace flows retain their audience fence, and non-flow callers retain their existing access.

- **Handles.** One row per App (`github_app_handle`), keyed on its vault record `github_app:<slug>`. The installation id is informational. Each handle has its own `github-handle-<slug>` connection and is bound to its agent's repository (`github_repo_binding`); a bot only ever speaks as its own agent, and a write to another agent's repository refuses `agent_repository_conflict`.
- **Stamp identity.** A bot write requires an authorized delegating scope naming an agent. Otherwise it refuses `delegating_scope_required` before handle lookup or credential access, with no fallback. The agent's bound bot is resolved from the store, and its scope is rechecked before each write.
- **Two grant layers.** The calling module needs a module grant (agent_id null) on the handle connection. The agent needs an agent grant, which belongs to the agent whichever module carries its stamped call. Neither layer substitutes for the other.
- **The request.** The facade maps each request kind to catalog actions, builds the GitHub arguments from a per-kind allowlist (never the caller's fields), runs its ownership pre-reads (edits touch only the bot's own comments and issues), and dispatches each leg through `GovernanceEngine`. The token comes from the vault's `credential.get_scoped` at dispatch; the bytes are opaque.
- **Never twice.** A receipt keyed on (agent, request nonce) replays a finished outcome, reports a write in flight, and leaves a write whose outcome is unknown unsent. Its reconciliation result is `unreconcilable`, because GitHub comment read-backs cannot be matched to the write.
- **Setup.** Operators import handles from an inventory with `github.handle.import` (dry run by default, one transaction) and prove each with `github.handle.probe`, which lists the installation's repositories with the handle's own token. An unproven handle refuses.

Identity-token arguments have been retired with no compatibility mode; old callers are refused by field name, never silently ignored. Deploy this tool-contract cutover in a restart window so route bindings and fetched definitions refresh together. Audit storage remains additive: token-only claim columns stay present and new calls leave them NULL.

The obligations each seam of the facade must meet are listed in `docs/design/github-writes-governance/facade-integration.md`.
