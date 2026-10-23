# Connector home

Plexus runs connector effects only when Entorhinal's `role.read` with
`{"role":"connector_home"}` confirms `known: true`, `held_here: true`, and
`stale: false`. It opens Entorhinal's management surface as `reserved:plexus`,
using the exact module id `entorhinal`. The daemon starts `unknown`; it does not
restore admission from disk. A task reads at boot and every 30 seconds. Each
route connection and call has a three-second deadline (at most six seconds for
both stages). Entorhinal decides whether the role is held here; Plexus does not
compare device identifiers.

Only fresh, well-formed reads replace the in-memory answer. A confirmed unheld
role is `not_held` with epoch 0 and no holder; a role held elsewhere reports
`holder_name`. Transport errors, malformed replies, and **any** `stale: true`
answer retain the last confirmed answer, whatever `held_here` says. Stale means
Entorhinal has not verified the cached answer since its own startup. Before the first
confirmed answer, Plexus refuses effects. `claim_integrity_failed` immediately
sets `integrity_failed` and records its code, even after a confirmed hold; only a
fresh read can replace it. Entorhinal keeps integrity failures sticky across its
own restarts until verified. Unknown reply fields are ignored, but all required
fields (including nullable ones) must be present and correctly typed.

Ownership is not an expiring lease: a confirmed holder intentionally works
offline. A takeover while the old holder is offline cannot immediately stop it;
it stops when a fresh read observes the new holder. Health is degraded with
`connector_home_not_held` unless held. Its `connectorHome` metric includes state
(`held`, `not_held`, `unknown`, `integrity_failed`), epoch, source, `holder_name`,
integrity `code`, and `checkedAt`. State transitions are logged.

## Rollout — pending: run at deploy

Deploy Plexus with this cutover and Entorhinal 0.1.25 or later. Then **the
operator runs `ck roles take connector_home` within the minute**, on the machine
that should be the connector home; the command asks for operator confirmation. Plexus refuses outside
effects until a confirmed read lands. Plexus no longer reads or takes claims
through Engram; only Entorhinal serves its connector-home reads.

```
ck-plexus-admin connector-home status --subc <connection-file>
ck roles take connector_home
```

Status is answered only to the operator's own local connection (`direct`), not
to a call carried by another module. It reads `role.read` and prints both the reply and the current gate. `ck-plexus-admin connector-home claim` is
removed and refuses by name, directing the operator to `ck roles take
connector_home`. Plexus never takes the role: Entorhinal's `role.take` is
Direct-only with operator confirmation and refuses `reserved:plexus`.

Moving connector state still requires carrying `store.db` and
`grant-revocations.jsonl` together; taking a role does not transfer the store.

## Effect-path census

While this machine is not confirmed as the connector home, each entry point below
refuses before doing any work. The refusal is `connector_home_not_held`, with the
state, epoch and holder name where known, and `transmission: not_sent`:

| Entry point | Effects behind the gate |
| --- | --- |
| Scheduler pass | Polls, write reconciliation, receipt sweeps, waiting approvals, repository ownership reconciliation, retired-agent sweep, health probes, transport pool sweeps |
| `invoke.call` | Catalog freshness/discovery, authorization/reservation, vendor dispatch |
| `github.bot_request` | Receipt reservation, ownership pre-reads, governed write legs |
| `web_search`, `code_search` | Backend/cache/rate-limiter admission, public search |
| `requests.approve` | Approval decision and execution |
| Consent answer task | Feed polling, approval execution, settlement, feed acknowledgment |
| `github_read` | Governed vendor reads (not reads of Plexus's store) |
| `connections.connect` | Ticket consumption and connection discovery |
| `github.handle.import`, `.probe`, `.bind` | Installation reads and credential resolution |
| `plexus.admin.issue_ticket`, `.rebind_credential` | Vault credential proof |
| `requests.deny`, `tool.withdraw` | Consent-card withdrawal |

Vendor reads, discovery, handle setup, vault proof and consent-card withdrawal
are effects too, even when they do not write to a vendor. Core governance checks before reservation,
approval execution and revalidated dispatch, so a long scheduler pass cannot
continue reserving or sending governed calls after a fresh role read revokes
admission. This is an admission fence, not cancellation of a call already sent.

Store-only operations remain available: connections/catalog/request/event
list/show, bindings reads, event registration and acknowledgment, grant/policy
management and action review. Startup catalog ingest and transport endpoint
registration perform local setup without vendor dispatch. The connector-home
management status remains open even while the daemon is unknown.

Tests use a peer double for every reply state and failure, and the conformance
harness supplies an Entorhinal management-surface double over real subc
RouteBind and route calls. It admits only daemon-attested `reserved:plexus`,
checks the exact `role.read` wire body, and exercises status and refusal of the
removed claim operation. A source scan fences removed claim operations with
planted controls. Entorhinal will publish `role.read` replies produced by its
own handler; they go, byte for byte, in
`crates/plexus-module/tests/fixtures/entorhinal-roles/` so plexus's decoding is
checked against real output. Until that file exists, the loader test skips with
a message.
