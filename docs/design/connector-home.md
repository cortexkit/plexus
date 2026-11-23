# Connector home

Plexus runs connector effects only while it holds Entorhinal's lease on the
`connector_home` role. It opens one management route to the exact module id
`entorhinal` as `reserved:plexus` and keeps a watch open on it:

```
{"method":"role.lease","params":{"role":"connector_home"}}
```

Each notice carries `seq`, `gen`, `holding`, `issued_at_ms` and
`valid_for_ms`, plus `handback: true` when another computer asks for the role
(a missing `handback` means false). Plexus acks every notice, `holding: false`
included, with `role.lease.ack {role, seq}` on the same route; Entorhinal renews
the holder's record only while it receives those acks. Notices arrive about
every 20 seconds. On the shared hub, `role.read` answers `held_here: true` only
while such a lease is live, so reading the role without holding the lease is
never enough.

The acting window ends at `issued_at_ms + valid_for_ms` on the OS boot clock
Entorhinal uses: `CLOCK_BOOTTIME` on Linux, `CLOCK_MONOTONIC` on macOS and
`GetTickCount64()` on Windows, in milliseconds. Plexus never uses wall time
or Rust's `Instant`, which on macOS does not count sleep. A notice admits
effects only after Plexus has acked it and journaled its generation. The
highest generation seen is kept in the store's `connector_home_generation`
table, so a restarted Plexus refuses to act under an older generation.

An act is one outgoing vendor leg (a REST or MCP request, an installation-token
fetch, a relay connect). Right before a leg is sent, the gate requires a holding
lease with at least 5 seconds left and takes a permit for the leg's lifetime.
The leg's timeout is then the smaller of its configured timeout (for example
the 30-second REST timeout) and the time left on the lease, so no leg outlives
the acting window. While renewals arrive, the window stays above about 25
seconds; it only runs down when renewals stop, which is when Plexus must stop. Waiting
(approval holds, the search chain, gaps between polls) is not an act. The
relay's established-socket controls (ack, ping, pong, close) are transport
control, not acts. The relay socket is dropped as soon as the lease stops
holding.

On `handback: true`, Plexus acks, starts no new leg, waits for in-flight
permits to settle or for the deadline, then calls
`role.lease.yield {role, gen}` on the watch's route. `yielded: true` stops
service at once; `yielded: false` keeps the lease, and service resumes only on a
fresh holding notice. If the watch ends, a reply is malformed or the store cannot
journal a generation, Plexus stops admitting and reopens the watch after three
seconds.

An Entorhinal that answers `role.lease` with `unknown_method` or `unsupported`
predates leases. Plexus then logs once and falls back, for the rest of the
process, to the earlier admission rule: `role.read` read at boot and every 30
seconds, admitting only `known: true`, `held_here: true`, `stale: false`. Any
other refusal or a transport failure means not holding, never the fallback.

`role.read` still serves `ck-plexus-admin connector-home status` and the
health report. Health's `connectorHome` metric includes the role-read state
(`held`, `not_held`, `unknown`, `integrity_failed`), epoch, source,
`holder_name`, integrity `code` and `checkedAt`, plus
`lease: {holding, gen, deadline_in_ms, handback, yield_pending}`. Health is
degraded with `connector_home_not_held` unless the lease is held. State
transitions are logged.

## Rollout — pending: run at deploy

Leases need Entorhinal 0.1.82 or later; the earlier role-read rule needs
0.1.25 or later. Deploy Plexus with this cutover. Then **the
operator runs `ck roles take connector_home` within the minute**, on the machine
that should be the connector home; the command asks for operator confirmation. Plexus refuses outside
effects until it holds the lease. Plexus no longer reads or takes claims
through Engram; only Entorhinal serves its connector-home reads.

```
ck-plexus-admin connector-home status --subc <connection-file>
ck roles take connector_home
```

Status is answered only to the operator's own local connection (`direct`), not
to a call carried by another module. It reads `role.read` and prints the reply and the current gate, including the
lease and `admitted`: whether Plexus would send an outside effect right now. The
role read can say `held` while Plexus still refuses, for example before its first
lease notice is acknowledged. `ck-plexus-admin connector-home claim` is
removed and refuses by name, directing the operator to `ck roles take
connector_home`. Plexus never takes the role: Entorhinal's `role.take` is
Direct-only with operator confirmation and refuses `reserved:plexus`.

Moving connector state still requires carrying `store.db` and
`grant-revocations.jsonl` together; taking a role does not transfer the store.

## Effect-path census

While this machine does not hold the connector-home lease, each entry point below
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
| `github_read` | Governed vendor reads; `github.bindings.list` only reads Plexus's store and is exempt |
| `connections.connect` | Ticket consumption and connection discovery |
| `github.handle.import`, `.probe`, `.bind` | Installation reads and credential resolution |
| `plexus.admin.issue_ticket`, `.rebind_credential` | Vault credential proof |
| `requests.deny`, `tool.withdraw` | Consent-card withdrawal |

Vendor reads, discovery, handle setup, vault proof and consent-card withdrawal
are effects too, even when they do not write to a vendor. Core governance checks before reservation,
approval execution and revalidated dispatch, so a long scheduler pass cannot
continue reserving or sending governed calls after the lease stops holding. This is an admission fence, not cancellation of a call already sent.

Store-only operations remain available: connections/catalog/request/event
list/show, bindings reads, event registration and acknowledgment, grant/policy
management and action review. Startup catalog ingest and transport endpoint
registration perform local setup without vendor dispatch. The connector-home
management status remains open even while the daemon is unknown.

Tests use a peer double for every reply state and failure, and the conformance
harness supplies an Entorhinal management-surface double over real subc
RouteBind and route calls. It admits only daemon-attested `reserved:plexus`,
checks the exact `role.read` wire body, and exercises status and refusal of the
removed claim operation. A source scan checks that the removed claim
operations stay absent, and its own tests prove it catches one put back. Entorhinal's published lease samples (tag `role-lease-v1.4`)
are vendored byte for byte in `crates/plexus-module/tests/fixtures/role-lease-v1/`
and driven through plexus's real lease client. Entorhinal will publish `role.read` replies produced by its
own handler; they go, byte for byte, in
`crates/plexus-module/tests/fixtures/entorhinal-roles/` so plexus's decoding is
checked against real output. Until that file exists, the loader test skips with
a message.
