# Connector home

Plexus runs connector effects only on the machine for which engram's
`claim.read` of `role:connector_home` returns `held_here: true`. The daemon
starts `unknown`; it does not restore an admission decision from disk. A task
reads at boot and every 30 seconds. Each route connection and each call has a
three-second deadline (at most six seconds for both stages). Engram decides
whether a claim is held here; Plexus does not compare device identifiers.

Successful reads replace the in-memory state. A missing claim is `not_held`
with epoch 0. Transport failures, timeouts, `key_unavailable`, and `unavailable`
retain the last answer. `verify_failed` changes it to `not_held`. Ownership is
not an expiring lease: this intentionally permits the confirmed holder to work
offline. A forced takeover while the old holder is offline cannot immediately
stop that holder; it stops when its next successful read observes the new epoch.
Health is degraded with `connector_home_not_held` unless the gate is held. Its
metrics include `connectorHome` with state, epoch, holder, source and checkedAt.
The scheduler and reader log state transitions rather than every refusal/read.

## Bootstrap

Deploy engram with support for the `to_device: "self"` literal before applying
a claim. The older engram implementation accepts only a device's hex id, and
will refuse that apply. Plexus's reader and preview work with either version.

```
ck-plexus-admin connector-home status --subc <connection-file>
ck-plexus-admin connector-home claim --reason 'bootstrap connector home' --subc <connection-file>
ck-plexus-admin connector-home claim --reason 'bootstrap connector home' --apply --subc <connection-file>
```

These are Direct-only management operations. Status performs a live read and
reports both the claim and the current gate. Claim previews by default, requires
a non-empty reason, and applies with `claim.force`, an empty cut, the latest
read epoch, and `to_device: "self"`. The CLI prints the fresh request id before
sending; retain it and pass `--request-id` to retry the same apply. Plexus retains
the original force body by request id in memory so a retry does not change its
expected epoch after a landed response. This retry cache does not survive a
Plexus restart; after a restart inspect status rather than treating a new epoch
as the original request. Engram's id-reuse refusal prevents a mismatched retry
from taking another epoch. Apply and outcome are audited before and after the
route call. Successful apply immediately rereads the claim before returning.
Moving the connector home to another machine is not built yet. It will need the
claim released here, `store.db` and `grant-revocations.jsonl` carried together,
and the claim taken on the new machine.

## Effect-path census

The gate returns `connector_home_not_held`, state/epoch/holder where known, and
`transmission: not_sent` before the following entry points do work:

| Entry point | Effects behind the gate |
| --- | --- |
| Scheduler pass | Polls, write reconciliation, receipt sweeps, waiting approvals, repository ownership reconciliation, retired-agent sweep, health probes, transport pool sweeps |
| `invoke.call` | Catalog freshness/discovery, authorization/reservation, vendor dispatch |
| `github.bot_request` | Receipt reservation, ownership pre-reads, governed write legs |
| `web_search` | Backend/cache/rate-limiter admission, vendor search |
| `requests.approve` | Approval decision and execution |
| Consent answer task | Feed polling, approval execution, settlement, feed acknowledgment |
| `github.read` | Governed vendor reads (not reads of Plexus's store) |
| `connections.connect` | Ticket consumption and connection discovery |
| `github.handle.import`, `.probe`, `.bind` | Installation reads and credential resolution |
| `plexus.admin.issue_ticket`, `.rebind_credential` | Vault credential proof |
| `requests.deny`, `tool.withdraw` | Consent-card withdrawal |

Vendor reads, discovery, handle setup, vault proof and consent-card withdrawal
are effects too, even when they do not write to a vendor. Core governance checks before reservation,
approval execution and revalidated dispatch, so a long scheduler pass cannot
continue reserving or sending governed calls after a later claim read revokes
admission. This is an admission fence, not cancellation of a call already sent.

Store-only operations remain available: connections/catalog/request/event
list/show, bindings reads, event registration and acknowledgment, grant/policy
management and action review. Startup catalog ingest and transport endpoint
registration perform local setup without vendor dispatch. The connector-home
management operations remain open so an unknown daemon can be bootstrapped.

Tests use a trait double for failures and state transitions, and the conformance
harness supplies an engram InternalService double over real subc RouteBind and
route calls. That engram stand-in checks the principal stamped by the daemon on
RouteBind, admitting only `reserved:plexus` (the supervised Plexus module,
authenticated with its launch nonce). It checks the force-to-self wire body
and exercises status, preview and apply.
