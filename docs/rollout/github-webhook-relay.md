# GitHub webhook relay consumer

Plexus connects outward to the GitHub webhook relay's WebSocket endpoint while
holding connector home, and authenticates with a relay credential read through
the existing scoped vault credential reader. The credential is opaque: neither
application diagnostics nor WebSocket transport tracing may print it. The relay
URL has no environment override; local WebSocket fixtures supply an explicit URL
in tests.

## Delivery and reconciliation

Migration 46 adds only `relay_cursor(source, stream_id, committed_seq)`. A hello
must match the dialled source before events or acknowledgments are accepted. A
new stream resets the cursor and schedules a full reconcile. The relay retains
unacknowledged frames for seven days; if its oldest buffered sequence skips past
Plexus's committed sequence, or its last ack is ahead of the local store, Plexus
also schedules a reconcile, including when an older store has been restored.

Each received frame is processed serially. Event insertion, the existing outbox
marker, the closed drop ledger counters and the relay cursor advance commit in
one fenced transaction. Only then is that received sequence acknowledged. A
crash before commit permits redelivery; a lost ack after commit replays the
cursor without inserting another event. Webhook projections use the same six
semantic event keys and the same insertion helper as polling. The first inserted
copy retains its body and project headers.

Only repositories with active issue/PR watches are admitted, using the issue
watch's project stamp and the payload's repository id. If that payload id differs
from the id in `github_repo_id_cache` for the same repository name, Plexus
suspends the repository's active watches rather than publishing under a reused
name. Polling resolves repository names to numeric ids with `get_repository`;
a failed initial lookup can leave that cache row's id null. A webhook fills
that unknown id from its verified payload, so the polled copy can derive the
same key without overwriting a known identity.
Other refusals increment closed `relay_drop_*` counters in
`event_outbox_counters`; they still advance the relay cursor and are acked.

Oversized and rate-limited stubs never publish. They make existing watches for
the repository due now; an absent repository conservatively makes the whole
watch set due. An overflow marker reports GitHub deliveries dropped for an
installation. These markers and installation-bound frames with null
repositories make all repository watches due. Agent bot App installations are
not the relay App's installations, and there is no authoritative installation
mapping in the store: a learned subset could miss repositories that never sent
a webhook. Installation-bound repository lists instead match names
case-insensitively and check any recorded repository id.

Reconciliation clears each watch's `last_polled_at_ms` timestamp, making it
eligible for the scheduler's next due-watch selection. It creates no new poller,
does not alter cadence, and still passes through the scheduler's existing
600-GitHub-Actions-requests-per-hour admission budget. Normal polling stays
unchanged while the relay is connected.

## Operator status and failures

The read-only management operation is `relay.status`, invoked as
`{"method":"relay.status","params":{}}` on an authenticated operator route
bound as the `direct` principal, not as an agent or module. Its result is
`{"sources":[{"source":"github","state":"no_credential","last_event_at":null,"message":"Plexus has no relay credential for GitHub. Use Connect GitHub."}]}`
on a poll-only boot. It does not read or return the credential.

Missing credentials are checked again after five minutes. HTTP 401 or close
4001 stops connection attempts until a five-minute scoped reread returns
different bytes; neither reports a vendor auth failure to the vault. HTTP 404
with exact body `{"error":"unknown_source"}`, specified by the vendored wire
contract and HTTP vectors, stops retrying as `source_not_served`.
Close 4009 immediately refreshes connector home; reconnects require the claim.
Other drops and protocol errors back off exponentially, capped at five minutes.
Protocol pings are sent every thirty seconds. Unknown frame types close 4400.

Rejected credentials and an unserved source degrade health with the same
operator sentence shown by status. Poll-only `no_credential` is healthy. A
superseded socket also degrades health while reconnecting, as required by the
wire contract; ordinary transient network reconnects do not.

Binary rollback leaves the additive cursor table in place. The migration test
opens the upgraded store with the prior binary's migration chain (through
migration 45, before the relay cursor table), checks
`store_ahead()` with no migrations applied, writes an old-schema audit row,
then re-forwards and verifies both the cursor and old-schema writes survive.

## Offline verification

The module tests replay the vendored JSONL frame bytes through loopback
WebSockets, substituting only the three permitted placeholders. Supplemental
GitHub payloads exercise projection, deduplication, transactional failure,
redelivery, ordering and the 64-frame window. Run crate tests and all-target
clippy on Linux.
The full CI gate remains separate.
