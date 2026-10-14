<!-- Vendored from cortexkit/cortexkit-cloud at 908eba9f442e3cf1a95772bfae81808816074a4c, docs/designs/webhook-relay-spec.md lines 242-422 (Stubs, Account buffer, Plexus connection wire contract, Relay credential). Do not edit; re-vendor. -->

### Stubs

A stub body carries `"repository":{"id","full_name"}` and `"item":{"kind","id","number"}` read
from the verified body, plus `"oversized":true` or `"rate_limited":true`. Field types are
enforced at extraction: `repository.id`, item `id` and `number` must be JSON integers in
0..2^53 - 1 and `full_name` a string of at most 256 bytes; any other value (wrong type, out of
range, too long) or a missing component becomes null, never a refusal. `kind` comes only from
this table, by `X-GitHub-Event`:

| event | kind | id | number |
|---|---|---|---|
| `issues`, `issue_comment` | `issue` | `issue.id` | `issue.number` |
| `pull_request`, `pull_request_review`, `pull_request_review_comment` | `pull_request` | `pull_request.id` | `pull_request.number` |
| `workflow_job` | `workflow_job` | `workflow_job.id` | null |
| `workflow_run` | `workflow_run` | `workflow_run.id` | null |
| `check_run`, `check_suite` | the event name | `check_run.id` / `check_suite.id` | null |
| `release` | `release` | `release.id` | null |
| any other (including `installation`, `installation_repositories`) | `item` is null: reconcile the repository, or the installation when `repository` is null |

### Account buffer, dedup, delivery (design: "Delivery guarantees", "Relay")

- Keep one `RelayAccountDO` per account, not one per source: metering emits the same
  `webhook-relay` service/resource facts per account, and GitHub installation ownership lives
  there. Inside it, partition credentials (four live per account and source), events, delivery
  tombstones, body-hash dedup, `seq`, `stream_id`, `oldest_seq`, `last_acked_seq`, the 64-frame
  in-flight window and connected socket by source. Suspension or an account-level ledger hold
  closes every source's socket; credential revocation or expiry affects only sockets using that
  credential/key. One shared alarm takes the minimum of all source deadlines. GitHub's
  installation-specific overflow-marker schedule remains in `InstallationDO`, inherently
  GitHub-scoped; its markers, every GitHub ingest event and `cortexkit_installation_bound` enter
  only the `github` stream. No stream state or ack is shared across sources.
- The worker is not deployed: change table definitions directly, without compatibility
  migrations for the former single stream.
- `RelayAccountDO` ingest transaction (one synchronous SQLite transaction, no await inside):
  first delete any event or tombstone whose `received_at` + 7 days is at or before now, so
  expiry never depends on the alarm having run; then dedup on `delivery_id` against the event
  table and the tombstone table; if new, assign the next per-account-and-source `seq`, store the event,
  and count one `webhook_events` unit through `packages/metering` in the same transaction. A
  duplicate `delivery_id` is answered 200, not stored and not counted. `seq` is an integer
  starting at 1, never reused, bounded by 2^53 - 1; reaching the bound makes ingest fail with
  500 (never wraps).
- Stored event: `seq`, `delivery_id`, `event`, `action` (a string of at most 128 bytes, else
  null), `installation_id`, `received_at`, and the body as the raw verified bytes, never
  re-serialized; the `event` frame splices them verbatim after its JSON envelope. Size is
  decided in the ingest transaction on the encoded frame with the assigned seq, from the body
  length passed as metadata, for every forwarded GitHub event including the ceiling-exempt
  lifecycle events: if the full frame exceeds 1,048,576 bytes, or `action` was over 128 bytes,
  the event is stored as an oversized stub built from the edge-extracted fields, still accepted
  and counted. The bounded header, action and stub fields keep every stub frame far below 1 MiB.
  Reading of the design: its body cap "set by the Durable Object row limit" is read as the
  smallest limit on the path to Plexus, which is the 1 MiB WebSocket message limit.
- Undelivered events expire 7 days after `received_at` (the alarm deletes the event and its
  dedup entry together; ingest also excludes expired rows as above). An event deleted by ack
  leaves a dedup tombstone (`delivery_id`, `received_at`) until `received_at` + 7 days, so a
  replay inside the window is refused; a replay after it is a new event (the design's dedup
  window is 7 days). Overflow markers rely on this window, which is why an unconfirmed row is
  abandoned after 6 days (step 4); the bound event's idempotency is the binding generation.
- Delivery never blocks ingest. If no consumer is connected, events wait. Plexus learns of a gap
  only through `seq`.
- The DO's single alarm is armed at the earliest of: the next TTL expiry, the metering library's
  next deadline, the end of a previous MAC key window while a socket using it is connected, and,
  while any socket is connected, the next account-status recheck (see "Relay credential").

### Plexus connection: the relay wire contract (counterpart PLEX; pinned with vectors)

- Public relay routes are `POST /v1/relay/<source>/credentials`,
  `DELETE /v1/relay/<source>/credentials/<id>`, `GET /v1/relay/<source>/ws`,
  `POST /v1/relay/<source>/connect`, `GET /v1/relay/<source>/connect/<attempt_id>`,
  `GET /v1/relay/<source>/status` and `DELETE /v1/relay/<source>/installations/<installation_id>`.
  The single source registry in code is `RELAY_SOURCES`, currently only `github` (case-sensitive).
  On all these routes an unknown source returns HTTP 404 with exact JSON
  `{"error":"unknown_source"}`, before credential parsing, authentication, storage access or
  addressing any DO. This is not a credential refusal (HTTP 401 or socket 4001): clients report
  a source/configuration error, not a revoked credential. The unscoped routes are removed;
  there are no aliases or compatibility paths.
- `GET /v1/relay/<source>/ws` with `Upgrade: websocket` and `Authorization: Bearer <relay credential>`.
  The worker resolves the credential to its account (see "Relay credential"), then hands the
  upgrade to that account's `RelayAccountDO`. Any credential refusal at connect (malformed, bad
  MAC, expired key, unknown or revoked id, wrong secret) is HTTP 401 with no upgrade. Hibernating
  WebSocket; one consumer per account and source: a new authenticated connection closes only the previous same-source one
  with close code 4009 `superseded`.
- Encodings: every seq field (`seq`, `next_seq`, `oldest_seq`, `last_acked_seq`, `through_seq`)
  is a JSON integer in 0..2^53 - 1 (0 only for "none yet"); `installation_id`, `binding_gen`
  and `overflow_seq` are JSON integers; `received_at` is RFC 3339 UTC with milliseconds
  (`YYYY-MM-DDTHH:MM:SS.sssZ`); `action` is always present, null when absent.
- All frames are JSON text frames with a `type` field; unknown types are a protocol error (close
  4400). Server to client:
  - `hello`: `{"type":"hello","v":1,"source":"<source>","account_id","stream_id","next_seq","oldest_seq","last_acked_seq"}`
    sent on connect. `stream_id` is a random 128-bit id (base64url) created once with the account-and-source
    buffer and never reused: a recreated buffer restarts seq at 1 under a new `stream_id`, so a
    client never mistakes a restart for being behind (it logs, runs a full reconcile poll and
    resets). `oldest_seq` is the smallest buffered seq (or `next_seq` when empty). A client whose
    committed seq is below `oldest_seq - 1`, or below `last_acked_seq`, has a gap: it logs the
    range and reconciles.
    `source` must equal the dialled source; a mismatch is a client-side protocol error and the
    client must refuse the stream before processing events or acks.
    At sequence exhaustion, `next_seq` saturates at 2^53 - 1 so the hello remains valid and the final event remains deliverable, while further ingest fails rather than wrapping.
  - `event`: `{"type":"event","seq","delivery_id","event","action","installation_id","received_at","stub","body"}`
    where `stub` is null, `"oversized"`, `"rate_limited"` or `"overflow"`, so a client never
    sniffs body keys, and `body` is the GitHub JSON object or the stub. Events are sent in `seq`
    order, starting after `last_acked_seq`, at most 64 unacked frames in flight. The relay's
    synthetic events use the same frame with `stub` null except the overflow marker:
    `cortexkit_installation_bound` (body `{"installation_id","repositories":[{"id","full_name"}]}`,
    `delivery_id` `bound:<installation_id>:<binding_gen>`) and `cortexkit_overflow`. The bound
    event's `repositories` is null, meaning reconcile every repository of the installation, when
    its frame encoded with seq 2^53 - 1 (the widest; every other envelope field is fixed width or
    known at bind) would exceed 1,048,576 bytes; `InstallationDO` applies this one rule at bind
    time and the account DO stores the result as is.
- Client to server: `ack`: `{"type":"ack","through_seq"}`. Cumulative: deletes every buffered
  event with `seq <= through_seq`. A `through_seq` above the highest sent seq, negative,
  fractional, non-integer or above 2^53 - 1 is a protocol error. A value not above a previous ack
  is ignored.
- Close codes: 4001 credential revoked or invalidated on an open socket (on revoke, at a
  previous MAC key's window end, and when the account is no longer active), 4009 superseded (the close reason carries the superseding
  credential id, which is also logged), 4400 protocol error, 1011 internal.
- Only the Plexus holding the connector-home claim may connect; PLEX's client enforces this, and
  when connector home moves the old machine's relay credential is revoked. On 4009 a client
  re-checks its claim, stops if it no longer holds it, and otherwise reconnects with exponential
  backoff and reports degraded health. On HTTP 401 or 4001 a client stops and reports that the
  connect-GitHub step must be re-run.
- Liveness: the client sends WebSocket protocol pings every 30 s, answered by the runtime's
  automatic ping/pong handling without waking a hibernated DO; the relay sends no pings and
  registers no auto-response pair. This is a platform guarantee the relay relies on and does
  not test: the vitest Workers pool's client cannot emit a control-frame ping.
- These frames are a pinned contract owned by this repository, published under
  `test-vectors/webhook-relay/` as JSONL, one file per frame type, one case per line as
  `{"name","frame","expect"}` following the `{name, ...}` envelope of the existing vectors
  (`test-vectors/rdv-wire/README.md:40-51`). For client-to-server files `expect` is `"valid"` or
  the close code. For server-to-client files `expect` is `"emitted"` and `frame` is exactly what
  the relay sends from the state the case names, with `stream_id`, `account_id` and
  `received_at` substituted by the test. Owned vectors carry no `.vendored` manifest
  (`scripts/check-vendored-vectors.sh:39` checks only vendored copies); PLEX vendors them with a
  source line naming this repository, a commit and that path. Cases include a hello whose
  `last_acked_seq` is ahead of the client, a changed `stream_id`, each stub kind,
  `cortexkit_installation_bound` with and without `repositories`, seq values at 2^53 - 1, the
  invalid acks above, and an unknown `type`. Client rules PLEX has fixed against these:
  `cortexkit_installation_bound` is acked once its reconcile poll is queued; rate-limited and
  oversized stubs publish no event and trigger a re-read; an overflow marker is a logged gap plus
  a reconcile of that installation's repositories. A frame change goes through PLEX first.
  `unknown-source.jsonl` pins real HTTP statuses and exact response body text on all three
  routes. `hello-source-mismatch.jsonl` pins a client-side protocol-error fixture: the generator
  takes a real hello and changes only its source; the worker never emits this invalid hello.

### Relay credential (design: "scoped relay credential issued when the user connects GitHub")

- Format `ckwr_<account_ulid>.<credential_id>.<mac_key_id>.<mac>.<secret>`, where
  `credential_id` is a ULID, `mac_key_id` matches `^[a-z0-9-]{1,32}$`, `<secret>` is 32 random
  bytes, base64url, and `mac` is HMAC-SHA256 (base64url) under the MAC key named by
  `mac_key_id` over `ckwr-v1\0<account_ulid>\0<source>\0<credential_id>`. Minted by
  `POST /v1/relay/<source>/credentials`, authenticated with the user's account JWT (verified through
  `packages/account-auth`, issuer and audience as the rendezvous uses); the response returns the
  credential once; with 4 live credentials for that account and source it answers 409 `credential_limit`.
  The mint reply remains HTTP 201 `{"id","credential"}`. The source is supplied by the route,
  not embedded in the credential string; verification for a different source fails its MAC
  before any account DO is addressed. Revocation replies are unchanged.
  `RelayAccountDO` stores the source, the SHA-256 of `secret`, the credential id, and created/revoked
  times.
- The edge parses the fields, selects the current or still-valid previous key by id, and
  verifies the MAC in constant time before addressing the account's DO, so unverified input
  never addresses a DO. The DO then checks that `credential_id` is live for the requested source and compares the SHA-256
  of `secret` in constant time.
- Rotation: a credential minted under a previous key works until that key's window ends, then is
  refused (connected sockets close 4001). Plexus never mints, so rotation is user-visible: every
  affected user must re-run the connect-GitHub consent step. The deploy documentation states this.
- Custody: the caller of `POST /v1/relay/<source>/credentials` is the connect-GitHub consent step, which
  holds the user's account JWT and stores the result in Claustrum (name `relay:github`, owned by
  the vault's seat); Plexus reads it by name.
  More generally `ck-account relay connect <source>` stores it as `relay:<source>` and each
  source has its own consumer module; Plexus consumes `github`.
- `DELETE /v1/relay/<source>/credentials/<id>` with the account JWT revokes; it is routed to the account's
  `RelayAccountDO`, which closes only that source's socket using that credential with 4001 before answering.
- Account status, independent of metering (which ships disabled and so cannot signal a
  suspension): `RelayAccountDO` asks `ACCOUNT_IDENTITY.accountActive(account)` on every mint
  (inactive: 403 `account_inactive`), on every WebSocket connect once the credential's secret
  matches (inactive: 401), and, while a socket is connected, from its alarm at most once per hour
  (inactive: close 4001). The answer is cached in the DO for at most that hour and enforced on
  delivery and acks. A failed lookup keeps the last known state and retries after 5 minutes; an
  outage alone never closes a socket, and with no known state mint and connect answer 503
  `account_status_unavailable`. The metering ledger's `account_not_active` hold remains a second,
  independent gate.

