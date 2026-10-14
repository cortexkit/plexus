# Webhook relay wire vectors

Owned by cortexkit-cloud. The normative contract is
`docs/designs/webhook-relay-spec.md`, “Plexus connection: the relay wire contract”.
These files have no vendored manifest. A consumer should vendor them with a source
line identifying this repository, the source commit, and `test-vectors/webhook-relay/`.

WebSocket JSONL lines are `{ "name", "frame", "expect" }`. `frame` is the JSON object
in a text WebSocket message; serialize it without whitespace in the property order
shown to recover the pinned bytes. `expect` is `"emitted"` for server frames,
`"valid"` for accepted client frames, or the integer close code for refused frames.
Only `<account_id>`, `<stream_id>`, and `<received_at>` are placeholders. They stand
for the account ULID, the buffer's 128-bit base64url stream identity, and the receipt
instant (`YYYY-MM-DDTHH:MM:SS.sssZ`). They do not permit substitution of other fields.

| File | Direction and cases |
|---|---|
| `hello.jsonl` | Server: empty and buffered accounts; a last ack of 1 ahead of a client's committed 0 (reconcile); a recreated buffer with a changed stream id (reset and reconcile); the safe-integer sequence boundary. In the changed-stream case, the test first observes the original id and proves the recreated id differs. |
| `event.jsonl` | Server: full GitHub event; oversized, rate-limited, and overflow stubs; `cortexkit_installation_bound` with a repository list and with null (reconcile the whole installation); maximum safe seq. Synthetic binding bodies are the durable output expected of the separate binding producer. |
| `ack.jsonl` | Client: zero, cumulative, equal, lower, and maximum-safe acks; above highest sent, negative, fractional, above safe-integer maximum, string, null, and missing sequence refusals. Equal/lower cases start with the account already acked through 2. Other cases have seqs 1 and 2 sent, except zero (empty) and max-safe (only the maximum seq sent). |
| `unknown-type.jsonl` | Client: unknown/future type, server-only hello/event types, and a missing type all close 4400. Unknown types are not ignored. |
| `unknown-source.jsonl` | HTTP: real mint, revoke and ws requests for an unregistered source, each with status 404 and exact body text `{"error":"unknown_source"}`. Lines contain `name`, `request` (`method`, `path`), `status` and `body` (the exact response text). No credential refusal is interchangeable with this response. |
| `hello-source-mismatch.jsonl` | Client-side refusal: `dialled_source` is `github`, but the hello's `source` is `stripe`; `expect` is `"client_protocol_error"`. Generated from an observed empty hello with only its source replaced. This is not a frame the server emits, nor a client-to-server frame; clients must refuse it before processing events or acks. |
| `connect.jsonl` | HTTP: 201 connect reply, with a fixed test clock/account and deterministic random input for attempt id and signed install state. |
| `attempt-pending.jsonl`, `attempt-connected.jsonl`, `attempt-refused.jsonl`, `attempt-expired.jsonl` | HTTP: one reply for each attempt state, including all explicit nullable fields. Only random refused/expired public ids are substituted with `<attempt_id>` in body and request path. |
| `status.jsonl` | HTTP: bound installation and minted credential after a real client close. Only the observed random public credential id is substituted with `<credential_id>`. |
| `attempt-not-found.jsonl`, `github-not-linked.jsonl` | HTTP: 404 unknown attempt and 409 early unlinked refusal, including the shared message. |

Connections use `/v1/relay/<source>/ws`; credentials are minted/revoked at
`/v1/relay/<source>/credentials[/<id>]`. Only `github` is registered. Every valid hello
includes `source`, exactly matching the dialled source. Sequences, stream identity,
acknowledgments and the delivery window belong to an account-and-source stream.

The worker sends at most 64 unacked events and preserves the verified body bytes,
including whitespace/escapes. The vector bodies use canonical whitespace; the real
WebSocket tests separately prove verbatim noncanonical body delivery at exactly
1,048,576 bytes, and stubbing at one byte over. Acks are cumulative. Stub handling
does not depend on sniffing body keys: use the envelope's explicit `stub` value.

## Regeneration and verification

From `workers/webhook-relay`, after `bun run pretest` has built the account fixture:

```sh
node scripts/update-vectors.mjs
bun run vitest run test/vectors.test.ts test/consent.test.ts --max-workers=1 --no-isolate
```

Ordinary tests compare pinned bytes and client behavior without emitting or writing
vectors. The update script explicitly sets `UPDATE_RELAY_VECTORS=1` and selects the
`generate worker replies` Workers-pool test, observes real
account DO WebSockets and HTTP replies, and writes only the fourteen named files. HTTP cases in
`test/consent.test.ts` traverse real consent routes and DO storage with stubbed GitHub responses.
Server bytes are never
authored by a parallel serializer: the verifier compares the actual message text to
the pinned bytes after the three allowed substitutions. Client cases are each sent
to a real socket and checked for durable acknowledgment or their exact close code.
The source-mismatch fixture is the sole deliberately altered server frame; ordinary
tests compare it with the observed hello after changing only `source`. No client
implementation lives here, so the fixture declares the consumer's required refusal.
Do not regenerate merely to make a failing comparison pass: a wire change requires
coordination with the Plexus client owner first.

At sequence exhaustion, `next_seq` is saturated at 2^53 - 1 to keep the hello within
the declared integer range and the final event deliverable; further ingest fails rather than wrapping. No control
frame ping vector exists: the Workers-pool client exposes only data-message `send`,
so runtime control-frame pong/hibernation is not observed by these tests. No
application auto-response pair is registered.
