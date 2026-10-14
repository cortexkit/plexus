# Probe registration: authority, ownership, and lifetime

Companion to the probe execution sandbox (`crates/plexus-probe`). This note
covers the half that binds a probe to a connection and decides who may do what
to it.

## The question that blocks everything else

A supervised module (prefrontal) wants to register a probe against a connection
owned by the operator. Six things must be explicit, and an earlier draft left
them implicit:

1. who durably OWNS the subscription row
2. who REGISTERED it
3. which grant AUTHORIZES it
4. which principal the SCHEDULER loads it under
5. whose authority is checked AT POLL TIME
6. who may UNREGISTER it, including after that authority is revoked

## Ownership: the connection owner, always

THE SUBSCRIPTION ROW BELONGS TO THE CONNECTION OWNER. The registrant is recorded
as provenance, never as owner.

This is forced rather than chosen. Everything a poll touches is owner-scoped in
shipped code:

- `self.connection(principal, connection_id)` — a connection belongs to its owner
- `self.catalog_action(principal, connection_id, action)` — likewise
- credential resolution reads the binding on the owner's connection

The scheduler is NOT the constraint — `run_pass(&[String], now)` already iterates
a list of principals, so a row owned by the registrant would still be loaded.
It would then fail at the first lookup, because the registrant owns no
connection. So ownership follows the credential, not the caller.

Stated as a rule: A SUBSCRIPTION IS A THING THAT POLLS SOMEONE'S CONNECTION WITH
SOMEONE'S CREDENTIAL, AND IT BELONGS TO THAT SOMEONE. Who asked for it is
history.

Consequences, all of which fall out rather than needing separate decisions:
- The scheduler is unchanged. It keeps loading under the owner.
- Poll-time authority is the existing check against the owner's connection and
  the poll grant. No new authorization path.
- The registrant appears in the row as `registered_by` and in the audit journal,
  so attribution survives without granting the registrant anything.

## Registration authority: a facade op through the grant owner

Registration is a FACADE operation, not a management one. Two independent
reasons, both measured in shipped code:

1. `handle_management_request` refuses every principal that is not
   `Principal::Direct`, and that refusal is what stops supervised modules
   minting authority. Widening it to admit a registrant would erode the boundary
   that makes privileged ceremony safe.
2. Registration is authorized by a grant that ALREADY EXISTS, which is exactly
   the `subscribe` shape — authority by grant possession, not by caller identity.

Cross-principal resolution reuses the shipped `events_consume` pattern:
`events_consume_connections` already returns `(owner, connection, selectors)` for
grants naming the caller as grantee. Probe registration resolves the same way.

The authority kind is the existing `poll`. A probe creates a subscription that
polls; no new kind is needed, and inventing one would mean an operator has to
learn a second ceremony for the same capability.

REGISTRATION MINTS NOTHING. It binds a script to a connection and actions already
covered by that grant, and refuses anything outside it. A plan needing new
authority is refused so it can park as an operator ask.

## Unregistration: narrowing is always allowed

The owner may unregister any probe on their connection, always.

The registrant may unregister probes it registered, INCLUDING AFTER ITS GRANT IS
REVOKED. This follows the fleet rule that the discriminator for requiring
authority is the DIRECTION of the change: minting or widening needs authority,
narrowing or revoking must be as frictionless as possible. A registrant that
cannot withdraw its own probe after losing its grant leaves rows nobody can clean
up except by operator ceremony, which is friction applied to the safe action.

## Lifetime: three distinct states, three distinct remedies

An earlier draft collapsed these into "not running", which is a listing that
tells an operator nothing about what to do.

- GRANT REVOKED -> `suspended`, reason names lost authority. NOT retired:
  authority can be re-granted, and the probe should resume.
- CONNECTION REVOKED OR DISABLED -> `suspended`, reason names the connection.
  Distinct because the remedy is a connection ceremony, not a grant.
- REPEATED VENDOR FAILURE -> the existing circuit breaker suspends after the
  shipped threshold. Unchanged for probes.
- `once` PROBE FIRED -> `retired`, terminal.

Resume after re-grant is NOT automatic. A suspended subscription stays suspended
until something explicitly resumes it, matching the shipped risk-drift behaviour
where auto-resumption is deliberately blocked. Automatic resumption would mean a
probe silently restarts on a grant an operator minted for an unrelated purpose.

## Atomicity: retirement belongs inside the fenced transaction

A successful `once` fire must, IN ONE FENCED TRANSACTION: insert the event,
advance the cursor baseline, advance the observation ordinal, and move the
subscription to `retired`.

If retirement sits outside, a crash between insert and retire re-fires the probe
on the next pass — a one-shot that executes twice, which is the exact failure a
one-shot exists to prevent. This is not hypothetical: the poll path already
commits events and cursor advances together for the same reason.

## Event identity: ordinal, not value alone

Identity is `(subscription_id, observation_ordinal, canonical_value)`.

Value-only identity is wrong because the shipped uniqueness constraint —
`(connection_id, subscription_id, vendor_event_id, payload_hash)` since migration
16 — would suppress every recurrence of a value. A probe alternating A, B, A is
reporting two real transitions and the second A must deliver.

The ordinal is monotonic per subscription and advances in the same fenced
transaction as the insert, so a poll that fails before commit consumes no ordinal
and a retry skips none.

Re-observing an UNCHANGED value still does not deliver. That is decided by the
cursor strategy comparing against the stored baseline, before any row is written,
exactly as `scalar_diff` does today.

## Storage shape

`name`, `actions`, `script_source`, `return_schema`, `rearm` and `registered_by`
live in a COMPANION TABLE keyed on `subscription_id`, not on the shared
subscription row. They apply only to probe subscriptions, and widening the shared
row with six mostly-null columns makes every vendor watch carry them.

Two migrations are required and neither is optional:
- add `probe` to the `cursor_kind` CHECK — a table rebuild, as migrations 11 and
  12 were for `scalar_diff` and `sorted_head`
- widen the status CHECK to admit `retired`

The listing response must carry `name`, because "which probe fired" depends on
it and the alternative is a join the consumer should not have to make.

## Vocabulary, fixed here so a migration author does not invent it

- cursor kind: `probe`
- `strategy_for` dispatch string: `probe`
- terminal status: `retired`
- reason codes: `probe_timeout`, `probe_memory`, `probe_return_invalid`,
  `probe_action_refused`

A cursor kind that nothing dispatches is a subscription that cannot poll, so the
dispatch string is part of the contract rather than an implementation detail.

## What the sandbox already settled, recorded so it is not relitigated

The execution half is merged. Its constraints bind this half:

- exactly one host capability, and the reachable action set is fixed at
  construction with a RUNTIME refusal for anything outside it
- returned values validated on every run against a closed grammar, with string
  caps in every position
- a validation failure or budget kill produces a non-completing outcome, no event
  row, no cursor advance, AND NO RETIREMENT — a malformed return must never
  silently kill the watch it was meant to serve
- THE SANDBOX TIMEOUT DOES NOT BOUND THE ACTION CALLBACK. Epoch interruption
  preempts guest execution only, so a hanging vendor request stalls the pass
  while the budget reports nothing wrong. Whatever wires the real dispatch must
  enforce its own deadline; this is the single most important thing this note
  hands to the next implementer.
