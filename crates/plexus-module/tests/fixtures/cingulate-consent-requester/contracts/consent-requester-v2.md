# Consent requester contract, v2

Version 2 preserves every v1 operation and body for existing kinds. It adds AFT
permission asks and the optional generic-consent correlation field described below. Pin the [served corpus](../../test-vectors/tool-permission-v1/README.md)
and its `SHA256SUMS`; the phone projection is specified in
[consent-phone-v2.md](consent-phone-v2.md). These asks deliberately have no expiry,
retention tombstone, execution report, acknowledgment or settlement-feed entry:
AFT uses durable request/get/await/withdraw and core receives notices.

## Generic consent and requester correlation

To preserve v1 behavior, the generic-consent rule admits `direct` and
`reserved:cerebellum`, `reserved:plexus` and `reserved:entorhinal` for
`kind: "consent"` only. These requesters use the generic consent body; none can
request `flow_install`, `flow_decision`, `package`, `tool_permission` or
`macos_permission`. A disallowed kind refuses `elicitation_requester_refused`.
Requester and subject identity come only from the daemon's route stamp, never
from body fields. A nonblank carried agent id is required for reserved requesters
except for the worker admission rule below.

For `kind: "consent"` from any requester already admitted for that kind, a stamp
without an agent id may be a `worker` owned by `reserved:prefrontal-core`.
Cingulate resolves its same-owner stamped `parent` through the daemon's
`scope.describe`, using the permission-ask liveness rules in
[Admission and stamped identity](#admission-and-stamped-identity). The parent (a
worker's parent is always its head) must be live at the stamped epoch, with a
nonblank agent id. A missing parent,
a definitively non-live parent or a parent without an agent id refuses
`access_no_head`; unknown or failed liveness refuses `access_unavailable`.
All other missing-agent stamps retain their existing admission behavior.

The subject is the parent's agent, with its name resolved exactly as on the
head's own card. The stamped worker scope, not the head scope, is recorded as
`asker`: a detached card's later `consent_answered` notice targets the worker's
session. Body fields cannot supply either identity. Requester reads and the core
outcome feed include `subject.via_worker: true` for these cards; phone reads use
`subject.viaWorker: true`. The flag is omitted, not false, on every other card.
Generic worker cards retain the ordinary generic-consent state machine and
fail-closed expiry. They ask the user directly; they do not first require an
answer from the head, unlike worker permission asks.

`reserved:cerebellum` and `reserved:plexus` may call `consent.request`,
`consent.await`, `consent.get`, `consent.answers`, `consent.ack`,
`consent.withdraw`, `consent.report_execution` and `consent.detach`. Get, await,
report_execution, withdraw and detach require the raising owner. `consent.answers`
returns only that owner's answers, and `consent.ack` acknowledges only that
owner's answers. Neither requester can call phone-only `consent.answer` or
`consent.list_pending`, nor read the core-only `consent.outcomes` feed.
Generic `consent` params add one optional field:

| Field | Rule |
|---|---|
| `requester_ref` | Opaque string of 1–128 printable ASCII characters (bytes `0x20`–`0x7e`), returned unchanged. If present, null, non-string, empty, overlong, control and non-ASCII values refuse `elicitation_invalid_request` with `requester_ref` in the message. Other kinds cannot carry it. |

The reference correlates an originating call with a later answer; it supplies
neither identity nor display text. It is stored durably and returned as
`requester_ref` in requester `consent.get`, `consent.await`, `consent.answers`
and the core outcome feed, as well as requester mutation readbacks. When absent,
the field is omitted. Phone `consent.list_pending`, `consent.get` and answer
readbacks never include it, in either snake_case or camelCase.

It has no uniqueness or deduplication meaning: two cards may share the same
reference. Only `dedup_key` selects a pending card to refresh. Changing or removing
`requester_ref` on an otherwise matching dedup refresh retains the card id and
updates the stored reference; it does not withdraw and replace the card.

The [generic-consent v2 served vectors](../../test-vectors/consent-requester-v2/README.md)
cover requests with and without a reference, worker admission and liveness
refusals, requester and phone records, answers/outcomes, and refusal of a
non-consent request. Their `SHA256SUMS` is
generated from actual handler replies. Existing v1 contracts and corpora remain
byte-for-byte unchanged.

## Admission and stamped identity

Only `reserved:aft` may request `tool_permission` or `macos_permission`.
Other requesters refuse `elicitation_requester_refused`, naming the requester.
AFT cannot request any existing kind. An absent scope or a scope owned by anything
other than `reserved:prefrontal-core` refuses `access_not_alfonso`.
The daemon-stamped scope ref, epoch, kind, agent and route harness are recorded;
no body field supplies identity. Workers do not need an agent id.

A `worker` with a stamped `parent` starts in `pending:head`. A missing or
non-live parent refuses `access_no_head`. A `head` or `ephemeral` starts in
`pending:user`. Worker parent liveness is read from the daemon's `scope.describe`,
not route disappearance or a core lookup. The daemon's `not_live` while its
configured owner has not re-synced is unknown, not proof of death. Unknown or
failed liveness at creation refuses `access_unavailable`; for an already-open
ask it leaves the ask pending. The existing maintenance sweep checks pending
head legs and settles definitive head loss as `access_head_gone`. It never
compares an ask's age or a reply deadline. No answer leg expires.

## Request bodies

For permission asks, `params` is a closed object with `kind` and the following fields, not a nested
body. Unknown keys (including `parent`, `scope`, requester identity and expiry)
refuse `elicitation_invalid_request`. The entire framed request retains v1's
1,310,720-byte limit; no field is truncated.

| `tool_permission` field | Rule |
|---|---|
| `call_key` | Required nonblank string; persistent idempotency key. |
| `tool` | Required nonblank string, at most 64 Unicode characters. |
| `operation` | Required `read`, `write` or `exec`. |
| `paths` | Required array of at most 16 absolute `/`-rooted paths; no NUL. Empty is allowed for pathless commands. |
| `command` | Required for `exec`, forbidden otherwise; nonblank, at most 600 characters. |
| `reason` | Required nonblank single line, at most 160 characters; no CR, LF or NUL. |
| `args_hash`, `pattern` | Required nonblank strings, opaque to Cingulate. AFT owns hash and pattern semantics. |
| `schema_pin` | Optional nonblank string; opaque. |
| `head_policy` | Required on workers only: `allow` or `not_held`. AFT attests whether the head holds a covering permission. |

The fixed options are `allow_once`, `allow_scope` (effect `grant`) and `deny`
(effect `decline`, default). Heads also have `escalate`. A head with `not_held`
is offered only `deny` and `escalate`. Unavailable answers are omitted.

`macos_permission` has required string `folder` (absolute, no NUL), `program`
(nonblank), and `steps` (nonblank instructions for System Settings). It refuses
`access_macos_only` outside macOS. It is informational: empty options, no default,
no core park notice, no awaiting call (`consent.await` refuses `access_informational`).
One open card per `(folder, program)` across AFT sessions; a repeat returns the
open id. AFT withdraws it when the folder becomes readable. After withdrawal a
new request can create a new card.

Success remains exactly `{elicitation_id: string}`, with an `acc_` id. For tool
asks, `(raising principal, call_key)` returns the original ask, even if settled
or request content changed, across AFT and Cingulate restarts. The original
fields and identity never change. A replay must still be an admitted scoped AFT
request; a settled replay does not require its original head to remain live.

## Records, await and withdrawal

Requester get uses `elicitation_id` (permission asks also accept `elicitationId`).
The record is flattened: request fields, `elicitation_id`, `created_at_ms`,
`state`, `requester_label`, stamped `asker: {scope_ref, scope_epoch, agent_id?}`,
worker-only `head` of the same shape, fixed `options`, and `default: "deny"`
on tool asks. It omits all expiry fields. Pending records may have
`block_until_ms` for active waits. Escalated records carry `escalation_note`.
Settled records add `outcome`, `answered_by: "head" | "user"`, `answered_at_ms`
and optional `note`. Refusals have no `answered_by` and have their `access_*`
`outcome` and `code`. Explicit `deny` has outcome `deny`, code `access_declined`.

States are `pending:head`, `pending:user`, `settled`,
`refused:access_head_gone`, or `refused:access_withdrawn`. An answer never changes
the recorded asker scope. A user's `allow_scope` on an escalated ask applies to
the worker, not its head. Cingulate stores no grants and performs no operation.

Get/await require the raising **principal**, not a mutable transport session.
Another principal refuses `elicitation_not_owner`; an unknown id refuses
`elicitation_not_found`. Records and audit survive indefinitely for recovery.
`consent.await` accepts the id plus v1 `timeout_ms` (0–120,000 after capping),
returns the current requester record when settled or at the caller's wait bound,
is read-only and can be repeated. A returned pending state grants nothing.
Cancelling/dropping a wait removes its transient registration and changes no row.

`consent.withdraw` accepts the id only from the raising principal. It moves any
pending state to `refused:access_withdrawn`; a terminal record is returned
unchanged. Withdrawal, answer and head loss are serialized store transactions.

## Core relays and first-answer-wins

Core answers from `reserved:prefrontal-core` using
`{elicitation_id, answer, note?, answered_by: {agent_id, scope_ref, scope_epoch}}`.
`answered_by` is closed and must exactly match the worker's stamped parent ref
and epoch and its daemon-described agent. Only `pending:head` tool asks accept a
relay. `allow_once` and `allow_scope` require `head_policy: "allow"`; `deny` and
`escalate` do not. A refused relay records an attempt but leaves the ask pending.
An optional note is one line, at most 160 characters. `escalate` changes the leg
to `pending:user`, recording the note and newly offered user surface.

The user answers only through the v1 Callosum + `fed-phone:` phone bind rule,
only in `pending:user`. No body field can enable that rule. The immediate store
transaction reads the leg, validates authority/options, records the attempt and
compares/sets the new state. The first settlement wins. A later answer, including
the same answer, returns `{ok:false, code:"conflict", elicitation:Record}` with
the committed outcome. Accepted answers return `{ok:true, alreadyAnswered:false,
elicitation:Record}`. Wrong legs use `access_wrong_leg`, wrong parents use
`access_wrong_head`, and an unheld head grant uses `access_head_not_held` in that
same `ok:false` form. Invalid options use `elicitation_invalid_choice`.

## Notices and audit

A transaction enqueues each notice uniquely on `(elicitation_id, purpose)`.
Cingulate calls core's `session.notice` as `reserved:cingulate`, with the exact
[design wire](../designs/tool-permission-asks.md#the-sessionnotice-wire):
`elicitation_id`, `purpose`, `asker: {scope_ref,scope_epoch}`, worker-only `head`
of the same shape, and typed `fields`. Purposes are `head_ask`, `user_ask`,
`escalated`, `settled`, `withdrawn`. There is no phone push in the head leg.
Settlements withdraw previously offered user surfaces and wake awaiters after
commit. Superseded undelivered opening notices cannot later re-park a settled ask.

Notice delivery is off the state-machine request path. Missing handlers, core
unavailability and transport errors retry from the durable outbox, with capped
exponential backoff (250 ms to 60 s), using the existing maintenance cadence.
This scheduling is not an ask deadline or timed settlement. `unknown_session`
or `session_not_live` on `head_ask` settles `access_head_gone`; on `settled` it
records `unclaimed`. On other purposes it records refusal only. None retry.
`unauthorized_caller` and `invalid_params` are logged defects and never retry.

The durable audit retains original request, requester principal, stamped asker
and head identity, scope kind and harness, creation time, every offered surface
and its answers/time, every answer attempt including losers and malformed
attempts (surface, principal, time, answer, note, relayed identity, result),
escalation note, final state and settlement time. Outbox rows retain delivery
status, attempt count and last refusal. A late answer never overwrites an earlier
outcome or its note. Standing grants remain entirely AFT's responsibility.

## Late answers on generic consent cards

A requester that raises a generic `consent` card while holding an agent's tool
call usually waits on `consent.await` and returns the answer in that call. When
it stops holding the call and returns "still waiting" to the agent instead, any
later answer has to reach the agent through core. An answer that arrives while
the requester still holds the call must not reach the agent a second time.
The requester marks the moment it stops holding the call with `consent.detach`,
and only settlements after that mark produce a notice.

### `consent.detach {id}`

Admitted only from the principal that raised the card, and only for kind
`consent`. Other kinds refuse `elicitation_requester_refused`; an unknown id or a
card raised by another principal answers with the existing not-found and owner
refusals.

- **Pending card:** detach commits, and the reply is the card record with
  `detached: true`.
- **Already settled card:** detach changes nothing and returns the settled
  record. The requester then returns that answer in the held call, and no notice
  is ever sent for the card.
- **Repeated detach:** always returns the card's current record: still pending
  with `detached: true`, or settled if it settled in between. It never undoes
  the first detach.

Detach and settlement are ordered in one store transaction, so exactly one of
"settled while held" and "settled after detach" applies to every card. A
requester calls detach exactly when it stops holding the call, and must handle
the settled-record reply.

Only the `consent.detach` reply carries `detached`. Every other requester read,
the core outcomes feed and phone reads never do. A dedup refresh that keeps the
card in place clears the detach mark, because the requester is holding a new
call.

### The `consent_answered` notice

When a detached card settles, Cingulate sends core `session.notice` with
purpose `consent_answered`. It is addressed to the agent session whose scope
the subconscious daemon stamped on the route the requester used for
`consent.request`. The body follows the `session.notice` wire described in
"Notices and audit" above (`elicitation_id`, `purpose`, `asker`, `fields`).
The `head` member, which only worker asks carry, is absent:

```json
{
  "elicitation_id": "el_0000000000000042",
  "purpose": "consent_answered",
  "asker": {"scope_ref": "sc_head_alf", "scope_epoch": 3},
  "fields": {
    "requester": "cerebellum",
    "outcome": "answered",
    "choice_id": "allow_30m",
    "choice_label": "Allow for 30 minutes",
    "settled_at_ms": 1792000000000
  }
}
```

| `fields` key | Type and limit |
|---|---|
| `requester` | Module id of the raising principal, without the `reserved:` prefix: 1–64 ASCII characters. |
| `outcome` | `answered` \| `expired` \| `withdrawn`. |
| `choice_id` | The chosen option's `id`, 1–64 characters. Present only when `outcome` is `answered`. |
| `choice_label` | The chosen option's `label`, 1–200 characters, as the operator saw it. Present only when `outcome` is `answered`. Core escapes it before showing it to the agent. |
| `settled_at_ms` | Unsigned integer, Unix milliseconds. |

The notice never carries `requester_ref`, the prompt, facts or the request
body. A card that was never detached never produces this notice. Core
deduplicates on `(elicitation_id, purpose)` and wakes the agent with the
notice; that handling is core's change, made alongside this one. Delivery,
retry and refusal handling are those of the other notices above:
`unknown_session` or `session_not_live` records the settlement as `unclaimed`
and never blocks it.

The target bytes are pinned in
[`test-vectors/consent-late-answer-v1/`](../../test-vectors/consent-late-answer-v1/README.md).
Cingulate's implementation must produce them byte for byte, and core decodes
them.
