# Consent requester contract, v2

Version 2 preserves every v1 operation and body for existing kinds. It adds AFT
permission asks and the optional generic-consent correlation field described below. Pin the [served corpus](../../test-vectors/tool-permission-v1/README.md)
and its `SHA256SUMS`; the phone projection is specified in
[consent-phone-v2.md](consent-phone-v2.md). These asks deliberately have no expiry,
retention tombstone, execution report, acknowledgment or settlement-feed entry:
AFT uses durable request/get/await/withdraw and core receives notices.

Package and flow-install `consent.request`/`consent.get` also support the optional
[`explanation` and `changes` author texts](consent-card-explanations-v1.md) when
`consent-card-explanations/v1` is declared. The same objects appear unchanged in
app pending lists; they never appear in notices.

## Federated consent carriers

Since ck-cingulate 0.16.0, Cingulate declares `scope-federated/v1`. An admitted
provider carrying a daemon-stamped `federated` scope may raise `kind: "consent"`
without a local agent id. The subject comes only from the stamp's
`attributes.federated`: `peer_name`, `peer_class`, `peer_fingerprint`, `pairing_id`
and `remote_claim`. No roster fetch, local agent resolution, body-supplied name
or harness string supplies that identity. A present `parent_state` other than
`linked` refuses `elicitation_federated_unlinked`. Other request kinds remain
local-only. Federated routes never inherit local agent, local operator or module
authority. Callosum operator phones and simulator inventory readers use stamped
peer class; unstamped Callosum routes keep the existing harness rules and never
select federated grants.

Only for a card raised on a federated-stamped route, ownership is the admitted
requester principal plus (`peer_fingerprint`, `pairing_id`, `peer_class`,
canonical claim identity). Claim identity includes its kind and is:

- no claim: an explicit claimless identity;
- agent or run: `agent_id` (agent and run remain distinct kinds);
- worker: `owner_module_id` and `worker_ref`;
- flow: all four of `flow_id`, `flow_version`, `flow_install_id`, `flow_code_hash`.

The scope ref/epoch, `peer_name`, worker `on_behalf_of`, `agent_name` and
`flow_name` do not enter that identity. A different provider, pairing, class or
claim cannot collect the card.
Pending `el_` records already persist independently of a route; route closure
cancels its wait, not its card. On a new route with the same paired subject the
provider can get, await, collect answers and acknowledge them through the normal
operations. A rename or re-created claim scope does not orphan a card. Local v1
and v2 ownership remains the principal plus scope owner/ref/epoch, unchanged.
Remote scopes never become targets for local-agent session-ended checks or
local-agent notices.

For federated cards only, `prompt` is an **action phrase**, not a whole sentence.
For example, the provider sends `"prompt":"read your mail."`; for roster name
`Juniper` and stamped agent id `Sage`, Cingulate displays
`“Juniper” says agent Sage wants to read your mail.`. Agent and flow ids are
displayed verbatim, not resolved through this computer's local roster. The
stored `subject.federated` contains the stamped facts, with nested protocol keys
unchanged on both phone and requester projections. Its `subject.label` uses the
[federated permissions label](permissions-v1.md#federated-grants), or just the
peer name for a run; no local `subject.agent_id` or `head_agent_id` is emitted.

| Claim | Displayed prompt for action `read your mail.` |
|---|---|
| agent `Sage` | `“Juniper” says agent Sage wants to read your mail.` |
| worker with `on_behalf_of: "Sage"` | `“Juniper” says a worker for agent Sage wants to read your mail.` |
| worker without attribution | `“Juniper” says one of its workers wants to read your mail.` |
| flow `Morning-digest`, version 3 | `“Juniper” says flow “Morning-digest” (version 3) wants to read your mail.` |
| run for `Sage` | `“Juniper” says a run for agent Sage wants to read your mail. (this time only)` |
| no claim | `A program on “Juniper” (no agent named) wants to read your mail.` |

Every card adds the fact `“Juniper” is paired with this computer.`. “Cloud” and
“hosted” are never added unless present in the person's roster name.

Since 0.16.1, validated optional names from the stamped claim are shown in quotes
with the id beside them in parentheses. Without a name the sentences above are
unchanged. Names are stored as display data in `subject.federated.remote_claim`,
never used as identity. See the exact named sentences and validation rule in
[consent-card-text-v1](consent-card-text-v1.md#federated-caller-names).

A run card is **one immutable answer per elicitation, for the call that raised
it**, not a standing grant. The provider binds the elicitation id (and its
optional `requester_ref` / private `binding`) to that call and MUST NOT reuse its
answer for another call. Answer recovery remains idempotent until normal ack or
retention: a lost reply may be read again. `requester_ref` is still correlation,
not a dedup key or credential. Cingulate sets `single_use: true`, removes
`duration`, requires exactly one `effect: "grant"` option, and labels that option
`Allow this time`, with no provider-authored detail. More than one or no grant
choice is refused. The provider's own `effect: "decline"` options and the card's
default are passed through as sent, so a run card's default is still a decline;
silence, expiry and errors never grant. Providers MUST honor single use and
create no standing grant for runs. Cingulate itself creates no standing grants
for any card. Selectors and base-scope liveness remain the provider's obligations
under [permissions/v1](permissions-v1.md#federated-grants).

## Generic consent and requester correlation

To preserve v1 behavior, the generic-consent rule admits `direct` and
`reserved:cerebellum`, `reserved:plexus`, `reserved:broca` and
`reserved:entorhinal` for
`kind: "consent"` only. These requesters use the generic consent body; none can
request `flow_install`, `flow_decision`, `package`, `tool_permission` or
`macos_permission`. Separately, Cerebellum may file `secret_use` and Plexus may
file `manifest_binding` under the dedicated vault-card rules below. A disallowed
kind refuses `elicitation_requester_refused`.
Requester and subject identity come only from the daemon's route stamp, never
from body fields. A nonblank carried agent id is required for reserved requesters
except for the worker admission rule below and `manifest_binding` as described
in its dedicated section.

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
fail-closed expiry when a lifetime is supplied. They ask the user directly; they do not first require an
answer from the head, unlike worker permission asks.

All existing v1 kinds, including generic worker consent, may omit
`expires_in_ms` only when Cingulate advertises `consent-no-expiry/v1` in its
`catalog.list` capabilities. Omission (or null) means no deadline: the card stays
pending until answered or withdrawn, with no expiry fields on requester or
phone reads. A present integer retains v1's 1–86,400,000 ms bounds and fail-closed
expiry. Older versions refuse an omitted lifetime, so the capability check is
required. Await timeouts bound only the call; on a no-deadline card neither await
nor `block_until_ms` gains an expiry cap. Detached generic cards can be answered
arbitrarily later and still produce the usual late-answer notice. Permission
asks continue to forbid expiry fields entirely. The optional execution-report
`reason` for existing kinds follows [v1](consent-requester-v1.md#consentreport_execution).
Generic-consent requesters may report after ack while retained. Cingulate's
`approved_not_executed` / `session_ended` backstop fills in only when no report
exists and the stamped asker scope has definitely ended; requester reports always
replace earlier reports, including the backstop, as specified in v1.

`reserved:cerebellum`, `reserved:plexus`, `reserved:broca` and
`reserved:entorhinal` may call `consent.request`,
`consent.await`, `consent.get`, `consent.answers`, `consent.ack`,
`consent.withdraw`, `consent.report_execution` and `consent.detach`. Get, await,
report_execution, withdraw and detach require the raising owner. `consent.answers`
returns only that owner's answers, and `consent.ack` acknowledges only that
owner's answers. None of these requesters can call phone-only `consent.answer` or
`consent.list_pending`, nor read the core-only `consent.outcomes` feed.
Generic `consent` params add two optional top-level fields:

| Field | Rule |
|---|---|
| `requester_ref` | Opaque string of 1–128 printable ASCII characters (bytes `0x20`–`0x7e`), returned unchanged. If present, null, non-string, empty, overlong, control and non-ASCII values refuse `elicitation_invalid_request` with `requester_ref` in the message. Other kinds cannot carry it. |
| `single_use` | Optional boolean accepted only for `kind: "consent"`; null and every non-boolean value refuse `elicitation_invalid_request` with `single_use` in the message. Absence means false. Providers must check `catalog.list` for `consent-single-use/v1` before sending it. |

The reference correlates an originating call with a later answer; it supplies
neither identity nor display text. It is stored durably and returned as
`requester_ref` in requester `consent.get`, `consent.await`, `consent.answers`
and the core `consent.outcomes` feed, as well as requester mutation readbacks.
There it is an opaque correlation key exactly as stored on the card. When absent,
the field is omitted. Phone `consent.list_pending`, `consent.get` and answer
readbacks never include it, in either snake_case or camelCase. Acknowledgment
still controls requester reads only; phone get returns settled generic cards until
their payloads are pruned 24 hours after settlement, as specified by the phone
contracts.

It has no uniqueness or deduplication meaning: two cards may share the same
reference. Only `dedup_key` selects a pending card to refresh. Changing or removing
`requester_ref` on an otherwise matching dedup refresh retains the card id and
updates the stored reference; it does not withdraw and replace the card.

`single_use` is stored with the card and returned on requester reads when supplied.
The core outcome feed includes it only when true. It is never added to a phone
projection, so existing phone card bytes are unchanged.

An outcome record includes `late: true` only when `consent.detach` committed before
the card settled. Settlement captures the stored detach state in the same store
transaction that records the outcome; a later clock reading does not affect it. A
dedup refresh clears detachment, so an answer to the re-raised card is not late.
Core may interpret an absent `late` as “settled while the raiser waited” only when
`catalog.list` advertises `consent-outcomes-late/v1`. Without that capability,
absence means the status was not reported.

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
head legs and settles definitive head loss as `access_head_gone`. It also
checks the stamped asking session itself, including worker scopes, for every
pending answer leg. Definitive asker loss settles as `access_asker_gone`,
retracts the user card and queues the usual `settled` notice. Asker probes are
paged and time-bounded; unknown liveness, errors and timeouts keep asks pending
with bounded exponential backoff. Neither sweep compares an ask's age or a
reply deadline. No answer leg expires.

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
`refused:access_head_gone`, `refused:access_asker_gone`, or
`refused:access_withdrawn`. An answer never changes
the recorded asker scope. A user's `allow_scope` on an escalated ask applies to
the worker, not its head. Cingulate stores no grants and performs no operation.

Get/await require the raising **principal**, not a mutable transport session.
Another principal refuses `elicitation_not_owner`; an unknown id refuses
`elicitation_not_found`. Records and audit survive indefinitely for recovery.
`consent.await` accepts the id plus v1 `timeout_ms` (0–120,000 after capping),
returns the current requester record when settled or at the caller's wait bound,
is read-only and can be repeated. A returned pending state grants nothing.
Cancelling/dropping a wait removes its transient registration and changes no row.

`consent.withdraw` accepts the id from the raising principal, or, for `tool_permission`
asks only, from `reserved:prefrontal-core` when the recorded asker scope is owned by
`reserved:prefrontal-core`. Cingulate checks only that ownership; it cannot see worker
runs. Prefrontal Core withdraws only once a worker run is terminal (delivered, failed
or cancelled), never while the worker is parked waiting on the ask. It moves any
pending state to `refused:access_withdrawn`; a terminal record is returned
unchanged. Withdrawal, answer and head loss are serialized store transactions.

## Core relays and first-answer-wins

Core answers from `reserved:prefrontal-core` using
`{elicitation_id, answer, note?, answered_by: {agent_id, scope_ref, scope_epoch}}`.
`answered_by` is closed and must exactly match the worker's stamped parent ref
and epoch and its daemon-described agent. Normally only `pending:head` tool asks
accept a relay. `allow_once` and `allow_scope` require `head_policy: "allow"`; `deny` and
`escalate` do not. A refused relay records an attempt but leaves the ask pending.
An optional note is one line, at most 160 characters. `escalate` changes the leg
to `pending:user`, recording the note and newly offered user surface.

While an escalated `tool_permission` ask remains `pending:user`, the head recorded
in its accepted escalation attempt may relay `deny`, with the existing optional
one-line, 160-character note. All three `answered_by` identity fields must match
that escalator exactly; a different head gets `access_wrong_head`, and a record
without a recorded escalator gets `access_wrong_leg`. Head grants and repeated
escalation still get `access_wrong_leg`. This deny settles exactly like a user
deny (`settled`, outcome `deny`, code `access_declined`, usual `settled` notice),
but keeps `answered_by: "head"` and the ordered head escalation/denial attempts in
the audit. It wakes awaiters and removes the phone card. The first user answer or
head deny to settle wins in the same store transaction; the loser gets `conflict`.
Generic consent and macOS cards do not gain a head-answer path.

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

### Person-facing elicitation cards (`el_`)

Phone-answerable cards with a daemon-stamped asker scope queue an `escalated`
notice in their filing transaction, regardless of the filing module. Cards
requiring `at_console` do not push: a phone has no attested console-machine identity.
The existing subject string supplies the agent name (or resolved fallback), plus
`in project <name>` when the daemon stamp identifies a project. It is truncated
to at most 200 Unicode characters, including a trailing `…` when shortened.

The exact stored JSON has this stable key order (optional keys are omitted):

```json
{"elicitation_id":"el_1","purpose":"escalated","asker":{"scope_epoch":3,"scope_ref":"worker"},"head":{"scope_epoch":7,"scope_ref":"head"},"fields":{"card_kind":"secret_use","subject":"ALF in project Example","expires_at_ms":1700000600000}}
{"elicitation_id":"el_1","purpose":"settled","asker":{"scope_epoch":3,"scope_ref":"worker"},"head":{"scope_epoch":7,"scope_ref":"head"},"fields":{"outcome":"answered"}}
{"elicitation_id":"el_1","purpose":"withdrawn","asker":{"scope_epoch":3,"scope_ref":"worker"},"head":{"scope_epoch":7,"scope_ref":"head"}}
```

A person card filed without a daemon-stamped session scope (an install card core
files itself, or a local app's card) queues the same notices with `asker` and
`head` omitted, so the person is still told; core pushes it with no agent label:

```json
{"elicitation_id":"el_1","purpose":"escalated","fields":{"card_kind":"consent","subject":"an unverified local process","expires_at_ms":1700000600000}}
{"elicitation_id":"el_1","purpose":"settled","fields":{"outcome":"answered"}}
```

Core must accept a missing `asker` on these `el_` notices before a Cingulate
that sends them is deployed.

- `asker`, when present, and optional `head` come only from daemon-attested
  owner scopes. A
  worker's `head` requires a same-owner parent with daemon-confirmed `Linked`
  state; otherwise attribution stays with its asker. Older cards without a saved
  parent omit `head`; no body-supplied session is used.
- `escalated.fields` contains only `card_kind`, `subject`, and optional
  `expires_at_ms`, in that order. `card_kind` is `consent` for consent, package
  and flow-decision cards, `secret_use` for secret use, `manifest_binding` for
  repository bindings, and `flow_install` for
  installs (including those carrying secrets). Cards with no expiry omit
  `expires_at_ms`.
- `settled.fields` contains only `outcome`: `answered` or `expired`. Withdrawal
  has no `fields` key. No notice contains requester titles, prompts, scope text,
  statements, vault bytes or choice details.
- Settlement supersedes any pending `escalated` row in the same transaction,
  including expiry sweeps. Startup backfills still-pending cards with
  `INSERT OR IGNORE` on `(elicitation_id, purpose)`; a delivered or superseded
  notice is never replaced. This uses the existing shared `access_notices`
  outbox and delivery loop, without a schema migration.
  An already-backfilled startup reads first and opens no backfill write transaction.

### Permission asks (`acc_`)

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

This detached-call definition does not authorize answers after a deadline.
`secret_use` is refused after its earliest statement expiry, for both allow and
decline; it does not support `consent.detach`.

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

## Manifest-binding requester (0.18.0)

**Readers first.** The phone and desktop must render `manifest_binding` before
Plexus files one. Phones advertise the separate `manifest-binding-approval`
feature; `secret-use-approval` alone does not opt into this kind.

Only the full daemon-attested principal `reserved:plexus` may file this kind.
Other principals (including bare `plexus`, enrolled identities and Direct) get
the ordinary `elicitation_requester_refused`, before statement decoding.
The filing is a closed object, with exactly one statement:

```json
{"kind":"manifest_binding","manifest_binding":{"statement_b64url":"<vault propose reply, unchanged>"}}
```

No authored title, prompt, facts, display name, requested expiry, or other member
is accepted. In particular, both `expires_at_ms` and `expires_in_ms` are refused
as unknown filing fields. Cingulate derives the card expiry from the statement's
`expires_at_ms`; a filing at or after that time refuses `elicitation_expired`.
There is no expiry override or refresh.

The unpadded base64url statement must decode to RFC 8785 JCS canonical UTF-8 bytes
with exactly `{v, proposal_id, agent_id, app_slug, repo, installation_permissions,
manifest_version, manifest_sha256, prior_version, prior_sha256, expires_at_ms}`.
`v` is `ck-manifest-binding-statement/v1`, `proposal_id` is a ULID, permissions
are a map with values only `read`, `write` or `admin`, the new version is exactly
`prior_version + 1`, and both SHA-256 fields are 64 lowercase hex digits. Integers
are nonnegative and at most 2^53 − 1. Defects refuse
`elicitation_invalid_request` with a reason naming `manifest_binding.<field>`;
invalid encoding or noncanonical bytes name `manifest_binding.statement_b64url`.
Cingulate stores those exact statement bytes (as unchanged base64url) and their
lowercase-hex SHA-256, plus read-only `agent_id`, `app_slug`, `repo` and the full
`installation_permissions` map. It stores no target-agent display name; apps
resolve that name from core's agent record. Generic card text is fixed locally.
The vault's proposal grammar also applies: `agent_id` is 1–128 ASCII letters,
digits, `_` or `-`; `app_slug` is 1–100 lowercase ASCII letters, digits or `-`;
`repo` has exactly two slash-separated parts of 1–100 ASCII letters, digits,
`.`, `_` or `-`, with neither part `.` or `..`.

Plexus may file without a carried agent: the subject is Plexus. When either the
carried agent or scope agent is daemon-stamped, every such agent must equal the
statement's `agent_id`, or the filing refuses `elicitation_invalid_request` with
an `agent_id` reason. Subject identity is never taken from the statement.

Identical statement bytes dedup by `statement_sha256`, for the same full owner
(principal plus session), just as `secret_use` re-requests do. While unexpired,
a repeat returns the existing card id without refreshing it, including after
an answer. A new statement is a new card. A repeat from another session gets
`elicitation_request_conflict`: a card for this statement is already filed under
another session. Do not refile it. Learn an approval from the vault's
`manifest.watch`; otherwise the pending card lapses at the statement's expiry.
Outcome reads do not acquire cross-session authority.

Plexus reads its card through the usual requester `consent.get` with
`{elicitation_id}` or `consent.await` with `{elicitation_id, timeout_ms}`. The
snake_case record has `manifest_binding` facts and, after an accepted answer,
`manifest_binding_answer`:

- allow: `{decision:"allow", statement_sha256, envelope_sha256}`, with the
  route-derived `answered_device` alongside it;
- decline: `{decision:"decline", statement_sha256}`, with `answered_device`
  and no envelope hash;
- expired: `state:"expired"`, no selected choice and no
  `manifest_binding_answer` because no phone answered. Expiry is a denial, never
  an allow.

Only the attested Callosum phone route may answer; the development desktop
operator switch is not authority for this kind. See the
[phone binding contract](consent-phone-v2.md#manifest-binding-approvals-0180).
Cingulate never calls the vault: the phone signs and submits an allow envelope
directly to `manifest.approve`; a decline is recorded only in Cingulate.
Escalate, settle and withdraw push notices contain only Cingulate-vouched
metadata, never the statement, repository or permissions. Their field shapes
are the same as secret-use notices.

[Handler-generated samples](../../test-vectors/manifest-binding-v1/README.md)
include first and repeated filing, phone get and answers, and both requester
get and await records for allow, decline and expired outcomes. The copied vault
statement and envelope are pinned to claustrum tag `manifest-binding-vectors-v1`
at `c2a9ce2eaf99da646160eeb0c73d6b11d9341cbf`.

## Vault secret-use requester (0.12.0)

Cingulate advertises `secret-use-approval/v1`. Only `reserved:aft` and
`reserved:cerebellum` routes with a daemon-attested scope stamp may file
`kind: "secret_use"`; all other requesters or unstamped routes refuse
`elicitation_requester_refused`. No requester or subject identity is supplied in
the body. The complete closed filing body is:

```json
{"kind":"secret_use","secret_use":{"items":[{"request_id":"01HF7YAT000000000000000001","statement_b64url":"<vault statement>"}]}}
```

There are 1–16 items. No title, prompt, labels, options, expiry override or other
filer fields are accepted. Cingulate supplies fixed generic card chrome and
allow/decline options, default `decline`, `on_expiry: "deny"`. The phone renders
access details from statements, with the subject resolved from the route stamp.
Notification pointers contain no secret name, host or agent id.

Each statement is strict unpadded base64url (nonzero trailing bits refused),
decoding to RFC 8785 canonical JSON, byte-identical to its re-encoding. Its
closed key set is `{v, request_id, member_id, scope, agent_id, coverage, secret,
use, durations, request_expires_at_ms}` with `v: "ck-secret-use-statement/v1"`.
Nested closed shapes are `scope: {owner, kind, ref, epoch}`,
`secret: {name, kind, incarnation}`, and `use: {host, path_prefix, location}` for
API keys or `{origin}` for logins, as defined by Claustrum's Agent secrets
contract. Integers are nonnegative and at most 2^53 − 1; floats are refused.
Each canonical 26-character uppercase ULID `request_id` must equal its item's.
`agent_id` equals the stamp's `attributes.agent_id`, including null. Every item
shares one agent and one member, and request ids never repeat.

The card expires at the earliest statement `request_expires_at_ms`. Already
expired statements and answers at or after expiry refuse `elicitation_expired`.
Identical ordered items on the same owner return the existing card without
refreshing its deadline, including after an answer while requests remain live.
Any different filing that reuses a request id refuses
`elicitation_request_conflict`. Request-id reservations survive card retention;
an expired filing is refused even if identical to an older card.

After the phone submits `secret.approve` to the vault using this elicitation id
as `card_ref`, it answers Cingulate with the exact `envelope_b64url`. The vault
verifies the signature, not Cingulate. Cingulate verifies the envelope binding
specified in the [phone contract](consent-phone-v2.md#vault-secret-use-approvals-0120).
A decline carries no envelope. Owned get/await/answers expose `secret_use_answer`:

```json
{"decision":"allow","duration":"hour","items":[{"request_id":"01HF7YAT000000000000000001","decision":"allow"}],"envelope_sha256":"7bcd68a3ec5698ad9c9d11e0efa1d67ef7e7aa6ee18c56d963d5f6b18014f180"}
```

Items are recorded in card order; omitted envelope items are `decline`. A whole
decline records every item as declined and omits duration/hash. Repeating an
answer requires the same choice and binding, not merely another allow envelope;
a different binding returns the existing conflict record. The SHA-256 is over
the decoded envelope bytes and matches the vault's grant and audit
`payload_hash`. See the [pinned vault and served phone vectors](../../test-vectors/secret-use-approval-v1/README.md).


## Flow-install secret approvals (0.13.0)

Cingulate advertises `flow-install-secrets/v1`. Core sends the new fields only
when that capability is present. Only `reserved:prefrontal-core` may file
`flow_install`, as before. The existing `flow_install.flow` remains the flow's
name; the new identity key is **`flow_identity`**, not `flow`.

Inside the otherwise opaque `flow_install` object, supply both new keys or
neither:

```json
{"flow":"daily-fetch","flow_identity":{"flow_id":"daily-fetch","version":7,"code_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","install_id":"install-A"},"secrets":[{"request_id":"01HF7YAT000000000000000001","statement_b64url":"<unchanged vault flow statement>"}]}
```

`flow_identity` is closed: `flow_id` and `install_id` are 1–256 printable ASCII
bytes, `version` is an integer 1 through 2^53 − 1, and `code_hash` is exactly 64
lowercase hex characters. `secrets` has 1–16 closed `{request_id,
statement_b64url}` objects with unique request ids. Every other install-body key
remains opaque. Cards without these two keys keep their previous behavior.

Basal obtains each statement via the vault's `secret.request_flow_approval`;
core forwards its bytes unchanged. Filing reuses the `secret_use` strict
unpadded base64url and canonical JSON checks (including trailing bits, duplicate
keys, closed shapes and safe integer bounds). The decoded closed statement is
`{v, request_id, member_id, flow, secret, use, durations, request_expires_at_ms}`
with `v: "ck-secret-flow-statement/v1"`. `flow` equals `flow_identity` exactly;
`request_id` equals the entry's ULID; `durations` is exactly `["version"]`.
`secret` has the same closed shape as an agent statement. A login uses
`use: {origin}`; an API key uses `{host, path_prefix, location, methods}`, with
nonempty, unique, ascending uppercase methods of 1–16 bytes each.

Invalid filings store nothing. Named refusal codes are
`elicitation_flow_secrets_pair_required` (one key missing),
`elicitation_invalid_flow_identity` (identity shape/bounds),
`elicitation_invalid_flow_secrets` (entry/statement shape, count or encoding),
`elicitation_duplicate_request_id`, `elicitation_flow_identity_mismatch`, and
`elicitation_invalid_flow_durations`.

Core normally omits `expires_in_ms` under `consent-no-expiry/v1`. A secret-bearing
install still has a deadline: the earliest statement's `request_expires_at_ms`,
or the filed expiry if earlier. Vault flow requests may last up to 24 hours.
An already expired statement refuses `elicitation_expired`; any answer at or
after the deadline does too. Expiry settles the card as `expired` (denied, no
grant), regardless of the supplied `on_expiry`, which is normalized to `deny`.
The decline default is still required.

Only supported phone routes may see or answer these cards, including declines;
see the [phone contract](consent-phone-v2.md#flow-install-secret-approvals-0130).
A successful install answer records `secret_use_answer` with duration `version`,
all items allowed and the exact envelope SHA-256. A decline records all items
declined without duration/hash. The route's device fingerprint is recorded in
`answered_device`. Repeat answers require the same choice and exact envelope
bytes, as for `secret_use`. No storage migration is needed: the existing JSON
record, answer binding and retained secret-card visibility flag hold these
values. See [generated vectors](../../test-vectors/flow-install-secrets-v1/README.md).

## Forwarded secret statements v2 (0.13.1)

When an agent or flow on another paired computer asks for a secret, the home
computer's vault forwards the request and writes a v2 statement. The card is
filed on the asking computer, by its own AFT, Cerebellum or core, to its own
Cingulate, exactly as for v1. A v2 statement is the v1 statement plus one key,
`asking_member_id`, and `v` ends in `/v2`: `ck-secret-use-statement/v2` on a
`secret_use` card, `ck-secret-flow-statement/v2` in `flow_install.secrets`.
`member_id` still names the home vault serving the grant. Canonical bytes,
envelope digests, expiry, idempotency and every other rule above are unchanged.
Legacy requests made on the home computer stay v1, byte for byte.

- A v1 statement must not carry `asking_member_id`, not even as `null`.
- A v2 statement must carry it as `fed-computer:` plus exactly 32 lowercase hex
  characters, different from `member_id` (the home vault never forwards to
  itself).
- A version string from the other family is refused.
- Every statement on one card has the same `asking_member_id`, or none has it,
  so v1 and v2 statements never share a card.

Refusals reuse the existing codes: `elicitation_invalid_request` for
`secret_use`, `elicitation_invalid_flow_secrets` for flow statements. Cingulate
does not compare `asking_member_id` with this computer's identity; the home
vault sets it from the attested forwarding route and grants only a statement
whose digest matches its stored request. Vault vectors and generated cards:
[secret_use](../../test-vectors/secret-use-approval-v2/README.md) and
[flow install](../../test-vectors/flow-install-secrets-v2/README.md).

## Extended secret statements v3 (ck-cingulate 0.16.2)

Extended scopes use `ck-secret-use-statement/v3` for `secret_use` and
`ck-secret-flow-statement/v3` in `flow_install.secrets`, for both local and
forwarded requests. All other fields retain their v1 meanings, except that
`asking_member_id` is present exactly for forwarded requests, with the same
grammar and serving-vault exclusion as v2. Per-card asker consistency is
unchanged; a `secret_use` card also retains its one-agent check. Every statement
on a secret-use or flow-install card must name the same serving vault, because
one home vault holds all agent secrets and flow grants for the account.

The closed `use` shapes are version-specific:

| Version | API key | Login |
| --- | --- | --- |
| v1/v2 | `{host, path_prefix, location}` | `{origin}` |
| v3 | `{rules: [{host, path_prefix}, ...], location}` | `{origins: [...]}` |

Flow API keys additionally require the existing sorted, nonempty `methods` list
beside the legacy fields or `rules`. Every v3 rule must contain both string keys;
`path_prefix: ""` means no prefix. For v3, `secret.kind: "agent_api_key"` requires
the API-key shape and `"site_login"` the login shape; any other kind refuses.
Unknown keys, mixed shapes and shapes under the wrong version refuse with the
existing invalid-statement codes. Cingulate checks shape/version agreement and
card binding, not host grammar, scope counts, public suffixes or scope matching:
the vault remains the authority on the signed scope.

For flow statements, an extended v3 request cannot use either v3 statement tag as
`flow_id`, local or forwarded. A forwarded request (v2 or v3) also cannot use
either v2 statement tag as `flow_id`. A local v3 request may use a v2 tag; local
legacy v1 flow ids remain unchanged.

Envelope bytes, signatures, approvals and the recorded `envelope_sha256` are
unchanged. Cingulate does not render statement `use` content into card text or
labels; it relays all statement bytes unchanged to the phone, which renders the
complete scope. The [pinned vault samples](../../test-vectors/secret-statements-v3/README.md)
cover canonical multi-rule and wildcard scopes and multiple origins.
