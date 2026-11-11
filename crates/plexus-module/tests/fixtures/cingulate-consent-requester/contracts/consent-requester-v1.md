# Consent requester contract, v1

The AFT permission-ask interface is [v2](consent-requester-v2.md). Existing v1
request bodies and served examples retain the behavior specified below.

This is the implemented requester interface for raising cards and consuming their
settlements. Requests use `{method: string, params: object}`; successful responses
wrap the result in `{result: ...}`. Refusals are transport errors with string
`code` and `message`, not result objects. The
[generated corpus](../../test-vectors/consent-requester-v1/README.md) pins actual
request envelopes and untouched handler response bytes with a fixed clock and
fresh temporary stores. The [phone contract](consent-phone-v1.md) describes the
other side of these cards. The optional `source` and `dry_run_text` fields and
their requester readbacks are specified in [consent-card-text-v1](consent-card-text-v1.md).

## Optional author explanations

With `consent-card-explanations/v1`, `consent.request` also accepts optional
`explanation: {label, text}` and `changes: {label, text}`, only on `package` and
`flow_install`. Both are plain author text shown with the labels core supplies.
Each string is nonempty; labels are at most 64 Unicode scalar values and text
at most 8,192 UTF-8 bytes. C0/C1 controls (U+0000–U+001F, U+007F–U+009F) are
refused except newline U+000A, including in labels. Invalid members or members
on other kinds return `elicitation_invalid_request` naming the field. Objects
are closed and null is not absence.

`consent.get` returns both objects unchanged. App `consent.list_pending` records
also include them; absent members are omitted and notifications never carry
them. The [explanations contract](consent-card-explanations-v1.md) defines storage,
display semantics and checksum-pinned phone/desktop samples.

## Identity and admission

Only the daemon's route bind supplies requester and subject identity. Ownership
is the pair of requester principal and attested bind session. An attested scoped
session includes its owner, reference and epoch; a reused reference with a new
epoch cannot read the previous session's cards. Unscoped binds have an empty bind
session. Body session references are card content, not ownership credentials.
Federated-stamped consent carriers use the paired-subject ownership exception
in [consent-requester-v2](consent-requester-v2.md#federated-consent-carriers),
not the scope reference and epoch. Local ownership is unchanged.

| Requester principal | Allowed request kinds |
|---|---|
| `reserved:basal` | `flow_decision` |
| `reserved:prefrontal-core` | `flow_install`, `package` |
| `reserved:cerebellum`, `reserved:plexus`, `reserved:entorhinal` | `consent`; must also carry a nonblank daemon-attested subject agent |
| `direct` | `consent`; displayed as an unverified local process |
| Anything else, including absent / unverified / `reserved:callosum` | No requests |

The dedicated `secret_use` and `manifest_binding` filing rules are in
[requester v2](consent-requester-v2.md), not the generic-consent admission above.

Disallowed principals or principal/kind combinations refuse
`elicitation_requester_refused`. Requesters need an admitted daemon route but
**no phone bind or harness prefix**. The `fed-phone:` rule applies only to
operator answering/listing (and the operator projection of get), not request,
answers, ack, await, execution reporting or withdrawal.

`consent.request` is a closed params object. Identity-looking fields such as
`principal`, `requester`, `owner`, `subject`, `agent_id`, `device_id`, `harness`
and other unknown keys are refused as `elicitation_invalid_request`, not silently
used. `session_ref` and `parent_session_ref` are supported content fields for some
kinds, but **forbidden on flow_decision**. Requester operations other than request
use direct param lookups and ignore unrelated keys; those keys still cannot
change the bound owner.

## `consent.request`: Basal flow decisions

`params` is the body below, not a nested `request` object. Use snake_case keys
except the explicitly spelled `requestedSchema`. No camelCase aliases exist.

| Param | Type | Requirement for `flow_decision` |
|---|---|---|
| `kind` | String | Required; exactly `flow_decision`. |
| `flow_decision` | JSON object | Required; stored verbatim as opaque display data. |
| `title`, `prompt` | Strings | Required, nonblank. |
| `options` | Array | Required; 2–4 objects with string `id`, `label`, `effect`, optional string `detail`. Ids must be unique/nonblank, labels nonblank. Exactly one effect `decline`, all others `choose`. Unknown option keys are refused. |
| `default` | String | Required; id of the decline option. |
| `urgency` | String | Required: `low`, `normal`, or `high`. |
| `on_expiry` | String | Required: `deny`. |
| `material_damage` | Boolean | Required. |
| `late_execution` | String | Required: `execute` or `notify_only`. It states what the requester does with an answer that arrives after its own wait ended. `execute`: a late grant still takes effect, either by running the held action or by recording a grant the next attempt uses. `notify_only`: a late answer is recorded and reported but has no effect. Neither value causes Cingulate to execute a choice. |
| `target` | Object | Required: exactly string `kind` and `label`, both nonblank. |
| `expires_in_ms` | Signed-64-bit integer | Optional; when present, 1–86,400,000. Omitted or null means no deadline; requires `consent-no-expiry/v1`. |
| `scope` | JSON value | Optional, but either non-null scope or nonblank `args_digest` must be supplied. Contents are opaque. |
| `args_digest` | String | Optional; needed if no scope. |
| `dedup_key` | String | Optional; owner-scoped pending-card key, described below. |
| `duration` | JSON value | Optional, opaque. |
| `facts` | Array | Optional, defaults to `[]`; each item has exactly string `label` and `value`. No facts are synthesized from the decision body. |
| `preview` | Object | Optional: exactly string `label` and `text`. |
| `binding` | JSON value | Optional; opaque correlation data returned to the requester, never to the phone. |
| `at_console` | Nonblank string | Optional; must match the hosting daemon's machine id at request time. Adds an answering-machine constraint; not requester identity. Phone answering currently cannot satisfy it. |
| `requestedSchema` | JSON value | Optional; `/properties/decision/enum` must be an array of strings equal to the option ids (order ignored). Checked then discarded, never stored/served. Other schema semantics are not enforced. |

`package`, `flow_install`, `session_ref`, and `parent_session_ref` are not usable
on a decision request. Unknown top-level fields are refused. Optional null values
decode as absent. The complete request envelope, including JSON framing, must be
at most 1,310,720 bytes; overflow is refused, not truncated.

Success result is exactly `{elicitation_id: string}` for creation, in-place
refresh and replacement. The reply alone does not distinguish those cases: a
refresh preserves id, a replacement returns a new id. Use requester get or await
with the returned id to read the current record.

For every v1 card kind, requesters may omit `expires_in_ms` only after checking
that Cingulate's `catalog.list` entry advertises `consent-no-expiry/v1` in
`capabilities.provides`. Older Cingulate requires the field and refuses omission.
A supplied integer retains its existing bounds and fail-closed expiry behavior.
Without a deadline the card stays pending until answered or withdrawn; it is
never expired by a maintenance sweep or a wait timeout. Pending payloads are not
retention-pruned. `on_expiry: "deny"` and a decline default remain required, but
silence never selects a choice. No-deadline requester records omit both
`expires_in_ms` and `expires_at_ms`; phone cards omit `expiresInMs` and
`expiresAtMs`. See the additive
[no-expiry vectors](../../test-vectors/consent-no-expiry-v1/README.md).
The phone pending list orders all cards oldest first by creation time, then id,
regardless of deadline. Its new continuation is a JSON object keyed by
`created_at_ms` and `elicitation_id`; the previous expiry-keyed input remains
accepted for one release as described in the phone contract.

### Three decision bodies and choices

The following are the existing requester-owned schema examples, **not extra
validation performed by Cingulate**. Basal owns their validity and what an
explicit choice does. The copied raw bodies and generated request/reply pairs
are linked in the corpus index.

| Decision | Nested `flow_decision` fields in the copied schema | Options / default |
|---|---|---|
| `reconcile` | `decision: "reconcile"`, `flow_id`, `version`, `run_id`, `run_admitted_at_ms`, optional `step`, `call_key`, `op`, `attempts`, `unknown_reason` | `send_again`, `continue`, `cancel` (`choose`); `unresolved` (`decline`, default). |
| Re-enable | `decision: "reenable"`, `flow_id`, `version`, `disabled_at_ms`, `disabled_reason`, `limit`, `window_ms`, `saturated_windows` | `reenable` (`choose`); `disabled` (`decline`, default). |
| `grant_lost` | `decision: "grant_lost"` plus `{flow_id, provider, grant, grant_label, refused_at_ms}`; **no version** | `check_now` (`choose`); `keep_disabled` (`decline`, default). |

`grant_lost` is informational. It carries the provider's opaque grant string and
untrusted display label without decoding or normalizing either. No choice mints
a grant; the module stores a decision and never calls a grant provider or resumes
a flow. Basal interprets explicit `check_now` / `keep_disabled` answers in its
own policy. Expiry supplies no choice; the decline default is not an implicit
operator answer.

### Compatibility with prefrontal's decision corpus

**All three raw request bodies from `test-vectors/flow-decision-card-v2` are
accepted unchanged as `reserved:basal` requests.** The copied inputs are hash
pinned, submitted to the real handler, and their fields checked on readback.
Prefrontal's design document calls the flow-decision card format "v2.2". Its only
published example bodies are in `test-vectors/flow-decision-card-v2`; the three
request bodies pinned here are copied from that corpus. Acceptance of those
examples is **not a claim of semantic parity with the format called "v2.2"**.

Cingulate renders nothing and carries typed bodies opaquely. The authority that
holds the flow record raises and validates its card. Cingulate validates the
envelope (kind, allowed requester, option structure/effects, size, fact shape),
then stores the `flow_decision` JSON object verbatim. The requester owns that
body's validity. Field-by-field comparison with the copied core schema:

| Core-side field or rule | Cingulate behavior |
|---|---|
| Nested `decision` discriminator and variant-specific required fields | No discriminator/variant validation; any object is accepted, even an empty one. No nested field is required by the module. |
| Unknown nested keys | Preserved, not rejected. |
| `flow_id`; `run_id` and `call_key` on reconcile; `provider` on grant_lost | No string, nonblank or 256-byte limit check inside the body. |
| `version` on reconcile/reenable | No integer or positive-value check. |
| `run_admitted_at_ms`, `disabled_at_ms`, `refused_at_ms` | No signed-integer timestamp check. |
| Reconcile `step` | No optional-string type check. |
| Reconcile `op` | No string check, 128-byte cap, two-or-more dotted segments, or lowercase ASCII letter/digit/underscore/hyphen segment rule. |
| Reconcile `attempts` | No unsigned-integer or greater-than-zero check. |
| Reconcile `unknown_reason` | No enum check for `basal_restarted`, `connection_lost`, `reply_timeout`, `reply_unreadable`, `retries_exhausted`, `provider_lost_run`. |
| Re-enable `disabled_reason` | No enum check for `run_limit_saturated`, `dispatch_limit_saturated`. |
| Re-enable `limit`, `window_ms`, `saturated_windows` | No unsigned-integer or greater-than-zero checks. |
| Grant-lost `grant` | No string, nonempty or 4096-byte token cap check beyond the overall envelope budget. |
| Grant-lost `grant_label` | No string or nonblank check. |

The common raw examples' envelope fields (`kind`, `flow_decision`, `title`,
`prompt`, `options`, `default`, `urgency`, `on_expiry`, `material_damage`, `scope`,
`late_execution`, `target`, `expires_in_ms`) have matching spellings and accepted
values. Both interfaces support optional `dedup_key`, `duration`, `args_digest`,
`facts`, `preview` and transient `requestedSchema`. Neither allows session
references on decision cards. The core envelope additionally declares optional
`call_key`, `executor`, `module`, `tool`, `schema_pin`, `args_jcs`, `args_hash`,
and transport-only `approval_scope` / `requester_session`; these are **not**
accepted Cingulate params. Cingulate additionally accepts `binding` and
`at_console`. No compatibility shim or decoder change is made.

Lifecycle differences also matter:

* Core derives grant-lost dedup identity from `[flow_id, provider, grant]` and
  refreshes its label/refusal details. Cingulate derives no key from the body:
  Basal must send `dedup_key`; changed label/refusal/body content **replaces** the
  pending card instead of refreshing it in place.
* Core's corpus describes expiry selecting the decline choice for reconcile and
  re-enable. Cingulate expiry omits `answered_choice_id` for **every** kind,
  including those two. No choice is applied on silence.

## Requester record shape and `consent.get`

Requester get requires string `elicitation_id`, not phone `elicitationId`.
Success is the full record directly: the phone card's top-level keys and subject
keys converted to snake_case, plus `binding` when present. Nested JSON stays
verbatim; request data is flattened, not under `request`. `requester_label` is
the daemon-stamped requester label. Basal's subject is `{label: "operator
decision"}`, with no agent fields. Facts are present even if empty. Package
records retain their script and manifest bodies. Optional unanswered fields are
omitted, not null.

Unknown / another owner's id refuses `elicitation_not_owner`; an owned but
acknowledged or no-longer-retained id refuses `elicitation_not_found` on requester
get. Get sweeps expiry before serving an owned record. Requester get and the
answer feed stop exposing a settlement after acknowledgment; the phone's separate
`consent.get` continues to return a settled card until its payload is pruned 24
hours after settlement.

## `consent.answers`: read the owner's settlement feed

Required param: `since`, a nonnegative signed-64-bit integer. Begin at `0`.
Success: `{records: RequesterRecord[], cursor: integer, continuation?: integer}`.

* Only this bound owner's **unacknowledged answered and expired** cards appear,
  in increasing settlement cursor order, strictly after `since`. **Withdrawn
  cards do not appear**, including cards withdrawn by dedup replacement.
* Cursor is a durable store-global answer-log position, not a count of this
  owner's records, not a card id and not a timestamp. Other owners and
  withdrawals also consume positions. Individual records carry no row cursor.
* Each serialized page is below 3 MiB. On a partial page, `cursor` and
  `continuation` are the last returned row's position. Pass `continuation` as
  the next `since`; acknowledging that page cursor cannot discard unread rows.
* On a final page, `continuation` is omitted and `cursor` is the global
  high-water position, even for an empty feed. Persist it after processing the
  whole page, then poll with it as `since`.
* Reading does not acknowledge anything. Full retained records include private
  binding and package bodies. At or after 24 hours since settlement, an
  unacknowledged row is a tombstone: `{elicitation_id: string, state: "expired",
  settled_at: integer}`. That tombstone's `state` is a retention marker, not
  evidence of the original choice or terminal state.

## `consent.ack`: discard processed owner settlements

Required param: `cursor`, a nonnegative signed-64-bit integer. Success:
`{ok: true}`. Acknowledgment is cumulative for this owner through that cursor,
including withdrawals even though answers omits them. It hides those settled
records from requester get/await and future answers; it does not affect pending
cards or another owner's records, or undo an answer. It does not hide the card from
phone `consent.get`, which remains available until the 24-hour retention prune.
Ack as soon as the answer is durably saved; reporting the effect may happen later.
`consent.report_execution` still accepts an acknowledged answered card while its
record is retained. Ack neither reports execution nor extends retention.
Rows are physically pruned only after retention. A future cursor is accepted, but
does not pre-acknowledge settlements created later. Send only a cursor whose
page(s) you processed: an arbitrary high cursor can discard unread existing answers.

## `consent.await`: wait without granting on timeout

Required params: string `elicitation_id` and nonnegative signed-64-bit integer
`timeout_ms`. The timeout is capped at 120,000 ms. Success is the current full
requester record, **not** an answer wrapper. `timeout_ms: 0` is an immediate read.
Otherwise wait until settlement, the caller's wait deadline, or card expiry
(when present), whichever is first.
A timeout can return `state: "pending"`; inspect state/choice, never infer approval
from a completed wait. Dedup refresh wakes the waiter to re-read the card, but
does not extend the call's timeout. While waiting, pending phone/get projections
carry `blockUntilMs` / `block_until_ms`, capped at expiry only when the card has
one. A no-deadline card uses only the caller's wait bound. Dropping/cancelling the
wait removes its registration. Same owner/not-found refusals as requester get.

## `consent.report_execution`

Required params: string `elicitation_id` and string `execution`, one of
`executed`, `approved_not_executed`, `outcome_unknown`. Success is the full
requester record with the stored `execution`. The module does not execute
anything, and reporting adds no new answer-log row/cursor.

**Flow decisions cannot report execution**, even if answered:
`elicitation_invalid_execution`. That code also covers an unsupported execution
string. For other kinds, the card must already be answered or the refusal is
`elicitation_store_error`. The implementation requires answered state, not a
particular grant effect; requesters remain responsible for acting only on an
appropriate explicit answer. Ownership and retention checks still apply.
Unlike get, await and answers, reporting is allowed after acknowledgment while
the answered record is retained (24 hours after settlement). After an acknowledged
record is physically pruned, reporting refuses `elicitation_not_owner`, the same
uniform refusal as an unknown id because the stored owner is gone. A requester
which already acked that card treats this as **too late, drop it**, not a reason
to retry or repeat the effect. If an owner tombstone still exists after retention,
reporting refuses `elicitation_not_found`. Owner checks are unchanged.

Optional `reason` is accepted **only** with `execution: "approved_not_executed"`.
It is an open-set code of 1–64 bytes matching `^[a-z][a-z0-9_]{0,63}$`; null,
non-strings, malformed codes, or a reason with any other execution value refuse
`elicitation_invalid_execution` with `reason` in the diagnostic. Known codes are
`session_ended`, `target_gone`, `grant_store_unavailable` and
`refused_at_dispatch`. Cingulate stores any well-formed code, including unknown
ones, with the execution report. Requester reads use `execution_reason`; phone
reads use `executionReason`. Both omit it when absent. Each valid requester report
replaces execution and reason together in one store transaction, so reporting
without a reason clears any previous reason. This includes replacing an earlier
requester report (for example, `outcome_unknown` followed by `executed`) or
Cingulate's session-ended backstop: the requester knows what actually happened,
whereas the backstop only infers non-execution from session liveness.

On the maintenance cadence, Cingulate itself records
`execution: "approved_not_executed"`, `execution_reason: "session_ended"` for a
retained, answered card of kind `consent` with no execution report whose recorded
asker scope has definitely ended. The asker is the scope stamped at
`consent.request` (a worker's own scope, not its parent). Liveness follows the
permission-ask `scope.describe` rules: an ended scope, a replaced epoch, or a
definitively non-live scope counts; unknown, unsynced or unreachable liveness
does not. Cards without a recorded scope are left alone. Passes are bounded and
uncertain lookups use the existing bounded exponential maintenance backoff.
Acknowledgment does not exclude a retained card. Pending cards, `flow_decision`
cards and permission asks are not backstopped. The backstop atomically rechecks
that no report exists and never overwrites any report. A requester report always
replaces the backstop, including when the two race. These fields describe a recorded
outcome, not permission to execute anything. Served examples are pinned in
[consent-session-ended-v1](../../test-vectors/consent-session-ended-v1/README.md).

## Updating or withdrawing an open card

Submit another `consent.request` with the same `dedup_key` on the same bound
owner. Only a **pending** card matches; a settled card never suppresses a new
request. No key means always create. Matching content ignores expiry duration,
the key itself, discarded answer schema, and resolved subject label, but compares
all other request data and subject agent/head ids:

* Same content: refresh in place, same id and creation time. A supplied lifetime
  moves expiry to current time plus that lifetime; an omitted lifetime leaves
  the refreshed card without a deadline, including when the old card had one.
  A no-deadline refresh of a no-deadline card stays no-deadline. A newly resolved display label may
  update. Waiters wake; no new-card pointer is delivered. The phone's revision
  changes when persisted pending content/expiry changes, so it receives the
  refreshed card on its next poll.
* Changed content: old card becomes `withdrawn`, then a new pending card with a
  new id is created in the **same transaction**. Reply is the new id. Old
  waiters wake; old-card retraction precedes new-card notification, after commit.
  The phone's next list has the new card instead of the old and a new revision;
  get of the old retained id shows withdrawn. An answer against the old id
  conflicts. No answer automatically transfers to the new id.
* Due match: old card becomes `expired` at its deadline and a new card is
  created. Request does not sweep unrelated cards.

`consent.withdraw` requires string `elicitation_id`. Success is the full
requester record. A pending live card becomes withdrawn with settlement time
and **no** `answered_choice_id`; a due card expires instead. An already-settled
card returns its existing terminal record unchanged. First settlement wins; a
withdraw cannot reverse an answer. Same owner/retention refusals as get.

## Refusals and fail-closed handling

Shared envelope/transport failures are documented in the phone contract:
`elicitation_request_too_large`, `invalid_request`, `unknown_method`,
`consent_unavailable`, `elicitation_store_error`, `cancelled`. None grant anything;
a cancelled mutation may already have committed, so read back before deciding.

| Code | Requester-specific condition |
|---|---|
| `elicitation_requester_refused` | Principal not allowed, kind not allowed for it, or carrier missing an attested agent. |
| `elicitation_invalid_request` | Closed envelope/type/range errors, unknown keys, invalid options/target/expiry/schema, missing decision object or scope/digest; bad operation params/cursors; or single record exceeding a page budget. An `at_console` request not matching the daemon machine also uses this code. |
| `elicitation_unknown_kind` | Unsupported request kind after decoding. |
| `elicitation_fail_closed_required` | Default is not a decline option, or `on_expiry` is not `deny`. |
| `consent_retired` | A carrier's attested subject resolves as retired. Unavailable name resolution falls back to raw agent id, not authority. |
| `elicitation_not_owner` | An id operation names an unknown card or a card outside this route's owner. |
| `elicitation_not_found` | Matching owner, but acknowledged or no longer retained. |
| `elicitation_invalid_execution` | Execution reporting on a decision card or unsupported execution string. |

Availability and principal admission precede request decoding. The per-kind
requester check follows decoding; a malformed body can therefore refuse before
a wrong-kind refusal for an otherwise admitted requester. No operation changes
requester or subject identity based on its params.

## Executable checks and comparison sources

The three copied decision request bodies are accepted without modification, and
their fields survive requester readback. Nested decision data is preserved even
when its keys are unknown; a non-object decision body or an unknown top-level
request field is refused. Basal can raise a card without a phone harness, but
requester reads require the same bound owner. Answer cursors are store-global;
acknowledgment
hides that owner's existing settlements through the cursor, including
withdrawals, without hiding pending cards or another owner's answers. Withdrawal
records consume cursor positions but do not appear in `consent.answers`. The
vector bytes, original copied input hashes and complete corpus hash coverage are
checked independently (`crates/cingulate-vectors/tests/requester_contract.rs`).

A wait that times out may return a pending card and never implies approval;
cancelling a wait removes its registration. Execution reporting records the
requester's outcome without executing an action, and is refused for decision
cards. Partial answer pages advance only through returned rows. Dedup refresh
preserves the card id, while changed content atomically withdraws the old card
and creates its replacement. Withdrawal cannot reverse an answer. Acknowledged
or no-longer-retained cards are unavailable to requester reads. Availability and
principal admission are checked before request decoding; the per-kind requester
check follows decoding. These behaviors are also checked by the requester,
module and store lifecycle tests.

The read-only schema comparison uses prefrontal's
`test-vectors/flow-decision-card-v2/{reconcile,reenable,grant_lost}-request.json`,
its corpus README, `crates/prefrontal-core-store/src/elicitation.rs` (decision
variants, validation and request envelope), and `docs/designs/consent-module.md`.
That design document calls the flow-decision card format "v2.2"; the only
published example bodies for it are the `test-vectors/flow-decision-card-v2`
corpus, from which the three request bodies in these vectors are copied. These
source paths identify the comparison, not runtime dependencies.
