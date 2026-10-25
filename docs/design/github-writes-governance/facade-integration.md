# Facade integration

The GitHub facade (`github.bot_request`) combines repository binding, authorization and durable write receipts in one request path.

## Identity (gate G1)

- Require the daemon route scope to name an agent and allow it to act as that agent (`delegates` and `owner_authorized`). Resolve only that agent's bound bot.
- A missing or non-delegating scope refuses `delegating_scope_required`. A bot write never falls back to a default identity.
- Signed agent tokens and the signing-key lookup are retired. `assertion` and `agent_assertion` are undeclared arguments, refused by field name before any handler runs.

## Resolution and arguments (G2, G3)

- Use `crate::github::resolver` for repository-to-handle resolution. Its outcomes map onto `repository_unbound`, `agent_repository_conflict` and `request_field_forbidden`.
- Build every vendor call's arguments with the resolver's per-kind allowlist (`mapped_args`), never by copying request fields. Governance checks the pinned argument schema and REST serializes non-path arguments, so each leg must receive only its own declared fields.

### Caller-pinned authority

`github` / `bot_request` accepts an optional top-level `expect` beside `request`
and `request_nonce`:

```json
{"app_handle_id":"app-example","repo_binding_generation":7}
```

Both fields are required, the handle is a string, and the generation is a
non-negative integer. Other keys and malformed values refuse `invalid_request`
with the offending `expect` field named and `transmission: not_sent`.

After selecting the agent's handle and checking its repository binding, the facade
first checks for a terminal nonce replay. For a new or resumable write, the expectation
is compared at authority-baseline capture: the handle must match G2's selected
handle, and the generation must match the baseline's `repo_binding_generation`,
not the earlier reply-generation preflight. A mismatch refuses
`stale_authority{dimension: expected_handle}` or
`stale_authority{dimension: expected_binding}`, with `transmission: not_sent`,
before any claim, ownership pre-read, credential preparation or GitHub contact.
The baseline subsequently pinned by the receipt is still rechecked before and
after pre-dispatch reads and after credential preparation. The expectation is
never a credential or a substitute for grants, binding checks or live scope checks.

### Caller-run liveness

`bot_request` also accepts an optional top-level
`run_scope: {"owner":"reserved:aft","ref":"run-1","epoch":11}` beside
`request`, `request_nonce` and `expect`. All three members are required: owner
and ref are strings, epoch is a non-negative integer, and extra keys are refused.
Malformed values refuse `invalid_request`, naming the `run_scope` field, with
`transmission: not_sent` before claiming a receipt or contacting GitHub.

The route's stamped scope remains the sole source of bot authority. Before every
unsent write leg, after rechecking that route scope, the facade describes the run
through the same uncached daemon reader. The run must be live at the supplied
epoch, and its structured live parent must match the route's owner, ref and epoch.
Plexus also checks its own clock against the live stamp's `expires_at_ms`, when
present; a daemon reply that still says live cannot extend an expired run.

Run refusals carry `scope_role: run` and `transmission: not_sent`, with `legs_sent`
listing any earlier writes that remain sent. Ended, replaced, expired or absent
after owner sync means `scope_ended`; a different parent means
`run_scope_not_child`. A missing parent or stamp, a failed read or an unconfigured
owner means `scope_unverifiable`. An owner not yet synced means `scope_not_synced`.
The latter two release the claim, allowing an explicit same-nonce retry to resume
unsent legs without repeating completed writes. Route-scope refusals instead carry
`scope_role: route`, with their other fields unchanged.

Unlike `expect`, `run_scope` is excluded from the request fingerprint: it only
narrows liveness. A terminal same-nonce receipt replays its recorded outcome even
when the run constraint changes or ends. Omitting `run_scope` preserves the
existing behavior except for the additive route-refusal role.

## Governance wiring

- `GithubGovernanceSeams` holds `Arc<PlexusStore>` and the scoped credential provider. The daemon installs it in its governance engine.
- The production `facade_only` is `catalog::facade_only_from_stored_manifest`. Seen markers use `github.bot_request`, not ordinary invoke. Both AFT and Prefrontal carry stamp-only bot writes.
- Facade audit rows record the stamped agent and resolved `app_handle_id`, NULL before resolution. The token-only claimed bot login is no longer written; its additive audit column remains NULL.
- Recheck the daemon scope before each write. Flows require the Basal carrier and `flow_id`; an ask-first policy refuses `consent_unavailable` without claiming a receipt or parking an approval.
- Deploy the identity-token cutover in a restart window; there is no compatibility mode.
- Log the principal the vault route opened as on every credential refusal. A read that arrives as `direct` is refused `not_found`, byte-identical to a missing record.

## Receipts (G4)

- Attach a `ReceiptClaim` to each effect through the private facade constructor. It must never enter `args`.
- A failed `pre_transmit` compare-and-set on a receipt returns `nonce_in_flight` without transmitting.
- Set the audit journal's `idempotency_key_fingerprint` to the receipt's `request_fingerprint` on every facade write.
- The store sweeper records expired uncertain effects in reconciliation before returning them for diagnostics. Callers must not enqueue those effects again.
- Pagination and receipt claims share `github::receipt::DEFAULT_CLAIM_LEASE_SECONDS` (120 seconds).
- Integration tests exercise terminal replay, uncertainty, claim ownership and takeover through the real facade path.
- With `expect`, the fingerprint hashes sorted exact-integer JSON containing the canonical request and expectation under `exact-json-expect-v1`. Changing or removing the expectation on the same nonce refuses `nonce_payload_mismatch`. A retry with the same canonical request and expectation replays a terminal receipt's recorded outcome, even if the repository binding has since moved. Without `expect`, request fingerprint bytes remain exactly `exact-json-v1` as before, including for existing receipts.
- A route stamp is not liveness: even a new nonce on a cached, delegating route must pass an uncached daemon scope description before its first unsent write. An ended scope or a changed epoch refuses `scope_ended` with zero GitHub writes.

## Request kinds

- Own-issue `issue edit`: read the issue first, and refuse `issue_edit_not_own` unless the ISSUE's author passes the two-leg bot check (`user.login == "<slug>[bot]"` and `user.type == "Bot"`). Apply up to six fields as ordered legs (title and body through `edit_issue`, then `add_issue_labels`, `remove_issue_label`, `add_issue_assignees`, `remove_issue_assignees`), recording each in the receipt's `effects`. A 404 is `not_present`.
- Edit-last: complete `pagination::walk_newest_bot_comment`, retaining only the latest own comment. An incomplete walk refuses; it never means "no comment". Ownership is checked again on the chosen comment before dispatch.
- Request shapes come from `crates/plexus-core/tests/fixtures/gh_shim_wire/`. Parse them as JSON and never rely on key order.

## Every reply

- Every `github.bot_request` reply carries the current repository-binding generation when the preflight read succeeds. If that read fails, the reply omits `repo_binding_generation` and performs no new claim or vendor contact. A fresh or unattempted receipt receives transient `store_failure`. Verified terminal receipts replay their recorded outcomes; attempted in-flight receipts keep their normal `nonce_in_flight` refusal. An expired partial request would normally resume its unsent legs; while generation is unavailable, this non-sending path returns ephemeral `outcome_unknown` without changing its receipt, so a later healthy same-nonce retry can resume unsent legs. The GitHub command-line shim's `gh_shim_relay_client.rs` treats `store_failure` as transient (two same-nonce retries); absent generation neither replaces its cached binding coverage result nor starts a new comparison against the signed routing manifest (around lines 693-719). Zero is a real generation and must never stand in for an unknown value. Successful new writes retain the real generation read before contact.
