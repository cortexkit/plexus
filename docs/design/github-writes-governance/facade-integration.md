# Facade integration

The GitHub facade (`github.bot_request`) combines repository binding, authorization and durable write receipts in one request path.

## Identity (gate G1)

- Require the daemon route scope to name an agent and allow it to act as that agent (`delegates` and `owner_authorized`). Resolve only that agent's bound bot.
- A missing or non-delegating scope refuses `delegating_scope_required`. A bot write never falls back to a default identity.
- Signed agent tokens and the signing-key lookup are retired. `assertion` and `agent_assertion` are undeclared arguments, refused by field name before any handler runs.

## Resolution and arguments (G2, G3)

- Use `crate::github::resolver` for repository-to-handle resolution. Its outcomes map onto `repository_unbound`, `agent_repository_conflict` and `request_field_forbidden`.
- Build every vendor call's arguments with the resolver's per-kind allowlist (`mapped_args`), never by copying request fields. Governance checks the pinned argument schema and REST serializes non-path arguments, so each leg must receive only its own declared fields.

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

## Request kinds

- Own-issue `issue edit`: read the issue first, and refuse `issue_edit_not_own` unless the ISSUE's author passes the two-leg bot check (`user.login == "<slug>[bot]"` and `user.type == "Bot"`). Apply up to six fields as ordered legs (title and body through `edit_issue`, then `add_issue_labels`, `remove_issue_label`, `add_issue_assignees`, `remove_issue_assignees`), recording each in the receipt's `effects`. A 404 is `not_present`.
- Edit-last: complete `pagination::walk_newest_bot_comment`, retaining only the latest own comment. An incomplete walk refuses; it never means "no comment". Ownership is checked again on the chosen comment before dispatch.
- Request shapes come from `crates/plexus-core/tests/fixtures/gh_shim_wire/`. Parse them as JSON and never rely on key order.

## Every reply

- Every `github.bot_request` reply carries the current repository-binding generation when the preflight read succeeds. If that read fails, the reply omits `repo_binding_generation` and performs no new claim or vendor contact. A fresh or unattempted receipt receives transient `store_failure`. Verified terminal receipts replay their recorded outcomes; attempted in-flight receipts keep their normal `nonce_in_flight` refusal. An expired partial request would normally resume its unsent legs; while generation is unavailable, this non-sending path returns ephemeral `outcome_unknown` without changing its receipt, so a later healthy same-nonce retry can resume unsent legs. The GitHub command-line shim's `gh_shim_relay_client.rs` treats `store_failure` as transient (two same-nonce retries); absent generation neither replaces its cached binding coverage result nor starts a new comparison against the signed routing manifest (around lines 693-719). Zero is a real generation and must never stand in for an unknown value. Successful new writes retain the real generation read before contact.
