# permissions/v1: the operator's view of agent GitHub bot grants

Cingulate serves the operator one permissions page (phone and desktop) that
lists every standing grant across modules and can revoke any of them. Plexus
declares `permissions/v1` in its manifest's `capabilities.provides` and serves
the two provider operations of cingulate's contract
(`docs/contracts/permissions-v1.md` in the cingulate repository; the provider
vectors are copied into `crates/plexus-module/tests/fixtures/permissions-v1/`).

Both operations are route operations sent as `{method, params}`, like
`grants.would_ask`. They are not facade tools.

## What is listed

Only agent-layer grants: `grants` rows with an `agent_id`, while they are live
(`now < expires_at`). These are the per-agent GitHub bot grants a handle import
or handle grant mints. Two things are not listed, by the operator's ruling
(cingulate `docs/design.md`, item 10), because neither is a grant an operator
gave an agent:

- module-layer grants (`agent_id IS NULL`): the carrier ceilings held for aft,
  prefrontal-core, basal, broca and direct. A ceiling decides whether a whole
  module may act through plexus at all. A page revoke takes one tap and raises
  no prompt, and revoking a ceiling would cut off that module for every agent
  (for example all of aft's GitHub access, or every Basal flow), so ceilings
  belong in a settings surface with an explicit confirmation;
- policies (`allow`, `ask_first`, `block`). A policy decides whether an action
  that a grant already allows runs, asks first or is blocked; it gives no
  authority of its own, so there is nothing for the page to revoke.

An agent's grants on one bot connection fold into capability rows. The rows are
the same for every bot and never depend on when grants were minted. Plexus's
`scope` vocabulary is exactly these three tokens:

| `scope` | Grants in the row | `subject_label` |
|---|---|---|
| `github_bot_speak` | every selector except `create_issue` and `create_pull_request`: comment, edit comment, review, react, edit, close, reopen, assignees, labels, and the reads they depend on | `Speak as <bot login> on <bound repos>` |
| `github_bot_open_issues` | `create_issue` | `Open issues as <bot login>` |
| `github_bot_open_pull_requests` | `create_pull_request` | `Open pull requests as <bot login>` |

A selector plexus does not know lands in the speak row. A row exists only while
at least one of its grants is live. A grant whose selectors span rows (`*`, or a
list naming `create_issue` beside a comment action) is in every row it touches,
and revoking any of them removes the whole grant: a grant row cannot be split,
and keeping it would keep authority the operator asked to end.

Row fields: `id` is `plx_` plus 24 hex digits of a SHA-256 over the agent id,
the connection id and the scope, so a row keeps its id for as long as any of its
grants is live. `agent_id`, `holder: {kind: "agent", agent_id}`,
`module: "plexus"`, `subject_label`, `scope`, `scope_label` (one plain sentence,
for example "example-bot[bot] can comment, review, react, edit, close and
reopen issues and pull requests on example-org/example-repo."),
`granted_at_ms` (the newest mint among the row's grants) and `expires_at_ms`
(the earliest expiry among them, absent when none expires). There is no
`group` and no `card_ref`: no plexus grant came from a consent card. The bot
login is the App slug of the connection's handle plus `[bot]`, the same login
the bot-write path checks comment authors against.

## Revoke

`permissions.revoke {id}` revokes the row's live grants and nothing else, each
through `PlexusStore::revoke_grant`, the path `ck-plexus-admin revoke-grant`
takes: the revocation is appended to `grant-revocations.jsonl` and fsynced,
then one fenced transaction snapshots the grant into `grant_revocations` and
deletes it. A database restored from before the revoke replays the journal on
open, so the grants stay revoked. Each revoked grant gets an audit row
(`reason_code` `permissions_revoke`, the caller as acting principal).

Grants are revoked one at a time. A crash or store error part way leaves the
grants before it fully revoked and the ones after it live; a grant whose journal
line was written but whose delete did not commit is removed by the replay on the
next open. The row is still listed under the same id, and a retry revokes the
rest.

The reply is `{outcome: "revoked"}` when any grant was revoked and
`{outcome: "not_found"}` when the row has no live grants (an unknown id, a row
already revoked, or one whose grants all expired). Plexus never answers
`stopping`: it checks grants again before every dispatch and every bot-write
leg, so there is no running work for a revoke to stop.

## Admission

Only `reserved:cingulate` and the local operator's `direct` route are admitted,
and only on a classic route: a flow or a codemode run is refused even when its
principal would otherwise be admitted. Every other caller gets
`{error: {code: "permissions_operator_required", message}}`, with the message
worded as in cingulate's test vector
`test-vectors/permissions-v1/provider-revoke-refused-agent.json` (copied to
`crates/plexus-module/tests/fixtures/permissions-v1/`). `cingulate` is on the
first-party list so it can bind at all; binding gives it no tool authority,
because it holds no grants.
