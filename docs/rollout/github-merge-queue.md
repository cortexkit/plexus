# Governed bot merge queue add/remove

The `github` tool's `bot_request` operation accepts two repository-bound kinds:

```json
{"action":"pr enqueue","repository":"org/repo","target":{"number":7},"body":{"expected_head_sha":"0123456789abcdef0123456789abcdef01234567"}}
```

```json
{"action":"pr dequeue","repository":"org/repo","target":{"number":7}}
```

Use a lowercased repository and the [shim envelope and contract vectors](../../crates/plexus-core/tests/fixtures/gh_shim_wire/README.md#requests-contractnamejson).
For example, the complete enqueue request is pinned in
[`accepted-pr-enqueue.json`](../../crates/plexus-core/tests/fixtures/gh_shim_wire/requests-contract/accepted-pr-enqueue.json).
The outer `github` tool arguments are
`{"operation":"bot_request","request_nonce":"unique-nonce","request":{...}}`;
the vector's `request` object goes in that final field. Enqueue requires exactly 40 hexadecimal digits. Dequeue
accepts no body, not even an empty object. Unknown fields, including `jump`,
queries and transport variables, are refused by name. The fixed reviewed
GraphQL documents never send `jump`.

One fixed PR read supplies the node id, author, head SHA, state and queue state.
Only the acting agent's bound repository bot's own open PRs are eligible.
Ownership refusals use `pr_edit_not_own` and the same explanatory message as
`pr edit`. Closed or merged PRs return `pull_request_not_open`; enqueue with a
changed head returns `pull_request_head_moved` with expected and actual SHAs,
without a mutation. These guards apply even to a no-op. Enqueue on an already
queued PR and dequeue on an unqueued PR complete without a mutation.

The completed receipt projects `{url, number, queued, head_sha}`. `queued` is
the after-state. A repeated nonce replays the stored result without another
GitHub call. A GraphQL error in HTTP 200 is a sanitized refusal; a missing or
contradictory mutation result is `outcome_unknown`, not permission to resend.
No other merge, queue administration, or operator-only operation is enabled.

## Deployment and existing bots

An operator installs the binary, then the catalog and restarts to ingest it.
The catalog addition must not quarantine existing actions: the loader regression
test loads the catalog without the three new actions, then the complete catalog,
and compares every existing action's schema hash and status.

For **each of the 28 existing bots**, the bulk handle grant must add these exact
action names on its bound repository:

- `enqueue_pull_request`
- `dequeue_pull_request`
- `github.pull_request.queue_state.get`

The import action table accepts the two writes. New imports and `handle-grant`
default expansion imply `github.pull_request.queue_state.get` from either write;
new bots can select the writes in `onboard-github-bot --actions`. There is no
automatic migration of existing bots' stored grants. No prefrontal module write
grant is widened.

## App permission evidence: confirm live, do not assume

The bots currently have neither Contents: write nor Merge queues permission.
Do not add Contents: write or widen any App permission as part of this rollout.
Whether **Merge queues: write** is required remains to be confirmed live.

The first live authorization probe must call GitHub's fixed enqueue mutation
with a deliberately wrong `expectedHeadOid` against an eligible bot-owned PR.
GitHub checks authorization before rejecting the head mismatch, so the mismatch
proves authorization without queueing anything. This is an **operator diagnostic
probe**, not `bot_request`: the facade deliberately rejects a wrong expected SHA
in its pre-read, before GitHub can answer. If GitHub refuses permission instead,
record its accepted-permissions header. The operator/App owner then requests only
the proven required repository permission in the GitHub App's **Permissions &
events** settings, obtains the required human approval, and accepts the updated
installation permissions before repeating the safe probe. An actual
queue/dequeue smoke test follows only after authorization is settled.

For HTTP 200 permission errors (`FORBIDDEN`, including extension codes, or
“Resource not accessible by integration”), the REST transport emits a dedicated
operator-only `github GraphQL permission refusal` line containing
`X-Accepted-GitHub-Permissions`, when present, alongside the facade's existing
GraphQL error line. HTTP 401/403 already include that header in the REST vendor
error line. No response-header plumbing was added: logging at the transport
boundary keeps the header out of vendor bodies, agent replies and receipts.
