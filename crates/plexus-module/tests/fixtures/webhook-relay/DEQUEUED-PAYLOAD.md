# Dequeued payload projection

`pull-request-dequeued.json` is a synthetic, reduced GitHub webhook payload,
not a captured live dequeue. No live dequeue was available in the relay vectors.

GitHub's [pull_request/dequeued documentation](https://docs.github.com/en/webhooks/webhook-events-and-payloads?actionType=dequeued#pull_request)
describes removal from the merge queue and requires top-level `number`,
`pull_request`, and `reason`. The common webhook fields include `repository`
and `sender`; `X-GitHub-Delivery` is the globally unique delivery GUID carried
by the relay as `delivery_id`. The nested `pull_request.head.ref` and
`pull_request.head.sha` shape is also pinned in the anonymized real PR capture
at `crates/plexus-core/tests/fixtures/event-envelope-v2/webhook_pull_request.json`.
The sample reason is illustrative, not an enum contract: Plexus copies the
string without translating or restricting it.

`pull-request-dequeued.body-v1.json` pins the fetch body. This webhook-only
event uses the existing PR-watch visibility rules. It is published only as
`github_pr_dequeued.v1`; fetch it with `events_get` (default `version: 1`).
Unlike legacy change events, this new body is a compact projection with six
fields rather than the general changed-item envelope. `sender` is GitHub's
login, not proof of a human actor. Delivery identity is in the notice's
`event_key` header; identical timestamps do not collapse separate dequeues.
