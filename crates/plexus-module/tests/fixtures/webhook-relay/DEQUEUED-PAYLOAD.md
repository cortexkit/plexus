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
Unlike legacy change events, this body is a compact projection with seven
fields rather than the general changed-item envelope. `observed_at` is the
relay receipt time, when the item first reached CortexKit, in RFC 3339 UTC with
millisecond precision. It is added by Plexus, not taken from the GitHub payload.
Bodies stored before this field was introduced lack it and retain their exact
bytes and digests. Comparing observation and activity times distinguishes a
delivery delay from old news; publication time is not observation time.
`sender` is GitHub's
login, not proof of a human actor. Delivery identity is in the notice's
`event_key` header; identical timestamps do not collapse separate dequeues.
