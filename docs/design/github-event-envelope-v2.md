# GitHub event envelope v2

Plexus publishes v2 notices beside v1 on
`ck.<acct>.event.plexus.<event_name>.v2`. The versions share an event key and
filter labels, but each notice has its own digest and publication acknowledgement.
V1's transport message id remains the bare `event_key`, with unchanged headers.
V2's transport id (`Nats-Msg-Id`, also the bus message id) is `<event_key>.v2`,
and its extra `event_key` header carries the unchanged bare fetch key. JetStream
deduplicates ids across an entire stream, not per subject; equal ids would silently
suppress the second version. V2 consumers must fetch using its `event_key` header,
not the version-qualified transport id. The manifest declares this v2-only header
beside the unchanged per-event filter labels.
V1 subjects, stored bodies, list responses, and the default fetch remain unchanged.

## Publish receipts and retries

The bus 0.3.0 publisher returns a `PublishReceipt` with `stream_sequence()` and
`duplicate()`. Plexus preserves that receipt through its NATS adapter. The outbox
drain treats a duplicate acknowledgement as idempotent success for both versions:
it logs at DEBUG through the `plexus.bus` shadow logger, including subject,
transport id, event key, and stored stream sequence, then stamps that version
published. A crash after publishing but before stamping therefore leaves one
stream entry and a pending marker that the next drain can finish.

Each canonical row is unique by event key; insertion preserves the first stored
body, digest, event name, and labels. The only production publisher is the outbox
drain, which deterministically uses the bare event key for v1 and
`<event_key>.v2` for v2. Within this publisher, a duplicate on either id can only
be a retry of the same immutable notice, not a second event sharing a reusable
id. A receipt contains no prior body or digest to diagnose an externally injected
id collision, so Plexus does not invent a retry-versus-collision distinction.
Transport errors still leave the version pending. Duplicate suppression applies
only within the stream's configured window (two minutes by default); after that
window, a retry can create another entry with the same stable notice id.

## Stored representation

The first committed copy of a change owns its envelope, whether it arrived by
webhook or polling. Plexus normalizes it at insertion, serializes it once using
JCS, and stores that string. The v2 digest is SHA-256 of exactly those UTF-8 bytes;
fetch returns that same string, without reconstructing it from the v1 body.

Each field listed for a kind is always present. Unknown values are JSON `null`,
not omitted. Fields belonging only to another kind are not included. There are
no labels in the envelope, and normalization adds no GitHub requests. CI-job
envelopes stored before `workflow_name` was added do not contain that field; their
stored bytes and digests remain unchanged. Likewise, CI-job and CI-run envelopes
stored before `actor`, `triggering_actor`, `event` and `head_repo_is_fork` were
added do not contain those fields, and keep their stored bytes and digests.

## Fields

All kinds contain:

| Field | Type | Meaning |
| --- | --- | --- |
| `event_key` | string | Stable shared event key |
| `kind` | string | `issue`, `pull_request`, `ci_job`, `ci_run`, or `release` |
| `repo` | string | Lowercase `owner/name` |
| `action` | string or null | Source action, as described below |
| `actor_logins` | array of strings or null | Issue/PR actor attribution; null for CI and release |
| `actor_unknown` | object or null | Issue/PR unknown-actor reason; null for CI and release |

### Issue and pull request

| Field | Type (or null) | Meaning |
| --- | --- | --- |
| `number` | integer | Issue or PR number |
| `title` | string | Title |
| `state` | string | Lowercase state |
| `url` | string | HTML URL; derived from repo and number when absent |
| `author` | string | Author login only |
| `updated_at` | string | Source update timestamp |
| `actor_logins` | array of strings | Actors found by existing enrichment |
| `actor_unknown` | object | Existing structured unknown-actor reason |
| `comment_url` | string | URL of an identified conversation comment |
| `comment_author` | string | Comment author login only |

For issue and PR envelopes, exactly one of `actor_logins` and `actor_unknown` is
non-null, including an empty actor list when enrichment knows there were no
actors. Unbound enrichment uses the existing structured `actor_source_unbound`
reason in v2 only, with class `unexpected` (`ActorSourceUnbound`); v1 retains its existing both-null representation. CI and
release envelopes always have both actor fields null. Both comment fields are
null for non-comment changes or when the comment cannot be identified. The
comment's target is the envelope's own `kind` and `number`.

Pull requests additionally always contain `draft` and `merged` (boolean or null),
and `head_ref` and `base_ref` (string or null), taken from the source when known.

PR conversation-comment webhooks do not directly publish a change; they make the
PR watch due, preserving exactly one polled `github_pr_changed` notice per
version. When existing `pull_request_read` actor enrichment reads conversation
comments in its window, the newest comment supplies `comment_url` and
`comment_author`. Otherwise both are null. No additional requests are made.

### CI job and CI run

Each field is present in CI-job and CI-run envelopes and nullable when the source lacks it:

| Field | Type (or null) |
| --- | --- |
| `id` | integer |
| `name` | string |
| `conclusion` | string |
| `status` | string |
| `head_branch` | string |
| `head_sha` | string |
| `url` | string (source `html_url`) |
| `run_id` | integer |
| `run_attempt` | integer |
| `completed_at` | string |

For CI jobs, `completed_at` comes from the job's `completed_at`. For CI runs,
GitHub provides no `completed_at`, so both webhook and polling envelopes use the
run's `updated_at` when `status` is `completed`; otherwise the field is `null`.
This normalization applies only to newly inserted envelopes. Previously stored
envelopes remain byte-identical, including any `completed_at: null` value.

CI-job envelopes additionally always contain:

| Field | Type (or null) | Source |
| --- | --- | --- |
| `workflow_name` | string | Webhooks: `workflow_job.workflow_name`; polling: `workflow_name` on the job object. Missing, empty, or non-string values are `null`. |

#### Run actor, event and fork status

CI-job and CI-run envelopes both always contain these four fields, describing
the workflow run (for a job, the run attempt the job belongs to). Other kinds
never contain them. They let a consumer tell runs started by its own accounts
from runs on outside contributors' branches.

| Field | Type (or null) | Value |
| --- | --- | --- |
| `actor` | string | The run's `actor.login`: the account whose push or pull request started the workflow. |
| `triggering_actor` | string | The run's `triggering_actor.login`: the account that started this run attempt. A re-run changes this field and leaves `actor` alone. |
| `event` | string | The run's `event`, for example `push`, `pull_request`, `pull_request_target`, `merge_group`, `schedule` or `workflow_dispatch`. |
| `head_repo_is_fork` | boolean | `true` when the run's `head_repository.full_name` differs from its `repository.full_name`, compared ASCII case-insensitively; `false` when they are equal. |

Null rules: a missing, `null`, empty or non-string source value is `null`.
`actor` and `triggering_actor` are read independently; neither ever falls back
to the other. `head_repo_is_fork` is `null` when either repository name is
missing or empty.

Sources:

- **CI run, webhook and polling.** The stored item is GitHub's full workflow-run
  object (`workflow_run` in the webhook, the `get_workflow_run` response when
  polling), so the values are read from it directly.
- **CI job, polling.** The poller reads each run attempt (`get_workflow_run`)
  before listing its jobs, and passes that run's values to the job envelopes.
  No request is added. The values are not stored in the job's v1 body or in the
  CI cursor: both hold the run metadata object, which older binaries read with
  unknown fields refused, so it is unchanged.
- **CI job, webhook.** A `workflow_job` delivery does not carry these values.
  The relay remembers them, in memory, from every `workflow_run` webhook
  (`requested`, `in_progress` and `completed`), keyed by lowercase repository
  full name, run id and run attempt. A later job webhook for that run attempt
  takes its values from there. A job whose run attempt was not remembered gets
  `null` for all four. The cache holds at most 10,000 run attempts, evicting the
  oldest first, and forgets an attempt 24 hours (by relay receipt time) after
  its latest `workflow_run` webhook. It is empty after a restart. Remembering a
  run does not admit it: `workflow_run` webhooks that are not `completed` still
  publish nothing.

The first stored copy of an event owns its envelope, so a job first seen by
webhook without a remembered run keeps `null` values even if a later poll could
have supplied them.

### Release

The deployed GitHub App deliberately has no Contents permission and receives no
release webhooks. Release envelopes currently come only from polling; the
normalizer also accepts the release item shape if permissions change later.

| Field | Type (or null) |
| --- | --- |
| `id` | integer |
| `tag` | string (source `tag_name`) |
| `name` | string |
| `url` | string (source `html_url`) |
| `published_at` | string |

## Action semantics by source

Webhook actions preserve GitHub's action, including `opened`, `edited`, `closed`,
`reopened`, `synchronize`, `created` for comments, and `completed`.
Polling reports the coarser `opened` when non-null `created_at` equals
`updated_at`, otherwise `updated`. Therefore action is coarser when polling saw
the change first. Consumers must not use it as an exact reconstruction of every
GitHub transition. Comment fields may also depend on which source saw the change
first and which comments existing enrichment could identify.

## Versioning, visibility, and retention

`events_get` and `events op:get` accept only `event_key`, `event_name`, and the
optional integer `version` (`1` or `2`). Omitting it selects v1. Visibility is
checked exactly as before. A v2 request for an old row without an envelope
refuses `event_not_visible`, just like an unknown or inaccessible key; there is
no fallback to v1.

Migration 47 adds three nullable columns on `event_outbox`: `envelope_v2`,
`digest_v2`, and `published_v2_at_ms`. This minimal shape reuses the existing v1
marker row and its routing labels without changing its primary key or v1 ack.
The digest is saved alongside the canonical string at insertion. Migration 47
is additive and does not backfill old rows. The v1 publication
marker remains in place; a separate nullable v2 acknowledgement tracks the
second notice. A missing v2 envelope means no v2 work, not pending work. Pending
work in either version protects the body from retention. The body is saved
before publication and each marker is acknowledged only after its own JetStream
ack, so a failed version does not prevent publication of the other. The shared
event catalog drives both publication subjects and manifest declarations.

## Verification prerequisite

The real-stream regression test
`bus::tests::real_nats_stream_stores_both_versions_with_distinct_transport_ids`
requires `nats-server` on PATH (JetStream support, version 2.10 or newer). It
starts a temporary server bound only to loopback, creates an isolated event
stream, and reads its stored messages after publishing through the production
NATS adapter. CI installs the pinned, checksum-verified release declared in its
workflow before module tests and mutation shards. The test checks that both
versions are stored under distinct ids, and that publishing those same notices
again yields duplicate receipts with their original stream sequences and no
additional entries. The in-memory regression
`bus::tests::duplicate_retry_after_publish_before_stamp_finishes_both_versions`
checks the publish-before-stamp crash/retry claim and the DEBUG diagnostic using
bus 0.3.0's in-memory stream: the drain stamps both pending versions without
adding entries. The NATS server child is killed and reaped on success, failure,
or timeout. Server startup has its own named three-second deadline. Cleanup
kills the service and reaps it through the shared bounded child helper, with a
two-second deadline, so a stuck child cannot hang an async test destructor.
