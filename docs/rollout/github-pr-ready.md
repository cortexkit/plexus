# Governed pull request ready/draft writes

The GitHub bot facade accepts `pr ready` with a required boolean `undo`: false
marks an owned PR ready for review, true converts it to a draft. The request
body is carried in the existing `github` tool's `bot_request` operation, with
`request_nonce` beside the request. AFT renders the result envelope.

## Live deployment — pending: run at deploy

Workers do not access the live store. Deploy in this order:

1. Install the new binary first, so it understands the new actions and transport
   projection before the catalog advertises them.
2. Install `catalog/github_rest.jsonc` and ingest the reviewed catalog.
3. Run `handle-grant` for `mark_pull_request_ready`,
   `convert_pull_request_to_draft`, and the pre-read `github.pull_request.get` on
   every bot. Both writes require that pre-read; fresh imports imply it from
   either write grant.

AFT can release its v19 signed manifest after plexus serves `pr ready` with
both `undo: false` and `undo: true` through the governed bot facade.
No GitHub App permission widening is intended: the mutations use the existing
installation token and pull-requests write permission.
