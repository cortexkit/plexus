# Governed pull request ready/draft writes

The GitHub bot facade accepts `pr ready` with a required boolean `undo`: false
marks an owned PR ready for review, true converts it to a draft. The request
body is carried in the existing `github` tool's `bot_request` operation, with
`request_nonce` beside the request. AFT renders the result envelope.

## Live deployment — pending: run at deploy

These steps change the running service's database and catalog, so an
operator runs them, never an automated worker. Deploy in this order:

1. Install the new binary first, so the actions the catalog adds are served by
   code that maps `pr ready` to them and sends GraphQL requests without the
   repository fields.
2. Install `catalog/github_rest.jsonc` and restart so the reviewed catalog is
   ingested.
3. Run `handle-grant` for `mark_pull_request_ready`,
   `convert_pull_request_to_draft`, and the pre-read `github.pull_request.get` on
   every bot. Both writes require that pre-read; fresh imports imply it from
   either write grant. A bot onboarded after this release can take both writes
   in the `--actions` list of `ck-plexus-admin onboard-github-bot`, which
   imports, binds and grants it with one Touch ID confirmation; `handle-grant`
   stays the command for bots that already exist.

AFT's `gh` shim sends these requests only once its signed list of allowed `gh`
commands (manifest version 19) includes `pr ready`. Release that manifest after
plexus serves `pr ready` with both `undo: false` and `undo: true`.
No GitHub App permission widening is intended: the mutations use the existing
installation token and pull-requests write permission.
