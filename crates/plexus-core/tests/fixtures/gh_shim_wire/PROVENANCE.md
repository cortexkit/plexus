# Where these fixtures come from

Copied byte-for-byte from the AFT repository, commit `5d879f59f`, directory `docs/investigations/gh-shim-wire-goldens/`. All 56 files were compared against that commit after copying and none differed. Everything in this directory except this file is AFT's. (The first copy was taken at `d5bcb0c0a`, an ancestor; `5d879f59f` adds the own-issue `issue edit` captures.)

## Which manifest version these describe

The v14 rows (`issue create`, the body-only comment PATCH, own-issue `issue edit`) exist in the shim's code but refuse as unclassified until a signed v14 manifest declares them. These fixtures were captured against a dev-signed v14 test manifest in an isolated state directory, so the v14 requests here are what the shim sends once a v14 manifest is signed. Plexus must serve them, because they route the moment v14 activates.

The `gh` shim is AFT's, so AFT owns these bytes. They are copied, not referenced across repositories, because CI checks out only this repository: a test reading them from AFT's tree would pass on a developer machine and be unrunnable in CI.

## What is real and what is derived

- `requests/` is REAL. Request payloads captured from the shim binary, running against a loopback stand-in for the route holder in an isolated state directory: v1 issue and PR comment, PR review, issue reaction; v10 edit-last on an issue and a PR comment; v12 issue close and reopen, PR close and reopen; v14 issue create and the body-only comment PATCH. `session-v1-issue-comment.frames.json` holds every frame of one session.
- `exchanges/` holds success, refusal and outcome-unknown exchanges, each with the exit code and stderr the shim produced.
- The own-issue `issue edit` captures (title/body and label edits, each with success, generic-refusal and not-own exchanges) carry the not-own refusal code `issue_edit_not_own`, taken from prefrontal's gh.route. Their response bytes are DERIVED from that code, not captured, and the success body reuses the comment-shaped result because no real issue-edit success body existed.
- `responses/` is DERIVED, not captured. These are the response shapes the shim's parser accepts, read from its source (each file cites the lines). No real response bytes from a route holder existed when they were written. Treat them as the shim's contract for what it will accept, not as evidence of what any server sent.
- `exits.md` maps each response to the shim's exit code (0, 86 or 87).

## Two rules for anything that reads these

1. **Parse the JSON; never compare bytes or rely on key order.** The requests happen to be in insertion order only because an unrelated dependency turns on serde_json's `preserve_order` feature in AFT's build. Key order is not part of the contract.
2. **Ignore AFT's `tests/fixtures/gh_shim/gh-route-request-v1-golden.json`.** It is stale (sorted keys, `manifest_version 1`, not what the shim sends).

## When these go stale

AFT's `gh_shim_wire_goldens_test` fails if the shim's bytes change. When it does, AFT updates its directory, and these copies must be re-taken from the new commit and this file's commit reference updated.
