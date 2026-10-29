# Plexus worker rules

## Building, testing and delivery

- Build and test on Linux through `runon` or `ck motor run`, never on the Mac.
  The no-compile fast phase of `scripts/prepush.sh` is the exception: it runs
  locally before dispatching the full Linux gate at 16 vCPUs.
- Commit the intended changes, run `scripts/prepush.sh` before delivering, and
  paste its final PASS line in the delivery. A PASS is valid for that commit
  only; changing the commit requires another run. The train and pre-push hook
  require a recent PASS and still require green CI before landing main.
- For a bug fix, show once that the new regression test fails without the fix.

## Pre-approved: no need to ask

- Regenerate pinned fixtures with their documented generator, for example
  `PLEXUS_REGENERATE_CATALOG_FIXTURES=1` or
  `PLEXUS_REGENERATE_GH_ROUTE_REPLIES=1`, when the diff has only the stated cause.
- Re-pin catalog schema hashes for new actions only.
- Add test-only seams that do not alter shipped behavior.
- Fix comments flagged as unclear by the comment review.
- Merge main and keep both sides' changes.

## Ask first

- Anything agents or operators see, including tool schemas, refusal codes and
  reply shapes.
- Store migrations.
- Catalog changes that move an existing action's schema hash.
- Security boundaries: grants, scopes and credentials.
- Changes to vendored contract files.
- New dependencies.

## Plexus conventions

- The `gh_shim_wire` contract vectors are vendored by AFT. Report any change to
  them explicitly; do not quietly regenerate or edit the contract.
- Launch test binaries through `cortexkit_test_support::ckdev_binary` so they
  use `ckdev-...` process names, not production `ck-...` names.
- Use `plexus_core::test_scratch` for test scratch files and directories, not
  raw shared temporary paths.
- Use `diag!(<level> <component>: ...)` for daemon logging, not bare `eprintln!`.
