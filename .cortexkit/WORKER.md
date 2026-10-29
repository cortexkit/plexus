# Plexus worker rules

## Building, testing and delivery

- Build and test on Linux through `runon` or `ck motor run`, never on the Mac.
  The no-compile fast phase of `scripts/prepush.sh` is the exception: it runs
  locally before dispatching the full Linux gate at 8 vCPUs.
- Commit the intended changes, then run `scripts/prepush.sh --fast` locally
  and `scripts/prepush.sh --full` with `runon: "linux,8c,net"` (network enabled
  for pinned tool downloads). Paste both commit-naming PASS lines in the delivery.
  Changing the commit requires another run. Worker sandboxes cannot connect to
  Motor directly; do not invoke plain `scripts/prepush.sh` from a worker shell.
- From a shell with access to `ck motor`, plain `scripts/prepush.sh` runs fast
  locally, dispatches full through Motor, and writes a local receipt valid for
  24 hours. The train and pre-push hook require this receipt for the pushed
  commit and still require green CI before landing main. Separate phase runs do not write a
  combined receipt.
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
