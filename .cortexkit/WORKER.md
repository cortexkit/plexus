# Plexus worker rules

## Building, testing and delivery

- Build and test on Linux through `runon`, never on the Mac. Use `linux,4c` for
  one crate's tests and keep the normal build directory: don't set your own
  `CARGO_TARGET_DIR`.
- Run only the tests for what you changed: the test modules that cover the
  files and behaviour you touched, selected by module or test name
  (`cargo test --locked -p <crate> <module>::`), plus `cargo fmt --check` and
  `cargo clippy --locked -p <crate> --all-targets -- -D warnings` for the crates
  you changed. Also run tests your change can break by name, for example the
  manifest, catalog-fixture or `gh_shim_wire` contract tests when you touch
  those surfaces.
- Run `scripts/prepush.sh --fast` locally. It compiles nothing and takes seconds.
- For a bug fix, show once that the new regression test fails without the fix.
- Never run a whole crate or workspace suite, `scripts/prepush.sh --full`,
  plain `scripts/prepush.sh`, or `scripts/rust-test-gate.sh`. The head runs the
  full gate once over each merged batch before landing.
- If a test that looks unrelated fails, rerun that one test by name on the base
  commit, never the suite, and report both results.
- A filtered run that takes more than about 15 minutes means the filter is too
  broad. Narrow it rather than waiting in long `bash_watch` loops.
- Commit your changes and list in the delivery exactly which test filters you
  ran, with their pass counts.

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
