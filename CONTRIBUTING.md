# Contributing to ck-plexus

## Open an issue before writing code

Every change starts as an issue, tagged `design discussion` or `bug`. We read it,
discuss if there is anything to discuss, and give an explicit go. A pull request
comes after that go, not before it.

If a pull request arrives without one, we will ask for the issue rather than
review the diff. That is not a rejection of the work; it is the conversation
happening in the order that costs least.

## Why, stated plainly

A design question costs about ten lines to settle in an issue. The same question
costs several hundred lines and two review rounds once a working implementation
exists, and the author has already paid for all of them.

There is a second cost that is easier to miss. A reviewer facing finished,
working code is under quiet pressure to find a way to take it, because saying no
means discarding someone's effort. An issue has no such pressure, which makes it
the honest place to decide whether a change belongs at all.

This gate is cheap because most issues get a go quickly. A bug with an obvious
shape (a build that fails, a diagnostic that says nothing useful, a manifest
that refuses a valid file) needs an issue only so the reproduction is written
down somewhere, and the go usually arrives in the first reply.

The expensive case is the one the rule exists for: a change that works, is well
tested, and answers a design question nobody has ruled on. That decision belongs
to the project before the code is written, not to a reviewer afterwards.

## What makes an issue easy to say yes to

- The behaviour you observed, and what you expected instead.
- What you ran, on what platform, and what it printed. Verbatim beats summarised:
  a truncated error has cost this repository real time more than once.
- For a design change: what the current shape prevents you from doing. The
  problem is more useful than a proposed patch, because it leaves room for a
  solution neither of us has thought of.

The issues that move this project fastest name one concrete failure and attach
the evidence for it.

The [issue forms](.github/ISSUE_TEMPLATE/) ask for exactly this. Never paste
credentials, vault references, tokens, connection files, store contents or
private repository data into an issue; redact them, and report anything
security-sensitive privately as described in [SECURITY.md](SECURITY.md).

## Building

Every external dependency comes from crates.io, and the committed `Cargo.lock`
pins each one to an exact version. The subc and cortexkit wire crates are also
pinned exactly in the workspace `Cargo.toml`, because two copies of one of them
in the graph would not interoperate. No sibling repository checkout is needed.
See [README.md](README.md) for prerequisites and build commands.

## Checks you can run

All of these run from a clean checkout with the prerequisites in the README.
They are the checks CI's test job runs on a pull request.

- `./scripts/rust-test-gate.sh`: source-convention checks, the rejection of
  path dependencies outside this repository, the operator-script regression
  tests (Python 3.11 or newer), `cargo fmt --check`, clippy with warnings
  denied, and the workspace tests, all with `--locked`. One bus test starts a
  real `nats-server` and fails if it is not on `PATH`.
- The conformance fixtures, which run against stub vendors with no network
  access:

  ```sh
  cargo build --locked -p plexus-conformance --bin plexus-conformance
  target/debug/plexus-conformance list
  target/debug/plexus-conformance run --fixture <name>
  ```

- `cargo run --locked -p plexus-module --bin ck-plexus -- --check-catalog catalog`
  when you change a vendor manifest.
- The mutation catalogue check, `ckdev-mutate check`, after installing the
  pinned runner as shown in [docs/mutations.md](docs/mutations.md).

The train, staging, release and deployment-acceptance scripts under `scripts/`
are maintainer tooling. They need repository push rights or a live operator
installation, and a pull request never needs them.

## Once a change has a go

- `./scripts/rust-test-gate.sh` must pass.
- `Cargo.lock` is committed and enforced. If a change needs a different
  dependency version, make the lock change deliberately and say so in the pull
  request, rather than letting it ride along in an unrelated commit: a lock
  rewrite hidden that way is invisible to anyone bisecting a dependency change
  later.
- Tests are expected to be able to fail for the reason they claim. A test whose
  setup writes the value it then asserts, or an assertion that passes when the
  code under test is deleted, is worth less than no test, because it reports
  coverage that does not exist. Name the change to the code under test that
  makes your new test fail, and show it failing.

## Where things are

- [ARCHITECTURE.md](ARCHITECTURE.md): the governance pipeline, the rules that
  bite, and a code map.
- [STRUCTURE.md](STRUCTURE.md): the directory layout and where new code goes.
- [docs/design/](docs/design/): design notes and the contracts plexus serves.
- [docs/mutations.md](docs/mutations.md): the checked-in mutation catalogue and
  its runner.
