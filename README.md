# plexus

plexus is the connectors plane for CortexKit. It gives agents structured,
credentialed access to external services such as GitHub, Linear, Notion, Exa
and Google Calendar, without ever handing them a credential. It runs as
`ck-plexus`, a module supervised by the
[subconscious](https://github.com/cortexkit/subconscious) daemon (`ck-subc`).

Each vendor is a reviewed manifest in `catalog/`, reached over REST, a remote
MCP server, or a local MCP server run by a subc adapter. Every vendor call,
including poller reads and reconciliation read-backs, goes through one
governance pipeline: it checks the caller's grant, the action's policy and
severity, and any required approval, writes an audit row, and only then
resolves the credential from the [claustrum](https://github.com/cortexkit/claustrum)
vault and dispatches. plexus also polls subscribed vendors for events, runs
author-supplied probe scripts in a QuickJS/WASI sandbox, and serves the GitHub
writes of agents' GitHub App bots.

Structured interfaces come first. Driving a GUI is the job of a separate
computer and browser plane, for services with no structured interface.

## Repository map

| Path | Role |
|---|---|
| `crates/plexus-core` | Manifests, store and migrations, governance, transports, poller, scheduler and the GitHub bot facade. |
| `crates/plexus-module` | The `ck-plexus` module binary and the `ck-plexus-admin` operator CLI. |
| `crates/plexus-probe` | The probe sandbox: Wasmtime running an embedded QuickJS-NG guest (`guest/`). |
| `crates/plexus-conformance` | Conformance checklist, stub vendors and live drift checker. |
| `catalog/` | Reviewed vendor manifests (`*.jsonc`), ingested at startup. |
| `schemas/` | JSON schema for the GitHub App handle import inventory. |
| `scripts/` | The test gate, guest and release builds, and maintainer tooling. |

[STRUCTURE.md](STRUCTURE.md) says where new code goes, and
[ARCHITECTURE.md](ARCHITECTURE.md) describes the pipeline and its invariants.

## Prerequisites

- Rust 1.95 or newer, with `rustfmt` and `clippy`. The repository has no
  `rust-toolchain` file; CI uses the current stable toolchain. 1.95 is the
  minimum the locked Wasmtime release requires.
- Python 3.11 or newer, for the operator-script tests the gate runs.
- `nats-server` 2.15.0 on `PATH`, the version CI installs. One bus test starts
  a real JetStream server and fails without it. Release archives are at
  https://github.com/nats-io/nats-server/releases/tag/v2.15.0.
- Bash, for the gate script.

Every external dependency comes from crates.io and is pinned by the committed
`Cargo.lock`, so a fresh checkout builds with no sibling repositories.

Rebuilding the embedded probe guest additionally needs the `wasm32-wasip1`
Rust target; `scripts/build-probe-guest.sh` fetches and verifies the pinned
WASI SDK. The checked-in guest module is used otherwise, so ordinary builds do
not need either.

## Build and test

```sh
cargo build --locked -p plexus-module
scripts/rust-test-gate.sh
```

The build produces `target/debug/ck-plexus` and `target/debug/ck-plexus-admin`.
The gate runs source-convention checks, the operator-script tests,
`cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`
and `cargo test --workspace --locked`, one cargo command at a time.

CI also runs every conformance fixture against stub vendors:

```sh
cargo build --locked -p plexus-conformance --bin plexus-conformance
target/debug/plexus-conformance list
target/debug/plexus-conformance run --fixture <name>
```

## Running against a local subconscious daemon

Without a daemon, `ck-plexus` answers three checks and exits:

```sh
target/debug/ck-plexus --version
target/debug/ck-plexus --check-catalog catalog   # validate vendor manifests
target/debug/ck-plexus --smoke-probe             # run one guest through the probe sandbox
```

Otherwise `ck-plexus` runs only as a module launched by `ck-subc`; it is not a
standalone server. At startup it:

- reads the daemon connection file named by `--subc <path>` and connects to
  the daemon's first endpoint;
- proves it was launched by the daemon with a launch nonce the daemon passes on
  a file descriptor, and refuses to start without it;
- opens its SQLite store at the location the daemon assigns in the handshake.

It reads this configuration from its environment:

| Variable | Meaning |
|---|---|
| `PLEXUS_CATALOG_DIR` | Catalog directory. Required by release builds; debug builds fall back to this repository's `catalog/`. |
| `SUBC_MODULE_ID` | Module id; defaults to `plexus`. |
| `PLEXUS_AUDIT_RETENTION_DAYS` | Audit retention; defaults to 30 and must exceed the 7-day delete floor. |
| `PLEXUS_CKCRED_MODULE_ID` | Module id of the vault's credentials route. Without it, only credential-free vendors can be called. |
| `PLEXUS_MCP_STDIO_MODULE_ID` | Module id of the local MCP adapter, for vendors served by a local MCP server. Optional. |
| `PLEXUS_PREFRONTAL_MODULE_ID` | Module id of the Prefrontal route that serves the agent registry. Without it, agent lookups answer as unavailable. |
| `PLEXUS_PROJECT_ROOT` | Project root plexus names when it binds routes to other modules; defaults to `/`. |

Approval cards are filed with the module named `cingulate`. If that route
cannot be opened, plexus logs it and starts without approval cards.

The daemon's configuration (`subc.jsonc`) carries these in the module's `env`
block. The module entry itself is subconscious's format and is documented in
that repository; plexus does not yet document a complete entry.

With the module running, `ck-plexus-admin` is the operator client. It connects
as a direct client of the same daemon, issues binding tickets, and mints grants
and policies:

```sh
target/debug/ck-plexus-admin --help
target/debug/ck-plexus-admin list-grants --subc <connection file>
```

An operator intent that takes several authority-widening steps costs one Touch
ID confirmation when it runs as one composite command. Each previews by default
(writing nothing and contacting no vendor beyond what planning reads), refuses
before asking if anything in its plan is wrong, asks once with a summary naming
every change, and is safe to rerun:

| Command | Combines |
|---|---|
| `add-web-search-provider` | `issue-ticket`, `connections op=connect`, one search grant per caller |
| `add-write-connection` | `issue-ticket`, connect, a `connection_admin` grant to `direct`, `configure` with resource filters, invoke grants, optional allow policies |
| `add-poll-connection` | `issue-ticket`, connect, a poll grant to `direct`, `events_consume` grants |
| `widen-and-grant` | `widen-ceiling --apply` and the grants on the added actions, in one transaction |
| `onboard-github-bot` | `github.handle.import`, `github.handle.probe`, `handle-bind`, `handle-grant` (writes, reads, poll) |

Use the composite first. The single-step commands stay available as the manual
fallback; `ck-plexus-admin --help` documents both.

`cargo run --locked -p plexus-module --example facade_call -- <connection file> '<json>'`
sends one tool call to the running module and prints the reply, for example
`'{"name":"events","arguments":{"op":"list"}}'`.

Not documented yet: an end-to-end recipe that starts a fresh daemon with
plexus, the claustrum vault and the Cingulate consent module, enrolls a vendor
credential, issues a binding ticket and grant, and makes a first governed call.
The scripts under `scripts/` that stage binaries or run deployment acceptance
target the maintainer's own installation and are not that recipe.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): the governance pipeline, transports,
  triggers, probes, GitHub bot writes and the rules that bite.
- [STRUCTURE.md](STRUCTURE.md): directory layout and where new code goes.
- [docs/design/](docs/design/): design notes and the contracts plexus serves.
- [CONTRIBUTING.md](CONTRIBUTING.md): the issue-first workflow and the checks to run.
- [SECURITY.md](SECURITY.md): private vulnerability reporting and the threat model.
- [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md): embedded components, license
  elections and vendored test material.

## Contributing

Open an issue before writing code. A pull request follows an explicit go on
that issue rather than preceding it. [CONTRIBUTING.md](CONTRIBUTING.md) has the
reasoning and what makes an issue easy to say yes to.

## License

plexus is licensed under the [MIT License](LICENSE). Embedded components,
dependencies and copied test material keep their own licenses; see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
