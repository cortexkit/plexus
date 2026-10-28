# Structure

```
catalog/                 Reviewed vendor manifests (*.jsonc), ingested at startup
crates/
  plexus-core/           Domain, store, governance, transports, poller, scheduler
    src/                 One module per concern (see ARCHITECTURE.md code map)
    examples/            migration_rehearsal.rs
    tests/               Integration tests; fixtures/ holds vendored wire goldens
  plexus-module/         ck-plexus daemon and ck-plexus-admin operator CLI
    src/bin/             ck-plexus-admin
    examples/            facade_call.rs, vault_call.rs (live diagnostic clients)
  plexus-probe/          QuickJS/WASI probe sandbox and its embedded guest
  plexus-conformance/    Conformance checklist, stub vendors, live drift checker
docs/design/             Current contracts: wire formats, governance, concurrency
docs/rollout/            Operator rollout guides
docs/explainer/          Project overview page
scripts/                 Test gate, trains, release, staging, deploy acceptance
```

## Where new code goes

- **A vendor:** a new `catalog/<vendor>.jsonc`. Core's `manifest::tests::every_shipped_manifest_is_valid` and `crates/plexus-conformance/tests/it/shipped_catalog_ingests.rs` prove the manifest parses. Review output contracts as well as input schemas; credential-returning actions are never declared. See `docs/design/manifest-model.md`.
- **A wire tool or operation:** a handler in `crates/plexus-module/src/lib.rs`, declared in `crates/plexus-module/src/manifest.rs`.
- **A GitHub read:** use the separate `github_read` tool and its shared GitHub read implementation; the `github` facade serves only `bot_request`, `bindings.read`, and `bindings.read_for_agent`.
- **Agent identity:** daemon scope stamps in `crates/plexus-core/src/scope.rs`, carried by route bindings in `crates/plexus-module/src/lib.rs`. Bot writes resolve the stamped agent's bound handle in `github/facade/gates.rs`; identity-token arguments are refused centrally before tool dispatch.
- **A governance gate:** `authorize` in `crates/plexus-core/src/governance.rs`.
- **A table or column:** append a `Migration` to `MIGRATIONS` in `crates/plexus-core/src/storage.rs` and rehearse it with `examples/migration_rehearsal.rs`.
- **A cursor strategy:** implement `CursorStrategy` in `poller.rs`, add the `CursorKind` variant in `manifest.rs`, and widen the `trigger_subscriptions` CHECK constraint with a migration.
- **A GitHub bot request kind:** map it in `crates/plexus-core/src/github/facade/request_map.rs` with its argument allowlist and pre-reads, list its legs in `facade/effects.rs`, declare its actions `facade_only` in `catalog/github_rest.jsonc`, and add it to the import's action table in `github/control/mod.rs` so imported agents are granted it.
- **A transport:** a new `crates/plexus-core/src/<transport>.rs`, routed in `crates/plexus-module/src/composition.rs` and accepted by manifest validation.
- **Tests:** unit tests under `#[cfg(test)]` beside the code; integration tests in `crates/*/tests/`. Scratch files go through `test_scratch`, never a raw `temp_dir()`. A test that runs `ck-plexus` or `ck-plexus-admin` launches it through `cortexkit_test_support::ckdev_binary`, so the process is named `ckdev-...`. Deployed executables retain the `ck-plexus` and `ck-plexus-admin` names; the distinct `ckdev-...` filenames keep test launches distinguishable from them in process listings.

## Naming

Snake case for files and functions, kebab case for crates, PascalCase for types. Manifests are named after the vendor (`github_rest.jsonc`).
