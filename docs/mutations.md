# Mutation catalogue

[`mutations.toml`](../mutations.toml) pairs deliberate source breaks with the exact
tests that must detect them. It covers silent, costly failures in authority,
crash safety, data loss and wire contracts: empty grants, stale approvals,
credential handling, receipt replay, reconciliation, migrations and transport
payload preservation. An ordinary green suite does not establish that each
individual guard is load-bearing; a deliberate break must make its named test
fail for the intended reason.

Mutation replay supplements, rather than replaces, `scripts/rust-test-gate.sh`.
Every break is temporary, marked `NON-VACUITY BREAK`, and restored by the runner.
`Cargo.lock` must remain unchanged. A hung test is a harness defect, never proof
that the guard was caught.

## Verdicts

| Verdict | Meaning and required response |
| --- | --- |
| **CAUGHT** | The named test failed with the required assertion message. Without `--broad`, other package test targets have not been audited. |
| **CAUGHT_BROADLY** | The named assertion failed, but tests in other targets also failed. Review their actual assertions; narrow incidental failures or document a shared-property HUB. |
| **HUB** | A reviewed broad catch: the collateral tests enforce the same stated property, and the observed other targets exactly match `hub_targets`. Newly observed targets require review. |
| **EQUIVALENT** | The replacement does not change observable behavior. Explain the equivalence; do not use it to excuse a surviving real guard. |
| **RED_FOR_ANOTHER_REASON** | Tests failed, but the expected test/message did not establish the intended property. Diagnose the failure before claiming a catch. |
| **TIMED_OUT** | Build or tests exceeded their deadline. Bound hanging fixtures or diagnose build contention; never count a timeout as a catch. |
| **ERROR** | The runner could not establish a valid result, for example inconsistent test accounting or an invalid anchor. Fix or diagnose the error and replay. |

## Replay and maintenance

Use `ckdev-mutate 0.9.8` from
[commons revision 0c99c7e16d8ae22b6e114136b6b7b68be6f1394e](https://github.com/cortexkit/commons/tree/0c99c7e16d8ae22b6e114136b6b7b68be6f1394e).
The [runner README](https://github.com/cortexkit/commons/blob/0c99c7e16d8ae22b6e114136b6b7b68be6f1394e/crates/cortexkit-mutate/README.md)
defines anchor matching, multi-file edits and report fields. This revision
keeps its lock and output captures in the temp directory, not under `.git`, so
`check` and replays also run where `.git` is read-only, as in remote build jobs.

From a clean checkout:

```sh
cargo install --locked --git https://github.com/cortexkit/commons \
  --rev 0c99c7e16d8ae22b6e114136b6b7b68be6f1394e cortexkit-mutate
ckdev-mutate --version
cargo --version
ckdev-mutate check
mkdir -p target/mutations
ckdev-mutate run --only gap-reconciliation-read-risk-preflight --report target/mutations/one.json
ckdev-mutate run --all --report target/mutations/all.json
ckdev-mutate run --all --broad --report target/mutations/broad.json
```

`check` validates anchors and exact full test names without mutating source.
`--allow-dirty` is for deliberate local work; stage the live files before manual
mutation proofs so restoring a mutant cannot discard the implementation.
Use `cargo t` (the repository alias for `test --locked`) and `test_scratch` for
fixture files. Never refresh the lockfile as a side effect of a proof.

### Add a control

1. Name the safety property and inspect the guard in current production source.
2. Choose an exact anchor and a replacement marked `NON-VACUITY BREAK` that
   isolates that property, rather than changing unrelated behavior.
3. Name a real test and the assertion message printed when the guard is removed.
   If two guards produce the same code, discriminate by observable behavior.
4. Run `prove` to append only a caught control, then audit its breadth:

```sh
ckdev-mutate prove --id new-control --guards 'the safety property' \
  --file crates/plexus-core/src/example.rs --old 'exact current anchor' \
  --new 'deliberate source break /* NON-VACUITY BREAK */' \
  --test-file crates/plexus-core/tests/example.rs --package plexus-core \
  --target='--test example' --expect-red exact_full_test_name \
  --expect-message 'the intended assertion' --build-timeout-s 3600 \
  --report target/mutations/new-control.json
ckdev-mutate check
ckdev-mutate run --only new-control --broad --report target/mutations/new-control-broad.json
```

The example paths and test name are placeholders; copy the real ones from source.
A broad catch must be narrowed or reviewed as HUB with the shared property and
exactly the observed other targets. A red suite alone is weaker evidence than a
named assertion with the other tests accounted for.

### CI

[CI](../.github/workflows/ci.yml) validates the catalogue in the Linux Test job
and replays selected controls in nonempty mutation shards. The planner
(`scripts/mutation-plan.py`) sizes the shard count to the selection: one shard
per 120 rows for a train replay, one per 80 rows for a broad replay, at most 16,
so each shard finishes inside the job's 180-minute limit. Train pushes select
changed rows with `--diff origin/main`. Main pushes replay nothing: a commit
reaches main only after its train's run replayed every touched row on that
exact commit, which the pre-push hook and `scripts/train.sh` enforce. The
nightly schedule at 03:23 UTC and manual runs replay all rows with `--broad`,
which catches interactions between changes that no single train's diff
selects. Only CAUGHT and HUB are accepted, and JSON reports are uploaded even
when a shard fails.

The planner computes selection before shard allocation, and the replay step
passes it to the mutation runner. `scripts/check-train-preconditions.sh` refuses
ref- or event-dependent job and step conditions except the explicit PR exclusion
on the mutation job. Train and main execute the same CI steps; main skips only
the mutation shards its train already ran, and fork PRs allocate no mutation
runners. Concurrency groups include the event name so main pushes
cannot cancel the nightly broad replay on the same ref.
