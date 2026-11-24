# Entorhinal role-claim vectors

`role-claims-v1/` is copied byte for byte from Entorhinal's
`test-vectors/role-claims-v1/` at tag `hub-only-samples-v1`, commit
`291c1eddafaad4098309a8c28c23d62aaa1e1a64`. Entorhinal's `records.json`
comes from its real `role.read` and `role.take` handlers and is byte-compared in
its CI. The tag also includes hub-mode samples.

| File | SHA-256 |
| --- | --- |
| `records.json` | `28d9542b066adfbba61b2e2d8b87d5ace09b1b95bb823699a0a8c14748312184` |
| `README.md` | `b218c11d81c1cebd01d2a24569da5be03ae6074be09cf9b4f3323f4cff53fc87` |
| `fence-hub.json` | `253be7298977a4ee2e6f07bd33cb933a8f7e69f2b9e7cf80002bcaa34fcef02b` |
| `handback-requested.json` | `8390995b7a3f31eaa5b8f526e321a7577f7b66d5538023a88dc7d2d89081eac5` |
| `read-hub.json` | `48e2064b773ff160fcec2dd024160ac421d3080c9cd20d4c6a771065d8cbc0eb` |
| `SHA256SUMS` | `30fed210d756cc2a206f6cc2d11808277d2c2356716878d757a68fd22ec08c9e` |

Do not edit these files. To update them, copy a newer Entorhinal commit's files
unchanged and record its tag, commit, and checksums here.

The tests in `src/connector_home_tests.rs` retarget the `never_read` reply in
`records.json` to `connector_home` and verify that it does not admit effects.
The other case is a refused `role.take` request from Plexus. The test fails
on any case name it doesn't know.

Both `read-hub.json` replies are retargeted from dreamer roles to
`connector_home`. The tests check that a reply for another role cannot grant
admission, that health records `source: "hub"`, and that stale replies do not
replace a confirmed snapshot. Plexus never calls `role.take`; the operator
runs `ck roles take`.
The `handback-requested.json` reply is tested as an unexpected answer to
`role.read`: the reader rejects it, leaves admission unchanged, and keeps
refusing effects until a fresh read confirms the hold. `fence-hub.json` is
included to preserve the upstream corpus, not replayed by the connector-home
reader.
