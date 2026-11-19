# Entorhinal role-claim vectors

`role-claims-v1/` is copied byte for byte from Entorhinal's
`test-vectors/role-claims-v1/` at tag `hub-samples-v1`
(tag object `31d31a7b25710e0a234a7f10cc1fe6e476cd9608`,
commit `63cf03302af2985810cbc10e822ddf3cc6bcae20`). Entorhinal's `records.json`
comes from its real `role.read` and `role.take` handlers and is byte-compared in
its CI. The tag also includes hub-mode samples.

| File | SHA-256 |
| --- | --- |
| `records.json` | `d77d23708b39f6c3ae645151f3cd0dc259655e03892877fd67408d15ca889092` |
| `README.md` | `dac01da28600a4473f03ff0a08b2df3839dc642bc95ebc9f7ad52584b81ec893` |
| `fence-hub.json` | `253be7298977a4ee2e6f07bd33cb933a8f7e69f2b9e7cf80002bcaa34fcef02b` |
| `handback-requested.json` | `8390995b7a3f31eaa5b8f526e321a7577f7b66d5538023a88dc7d2d89081eac5` |
| `read-hub.json` | `48e2064b773ff160fcec2dd024160ac421d3080c9cd20d4c6a771065d8cbc0eb` |
| `SHA256SUMS` | `486de78b2d1774b5d7d7910abc69b92b511482f2c4bd8d690aa9faf3e2f0108a` |

Do not edit these files. To update them, copy a newer Entorhinal commit's files
unchanged and record its tag, commit, and checksums here.

The tests in `src/connector_home_tests.rs` replay every `role.read` case in
`records.json` through Plexus's real reader. They check that an answer about
another role cannot grant admission, then change the reply's `role` field from
`x` to `connector_home` in memory to test each state. The two `role.take` cases
are only checked to be take requests. The test fails on any case name it
doesn't know.

Both `read-hub.json` replies are retargeted from dreamer roles to
`connector_home`. The tests check that health records `source: "hub"` and use
in-memory variations of `held_here` and `stale` to check admission and snapshot
preservation. Plexus never calls `role.take`; the operator runs `ck roles take`.
The `handback-requested.json` reply is tested as an unexpected answer to
`role.read`: the reader rejects it, leaves admission unchanged, and keeps
refusing effects until a fresh read confirms the hold. `fence-hub.json` is
included to preserve the upstream corpus, not replayed by the connector-home
reader.
