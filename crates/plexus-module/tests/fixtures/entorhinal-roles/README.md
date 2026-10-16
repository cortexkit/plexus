# Entorhinal role-claim vectors

`role-claims-v1/` is copied byte for byte from Entorhinal's
`test-vectors/role-claims-v1/` at commit `53d7b47`. Entorhinal generates these
files from its real `role.read` and `role.take` handlers and byte-compares them
on every CI run, so plexus's decoding is tested against what Entorhinal actually
sends.

| File | SHA-256 |
| --- | --- |
| `records.json` | `2caca960dc3e3e1bf26dab9a8601054ca312c71ec448ed9bb44e35a49e634242` |
| `README.md` | `26d1add95c0a98584566e13006043ca473a356003cd219e379d9ddcdeea846a3` |
| `SHA256SUMS` | `9965ec92352b6d8e70a09b7c42fbb3b0aa692be2e761965e7c7add1707353ec3` |

Do not edit these files. To update them, copy a newer Entorhinal commit's files
unchanged and record its commit and checksums here.

`entorhinal_role_vectors_through_real_reader` in `src/connector_home_tests.rs`
feeds every `role.read` case through plexus's real reader and checks it against
plexus's own expectations (which state each answer leads to, and whether plexus
may serve). The vectors read a placeholder role named `x`; the test checks that plexus
refuses an answer about any role but `connector_home`, then renames the role in
memory to test each state. Plexus never calls `role.take`, so the two take cases
are only checked to be take requests. The test fails on any case name it doesn't
know.
