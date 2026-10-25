# ENTO project-identity reply samples

Copied byte for byte from
`crates/cortexkit-project-identity/test-vectors/project-resolve-v1/` in
[commons](https://github.com/cortexkit/commons), commit
`9834c6652abd47d62d49e91d73e64dd07f67d94f`.

Only the two operations Plexus calls are vendored: `resolve-remote.json`
contains eight samples, and `enumerate.json` contains one. The upstream
`resolve.json`, `resolve-root-records.json`, and `resolve-project-id.json`
are deliberately omitted because Plexus does not call those operations.
The upstream README and SHA256SUMS cover the larger bundle and are not copied.
This README is Plexus's own provenance record.

| File | SHA-256 |
| --- | --- |
| `resolve-remote.json` | `e0504720dc0f4a81b532fbe4e0cfa4a43d0fa1b218f703cbc3efca5387e17cba` |
| `enumerate.json` | `89afedb88fa4ddec219f4932df22f26ca8395022c5c1dd399e3e50c9d50b94dd` |

The upstream samples are captured handler replies, with paths and generated
values normalized by commons. The replay test pins both hashes and recognises
every case before checking Plexus's ownership decision. The final remote
sample captures a refusal to a malformed request; Plexus always supplies both
request params, but must still treat that refusal as unanswered.

The copied data is MIT licensed, Copyright (c) 2026 Ufuk Altinok. The license
text is the same as this repository's root `LICENSE`.
