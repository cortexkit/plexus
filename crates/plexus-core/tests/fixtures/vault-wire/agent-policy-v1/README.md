# Agent policy contract fixtures

These fixtures come from the Claustrum credential vault, tag `agent-policy-vectors-v1`
(commit `1d391cdf1c41e8108eacc4b58ce499912e83d802`).

The four policy reply goldens come from §17a, **Policy read samples**, in
`docs/wire-contract-v1.md` (source file SHA-256:
`02967be39f5bbb27b1b2ed3045c0e77ac8e4ce419fdc2a5571a34d07f653669d`).
Each file contains the JSON code block immediately following its matching
`<!-- golden:NAME -->` marker, copied verbatim without the Markdown fences,
including the newline before the closing fence.

| File | SHA-256 |
| --- | --- |
| `policy.active.none.json` | `3c0ebdb32b66ece759f5baee3e3dae552da9ce4224747a20b60011a63f87ca59` |
| `policy.active.ready.json` | `9aeb3035ac9cb7b5e71cafce723bf29de77a2ff49f4cadc197e800339c27e166` |
| `policy.watch.initial.json` | `b7b4d16d9a8a6905bf91b07177844dad19b90fc599ef20adc717bbf37b07eca6` |
| `policy.watch.changed.json` | `b270cf61622a0ee32a79b8b5f8c43e5f6a18c9855c232568d6ec74ba2ce67e2e` |

`github.json` is a byte-for-byte copy of
`crates/credentials-core/policy-defaults/github.json` (SHA-256:
`aca7b285dce9d1ebff602aae291d0205779a932fc47cf2afd380b3ee5d91f1a7`).
This GitHub default is a fixture, not a runtime policy source.
