# prefrontal agent registry replies

`replies.json` is prefrontal's own fixture of agent-registry operation replies,
copied verbatim from the prefrontal repository at commit `d3ac85d72a7be955c3b0405908246cbb00c61ac2`, path
`crates/prefrontal-core-module/tests/fixtures/agent-registry/replies.json`.
sha256: `08b29fb6cabfeec7c0f609682ed17b507397bd23c64c6a88dc8ea654fb2ccb42`

Plexus's hourly retired-agent sweep calls prefrontal-core's `agent.resolve`. Its
tests read the live (`{"agent": {...}}`), deleted and merged
(`{"gone": {...}}`) replies from this file, so the sweep's parser is checked
against the bytes prefrontal produces rather than hand-written examples. To move
to a newer fixture, copy the file again and update the commit and checksum.
