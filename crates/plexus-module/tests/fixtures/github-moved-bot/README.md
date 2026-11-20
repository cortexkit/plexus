# Moved GitHub bot wire vector

`stale-residence.request.json` is a classic `github` bot request on a
Callosum-bound agent route. `stale-residence.reply.json` is the complete
response frame body when the residence epoch changes after GitHub accepts the
comment, but before the issue-close leg. `not_sent` describes the unsent leg;
`legs_sent` records the comment and the same nonce can resume from the new
holder. The federated handler test compares the complete serialized reply.

These Plexus-owned vectors cover admission through Callosum. AFT's vendored
`gh_shim_wire` corpus covers the local GitHub shim request and reply contract.
