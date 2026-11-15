# Plexus provenance: route.select search v1

Source repository: `striatum`, tag `route-select-search-v1`, recorded with
`cortexkit-role-routing` 0.7.32.
`01-allowance-wins.json`, `02-paid-clears-level.json`, `03-empty-subset.json`,
`04-refused-requirement.json`, `SHA256SUMS` and `README.md` are vendored byte
for byte. `SHA256SUMS` itself hashes to
`94fedafb7e06c54e9a2a174c2312180af9cc421b36dd194d9870281a9b293745`.
Run `shasum -a 256 -c SHA256SUMS` in this directory to verify the pairs.

Plexus checks them in `route_select_search_vectors_tests`: the checksums, the
request its own builder makes for each pair's routes (byte for byte), and how
it reads each recorded answer. Plexus never sends the fourth pair's `format`
requirement, so that test asserts plexus's request is the recorded one
without it.
