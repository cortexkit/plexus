# `route.select` search v1 wire pairs

These synthetic Plexus fixtures are captured from striatum's real frame handler,
using `cortexkit-role-routing` 0.7.32 and `cortexkit-role-routing-conformance`
0.10.36. Final verification uses conformance 0.10.37. Its `placement_consumer_declarations`
case declares a search route through the `search-provider/v1` slot, sends a
`kind: "search"` select with `privacy`, and requires the answer's `engine` to be
that declared route (contract §16.4.2). 0.10.36 sent no `kind` or `privacy`.
No daemon or provider is contacted.
The nonce-verified `plexus` module declares consumer `plexus.web_search` with
selector `plexus`, plus three `search-provider/v1` routes. Search credentials
remain owned by that module; routing has no credential fixture for them.

The synthetic Fusiform search rows use provider `search-fixture`: `allowance`
has grade 400 and `request.per_request` price $0.01, `paid` has grade 400 and
`output.per_result` price $0.001, and `unpriced` has no rates. The demand level
is 75. In the second pair only, the allowance route's grade is lowered to 100,
below the bar of 300. No rate from a real provider is asserted here.

Each JSON file encloses the exact request and reply bodies without reserializing
them. The clock is fixed at 1750000000000 ms and decision IDs are deterministic.
`SHA256SUMS` covers the JSON files sorted by filename.

| Pair | Result |
| --- | --- |
| `01-allowance-wins.json` | An adequate allowance route beats a cheaper paid route; the answer retains its catalog price. |
| `02-paid-clears-level.json` | A paid route beats the below-level allowance route. |
| `03-empty-subset.json` | An empty eligible subset is `no_route`. |
| `04-refused-requirement.json` | `format` is refused by name as `invalid_requirements`. |

Verify with:

```sh
cargo nextest run --locked -p striatum-module --bin ck-striatum -E 'test(routing_v1::search_tests::serving_bytes_match_search_vectors)'
```

To intentionally regenerate these search-only vectors, set
`UPDATE_ROUTE_SELECT_SEARCH_VECTORS=1` on that command. The verifier checks the
raw bytes, checksums and exact directory membership. Existing media and chat
recordings are not regenerated.
