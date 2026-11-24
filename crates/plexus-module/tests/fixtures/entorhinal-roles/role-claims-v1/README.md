# Role claim v1 served vectors

`records.json` captures two role operations through entorhinal's real
`ProjectsHandler::handle_served_request`. Each entry records the complete request
bytes, the route's caller principal, whether the handler returned a response or
refusal, and the exact successful response bytes. Refusals have no serialized
response body at this layer; `reply_bytes` uses the same vector representation as
the other served-vector sets: the structured error encoded as `{code, detail,
message}` (`detail` is `null` when absent).

The fixture opens a store with sharing disabled. Both requests use role `x`
and a `reserved:plexus` route.

Cases, in order:

1. `never_read`: a role not yet enrolled in the local claim cache; `known` is
   false.
2. `take_reserved_plexus`: the admission refusal for a take from `reserved:plexus`
   (`caller_forbidden`).

Role replies include no read time. A successful reply is the exact UTF-8 JSON
body, including its `result` envelope; successful object key order and whitespace
are not normalized before comparison.

`read-hub.json`, `fence-hub.json`, and `handback-requested.json` capture the
selected hub backend. The live hub tests regenerate those files.

`SHA256SUMS` covers this README and all four JSON files.

Regenerate the vectors from the repository root:

```sh
ENTO_WRITE_SERVED_VECTORS=1 cargo test --workspace --all-targets --locked role_claims_v1_records_match_published_files -- --nocapture
(cd test-vectors/role-claims-v1 && shasum -a 256 README.md records.json fence-hub.json handback-requested.json read-hub.json > SHA256SUMS)
```

Without `ENTO_WRITE_SERVED_VECTORS=1`,
the `served_vectors::role_claims_v1_records_match_published_files` test recreates
both non-hub requests and replies from the real handler and byte-compares
`records.json` on every run.
