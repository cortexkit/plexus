# Role claim v1 served vectors

`records.json` captures eight role operations through entorhinal's real
`ProjectsHandler::handle_served_request`. Each entry records the complete request
bytes, the route's caller principal, whether the handler returned a response or
refusal, and the exact successful response bytes. Refusals have no serialized
response body at this layer; `reply_bytes` uses the same vector representation as
the other served-vector sets: the structured error encoded as `{code, detail,
message}` (`detail` is `null` when absent). The principal uses the established
vector schema: `{"kind":"reserved","moduleId":"plexus"}` or
`{"kind":"direct"}`.

The fixed role is `x`. The fixture uses clock `700`, incarnation
`0123456789abcdef`, local author `01010101010101010101010101010101` (named
`This machine`), and remote author `02020202020202020202020202020202` (named
`Other machine`). Calls are made through served routes: reads and the admission
refusal use `reserved:plexus`; the compare-and-set attempt uses `Direct`.

Cases, in order:

1. `never_read`: a role not yet enrolled in the local claim cache; `known` is
   false.
2. `read_unheld`: a verified absent record after refresh; epoch `0`, `known`
   true, and `stale` false.
3. `held_here`: a verified claim held by this machine, with its member name.
4. `held_elsewhere`: a verified claim held by the other author, with that
   member's name.
5. `stale_after_restart`: a cached held-here claim after the store is reopened.
   `stale` means the claim has not been confirmed in this process. Every role is
   marked stale at process start; only a verified engram read or a landed take
   clears it.
6. `integrity_failure`: a failed verified record read is surfaced as
   `claim_integrity_failed`.
7. `take_epoch_moved`: a fake operator confirmer approves `role.take`; the fake
   record peer moves the version immediately before the compare-and-set, so the
   real handler returns `epoch_moved` with the winning holder and epoch.
8. `take_reserved_plexus`: the admission refusal for a take from `reserved:plexus`
   (`caller_forbidden`).

Role replies include no read time. A successful reply is the exact UTF-8 JSON
body, including its `result` envelope; successful object key order and whitespace
are not normalized before comparison. The role cache's local `source` field is
present where a claim is known; it is not a remote read timestamp.

Releases after 0.1.44 renamed the member names from `This Mac` and `Other Mac`
to `This machine` and `Other machine`; codes and keys are unchanged, but
`records.json` has a new hash, so consumers that pin it must re-pin.

`SHA256SUMS` covers this README and `records.json`.

Regenerate the vectors from the repository root:

```sh
ENTO_WRITE_SERVED_VECTORS=1 cargo test --workspace --all-targets --locked role_claims_v1_records_match_published_files -- --nocapture
(cd test-vectors/role-claims-v1 && shasum -a 256 README.md records.json > SHA256SUMS)
```

Without `ENTO_WRITE_SERVED_VECTORS=1`,
the `served_vectors::role_claims_v1_records_match_published_files` test recreates
every request and reply from the real handler and byte-compares the generated
file on every run.
