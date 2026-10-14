# Generic consent requester additions, v2

This corpus adds generic-consent requests from Cerebellum and Plexus to the
requester v2 contract. Existing v1 corpora are unchanged. Requests/replies are
actual envelopes served by the handler over scratch SQLite stores with a
deterministic clock and ids. The stamped principals are `reserved:cerebellum`
and `reserved:plexus`, with carried subject agent `agent-alf`; neither identity
is supplied in request params. Phone records use the daemon-attested Callosum
phone surface. Outcome records are read through the daemon-stamped
`reserved:prefrontal-core` route.

- `cerebellum-*`: a generic request without `requester_ref`.
- `cerebellum-ref-*`: a generic request with opaque reference `tool-call-42`,
  including get, await, answers and outcomes carrying it unchanged, and phone
  get/list omitting it.
- `cerebellum-non-consent-*`: a valid flow decision refused for Cerebellum.
- `plexus-*`: a generic request from Plexus, with a valid flow decision refused
  for its non-consent-kind vector.

Regenerate the corpus and its SHA256SUMS using the existing generator:

```sh
cargo run -p cingulate-vectors --example generate_requester_vectors --locked -- --v2
cargo run -p cingulate-vectors --example generate_requester_vectors --locked -- --v2 --check
cargo test -p cingulate-vectors --test requester_contract --locked
```

`SHA256SUMS` covers every file except itself. The contract test pins its digest,
checks file coverage and every hash, and compares regenerated served bytes.
