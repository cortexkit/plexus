# permissions-v1 provider vectors (copy)

Only these files were copied, byte for byte, from cingulate's `permissions/v1`
test vectors: the `provider-*` files (the provider cases, each as `.json`,
`.jcs` and `.sha256`), plus cingulate's `README.md` and `SHA256SUMS` for that
directory. Plexus-generated additions are documented separately below. They live here because
CI checks out only this repository. The contract itself is cingulate's
`docs/contracts/permissions-v1.md`.

- Source: the cingulate repository's `main` branch at commit
  `a87da8c86f526f2d489adc433517246e1399e604` (a87da8c), directory
  `test-vectors/permissions-v1/`, taken with
  `git show a87da8c:test-vectors/permissions-v1/<file>`. The last commit to
  change that directory is `c3b4c27df8edf0225f82531dc363fc9c1a132b79`.
- `README.md` here is cingulate's README, unchanged, so the checksum list still
  covers it. Neither those copied bytes nor their checksum list are changed for Plexus samples.
- Only the provider cases are copied. The aggregator cases (`list-all-*`,
  `revoke-*`) describe cingulate's own operations, so they are absent here even
  though `SHA256SUMS` still lists them. Check the copied files with
  `grep -E ' (provider-|README)' SHA256SUMS | shasum -a 256 -c -`;
  `permissions_tests.rs` checks the same lines.
- The rows in these vectors are Cerebellum's. Cerebellum is another module
  that provides `permissions/v1`, for its grants to use desktop apps and sites
  in the agent browser. Plexus's tests compare the shape of their replies with
  these rows (field names and types, outcome values, the refusal code and its
  shape), never the values.
- Do not edit the files to fit Plexus. When cingulate changes the vectors,
  copy them again and update the commit above.

## Plexus-generated module search sample

`plexus-module-search-list.json`, `.jcs` and `.sha256` are generated locally
by Plexus, not copied from cingulate and not included in its `SHA256SUMS`.
They illustrate the module-holder rules in cingulate's
`docs/contracts/permissions-v1.md` at commit `5f9a598`: a bare `module_id`, no
agent fields, and no display label without an authoritative module name.
The list includes agent bot rows and the `web_search` and `code_search`
capabilities held by `broca`. Three web provider grants fold into one row.

The generator binds a cingulate route and calls the real permissions handler
against a file-backed fixture store with fixed grant mint times. `.json` is
pretty-printed with a trailing newline; `.jcs` is RFC 8785 canonical JSON with
no trailing newline; `.sha256` is the lowercase SHA-256 of the `.jcs` bytes,
with a trailing newline. The same test checks all three files byte for byte.
The phone (CKIOS) and desktop (CKDESK) apps can pin these files independently
of the copied vectors.

Regenerate from the repository root (on the Linux build server):

```sh
PLEXUS_REGENERATE_PERMISSIONS_FIXTURES=1 cargo test --locked -p plexus-module --lib permissions_tests::plexus_module_search_list_vector_matches_handler -- --exact --nocapture
```

Return the three generated files from the remote job, then check without
the regeneration variable using the same command.
