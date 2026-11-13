# permissions-v1 federated vectors (copy)

These files are copied byte for byte from cingulate's `permissions/v1` test
vectors. They are kept here because CI checks out only this repository. The
contract is cingulate's `docs/contracts/permissions-v1.md`, sections
"Federated grants" and "Standing denials".

- Source: the cingulate repository at commit
  `169d6dc982745e9b07b6a7a5e6c1221c11c4af8f` (tag
  `permissions-federated-deny-v1`), directory `test-vectors/permissions-v1/`.
  Each file was taken with `git show 169d6dc:test-vectors/permissions-v1/<file>`.
- Copied: every `federated-*` and `provider-list-federated-*` case, as `.json`,
  `.jcs` and `.sha256`.
- `SHA256SUMS` holds only the lines of cingulate's own `SHA256SUMS` at that
  commit that name these files, unchanged. Check them from this directory with
  `shasum -a 256 -c SHA256SUMS`. A test must compare against these lines, not
  against checksums plexus computes, so a copy from the wrong commit fails.

Never edit or regenerate these files. A newer contract means a new copy from a
named cingulate commit, with this file updated to match.
