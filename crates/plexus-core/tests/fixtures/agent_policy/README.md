# GitHub agent-policy revision 2 draft

`github-rules-revision-2-kinds.draft.json` is a byte-for-byte copy of
`CortexKit-scratch/shared-bot-permissions/github-rules-revision-2-kinds.draft.json`.
It contains the draft policy kind entries for tests, not an approved policy.

SHA-256: `394f278e7470b0bab27e4275632673995dbdb5641c89ed12523ac283b5f27486`

## Path parameter types

The table below is from `CortexKit-scratch/shared-bot-permissions/aft-extractor-github-rest-graphql-v1.md`
(SHA-256 `be5018badae92b4d39a91da029b4d0be27c1b4428298f025239117768cd1258e`).

| Type | Values (after decoding) | Notes |
|---|---|---|
| `owner` | `[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?` optionally followed by `_[A-Za-z0-9]{1,16}` | A GitHub user or organization login. The `_suffix` form covers enterprise-managed users. It's compared lowercase against bindings. |
| `repo` | `[A-Za-z0-9._-]{1,100}`, except `.` and `..` | A repository name. Compared lowercase against bindings. Together with the `owner` in the same path, it forms the resource. |
| `number` | `[1-9][0-9]{0,9}`, value at most 2147483647 | An issue, pull request, milestone or discussion number. |
| `id` | `[1-9][0-9]{0,15}`, value at most 2^53−1 | A database id (comment, review, run, job, artifact, release, hook). |
| `sha` | `[0-9a-f]{40}` or `[0-9a-f]{64}` | A full commit or object id, lowercase only. Abbreviated ids don't match. |
| `name` | 1 to 255 bytes of UTF-8, with no `/`, `\` or control character, except `.` and `..` | A label, environment, workflow file, tag, branch segment or similar single segment. |
| `{param*}` (tail) | One or more segments, each a `name` value, at most 1024 bytes in total joined with `/` | Only as the last template segment. For git refs (`/git/refs/{ref*}`) and file paths (`/contents/{path*}`). |
