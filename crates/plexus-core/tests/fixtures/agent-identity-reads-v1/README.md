# Served agent identity reads v1

These records come from entorhinal's real `ProjectsHandler`, through admitted
routes and the serving request path. Project/workspace registration and the
`agent.import` cutover are real handler requests; import runs with
`Reserved(prefrontal-core)`. Reads run with `Reserved(phone)` (recorded as
`{"kind":"reserved","moduleId":"phone"}`). The fixture binds this synthetic
reader identity to exercise handler admission and dispatch. A deployed phone
peer still needs permission from the SUBC router to call these operations;
this fixture does not check or grant that production access.

Each JSON file is an array of `{op, request, principal, reply}` records. `request`
is the operation's params object. Successful `reply` values embed the exact
UTF-8 JSON bytes returned by the handler, including its `result` envelope;
they are not parsed and re-serialized. Refusals are handler outcomes, not
response bytes, and are recorded as `{code, message, detail}` (`null` when no
detail was supplied).

- **`agent-resolve.json`**: seven direct `agent.resolve` records, in order:
  - live head Mira (`agent_0000000000000001`);
  - live hiree Neri (`agent_0000000000000005`), supervised by Mira;
  - retired assistant Ivo (`agent_0000000000000004`);
  - unseeded id `agent_ffffffffffffffff`;
  - missing `agent_id` (`{}`);
  - wrongly typed `agent_id` (`42`);
  - an unknown param alongside the head id (`unknown: true`).
  The first four are successful results, including the retired and unknown ids:
  their statuses are `live`, `live`, `retired`, and `unknown`. The retired result
  has `gone: {"at":10,"reason":"deleted"}`; the others have `gone: null`.
  Every successful result has `agent_id`, `generation`, `gone`, `incarnation`,
  `merged_into` (null here), and `status`. All three malformed requests produce
  `invalid_request` refusals with no detail. The head is imported with a
  versioned avatar, then given a nonempty tag and labels through handler writes.
  The hiree is created by calling the store's `agent.create` mutation directly
  with a fixed fixture id, rather than through a handler request; this still
  runs supervisor and placement validation. Despite those populated identities,
  `agent.resolve` does not emit names, roles, tags, labels, avatars, placement, or
  `supervisor_agent_id`; the head and hiree have the same result shape.
- **`agent-resolve-merged.json`**: two direct `agent.resolve` records after a merge,
  in order:
  - merged assistant Luma (`agent_0000000000000601`), with `status: "merged"`,
    `merged_into: "agent_0000000000000602"`, and
    `gone: {"at":700,"reason":"merged","into_agent_id":"agent_0000000000000602"}`;
  - surviving assistant Sora (`agent_0000000000000602`), with `status: "live"`,
    `merged_into: null`, and `gone: null`.
  Both agents are created with invented names and fixed ids through the store's
  real `agent.create` mutation, then merged through its real `agent.merge`
  mutation, all as `reserved:prefrontal-core`. Reads go through the handler as
  `Reserved(phone)`. No terminal state is seeded with SQL. The separate file
  leaves the previously published `agent-resolve.json` bytes and checksum intact.
- **`fleet-identity.json`**: a full `{}` read, the unchanged read using its
  returned token, and an unknown-field `invalid_request` refusal. The fixture
  has a head with a versioned avatar, an assistant with an unversioned avatar,
  an assistant without an avatar, and a retired assistant with an avatar.
  Only the three live agents appear in fleet identity. Every reply carries
  `logPosition`: the last shared identity-log position this machine applied,
  `0` here because sharing is off. A client merging several machines' replies
  keeps the one with the highest `logPosition`; `generation` and `token` count
  each machine's own journal and are never compared across machines.
- **`avatar-read.json`**: both live stored avatars; then an ordered mix of a
  present avatar, an unknown id, an unset avatar, a retired avatar, another
  present avatar, and a duplicate of the first id. Unknown/unset avatars are
  omitted, while retired avatars and duplicates are retained in request order.
  The last three records refuse zero ids, 65 ids, and an empty-string id.
- **`SHA256SUMS`**: SHA-256 hashes of the four JSON files, with filenames relative
  to this directory.

## Reproduce and verify

From the repository root, the generation command is:

```sh
ENTO_WRITE_SERVED_VECTORS=1 cargo test --workspace --all-targets --locked served_vectors -- --nocapture
```

On PowerShell, set `$env:ENTO_WRITE_SERVED_VECTORS = '1'` before the same cargo
command, and remove that environment variable afterwards. Generation rewrites
the four JSON files in this directory. To regenerate only the merged sample
without rewriting previously published files, use:

```sh
ENTO_WRITE_SERVED_VECTORS=1 cargo test --workspace --all-targets --locked served_vectors::agent_resolve_merged_records_match_published_file -- --exact --nocapture
```

Refresh their hashes from the repository
root with:

```sh
python3 - <<'PY'
import hashlib
from pathlib import Path
root = Path('test-vectors/agent-identity-reads-v1')
names = ['agent-resolve.json', 'agent-resolve-merged.json', 'avatar-read.json', 'fleet-identity.json']
root.joinpath('SHA256SUMS').write_text(''.join(
    f'{hashlib.sha256(root.joinpath(name).read_bytes()).hexdigest()}  {name}\n'
    for name in names), encoding='utf-8')
PY
```

Without the write environment variable, the non-ignored
`served_vectors::served_records_match_published_files`,
`served_vectors::agent_resolve_records_match_published_file`, and
`served_vectors::agent_resolve_merged_records_match_published_file` tests byte-compare
the captured records with these files on every CI run, including Linux, macOS,
and Windows. The fixed clock is `700` and the process incarnation is
`0123456789abcdef`. The project is
registered with an empty roots list, a supported rootless placement, so its
optional `canonicalRoot` is absent, and the workspace has no root folder. No
platform path or temporary-directory name enters the fixture or the captured
replies. In particular, `agent.resolve` emits no filesystem paths, so its
records need no path substitutions.

The direct resolve generators can also be checked independently with both test
runners (leave `ENTO_WRITE_SERVED_VECTORS` unset):

```sh
cargo test --workspace --all-targets --locked served_vectors::agent_resolve_records_match_published_file -- --exact
cargo nextest run --workspace --all-targets --locked -E 'test(served_vectors::agent_resolve_records_match_published_file)'
cargo test --workspace --all-targets --locked served_vectors::agent_resolve_merged_records_match_published_file -- --exact
cargo nextest run --workspace --all-targets --locked -E 'test(served_vectors::agent_resolve_merged_records_match_published_file)'
```

Fleet avatar fingerprints are the first 32 hexadecimal characters of BLAKE3
over `genome + "\n" + type + "\n" + version`, with the version written in decimal
and an empty string used for a missing version. The avatar-read operation
returns the stored genome/type/version, not the fingerprint.

## Core v1.0 compatibility boundary

The non-ignored `served_vectors::avatar_read_matches_core_contract_v1_0` test
reads the unchanged published fixture at
`crates/entorhinal-module/tests/fixtures/core-avatar-read-vectors-v1.0.json`.
Entorhinal imports ids of the form `agent_` followed by 8 or 16 lowercase hex
characters, while core's fixture uses `agent-avatar-*`. The test maps the ids
reversibly before importing the fixture's exact genome/type/version triples
through the real `agent.import` operation:

- `agent-avatar-NN` maps to `agent_` plus the decimal suffix's value encoded as
  16 lowercase hex digits (for example, `agent-avatar-29` maps to
  `agent_000000000000001d`).
- `agent-avatar-absent` maps to `agent_fffffffffffffffe` and is imported as a
  known agent without an avatar.
- `agent-avatar-unknown` maps to `agent_ffffffffffffffff` and remains unseeded.

The test rejects mapping collisions and unsupported ids with explicit errors.
Every vector runs through the real handler with mapped request ids. Because
`avatar_read` echoes each requested id in `agentId`, only that reply field is
mapped back before comparison. Genomes, types, versions, omissions, duplicates,
and order remain unchanged: `avatars` must equal core's reply exactly, with
only `generation` and `incarnation` allowed as extra top-level keys. The same
strict reply-key assertion also runs in the served-record test.
