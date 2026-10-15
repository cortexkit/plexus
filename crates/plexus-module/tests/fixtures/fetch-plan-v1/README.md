# fetch-plan-v1 relayed-call vectors

Pinned wire vectors for a tool call that Prefrontal core relays onward to the
modules that serve its tools, Plexus and Cerebellum, originally copied from the Prefrontal repository's
`test-vectors/fetch-plan-v1/calls/` ("Relayed tool call" section of that
directory's README). They live here because CI checks out only this
repository.

- Source: the Prefrontal repository's `main` branch (`origin/main` in a
  clone) at commit `e3674ba137889909be06d5d59c85a59f27661f0e`, taken with
  `git show origin/main:test-vectors/fetch-plan-v1/calls/<file>`.
- In the Prefrontal repository the directory last changed at commit
  `f2c3bba04bc2929f888b24efc249f856685422b7`, which added
  `relayed-web-search-from-opencode-plugin.json`; the commit before it,
  `594dc3049562c69401abddb9f693aa17ca8a3645`, changed `origin.carrier` from a
  display string to a principal object.
- All copies except the web-search vector remain byte-for-byte source copies.
  The web-search vector now omits the retired token field; its current hashes
  are below. Its original source blob was `753cfede9c6c3c5cc1c65c59bb0876e78fa3c3b0`.

| File | sha256 | git blob |
| --- | --- | --- |
| `pf-call-keys.json` | `259a8d2c9c47ba8f44f111dc1607d35af54ad4e0eacde342dc441eca567e8eb8` | `1ddd969d26f20ff33230beef0d4bd2cdfc218600` |
| `relayed-from-broca.json` | `ec29929c4c863ad52d24708219dbaefb119dd046d825f2e975547c33342834f9` | `37634c863684ba7a507e4bab62c0be3ca9a43086` |
| `relayed-from-claude-code-bridge.json` | `3d6f0796535d04bd525e9615bbc1f40746de32e26b38ab7229f3367263edab39` | `c038da6b4095f117fc3d86acae3a5417e7ecffd5` |
| `relayed-from-opencode-plugin.json` | `242b05d47484a51ab52feafdc59abca5ebe321a2888384c62e2cc975e7dad3fc` | `c09b8397d838034356eced74947869831dad040b` |
| `relayed-web-search-from-opencode-plugin.json` | `754f6596b722f42c33e563ef54b5919eb934870b9f6d26bc7bd75cdca9aac78a` | `48b9920c9a22e2421b3134f0e7d9598691d9f163` |

## How the tests use them

Do not edit the files merely to fit a test. The token-field removal is an
explicit contract retirement; otherwise, when Prefrontal changes the source,
re-copy it and update the table above.

1. **The carrier is a principal object.** `origin.carrier` is written as a
   subc-protocol `Principal` object (`{"kind": "reserved", "module_id":
   "broca"}`), the form Plexus parses, so each vector's `origin` passes
   Plexus's checks as it stands. Plexus records the carrier in its stored
   principal form, `reserved:broca`.
2. **Three vectors name tools Plexus does not serve.** `relayed-from-broca`,
   `relayed-from-claude-code-bridge` and `relayed-from-opencode-plugin` name
   `browser_use` and `computer_use`, which another module, Cerebellum,
   serves. Sent unchanged,
   each passes the `origin` check and is refused as `unknown_method`.
   Recording tests keep each vector's envelope (`call_key`, and `origin`
   when present) and swap only `name` and `arguments`: `web_search` for the
   audit rows, `invoke` for the held approval request.
3. **The `web_search` vector is sent unchanged.**
   `relayed-web-search-from-opencode-plugin.json` is a call core relays for an
   OpenCode head: core's forwarded arguments, a `pf:` key and no `origin`. The
   tests send it as `reserved:prefrontal-core` under a daemon session stamp.
   The vendored vector has been updated only to remove the retired
   `agent_assertion` field; its envelope and forwarded search arguments are
   unchanged. The stamped relay test checks dispatch, agent attribution and
   that every audit row has no origin, because the vector states none.

`pf-call-keys.json` drives the `call_key` validator through `origin.call_key`:
every `valid` key is accepted there, and every `invalid` key the vector says
`validate_call_key` refuses is refused naming `origin.call_key`. The one
refused by Prefrontal's own record-id rule (`pf:`) passes the protocol
validator and so is accepted, as the vector says.

## Broca tool-catalog plan fixture

`broca-head-plexus-direct.json` is copied unchanged from
`broca/crates/broca-fetch-plan/tests/fixtures/fetch-plan-v1/plans/broca-head-plexus-direct.json`
at Broca commit `b3b383755ff2e0d12d1114c4311e4cf70433dc17`
(2026-10-08T02:31:47+02:00).

The accompanying `.sha256` is the plan identity: SHA-256 over the RFC 8785
(JCS) bytes of the entire plan as received, not the pretty JSON file bytes.
The plan's `composition_digest` hashes the composition object without stripping
any members. The upstream fixture README's Composition section defines
`providers` as an array of module ids with ordered tool names and capability
tags, with empty tool lists for text-only and hook-only providers. Broca compares
fetched tool names and tags with the corresponding composition entry.

The copied plan predates capability-param selection: its Plexus tool item has
empty `params`. Tests retain those original bytes, verify that they select no
tools on a plan fetch, and then supply `params.capabilities` for the fixture's
`github` and `web_search` tools. Plexus keeps the composition opaque and selects
tools only from the capability params, not from the composition entry.

This local copy lets the catalog tests run when CI checks out only Plexus.

## Plexus frozen-preset catalog request

`plexus-worker-catalog-request.json` is the catalog request a coding worker's
session sends a provider, taken from the `worker-tool-and-text` case
from `cortexkit/prefrontal`, `test-vectors/fetch-plan-v1/catalog-requests.json`,
last changed at commit `4ab3e1ed69e1619cfdb700ae2aa543a657aba38e` (identical at
`33141054d1bb308800195bec76657f00feb18ea9`). The original file's SHA-256 is
`b452afaa60085349bcc23f1531a0a720b5d6bcd7eafb5d6448aa2f812c3b13ab`.

The provider and its composition tool item are replaced with Plexus and its two
search tools; `params.exclude` becomes `params.capabilities` with the public code
search and web search tags used by the prefrontal-core worker and reader plans.
The AFT composition item and `step_transform_items` are unchanged. `system_text`
is dropped because Plexus serves no system text and prefrontal-core gives it none. The
request retains `preset`, `params`, and `composition`. Tests copy the request's
preset to the top-level tool-call envelope, as Broca's catalog fetch does, and
reuse the composition for the reader preset.
