# Tool catalog preset reply vectors

These files contain the exact `tool.catalog` response bodies sent by the Plexus
route: compact JSON, with no trailing newline. The fixture test sends the
requests through that route and compares the raw response bytes and `SHA256SUMS`.

| Reply | `tool.catalog` arguments | Tools in reply order |
| --- | --- | --- |
| `head.reply.json` | `{"preset":"head"}` | `web_search`, `code_search` |
| `worker.reply.json` | `{"preset":"worker"}` | `web_search`, `code_search` |
| `reader.reply.json` | `{"preset":"reader"}` | `code_search` |
| `flow.reply.json` | `{"preset":"flow"}` | `catalog`, `invoke`, `github`, `github_read`, `github_react`, `events_get`, `web_search`, `code_search` |
| `no-preset.reply.json` | `{}` | None |

Consumers discover the served `presets` list from the full no-preset reply.
Named preset replies do not repeat the list. Plexus accepts but ignores the
retired `params.capabilities` member; see the [legacy request vectors](../tool-catalog/README.md).
Digest-only replies contain only `generation` and `catalog_digest`, with the
same digests as their corresponding full replies.

To regenerate after an intentional change, run in a writable Linux checkout:

```sh
PLEXUS_REGENERATE_CATALOG_PRESET_FIXTURES=1 cargo test --locked -p plexus-module tool_provider::tests::catalog_preset_wire_vectors_match_reply
```

Copy the five replies and `SHA256SUMS` back if using a remote build machine,
review the changes, and rerun the test without the environment variable.
