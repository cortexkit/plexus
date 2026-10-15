# Broca request frames

These are the exact request bodies Broca sends to plexus for a worker plan that
includes plexus's search tools. Broca produced them with its own request
builders at commit `497e149` of `cortexkit/broca`:

- `catalog-fetch.json` comes from `fetch_body` in
  `crates/broca-subc/src/plan_fetch.rs`, for the plan item
  `{provider: "plexus", preset: "worker", params: {capabilities: [...]}}`. Broca
  copies the item's preset into the frame's top-level `preset` as well as
  `arguments.preset`.
- `web-search-call.json` is a later tool call in the same session, built by
  `SubcConnection::tool_call_with_preset`. Broca sends the plan's preset on every
  call to plexus. `tool_call_id` is the model's own call id; `call_1` stands in.

Tests decode these as JSON, so key order is not significant. Plexus must
answer the catalog fetch with exactly `web_search` and `code_search`, and
must not refuse the tool call because of its preset or `tool_call_id`.
