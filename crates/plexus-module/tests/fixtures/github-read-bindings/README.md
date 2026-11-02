# GitHub binding-list example

`list.request.json` is the exact tool-call body for an agentless global flow
on a route authenticated as the Basal module (`reserved:basal`).
`list.reply.json` is the complete reply body,
including MCP `structuredContent` and JSON text content. Both are compact JSON
without a trailing newline. The focused
`github_bindings_list::tests::example_replays_exact_request_and_reply_bytes`
test sends the request bytes through the real tool handler and compares the
reply bytes exactly.

The seeded store has generation 6: `o/x` belongs to `agent-x` / `app-x`,
and `o/a` and `o/z` belong to `agent-y` / `app-y`. Disabled, ungranted and
expired-grant handles are omitted. There are no GitHub requests or read-budget
charges. The global generation is not narrowed to the visible rows.

This Plexus-local pair follows the request/reply naming and complete tool-reply
convention of `github-read-bot`, but is separate from AFT's vendored bot vectors
and needs no mock GitHub exchange file because it only reads Plexus's store.
