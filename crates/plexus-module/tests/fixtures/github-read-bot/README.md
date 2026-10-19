# GitHub bot read vectors

Wire vectors for the agent bot reads on the `github_read` tool, for AFT's `gh`
shim. Each vector is three files:

- `<name>.request.json`: `scope` is the scope stamp the daemon put on the
  route (`{"kind": "head", "agent_id": ...}`, `{"kind": "worker",
  "on_behalf_of_agent": ...}`, or a stamp naming neither), and `call` is the
  exact tool-call body AFT sends (`{"name": "github_read", "arguments": ...}`)
  on a route carried by `reserved:aft`.
- `<name>.github.json`: the GitHub side, which the replay supplies through a
  mock transport. `replies` maps each catalog action to what plexus's REST
  transport would hand back for it (`success`, the transport's reply envelope,
  or `vendor_error`, the code it reports for a non-2xx answer or an oversized
  body). `setup.reads_spent` pre-spends that many units of the bot's hourly
  read budget. `expected_requests` lists every governed GitHub request plexus
  must send, in order, with its connection and exact vendor arguments; an
  empty list means the call is refused before anything is sent.
- `<name>.reply.json`: the reply frame body plexus answers with.

`github_read_frame_tests::bot_read_vector_tests::every_bot_read_vector_replays_byte_for_byte`
in `crates/plexus-module/src/bot_read_vector_tests.rs` replays every vector
here through the real tool-call handler (`handle_tool_request`, which builds
the reply with `with_call_tool_result_with_repo`) and compares the reply body
byte for byte with `<name>.reply.json` after re-serializing that file
compactly (keys sorted, which is how the handler serializes too). The test
also fails if no vector covers one of the actions or refusal codes.

One exception: `read_budget_exhausted` carries `retry_after_ms`, which depends
on the clock at replay time. The replay checks it is between 1 and 3,600,000
and then uses the vector's value for both `error.retry_after_ms` and the
`content` text that repeats it (in whole seconds), before comparing bytes.
Every other reply, `content` text included, is compared exactly.

Regenerate the reply files after an intended change with

    PLEXUS_REGENERATE_BOT_READ_VECTORS=1 cargo test -p plexus-module --lib bot_read_vector_tests

and review the diff: these replies are a contract AFT reads.

## Reply shapes

Success is `{"result": R, "content": [{"type": "text", "text": <R pretty-printed
under "result">}], "isError": false, "structuredContent": R}` where R is

- `github.repo.get`: `{status, body, next_page}`; `body` is parsed JSON for
  `application/vnd.github+json` and a string for the raw, diff and patch media
  types; `next_page` is the page number of GitHub's `Link` `rel="next"`, else
  null.
- `github.search.code`, `github.search.issues`:
  `{total_count, incomplete_results, items, next_page}`.
- `github.actions.job_log` (from AFT without `max_bytes`):
  `{body, offset, length, total_bytes}`; `length` counts the raw log bytes
  read, so the next range starts at `offset + length`.

A refusal is `{"error": {"code", "message", "transmission", ...}, "content":
[{"type": "text", "text": "<code>: <message>..."}], "isError": true}` with no
`structuredContent`:

| code | extra fields | transmission |
| --- | --- | --- |
| `read_budget_exhausted` | `retry_after_ms` | `not_sent` |
| `repository_not_visible` | | `not_sent` |
| `endpoint_not_allowed` | `field` (`path`, `accept`, `q`, `query`, or the other argument refused) | `not_sent` |
| `response_too_large` | | `sent` |
| `agent_identity_required` | | `not_sent` |
| `vendor_error` | `status` (GitHub's HTTP status) | `sent` |
