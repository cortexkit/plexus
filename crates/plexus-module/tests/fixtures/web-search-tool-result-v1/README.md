# Web search reply bytes for Core

These are raw JSON response bodies emitted by the real tool request handler,
not hand-authored envelopes or a wrapper containing a reply. JSON files are
compact and have no trailing newline, exactly like the response frame body.

`web_search_tests::tool_result_v1::handler_reply_fixtures_match_bytes` invokes
`handle_tool_request_with_web_search_reader`, the same handler used by routes.
Its explicit rollout argument sets the `CORE_WEB_SEARCH_TOOL_RESULT_V1_READER_READY`
gate per call, so the samples stay the same whichever way the shipped constant
is set. It ships enabled since core's readers read this shape. The test uses route.bind negotiation, a fixed search clock and a local
mock provider; no public search service or credential is used. The fixture's
backend delegates to the real Exa adapter with a fixed `fetched_at` timestamp,
because the service clock deliberately does not replace the event clock.

Samples:

- `result.json`: two results, with and without `published_at`.
- `result-shown-subset.json`: the existing whole-result shaping omits results
  and reports `results_shown`, `results_found` and `results_omitted`.
- `refusal-rate-limited.json`: a real exhausted caller rate bucket. Programs
  read the numeric delay at `structuredContent.retry_after_ms` and the refusal
  code at `errorCode` (also `structuredContent.code`). Models read `content`.
- `refusal-other.json`: the real `web_search_code_lookup` refusal, which has no
  detail member.
- `legacy-result.json`: the same two-result success on a route that did not
  negotiate tool-result/v1, even with the rollout gate enabled. It keeps the
  legacy `result` member as well as the existing tool-result/v1 fields.

The four negotiated replies have no legacy `result` or `error` member.
Refusal `structuredContent` is the complete original error object, not an
`error` wrapper. `SHA256SUMS` covers all five JSON files and is checked by the
same test.

Regenerate intentionally, then review the bytes and hashes:

```sh
PLEXUS_REGENERATE_WEB_SEARCH_TOOL_RESULT_V1=1 cargo test --locked -p plexus-module web_search_tests::tool_result_v1::handler_reply_fixtures_match_bytes
```

Without that environment variable set to `1`, the test compares response frame
bodies and `SHA256SUMS` byte for byte. Regenerate on Linux, as CI does. If you
run the command on a remote build machine, copy the five JSON files and
`SHA256SUMS` back into this directory afterwards; `.cortexkit/WORKER.md` names
the build-machine settings this repository uses.
