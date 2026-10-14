# Core web_search model-facing contract

These JSON values are vendored from Prefrontal commit
`55bdc54475387f5b4178cc40cb56d0df74b7bc53` (`55bdc5447`):

- `description.json`: the tool description models see for web_search. It
  started as core's text (`WEB_SEARCH_DESCRIPTION` in
  `crates/prefrontal-core-module/src/forwarding_provider/mod.rs:197-199`) and
  now deliberately differs: it steers callers away from looking up source
  code, a use web search rarely answers well.
- `schema.json`: the argument schema models see for web_search
  (`web_search_input_schema()` in the same file at lines 201-236).

The fixtures are independent of Plexus's implementation so a definition change
cannot silently change its expected value. The schema omits retired identity-token fields (`assertion`, `agent_assertion`).
Prefrontal's relay now sends calls with a daemon session stamp and no identity tokens. Plexus attributes searches from
the daemon's session stamp and refuses a caller that supplies a retired field
as `argument_undeclared`, before search or credential access.

Rendering cases are ported into `src/web_search_rendering_tests.rs` from
`crates/prefrontal-core-module/src/web_search_relay/tests.rs:280-300,354-457`.
Their implementation follows the neutral result and refusal wording from that
revision; token-only refusal rendering has been retired. The module-grant
wording uses `the calling module`, not `prefrontal-core`.
