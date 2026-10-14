# grep.app MCP fixtures

These files are anonymous captures of grep.app's public MCP endpoint
(`https://mcp.grep.app`), taken without credentials or a session identifier.
Tests replay them as regression input, so the code-search reply parser and the
remote MCP transport are checked against the vendor's real wire format rather
than a hand-written imitation.

- `initialize.sse`: the server's reply to `initialize`.
- `search.sse`: a `searchGitHub` reply with results, as an unmodified
  `text/event-stream` body.
- `empty.sse`: a `searchGitHub` reply for a query with no matches, carrying the
  server's no-match text.
- `no_results_tool_error.txt` and `rate_limit_tool_error.txt`: the two
  `searchGitHub` tool-error strings the transport tests handle.
