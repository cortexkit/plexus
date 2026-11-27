# `plexus:github.watch/v1` wire samples

`vectors.json` records tool calls and their legacy `result` or `error` replies from the Plexus flow handler with a mock GitHub transport. The carrier is `reserved:basal`, flow `flow-a`, stamped with `agent-x`; the `agent_identity_required` sample omits the agent stamp. The samples are independent examples; the expiry and event observation time are captured from the generating run, not values to reuse at deployment. `event-v2.json` is the body of a `github_issue_changed` event produced and marked published by the outside subscription. Consumers should use the same v2 event decoder as for fleet issues.

`ensure` needs a future expiry in Unix milliseconds. A fleet subscription of the requested kind returns `existing` with a null expiry; an outside watch returns the stored expiry (at most 30 days out on creation). Release watches omit `number` in the request and return it as null. `end` only removes the caller's own outside watch.

The `item_not_found` sample injects an explicit HTTP 404. That code requires a definite not-found signal; the current GitHub MCP actions surface generic tool errors instead. The `read_dispatch_failed` sample shows that case, which can also be an upstream failure. No outside watch is committed on either refusal.

## Deploy authority

On the operator route, use `ck-plexus-admin grant --subc "$SUBC" --connection <connection> --grantee reserved:basal --kind poll --risk read --actions <comma-separated-selectors>` for each row below. The grants name the module, not an agent, and carry no write authority:

| Connection | Exact action selectors |
| --- | --- |
| `conn-github` | `list_issues`, `issue_read` |
| `conn-github-prs` | `list_pull_requests`, `pull_request_read` |
| `conn-github-releases` | `get_latest_release` |
| `conn-github-actions` | `get_repository` |

The subscriptions and hourly public recheck use the operator's own poll authority. The module grants above authorize Basal to create subscriptions and perform the pre-reads; they do not replace the operator's scheduled-poll grants.

## Regenerate

Run in a writable checkout:

```sh
PLEXUS_REGENERATE_GITHUB_WATCH_FIXTURES=1 cargo test --locked -p plexus-module github_watch_tests::wire_vectors_match_the_flow_handler
```

The test also regenerates `SHA256SUMS`. It compares the recorded bytes on a normal run after substituting the recorded clock values for the live expiry and observation time.
