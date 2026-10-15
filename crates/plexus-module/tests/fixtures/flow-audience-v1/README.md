# Flow audience v1 wire vectors

`records.json` pins the `flow.audience` request and reply shapes. The `caller` field is fixture metadata representing the verified connection identity; it is not part of the operation body. Each request body contains the `flow_id` object supplied to the query. The workspace example uses the fixture projects consumer's enumeration of registered workspaces and projects, then pins the sorted, deduplicated projects whose workspace ID matches the flow audience.

The refusals cover callers other than `reserved:plexus` (the daemon-verified identity of Plexus, which alone may read flow audiences), an unknown request field, an unknown flow, a flow with only a declined install, conflicting approved versions, and unavailable workspace membership. Refusal replies contain the operation's stable error code and message.

Regenerate the records by running the fixture-backed query test with:

```sh
UPDATE_FLOW_AUDIENCE_VECTOR=1 cargo nextest run -p prefrontal-core-module --test it -E 'test(/flow_audiences::flow_audience_vectors_pin_real_requests_and_replies/)'
```

Verify the pinned file from this directory with:

```sh
shasum -a 256 -c SHA256SUMS
```

The test runs the real core query against a migrated fixture store and a projects consumer configured with a fixed workspace/project listing (or an unavailable response), then compares the serialized bytes with `records.json`.
