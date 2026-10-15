# Plexus provenance: flow audience v1

Source repository: `prefrontal` (prefrontal-core), commit `078861cc0`.
Source directory: `test-vectors/flow-audience-v1/`.

`records.json`, `SHA256SUMS`, and `README.md` are vendored byte-for-byte.
The SHA-256 of `records.json` is
`f9460cd1f47b5d94cb55d6a20ae68208e144e46e978186d6ae453068be9dc080`.
Run `shasum -a 256 -c SHA256SUMS` in this directory to verify it.

Plexus decodes every case over its real subc lookup and parser in
`flow_audience::tests::upstream_flow_audience_vectors_decode_through_plexus`.
The `unknown-field` case intentionally describes a malformed core request;
Plexus asserts that its own request omits the extra field, then decodes the
recorded refusal as `flow_audience_unavailable`.
