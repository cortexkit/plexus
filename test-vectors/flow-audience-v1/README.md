# Prefrontal flow audience v1 vectors

Vendor the contents of prefrontal-core's `test-vectors/flow-audience-v1/`
here without rewriting the replies. Then remove the `ignore` attribute from
`flow_audience::tests::upstream_flow_audience_vectors_decode_through_plexus`.

The upstream vectors have not been published yet. Current tests cover the
confirmed `{flow_id, audience, revision}` contract, not upstream compatibility.
