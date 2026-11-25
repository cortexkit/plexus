# GitHub v2 comment excerpt samples

`issue-comment.json` models a direct issue conversation-comment webhook.
`pr-comment.json` models a poll that finds a PR conversation comment during
actor enrichment. Inputs are synthetic. Both files contain the exact canonical
bytes from the production v2 envelope builder, with no trailing newline.
`SHA256SUMS` records the digests of those bytes.

To regenerate the samples and checksums from the workspace root:

```sh
PLEXUS_REGENERATE_COMMENT_EXCERPT_FIXTURES=1 cargo test --locked -p plexus-core --lib event_envelope::tests::comment_excerpt_samples_match_the_stored_envelope_bytes
```

Without the environment variable, the same test checks the samples and their
checksums against the builder's output.
