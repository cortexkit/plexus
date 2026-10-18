# Tool catalog wire vectors

Each request file contains the arguments sent to `tool.catalog`; its paired
reply file contains the exact compact JSON bytes Plexus serves for that
request. The `tool_provider` unit test runs the real `reply()` function and
compares its serialized output byte-for-byte with these committed replies.

After an intentional catalog contract change, regenerate the replies explicitly:

```sh
PLEXUS_REGENERATE_CATALOG_FIXTURES=1 cargo test -p plexus-module --lib tool_provider::tests::catalog_core_wire_vectors_match_reply -- --exact --nocapture
```

The opt-in mode writes real `reply()` output and prints each changed path.
Without that environment variable the test only compares bytes and never writes;
CI must leave it unset. Review the non-hash changes before committing, and run the
same command again without the variable to verify the committed replies.
