# Tool catalog wire vectors

Each request file contains the arguments sent to `tool.catalog`; its paired
reply file contains the exact compact JSON bytes Plexus serves for that
request. The `tool_provider` unit test runs the real `reply()` function and
compares its serialized output byte-for-byte with these committed replies. The
test does not write or regenerate fixtures at runtime.
