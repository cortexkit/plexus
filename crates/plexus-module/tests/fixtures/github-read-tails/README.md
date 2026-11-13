# GitHub tool tail replies

These four reply vectors pin the lean legacy tail envelope for job logs and
artifact files. Each has a 60,000-byte applied `max_bytes` limit. The short
natural log returns `length: 17` without truncation; the control-character log
is shortened from the oldest end until its complete canonical JSON body fits
65,536 bytes. Its `length` is the actual UTF-8 byte length of `text`, not the
applied limit or the original `total_bytes`.

The inputs and independent length/truncation assertions live in
`github_read_frame_tests::size_tests::tail_shape_vectors_pin_short_and_escaped_lengths`.
Regenerate intentionally with:

```sh
PLEXUS_REGENERATE_GITHUB_READ_TAIL_VECTORS=1 cargo test --locked -p plexus-module github_read_frame_tests::size_tests::tail_shape_vectors_pin_short_and_escaped_lengths -- --exact
```

The separate real-frame tests cover default/oversized requests and dispatch
clamping. No vector here describes or changes `github.read.bulk`.
